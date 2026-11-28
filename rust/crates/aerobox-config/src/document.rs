use crate::{Fields, Result, address, convert_outbound, error};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

/// Convert the current Android document to runtime JSON.
pub fn normalize_json(input: &str, tun_fd: Option<i32>) -> Result<String> {
    let value: Value = serde_json::from_str(input).map_err(|e| error("$", e.to_string()))?;
    serde_json::to_string(&normalize_value(value, tun_fd)?).map_err(|e| error("$", e.to_string()))
}

/// Convert an already parsed document without serializing intermediate values.
/// TUN descriptors are borrowed until the runtime duplicates them.
pub fn normalize_value(value: Value, tun_fd: Option<i32>) -> Result<Value> {
    let mut root = Fields::new(value, "$")?;
    let outbounds = root.required("outbounds")?;
    let outbounds = outbounds
        .as_array()
        .ok_or_else(|| error("$.outbounds", "expected array"))?;
    let mut names = HashSet::new();
    for (i, value) in outbounds.iter().enumerate() {
        let tag = value["tag"]
            .as_str()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| error(format!("$.outbounds[{i}].tag"), "nonempty tag required"))?;
        if !names.insert(tag.to_owned()) {
            return Err(error(
                format!("$.outbounds[{i}].tag"),
                "duplicate outbound tag",
            ));
        }
    }
    let plan = root
        .take("dns")
        .map(|value| crate::dns::Plan::parse(value, &names))
        .transpose()?;
    let mut entries = Vec::new();
    for (i, value) in outbounds.iter().enumerate() {
        let path = format!("$.outbounds[{i}]");
        let mut value = value.clone();
        if let Some(binding) = value.get_mut("domain_resolver") {
            let tags = plan.as_ref().map(|p| &p.tags).ok_or_else(|| {
                error(
                    format!("{path}.domain_resolver"),
                    "named DNS servers are required",
                )
            })?;
            *binding = crate::dns::domain_resolver(
                binding.take(),
                &format!("{path}.domain_resolver"),
                tags,
            )?;
        }
        entries.push(convert_outbound(value, &path)?);
    }
    let bootstrap = plan
        .as_ref()
        .and_then(|p| p.tags.contains("dns-direct").then_some("dns-direct"))
        .unwrap_or("system");
    let mut route =
        crate::singbox::route(root.take("route").unwrap_or(json!({})), &names, bootstrap)?;
    let blocked_networks: HashMap<_, _> = outbounds
        .iter()
        .filter_map(|outbound| {
            let blocked = match outbound["network"].as_str()? {
                "tcp" => "udp",
                "udp" => "tcp",
                _ => return None,
            };
            Some((outbound["tag"].as_str().unwrap(), blocked))
        })
        .collect();
    if !blocked_networks.is_empty() {
        // Preserve first-match routing and direct exceptions. DNS detours and
        // latency probes use the same client independently of this flow policy.
        route.rules = route
            .rules
            .into_iter()
            .flat_map(|rule| {
                let reject = rule["client_chain"]
                    .as_str()
                    .and_then(|tag| blocked_networks.get(tag))
                    .map(|network| {
                        json!({"action":"block", "conditions":{"all":[
                            rule["conditions"], {"network":[network]}
                        ]}})
                    });
                reject.into_iter().chain(std::iter::once(rule))
            })
            .collect();
    }
    if !route.auto_detect_interface {
        for (i, value) in outbounds.iter().enumerate() {
            if [
                "network_strategy",
                "network_type",
                "fallback_network_type",
                "fallback_delay",
            ]
            .iter()
            .any(|name| value.get(name).is_some())
            {
                return Err(error(
                    format!("$.outbounds[{i}]"),
                    "physical network settings require route.auto_detect_interface=true",
                ));
            }
        }
    }
    entries.extend(route.sources);
    if let Some(plan) = &plan {
        entries.extend(plan.entries.iter().cloned());
    }
    let inbounds = root.required("inbounds")?;
    let inbounds = inbounds
        .as_array()
        .ok_or_else(|| error("$.inbounds", "expected array"))?;
    // Empty listeners are used by the Android URL-test configuration.
    let mut tun_count = 0;
    for (i, value) in inbounds.iter().enumerate() {
        let path = format!("$.inbounds[{i}]");
        let mut f = Fields::new(value.clone(), &path)?;
        let kind = f.text("type")?;
        let tag = f.string("tag")?;
        let mut entry = json!({"rules":route.rules});
        if let Some(tag) = &tag {
            entry["name"] = tag.clone().into();
        }
        entry["sniff"] = f.boolean("sniff", route.sniff)?.into();
        if kind == "tun" {
            tun_count += 1;
            if tun_count > 1 && tun_fd.is_some() {
                return Err(error(
                    &path,
                    "one borrowed TUN descriptor cannot back multiple inbounds",
                ));
            }
            let fd = tun_fd.map(Value::from).or_else(|| f.take("device_fd"));
            f.take("device_fd");
            // Android's VpnService owns the interface and passes its descriptor.
            f.string("interface_name")?;
            if let Some(fd) = fd {
                if !fd
                    .as_i64()
                    .is_some_and(|n| (0..=i32::MAX as i64).contains(&n))
                {
                    return Err(error(format!("{path}.device_fd"), "invalid TUN descriptor"));
                }
                entry["device_fd"] = fd;
            } else {
                return Err(error(
                    format!("{path}.device_fd"),
                    "borrowed TUN descriptor required",
                ));
            }
            if let Some(stack) = f.string("stack")? {
                if !["mixed", "system", "gvisor"].contains(&stack.as_str()) {
                    return Err(error(format!("{path}.stack"), "unknown stack"));
                }
            }
            if let Some(addresses) = f.take("address") {
                if addresses.is_array() {
                    entry["addresses"] = addresses;
                } else {
                    entry["address"] = addresses;
                }
            }
            f.boolean("auto_route", false)?;
            entry["auto_route"] = false.into();
            entry["dns_hijack"] = f.boolean("dns_hijack", route.hijack)?.into();
            for key in [
                "mtu",
                "netmask",
                "tcp_enabled",
                "udp_enabled",
                "icmp_enabled",
                "packet_information",
                "resource_limits",
                "addresses",
                "bootstrap_dns",
            ] {
                f.copy(key, &mut entry, key);
            }
        } else if ["socks", "http", "mixed"].contains(&kind.as_str()) {
            let host = f.string("listen")?.unwrap_or("127.0.0.1".into());
            let port = f
                .required("listen_port")?
                .as_u64()
                .ok_or_else(|| error(format!("{path}.listen_port"), "expected port"))?;
            entry["address"] = address(&host, port, &path)?.into();
            let mut protocol = json!({"type":kind});
            for key in ["username", "password", "udp_enabled"] {
                f.copy(key, &mut protocol, key);
            }
            entry["protocol"] = protocol;
            if route.hijack {
                entry["dns_hijack"] = true.into();
            }
        } else {
            return Err(error(format!("{path}.type"), "unsupported inbound"));
        }
        if let Some(plan) = &plan {
            let mut dns = plan.for_inbound(tag.as_deref(), i)?;
            if let Some(strategy) = &route.strategy {
                dns["routing"]["ip_strategy"] =
                    crate::dns::strategy(strategy, "$.route.resolve.strategy")?.into();
                dns["routing"]["resolve_before_route"] = true.into();
            }
            entry["dns"] = json!({"servers":dns["dns_group"]});
            entries.push(dns);
        }
        f.finish()?;
        entries.push(entry);
    }
    if inbounds.is_empty() {
        if let Some(plan) = &plan {
            let dns = plan.for_inbound(None, 0)?;
            entries.push(json!({"global_settings":{"default_dns":{"servers":dns["dns_group"]}}}));
            entries.push(dns);
        }
    }
    if let Some(log) = root.take("log") {
        let mut f = Fields::new(log, "$.log")?;
        if let Some(level) = f.string("level")? {
            if !["trace", "debug", "info", "warn", "error", "fatal", "panic"]
                .contains(&level.as_str())
            {
                return Err(error("$.log.level", "unknown log level"));
            }
        }
        let _ = f.boolean("timestamp", false)?;
        f.finish()?;
    }
    if let Some(experimental) = root.take("experimental") {
        experimental_settings(experimental, &mut entries)?;
    }
    root.finish()?;
    // The runtime owns a built-in `direct` group. Android's same-named outbound
    // remains a distinct configured group so its options and statistics survive.
    if names.contains("direct") {
        if names.contains("__aerobox_direct") {
            return Err(error(
                "$.outbounds",
                "reserved adapter outbound tag __aerobox_direct",
            ));
        }
        fn remap(value: &mut Value, key: Option<&str>) {
            match value {
                Value::String(text)
                    if text == "direct"
                        && key.is_some_and(|key| {
                            ["client_group", "client_chain", "chain", "default"].contains(&key)
                        }) =>
                {
                    *text = "__aerobox_direct".into()
                }
                Value::Array(values) => {
                    for value in values {
                        remap(value, key);
                    }
                }
                Value::Object(values) => {
                    for (key, value) in values {
                        remap(value, Some(key));
                    }
                }
                _ => {}
            }
        }
        for entry in &mut entries {
            remap(entry, None);
        }
    }
    Ok(Value::Array(entries))
}

fn experimental_settings(value: Value, entries: &mut Vec<Value>) -> Result<()> {
    let mut f = Fields::new(value, "$.experimental")?;
    if let Some(value) = f.take("cache_file") {
        let mut c = Fields::new(value, "$.experimental.cache_file")?;
        let enabled = c.boolean("enabled", false)?;
        let store = c.boolean("store_fakeip", false)?;
        let path = c.string("path")?;
        c.finish()?;
        if enabled {
            if let Some(path) = path {
                if !std::path::Path::new(&path).is_absolute() {
                    return Err(error(
                        "$.experimental.cache_file.path",
                        "cache path must be absolute",
                    ));
                }
                for entry in entries.iter_mut() {
                    if store {
                        if let Some(fake) = entry.get_mut("fake_ip") {
                            fake["state_file"] = format!("{path}.fakeip").into();
                        }
                    }
                }
                if let Some(global) = entries
                    .iter_mut()
                    .find_map(|entry| entry.get_mut("global_settings"))
                {
                    global["rule_cache_dir"] = format!("{path}.rules").into();
                } else {
                    entries.push(
                        json!({"global_settings":{"rule_cache_dir":format!("{path}.rules")}}),
                    );
                }
            } else {
                return Err(error(
                    "$.experimental.cache_file.path",
                    "persistent FakeIP requires an explicit app-private file path",
                ));
            }
        }
    }
    f.finish()
}
