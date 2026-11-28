use crate::{Fields, Result, error};
use serde_json::{Value, json};
use std::collections::HashSet;

pub(crate) fn strings(value: Value, path: &str) -> Result<Vec<String>> {
    let values = match value {
        Value::Array(values) => values,
        value => vec![value],
    };
    if values.is_empty() {
        return Err(error(path, "nonempty list required"));
    }
    values
        .into_iter()
        .map(|value| {
            value
                .as_str()
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| error(path, "nonempty string required"))
        })
        .collect()
}

pub(crate) fn conditions(f: &mut Fields) -> Result<Value> {
    let invert = f.boolean("invert", false)?;
    let mut all = Vec::new();
    for key in [
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "ip_cidr",
        "network",
        "protocol",
    ] {
        if let Some(value) = f.take(key) {
            let mut values = strings(value, &format!("{}.{}", f.path, key))?;
            if key == "domain_suffix" {
                for value in &mut values {
                    *value = value.trim_start_matches('.').to_owned();
                }
            }
            all.push(json!({key:values}));
        }
    }
    if let Some(value) = f.take("port") {
        let values = match value {
            Value::Array(values) => values,
            value => vec![value],
        };
        if values.is_empty()
            || values
                .iter()
                .any(|v| !v.as_u64().is_some_and(|v| (1..=65535).contains(&v)))
        {
            return Err(error(format!("{}.port", f.path), "expected ports 1..65535"));
        }
        all.push(json!({"destination_port":values}));
    }
    if let Some(value) = f.take("port_range") {
        all.push(
            json!({"destination_port_range":strings(value,&format!("{}.port_range",f.path))?}),
        );
    }
    if let Some(value) = f.take("rule_set") {
        let names = strings(value, &format!("{}.rule_set", f.path))?;
        let terms: Vec<_> = names
            .into_iter()
            .map(|name| json!({"rule_source_group":name}))
            .collect();
        all.push(if terms.len() == 1 {
            terms[0].clone()
        } else {
            json!({"any":terms})
        });
    }
    if let Some(kind) = f.string("type")? {
        if kind != "logical" {
            return Err(error(format!("{}.type", f.path), "unsupported rule type"));
        }
        let mode = f.text("mode")?;
        let key = match mode.as_str() {
            "and" => "all",
            "or" => "any",
            _ => return Err(error(format!("{}.mode", f.path), "expected and/or")),
        };
        let values = f.required("rules")?;
        let values = values
            .as_array()
            .ok_or_else(|| error(&f.path, "logical rules require array"))?;
        let mut terms = Vec::new();
        for (i, value) in values.iter().enumerate() {
            let mut child = Fields::new(value.clone(), &format!("{}.rules[{i}]", f.path))?;
            terms.push(conditions(&mut child)?);
            child.finish()?;
        }
        if terms.is_empty() {
            return Err(error(&f.path, "logical rules cannot be empty"));
        }
        all.push(json!({key:terms}));
    }
    let condition = match all.len() {
        0 => json!({"any_destination":true}),
        1 => all.pop().unwrap(),
        _ => json!({"all":all}),
    };
    Ok(if invert {
        json!({"not":condition})
    } else {
        condition
    })
}

pub(crate) struct Route {
    pub auto_detect_interface: bool,
    pub rules: Vec<Value>,
    pub sources: Vec<Value>,
    pub sniff: bool,
    pub hijack: bool,
    pub strategy: Option<String>,
}
pub(crate) fn route(value: Value, tags: &HashSet<String>, bootstrap: &str) -> Result<Route> {
    let mut f = Fields::new(value, "$.route")?;
    let final_tag = f.text("final")?;
    if !tags.contains(&final_tag) {
        return Err(error("$.route.final", "unknown outbound tag"));
    }
    let auto_detect_interface = f.boolean("auto_detect_interface", false)?;
    let mut output = Route {
        auto_detect_interface,
        rules: Vec::new(),
        sources: Vec::new(),
        sniff: false,
        hijack: false,
        strategy: None,
    };
    let sources = f.take("rule_set").unwrap_or(json!([]));
    let sources = sources
        .as_array()
        .ok_or_else(|| error("$.route.rule_set", "expected array"))?;
    let mut seen = HashSet::new();
    for (index, value) in sources.iter().enumerate() {
        let path = format!("$.route.rule_set[{index}]");
        let mut s = Fields::new(value.clone(), &path)?;
        let tag = s.text("tag")?;
        if !seen.insert(tag.clone()) {
            return Err(error(&path, "duplicate rule set tag"));
        }
        let kind = s.text("type")?;
        let format = s.string("format")?.unwrap_or("source".into());
        let format = match format.as_str() {
            "binary" => "srs",
            "source" => "singbox_json",
            _ => return Err(error(&path, "unsupported rule set format")),
        };
        let mut source = json!({"format":format});
        match kind.as_str() {
            "local" => source["path"] = s.text("path")?.into(),
            "remote" => {
                source["url"] = s.text("url")?.into();
                if let Some(value) = s.take("update_interval") {
                    source["update_interval"] = value;
                }
                let detour = if let Some(value) = s.take("http_client") {
                    let mut h = Fields::new(value, &format!("{path}.http_client"))?;
                    let name = h.text("detour")?;
                    h.finish()?;
                    name
                } else {
                    s.string("download_detour")?.unwrap_or(final_tag.clone())
                };
                if !tags.contains(&detour) {
                    return Err(error(&path, "unknown download detour"));
                }
                source["download"] = json!({"client_chain":detour,"bootstrap_url":bootstrap});
            }
            _ => return Err(error(&path, "unsupported rule set type")),
        }
        s.finish()?;
        output
            .sources
            .push(json!({"rule_source_group":tag,"rules":[source]}));
    }
    let values = f.take("rules").unwrap_or(json!([]));
    let values = values
        .as_array()
        .ok_or_else(|| error("$.route.rules", "expected array"))?;
    let mut saw_decision = false;
    for (index, value) in values.iter().enumerate() {
        let path = format!("$.route.rules[{index}]");
        let mut r = Fields::new(value.clone(), &path)?;
        let action = r.string("action")?.unwrap_or("route".into());
        match action.as_str() {
            "sniff" => {
                if saw_decision {
                    return Err(error(&path, "sniff must precede routing decisions"));
                }
                output.sniff = true;
                r.finish()?;
            }
            "resolve" => {
                if saw_decision {
                    return Err(error(&path, "resolve must precede routing decisions"));
                }
                let strategy = r.string("strategy")?.unwrap_or("prefer_ipv4".into());
                crate::dns::strategy(&strategy, &format!("{path}.strategy"))?;
                output.strategy = Some(strategy);
                r.finish()?;
            }
            "hijack-dns" => {
                if saw_decision {
                    return Err(error(
                        &path,
                        "DNS interception must precede routing decisions",
                    ));
                }
                if !matches!(r.take("port"),Some(v) if v==json!([53])||v==json!(53))
                    && !matches!(r.take("protocol"),Some(v) if v==json!("dns")||v==json!(["dns"]))
                {
                    return Err(error(
                        &path,
                        "DNS interception requires port 53 or DNS protocol",
                    ));
                }
                r.finish()?;
                output.hijack = true;
            }
            "route" | "reject" => {
                saw_decision = true;
                if let Some(source) = r.take("source_ip_cidr") {
                    let mut values = strings(source, &format!("{path}.source_ip_cidr"))?;
                    values.sort();
                    if action != "reject" || values != ["224.0.0.0/3", "ff00::/8"] {
                        return Err(error(
                            &path,
                            "only the Android reserved/multicast source rejection is supported; arbitrary source rules require native routing support",
                        ));
                    }
                    r.finish()?;
                    continue;
                }
                let mut rule = json!({});
                if action == "reject" {
                    rule["action"] = "block".into();
                } else {
                    let tag = r.text("outbound")?;
                    if !tags.contains(&tag) {
                        return Err(error(&path, "unknown outbound tag"));
                    }
                    rule["client_chain"] = tag.into();
                }
                rule["conditions"] = conditions(&mut r)?;
                r.finish()?;
                output.rules.push(rule);
            }
            _ => {
                return Err(error(
                    format!("{path}.action"),
                    "unsupported routing action",
                ));
            }
        }
    }
    output
        .rules
        .push(json!({"conditions":{"any_destination":true},"client_chain":final_tag}));
    f.finish()?;
    Ok(output)
}
