use crate::{Fields, Result, address, error};
use serde_json::{Value, json};
use std::collections::HashSet;

pub(crate) fn strategy(value: &str, path: &str) -> Result<&'static str> {
    match value {
        "" | "prefer_ipv4" => Ok("ipv4_then_ipv6"),
        "prefer_ipv6" => Ok("ipv6_then_ipv4"),
        "ipv4_only" => Ok("ipv4_only"),
        "ipv6_only" => Ok("ipv6_only"),
        "as_is" => Ok("ipv4_and_ipv6"),
        _ => Err(error(path, "unknown DNS address strategy")),
    }
}
pub(crate) fn domain_resolver(value: Value, path: &str, tags: &HashSet<String>) -> Result<Value> {
    let (name, policy) = if let Some(name) = value.as_str() {
        (name.to_owned(), "ipv4_then_ipv6")
    } else {
        let mut f = Fields::new(value, path)?;
        let name = f.text("server")?;
        let policy = strategy(
            &f.string("strategy")?.unwrap_or("prefer_ipv4".into()),
            &format!("{path}.strategy"),
        )?;
        f.default_only("disable_cache", &[json!(false)])?;
        f.finish()?;
        (name, policy)
    };
    if !tags.contains(&name) {
        return Err(error(path, "unknown domain resolver server"));
    }
    Ok(json!({"server":name,"ip_strategy":policy}))
}

pub(crate) struct Plan {
    pub entries: Vec<Value>,
    pub tags: HashSet<String>,
    rules: Vec<Value>,
    final_server: String,
    strategy: String,
    fake: Option<(String, Value)>,
}
impl Plan {
    pub fn parse(value: Value, outbounds: &HashSet<String>) -> Result<Self> {
        let mut f = Fields::new(value, "$.dns")?;
        let servers = f.required("servers")?;
        let servers = servers
            .as_array()
            .ok_or_else(|| error("$.dns.servers", "expected array"))?;
        let mut tags = HashSet::new();
        for (index, server) in servers.iter().enumerate() {
            let tag = server["tag"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    error(
                        format!("$.dns.servers[{index}].tag"),
                        "required nonempty string",
                    )
                })?;
            if !tags.insert(tag.to_owned()) {
                return Err(error("$.dns.servers", "duplicate DNS tag"));
            }
        }
        let final_server = f.text("final")?;
        if !tags.contains(&final_server) {
            return Err(error("$.dns.final", "unknown DNS server"));
        }
        let policy = strategy(
            &f.string("strategy")?.unwrap_or("prefer_ipv4".into()),
            "$.dns.strategy",
        )?
        .to_owned();
        let rules = f.take("rules").unwrap_or(json!([]));
        let rules = rules
            .as_array()
            .ok_or_else(|| error("$.dns.rules", "expected array"))?
            .clone();
        for key in ["disable_cache", "disable_expire", "independent_cache"] {
            f.default_only(key, &[json!(false)])?;
        }
        f.finish()?;
        let mut entries = Vec::new();
        let mut fake = None;
        for (index, server) in servers.iter().enumerate() {
            let path = format!("$.dns.servers[{index}]");
            let mut f = Fields::new(server.clone(), &path)?;
            let kind = f.text("type")?;
            let tag = f.text("tag")?;
            if kind == "fakeip" {
                if fake.is_some() {
                    return Err(error(&path, "only one FakeIP pool is supported"));
                }
                let ipv4 = f.string("inet4_range")?;
                let ipv6 = f.string("inet6_range")?;
                if ipv4.is_none() && ipv6.is_none() {
                    return Err(error(&path, "FakeIP requires an address range"));
                }
                fake = Some((
                    tag,
                    json!({"ipv4_range":ipv4,"ipv6_range":ipv6,"missing_family":"nodata"}),
                ));
                f.finish()?;
                continue;
            }
            let mut spec = if kind == "local" {
                json!({"url":"system","ip_strategy":"ipv4_and_ipv6"})
            } else {
                if !["udp", "tcp", "tls", "https", "quic", "h3"].contains(&kind.as_str()) {
                    return Err(error(format!("{path}.type"), "unsupported DNS transport"));
                }
                let host = f.text("server")?;
                let port = f
                    .take("server_port")
                    .unwrap_or_else(|| {
                        json!(match kind.as_str() {
                            "https" | "h3" => 443,
                            "tls" | "quic" => 853,
                            _ => 53,
                        })
                    })
                    .as_u64()
                    .ok_or_else(|| error(&path, "invalid DNS port"))?;
                let endpoint = address(&host, port, &path)?;
                let suffix = if ["https", "h3"].contains(&kind.as_str()) {
                    f.string("path")?.unwrap_or("/dns-query".into())
                } else {
                    String::new()
                };
                if !suffix.is_empty()
                    && (!suffix.starts_with('/')
                        || suffix.contains(['#', '?'])
                        || suffix.chars().any(char::is_whitespace))
                {
                    return Err(error(format!("{path}.path"), "invalid DNS request path"));
                }
                let mut spec = json!({"url":format!("{kind}://{endpoint}{suffix}"),"ip_strategy":"ipv4_and_ipv6"});
                if let Some(binding) = f.take("domain_resolver") {
                    let binding =
                        domain_resolver(binding, &format!("{path}.domain_resolver"), &tags)?;
                    spec["bootstrap_url"] = binding["server"].clone();
                } else if host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_err()
                {
                    return Err(error(
                        format!("{path}.domain_resolver"),
                        "hostname DNS upstream requires an explicit bootstrap resolver",
                    ));
                }
                spec
            };
            if let Some(detour) = f.string("detour")? {
                if !outbounds.contains(&detour) {
                    return Err(error(format!("{path}.detour"), "unknown outbound"));
                }
                if kind == "local" {
                    return Err(error(&path, "platform DNS cannot have a proxy detour"));
                }
                spec["client_chain"] = detour.into();
            }
            if let Some(timeout) = f.take("timeout") {
                spec["timeout_secs"] = crate::seconds(timeout, &format!("{path}.timeout"))?.into();
            }
            f.finish()?;
            entries.push(json!({"dns_group":tag,"dns_servers":[spec]}));
        }
        if fake.as_ref().is_some_and(|(name, _)| name == &final_server) {
            return Err(error(
                "$.dns.final",
                "default resolver must provide real addresses",
            ));
        }
        Ok(Self {
            entries,
            tags,
            rules,
            final_server,
            strategy: policy,
            fake,
        })
    }
    pub fn for_inbound(&self, tag: Option<&str>, index: usize) -> Result<Value> {
        let mut rules = Vec::new();
        let mut fake_used = false;
        for (i, value) in self.rules.iter().enumerate() {
            let path = format!("$.dns.rules[{i}]");
            let mut f = Fields::new(value.clone(), &path)?;
            let selected = match f.take("inbound") {
                None => true,
                Some(value) => {
                    let inbound = crate::singbox::strings(value, &format!("{path}.inbound"))?;
                    tag.is_some_and(|tag| inbound.iter().any(|s| s == tag))
                }
            };
            let action = f.string("action")?.unwrap_or("route".into());
            let mut rule = json!({});
            if let Some(types) = f.take("query_type") {
                let values = match types {
                    Value::Array(values) => values,
                    value => vec![value],
                };
                let mut query_types = Vec::new();
                for value in values {
                    let code = if let Some(code) = value.as_u64() {
                        code
                    } else {
                        match value.as_str().unwrap_or("") {
                            "A" => 1,
                            "AAAA" => 28,
                            "HTTPS" => 65,
                            "SVCB" => 64,
                            "TXT" => 16,
                            "CNAME" => 5,
                            "MX" => 15,
                            "NS" => 2,
                            "PTR" => 12,
                            _ => {
                                return Err(error(
                                    format!("{path}.query_type"),
                                    "unknown DNS query type",
                                ));
                            }
                        }
                    };
                    if !(1..=65535).contains(&code) {
                        return Err(error(&path, "invalid DNS query type"));
                    }
                    query_types.push(code);
                }
                rule["query_types"] = json!(query_types);
            }
            match action.as_str() {
                "route" => {
                    let server = f.text("server")?;
                    if !self.tags.contains(&server) {
                        return Err(error(format!("{path}.server"), "unknown DNS server"));
                    }
                    if self.fake.as_ref().is_some_and(|(name, _)| name == &server) {
                        rule["fake_ip"] = true.into();
                        fake_used |= selected;
                    } else {
                        rule["server"] = server.into();
                    }
                }
                "predefined" => {
                    let rcode = f.string("rcode")?.unwrap_or("NOERROR".into());
                    rule["rcode"] = json!(match rcode.as_str() {
                        "NOERROR" => 0,
                        "FORMERR" => 1,
                        "SERVFAIL" => 2,
                        "NXDOMAIN" => 3,
                        "NOTIMP" => 4,
                        "REFUSED" => 5,
                        _ =>
                            return Err(error(format!("{path}.rcode"), "unsupported response code")),
                    });
                }
                "reject" => rule["rcode"] = json!(5),
                _ => {
                    return Err(error(
                        format!("{path}.action"),
                        "unsupported DNS rule action",
                    ));
                }
            }
            rule["conditions"] = crate::singbox::conditions(&mut f)?;
            f.finish()?;
            if selected {
                rules.push(rule);
            }
        }
        let name = format!("__aerobox_dns_{index}");
        let mut entry = json!({"dns_group":name,"routing":{"final_server":self.final_server,"ip_strategy":self.strategy,"rules":rules}});
        if fake_used {
            entry["fake_ip"] = self.fake.as_ref().unwrap().1.clone();
        }
        Ok(entry)
    }
}
