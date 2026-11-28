use crate::{Fields, Result, error};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// SIP003 uses backslash escapes, including in keys. The first value wins if
/// an option occurs more than once, matching the Android core's parser.
fn options(input: &str, path: &str) -> Result<BTreeMap<String, String>> {
    if input.len() > 64 * 1024 {
        return Err(error(path, "plugin options exceed 64 KiB"));
    }
    let mut options = BTreeMap::new();
    let mut chars = input.chars().peekable();
    while chars.peek().is_some() {
        let mut key = String::new();
        let mut value = String::new();
        let mut in_value = false;
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    let escaped = chars
                        .next()
                        .ok_or_else(|| error(path, "incomplete plugin option escape"))?;
                    if in_value {
                        value.push(escaped);
                    } else {
                        key.push(escaped);
                    }
                }
                ';' => break,
                '=' if !in_value => in_value = true,
                ch if in_value => value.push(ch),
                ch => key.push(ch),
            }
        }
        if key.is_empty() {
            return Err(error(path, "empty plugin option name"));
        }
        if !in_value {
            value.push('1');
        }
        options.entry(key).or_insert(value);
    }
    Ok(options)
}

pub(crate) fn convert(fields: &mut Fields) -> Result<Option<Value>> {
    let plugin = fields.string("plugin")?.unwrap_or_default();
    let input = fields.string("plugin_opts")?.unwrap_or_default();
    let path = format!("{}.plugin_opts", fields.path);
    if plugin.is_empty() {
        if !input.is_empty() {
            return Err(error(path, "plugin_opts requires a plugin"));
        }
        return Ok(None);
    }
    let mut options = options(&input, &path)?;
    let config = match plugin.as_str() {
        "obfs-local" => {
            let mode = options.remove("obfs").unwrap_or_else(|| "http".into());
            if !matches!(mode.as_str(), "http" | "tls") {
                return Err(error(&path, "obfs must be http or tls"));
            }
            let host = options.remove("obfs-host").unwrap_or_default();
            json!({"type":"obfs-local", "mode":mode, "host":host})
        }
        "v2ray-plugin" => {
            let mode = options.remove("mode").unwrap_or_else(|| "websocket".into());
            if !matches!(mode.as_str(), "websocket" | "quic") {
                return Err(error(&path, "v2ray-plugin mode must be websocket or quic"));
            }
            let explicit_host = options.remove("host");
            let host = explicit_host
                .clone()
                .unwrap_or_else(|| "cloudfront.com".into());
            let uri = options.remove("path").unwrap_or_else(|| "/".into());
            let tls = options.remove("tls").is_some();
            if mode == "quic" && !tls {
                return Err(error(&path, "v2ray-plugin QUIC requires tls"));
            }
            let mux: i32 = options
                .remove("mux")
                .unwrap_or_else(|| "1".into())
                .parse()
                .map_err(|_| error(&path, "invalid v2ray-plugin mux integer"))?;
            let certificate = options.remove("cert");
            let raw = options.remove("certRaw");
            let mut roots = Vec::new();
            // The Android plugin fills both TLS fields; its TLS builder
            // prefers inline Certificate over CertificatePath.
            if let Some(cert) = raw {
                roots.push(format!(
                    "-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----\n"
                ));
            } else if let Some(cert) = certificate.filter(|v| !v.is_empty()) {
                roots.push(cert);
            }
            if !tls && !roots.is_empty() {
                return Err(error(&path, "plugin certificates require tls"));
            }
            json!({"type":"v2ray-plugin", "mode":mode, "host":host, "path":uri, "mux":mux, "tls":tls, "sni_hostname":explicit_host, "root_certificates":roots})
        }
        _ => {
            return Err(error(
                format!("{}.plugin", fields.path),
                "unsupported Shadowsocks plugin",
            ));
        }
    };
    if let Some((key, _)) = options.first_key_value() {
        return Err(error(path, format!("unsupported plugin option: {key}")));
    }
    Ok(Some(config))
}

pub(crate) fn uses_quic(protocol: &Value) -> bool {
    protocol.get("plugin").is_some_and(|p| p["mode"] == "quic")
        || protocol.get("protocol").is_some_and(uses_quic)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sip003_escapes_flags_repeated_and_empty_values() {
        let parsed = options(r"a\=b=c\;d\\e;tls;empty=;a\=b=ignored;eq=x=y;", "opts").unwrap();
        assert_eq!(parsed["a=b"], "c;d\\e");
        assert_eq!(parsed["tls"], "1");
        assert_eq!(parsed["empty"], "");
        assert_eq!(parsed["eq"], "x=y");
        for invalid in [";x=y", "x=1;;y=2", "=1", "key\\"] {
            assert!(options(invalid, "opts").is_err(), "{invalid}");
        }
    }
    #[test]
    fn plugin_selection_and_options_are_strict() {
        for (input, mode, host) in [
            ("", "http", ""),
            ("obfs=tls;obfs-host=cdn.example", "tls", "cdn.example"),
        ] {
            let mut fields =
                Fields::new(json!({"plugin":"obfs-local", "plugin_opts":input}), "node").unwrap();
            let plugin = convert(&mut fields).unwrap().unwrap();
            assert_eq!(plugin["mode"], mode);
            assert_eq!(plugin["host"], host);
            fields.finish().unwrap();
        }
        for input in [
            json!({"plugin":"unknown"}),
            json!({"plugin_opts":"obfs=http"}),
            json!({"plugin":"obfs-local", "plugin_opts":"obfs=invalid"}),
            json!({"plugin":"obfs-local", "plugin_opts":"obfs=http;unused=1"}),
        ] {
            assert!(convert(&mut Fields::new(input, "node").unwrap()).is_err());
        }
    }
    #[test]
    fn websocket_plugin_defaults_mux_tls_and_certificate_precedence() {
        let read = |input| {
            convert(
                &mut Fields::new(
                    json!({"plugin":"v2ray-plugin", "plugin_opts":input}),
                    "node",
                )
                .unwrap(),
            )
            .unwrap()
            .unwrap()
        };
        let defaults = read("");
        assert_eq!(defaults["host"], "cloudfront.com");
        assert_eq!(defaults["mux"], 1);
        assert_eq!(defaults["path"], "/");
        assert_eq!(defaults["sni_hostname"], Value::Null);
        let custom =
            read("host=cdn.example;path=/v2;tls=0;mux=0;cert=/local/ca.pem;certRaw=base64");
        assert_eq!(custom["sni_hostname"], "cdn.example");
        assert_eq!(custom["tls"], true, "SIP003 flags are selected by presence");
        assert_eq!(custom["mux"], 0);
        assert_eq!(custom["root_certificates"], json!(["-----BEGIN CERTIFICATE-----\nbase64\n-----END CERTIFICATE-----\n"]));
        assert_eq!(read("tls;cert=/local/ca.pem")["root_certificates"], json!(["/local/ca.pem"]));
        assert_eq!(
            read("tls;certRaw=YWJj")["root_certificates"],
            json!(["-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"])
        );
    }

    #[test]
    fn quic_plugin_selects_udp_transport_and_owns_tls_across_wrappers() {
        let node = json!({"type":"shadowsocks", "tag":"ss", "server":"proxy.example", "server_port":443,
            "method":"aes-128-gcm", "password":"test", "plugin":"v2ray-plugin", "plugin_opts":"mode=quic;tls;host=cdn.example;mux=8"});
        for wrapper in [
            Value::Null,
            json!({"udp_over_tcp":true}),
            json!({"multiplex":{"enabled":true,"protocol":"h2mux"}}),
        ] {
            let mut value = node.clone();
            if let Some(fields) = wrapper.as_object() {
                value.as_object_mut().unwrap().extend(fields.clone());
            }
            let converted = crate::outbound::convert_outbound(value, "node").unwrap();
            let client = &converted["client_chains"][0]["chain"][0];
            assert_eq!(client["transport"], "quic");
            assert!(client.get("quic_settings").is_none());
            assert!(uses_quic(&client["protocol"]));
        }
        for extra in [
            json!({"plugin_opts":"mode=quic"}),
            json!({"transport":{"type":"ws"}}),
            json!({"tls":{"enabled":true}}),
            json!({"tcp_fast_open":true}),
        ] {
            let mut value = node.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(crate::outbound::convert_outbound(value, "node").is_err());
        }
    }
}
