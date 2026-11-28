//! Translation of the Android dial fields shared by every outbound protocol.
use crate::{Fields, Result, error};
use serde_json::{Value, json};

pub(crate) fn convert(
    fields: &mut Fields,
    client: &mut Value,
    protocol: &str,
    native_quic: bool,
) -> Result<()> {
    let mut options = json!({});
    let strategy = fields.string("network_strategy")?;
    if let Some(value) = strategy.as_deref() {
        if !matches!(value, "default" | "hybrid" | "fallback") {
            return Err(error(
                format!("{}.network_strategy", fields.path),
                "expected default, hybrid or fallback",
            ));
        }
        options["network_strategy"] = value.into();
    }
    for name in ["network_type", "fallback_network_type"] {
        if let Some(value) = fields.take(name) {
            let values = match value {
                Value::String(value) => vec![Value::String(value)],
                Value::Array(values) => values,
                _ => {
                    return Err(error(
                        format!("{}.{}", fields.path, name),
                        "expected a network type or an array of network types",
                    ));
                }
            };
            let mut types = Vec::new();
            for value in values {
                let value = value
                    .as_str()
                    .filter(|value| matches!(*value, "wifi" | "cellular" | "ethernet" | "other"))
                    .ok_or_else(|| {
                        error(
                            format!("{}.{}", fields.path, name),
                            "expected wifi, cellular, ethernet or other",
                        )
                    })?;
                if !types.contains(&value.to_owned()) {
                    types.push(value.to_owned());
                }
            }
            if !types.is_empty() {
                options[name] = json!(types);
            }
        }
    }
    if let Some(value) = fields.string("fallback_delay")? {
        if value.trim().is_empty() {
            return Err(error(
                format!("{}.fallback_delay", fields.path),
                "expected a duration",
            ));
        }
        options["fallback_delay"] = value.into();
    }
    let network_policy = !options.as_object().unwrap().is_empty();
    if network_policy
        && client
            .get("bind_interface")
            .is_some_and(|value| !value.is_null())
    {
        return Err(error(
            &fields.path,
            "network strategy conflicts with bind_interface",
        ));
    }
    for name in [
        "connect_timeout",
        "tcp_keep_alive",
        "tcp_keep_alive_interval",
    ] {
        if let Some(value) = fields.string(name)? {
            if value.trim().is_empty() {
                return Err(error(format!("{}.{}", fields.path, name), "empty duration"));
            }
            if native_quic && name != "connect_timeout" {
                return Err(error(
                    format!("{}.{}", fields.path, name),
                    "TCP keepalive has no effect on a QUIC socket",
                ));
            }
            // Native DialDuration parses the complete Go duration syntax,
            // including fractions and mixed units, during configuration check.
            options[name] = value.into();
        }
    }
    for name in [
        "disable_tcp_keep_alive",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
    ] {
        if let Some(value) = fields.take(name) {
            let enabled = value
                .as_bool()
                .ok_or_else(|| error(format!("{}.{}", fields.path, name), "expected a boolean"))?;
            if enabled && native_quic && name != "udp_fragment" {
                return Err(error(
                    format!("{}.{}", fields.path, name),
                    "TCP socket options cannot be applied to a QUIC socket",
                ));
            }
            if enabled && name == "tcp_fast_open" && network_policy {
                return Err(error(
                    format!("{}.{}", fields.path, name),
                    "network strategy conflicts with tcp_fast_open",
                ));
            }
            if enabled && name == "tcp_fast_open" && protocol == "anytls" {
                return Err(error(
                    format!("{}.{}", fields.path, name),
                    "AnyTLS requires an established connection before its handshake",
                ));
            }
            options[name] = enabled.into();
        }
    }
    // sing-box's direct outbound sets UDPFragmentDefault=true. Other
    // outbounds use false, while an explicit direct false still wins.
    if protocol == "direct" && options.get("udp_fragment").is_none() {
        options["udp_fragment"] = true.into();
    }
    if !options.as_object().unwrap().is_empty() {
        client["dial_options"] = options;
    }
    Ok(())
}
