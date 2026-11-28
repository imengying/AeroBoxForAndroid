use crate::{Fields, Result, address, error, seconds};
use serde_json::{Value, json};

/// Convert a single Android/sing-box outbound into a named Rust client group.
/// Returns an error for every field that cannot be represented faithfully.
pub fn convert_outbound(value: Value, path: &str) -> Result<Value> {
    let mut f = Fields::new(value, path)?;
    let kind = f.text("type")?;
    let tag = f.text("tag")?;
    if tag.is_empty() {
        return Err(error(format!("{path}.tag"), "must not be empty"));
    }
    // The outbound tag names its group. Reusing it on the inline client
    // collides when latency probes enable the control catalog; the catalog
    // assigns internal client identities while routes keep the group tag.
    let mut client = json!({});
    if kind == "direct" {
        // Android's direct group is remapped to __aerobox_direct. Keep its
        // configured client distinct from the catalog's built-in DIRECT.
        client["name"] = tag.clone().into();
    }
    if kind != "direct" {
        let server = f.text("server")?;
        let mut port = f.take("server_port");
        if port.is_none() && kind == "hysteria2" {
            port = f
                .values
                .get("server_ports")
                .and_then(Value::as_array)
                .and_then(|v| v.first())
                .and_then(Value::as_str)
                .and_then(|v| v.split(':').next())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Value::from);
        }
        let port = port
            .and_then(|v| v.as_u64())
            .ok_or_else(|| error(format!("{path}.server_port"), "required port in 1..65535"))?;
        client["address"] = address(&server, port, path)?.into();
    }
    f.copy("bind_interface", &mut client, "bind_interface");
    f.copy("domain_resolver", &mut client, "domain_resolver");
    // This restricts routed user flows, not the carrier used by DNS or probes.
    // document::normalize_value applies it at each route selecting this outbound.
    match f.string("network")?.as_deref() {
        None | Some("" | "tcp,udp" | "udp,tcp" | "tcp" | "udp") => {}
        Some(_) => {
            return Err(error(
                format!("{path}.network"),
                "expected tcp, udp, or tcp,udp",
            ));
        }
    }
    let mut protocol = match kind.as_str() {
        "direct" => json!({"type":"direct"}),
        "shadowsocks" => {
            let mut p = json!({"type":"shadowsocks", "cipher":f.text("method")?, "password":f.text("password")?});
            if let Some(plugin) = crate::ss_plugin::convert(&mut f)? {
                p["plugin"] = plugin;
            }
            p
        }
        "vmess" => {
            let alter_id = match f.take("alter_id") {
                None => 0,
                Some(value) => value
                    .as_u64()
                    .filter(|value| *value <= u16::MAX as u64)
                    .ok_or_else(|| {
                        error(
                            format!("{path}.alter_id"),
                            "expected an integer in 0..65535",
                        )
                    })?,
            };
            let encoding = packet_encoding(&mut f, false)?;
            let cipher = f.string("security")?.unwrap_or("auto".into());
            let cipher = if cipher == "auto" {
                "any".into()
            } else {
                cipher
            };
            let mut p = json!({"type":"vmess", "packet_encoding":encoding, "cipher":cipher, "user_id":f.text("uuid")?, "alter_id":alter_id});
            f.copy("global_padding", &mut p, "global_padding");
            f.copy("authenticated_length", &mut p, "authenticated_length");
            p
        }
        "vless" => {
            let encoding = packet_encoding(&mut f, true)?;
            let flow = f.string("flow")?.unwrap_or_default();
            if !["", "xtls-rprx-vision"].contains(&flow.as_str()) {
                return Err(error(format!("{path}.flow"), "unsupported VLESS flow"));
            }
            json!({"type":"vless", "packet_encoding":encoding, "user_id":f.text("uuid")?, "vision":flow == "xtls-rprx-vision"})
        }
        "trojan" => json!({"type":"trojan", "password":f.text("password")?}),
        "anytls" => {
            let mut p = json!({"type":"anytls", "password":f.text("password")?});
            for (src, dst) in [
                (
                    "idle_session_check_interval",
                    "idle_session_check_interval_secs",
                ),
                ("idle_session_timeout", "idle_session_timeout_secs"),
            ] {
                if let Some(v) = f.take(src) {
                    p[dst] = seconds(v, &format!("{path}.{src}"))?.into();
                }
            }
            f.copy("min_idle_session", &mut p, "min_idle_session");
            p
        }
        "hysteria2" => {
            let mut p = json!({"type":"hysteria2", "password":f.text("password")?});
            f.copy("obfs", &mut p, "obfs");
            for key in ["up_mbps", "down_mbps"] {
                f.copy(key, &mut p, key);
            }
            if let Some(ports) = f.take("server_ports") {
                let values = ports
                    .as_array()
                    .ok_or_else(|| error(format!("{path}.server_ports"), "expected array"))?;
                let ports = values
                    .iter()
                    .map(|v| {
                        v.as_str().map(|s| s.replace(':', "-")).ok_or_else(|| {
                            error(format!("{path}.server_ports"), "expected port strings")
                        })
                    })
                    .collect::<Result<Vec<_>>>()?
                    .join(",");
                let mut hopping = json!({"ports":ports});
                if let Some(v) = f.take("hop_interval") {
                    hopping["interval_secs"] = seconds(v, &format!("{path}.hop_interval"))?.into();
                }
                p["hopping"] = hopping;
            }
            f.default_only("disable_chrome_parrot", &[json!(true)])?;
            // Original HY2 BrutalDebug only emits logger.Debug diagnostics; the App
            // fixes both VPN and probe log levels to error. It does not change pacing.
            f.boolean("brutal_debug", false)?;
            p
        }
        "tuic" => {
            let mut p =
                json!({"type":"tuic", "uuid":f.text("uuid")?, "password":f.text("password")?});
            let udp_over_stream = f.boolean("udp_over_stream", false)?;
            let relay_mode = f.string("udp_relay_mode")?.filter(|mode| !mode.is_empty());
            if udp_over_stream && relay_mode.is_some() {
                return Err(error(
                    format!("{path}.udp_over_stream"),
                    "conflicts with an explicit udp_relay_mode",
                ));
            }
            if let Some(mode) = relay_mode {
                if !matches!(mode.as_str(), "native" | "quic") {
                    return Err(error(
                        format!("{path}.udp_relay_mode"),
                        "expected native or quic",
                    ));
                }
                p["udp_relay_mode"] = mode.into();
            }
            if udp_over_stream {
                p["udp_over_stream"] = true.into();
            }
            if let Some(v) = f.take("heartbeat") {
                p["heartbeat_interval_secs"] = seconds(v, &format!("{path}.heartbeat"))?.into();
            }
            p["zero_rtt_handshake"] = f.boolean("zero_rtt_handshake", false)?.into();
            f.copy("congestion_control", &mut p, "congestion_control");
            p
        }
        "naive" => {
            let quic = f.boolean("quic", false)?;
            let mut settings = json!({"quic": quic});
            if let Some(headers) = f.take("extra_headers") {
                settings["extra_headers"] =
                    naive_extra_headers(headers, &format!("{path}.extra_headers"))?;
            }
            for key in ["insecure_concurrency", "quic_congestion_control"] {
                f.copy(key, &mut settings, key);
            }
            crate::naive_windows::apply(&mut f, &mut settings, quic)?;
            json!({"type":"naiveproxy", "settings":settings, "username":f.string("username")?.unwrap_or_default(), "password":f.string("password")?.unwrap_or_default()})
        }
        "socks" | "http" => {
            let mut p = json!({"type":kind});
            f.copy("username", &mut p, "username");
            f.copy("password", &mut p, "password");
            if kind == "socks" {
                f.default_only("version", &[json!("5")])?;
            } else {
                let mut settings = json!({});
                for key in ["path", "headers"] {
                    f.copy(key, &mut settings, key);
                }
                p["settings"] = settings;
            }
            p
        }
        _ => {
            return Err(error(
                format!("{path}.type"),
                "unsupported outbound protocol",
            ));
        }
    };
    if let Some(v) = f.take("multiplex") {
        let mut mux = Fields::new(v, &format!("{path}.multiplex"))?;
        if mux.boolean("enabled", false)? {
            if !["shadowsocks", "vmess", "vless", "trojan"].contains(&kind.as_str()) {
                return Err(error(
                    &mux.path,
                    "multiplex requires Shadowsocks, VMess, VLESS or Trojan",
                ));
            }
            let mut out = json!({});
            mux.copy("protocol", &mut out, "protocol");
            for key in ["max_connections", "min_streams", "max_streams", "padding"] {
                mux.copy(key, &mut out, key);
            }
            if let Some(value) = mux.take("brutal") {
                out["brutal"] = crate::brutal::convert(value, &format!("{}.brutal", mux.path))?;
            }
            if kind == "shadowsocks" {
                protocol = json!({"type":"multiplex","settings":out,"protocol":protocol});
            } else {
                protocol["h2mux"] = out;
            }
            mux.finish()?;
        } else {
            mux.default_only("protocol", &[json!("smux"), json!("yamux"), json!("h2mux")])?;
            mux.finish()?;
        }
    }
    let tls = f.take("tls");
    let has_tls = tls
        .as_ref()
        .and_then(|v| v.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if ["anytls", "trojan", "naive", "tuic", "hysteria2"].contains(&kind.as_str()) && !has_tls {
        return Err(error(
            format!("{path}.tls.enabled"),
            "this protocol requires TLS",
        ));
    }
    let native_quic = ["hysteria2", "tuic"].contains(&kind.as_str())
        || (kind == "naive" && protocol["settings"]["quic"] == true);
    let plugin_quic = crate::ss_plugin::uses_quic(&protocol);
    if plugin_quic && (has_tls || f.values.contains_key("transport")) {
        return Err(error(
            path,
            "v2ray-plugin QUIC configures its own transport and TLS through plugin_opts",
        ));
    }
    let mut quic_transport = native_quic || plugin_quic;
    if let Some(v) = f.take("transport") {
        let (wrapped, quic) = transport(v, protocol, has_tls, path)?;
        protocol = wrapped;
        quic_transport |= quic;
    }
    if let Some(tls) = tls {
        let (wrapped, quic) = tls_config(tls, protocol, quic_transport, &kind, path)?;
        protocol = wrapped;
        if let Some(quic) = quic {
            client["quic_settings"] = quic;
        }
    }
    if quic_transport {
        client["transport"] = "quic".into();
    }
    crate::dial_fields::convert(&mut f, &mut client, &kind, quic_transport)?;
    if let Some(uot) = f.take("udp_over_tcp") {
        let (enabled, version) = match uot {
            Value::Bool(enabled) => (enabled, 2),
            value => {
                let mut u = Fields::new(value, &format!("{path}.udp_over_tcp"))?;
                let enabled = u.boolean("enabled", true)?;
                let version = u
                    .take("version")
                    .unwrap_or(json!(2))
                    .as_u64()
                    .ok_or_else(|| error(&u.path, "invalid UoT version"))?;
                u.finish()?;
                (enabled, version)
            }
        };
        if !matches!(version, 1 | 2) {
            return Err(error(
                format!("{path}.udp_over_tcp.version"),
                "expected 1 or 2",
            ));
        }
        if enabled {
            if !["shadowsocks", "socks", "naive"].contains(&kind.as_str()) {
                return Err(error(
                    format!("{path}.udp_over_tcp"),
                    "UoT is not configurable for this protocol",
                ));
            }
            if kind == "naive" && native_quic {
                protocol["settings"]["udp_over_tcp"] = version.into();
            } else {
                protocol = json!({"type":"udp_over_tcp","version":version,"protocol":protocol});
            }
        }
    }
    client["protocol"] = protocol;
    f.finish()?;
    Ok(json!({"client_group":tag, "client_chains":[{"chain":[client]}]}))
}
fn packet_encoding(f: &mut Fields, xudp: bool) -> Result<String> {
    let encoding = f
        .string("packet_encoding")?
        .unwrap_or(if xudp { "xudp" } else { "none" }.into());
    if !["", "none", "xudp", "packetaddr"].contains(&encoding.as_str()) {
        return Err(error(
            format!("{}.packet_encoding", f.path),
            "expected none, xudp or packetaddr",
        ));
    }
    Ok(if encoding.is_empty() {
        "none".into()
    } else {
        encoding
    })
}
fn transport(value: Value, protocol: Value, tls: bool, path: &str) -> Result<(Value, bool)> {
    let mut f = Fields::new(value, &format!("{path}.transport"))?;
    let kind = f.text("type")?;
    if kind == "quic" {
        if !tls {
            return Err(error(&f.path, "QUIC requires TLS"));
        }
        f.finish()?;
        return Ok((protocol, true));
    }
    let mut out = if kind == "ws" {
        json!({"type":"websocket", "protocol":protocol})
    } else {
        json!({"type":"stream_transport", "kind":match kind.as_str() {"grpc"=>"grpc", "httpupgrade"=>"http_upgrade", "http" if tls=>"http2", "http"=>"http1", _=>return Err(error(format!("{}.type",f.path),"unsupported transport"))}, "protocol":protocol})
    };
    if kind == "ws" {
        f.copy("path", &mut out, "matching_path");
        f.copy("headers", &mut out, "matching_headers");
        f.copy("max_early_data", &mut out, "max_early_data");
        f.copy("early_data_header_name", &mut out, "early_data_header_name");
    } else {
        for key in ["path", "method", "headers", "service_name"] {
            f.copy(key, &mut out, key);
        }
        if let Some(host) = f.take("host") {
            if !host.is_string()
                && !host
                    .as_array()
                    .is_some_and(|v| v.iter().all(Value::is_string))
            {
                return Err(error(
                    format!("{}.host", f.path),
                    "expected a host or an array of hosts",
                ));
            }
            out["host"] = host;
        }
        if kind == "grpc" || kind == "http" {
            for key in ["idle_timeout", "ping_timeout"] {
                if let Some(value) = f.string(key)? {
                    if value.is_empty() {
                        return Err(error(format!("{}.{}", f.path, key), "empty duration"));
                    }
                    // The native DialDuration validates Go-style fractions and mixed units.
                    out[key] = value.into();
                }
            }
        }
        if kind == "grpc" {
            // AeroBox's sing-box build omitted with_grpc and used grpc-lite.
            // That transport accepts this field but has no separate idle-stream policy.
            f.boolean("permit_without_stream", false)?;
        }
    }
    f.finish()?;
    Ok((out, false))
}
fn tls_config(
    value: Value,
    mut protocol: Value,
    quic: bool,
    kind: &str,
    path: &str,
) -> Result<(Value, Option<Value>)> {
    let mut f = Fields::new(value, &format!("{path}.tls"))?;
    if !f.boolean("enabled", false)? {
        f.finish()?;
        return Ok((protocol, None));
    }
    let vision = protocol
        .get("vision")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if vision {
        // Android's flow uses legacy Vision on the TLS/REALITY wrapper.
        // VLESS's own vision flag belongs to native VLESS encryption, which
        // this input does not configure; retaining it selects two layers.
        protocol.as_object_mut().unwrap().remove("vision");
    }
    if kind == "naive" {
        for key in [
            "disable_sni",
            "insecure",
            "fragment",
            "record_fragment",
            "kernel_tx",
            "kernel_rx",
        ] {
            f.default_only(key, &[json!(false)])?;
        }
        for key in [
            "min_version",
            "max_version",
            "client_certificate_path",
            "client_key_path",
        ] {
            f.default_only(key, &[json!("")])?;
        }
        for key in [
            "alpn",
            "cipher_suites",
            "curve_preferences",
            "client_certificate",
            "client_key",
            "certificate_public_key_sha256",
        ] {
            f.default_only(key, &[json!([]), json!("")])?;
        }
        for key in ["utls", "reality"] {
            if f.values
                .get(key)
                .and_then(|v| v.get("enabled"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                return Err(error(
                    format!("{path}.tls.{key}"),
                    "not supported by the original Naive outbound",
                ));
            }
        }
    }
    let mut out =
        json!({"type":"tls", "protocol":protocol, "verify":!f.boolean("insecure", false)?});
    f.copy("server_name", &mut out, "sni_hostname");
    let mut options = json!({});
    for key in [
        "disable_sni",
        "min_version",
        "max_version",
        "cipher_suites",
        "certificate_public_key_sha256",
    ] {
        if let Some(v) = f.take(key) {
            options[key] = if matches!(key, "cipher_suites" | "certificate_public_key_sha256")
                && v.is_string()
            {
                json!([v])
            } else {
                v
            };
        }
    }
    if let Some(v) = f.take("certificate") {
        options["root_certificates"] = if v.is_string() { json!([v]) } else { v };
    }
    if let Some(v) = f.take("certificate_path") {
        if options.get("root_certificates").is_some() {
            return Err(error(
                &f.path,
                "certificate and certificate_path cannot both be set",
            ));
        }
        options["root_certificates"] = json!([v]);
    }
    if options
        .get("certificate_public_key_sha256")
        .and_then(Value::as_array)
        .is_some_and(|pins| !pins.is_empty())
    {
        if options
            .get("root_certificates")
            .and_then(Value::as_array)
            .is_some_and(|roots| !roots.is_empty())
        {
            return Err(error(
                &f.path,
                "certificate_public_key_sha256 conflicts with certificate or certificate_path",
            ));
        }
        // Match the App's pin-only trust mode. The runtime still checks the pin
        // and verifies TLS handshake signatures; malformed pins fail validation.
        out["verify"] = false.into();
    }
    if !options.as_object().unwrap().is_empty() {
        out["options"] = options;
    }
    f.copy("alpn", &mut out, "alpn_protocols");
    if out.get("alpn_protocols").is_none()
        && (kind == "naive" || matches!(out["protocol"]["kind"].as_str(), Some("grpc" | "http2")))
    {
        out["alpn_protocols"] = json!([if quic { "h3" } else { "h2" }]);
    }
    if let Some(groups) = f.take("curve_preferences") {
        // Android's putStringOrArray emits a scalar for one preference.
        // The native allowlist always uses a sequence, including one group.
        out["key_exchange_groups"] = if groups.is_string() {
            json!([groups])
        } else {
            groups
        };
    }
    for (inline, file, target) in [
        ("client_certificate", "client_certificate_path", "cert"),
        ("client_key", "client_key_path", "key"),
    ] {
        f.copy(inline, &mut out, target);
        if let Some(v) = f.take(file) {
            if out.get(target).is_some() {
                return Err(error(
                    &f.path,
                    "inline client credential and path cannot both be set",
                ));
            }
            out[target] = v;
        }
    }
    if let Some(reality) = f.take("reality") {
        let mut r = Fields::new(reality, &format!("{}.reality", f.path))?;
        if r.boolean("enabled", false)? {
            if quic {
                return Err(error(&r.path, "REALITY requires TCP"));
            }
            if out.get("key_exchange_groups").is_some() {
                return Err(error(
                    &f.path,
                    "REALITY does not support explicit curve_preferences",
                ));
            }
            if out.get("options").is_some() || out.get("cert").is_some() || out.get("key").is_some()
            {
                return Err(error(
                    &f.path,
                    "ordinary TLS certificate options do not apply to REALITY",
                ));
            }
            if out["verify"] == false {
                return Err(error(&f.path, "REALITY authentication cannot be disabled"));
            }
            out.as_object_mut().unwrap().remove("verify");
            out["type"] = "reality".into();
            out["public_key"] = r.required("public_key")?;
            r.copy("short_id", &mut out, "short_id");
        }
        r.finish()?;
    }
    if vision {
        out["vision"] = true.into();
    }
    let fragment = f.boolean("fragment", false)?;
    let record_fragment = f.boolean("record_fragment", false)?;
    let fallback_delay = f.string("fragment_fallback_delay")?;
    if quic && (fragment || record_fragment || fallback_delay.is_some()) {
        return Err(error(
            &f.path,
            "TLS fragment options require a stream transport, not QUIC",
        ));
    }
    if fragment || record_fragment || fallback_delay.is_some() {
        let mut fragmentation = json!({"fragment":fragment,"record_fragment":record_fragment});
        if let Some(value) = fallback_delay {
            if value.is_empty() {
                return Err(error(&f.path, "fragment_fallback_delay must not be empty"));
            }
            fragmentation["fragment_fallback_delay"] = value.into();
        }
        // Native DialDuration performs complete Go duration validation during
        // configuration check, as with the other outbound duration fields.
        out["fragmentation"] = fragmentation;
    }
    for key in ["kernel_tx", "kernel_rx"] {
        f.default_only(key, &[json!(false)])?;
    }
    if let Some(utls) = f.take("utls") {
        let mut u = Fields::new(utls, &format!("{}.utls", f.path))?;
        let enabled = u.boolean("enabled", false)?;
        let fingerprint = u.string("fingerprint")?;
        if enabled {
            if quic || kind == "naive" {
                return Err(error(
                    &u.path,
                    "Chrome133 requires ordinary stream TLS or REALITY; QUIC and Naive browser profiles are not implemented",
                ));
            }
            let profile = match fingerprint.as_deref().unwrap_or("") {
                ""
                | "chrome"
                | "chrome_psk"
                | "chrome_psk_shuffle"
                | "chrome_padding_psk_shuffle"
                | "chrome_pq"
                | "chrome_pq_psk" => "chrome133",
                "android" => "android11",
                "edge" => "edge85",
                "qq" => "qq11_1",
                "safari" => "safari16",
                "ios" => "ios14",
                "firefox" => "firefox120",
                "360" => "360_7_5",
                "randomized" => "randomized",
                "random" => aerobox_fingerprint::random_profile()
                    .map_err(|error| crate::error(&u.path, error.to_string()))?
                    .as_str(),
                _ => {
                    return Err(error(
                        &u.path,
                        "this browser TLS fingerprint is not implemented",
                    ));
                }
            };
            if profile == "randomized" {
                let plan = aerobox_fingerprint::randomized::process_plan()
                    .and_then(|p| p.for_stream(out["type"] == "reality"))
                    .map_err(|cause| error(&u.path, cause.to_string()))?;
                if vision && plan.maximum() != 0x0304 {
                    return Err(error(&u.path, "randomized plan has no TLS1.3 for Vision"));
                }
                if !plan.extensions().contains(&16)
                    && out["alpn_protocols"]
                        .as_array()
                        .is_some_and(|p| !p.is_empty())
                {
                    return Err(error(
                        &u.path,
                        "randomized plan did not select ALPN but this transport explicitly requires it",
                    ));
                }
            }
            if matches!(profile, "android11" | "360_7_5") && (out["type"] == "reality" || vision) {
                return Err(error(
                    &u.path,
                    "this legacy browser profile is incompatible with REALITY or Vision",
                ));
            }
            if out["type"] == "reality" {
                out["fingerprint"] = profile.into();
            } else {
                if out.get("options").is_none() {
                    out["options"] = json!({});
                }
                out["options"]["fingerprint"] = profile.into();
            }
        }
        u.finish()?;
    }
    if let Some(ech) = f.take("ech") {
        let mut e = Fields::new(ech, &format!("{}.ech", f.path))?;
        if e.boolean("enabled", false)? {
            if out["type"] == "reality" {
                return Err(error(&e.path, "ECH cannot be combined with REALITY"));
            }
            if matches!(
                out["options"]["fingerprint"].as_str(),
                Some(
                    "android11"
                        | "edge85"
                        | "qq11_1"
                        | "safari16"
                        | "ios14"
                        | "firefox120"
                        | "360_7_5"
                        | "randomized"
                )
            ) {
                return Err(error(&e.path, "this browser profile cannot negotiate ECH"));
            }
            let mut ech = json!({});
            if let Some(config) = e.take("config") {
                let value = match config {
                    Value::String(value) => value,
                    Value::Array(values) => values
                        .iter()
                        .map(|v| {
                            v.as_str().ok_or_else(|| {
                                error(&e.path, "ECH config must contain PEM strings")
                            })
                        })
                        .collect::<Result<Vec<_>>>()?
                        .join("\n"),
                    _ => {
                        return Err(error(
                            &e.path,
                            "ECH config requires PEM text or a list of lines",
                        ));
                    }
                };
                if !value.is_empty() {
                    ech["config"] = value.into();
                }
            }
            if let Some(path) = e.string("config_path")? {
                if ech.get("config").is_none() && !path.is_empty() {
                    ech["config_path"] = path.into();
                }
            }
            if let Some(name) = e.string("query_server_name")? {
                if !name.is_empty() {
                    ech["query_server_name"] = name.into();
                }
            }
            for key in [
                "pq_signature_schemes_enabled",
                "dynamic_record_sizing_disabled",
            ] {
                e.default_only(key, &[json!(false)])?;
            }
            if out["options"]["disable_sni"] == true {
                return Err(error(&e.path, "ECH requires SNI"));
            }
            if out.get("options").is_none() {
                out["options"] = json!({});
            }
            out["options"]["ech"] = ech;
        }
        e.finish()?;
    }
    f.finish()?;
    if quic {
        let protocol = out.as_object_mut().unwrap().remove("protocol").unwrap();
        out.as_object_mut().unwrap().remove("type");
        Ok((protocol, Some(out)))
    } else {
        Ok((out, None))
    }
}

// sing-box v1.14.4 protocol/naive/outbound.go converts Build() to a
// map[string]string using values[0]. Native HeaderValues::Many is separate.
fn naive_extra_headers(value: Value, path: &str) -> Result<Value> {
    let Value::Object(headers) = value else {
        return Err(error(path, "expected an object"));
    };
    let mut converted = serde_json::Map::new();
    for (name, value) in headers {
        let field = format!("{path}.{name}");
        match value {
            Value::String(value) => {
                converted.insert(name, Value::String(value));
            }
            Value::Array(values) => {
                // Go decodes every element before selecting the first; an
                // invalid later element must not disappear during conversion.
                for (index, value) in values.iter().enumerate() {
                    if !value.is_string() {
                        return Err(error(format!("{field}[{index}]"), "expected a string"));
                    }
                }
                if let Some(value) = values.into_iter().next() {
                    converted.insert(name, value);
                }
            }
            _ => return Err(error(field, "expected a string or array of strings")),
        }
    }
    Ok(Value::Object(converted))
}
