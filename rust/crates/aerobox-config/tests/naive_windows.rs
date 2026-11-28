use aerobox_config::convert_outbound;
use serde_json::{Value, json};

fn node(quic: bool) -> Value {
    json!({
        "type": "naive", "tag": "proxy", "server": "naive.example", "server_port": 443,
        "quic": quic, "tls": {"enabled": true, "server_name": "naive.example"},
    })
}

fn settings(value: Value) -> Value {
    let converted = convert_outbound(value, "$.outbounds[2]").unwrap();
    let client = &converted["client_chains"][0]["chain"][0];
    if client["transport"] == "quic" {
        client["protocol"]["settings"].clone()
    } else {
        assert_eq!(client["protocol"]["type"], "tls");
        client["protocol"]["protocol"]["settings"].clone()
    }
}

#[test]
fn android_defaults_and_explicit_zero_match_pinned_cronet_modes() {
    for (quic, stream, session) in [
        (false, 64 * 1024 * 1024, 128 * 1024 * 1024),
        (true, 6 * 1024 * 1024, 15 * 1024 * 1024),
    ] {
        for zero in [None, Some(json!(0)), Some(json!("0 B"))] {
            let mut value = node(quic);
            if let Some(zero) = zero {
                value["stream_receive_window"] = zero.clone();
                value["quic_session_receive_window"] = zero;
            }
            let parsed = settings(value);
            assert_eq!(parsed["stream_receive_window"], stream);
            assert_eq!(parsed["session_receive_window"], session);
        }
    }
}

#[test]
fn http2_receive_setting_controls_connection_and_halves_stream_credit() {
    for (input, expected) in [(json!("2 MiB"), 2 * 1024 * 1024), (json!(65537), 65537)] {
        let mut value = node(false);
        value["stream_receive_window"] = input;
        let parsed = settings(value);
        assert_eq!(parsed["session_receive_window"], expected);
        assert_eq!(parsed["stream_receive_window"], expected / 2);
    }
}

#[test]
fn http3_windows_remain_independent_and_concurrency_is_preserved() {
    let mut value = node(true);
    value["stream_receive_window"] = json!("512 KiB");
    value["quic_session_receive_window"] = json!("2 MiB");
    value["insecure_concurrency"] = 3.into();
    let parsed = settings(value);
    assert_eq!(parsed["stream_receive_window"], 512 * 1024);
    assert_eq!(parsed["session_receive_window"], 2 * 1024 * 1024);
    assert_eq!(parsed["insecure_concurrency"], 3);

    let mut stream_only = node(true);
    stream_only["stream_receive_window"] = json!("1 MiB");
    assert_eq!(
        settings(stream_only)["session_receive_window"],
        15 * 1024 * 1024
    );
    let mut session_only = node(true);
    session_only["quic_session_receive_window"] = json!("16 MiB");
    assert_eq!(
        settings(session_only)["stream_receive_window"],
        6 * 1024 * 1024
    );
}

#[test]
fn non_quic_session_override_is_rejected_instead_of_silently_repurposed() {
    let mut value = node(false);
    value["quic_session_receive_window"] = json!("2 MiB");
    let error = convert_outbound(value, "$.outbounds[2]").unwrap_err();
    assert_eq!(error.path, "$.outbounds[2].quic_session_receive_window");
    assert!(error.message.contains("quic is enabled"));
}

#[test]
fn window_range_and_integer_errors_report_the_original_field() {
    for (quic, key, value) in [
        (false, "stream_receive_window", json!(i32::MAX as u64 + 1)),
        (true, "stream_receive_window", json!(i32::MAX as u64 + 1)),
        (true, "quic_session_receive_window", json!("2 GB")),
        (true, "stream_receive_window", json!(-1)),
        (true, "stream_receive_window", json!("1.5 MB")),
        (true, "stream_receive_window", json!(1.5)),
        (
            true,
            "stream_receive_window",
            json!("18446744073709551615 KB"),
        ),
    ] {
        let mut candidate = node(quic);
        candidate[key] = value;
        let error = convert_outbound(candidate, "$.outbounds[2]").unwrap_err();
        assert_eq!(error.path, format!("$.outbounds[2].{key}"));
    }
    for (quic, receive) in [
        (false, 1),
        (false, 32767),
        (false, 128 * 1024 * 1024 + 1),
        (false, i32::MAX as u32),
        (true, 1),
        (true, 16 * 1024 - 1),
        (true, 64 * 1024 * 1024 + 1),
        (true, i32::MAX as u32),
    ] {
        let mut value = node(quic);
        value["stream_receive_window"] = receive.into();
        let parsed = settings(value);
        assert_eq!(
            parsed["stream_receive_window"],
            if quic {
                receive.max(16 * 1024)
            } else {
                receive / 2
            }
        );
    }
    for session in [1, 16383, 128 * 1024 * 1024 + 1, i32::MAX as u32] {
        let mut value = node(true);
        value["quic_session_receive_window"] = session.into();
        assert_eq!(
            settings(value)["session_receive_window"],
            session.max(16 * 1024)
        );
    }
}

#[test]
fn naive_memory_units_are_binary_and_do_not_round_through_floating_point() {
    for (input, bytes) in [
        (json!("512 kB"), 512 * 1024),
        (json!("128 MB"), 128 * 1024 * 1024),
        (json!("1g"), 1024 * 1024 * 1024),
        (json!("2 MiB"), 2 * 1024 * 1024),
        (json!("2147483647 B"), i32::MAX as u32),
    ] {
        for quic in [false, true] {
            let mut value = node(quic);
            value["stream_receive_window"] = input.clone();
            let parsed = settings(value);
            assert_eq!(
                parsed["stream_receive_window"],
                if quic { bytes } else { bytes / 2 }
            );
            if !quic {
                assert_eq!(parsed["session_receive_window"], bytes);
            }
        }
    }
}
