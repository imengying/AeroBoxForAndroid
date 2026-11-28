use serde_json::json;

#[test]
fn android_naive_quic_accepts_bbr2_and_rejects_unknown_controllers() {
    let runtime = aerobox::AndroidRuntime::new().unwrap();
    let mut document = json!({
        "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":2080}],
        "outbounds":[{"type":"naive","tag":"proxy","server":"127.0.0.1","server_port":443,
            "quic":true,"username":"user","password":"pass",
            "tls":{"enabled":true,"server_name":"proxy.test"}}],
        "route":{"final":"proxy"}
    });
    for controller in ["cubic", "bbr", "bbr2", "new_reno"] {
        document["outbounds"][0]["quic_congestion_control"] = controller.into();
        runtime
            .check(&document.to_string())
            .unwrap_or_else(|error| panic!("{controller}: {error}"));
        assert!(!runtime.is_running());
    }
    document["outbounds"][0]["quic_congestion_control"] = "bbr-invalid".into();
    assert!(runtime.check(&document.to_string()).is_err());
    assert!(!runtime.is_running());
}
