//! Dynamic structure plus real independent key exchanges, not seeded TLS keys.
#[path = "../../../../vendor/shoes/src/crypto/rustcrypto_kx.rs"]
pub mod production_hybrid;
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, RootCertStore,
    client::{
        ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout,
        RandomizedClientHello, Resumption,
    },
};
use std::sync::Arc;

pub fn ids(value: &serde_json::Value, name: &str) -> Vec<u16> {
    value[name]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u16)
        .collect()
}
pub fn structure(value: &serde_json::Value) -> Result<RandomizedClientHello, rustls::Error> {
    RandomizedClientHello::new(
        value["minimum"].as_u64().unwrap() as u16,
        value["maximum"].as_u64().unwrap() as u16,
        &ids(value, "suites"),
        &ids(value, "signatures"),
        &ids(value, "groups"),
        &ids(value, "shares"),
        &ids(value, "extensions"),
    )
}
pub fn config(value: &serde_json::Value, tls13_only: bool) -> Result<ClientConfig, rustls::Error> {
    let plan = structure(value)?;
    let mut provider = aerobox_crypto::randomized::provider(&ids(value, "suites"))?;
    provider.kx_groups = ids(value, "groups")
        .into_iter()
        .map(|g| production_hybrid::group(NamedGroup::from(g)))
        .collect();
    let maximum = value["maximum"].as_u64().unwrap();
    let versions = if tls13_only {
        vec![&rustls::version::TLS13]
    } else if maximum == 0x0304 {
        vec![&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        vec![&rustls::version::TLS12]
    };
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)?
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    cfg.cert_compressors.clear();
    cfg.cert_decompressors.clear();
    cfg.require_ems = false;
    cfg.resumption = Resumption::disabled();
    cfg.initial_key_share_groups = ids(value, "shares")
        .into_iter()
        .map(NamedGroup::from)
        .collect();
    let extensions = ids(value, "extensions");
    cfg.enable_tls12_renegotiation = !tls13_only && extensions.contains(&65281);
    if extensions.contains(&16) {
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    if extensions.contains(&17513) {
        cfg.application_settings = Some(ApplicationSettings::new(
            ApplicationSettingsCodepoint::Legacy,
            vec![(b"h2".to_vec(), vec![])],
        )?);
    }
    if !tls13_only && value["minimum"] == 0x0301 {
        let versions = (0x0301..=maximum as u16)
            .map(rustls::ProtocolVersion::from)
            .collect::<Vec<_>>();
        cfg.enable_legacy_tls(&aerobox_crypto::randomized::LEGACY_TLS, &versions)?;
    }
    cfg.client_hello_layout = Some(ClientHelloLayout::Randomized);
    cfg.randomized_client_hello = Some(Arc::new(plan));
    Ok(cfg)
}
pub fn plan() -> serde_json::Value {
    // Independently executed uTLS corpus seed index 0, all structural fields.
    serde_json::json!({"minimum":771,"maximum":772,
        "suites":[4866,4865,4867,52392,49187,49195,49191,60,157,49200,49199,156,52393,53,49170,49161,10,49162],
        "signatures":[1537,1281,1025,1283,515,1027,2053,2054,513,2052],
        "groups":[29,23,24],"shares":[29,23],
        "extensions":[16,13,11,18,65281,51,5,35,10,43,0,17513,45,21]})
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
pub fn start(cfg: ClientConfig, name: &str) -> Result<(ClientConnection, Vec<u8>), rustls::Error> {
    let mut client = ClientConnection::new(Arc::new(cfg), name.to_owned().try_into().unwrap())?;
    let mut wire = vec![];
    while client.wants_write() {
        client.write_tls(&mut wire).unwrap();
    }
    Ok((client, wire))
}
