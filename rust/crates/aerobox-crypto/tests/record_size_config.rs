//! Public opt-in and wire advertisement for RFC8449 receive capacity.
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::sync::Arc;

fn config(tls13: bool) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(include_bytes!("fixtures/rsa-cert.der").as_slice().into())
        .unwrap();
    let versions = if tls13 {
        vec![&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        vec![&rustls::version::TLS12]
    };
    ClientConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
        .with_protocol_versions(&versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}
fn extension(config: ClientConfig) -> Option<Vec<u8>> {
    let mut client =
        ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut wire = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut wire).unwrap();
    }
    let mut hello = Vec::new();
    let mut records = wire.as_slice();
    while !records.is_empty() {
        let length = usize::from(u16::from_be_bytes([records[3], records[4]]));
        assert_eq!(records[0], 22);
        hello.extend_from_slice(&records[5..5 + length]);
        records = &records[5 + length..];
    }
    assert_eq!(hello[0], 1);
    assert_eq!(
        4 + (usize::from(hello[1]) << 16) + (usize::from(hello[2]) << 8) + usize::from(hello[3]),
        hello.len()
    );
    let mut pos = 38;
    pos += 1 + usize::from(hello[pos]);
    let length = usize::from(u16::from_be_bytes([hello[pos], hello[pos + 1]]));
    pos += 2 + length;
    pos += 1 + usize::from(hello[pos]);
    let total = usize::from(u16::from_be_bytes([hello[pos], hello[pos + 1]]));
    pos += 2;
    assert_eq!(pos + total, hello.len());
    let mut found = None;
    while pos < hello.len() {
        let id = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let length = usize::from(u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]));
        pos += 4;
        if id == 28 {
            assert!(found.is_none());
            found = Some(hello[pos..pos + length].to_vec());
        }
        pos += length;
    }
    found
}
#[test]
fn advertised_receive_capacity_is_independent_of_local_write_fragment_size() {
    for tls13 in [false, true] {
        assert!(extension(config(tls13)).is_none());
        for fragment in [None, Some(37), Some(512)] {
            let mut config = config(tls13);
            config.advertise_record_size_limit = true;
            config.max_fragment_size = fragment;
            assert_eq!(
                extension(config),
                Some(if tls13 { vec![0x40, 1] } else { vec![0x40, 0] })
            );
        }
    }
}
#[test]
fn opt_in_refuses_early_data_secret_extraction_and_existing_fixed_layouts() {
    for policy in 0..3 {
        let mut config = config(true);
        config.advertise_record_size_limit = true;
        match policy {
            0 => config.enable_early_data = true,
            1 => config.enable_secret_extraction = true,
            _ => config.client_hello_layout = Some(rustls::client::ClientHelloLayout::Chrome133),
        }
        assert!(ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).is_err());
    }
}
#[test]
fn quic_rejects_the_tls_record_extension_before_a_connection_exists() {
    let mut config = config(true);
    config.advertise_record_size_limit = true;
    assert!(
        rustls::quic::ClientConnection::new(
            Arc::new(config),
            rustls::quic::Version::V1,
            "localhost".try_into().unwrap(),
            vec![]
        )
        .is_err()
    );
}
