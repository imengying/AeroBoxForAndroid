//! Real production configuration and asynchronous stream, against independent Go TLS.
use super::*;
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod random;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/aerobox-crypto/tests/fixtures"
);
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn peer(variable: &str, args: &[String]) -> (Peer, tokio::net::TcpStream) {
    let mut child = Command::new(std::env::var_os(variable).expect(variable))
        .args(args)
        .args(["-fixtures", FIXTURES])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    let socket =
        tokio::net::TcpStream::connect(("127.0.0.1", ready["port"].as_u64().unwrap() as u16))
            .await
            .unwrap();
    (Peer(child), socket)
}
#[derive(Debug)]
struct FixedTime;
impl rustls::time_provider::TimeProvider for FixedTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(1893456000),
        ))
    }
}
fn production_client(tls13: bool, mutual: bool, alpn: Vec<String>) -> rustls::ClientConfig {
    production_profile(TlsClientFingerprint::Chrome133, tls13, mutual, alpn)
}
fn production_profile(
    profile: TlsClientFingerprint,
    tls13: bool,
    mutual: bool,
    alpn: Vec<String>,
) -> rustls::ClientConfig {
    use base64::Engine;
    let certificate = std::fs::read(format!("{FIXTURES}/rsa-cert.der")).unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&certificate).unwrap();
    let pin = base64::engine::general_purpose::STANDARD.encode(aerobox_primitives::digest::digest(
        &aerobox_primitives::digest::SHA256,
        cert.public_key().raw,
    ));
    fn pem(kind: &str, bytes: &[u8]) -> String {
        let body = base64::engine::general_purpose::STANDARD.encode(bytes);
        format!("-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n")
    }
    let cert_pem = pem("CERTIFICATE", &certificate);
    let options = TlsClientOptions {
        root_certificates: vec![cert_pem.clone()],
        certificate_public_key_sha256: vec![pin],
        fingerprint: Some(profile),
        ..Default::default()
    };
    let credentials = mutual.then(|| {
        (
            pem(
                "PRIVATE KEY",
                &std::fs::read(format!("{FIXTURES}/rsa-key.der")).unwrap(),
            )
            .into_bytes(),
            cert_pem.into_bytes(),
        )
    });
    let mut config = try_create_client_config_with_options(
        true,
        vec![],
        alpn,
        true,
        credentials,
        tls13,
        &Default::default(),
        &options,
    )
    .unwrap();
    config.time_provider = Arc::new(FixedTime);
    config.max_fragment_size = Some(137);
    config
}
async fn echo(stream: &mut CryptoTlsStream<tokio::net::TcpStream>) {
    let sent: Vec<_> = (0..65537).map(|n| (n % 251) as u8).collect();
    let mut output = vec![0; sent.len()];
    stream.write_all(&sent).await.unwrap();
    stream.flush().await.unwrap();
    stream.read_exact(&mut output).await.unwrap();
    assert_eq!(sent, output);
    stream.shutdown().await.unwrap();
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
}
#[tokio::test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER"]
async fn production_chrome_tls13_authentication_groups_and_compression() {
    for group in [29, 23, 24, 4588] {
        for tls13 in [false, true] {
            tokio::time::timeout(Duration::from_secs(15), async {
                let args = [
                    "-group".into(),
                    group.to_string(),
                    "-alps".into(),
                    "17613".into(),
                    "-brotli".into(),
                    "-mutual".into(),
                    "-expect-shares".into(),
                    "4588,29".into(),
                ];
                let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
                let connection = rustls::ClientConnection::new(
                    Arc::new(production_client(tls13, true, vec!["h2".into()])),
                    "localhost".try_into().unwrap(),
                )
                .unwrap();
                let mut stream = CryptoTlsStream::handshake(
                    socket,
                    TlsConnection::new(connection),
                    TlsReadMode::Stream,
                    &[],
                )
                .await
                .unwrap();
                assert_eq!(
                    stream.negotiated_group(),
                    Some(NamedGroup::from(group as u16))
                );
                echo(&mut stream).await;
            })
            .await
            .unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires AEROBOX_TLS12_RENEGOTIATION_PEER"]
async fn production_chrome_tls12_reauthenticates_and_rejects_bad_finished() {
    for suite in [0xc02f, 0xc013, 0x009c, 0x002f] {
        for mode in ["valid", "fragment", "bad-finished"] {
            tokio::time::timeout(Duration::from_secs(15), async {
                let args = [
                    "-suite".into(),
                    suite.to_string(),
                    "-mode".into(),
                    mode.into(),
                    "-mutual".into(),
                ];
                let (_peer, socket) = peer("AEROBOX_TLS12_RENEGOTIATION_PEER", &args).await;
                let connection = rustls::ClientConnection::new(
                    Arc::new(production_client(false, true, vec![])),
                    "localhost".try_into().unwrap(),
                )
                .unwrap();
                let mut stream = CryptoTlsStream::handshake(
                    socket,
                    TlsConnection::new(connection),
                    TlsReadMode::PreserveRecords,
                    &[],
                )
                .await
                .unwrap();
                let mut initial = [0; 39];
                stream.read_exact(&mut initial).await.unwrap();
                assert_eq!(&initial[..7], b"initial");
                stream.write_all(b"ack").await.unwrap();
                stream.flush().await.unwrap();
                let mut renewed = [0; 39];
                let result = stream.read_exact(&mut renewed).await;
                if mode == "bad-finished" {
                    assert!(result.is_err());
                    return;
                }
                result.unwrap();
                assert_eq!(&renewed[..7], b"renewed");
                assert_ne!(&initial[7..], &renewed[7..]);
                echo(&mut stream).await;
            })
            .await
            .unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER"]
async fn production_chrome_reality_checks_independent_authentication() {
    for mode in ["valid", "bad-hmac", "bad-signature", "bad-short-id"] {
        tokio::time::timeout(Duration::from_secs(15), async {
            let args = [
                "-group".into(),
                "29".into(),
                "-reality".into(),
                mode.into(),
                "-reality-browser".into(),
                "-alps".into(),
                "17613".into(),
            ];
            let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
            let public = aerobox_primitives::agreement::PrivateKey::from_private_key(
                &aerobox_primitives::agreement::X25519,
                &[42; 32],
            )
            .unwrap()
            .compute_public_key()
            .unwrap();
            let config = crate::reality::RealityClientConfig {
                mldsa65_verify: None,
                public_key: public.as_ref().try_into().unwrap(),
                short_id: [1; 8],
                server_name: "cover.test".try_into().unwrap(),
                cipher_suites: vec![],
            };
            let connection = config
                .create_connection_with_alpn(vec!["h2".into()], true)
                .unwrap();
            let result =
                CryptoTlsStream::handshake(socket, connection, TlsReadMode::Stream, &[]).await;
            if mode != "valid" {
                assert!(result.is_err(), "{mode}");
                return;
            }
            let mut stream = result.unwrap();
            assert!(stream.is_reality());
            echo(&mut stream).await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER"]
async fn production_edge_qq_tls13_authentication_and_reality() {
    for profile in [TlsClientFingerprint::Edge85, TlsClientFingerprint::Qq11_1] {
        let alps = if profile == TlsClientFingerprint::Qq11_1 {
            "17513"
        } else {
            "0"
        };
        for group in [29, 23, 24] {
            for tls13 in [false, true] {
                tokio::time::timeout(Duration::from_secs(15), async {
                    let args = [
                        format!("-group={group}"),
                        format!("-alps={alps}"),
                        "-brotli".into(),
                        "-mutual".into(),
                        "-expect-shares=29".into(),
                    ];
                    let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
                    let connection = rustls::ClientConnection::new(
                        Arc::new(production_profile(profile, tls13, true, vec!["h2".into()])),
                        "localhost".try_into().unwrap(),
                    )
                    .unwrap();
                    let mut stream = CryptoTlsStream::handshake(
                        socket,
                        TlsConnection::new(connection),
                        if tls13 {
                            TlsReadMode::PreserveRecords
                        } else {
                            TlsReadMode::Stream
                        },
                        &[],
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        stream.negotiated_group(),
                        Some(NamedGroup::from(group as u16))
                    );
                    echo(&mut stream).await;
                })
                .await
                .unwrap();
            }
        }
        for mode in ["valid", "bad-hmac", "bad-signature", "bad-short-id"] {
            tokio::time::timeout(Duration::from_secs(15), async {
                let args = [
                    "-group=29".into(),
                    format!("-reality={mode}"),
                    "-reality-browser".into(),
                    format!("-alps={alps}"),
                ];
                let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
                let public = aerobox_primitives::agreement::PrivateKey::from_private_key(
                    &aerobox_primitives::agreement::X25519,
                    &[42; 32],
                )
                .unwrap()
                .compute_public_key()
                .unwrap();
                let config = crate::reality::RealityClientConfig {
                    mldsa65_verify: None,
                    public_key: public.as_ref().try_into().unwrap(),
                    short_id: [1; 8],
                    server_name: "cover.test".try_into().unwrap(),
                    cipher_suites: vec![],
                };
                let connection = config
                    .create_connection_with_profile(vec!["h2".into()], Some(profile))
                    .unwrap();
                let result =
                    CryptoTlsStream::handshake(socket, connection, TlsReadMode::Stream, &[]).await;
                if mode != "valid" {
                    assert!(result.is_err(), "{profile:?}: {mode}");
                    return;
                }
                let mut stream = result.unwrap();
                assert!(stream.is_reality());
                echo(&mut stream).await;
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_LEGACY_RENEGOTIATION_PEER"]
async fn production_edge_qq_legacy_records_and_authenticated_renegotiation() {
    for profile in [TlsClientFingerprint::Edge85, TlsClientFingerprint::Qq11_1] {
        for version in ["1.0", "1.1", "1.2"] {
            for suite in [0xc013, 0x002f] {
                for mode in ["valid", "inflight-fragment", "bad-finished"] {
                    tokio::time::timeout(Duration::from_secs(20), async {
                        let args = [
                            format!("-version={version}"),
                            format!("-suite={suite}"),
                            format!("-mode={mode}"),
                            "-mutual".into(),
                        ];
                        let (_peer, socket) =
                            peer("AEROBOX_LEGACY_RENEGOTIATION_PEER", &args).await;
                        let connection = rustls::ClientConnection::new(
                            Arc::new(production_profile(profile, false, true, vec![])),
                            "localhost".try_into().unwrap(),
                        )
                        .unwrap();
                        let mut stream = CryptoTlsStream::handshake(
                            socket,
                            TlsConnection::new(connection),
                            TlsReadMode::Stream,
                            &[],
                        )
                        .await
                        .unwrap();
                        let mut initial = [0; 39];
                        stream.read_exact(&mut initial).await.unwrap();
                        assert_eq!(&initial[..7], b"initial");
                        stream.write_all(b"ack").await.unwrap();
                        stream.flush().await.unwrap();
                        if mode.starts_with("inflight") {
                            let mut old = [0; 8];
                            stream.read_exact(&mut old).await.unwrap();
                            assert_eq!(&old, b"old-data");
                        }
                        let mut renewed = [0; 39];
                        let result = stream.read_exact(&mut renewed).await;
                        if mode == "bad-finished" {
                            assert!(result.is_err());
                            return;
                        }
                        result.unwrap();
                        assert_eq!(&renewed[..7], b"renewed");
                        assert_ne!(&initial[7..], &renewed[7..]);
                        echo(&mut stream).await;
                    })
                    .await
                    .unwrap();
                }
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires extended AEROBOX_TLS_PROFILE_PEER"]
async fn production_android_safari_ios_tls13_and_reality_authenticate_with_exact_profiles() {
    for profile in [TlsClientFingerprint::Safari16, TlsClientFingerprint::Ios14] {
        for group in [29u16, 23, 24, 25] {
            for tls13 in [false, true] {
                tokio::time::timeout(Duration::from_secs(20), async {
                    let mut args = vec![
                        format!("-group={group}"),
                        "-alps=0".into(),
                        "-brotli=false".into(),
                        "-expect-shares=29".into(),
                    ];
                    if profile == TlsClientFingerprint::Safari16 {
                        args.push("-zlib".into());
                    }
                    let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
                    let connection = rustls::ClientConnection::new(
                        Arc::new(production_profile(profile, tls13, false, vec!["h2".into()])),
                        "localhost".try_into().unwrap(),
                    )
                    .unwrap();
                    let mut stream = CryptoTlsStream::handshake(
                        socket,
                        TlsConnection::new(connection),
                        if tls13 {
                            TlsReadMode::PreserveRecords
                        } else {
                            TlsReadMode::Stream
                        },
                        &[],
                    )
                    .await
                    .unwrap();
                    assert_eq!(stream.negotiated_group(), Some(NamedGroup::from(group)));
                    echo(&mut stream).await;
                })
                .await
                .unwrap();
            }
        }
        for mode in ["valid", "bad-hmac", "bad-signature", "bad-short-id"] {
            tokio::time::timeout(Duration::from_secs(20), async {
                let args = vec![
                    "-group=29".into(),
                    format!("-reality={mode}"),
                    "-reality-browser".into(),
                    format!(
                        "-reality-profile={}",
                        if profile == TlsClientFingerprint::Safari16 {
                            "safari"
                        } else {
                            "ios"
                        }
                    ),
                    "-alps=0".into(),
                    "-brotli=false".into(),
                    "-expect-shares=29".into(),
                ];
                let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
                let public = aerobox_primitives::agreement::PrivateKey::from_private_key(
                    &aerobox_primitives::agreement::X25519,
                    &[42; 32],
                )
                .unwrap()
                .compute_public_key()
                .unwrap();
                let config = crate::reality::RealityClientConfig {
                    mldsa65_verify: None,
                    public_key: public.as_ref().try_into().unwrap(),
                    short_id: [1; 8],
                    server_name: "cover.test".try_into().unwrap(),
                    cipher_suites: vec![],
                };
                let connection = config
                    .create_connection_with_profile(vec!["h2".into()], Some(profile))
                    .unwrap();
                let result =
                    CryptoTlsStream::handshake(socket, connection, TlsReadMode::Stream, &[]).await;
                if mode != "valid" {
                    assert!(result.is_err(), "{profile:?}: {mode}");
                    return;
                }
                let mut stream = result.unwrap();
                assert!(stream.is_reality());
                echo(&mut stream).await;
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires extended AEROBOX_TLS_PROFILE_PEER"]
async fn production_firefox_tls13_all_groups_and_reality_keep_independent_authentication() {
    for profile in [TlsClientFingerprint::Firefox120] {
        for group in [29u16, 23, 24, 25, 256, 257] {
            for tls13 in [false, true] {
                tokio::time::timeout(Duration::from_secs(20), async {
                    let args = vec![
                        format!("-group={group}"),
                        "-alps=0".into(),
                        "-brotli=false".into(),
                        "-expect-shares=29,23".into(),
                    ];
                    let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
                    let connection = rustls::ClientConnection::new(
                        Arc::new(production_profile(profile, tls13, false, vec!["h2".into()])),
                        "localhost".try_into().unwrap(),
                    )
                    .unwrap();
                    let mut stream = CryptoTlsStream::handshake(
                        socket,
                        TlsConnection::new(connection),
                        if tls13 {
                            TlsReadMode::PreserveRecords
                        } else {
                            TlsReadMode::Stream
                        },
                        &[],
                    )
                    .await
                    .unwrap();
                    assert_eq!(stream.negotiated_group(), Some(NamedGroup::from(group)));
                    echo(&mut stream).await;
                })
                .await
                .unwrap();
            }
        }
        for (group, mode) in [
            (29, "valid"),
            (23, "valid"),
            (29, "bad-hmac"),
            (29, "bad-signature"),
            (29, "bad-short-id"),
        ] {
            tokio::time::timeout(Duration::from_secs(20), async {
                let args = vec![
                    format!("-group={group}"),
                    format!("-reality={mode}"),
                    "-reality-browser".into(),
                    "-reality-profile=firefox".into(),
                    "-alps=0".into(),
                    "-brotli=false".into(),
                    "-expect-shares=29,23".into(),
                ];
                let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
                let public = aerobox_primitives::agreement::PrivateKey::from_private_key(
                    &aerobox_primitives::agreement::X25519,
                    &[42; 32],
                )
                .unwrap()
                .compute_public_key()
                .unwrap();
                let config = crate::reality::RealityClientConfig {
                    mldsa65_verify: None,
                    public_key: public.as_ref().try_into().unwrap(),
                    short_id: [1; 8],
                    server_name: "cover.test".try_into().unwrap(),
                    cipher_suites: vec![],
                };
                let connection = config
                    .create_connection_with_profile(vec!["h2".into()], Some(profile))
                    .unwrap();
                let result =
                    CryptoTlsStream::handshake(socket, connection, TlsReadMode::Stream, &[]).await;
                if mode != "valid" {
                    assert!(result.is_err(), "{profile:?}: {mode}");
                    return;
                }
                let mut stream = result.unwrap();
                assert!(stream.is_reality());
                echo(&mut stream).await;
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER"]
async fn production_firefox_reality_cannot_delegate_or_relax_ordinary_signature_offers() {
    for reality in [true, false] {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut args = vec![
                "-group=29".into(),
                "-alps=0".into(),
                "-brotli=false".into(),
                "-expect-shares=29,23".into(),
            ];
            if reality {
                args.extend([
                    "-reality=valid".into(),
                    "-reality-browser".into(),
                    "-reality-profile=firefox".into(),
                    "-reality-delegated".into(),
                ]);
            } else {
                args.push("-unadvertised-signature".into());
            }
            let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
            let connection = if reality {
                let public = aerobox_primitives::agreement::PrivateKey::from_private_key(
                    &aerobox_primitives::agreement::X25519,
                    &[42; 32],
                )
                .unwrap()
                .compute_public_key()
                .unwrap();
                crate::reality::RealityClientConfig {
                    mldsa65_verify: None,
                    public_key: public.as_ref().try_into().unwrap(),
                    short_id: [1; 8],
                    server_name: "cover.test".try_into().unwrap(),
                    cipher_suites: vec![],
                }
                .create_connection_with_profile(
                    vec!["h2".into()],
                    Some(TlsClientFingerprint::Firefox120),
                )
                .unwrap()
            } else {
                use base64::Engine;
                let der = std::fs::read(format!("{FIXTURES}/rsa-cert.der")).unwrap();
                // Trust the issuer of the strong Ed25519 leaf, so failure
                // specifically proves the actual Firefox signature offer.
                let options = TlsClientOptions {
                    fingerprint: Some(TlsClientFingerprint::Firefox120),
                    root_certificates: vec![format!(
                        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                        base64::engine::general_purpose::STANDARD.encode(der)
                    )],
                    ..Default::default()
                };
                let mut config = try_create_client_config_with_options(
                    true,
                    vec![],
                    vec!["h2".into()],
                    true,
                    None,
                    true,
                    &Default::default(),
                    &options,
                )
                .unwrap();
                config.time_provider = Arc::new(FixedTime);
                TlsConnection::new(
                    rustls::ClientConnection::new(
                        Arc::new(config),
                        "localhost".try_into().unwrap(),
                    )
                    .unwrap(),
                )
            };
            let error = match CryptoTlsStream::handshake(
                socket,
                connection,
                TlsReadMode::Stream,
                &[],
            )
            .await
            {
                Err(error) => error,
                Ok(_) => panic!("accepted incompatible Firefox authentication path"),
            };
            let message = error.to_string();
            if reality {
                assert!(
                    message.contains("REALITY requires its original authenticated certificate key"),
                    "{message}"
                );
            } else {
                assert!(
                    message.contains("SignedHandshakeWithUnadvertisedSigScheme"),
                    "{message}"
                );
            }
        })
        .await
        .unwrap();
    }
}
