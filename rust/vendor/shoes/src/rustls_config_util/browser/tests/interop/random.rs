//! Exercise the `random` configuration boundary through the production stream.
//! Fixed-profile algorithm matrices remain in the existing profile tests.
use super::*;
use serde_json::json;

fn resolved() -> TlsClientFingerprint {
    let options: TlsClientOptions =
        serde_json::from_value(json!({"fingerprint":"random"})).unwrap();
    options.fingerprint.unwrap()
}

fn wire_options(profile: TlsClientFingerprint, reality: bool) -> Vec<String> {
    let (name, shares, alps, brotli) = match profile {
        TlsClientFingerprint::Chrome133 => (
            "chrome",
            if reality { "29" } else { "4588,29" },
            "17613",
            true,
        ),
        TlsClientFingerprint::Firefox120 => ("firefox", "29,23", "0", false),
        TlsClientFingerprint::Edge85 => ("edge", "29", "0", true),
        TlsClientFingerprint::Safari16 => ("safari", "29", "0", false),
        TlsClientFingerprint::Ios14 => ("ios", "29", "0", false),
        other => panic!("not in the fixed random pool: {other:?}"),
    };
    let mut args = vec![
        "-group=29".into(),
        format!("-expect-shares={shares}"),
        format!("-alps={alps}"),
        format!("-brotli={brotli}"),
    ];
    if profile == TlsClientFingerprint::Safari16 && !reality {
        args.push("-zlib".into());
    }
    if reality {
        args.push("-reality-browser".into());
        args.push(format!("-reality-profile={name}"));
    }
    args
}

#[tokio::test]
#[ignore = "requires AEROBOX_TLS_PROFILE_PEER"]
async fn production_random_resolves_once_for_tls_and_reality_without_failure_fallback() {
    let profile = resolved();
    assert_eq!(
        profile,
        TlsClientFingerprint::from(aerobox_fingerprint::random_profile().unwrap())
    );
    for tls13_only in [false, true] {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut args = wire_options(profile, false);
            args.push("-mutual".into());
            let (_peer, socket) = peer("AEROBOX_TLS_PROFILE_PEER", &args).await;
            let config = production_profile(resolved(), tls13_only, true, vec!["h2".into()]);
            let connection =
                rustls::ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap())
                    .unwrap();
            let mut stream = CryptoTlsStream::handshake(
                socket,
                TlsConnection::new(connection),
                TlsReadMode::Stream,
                &[],
            )
            .await
            .unwrap();
            assert_eq!(stream.negotiated_group(), Some(NamedGroup::X25519));
            echo(&mut stream).await;
        })
        .await
        .unwrap();
        assert_eq!(resolved(), profile);
    }
    for mode in ["bad-hmac", "valid"] {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut args = wire_options(profile, true);
            args.push(format!("-reality={mode}"));
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
                .create_connection_with_profile(vec!["h2".into()], Some(resolved()))
                .unwrap();
            let result =
                CryptoTlsStream::handshake(socket, connection, TlsReadMode::Stream, &[]).await;
            if mode == "bad-hmac" {
                assert!(result.is_err());
            } else {
                let mut stream = result.unwrap();
                assert!(stream.is_reality());
                echo(&mut stream).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(resolved(), profile);
    }
}
