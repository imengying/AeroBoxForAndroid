//! Exercise the same file-loading and semantic compilation stages as the host.
//! Factory-only fixtures deliberately skip these stages and cannot cover them.
use super::{list, pem};
use crate::config::{
    self, ResolvedClientConfig, ResolvedClientHop, ResolvedClientProxyConfig, ResolvedConfig,
    ResolvedRuleActionConfig, ValidatedConfigs,
};
use serde_json::{Value, json};
use std::{io, sync::Arc};

fn client(quic: bool, options: Value) -> Value {
    let tls = json!({
        "sni_hostname":"secret.example",
        "verify":true,
        "options":options,
    });
    if quic {
        json!({
            "address":"127.0.0.1:443",
            "transport":"quic",
            "quic_settings":tls,
            "protocol":{"type":"noop"},
        })
    } else {
        let mut tls = tls;
        tls["type"] = "tls".into();
        tls["protocol"] = json!({"type":"noop"});
        json!({"address":"127.0.0.1:443","protocol":tls})
    }
}

fn document(client: Value) -> Value {
    json!([{
        "address":"127.0.0.1:0",
        "protocol":{"type":"socks"},
        "rules":[{"conditions":{"any_destination":true},"client_chain":client}],
    }])
}

async fn compile(client: Value) -> io::Result<ValidatedConfigs> {
    let configs = serde_json::from_value(document(client)).map_err(io::Error::other)?;
    let (configs, _) = config::convert_cert_paths(configs).await?;
    config::compile_configs(configs).await
}

fn compiled_client(validated: &ValidatedConfigs) -> &ResolvedClientConfig {
    let ResolvedConfig::Server(server) = &validated.configs[0] else {
        panic!("expected SOCKS server");
    };
    let ResolvedRuleActionConfig::Allow { client_chains, .. } =
        &server.rules.iter().next().unwrap().action
    else {
        panic!("expected allow rule");
    };
    let ResolvedClientHop::Single(client) = client_chains
        .iter()
        .next()
        .unwrap()
        .hops
        .iter()
        .next()
        .unwrap()
    else {
        panic!("expected single client hop");
    };
    client
}

fn tls_options(client: &ResolvedClientConfig) -> &crate::config::tls::TlsClientOptions {
    if let Some(quic) = &client.quic_settings {
        &quic.options
    } else if let ResolvedClientProxyConfig::Tls(tls) = &client.protocol {
        &tls.options
    } else {
        panic!("expected TLS or QUIC client")
    }
}

#[tokio::test]
async fn compiler_embeds_ca_and_ech_files_before_connections_are_created() {
    let cert = rcgen::generate_simple_self_signed(vec!["public.test".into()]).unwrap();
    let certificate_pem = cert.cert.pem();
    let ech_pem = pem(&list());
    for quic in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("ca.pem");
        let ech_path = directory.path().join("ech.pem");
        std::fs::write(&ca_path, &certificate_pem).unwrap();
        std::fs::write(&ech_path, &ech_pem).unwrap();
        let input = client(
            quic,
            json!({
                "root_certificates":[ca_path],
                "ech":{"config_path":ech_path},
            }),
        );
        // Exercise the public application check as well as inspect its compiler output.
        assert!(
            crate::embedding::EmbeddedCore::check_document(
                serde_json::from_value(document(input.clone())).unwrap(),
            )
            .await
            .unwrap()
            .is_empty()
        );
        let validated = compile(input).await.unwrap();
        let client = compiled_client(&validated);
        let options = tls_options(client);
        assert_eq!(options.root_certificates, [certificate_pem.clone()]);
        let ech = options.ech.as_ref().unwrap();
        assert_eq!(ech.config.as_deref(), Some(ech_pem.as_str()));
        assert!(ech.config_path.is_none());

        // Deleting the originals must not turn runtime construction into file I/O.
        std::fs::remove_file(ca_path).unwrap();
        std::fs::remove_file(ech_path).unwrap();
        let mut tls = crate::rustls_config_util::try_create_client_config_with_options(
            true,
            vec![],
            vec![],
            true,
            None,
            quic,
            &Default::default(),
            options,
        )
        .unwrap();
        tls.set_ech_config(ech.static_config().unwrap().unwrap())
            .unwrap();
        rustls::ClientConnection::new(Arc::new(tls), "secret.example".try_into().unwrap()).unwrap();
    }
}

#[tokio::test]
async fn compiler_rejects_missing_and_malformed_ech_or_ca_files() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pem");
    let bad_ech = directory.path().join("bad-ech.pem");
    let bad_ca = directory.path().join("bad-ca.pem");
    std::fs::write(
        &bad_ech,
        "-----BEGIN ECH CONFIGS-----\nAA==\n-----END ECH CONFIGS-----\n",
    )
    .unwrap();
    std::fs::write(&bad_ca, "not a PEM certificate").unwrap();
    for quic in [false, true] {
        for (name, options) in [
            ("missing ECH", json!({"ech":{"config_path":missing}})),
            ("malformed ECH", json!({"ech":{"config_path":bad_ech}})),
            (
                "missing CA",
                json!({"root_certificates":[missing],"ech":{"config":pem(&list())}}),
            ),
            (
                "malformed CA",
                json!({"root_certificates":[bad_ca],"ech":{"config":pem(&list())}}),
            ),
        ] {
            let input = client(quic, options);
            assert!(compile(input.clone()).await.is_err(), "quic={quic}: {name}");
            assert!(
                crate::embedding::EmbeddedCore::check_document(
                    serde_json::from_value(document(input)).unwrap(),
                )
                .await
                .is_err(),
                "application check accepted quic={quic}: {name}"
            );
        }
    }
}

#[tokio::test]
async fn compiler_rejects_ech_without_tls13_or_with_sni_disabled() {
    for quic in [false, true] {
        for (name, options) in [
            (
                "TLS 1.2",
                json!({"max_version":"1.2","ech":{"config":pem(&list())}}),
            ),
            (
                "disabled SNI",
                json!({"disable_sni":true,"ech":{"config":pem(&list())}}),
            ),
            (
                "invalid ECH DNS identity",
                json!({"ech":{"query_server_name":"127.0.0.1"}}),
            ),
        ] {
            let input = client(quic, options);
            assert!(compile(input.clone()).await.is_err(), "quic={quic}: {name}");
            assert!(
                crate::embedding::EmbeddedCore::check_document(
                    serde_json::from_value(document(input)).unwrap(),
                )
                .await
                .is_err(),
                "application check accepted quic={quic}: {name}"
            );
        }
    }
}

#[tokio::test]
async fn compiler_rejects_disabled_ip_and_missing_ech_server_identity() {
    for quic in [false, true] {
        for identity in [Some(Value::Null), Some(json!("127.0.0.1")), None] {
            let mut input = client(quic, json!({"ech":{"config":pem(&list())}}));
            let tls = if quic {
                &mut input["quic_settings"]
            } else {
                &mut input["protocol"]
            };
            if let Some(identity) = &identity {
                tls["sni_hostname"] = identity.clone();
            } else {
                tls.as_object_mut().unwrap().remove("sni_hostname");
            }
            let error = match compile(input.clone()).await {
                Ok(_) => panic!("compiler accepted quic={quic}, SNI={identity:?}"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("ECH"), "{error}");
            assert!(
                crate::embedding::EmbeddedCore::check_document(
                    serde_json::from_value(document(input)).unwrap(),
                )
                .await
                .is_err(),
                "application check accepted quic={quic}, SNI={identity:?}"
            );
        }
    }
}

#[tokio::test]
async fn compiler_allows_ech_identity_inherited_from_a_hostname_endpoint() {
    for quic in [false, true] {
        let mut input = client(quic, json!({"ech":{"config":pem(&list())}}));
        input["address"] = "secret.example:443".into();
        let tls = if quic {
            &mut input["quic_settings"]
        } else {
            &mut input["protocol"]
        };
        tls.as_object_mut().unwrap().remove("sni_hostname");
        compile(input.clone()).await.unwrap();
        assert!(
            crate::embedding::EmbeddedCore::check_document(
                serde_json::from_value(document(input)).unwrap(),
            )
            .await
            .unwrap()
            .is_empty()
        );
    }
}
