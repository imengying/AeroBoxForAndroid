//! TLS policy for the fixed Android Naive/Cronet transport.
use crate::config::tls::TlsClientOptions;
use rustls::{
    ClientConfig, NamedGroup, SignatureScheme,
    client::{ApplicationSettings, ApplicationSettingsCodepoint, ClientHelloLayout},
    crypto::WebPkiSupportedAlgorithms,
};
use std::{
    io,
    sync::{Arc, OnceLock},
};

const SIGNATURES: &[u16] = &[
    0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

fn algorithms() -> WebPkiSupportedAlgorithms {
    static ALGORITHMS: OnceLock<WebPkiSupportedAlgorithms> = OnceLock::new();
    *ALGORITHMS.get_or_init(|| {
        let ordinary = aerobox_crypto::provider().signature_verification_algorithms;
        let post_quantum = aerobox_crypto::mldsa::ALGORITHMS;
        let mut all = ordinary.all.to_vec();
        all.extend_from_slice(post_quantum.all);
        let mapping = SIGNATURES
            .iter()
            .map(|id| {
                let scheme = SignatureScheme::from(*id);
                *post_quantum
                    .mapping
                    .iter()
                    .chain(ordinary.mapping.iter())
                    .find(|(candidate, _)| *candidate == scheme)
                    .expect("compiled Naive signature verification algorithm")
            })
            .collect::<Vec<_>>();
        WebPkiSupportedAlgorithms {
            all: Box::leak(all.into_boxed_slice()),
            mapping: Box::leak(mapping.into_boxed_slice()),
        }
    })
}

pub(crate) fn aes_hardware() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

fn provider(quic: bool) -> rustls::crypto::CryptoProvider {
    let mut provider = super::browser::provider();
    provider.signature_verification_algorithms = if quic {
        // QUICHE uses the nine BoringSSL defaults, without TCP Cronet's
        // additional ML-DSA preferences. Reuse implemented signature mappings;
        // this does not enable old TLS versions or SHA1 certificate chains.
        aerobox_crypto::legacy_provider::provider().signature_verification_algorithms
    } else {
        algorithms()
    };
    provider
}

pub(crate) fn create_config(options: &TlsClientOptions, quic: bool) -> io::Result<ClientConfig> {
    if options.disable_sni
        || options.min_version.is_some()
        || options.max_version.is_some()
        || !options.cipher_suites.is_empty()
        || options.fingerprint.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Naive requires its own TLS version, cipher and signature policy",
        ));
    }
    let provider = Arc::new(provider(quic));
    let roots = super::tls_options::roots(options)?;
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .map_err(io::Error::other)?;
    let verifier = super::tls_options::ech_verifier(verifier.clone(), Some(verifier));
    let versions: &[&rustls::SupportedProtocolVersion] = if quic || options.ech.is_some() {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let mut config = ClientConfig::builder_with_details(provider, crate::clock::time_provider())
        .with_protocol_versions(versions)
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = if quic {
        vec![b"h3".to_vec()]
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };
    config.initial_key_share_groups = vec![NamedGroup::X25519MLKEM768, NamedGroup::X25519];
    config.cert_compressors.clear();
    config.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR];
    config.enable_early_data = false;
    config.enable_tls12_renegotiation = !quic;
    config.reverify_on_resume = true;
    config.application_settings = Some(
        ApplicationSettings::new(
            ApplicationSettingsCodepoint::Chrome,
            vec![(if quic { b"h3".to_vec() } else { b"h2".to_vec() }, vec![])],
        )
        .map_err(io::Error::other)?,
    );
    config.client_hello_layout = Some(if quic {
        ClientHelloLayout::Naive150Quic {
            aes_hardware: aes_hardware(),
        }
    } else {
        ClientHelloLayout::Naive150 {
            aes_hardware: aes_hardware(),
        }
    });
    if let Some(ech) = &options.ech {
        let mut ech = ech.clone();
        ech.embed()?;
        if let Some(ech) = ech.static_config()? {
            config.set_ech_config(ech).map_err(io::Error::other)?;
        }
    }
    Ok(config)
}
