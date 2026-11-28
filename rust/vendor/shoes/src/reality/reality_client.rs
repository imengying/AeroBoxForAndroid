use std::io;
use std::sync::Arc;

use rustls::pki_types::ServerName;

use super::CipherSuite;
use super::reality_rustls_adapter::{client_authentication, provider};
use crate::crypto::{TlsConnection, tls_error};

#[derive(Clone)]
pub struct RealityClientConfig {
    pub mldsa65_verify: Option<super::reality_mldsa::VerifyKey>,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub server_name: ServerName<'static>,
    pub cipher_suites: Vec<CipherSuite>,
}

impl RealityClientConfig {
    pub fn create_connection(self) -> io::Result<TlsConnection> {
        self.create_connection_with_alpn(Vec::new(), false)
    }

    pub fn create_connection_with_alpn(
        self,
        alpn: Vec<String>,
        browser: bool,
    ) -> io::Result<TlsConnection> {
        self.create_connection_with_profile(
            alpn,
            browser.then_some(crate::config::tls::TlsClientFingerprint::Chrome133),
        )
    }

    pub fn create_connection_with_profile(
        self,
        alpn: Vec<String>,
        profile: Option<crate::config::tls::TlsClientFingerprint>,
    ) -> io::Result<TlsConnection> {
        let crypto = if let Some(profile) = profile {
            validate_profile_suites(&self.cipher_suites, profile)?;
            crate::rustls_config_util::browser::profile_provider_for_stream(profile, true)?
        } else {
            provider(&self.cipher_suites)
        };
        let schemes = crypto.signature_verification_algorithms.supported_schemes();
        self.create_connection_inner(
            crypto,
            schemes,
            Arc::new(rustls::NoKeyLog {}),
            alpn,
            profile,
        )
    }

    pub(super) fn create_connection_with_options(
        self,
        crypto: rustls::crypto::CryptoProvider,
        schemes: Vec<rustls::SignatureScheme>,
        key_log: Arc<dyn rustls::KeyLog>,
    ) -> io::Result<TlsConnection> {
        self.create_connection_inner(crypto, schemes, key_log, Vec::new(), None)
    }

    fn create_connection_inner(
        self,
        crypto: rustls::crypto::CryptoProvider,
        schemes: Vec<rustls::SignatureScheme>,
        key_log: Arc<dyn rustls::KeyLog>,
        alpn: Vec<String>,
        profile: Option<crate::config::tls::TlsClientFingerprint>,
    ) -> io::Result<TlsConnection> {
        let (hooks, verifier) = if profile.is_some() {
            super::reality_rustls_adapter::browser_client_authentication(&self, schemes)
        } else {
            client_authentication(&self, schemes)
        };
        let verifier =
            crate::rustls_config_util::browser::profile_verifier(Arc::new(verifier), profile);
        let mut tls = rustls::ClientConfig::builder_with_details(
            Arc::new(crypto),
            crate::clock::time_provider(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
        tls.alpn_protocols = if alpn.is_empty()
            && profile != Some(crate::config::tls::TlsClientFingerprint::Randomized)
        {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            alpn.into_iter().map(String::into_bytes).collect()
        };
        tls.cert_decompressors.clear();
        tls.key_log = key_log;
        if let Some(profile) = profile {
            crate::rustls_config_util::browser::configure_profile(&mut tls, profile, true, true)?;
        }
        let connection =
            rustls::ClientConnection::new_reality(Arc::new(tls), self.server_name, Box::new(hooks))
                .map_err(tls_error)?;
        Ok(TlsConnection::new_reality(connection))
    }
}

pub(crate) fn validate_profile_suites(
    suites: &[CipherSuite],
    profile: crate::config::tls::TlsClientFingerprint,
) -> io::Result<()> {
    if profile == crate::config::tls::TlsClientFingerprint::Randomized {
        return crate::rustls_config_util::browser::randomized::validate_reality_suites(suites);
    }
    let expected = if profile == crate::config::tls::TlsClientFingerprint::Firefox120 {
        [0x1301, 0x1303, 0x1302]
    } else {
        [0x1301, 0x1302, 0x1303]
    };
    if !suites.is_empty() && !suites.iter().map(|suite| suite.id()).eq(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY browser profile conflicts with the explicit cipher suite policy",
        ));
    }
    Ok(())
}
