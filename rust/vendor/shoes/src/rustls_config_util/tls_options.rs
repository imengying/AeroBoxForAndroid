use std::{io, sync::Arc};

use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use subtle::ConstantTimeEq;

use crate::config::tls::{TlsClientFingerprint, TlsClientOptions, TlsVersion};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(super) fn provider(
    groups: &crate::config::TlsKeyExchangeGroups,
    options: &TlsClientOptions,
) -> io::Result<Arc<rustls::crypto::CryptoProvider>> {
    let mut provider = if options.fingerprint.is_some() {
        super::browser::validate_policy(groups, options)?;
        super::browser::profile_provider(options.fingerprint.unwrap())?
    } else {
        (*super::crypto_provider_with_groups(groups)).clone()
    };
    if options.fingerprint.is_none()
        && options
            .min_version
            .is_some_and(|version| version < TlsVersion::V12)
    {
        // Go's ordinary client uses ECDHE AES-CBC when an explicitly lowered
        // minimum permits TLS 1.0/1.1. Keep static RSA, 3DES and RC4 out of the
        // default offer, and leave clients using the normal minimum unchanged.
        provider
            .cipher_suites
            .extend(aerobox_crypto::legacy_cbc::suites());
    }
    if !options.cipher_suites.is_empty() {
        let mut selected = Vec::with_capacity(options.cipher_suites.len());
        for name in &options.cipher_suites {
            // rustls uses a TLS13_ prefix internally; configuration accepts
            // the IANA names used by Android/sing-box as well as that spelling.
            let canonical = match name.as_str() {
                "TLS_AES_128_GCM_SHA256" => "TLS13_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384" => "TLS13_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256" => "TLS13_CHACHA20_POLY1305_SHA256",
                other => other,
            };
            let suite = provider
                .cipher_suites
                .iter()
                .copied()
                .chain(aerobox_crypto::legacy_cbc::suites())
                .chain(aerobox_crypto::legacy_rsa::suites())
                .find(|suite| suite.suite().as_str() == Some(canonical))
                .ok_or_else(|| {
                    invalid(format!("unsupported pure Rust TLS cipher suite: {name}"))
                })?;
            if selected
                .iter()
                .any(|s: &rustls::SupportedCipherSuite| s.suite() == suite.suite())
            {
                return Err(invalid(format!("duplicate TLS cipher suite: {name}")));
            }
            selected.push(suite);
        }
        if options.fingerprint.is_some()
            && !selected
                .iter()
                .map(|suite| u16::from(suite.suite()))
                .eq(super::browser::ciphers(options.fingerprint.unwrap())?
                    .iter()
                    .copied())
        {
            return Err(invalid(
                "browser profile conflicts with the explicit cipher suite policy",
            ));
        }
        if options.fingerprint.is_some() {
            provider.cipher_suites = selected;
        } else {
            // sing-box passes CipherSuites to Go's tls.Config: it controls
            // TLS <= 1.2 only. Even a list containing TLS 1.3 names must not
            // remove TLS 1.3 or narrow its fixed suite set.
            provider
                .cipher_suites
                .retain(|suite| suite.tls13().is_some());
            provider
                .cipher_suites
                .extend(selected.into_iter().filter(|suite| suite.tls13().is_none()));
        }
    }
    Ok(Arc::new(provider))
}

pub(super) fn versions(
    options: &TlsClientOptions,
    tls13_only: bool,
) -> io::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    if options.fingerprint == Some(TlsClientFingerprint::Randomized) {
        return super::browser::randomized::versions(tls13_only);
    }
    if matches!(
        options.fingerprint,
        Some(TlsClientFingerprint::Android11 | TlsClientFingerprint::Browser360_7_5)
    ) {
        if tls13_only {
            return Err(invalid(
                "this legacy browser profile is incompatible with TLS1.3-only transports, Vision, or ECH",
            ));
        }
        return Ok(vec![&rustls::version::TLS12]); // legacy versions are explicitly enabled after building the client
    }
    if matches!(
        options.fingerprint,
        Some(
            TlsClientFingerprint::Edge85
                | TlsClientFingerprint::Qq11_1
                | TlsClientFingerprint::Safari16
                | TlsClientFingerprint::Ios14
        )
    ) {
        return Ok(if tls13_only {
            vec![&rustls::version::TLS13]
        } else {
            vec![&rustls::version::TLS13, &rustls::version::TLS12]
        });
    }
    let min = options.min_version.unwrap_or(TlsVersion::V12);
    let max = options.max_version.unwrap_or(TlsVersion::V13);
    if min > max {
        return Err(invalid("TLS min_version exceeds max_version"));
    }
    if tls13_only && max < TlsVersion::V13 {
        return Err(invalid("this transport or key exchange requires TLS 1.3"));
    }
    let mut versions = Vec::new();
    if max == TlsVersion::V13 {
        versions.push(&rustls::version::TLS13);
    }
    if min <= TlsVersion::V12 && max >= TlsVersion::V12 && !tls13_only {
        versions.push(&rustls::version::TLS12);
    }
    if versions.is_empty() {
        // The builder only accepts modern versions. configure_legacy_versions
        // replaces this temporary version list before the config can escape.
        versions.push(&rustls::version::TLS12);
    }
    Ok(versions)
}

pub(super) fn configure_legacy_versions(
    config: &mut rustls::ClientConfig,
    options: &TlsClientOptions,
    tls13_only: bool,
) -> io::Result<()> {
    if options.fingerprint.is_some() || tls13_only {
        return Ok(());
    }
    let min = options.min_version.unwrap_or(TlsVersion::V12);
    let max = options.max_version.unwrap_or(TlsVersion::V13);
    if min >= TlsVersion::V12 {
        return Ok(());
    }
    use rustls::ProtocolVersion::{TLSv1_0, TLSv1_1, TLSv1_2, TLSv1_3};
    use rustls::client::LegacyTlsProvider;

    let legacy = &aerobox_crypto::legacy_provider::LEGACY_TLS;
    let versions: Vec<_> = [
        (TlsVersion::V13, TLSv1_3),
        (TlsVersion::V12, TLSv1_2),
        (TlsVersion::V11, TLSv1_1),
        (TlsVersion::V10, TLSv1_0),
    ]
    .into_iter()
    .filter(|(version, _)| *version >= min && *version <= max)
    .filter(|(version, protocol)| {
        config.crypto_provider().cipher_suites.iter().any(|suite| {
            if *version < TlsVersion::V12 {
                legacy.cipher_suite(suite.suite(), *protocol).is_some()
            } else {
                suite.version().version == *protocol
            }
        })
    })
    .map(|(_, protocol)| protocol)
    .collect();
    if versions.is_empty() {
        return Err(invalid(
            "no cipher suite supports the configured TLS version range",
        ));
    }
    if versions
        .iter()
        .any(|version| matches!(version, TLSv1_0 | TLSv1_1))
    {
        // This enables only the old PRF, record and handshake-signature paths.
        // It does not select a browser layout or replace the PKI/pin verifier.
        config
            .enable_legacy_tls(legacy, &versions)
            .map_err(io::Error::other)?;
    }
    Ok(())
}

pub(super) fn roots(options: &TlsClientOptions) -> io::Result<Arc<rustls::RootCertStore>> {
    if options.root_certificates.is_empty() {
        return Ok(super::get_root_cert_store());
    }
    let mut store = rustls::RootCertStore::empty();
    for pem in &options.root_certificates {
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert =
                cert.map_err(|error| invalid(format!("invalid TLS trust certificate: {error}")))?;
            store
                .add(cert)
                .map_err(|error| invalid(format!("invalid TLS trust certificate: {error}")))?;
            count += 1;
        }
        if count == 0 {
            return Err(invalid("TLS trust root contains no PEM certificate"));
        }
    }
    Ok(Arc::new(store))
}

pub(super) fn pin_verifier(
    inner: Arc<dyn ServerCertVerifier>,
    options: &TlsClientOptions,
) -> io::Result<Arc<dyn ServerCertVerifier>> {
    if options.certificate_public_key_sha256.is_empty() {
        return Ok(inner);
    }
    let pins = options
        .certificate_public_key_sha256
        .iter()
        .map(|pin| {
            let decoded = STANDARD
                .decode(pin)
                .map_err(|_| invalid("certificate_public_key_sha256 must use base64"))?;
            <[u8; 32]>::try_from(decoded)
                .map_err(|_| invalid("certificate_public_key_sha256 must contain 32 bytes"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Arc::new(PinnedVerifier { inner, pins }))
}

#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, name, ocsp, now)?;
        let (remaining, cert) =
            x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        if !remaining.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::BadEncoding,
            ));
        }
        let hash = aerobox_primitives::digest::digest(
            &aerobox_primitives::digest::SHA256,
            cert.public_key().raw,
        );
        let matches = self
            .pins
            .iter()
            .fold(subtle::Choice::from(0), |found, pin| {
                found | pin.as_slice().ct_eq(hash.as_ref())
            });
        if bool::from(matches) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "TLS certificate public key pin mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests;

pub(super) fn ech_verifier(
    inner: Arc<dyn ServerCertVerifier>,
    public: Option<Arc<rustls::client::WebPkiServerVerifier>>,
) -> Arc<dyn ServerCertVerifier> {
    match public {
        Some(public) => Arc::new(EchVerifier { inner, public }),
        None => inner,
    }
}
#[derive(Debug)]
struct EchVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    public: Arc<rustls::client::WebPkiServerVerifier>,
}
impl ServerCertVerifier for EchVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(cert, chain, name, ocsp, now)
    }
    fn verify_ech_rejection_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.public.verify_server_cert(cert, chain, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
