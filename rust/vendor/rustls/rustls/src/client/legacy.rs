//! Explicit client-only TLS 1.0/1.1 support for pinned compatibility profiles.
//!
//! The ordinary protocol-version list, cipher providers, and server state
//! machine do not enable these versions. A caller supplies a separate provider
//! for the old PRF, transcript hash, records, and handshake signatures.
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use pki_types::CertificateDer;

use super::{ClientConfig, Resumption, Tls12Resumption};
use crate::common_state::Protocol;
use crate::crypto::KeyExchangeAlgorithm;
use crate::msgs::enums::ClientCertificateType;
use crate::msgs::handshake::DistinguishedName;
use crate::sign::{CertifiedKey, Signer};
use crate::sync::Arc;
use crate::verify::HandshakeSignatureValid;
use crate::{
    CipherSuite, Error, ProtocolVersion, SignatureAlgorithm, SignatureScheme, Tls12CipherSuite,
};

/// Cryptographic capabilities for explicitly opted-in legacy TLS clients.
///
/// Certificate chain/name/validity checks still run through the configured
/// `ServerCertVerifier`. This provider must independently verify the old
/// ServerKeyExchange proof using that authenticated leaf certificate.
pub trait LegacyTlsProvider: Debug + Send + Sync {
    /// Select a genuine TLS 1.0/1.1 implementation of an offered cipher suite.
    /// Return `None` for unsupported suites or versions, including TLS 1.2-only
    /// AEAD suites. The result has the same cipher ID as the input, but uses
    /// the old PRF/transcript hash and version-specific record factory.
    fn cipher_suite(
        &self,
        suite: CipherSuite,
        version: ProtocolVersion,
    ) -> Option<&'static Tls12CipherSuite>;

    /// Verify the exact signed message, not a precomputed digest. RSA uses
    /// raw PKCS#1 v1.5 over MD5 || SHA-1; ECDSA uses SHA-1.
    fn verify_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        algorithm: SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<HandshakeSignatureValid, Error>;
}

#[derive(Clone, Debug)]
pub(super) struct LegacyTlsOptions {
    pub(super) provider: &'static dyn LegacyTlsProvider,
    tls10: bool,
    tls11: bool,
}

impl LegacyTlsOptions {
    pub(super) fn supports(&self, version: ProtocolVersion) -> bool {
        match version {
            ProtocolVersion::TLSv1_0 => self.tls10,
            ProtocolVersion::TLSv1_1 => self.tls11,
            _ => false,
        }
    }
}

impl ClientConfig {
    /// Opt this client into a version list containing TLS 1.0 or 1.1.
    ///
    /// TLS 1.2/1.3 may be selected alongside the old versions. TLS 1.3 keeps its
    /// real key shares, cipher implementations, and optional ALPS negotiation.
    /// QUIC, ECH, REALITY, early data, and secret extraction cannot use this mode.
    /// Session resumption is disabled, matching the pinned browser wrappers.
    /// The separate `enable_tls12_renegotiation` option permits one securely
    /// bound renegotiation when TLS 1.0, 1.1, or 1.2 is selected.
    /// This method never changes certificate authentication or the suite list.
    pub fn enable_legacy_tls(
        &mut self,
        provider: &'static dyn LegacyTlsProvider,
        versions: &[ProtocolVersion],
    ) -> Result<(), Error> {
        use ProtocolVersion::{TLSv1_0, TLSv1_1, TLSv1_2, TLSv1_3};
        if versions.is_empty()
            || versions
                .iter()
                .any(|v| !matches!(v, TLSv1_0 | TLSv1_1 | TLSv1_2 | TLSv1_3))
            || !versions.iter().any(|v| matches!(v, TLSv1_0 | TLSv1_1))
            || self.ech_mode.is_some()
            || (self.application_settings.is_some() && !versions.contains(&TLSv1_3))
            || self.enable_secret_extraction
        {
            return Err(invalid_config());
        }
        for &version in versions.iter().filter(|v| is_legacy(**v)) {
            if !self
                .provider
                .cipher_suites
                .iter()
                .any(|suite| provider.cipher_suite(suite.suite(), version).is_some())
            {
                return Err(invalid_config());
            }
        }
        let modern: Vec<_> = [&crate::versions::TLS13, &crate::versions::TLS12]
            .into_iter()
            .filter(|v| versions.contains(&v.version))
            .collect();
        for version in &modern {
            if !self.provider.cipher_suites.iter().any(|suite| {
                suite.version() == *version && suite.usable_for_protocol(Protocol::Tcp)
            }) || (version.version == TLSv1_3
                && !self
                    .provider
                    .kx_groups
                    .iter()
                    .any(|group| group.usable_for_version(TLSv1_3)))
            {
                return Err(invalid_config());
            }
        }
        self.versions = crate::versions::EnabledVersions::new(&modern);
        self.legacy_tls = Some(LegacyTlsOptions {
            provider,
            tls10: versions.contains(&TLSv1_0),
            tls11: versions.contains(&TLSv1_1),
        });
        self.resumption = Resumption::disabled();
        self.enable_early_data = false;
        if !versions.contains(&TLSv1_3) {
            self.initial_key_share_groups.clear();
        }
        Ok(())
    }

    pub(super) fn legacy_enabled(&self) -> bool {
        self.legacy_tls.is_some()
    }

    pub(super) fn validate_legacy(&self, protocol: Protocol, reality: bool) -> Result<(), Error> {
        if self.legacy_tls.is_none() {
            return Ok(());
        }
        if protocol != Protocol::Tcp
            || reality
            || self.ech_mode.is_some()
            || self.enable_early_data
            || self.enable_secret_extraction
            || (!self.versions.contains(ProtocolVersion::TLSv1_3)
                && (self.application_settings.is_some()
                    || !self.initial_key_share_groups.is_empty()))
            || self.resumption.tls12_resumption != Tls12Resumption::Disabled
        {
            return Err(invalid_config());
        }
        Ok(())
    }

    pub(super) fn legacy_client_version(&self) -> ProtocolVersion {
        if self.versions.contains(ProtocolVersion::TLSv1_2)
            || self.versions.contains(ProtocolVersion::TLSv1_3)
        {
            ProtocolVersion::TLSv1_2
        } else if self.legacy_tls.as_ref().is_some_and(|v| v.tls11) {
            ProtocolVersion::TLSv1_1
        } else {
            ProtocolVersion::TLSv1_0
        }
    }
}

pub(super) fn is_legacy(version: ProtocolVersion) -> bool {
    matches!(version, ProtocolVersion::TLSv1_0 | ProtocolVersion::TLSv1_1)
}

pub(super) fn invalid_config() -> Error {
    Error::General("legacy TLS client configuration conflicts with required capabilities".into())
}

pub(super) fn signature_algorithm(suite: &Tls12CipherSuite) -> Result<SignatureAlgorithm, Error> {
    if suite.kx == KeyExchangeAlgorithm::RSA {
        return Ok(SignatureAlgorithm::RSA);
    }
    suite
        .sign
        .first()
        .and_then(SignatureScheme::algorithm)
        .ok_or_else(invalid_config)
}

pub(super) fn resolve_client_auth(
    config: &ClientConfig,
    issuers: &[DistinguishedName],
    types: &[ClientCertificateType],
) -> Option<(Arc<CertifiedKey>, Box<dyn Signer>)> {
    let names = issuers.iter().map(|p| p.as_ref()).collect::<Vec<_>>();
    let mut schemes = Vec::new();
    if types.contains(&ClientCertificateType::RSASign) {
        schemes.push(SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy);
    }
    if types.contains(&ClientCertificateType::ECDSASign) {
        schemes.push(SignatureScheme::ECDSA_SHA1_Legacy);
    }
    let cert = config.client_auth_cert_resolver.resolve(&names, &schemes)?;
    let signer = cert.key.choose_legacy_scheme()?;
    schemes.contains(&signer.scheme()).then_some((cert, signer))
}
