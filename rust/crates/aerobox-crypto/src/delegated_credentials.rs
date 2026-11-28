//! Explicit RFC 9345 server delegation support for the Android Firefox profile.
//!
//! Wrap the application's existing certificate verifier, then set
//! `ClientConfig::enable_delegated_credentials`. The original chain, hostname,
//! OCSP and pin policy runs before the delegated credential path. This wrapper
//! does not make an insecure inner verifier secure. Keep it outermost so that
//! the original policy is retained. Rustls rejects real ECH/early data and
//! disables ticket restoration and storage while this opt-in is enabled.
//! Firefox REALITY cover may retain the DC offer, but REALITY authenticates its
//! original certificate directly and rejects received delegated credentials.
use std::sync::Arc;

use rustls::{
    DigitallySignedStruct, Error, SignatureScheme,
    client::{
        DelegatedCredential,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};

/// Exact DC offer in the pinned Firefox 120 template. The legacy final value
/// can appear on the wire but is always rejected if selected in TLS 1.3.
pub const FIREFOX_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_SHA1_Legacy,
];

/// A verifier preserving an existing certificate policy while adding real DC
/// validation. Ordinary TLS signature methods continue to use the inner policy.
#[derive(Debug)]
pub struct Verifier {
    inner: Arc<dyn ServerCertVerifier>,
    schemes: Vec<SignatureScheme>,
}

impl Verifier {
    /// Add the pinned Firefox DC offer to an existing certificate policy.
    pub fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            inner,
            schemes: FIREFOX_SCHEMES.to_vec(),
        }
    }

    /// Choose an explicit nonempty DC offer using the implemented EC/Ed25519
    /// schemes. ECDSA/SHA1 is allowed only as a legacy wire value beside at least
    /// one usable scheme; it never becomes a valid TLS1.3 signature.
    pub fn with_schemes(
        inner: Arc<dyn ServerCertVerifier>,
        schemes: Vec<SignatureScheme>,
    ) -> Result<Self, Error> {
        if schemes.is_empty()
            || schemes.len() > 32
            || !schemes.iter().any(|scheme| usable(*scheme))
            || schemes.iter().enumerate().any(|(i, scheme)| {
                (!usable(*scheme) && *scheme != SignatureScheme::ECDSA_SHA1_Legacy)
                    || schemes[..i].contains(scheme)
            })
        {
            return Err(invalid("unsupported delegated credential advertisement"));
        }
        Ok(Self { inner, schemes })
    }
}

fn invalid(message: &'static str) -> Error {
    Error::General(message.into())
}

fn usable(scheme: SignatureScheme) -> bool {
    matches!(
        scheme,
        SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512
            | SignatureScheme::ED25519
    )
}

fn issuer_usable(scheme: SignatureScheme) -> bool {
    usable(scheme)
        || matches!(
            scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
        )
}

fn validate_certificate(
    certificate: &CertificateDer<'_>,
    offset: u32,
    now: UnixTime,
) -> Result<(), Error> {
    let (remaining, cert) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(|_| invalid("invalid delegation certificate encoding"))?;
    if !remaining.is_empty() {
        return Err(invalid("trailing delegation certificate data"));
    }
    // 1.3.6.1.4.1.44363.44, DER OID content. Unknown noncritical extensions are
    // deliberately ignored by WebPKI, so verify presence, encoding and uniqueness here.
    const DELEGATION_USAGE: &[u8] = &[0x2b, 6, 1, 4, 1, 0x82, 0xda, 0x4b, 0x2c];
    let mut found = false;
    for extension in cert.extensions() {
        if extension.oid.as_bytes() == DELEGATION_USAGE {
            if found || extension.critical || extension.value != [5, 0] {
                return Err(invalid("invalid DelegationUsage extension"));
            }
            found = true;
        }
    }
    if !found {
        return Err(invalid("missing DelegationUsage extension"));
    }
    if !cert
        .key_usage()
        .map_err(|_| invalid("invalid delegation KeyUsage"))?
        .is_some_and(|usage| usage.value.digital_signature())
    {
        return Err(invalid("delegation certificate requires digitalSignature"));
    }
    if cert
        .basic_constraints()
        .map_err(|_| invalid("invalid delegation BasicConstraints"))?
        .is_some_and(|constraints| constraints.value.ca)
    {
        return Err(invalid("delegation requires an end-entity certificate"));
    }
    // Use a wider signed domain: certificate times can precede the Unix epoch,
    // while UnixTime uses u64. No narrowing cast or offset addition can wrap.
    let now = i128::from(now.as_secs());
    let not_before = i128::from(cert.validity().not_before.timestamp());
    let not_after = i128::from(cert.validity().not_after.timestamp());
    let expiry = not_before + i128::from(offset);
    if now < not_before || now > expiry || expiry > now + 7 * 24 * 60 * 60 || expiry >= not_after {
        return Err(invalid("invalid delegated credential validity"));
    }
    Ok(())
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner.verify_server_cert(cert, chain, name, ocsp, now)
    }

    fn verify_ech_rejection_cert(
        &self,
        cert: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_ech_rejection_cert(cert, chain, name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn supported_delegated_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }

    fn verify_tls13_delegated_credential(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        credential: &DelegatedCredential,
        dss: &DigitallySignedStruct,
        now: UnixTime,
    ) -> Result<HandshakeSignatureValid, Error> {
        let expected = credential.expected_verify_scheme();
        if !usable(expected)
            || expected != dss.scheme
            || !self.schemes.contains(&expected)
            || !issuer_usable(credential.signature().scheme)
            || !self
                .inner
                .supported_verify_schemes()
                .contains(&credential.signature().scheme)
        {
            return Err(invalid("invalid delegated credential signature scheme"));
        }
        validate_certificate(cert, credential.valid_time(), now)?;
        let issuer_message = credential.server_signature_input(cert);
        // The DC implementation itself enforces its cryptographic policy even
        // if a custom inner verifier skips ordinary TLS signature validation.
        rustls::crypto::verify_tls13_signature(
            &issuer_message,
            cert,
            credential.signature(),
            &crate::verify::algorithms(),
        )
        .map_err(|_| invalid("invalid delegated credential issuer signature"))?;
        self.inner
            .verify_tls13_signature(&issuer_message, cert, credential.signature())
            .map_err(|_| invalid("invalid delegated credential issuer signature"))?;
        // This uses the strict TLS1.3 first mapping: ECDSA curve/hash pairs must
        // match the DER SPKI, and rsaEncryption cannot masquerade as an EC key.
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            credential.public_key(),
            dss,
            &crate::verify::algorithms(),
        )
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[cfg(test)]
mod tests;
