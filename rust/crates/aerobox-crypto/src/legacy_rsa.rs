//! Opt-in TLS 1.0/1.1/1.2 static RSA key transport for compatibility profiles.
//! Only public-key encryption is implemented; TLS servers cannot negotiate it.
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rsa::{BigUint, RsaPublicKey, pkcs8::der::Decode};
use rustls::{CipherSuite, Error, SupportedCipherSuite, Tls12CipherSuite, crypto::SharedSecret};
use zeroize::Zeroizing;

pub static TLS_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
);
pub static TLS_RSA_WITH_AES_256_GCM_SHA384: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    &super::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
);
pub static TLS_RSA_WITH_AES_128_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
    &super::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
);
pub static TLS_RSA_WITH_AES_256_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    &super::legacy_cbc::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
);
const fn suite(id: CipherSuite, base: &'static Tls12CipherSuite) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: id,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: base.prf_provider,
        kx: rustls::crypto::KeyExchangeAlgorithm::RSA,
        sign: base.sign,
        aead_alg: base.aead_alg,
    }
}
/// Client-only compatibility suites; the ordinary provider excludes them.
pub fn suites() -> [SupportedCipherSuite; 4] {
    [
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_256_GCM_SHA384),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_128_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_256_CBC_SHA),
    ]
}
pub(crate) fn encrypt(
    certificate: &rustls::pki_types::CertificateDer<'_>,
    version: rustls::ProtocolVersion,
) -> Result<(Vec<u8>, SharedSecret), Error> {
    encrypt_with_seed_source(certificate, version, |seed| {
        rand_core::OsRng
            .try_fill_bytes(seed)
            .map_err(|_| Error::FailedToGetRandomBytes)
    })
}

fn encrypt_with_seed_source(
    certificate: &rustls::pki_types::CertificateDer<'_>,
    version: rustls::ProtocolVersion,
    seed_source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<(Vec<u8>, SharedSecret), Error> {
    // This is the ClientHello's highest supported version, not the selected
    // ServerHello version (RFC 2246/4346/5246 RSA rollback detection).
    if !matches!(
        version,
        rustls::ProtocolVersion::TLSv1_0
            | rustls::ProtocolVersion::TLSv1_1
            | rustls::ProtocolVersion::TLSv1_2
    ) {
        return Err(Error::General(
            "static RSA requires a TLS 1.0..1.2 ClientHello version".into(),
        ));
    }
    let bad_encoding = || Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
    let (rest, cert) =
        x509_parser::parse_x509_certificate(certificate.as_ref()).map_err(|_| bad_encoding())?;
    if !rest.is_empty() {
        return Err(bad_encoding());
    }
    if cert
        .key_usage()
        .map_err(|_| bad_encoding())?
        .is_some_and(|usage| !usage.value.key_encipherment())
    {
        return Err(Error::General(
            "RSA key transport requires certificate keyEncipherment".into(),
        ));
    }
    let key = decode_public_key(cert.public_key().raw)?;
    // RSA's PKCS#1 padding API calls the infallible RngCore::fill_bytes,
    // including when it replaces zero padding bytes. Seed a local CSPRNG with
    // one fallible OS call so an entropy error can never panic inside padding.
    // This seed and the premaster buffer are wiped on drop. rand_chacha 0.3
    // does not expose zeroization of its internal key/state or buffered output;
    // do not claim those internal copies are erased when this RNG is dropped.
    let mut seed = Zeroizing::new([0u8; 32]);
    seed_source(&mut seed)?;
    let mut rng = ChaCha20Rng::from_seed(*seed);
    let mut premaster = Zeroizing::new([0u8; 48]);
    rng.fill_bytes(premaster.as_mut());
    premaster[..2].copy_from_slice(&u16::from(version).to_be_bytes());
    let ciphertext = key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, premaster.as_ref())
        .map_err(|_| Error::EncryptError)?;
    Ok((ciphertext, SharedSecret::from(premaster.as_slice())))
}

fn decode_public_key(der: &[u8]) -> Result<RsaPublicKey, Error> {
    let bad_encoding = || Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
    // An 8192-bit RSA key with the permitted <=33-bit exponent needs less
    // than 1120 DER bytes. Reject oversized input before allocating big ints.
    if der.len() > 1120 {
        return Err(bad_encoding());
    }
    let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(der).map_err(|_| bad_encoding())?;
    // Keep the same strict rsaEncryption + NULL algorithm check as the RSA
    // crate's SPKI decoder. In particular, a PSS-only signing key cannot be
    // used for PKCS#1 encryption. Its generic decoder otherwise imposes a
    // 4096-bit maximum, so decode n/e here with our explicit 8192-bit bound.
    if spki.algorithm.oid != rsa::pkcs1::ALGORITHM_OID
        || spki.algorithm.parameters != Some(rsa::pkcs8::der::asn1::AnyRef::NULL)
    {
        return Err(bad_encoding());
    }
    let key = rsa::pkcs1::RsaPublicKey::from_der(
        spki.subject_public_key
            .as_bytes()
            .ok_or_else(bad_encoding)?,
    )
    .map_err(|_| bad_encoding())?;
    let modulus = BigUint::from_bytes_be(key.modulus.as_bytes());
    if !(2048..=8192).contains(&modulus.bits()) {
        return Err(Error::General(
            "RSA key transport requires a 2048..8192-bit key".into(),
        ));
    }
    RsaPublicKey::new_with_max_size(
        modulus,
        BigUint::from_bytes_be(key.public_exponent.as_bytes()),
        8192,
    )
    .map_err(|_| bad_encoding())
}

#[cfg(test)]
mod tests;
