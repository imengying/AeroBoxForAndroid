//! TLS 1.0/1.1 RSA signatures: PKCS#1 v1.5 over raw MD5 || SHA-1.
//!
//! RFC 2246/4346 sections 4.7 and 7.4.8 require a 36-byte digest without a
//! DigestInfo prefix. RSA_PKCS1_SHA1 is a different signature format and must
//! never be used as an alias. These helpers are only for explicitly enabled
//! legacy handshake signatures, not X.509 certificate signature verification.
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rsa::{
    BigUint, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey, pkcs8::der::Decode, traits::PublicKeyParts,
};
use rustls::{CertificateError, Error, pki_types::CertificateDer};
use zeroize::Zeroizing;

/// Verify a prehashed TLS 1.0/1.1 RSA signature. Key size remains bounded to
/// 2048..8192 bits, matching the project's ordinary RSA signature provider.
pub fn verify_rsa_md5_sha1(
    key: &RsaPublicKey,
    digest: &[u8; 36],
    signature: &[u8],
) -> Result<(), Error> {
    check_size(key)?;
    if signature.len() != key.size() {
        return Err(bad_signature());
    }
    key.verify(raw_md5_sha1_padding(), digest, signature)
        .map_err(|_| bad_signature())
}

/// Sign an already-computed MD5 || SHA-1 handshake hash for legacy
/// CertificateVerify or ServerKeyExchange. The private key must be one already
/// validated by the signing-key loader. The private operation is RSA-blinded;
/// an entropy failure is returned before attempting it.
pub fn sign_rsa_md5_sha1(key: &RsaPrivateKey, digest: &[u8; 36]) -> Result<Vec<u8>, Error> {
    sign_with_seed_source(key, digest, |seed| {
        rand_core::OsRng
            .try_fill_bytes(seed)
            .map_err(|_| Error::FailedToGetRandomBytes)
    })
}

/// Verify the RSA signature on legacy ServerKeyExchange using the already
/// authenticated leaf certificate. `parts` must contain the exact encoded
/// client_random, server_random and key-exchange parameters, in that order.
///
/// This checks key type, size, digitalSignature usage, and the signature. The
/// caller still performs certificate-chain, validity-time and name validation.
pub fn verify_rsa_certificate(
    certificate: &CertificateDer<'_>,
    parts: &[&[u8]],
    signature: &[u8],
) -> Result<(), Error> {
    if certificate.as_ref().len() > 65536 {
        return Err(bad_encoding());
    }
    let (rest, cert) =
        x509_parser::parse_x509_certificate(certificate.as_ref()).map_err(|_| bad_encoding())?;
    if !rest.is_empty() {
        return Err(bad_encoding());
    }
    if cert
        .key_usage()
        .map_err(|_| bad_encoding())?
        .is_some_and(|usage| !usage.value.digital_signature())
    {
        return Err(Error::General(
            "legacy RSA signature requires digitalSignature key usage".into(),
        ));
    }
    let key = rsa_public_key_from_spki(cert.public_key().raw)?;
    verify_rsa_md5_sha1(&key, &crate::legacy_hash::digest(parts), signature)
}

/// Verify the SHA-1 ECDSA proof on a pre-TLS-1.2 handshake. Certificate-chain
/// authentication is performed by the caller. Named P-256/P-384/P-521 public
/// keys and canonical DER ECDSA signatures are accepted; other keys are not.
pub fn verify_ecdsa_sha1_certificate(
    certificate: &CertificateDer<'_>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use sha1::Digest;
    if certificate.as_ref().len() > 65536 || signature.len() > 141 {
        return Err(bad_encoding());
    }
    let (rest, cert) =
        x509_parser::parse_x509_certificate(certificate.as_ref()).map_err(|_| bad_encoding())?;
    if !rest.is_empty() {
        return Err(bad_encoding());
    }
    if cert
        .key_usage()
        .map_err(|_| bad_encoding())?
        .is_some_and(|usage| !usage.value.digital_signature())
    {
        return Err(Error::General(
            "legacy ECDSA signature requires digitalSignature key usage".into(),
        ));
    }
    let public = cert.public_key().raw;
    if public.len() > 160 {
        return Err(bad_encoding());
    }
    let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(public).map_err(|_| bad_encoding())?;
    const EC: rsa::pkcs8::ObjectIdentifier =
        rsa::pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const P256: rsa::pkcs8::ObjectIdentifier =
        rsa::pkcs8::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    const P384: rsa::pkcs8::ObjectIdentifier =
        rsa::pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.34");
    const P521: rsa::pkcs8::ObjectIdentifier =
        rsa::pkcs8::ObjectIdentifier::new_unwrap("1.3.132.0.35");
    if spki.algorithm.oid != EC {
        return Err(bad_encoding());
    }
    let curve = spki
        .algorithm
        .parameters_oid()
        .map_err(|_| bad_encoding())?;
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(bad_encoding)?;
    let digest = sha1::Sha1::digest(message);
    macro_rules! verify {
        ($curve:ident, $field:expr) => {{
            let key =
                $curve::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| bad_encoding())?;
            let signature =
                $curve::ecdsa::Signature::from_der(signature).map_err(|_| bad_signature())?;
            let mut prehash = [0u8; $field];
            prehash[$field - 20..].copy_from_slice(&digest);
            key.verify_prehash(&prehash, &signature)
                .map_err(|_| bad_signature())
        }};
    }
    match curve {
        P256 => verify!(p256, 32),
        P384 => verify!(p384, 48),
        P521 => verify!(p521, 66),
        _ => Err(bad_encoding()),
    }
}

/// Decode a bounded rsaEncryption SubjectPublicKeyInfo. PSS-only public keys
/// cannot authorize a PKCS#1 v1.5 signature; other algorithm IDs are rejected.
pub fn rsa_public_key_from_spki(der: &[u8]) -> Result<RsaPublicKey, Error> {
    if der.len() > 1120 {
        return Err(bad_encoding());
    }
    let spki = rsa::pkcs8::SubjectPublicKeyInfoRef::from_der(der).map_err(|_| bad_encoding())?;
    if spki.algorithm.oid != rsa::pkcs1::ALGORITHM_OID
        || spki.algorithm.parameters != Some(rsa::pkcs8::der::asn1::AnyRef::NULL)
    {
        return Err(bad_encoding());
    }
    rsa_public_key_from_pkcs1(
        spki.subject_public_key
            .as_bytes()
            .ok_or_else(bad_encoding)?,
    )
}

pub(crate) fn rsa_public_key_from_pkcs1(der: &[u8]) -> Result<RsaPublicKey, Error> {
    if der.len() > 1100 {
        return Err(bad_encoding());
    }
    let pkcs1 = rsa::pkcs1::RsaPublicKey::from_der(der).map_err(|_| bad_encoding())?;
    // Check the size before invoking any RSA arithmetic. Construction validates
    // modulus parity and bounds the public exponent to the rsa crate's limit.
    let n = BigUint::from_bytes_be(pkcs1.modulus.as_bytes());
    if !(2048..=8192).contains(&n.bits()) {
        return Err(Error::General(
            "legacy RSA requires a 2048..8192-bit key".into(),
        ));
    }
    RsaPublicKey::new_with_max_size(
        n,
        BigUint::from_bytes_be(pkcs1.public_exponent.as_bytes()),
        8192,
    )
    .map_err(|_| bad_encoding())
}

/// Standard TLS 1.2 RSA/SHA-1 has DigestInfo, unlike the raw legacy format.
pub(crate) fn rsa_sha1_padding() -> Pkcs1v15Sign {
    Pkcs1v15Sign {
        hash_len: Some(20),
        prefix: Box::new([
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
            0x14,
        ]),
    }
}

fn raw_md5_sha1_padding() -> Pkcs1v15Sign {
    // Restrict the unprefixed scheme to exactly the required digest length,
    // even though the public helpers already enforce it in their types.
    Pkcs1v15Sign {
        hash_len: Some(36),
        prefix: Box::new([]),
    }
}

fn check_size(key: &impl PublicKeyParts) -> Result<(), Error> {
    if !(2048..=8192).contains(&key.n().bits()) {
        return Err(Error::General(
            "legacy RSA requires a 2048..8192-bit key".into(),
        ));
    }
    Ok(())
}

fn bad_signature() -> Error {
    Error::InvalidCertificate(CertificateError::BadSignature)
}

fn bad_encoding() -> Error {
    Error::InvalidCertificate(CertificateError::BadEncoding)
}

fn sign_with_seed_source(
    key: &RsaPrivateKey,
    digest: &[u8; 36],
    source: impl FnOnce(&mut [u8; 32]) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    check_size(key)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    source(&mut seed)?;
    let mut rng = ChaCha20Rng::from_seed(*seed);
    // sign_with_rng blinds the private operation and checks the result against
    // the public key. The owned seed is wiped; rand_chacha 0.3 does not promise
    // erasure of its internal key/state or generated random buffers.
    key.sign_with_rng(&mut rng, raw_md5_sha1_padding(), digest)
        .map_err(|_| Error::General("legacy RSA signing failed".into()))
}

#[cfg(test)]
mod tests;
