//! RustCrypto signing adapter; no native crypto provider is selected.
use crate::{Error, PublicKeyData, SignatureAlgorithm, SigningKey};
use p256::ecdsa::signature::Signer;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{pkcs1::EncodeRsaPublicKey, signature::SignatureEncoding};

enum Material {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    Rsa(rsa::RsaPrivateKey),
}

/// A certificate signing key implemented entirely with RustCrypto.
pub struct KeyPair {
    key: Material,
    alg: &'static SignatureAlgorithm,
    public: Vec<u8>,
    serialized_der: Vec<u8>,
}
impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair").field("algorithm", &self.alg).finish_non_exhaustive()
    }
}
impl KeyPair {
    /// Generate a P-256 key.
    pub fn generate() -> Result<Self, Error> { Self::generate_for(&crate::PKCS_ECDSA_P256_SHA256) }
    /// Generate a key for the requested algorithm.
    pub fn generate_for(alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
        let mut rng = rand_core::OsRng;
        let key = if alg == &crate::PKCS_ECDSA_P256_SHA256 {
            Material::P256(p256::ecdsa::SigningKey::random(&mut rng))
        } else if alg == &crate::PKCS_ECDSA_P384_SHA384 {
            Material::P384(p384::ecdsa::SigningKey::random(&mut rng))
        } else if alg == &crate::PKCS_ED25519 {
            Material::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng))
        } else if [ &crate::PKCS_RSA_SHA256, &crate::PKCS_RSA_SHA384, &crate::PKCS_RSA_SHA512 ].contains(&alg) {
            Material::Rsa(rsa::RsaPrivateKey::new(&mut rng, 2048).map_err(|_| Error::KeyGenerationUnavailable)?)
        } else { return Err(Error::UnsupportedSignatureAlgorithm); };
        Self::from_material(key, alg)
    }
    fn from_material(key: Material, alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
        let (public, der) = match &key {
            Material::P256(k) => (k.verifying_key().to_encoded_point(false).as_bytes().to_vec(), k.to_pkcs8_der()),
            Material::P384(k) => (k.verifying_key().to_encoded_point(false).as_bytes().to_vec(), k.to_pkcs8_der()),
            Material::Ed25519(k) => (k.verifying_key().to_bytes().to_vec(), k.to_pkcs8_der()),
            Material::Rsa(k) => (k.to_public_key().to_pkcs1_der().map_err(|_| Error::CouldNotParseKeyPair)?.as_bytes().to_vec(), k.to_pkcs8_der()),
        };
        Ok(Self { key, alg, public, serialized_der: der.map_err(|_| Error::CouldNotParseKeyPair)?.as_bytes().to_vec() })
    }
    /// Read a PKCS#8 PEM private key.
    #[cfg(feature = "pem")]
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let pem = pem::parse(pem).map_err(|e| Error::PemError(e.to_string()))?;
        Self::try_from(pem.contents())
    }
    /// Read a PKCS#8 key using an explicitly requested signing algorithm.
    pub fn from_pkcs8_der_and_sign_algo(der: &pki_types::PrivatePkcs8KeyDer<'_>, alg: &'static SignatureAlgorithm) -> Result<Self, Error> {
        let mut key = Self::try_from(der.secret_pkcs8_der())?;
        let rsa = matches!(key.key, Material::Rsa(_)) && [&crate::PKCS_RSA_SHA256, &crate::PKCS_RSA_SHA384, &crate::PKCS_RSA_SHA512].contains(&alg);
        if key.alg != alg && !rsa { return Err(Error::UnsupportedSignatureAlgorithm); }
        key.alg = alg;
        Ok(key)
    }
    /// Return the chosen signature algorithm.
    pub fn algorithm(&self) -> &'static SignatureAlgorithm { self.alg }
    /// Borrow the PKCS#8 DER representation.
    pub fn serialized_der(&self) -> &[u8] { &self.serialized_der }
    /// Serialize this key as PKCS#8 DER.
    pub fn serialize_der(&self) -> Vec<u8> { self.serialized_der.clone() }
    /// Serialize this key as PKCS#8 PEM.
    #[cfg(feature = "pem")]
    pub fn serialize_pem(&self) -> String { pem::encode(&pem::Pem::new("PRIVATE KEY", self.serialized_der.as_slice())) }
    /// Serialize the public key as DER SubjectPublicKeyInfo.
    pub fn public_key_der(&self) -> Vec<u8> { self.subject_public_key_info() }
    /// Serialize the public key as PEM SubjectPublicKeyInfo.
    #[cfg(feature = "pem")]
    pub fn public_key_pem(&self) -> String { pem::encode(&pem::Pem::new("PUBLIC KEY", self.public_key_der())) }
}
impl TryFrom<&[u8]> for KeyPair {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if let Ok(k) = p256::ecdsa::SigningKey::from_pkcs8_der(bytes) { return Self::from_material(Material::P256(k), &crate::PKCS_ECDSA_P256_SHA256); }
        if let Ok(k) = p384::ecdsa::SigningKey::from_pkcs8_der(bytes) { return Self::from_material(Material::P384(k), &crate::PKCS_ECDSA_P384_SHA384); }
        if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_der(bytes) { return Self::from_material(Material::Ed25519(k), &crate::PKCS_ED25519); }
        if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_der(bytes) { return Self::from_material(Material::Rsa(k), &crate::PKCS_RSA_SHA256); }
        Err(Error::CouldNotParseKeyPair)
    }
}
impl TryFrom<Vec<u8>> for KeyPair { type Error = Error; fn try_from(v: Vec<u8>) -> Result<Self, Error> { Self::try_from(v.as_slice()) } }
impl PublicKeyData for KeyPair {
    fn der_bytes(&self) -> &[u8] { &self.public }
    fn algorithm(&self) -> &'static SignatureAlgorithm { self.alg }
}
impl SigningKey for KeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(match &self.key {
            Material::P256(k) => { let s: p256::ecdsa::Signature = k.sign(message); s.to_der().as_bytes().to_vec() }
            Material::P384(k) => { let s: p384::ecdsa::Signature = k.sign(message); s.to_der().as_bytes().to_vec() }
            Material::Ed25519(k) => k.sign(message).to_bytes().to_vec(),
            Material::Rsa(k) => {
                use rsa::signature::RandomizedSigner;
                let mut rng = rand_core::OsRng;
                // Blinded private RSA operations, even though PKCS#1 v1.5 signatures are deterministic.
                if self.alg == &crate::PKCS_RSA_SHA256 { rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(k.clone()).try_sign_with_rng(&mut rng, message) }
                else if self.alg == &crate::PKCS_RSA_SHA384 { rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(k.clone()).try_sign_with_rng(&mut rng, message) }
                else { rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(k.clone()).try_sign_with_rng(&mut rng, message) }
                    .map_err(|_| Error::RingUnspecified)?.to_vec()
            }
        })
    }
}

#[cfg(feature = "x509-parser")]
pub(crate) fn verify_csr(csr: &x509_parser::certification_request::X509CertificationRequest<'_>) -> Result<(), Error> {
    use p256::ecdsa::signature::Verifier;
    use rsa::pkcs1::DecodeRsaPublicKey;
    let invalid = || Error::InvalidCertificationRequestSignature;
    let info = &csr.certification_request_info;
    if info.subject_pki.subject_public_key.unused_bits != 0 || csr.signature_value.unused_bits != 0 { return Err(invalid()); }
    let key = info.subject_pki.subject_public_key.data.as_ref();
    let sig = csr.signature_value.data.as_ref();
    let message = info.raw;
    match csr.signature_algorithm.algorithm.to_id_string().as_str() {
        "1.2.840.10045.4.3.2" => p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_|invalid())?.verify(message, &p256::ecdsa::Signature::from_der(sig).map_err(|_|invalid())?).map_err(|_|invalid()),
        "1.2.840.10045.4.3.3" => p384::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_|invalid())?.verify(message, &p384::ecdsa::Signature::from_der(sig).map_err(|_|invalid())?).map_err(|_|invalid()),
        "1.3.101.112" => ed25519_dalek::VerifyingKey::from_bytes(key.try_into().map_err(|_|invalid())?).map_err(|_|invalid())?.verify_strict(message, &ed25519_dalek::Signature::from_slice(sig).map_err(|_|invalid())?).map_err(|_|invalid()),
        oid @ ("1.2.840.113549.1.1.11" | "1.2.840.113549.1.1.12" | "1.2.840.113549.1.1.13") => {
            let key = rsa::RsaPublicKey::from_pkcs1_der(key).map_err(|_|invalid())?;
            let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_|invalid())?;
            match oid {
                "1.2.840.113549.1.1.11" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key).verify(message, &sig),
                "1.2.840.113549.1.1.12" => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key).verify(message, &sig),
                _ => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key).verify(message, &sig),
            }.map_err(|_|invalid())
        }
        _ => Err(Error::UnsupportedSignatureAlgorithm),
    }
}
