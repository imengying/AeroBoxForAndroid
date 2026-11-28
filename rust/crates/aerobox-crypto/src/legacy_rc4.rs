//! Explicit RC4-128/HMAC-SHA1 compatibility records for TLS 1.0, 1.1 and 1.2.
//!
//! This module is not installed by the ordinary provider or any Android profile.
//! RC4 has known statistical weaknesses; there is no AEAD-style confidentiality
//! bound that makes it a safe default. The primitive uses secret-dependent table
//! indexes and is not claimed constant time. No IV, padding or RC4-drop is added.
//!
//! Every factory owns one directional continuous stream for one key epoch.
//! Sequence numbers start at zero and must increase exactly once per successful
//! record. Any error destroys that stream and its MAC key. Authentication errors
//! erase the decrypted buffer before returning; invalid headers rejected before
//! decryption still contain ciphertext, not exposed plaintext. RustCrypto's
//! zeroize feature erases its owned RC4 state on drop; the owned MAC and tag
//! buffers are zeroized. Transient HMAC/hash states and compiler-created copies
//! are not claimed erased.
use hmac::{Hmac, Mac};
use rc4::{KeyInit, StreamCipher};
use rustls::client::LegacyTlsProvider;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::{
    CipherSuite, ContentType, Error, ProtocolVersion, SupportedCipherSuite, Tls12CipherSuite,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const KEY_SIZE: usize = 16;
const MAC_SIZE: usize = 20;
const MAX_PLAIN: usize = 16384;
static TLS10: Algorithm = Algorithm(ProtocolVersion::TLSv1_0);
static TLS11: Algorithm = Algorithm(ProtocolVersion::TLSv1_1);
static TLS12: Algorithm = Algorithm(ProtocolVersion::TLSv1_2);

/// Only the protocol versions whose RC4-SHA record format is implemented.
pub const fn algorithm_for_version(
    version: ProtocolVersion,
) -> Option<&'static dyn Tls12AeadAlgorithm> {
    Some(match version {
        ProtocolVersion::TLSv1_0 => &TLS10,
        ProtocolVersion::TLSv1_1 => &TLS11,
        ProtocolVersion::TLSv1_2 => &TLS12,
        _ => return None,
    })
}

pub static TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    &crate::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::KeyExchangeAlgorithm::ECDHE,
);
pub static TLS_ECDHE_RSA_WITH_RC4_128_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    &crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::KeyExchangeAlgorithm::ECDHE,
);
pub static TLS_RSA_WITH_RC4_128_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
    &crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::KeyExchangeAlgorithm::RSA,
);

const fn suite(
    id: CipherSuite,
    base: &'static Tls12CipherSuite,
    kx: rustls::crypto::KeyExchangeAlgorithm,
) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: id,
            hash_provider: base.common.hash_provider,
            // Compatibility sentinel, NOT a claim that RC4 is secure for this
            // many records. Rustls still applies its sequence soft/hard limits;
            // Cipher separately rejects u64::MAX before a counter can overflow.
            confidentiality_limit: u64::MAX,
        },
        prf_provider: base.prf_provider,
        kx,
        sign: base.sign,
        aead_alg: &TLS12,
    }
}

/// The three actually implemented RC4-SHA suite IDs; no RC4-MD5 or fake DHE/DSS.
pub fn suites() -> [SupportedCipherSuite; 3] {
    [
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_RC4_128_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_RC4_128_SHA),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_RC4_128_SHA),
    ]
}

/// Explicit TLS1.2 RC4-only provider with ordinary strong signature/chain policy.
/// Old versions additionally require `enable_legacy_tls(&LEGACY_TLS_WITH_RC4, ...)`.
/// This is a cipher capability, not a 360 ClientHello profile or a global default.
pub fn provider() -> rustls::crypto::CryptoProvider {
    let mut provider = crate::provider();
    provider.cipher_suites = suites().into_iter().collect();
    provider
}

const fn old_suite(
    base: &'static Tls12CipherSuite,
    version: ProtocolVersion,
    rsa: bool,
) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: base.common.suite,
            hash_provider: &crate::legacy_hash::MD5_SHA1,
            confidentiality_limit: base.common.confidentiality_limit,
        },
        prf_provider: &crate::legacy_prf::TLS10_PRF,
        kx: base.kx,
        sign: if rsa {
            &[rustls::SignatureScheme::RSA_PKCS1_MD5_SHA1_Legacy]
        } else {
            &[rustls::SignatureScheme::ECDSA_SHA1_Legacy]
        },
        aead_alg: match version {
            ProtocolVersion::TLSv1_0 => &TLS10,
            ProtocolVersion::TLSv1_1 => &TLS11,
            _ => panic!("compiled RC4 legacy version"),
        },
    }
}
macro_rules! old_suites {
    ($version:expr) => {
        [
            old_suite(&TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, $version, false),
            old_suite(&TLS_ECDHE_RSA_WITH_RC4_128_SHA, $version, true),
            old_suite(&TLS_RSA_WITH_RC4_128_SHA, $version, true),
        ]
    };
}
static TLS10_SUITES: [Tls12CipherSuite; 3] = old_suites!(ProtocolVersion::TLSv1_0);
static TLS11_SUITES: [Tls12CipherSuite; 3] = old_suites!(ProtocolVersion::TLSv1_1);

#[derive(Debug)]
pub struct LegacyWithRc4;
pub static LEGACY_TLS_WITH_RC4: LegacyWithRc4 = LegacyWithRc4;
impl LegacyTlsProvider for LegacyWithRc4 {
    fn cipher_suite(
        &self,
        id: CipherSuite,
        version: ProtocolVersion,
    ) -> Option<&'static Tls12CipherSuite> {
        let suites = match version {
            ProtocolVersion::TLSv1_0 => &TLS10_SUITES,
            ProtocolVersion::TLSv1_1 => &TLS11_SUITES,
            _ => return None,
        };
        suites.iter().find(|suite| suite.common.suite == id)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        algorithm: rustls::SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, Error> {
        crate::legacy_provider::LEGACY_TLS.verify_signature(message, cert, algorithm, signature)
    }
}

struct Algorithm(ProtocolVersion);
impl Tls12AeadAlgorithm for Algorithm {
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: KEY_SIZE,
            fixed_iv_len: 0,
            explicit_nonce_len: 0,
        }
    }
    fn mac_key_len(&self) -> usize {
        MAC_SIZE
    }
    fn encrypter(&self, _: AeadKey, _: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Invalid)
    }
    fn decrypter(&self, _: AeadKey, _: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Invalid)
    }
    fn encrypter_with_mac(
        &self,
        key: AeadKey,
        iv: &[u8],
        extra: &[u8],
        mac: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        match Cipher::new(key.as_ref(), mac, self.0).filter(|_| iv.is_empty() && extra.is_empty()) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid),
        }
    }
    fn decrypter_with_mac(&self, key: AeadKey, iv: &[u8], mac: &[u8]) -> Box<dyn MessageDecrypter> {
        match Cipher::new(key.as_ref(), mac, self.0).filter(|_| iv.is_empty()) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid),
        }
    }
    fn extract_keys(
        &self,
        _: AeadKey,
        _: &[u8],
        _: &[u8],
    ) -> Result<rustls::ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

struct Invalid;
impl MessageEncrypter for Invalid {
    fn encrypt(
        &mut self,
        _: OutboundPlainMessage<'_>,
        _: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n)
    }
}
impl MessageDecrypter for Invalid {
    fn decrypt<'a>(
        &mut self,
        _: InboundOpaqueMessage<'a>,
        _: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

struct Active {
    stream: rc4::Rc4,
    mac: Zeroizing<[u8; MAC_SIZE]>,
}
struct Cipher {
    // Taking this value before processing makes every unsuccessful attempt
    // permanent and immediately drops/zeroizes the directional key state.
    active: Option<Active>,
    version: ProtocolVersion,
    next_seq: u64,
}
impl Cipher {
    fn new(key: &[u8], mac: &[u8], version: ProtocolVersion) -> Option<Self> {
        if key.len() != KEY_SIZE
            || mac.len() != MAC_SIZE
            || algorithm_for_version(version).is_none()
        {
            return None;
        }
        Some(Self {
            active: Some(Active {
                stream: rc4::Rc4::new_from_slice(key).ok()?,
                mac: Zeroizing::new(mac.try_into().ok()?),
            }),
            version,
            next_seq: 0,
        })
    }

    fn accepts(&self, seq: u64, typ: ContentType, version: ProtocolVersion, length: usize) -> bool {
        seq == self.next_seq
            && seq < u64::MAX
            && version == self.version
            && length <= MAX_PLAIN
            && matches!(
                typ,
                ContentType::ChangeCipherSpec
                    | ContentType::Alert
                    | ContentType::Handshake
                    | ContentType::ApplicationData
            )
            && (length != 0 || typ == ContentType::ApplicationData)
    }
}
impl Active {
    fn tag(
        &self,
        seq: u64,
        typ: ContentType,
        version: ProtocolVersion,
        plain: &[u8],
    ) -> Option<Zeroizing<[u8; MAC_SIZE]>> {
        let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(self.mac.as_ref()).ok()?;
        mac.update(&make_tls12_aad(seq, typ, version, plain.len()));
        mac.update(plain);
        let mut tag = Zeroizing::new([0u8; MAC_SIZE]);
        sha1::digest::FixedOutput::finalize_into(mac, (&mut *tag).into());
        Some(tag)
    }
}
fn wire_len(length: usize) -> usize {
    length.checked_add(MAC_SIZE).unwrap_or(usize::MAX)
}

impl MessageEncrypter for Cipher {
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n)
    }

    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let mut active = self.active.take().ok_or(Error::EncryptError)?;
        if !self.accepts(seq, msg.typ, msg.version, msg.payload.len()) {
            return Err(Error::EncryptError);
        }
        let mut payload = PrefixedPayload::with_capacity(wire_len(msg.payload.len()));
        payload.extend_from_chunks(&msg.payload);
        let Some(tag) = active.tag(seq, msg.typ, msg.version, payload.as_ref()) else {
            payload.as_mut().zeroize();
            return Err(Error::EncryptError);
        };
        payload.extend_from_slice(tag.as_ref());
        if active.stream.try_apply_keystream(payload.as_mut()).is_err() {
            payload.as_mut().zeroize();
            return Err(Error::EncryptError);
        }
        self.next_seq += 1; // accepts rejects u64::MAX before this point.
        self.active = Some(active);
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypt_with_padding(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
        padding: usize,
    ) -> Result<OutboundOpaqueMessage, Error> {
        if padding != 0 {
            drop(self.active.take());
            return Err(Error::EncryptError);
        }
        self.encrypt(msg, seq)
    }
}
impl MessageDecrypter for Cipher {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let mut active = self.active.take().ok_or(Error::DecryptError)?;
        let Some(length) = msg.payload.len().checked_sub(MAC_SIZE) else {
            return Err(Error::DecryptError);
        };
        if !self.accepts(seq, msg.typ, msg.version, length) {
            return Err(Error::DecryptError);
        }
        if active.stream.try_apply_keystream(&mut msg.payload).is_err() {
            msg.payload[..].zeroize();
            return Err(Error::DecryptError);
        }
        let Some(tag) = active.tag(seq, msg.typ, msg.version, &msg.payload[..length]) else {
            msg.payload[..].zeroize();
            return Err(Error::DecryptError);
        };
        if !bool::from(tag[..].ct_eq(&msg.payload[length..])) {
            msg.payload[..].zeroize();
            return Err(Error::DecryptError);
        }
        // The MAC is no longer needed; never leave its decrypted value in the
        // borrowed backing storage beyond the returned authenticated payload.
        msg.payload[length..].zeroize();
        self.next_seq += 1;
        self.active = Some(active);
        Ok(msg.into_plain_message_range(0..length))
    }
}

#[cfg(test)]
mod tests;
