//! Explicit 3DES-EDE-CBC/SHA1 for the Android client's Safari/iOS TLS profiles.
//! Ordinary cipher providers do not include these suites. Record keys have a
//! hard 2^20 encrypted-block budget in each direction, including MAC/padding.
//! The 256-candidate padding/MAC check uses only public ciphertext length for
//! its work schedule. The DES primitive uses data-dependent S-box lookups, so
//! this is not a claim of constant-time 3DES or a security audit. Owned MAC,
//! implicit-IV and derived-key buffers and the DES expanded keys are zeroized;
//! transient HMAC/hash states and primitive temporaries are not claimed erased.
use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rustls::client::LegacyTlsProvider;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::{CipherSuite, Error, ProtocolVersion, SupportedCipherSuite, Tls12CipherSuite};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

const BLOCK: usize = 8;
const KEY: usize = 24;
const MAC_SIZE: usize = 20;
const MAX_PLAIN: usize = 16384;
const MAX_BLOCKS: u64 = 1 << 20;
const IV_LABEL: &[u8] = b"aerobox/tls-tdes-explicit-iv-key/v1\0";
static TLS10: Algorithm = Algorithm(ProtocolVersion::TLSv1_0);
static TLS11: Algorithm = Algorithm(ProtocolVersion::TLSv1_1);
static TLS12: Algorithm = Algorithm(ProtocolVersion::TLSv1_2);

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

pub static TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    &crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::KeyExchangeAlgorithm::ECDHE,
);
pub static TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    &crate::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::KeyExchangeAlgorithm::ECDHE,
);
pub static TLS_RSA_WITH_3DES_EDE_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
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
            // Record-layer guard plus a tighter block-count guard in Cipher.
            confidentiality_limit: MAX_BLOCKS / 3,
        },
        prf_provider: base.prf_provider,
        kx,
        sign: base.sign,
        aead_alg: &TLS12,
    }
}
pub fn suites() -> [SupportedCipherSuite; 3] {
    [
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_3DES_EDE_CBC_SHA),
    ]
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
        aead_alg: match algorithm_for_version(version) {
            Some(v) => v,
            None => panic!("compiled legacy version"),
        },
    }
}
macro_rules! old_suites {
    ($version:expr) => {
        [
            old_suite(&TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, $version, true),
            old_suite(&TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, $version, false),
            old_suite(&TLS_RSA_WITH_3DES_EDE_CBC_SHA, $version, true),
        ]
    };
}
static TLS10_SUITES: [Tls12CipherSuite; 3] = old_suites!(ProtocolVersion::TLSv1_0);
static TLS11_SUITES: [Tls12CipherSuite; 3] = old_suites!(ProtocolVersion::TLSv1_1);

/// Separate opt-in provider: the Android11 legacy provider remains unchanged.
#[derive(Debug)]
pub struct LegacyWithTdes;
pub static LEGACY_TLS_WITH_TDES: LegacyWithTdes = LegacyWithTdes;
impl LegacyTlsProvider for LegacyWithTdes {
    fn cipher_suite(
        &self,
        id: CipherSuite,
        version: ProtocolVersion,
    ) -> Option<&'static Tls12CipherSuite> {
        if let Some(value) = crate::legacy_provider::LEGACY_TLS.cipher_suite(id, version) {
            return Some(value);
        }
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
            enc_key_len: KEY,
            fixed_iv_len: if self.0 == ProtocolVersion::TLSv1_0 {
                BLOCK
            } else {
                0
            },
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
        match Cipher::new(key.as_ref(), iv, mac, self.0).filter(|_| extra.is_empty()) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid),
        }
    }
    fn decrypter_with_mac(&self, key: AeadKey, iv: &[u8], mac: &[u8]) -> Box<dyn MessageDecrypter> {
        match Cipher::new(key.as_ref(), iv, mac, self.0) {
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
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n, BLOCK)
    }
    fn encrypt(
        &mut self,
        _: OutboundPlainMessage<'_>,
        _: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
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

struct Cipher {
    tdes: des::TdesEde3,
    mac: Zeroizing<[u8; MAC_SIZE]>,
    iv: RecordIv,
    version: ProtocolVersion,
    blocks: u64,
    failed: bool,
}
enum RecordIv {
    Implicit(Zeroizing<[u8; BLOCK]>),
    // Independent PRP key: explicit IVs are unpredictable and do not repeat
    // for distinct sequence numbers in a key epoch. No per-record RNG call.
    Explicit(des::TdesEde3),
}
impl Cipher {
    fn new(key: &[u8], iv: &[u8], mac: &[u8], version: ProtocolVersion) -> Option<Self> {
        let iv_len = match version {
            ProtocolVersion::TLSv1_0 => BLOCK,
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_2 => 0,
            _ => return None,
        };
        if key.len() != KEY || iv.len() != iv_len || mac.len() != MAC_SIZE {
            return None;
        }
        let tdes = des::TdesEde3::new_from_slice(key).ok()?;
        let iv = if version == ProtocolVersion::TLSv1_0 {
            RecordIv::Implicit(Zeroizing::new(iv.try_into().ok()?))
        } else {
            let mut derive = <Hmac<sha2::Sha256> as Mac>::new_from_slice(mac).ok()?;
            derive.update(IV_LABEL);
            derive.update(key);
            let mut secret = Zeroizing::new([0u8; 32]);
            sha2::digest::FixedOutput::finalize_into(derive, (&mut *secret).into());
            RecordIv::Explicit(des::TdesEde3::new_from_slice(&secret[..KEY]).ok()?)
        };
        Some(Self {
            tdes,
            mac: Zeroizing::new(mac.try_into().ok()?),
            iv,
            version,
            blocks: 0,
            failed: false,
        })
    }
    fn explicit_len(&self) -> usize {
        if matches!(self.iv, RecordIv::Explicit(_)) {
            BLOCK
        } else {
            0
        }
    }
    fn iv(&self, seq: u64) -> [u8; BLOCK] {
        let mut bytes = seq.to_be_bytes();
        match &self.iv {
            RecordIv::Implicit(previous) => bytes.copy_from_slice(previous.as_ref()),
            RecordIv::Explicit(prp) => prp.encrypt_block((&mut bytes).into()),
        }
        bytes
    }
    fn tag(
        &self,
        seq: u64,
        typ: rustls::ContentType,
        version: ProtocolVersion,
        plain: &[u8],
    ) -> [u8; MAC_SIZE] {
        let mut hmac =
            <Hmac<sha1::Sha1> as Mac>::new_from_slice(self.mac.as_ref()).expect("fixed HMAC key");
        hmac.update(&make_tls12_aad(seq, typ, version, plain.len()));
        hmac.update(plain);
        hmac.finalize().into_bytes().into()
    }
    fn encrypt_blocks(&self, bytes: &mut [u8], mut previous: [u8; BLOCK]) {
        for block in bytes.chunks_exact_mut(BLOCK) {
            for (b, p) in block.iter_mut().zip(previous) {
                *b ^= p;
            }
            self.tdes
                .encrypt_block((&mut *block).try_into().expect("8-byte block"));
            previous.copy_from_slice(block);
        }
    }
    fn decrypt_blocks(&self, bytes: &mut [u8], mut previous: [u8; BLOCK]) {
        for block in bytes.chunks_exact_mut(BLOCK) {
            let next: [u8; BLOCK] = (&*block).try_into().unwrap();
            self.tdes
                .decrypt_block((&mut *block).try_into().expect("8-byte block"));
            for (b, p) in block.iter_mut().zip(previous) {
                *b ^= p;
            }
            previous = next;
        }
    }
    fn account(&mut self, encrypted_length: usize) -> bool {
        let Some(next) = self.blocks.checked_add((encrypted_length / BLOCK) as u64) else {
            return false;
        };
        if next > MAX_BLOCKS {
            return false;
        }
        self.blocks = next;
        true
    }
}
fn wire_len(plain: usize, explicit: usize) -> usize {
    plain
        .checked_add(MAC_SIZE + BLOCK)
        .and_then(|n| (n / BLOCK * BLOCK).checked_add(explicit))
        .unwrap_or(usize::MAX)
}
impl MessageEncrypter for Cipher {
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n, self.explicit_len())
    }
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        if self.failed {
            return Err(Error::EncryptError);
        }
        self.failed = true;
        let n = msg.payload.len();
        if n > MAX_PLAIN || msg.version != self.version {
            return Err(Error::EncryptError);
        }
        let explicit = self.explicit_len();
        let total = wire_len(n, explicit);
        if !self.account(total - explicit) {
            return Err(Error::EncryptError);
        }
        let iv = self.iv(seq);
        let mut payload = PrefixedPayload::with_capacity(total);
        if explicit != 0 {
            payload.extend_from_slice(&iv);
        }
        payload.extend_from_chunks(&msg.payload);
        let tag = self.tag(seq, msg.typ, msg.version, &payload.as_ref()[explicit..]);
        payload.extend_from_slice(&tag);
        let pad = total - explicit - n - MAC_SIZE;
        payload.extend_from_slice(&[(pad - 1) as u8; BLOCK][..pad]);
        self.encrypt_blocks(&mut payload.as_mut()[explicit..], iv);
        if let RecordIv::Implicit(previous) = &mut self.iv {
            previous.copy_from_slice(&payload.as_ref()[total - BLOCK..]);
        }
        self.failed = false;
        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }
}
impl MessageDecrypter for Cipher {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if self.failed {
            return Err(Error::DecryptError);
        }
        self.failed = true;
        let explicit = self.explicit_len();
        let length = msg.payload.len();
        if msg.version != self.version
            || length < explicit + 3 * BLOCK
            || length > explicit + MAX_PLAIN + MAC_SIZE + 256
            || length % BLOCK != 0
            || !self.account(length - explicit)
        {
            return Err(Error::DecryptError);
        }
        let iv = if explicit == 0 {
            self.iv(seq)
        } else {
            msg.payload[..BLOCK].try_into().unwrap()
        };
        let next: [u8; BLOCK] = msg.payload[length - BLOCK..].try_into().unwrap();
        self.decrypt_blocks(&mut msg.payload[explicit..], iv);
        let decrypted = &msg.payload[explicit..];
        let n = decrypted.len();
        let mut valid = Choice::from(0);
        let mut chosen = 0u32;
        // All 256 candidate locations depend only on public ciphertext length.
        // No secret padding byte selects a MAC input length or memory address.
        for pad in 1usize..=256 {
            let Some(plain) = n.checked_sub(MAC_SIZE + pad) else {
                continue;
            };
            if plain > MAX_PLAIN {
                continue;
            }
            let mut padding_ok = Choice::from(1);
            for byte in &decrypted[n - pad..] {
                padding_ok &= byte.ct_eq(&((pad - 1) as u8));
            }
            let tag = self.tag(seq, msg.typ, msg.version, &decrypted[..plain]);
            let accepted = padding_ok & tag.ct_eq(&decrypted[plain..plain + MAC_SIZE]);
            chosen = u32::conditional_select(&chosen, &(plain as u32), accepted);
            valid |= accepted;
        }
        if !bool::from(valid) {
            msg.payload[explicit..].zeroize();
            return Err(Error::DecryptError);
        }
        if let RecordIv::Implicit(previous) = &mut self.iv {
            previous.copy_from_slice(&next);
        }
        self.failed = false;
        Ok(msg.into_plain_message_range(explicit..explicit + chosen as usize))
    }
}

#[cfg(test)]
mod tests;
