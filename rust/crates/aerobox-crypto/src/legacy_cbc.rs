//! TLS 1.0/1.1/1.2 CBC records used by browser compatibility profiles. Explicit opt-in;
//! the ordinary provider continues to advertise only its existing AEAD suites.
//!
//! RFC 2246/4346/5246 sections 6.2.3.2 and 6.3: independent HMAC keys,
//! MAC over sequence/type/version/length/plaintext, and TLS padding. TLS 1.0
//! obtains its first IV from the key block and then chains each record's last
//! ciphertext block. TLS 1.1/1.2 carry an unpredictable explicit IV. TLS 1.0
//! application-data record splitting belongs in the record sender, because
//! MessageEncrypter can return only one record at a time.
//!
//! The explicit IV is AES-256(iv_key, zeroes[8] || sequence_be). An HMAC-SHA256
//! KDF with its own domain label derives iv_key from both directional traffic
//! keys. It is distinct from the record encryption key. Handshake key entropy
//! supplies unpredictability; rustls never repeats a sequence within a key
//! epoch, so this permutation also avoids IV collisions in that epoch. This
//! meets RFC 5246's unpredictable-IV requirement without fallible per-record
//! entropy calls (the rustls record sender expects encryption to be infallible).
//!
//! Owned MAC keys, derived IV-key buffers and AES expanded schedules are wiped
//! on drop. RustCrypto hmac 0.12's transient ipad/opad buffers and digest states
//! do not implement zeroization; this module does not claim those are erased.
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::{CipherSuite, Error, ProtocolVersion, SupportedCipherSuite, Tls12CipherSuite};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

const BLOCK: usize = 16;
const MAC_SIZE: usize = 20;
const MAX_PLAIN: usize = 16384;
const IV_KEY_LABEL: &[u8] = b"aerobox/tls12-cbc-explicit-iv-key/v1\0";
static AES128: Algorithm = Algorithm(16, ProtocolVersion::TLSv1_2);
static AES256: Algorithm = Algorithm(32, ProtocolVersion::TLSv1_2);
static AES128_TLS10: Algorithm = Algorithm(16, ProtocolVersion::TLSv1_0);
static AES256_TLS10: Algorithm = Algorithm(32, ProtocolVersion::TLSv1_0);
static AES128_TLS11: Algorithm = Algorithm(16, ProtocolVersion::TLSv1_1);
static AES256_TLS11: Algorithm = Algorithm(32, ProtocolVersion::TLSv1_1);

/// Select a version-bound AES-CBC/HMAC-SHA1 factory. `key_len` is in bytes.
///
/// Only callers opting into legacy TLS may request TLS 1.0/1.1. The returned
/// key-block shape includes a 16-byte per-direction initial IV for TLS 1.0;
/// TLS 1.1/1.2 consume no IV material from the key block. Unsupported versions
/// or key sizes are rejected instead of falling back to another record format.
pub const fn algorithm_for_version(
    key_len: usize,
    version: ProtocolVersion,
) -> Option<&'static dyn Tls12AeadAlgorithm> {
    Some(match (key_len, version) {
        (16, ProtocolVersion::TLSv1_0) => &AES128_TLS10,
        (32, ProtocolVersion::TLSv1_0) => &AES256_TLS10,
        (16, ProtocolVersion::TLSv1_1) => &AES128_TLS11,
        (32, ProtocolVersion::TLSv1_1) => &AES256_TLS11,
        (16, ProtocolVersion::TLSv1_2) => &AES128,
        (32, ProtocolVersion::TLSv1_2) => &AES256,
        _ => return None,
    })
}

pub static TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &AES128,
);
pub static TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    &super::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &AES256,
);
pub static TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    &super::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &AES128,
);
pub static TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    &super::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &AES256,
);
/// CBC-SHA uses HMAC-SHA1 on records but the TLS 1.2 PRF/transcript uses SHA256.
const fn suite(
    id: CipherSuite,
    base: &'static Tls12CipherSuite,
    alg: &'static Algorithm,
) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: id,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: 1 << 24,
        },
        prf_provider: base.prf_provider,
        kx: base.kx,
        sign: base.sign,
        aead_alg: alg,
    }
}
/// These are available for an explicit legacy suite/profile, never as a default.
pub fn suites() -> [SupportedCipherSuite; 4] {
    [
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
    ]
}
struct Algorithm(usize, ProtocolVersion);
impl Tls12AeadAlgorithm for Algorithm {
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.0,
            fixed_iv_len: if self.1 == ProtocolVersion::TLSv1_0 {
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
        match Cipher::new(self.0, key, iv, mac, self.1).filter(|_| extra.is_empty()) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid),
        }
    }
    fn decrypter_with_mac(&self, key: AeadKey, iv: &[u8], mac: &[u8]) -> Box<dyn MessageDecrypter> {
        match Cipher::new(self.0, key, iv, mac, self.1) {
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
        wire_len(n, BLOCK)
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
#[allow(clippy::large_enum_variant)]
enum Aes {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}
struct Cipher {
    aes: Aes,
    mac: Zeroizing<[u8; MAC_SIZE]>,
    iv: RecordIv,
    version: ProtocolVersion,
    failed: bool,
}
#[allow(clippy::large_enum_variant)]
enum RecordIv {
    Implicit(Zeroizing<[u8; BLOCK]>),
    Explicit(aes::Aes256),
}
impl Cipher {
    fn new(
        length: usize,
        key: AeadKey,
        iv: &[u8],
        mac: &[u8],
        version: ProtocolVersion,
    ) -> Option<Self> {
        Self::from_slices_for_version(length, key.as_ref(), iv, mac, version)
    }
    #[cfg(test)]
    fn from_slices(length: usize, key: &[u8], iv: &[u8], mac: &[u8]) -> Option<Self> {
        Self::from_slices_for_version(length, key, iv, mac, ProtocolVersion::TLSv1_2)
    }
    fn from_slices_for_version(
        length: usize,
        key: &[u8],
        iv: &[u8],
        mac: &[u8],
        version: ProtocolVersion,
    ) -> Option<Self> {
        let iv_len = match version {
            ProtocolVersion::TLSv1_0 => BLOCK,
            ProtocolVersion::TLSv1_1 | ProtocolVersion::TLSv1_2 => 0,
            _ => return None,
        };
        if key.len() != length || iv.len() != iv_len || mac.len() != MAC_SIZE {
            return None;
        }
        let aes = match length {
            16 => Aes::Aes128(aes::Aes128::new_from_slice(key).ok()?),
            32 => Aes::Aes256(aes::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        };
        let iv = if version == ProtocolVersion::TLSv1_0 {
            RecordIv::Implicit(Zeroizing::new(iv.try_into().ok()?))
        } else {
            let mut derive = <Hmac<sha2::Sha256> as Mac>::new_from_slice(mac).ok()?;
            derive.update(IV_KEY_LABEL);
            derive.update(&(length as u16).to_be_bytes());
            derive.update(key);
            let mut iv_key = Zeroizing::new([0u8; 32]);
            // Finalize directly into the zeroizing buffer, without another owned
            // output-key copy. HMAC's internal state has the limitation noted above.
            sha2::digest::FixedOutput::finalize_into(derive, (&mut *iv_key).into());
            RecordIv::Explicit(aes::Aes256::new_from_slice(iv_key.as_ref()).ok()?)
        };
        Some(Self {
            aes,
            mac: Zeroizing::new(mac.try_into().ok()?),
            iv,
            version,
            failed: false,
        })
    }
    fn explicit_iv_len(&self) -> usize {
        match &self.iv {
            RecordIv::Implicit(_) => 0,
            RecordIv::Explicit(_) => BLOCK,
        }
    }
    fn explicit_iv(&self, seq: u64) -> [u8; BLOCK] {
        let mut iv = [0u8; BLOCK];
        iv[8..].copy_from_slice(&seq.to_be_bytes());
        match &self.iv {
            RecordIv::Explicit(prf) => prf.encrypt_block((&mut iv).into()),
            RecordIv::Implicit(previous) => iv.copy_from_slice(previous.as_ref()),
        }
        iv
    }
    fn tag(
        &self,
        seq: u64,
        typ: rustls::ContentType,
        version: rustls::ProtocolVersion,
        plain: &[u8],
    ) -> [u8; MAC_SIZE] {
        let mut hmac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(self.mac.as_ref())
            .expect("fixed HMAC key length");
        hmac.update(&make_tls12_aad(seq, typ, version, plain.len()));
        hmac.update(plain);
        hmac.finalize().into_bytes().into()
    }
    fn encrypt_blocks(&self, plaintext: &mut [u8], mut previous: [u8; BLOCK]) {
        for block in plaintext.chunks_exact_mut(BLOCK) {
            for (byte, old) in block.iter_mut().zip(previous) {
                *byte ^= old;
            }
            match &self.aes {
                Aes::Aes128(aes) => aes.encrypt_block(block.into()),
                Aes::Aes256(aes) => aes.encrypt_block(block.into()),
            }
            previous.copy_from_slice(block);
        }
    }
    fn decrypt_blocks(&self, ciphertext: &mut [u8], mut previous: [u8; BLOCK]) {
        for block in ciphertext.chunks_exact_mut(BLOCK) {
            let next: [u8; BLOCK] = block.try_into().unwrap();
            match &self.aes {
                Aes::Aes128(aes) => aes.decrypt_block(block.into()),
                Aes::Aes256(aes) => aes.decrypt_block(block.into()),
            }
            for (byte, old) in block.iter_mut().zip(previous) {
                *byte ^= old;
            }
            previous = next;
        }
    }
}
fn wire_len(n: usize, explicit: usize) -> usize {
    n.checked_add(MAC_SIZE + BLOCK)
        .and_then(|n| (n / BLOCK * BLOCK).checked_add(explicit))
        .unwrap_or(usize::MAX)
}
impl MessageEncrypter for Cipher {
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n, self.explicit_iv_len())
    }
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let length = msg.payload.len();
        if self.failed {
            return Err(Error::EncryptError);
        }
        // Any error permanently retires this directional key/IV state.
        self.failed = true;
        if length > MAX_PLAIN || msg.version != self.version {
            return Err(Error::EncryptError);
        }
        let explicit = self.explicit_iv_len();
        let total = wire_len(length, explicit);
        let mut payload = PrefixedPayload::with_capacity(total);
        let iv = self.explicit_iv(seq);
        if explicit != 0 {
            payload.extend_from_slice(&iv);
        }
        payload.extend_from_chunks(&msg.payload);
        let tag = self.tag(seq, msg.typ, msg.version, &payload.as_ref()[explicit..]);
        payload.extend_from_slice(&tag);
        let pad = total - explicit - length - MAC_SIZE;
        let padding = [(pad - 1) as u8; BLOCK];
        payload.extend_from_slice(&padding[..pad]);
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
        let length = msg.payload.len();
        if self.failed {
            return Err(Error::DecryptError);
        }
        self.failed = true;
        let explicit = self.explicit_iv_len();
        // All early bounds depend only on the public ciphertext, never padding.
        if msg.version != self.version
            || length < explicit + BLOCK * 2
            || length > explicit + MAX_PLAIN + MAC_SIZE + 256
            || length % BLOCK != 0
        {
            return Err(Error::DecryptError);
        }
        let iv = match &self.iv {
            RecordIv::Explicit(_) => msg.payload[..BLOCK].try_into().unwrap(),
            RecordIv::Implicit(previous) => **previous,
        };
        // Save the last ciphertext block before decrypting in place. Commit the
        // next implicit IV only after authenticating the complete record.
        let next_iv: [u8; BLOCK] = msg.payload[length - BLOCK..].try_into().unwrap();
        self.decrypt_blocks(&mut msg.payload[explicit..], iv);
        let decrypted = &msg.payload[explicit..];
        let n = decrypted.len();
        let mut valid = Choice::from(0);
        let mut chosen = 0u32;
        // Evaluate EVERY structurally possible padding/MAC position. Work and
        // memory access depend only on ciphertext length; secret padding never
        // chooses a hash input length or an address (Lucky13/padding oracle).
        // This bounded compatibility path deliberately favors auditability over
        // throughput. Ordinary connections retain AEAD and do not execute it.
        for pad in 1usize..=256 {
            let Some(plain_len) = n.checked_sub(MAC_SIZE + pad) else {
                continue;
            };
            if plain_len > MAX_PLAIN {
                continue;
            }
            let expected = (pad - 1) as u8;
            let mut padding_ok = Choice::from(1);
            for byte in &decrypted[n - pad..] {
                padding_ok &= byte.ct_eq(&expected);
            }
            let tag = self.tag(seq, msg.typ, msg.version, &decrypted[..plain_len]);
            let accepted = padding_ok & tag.ct_eq(&decrypted[plain_len..plain_len + MAC_SIZE]);
            chosen = u32::conditional_select(&chosen, &(plain_len as u32), accepted);
            valid |= accepted;
        }
        if !bool::from(valid) {
            msg.payload[explicit..].fill(0);
            return Err(Error::DecryptError);
        }
        if let RecordIv::Implicit(previous) = &mut self.iv {
            previous.copy_from_slice(&next_iv);
        }
        self.failed = false;
        Ok(msg.into_plain_message_range(explicit..explicit + chosen as usize))
    }
}

#[cfg(test)]
mod tests;
