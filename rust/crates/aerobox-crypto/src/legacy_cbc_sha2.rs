//! Opt-in TLS1.2 AES-CBC/HMAC-SHA256 or HMAC-SHA384 (RFC5246/RFC5289).
//!
//! These six suites are never added to the ordinary provider and cannot be
//! mapped to TLS1.0/1.1. RSA/AES256-CBC-SHA256 deliberately retains SHA256 for
//! both records and the PRF/transcript, unlike ECDHE/AES256-CBC-SHA384.
//!
//! Record authentication evaluates all 256 TLS padding candidates; only public
//! ciphertext length can skip impossible candidates. No secret padding byte
//! chooses a hash length or memory address. Any failure permanently retires
//! that direction and erases any unauthenticated plaintext decrypted in place.
//! This bounded compatibility path prioritizes auditability over throughput.
//!
//! Explicit IVs use AES256 under an independently HMAC-derived key, with a
//! separate SHA2-CBC domain label and key/MAC lengths. Sequence numbers must
//! not repeat within an epoch, as required and enforced by rustls. Owned MAC
//! keys, derived-IV buffers and AES expanded keys are zeroized; hmac/digest
//! transient internal states do not implement zeroization and are not claimed
//! to be erased. No native crypto backend is required by this module.
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls12AeadAlgorithm, UnsupportedOperationError, make_tls12_aad,
};
use rustls::{CipherSuite, Error, ProtocolVersion, SupportedCipherSuite, Tls12CipherSuite};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

const BLOCK: usize = 16;
const MAX_MAC: usize = 48;
const MAX_PLAIN: usize = 16384;
const IV_KEY_LABEL: &[u8] = b"aerobox/tls12-cbc-sha2-explicit-iv-key/v1\0";

#[derive(Clone, Copy)]
enum Digest {
    Sha256,
    Sha384,
}
impl Digest {
    const fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}
struct Algorithm {
    key_len: usize,
    digest: Digest,
}
static AES128_SHA256: Algorithm = Algorithm {
    key_len: 16,
    digest: Digest::Sha256,
};
static AES256_SHA256: Algorithm = Algorithm {
    key_len: 32,
    digest: Digest::Sha256,
};
static AES256_SHA384: Algorithm = Algorithm {
    key_len: 32,
    digest: Digest::Sha384,
};

pub static TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    &crate::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    &AES128_SHA256,
    false,
);
pub static TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    &crate::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    &AES256_SHA384,
    false,
);
pub static TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    &crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &AES128_SHA256,
    false,
);
pub static TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: Tls12CipherSuite = suite(
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    &crate::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    &AES256_SHA384,
    false,
);
pub static TLS_RSA_WITH_AES_128_CBC_SHA256: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
    &crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &AES128_SHA256,
    true,
);
pub static TLS_RSA_WITH_AES_256_CBC_SHA256: Tls12CipherSuite = suite(
    CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
    &crate::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    &AES256_SHA256,
    true,
);

const fn suite(
    id: CipherSuite,
    base: &'static Tls12CipherSuite,
    alg: &'static Algorithm,
    rsa: bool,
) -> Tls12CipherSuite {
    Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: id,
            hash_provider: base.common.hash_provider,
            confidentiality_limit: 1 << 24,
        },
        prf_provider: base.prf_provider,
        kx: if rsa {
            rustls::crypto::KeyExchangeAlgorithm::RSA
        } else {
            base.kx
        },
        sign: base.sign,
        aead_alg: alg,
    }
}

/// All six real implementations, available only by explicit suite selection.
pub fn suites() -> [SupportedCipherSuite; 6] {
    [
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_128_CBC_SHA256),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_256_CBC_SHA256),
    ]
}

impl Tls12AeadAlgorithm for Algorithm {
    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: self.key_len,
            fixed_iv_len: 0,
            explicit_nonce_len: 0,
        }
    }
    fn mac_key_len(&self) -> usize {
        self.digest.size()
    }
    fn encrypter(&self, _: AeadKey, _: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Invalid(self.digest.size()))
    }
    fn decrypter(&self, _: AeadKey, _: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Invalid(self.digest.size()))
    }
    fn encrypter_with_mac(
        &self,
        key: AeadKey,
        iv: &[u8],
        extra: &[u8],
        mac: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        match Cipher::new(self, key.as_ref(), iv, mac).filter(|_| extra.is_empty()) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid(self.digest.size())),
        }
    }
    fn decrypter_with_mac(&self, key: AeadKey, iv: &[u8], mac: &[u8]) -> Box<dyn MessageDecrypter> {
        match Cipher::new(self, key.as_ref(), iv, mac) {
            Some(cipher) => Box::new(cipher),
            None => Box::new(Invalid(self.digest.size())),
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

struct Invalid(usize);
impl MessageEncrypter for Invalid {
    fn encrypt(
        &mut self,
        _: OutboundPlainMessage<'_>,
        _: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n, self.0)
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
    mac: Zeroizing<[u8; MAX_MAC]>,
    digest: Digest,
    iv: aes::Aes256,
    failed: bool,
}
impl Cipher {
    fn new(algorithm: &Algorithm, key: &[u8], fixed_iv: &[u8], mac: &[u8]) -> Option<Self> {
        if key.len() != algorithm.key_len
            || !fixed_iv.is_empty()
            || mac.len() != algorithm.digest.size()
        {
            return None;
        }
        let aes = match algorithm.key_len {
            16 => Aes::Aes128(aes::Aes128::new_from_slice(key).ok()?),
            32 => Aes::Aes256(aes::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        };
        let mut derive = <Hmac<sha2::Sha256> as Mac>::new_from_slice(mac).ok()?;
        derive.update(IV_KEY_LABEL);
        derive.update(&(key.len() as u16).to_be_bytes());
        derive.update(&(mac.len() as u16).to_be_bytes());
        derive.update(key);
        let mut iv_key = Zeroizing::new([0u8; 32]);
        sha2::digest::FixedOutput::finalize_into(derive, (&mut *iv_key).into());
        let iv = aes::Aes256::new_from_slice(iv_key.as_ref()).ok()?;
        let mut owned_mac = Zeroizing::new([0u8; MAX_MAC]);
        owned_mac[..mac.len()].copy_from_slice(mac);
        Some(Self {
            aes,
            mac: owned_mac,
            digest: algorithm.digest,
            iv,
            failed: false,
        })
    }
    fn explicit_iv(&self, seq: u64) -> [u8; BLOCK] {
        let mut iv = [0u8; BLOCK];
        iv[8..].copy_from_slice(&seq.to_be_bytes());
        self.iv.encrypt_block((&mut iv).into());
        iv
    }
    fn tag(&self, seq: u64, typ: rustls::ContentType, plain: &[u8]) -> [u8; MAX_MAC] {
        let aad = make_tls12_aad(seq, typ, ProtocolVersion::TLSv1_2, plain.len());
        let mut output = [0u8; MAX_MAC];
        match self.digest {
            Digest::Sha256 => {
                let mut hmac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&self.mac[..32])
                    .expect("fixed MAC key");
                hmac.update(&aad);
                hmac.update(plain);
                sha2::digest::FixedOutput::finalize_into(hmac, (&mut output[..32]).into());
            }
            Digest::Sha384 => {
                let mut hmac = <Hmac<sha2::Sha384> as Mac>::new_from_slice(&self.mac[..48])
                    .expect("fixed MAC key");
                hmac.update(&aad);
                hmac.update(plain);
                sha2::digest::FixedOutput::finalize_into(hmac, (&mut output[..48]).into());
            }
        }
        output
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

fn wire_len(n: usize, mac: usize) -> usize {
    n.checked_add(mac + BLOCK)
        .and_then(|n| (n / BLOCK * BLOCK).checked_add(BLOCK))
        .unwrap_or(usize::MAX)
}

impl MessageEncrypter for Cipher {
    fn encrypted_payload_len(&self, n: usize) -> usize {
        wire_len(n, self.digest.size())
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
        let length = msg.payload.len();
        if length > MAX_PLAIN || msg.version != ProtocolVersion::TLSv1_2 {
            return Err(Error::EncryptError);
        }
        let mac_len = self.digest.size();
        let total = wire_len(length, mac_len);
        let mut payload = PrefixedPayload::with_capacity(total);
        let iv = self.explicit_iv(seq);
        payload.extend_from_slice(&iv);
        payload.extend_from_chunks(&msg.payload);
        let tag = self.tag(seq, msg.typ, &payload.as_ref()[BLOCK..]);
        payload.extend_from_slice(&tag[..mac_len]);
        let pad = total - BLOCK - length - mac_len;
        payload.extend_from_slice(&[(pad - 1) as u8; BLOCK][..pad]);
        self.encrypt_blocks(&mut payload.as_mut()[BLOCK..], iv);
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
        let length = msg.payload.len();
        let mac_len = self.digest.size();
        // SHA2 MAC lengths are block-aligned. Even an empty fragment needs
        // the explicit IV, the whole MAC, and one encrypted padding block.
        if msg.version != ProtocolVersion::TLSv1_2
            || length < BLOCK + mac_len + BLOCK
            || length > BLOCK + MAX_PLAIN + mac_len + 256
            || length % BLOCK != 0
        {
            return Err(Error::DecryptError);
        }
        let iv = msg.payload[..BLOCK].try_into().unwrap();
        self.decrypt_blocks(&mut msg.payload[BLOCK..], iv);
        let decrypted = &msg.payload[BLOCK..];
        let n = decrypted.len();
        let mut valid = Choice::from(0);
        let mut chosen = 0u32;
        for pad in 1usize..=256 {
            let Some(plain_len) = n.checked_sub(mac_len + pad) else {
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
            let tag = self.tag(seq, msg.typ, &decrypted[..plain_len]);
            let accepted =
                padding_ok & tag[..mac_len].ct_eq(&decrypted[plain_len..plain_len + mac_len]);
            chosen = u32::conditional_select(&chosen, &(plain_len as u32), accepted);
            valid |= accepted;
        }
        if !bool::from(valid) {
            msg.payload[BLOCK..].zeroize();
            return Err(Error::DecryptError);
        }
        self.failed = false;
        Ok(msg.into_plain_message_range(BLOCK..BLOCK + chosen as usize))
    }
}

#[cfg(test)]
mod tests;
