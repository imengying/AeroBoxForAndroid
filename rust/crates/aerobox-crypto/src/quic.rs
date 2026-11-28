//! RFC 9001 sections 5.3 and 5.4. The cryptographic primitives are supplied by
//! RustCrypto; this module adapts their APIs and QUIC nonce/header formatting.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::AeadInPlace;
use chacha20::cipher::{KeyIvInit, StreamCipherCore, StreamCipherSeekCore, consts::U10};
use rustls::{
    Error,
    crypto::cipher::{AeadKey, Iv, Nonce},
    quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag},
};
use zeroize::{Zeroize, Zeroizing};

pub(super) static AES_128_GCM: QuicAlgorithm = QuicAlgorithm(Kind::Aes128);
pub(super) static AES_256_GCM: QuicAlgorithm = QuicAlgorithm(Kind::Aes256);
pub(super) static CHACHA20_POLY1305: QuicAlgorithm = QuicAlgorithm(Kind::ChaCha20);

#[derive(Clone, Copy)]
enum Kind {
    Aes128,
    Aes256,
    ChaCha20,
}

pub(super) struct QuicAlgorithm(Kind);

impl Algorithm for QuicAlgorithm {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(PacketProtection {
            key: PayloadCipher::new(self.0, key.as_ref()),
            iv,
        })
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(HeaderCipher::new(self.0, key.as_ref()))
    }

    fn aead_key_len(&self) -> usize {
        match self.0 {
            Kind::Aes128 => 16,
            Kind::Aes256 | Kind::ChaCha20 => 32,
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "the key is already boxed at the rustls API boundary; avoid another allocation"
)]
enum HeaderCipher {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
    ChaCha20(Zeroizing<[u8; 32]>),
}

impl HeaderCipher {
    fn new(kind: Kind, key: &[u8]) -> Self {
        // rustls derives exactly Algorithm::aead_key_len() bytes.
        match kind {
            Kind::Aes128 => {
                Self::Aes128(aes::Aes128::new_from_slice(key).expect("AES-128 key size"))
            }
            Kind::Aes256 => {
                Self::Aes256(aes::Aes256::new_from_slice(key).expect("AES-256 key size"))
            }
            Kind::ChaCha20 => {
                Self::ChaCha20(Zeroizing::new(key.try_into().expect("ChaCha key size")))
            }
        }
    }

    fn mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        let sample: [u8; 16] = sample.try_into().map_err(|_| invalid_header())?;
        let mut mask = [0; 5];
        match self {
            Self::Aes128(key) => {
                let mut block = sample.into();
                key.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            Self::Aes256(key) => {
                let mut block = sample.into();
                key.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            Self::ChaCha20(key) => {
                let counter =
                    u32::from_le_bytes(sample[..4].try_into().expect("four-byte counter"));
                let mut cipher =
                    chacha20::ChaChaCore::<U10>::new_from_slices(&key[..], &sample[4..])
                        .expect("validated ChaCha key and nonce sizes");
                // A header sample selects one independent block, including
                // counter u32::MAX. The streaming wrapper forbids that final
                // counter to prevent reuse after wrapping; we discard the core
                // after generating this single block.
                cipher.set_block_pos(counter);
                let mut block = chacha20::cipher::Block::<chacha20::ChaChaCore<U10>>::default();
                cipher.write_keystream_block(&mut block);
                mask.copy_from_slice(&block[..5]);
                block.zeroize();
            }
        }
        Ok(mask)
    }

    fn apply(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        decrypt: bool,
    ) -> Result<(), Error> {
        let mask = self.mask(sample)?;
        let bits = if *first & 0x80 != 0 { 0x0f } else { 0x1f };
        let plain_first = if decrypt {
            *first ^ (mask[0] & bits)
        } else {
            *first
        };
        let number_len = usize::from(plain_first & 3) + 1;
        if packet_number.len() > 4 || packet_number.len() < number_len {
            return Err(invalid_header());
        }
        // Validation is complete before changing either output slice.
        *first ^= mask[0] & bits;
        for (byte, mask_byte) in packet_number[..number_len].iter_mut().zip(&mask[1..]) {
            *byte ^= mask_byte;
        }
        Ok(())
    }
}

fn invalid_header() -> Error {
    Error::General("invalid QUIC header protection input".into())
}

impl HeaderProtectionKey for HeaderCipher {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        number: &mut [u8],
    ) -> Result<(), Error> {
        self.apply(sample, first, number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        number: &mut [u8],
    ) -> Result<(), Error> {
        self.apply(sample, first, number, true)
    }

    fn sample_len(&self) -> usize {
        16
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "the containing packet key is already boxed; keep the expanded AES key inline"
)]
enum PayloadCipher {
    Aes128(aes_gcm::Aes128Gcm),
    Aes256(aes_gcm::Aes256Gcm),
    ChaCha20(chacha20poly1305::ChaCha20Poly1305),
}

impl PayloadCipher {
    fn new(kind: Kind, key: &[u8]) -> Self {
        match kind {
            Kind::Aes128 => {
                Self::Aes128(aes_gcm::Aes128Gcm::new_from_slice(key).expect("AES-128 key size"))
            }
            Kind::Aes256 => {
                Self::Aes256(aes_gcm::Aes256Gcm::new_from_slice(key).expect("AES-256 key size"))
            }
            Kind::ChaCha20 => Self::ChaCha20(
                chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).expect("ChaCha key size"),
            ),
        }
    }

    fn seal(&self, nonce: [u8; 12], header: &[u8], payload: &mut [u8]) -> Result<Tag, Error> {
        let result = match self {
            Self::Aes128(key) => key.encrypt_in_place_detached(&nonce.into(), header, payload),
            Self::Aes256(key) => key.encrypt_in_place_detached(&nonce.into(), header, payload),
            Self::ChaCha20(key) => key.encrypt_in_place_detached(&nonce.into(), header, payload),
        };
        result
            .map(|tag| Tag::from(tag.as_slice()))
            .map_err(|_| Error::EncryptError)
    }

    fn open<'a>(
        &self,
        nonce: [u8; 12],
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let plain_len = payload.len().checked_sub(16).ok_or(Error::DecryptError)?;
        let (body, tag) = payload.split_at_mut(plain_len);
        let tag = aes_gcm::Tag::from_slice(tag);
        let result = match self {
            Self::Aes128(key) => key.decrypt_in_place_detached(&nonce.into(), header, body, tag),
            Self::Aes256(key) => key.decrypt_in_place_detached(&nonce.into(), header, body, tag),
            Self::ChaCha20(key) => key.decrypt_in_place_detached(&nonce.into(), header, body, tag),
        };
        result.map_err(|_| Error::DecryptError)?;
        Ok(body)
    }
}

struct PacketProtection {
    key: PayloadCipher,
    iv: Iv,
}

impl PacketKey for PacketProtection {
    fn encrypt_in_place(
        &self,
        number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        self.key
            .seal(Nonce::new(&self.iv, number).0, header, payload)
    }

    fn decrypt_in_place<'a>(
        &self,
        number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.key
            .open(Nonce::new(&self.iv, number).0, header, payload)
    }

    fn encrypt_in_place_for_path(
        &self,
        path: u32,
        number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        self.key
            .seal(Nonce::for_path(path, &self.iv, number).0, header, payload)
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path: u32,
        number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.key
            .open(Nonce::for_path(path, &self.iv, number).0, header, payload)
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        // RFC 9001 section 6.6.
        match self.key {
            PayloadCipher::Aes128(_) | PayloadCipher::Aes256(_) => 1 << 23,
            PayloadCipher::ChaCha20(_) => u64::MAX,
        }
    }

    fn integrity_limit(&self) -> u64 {
        match self.key {
            PayloadCipher::Aes128(_) | PayloadCipher::Aes256(_) => 1 << 52,
            PayloadCipher::ChaCha20(_) => 1 << 36,
        }
    }
}
