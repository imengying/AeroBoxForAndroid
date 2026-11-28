//! Bounds and traffic-secret export fixes for the upstream record adapters.

use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, KeyBlockShape, MessageDecrypter,
    MessageEncrypter, Tls12AeadAlgorithm, Tls13AeadAlgorithm, UnsupportedOperationError,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Nonce, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, Error, SupportedCipherSuite};
use aes_gcm::aead::{AeadInPlace, KeyInit};

#[derive(Clone, Copy)]
enum Kind {
    Aes128,
    Aes256,
    ChaCha,
}

impl Kind {
    fn secrets(self, key: AeadKey, iv: Iv) -> ConnectionTrafficSecrets {
        match self {
            Self::Aes128 => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            Self::Aes256 => ConnectionTrafficSecrets::Aes256Gcm { key, iv },
            Self::ChaCha => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        }
    }
}

pub(super) static TLS13_AES128: Tls13Adapter =
    Tls13Adapter::new(rustls_rustcrypto::TLS13_AES_128_GCM_SHA256, Kind::Aes128);
pub(super) static TLS13_AES256: Tls13Adapter =
    Tls13Adapter::new(rustls_rustcrypto::TLS13_AES_256_GCM_SHA384, Kind::Aes256);
pub(super) static TLS13_CHACHA: Tls13Adapter = Tls13Adapter::new(
    rustls_rustcrypto::TLS13_CHACHA20_POLY1305_SHA256,
    Kind::ChaCha,
);
pub(super) static TLS12_AES128: Tls12Adapter = Tls12Adapter::new(
    rustls_rustcrypto::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    Kind::Aes128,
);
pub(super) static TLS12_AES256: Tls12Adapter = Tls12Adapter::new(
    rustls_rustcrypto::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    Kind::Aes256,
);
pub(super) static TLS12_CHACHA: Tls12Adapter = Tls12Adapter::new(
    rustls_rustcrypto::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    Kind::ChaCha,
);

pub(super) struct Tls13Adapter {
    inner: &'static dyn Tls13AeadAlgorithm,
    kind: Kind,
}

impl Tls13Adapter {
    const fn new(suite: SupportedCipherSuite, kind: Kind) -> Self {
        let SupportedCipherSuite::Tls13(suite) = suite else {
            panic!("TLS 1.3 suite required")
        };
        Self {
            inner: suite.aead_alg,
            kind,
        }
    }
}

impl Tls13AeadAlgorithm for Tls13Adapter {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        let cipher = match self.kind {
            Kind::Aes128 => Tls13Cipher::Aes128(aes_gcm::Aes128Gcm::new_from_slice(key.as_ref()).expect("rustls supplies a 16-byte AES key")),
            Kind::Aes256 => Tls13Cipher::Aes256(aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).expect("rustls supplies a 32-byte AES key")),
            Kind::ChaCha => Tls13Cipher::ChaCha(chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("rustls supplies a 32-byte ChaCha key")),
        };
        Box::new(PaddedEncrypter { cipher, iv })
    }
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.inner.decrypter(key, iv)
    }
    fn key_len(&self) -> usize {
        self.inner.key_len()
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(self.kind.secrets(key, iv))
    }
}

pub(super) struct Tls12Adapter {
    inner: &'static dyn Tls12AeadAlgorithm,
    kind: Kind,
}

impl Tls12Adapter {
    const fn new(suite: SupportedCipherSuite, kind: Kind) -> Self {
        let SupportedCipherSuite::Tls12(suite) = suite else {
            panic!("TLS 1.2 suite required")
        };
        Self {
            inner: suite.aead_alg,
            kind,
        }
    }
}

impl Tls12AeadAlgorithm for Tls12Adapter {
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter> {
        self.inner.encrypter(key, iv, extra)
    }
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(BoundedDecrypter {
            inner: self.inner.decrypter(key, iv),
            minimum_len: match self.kind {
                Kind::ChaCha => 16,
                _ => 24,
            },
        })
    }
    fn key_block_shape(&self) -> KeyBlockShape {
        self.inner.key_block_shape()
    }
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        let shape = self.key_block_shape();
        if key.as_ref().len() != shape.enc_key_len
            || iv.len() != shape.fixed_iv_len
            || explicit.len() != shape.explicit_nonce_len
        {
            return Err(UnsupportedOperationError);
        }
        let mut nonce = [0; 12];
        nonce[..iv.len()].copy_from_slice(iv);
        nonce[iv.len()..].copy_from_slice(explicit);
        Ok(self.kind.secrets(key, Iv::from(nonce)))
    }
}

struct BoundedDecrypter {
    inner: Box<dyn MessageDecrypter>,
    minimum_len: usize,
}

impl MessageDecrypter for BoundedDecrypter {
    fn decrypt<'a>(
        &mut self,
        msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        if msg.payload.len() < self.minimum_len {
            return Err(Error::DecryptError);
        }
        self.inner.decrypt(msg, seq)
    }
}

// Cipher objects retain their expanded key schedules and zeroize them on drop.
#[allow(clippy::large_enum_variant, reason = "one fixed-size cipher per TLS direction avoids per-record allocation")]
enum Tls13Cipher {
    Aes128(aes_gcm::Aes128Gcm),
    Aes256(aes_gcm::Aes256Gcm),
    ChaCha(chacha20poly1305::ChaCha20Poly1305),
}
struct PaddedEncrypter { cipher: Tls13Cipher, iv: Iv }
impl MessageEncrypter for PaddedEncrypter {
    fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, seq: u64) -> Result<OutboundOpaqueMessage, Error> {
        self.encrypt_with_padding(msg, seq, 0)
    }
    fn encrypt_with_padding(&mut self, msg: OutboundPlainMessage<'_>, seq: u64, padding: usize) -> Result<OutboundOpaqueMessage, Error> {
        let length = msg.payload.len().checked_add(1).and_then(|v|v.checked_add(padding)).ok_or(Error::EncryptError)?;
        // RFC 8446: TLSInnerPlaintext is bounded by 2^14+1 bytes, including padding.
        if length > 16385 { return Err(Error::EncryptError); }
        let mut payload = PrefixedPayload::with_capacity(length+16);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        const ZEROS: [u8;256] = [0;256];
        let mut left=padding;
        while left!=0 { let count=left.min(ZEROS.len());payload.extend_from_slice(&ZEROS[..count]);left-=count; }
        let nonce=Nonce::new(&self.iv,seq).0;
        let aad=make_tls13_aad(length+16);
        let tag=match &self.cipher {
            Tls13Cipher::Aes128(cipher)=>cipher.encrypt_in_place_detached((&nonce).into(),&aad,payload.as_mut()),
            Tls13Cipher::Aes256(cipher)=>cipher.encrypt_in_place_detached((&nonce).into(),&aad,payload.as_mut()),
            Tls13Cipher::ChaCha(cipher)=>cipher.encrypt_in_place_detached((&nonce).into(),&aad,payload.as_mut()),
        }.map_err(|_|Error::EncryptError)?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(rustls::ContentType::ApplicationData,rustls::ProtocolVersion::TLSv1_2,payload))
    }
    fn encrypted_payload_len(&self, length:usize)->usize {length+17}
}

#[cfg(test)]
mod padding_tests {
    use super::*;
    use rustls::crypto::cipher::OutboundChunks;
    #[test]
    fn padded_records_roundtrip_at_boundaries_and_authenticate_zeros() {
        for suite in [&super::super::TLS13_AES_128_GCM_SHA256,&super::super::TLS13_AES_256_GCM_SHA384,&super::super::TLS13_CHACHA20_POLY1305_SHA256] {
            for padding in [0,1,255,256,8192,16381] {
                let make_cipher = || match suite.aead_alg.key_len() {
                    16 => Tls13Cipher::Aes128(aes_gcm::Aes128Gcm::new_from_slice(&[7;16]).unwrap()),
                    _ if suite.common.suite == rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => Tls13Cipher::Aes256(aes_gcm::Aes256Gcm::new_from_slice(&[7;32]).unwrap()),
                    _ => Tls13Cipher::ChaCha(chacha20poly1305::ChaCha20Poly1305::new_from_slice(&[7;32]).unwrap()),
                };
                let mut encrypt=PaddedEncrypter {cipher:make_cipher(),iv:Iv::from([4;12])};
                let message=||OutboundPlainMessage {typ:rustls::ContentType::ApplicationData,version:rustls::ProtocolVersion::TLSv1_2,payload:OutboundChunks::Single(b"abc")};
                let encrypted=encrypt.encrypt_with_padding(message(),17,padding).unwrap();
                let mut data=encrypted.payload.as_ref().to_vec();
                assert_eq!(data.len(),3+1+padding+16);
                let tag=data.split_off(data.len()-16);
                let mut nonce=[4u8;12];nonce[11]^=17;
                let aad=[23,3,3,((data.len()+16)>>8) as u8,(data.len()+16) as u8];
                let open=|data:&mut [u8]| match make_cipher() {
                    Tls13Cipher::Aes128(c)=>c.decrypt_in_place_detached((&nonce).into(),&aad,data,tag.as_slice().into()),
                    Tls13Cipher::Aes256(c)=>c.decrypt_in_place_detached((&nonce).into(),&aad,data,tag.as_slice().into()),
                    Tls13Cipher::ChaCha(c)=>c.decrypt_in_place_detached((&nonce).into(),&aad,data,tag.as_slice().into()),
                };
                let mut tampered=data.clone();tampered[3]^=1;assert!(open(&mut tampered).is_err());
                open(&mut data).unwrap();assert_eq!(&data[..4],b"abc\x17");assert!(data[4..].iter().all(|v|*v==0));
                assert!(encrypt.encrypt_with_padding(message(),19,usize::MAX).is_err());
                assert!(encrypt.encrypt_with_padding(message(),19,16382).is_err());
            }
        }
    }
}
