//! Combined MD5 || SHA-1 handshake hash for explicitly enabled TLS 1.0/1.1.
//!
//! Finished, extended master secret, and legacy RSA CertificateVerify use
//! these 36 bytes in this order. Legacy ECDSA uses only the final 20 bytes.
//! No transcript is buffered here: forkable digest states bound memory use.
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha1::Digest;

/// The combined MD5/SHA-1 hash, with an internal, non-wire algorithm marker.
pub static MD5_SHA1: Md5Sha1 = Md5Sha1;

/// Provider for the combined pre-TLS-1.2 handshake hash.
#[derive(Debug)]
pub struct Md5Sha1;

impl Hash for Md5Sha1 {
    fn start(&self) -> Box<dyn Context> {
        Box::new(State::default())
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&digest(&[data]))
    }

    fn output_len(&self) -> usize {
        36
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::MD5_SHA1
    }
}

/// Hash ordered message fragments without concatenating or buffering them.
/// For ServerKeyExchange these are client_random, server_random, and params.
pub fn digest(parts: &[&[u8]]) -> [u8; 36] {
    let mut state = State::default();
    for part in parts {
        state.update(part);
    }
    state.finish_bytes()
}

#[derive(Clone, Default)]
struct State {
    md5: md5::Md5,
    sha1: sha1::Sha1,
}

impl State {
    fn finish_bytes(self) -> [u8; 36] {
        let mut result = [0u8; 36];
        result[..16].copy_from_slice(&self.md5.finalize());
        result[16..].copy_from_slice(&self.sha1.finalize());
        result
    }
}

impl Context for State {
    fn fork_finish(&self) -> Output {
        Output::new(&self.clone().finish_bytes())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&(*self).finish_bytes())
    }

    fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.sha1.update(data);
    }
}

#[cfg(test)]
mod tests;
