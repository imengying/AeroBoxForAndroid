//! The TLS 1.0 / 1.1 PRF (RFC 2246 and RFC 4346 section 5).
//!
//! This combines P_MD5(S1, label || seed) XOR P_SHA1(S2, label || seed).
//! For an odd-sized secret its middle byte belongs to both halves. This is
//! deliberately separate from the SHA-256/SHA-384 TLS 1.2 PRFs. It is only
//! selected by an explicit legacy TLS provider, never by the normal provider.
use hmac::{Hmac, Mac};
use rustls::{
    Error,
    crypto::{ActiveKeyExchange, tls12::Prf},
};
use zeroize::Zeroizing;

/// TLS 1.0 and TLS 1.1 share the same split-secret PRF.
pub static TLS10_PRF: LegacyPrf = LegacyPrf;

/// Provider for the TLS 1.0 / 1.1 split-secret PRF.
#[derive(Debug)]
pub struct LegacyPrf;

impl Prf for LegacyPrf {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), Error> {
        // TLS 1.0/1.1 use the same ECDHE shared-secret encoding, and the same
        // leading-zero stripping for finite-field DH, as TLS 1.2. The legacy
        // handshake must separately restrict the negotiated key exchange.
        let secret = kx.complete_for_tls_version(peer_pub_key, &rustls::version::TLS12)?;
        self.for_secret(output, secret.secret_bytes(), label, seed);
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        let (first, second) = split_secret(secret);
        let md5 = <Hmac<md5::Md5> as Mac>::new_from_slice(first)
            .expect("HMAC accepts arbitrary key lengths");
        let sha1 = <Hmac<sha1::Sha1> as Mac>::new_from_slice(second)
            .expect("HMAC accepts arbitrary key lengths");
        output.fill(0);
        xor_p_hash(output, label, seed, |parts| {
            let mut mac = md5.clone();
            for part in parts {
                mac.update(part);
            }
            <[u8; 16]>::from(mac.finalize().into_bytes())
        });
        xor_p_hash(output, label, seed, |parts| {
            let mut mac = sha1.clone();
            for part in parts {
                mac.update(part);
            }
            <[u8; 20]>::from(mac.finalize().into_bytes())
        });
    }
}

fn split_secret(secret: &[u8]) -> (&[u8], &[u8]) {
    // Avoid len + 1 so even a theoretical maximum-sized slice cannot overflow.
    (
        &secret[..secret.len().div_ceil(2)],
        &secret[secret.len() / 2..],
    )
}

fn xor_p_hash<const N: usize>(
    output: &mut [u8],
    label: &[u8],
    seed: &[u8],
    hmac: impl Fn(&[&[u8]]) -> [u8; N],
) {
    let mut a = Zeroizing::new(hmac(&[label, seed]));
    for chunk in output.chunks_mut(N) {
        let term = Zeroizing::new(hmac(&[a.as_ref(), label, seed]));
        for (byte, mask) in chunk.iter_mut().zip(term.iter()) {
            *byte ^= mask;
        }
        *a = hmac(&[a.as_ref()]);
    }
    // Only fixed-size intermediates are retained; output length does not cause
    // another secret-sized allocation. Owned A/term buffers are wiped. The
    // digest 0.10/HMAC implementation does not wipe its internal hash state.
}

#[cfg(test)]
mod tests;
