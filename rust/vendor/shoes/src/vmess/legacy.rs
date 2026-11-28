//! Legacy VMess authentication and CFB128, kept independent of payload AEAD.
//! Wire behavior follows sing-vmess a0c58542bd9d; all cryptography uses Rust.

use aerobox_primitives::cipher::{AES_128, EncryptingKey, EncryptionContext, UnboundCipherKey};

use super::md5::compute_md5;

/// CFB128 is a continuous byte stream: the feedback block and its cursor must
/// survive arbitrary network chunking. AES encryption is used in both directions.
pub(super) struct Cfb128 {
    cipher: EncryptingKey,
    feedback: [u8; 16],
    offset: usize,
}

impl Cfb128 {
    pub(super) fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: EncryptingKey::ecb(UnboundCipherKey::new(&AES_128, key).unwrap()).unwrap(),
            feedback: *iv,
            offset: 0,
        }
    }

    pub(super) fn encrypt(&mut self, bytes: &mut [u8]) {
        self.apply(bytes, false);
    }

    pub(super) fn decrypt(&mut self, bytes: &mut [u8]) {
        self.apply(bytes, true);
    }

    fn apply(&mut self, bytes: &mut [u8], decrypt: bool) {
        for byte in bytes {
            if self.offset == 0 {
                self.cipher
                    .less_safe_encrypt(&mut self.feedback, EncryptionContext::None)
                    .expect("one initialized AES block");
            }
            let input = *byte;
            *byte ^= self.feedback[self.offset];
            self.feedback[self.offset] = if decrypt { input } else { *byte };
            self.offset = (self.offset + 1) & 15;
        }
    }
}

pub(super) fn alter_id(user: &[u8; 16]) -> [u8; 16] {
    let mut material = user.to_vec();
    material.extend_from_slice(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    loop {
        let derived = compute_md5(&material);
        if derived != *user {
            return derived;
        }
        material.extend_from_slice(b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2");
    }
}

fn authentication(alter: &[u8; 16], timestamp: u64) -> [u8; 16] {
    // HMAC-MD5 with a fixed 16-byte key, RFC 2104's 64-byte MD5 block size.
    let mut inner = [0x36u8; 72];
    let mut outer = [0x5cu8; 80];
    for (index, byte) in alter.iter().enumerate() {
        inner[index] ^= byte;
        outer[index] ^= byte;
    }
    inner[64..].copy_from_slice(&timestamp.to_be_bytes());
    outer[64..].copy_from_slice(&compute_md5(&inner));
    compute_md5(&outer)
}

pub(super) fn seal_request(
    instruction_key: &[u8; 16],
    alter: &[u8; 16],
    timestamp: u64,
    header: &[u8],
) -> Vec<u8> {
    let mut repeated_time = [0u8; 32];
    for chunk in repeated_time.chunks_exact_mut(8) {
        chunk.copy_from_slice(&timestamp.to_be_bytes());
    }
    let mut output = Vec::with_capacity(16 + header.len());
    output.extend_from_slice(&authentication(alter, timestamp));
    output.extend_from_slice(header);
    Cfb128::new(instruction_key, &compute_md5(&repeated_time)).encrypt(&mut output[16..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn cfb128_matches_nist_vector_under_every_fragment_size() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let iv = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let plain = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let expected = hex(concat!(
            "3b3fd92eb72dad20333449f8e83cfb4a",
            "c8a64537a0b3a93fcde3cdad9f1ce58b",
            "26751f67a3cbb140b1808cf187a4f4df",
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        ));
        for length in 1..=plain.len() {
            let mut encrypted = plain.clone();
            let mut cipher = Cfb128::new(&key, &iv);
            for chunk in encrypted.chunks_mut(length) {
                cipher.encrypt(chunk);
            }
            assert_eq!(encrypted, expected, "fragment {length}");
            let mut cipher = Cfb128::new(&key, &iv);
            for chunk in encrypted.chunks_mut(plain.len() + 1 - length) {
                cipher.decrypt(chunk);
            }
            assert_eq!(encrypted, plain, "fragment {length}");
        }
    }

    #[test]
    fn authentication_matches_independent_md5_hmac_vector() {
        let user = hex("d9ad4eabf118492ba99be0e27332b4b2").try_into().unwrap();
        let alter = alter_id(&user);
        assert_eq!(alter.as_slice(), hex("b8f8b8b2d926a31b12680b0540917f83"));
        assert_eq!(
            authentication(&alter, 1_700_000_000).as_slice(),
            hex("9bcd7d88089ea9b83c9fb6325889b3b1")
        );
        let key = [11; 16];
        let header: Vec<_> = (0..254).collect();
        let request = seal_request(&key, &alter, 1_700_000_000, &header);
        let mut plain = request[16..].to_vec();
        let iv = hex("7a29d7bdc972aaefb1f54e5205589e78").try_into().unwrap();
        Cfb128::new(&key, &iv).decrypt(&mut plain);
        assert_eq!(plain, header);
    }
}
