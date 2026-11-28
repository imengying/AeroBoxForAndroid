use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result, bail, ensure};
use aerobox_primitives::{aead, hkdf, rand};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_proto::rr::Name;
use zeroize::Zeroizing;

use crate::names::{canonical_name, canonical_wire, entry_name, validate_label};

pub const PREFIX: &str = "td1.";
pub const MAX_PLAINTEXT: usize = 4096;
pub const MAX_ENTRIES: usize = 256;
pub const MAX_ENCODED: usize = 5504;
pub const CLOCK_SKEW: u64 = 60;

pub struct Secret(Zeroizing<[u8; 32]>);

impl Secret {
    pub fn decode(value: &str) -> Result<Self> {
        let bytes =
            Zeroizing::new(URL_SAFE_NO_PAD.decode(value).map_err(|_| {
                anyhow::anyhow!("key must be 32 bytes encoded as unpadded base64url")
            })?);
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("key must contain exactly 32 bytes"))?;
        Ok(Self(Zeroizing::new(key)))
    }

    pub fn generate() -> Result<String> {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::fill(key.as_mut()).map_err(|_| anyhow::anyhow!("OS random generator failed"))?;
        Ok(URL_SAFE_NO_PAD.encode(key.as_ref()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub subdomain: String,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    pub issued_at: u64,
    pub expires_at: u64,
    pub entries: Vec<Entry>,
}

impl Publication {
    pub fn validate(&self, owner: &Name) -> Result<()> {
        ensure!(
            self.expires_at > self.issued_at,
            "expiry must follow issuance"
        );
        ensure!(
            !self.entries.is_empty() && self.entries.len() <= MAX_ENTRIES,
            "publication must contain 1-256 entries"
        );
        let mut owners: HashMap<&str, (usize, bool)> = HashMap::new();
        for entry in &self.entries {
            if !entry.subdomain.is_empty() {
                validate_label(&entry.subdomain)?;
                ensure!(
                    entry.subdomain == entry.subdomain.to_ascii_lowercase(),
                    "subdomain must be lowercase"
                );
            }
            entry_name(owner, &entry.subdomain)?;
            let (entry_count, has_cname) = owners.entry(&entry.subdomain).or_default();
            *entry_count += 1;
            if let Value::Cname(target) = &entry.value {
                ensure!(
                    canonical_name(&target.to_ascii())? == *target && target.is_fqdn(),
                    "CNAME target must be absolute"
                );
                *has_cname = true;
            }
            ensure!(
                !*has_cname || *entry_count == 1,
                "CNAME must be the only entry for its hostname"
            );
        }
        Ok(())
    }

    pub fn validate_time(&self, now: u64) -> Result<()> {
        ensure!(self.expires_at > now, "publication has expired");
        ensure!(
            self.issued_at <= now.saturating_add(CLOCK_SKEW),
            "publication issued in the future"
        );
        Ok(())
    }

    pub fn encode(&self, owner: &Name) -> Result<Vec<u8>> {
        self.validate(owner)?;
        let mut bytes = Vec::new();
        bytes.extend(self.issued_at.to_be_bytes());
        bytes.extend(self.expires_at.to_be_bytes());
        for entry in &self.entries {
            bytes.push(match entry.value {
                Value::A(_) => 0,
                Value::Aaaa(_) => 1,
                Value::Cname(_) => 2,
            });
            bytes.push(entry.subdomain.len() as u8);
            bytes.extend(entry.subdomain.as_bytes());
            match &entry.value {
                Value::A(ip) => bytes.extend(ip.octets()),
                Value::Aaaa(ip) => bytes.extend(ip.octets()),
                Value::Cname(target) => {
                    let target = target.to_lowercase().to_ascii();
                    bytes.extend((target.len() as u16).to_be_bytes());
                    bytes.extend(target.as_bytes());
                }
            }
        }
        ensure!(
            bytes.len() <= MAX_PLAINTEXT,
            "publication exceeds 4096 bytes"
        );
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], owner: &Name) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_PLAINTEXT,
            "publication exceeds 4096 bytes"
        );
        let mut cursor = Cursor(bytes);
        let issued_at = u64::from_be_bytes(cursor.array()?);
        let expires_at = u64::from_be_bytes(cursor.array()?);
        let mut entries = Vec::new();
        while !cursor.0.is_empty() {
            ensure!(entries.len() < MAX_ENTRIES, "too many entries");
            let kind = cursor.array::<1>()?[0];
            let subdomain_len = cursor.array::<1>()?[0] as usize;
            let subdomain = std::str::from_utf8(cursor.take(subdomain_len)?)
                .context("invalid subdomain")?
                .to_owned();
            let value = match kind {
                0 => Value::A(Ipv4Addr::from(cursor.array::<4>()?)),
                1 => Value::Aaaa(Ipv6Addr::from(cursor.array::<16>()?)),
                2 => {
                    let target_len = u16::from_be_bytes(cursor.array()?) as usize;
                    let target =
                        std::str::from_utf8(cursor.take(target_len)?).context("invalid CNAME")?;
                    ensure!(target.ends_with('.'), "CNAME target must be absolute");
                    Value::Cname(canonical_name(target)?)
                }
                _ => bail!("unsupported entry type"),
            };
            entries.push(Entry { subdomain, value });
        }
        let result = Self {
            issued_at,
            expires_at,
            entries,
        };
        result.validate(owner)?;
        Ok(result)
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= len, "truncated publication");
        let (value, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("checked length"))
    }
}

fn key(secret: &Secret, owner: &Name) -> Result<aead::LessSafeKey> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"tendns/td1");
    let prk = salt.extract(secret.0.as_ref());
    let wire = canonical_wire(owner);
    let info = [b"aes-256-gcm-siv".as_slice(), wire.as_slice()];
    let okm = prk
        .expand(&info, hkdf::HKDF_SHA256)
        .map_err(|_| anyhow::anyhow!("key derivation failed"))?;
    let mut material = Zeroizing::new([0; 32]);
    okm.fill(material.as_mut()).map_err(|_| anyhow::anyhow!("key derivation failed"))?;
    Ok(aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM_SIV, material.as_ref())?))
}

fn aad(owner: &Name) -> Vec<u8> {
    let mut bytes = b"tendns/td1\0".to_vec();
    bytes.extend(canonical_wire(owner));
    bytes
}

pub fn encrypt(publication: &Publication, secret: &Secret, owner: &Name) -> Result<String> {
    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce).map_err(|_| anyhow::anyhow!("OS random generator failed"))?;
    encrypt_with_nonce(publication, secret, owner, nonce)
}

fn encrypt_with_nonce(
    publication: &Publication,
    secret: &Secret,
    owner: &Name,
    nonce: [u8; 12],
) -> Result<String> {
    let mut plaintext = Zeroizing::new(publication.encode(owner)?);
    let tag = key(secret, owner)?
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(owner)),
            &mut plaintext,
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut bytes = nonce.to_vec();
    bytes.extend(plaintext.iter());
    bytes.extend(tag.as_ref());
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

pub fn decrypt(value: &[u8], secret: &Secret, owner: &Name, now: u64) -> Result<Publication> {
    let publication = decrypt_for_update(value, secret, owner)?;
    publication.validate_time(now)?;
    Ok(publication)
}

// Administrative updates must authenticate expired publications without renewing them implicitly.
pub(crate) fn decrypt_for_update(
    value: &[u8],
    secret: &Secret,
    owner: &Name,
) -> Result<Publication> {
    ensure!(value.len() <= MAX_ENCODED, "TXT value too large");
    let encoded = value
        .strip_prefix(PREFIX.as_bytes())
        .context("unsupported TXT version")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("invalid TXT encoding")?;
    ensure!(bytes.len() >= 12 + 16 + 16, "truncated TXT value");
    let nonce: [u8; 12] = bytes[..12].try_into().expect("checked length");
    let mut encrypted = Zeroizing::new(bytes[12..].to_vec());
    let plaintext = key(secret, owner)?
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(owner)),
            &mut encrypted,
        )
        .map_err(|_| anyhow::anyhow!("TXT authentication failed"))?;
    Publication::decode(plaintext, owner)
}

pub(crate) fn is_encrypted_txt(value: &[u8]) -> bool {
    let prefix = value.split(|byte| *byte == b'.').next().unwrap_or_default();
    prefix
        .strip_prefix(b"td")
        .is_some_and(|version| !version.is_empty() && version.iter().all(u8::is_ascii_digit))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Name, Secret, Publication) {
        (
            canonical_name("example.com").unwrap(),
            Secret::decode(&URL_SAFE_NO_PAD.encode([7u8; 32])).unwrap(),
            Publication {
                issued_at: 100,
                expires_at: 200,
                entries: vec![
                    Entry {
                        subdomain: String::new(),
                        value: Value::A("192.0.2.1".parse().unwrap()),
                    },
                    Entry {
                        subdomain: "nas".into(),
                        value: Value::Aaaa("2001:db8::1".parse().unwrap()),
                    },
                    Entry {
                        subdomain: "www".into(),
                        value: Value::Cname(canonical_name("target.example").unwrap()),
                    },
                ],
            },
        )
    }

    #[test]
    fn wire_roundtrip_and_fixed_layout() {
        let (owner, _, publication) = fixture();
        let bytes = publication.encode(&owner).unwrap();
        assert_eq!(
            &bytes[..22],
            &[
                0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 192, 0, 2, 1
            ]
        );
        assert_eq!(Publication::decode(&bytes, &owner).unwrap(), publication);
        for len in 0..22 {
            assert!(Publication::decode(&bytes[..len], &owner).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(255);
        assert!(Publication::decode(&bad, &owner).is_err());
    }

    #[test]
    fn authenticated_roundtrip_and_tampering() {
        let (owner, secret, publication) = fixture();
        let value = encrypt_with_nonce(&publication, &secret, &owner, [3; 12]).unwrap();
        assert_eq!(
            value,
            "td1.AwMDAwMDAwMDAwMDQdMzX-MqaK8AttXVYBgv3F5VwtrJJZtaCQGzQVXnc30ikXeWrO5MxidyTgpQGtbOi2nbg6HdfzAzgNpoH_omme2f3loM7fyWCbp_4qa8YC3e"
        );
        assert_eq!(
            decrypt(
                value.as_bytes(),
                &secret,
                &canonical_name("EXAMPLE.COM.").unwrap(),
                100
            )
            .unwrap(),
            publication
        );
        assert!(
            decrypt(
                value.as_bytes(),
                &secret,
                &canonical_name("other.com").unwrap(),
                100
            )
            .is_err()
        );
        let wrong = Secret::decode(&URL_SAFE_NO_PAD.encode([8; 32])).unwrap();
        assert!(decrypt(value.as_bytes(), &wrong, &owner, 100).is_err());
        let bytes = URL_SAFE_NO_PAD.decode(&value[4..]).unwrap();
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            let bad = format!("td1.{}", URL_SAFE_NO_PAD.encode(bad));
            assert!(decrypt(bad.as_bytes(), &secret, &owner, 100).is_err());
        }
        assert!(
            decrypt(
                value.replacen("td1", "td2", 1).as_bytes(),
                &secret,
                &owner,
                100
            )
            .is_err()
        );
        assert!(decrypt(format!("{value}=").as_bytes(), &secret, &owner, 100).is_err());
        assert!(decrypt(value.as_bytes(), &secret, &owner, 200).is_err());
        assert!(decrypt(value.as_bytes(), &secret, &owner, 39).is_err());
        assert!(decrypt(value.as_bytes(), &secret, &owner, 40).is_ok());
    }

    #[test]
    fn independent_nonce_and_siv_reuse() {
        let (owner, secret, mut publication) = fixture();
        assert_ne!(
            encrypt(&publication, &secret, &owner).unwrap(),
            encrypt(&publication, &secret, &owner).unwrap()
        );
        let one = encrypt_with_nonce(&publication, &secret, &owner, [0; 12]).unwrap();
        publication.entries[0].value = Value::A("192.0.2.2".parse().unwrap());
        let two = encrypt_with_nonce(&publication, &secret, &owner, [0; 12]).unwrap();
        assert_ne!(one, two);
        assert_eq!(
            decrypt(two.as_bytes(), &secret, &owner, 100).unwrap(),
            publication
        );
    }

    #[test]
    fn invalid_publications_and_parser_bounds() {
        let (owner, _, mut publication) = fixture();
        publication.entries.push(Entry {
            subdomain: "www".into(),
            value: Value::A(Ipv4Addr::LOCALHOST),
        });
        assert!(publication.encode(&owner).is_err());
        publication.entries.reverse();
        assert!(publication.encode(&owner).is_err());
        for len in 0..512 {
            let bytes: Vec<_> = (0..len).map(|i| ((i * 131 + len) % 256) as u8).collect();
            let _ = Publication::decode(&bytes, &owner);
        }
        assert!(Publication::decode(&[0; MAX_PLAINTEXT + 1], &owner).is_err());
    }

    #[test]
    fn long_cname_and_name_length_limits() {
        let (owner, secret, mut publication) = fixture();
        let target = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let target = canonical_name(&target).unwrap();
        publication.entries = vec![Entry {
            subdomain: String::new(),
            value: Value::Cname(target.clone()),
        }];
        let encoded = encrypt(&publication, &secret, &owner).unwrap();
        assert!(encoded.len() > 255);
        assert_eq!(
            decrypt(encoded.as_bytes(), &secret, &owner, 100).unwrap(),
            publication
        );
        publication.entries[0].subdomain = "a".into();
        assert!(publication.encode(&target).is_err());
        publication.entries[0].subdomain = "a.b".into();
        assert!(publication.encode(&owner).is_err());
    }

    #[test]
    fn every_entry_type_rejects_partial_encoding() {
        let (owner, _, publication) = fixture();
        for entry in publication.entries {
            let one = Publication {
                issued_at: 100,
                expires_at: 200,
                entries: vec![entry],
            };
            let bytes = one.encode(&owner).unwrap();
            for end in 0..bytes.len() {
                assert!(
                    Publication::decode(&bytes[..end], &owner).is_err(),
                    "entry {:?}, prefix {end}",
                    one.entries[0]
                );
            }
            assert_eq!(Publication::decode(&bytes, &owner).unwrap(), one);
        }
    }

    #[test]
    fn malformed_entry_fields_are_rejected() {
        let (owner, _, _) = fixture();
        let header = [100u64.to_be_bytes(), 200u64.to_be_bytes()].concat();
        for (label, entry) in [
            ("unknown type", vec![3, 0]),
            ("invalid UTF-8 label", vec![0, 1, 255, 192, 0, 2, 1]),
            ("uppercase label", vec![0, 1, b'A', 192, 0, 2, 1]),
            ("dotted label", vec![0, 3, b'a', b'.', b'b', 192, 0, 2, 1]),
            ("relative CNAME", vec![2, 0, 0, 3, b'a', b'.', b'b']),
            ("empty CNAME", vec![2, 0, 0, 0]),
            ("invalid UTF-8 CNAME", vec![2, 0, 0, 2, 255, b'.']),
            ("overstated CNAME length", vec![2, 0, 255, 255, b'a', b'.']),
        ] {
            assert!(
                Publication::decode(&[header.as_slice(), &entry].concat(), &owner).is_err(),
                "{label}"
            );
        }
        assert!(Publication::decode(&header, &owner).is_err());
    }

    #[test]
    fn size_and_entry_limits_accept_the_boundary_only() {
        let (owner, secret, mut publication) = fixture();
        let entry = publication.entries[0].clone();
        publication.entries = vec![entry.clone(); MAX_ENTRIES];
        let mut encoded = publication.encode(&owner).unwrap();
        assert_eq!(
            Publication::decode(&encoded, &owner).unwrap().entries.len(),
            MAX_ENTRIES
        );
        publication.entries.push(entry);
        assert!(publication.encode(&owner).is_err());
        encoded.extend([0, 0, 192, 0, 2, 1]);
        assert!(Publication::decode(&encoded, &owner).is_err());

        publication.entries = vec![
            Entry {
                subdomain: "abcdefghij".into(),
                value: Value::A(Ipv4Addr::LOCALHOST)
            };
            255
        ];
        assert_eq!(publication.encode(&owner).unwrap().len(), MAX_PLAINTEXT);
        let encrypted = encrypt(&publication, &secret, &owner).unwrap();
        assert!(encrypted.len() <= MAX_ENCODED);
        assert_eq!(
            decrypt(encrypted.as_bytes(), &secret, &owner, 100).unwrap(),
            publication
        );
        publication.entries[0].subdomain.push('k');
        assert!(publication.encode(&owner).is_err());
        assert!(decrypt(&vec![b'a'; MAX_ENCODED + 1], &secret, &owner, 100).is_err());
    }

    #[test]
    fn timestamp_and_label_boundaries_are_enforced() {
        let (owner, _, mut publication) = fixture();
        for expiry in [0, 99, 100] {
            publication.expires_at = expiry;
            assert!(publication.encode(&owner).is_err(), "expiry {expiry}");
        }
        publication.expires_at = 200;
        for (now, valid) in [
            (39, false),
            (40, true),
            (199, true),
            (200, false),
            (u64::MAX, false),
        ] {
            assert_eq!(publication.validate_time(now).is_ok(), valid, "now {now}");
        }
        publication.entries.truncate(1);
        publication.entries[0].subdomain = "a".repeat(63);
        assert!(publication.encode(&owner).is_ok());
        publication.entries[0].subdomain.push('a');
        assert!(publication.encode(&owner).is_err());
    }

    #[test]
    fn authentication_and_plaintext_validation_are_independent() {
        let (owner, secret, _) = fixture();
        let nonce = [0; 12];
        let mut malformed = [100u64.to_be_bytes(), 200u64.to_be_bytes()].concat();
        malformed.extend([3, 0]);
        key(&secret, &owner)
            .unwrap()
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad(&owner)),
                &mut malformed,
            )
            .unwrap();
        let envelope = format!(
            "td1.{}",
            URL_SAFE_NO_PAD.encode([nonce.as_slice(), &malformed].concat())
        );
        assert_eq!(
            decrypt(envelope.as_bytes(), &secret, &owner, 100)
                .unwrap_err()
                .to_string(),
            "unsupported entry type"
        );

        let (_, _, publication) = fixture();
        let mut body = publication.encode(&owner).unwrap();
        key(&secret, &owner)
            .unwrap()
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(b"wrong protocol context"),
                &mut body,
            )
            .unwrap();
        let envelope = format!(
            "td1.{}",
            URL_SAFE_NO_PAD.encode([nonce.as_slice(), &body].concat())
        );
        assert_eq!(
            decrypt(envelope.as_bytes(), &secret, &owner, 100)
                .unwrap_err()
                .to_string(),
            "TXT authentication failed"
        );
    }

    #[test]
    fn secrets_require_exact_length_and_canonical_base64url() {
        for value in [
            String::new(),
            URL_SAFE_NO_PAD.encode([0; 31]),
            URL_SAFE_NO_PAD.encode([0; 33]),
            format!("{}=", URL_SAFE_NO_PAD.encode([0; 32])),
            "!".repeat(43),
        ] {
            assert!(Secret::decode(&value).is_err());
        }
    }
}
