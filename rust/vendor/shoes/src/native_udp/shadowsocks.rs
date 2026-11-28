//! SIP004/007 and SIP022/023 datagram codecs. Replay state changes only after
//! successful authentication, header checks and association validation.
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use aerobox_primitives::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey},
    cipher::{
        AES_128, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
        UnboundCipherKey,
    },
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{AeadInPlace, KeyInit},
};
use parking_lot::Mutex;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{check_source, invalid};
use crate::{
    address::NetLocation,
    config::ShadowsocksConfig,
    shadowsocks::{DefaultKey, ShadowsocksCipher, ShadowsocksKey},
};

const RETAIN: Duration = Duration::from_secs(61);
const MAX_SALTS: usize = 65_536;
const MAX_SESSIONS: usize = 32;

pub(crate) struct Client {
    config: ShadowsocksConfig,
    salts: Arc<Mutex<SaltCache>>,
}
impl Client {
    pub(super) fn new(config: ShadowsocksConfig) -> io::Result<Self> {
        config.validate_keys()?;
        Ok(Self {
            config,
            salts: Arc::new(Mutex::new(SaltCache::default())),
        })
    }

    pub(super) fn session(&self) -> io::Result<Session> {
        let mode = match &self.config {
            ShadowsocksConfig::Legacy { cipher, password } => Mode::Legacy {
                cipher: *cipher,
                key: DefaultKey::new(password, cipher.key_len()),
                salts: self.salts.clone(),
            },
            ShadowsocksConfig::Aead2022 {
                cipher,
                key_bytes,
                identity_keys,
            } => Mode::Aead2022 {
                cipher: *cipher,
                key: Zeroizing::new(key_bytes.to_vec()),
                identities: identity_keys
                    .iter()
                    .map(|key| Zeroizing::new(key.to_vec()))
                    .collect(),
            },
        };
        let mut id = [0; 8];
        random(&mut id)?;
        Ok(Session {
            mode,
            id,
            counter: Some(0),
            servers: HashMap::new(),
        })
    }
}

enum Mode {
    Legacy {
        cipher: ShadowsocksCipher,
        key: DefaultKey,
        salts: Arc<Mutex<SaltCache>>,
    },
    Aead2022 {
        cipher: ShadowsocksCipher,
        key: Zeroizing<Vec<u8>>,
        identities: Vec<Zeroizing<Vec<u8>>>,
    },
}

pub(super) struct Session {
    mode: Mode,
    id: [u8; 8],
    counter: Option<u64>,
    servers: HashMap<[u8; 8], ServerSession>,
}

struct ServerSession {
    packets: ReplayWindow,
    last_seen: Instant,
}

impl Session {
    pub(super) fn encode(&mut self, target: &NetLocation, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.encode_at(target, payload, crate::clock::unix_seconds()?, random)
    }

    fn encode_at(
        &mut self,
        target: &NetLocation,
        payload: &[u8],
        now: u64,
        entropy: impl Fn(&mut [u8]) -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        let address = crate::socks_handler::write_location_to_vec(target)?;
        match &self.mode {
            Mode::Legacy { cipher, key, salts } => {
                let mut salt = vec![0; cipher.salt_len()];
                entropy(&mut salt)?;
                if !salts.lock().insert(&salt) {
                    return Err(invalid("Shadowsocks UDP salt cache capacity reached"));
                }
                let subkey = Zeroizing::new(key.create_session_key(&salt));
                let key = aead(*cipher, &subkey)?;
                let mut body = address;
                body.extend_from_slice(payload);
                key.seal_in_place_append_tag(
                    Nonce::assume_unique_for_key([0; 12]),
                    Aad::empty(),
                    &mut body,
                )
                .map_err(crypto_error)?;
                salt.extend_from_slice(&body);
                Ok(salt)
            }
            Mode::Aead2022 {
                cipher,
                key,
                identities,
            } => {
                let number = self
                    .counter
                    .ok_or_else(|| invalid("Shadowsocks UDP packet counter exhausted"))?;
                self.counter = number.checked_add(1);
                let mut separate = [0; 16];
                separate[..8].copy_from_slice(&self.id);
                separate[8..].copy_from_slice(&number.to_be_bytes());
                let mut body = Vec::with_capacity(11 + address.len() + payload.len());
                body.push(0);
                body.extend_from_slice(&now.to_be_bytes());
                body.extend_from_slice(&0_u16.to_be_bytes());
                body.extend_from_slice(&address);
                body.extend_from_slice(payload);
                if is_chacha(*cipher) {
                    let mut nonce = [0; 24];
                    entropy(&mut nonce)?;
                    let mut plaintext = separate.to_vec();
                    plaintext.extend_from_slice(&body);
                    let aead = XChaCha20Poly1305::new_from_slice(key).map_err(crypto_error)?;
                    let tag = aead
                        .encrypt_in_place_detached((&nonce).into(), &[], &mut plaintext)
                        .map_err(crypto_error)?;
                    let mut packet = nonce.to_vec();
                    packet.extend_from_slice(&plaintext);
                    packet.extend_from_slice(&tag);
                    Ok(packet)
                } else {
                    let mut packet = separate.to_vec();
                    encrypt_header(
                        *cipher,
                        identities
                            .first()
                            .map_or(key.as_slice(), |key| key.as_slice()),
                        &mut packet,
                    )?;
                    for (identity, next) in identities.iter().zip(
                        identities
                            .iter()
                            .skip(1)
                            .map(|key| key.as_slice())
                            .chain(std::iter::once(key.as_slice())),
                    ) {
                        let hash = blake3::hash(next);
                        let mut block = [0; 16];
                        for index in 0..16 {
                            block[index] = separate[index] ^ hash.as_bytes()[index];
                        }
                        encrypt_header(*cipher, identity, &mut block)?;
                        packet.extend_from_slice(&block);
                    }
                    let subkey = session_key(*cipher, key, &self.id);
                    aead(*cipher, &subkey)?
                        .seal_in_place_append_tag(
                            Nonce::try_assume_unique_for_key(&separate[4..])
                                .map_err(crypto_error)?,
                            Aad::empty(),
                            &mut body,
                        )
                        .map_err(crypto_error)?;
                    packet.extend_from_slice(&body);
                    Ok(packet)
                }
            }
        }
    }

    pub(super) fn decode(
        &mut self,
        target: &NetLocation,
        packet: &mut [u8],
    ) -> io::Result<Vec<u8>> {
        self.decode_at(target, packet, crate::clock::unix_seconds()?)
    }

    fn decode_at(
        &mut self,
        target: &NetLocation,
        packet: &mut [u8],
        now: u64,
    ) -> io::Result<Vec<u8>> {
        match &self.mode {
            Mode::Legacy { cipher, key, salts } => {
                if packet.len() < cipher.salt_len() + 16 + 5 {
                    return Err(invalid("short Shadowsocks UDP packet"));
                }
                let (salt, body) = packet.split_at_mut(cipher.salt_len());
                let subkey = Zeroizing::new(key.create_session_key(salt));
                let key = aead(*cipher, &subkey)?;
                let body = key
                    .open_in_place(Nonce::assume_unique_for_key([0; 12]), Aad::empty(), body)
                    .map_err(crypto_error)?;
                let (source, payload) = parse_address(body)?;
                check_source(target, &source)?;
                if !salts.lock().insert(salt) {
                    return Err(invalid("replayed Shadowsocks UDP salt"));
                }
                Ok(payload.to_vec())
            }
            Mode::Aead2022 { cipher, key, .. } => {
                let (separate, body) = if is_chacha(*cipher) {
                    if packet.len() < 24 + 16 + 19 + 5 + 16 {
                        return Err(invalid("short SS2022 ChaCha UDP packet"));
                    }
                    let (nonce, ciphertext) = packet.split_at_mut(24);
                    let length = ciphertext.len() - 16;
                    let (body, tag) = ciphertext.split_at_mut(length);
                    XChaCha20Poly1305::new_from_slice(key)
                        .map_err(crypto_error)?
                        .decrypt_in_place_detached((&*nonce).into(), &[], body, (&*tag).into())
                        .map_err(crypto_error)?;
                    let (header, body) = body.split_at_mut(16);
                    (<[u8; 16]>::try_from(&*header).unwrap(), body)
                } else {
                    if packet.len() < 16 + 19 + 5 + 16 {
                        return Err(invalid("short SS2022 AES UDP packet"));
                    }
                    let (header, body) = packet.split_at_mut(16);
                    decrypt_header(*cipher, key, header)?;
                    let separate = <[u8; 16]>::try_from(&*header).unwrap();
                    let subkey = session_key(*cipher, key, &separate[..8]);
                    let cipher = aead(*cipher, &subkey)?;
                    let body = cipher
                        .open_in_place(
                            Nonce::try_assume_unique_for_key(&separate[4..])
                                .map_err(crypto_error)?,
                            Aad::empty(),
                            body,
                        )
                        .map_err(crypto_error)?;
                    (separate, body)
                };
                let server_id: [u8; 8] = separate[..8].try_into().unwrap();
                let number = u64::from_be_bytes(separate[8..].try_into().unwrap());
                if server_id == self.id || body.len() < 19 || body[0] != 1 {
                    return Err(invalid("invalid SS2022 UDP response type or session"));
                }
                let timestamp = u64::from_be_bytes(body[1..9].try_into().unwrap());
                if timestamp.abs_diff(now) > 30 {
                    return Err(invalid("SS2022 UDP timestamp outside acceptance window"));
                }
                if !bool::from(self.id.ct_eq(&body[9..17])) {
                    return Err(invalid(
                        "SS2022 UDP response belongs to another client session",
                    ));
                }
                let padding = u16::from_be_bytes(body[17..19].try_into().unwrap()) as usize;
                let body = body
                    .get(19 + padding..)
                    .ok_or_else(|| invalid("SS2022 UDP padding exceeds packet"))?;
                let (source, payload) = parse_address(body)?;
                check_source(target, &source)?;
                self.servers
                    .retain(|_, server| server.last_seen.elapsed() < RETAIN);
                if !self.servers.contains_key(&server_id) && self.servers.len() >= MAX_SESSIONS {
                    return Err(invalid("SS2022 UDP server session limit reached"));
                }
                let server = self
                    .servers
                    .entry(server_id)
                    .or_insert_with(|| ServerSession {
                        packets: ReplayWindow::default(),
                        last_seen: Instant::now(),
                    });
                if !server.packets.insert(number) {
                    return Err(invalid("replayed or expired SS2022 UDP packet"));
                }
                server.last_seen = Instant::now();
                Ok(payload.to_vec())
            }
        }
    }
}

fn is_chacha(cipher: ShadowsocksCipher) -> bool {
    cipher.name() == "chacha20-ietf-poly1305"
}
fn random(bytes: &mut [u8]) -> io::Result<()> {
    aerobox_primitives::rand::fill(bytes).map_err(crypto_error)
}
fn crypto_error(_: impl std::fmt::Debug) -> io::Error {
    invalid("Shadowsocks UDP authentication or cryptographic operation failed")
}
fn aead(cipher: ShadowsocksCipher, key: &[u8]) -> io::Result<LessSafeKey> {
    UnboundKey::new(cipher.algorithm(), key)
        .map(LessSafeKey::new)
        .map_err(crypto_error)
}
fn session_key(cipher: ShadowsocksCipher, key: &[u8], session: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut hash = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hash.update(key);
    hash.update(session);
    let mut output = Zeroizing::new(vec![0; cipher.key_len()]);
    hash.finalize_xof().fill(&mut output);
    output
}
fn ecb_key(cipher: ShadowsocksCipher, key: &[u8]) -> io::Result<UnboundCipherKey> {
    UnboundCipherKey::new(
        if cipher.key_len() == 16 {
            &AES_128
        } else {
            &AES_256
        },
        key,
    )
    .map_err(crypto_error)
}
fn encrypt_header(cipher: ShadowsocksCipher, key: &[u8], header: &mut [u8]) -> io::Result<()> {
    EncryptingKey::ecb(ecb_key(cipher, key)?)
        .map_err(crypto_error)?
        .less_safe_encrypt(header, EncryptionContext::None)
        .map_err(crypto_error)
        .map(|_| ())
}
fn decrypt_header(cipher: ShadowsocksCipher, key: &[u8], header: &mut [u8]) -> io::Result<()> {
    DecryptingKey::ecb(ecb_key(cipher, key)?)
        .map_err(crypto_error)?
        .decrypt(header, DecryptionContext::None)
        .map_err(crypto_error)
        .map(|_| ())
}

fn parse_address(body: &[u8]) -> io::Result<(NetLocation, &[u8])> {
    // Reuse the checked RFC1928 parser; the three zero bytes are the SOCKS UDP
    // envelope omitted by Shadowsocks. The returned slice must borrow body.
    let mut envelope = Vec::with_capacity(body.len() + 3);
    envelope.extend_from_slice(&[0; 3]);
    envelope.extend_from_slice(body);
    let (source, payload) = crate::socks5_udp_relay::parse_socks5_udp_packet(&envelope)?;
    let start = body.len() - payload.len();
    Ok((source, &body[start..]))
}

#[derive(Default)]
struct SaltCache {
    order: VecDeque<(Instant, Vec<u8>)>,
    salts: HashSet<Vec<u8>>,
}
impl SaltCache {
    fn insert(&mut self, salt: &[u8]) -> bool {
        while self
            .order
            .front()
            .is_some_and(|(time, _)| time.elapsed() >= RETAIN)
        {
            self.salts.remove(&self.order.pop_front().unwrap().1);
        }
        if self.salts.len() >= MAX_SALTS || !self.salts.insert(salt.to_vec()) {
            return false;
        }
        self.order.push_back((Instant::now(), salt.to_vec()));
        true
    }
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; 16],
}
impl ReplayWindow {
    fn insert(&mut self, number: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(number);
            self.bits[0] = 1;
            return true;
        };
        if number > highest {
            let shift = number - highest;
            if shift >= 1024 {
                self.bits.fill(0);
            } else {
                let words = (shift / 64) as usize;
                let bits = (shift % 64) as u32;
                for index in (0..16).rev() {
                    self.bits[index] = if index < words {
                        0
                    } else {
                        (self.bits[index - words] << bits)
                            | if bits != 0 && index > words {
                                self.bits[index - words - 1] >> (64 - bits)
                            } else {
                                0
                            }
                    };
                }
            }
            self.highest = Some(number);
            self.bits[0] |= 1;
            true
        } else {
            let offset = highest - number;
            if offset >= 1024 {
                return false;
            }
            let word = &mut self.bits[(offset / 64) as usize];
            let bit = 1_u64 << (offset % 64);
            if *word & bit != 0 {
                return false;
            }
            *word |= bit;
            true
        }
    }
}

#[cfg(test)]
mod tests;
