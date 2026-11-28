use std::pin::Pin;
use std::task::{Context, Poll};

use aerobox_primitives::aead::{AES_128_GCM, Aad, BoundKey, OpeningKey, SealingKey, UnboundKey};
use bytes::BytesMut;
use digest::XofReader;
use futures::ready;
use log::warn;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::nonce::{SingleUseNonce, VmessNonceSequence};
use super::typed::VmessReader;

use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};
use crate::util::allocate_vec;
// this should be the same as vmess_handler.rs TAG_LEN.
const HEADER_TAG_LEN: usize = 16;
const ENCRYPTION_TAG_LEN: usize = 16;
const MAX_PADDING_LEN: usize = 64;

// Use 8192 + tag (8208) so plaintext chunk is 8192 bytes, matching Xray-core.
// (Previously was 2^14 - 1 = 16383 due to quantumult bug workaround)
// Reducing the size fixed a hanging issue with sing-box client on mobile
const MAX_ENCRYPTED_WRITE_DATA_SIZE: usize = 8192 + ENCRYPTION_TAG_LEN;

// although the dev docs say that the max data segment is 2^14, seems like
// some clients (like surge pre-aead) send up to 65535 bytes in a packet.
// we need to be able to handle this much data, even if we always write
// at most MAX_ENCRYPTED_WRITE_DATA_SIZE in a packet.
const MAX_ENCRYPTED_READ_DATA_SIZE: usize = u16::MAX as usize;

struct LengthMask {
    reader: VmessReader,
    mask: [u8; 2],
    enable_padding: bool,
}

impl LengthMask {
    fn new(reader: VmessReader, enable_padding: bool) -> Self {
        Self {
            reader,
            mask: [0u8; 2],
            enable_padding,
        }
    }

    fn next_u16(&mut self) -> u16 {
        self.reader.read(&mut self.mask);
        ((self.mask[0] as u16) << 8) | (self.mask[1] as u16)
    }

    fn next_values(&mut self) -> (usize, u16) {
        // returns the next padding and length mask
        let padding = if self.enable_padding {
            (self.next_u16() % (MAX_PADDING_LEN as u16)) as usize
        } else {
            0
        };

        (padding, self.next_u16())
    }
}

enum ShutdownState {
    WriteRemainingData,
    WriteEmptyPacket,
    PollShutdown,
}

pub struct VmessStream {
    stream: Box<dyn AsyncStream>,
    is_udp: bool,

    read_header_state: ReadHeaderState,
    read_header_info: Option<ReadHeaderInfo>,

    opening_key: Option<OpeningKey<VmessNonceSequence>>,
    sealing_key: Option<SealingKey<VmessNonceSequence>>,
    tag_len: usize,
    read_cfb: Option<super::legacy::Cfb128>,
    write_cfb: Option<super::legacy::Cfb128>,
    legacy_response_cfb: Option<super::legacy::Cfb128>,
    raw_body: bool,
    read_length_mask: Option<LengthMask>,
    write_length_mask: Option<LengthMask>,
    read_length_key: Option<OpeningKey<VmessNonceSequence>>,
    write_length_key: Option<SealingKey<VmessNonceSequence>>,

    unprocessed_buf: Box<[u8]>,
    unprocessed_start_offset: usize,
    unprocessed_end_offset: usize,
    unprocessed_pending_len: Option<(usize, usize)>,

    processed_buf: Box<[u8]>,
    processed_start_offset: usize,
    processed_end_offset: usize,
    processed_empty_message: bool,

    write_cache: Box<[u8]>,
    write_cache_size: usize,

    write_packet: Box<[u8]>,
    write_packet_start_offset: usize,
    write_packet_end_offset: usize,

    // Response header bytes to write on first poll_write (server mode).
    pending_prefix_write: Option<BytesMut>,

    shutdown_state: ShutdownState,
    is_eof: bool,
    read_failure: Option<(std::io::ErrorKind, String)>,
}

enum DecryptState {
    NeedData,
    BufferFull,
    Success,
    ReceivedEof,
}

// Expected VMess header response, when we're a client.
pub struct ReadHeaderInfo {
    pub response_header_key: [u8; 16],
    pub response_header_iv: [u8; 16],
    pub response_authentication_v: u8,
}

#[derive(PartialEq, Eq, Debug)]
enum ReadHeaderState {
    ReadAeadLength,
    ReadAeadContent(usize),
    ReadLegacy,
    ReadLegacyCommand(usize),
    Done,
}

fn check_header_response(
    response_header_bytes: &[u8],
    response_authentication_v: u8,
) -> std::io::Result<()> {
    if response_header_bytes[0] != response_authentication_v {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Invalid response auth value, expected {}, got {}",
                response_authentication_v, response_header_bytes[0]
            ),
        ));
    }

    // ignore the option byte at response_header_bytes[1], since we don't do reuse of tcp
    // connections.
    if (response_header_bytes[2] & 0x01) == 0x01 {
        warn!("Ignoring unsupported server dynamic port instructions.");
    }
    Ok(())
}

impl VmessStream {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stream: Box<dyn AsyncStream>,
        is_udp: bool,
        encryption_keys: Option<(
            OpeningKey<VmessNonceSequence>,
            SealingKey<VmessNonceSequence>,
        )>,
        read_length_shake_reader: Option<VmessReader>,
        write_length_shake_reader: Option<VmessReader>,
        enable_global_padding: bool,
        prefix_write_bytes: Option<BytesMut>,
        read_header_info: Option<ReadHeaderInfo>,
    ) -> Self {
        let (tag_len, opening_key, sealing_key) = match encryption_keys {
            Some((opening_key, sealing_key)) => {
                (ENCRYPTION_TAG_LEN, Some(opening_key), Some(sealing_key))
            }
            None => (0, None, None),
        };

        let max_unencrypted_read_data_size = MAX_ENCRYPTED_READ_DATA_SIZE - tag_len;
        let max_unencrypted_write_data_size = MAX_ENCRYPTED_WRITE_DATA_SIZE - tag_len;

        const MAX_READ_PACKET_SIZE: usize = MAX_ENCRYPTED_READ_DATA_SIZE + 18;
        let unprocessed_buf = allocate_vec(MAX_READ_PACKET_SIZE).into_boxed_slice();
        let processed_buf = allocate_vec(max_unencrypted_read_data_size).into_boxed_slice();

        let (write_cache, write_packet) = if !is_udp {
            let write_cache = allocate_vec(max_unencrypted_write_data_size).into_boxed_slice();
            const MAX_WRITE_PACKET_SIZE: usize = MAX_ENCRYPTED_WRITE_DATA_SIZE + 18;
            // we need to be able to send a full packet, and the prefix (response) data all
            // at once. the response is relatively small, check vmess_handler.
            let write_packet = allocate_vec(MAX_WRITE_PACKET_SIZE + 40).into_boxed_slice();

            (write_cache, write_packet)
        } else {
            // write_message can be called with a full UDP message, which we need to handle,
            // i.e. packetize into multiple packets and store in write_packet.
            let write_cache = allocate_vec(65535).into_boxed_slice();

            let write_packet_size = 65535
                + (65535usize.div_ceil(max_unencrypted_write_data_size)
                    * (MAX_PADDING_LEN * ENCRYPTION_TAG_LEN));
            let write_packet = allocate_vec(write_packet_size + 40).into_boxed_slice();

            (write_cache, write_packet)
        };

        let read_header_state = match read_header_info {
            Some(_) => ReadHeaderState::ReadAeadLength,
            None => ReadHeaderState::Done,
        };

        Self {
            stream,
            is_udp,
            read_header_state,
            read_header_info,
            opening_key,
            sealing_key,
            tag_len,
            read_cfb: None,
            write_cfb: None,
            legacy_response_cfb: None,
            raw_body: false,
            read_length_key: None,
            write_length_key: None,
            read_length_mask: read_length_shake_reader
                .map(|reader| LengthMask::new(reader, enable_global_padding)),
            write_length_mask: write_length_shake_reader
                .map(|reader| LengthMask::new(reader, enable_global_padding)),
            unprocessed_buf,
            unprocessed_start_offset: 0,
            unprocessed_end_offset: 0,
            unprocessed_pending_len: None,
            processed_buf,
            processed_start_offset: 0,
            processed_end_offset: 0,
            processed_empty_message: false,
            write_cache,
            write_cache_size: 0,
            write_packet,
            write_packet_start_offset: 0,
            write_packet_end_offset: 0,
            // previously we wrote it to the write packet directly, but wrapping streams
            // such as TLS can set need_initial_flush to true, causing it to be sent independently.
            pending_prefix_write: prefix_write_bytes,
            shutdown_state: ShutdownState::WriteRemainingData,
            is_eof: false,
            read_failure: None,
        }
    }

    pub fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.check_read_failure()?;
        let result = self.feed_initial_read_data_inner(data);
        if let Err(error) = &result {
            self.poison_read(error);
        }
        result
    }

    fn check_read_failure(&self) -> std::io::Result<()> {
        match &self.read_failure {
            Some((kind, message)) => Err(std::io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }

    fn poison_read(&mut self, error: &std::io::Error) {
        // A caller may retry a datagram with a larger destination buffer. All
        // other read failures are terminal: cipher state and in-place header
        // decoding cannot safely be replayed after an authentication failure.
        if error.kind() != std::io::ErrorKind::InvalidInput && self.read_failure.is_none() {
            self.read_failure = Some((error.kind(), error.to_string()));
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
            self.processed_empty_message = false;
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
            self.unprocessed_pending_len = None;
        }
    }

    fn feed_initial_read_data_inner(&mut self, data: &[u8]) -> std::io::Result<()> {
        assert!(self.unprocessed_end_offset == 0);

        if data.len() > self.unprocessed_buf.len() {
            return Err(std::io::Error::other(
                "feed_initial_read_data called with too much data",
            ));
        }

        self.unprocessed_buf[0..data.len()].copy_from_slice(data);
        self.unprocessed_end_offset = data.len();

        if self.read_header_state != ReadHeaderState::Done {
            self.process_read_header()?;
            if self.read_header_state != ReadHeaderState::Done {
                return Ok(());
            }
        }

        loop {
            match self.try_decrypt()? {
                DecryptState::NeedData => {
                    break;
                }
                DecryptState::ReceivedEof => {
                    self.is_eof = true;
                    break;
                }
                DecryptState::BufferFull => {
                    break;
                }
                DecryptState::Success => {
                    if self.is_udp {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    fn process_read_header(&mut self) -> std::io::Result<()> {
        match self.read_header_state {
            ReadHeaderState::ReadAeadLength => self.process_read_header_aead_length(),
            ReadHeaderState::ReadAeadContent(content_len) => {
                self.process_read_header_aead_content(content_len)
            }
            ReadHeaderState::ReadLegacy | ReadHeaderState::ReadLegacyCommand(_) => {
                self.process_read_header_legacy()
            }
            ReadHeaderState::Done => {
                panic!("process_read_header called with Done state");
            }
        }
    }

    pub(super) fn with_raw_body(mut self, raw: bool) -> Self {
        self.raw_body = raw;
        self
    }

    pub(super) fn with_cfb(
        mut self,
        read_key: &[u8; 16],
        read_iv: &[u8; 16],
        write_key: &[u8; 16],
        write_iv: &[u8; 16],
    ) -> Self {
        self.read_cfb = Some(super::legacy::Cfb128::new(read_key, read_iv));
        self.write_cfb = Some(super::legacy::Cfb128::new(write_key, write_iv));
        // CFB chunks prepend a four-byte FNV-1a checksum, rather than an AEAD tag.
        self.tag_len = 4;
        self
    }

    pub(super) fn with_legacy_response(mut self, legacy: bool) -> Self {
        if legacy {
            let info = self
                .read_header_info
                .as_ref()
                .expect("client response metadata");
            self.legacy_response_cfb = Some(super::legacy::Cfb128::new(
                &info.response_header_key,
                &info.response_header_iv,
            ));
            self.read_header_state = ReadHeaderState::ReadLegacy;
        }
        self
    }

    fn process_read_header_legacy(&mut self) -> std::io::Result<()> {
        if self.read_header_state == ReadHeaderState::ReadLegacy {
            if self.unprocessed_end_offset - self.unprocessed_start_offset < 4 {
                return Ok(());
            }
            let header = &mut self.unprocessed_buf
                [self.unprocessed_start_offset..self.unprocessed_start_offset + 4];
            self.legacy_response_cfb.as_mut().unwrap().decrypt(header);
            check_header_response(
                header,
                self.read_header_info
                    .as_ref()
                    .unwrap()
                    .response_authentication_v,
            )?;
            let command_length = usize::from(header[3]);
            self.unprocessed_start_offset += 4;
            self.read_header_state = ReadHeaderState::ReadLegacyCommand(command_length);
        }
        let ReadHeaderState::ReadLegacyCommand(length) = self.read_header_state else {
            unreachable!()
        };
        if self.unprocessed_end_offset - self.unprocessed_start_offset < length {
            return Ok(());
        }
        self.legacy_response_cfb.as_mut().unwrap().decrypt(
            &mut self.unprocessed_buf
                [self.unprocessed_start_offset..self.unprocessed_start_offset + length],
        );
        self.unprocessed_start_offset += length;
        if self.read_cfb.is_some() {
            // Legacy CFB data continues the response header's cipher state.
            self.read_cfb = self.legacy_response_cfb.take();
        } else {
            self.legacy_response_cfb = None;
        }
        self.read_header_info = None;
        self.read_header_state = ReadHeaderState::Done;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }
        Ok(())
    }

    fn process_read_header_aead_length(&mut self) -> std::io::Result<()> {
        if self.unprocessed_end_offset - self.unprocessed_start_offset < 2 + HEADER_TAG_LEN {
            return Ok(());
        }

        let encrypted_response_header_length = &mut self.unprocessed_buf
            [self.unprocessed_start_offset..self.unprocessed_start_offset + 2 + HEADER_TAG_LEN];

        let ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            ..
        } = self.read_header_info.as_ref().unwrap();

        let response_header_length_aead_key =
            super::sha2::kdf(&response_header_key[..], &[b"AEAD Resp Header Len Key"]);
        let response_header_length_nonce =
            super::sha2::kdf(&response_header_iv[..], &[b"AEAD Resp Header Len IV"]);

        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &response_header_length_aead_key[0..16]).unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_length_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::empty(), encrypted_response_header_length)
            .is_err()
        {
            return Err(std::io::Error::other(
                "failed to open encrypted response header length",
            ));
        }

        let response_header_length =
            u16::from_be_bytes(encrypted_response_header_length[0..2].try_into().unwrap()) as usize;

        if !(4..=259).contains(&response_header_length) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VMess response header length",
            ));
        }
        self.read_header_state = ReadHeaderState::ReadAeadContent(response_header_length);
        self.unprocessed_start_offset += 2 + HEADER_TAG_LEN;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        self.process_read_header_aead_content(response_header_length)
    }

    fn process_read_header_aead_content(&mut self, content_len: usize) -> std::io::Result<()> {
        if self.unprocessed_end_offset - self.unprocessed_start_offset
            < content_len + HEADER_TAG_LEN
        {
            return Ok(());
        }

        let encrypted_response_header = &mut self.unprocessed_buf[self.unprocessed_start_offset
            ..self.unprocessed_start_offset + content_len + HEADER_TAG_LEN];

        let ReadHeaderInfo {
            response_header_key,
            response_header_iv,
            ..
        } = self.read_header_info.as_ref().unwrap();

        let response_header_aead_key =
            super::sha2::kdf(&response_header_key[..], &[b"AEAD Resp Header Key"]);
        let response_header_nonce =
            super::sha2::kdf(&response_header_iv[..], &[b"AEAD Resp Header IV"]);
        let unbound_key = UnboundKey::new(&AES_128_GCM, &response_header_aead_key[0..16]).unwrap();
        let mut opening_key = OpeningKey::new(
            unbound_key,
            SingleUseNonce::new(&response_header_nonce[0..12]),
        );

        if opening_key
            .open_in_place(Aad::empty(), encrypted_response_header)
            .is_err()
        {
            return Err(std::io::Error::other(
                "failed to open encrypted response header",
            ));
        }

        if content_len < 4 || usize::from(encrypted_response_header[3]) + 4 != content_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid VMess response header length",
            ));
        }
        let command_len = encrypted_response_header[3];
        if command_len > 0 {
            warn!("Ignoring unused command bytes from AEAD block");
        }

        self.read_header_state = ReadHeaderState::Done;
        self.unprocessed_start_offset += content_len + HEADER_TAG_LEN;
        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        let ReadHeaderInfo {
            response_authentication_v,
            ..
        } = self.read_header_info.take().unwrap();

        check_header_response(encrypted_response_header, response_authentication_v)
    }

    pub(super) fn with_authenticated_length(
        mut self,
        enabled: bool,
        chacha: bool,
        request_key: &[u8],
        request_iv: &[u8],
    ) -> Self {
        if !enabled {
            return self;
        }
        let derived = super::sha2::kdf(request_key, &[b"auth_len"]);
        let (algorithm, key) = if chacha {
            (
                &aerobox_primitives::aead::CHACHA20_POLY1305,
                super::md5::create_chacha_key(&derived[..16]).to_vec(),
            )
        } else {
            (&AES_128_GCM, derived[..16].to_vec())
        };
        self.read_length_key = Some(OpeningKey::new(
            UnboundKey::new(algorithm, &key).unwrap(),
            VmessNonceSequence::new(request_iv),
        ));
        self.write_length_key = Some(SealingKey::new(
            UnboundKey::new(algorithm, &key).unwrap(),
            VmessNonceSequence::new(request_iv),
        ));
        self
    }

    fn try_decrypt(&mut self) -> std::io::Result<DecryptState> {
        // returns true if a full packet was decrypted, false if not (ie. more data required)
        let available_len = self.unprocessed_end_offset - self.unprocessed_start_offset;

        if self.raw_body {
            if available_len == 0 {
                return Ok(DecryptState::NeedData);
            }
            let count = available_len.min(self.processed_buf.len() - self.processed_end_offset);
            if count == 0 {
                return Ok(DecryptState::BufferFull);
            }
            if let Some(cipher) = &mut self.read_cfb {
                cipher.decrypt(
                    &mut self.unprocessed_buf
                        [self.unprocessed_start_offset..self.unprocessed_start_offset + count],
                );
            }
            self.processed_buf[self.processed_end_offset..self.processed_end_offset + count]
                .copy_from_slice(
                    &self.unprocessed_buf
                        [self.unprocessed_start_offset..self.unprocessed_start_offset + count],
                );
            self.processed_end_offset += count;
            self.unprocessed_start_offset += count;
            if self.unprocessed_start_offset == self.unprocessed_end_offset {
                self.unprocessed_start_offset = 0;
                self.unprocessed_end_offset = 0;
            }
            return Ok(DecryptState::Success);
        }

        let (padding_len, data_len) = match self.unprocessed_pending_len {
            None => {
                let header_len = if self.read_length_key.is_some() {
                    18
                } else {
                    2
                };
                if available_len < header_len {
                    return Ok(DecryptState::NeedData);
                }

                let length_bytes = &mut self.unprocessed_buf
                    [self.unprocessed_start_offset..self.unprocessed_start_offset + header_len];

                if let Some(cipher) = &mut self.read_cfb {
                    cipher.decrypt(length_bytes);
                }

                if let Some(key) = &mut self.read_length_key {
                    key.open_in_place(Aad::empty(), length_bytes).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "VMess length authentication failed",
                        )
                    })?;
                }

                let mut data_len = ((length_bytes[0] as u16) << 8) | (length_bytes[1] as u16);

                let padding_len = match self.read_length_mask {
                    Some(ref mut mask) => {
                        let (padding_len, length_mask) = if self.read_length_key.is_some() {
                            (
                                if mask.enable_padding {
                                    (mask.next_u16() % 64) as usize
                                } else {
                                    0
                                },
                                0,
                            )
                        } else {
                            mask.next_values()
                        };
                        data_len ^= length_mask;
                        padding_len
                    }
                    None => 0,
                };

                let data_len = if self.read_length_key.is_some() {
                    data_len.wrapping_add(16)
                } else {
                    data_len
                } as usize;

                if data_len > MAX_ENCRYPTED_READ_DATA_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("encrypted data length larger than {MAX_ENCRYPTED_READ_DATA_SIZE}"),
                    ));
                }

                if data_len < padding_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "padding exceeds VMess chunk length",
                    ));
                }
                if self.read_cfb.is_some() && data_len == 0 && padding_len == 0 {
                    self.unprocessed_start_offset += header_len;
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::ReceivedEof);
                }
                if self.tag_len > 0 && (data_len - padding_len) < self.tag_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "data length ({}) is smaller than tag length ({})",
                            data_len, self.tag_len
                        ),
                    ));
                }

                self.unprocessed_start_offset += header_len;

                if available_len - header_len < data_len {
                    self.unprocessed_pending_len = Some((padding_len, data_len));
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::NeedData);
                }

                let processed_data_len = data_len - padding_len - self.tag_len;
                if self.processed_end_offset + processed_data_len > self.processed_buf.len() {
                    self.unprocessed_pending_len = Some((padding_len, data_len));
                    if self.unprocessed_start_offset == self.unprocessed_end_offset {
                        self.unprocessed_start_offset = 0;
                        self.unprocessed_end_offset = 0;
                    }
                    return Ok(DecryptState::BufferFull);
                }

                (padding_len, data_len)
            }

            Some((padding_len, data_len)) => {
                if available_len < data_len {
                    return Ok(DecryptState::NeedData);
                }

                let processed_data_len = data_len - padding_len - self.tag_len;
                if self.processed_end_offset + processed_data_len > self.processed_buf.len() {
                    return Ok(DecryptState::BufferFull);
                }

                self.unprocessed_pending_len = None;
                (padding_len, data_len)
            }
        };

        if let Some(ref mut opening_key) = self.opening_key
            && opening_key
                .open_in_place(
                    Aad::empty(),
                    &mut self.unprocessed_buf[self.unprocessed_start_offset
                        ..self.unprocessed_start_offset + data_len - padding_len],
                )
                .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "open failed for data",
            ));
        }

        let processed_data_len = data_len - padding_len - self.tag_len;
        let payload_start = if let Some(cipher) = &mut self.read_cfb {
            let bytes = &mut self.unprocessed_buf
                [self.unprocessed_start_offset..self.unprocessed_start_offset + data_len];
            cipher.decrypt(bytes);
            let expected = u32::from_be_bytes(bytes[..4].try_into().unwrap());
            let mut checksum = super::fnv1a::Fnv1aHasher::new();
            checksum.write(&bytes[4..4 + processed_data_len]);
            if checksum.finish() != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "VMess CFB chunk checksum mismatch",
                ));
            }
            self.unprocessed_start_offset + 4
        } else {
            self.unprocessed_start_offset
        };
        self.processed_buf
            [self.processed_end_offset..self.processed_end_offset + processed_data_len]
            .copy_from_slice(
                &self.unprocessed_buf[payload_start..payload_start + processed_data_len],
            );

        self.processed_end_offset += processed_data_len;
        self.unprocessed_start_offset += data_len;

        if self.unprocessed_start_offset == self.unprocessed_end_offset {
            self.unprocessed_start_offset = 0;
            self.unprocessed_end_offset = 0;
        }

        Ok(
            if processed_data_len == 0 && self.is_udp && self.tag_len > 0 {
                self.processed_empty_message = true;
                DecryptState::Success
            } else if processed_data_len == 0 {
                DecryptState::ReceivedEof
            } else {
                DecryptState::Success
            },
        )
    }

    fn check_transport_eof(&self) -> std::io::Result<()> {
        if self.read_header_state != ReadHeaderState::Done
            || self.unprocessed_pending_len.is_some()
            || self.unprocessed_end_offset != self.unprocessed_start_offset
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated VMess frame",
            ));
        }
        Ok(())
    }

    fn read_processed_message(&mut self, buf: &mut ReadBuf<'_>) -> std::io::Result<()> {
        if self.processed_empty_message {
            self.processed_empty_message = false;
            return Ok(());
        }
        if buf.remaining() < self.processed_end_offset - self.processed_start_offset {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "buffer too small for VMess datagram",
            ));
        }
        self.read_processed(buf);
        Ok(())
    }

    fn message_eof(&self) -> std::io::Result<()> {
        if self.is_udp && self.tag_len > 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "VMess datagram transport closed",
            ))
        } else {
            Ok(())
        }
    }

    fn read_processed(&mut self, buf: &mut ReadBuf<'_>) {
        assert!(
            self.processed_end_offset > 0,
            "called without any processed data"
        );

        let available_len = self.processed_end_offset - self.processed_start_offset;

        let unfilled_len = buf.remaining();

        let write_amount = std::cmp::min(unfilled_len, available_len);
        assert!(
            write_amount > 0,
            "no data to write (available_len = {available_len}, unfilled_len = {unfilled_len})",
        );

        buf.put_slice(
            &self.processed_buf
                [self.processed_start_offset..self.processed_start_offset + write_amount],
        );

        let new_processed_start_offset = self.processed_start_offset + write_amount;
        if new_processed_start_offset == self.processed_end_offset {
            self.processed_start_offset = 0;
            self.processed_end_offset = 0;
        } else {
            self.processed_start_offset = new_processed_start_offset;
        }
    }

    fn create_write_packet(&mut self) -> std::io::Result<bool> {
        // If we have a pending prefix, prepend it to the write_packet buffer
        // so that the response header and first data packet go out together.
        if let Some(prefix) = self.pending_prefix_write.take() {
            assert!(self.write_packet_end_offset == 0);
            let prefix_len = prefix.len();
            self.write_packet[0..prefix_len].copy_from_slice(&prefix);
            self.write_packet_end_offset = prefix_len;
        }

        // note that this should allow creating an empty packet.
        let write_packet_space = self.write_packet.len() - self.write_packet_end_offset;
        if self.raw_body {
            let count = self.write_cache_size.min(write_packet_space);
            if count == 0 {
                return Ok(self.write_cache_size == 0);
            }
            self.write_packet[self.write_packet_end_offset..self.write_packet_end_offset + count]
                .copy_from_slice(&self.write_cache[..count]);
            if let Some(cipher) = &mut self.write_cfb {
                cipher.encrypt(
                    &mut self.write_packet
                        [self.write_packet_end_offset..self.write_packet_end_offset + count],
                );
            }
            self.write_packet_end_offset += count;
            self.write_cache
                .copy_within(count..self.write_cache_size, 0);
            self.write_cache_size -= count;
            return Ok(true);
        }
        let max_padding_len = if self.write_length_mask.is_some() {
            MAX_PADDING_LEN
        } else {
            0
        };

        let header_len = if self.write_length_key.is_some() {
            18
        } else {
            2
        };
        let max_metadata_size = header_len + max_padding_len + self.tag_len;
        if max_metadata_size >= write_packet_space {
            return Ok(false);
        }

        // TODO: allow peeking so that we don't need to use MAX_PADDING_LEN above.
        let (padding_len, length_mask) = match self.write_length_mask {
            Some(ref mut mask) => {
                if self.write_length_key.is_some() {
                    (
                        if mask.enable_padding {
                            (mask.next_u16() % 64) as usize
                        } else {
                            0
                        },
                        0,
                    )
                } else {
                    mask.next_values()
                }
            }
            None => (0, 0),
        };

        let metadata_size = header_len + padding_len + self.tag_len;
        let max_data_size = std::cmp::min(
            write_packet_space - metadata_size,
            MAX_ENCRYPTED_WRITE_DATA_SIZE - padding_len - self.tag_len,
        );
        let data_size = std::cmp::min(max_data_size, self.write_cache_size);

        let write_packet_size: usize = data_size + padding_len + self.tag_len;
        assert!(write_packet_size + header_len <= self.write_packet.len());

        let frame_start = self.write_packet_end_offset;
        let mut next_index = frame_start;

        let write_packet_size = if self.write_length_key.is_some() {
            (write_packet_size as u16).wrapping_sub(16)
        } else {
            (write_packet_size as u16) ^ length_mask
        };
        self.write_packet[next_index] = (write_packet_size >> 8) as u8;
        self.write_packet[next_index + 1] = (write_packet_size & 0xff) as u8;

        if let Some(key) = &mut self.write_length_key {
            let tag = key
                .seal_in_place_separate_tag(
                    Aad::empty(),
                    &mut self.write_packet[next_index..next_index + 2],
                )
                .map_err(|_| std::io::Error::other("VMess length encryption failed"))?;
            self.write_packet[next_index + 2..next_index + 18].copy_from_slice(tag.as_ref());
        }
        next_index += header_len;
        if self.write_cfb.is_some() {
            let mut checksum = super::fnv1a::Fnv1aHasher::new();
            checksum.write(&self.write_cache[..data_size]);
            self.write_packet[next_index..next_index + 4]
                .copy_from_slice(&checksum.finish().to_be_bytes());
            next_index += 4;
        }
        self.write_packet[next_index..next_index + data_size]
            .copy_from_slice(&self.write_cache[0..data_size]);

        match self.sealing_key {
            Some(ref mut sealing_key) => {
                let tag = sealing_key
                    .seal_in_place_separate_tag(
                        Aad::empty(),
                        &mut self.write_packet[next_index..next_index + data_size],
                    )
                    .map_err(|_| std::io::Error::other("VMess payload encryption failed"))?;
                next_index += data_size;

                self.write_packet[next_index..next_index + self.tag_len]
                    .copy_from_slice(tag.as_ref());
                next_index += self.tag_len;
            }
            None => {
                next_index += data_size;
            }
        }

        if padding_len > 0 {
            rand::rng().fill_bytes(&mut self.write_packet[next_index..next_index + padding_len]);
            next_index += padding_len;
        }

        if let Some(cipher) = &mut self.write_cfb {
            cipher.encrypt(&mut self.write_packet[frame_start..next_index]);
        }

        self.write_packet_end_offset = next_index;

        // TODO: keep track of start/stop offset instead?
        if data_size == self.write_cache_size {
            self.write_cache_size = 0;
        } else {
            self.write_cache
                .copy_within(data_size..self.write_cache_size, 0);
            self.write_cache_size -= data_size;
        }

        Ok(true)
    }

    #[inline]
    fn do_write_packet(&mut self, cx: &mut Context<'_>) -> std::io::Result<bool> {
        // returns true when everything is written.
        loop {
            let remaining_data =
                &self.write_packet[self.write_packet_start_offset..self.write_packet_end_offset];

            match Pin::new(&mut self.stream).poll_write(cx, remaining_data) {
                Poll::Ready(Ok(written)) => {
                    if written == 0 {
                        // eof, TODO fix
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "write packet eof",
                        ));
                    }
                    self.write_packet_start_offset += written;
                    if self.write_packet_start_offset == self.write_packet_end_offset {
                        self.write_packet_start_offset = 0;
                        self.write_packet_end_offset = 0;
                        return Ok(true);
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Err(e);
                }
                Poll::Pending => {
                    return Ok(false);
                }
            }
        }
    }

    fn reset_unprocessed_buf_offset(&mut self) {
        assert!(
            self.unprocessed_start_offset > 0
                && self.unprocessed_end_offset > self.unprocessed_start_offset
        );

        self.unprocessed_buf.copy_within(
            self.unprocessed_start_offset..self.unprocessed_end_offset,
            0,
        );
        self.unprocessed_end_offset -= self.unprocessed_start_offset;
        self.unprocessed_start_offset = 0;
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.check_read_failure()?;
        let result = self.as_mut().poll_read_inner(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.poison_read(error);
        }
        result
    }
}

impl VmessStream {
    fn poll_read_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();

        if this.read_header_state != ReadHeaderState::Done && !this.is_eof {
            loop {
                let mut read_buf =
                    ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
                let len = read_buf.filled().len();
                if len == 0 {
                    this.check_transport_eof()?;
                    this.is_eof = true;
                    return Poll::Ready(Ok(()));
                }
                this.unprocessed_end_offset += len;
                this.process_read_header()?;
                if this.read_header_state == ReadHeaderState::Done {
                    break;
                }
            }

            // We probably already have some user data ready to be processed, so we need
            // to do so immediately since we go straight to a poll_read below.
            loop {
                match this.try_decrypt()? {
                    DecryptState::NeedData => {
                        break;
                    }
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::BufferFull => {
                        assert!(this.processed_end_offset > 0);
                        this.read_processed(buf);
                        return Poll::Ready(Ok(()));
                    }
                    DecryptState::Success => {
                        continue;
                    }
                }
            }
        }

        if this.processed_end_offset > 0 {
            this.read_processed(buf);
            return Poll::Ready(Ok(()));
        } else if this.is_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            // BufferFull can leave a complete encrypted chunk after the caller
            // drains processed bytes. Consume it before polling the transport.
            loop {
                match this.try_decrypt()? {
                    DecryptState::Success => continue,
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::NeedData | DecryptState::BufferFull => break,
                }
            }
            if this.processed_end_offset > 0 {
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }
            if this.is_eof {
                return Poll::Ready(Ok(()));
            }
            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                // if we got here, there's no data in processed buf, and we don't have
                // space in unprocessed buf to read more to decrypt.
                // since we know we have enough space for 1 full-sized packet,
                // this must be because start offset has moved forward too much.
                this.reset_unprocessed_buf_offset();
                assert!(this.unprocessed_end_offset < this.unprocessed_buf.len());
            }

            let mut read_buf =
                ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;

            let len = read_buf.filled().len();

            // Make sure we have enough space to store the processed data.
            if len == 0 {
                this.check_transport_eof()?;
                // We've reached EOF. Return any available data first.
                this.is_eof = true;
                if this.processed_end_offset > 0 {
                    // TODO: I don't think we ever hit this clause.
                    // The only time we read is when processed_end_offset is 0.
                    this.read_processed(buf);
                }
                return Poll::Ready(Ok(()));
            }

            this.unprocessed_end_offset += len;

            // Process some data to free up unprocessed_buf space.
            loop {
                match this.try_decrypt()? {
                    DecryptState::NeedData => {
                        break;
                    }
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::BufferFull => {
                        assert!(this.processed_end_offset > 0);
                        this.read_processed(buf);
                        return Poll::Ready(Ok(()));
                    }
                    DecryptState::Success => {
                        continue;
                    }
                }
            }

            if this.processed_end_offset > 0 {
                // Return the data we just got.
                this.read_processed(buf);
                return Poll::Ready(Ok(()));
            }

            if this.is_eof {
                return Poll::Ready(Ok(()));
            }

            // We don't want to return zero bytes, and we haven't yet hit a Poll::Pending,
            // so try to read again.
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        let mut cache_space = this.write_cache.len().saturating_sub(this.write_cache_size);

        if cache_space == 0 {
            while this.write_cache_size > 0 && this.create_write_packet()? {}
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            // now that we've written out all the packet data, create more packets to free up cache
            // space.
            while this.write_cache_size > 0 && this.create_write_packet()? {}
            cache_space = this.write_cache.len().saturating_sub(this.write_cache_size);
            assert!(cache_space > 0);
        }

        let write_count = std::cmp::min(cache_space, buf.len());

        this.write_cache[this.write_cache_size..this.write_cache_size + write_count]
            .copy_from_slice(&buf[0..write_count]);
        this.write_cache_size += write_count;

        Poll::Ready(Ok(write_count))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.write_cache_size == 0 && this.write_packet_end_offset == 0 {
            return Pin::new(&mut this.stream).poll_flush(cx);
        }

        // Create a new write frame when flush is called when we don't have one.
        while this.write_cache_size > 0 || this.write_packet_end_offset > 0 {
            while this.write_cache_size > 0 && this.create_write_packet()? {}
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
            ready!(Pin::new(&mut this.stream).poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut this = self.get_mut();

        loop {
            match this.shutdown_state {
                ShutdownState::WriteRemainingData => {
                    if this.write_cache_size > 0 {
                        // create data packets.
                        while this.write_cache_size > 0 && this.create_write_packet()? {}
                    }

                    // create the empty packet.
                    // it's possible that the write_packet buffer contains the server response,
                    // and the empty shutdown packet together, ready to send off together.
                    if this.write_cache_size == 0 && this.create_write_packet()? {
                        this.shutdown_state = ShutdownState::WriteEmptyPacket;
                        continue;
                    }
                    // if we cannot create the empty packet, the write_packet buffer must
                    // be too full, so flush and try again.
                    ready!(Pin::new(&mut this).poll_flush(cx))?;
                }
                ShutdownState::WriteEmptyPacket => {
                    ready!(Pin::new(&mut this).poll_flush(cx))?;
                    this.shutdown_state = ShutdownState::PollShutdown;
                }
                ShutdownState::PollShutdown => {
                    ready!(Pin::new(&mut this.stream).poll_shutdown(cx))?;
                    break;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncPing for VmessStream {
    fn supports_ping(&self) -> bool {
        self.stream.supports_ping()
    }

    fn poll_write_ping(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        Pin::new(&mut self.stream).poll_write_ping(cx)
    }
}

impl AsyncStream for VmessStream {
    fn tcp_socket_control(&self) -> std::io::Result<Option<crate::tcp::socket_control::TcpSocketControl>> {
        self.stream.tcp_socket_control()
    }

    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.local_addr()
    }
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

impl AsyncReadMessage for VmessStream {
    fn read_message_eof_on_empty(&self) -> bool {
        !(self.is_udp && self.tag_len > 0)
    }

    fn poll_read_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.check_read_failure()?;
        let result = self.as_mut().poll_read_message_inner(cx, buf);
        if let Poll::Ready(Err(error)) = &result {
            self.poison_read(error);
        }
        result
    }
}

impl VmessStream {
    fn poll_read_message_inner(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.processed_empty_message {
            return Poll::Ready(this.read_processed_message(buf));
        }
        if this.is_eof {
            return Poll::Ready(this.message_eof());
        }

        if this.read_header_state != ReadHeaderState::Done && !this.is_eof {
            loop {
                let mut read_buf =
                    ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
                ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;
                let len = read_buf.filled().len();
                if len == 0 {
                    this.check_transport_eof()?;
                    this.is_eof = true;
                    return Poll::Ready(this.message_eof());
                }
                this.unprocessed_end_offset += len;
                this.process_read_header()?;
                if this.read_header_state == ReadHeaderState::Done {
                    break;
                }
            }

            // We probably already have some user data ready to be processed, so we need
            // to do so immediately since we go straight to a poll_read below.
            loop {
                match this.try_decrypt()? {
                    DecryptState::NeedData => {
                        break;
                    }
                    DecryptState::ReceivedEof => {
                        this.is_eof = true;
                        break;
                    }
                    DecryptState::BufferFull => {
                        assert!(this.processed_end_offset > 0);
                        this.read_processed_message(buf)?;
                        return Poll::Ready(Ok(()));
                    }
                    DecryptState::Success => break,
                }
            }
        }

        if this.processed_end_offset > 0 || this.processed_empty_message {
            this.read_processed_message(buf)?;
            return Poll::Ready(Ok(()));
        }
        if this.is_eof {
            return Poll::Ready(this.message_eof());
        }

        match this.try_decrypt()? {
            DecryptState::NeedData => {}
            DecryptState::ReceivedEof => {
                this.is_eof = true;
            }
            DecryptState::BufferFull => {
                assert!(this.processed_end_offset > 0);
                this.read_processed_message(buf)?;
                return Poll::Ready(Ok(()));
            }
            DecryptState::Success => {
                this.read_processed_message(buf)?;
                return Poll::Ready(Ok(()));
            }
        }

        if this.is_eof {
            return Poll::Ready(this.message_eof());
        }

        loop {
            if this.unprocessed_end_offset == this.unprocessed_buf.len() {
                // if we got here, there's no data in processed buf, and we don't have
                // space in unprocessed buf to read more to decrypt.
                // since we know we have enough space for 1 full-sized packet,
                // this must be because start offset has moved forward too much.
                this.reset_unprocessed_buf_offset();
                assert!(this.unprocessed_end_offset < this.unprocessed_buf.len());
            }

            let mut read_buf =
                ReadBuf::new(&mut this.unprocessed_buf[this.unprocessed_end_offset..]);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut read_buf))?;

            let len = read_buf.filled().len();

            // Make sure we have enough space to store the processed data.
            if len == 0 {
                this.check_transport_eof()?;
                // We've reached EOF. Return any available data first.
                this.is_eof = true;
                if this.processed_end_offset > 0 {
                    // TODO: I don't think we ever hit this clause.
                    // The only time we read is when processed_end_offset is 0.
                    this.read_processed_message(buf)?;
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(this.message_eof());
            }

            this.unprocessed_end_offset += len;

            // Process some data to free up unprocessed_buf space.
            match this.try_decrypt()? {
                DecryptState::NeedData => {}
                DecryptState::ReceivedEof => {
                    this.is_eof = true;
                    return Poll::Ready(this.message_eof());
                }
                DecryptState::BufferFull => {
                    assert!(this.processed_end_offset > 0);
                    this.read_processed_message(buf)?;
                    return Poll::Ready(Ok(()));
                }
                DecryptState::Success => {
                    this.read_processed_message(buf)?;
                    return Poll::Ready(Ok(()));
                }
            }

            // We don't want to return zero bytes, and we haven't yet hit a Poll::Pending,
            // so try to read again.
        }
    }
}

impl AsyncWriteMessage for VmessStream {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if buf.is_empty() && this.tag_len == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VMess none/zero native UDP cannot represent an empty datagram; use XUDP or packetaddr",
            )));
        }

        // the write cache is not used in message mode.
        assert!(this.write_cache_size == 0);

        let header_len = if this.write_length_key.is_some() {
            18
        } else {
            2
        };
        let padding_reserve = if this
            .write_length_mask
            .as_ref()
            .is_some_and(|mask| mask.enable_padding)
        {
            MAX_PADDING_LEN - 1
        } else {
            0
        };
        let max_payload = (u16::MAX as usize)
            .min(this.write_packet.len().saturating_sub(header_len))
            .saturating_sub(this.tag_len + padding_reserve);
        if buf.len() > max_payload {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VMess message exceeds the frame payload limit",
            )));
        }

        if let Some(prefix) = this.pending_prefix_write.take() {
            // we need to handle this here because we do not call create_write_packet
            // for UDP streams
            assert!(this.write_packet_end_offset == 0);
            let prefix_len = prefix.len();
            this.write_packet[0..prefix_len].copy_from_slice(&prefix);
            this.write_packet_end_offset = prefix_len;
        }

        if this.write_packet_end_offset > 0 {
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }
        let (padding_len, length_mask) = match this.write_length_mask {
            Some(ref mut mask) => {
                if this.write_length_key.is_some() {
                    (
                        if mask.enable_padding {
                            (mask.next_u16() % 64) as usize
                        } else {
                            0
                        },
                        0,
                    )
                } else {
                    mask.next_values()
                }
            }
            None => (0, 0),
        };

        let metadata_size = header_len + padding_len + this.tag_len;

        let available_space = this.write_packet.len() - metadata_size;
        if available_space < buf.len() {
            return Poll::Ready(Err(std::io::Error::other("write payload is too large")));
        }

        let write_packet_size = buf.len() + padding_len + this.tag_len;
        let write_packet_size = if this.write_length_key.is_some() {
            (write_packet_size as u16).wrapping_sub(16)
        } else {
            (write_packet_size as u16) ^ length_mask
        };

        this.write_packet[0] = (write_packet_size >> 8) as u8;
        this.write_packet[1] = (write_packet_size & 0xff) as u8;

        if let Some(key) = &mut this.write_length_key {
            let tag = key
                .seal_in_place_separate_tag(Aad::empty(), &mut this.write_packet[..2])
                .map_err(|_| std::io::Error::other("VMess length encryption failed"))?;
            this.write_packet[2..18].copy_from_slice(tag.as_ref());
        }
        let payload_start = if this.write_cfb.is_some() {
            let mut checksum = super::fnv1a::Fnv1aHasher::new();
            checksum.write(buf);
            this.write_packet[header_len..header_len + 4]
                .copy_from_slice(&checksum.finish().to_be_bytes());
            header_len + 4
        } else {
            header_len
        };
        let mut end_index = payload_start + buf.len();
        this.write_packet[payload_start..end_index].copy_from_slice(buf);

        if let Some(ref mut sealing_key) = this.sealing_key {
            let tag = sealing_key
                .seal_in_place_separate_tag(
                    Aad::empty(),
                    &mut this.write_packet[header_len..end_index],
                )
                .map_err(|err| std::io::Error::other(format!("failed to seal message: {err}")))?;

            this.write_packet[end_index..end_index + this.tag_len].copy_from_slice(tag.as_ref());

            end_index += this.tag_len;
        }

        if padding_len > 0 {
            rand::rng().fill_bytes(&mut this.write_packet[end_index..end_index + padding_len]);
            end_index += padding_len;
        }
        if let Some(cipher) = &mut this.write_cfb {
            cipher.encrypt(&mut this.write_packet[..end_index]);
        }
        this.write_packet_end_offset = end_index;

        Poll::Ready(Ok(()))
    }
}

impl AsyncFlushMessage for VmessStream {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // the write cache is not used in message mode.
        assert!(this.write_cache_size == 0);

        if this.write_packet_end_offset > 0 {
            match this.do_write_packet(cx) {
                Ok(all_written) => {
                    if !all_written {
                        return Poll::Pending;
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }

        ready!(Pin::new(&mut this.stream).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }
}

impl AsyncShutdownMessage for VmessStream {
    fn poll_shutdown_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.is_udp {
            // A checksum/tag-only frame is a valid empty UDP packet, not a
            // shutdown sentinel. Finish buffered data and close the transport.
            ready!(self.as_mut().poll_flush_message(cx))?;
            Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
        } else {
            self.poll_shutdown(cx)
        }
    }
}

impl AsyncMessageStream for VmessStream {}

#[cfg(test)]
mod tests;
