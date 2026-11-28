use super::*;
use crate::copy_bidirectional::tests::{copy_response_with_flush_pressure, quota_test_payload};
use crate::prepend_stream::PrependStream;
use aerobox_primitives::aead::{Algorithm, CHACHA20_POLY1305, UnboundKey};
use shake::Shake128;
use shake::digest::{ExtendableOutput, Update};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn legacy_response_cfb_state_continues_into_fragmented_checked_body() {
    for cfb in [false, true] {
        let key = [33; 16];
        let iv = [44; 16];
        let (wire, mut peer) = tokio::io::duplex(5);
        let mut reader = VmessStream::new(
            Box::new(wire),
            false,
            None,
            None,
            None,
            false,
            None,
            Some(ReadHeaderInfo {
                response_header_key: key,
                response_header_iv: iv,
                response_authentication_v: 81,
            }),
        );
        if cfb {
            reader = reader.with_cfb(&key, &iv, &key, &iv);
        }
        reader = reader.with_legacy_response(true);
        let payload = b"fragmented legacy response body";
        let mut bytes = vec![81, 0, 0, 0];
        let mut cipher = super::super::legacy::Cfb128::new(&key, &iv);
        cipher.encrypt(&mut bytes);
        let mut body = ((payload.len() + if cfb { 4 } else { 0 }) as u16)
            .to_be_bytes()
            .to_vec();
        if cfb {
            let mut checksum = super::super::fnv1a::Fnv1aHasher::new();
            checksum.write(payload);
            body.extend_from_slice(&checksum.finish().to_be_bytes());
        }
        body.extend_from_slice(payload);
        if cfb {
            cipher.encrypt(&mut body);
        }
        bytes.extend(body);
        let sender = async {
            for byte in bytes {
                peer.write_u8(byte).await.unwrap();
            }
            peer.shutdown().await.unwrap();
        };
        let receiver = async {
            let mut output = Vec::new();
            reader.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, payload);
        };
        tokio::join!(sender, receiver);
    }
}

#[tokio::test]
async fn cfb_rejects_modified_checksum_and_preserves_datagram_boundaries() {
    for corrupt in [false, true] {
        let key = [12; 16];
        let iv = [19; 16];
        let (wire, mut peer) = tokio::io::duplex(65536);
        let mut reader =
            VmessStream::new(Box::new(wire), true, None, None, None, false, None, None)
                .with_cfb(&key, &iv, &key, &iv);
        let mut cipher = super::super::legacy::Cfb128::new(&key, &iv);
        let mut bytes = Vec::new();
        for payload in [b"first datagram".as_slice(), b"second datagram"] {
            let mut checksum = super::super::fnv1a::Fnv1aHasher::new();
            checksum.write(payload);
            let mut frame = ((payload.len() + 4) as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&(checksum.finish() ^ u32::from(corrupt)).to_be_bytes());
            frame.extend_from_slice(payload);
            cipher.encrypt(&mut frame);
            bytes.extend(frame);
        }
        peer.write_all(&bytes).await.unwrap();
        for expected in [b"first datagram".as_slice(), b"second datagram"] {
            let mut bytes = [0; 128];
            let mut output = ReadBuf::new(&mut bytes);
            let result =
                std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read_message(cx, &mut output))
                    .await;
            if corrupt {
                assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
                break;
            }
            result.unwrap();
            assert_eq!(output.filled(), expected);
        }
    }
}

#[tokio::test]
async fn authenticated_empty_datagrams_survive_then_transport_eof_is_explicit() {
    for cfb in [false, true] {
        let (wire, peer) = tokio::io::duplex(4096);
        let build = |wire: tokio::io::DuplexStream| {
            if cfb {
                VmessStream::new(Box::new(wire), true, None, None, None, false, None, None)
                    .with_cfb(&[12; 16], &[19; 16], &[12; 16], &[19; 16])
            } else {
                response_test_stream(Box::new(wire), Some(&AES_128_GCM), true, true, None)
            }
        };
        let mut writer = build(wire);
        let mut reader = build(peer);
        // The shared test helper builds a TCP stream by default.
        writer.is_udp = true;
        reader.is_udp = true;
        assert!(!reader.read_message_eof_on_empty());
        for expected in [b"".as_slice(), b"after empty"] {
            std::future::poll_fn(|cx| Pin::new(&mut writer).poll_write_message(cx, expected))
                .await
                .unwrap();
            std::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush_message(cx))
                .await
                .unwrap();
            let mut bytes = [0; 128];
            let mut output = ReadBuf::new(&mut bytes);
            std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read_message(cx, &mut output))
                .await
                .unwrap();
            assert_eq!(output.filled(), expected);
        }
        std::future::poll_fn(|cx| Pin::new(&mut writer).poll_shutdown_message(cx))
            .await
            .unwrap();
        let mut bytes = [0; 128];
        let mut output = ReadBuf::new(&mut bytes);
        assert_eq!(
            std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read_message(cx, &mut output))
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test]
async fn cancelling_cfb_flush_preserves_feedback_and_partially_written_frame() {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let (wire, mut peer) = tokio::io::duplex(1);
        let key = [12; 16];
        let iv = [19; 16];
        let mut writer =
            VmessStream::new(Box::new(wire), false, None, None, None, false, None, None)
                .with_cfb(&key, &iv, &key, &iv);
        writer.write_all(b"first").await.unwrap();
        {
            let flush = writer.flush();
            tokio::pin!(flush);
            assert!(futures::poll!(flush.as_mut()).is_pending());
        }
        let send = async {
            writer.flush().await.unwrap();
            writer.write_all(b"second").await.unwrap();
            writer.flush().await.unwrap();
        };
        let receive = async {
            let mut wire = [0; 23];
            peer.read_exact(&mut wire).await.unwrap();
            super::super::legacy::Cfb128::new(&key, &iv).decrypt(&mut wire);
            let mut cursor = 0;
            for payload in [b"first".as_slice(), b"second"] {
                let length =
                    u16::from_be_bytes(wire[cursor..cursor + 2].try_into().unwrap()) as usize;
                assert_eq!(length, payload.len() + 4);
                let mut checksum = super::super::fnv1a::Fnv1aHasher::new();
                checksum.write(payload);
                assert_eq!(
                    &wire[cursor + 2..cursor + 6],
                    &checksum.finish().to_be_bytes()
                );
                assert_eq!(&wire[cursor + 6..cursor + 2 + length], payload);
                cursor += 2 + length;
            }
        };
        tokio::join!(send, receive);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn invalid_response_auth_never_exposes_body_on_retry() {
    for legacy in [false, true] {
        for initial_feed in [false, true] {
            let key = [33; 16];
            let iv = [44; 16];
            let (wire, mut peer) = tokio::io::duplex(4096);
            let mut reader = VmessStream::new(
                Box::new(wire),
                false,
                None,
                None,
                None,
                false,
                None,
                Some(ReadHeaderInfo {
                    response_header_key: key,
                    response_header_iv: iv,
                    response_authentication_v: 81,
                }),
            )
            .with_raw_body(true)
            .with_legacy_response(legacy);
            let mut header = vec![80, 0, 0, 0];
            let mut bytes = if legacy {
                super::super::legacy::Cfb128::new(&key, &iv).encrypt(&mut header);
                header
            } else {
                let seal = |mut value: Vec<u8>, key_label: &[u8], iv_label: &[u8]| {
                    let key = super::super::sha2::kdf(&key, &[key_label]);
                    let nonce = super::super::sha2::kdf(&iv, &[iv_label]);
                    let mut cipher = SealingKey::new(
                        UnboundKey::new(&AES_128_GCM, &key[..16]).unwrap(),
                        SingleUseNonce::new(&nonce[..12]),
                    );
                    cipher
                        .seal_in_place_append_tag(Aad::empty(), &mut value)
                        .unwrap();
                    value
                };
                let mut bytes = seal(
                    vec![0, 4],
                    b"AEAD Resp Header Len Key",
                    b"AEAD Resp Header Len IV",
                );
                bytes.extend(seal(
                    header,
                    b"AEAD Resp Header Key",
                    b"AEAD Resp Header IV",
                ));
                bytes
            };
            bytes.extend_from_slice(b"untrusted response body");
            if initial_feed {
                assert_eq!(
                    reader.feed_initial_read_data(&bytes).unwrap_err().kind(),
                    std::io::ErrorKind::InvalidData,
                );
            } else {
                peer.write_all(&bytes).await.unwrap();
                peer.shutdown().await.unwrap();
            }
            for _ in 0..2 {
                let mut bytes = [0; 128];
                let mut output = ReadBuf::new(&mut bytes);
                let error =
                    std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read(cx, &mut output))
                        .await
                        .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                assert!(output.filled().is_empty());
            }
        }
    }
}

#[tokio::test]
async fn malformed_frame_discards_preceding_buffered_plaintext_after_error() {
    for cfb in [false, true] {
        let (wire, mut peer) = tokio::io::duplex(4096);
        let mut reader = if cfb {
            VmessStream::new(Box::new(wire), false, None, None, None, false, None, None)
                .with_cfb(&[42; 16], &[23; 16], &[42; 16], &[23; 16])
        } else {
            response_test_stream(Box::new(wire), Some(&AES_128_GCM), false, false, None)
        };
        let mut cfb_cipher = super::super::legacy::Cfb128::new(&[42; 16], &[23; 16]);
        let mut aead_cipher = SealingKey::new(
            UnboundKey::new(&AES_128_GCM, &[42; 16]).unwrap(),
            VmessNonceSequence::new(&[23; 16]),
        );
        let mut bytes = Vec::new();
        for (index, payload) in [b"buffered".as_slice(), b"corrupt"].into_iter().enumerate() {
            if cfb {
                let mut checksum = super::super::fnv1a::Fnv1aHasher::new();
                checksum.write(payload);
                let mut frame = ((payload.len() + 4) as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&(checksum.finish() ^ index as u32).to_be_bytes());
                frame.extend_from_slice(payload);
                cfb_cipher.encrypt(&mut frame);
                bytes.extend(frame);
            } else {
                let mut frame = payload.to_vec();
                aead_cipher
                    .seal_in_place_append_tag(Aad::empty(), &mut frame)
                    .unwrap();
                if index == 1 {
                    *frame.last_mut().unwrap() ^= 1;
                }
                bytes.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                bytes.extend(frame);
            }
        }
        peer.write_all(&bytes).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut bytes = [0; 128];
        let mut output = ReadBuf::new(&mut bytes);
        let first_error =
            std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read(cx, &mut output))
                .await
                .unwrap_err();
        assert!(output.filled().is_empty());
        for message in [false, true] {
            let error = std::future::poll_fn(|cx| {
                if message {
                    Pin::new(&mut reader).poll_read_message(cx, &mut output)
                } else {
                    Pin::new(&mut reader).poll_read(cx, &mut output)
                }
            })
            .await
            .unwrap_err();
            assert_eq!(error.kind(), first_error.kind());
            assert_eq!(error.to_string(), first_error.to_string());
            assert!(output.filled().is_empty());
        }
    }
}

#[tokio::test]
async fn message_padding_and_rejection_preserve_masks_and_nonces() {
    for algorithm in [None, Some(&AES_128_GCM), Some(&CHACHA20_POLY1305)] {
        for padding in [false, true] {
            let (transport, mut peer) = tokio::io::duplex(32768);
            let mut writer =
                response_test_stream(Box::new(transport), algorithm, true, padding, None);
            let mut masks = LengthMask::new(create_shake128_reader(&[23; 16]), padding);
            let mut opening = algorithm.map(|algorithm| {
                OpeningKey::new(
                    UnboundKey::new(algorithm, &vec![42; algorithm.key_len()]).unwrap(),
                    VmessNonceSequence::new(&[23; 16]),
                )
            });
            for payload in [b"first".as_slice(), b"next", b""] {
                let invalid = vec![0; 65536];
                assert_eq!(
                    std::future::poll_fn(
                        |cx| Pin::new(&mut writer).poll_write_message(cx, &invalid)
                    )
                    .await
                    .unwrap_err()
                    .kind(),
                    std::io::ErrorKind::InvalidInput
                );
                if payload.is_empty() && algorithm.is_none() {
                    assert_eq!(
                        std::future::poll_fn(
                            |cx| Pin::new(&mut writer).poll_write_message(cx, payload)
                        )
                        .await
                        .unwrap_err()
                        .kind(),
                        std::io::ErrorKind::InvalidInput,
                    );
                    continue;
                }
                std::future::poll_fn(|cx| Pin::new(&mut writer).poll_write_message(cx, payload))
                    .await
                    .unwrap();
                std::future::poll_fn(|cx| Pin::new(&mut writer).poll_flush_message(cx))
                    .await
                    .unwrap();
                let (pad, mask) = masks.next_values();
                let length = peer.read_u16().await.unwrap() ^ mask;
                assert_eq!(length as usize, payload.len() + writer.tag_len + pad);
                let mut bytes = vec![0; length as usize];
                peer.read_exact(&mut bytes).await.unwrap();
                bytes.truncate(bytes.len() - pad);
                if let Some(opening) = &mut opening {
                    let data = opening.open_in_place(Aad::empty(), &mut bytes).unwrap();
                    assert_eq!(data, payload);
                } else {
                    assert_eq!(bytes, payload);
                }
            }
        }
    }
}

#[tokio::test]
async fn full_output_chunk_is_accepted_with_or_without_pending_length() {
    for pending in [false, true] {
        let (transport, _) = tokio::io::duplex(1);
        let mut stream = response_test_stream(Box::new(transport), None, false, false, None);
        let len = stream.processed_buf.len();
        assert!(len <= u16::MAX as usize);
        stream.unprocessed_buf[..2].copy_from_slice(&(len as u16).to_be_bytes());
        stream.unprocessed_buf[2..2 + len].fill(42);
        stream.unprocessed_end_offset = 2 + len;
        if pending {
            stream.unprocessed_pending_len = Some((0, len));
            stream.unprocessed_start_offset = 2;
        }
        assert!(matches!(
            stream.try_decrypt().unwrap(),
            DecryptState::Success
        ));
        assert_eq!(&*stream.processed_buf, vec![42; len]);
    }
}

#[tokio::test]
async fn padding_larger_than_chunk_is_rejected() {
    let (transport, _) = tokio::io::duplex(1);
    let mut stream = response_test_stream(Box::new(transport), None, true, true, None);
    let (padding, mask) = LengthMask::new(create_shake128_reader(&[23; 16]), true).next_values();
    assert!(padding > 0);
    stream.unprocessed_buf[..2].copy_from_slice(&mask.to_be_bytes());
    stream.unprocessed_end_offset = 2;
    assert!(
        matches!(stream.try_decrypt(), Err(error) if error.kind() == std::io::ErrorKind::InvalidData)
    );
}

fn create_shake128_reader(iv: &[u8]) -> VmessReader {
    let mut hasher = Shake128::default();
    hasher.update(iv);
    hasher.finalize_xof()
}

fn response_test_stream(
    stream: Box<dyn AsyncStream>,
    algorithm: Option<&'static Algorithm>,
    masked: bool,
    padding: bool,
    prefix: Option<BytesMut>,
) -> VmessStream {
    let keys = algorithm.map(|algorithm| {
        let key = vec![42; algorithm.key_len()];
        (
            OpeningKey::new(
                UnboundKey::new(algorithm, &key).unwrap(),
                VmessNonceSequence::new(&[23; 16]),
            ),
            SealingKey::new(
                UnboundKey::new(algorithm, &key).unwrap(),
                VmessNonceSequence::new(&[23; 16]),
            ),
        )
    });
    VmessStream::new(
        stream,
        false,
        keys,
        masked.then(|| create_shake128_reader(&[23; 16])),
        masked.then(|| create_shake128_reader(&[23; 16])),
        padding,
        prefix,
        None,
    )
}

async fn check_response_flushes(payload: &[u8]) {
    // The handler supplies an opaque, already encrypted 38-byte response prefix.
    let prefix = [0x5a; 38];
    for algorithm in [None, Some(&AES_128_GCM), Some(&CHACHA20_POLY1305)] {
        for (masked, padding) in [(false, false), (true, false), (true, true)] {
            let capture = copy_response_with_flush_pressure(
                |stream| async move {
                    response_test_stream(
                        stream,
                        algorithm,
                        masked,
                        padding,
                        Some(BytesMut::from(&prefix[..])),
                    )
                },
                payload,
            )
            .await;
            assert!(capture.first_write_offer.starts_with(&prefix));
            assert!(capture.first_write_offer.len() > prefix.len());
            assert!(capture.data.starts_with(&prefix));

            let (transport, _) = tokio::io::duplex(1);
            let mut decoder = response_test_stream(
                Box::new(PrependStream::new(
                    transport,
                    Some(capture.data[prefix.len()..].into()),
                )),
                algorithm,
                masked,
                padding,
                None,
            );
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).await.unwrap();
            assert_eq!(decoded, payload);

            let mut mask =
                masked.then(|| LengthMask::new(create_shake128_reader(&[23; 16]), padding));
            let tag_len = if algorithm.is_some() {
                ENCRYPTION_TAG_LEN
            } else {
                0
            };
            let mut frame_start = prefix.len();
            let mut eof_count = 0;
            while frame_start < capture.data.len() {
                let (padding_len, length_mask) =
                    mask.as_mut().map_or((0, 0), LengthMask::next_values);
                let encoded_len = u16::from_be_bytes(
                    capture.data[frame_start..frame_start + 2]
                        .try_into()
                        .unwrap(),
                );
                let frame_len = usize::from(encoded_len ^ length_mask);
                assert!(frame_len >= padding_len + tag_len);
                let frame_end = frame_start + 2 + frame_len;
                assert!(frame_end <= capture.data.len());
                let is_eof = frame_len == padding_len + tag_len;
                if frame_start == prefix.len() {
                    // The first offered write contains a complete body frame, not just its prefix.
                    assert!(capture.first_write_offer.len() >= frame_end);
                    assert_eq!(is_eof, payload.is_empty());
                }
                if is_eof {
                    eof_count += 1;
                    assert_eq!(frame_end, capture.data.len());
                    assert_eq!(
                        capture.bytes_before_shutdown,
                        if payload.is_empty() { 0 } else { frame_start }
                    );
                    // read_to_end authenticated the EOF tag and advanced its nonce.
                    assert!(decoder.is_eof);
                }
                frame_start = frame_end;
            }
            assert_eq!(eof_count, 1);
        }
    }
}

#[tokio::test]
async fn response_header_waits_for_content_across_copier_flushes() {
    check_response_flushes(b"first response").await;
}

#[tokio::test]
async fn response_survives_copier_quota_flushes_and_eof() {
    let payload = quota_test_payload();
    check_response_flushes(&payload).await;
}

#[tokio::test]
async fn empty_response_pairs_header_with_eof_only_at_shutdown() {
    check_response_flushes(b"").await;
}

#[test]
fn test_length_mask_creation() {
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, false);

    // Verify it produces u16 values
    let value = mask.next_u16();
    // The value should be deterministic for the same input
    let reader2 = create_shake128_reader(&[0u8; 16]);
    let mut mask2 = LengthMask::new(reader2, false);
    assert_eq!(value, mask2.next_u16());
}

#[test]
fn test_length_mask_with_padding() {
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, true);

    let (padding, _length_mask) = mask.next_values();
    // Padding should be less than MAX_PADDING_LEN (64)
    assert!(padding < MAX_PADDING_LEN);
}

#[test]
fn test_length_mask_without_padding() {
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, false);

    let (padding, _length_mask) = mask.next_values();
    // Padding should always be 0 when disabled
    assert_eq!(padding, 0);
}

#[test]
fn test_length_mask_deterministic() {
    // Same input should produce same sequence
    let reader1 = create_shake128_reader(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ]);
    let mut mask1 = LengthMask::new(reader1, true);

    let reader2 = create_shake128_reader(&[
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ]);
    let mut mask2 = LengthMask::new(reader2, true);

    for _ in 0..10 {
        let (p1, m1) = mask1.next_values();
        let (p2, m2) = mask2.next_values();
        assert_eq!(p1, p2);
        assert_eq!(m1, m2);
    }
}

#[test]
fn test_length_mask_sequence_matches_sing_vmess() {
    // sing-vmess reads padding first (if enabled), then length mask
    // Both are read as big-endian u16 from SHAKE128
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, true);

    // Get first pair
    let (padding1, _length_mask1) = mask.next_values();
    // Get second pair
    let (padding2, _length_mask2) = mask.next_values();

    // Values should be different (SHAKE128 produces pseudo-random output)
    // Though in rare cases they could be equal, so we just check they're valid
    assert!(padding1 < MAX_PADDING_LEN);
    assert!(padding2 < MAX_PADDING_LEN);
}

#[test]
fn test_check_header_response_valid() {
    // Test valid response header
    let response_v = 0x42u8;
    let response_bytes = [response_v, 0x00, 0x00, 0x00]; // auth, opt, cmd, cmdlen
    assert!(check_header_response(&response_bytes, response_v).is_ok());
}

#[test]
fn test_check_header_response_invalid_auth() {
    // Test invalid auth value
    let response_v = 0x42u8;
    let response_bytes = [0x43u8, 0x00, 0x00, 0x00]; // Wrong auth value
    let result = check_header_response(&response_bytes, response_v);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("Invalid response auth value"));
}

#[test]
fn test_check_header_response_with_dynamic_port_flag() {
    // Test with dynamic port flag set (should log warning but not fail)
    let response_v = 0x42u8;
    let response_bytes = [response_v, 0x00, 0x01, 0x00]; // dynamic port flag set
    assert!(check_header_response(&response_bytes, response_v).is_ok());
}

#[test]
fn test_constants() {
    // Verify constants match protocol specification
    assert_eq!(HEADER_TAG_LEN, 16);
    assert_eq!(ENCRYPTION_TAG_LEN, 16);
    assert_eq!(MAX_PADDING_LEN, 64);
    // Chunk size: 8192 data + 16 tag = 8208
    assert_eq!(MAX_ENCRYPTED_WRITE_DATA_SIZE, 8208);
    // Max read size is u16::MAX to handle all clients
    assert_eq!(MAX_ENCRYPTED_READ_DATA_SIZE, 65535);
}

#[test]
fn test_read_header_state_transitions() {
    // Verify state machine enum values
    assert_eq!(
        ReadHeaderState::ReadAeadLength,
        ReadHeaderState::ReadAeadLength
    );
    assert_eq!(ReadHeaderState::Done, ReadHeaderState::Done);
    assert_ne!(ReadHeaderState::ReadAeadLength, ReadHeaderState::Done);
}

#[test]
fn test_aead_key_creation() {
    // Test creating AEAD keys (AES-128-GCM)
    let key = [0x42u8; 16];
    let iv = [0x11u8; 16];

    let opening_unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();
    let sealing_unbound = UnboundKey::new(&AES_128_GCM, &key).unwrap();

    let opening_key = OpeningKey::new(opening_unbound, VmessNonceSequence::new(&iv));
    let sealing_key = SealingKey::new(sealing_unbound, VmessNonceSequence::new(&iv));

    // Keys should be created successfully (no panic)
    // We can't easily test encryption/decryption without the full stream
    // but we verify the keys are valid by checking they exist
    assert!(std::mem::size_of_val(&opening_key) > 0);
    assert!(std::mem::size_of_val(&sealing_key) > 0);
}

#[test]
fn test_chacha20_poly1305_key_creation() {
    // Test creating ChaCha20-Poly1305 keys
    let key = [0x42u8; 16];
    let chacha_key = super::super::md5::create_chacha_key(&key);
    let iv = [0x11u8; 16];

    let opening_unbound = UnboundKey::new(&CHACHA20_POLY1305, &chacha_key).unwrap();
    let sealing_unbound = UnboundKey::new(&CHACHA20_POLY1305, &chacha_key).unwrap();

    let opening_key = OpeningKey::new(opening_unbound, VmessNonceSequence::new(&iv));
    let sealing_key = SealingKey::new(sealing_unbound, VmessNonceSequence::new(&iv));

    assert!(std::mem::size_of_val(&opening_key) > 0);
    assert!(std::mem::size_of_val(&sealing_key) > 0);
}

#[test]
fn test_length_encoding_unmasked() {
    // Test that unmasked length is encoded correctly as big-endian u16
    let length: u16 = 0x1234;
    let bytes = length.to_be_bytes();
    assert_eq!(bytes, [0x12, 0x34]);
}

#[test]
fn test_length_encoding_masked() {
    // Test length XOR masking behavior
    let length: u16 = 0x1234;
    let mask: u16 = 0xabcd;
    let masked = length ^ mask;
    // XOR is reversible
    assert_eq!(masked ^ mask, length);
}

#[test]
fn test_padding_calculation() {
    // Padding is computed as u16 % MAX_PADDING_LEN (64)
    let reader = create_shake128_reader(&[0u8; 16]);
    let mut mask = LengthMask::new(reader, true);

    // Run multiple iterations to verify padding is always in range
    for _ in 0..100 {
        let (padding, _) = mask.next_values();
        assert!(
            padding < MAX_PADDING_LEN,
            "Padding {} should be < {}",
            padding,
            MAX_PADDING_LEN
        );
    }
}

#[test]
fn test_chunk_size_limits() {
    // VMess chunks have specific size limits
    // Write chunk: 8192 + 16 (tag) = 8208 max encrypted size
    // This is different from sing-vmess which uses different defaults

    // Verify the constant values match the protocol
    assert_eq!(MAX_ENCRYPTED_WRITE_DATA_SIZE, 8192 + ENCRYPTION_TAG_LEN);

    // Read allows larger chunks to be compatible with other implementations
    assert_eq!(MAX_ENCRYPTED_READ_DATA_SIZE, 65535);
}

#[test]
fn test_response_header_format() {
    // VMess response header is 4 bytes: auth, opt, cmd, cmdlen
    // auth = response_v (random byte set by client)
    // opt = options (usually 0)
    // cmd = command response (0x01 = dynamic port)
    // cmdlen = additional command data length (usually 0)

    let response_v = 0x42u8;

    // Standard successful response
    let header = [response_v, 0x00, 0x00, 0x00];
    assert!(check_header_response(&header, response_v).is_ok());

    // Response with options set (should still succeed)
    let header_with_opts = [response_v, 0x01, 0x00, 0x00];
    assert!(check_header_response(&header_with_opts, response_v).is_ok());
}

#[tokio::test]
async fn authenticated_lengths_survive_fragmentation_and_reject_tampering() {
    for algorithm in [&AES_128_GCM, &CHACHA20_POLY1305] {
        let chacha = std::ptr::eq(algorithm, &CHACHA20_POLY1305);
        for padding in [false, true] {
            let make_stream = || {
                let (wire, _) = tokio::io::duplex(1);
                response_test_stream(Box::new(wire), Some(algorithm), true, padding, None)
                    .with_authenticated_length(true, chacha, &[42; 16], &[23; 16])
            };
            let mut writer = make_stream();
            let payload = b"authenticated data";
            writer.write_cache[..payload.len()].copy_from_slice(payload);
            writer.write_cache_size = payload.len();
            assert!(writer.create_write_packet().unwrap());
            let packet = writer.write_packet[..writer.write_packet_end_offset].to_vec();
            for split in 0..packet.len() {
                let mut reader = make_stream();
                reader.feed_initial_read_data(&packet[..split]).unwrap();
                assert_eq!(reader.processed_end_offset, 0);
                let at = reader.unprocessed_end_offset;
                reader.unprocessed_buf[at..at + packet.len() - split]
                    .copy_from_slice(&packet[split..]);
                reader.unprocessed_end_offset += packet.len() - split;
                assert!(matches!(
                    reader.try_decrypt().unwrap(),
                    DecryptState::Success
                ));
                assert_eq!(
                    &reader.processed_buf[..reader.processed_end_offset],
                    payload
                );
            }
            for offset in [0, 1, 2, 17, 18, 18 + payload.len()] {
                let mut corrupted = packet.clone();
                corrupted[offset] ^= 0x80;
                assert_eq!(
                    make_stream()
                        .feed_initial_read_data(&corrupted)
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::InvalidData
                );
            }
            // A valid authenticated EOF follows the data using the next nonce.
            writer.write_packet_end_offset = 0;
            assert!(writer.create_write_packet().unwrap());
            let eof = writer.write_packet[..writer.write_packet_end_offset].to_vec();
            let mut reader = make_stream();
            reader.feed_initial_read_data(&packet).unwrap();
            reader.unprocessed_buf[..eof.len()].copy_from_slice(&eof);
            reader.unprocessed_end_offset = eof.len();
            assert!(matches!(
                reader.try_decrypt().unwrap(),
                DecryptState::ReceivedEof
            ));
            // EOF still authenticates the payload tag even with a valid length header.
            let mut reader = make_stream();
            reader.feed_initial_read_data(&packet).unwrap();
            reader.unprocessed_buf[..eof.len()].copy_from_slice(&eof);
            reader.unprocessed_buf[18] ^= 1;
            reader.unprocessed_end_offset = eof.len();
            assert_eq!(
                reader.try_decrypt().err().unwrap().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }
}

#[tokio::test]
async fn coalesced_udp_packets_keep_boundaries_and_small_buffer_can_retry() {
    for auth in [false, true] {
        let (wire, _) = tokio::io::duplex(1);
        let mut writer = response_test_stream(Box::new(wire), Some(&AES_128_GCM), true, true, None)
            .with_authenticated_length(auth, false, &[42; 16], &[23; 16]);
        let mut packets = Vec::new();
        for payload in [b"first".as_slice(), b"second", b"third"] {
            writer.write_packet_end_offset = 0;
            writer.write_cache[..payload.len()].copy_from_slice(payload);
            writer.write_cache_size = payload.len();
            writer.create_write_packet().unwrap();
            packets.extend_from_slice(&writer.write_packet[..writer.write_packet_end_offset]);
        }
        let (wire, _peer) = tokio::io::duplex(1);
        let mut reader = response_test_stream(Box::new(wire), Some(&AES_128_GCM), true, true, None)
            .with_authenticated_length(auth, false, &[42; 16], &[23; 16]);
        reader.is_udp = true;
        reader.feed_initial_read_data(&packets).unwrap();
        for payload in [b"first".as_slice(), b"second", b"third"] {
            let mut tiny = [0; 1];
            assert_eq!(
                std::future::poll_fn(
                    |cx| Pin::new(&mut reader).poll_read_message(cx, &mut ReadBuf::new(&mut tiny))
                )
                .await
                .unwrap_err()
                .kind(),
                std::io::ErrorKind::InvalidInput
            );
            let mut bytes = [0; 32];
            let mut output = ReadBuf::new(&mut bytes);
            std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read_message(cx, &mut output))
                .await
                .unwrap();
            assert_eq!(output.filled(), payload);
        }
    }
}

#[tokio::test]
async fn transport_eof_rejects_incomplete_authenticated_frames() {
    for auth in [false, true] {
        let (wire, _) = tokio::io::duplex(1);
        let mut writer =
            response_test_stream(Box::new(wire), Some(&AES_128_GCM), true, false, None)
                .with_authenticated_length(auth, false, &[42; 16], &[23; 16]);
        writer.write_cache[..4].copy_from_slice(b"data");
        writer.write_cache_size = 4;
        writer.create_write_packet().unwrap();
        let packet = writer.write_packet[..writer.write_packet_end_offset].to_vec();
        for split in 1..packet.len() {
            let (wire, mut peer) = tokio::io::duplex(128);
            tokio::io::AsyncWriteExt::write_all(&mut peer, &packet[..split])
                .await
                .unwrap();
            drop(peer);
            let mut reader =
                response_test_stream(Box::new(wire), Some(&AES_128_GCM), true, false, None)
                    .with_authenticated_length(auth, false, &[42; 16], &[23; 16]);
            assert_eq!(
                reader.read(&mut [0; 32]).await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        }
    }
}

#[tokio::test]
async fn full_plaintext_buffer_does_not_wait_for_more_transport_bytes() {
    let (wire, _peer) = tokio::io::duplex(1);
    let mut reader = response_test_stream(Box::new(wire), None, false, false, None);
    reader.processed_buf.fill(7);
    reader.processed_end_offset = reader.processed_buf.len();
    reader.unprocessed_buf[..6].copy_from_slice(&[0, 4, 1, 2, 3, 4]);
    reader.unprocessed_end_offset = 6;
    assert!(matches!(
        reader.try_decrypt().unwrap(),
        DecryptState::BufferFull
    ));
    let mut all = vec![0; reader.processed_buf.len() + 4];
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        reader.read_exact(&mut all),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&all[all.len() - 4..], &[1, 2, 3, 4]);
}
