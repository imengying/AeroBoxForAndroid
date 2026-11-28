//! HTTP/3 application settings authenticated by the TLS handshake.
use std::collections::HashSet;

use crate::{
    config::Settings,
    error::{Code, ConnectionError, LocalError},
    proto::{
        frame::{SettingId, Settings as WireSettings},
        varint::VarInt,
    },
};

pub(super) fn parse(mut bytes: &[u8]) -> Result<Option<Settings>, ConnectionError> {
    // ALPS is a TLS extension with a 16-bit length. Do not allow callers of the
    // public builder to bypass that bound and create unbounded parsing work.
    if bytes.len() > u16::MAX as usize {
        return Err(error(
            Code::H3_EXCESSIVE_LOAD,
            "ALPS exceeds the TLS extension limit",
        ));
    }
    let mut settings = None;
    while !bytes.is_empty() {
        let kind = integer(&mut bytes)?;
        let length = integer(&mut bytes)?;
        if length > bytes.len() as u64 {
            return Err(error(Code::H3_FRAME_ERROR, "incomplete HTTP/3 ALPS frame"));
        }
        let (payload, rest) = bytes.split_at(length as usize);
        bytes = rest;
        match kind {
            4 => {
                if settings.is_some() {
                    return Err(error(
                        Code::H3_FRAME_UNEXPECTED,
                        "multiple ALPS SETTINGS frames",
                    ));
                }
                settings = Some(parse_settings(payload)?);
            }
            // Request, push, shutdown, HTTP/2-only and PRIORITY_UPDATE frames
            // have no meaning during the application-settings handshake.
            0 | 1 | 2 | 3 | 5 | 6 | 7 | 8 | 9 | 13 | 0x4d | 0xf0700 | 0xf0701 => {
                return Err(error(
                    Code::H3_FRAME_UNEXPECTED,
                    "forbidden HTTP/3 ALPS frame",
                ));
            }
            0x89 => validate_accept_ch(payload)?,
            0x0c => validate_origins(payload)?,
            _ => {} // Unknown extension frames, including GREASE, are ignored.
        }
    }
    Ok(settings)
}

fn validate_accept_ch(mut payload: &[u8]) -> Result<(), ConnectionError> {
    while !payload.is_empty() {
        // Each entry has a varint-length origin followed by varint-length hints.
        for _ in 0..2 {
            let length = integer(&mut payload)?;
            if length > payload.len() as u64 {
                return Err(error(
                    Code::H3_FRAME_ERROR,
                    "incomplete ALPS ACCEPT_CH field",
                ));
            }
            payload = &payload[length as usize..];
        }
    }
    Ok(())
}

fn validate_origins(mut payload: &[u8]) -> Result<(), ConnectionError> {
    while !payload.is_empty() {
        if payload.len() < 2 {
            return Err(error(Code::H3_FRAME_ERROR, "incomplete ALPS ORIGIN length"));
        }
        let length = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        payload = &payload[2..];
        if length > payload.len() {
            return Err(error(Code::H3_FRAME_ERROR, "incomplete ALPS ORIGIN field"));
        }
        payload = &payload[length..];
    }
    Ok(())
}

fn parse_settings(mut payload: &[u8]) -> Result<Settings, ConnectionError> {
    let mut seen = HashSet::new();
    let mut settings = WireSettings::default();
    while !payload.is_empty() {
        let id = integer(&mut payload)
            .map_err(|_| error(Code::H3_SETTINGS_ERROR, "incomplete ALPS setting"))?;
        let value = integer(&mut payload)
            .map_err(|_| error(Code::H3_SETTINGS_ERROR, "incomplete ALPS setting"))?;
        if !seen.insert(id) {
            return Err(error(Code::H3_SETTINGS_ERROR, "duplicate ALPS setting"));
        }
        if matches!(id, 0 | 2 | 3 | 4 | 5) {
            return Err(error(
                Code::H3_SETTINGS_ERROR,
                "HTTP/2 setting in HTTP/3 ALPS",
            ));
        }
        if matches!(id, 8 | 0x33 | 0x2b603742) && value > 1 {
            return Err(error(
                Code::H3_SETTINGS_ERROR,
                "ALPS boolean setting is not zero or one",
            ));
        }
        if matches!(id, 1 | 6 | 7 | 8 | 0x33 | 0x2b603742 | 0x2b603743) {
            settings
                .insert(SettingId(id), value)
                .map_err(|_| error(Code::H3_SETTINGS_ERROR, "invalid ALPS setting"))?;
        }
    }
    // Dynamic QPACK remains disabled locally. Peer capacity is permission to
    // use it, not an obligation; do not advertise or enable an unimplemented table.
    Ok((&settings).into())
}

fn integer(bytes: &mut &[u8]) -> Result<u64, ConnectionError> {
    VarInt::decode(bytes)
        .map(VarInt::into_inner)
        .map_err(|_| error(Code::H3_FRAME_ERROR, "incomplete HTTP/3 ALPS integer"))
}

fn error(code: Code, reason: &str) -> ConnectionError {
    ConnectionError::Local {
        error: LocalError::Application {
            code,
            reason: reason.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        VarInt::from_u64(kind).unwrap().encode(&mut bytes);
        VarInt::from_u64(payload.len() as u64)
            .unwrap()
            .encode(&mut bytes);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn setting(id: u64, value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        VarInt::from_u64(id).unwrap().encode(&mut bytes);
        VarInt::from_u64(value).unwrap().encode(&mut bytes);
        bytes
    }

    #[test]
    fn alps_accepts_complete_settings_and_unknown_frames() {
        assert!(parse(&[]).unwrap().is_none());
        let payload = [
            setting(6, 4096),
            setting(8, 1),
            setting(1, 65536),
            setting(7, 100),
            setting(12345, 17),
        ]
        .concat();
        let bytes = [
            frame(0x21, b"ignored"),
            frame(4, &payload),
            frame(0x40, b"also ignored"),
        ]
        .concat();
        let settings = parse(&bytes).unwrap().unwrap();
        assert_eq!(settings.max_field_section_size, 4096);
        assert!(settings.enable_extended_connect);
        assert!(!settings.enable_datagram);
    }

    #[test]
    fn alps_rejects_duplicate_invalid_and_incomplete_frames_or_settings() {
        for kind in [0, 1, 2, 3, 5, 6, 7, 8, 9, 13, 0x4d, 0xf0700, 0xf0701] {
            assert!(parse(&frame(kind, &[])).is_err(), "forbidden frame {kind}");
        }
        assert!(parse(&[frame(4, &[]), frame(4, &[])].concat()).is_err());
        for id in [0, 2, 3, 4, 5] {
            assert!(parse(&frame(4, &setting(id, 0))).is_err());
        }
        for id in [8, 0x33, 0x2b603742] {
            assert!(parse(&frame(4, &setting(id, 2))).is_err());
        }
        for id in [6, 12345] {
            let repeated = [setting(id, 1), setting(id, 2)].concat();
            assert!(
                parse(&frame(4, &repeated)).is_err(),
                "duplicate setting {id}"
            );
        }
        for truncated in [
            vec![0x40],
            vec![4, 0x40],
            vec![4, 3, 6, 0],
            frame(4, &[6]),
            frame(4, &[6, 0x40]),
        ] {
            assert!(parse(&truncated).is_err());
        }
        assert!(parse(&vec![0; u16::MAX as usize + 1]).is_err());
    }

    #[test]
    fn alps_validates_known_hint_frame_lengths_before_ignoring_them() {
        assert!(parse(&frame(0x89, &[1, b'a', 1, b'b', 0, 0])).is_ok());
        assert!(parse(&frame(0x0c, &[0, 1, b'a', 0, 0])).is_ok());
        for payload in [vec![1], vec![1, b'a'], vec![0, 2, b'b'], vec![0x40]] {
            assert!(parse(&frame(0x89, &payload)).is_err());
        }
        for payload in [vec![0], vec![0, 2, b'a']] {
            assert!(parse(&frame(0x0c, &payload)).is_err());
        }
    }
}
