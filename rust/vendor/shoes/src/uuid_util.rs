use std::fmt::Write;

use aerobox_primitives::rand::{SecureRandom, SystemRandom};

/// Fixed sing-vmess clients use any syntactically valid UUID verbatim. Other
/// strings become UUID v5 with the nil namespace, including empty/Unicode IDs.
/// This does not change the stricter native server UUID configuration parser.
pub(crate) fn parse_vmess_user_id(value: &str) -> [u8; 16] {
    if let Some(uuid) = parse_uuid_text(value.as_bytes()) {
        return uuid;
    }
    use aerobox_primitives::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
    let mut hash = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    hash.update(&[0; 16]);
    hash.update(value.as_bytes());
    let digest = hash.finish();
    let mut uuid: [u8; 16] = digest.as_ref()[..16].try_into().unwrap();
    uuid[6] = (uuid[6] & 0x0f) | 0x50;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

fn parse_uuid_text(mut text: &[u8]) -> Option<[u8; 16]> {
    // Match gofrs/uuid/v5's accepted shapes and case-sensitive URN prefix.
    match text.len() {
        32 | 36 => {}
        34 | 38 if text[0] == b'{' && text[text.len() - 1] == b'}' => {
            text = &text[1..text.len() - 1];
        }
        41 | 45 if text.starts_with(b"urn:uuid:") => text = &text[9..],
        _ => return None,
    }
    let canonical = text.len() == 36;
    if canonical && [8, 13, 18, 23].iter().any(|&i| text[i] != b'-') {
        return None;
    }
    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }
    let mut uuid = [0; 16];
    let mut position = 0;
    for byte in &mut uuid {
        if canonical && matches!(position, 8 | 13 | 18 | 23) {
            position += 1;
        }
        *byte = (nibble(text[position])? << 4) | nibble(text[position + 1])?;
        position += 2;
    }
    Some(uuid)
}

/// Parse a UUID v4 string (with or without dashes) into 16 bytes.
/// Validates that the UUID has version 4 and RFC 4122 variant.
#[inline]
pub fn parse_uuid(uuid_str: &str) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(16);
    let mut first_nibble: Option<u8> = None;
    for &c in uuid_str.as_bytes() {
        let hex = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            b'-' => continue,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid uuid: {uuid_str}"),
                ));
            }
        };
        if let Some(first) = first_nibble.take() {
            bytes.push((first << 4) | hex);
        } else {
            first_nibble = Some(hex);
        }
    }
    if first_nibble.is_some() || bytes.len() != 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid uuid: {uuid_str}"),
        ));
    }

    // Validate version 4: upper nibble of byte 6 must be 4
    if (bytes[6] >> 4) != 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UUID is not version 4: {uuid_str}"),
        ));
    }

    // Validate variant (RFC 4122): upper 2 bits of byte 8 must be 10
    if (bytes[8] >> 6) != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("UUID does not have RFC 4122 variant: {uuid_str}"),
        ));
    }

    Ok(bytes)
}

/// Generate a random UUID v4 and return it as a formatted string.
#[inline]
pub fn generate_uuid() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).expect("RNG failed");

    // Set version (4) in bits 12-15 of byte 6
    bytes[6] = (bytes[6] & 0x0f) | 0x40;

    // Set variant (RFC 4122) in bits 6-7 of byte 8
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut s = String::with_capacity(36);
    for (i, &b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_uuid_format() {
        let uuid = generate_uuid();
        // Check format: 8-4-4-4-12
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().nth(8), Some('-'));
        assert_eq!(uuid.chars().nth(13), Some('-'));
        assert_eq!(uuid.chars().nth(18), Some('-'));
        assert_eq!(uuid.chars().nth(23), Some('-'));

        // Check version (4) at position 14
        assert_eq!(uuid.chars().nth(14), Some('4'));

        // Check variant at position 19 (must be 8, 9, a, or b)
        let variant_char = uuid.chars().nth(19).unwrap();
        assert!(
            variant_char == '8'
                || variant_char == '9'
                || variant_char == 'a'
                || variant_char == 'b'
        );
    }

    #[test]
    fn test_generate_uuid_roundtrip() {
        let uuid = generate_uuid();
        let bytes = parse_uuid(&uuid).unwrap();
        assert_eq!(bytes.len(), 16);

        // Verify version nibble
        assert_eq!(bytes[6] >> 4, 4);

        // Verify variant bits
        assert_eq!(bytes[8] >> 6, 2);
    }

    #[test]
    fn test_parse_uuid_with_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_without_dashes() {
        // Valid v4 UUID (version=4, variant=10xx)
        let uuid = "550e8400e29b41d4a716446655440000";
        let bytes = parse_uuid(uuid).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x0e);
    }

    #[test]
    fn test_parse_uuid_rejects_non_v4() {
        // Version 1 UUID (version nibble = 1)
        let uuid = "550e8400-e29b-11d4-a716-446655440000";
        assert!(parse_uuid(uuid).is_err());
    }

    #[test]
    fn test_parse_uuid_rejects_wrong_variant() {
        // Wrong variant (upper 2 bits of byte 8 = 11 instead of 10)
        let uuid = "550e8400-e29b-41d4-c716-446655440000";
        assert!(parse_uuid(uuid).is_err());
    }
}

#[cfg(test)]
mod compatible_client_ids {
    use super::*;

    #[test]
    fn fixed_name_vectors_and_all_uuid_shapes() {
        for (name, expected) in [
            ("", "e129f27c51035c5c844bcdf0a15e160d"),
            ("test-user", "ebf60aed2fea54fba7f249898ad18b8c"),
            ("用户", "0493110b9e245b2d9beac3512239cf7c"),
            (
                "550e8400-e29b-11d4-a716-446655440000",
                "550e8400e29b11d4a716446655440000",
            ),
            (
                "00000000-0000-0000-0000-000000000000",
                "00000000000000000000000000000000",
            ),
            (
                "550E8400E29B41D4C716446655440000",
                "550e8400e29b41d4c716446655440000",
            ),
            (
                "{550e8400e29b41d4a716446655440000}",
                "550e8400e29b41d4a716446655440000",
            ),
            (
                "{550e8400-e29b-41d4-a716-446655440000}",
                "550e8400e29b41d4a716446655440000",
            ),
            (
                "urn:uuid:550e8400e29b41d4a716446655440000",
                "550e8400e29b41d4a716446655440000",
            ),
            (
                "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
                "550e8400e29b41d4a716446655440000",
            ),
            (
                "URN:UUID:550e8400-e29b-41d4-a716-446655440000",
                "c7258721f8bd57bc87200a60c583081a",
            ),
            (
                "-550e8400e29b41d4a716446655440000",
                "a63caca09f12597d90e3f40d3836027a",
            ),
            (
                "550e8400-e29b41d4-a716-446655440000",
                "2e3e5875acfc5c039ff55f82ec8d41a8",
            ),
            (" test-user ", "04a89ffb51d65fc59030b793d5ed2b26"),
            ("nul\0byte", "a6b3649cc6e15a82992857a73752b9f3"),
        ] {
            let actual = parse_vmess_user_id(name);
            let hex = actual
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(hex, expected, "{name:?}");
        }
    }

    #[test]
    fn v5_names_are_byte_exact_and_strict_server_policy_stays_separate() {
        assert_ne!(
            parse_vmess_user_id("test-user"),
            parse_vmess_user_id(" test-user ")
        );
        assert_ne!(parse_vmess_user_id("é"), parse_vmess_user_id("e\u{301}"));
        assert!(parse_uuid("550e8400-e29b-11d4-a716-446655440000").is_err());
        assert!(parse_uuid("test-user").is_err());
    }
}
