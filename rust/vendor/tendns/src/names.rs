use anyhow::{Result, ensure};
use hickory_proto::rr::Name;

pub fn canonical_name(value: &str) -> Result<Name> {
    let value = value.strip_suffix('.').unwrap_or(value);
    ensure!(!value.is_empty(), "DNS name must not be the root");
    for label in value.split('.') {
        validate_label(label)?;
    }
    Ok(Name::from_ascii(format!(
        "{}.",
        value.to_ascii_lowercase()
    ))?)
}

pub fn validate_label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-'),
        "expected one ASCII hostname label (1-63 bytes)"
    );
    Ok(())
}

pub fn entry_name(owner: &Name, subdomain: &str) -> Result<Name> {
    if subdomain.is_empty() {
        return Ok(owner.clone());
    }
    validate_label(subdomain)?;
    Ok(Name::from_ascii(subdomain)?
        .append_domain(owner)?
        .to_lowercase())
}

pub fn canonical_wire(owner: &Name) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(255);
    for label in owner.iter() {
        bytes.push(label.len() as u8);
        bytes.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    bytes.push(0);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_names_and_boundaries() {
        let name = canonical_name("HOME.Example.com").unwrap();
        assert_eq!(name.to_ascii(), "home.example.com.");
        assert_eq!(canonical_wire(&name), b"\x04home\x07example\x03com\0");
        for bad in [
            "",
            ".",
            "a..com",
            "a\\.b.com",
            "-a.com",
            "a-.com",
            "a_b.com",
        ] {
            assert!(canonical_name(bad).is_err(), "{bad}");
        }
        assert!(entry_name(&name, "a.b").is_err());
    }
}
