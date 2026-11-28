#![cfg(feature = "cli")]

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

use tendns::{
    config::Config,
    names::canonical_name,
    protocol::{Entry, Publication, Secret, Value, decrypt},
    resolver::{Clock, SystemClock},
};

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl Fixture {
    fn new(text: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tendns.toml");
        fs::write(&path, text).unwrap();
        Self {
            _directory: directory,
            path,
        }
    }

    fn basic() -> Self {
        Self::new(&format!(
            "valid_for='2h'\n[[discovery]]\ndomain='example.com'\nkey='{KEY}'"
        ))
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tendns"))
            .arg("--config")
            .arg(&self.path)
            .args(args)
            .output()
            .unwrap()
    }

    fn publication(&self, name: &str, args: &[&str]) -> Publication {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let output = String::from_utf8(output.stdout).unwrap();
        assert_eq!(output.lines().count(), 1);
        assert!(output.starts_with("td1."));
        assert!(!output.contains(KEY));
        let config = Config::load(&self.path).unwrap();
        let owner = canonical_name(name).unwrap();
        decrypt(
            output.trim().as_bytes(),
            &config.discovery_for(&owner).unwrap().key,
            &owner,
            SystemClock.now().unwrap(),
        )
        .unwrap()
    }
}

#[test]
fn offline_cli_generates_mixed_publication_with_explicit_validity() {
    let fixture = Fixture::basic();
    let publication = fixture.publication(
        "example.com",
        &[
            "txt",
            "--name",
            "EXAMPLE.COM",
            "--entry",
            "@:A:192.0.2.1",
            "--entry",
            "nas:AAAA:2001:db8::1",
            "--entry",
            "www:CNAME:target.net",
            "--valid-for",
            "1h",
        ],
    );
    assert_eq!(publication.expires_at - publication.issued_at, 3600);
    assert_eq!(
        publication.entries,
        vec![
            Entry {
                subdomain: String::new(),
                value: Value::A("192.0.2.1".parse().unwrap())
            },
            Entry {
                subdomain: "nas".into(),
                value: Value::Aaaa("2001:db8::1".parse().unwrap())
            },
            Entry {
                subdomain: "www".into(),
                value: Value::Cname(canonical_name("target.net").unwrap())
            },
        ]
    );
}

#[test]
fn repeated_address_flags_apply_hidden_label_and_configured_validity() {
    let fixture = Fixture::basic();
    let publication = fixture.publication(
        "example.com",
        &[
            "txt",
            "--name",
            "example.com",
            "--subdomain",
            "NAS",
            "--a",
            "192.0.2.1",
            "--a",
            "192.0.2.2",
            "--aaaa",
            "2001:db8::1",
            "--aaaa",
            "2001:db8::2",
        ],
    );
    assert_eq!(publication.expires_at - publication.issued_at, 7200);
    assert_eq!(publication.entries.len(), 4);
    assert!(publication.entries.iter().all(|e| e.subdomain == "nas"));
    assert_eq!(
        publication.entries[1].value,
        Value::A("192.0.2.2".parse().unwrap())
    );
    assert_eq!(
        publication.entries[3].value,
        Value::Aaaa("2001:db8::2".parse().unwrap())
    );
    let alias = fixture.publication(
        "example.com",
        &[
            "txt",
            "--name",
            "example.com",
            "--cname",
            "TARGET.NET",
            "--subdomain",
            "WWW",
        ],
    );
    assert_eq!(
        alias.entries,
        vec![Entry {
            subdomain: "www".into(),
            value: Value::Cname(canonical_name("target.net").unwrap())
        }]
    );
}

#[test]
fn txt_uses_the_most_specific_domains_distinct_key() {
    let child_key = Secret::generate().unwrap();
    let fixture = Fixture::new(&format!(
        "[[discovery]]\ndomain='example.com'\nkey='{KEY}'\n[[discovery]]\ndomain='inner.example.com'\nkey='{child_key}'"
    ));
    let output = fixture.run(&["txt", "--name", "a.inner.example.com", "--a", "192.0.2.1"]);
    assert!(output.status.success());
    let value = String::from_utf8(output.stdout).unwrap();
    let owner = canonical_name("a.inner.example.com").unwrap();
    let now = SystemClock.now().unwrap();
    assert!(
        decrypt(
            value.trim().as_bytes(),
            &Secret::decode(&child_key).unwrap(),
            &owner,
            now
        )
        .is_ok()
    );
    assert!(
        decrypt(
            value.trim().as_bytes(),
            &Secret::decode(KEY).unwrap(),
            &owner,
            now
        )
        .is_err()
    );
}

#[test]
fn invalid_txt_requests_fail_without_output_or_secret_disclosure() {
    let fixture = Fixture::basic();
    for args in [
        vec!["txt", "--name", "example.com"],
        vec!["txt", "--name", "other.net", "--a", "192.0.2.1"],
        vec![
            "txt",
            "--name",
            "example.com",
            "--subdomain",
            "a.b",
            "--a",
            "192.0.2.1",
        ],
        vec!["txt", "--name", "example.com", "--entry", "a.b:A:192.0.2.1"],
        vec!["txt", "--name", "example.com", "--a", "not-an-ip"],
        vec!["txt", "--name", "example.com", "--aaaa", "192.0.2.1"],
        vec!["txt", "--name", "example.com", "--cname", "a..net"],
        vec![
            "txt",
            "--name",
            "example.com",
            "--a",
            "192.0.2.1",
            "--cname",
            "target.net",
        ],
        vec!["txt", "--name", "example.com", "--entry", "a:MX:target.net"],
        vec![
            "txt",
            "--name",
            "example.com",
            "--a",
            "192.0.2.1",
            "--valid-for",
            "0s",
        ],
        vec![
            "txt",
            "--name",
            "example.com",
            "--a",
            "192.0.2.1",
            "--valid-for",
            "500ms",
        ],
        vec![
            "txt",
            "--name",
            "example.com",
            "--a",
            "192.0.2.1",
            "--valid-for",
            "invalid",
        ],
        vec!["serve"],
    ] {
        let output = fixture.run(&args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains(KEY));
    }
}

#[test]
fn malformed_config_diagnostics_do_not_echo_keys() {
    let fixture = Fixture::new(&format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}"));
    let output = fixture.run(&["txt", "--name", "example.com", "--a", "192.0.2.1"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(KEY));
}

#[test]
fn keygen_needs_no_config_and_does_not_repeat() {
    let mut keys = Vec::new();
    let directory = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        let result = Command::new(env!("CARGO_BIN_EXE_tendns"))
            .arg("--config")
            .arg(directory.path().join("nonexistent.toml"))
            .arg("keygen")
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        let key = String::from_utf8(result.stdout).unwrap();
        assert_eq!(key.lines().count(), 1);
        assert_eq!(key.trim().len(), 43);
        Secret::decode(key.trim()).unwrap();
        keys.push(key);
    }
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn cloudflare_commands_require_an_environment_token_without_disclosing_keys() {
    let fixture = Fixture::basic();
    for args in [
        vec![
            "cloudflare-set",
            "--name",
            "nas.example.com",
            "--a",
            "192.0.2.1",
        ],
        vec![
            "cloudflare-remove",
            "--name",
            "nas.example.com",
            "--type",
            "A",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_tendns"))
            .arg("--config")
            .arg(&fixture.path)
            .args(args)
            .env_remove("CLOUDFLARE_API_TOKEN")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("CLOUDFLARE_API_TOKEN"));
        assert!(!error.contains(KEY));
    }
}
