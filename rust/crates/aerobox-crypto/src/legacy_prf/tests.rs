use super::*;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn secret_halves_overlap_only_at_the_middle_byte() {
    for (input, left, right) in [
        ("", "", ""),
        ("00", "00", "00"),
        ("0011", "00", "11"),
        ("001122", "0011", "1122"),
        ("00112233", "0011", "2233"),
    ] {
        let input = hex(input);
        let (a, b) = split_secret(&input);
        assert_eq!(a, hex(left));
        assert_eq!(b, hex(right));
    }
}

#[test]
fn fixed_utls_gnutls_master_secret_key_expansion_and_exporter_vectors() {
    // uTLS v1.8.7 prf_test.go, first GnuTLS-generated TLS 1.0 vector. The
    // fixture's record cipher is irrelevant to the PRF and is not advertised.
    let secret = hex(
        "0302cac83ad4b1db3b9ab49ad05957de2a504a634a386fc600889321e1a971f57479466830ac3e6f468e87f5385fa0c5",
    );
    let client = hex("4ae66303755184a3917fcb44880605fcc53baa01912b22ed94473fc69cebd558");
    let server = hex("4ae663020ec16e6bb5130be918cfcafd4d765979a3136a5d50c593446e4e44db");
    let mut master = [0xa5; 48];
    TLS10_PRF.for_secret(
        &mut master,
        &secret,
        b"master secret",
        &[client.as_slice(), server.as_slice()].concat(),
    );
    assert_eq!(
        master.as_slice(),
        hex(
            "3d851bab6e5556e959a16bc36d66cfae32f672bfa9ecdef6096cbb1b23472df1da63dbbd9827606413221d149ed08ceb"
        )
    );
    let mut keys = [0; 72];
    TLS10_PRF.for_secret(
        &mut keys,
        &master,
        b"key expansion",
        &[server.as_slice(), client.as_slice()].concat(),
    );
    assert_eq!(
        keys.as_slice(),
        hex(concat!(
            "805aaa19b3d2c0a0759a4b6c9959890e08480119",
            "2d22f9fe519c075c16448305ceee209fc24ad109",
            "d50b5771244f850cd8117a9ccafe2cf1",
            "e076e33206b30507a85c32855acd0919",
        ))
    );
    let mut exported = [0; 32];
    let seed = [client.as_slice(), server.as_slice()].concat();
    TLS10_PRF.for_secret(&mut exported, &master, b"label", &seed);
    assert_eq!(
        exported.as_slice(),
        hex("93fba89599b6321ae538e27c6548ceb8b46821864318f5190d64a375e5d69d41")
    );
    let seed = [seed.as_slice(), b"\x00\x07context"].concat();
    TLS10_PRF.for_secret(&mut exported, &master, b"label", &seed);
    assert_eq!(
        exported.as_slice(),
        hex("4d1bb6fc278c37d27aa6e2a13c2e079095d143272c2aa939da33d88c1c0cec22")
    );
}

#[test]
fn odd_secrets_binary_labels_long_hmac_keys_and_partial_output_blocks() {
    // Independent Python hashlib/hmac implementation, recorded in stage notes.
    let cases = [
        (
            vec![0, 0x11, 0x22],
            b"test label".to_vec(),
            (0..16).collect::<Vec<u8>>(),
            "69ffab499ae664ee49ac6c289f882abaa08bbac883583d397a5d5687b4693ec5d6b4a4900ef2b4b2bcd43a23d0e4d4f6b890050c829f5576562224faf4cb001f06784a0eb6391c04e8f6079529def363069f0e1c5bfb2b8260d0336da103a9c06de43291",
        ),
        (
            vec![0x80],
            b"A\0B".to_vec(),
            vec![0xff, 0, 0x81],
            "039dadd7a0404a0ee17cde25e964d058a499d4c8fdaf45d1439c68418957c281f1995758015a0f7b74bfbbf1a3aac3049212cff8b45a943b957ce57b9b6f89d310b8b74a3db08b2c5f9890852f0c35b9b506bfa6a04165413bd775960712920c1ac2c74c",
        ),
        (
            (0..129).collect::<Vec<u8>>(),
            b"key expansion".to_vec(),
            (0..64).collect::<Vec<u8>>(),
            "65854be4ba4b50094825e15913385a56703bd3c6df352e635026002f4117b6dd89b8075757da4def45c498cd0c309a88089ef88f151ce6cbe2dd86003b5269f4ee4155581c3196d5a1dd8c87bdcc349b4fbafa8fb073776b9833a75249ee131de8ae4913",
        ),
    ];
    for (secret, label, seed, expected) in cases {
        let expected = hex(expected);
        for len in [0, 1, 12, 15, 16, 17, 19, 20, 21, 31, 32, 33, 48, 99, 100] {
            let mut out = vec![0xa5; len];
            TLS10_PRF.for_secret(&mut out, &secret, &label, &seed);
            assert_eq!(out, expected[..len]);
        }
    }
    assert!(!TLS10_PRF.fips());
}

struct Exchange {
    group: rustls::NamedGroup,
}
impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<rustls::crypto::SharedSecret, Error> {
        if peer != b"validated peer" {
            return Err(Error::General("invalid test key exchange".into()));
        }
        Ok(rustls::crypto::SharedSecret::from(&[0, 0, 1, 2, 3][..]))
    }
    fn pub_key(&self) -> &[u8] {
        b"our key"
    }
    fn group(&self) -> rustls::NamedGroup {
        self.group
    }
}

#[test]
fn key_exchange_validation_and_pre_tls13_shared_secret_encoding() {
    for group in [rustls::NamedGroup::X25519, rustls::NamedGroup::FFDHE2048] {
        let mut out = [0xa5; 48];
        TLS10_PRF
            .for_key_exchange(
                &mut out,
                Box::new(Exchange { group }),
                b"validated peer",
                b"master secret",
                b"randoms",
            )
            .unwrap();
        let secret: &[u8] = if group == rustls::NamedGroup::FFDHE2048 {
            &[1, 2, 3]
        } else {
            &[0, 0, 1, 2, 3]
        };
        let mut expected = [0; 48];
        TLS10_PRF.for_secret(&mut expected, secret, b"master secret", b"randoms");
        assert_eq!(out, expected);
        let mut out = [0xa5; 48];
        assert!(
            TLS10_PRF
                .for_key_exchange(
                    &mut out,
                    Box::new(Exchange { group }),
                    b"invalid",
                    b"master secret",
                    b"randoms"
                )
                .is_err()
        );
        assert_eq!(out, [0xa5; 48]);
    }
}
