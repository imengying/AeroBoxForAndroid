use aerobox_primitives::{
    agreement, digest, kem,
    signature::{self, KeyPair},
};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>().0.iter()
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn rfc7748_x25519_and_noncontributory_peer() {
    let private = agreement::PrivateKey::from_private_key(
        &agreement::X25519,
        &hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
    )
    .unwrap();
    assert_eq!(
        private.compute_public_key().unwrap().as_ref(),
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    let peer = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = agreement::agree(
        &private,
        agreement::UnparsedPublicKey::new(&agreement::X25519, peer),
        (),
        |s| Ok(s.to_vec()),
    )
    .unwrap();
    assert_eq!(
        shared,
        hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    for invalid in [vec![0; 32], vec![1; 31], {
        let mut p = vec![0; 32];
        p[0] = 1;
        p
    }] {
        let result = agreement::agree(
            &private,
            agreement::UnparsedPublicKey::new(&agreement::X25519, invalid),
            (),
            |_| -> Result<(), ()> { panic!("invalid peer must not expose a secret") },
        );
        assert!(result.is_err());
    }
}

#[test]
fn rfc8032_ed25519_signature() {
    let key = signature::Ed25519KeyPair::from_seed_unchecked(&hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))
    .unwrap();
    assert_eq!(
        key.public_key().as_ref(),
        hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let sig = key.sign(b"");
    assert_eq!(
        sig.as_ref(),
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    let public = signature::UnparsedPublicKey::new(&signature::ED25519, key.public_key().as_ref());
    public.verify(b"", sig.as_ref()).unwrap();
    assert!(public.verify(b"changed", sig.as_ref()).is_err());
    assert!(public.verify(b"", &sig.as_ref()[..63]).is_err());
}

#[test]
fn mlkem_seed_matches_go_and_rejects_malformed_keys() {
    use ml_kem::kem::KeyExport;
    let key = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::from_seed([0; 64].into());
    let public = key.encapsulation_key().to_bytes();
    assert_eq!(
        digest::digest(&digest::SHA256, &public).as_ref(),
        hex("f95c185fe5b2335d2fc938dd889c6425944acd74376b6952bf1130f720f6ba99")
    );
    assert!(kem::EncapsulationKey::new(&kem::ML_KEM_768, &[0xff; 1184]).is_err());
    assert!(kem::EncapsulationKey::new(&kem::ML_KEM_768, &[0; 1183]).is_err());
    let key = kem::DecapsulationKey::generate(&kem::ML_KEM_768).unwrap();
    let public = key.encapsulation_key().unwrap();
    let (ciphertext, secret) = public.encapsulate().unwrap();
    assert_eq!(
        key.decapsulate(kem::Ciphertext::from(ciphertext.as_ref()))
            .unwrap()
            .as_ref(),
        secret.as_ref()
    );
    let mut modified = ciphertext.as_ref().to_vec();
    modified[0] ^= 1;
    assert_ne!(
        key.decapsulate(kem::Ciphertext::from(modified.as_slice()))
            .unwrap()
            .as_ref(),
        secret.as_ref()
    );
    assert!(
        key.decapsulate(kem::Ciphertext::from(&modified[..1087]))
            .is_err()
    );
}

#[test]
fn mldsa65_binds_message_key_and_signature() {
    let signer =
        signature::PqdsaKeyPair::from_seed(&signature::ML_DSA_65_SIGNING, &[7; 32]).unwrap();
    let verifier =
        signature::UnparsedPublicKey::new(&signature::ML_DSA_65, signer.public_key().as_ref());
    let mut sig = vec![0; 3309];
    assert_eq!(signer.sign(b"REALITY transcript", &mut sig).unwrap(), 3309);
    verifier.verify(b"REALITY transcript", &sig).unwrap();
    assert!(verifier.verify(b"REALITY Transcript", &sig).is_err());
    sig[100] ^= 1;
    assert!(verifier.verify(b"REALITY transcript", &sig).is_err());
    assert!(
        verifier
            .verify(b"REALITY transcript", &sig[..3308])
            .is_err()
    );
    assert!(signer.sign(b"message", &mut sig[..3000]).is_err());
}
