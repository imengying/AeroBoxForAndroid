//! RFC 9345 wire data and policy checks, independent of a certificate backend.
use alloc::vec::Vec;

use pki_types::{CertificateDer, SubjectPublicKeyInfoDer};

use crate::msgs::codec::{Codec, Reader, u24};
use crate::verify::DigitallySignedStruct;
use crate::{Error, InvalidMessage, SignatureScheme};

/// A server delegated credential carried by the leaf CertificateEntry.
///
/// Parsing does not authenticate this value. Rustls first authenticates the
/// original certificate chain and identity, checks the actual ClientHello
/// offers, then calls the configured verifier's delegated-credential method.
#[derive(Clone, Debug)]
pub struct DelegatedCredential {
    valid_time: u32,
    expected_scheme: SignatureScheme,
    public_key: SubjectPublicKeyInfoDer<'static>,
    credential: Vec<u8>,
    signature: DigitallySignedStruct,
}

impl DelegatedCredential {
    /// Parse a bounded TLS DelegatedCredential, rejecting trailing bytes.
    /// This is TLS wire encoding, not a DER certificate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::read_bytes(bytes).map_err(Error::from)
    }

    /// Expiry offset in seconds from the original certificate's notBefore.
    pub fn valid_time(&self) -> u32 {
        self.valid_time
    }

    /// The exact signature scheme required in the server CertificateVerify.
    pub fn expected_verify_scheme(&self) -> SignatureScheme {
        self.expected_scheme
    }

    /// The delegated SubjectPublicKeyInfo, whose algorithm must match the scheme.
    pub fn public_key(&self) -> &SubjectPublicKeyInfoDer<'static> {
        &self.public_key
    }

    /// The original certificate key's signature over this delegation.
    pub fn signature(&self) -> &DigitallySignedStruct {
        &self.signature
    }

    /// Construct the RFC 9345 server authentication input, including the full
    /// original certificate, the exact Credential bytes, and issuer scheme.
    pub fn server_signature_input(&self, certificate: &CertificateDer<'_>) -> Vec<u8> {
        let context = b"TLS, server delegated credentials\0";
        let mut input = Vec::with_capacity(
            64 + context.len() + certificate.as_ref().len() + self.credential.len() + 2,
        );
        input.resize(64, 0x20);
        input.extend_from_slice(context);
        input.extend_from_slice(certificate.as_ref());
        input.extend_from_slice(&self.credential);
        self.signature.scheme.encode(&mut input);
        input
    }

    pub(crate) fn verify_offers(
        &self,
        certificate_schemes: &[SignatureScheme],
        delegated_schemes: &[SignatureScheme],
        handshake_signature: &DigitallySignedStruct,
    ) -> Result<(), Error> {
        if !delegated_scheme_is_usable(self.expected_scheme)
            || self.expected_scheme != handshake_signature.scheme
            || !delegated_schemes.contains(&self.expected_scheme)
            || !issuer_scheme_is_usable(self.signature.scheme)
            || !certificate_schemes.contains(&self.signature.scheme)
        {
            return Err(Error::General(
                "invalid delegated credential signature scheme".into(),
            ));
        }
        Ok(())
    }
}

// Issuer signatures and delegated CertificateVerify have different key rules:
// the authenticated certificate may use RSA rsaEncryption + PSS even though
// RFC 9345 forbids that key form in the delegated Credential. Keep the issuer
// policy independent and explicit; SHA1 and PKCS1 issuer signatures are not
// implemented by this opt-in, even if advertised for TLS 1.2 compatibility.
fn issuer_scheme_is_usable(scheme: SignatureScheme) -> bool {
    delegated_scheme_is_usable(scheme)
        || matches!(
            scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
        )
}

pub(crate) fn delegated_scheme_is_usable(scheme: SignatureScheme) -> bool {
    // RSA rsaEncryption keys are forbidden by RFC 9345. PSS-only RSA keys and
    // other schemes require an explicit implementation before advertising them.
    matches!(
        scheme,
        SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512
            | SignatureScheme::ED25519
    )
}

pub(crate) fn validate_advertised_schemes(schemes: &[SignatureScheme]) -> Result<(), Error> {
    if schemes.is_empty()
        || schemes.len() > 32
        || !schemes
            .iter()
            .any(|scheme| delegated_scheme_is_usable(*scheme))
        || schemes.iter().enumerate().any(|(i, scheme)| {
            (!delegated_scheme_is_usable(*scheme) && *scheme != SignatureScheme::ECDSA_SHA1_Legacy)
                || schemes[..i].contains(scheme)
        })
    {
        return Err(Error::General(
            "unsupported delegated credential advertisement".into(),
        ));
    }
    Ok(())
}

impl Codec<'_> for DelegatedCredential {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.credential);
        self.signature.encode(bytes);
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let bytes = reader.rest();
        // An extension is u16 bounded; additionally bound both opaque objects
        // before allocating. All currently usable delegated keys fit in 158 B.
        if bytes.len() > 65535 {
            return Err(InvalidMessage::MessageTooLarge);
        }
        let mut input = Reader::init(bytes);
        let valid_time = u32::read(&mut input)?;
        let expected_scheme = SignatureScheme::read(&mut input)?;
        let public_len = usize::from(u24::read(&mut input)?);
        if public_len == 0 {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        if public_len > 4096 {
            return Err(InvalidMessage::MessageTooLarge);
        }
        let public_key = input.sub(public_len)?.rest().to_vec().into();
        let credential = bytes[..input.used()].to_vec();
        let scheme = SignatureScheme::read(&mut input)?;
        let signature_len = usize::from(u16::read(&mut input)?);
        if signature_len == 0 {
            return Err(InvalidMessage::IllegalEmptyValue);
        }
        if signature_len > 16384 {
            return Err(InvalidMessage::MessageTooLarge);
        }
        let signature =
            DigitallySignedStruct::new(scheme, input.sub(signature_len)?.rest().to_vec());
        input.expect_empty("DelegatedCredential")?;
        Ok(Self {
            valid_time,
            expected_scheme,
            public_key,
            credential,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn wire() -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 9, 4, 3, 0, 0, 2, 0x30, 0];
        bytes.extend_from_slice(&[8, 4, 0, 1, 7]);
        bytes
    }

    #[test]
    fn parser_is_bounded_and_context_binds_full_certificate_and_both_schemes() {
        let bytes = wire();
        let credential = DelegatedCredential::from_bytes(&bytes).unwrap();
        assert_eq!(credential.valid_time(), 9);
        assert_eq!(
            credential.expected_verify_scheme(),
            SignatureScheme::ECDSA_NISTP256_SHA256
        );
        assert_eq!(credential.get_encoding(), bytes);
        let cert = CertificateDer::from(&b"exact certificate"[..]);
        let signed = credential.server_signature_input(&cert);
        assert_eq!(&signed[..64], &[0x20; 64]);
        assert_eq!(&signed[64..98], b"TLS, server delegated credentials\0");
        assert_eq!(&signed[98..115], cert.as_ref());
        assert_eq!(&signed[115..], &bytes[..13]);
        for n in 0..bytes.len() {
            assert!(
                DelegatedCredential::from_bytes(&bytes[..n]).is_err(),
                "truncated at {n}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DelegatedCredential::from_bytes(&trailing).is_err());
        for range in [6..9, 13..15] {
            let mut empty = bytes.clone();
            empty[range].fill(0);
            assert!(DelegatedCredential::from_bytes(&empty).is_err());
        }
        let mut huge = bytes;
        huge[6..9].copy_from_slice(&[0xff; 3]);
        assert!(matches!(
            DelegatedCredential::from_bytes(&huge),
            Err(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        ));
    }

    #[test]
    fn actual_offers_and_cv_must_match_and_legacy_advertisement_never_enables_sha1() {
        let dc = DelegatedCredential::from_bytes(&wire()).unwrap();
        let cv = DigitallySignedStruct::new(SignatureScheme::ECDSA_NISTP256_SHA256, vec![1]);
        let main = [SignatureScheme::RSA_PSS_SHA256];
        let delegated = [cv.scheme, SignatureScheme::ECDSA_SHA1_Legacy];
        assert!(validate_advertised_schemes(&delegated).is_ok());
        assert!(dc.verify_offers(&main, &delegated, &cv).is_ok());
        assert!(dc.verify_offers(&[], &delegated, &cv).is_err());
        assert!(dc.verify_offers(&main, &[], &cv).is_err());
        for scheme in [
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
        ] {
            let wrong = DigitallySignedStruct::new(scheme, vec![1]);
            assert!(dc.verify_offers(&main, &delegated, &wrong).is_err());
        }
        assert!(validate_advertised_schemes(&[SignatureScheme::ECDSA_SHA1_Legacy]).is_err());
        assert!(validate_advertised_schemes(&[cv.scheme, cv.scheme]).is_err());
    }
}
