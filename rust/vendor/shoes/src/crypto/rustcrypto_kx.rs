//! RFC 7748 / TLS ML-KEM hybrid key exchange with RustCrypto primitives.
use aerobox_primitives::kem;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};
use zeroize::Zeroizing;

fn invalid() -> Error {
    Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}
fn classical(name: NamedGroup) -> &'static dyn SupportedKxGroup {
    aerobox_crypto::provider()
        .kx_groups
        .into_iter()
        .find(|g| g.name() == name)
        .expect("AeroBox's validated provider includes X25519, P-256, P-384 and P-521")
}
pub(crate) fn group(name: NamedGroup) -> &'static dyn SupportedKxGroup {
    match name {
        NamedGroup::X25519MLKEM768 => &X25519_MLKEM,
        NamedGroup::secp256r1MLKEM768 => &P256_MLKEM,
        _ => classical(name),
    }
}
#[derive(Debug)]
struct Hybrid {
    name: NamedGroup,
    classical: NamedGroup,
    classical_len: usize,
    pq_first: bool,
}
static X25519_MLKEM: Hybrid = Hybrid {
    name: NamedGroup::X25519MLKEM768,
    classical: NamedGroup::X25519,
    classical_len: 32,
    pq_first: true,
};
static P256_MLKEM: Hybrid = Hybrid {
    name: NamedGroup::secp256r1MLKEM768,
    classical: NamedGroup::secp256r1,
    classical_len: 65,
    pq_first: false,
};
impl Hybrid {
    fn split<'a>(&self, bytes: &'a [u8], pq_len: usize) -> Result<(&'a [u8], &'a [u8]), Error> {
        if bytes.len() != pq_len + self.classical_len {
            return Err(invalid());
        }
        if self.pq_first {
            Ok(bytes.split_at(pq_len))
        } else {
            let (cl, pq) = bytes.split_at(self.classical_len);
            Ok((pq, cl))
        }
    }
    fn concat(&self, pq: &[u8], cl: &[u8]) -> Vec<u8> {
        if self.pq_first {
            [pq, cl].concat()
        } else {
            [cl, pq].concat()
        }
    }
}
impl SupportedKxGroup for Hybrid {
    fn name(&self) -> NamedGroup {
        self.name
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = classical(self.classical).start()?;
        let pq = kem::DecapsulationKey::generate(&kem::ML_KEM_768).map_err(|_| invalid())?;
        let public = pq
            .encapsulation_key()
            .and_then(|k| k.key_bytes())
            .map_err(|_| invalid())?;
        let public = self.concat(public.as_ref(), classical.pub_key());
        Ok(Box::new(Active {
            name: self.name,
            classical,
            pq,
            public,
        }))
    }
    fn start_and_complete(&self, client: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let (pq, cl) = self.split(client, 1184)?;
        let cl = classical(self.classical).start_and_complete(cl)?;
        let (ciphertext, secret) = kem::EncapsulationKey::new(&kem::ML_KEM_768, pq)
            .and_then(|k| k.encapsulate())
            .map_err(|_| invalid())?;
        let combined = Zeroizing::new(self.concat(secret.as_ref(), cl.secret.secret_bytes()));
        Ok(CompletedKeyExchange {
            group: self.name,
            pub_key: self.concat(ciphertext.as_ref(), &cl.pub_key),
            secret: SharedSecret::from(combined.as_slice()),
        })
    }
}
struct Active {
    name: NamedGroup,
    classical: Box<dyn ActiveKeyExchange>,
    pq: kem::DecapsulationKey,
    public: Vec<u8>,
}
impl ActiveKeyExchange for Active {
    fn group(&self) -> NamedGroup {
        self.name
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }
    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        self.classical.complete(peer)
    }
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let layout = if self.name == NamedGroup::X25519MLKEM768 {
            &X25519_MLKEM
        } else {
            &P256_MLKEM
        };
        let (pq, cl) = layout.split(peer, 1088)?;
        let cl = self.classical.complete(cl)?;
        let pq = self
            .pq
            .decapsulate(kem::Ciphertext::from(pq))
            .map_err(|_| invalid())?;
        let combined = Zeroizing::new(layout.concat(pq.as_ref(), cl.secret_bytes()));
        Ok(SharedSecret::from(combined.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hybrid_exchange_and_classical_fallback() {
        for hybrid in [&X25519_MLKEM, &P256_MLKEM] {
            let client = hybrid.start().unwrap();
            let server = hybrid.start_and_complete(client.pub_key()).unwrap();
            let client_secret = client.complete(&server.pub_key).unwrap();
            assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
            assert_eq!(client_secret.secret_bytes().len(), 64);
            let client = hybrid.start().unwrap();
            let (_, share) = client.hybrid_component().unwrap();
            let server = classical(hybrid.classical)
                .start_and_complete(share)
                .unwrap();
            assert_eq!(
                client
                    .complete_hybrid_component(&server.pub_key)
                    .unwrap()
                    .secret_bytes(),
                server.secret.secret_bytes()
            );
            assert!(hybrid.start_and_complete(&[0; 2]).is_err());
            assert!(hybrid.start().unwrap().complete(&[0; 2]).is_err());
        }
    }
}
