//! Connection-scoped integration points for the REALITY TLS 1.3 transport.
//!
//! These APIs do not authenticate REALITY peers. The caller must supply the
//! authentication and certificate policy. Ordinary TLS connections never use them.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::crypto::{ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SupportedKxGroup};
use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{Compression, ExtensionType};
use crate::msgs::handshake::{
    HandshakeMessagePayload, HandshakePayload, KeyShareEntry, Random, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::{CipherSuite, Error, NamedGroup, ProtocolVersion};

/// State owned by exactly one REALITY client connection.
///
/// Implementations must not print private keys or authentication material in Debug.
pub trait ClientHooks: Debug + Send + Sync {
    /// Start the TLS exchange and derive any additional REALITY authentication
    /// secret without consuming the exchange. The returned group must match `group`.
    fn start_key_exchange(
        &mut self,
        group: &'static dyn SupportedKxGroup,
    ) -> Result<Box<dyn ActiveKeyExchange>, Error>;

    /// Authenticate the final encoded ClientHello by replacing only its 32-byte
    /// legacy session ID. `hello` includes the handshake header, not a record header.
    /// Rustls updates both the encoded hello and its retained session-ID state.
    fn session_id(&mut self, hello: &[u8]) -> Result<[u8; 32], Error>;

    /// Capture the exact finalized hello messages before certificate verification.
    /// Both slices include handshake headers and exclude record headers.
    fn server_hello(&mut self, client: &[u8], server: &[u8]) -> Result<(), Error>;
}

/// A target-derived ServerHello and fresh exchange, bound to one ClientHello.
///
/// Construction validates the target and performs key exchange through the provider.
/// There is deliberately no API for injecting arbitrary shared secrets. The caller
/// must authenticate the client before constructing this value and generate its
/// certificate against [`Self::server_hello`] before creating the server connection.
pub struct PreparedServerHello {
    client: Vec<u8>,
    server: Vec<u8>,
    peer_share: Vec<u8>,
    suite: CipherSuite,
    group: NamedGroup,
    pub(crate) random: Random,
    session_id: SessionId,
    exchange: Option<CompletedKeyExchange>,
    pub(crate) flight: Option<FlightPlan>,
}

impl Debug for PreparedServerHello {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedServerHello")
            .field("suite", &self.suite)
            .field("group", &self.group)
            .finish_non_exhaustive()
    }
}

impl PreparedServerHello {
    /// Validate complete handshake messages (without record headers) and replace
    /// only the target's supported key-share bytes. HRR, PSK, early data and
    /// extensions other than supported_versions/key_share are not supported.
    pub fn new(client: &[u8], target: &[u8], provider: &CryptoProvider) -> Result<Self, Error> {
        if client.len() > 65_536 || target.len() > 16_384 {
            return Err(incompatible());
        }
        let ch = HandshakeMessagePayload::read_bytes(client).map_err(|_| incompatible())?;
        let sh = HandshakeMessagePayload::read_bytes(target).map_err(|_| incompatible())?;
        let (HandshakePayload::ClientHello(ch), HandshakePayload::ServerHello(sh)) = (ch.0, sh.0)
        else {
            return Err(incompatible());
        };
        if sh.legacy_version != ProtocolVersion::TLSv1_2
            || sh.selected_version != Some(ProtocolVersion::TLSv1_3)
            || !ch
                .supported_versions
                .as_ref()
                .is_some_and(|v| v.tls13)
            || ch.session_id.as_ref().len() != 32
            || sh.session_id != ch.session_id
            || sh.compression_method != Compression::Null
            || ch.early_data_request.is_some()
            || !sh.unknown_extensions.is_empty()
            || sh.collect_used().iter().any(|ext| {
                !matches!(
                    ext,
                    ExtensionType::SupportedVersions | ExtensionType::KeyShare
                )
            })
            || !ch
                .cipher_suites
                .contains(&sh.cipher_suite)
            || !matches!(
                sh.cipher_suite,
                CipherSuite::TLS13_AES_128_GCM_SHA256
                    | CipherSuite::TLS13_AES_256_GCM_SHA384
                    | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            )
            || !provider
                .cipher_suites
                .iter()
                .any(|s| s.suite() == sh.cipher_suite)
        {
            return Err(incompatible());
        }
        let share = sh
            .key_share
            .as_ref()
            .ok_or_else(incompatible)?;
        let (client_len, server_len) = match share.group {
            NamedGroup::X25519 => (32, 32),
            NamedGroup::X25519MLKEM768 => (1216, 1120),
            _ => return Err(incompatible()),
        };
        if share.payload.0.len() != server_len
            || !ch
                .named_groups
                .as_ref()
                .is_some_and(|g| g.contains(&share.group))
        {
            return Err(incompatible());
        }
        let peer = ch
            .key_shares
            .as_ref()
            .and_then(|shares| {
                shares
                    .iter()
                    .find(|s| s.group == share.group)
            })
            .ok_or_else(incompatible)?;
        if peer.payload.0.len() != client_len {
            return Err(incompatible());
        }
        let kx = provider
            .kx_groups
            .iter()
            .find(|g| g.name() == share.group)
            .ok_or_else(incompatible)?;
        let exchange = kx.start_and_complete(&peer.payload.0)?;
        if exchange.group != share.group || exchange.pub_key.len() != server_len {
            return Err(incompatible());
        }
        let mut server = target.to_vec();
        let extensions_start = 44 + sh.session_id.as_ref().len();
        let mut extensions = Reader::init(
            target
                .get(extensions_start..)
                .ok_or_else(incompatible)?,
        );
        while extensions.any_left() {
            let typ = ExtensionType::read(&mut extensions)?;
            let len = usize::from(u16::read(&mut extensions)?);
            let offset = extensions_start + extensions.used();
            extensions.sub(len)?;
            if typ == ExtensionType::KeyShare {
                server
                    .get_mut(offset + 4..offset + len)
                    .ok_or_else(incompatible)?
                    .copy_from_slice(&exchange.pub_key);
            }
        }
        Ok(Self {
            client: client.to_vec(),
            server,
            peer_share: peer.payload.0.clone(),
            suite: sh.cipher_suite,
            group: share.group,
            random: sh.random,
            session_id: sh.session_id,
            exchange: Some(exchange),
            flight: None,
        })
    }

    /// Shape the synthetic first flight to a validated record plan.
    pub fn with_flight_plan(mut self, plan: FlightPlan) -> Self {
        self.flight = Some(plan);
        self
    }

    /// Final handshake bytes to bind into REALITY certificate authentication.
    pub fn server_hello(&self) -> &[u8] {
        &self.server
    }

    /// The target-selected cipher, validated against the supplied provider.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.suite
    }

    /// The target-selected key-exchange group.
    pub fn group(&self) -> NamedGroup {
        self.group
    }

    pub(crate) fn check_client(&self, message: &Message<'_>) -> Result<(), Error> {
        match &message.payload {
            MessagePayload::Handshake { encoded, .. } if encoded.bytes() == self.client => Ok(()),
            _ => Err(incompatible()),
        }
    }

    pub(crate) fn take_exchange(
        &mut self,
        suite: CipherSuite,
        session_id: &SessionId,
        share: &KeyShareEntry,
    ) -> Result<CompletedKeyExchange, Error> {
        if suite != self.suite
            || session_id != &self.session_id
            || share.group != self.group
            || share.payload.0 != self.peer_share
        {
            return Err(incompatible());
        }
        self.exchange
            .take()
            .ok_or_else(incompatible)
    }

    pub(crate) fn message(&self) -> Result<Message<'static>, Error> {
        Ok(Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::Handshake {
                parsed: HandshakeMessagePayload::read_bytes(&self.server)?.into_owned(),
                encoded: Payload::new(self.server.clone()),
            },
        })
    }
}

/// Lengths of complete TLS records, including their five-byte record headers.
///
/// Supports one combined encrypted handshake record or four separate records,
/// optionally followed by one padded empty application-data record. No tickets
/// or application payload are synthesized by this plan.
#[derive(Clone, Debug)]
pub struct FlightPlan {
    handshake: Vec<usize>,
    pub(crate) trailing: Option<usize>,
}

impl FlightPlan {
    /// Validate a bounded flight layout. Actual message capacity is checked before
    /// any encrypted handshake record is queued; undersized records are rejected.
    pub fn new(handshake: &[usize], trailing: Option<usize>) -> Result<Self, Error> {
        if !matches!(handshake.len(), 1 | 4)
            || handshake
                .iter()
                .chain(trailing.iter())
                .any(|len| !(22..=16_406).contains(len))
        {
            return Err(incompatible());
        }
        Ok(Self {
            handshake: handshake.to_vec(),
            trailing,
        })
    }

    pub(crate) fn fragments<'a>(&self, body: &'a [u8]) -> Result<Vec<(&'a [u8], usize)>, Error> {
        let mut records = Vec::with_capacity(4);
        let mut offset = 0;
        for typ in [8, 11, 15, 20] {
            let header = body
                .get(offset..offset + 4)
                .ok_or_else(incompatible)?;
            if header[0] != typ {
                return Err(incompatible());
            }
            let len =
                usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
            let end = offset + 4 + len;
            let fragment = body
                .get(offset..end)
                .ok_or_else(incompatible)?;
            if self.handshake.len() == 4 {
                let wire_len = self.handshake[records.len()];
                padding_for(fragment.len(), wire_len)?;
                records.push((fragment, wire_len));
            }
            offset = end;
        }
        if offset != body.len() {
            return Err(incompatible());
        }
        if self.handshake.len() == 1 {
            padding_for(body.len(), self.handshake[0])?;
            records.push((body, self.handshake[0]));
        }
        Ok(records)
    }
}

pub(crate) fn padding_for(content_len: usize, wire_len: usize) -> Result<usize, Error> {
    if !(22..=16_406).contains(&wire_len) {
        return Err(incompatible());
    }
    let padding = wire_len
        .checked_sub(22)
        .and_then(|n| n.checked_sub(content_len))
        .ok_or_else(incompatible)?;
    padded_plaintext_len(content_len, padding)?;
    Ok(padding)
}

pub(crate) fn padded_plaintext_len(content_len: usize, padding: usize) -> Result<usize, Error> {
    content_len
        .checked_add(padding)
        .filter(|len| *len <= 16_384)
        .ok_or_else(incompatible)
}

pub(crate) fn incompatible() -> Error {
    crate::PeerIncompatible::RealityUnsupported.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_plan_checks_every_capacity_before_encryption() {
        let body = [8, 0, 0, 0, 11, 0, 0, 0, 15, 0, 0, 0, 20, 0, 0, 0];
        assert!(
            FlightPlan::new(&[38], None)
                .unwrap()
                .fragments(&body)
                .is_ok()
        );
        assert!(
            FlightPlan::new(&[37], None)
                .unwrap()
                .fragments(&body)
                .is_err()
        );
        assert!(
            FlightPlan::new(&[26; 4], Some(22))
                .unwrap()
                .fragments(&body)
                .is_ok()
        );
        for index in 0..4 {
            let mut lengths = [26; 4];
            lengths[index] -= 1;
            assert!(
                FlightPlan::new(&lengths, None)
                    .unwrap()
                    .fragments(&body)
                    .is_err()
            );
        }
        assert!(FlightPlan::new(&[22; 2], None).is_err());
        assert!(FlightPlan::new(&[16_407], None).is_err());
        assert!(FlightPlan::new(&[38], Some(21)).is_err());
        assert!(padding_for(usize::MAX, 100).is_err());
        assert!(padded_plaintext_len(1, usize::MAX).is_err());
    }
}
