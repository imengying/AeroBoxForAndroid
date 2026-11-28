//! Client ALPS, including the two codepoints used by the pinned browser profiles.
use alloc::{collections::BTreeSet, vec::Vec};

use crate::error::Error;
use crate::msgs::base::Payload;
use crate::msgs::handshake::{ClientExtensions, ProtocolName, ServerExtensions};

/// Application settings extension version used by the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationSettingsCodepoint {
    /// The original browser extension, 17513.
    Legacy,
    /// The Chrome 133 extension, 17613.
    Chrome,
}

/// Settings associated with ALPN names, chosen before beginning the handshake.
///
/// ALPS is offered only when TLS 1.3 is enabled. Settings are opaque to TLS.
/// Both an empty settings value and a declined ALPS offer are valid, distinct
/// outcomes. This API implements the client side of draft-vvv-tls-alps-01.
#[derive(Clone, Debug)]
pub struct ApplicationSettings {
    pub(crate) codepoint: ApplicationSettingsCodepoint,
    protocols: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ApplicationSettings {
    /// Configure unique, nonempty ALPN names and their fixed settings.
    /// Names are at most 255 bytes; a settings value is at most 65,531 bytes.
    /// The encoded list of names must fit in a TLS extension.
    pub fn new(
        codepoint: ApplicationSettingsCodepoint,
        protocols: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Self, Error> {
        let mut encoded_len = 0usize;
        let mut names = BTreeSet::new();
        if protocols.is_empty() {
            return Err(Error::General("ALPS requires at least one protocol".into()));
        }
        for (name, settings) in &protocols {
            if name.is_empty()
                || name.len() > 255
                || settings.len() > 65531
                || !names.insert(name.as_slice())
            {
                return Err(Error::General("invalid ALPS protocol or settings".into()));
            }
            encoded_len += 1 + name.len();
            if encoded_len > 65533 {
                return Err(Error::General(
                    "ALPS protocol list exceeds extension size".into(),
                ));
            }
        }
        Ok(Self {
            codepoint,
            protocols,
        })
    }

    pub(crate) fn settings(&self, protocol: &[u8]) -> Option<&[u8]> {
        self.protocols
            .iter()
            .find(|(name, _)| name == protocol)
            .map(|(_, settings)| settings.as_slice())
    }

    pub(crate) fn offer(&self, extensions: &mut ClientExtensions<'_>) -> Result<(), Error> {
        if extensions
            .protocols
            .as_ref()
            .map_or(true, Vec::is_empty)
        {
            return Err(Error::General("ALPS requires an ALPN offer".into()));
        }
        let names = self
            .protocols
            .iter()
            .map(|(name, _)| ProtocolName::from(name.clone()))
            .collect();
        match self.codepoint {
            ApplicationSettingsCodepoint::Legacy => {
                extensions.application_settings_legacy = Some(names)
            }
            ApplicationSettingsCodepoint::Chrome => extensions.application_settings = Some(names),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NegotiatedApplicationSettings {
    pub(crate) codepoint: ApplicationSettingsCodepoint,
    pub(crate) protocol: Vec<u8>,
    pub(crate) local: Vec<u8>,
    pub(crate) peer: Vec<u8>,
}

impl NegotiatedApplicationSettings {
    pub(crate) fn client_extensions(&self) -> ServerExtensions<'static> {
        let mut extensions = ServerExtensions::default();
        let payload = Some(Payload::new(self.local.clone()));
        match self.codepoint {
            ApplicationSettingsCodepoint::Legacy => {
                extensions.application_settings_legacy = payload
            }
            ApplicationSettingsCodepoint::Chrome => extensions.application_settings = payload,
        }
        extensions
    }
}

pub(crate) fn early_data_compatible(
    configured: Option<&ApplicationSettings>,
    previous: Option<&NegotiatedApplicationSettings>,
    previous_alpn: Option<&[u8]>,
) -> bool {
    match (configured, previous) {
        (None, None) => true,
        (Some(config), Some(previous)) => {
            config.codepoint == previous.codepoint
                && previous_alpn == Some(previous.protocol.as_slice())
                && config.settings(&previous.protocol) == Some(previous.local.as_slice())
        }
        (Some(config), None) => {
            previous_alpn.is_none_or(|protocol| config.settings(protocol).is_none())
        }
        (None, Some(_)) => false,
    }
}

pub(super) fn receive(
    config: &super::ClientConfig,
    offered_alpn: &[ProtocolName],
    cx: &mut super::hs::ClientContext<'_>,
    extensions: &ServerExtensions<'_>,
    resuming: Option<&crate::msgs::persist::Tls13ClientSessionValue>,
) -> Result<(), Error> {
    use crate::{AlertDescription, PeerMisbehaved};
    let invalid = |common: &mut crate::CommonState| {
        common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::UnsolicitedEncryptedExtension,
        )
    };
    cx.data.pending_application_settings = None;
    cx.data.send_application_settings = false;
    if extensions.early_data_ack.is_some() {
        let previous = resuming.ok_or_else(|| invalid(cx.common))?;
        if !cx.common.early_traffic
            || extensions
                .application_settings
                .is_some()
            || extensions
                .application_settings_legacy
                .is_some()
            || cx.common.alpn_protocol() != previous.alpn.as_deref()
        {
            return Err(invalid(cx.common));
        }
        cx.data.pending_application_settings = previous.application_settings.clone();
        return Ok(());
    }

    // Previous settings can only be reused when early data was accepted.
    cx.common.application_settings = None;
    let (codepoint, peer) = match (
        extensions
            .application_settings_legacy
            .as_ref(),
        extensions.application_settings.as_ref(),
    ) {
        (None, None) => return Ok(()),
        (Some(peer), None) => (ApplicationSettingsCodepoint::Legacy, peer),
        (None, Some(peer)) => (ApplicationSettingsCodepoint::Chrome, peer),
        (Some(_), Some(_)) => return Err(invalid(cx.common)),
    };
    let configured = config
        .application_settings
        .as_ref()
        .ok_or_else(|| invalid(cx.common))?;
    let protocol = cx
        .common
        .alpn_protocol()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| invalid(cx.common))?;
    if codepoint != configured.codepoint
        || !offered_alpn
            .iter()
            .any(|name| name.as_ref() == protocol.as_slice())
    {
        return Err(invalid(cx.common));
    }
    let local = configured
        .settings(&protocol)
        .ok_or_else(|| invalid(cx.common))?;
    cx.data.pending_application_settings = Some(NegotiatedApplicationSettings {
        codepoint,
        protocol,
        local: local.to_vec(),
        peer: peer.bytes().to_vec(),
    });
    cx.data.send_application_settings = true;
    Ok(())
}
