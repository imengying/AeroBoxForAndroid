//! A bounded structural plan; entropy and seed lifetime belong to the caller.
use super::{ClientConfig, hs::ClientContext};
use crate::msgs::{
    base::PayloadU8,
    enums::ExtensionType,
    handshake::{ClientHelloPayload, ClientSessionTicket, SupportedProtocolVersions},
};
use crate::{CipherSuite, Error, NamedGroup, ProtocolVersion, SignatureScheme};
use alloc::{sync::Arc, vec::Vec};

pub(super) const CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xcca8, 0xcca9, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027, 0xc013, 0xc023,
    0xc009, 0xc014, 0xc00a, 0x009c, 0x009d, 0x003c, 0x002f, 0x0035, 0xc012, 0x000a, 0x0005, 0xc011,
    0xc007,
];
pub(super) const SIGNATURES: &[u16] = &[
    0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601, 0x0203, 0x0603, 0x0804, 0x0805, 0x0806,
];
pub(super) const GROUPS: &[u16] = &[4588, 29, 23, 24, 25];
const EXTENSIONS: &[u16] = &[
    0, 35, 13, 11, 10, 16, 21, 5, 18, 65281, 23, 51, 45, 43, 17513,
];

/// Immutable, validated fields for the pinned Android randomized layout.
///
/// This API supplies no seed or private key. Each connection obtains fresh TLS
/// entropy and independent key exchanges from its crypto provider. The caller
/// must preserve its process-wide structural plan rather than retrying after a
/// policy, authentication or key-share failure. QUIC and ECH are unsupported.
#[derive(Clone, Debug)]
pub struct RandomizedClientHello {
    minimum: u16,
    maximum: u16,
    ciphers: Vec<u16>,
    signatures: Vec<u16>,
    pub(super) groups: Vec<u16>,
    shares: Vec<u16>,
    pub(super) extensions: Vec<u16>,
}

pub(super) fn invalid() -> Error {
    Error::General("randomized ClientHello plan conflicts with configured TLS capabilities".into())
}
fn unique(values: &[u16], allowed: &[u16], maximum: usize, nonempty: bool) -> bool {
    (!nonempty || !values.is_empty())
        && values.len() <= maximum
        && values
            .iter()
            .enumerate()
            .all(|(i, value)| allowed.contains(value) && !values[..i].contains(value))
}
impl RandomizedClientHello {
    /// Validate the bounded result of the fixed generator, including consistency
    /// between advertised groups and actual shares. Unsupported plans fail;
    /// nothing is silently filtered, substituted, or sampled here.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        minimum: u16,
        maximum: u16,
        cipher_suites: &[u16],
        signature_schemes: &[u16],
        groups: &[u16],
        key_shares: &[u16],
        extensions: &[u16],
    ) -> Result<Self, Error> {
        let tls13 = maximum == 0x0304;
        if !matches!(
            (minimum, maximum),
            (0x0301, 0x0303 | 0x0304) | (0x0303, 0x0304)
        ) || !unique(cipher_suites, CIPHERS, 22, true)
            || !unique(signature_schemes, SIGNATURES, 11, true)
            || !unique(groups, GROUPS, 5, true)
            || !unique(key_shares, &[4588, 29, 23], 3, tls13)
            || !unique(extensions, EXTENSIONS, 15, true)
            || [0, 35, 13, 11, 10]
                .iter()
                .any(|id| !extensions.contains(id))
            || [0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601]
                .iter()
                .any(|id| !signature_schemes.contains(id))
            || !groups.contains(&23)
            || !groups.contains(&24)
            || key_shares
                .iter()
                .any(|id| !groups.contains(id))
            || !cipher_suites
                .iter()
                .any(|id| !is_tls13(*id))
            || tls13
                != cipher_suites
                    .iter()
                    .any(|id| is_tls13(*id))
            || (tls13
                && (!extensions.contains(&21)
                    || !signature_schemes.contains(&0x0804)
                    || !key_shares.contains(&29)
                    || cipher_suites
                        .iter()
                        .any(|id| matches!(id, 5 | 0xc011 | 0xc007))))
            || (!tls13 && (!key_shares.is_empty() || groups.contains(&4588)))
            || [51, 45, 43]
                .iter()
                .any(|id| extensions.contains(id) != tls13)
            || (extensions.contains(&17513) && (!tls13 || !extensions.contains(&16)))
        {
            return Err(invalid());
        }
        Ok(Self {
            minimum,
            maximum,
            ciphers: cipher_suites.to_vec(),
            signatures: signature_schemes.to_vec(),
            groups: groups.to_vec(),
            shares: key_shares.to_vec(),
            extensions: extensions.to_vec(),
        })
    }

    #[cfg(feature = "tls12")]
    pub(super) fn validate_config(
        config: &ClientConfig,
        cx: &ClientContext<'_>,
    ) -> Result<Arc<Self>, Error> {
        let plan = config
            .randomized_client_hello
            .as_ref()
            .ok_or_else(invalid)?;
        let reality = cx.data.reality.is_some();
        let modern_only = !config.legacy_enabled()
            && config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol)
            && !config.supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol);
        if cx.common.is_quic()
            || config.ech_mode.is_some()
            || config.enable_early_data
            || config.enable_secret_extraction
            || config.enable_delegated_credentials
            || config.advertise_record_size_limit
            || config.send_ticket_request.is_some()
            || config.require_ems
            || !config.check_selected_alpn
            || !config.cert_compressors.is_empty()
            || !config.cert_decompressors.is_empty()
            || config
                .verifier
                .requires_raw_public_keys()
            || config
                .client_auth_cert_resolver
                .only_raw_public_keys()
            || config.resumption.tls12_resumption != super::Tls12Resumption::Disabled
            || (reality && (!modern_only || plan.groups.contains(&4588)))
            || (modern_only && plan.maximum != 0x0304)
            || config.enable_tls12_renegotiation
                != (!modern_only && plan.extensions.contains(&65281))
            || !config
                .initial_key_share_groups
                .iter()
                .map(|g| u16::from(*g))
                .eq(plan.shares.iter().copied())
            || !config
                .provider
                .kx_groups
                .iter()
                .map(|g| u16::from(g.name()))
                .eq(plan.groups.iter().copied())
        {
            return Err(invalid());
        }
        if !modern_only {
            for id in 0x0301..=0x0304 {
                if config.supports_version(ProtocolVersion::from(id), cx.common.protocol)
                    != (plan.minimum..=plan.maximum).contains(&id)
                {
                    return Err(invalid());
                }
            }
        }
        let full_suites = config
            .provider
            .cipher_suites
            .iter()
            .map(|s| u16::from(s.suite()))
            .eq(plan.ciphers.iter().copied());
        let modern_suites = modern_only
            && config
                .provider
                .cipher_suites
                .iter()
                .map(|s| u16::from(s.suite()))
                .eq(plan
                    .ciphers
                    .iter()
                    .copied()
                    .filter(|id| is_tls13(*id)));
        let signatures = config
            .verifier
            .supported_verify_schemes();
        if (!full_suites && !modern_suites)
            || plan
                .signatures
                .iter()
                .any(|s| !signatures.contains(&SignatureScheme::from(*s)))
            || plan.groups.iter().any(|g| {
                config
                    .find_kx_group(NamedGroup::from(*g), ProtocolVersion::from(plan.maximum))
                    .is_none()
            })
            || (plan.extensions.contains(&16) == config.alpn_protocols.is_empty())
        {
            return Err(invalid());
        }
        if plan.extensions.contains(&17513) {
            if !config
                .application_settings
                .as_ref()
                .is_some_and(|settings| {
                    settings.codepoint == super::ApplicationSettingsCodepoint::Legacy
                        && settings.settings(b"h2") == Some(&[])
                })
            {
                return Err(invalid());
            }
        } else if config.application_settings.is_some() {
            return Err(invalid());
        }
        Ok(plan.clone())
    }

    pub(super) fn apply(
        &self,
        hello: &mut ClientHelloPayload,
        changed_group: bool,
        encoding: &super::hello_layout::WireEncoding,
    ) -> Result<(), Error> {
        hello.cipher_suites = self
            .ciphers
            .iter()
            .copied()
            .map(CipherSuite::from)
            .collect();
        hello.named_groups = Some(
            self.groups
                .iter()
                .copied()
                .map(NamedGroup::from)
                .collect(),
        );
        hello.signature_schemes = Some(
            self.signatures
                .iter()
                .copied()
                .map(SignatureScheme::from)
                .collect(),
        );
        hello.extended_master_secret_request = self
            .extensions
            .contains(&23)
            .then_some(());
        hello.renegotiation_info = self
            .extensions
            .contains(&65281)
            .then(|| PayloadU8::new(Vec::new()));
        hello.sct_request = self
            .extensions
            .contains(&18)
            .then_some(());
        if !self.extensions.contains(&5) {
            hello.certificate_status_request = None;
        }
        if !self.extensions.contains(&16) {
            hello.protocols = None;
        }
        hello.session_ticket = Some(ClientSessionTicket::Request);
        if self.maximum == 0x0304 {
            hello.supported_versions = Some(SupportedProtocolVersions {
                tls13: true,
                tls12: true,
                tls11: self.minimum == 0x0301,
                tls10: self.minimum == 0x0301,
            });
            let shares = hello
                .key_shares
                .as_ref()
                .ok_or_else(invalid)?;
            if (!changed_group
                && !shares
                    .iter()
                    .map(|s| u16::from(s.group))
                    .eq(self.shares.iter().copied()))
                || (changed_group
                    && (shares.len() != 1
                        || !self
                            .groups
                            .contains(&u16::from(shares[0].group))))
            {
                return Err(invalid());
            }
        } else {
            if changed_group || hello.key_shares.is_some() {
                return Err(invalid());
            }
            hello.supported_versions = None;
        }
        if self.extensions.contains(&17513)
            && !hello
                .application_settings_legacy
                .as_ref()
                .is_some_and(|v| v.len() == 1 && v[0].as_ref() == b"h2")
        {
            return Err(invalid());
        }
        if hello.collect_used().iter().any(|id| {
            !self
                .extensions
                .contains(&u16::from(*id))
                && *id != ExtensionType::Cookie
        }) {
            return Err(invalid());
        }
        hello.wire_encoding = Some(encoding.clone());
        hello.update_boring_padding()
    }
}
fn is_tls13(id: u16) -> bool {
    (0x1301..=0x1303).contains(&id)
}
