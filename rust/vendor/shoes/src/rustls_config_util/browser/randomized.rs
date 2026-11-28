//! One shared process plan, adapted to the actual stream without resampling.
use crate::config::tls::{TlsClientOptions, TlsKeyExchangeGroups, TlsVersion};
use aerobox_fingerprint::randomized::Plan;
use rustls::{ClientConfig, NamedGroup, ProtocolVersion, SupportedProtocolVersion};
use std::{io, sync::Arc};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn plan(reality: bool) -> io::Result<Plan> {
    aerobox_fingerprint::randomized::process_plan()
        .and_then(|p| p.for_stream(reality))
        .map_err(|error| invalid(error.to_string()))
}

/// Borrow the fixed structure for one configuration operation. This is not an
/// additional seed, cache, public plan override or second global resolver.
#[derive(Clone, Copy)]
struct Fields<'a> {
    minimum: u16,
    maximum: u16,
    suites: &'a [u16],
    signatures: &'a [u16],
    groups: &'a [u16],
    shares: &'a [u16],
    extensions: &'a [u16],
}
impl<'a> From<&'a Plan> for Fields<'a> {
    fn from(p: &'a Plan) -> Self {
        Self {
            minimum: p.minimum(),
            maximum: p.maximum(),
            suites: p.suites(),
            signatures: p.signatures(),
            groups: p.groups(),
            shares: p.shares(),
            extensions: p.extensions(),
        }
    }
}
impl Fields<'_> {
    fn has(self, extension: u16) -> bool {
        self.extensions.contains(&extension)
    }
    fn checked(self) -> io::Result<Self> {
        if !matches!(self.minimum, 0x0301 | 0x0303)
            || !matches!(self.maximum, 0x0303 | 0x0304)
            || self.minimum > self.maximum
            || self
                .groups
                .iter()
                .any(|g| !matches!(*g, 23 | 24 | 25 | 29 | 4588))
            || self.shares.iter().any(|g| !self.groups.contains(g))
        {
            return Err(invalid(
                "randomized stream plan has unsupported versions or inconsistent key shares",
            ));
        }
        Ok(self)
    }
    fn versions(self, tls13_only: bool) -> io::Result<Vec<&'static SupportedProtocolVersion>> {
        self.checked()?;
        if tls13_only && self.maximum != 0x0304 {
            return Err(invalid(
                "randomized plan does not support this TLS1.3-only transport",
            ));
        }
        let mut versions = Vec::new();
        if self.maximum == 0x0304 {
            versions.push(&rustls::version::TLS13);
        }
        if !tls13_only {
            versions.push(&rustls::version::TLS12);
        }
        Ok(versions)
    }
    fn validate_policy(
        self,
        groups: &TlsKeyExchangeGroups,
        options: &TlsClientOptions,
    ) -> io::Result<()> {
        self.checked()?;
        let id = |version: TlsVersion| match version {
            TlsVersion::V10 => 0x0301,
            TlsVersion::V11 => 0x0302,
            TlsVersion::V12 => 0x0303,
            TlsVersion::V13 => 0x0304,
        };
        if options.ech.is_some()
            || options.min_version.is_some_and(|v| id(v) != self.minimum)
            || options.max_version.is_some_and(|v| id(v) != self.maximum)
            || groups.groups().is_some_and(|g| {
                !g.iter()
                    .map(|v| u16::from(v.rustls_group().name()))
                    .eq(self.groups.iter().copied())
            })
        {
            return Err(invalid(
                "randomized fingerprint conflicts with explicit TLS versions, groups, or ECH",
            ));
        }
        Ok(())
    }
    fn provider(self) -> io::Result<rustls::crypto::CryptoProvider> {
        self.checked()?;
        let mut provider =
            aerobox_crypto::randomized::provider(self.suites).map_err(io::Error::other)?;
        provider.kx_groups = self
            .groups
            .iter()
            .map(|id| crate::crypto::rustcrypto_kx::group(NamedGroup::from(*id)))
            .collect();
        Ok(provider)
    }
    fn configure(
        self,
        config: &mut ClientConfig,
        reality: bool,
        tls13_only: bool,
    ) -> io::Result<()> {
        self.versions(tls13_only || reality)?;
        let requested_alpn = !config.alpn_protocols.is_empty();
        if !self.has(16) && requested_alpn {
            return Err(invalid(
                "randomized plan did not select ALPN but this transport explicitly requires it",
            ));
        }
        if self.has(16) && !requested_alpn {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }
        // Fixed uTLS keeps the h2 ALPS object when explicit ALPN replaces the
        // ALPN object's protocols. Never synthesize or rewrite that structure.
        config.application_settings = if self.has(17513) {
            Some(
                rustls::client::ApplicationSettings::new(
                    rustls::client::ApplicationSettingsCodepoint::Legacy,
                    vec![(b"h2".to_vec(), vec![])],
                )
                .map_err(io::Error::other)?,
            )
        } else {
            None
        };
        config.cert_compressors.clear();
        config.cert_decompressors.clear();
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_delegated_credentials = false;
        config.advertise_record_size_limit = false;
        config.require_ems = false;
        config.enable_tls12_renegotiation = self.has(65281) && !reality && !tls13_only;
        config.initial_key_share_groups =
            self.shares.iter().map(|g| NamedGroup::from(*g)).collect();
        if !reality && !tls13_only && self.minimum < 0x0303 {
            let versions = (self.minimum..=self.maximum)
                .map(ProtocolVersion::from)
                .collect::<Vec<_>>();
            config
                .enable_legacy_tls(&aerobox_crypto::randomized::LEGACY_TLS, &versions)
                .map_err(io::Error::other)?;
        }
        config.randomized_client_hello = Some(Arc::new(
            rustls::client::RandomizedClientHello::new(
                self.minimum,
                self.maximum,
                self.suites,
                self.signatures,
                self.groups,
                self.shares,
                self.extensions,
            )
            .map_err(io::Error::other)?,
        ));
        config.client_hello_layout = Some(rustls::client::ClientHelloLayout::Randomized);
        Ok(())
    }
}

pub(crate) fn validate_policy(
    groups: &TlsKeyExchangeGroups,
    options: &TlsClientOptions,
) -> io::Result<()> {
    Fields::from(&plan(false)?).validate_policy(groups, options)
}
pub(crate) fn provider(reality: bool) -> io::Result<rustls::crypto::CryptoProvider> {
    Fields::from(&plan(reality)?).provider()
}
pub(crate) fn versions(tls13_only: bool) -> io::Result<Vec<&'static SupportedProtocolVersion>> {
    Fields::from(&plan(false)?).versions(tls13_only)
}
pub(crate) fn configure(
    config: &mut ClientConfig,
    reality: bool,
    tls13_only: bool,
) -> io::Result<()> {
    Fields::from(&plan(reality)?).configure(config, reality, tls13_only)
}
pub(crate) fn validate_alpn(reality: bool, requested: &[String]) -> io::Result<()> {
    if !requested.is_empty() && !plan(reality)?.extensions().contains(&16) {
        return Err(invalid(
            "randomized plan did not select ALPN but this transport explicitly requires it",
        ));
    }
    Ok(())
}

pub(crate) fn validate_reality_suites(suites: &[crate::reality::CipherSuite]) -> io::Result<()> {
    let plan = plan(true)?;
    if !suites.is_empty()
        && !suites.iter().map(|s| s.id()).eq(plan
            .suites()
            .iter()
            .copied()
            .filter(|id| (0x1301..=0x1303).contains(id)))
    {
        return Err(invalid(
            "REALITY randomized fingerprint conflicts with the fixed TLS1.3 cipher order",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
