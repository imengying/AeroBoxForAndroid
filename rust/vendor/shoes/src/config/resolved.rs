//! Routing output of configuration compilation. These types are not input syntax.
//!
//! Source and resolved records are distinct despite sharing their settings layout.
//! ```compile_fail
//! use shoes::config::{ClientConfig, resolved::ResolvedClientConfig};
//! let source: ClientConfig = ResolvedClientConfig::default();
//! ```
//!
//! Resolved output cannot be parsed as configuration.
//! ```compile_fail
//! use shoes::config::resolved::ResolvedClientConfig;
//! let _: ResolvedClientConfig = serde_yaml::from_str("{}").unwrap();
//! ```
//!
//! Source routes cannot contain resolved choices.
//! ```compile_fail
//! use shoes::config::{ClientChainHop, resolved::ResolvedClientChoice};
//! fn source(choice: ResolvedClientChoice) -> ClientChainHop {
//!     ClientChainHop::Choice(Box::new(choice))
//! }
//! ```
//!
//! Executable routes cannot contain source chains.
//! ```compile_fail
//! use shoes::config::{ClientChain, resolved::ResolvedClientChain};
//! fn execute(_: ResolvedClientChain) {}
//! execute(ClientChain::default());
//! ```
//!
//! Valid counterparts verify imports and field access independently of the
//! rejection tests, which cannot match diagnostic codes on stable Rust.
//! ```no_run
//! use shoes::config::{ClientChain, ClientChainHop, ClientConfig, ConfigSelection};
//! use shoes::config::resolved::{
//!     ResolvedClientChain, ResolvedClientChoice, ResolvedClientConfig,
//!     ResolvedClientHop,
//! };
//! let _: ClientConfig = ClientConfig::default();
//! let _: ResolvedClientConfig = ResolvedClientConfig::default();
//! let _: ClientChain = ClientChain::default();
//! fn parse_source(yaml: &str) -> Result<ClientConfig, serde_yaml::Error> {
//!     serde_yaml::from_str(yaml)
//! }
//! fn source(client: ClientConfig) -> ClientChainHop {
//!     ClientChainHop::Single(ConfigSelection::Config(client))
//! }
//! fn resolved(choice: ResolvedClientChoice) -> ResolvedClientHop {
//!     ResolvedClientHop::Choice(Box::new(choice))
//! }
//! fn execute(_: ResolvedClientChain) {}
//! execute(ResolvedClientChain::default());
//! ```

use serde::Serialize;

use super::GroupType;
use super::types::{client, rules, server, tun};
use crate::option_util::OneOrSome;

pub use client::ResolvedClientProxyConfig;
pub use server::ResolvedServerProxyConfig;

pub type ResolvedClientConfig = client::ClientRecord<ResolvedClientProxyConfig>;
pub type ResolvedTlsClientConfig = client::TlsClientRecord<ResolvedClientProxyConfig>;
pub type ResolvedWebsocketClientConfig = client::WebsocketClientRecord<ResolvedClientProxyConfig>;

pub type ResolvedRuleConfig = rules::RuleRecord<ResolvedClientChain>;
pub type ResolvedRuleActionConfig = rules::RuleActionRecord<ResolvedClientChain>;
pub type ResolvedServerConfig =
    server::ServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig, ResolvedDnsConfig>;
pub type ResolvedTunConfig = tun::TunRecord<ResolvedRuleConfig, ResolvedDnsConfig>;
pub type ResolvedTlsServerConfig =
    server::TlsServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig>;
pub type ResolvedWebsocketServerConfig =
    server::WebsocketServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig>;
pub type ResolvedRealityServerConfig =
    server::RealityServerRecord<ResolvedServerProxyConfig, ResolvedRuleConfig, ResolvedClientHop>;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ResolvedConfig {
    Server(ResolvedServerConfig),
    TunServer(ResolvedTunConfig),
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedDnsConfig {
    pub group: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainPlan<C> {
    #[serde(rename = "chain")]
    pub(crate) hops: OneOrSome<HopPlan<C>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum HopPlan<C> {
    Single(C),
    Choice(Box<ChoicePlan<C>>),
}

#[derive(Debug, Clone, Serialize)]
pub struct ChoicePlan<C> {
    pub(crate) name: String,
    pub(crate) group_type: GroupType,
    pub(crate) labels: Vec<String>,
    pub(crate) members: Vec<ChainPlan<C>>,
}

pub type ResolvedClientChain = ChainPlan<ResolvedClientConfig>;
pub type ResolvedClientHop = HopPlan<ResolvedClientConfig>;
pub type ResolvedClientChoice = ChoicePlan<ResolvedClientConfig>;

impl Default for ResolvedClientConfig {
    fn default() -> Self {
        Self {
            name: None,
            control: None,
            bind_interface: crate::option_util::NoneOrOne::None,
            address: super::types::common::unspecified_address(),
            domain_resolver: None,
            dial_options: Default::default(),
            protocol: ResolvedClientProxyConfig::Direct,
            transport: super::Transport::default(),
            tcp_settings: None,
            quic_settings: None,
        }
    }
}

impl Default for ResolvedClientChain {
    fn default() -> Self {
        Self {
            hops: OneOrSome::One(HopPlan::Single(ResolvedClientConfig::default())),
        }
    }
}

impl Default for ResolvedRuleConfig {
    fn default() -> Self {
        Self {
            criteria: super::rules::RuleCriteria::default(),
            action: ResolvedRuleActionConfig::Allow {
                override_address: None,
                client_chains: crate::option_util::NoneOrSome::One(ResolvedClientChain::default()),
            },
        }
    }
}

impl ResolvedDnsConfig {
    pub fn resolved_group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

#[cfg(test)]
mod tests;
