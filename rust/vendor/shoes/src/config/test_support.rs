//! Inline fixtures for factory tests that intentionally bypass semantic validation.
//! Named routing references still go through the real configuration compiler.

use super::resolved::*;
use super::{
    ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, ConfigSelection,
    RuleActionConfig, RuleConfig, ServerProxyConfig,
};
use crate::option_util::{NoneOrSome, OneOrSome};
use serde::de::DeserializeOwned;

pub(crate) trait Inline: Sized {
    type Source: DeserializeOwned;
    fn inline(source: Self::Source) -> Self;
}

pub(crate) fn from_json<T: Inline>(value: serde_json::Value) -> Result<T, serde_json::Error> {
    serde_json::from_value(value).map(T::inline)
}

pub(crate) fn from_yaml<T: Inline>(value: &str) -> Result<T, serde_yaml::Error> {
    serde_yaml::from_str(value).map(T::inline)
}

fn one<T, U>(value: OneOrSome<T>, mut f: impl FnMut(T) -> U) -> OneOrSome<U> {
    match value {
        OneOrSome::One(value) => OneOrSome::One(f(value)),
        OneOrSome::Some(values) => OneOrSome::Some(values.into_iter().map(f).collect()),
    }
}

fn rules(value: NoneOrSome<ConfigSelection<RuleConfig>>) -> NoneOrSome<ResolvedRuleConfig> {
    value.map(|rule| ResolvedRuleConfig::inline(rule.unwrap_config()))
}

impl Inline for ResolvedClientConfig {
    type Source = ClientConfig;
    fn inline(source: ClientConfig) -> Self {
        super::lower::client(source)
    }
}

impl Inline for ResolvedClientProxyConfig {
    type Source = ClientProxyConfig;
    fn inline(protocol: Self::Source) -> Self {
        ResolvedClientConfig::inline(ClientConfig {
            protocol,
            ..ClientConfig::default()
        })
        .protocol
    }
}

impl Inline for ResolvedClientChain {
    type Source = ClientChain;
    fn inline(source: ClientChain) -> Self {
        Self {
            hops: one(source.hops, ResolvedClientHop::inline),
        }
    }
}

impl Inline for ResolvedClientHop {
    type Source = ClientChainHop;
    fn inline(source: ClientChainHop) -> Self {
        fn client(selection: ConfigSelection<ClientConfig>) -> ResolvedClientConfig {
            ResolvedClientConfig::inline(selection.unwrap_config())
        }
        match source {
            ClientChainHop::Single(selection) => Self::Single(client(selection)),
            ClientChainHop::Pool(pool) => super::composition::pool_choice(
                pool.into_vec()
                    .into_iter()
                    .map(|selection| ResolvedClientChain {
                        hops: OneOrSome::One(Self::Single(client(selection))),
                    })
                    .collect(),
            ),
        }
    }
}

impl Inline for ResolvedRuleConfig {
    type Source = RuleConfig;
    fn inline(source: RuleConfig) -> Self {
        Self {
            criteria: source.criteria,
            action: match source.action {
                RuleActionConfig::Block => ResolvedRuleActionConfig::Block,
                RuleActionConfig::Allow {
                    override_address,
                    client_chains,
                } => ResolvedRuleActionConfig::Allow {
                    override_address,
                    client_chains: client_chains.map(ResolvedClientChain::inline),
                },
            },
        }
    }
}

impl Inline for ResolvedDnsConfig {
    type Source = super::DnsConfig;
    fn inline(source: Self::Source) -> Self {
        Self {
            group: source.resolved_group().map(str::to_owned),
        }
    }
}

impl Inline for ResolvedServerProxyConfig {
    type Source = ServerProxyConfig;
    fn inline(source: Self::Source) -> Self {
        match source {



            ServerProxyConfig::Tls {
                tls_targets,
                default_tls_target,

                reality_targets,
                tls_buffer_size,
            } => Self::Tls {
                tls_targets: tls_targets
                    .into_iter()
                    .map(|(name, config)| (name, ResolvedTlsServerConfig::inline(config)))
                    .collect(),
                default_tls_target: default_tls_target
                    .map(|config| Box::new(ResolvedTlsServerConfig::inline(*config))),

                reality_targets: reality_targets
                    .into_iter()
                    .map(|(name, config)| (name, ResolvedRealityServerConfig::inline(config)))
                    .collect(),
                tls_buffer_size,
            },
            ServerProxyConfig::Websocket { targets } => Self::Websocket {
                targets: Box::new(one(*targets, ResolvedWebsocketServerConfig::inline)),
            },
            ServerProxyConfig::Http { username, password } => Self::Http { username, password },
            ServerProxyConfig::Socks {
                username,
                password,
                udp_enabled,
            } => Self::Socks {
                username,
                password,
                udp_enabled,
            },
            ServerProxyConfig::Shadowsocks {
                config,
                udp_enabled,
            } => Self::Shadowsocks {
                config,
                udp_enabled,
            },

            ServerProxyConfig::Vless {
                user_id,
                decryption,
                _invalid_encryption,
                vision,
                encryption_limits,
                udp_enabled,
                fallback,
            } => Self::Vless {
                user_id,
                decryption,
                _invalid_encryption,
                vision,
                encryption_limits,
                udp_enabled,
                fallback,
            },
            ServerProxyConfig::Trojan {
                password,
                shadowsocks,
            } => Self::Trojan {
                password,
                shadowsocks,
            },
            ServerProxyConfig::Vmess {
                cipher,
                user_id,
                udp_enabled,
            } => Self::Vmess {
                cipher,
                user_id,
                udp_enabled,
            },
            ServerProxyConfig::Anytls {
                users,
                padding_scheme,
                udp_enabled,
                fallback,
            } => Self::Anytls {
                users,
                padding_scheme,
                udp_enabled,
                fallback,
            },
            ServerProxyConfig::PortForward { targets } => Self::PortForward { targets },
            ServerProxyConfig::Hysteria2 {
                password,
                udp_enabled,
            } => Self::Hysteria2 {
                password,
                udp_enabled,
            },
            ServerProxyConfig::TuicV5 {
                uuid,
                password,
                zero_rtt_handshake,
            } => Self::TuicV5 {
                uuid,
                password,
                zero_rtt_handshake,
            },
            ServerProxyConfig::Mixed {
                username,
                password,
                udp_enabled,
            } => Self::Mixed {
                username,
                password,
                udp_enabled,
            },
            ServerProxyConfig::Naiveproxy {
                users,
                padding,
                fallback,
                udp_enabled,
            } => Self::Naiveproxy {
                users,
                padding,
                fallback,
                udp_enabled,
            },
        }
    }
}

impl Inline for ResolvedServerConfig {
    type Source = super::ServerConfig;
    fn inline(source: Self::Source) -> Self {
        Self {
            name: source.name,
            sniff: source.sniff,
            dns_hijack: source.dns_hijack,
            bind_location: source.bind_location,
            protocol: ResolvedServerProxyConfig::inline(source.protocol),
            transport: source.transport,
            tcp_settings: source.tcp_settings,
            quic_settings: source.quic_settings,
            rules: rules(source.rules),
            dns: source.dns.map(ResolvedDnsConfig::inline),
        }
    }
}

impl Inline for ResolvedTunConfig {
    type Source = super::TunConfig;
    fn inline(source: Self::Source) -> Self {
        Self {
            auto_route: source.auto_route,
            auto_redirect: source.auto_redirect,
            auto_dns: source.auto_dns,
            addresses: source.addresses,
            route_address: source.route_address,
            route_exclude_address: source.route_exclude_address,
            bootstrap_dns: source.bootstrap_dns,
            linux: source.linux,
            dns_hijack: source.dns_hijack,
            name: source.name,
            sniff: source.sniff,
            segmentation_offload: source.segmentation_offload,
            resource_limits: source.resource_limits,
            packet_information: source.packet_information,
            device_name: source.device_name,
            device_fd: source.device_fd,
            address: source.address,
            netmask: source.netmask,
            destination: source.destination,
            mtu: source.mtu,
            tcp_enabled: source.tcp_enabled,
            udp_enabled: source.udp_enabled,
            icmp_enabled: source.icmp_enabled,
            rules: rules(source.rules),
            dns: source.dns.map(ResolvedDnsConfig::inline),
        }
    }
}

impl Inline for ResolvedTlsServerConfig {
    type Source = super::TlsServerConfig;
    fn inline(source: Self::Source) -> Self {
        Self {
            certificate_source: source.certificate_source,
            certificate_binding: source.certificate_binding,
            key_exchange_groups: source.key_exchange_groups,
            cert: source.cert,
            key: source.key,
            alpn_protocols: source.alpn_protocols,
            client_ca_certs: source.client_ca_certs,
            client_fingerprints: source.client_fingerprints,
            vision: source.vision,
            protocol: ResolvedServerProxyConfig::inline(source.protocol),
            override_rules: rules(source.override_rules),
        }
    }
}

impl Inline for ResolvedWebsocketServerConfig {
    type Source = super::WebsocketServerConfig;
    fn inline(source: Self::Source) -> Self {
        Self {
            matching_path: source.matching_path,
            matching_headers: source.matching_headers,
            max_early_data: source.max_early_data,
            early_data_header_name: source.early_data_header_name,
            protocol: ResolvedServerProxyConfig::inline(source.protocol),
            ping_type: source.ping_type,
            override_rules: rules(source.override_rules),
        }
    }
}



impl Inline for ResolvedRealityServerConfig {
    type Source = super::RealityServerConfig;
    fn inline(source: Self::Source) -> Self {
        Self {
            mldsa65_seed: source.mldsa65_seed,
            private_key: source.private_key,
            short_ids: source.short_ids,
            dest: source.dest,
            max_time_diff: source.max_time_diff,
            min_client_version: source.min_client_version,
            max_client_version: source.max_client_version,
            cipher_suites: source.cipher_suites,
            vision: source.vision,
            protocol: ResolvedServerProxyConfig::inline(source.protocol),
            dest_client_chain: source.dest_client_chain.map(ResolvedClientHop::inline),
            override_rules: rules(source.override_rules),
        }
    }
}





impl Inline for ResolvedConfig {
    type Source = super::Config;
    fn inline(source: Self::Source) -> Self {
        match source {
            super::Config::Server(server) => Self::Server(ResolvedServerConfig::inline(server)),
            super::Config::TunServer(tun) => Self::TunServer(ResolvedTunConfig::inline(tun)),
            _ => panic!("inline runtime fixture requires a listener"),
        }
    }
}
impl Inline for Vec<ResolvedConfig> {
    type Source = Vec<super::Config>;
    fn inline(source: Self::Source) -> Self {
        source.into_iter().map(ResolvedConfig::inline).collect()
    }
}
impl Inline for Vec<ResolvedRuleConfig> {
    type Source = Vec<RuleConfig>;
    fn inline(source: Self::Source) -> Self {
        source.into_iter().map(ResolvedRuleConfig::inline).collect()
    }
}

pub(crate) fn client(source: ClientConfig) -> ResolvedClientConfig {
    ResolvedClientConfig::inline(source)
}
pub(crate) fn chain(source: ClientChain) -> ResolvedClientChain {
    ResolvedClientChain::inline(source)
}

impl Inline for NoneOrSome<ResolvedRuleConfig> {
    type Source = NoneOrSome<RuleConfig>;
    fn inline(source: Self::Source) -> Self {
        source.map(ResolvedRuleConfig::inline)
    }
}
