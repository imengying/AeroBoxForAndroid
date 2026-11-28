//! Structural lowering after source settings validation.

use super::resolved::*;
use super::{ClientConfig, ClientProxyConfig};

pub(super) fn client(source: ClientConfig) -> ResolvedClientConfig {
    ResolvedClientConfig {
        name: source.name,
        control: source.control,
        bind_interface: source.bind_interface,
        address: source.address,
        domain_resolver: source.domain_resolver,
        dial_options: source.dial_options,
        protocol: client_protocol(source.protocol),
        transport: source.transport,
        tcp_settings: source.tcp_settings,
        quic_settings: source.quic_settings,
    }
}

fn client_protocol(source: ClientProxyConfig) -> ResolvedClientProxyConfig {
    match source {
        ClientProxyConfig::Direct => ResolvedClientProxyConfig::Direct,
        ClientProxyConfig::Hysteria2(config) => ResolvedClientProxyConfig::Hysteria2(config),
        ClientProxyConfig::Tuic(config) => ResolvedClientProxyConfig::Tuic(config),

        ClientProxyConfig::Http {
            settings,
            username,
            password,
            resolve_hostname,
            http_version,
        } => ResolvedClientProxyConfig::Http {
            settings,
            username,
            password,
            resolve_hostname,
            http_version,
        },
        ClientProxyConfig::Socks { username, password } => {
            ResolvedClientProxyConfig::Socks { username, password }
        }
        ClientProxyConfig::Shadowsocks {
            config,
            udp_enabled,
            plugin,
        } => ResolvedClientProxyConfig::Shadowsocks {
            config,
            udp_enabled,
            plugin,
        },

        ClientProxyConfig::Vless {
            user_id,
            encryption,
            _invalid_decryption,
            vision,
            udp_enabled,
            h2mux,
            packet_encoding,
        } => ResolvedClientProxyConfig::Vless {
            user_id,
            encryption,
            _invalid_decryption,
            vision,
            udp_enabled,
            h2mux,
            packet_encoding,
        },
        ClientProxyConfig::Trojan {
            password,
            shadowsocks,
            h2mux,
        } => ResolvedClientProxyConfig::Trojan {
            password,
            shadowsocks,
            h2mux,
        },
        ClientProxyConfig::Reality {
            fingerprint,
            alpn_protocols,
            fragmentation,
            mldsa65_verify,
            public_key,
            short_id,
            sni_hostname,
            cipher_suites,
            vision,
            protocol,
        } => ResolvedClientProxyConfig::Reality {
            fingerprint,
            alpn_protocols,
            fragmentation,
            mldsa65_verify,
            public_key,
            short_id,
            sni_hostname,
            cipher_suites,
            vision,
            protocol: Box::new(client_protocol(*protocol)),
        },

        ClientProxyConfig::Tls(config) => ResolvedClientProxyConfig::Tls(ResolvedTlsClientConfig {
            fragmentation: config.fragmentation,
            options: config.options,
            key_exchange_groups: config.key_exchange_groups,
            verify: config.verify,
            server_fingerprints: config.server_fingerprints,
            sni_hostname: config.sni_hostname,
            alpn_protocols: config.alpn_protocols,
            tls_buffer_size: config.tls_buffer_size,
            key: config.key,
            cert: config.cert,
            vision: config.vision,
            protocol: Box::new(client_protocol(*config.protocol)),
        }),
        ClientProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
            h2mux,
            packet_encoding,
            global_padding,
            authenticated_length,
            alter_id,
        } => ResolvedClientProxyConfig::Vmess {
            cipher,
            user_id,
            udp_enabled,
            h2mux,
            packet_encoding,
            global_padding,
            authenticated_length,
            alter_id,
        },
        ClientProxyConfig::Multiplex(config) => {
            ResolvedClientProxyConfig::Multiplex(config.map(client_protocol))
        }
        ClientProxyConfig::Uot(config) => {
            ResolvedClientProxyConfig::Uot(config.map(client_protocol))
        }
        ClientProxyConfig::StreamTransport(config) => {
            ResolvedClientProxyConfig::StreamTransport(config.map(client_protocol))
        }
        ClientProxyConfig::Websocket(config) => {
            ResolvedClientProxyConfig::Websocket(ResolvedWebsocketClientConfig {
                matching_path: config.matching_path,
                matching_headers: config.matching_headers,
                max_early_data: config.max_early_data,
                early_data_header_name: config.early_data_header_name,
                ping_type: config.ping_type,
                protocol: Box::new(client_protocol(*config.protocol)),
            })
        }

        ClientProxyConfig::PortForward => ResolvedClientProxyConfig::PortForward,
        ClientProxyConfig::Anytls {
            password,
            udp_enabled,
            padding_scheme,
            idle_session_check_interval_secs,
            idle_session_timeout_secs,
            min_idle_session,
            disable_reuse,
        } => ResolvedClientProxyConfig::Anytls {
            password,
            udp_enabled,
            padding_scheme,
            idle_session_check_interval_secs,
            idle_session_timeout_secs,
            min_idle_session,
            disable_reuse,
        },
        ClientProxyConfig::Naiveproxy {
            settings,
            username,
            password,
            padding,
        } => ResolvedClientProxyConfig::Naiveproxy {
            settings,
            username,
            password,
            padding,
        },
    }
}
