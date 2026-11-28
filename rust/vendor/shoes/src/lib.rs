//! shoes - A high-performance multi-protocol proxy server.
//!
//! This library provides the proxy engine used by AeroBox's Android backend.
//!
//! # Features
//!
//! - **Multi-protocol support**: VLESS, VMess, Trojan, Shadowsocks, and more
//! - **TUN device support**: Virtual network interface for VPN mode
//! - **Proxy chaining**: Connect through multiple proxies
//! - **Flexible routing**: Rule-based traffic routing
//!
//! # Android Integration
//!
//! AeroBox's `aerobox-android` crate owns the JNI interface and invokes
//! [`embedding::EmbeddedCore`]. The application owns the VPN service,
//! socket-protection callbacks, and native-library packaging.
//!
//! # Platform Support
//!
//! - Linux (x86_64, aarch64)
//! - Android (arm64-v8a, armeabi-v7a, x86_64, x86)

// This module tree backs the shoes binary and AeroBox's embedded engine.
mod address;
mod anytls;
mod async_stream;
mod atomic;
mod buf_reader;
mod certificates;
mod clash_api;
mod client_proxy_chain;
mod client_proxy_selector;
mod clock;
mod control;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod desktop;
pub mod dial_options;
pub mod dns;
pub mod ech;
pub mod embedding;
mod file_watcher;
mod h2mux;
mod http2;
mod http3_transport;
mod http_handler;
mod hysteria2_server;
mod listener_tasks;
mod mixed_handler;
mod naiveproxy;
mod native_udp;
pub mod network_dial;
mod network_tasks;
mod ntp;
mod option_util;
mod port_forward_handler;
mod prepend_stream;
mod process;
mod quic_client;
mod quic_endpoint;
mod quic_server;
mod quic_stream;
mod reality;
pub mod resolver;
pub mod resources;
mod routing;
pub mod rule_set;
#[cfg(unix)]
mod rule_updater;
pub mod rules;
mod rustls_config_util;
mod rustls_connection_util;

mod shadowsocks;
mod slide_buffer;

mod sniff;
mod socket_policy;
mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
#[cfg(target_os = "linux")]
mod splice;
pub mod ss_plugin;
mod stream_reader;
mod stream_transport;

mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
pub mod tls_fragment;
mod tls_hello;
mod tls_server_handler;
mod trojan_handler;
mod tuic_server;
mod udp_fragments;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

/// Command-line entry point of the `shoes` binary.
pub mod cli;

/// Configuration types.
pub mod config;

/// Multi-output logging infrastructure.
pub mod logging;

/// TUN device support for VPN mode.
#[cfg(unix)]
pub mod tun;

#[cfg(unix)]
pub(crate) mod ip_stack;

pub mod packet_encoding;
