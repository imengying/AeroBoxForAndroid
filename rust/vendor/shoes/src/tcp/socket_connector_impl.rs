//! SocketConnectorImpl - Implementation of SocketConnector trait.
//!
//! Handles TCP and QUIC transports with bind_interface support.
//! Created from the socket-related fields of any ResolvedClientConfig.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, error};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;

use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::{ClientQuicConfig, ResolvedClientConfig, Transport, quic_client::Obfuscation};
use crate::quic_endpoint::QuicEndpoint;
use crate::quic_stream::QuicStream;
use crate::resolver::{Resolver, resolve_addresses, resolve_location};
#[cfg(test)]
use crate::rustls_config_util::try_create_client_config;
use crate::rustls_config_util::try_create_client_config_with_options;
use crate::socket_util::{new_tcp_socket_on_network, new_udp_socket, new_udp_socket_on_network};
use crate::thread_util::get_num_threads;

use super::socket_connector::SocketConnector;

mod early;
mod naive;

const MAX_QUIC_ENDPOINTS: usize = 32;
const TCP_FALLBACK_DELAY: std::time::Duration = std::time::Duration::from_millis(250);
const TCP_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const NATIVE_QUIC_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_TCP_ATTEMPTS: usize = 2;

fn interleave_tcp_addresses(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addresses.first() else {
        return addresses;
    };
    let prefer_ipv6 = first.is_ipv6();
    let (preferred, alternate): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == prefer_ipv6);
    let mut alternate = alternate.into_iter();
    let mut ordered = Vec::with_capacity(preferred.len() + alternate.len());
    for address in preferred {
        ordered.push(address);
        if let Some(address) = alternate.next() {
            ordered.push(address);
        }
    }
    ordered.extend(alternate);
    ordered
}

pub(crate) async fn connect_tcp_candidates<T, F>(
    addresses: Vec<SocketAddr>,
    connect: impl FnMut(SocketAddr) -> std::io::Result<F>,
) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    connect_tcp_candidates_bounded(addresses, None, connect).await
}

pub(crate) async fn connect_tcp_candidates_bounded<T, F>(
    addresses: Vec<SocketAddr>,
    extra_attempts: Option<&tokio::sync::Semaphore>,
    mut connect: impl FnMut(SocketAddr) -> std::io::Result<F>,
) -> std::io::Result<T>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    if addresses.len() == 1 {
        return connect(addresses[0])?.await;
    }

    let mut candidates = interleave_tcp_addresses(addresses).into_iter().enumerate();
    let mut fork_permit = None;
    let mut attempts = FuturesUnordered::new();
    let mut next_launch = tokio::time::Instant::now();
    let mut last_error: Option<(usize, std::io::Error)> = None;

    while candidates.len() != 0 || !attempts.is_empty() {
        let has_active = !attempts.is_empty();
        tokio::select! {
            biased;
            Some((index, address, result)) = attempts.next(), if has_active => {
                match result {
                    Ok(stream) => {
                        drop(attempts);
                        return Ok(stream);
                    }
                    Err(error) => {
                        // Either completed branch ends the two-attempt fork, freeing its permit.
                        fork_permit.take();
                        debug!("TCP connect to {address} failed: {error}");
                        if last_error.as_ref().is_none_or(|(previous, _)| index > *previous) {
                            last_error = Some((index, error));
                        }
                        next_launch = tokio::time::Instant::now();
                    }
                }
            }
            permit = async {
                tokio::time::sleep_until(next_launch).await;
                if has_active
                    && let Some(budget) = extra_attempts
                {
                    return budget.acquire().await.map(Some).map_err(std::io::Error::other);
                }
                Ok(None)
            },
                if candidates.len() != 0 && attempts.len() < MAX_TCP_ATTEMPTS =>
            {
                fork_permit = permit?;
                let (index, address) = candidates.next().unwrap();
                // Socket creation, binding and protection still fail closed.
                let attempt = connect(address)?;
                attempts.push(async move {
                    let result = tokio::time::timeout(TCP_ATTEMPT_TIMEOUT, attempt)
                        .await
                        .unwrap_or_else(|_| Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut, format!("TCP connect to {address} timed out"),
                        )));
                    (index, address, result)
                });
                next_launch = tokio::time::Instant::now() + TCP_FALLBACK_DELAY;
            }
        }
    }
    Err(last_error
        .map(|(_, error)| error)
        .unwrap_or_else(|| std::io::Error::other("no resolved addresses succeeded")))
}

#[derive(Debug)]
enum TransportConfig {
    Tcp {
        no_delay: bool,
    },
    Quic {
        sni_hostname: Option<String>,
        endpoints: Vec<Arc<QuicEndpoint>>,
        next_endpoint_index: AtomicU8,
        hopping: Option<Box<HoppingEndpoint>>,
        native: bool,
        ech: Option<QuicEch>,
        network_endpoints: Option<NetworkQuicEndpoints>,
        naive: Option<Box<naive::Endpoints>>,
    },
}

#[derive(Clone, Debug)]
struct QuicEch {
    policy: Arc<crate::ech::Policy>,
    base: Arc<rustls::ClientConfig>,
    transport: Arc<quinn::TransportConfig>,
}
impl QuicEch {
    fn client_config(
        &self,
        prepared: &crate::ech::Prepared,
    ) -> std::io::Result<quinn::ClientConfig> {
        let crypto = quinn::crypto::rustls::QuicClientConfig::with_initial(
            prepared.config.clone(),
            aerobox_crypto::TLS13_AES_128_GCM_SHA256
                .quic_suite()
                .unwrap(),
        )
        .map_err(std::io::Error::other)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(self.transport.clone());
        Ok(config)
    }
}

#[derive(Debug)]
struct HoppingEndpoint {
    settings: crate::config::quic_client::HoppingConfig,
    obfs: Option<Obfuscation>,
    config: quinn::ClientConfig,
    memory_bytes: usize,
    socket_buffer: usize,
    dial_options: crate::dial_options::DialOptions,
}

#[derive(Debug)]
struct NetworkQuicEndpoints {
    config: quinn::ClientConfig,
    obfs: Option<Obfuscation>,
    memory_bytes: usize,
    socket_buffer: usize,
    dial_options: crate::dial_options::DialOptions,
    cache: parking_lot::Mutex<NetworkEndpointCache>,
}

#[derive(Debug, Default)]
struct NetworkEndpointCache {
    snapshot: Option<crate::network_dial::NetworkKey>,
    entries: Vec<(crate::network_dial::NetworkKey, bool, Arc<QuicEndpoint>)>,
}
impl NetworkEndpointCache {
    fn lookup(
        &mut self,
        key: crate::network_dial::NetworkKey,
        ipv6: bool,
    ) -> std::io::Result<Option<Arc<QuicEndpoint>>> {
        if self.snapshot.is_some_and(|old| !old.same_snapshot(key)) {
            if key.is_older_than(self.snapshot.unwrap()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "QUIC physical-network snapshot has expired",
                ));
            }
            for (_, _, endpoint) in self.entries.drain(..) {
                endpoint.close(0_u32.into(), b"physical network changed");
            }
        }
        self.snapshot = Some(key);
        if let Some(index) = self
            .entries
            .iter()
            .position(|(candidate, family, _)| *candidate == key && *family == ipv6)
        {
            let entry = self.entries.remove(index);
            let endpoint = entry.2.clone();
            self.entries.push(entry);
            return Ok(Some(endpoint));
        }
        Ok(None)
    }
}
impl NetworkQuicEndpoints {
    fn open(
        &self,
        address: SocketAddr,
        binding: &crate::network_dial::NetworkBinding,
    ) -> std::io::Result<Arc<QuicEndpoint>> {
        let key = binding.key();
        if let Some(endpoint) = self.cache.lock().lookup(key, address.is_ipv6())? {
            return Ok(endpoint);
        }
        let socket =
            new_udp_socket_on_network(address.is_ipv6(), None, Some(binding))?.into_std()?;
        let socket = wrap_quic_socket(
            socket,
            self.socket_buffer,
            self.obfs.as_ref(),
            &self.dial_options,
        )?;
        let mut endpoint =
            QuicEndpoint::with_abstract_socket(None, socket, self.memory_bytes, None)?;
        endpoint.set_default_client_config(self.config.clone());
        let endpoint = Arc::new(endpoint);
        let mut cache = self.cache.lock();
        if let Some(existing) = cache.lookup(key, address.is_ipv6())? {
            return Ok(existing);
        }
        if cache.entries.len() == MAX_QUIC_ENDPOINTS {
            // Active carriers retain their own endpoint Arc when an idle cache
            // entry is evicted. Network retirement explicitly closes all flows.
            cache.entries.remove(0);
        }
        cache
            .entries
            .push((key, address.is_ipv6(), endpoint.clone()));
        Ok(endpoint)
    }
}

impl HoppingEndpoint {
    fn open(
        &self,
        address: SocketAddr,
        bind_interface: Option<String>,
        network: Option<crate::network_dial::NetworkBinding>,
    ) -> std::io::Result<Arc<QuicEndpoint>> {
        let obfs = self.obfs.clone();
        let socket_buffer = self.socket_buffer;
        let dial_options = self.dial_options.clone();
        let factory = Arc::new(move || {
            let socket = new_udp_socket_on_network(
                address.is_ipv6(),
                bind_interface.clone(),
                network.as_ref(),
            )?
            .into_std()?;
            wrap_quic_socket(socket, socket_buffer, obfs.as_ref(), &dial_options)
        });
        let socket = crate::quic_client::hop::HoppingSocket::new(factory, address, &self.settings)?;
        let mut endpoint =
            QuicEndpoint::with_abstract_socket(None, socket, self.memory_bytes, None)?;
        endpoint.set_default_client_config(self.config.clone());
        Ok(Arc::new(endpoint))
    }
}

fn wrap_quic_socket(
    socket: std::net::UdpSocket,
    buffer_size: usize,
    obfs: Option<&Obfuscation>,
    options: &crate::dial_options::DialOptions,
) -> std::io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
    crate::socket_util::set_udp_socket_buffers(socket2::SockRef::from(&socket), buffer_size);
    let socket = options.wrap_quic_socket(socket)?;
    Ok(match obfs {
        Some(obfs) => {
            crate::quic_client::salamander::Salamander::wrap(socket, obfs.password().clone())
        }
        None => socket,
    })
}

/// Implementation of SocketConnector for TCP and QUIC transports.
///
/// Created from the socket-related fields of any ResolvedClientConfig:
/// - `bind_interface`
/// - `transport`
/// - `tcp_settings`
/// - `quic_settings`
#[derive(Debug)]
pub struct SocketConnectorImpl {
    network: crate::network_dial::NetworkPolicy,
    bind_interface: Option<String>,
    transport: TransportConfig,
    dial_options: crate::dial_options::DialOptions,
    direct_resolver: Option<crate::config::dns::DomainResolverConfig>,
    fast_open_write_first: bool,
}

impl SocketConnectorImpl {
    /// Create a SocketConnector from a ResolvedClientConfig's socket-related fields.
    ///
    /// # Arguments
    /// * `config` - The client config (socket fields are extracted)
    /// * `target_address` - The address this connector will connect to (used for QUIC SNI default).
    ///   Pass None for direct protocol (QUIC is not supported for direct).
    ///
    /// # Returns
    /// Returns any socket or QUIC endpoint initialization error.
    #[cfg(test)]
    pub fn from_config(
        config: &ResolvedClientConfig,
        target_address: Option<&NetLocation>,
    ) -> std::io::Result<Self> {
        Self::from_config_with_limits(config, target_address, crate::resources::limits())
    }

    pub fn from_config_with_limits(
        config: &ResolvedClientConfig,
        target_address: Option<&NetLocation>,
        limits: crate::config::GlobalLimits,
    ) -> std::io::Result<Self> {
        config.validate_quic_key_exchange(true)?;
        crate::ss_plugin::quic::validate_resolved(config, true)?;
        config.dial_options.validate()?;
        config
            .dial_options
            .validate_transport(config.transport == Transport::Tcp, false)?;
        let bind_interface = config.bind_interface.clone().into_option();
        let dial_options = config.dial_options.clone();
        dial_options.validate_binding(bind_interface.as_deref())?;
        let network = crate::network_dial::NetworkPolicy::new(&dial_options);
        let direct_resolver = config
            .protocol
            .is_direct()
            .then(|| config.domain_resolver.clone())
            .flatten();

        let default_sni_hostname =
            target_address.and_then(|addr| addr.address().hostname().map(ToString::to_string));

        // Direct protocol only supports TCP (no proxy server to connect via QUIC)
        let effective_transport = if config.protocol.is_direct() {
            &Transport::Tcp
        } else {
            &config.transport
        };

        let transport = match *effective_transport {
            Transport::Tcp | Transport::Udp => {
                let no_delay = config
                    .tcp_settings
                    .as_ref()
                    .map(|tc| tc.no_delay)
                    .unwrap_or(true);
                TransportConfig::Tcp { no_delay }
            }
            Transport::Quic => {
                // QUIC requires a target address for endpoint creation
                let target_address = target_address.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "QUIC transport requires a target address",
                    )
                })?;

                let plugin_quic = crate::ss_plugin::quic::resolved(&config.protocol);
                let settings = match plugin_quic {
                    Some(plugin) => crate::ss_plugin::quic::settings(plugin)?,
                    None => config.quic_settings.clone().unwrap_or_default(),
                };
                let ClientQuicConfig {
                    options,
                    key_exchange_groups,
                    verify,
                    server_fingerprints,
                    alpn_protocols,
                    sni_hostname,
                    key,
                    cert,
                } = settings;

                let sni_hostname = if sni_hostname.is_unspecified() {
                    if let Some(ref hostname) = default_sni_hostname {
                        debug!(
                            "Using default sni hostname for QUIC client connection: {}",
                            hostname
                        );
                    }
                    default_sni_hostname.clone()
                } else {
                    sni_hostname.into_option()
                };

                let tls13_suite = &aerobox_crypto::TLS13_AES_128_GCM_SHA256;

                let key_and_cert_bytes = key.zip(cert).map(|(key, cert)| {
                    let cert_bytes = cert.as_bytes().to_vec();
                    let key_bytes = key.as_bytes().to_vec();
                    (key_bytes, cert_bytes)
                });

                let is_native = config.protocol.is_native_quic() || plugin_quic.is_some();
                let (obfs, hopping) = match &config.protocol {
                    crate::config::ResolvedClientProxyConfig::Hysteria2(settings) => {
                        (settings.obfs.clone(), settings.hopping.clone())
                    }
                    _ => (None, None),
                };
                let is_tuic = matches!(
                    config.protocol,
                    crate::config::ResolvedClientProxyConfig::Tuic(_)
                );
                let is_naive = matches!(
                    config.protocol,
                    crate::config::ResolvedClientProxyConfig::Naiveproxy { .. }
                );
                let alpn_protocols = if is_native && alpn_protocols.is_unspecified() {
                    vec!["h3".to_owned()]
                } else {
                    alpn_protocols.into_vec()
                };
                let mut rustls_client_config = if is_naive {
                    crate::rustls_config_util::naive::create_config(&options, true)?
                } else {
                    try_create_client_config_with_options(
                        verify,
                        server_fingerprints.into_vec(),
                        alpn_protocols,
                        sni_hostname.is_some(),
                        key_and_cert_bytes,
                        true,
                        &key_exchange_groups,
                        &options,
                    )?
                };

                if let crate::config::ResolvedClientProxyConfig::Tuic(settings) = &config.protocol {
                    key_exchange_groups.validate_zero_rtt(settings.zero_rtt_handshake)?;
                    rustls_client_config.enable_early_data = settings.zero_rtt_handshake;
                }
                let rustls_client_config = Arc::new(rustls_client_config);
                let ech_policy = options
                    .ech
                    .as_ref()
                    .map(|options| {
                        let name = super::tcp_client_handler_factory::tls_verification_name(
                            sni_hostname.clone(),
                            target_address,
                        )?;
                        crate::ech::Policy::new(options, &name)
                    })
                    .transpose()?;
                let quic_client_config = quinn::crypto::rustls::QuicClientConfig::with_initial(
                    rustls_client_config.clone(),
                    tls13_suite.quic_suite().unwrap(),
                )
                .map_err(std::io::Error::other)?;

                let mut quinn_client_config =
                    quinn::ClientConfig::new(Arc::new(quic_client_config));

                let mut transport_config = quinn::TransportConfig::default();
                let mut memory_bytes = crate::resources::configure_quic_transport_with_limits(
                    &mut transport_config,
                    limits,
                );
                if let crate::config::ResolvedClientProxyConfig::Naiveproxy { settings, .. } =
                    &config.protocol
                {
                    transport_config
                        .congestion_controller_factory(settings.quic_congestion_control.factory());
                    // Naive uses stream data only; reserve the configured
                    // stream windows without unused QUIC datagram buffers.
                    memory_bytes =
                        limits.quic_send_window + settings.session_receive_window as usize;
                    transport_config
                        .receive_window(settings.session_receive_window.into())
                        .stream_receive_window(settings.stream_receive_window.into())
                        .datagram_receive_buffer_size(None)
                        .datagram_send_buffer_size(0);
                }
                if let crate::config::ResolvedClientProxyConfig::Tuic(settings) = &config.protocol {
                    transport_config
                        .congestion_controller_factory(settings.congestion_control.factory());
                }
                let max_uni_streams = if is_naive {
                    // QUICHE's incoming-stream allowance plus H3's three static streams.
                    103
                } else if is_tuic {
                    limits.max_streams_per_connection.unwrap_or(1024).min(1024) as u32
                } else if is_native {
                    16
                } else {
                    0
                };
                transport_config
                    .max_concurrent_bidi_streams(if is_naive { 100_u32 } else { 0 }.into())
                    .max_concurrent_uni_streams(max_uni_streams.into())
                    .keep_alive_interval(Some(std::time::Duration::from_secs(15)))
                    .max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
                if plugin_quic.is_some() {
                    transport_config
                        .datagram_receive_buffer_size(None)
                        .datagram_send_buffer_size(0);
                }
                if obfs.is_some() {
                    let mut mtu = quinn::MtuDiscoveryConfig::default();
                    mtu.upper_bound(1452 - crate::quic_client::salamander::OVERHEAD);
                    transport_config.mtu_discovery_config(Some(mtu));
                }

                let transport_config = Arc::new(transport_config);
                quinn_client_config.transport_config(transport_config.clone());
                let ech = ech_policy.map(|policy| QuicEch {
                    policy,
                    base: rustls_client_config,
                    transport: transport_config,
                });

                let endpoints_len = if hopping.is_some() || network.enabled() || is_naive {
                    0
                } else if is_native {
                    1
                } else {
                    std::cmp::min(get_num_threads(), MAX_QUIC_ENDPOINTS)
                };
                let mut endpoints = Vec::with_capacity(endpoints_len);

                for _ in 0..endpoints_len {
                    let udp_socket = if target_address.address().hostname().is_some() {
                        crate::socket_util::new_hostname_udp_socket(bind_interface.clone())?
                    } else {
                        new_udp_socket(target_address.address().is_ipv6(), bind_interface.clone())?
                    };
                    let socket = wrap_quic_socket(
                        udp_socket.into_std()?,
                        limits.quic_socket_buffer,
                        obfs.as_ref(),
                        &dial_options,
                    )?;
                    let mut endpoint =
                        QuicEndpoint::with_abstract_socket(None, socket, memory_bytes, None)?;
                    endpoint.set_default_client_config(quinn_client_config.clone());
                    endpoints.push(Arc::new(endpoint));
                }

                let network_endpoints =
                    (network.enabled() && !is_naive).then(|| NetworkQuicEndpoints {
                        config: quinn_client_config.clone(),
                        obfs: obfs.clone(),
                        memory_bytes,
                        socket_buffer: limits.quic_socket_buffer,
                        dial_options: dial_options.clone(),
                        cache: Default::default(),
                    });
                TransportConfig::Quic {
                    naive: is_naive.then(|| {
                        Box::new(naive::Endpoints::new(
                            quinn_client_config.clone(),
                            memory_bytes,
                            limits.quic_socket_buffer,
                            dial_options.clone(),
                        ))
                    }),
                    network_endpoints,
                    ech,
                    sni_hostname,
                    endpoints,
                    next_endpoint_index: AtomicU8::new(0),
                    hopping: hopping.map(|settings| {
                        Box::new(HoppingEndpoint {
                            settings,
                            obfs,
                            config: quinn_client_config,
                            memory_bytes,
                            socket_buffer: limits.quic_socket_buffer,
                            dial_options: dial_options.clone(),
                        })
                    }),
                    native: is_native,
                }
            }
        };

        Ok(Self {
            network,
            bind_interface,
            transport,
            dial_options,
            direct_resolver,
            // Domain resolution can race addresses outside this connector too.
            // Only a configured literal proxy endpoint is unambiguously a
            // single carrier whose initial protocol bytes may be sent in SYN.
            fast_open_write_first: !config.protocol.is_direct()
                && config.address.to_socket_addr_nonblocking().is_some(),
        })
    }

    /// Create a simple TCP SocketConnector for direct connections.
    ///
    /// Used when only TCP is needed (no QUIC).
    #[cfg(test)]
    pub fn new_tcp(bind_interface: Option<String>, no_delay: bool) -> Self {
        Self {
            network: crate::network_dial::NetworkPolicy::new(&Default::default()),
            bind_interface,
            transport: TransportConfig::Tcp { no_delay },
            dial_options: Default::default(),
            direct_resolver: None,
            fast_open_write_first: false,
        }
    }

    fn resolver(&self, resolver: &Arc<dyn Resolver>) -> std::io::Result<Arc<dyn Resolver>> {
        self.direct_resolver
            .as_ref()
            .map(|config| crate::dns::routing::endpoint_resolver(resolver, config))
            .transpose()
            .map(|selected| selected.unwrap_or_else(|| resolver.clone()))
    }
    async fn connect_quic_candidates<T>(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
        open: impl AsyncFn(super::carrier_dialer::QuicCarrier) -> std::io::Result<T>,
    ) -> std::io::Result<T> {
        let TransportConfig::Quic {
            sni_hostname,
            native,
            ech,
            naive,
            ..
        } = &self.transport
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "not a QUIC socket connector",
            ));
        };
        let mut addresses = match address.resolved_addr() {
            Some(address) => vec![address],
            None => resolve_addresses(resolver, address.location()).await?,
        };
        if address.address().hostname().is_some() {
            addresses.sort_by_key(SocketAddr::is_ipv6);
        }
        let verification_name = address.address().to_string();
        let domain = sni_hostname.as_deref().unwrap_or(&verification_name);
        let mut last_error = std::io::Error::other("no resolved addresses succeeded");
        for address in addresses {
            let mut endpoint = match self.quic_endpoint(address) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    debug!("QUIC socket creation for {address} failed: {error}");
                    last_error = error;
                    continue;
                }
            };
            let mut prepared = match ech {
                Some(ech) => Some(ech.policy.prepare(&ech.base, resolver).await?),
                None => None,
            };
            let original = prepared.as_ref().map(|prepared| prepared.mode.clone());
            let mut attempt = 0;
            let result = loop {
                let connecting = match (ech, &prepared) {
                    (Some(ech), Some(prepared)) => {
                        endpoint.connect_with(ech.client_config(prepared)?, address, domain)
                    }
                    _ => endpoint.connect(address, domain),
                };
                let result = match connecting {
                    Ok(connecting) if *native => {
                        tokio::time::timeout(NATIVE_QUIC_ATTEMPT_TIMEOUT, connecting)
                            .await
                            .map_err(std::io::Error::from)
                            .and_then(|r| r.map_err(std::io::Error::other))
                    }
                    Ok(connecting) => connecting.await.map_err(std::io::Error::other),
                    Err(error) => Err(error),
                };
                if result.is_err() && attempt == 0 {
                    if let (Some(ech), Some(previous)) = (ech, &prepared) {
                        if let Some(mode) = previous.retry.take()? {
                            prepared = Some(crate::ech::Prepared::new(&ech.base, Arc::new(mode))?);
                            if naive.is_some() {
                                // A zero-CID endpoint belongs to exactly one QUIC connection,
                                // including an authenticated ECH retry after a failed handshake.
                                endpoint = self.quic_endpoint(address)?;
                            }
                            attempt += 1;
                            continue;
                        }
                    }
                }
                if result.is_ok() && attempt == 1 {
                    if let (Some(ech), Some(previous), Some(prepared)) = (ech, &original, &prepared)
                    {
                        ech.policy.accepted_retry(previous, prepared.mode.clone());
                    }
                }
                break result;
            };
            let result = match result {
                Ok(connection) => {
                    open(super::carrier_dialer::QuicCarrier {
                        connection,
                        _endpoint: endpoint,
                    })
                    .await
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(result) => return Ok(result),
                Err(error) => {
                    debug!("QUIC connection to {address} failed: {error}");
                    last_error = error;
                }
            }
        }
        Err(last_error)
    }
}

#[async_trait]
impl SocketConnector for SocketConnectorImpl {
    async fn connect_quic(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> std::io::Result<super::carrier_dialer::QuicCarrier> {
        self.dial_options
            .connect(self.connect_quic_candidates(resolver, address, async |carrier| Ok(carrier)))
            .await
    }

    async fn connect_quic_early(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> std::io::Result<super::carrier_dialer::PendingQuicCarrier> {
        let deadline = tokio::time::Instant::now() + self.dial_options.timeout();
        tokio::time::timeout_at(
            deadline,
            self.connect_quic_early_candidates(resolver, address, deadline),
        )
        .await
        .map_err(std::io::Error::from)?
    }

    async fn connect(
        &self,
        resolver: &Arc<dyn Resolver>,
        address: &ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncStream>> {
        let connect_deadline = tokio::time::Instant::now() + self.dial_options.timeout();
        self.dial_options
            .connect(async {
                let resolver = self.resolver(resolver)?;
                match &self.transport {
                    TransportConfig::Tcp { no_delay } => {
                        let target_addrs = match address.resolved_addr() {
                            Some(r) => vec![r],
                            None => resolve_addresses(&resolver, address.location()).await?,
                        };

                        let defer_first_write =
                            self.fast_open_write_first && target_addrs.len() == 1;
                        let no_delay = *no_delay;
                        let options = self.dial_options.clone();
                        let bind_interface = self.bind_interface.clone();
                        self.network
                            .tcp(connect_deadline, move |network| {
                                let target_addrs = target_addrs.clone();
                                let options = options.clone();
                                let bind_interface = bind_interface.clone();
                                async move {
                                    connect_tcp_candidates(target_addrs, |address| {
                                        let socket = new_tcp_socket_on_network(
                                            bind_interface.clone(),
                                            address.is_ipv6(),
                                            &options,
                                            network.as_ref(),
                                        )?;
                                        let options = options.clone();
                                        Ok(async move {
                                            let stream = socket.connect(address).await?;
                                            if no_delay && let Err(e) = stream.set_nodelay(true) {
                                                error!("Failed to set TCP no-delay: {e}");
                                            }
                                            #[cfg(any(target_os = "linux", target_os = "android"))]
                                            if options.tcp_fast_open {
                                                let mut stream =
                                                    super::fast_open::FastOpenStream::new(
                                                        stream,
                                                        connect_deadline,
                                                    )?;
                                                if !defer_first_write {
                                                    stream.establish_without_data().await?;
                                                }
                                                return Ok(Box::new(stream) as Box<dyn AsyncStream>);
                                            }
                                            #[cfg(not(any(
                                                target_os = "linux",
                                                target_os = "android"
                                            )))]
                                            let _ = (defer_first_write, options, connect_deadline);
                                            Ok(Box::new(stream) as Box<dyn AsyncStream>)
                                        })
                                    })
                                    .await
                                }
                            })
                            .await
                    }
                    TransportConfig::Quic { .. } => {
                        self.connect_quic_candidates(&resolver, address, async |carrier| {
                            let (send, recv) = carrier
                                .connection
                                .open_bi()
                                .await
                                .map_err(std::io::Error::other)?;
                            Ok(Box::new(QuicStream::from(send, recv)) as Box<dyn AsyncStream>)
                        })
                        .await
                    }
                }
            })
            .await
    }

    async fn connect_udp_bidirectional(
        &self,
        resolver: &Arc<dyn Resolver>,
        mut target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        debug!(
            "[SocketConnector] connect_udp_bidirectional called, target: {}",
            target.location()
        );

        self.dial_options
            .connect(async {
                let resolver = self.resolver(resolver)?;
                let remote_addr = resolve_location(&mut target, &resolver).await?;
                let client_socket = self.network.udp(|network| {
                    new_udp_socket_on_network(
                        remote_addr.is_ipv6(),
                        self.bind_interface.clone(),
                        network,
                    )
                })?;
                self.dial_options.apply_udp(
                    socket2::SockRef::from(&client_socket),
                    remote_addr.is_ipv6(),
                )?;

                // Don't use connect() - wrap in UnconnectedUdpSocket instead.
                // A connected UDP socket filters incoming packets by source address,
                // which breaks when bind_interface causes packets to arrive from
                // a different source than the target address.
                Ok(
                    Box::new(UnconnectedUdpSocket::new(client_socket, remote_addr))
                        as Box<dyn AsyncMessageStream>,
                )
            })
            .await
    }

    fn bind_interface(&self) -> Option<&str> {
        self.bind_interface.as_deref()
    }

    async fn connect_proxy_datagram(
        &self,
        resolver: &Arc<dyn Resolver>,
        mut target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn crate::async_stream::AsyncMessageStream>> {
        self.dial_options
            .connect(async {
                let resolver = self.resolver(resolver)?;
                let address = resolve_location(&mut target, &resolver).await?;
                let socket = self.network.udp(|network| {
                    new_udp_socket_on_network(
                        address.is_ipv6(),
                        self.bind_interface.clone(),
                        network,
                    )
                })?;
                self.dial_options
                    .apply_udp(socket2::SockRef::from(&socket), address.is_ipv6())?;
                socket.connect(address).await?;
                Ok(Box::new(socket) as Box<dyn AsyncMessageStream>)
            })
            .await
    }
}

/// A UDP socket wrapper that tracks the destination and uses send_to/recv_from.
/// Unlike a connected UDP socket, this accepts incoming packets from any source.
struct UnconnectedUdpSocket {
    socket: UdpSocket,
    destination: SocketAddr,
}

impl UnconnectedUdpSocket {
    fn new(socket: UdpSocket, destination: SocketAddr) -> Self {
        Self {
            socket,
            destination,
        }
    }
}

impl crate::async_stream::AsyncReadMessage for UnconnectedUdpSocket {
    fn read_message_eof_on_empty(&self) -> bool {
        false
    }
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.socket.poll_recv_from(cx, buf) {
            Poll::Ready(Ok(addr)) => {
                log::debug!(
                    "[UnconnectedUdp] Received {} bytes from {} (target: {})",
                    buf.filled().len(),
                    addr,
                    this.destination
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl crate::async_stream::AsyncWriteMessage for UnconnectedUdpSocket {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.socket
            .poll_send_to(cx, buf, this.destination)
            .map(|r| r.map(|_| ()))
    }
}

impl crate::async_stream::AsyncFlushMessage for UnconnectedUdpSocket {
    fn poll_flush_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncShutdownMessage for UnconnectedUdpSocket {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl crate::async_stream::AsyncPing for UnconnectedUdpSocket {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl crate::async_stream::AsyncMessageStream for UnconnectedUdpSocket {}

#[cfg(test)]
mod network_tests;

#[cfg(test)]
mod early_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::option_util::NoneOrOne;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::time::Instant;

    #[derive(Debug)]
    struct FixedResolver(Vec<SocketAddr>);

    impl Resolver for FixedResolver {
        fn resolve_location(
            &self,
            _location: &NetLocation,
        ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
        {
            let addresses = self.0.clone();
            Box::pin(async move { Ok(addresses) })
        }
    }

    #[tokio::test]
    async fn routed_ip_pins_first_answer_instead_of_dialing_an_unjudged_fallback() {
        use crate::address::NetLocationMask;
        use crate::client_proxy_selector::{
            ClientProxySelector, ConnectAction, ConnectDecision, ConnectRule,
        };
        let refused = tokio::net::TcpSocket::new_v4().unwrap();
        refused.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let reachable = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let good = SocketAddr::from(([127, 0, 0, 1], reachable.local_addr().unwrap().port()));
        let resolver: Arc<dyn Resolver> =
            Arc::new(FixedResolver(vec![refused.local_addr().unwrap(), good]));
        let selector = ClientProxySelector::new(vec![ConnectRule::new(
            vec![NetLocationMask::from("127.0.0.0/8").unwrap()],
            ConnectAction::new_allow(
                None,
                super::super::chain_builder::build_direct_chain_group(resolver.clone()),
            ),
        )]);
        let location: ResolvedLocation = NetLocation::from_str("fallback.example:443", None)
            .unwrap()
            .into();
        let ConnectDecision::Allow {
            remote_location, ..
        } = selector.judge(location.clone(), &resolver).await.unwrap()
        else {
            panic!("expected allow")
        };
        assert_eq!(
            remote_location.resolved_addr(),
            Some(refused.local_addr().unwrap())
        );
        let connector = SocketConnectorImpl::new_tcp(None, true);
        assert!(
            connector
                .connect(&resolver, &remote_location)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), reachable.accept())
                .await
                .is_err()
        );
        let stream = connector.connect(&resolver, &location).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), reachable.accept())
            .await
            .unwrap()
            .unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn quic_hostname_verification_survives_explicit_null_sni() {
        check_quic_verification(
            "localhost",
            "localhost",
            NoneOrOne::None,
            false,
            true,
            &[
                "{type: socks}",
            ],
        )
        .await;
    }

    const QUIC_PROTOCOLS: &[&str] = &[
        "{type: socks}",
        "{type: hysteria2, password: password}",
        "{type: tuic, uuid: 01234567-89ab-4def-8123-456789abcdef, password: password}",
    ];

    #[tokio::test]
    async fn quic_verifies_ip_certificates_without_sni() {
        for (host, ipv6) in [("127.0.0.1", false), ("::1", true)] {
            for sni in [NoneOrOne::Unspecified, NoneOrOne::None] {
                check_quic_verification(host, host, sni, ipv6, true, QUIC_PROTOCOLS).await;
            }
        }
    }

    #[tokio::test]
    async fn quic_verifies_hostnames_and_sni_overrides() {
        use NoneOrOne::{One, Unspecified};

        for (host, certificate_name, sni, ipv6, succeeds) in [
            ("localhost", "localhost", Unspecified, false, true),
            ("localhost", "localhost", NoneOrOne::None, true, true),
            ("127.0.0.1", "localhost", One("localhost"), false, true),
            ("::1", "localhost", One("localhost"), true, true),
            ("127.0.0.1", "localhost", Unspecified, false, false),
            ("::1", "localhost", NoneOrOne::None, true, false),
            ("127.0.0.1", "example.com", NoneOrOne::None, false, false),
            ("::1", "example.com", Unspecified, true, false),
            ("localhost", "localhost", One("wrong.example"), true, false),
        ] {
            check_quic_verification(host, certificate_name, sni, ipv6, succeeds, QUIC_PROTOCOLS)
                .await;
        }
    }

    async fn check_quic_verification(
        host: &str,
        certificate_name: &str,
        sni: NoneOrOne<&str>,
        ipv6: bool,
        succeeds: bool,
        protocols: &[&str],
    ) {
        let certificate =
            rcgen::generate_simple_self_signed(vec![certificate_name.into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let mut server_tls =
            rustls::ServerConfig::builder_with_provider(Arc::new(aerobox_crypto::provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        certificate.signing_key.serialize_der(),
                    )
                    .into(),
                )
                .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
            )),
            if ipv6 { "[::]:0" } else { "0.0.0.0:0" }.parse().unwrap(),
        )
        .unwrap();
        let port = server.local_addr().unwrap().port();
        let peer_address = format!("{}:{port}", if ipv6 { "[::1]" } else { "127.0.0.1" });
        let resolver: Arc<dyn Resolver> =
            Arc::new(FixedResolver(vec![peer_address.parse().unwrap()]));
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(aerobox_crypto::provider()),
        )
        .build()
        .unwrap();
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let sni_yaml = match sni {
            NoneOrOne::Unspecified => String::new(),
            NoneOrOne::None => "sni_hostname: null, ".into(),
            NoneOrOne::One(name) => format!("sni_hostname: '{name}', "),
        };
        for protocol in protocols {
            let config: ResolvedClientConfig = crate::config::test_support::from_yaml(&format!(
                "address: '{host}:{port}'\ntransport: quic\nquic_settings: {{verify: true, {sni_yaml}alpn_protocols: [h3]}}\nprotocol: {protocol}\n"
            ))
            .unwrap();
            let expected_sni = match sni {
                NoneOrOne::Unspecified => config.address.address().hostname(),
                NoneOrOne::None => None,
                NoneOrOne::One(name) => Some(name),
            };
            let mut connector =
                SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
            let TransportConfig::Quic {
                endpoints,
                sni_hostname,
                ..
            } = &mut connector.transport
            else {
                unreachable!()
            };
            assert_eq!(sni_hostname.as_deref(), expected_sni);
            let mut client_tls = try_create_client_config(
                true,
                vec![],
                vec!["h3".into()],
                sni_hostname.is_some(),
                None,
                false,
                &Default::default(),
            )
            .unwrap();
            // Trusts the local test certificate without bypassing name verification.
            client_tls
                .dangerous()
                .set_certificate_verifier(verifier.clone());
            let client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
            ));
            for endpoint in endpoints {
                Arc::get_mut(endpoint)
                    .unwrap()
                    .set_default_client_config(client_config.clone());
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                let target = ResolvedLocation::new(config.address.clone());
                let (client, peer) =
                    tokio::join!(connector.connect_quic(&resolver, &target), async {
                        server.accept().await.unwrap().await
                    },);
                if !succeeds {
                    let error = match client {
                        Err(error) => error,
                        Ok(_) => panic!("certificate name mismatch unexpectedly succeeded"),
                    };
                    assert!(error.to_string().contains("not valid for name"), "{error}");
                    assert!(peer.is_err());
                    return;
                }
                let client = client.unwrap();
                let peer = peer.unwrap();
                let handshake = peer
                    .handshake_data()
                    .unwrap()
                    .downcast::<quinn::crypto::rustls::HandshakeData>()
                    .unwrap();
                assert_eq!(handshake.server_name.as_deref(), expected_sni);
                client.connection.close(0u32.into(), b"done");
            })
            .await
            .unwrap();
        }
        server.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn hostname_quic_prefers_ipv4_without_waiting_for_stalled_ipv6() {
        use tokio::io::AsyncWriteExt;
        let Ok(blackhole) = UdpSocket::bind("[::1]:0").await else {
            return;
        };
        let stalled = blackhole.local_addr().unwrap();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let server =
                quinn::Endpoint::server(server_config.clone(), bind.parse().unwrap()).unwrap();
            let server_addr = server.local_addr().unwrap();
            let addresses = if server_addr.is_ipv4() {
                vec![stalled, server_addr]
            } else {
                vec![server_addr]
            };
            let resolver: Arc<dyn Resolver> = Arc::new(FixedResolver(addresses));
            let config: ResolvedClientConfig = crate::config::test_support::from_yaml("address: 'localhost:443'\ntransport: quic\nquic_settings: {verify: false}\nprotocol: {type: socks}\n").unwrap();
            let connector =
                SocketConnectorImpl::from_config(&config, Some(&config.address)).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                let (client, received) = tokio::join!(
                    async {
                        let mut stream = connector
                            .connect(&resolver, &ResolvedLocation::new(config.address.clone()))
                            .await
                            .unwrap();
                        stream.write_all(b"ping").await.unwrap();
                        stream.flush().await.unwrap();
                        stream
                    },
                    async {
                        let connection = server.accept().await.unwrap().await.unwrap();
                        let (_send, mut recv) = connection.accept_bi().await.unwrap();
                        let mut data = [0; 4];
                        recv.read_exact(&mut data).await.unwrap();
                        assert_eq!(&data, b"ping");
                        connection
                    },
                );
                drop((client, received));
            })
            .await
            .unwrap();
            server.close(0u32.into(), b"done");
        }
    }

    fn addresses(count: u16) -> Vec<SocketAddr> {
        (1..=count)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .collect()
    }

    #[derive(Default)]
    struct Attempts {
        active: AtomicUsize,
        peak: AtomicUsize,
        starts: parking_lot::Mutex<Vec<(SocketAddr, Instant)>>,
    }

    struct ActiveAttempt(Arc<Attempts>);

    impl Attempts {
        fn start(self: &Arc<Self>, address: SocketAddr) -> ActiveAttempt {
            let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
            self.peak.fetch_max(active, Ordering::Relaxed);
            self.starts.lock().push((address, Instant::now()));
            ActiveAttempt(self.clone())
        }
    }

    impl Drop for ActiveAttempt {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn address_interleaving_preserves_resolver_family_preference() {
        let v4 = addresses(3);
        let v6: Vec<SocketAddr> = ["[::1]:1", "[::1]:2"].map(|s| s.parse().unwrap()).to_vec();
        assert_eq!(
            interleave_tcp_addresses(vec![v4[0], v4[1], v6[0], v6[1], v4[2]]),
            vec![v4[0], v6[0], v4[1], v6[1], v4[2]]
        );
        assert_eq!(
            interleave_tcp_addresses(vec![v6[0], v6[1], v4[0], v4[1]]),
            vec![v6[0], v4[0], v6[1], v4[1]]
        );
        assert_eq!(interleave_tcp_addresses(v4.clone()), v4);
        assert!(interleave_tcp_addresses(vec![]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stagger_keeps_slow_viable_attempts_and_cancels_losers() {
        let attempts = Arc::new(Attempts::default());
        let start = Instant::now();
        let winner = connect_tcp_candidates(addresses(3), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                if address.port() != 1 {
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(Duration::from_millis(750)).await;
                Ok(address)
            })
        })
        .await
        .unwrap();
        assert_eq!(winner.port(), 1);
        assert_eq!(start.elapsed(), Duration::from_millis(750));
        let starts = attempts.starts.lock();
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[1].1 - starts[0].1, TCP_FALLBACK_DELAY);
        assert_eq!(attempts.peak.load(Ordering::Relaxed), 2);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn attempt_timeout_reaches_later_candidates_without_exceeding_the_cap() {
        let attempts = Arc::new(Attempts::default());
        let start = Instant::now();
        let winner = connect_tcp_candidates(addresses(4), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                if address.port() < 3 {
                    std::future::pending::<()>().await;
                }
                Ok(address)
            })
        })
        .await
        .unwrap();
        assert_eq!(winner.port(), 3);
        assert_eq!(start.elapsed(), TCP_ATTEMPT_TIMEOUT);
        assert_eq!(attempts.starts.lock().len(), 3);
        assert_eq!(attempts.peak.load(Ordering::Relaxed), MAX_TCP_ATTEMPTS);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn failures_advance_immediately_and_singletons_keep_their_deadline() {
        let start = Instant::now();
        let error = connect_tcp_candidates(addresses(3), |address| {
            Ok(async move { Err::<(), _>(std::io::Error::other(address.to_string())) })
        })
        .await
        .unwrap_err();
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(error.to_string(), "127.0.0.1:3");
        connect_tcp_candidates(addresses(1), |_| {
            Ok(async {
                tokio::time::sleep(TCP_ATTEMPT_TIMEOUT * 2).await;
                Ok(())
            })
        })
        .await
        .unwrap();
        assert_eq!(start.elapsed(), TCP_ATTEMPT_TIMEOUT * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn outer_cancellation_drops_every_pending_socket() {
        let attempts = Arc::new(Attempts::default());
        let mut connect = Box::pin(connect_tcp_candidates(addresses(4), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                std::future::pending::<std::io::Result<()>>().await
            })
        }));
        assert!(futures::poll!(&mut connect).is_pending());
        tokio::time::advance(TCP_FALLBACK_DELAY).await;
        assert!(futures::poll!(&mut connect).is_pending());
        assert_eq!(attempts.active.load(Ordering::Relaxed), 2);
        drop(connect);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_fallback_recycles_the_fork_when_the_primary_fails() {
        let budget = tokio::sync::Semaphore::new(1);
        let attempts = Arc::new(Attempts::default());
        let start = Instant::now();
        let winner = connect_tcp_candidates_bounded(addresses(3), Some(&budget), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                match address.port() {
                    1 => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        Err(std::io::ErrorKind::ConnectionRefused.into())
                    }
                    2 => std::future::pending().await,
                    _ => Ok(address),
                }
            })
        })
        .await
        .unwrap();
        assert_eq!(winner.port(), 3);
        assert_eq!(start.elapsed(), Duration::from_millis(300));
        assert_eq!(attempts.peak.load(Ordering::Relaxed), 2);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
        assert_eq!(budget.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_fallback_keeps_primary_progress_while_waiting_for_capacity() {
        let budget = tokio::sync::Semaphore::new(1);
        let held = budget.acquire().await.unwrap();
        let attempts = Arc::new(Attempts::default());
        let start = Instant::now();
        let winner = connect_tcp_candidates_bounded(addresses(2), Some(&budget), |address| {
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                if address.port() == 1 {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    return Err(std::io::ErrorKind::ConnectionRefused.into());
                }
                Ok(address)
            })
        })
        .await
        .unwrap();
        assert_eq!(winner.port(), 2);
        assert_eq!(start.elapsed(), Duration::from_millis(300));
        assert_eq!(attempts.peak.load(Ordering::Relaxed), 1);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
        assert_eq!(budget.available_permits(), 0);
        drop(held);

        let mut connect = Box::pin(connect_tcp_candidates_bounded(
            addresses(2),
            Some(&budget),
            |address| {
                let guard = attempts.start(address);
                Ok(async move {
                    let _guard = guard;
                    std::future::pending::<std::io::Result<()>>().await
                })
            },
        ));
        let held = budget.acquire().await.unwrap();
        assert!(futures::poll!(&mut connect).is_pending());
        tokio::time::advance(TCP_FALLBACK_DELAY).await;
        assert!(futures::poll!(&mut connect).is_pending());
        assert_eq!(attempts.active.load(Ordering::Relaxed), 1);
        drop(connect);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
        drop(held);
        assert_eq!(budget.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn socket_creation_failure_does_not_bypass_protection_or_binding() {
        let attempts = Arc::new(Attempts::default());
        let error = connect_tcp_candidates(addresses(3), |address| {
            if address.port() == 2 {
                return Err(std::io::ErrorKind::PermissionDenied.into());
            }
            let guard = attempts.start(address);
            Ok(async move {
                let _guard = guard;
                std::future::pending::<std::io::Result<()>>().await
            })
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(attempts.starts.lock().len(), 1);
        assert_eq!(attempts.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn pinned_tcp_target_bypasses_dns() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        #[derive(Debug)]
        struct NoDns;
        impl Resolver for NoDns {
            fn resolve_location(
                &self,
                _: &NetLocation,
            ) -> Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>
            {
                panic!("a policy-pinned target must not resolve again")
            }
        }
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
        let target = ResolvedLocation::with_resolved(
            NetLocation::from_str("unknown.invalid:443", None).unwrap(),
            address,
        );
        let resolver: Arc<dyn Resolver> = Arc::new(NoDns);
        let mut stream = SocketConnectorImpl::new_tcp(None, true)
            .connect(&resolver, &target)
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        stream.write_all(b"pinned").await.unwrap();
        let mut data = [0; 6];
        peer.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pinned");
    }

    #[test]
    fn test_new_tcp() {
        let connector = SocketConnectorImpl::new_tcp(Some("eth0".to_string()), true);
        assert!(matches!(
            connector.transport,
            TransportConfig::Tcp { no_delay: true }
        ));
        assert_eq!(connector.bind_interface, Some("eth0".to_string()));
    }

    #[test]
    fn test_from_config_direct_protocol() {
        let config = ResolvedClientConfig::default(); // default is direct protocol
        let connector = SocketConnectorImpl::from_config(&config, None);
        assert!(connector.is_ok());
        assert!(matches!(
            connector.unwrap().transport,
            TransportConfig::Tcp { .. }
        ));
    }
}
