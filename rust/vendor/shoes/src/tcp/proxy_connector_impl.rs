//! ProxyConnectorImpl - Implementation of ProxyConnector trait.
//!
//! Handles protocol setup for proxy connections on existing streams.
//! Created from the protocol-related fields of a ResolvedClientConfig.

use std::sync::Arc;

use async_trait::async_trait;
use log::debug;

use super::carrier_dialer::CarrierDialer;
use super::proxy_connector::ProxyConnector;
use super::tcp_client_handler_factory::create_tcp_client_handler;
use crate::address::{NetLocation, ResolvedLocation};
use crate::async_stream::{AsyncMessageStream, AsyncStream};
use crate::config::ResolvedClientConfig;
use crate::resolver::Resolver;
use crate::tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};

pub(crate) fn create_proxy_connector(
    config: ResolvedClientConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Option<Box<dyn ProxyConnector>>> {
    let domain_resolver = config.domain_resolver.clone();
    let dial_options = config.dial_options.clone();
    Ok(
        create_proxy_connector_inner(config, resolver)?.map(|inner| {
            if domain_resolver.is_some()
                || dial_options.connect_timeout.is_some()
                || dial_options.tcp_fast_open
            {
                Box::new(DnsConnector {
                    inner,
                    config: domain_resolver,
                    dial_options,
                }) as Box<dyn ProxyConnector>
            } else {
                inner
            }
        }),
    )
}

fn create_proxy_connector_inner(
    config: ResolvedClientConfig,
    resolver: Arc<dyn Resolver>,
) -> std::io::Result<Option<Box<dyn ProxyConnector>>> {
    if matches!(&config.protocol,crate::config::ResolvedClientProxyConfig::Naiveproxy{settings,..} if settings.quic)
    {
        return Ok(Some(Box::new(crate::naiveproxy::quic::Client::new(
            config,
        )?)));
    }
    if config.protocol.is_native_quic() {
        return Ok(Some(Box::new(crate::quic_client::Client::new(config)?)));
    }
    Ok(ProxyConnectorImpl::from_config(config, resolver)?
        .map(|connector| Box::new(connector) as Box<dyn ProxyConnector>))
}

#[derive(Debug)]
struct DnsConnector {
    inner: Box<dyn ProxyConnector>,
    config: Option<crate::config::dns::DomainResolverConfig>,
    dial_options: crate::dial_options::DialOptions,
}
impl DnsConnector {
    async fn finish_tcp(
        &self,
        mut result: TcpClientSetupResult,
    ) -> std::io::Result<TcpClientSetupResult> {
        if self.dial_options.tcp_fast_open {
            // One-way protocol handshakes may otherwise return immediately
            // after queuing their first bytes in a deferred TFO socket. Keep
            // connection setup and its timeout alive until TCP establishes.
            tokio::io::AsyncWriteExt::flush(&mut result.client_stream).await?;
        }
        Ok(result)
    }

    async fn finish_datagram(
        &self,
        mut stream: Box<dyn AsyncMessageStream>,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if self.dial_options.tcp_fast_open {
            futures::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_flush_message(cx))
                .await?;
        }
        Ok(stream)
    }
}
#[async_trait]
impl ProxyConnector for DnsConnector {
    fn domain_resolver(&self) -> Option<&crate::config::dns::DomainResolverConfig> {
        self.config.as_ref()
    }
    fn needs_carrier_dialer(&self) -> bool {
        self.config.is_some()
            || self.dial_options.connect_timeout.is_some()
            || self.dial_options.tcp_fast_open
            || self.inner.needs_carrier_dialer()
    }
    fn proxy_location(&self) -> &NetLocation {
        self.inner.proxy_location()
    }
    fn supports_udp(&self) -> bool {
        self.inner.supports_udp()
    }
    fn requires_datagram_carrier(&self) -> bool {
        self.inner.requires_datagram_carrier()
    }
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        self.inner.prepare_target(target, resolver).await
    }
    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        self.dial_options
            .connect(self.inner.try_reuse_tcp_stream(target))
            .await
    }
    async fn connect_tcp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.dial_options
            .connect(async {
                let result = self.inner.connect_tcp_with_dialer(dialer, target).await?;
                self.finish_tcp(result).await
            })
            .await
    }
    async fn connect_udp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.dial_options
            .connect(async {
                let stream = self.inner.connect_udp_with_dialer(dialer, target).await?;
                self.finish_datagram(stream).await
            })
            .await
    }
    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.dial_options
            .connect(async {
                let result = self.inner.setup_tcp_stream(stream, target).await?;
                self.finish_tcp(result).await
            })
            .await
    }
    async fn setup_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        self.dial_options
            .connect(async {
                let stream = self.inner.setup_udp_bidirectional(stream, target).await?;
                self.finish_datagram(stream).await
            })
            .await
    }
}

/// Implementation of ProxyConnector for proxy protocol setup.
///
/// Created from the protocol-related fields of a ResolvedClientConfig:
/// - `protocol`
/// - `address`
///
/// This connector only wraps protocols on existing streams - it does not
/// create socket connections. Socket creation is handled by SocketConnector.
#[derive(Debug)]
pub struct ProxyConnectorImpl {
    location: NetLocation,
    retry_transport: bool,
    client_handler: Box<dyn TcpClientHandler>,

    plugin_quic: Option<crate::ss_plugin::quic::Pool>,
    native_udp: Option<crate::native_udp::Client>,
}

impl ProxyConnectorImpl {
    fn client_transport(&self, dialer: Arc<dyn CarrierDialer>) -> ClientTransport<'_> {
        let route = dialer.clone();
        let reopen: super::tcp_handler::ReopenTransport<'_> = Arc::new(move || {
            let dialer = dialer.clone();
            Box::pin(async move {
                if let Some(pool) = &self.plugin_quic {
                    return pool.open(dialer).await;
                }
                dialer.open_stream().await
            })
        });
        ClientTransport {
            route,
            open: reopen(),
            reopen: Some(reopen),
        }
    }

    /// Create a ProxyConnector from a ResolvedClientConfig's protocol-related fields.
    ///
    /// Returns None for direct protocol (direct has no ProxyConnector).
    pub fn from_config(
        config: ResolvedClientConfig,
        resolver: Arc<dyn Resolver>,
    ) -> std::io::Result<Option<Self>> {
        crate::ss_plugin::quic::validate_resolved(&config, true)?;
        if config.protocol.is_direct() {
            return Ok(None);
        }

        let native_udp = crate::native_udp::Client::from_config(&config)?;
        let plugin_quic = crate::ss_plugin::quic::resolved(&config.protocol)
            .map(|_| crate::ss_plugin::quic::Pool::default());
        let retry_transport = crate::ech::contains(&config.protocol);
        let client_handler = create_tcp_client_handler(config.protocol, &config.address, resolver)?;

        Ok(Some(Self {
            retry_transport,
            plugin_quic,
            native_udp,
            location: config.address,
            client_handler,
        }))
    }
}

#[async_trait]
impl ProxyConnector for ProxyConnectorImpl {
    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        self.client_handler.prepare_target(target, resolver).await
    }

    fn needs_carrier_dialer(&self) -> bool {
        self.retry_transport
            || self.native_udp.is_some()
            || self.plugin_quic.is_some()
            || self.client_handler.has_session_pool()
    }

    async fn connect_tcp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        self.client_handler
            .connect_client_tcp(self.client_transport(dialer), target.clone())
            .await
    }

    async fn connect_udp_with_dialer(
        &self,
        dialer: Arc<dyn CarrierDialer>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if let Some(native) = &self.native_udp {
            return native.connect(dialer, &self.location, target).await;
        }
        self.client_handler
            .connect_client_udp(self.client_transport(dialer), target)
            .await
    }

    fn proxy_location(&self) -> &NetLocation {
        &self.location
    }

    fn supports_udp(&self) -> bool {
        self.native_udp.is_some() || self.client_handler.supports_udp_over_tcp()
    }

    fn requires_datagram_carrier(&self) -> bool {
        self.native_udp.is_some()
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        self.client_handler.try_reuse_tcp_stream(target).await
    }

    async fn setup_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: &ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        debug!(
            "[ProxyConnector] setup_tcp_stream: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_tcp_stream(stream, target.clone())
            .await
    }

    async fn setup_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        debug!(
            "[ProxyConnector] setup_udp_bidirectional: {} -> {}",
            self.location, target
        );
        self.client_handler
            .setup_client_udp_bidirectional(stream, target)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedClientProxyConfig;
    use crate::resolver::NativeResolver;
    use crate::tcp::carrier_dialer::RouteKey;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn mock_resolver() -> Arc<dyn Resolver> {
        Arc::new(NativeResolver::new())
    }

    #[derive(Debug)]
    struct UnopenedDialer(RouteKey);

    #[async_trait]
    impl CarrierDialer for UnopenedDialer {
        fn route_key(&self) -> &RouteKey {
            &self.0
        }

        async fn open_stream(&self) -> std::io::Result<Box<dyn AsyncStream>> {
            panic!("pool hit must not open a carrier")
        }
    }

    #[derive(Debug)]
    struct PoolProbe {
        open_transport: bool,
    }

    const PROBE_PAYLOAD: &[u8] = b"cleartext probe";

    impl PoolProbe {
        async fn probe(&self, transport: ClientTransport<'_>) -> std::io::Result<()> {
            assert_eq!(transport.route.route_key(), &RouteKey(vec![1]));
            if self.open_transport {
                let mut stream = transport.open.await?;
                stream.write_all(PROBE_PAYLOAD).await?;
                stream.flush().await?;
            }
            Ok(())
        }
    }

    #[async_trait]
    impl TcpClientHandler for PoolProbe {
        fn has_session_pool(&self) -> bool {
            true
        }

        async fn connect_client_tcp(
            &self,
            transport: ClientTransport<'_>,
            _: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            self.probe(transport).await?;
            Err(std::io::Error::other("TCP pool reached"))
        }

        async fn connect_client_udp(
            &self,
            transport: ClientTransport<'_>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            self.probe(transport).await?;
            Err(std::io::Error::other("UDP pool reached"))
        }

        async fn setup_client_tcp_stream(
            &self,
            _: Box<dyn AsyncStream>,
            _: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            panic!("pool hit must use the lazy connect path")
        }
    }

    async fn assert_pool_forwarding(connector: &ProxyConnectorImpl) {
        assert!(connector.client_handler.has_session_pool());
        assert!(connector.needs_carrier_dialer());
        let dialer = Arc::new(UnopenedDialer(RouteKey(vec![1])));
        let target = NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        assert_eq!(
            connector
                .connect_tcp_with_dialer(dialer.clone(), &target)
                .await
                .err()
                .unwrap()
                .to_string(),
            "TCP pool reached"
        );
        assert_eq!(
            connector
                .connect_udp_with_dialer(dialer, target)
                .await
                .err()
                .unwrap()
                .to_string(),
            "UDP pool reached"
        );
    }

    fn wrapper_handlers(open_transport: bool) -> Vec<(&'static str, Box<dyn TcpClientHandler>)> {
        let tls = Arc::new(
            rustls::ClientConfig::builder_with_provider(aerobox_crypto::shared_provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );

        let mut public_key = [0; 32];
        public_key[0] = 9;
        let inner = || Box::new(PoolProbe { open_transport }) as Box<dyn TcpClientHandler>;
        vec![
            (
                "tls",
                Box::new(crate::tls_client_handler::TlsClientHandler::new(
                    tls.clone(),
                    None,
                    "localhost".try_into().unwrap(),
                    inner(),
                )),
            ),
            (
                "reality",
                Box::new(crate::reality::RealityClientHandler::new(
                    public_key,
                    [0; 8],
                    "localhost".try_into().unwrap(),
                    vec![],
                    inner(),
                )),
            ),
            (
                "websocket",
                Box::new(crate::websocket::WebsocketTcpClientHandler::new(
                    "localhost:443".into(),
                    None,
                    None,
                    Default::default(),
                    inner(),
                )),
            ),
        ]
    }

    #[tokio::test]
    async fn every_wrapper_forwards_pool_hits_without_opening_the_transport() {
        for (_, client_handler) in wrapper_handlers(false) {
            let connector = ProxyConnectorImpl {
                retry_transport: false,
                plugin_quic: None,
                location: NetLocation::from_str("localhost:443", None).unwrap(),
                client_handler,

                native_udp: None,
            };
            assert_pool_forwarding(&connector).await;
        }
    }

    #[tokio::test]
    async fn every_wrapper_wraps_the_transport_on_pool_misses() {
        for udp in [false, true] {
            for (name, handler) in wrapper_handlers(true) {
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    let (client, mut peer) = tokio::io::duplex(4096);
                    let transport = ClientTransport {
                        reopen: None,
                        route: Arc::new(UnopenedDialer(RouteKey(vec![1]))),
                        open: Box::pin(async { Ok(Box::new(client) as Box<dyn AsyncStream>) }),
                    };
                    let target = NetLocation::from_str("example.com:443", None)
                        .unwrap()
                        .into();
                    let connect = async {
                        if udp {
                            let _ = handler.connect_client_udp(transport, target).await;
                        } else {
                            let _ = handler.connect_client_tcp(transport, target).await;
                        }
                    };
                    let inspect = async {
                        let mut prefix = [0; 4];
                        peer.read_exact(&mut prefix).await.unwrap();
                        match name {
                            "websocket" => assert_eq!(&prefix, b"GET "),
                            _ => assert_eq!(&prefix[..2], &[0x16, 0x03]),
                        }
                        // Closing the peer ends handshakes after their first flight.
                        drop(peer);
                    };
                    tokio::join!(connect, inspect);
                })
                .await
                .unwrap_or_else(|_| panic!("wrapper did not emit bytes: {name}, udp={udp}"));
            }
        }
    }

    #[derive(Debug)]
    struct OneTransport {
        stream: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
        connects: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl crate::tcp::socket_connector::SocketConnector for OneTransport {
        async fn connect(
            &self,
            _: &Arc<dyn Resolver>,
            _: &ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncStream>> {
            self.connects
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Box::new(self.stream.lock().unwrap().take().ok_or_else(
                || std::io::Error::other("unexpected redundant dial"),
            )?))
        }
        async fn connect_udp_bidirectional(
            &self,
            _: &Arc<dyn Resolver>,
            _: ResolvedLocation,
        ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
            unreachable!()
        }
        fn bind_interface(&self) -> Option<&str> {
            None
        }
    }

    #[tokio::test]
    async fn warm_naive_streams_share_one_socket_and_tls_handshake() {
        check_warm_naive_reuse().await;
    }

    async fn check_warm_naive_reuse() {
        use crate::client_proxy_chain::{ClientProxyChain, InitialHopEntry};
        use crate::naiveproxy::NaiveProxyTcpClientHandler;
        use crate::tls_client_handler::TlsClientHandler;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let server_config =
            rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                        .into(),
                )
                .unwrap();
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(aerobox_crypto::shared_provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let (client, peer) = tokio::io::duplex(4096);
        let peer = tokio::spawn(async move {
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(peer)
                .await
                .unwrap();
            let mut h2 = h2::server::handshake(tls).await.unwrap();
            let mut echoes = tokio::task::JoinSet::new();
            while let Some(request) = h2.accept().await {
                let (request, mut respond) = request.unwrap();
                assert_eq!(
                    request.uri().authority().unwrap().as_str(),
                    "example.com:443"
                );
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                echoes.spawn(async move {
                    let mut receive = request.into_body();
                    let mut payload = Vec::new();
                    while let Some(data) = receive.data().await {
                        let data = data.unwrap();
                        receive.flow_control().release_capacity(data.len()).unwrap();
                        payload.extend_from_slice(&data);
                    }
                    send.send_data(payload.into(), true).unwrap();
                });
            }
        });
        let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let proxy = ProxyConnectorImpl {
            retry_transport: false,
            plugin_quic: None,

            native_udp: None,
            location: NetLocation::from_str("localhost:443", None).unwrap(),
            client_handler: Box::new(TlsClientHandler::new(
                client_config,
                None,
                "localhost".try_into().unwrap(),
                Box::new(NaiveProxyTcpClientHandler::new("user", "pass", false)),
            )),
        };
        let entries = vec![InitialHopEntry::Proxy {
            socket: Arc::new(OneTransport {
                stream: std::sync::Mutex::new(Some(client)),
                connects: connects.clone(),
            }),
            proxy: Box::new(proxy),
        }];
        let chain = ClientProxyChain::new(entries, vec![]);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for payload in [b"cold request".as_slice(), b"warm request"] {
                let target = NetLocation::from_str("example.com:443", None)
                    .unwrap()
                    .into();
                let mut stream = chain
                    .connect_tcp(target, &mock_resolver())
                    .await
                    .unwrap()
                    .client_stream;
                stream.write_all(payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, payload);
            }
        })
        .await
        .unwrap();
        assert_eq!(connects.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(chain);
        peer.abort();
        let _ = peer.await;
    }

    #[test]
    fn malformed_protocol_settings_return_errors_without_validation() {
        for protocol in [
            serde_json::json!({"type": "reality", "public_key": "invalid", "sni_hostname": "example.com", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "anytls", "password": "test", "padding_scheme": ["stop=invalid"]}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname": "127.0.0.1", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname": "::1", "protocol": {"type": "socks"}}),
            serde_json::json!({"type": "reality", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sni_hostname": "example.com", "protocol": {"type": "direct"}}),
            serde_json::json!({"type": "tls", "protocol": {"type": "direct"}}),
            serde_json::json!({"type": "websocket", "protocol": {"type": "direct"}}),
        ] {
            let config = crate::config::test_support::from_json(serde_json::json!({
                "address": "127.0.0.1:443", "protocol": protocol
            }))
            .unwrap();
            assert!(ProxyConnectorImpl::from_config(config, mock_resolver()).is_err());
        }
    }

    #[test]
    fn test_from_direct_config_returns_none() {
        let config = ResolvedClientConfig::default();
        assert!(config.protocol.is_direct());
        assert!(
            ProxyConnectorImpl::from_config(config, mock_resolver())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_from_proxy_config_returns_some() {
        let config = ResolvedClientConfig {
            address: NetLocation::from_ip_addr(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1080),
            protocol: ResolvedClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };
        let connector = ProxyConnectorImpl::from_config(config, mock_resolver()).unwrap();
        assert!(connector.is_some());
        let connector = connector.unwrap();
        assert_eq!(connector.proxy_location().port(), 1080);
    }
}
