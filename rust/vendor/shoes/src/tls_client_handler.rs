use std::sync::Arc;

use async_trait::async_trait;

use crate::address::ResolvedLocation;
use crate::async_stream::AsyncMessageStream;
use crate::async_stream::AsyncStream;
use crate::crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
use crate::tcp::tcp_handler::{ClientTransport, TcpClientHandler, TcpClientSetupResult};

#[derive(Debug)]
pub struct TlsClientHandler {
    pub client_config: Arc<rustls::ClientConfig>,
    pub tls_buffer_size: Option<usize>,
    pub server_name: rustls::pki_types::ServerName<'static>,
    pub handler: TlsInnerClientHandler,
    fragmentation: crate::tls_fragment::TlsFragmentOptions,
    ech: Option<(Arc<crate::ech::Policy>, Arc<dyn crate::resolver::Resolver>)>,
}

#[derive(Debug)]
pub enum TlsInnerClientHandler {
    Default(Box<dyn TcpClientHandler>),
    VisionVless { uuid: Box<[u8]>, udp_enabled: bool },
}

impl TlsClientHandler {
    fn create_connection(
        &self,
        config: Arc<rustls::ClientConfig>,
    ) -> Result<rustls::ClientConnection, rustls::Error> {
        let mut connection = rustls::ClientConnection::new(config, self.server_name.clone())?;
        if let Some(size) = self.tls_buffer_size {
            // Vision peers require the UUID and first frame header in one TLS record.
            let size = match self.handler {
                TlsInnerClientHandler::VisionVless { .. } => size.max(21),
                TlsInnerClientHandler::Default(_) => size,
            };
            connection.set_buffer_limit(Some(size));
        }
        Ok(connection)
    }

    pub(crate) async fn handshake(
        &self,
        mut stream: Box<dyn AsyncStream>,
        mode: TlsReadMode,
        reopen: Option<crate::tcp::tcp_handler::ReopenTransport<'_>>,
    ) -> std::io::Result<CryptoTlsStream<Box<dyn AsyncStream>>> {
        let mut prepared = match &self.ech {
            Some((policy, resolver)) => Some(policy.prepare(&self.client_config, resolver).await?),
            None => None,
        };
        let original = prepared.as_ref().map(|prepared| prepared.mode.clone());
        for attempt in 0..2 {
            let config = prepared
                .as_ref()
                .map_or_else(|| self.client_config.clone(), |p| p.config.clone());
            let connection = self
                .create_connection(config)
                .map_err(std::io::Error::other)?;
            match CryptoTlsStream::handshake(
                self.fragmentation.wrap(stream)?,
                TlsConnection::new(connection),
                mode,
                &[],
            )
            .await
            {
                Ok(stream) => {
                    if attempt == 1 {
                        if let (Some((policy, _)), Some(previous), Some(prepared)) =
                            (&self.ech, &original, &prepared)
                        {
                            policy.accepted_retry(previous, prepared.mode.clone());
                        }
                    }
                    return Ok(stream);
                }
                Err(error) => {
                    if attempt == 0 {
                        if let (Some(prepared_config), Some(reopen)) = (&prepared, &reopen) {
                            if let Some(mode) = prepared_config.retry.take()? {
                                prepared = Some(crate::ech::Prepared::new(
                                    &self.client_config,
                                    Arc::new(mode),
                                )?);
                                stream = reopen().await?;
                                continue;
                            }
                        }
                    }
                    return Err(error);
                }
            }
        }
        unreachable!()
    }

    async fn wrap_pooled_transport(
        &self,
        stream: Box<dyn AsyncStream>,
        reopen: Option<crate::tcp::tcp_handler::ReopenTransport<'_>>,
    ) -> std::io::Result<CryptoTlsStream<Box<dyn AsyncStream>>> {
        self.handshake(stream, TlsReadMode::Stream, reopen).await
    }

    pub(crate) fn with_ech(
        mut self,
        policy: Option<Arc<crate::ech::Policy>>,
        resolver: Arc<dyn crate::resolver::Resolver>,
    ) -> Self {
        self.ech = policy.map(|policy| (policy, resolver));
        self
    }

    pub fn new(
        client_config: Arc<rustls::ClientConfig>,
        tls_buffer_size: Option<usize>,
        server_name: rustls::pki_types::ServerName<'static>,
        handler: Box<dyn TcpClientHandler>,
    ) -> Self {
        Self {
            client_config,
            tls_buffer_size,
            server_name,
            handler: TlsInnerClientHandler::Default(handler),
            fragmentation: Default::default(),
            ech: None,
        }
    }

    pub fn new_vision_vless(
        client_config: Arc<rustls::ClientConfig>,
        tls_buffer_size: Option<usize>,
        server_name: rustls::pki_types::ServerName<'static>,
        uuid: Box<[u8]>,
        udp_enabled: bool,
    ) -> Self {
        Self {
            client_config,
            tls_buffer_size,
            server_name,
            handler: TlsInnerClientHandler::VisionVless { uuid, udp_enabled },
            fragmentation: Default::default(),
            ech: None,
        }
    }

    pub fn with_fragmentation(mut self, options: crate::tls_fragment::TlsFragmentOptions) -> Self {
        self.fragmentation = options;
        self
    }

    async fn setup_client_stream_common(
        &self,
        client_stream: Box<dyn AsyncStream>,
    ) -> std::io::Result<CryptoTlsStream<Box<dyn AsyncStream>>> {
        let mode = match self.handler {
            TlsInnerClientHandler::VisionVless { .. } => TlsReadMode::PreserveRecords,
            TlsInnerClientHandler::Default(_) => TlsReadMode::Stream,
        };
        self.handshake(client_stream, mode, None).await
    }
    async fn finish_tcp(
        &self,
        tls_stream: CryptoTlsStream<Box<dyn AsyncStream>>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler.validate_alpn(tls_stream.alpn_protocol())?;
                handler
                    .setup_client_tcp_stream(Box::new(tls_stream), remote_location)
                    .await
            }
            TlsInnerClientHandler::VisionVless { uuid, .. } => {
                crate::vless::vless_client_handler::setup_custom_tls_vision_vless_client_stream(
                    tls_stream,
                    uuid,
                    remote_location.location(),
                )
                .await
            }
        }
    }

    async fn finish_udp(
        &self,
        tls_stream: CryptoTlsStream<Box<dyn AsyncStream>>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler
                    .setup_client_udp_bidirectional(Box::new(tls_stream), target)
                    .await
            }
            TlsInnerClientHandler::VisionVless { uuid, .. } => {
                crate::vless::vless_client_handler::setup_vision_vless_udp_bidirectional(
                    tls_stream,
                    uuid,
                    target.into_location(),
                    crate::vless::VisionWriteErrorPolicy::Legacy,
                )
                .await
            }
        }
    }
}

#[async_trait]
impl TcpClientHandler for TlsClientHandler {
    fn has_session_pool(&self) -> bool {
        matches!(&self.handler, TlsInnerClientHandler::Default(handler) if handler.has_session_pool())
    }

    async fn connect_client_tcp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        if let TlsInnerClientHandler::Default(handler) = &self.handler {
            let reopen = transport.reopen.clone();
            let transport = transport.wrap(move |stream| {
                let reopen = reopen.clone();
                async move {
                    let stream = self.wrap_pooled_transport(stream, reopen).await?;
                    handler.validate_alpn(stream.alpn_protocol())?;
                    Ok(stream)
                }
            });
            handler.connect_client_tcp(transport, target).await
        } else {
            let tls_stream = self
                .handshake(
                    transport.open.await?,
                    TlsReadMode::PreserveRecords,
                    transport.reopen,
                )
                .await?;
            self.finish_tcp(tls_stream, target).await
        }
    }

    async fn connect_client_udp(
        &self,
        transport: ClientTransport<'_>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        if let TlsInnerClientHandler::Default(handler) = &self.handler {
            let reopen = transport.reopen.clone();
            let transport =
                transport.wrap(move |stream| self.wrap_pooled_transport(stream, reopen.clone()));
            handler.connect_client_udp(transport, target).await
        } else {
            let tls_stream = self
                .handshake(
                    transport.open.await?,
                    TlsReadMode::PreserveRecords,
                    transport.reopen,
                )
                .await?;
            self.finish_udp(tls_stream, target).await
        }
    }

    async fn prepare_target(
        &self,
        target: ResolvedLocation,
        resolver: &std::sync::Arc<dyn crate::resolver::Resolver>,
    ) -> std::io::Result<ResolvedLocation> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => {
                handler.prepare_target(target, resolver).await
            }
            TlsInnerClientHandler::VisionVless { .. } => Ok(target),
        }
    }

    async fn try_reuse_tcp_stream(
        &self,
        target: &ResolvedLocation,
    ) -> std::io::Result<Option<TcpClientSetupResult>> {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => handler.try_reuse_tcp_stream(target).await,
            TlsInnerClientHandler::VisionVless { .. } => Ok(None),
        }
    }

    async fn setup_client_tcp_stream(
        &self,
        client_stream: Box<dyn AsyncStream>,
        remote_location: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        let tls_stream = self.setup_client_stream_common(client_stream).await?;

        self.finish_tcp(tls_stream, remote_location).await
    }

    fn supports_udp_over_tcp(&self) -> bool {
        match &self.handler {
            TlsInnerClientHandler::Default(handler) => handler.supports_udp_over_tcp(),
            TlsInnerClientHandler::VisionVless { udp_enabled, .. } => *udp_enabled, // VLESS supports XUDP when enabled
        }
    }

    async fn setup_client_udp_bidirectional(
        &self,
        client_stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        let tls_stream = self.setup_client_stream_common(client_stream).await?;

        self.finish_udp(tls_stream, target).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    enum IdentityPath {
        Tcp,
        Udp,
    }

    #[tokio::test]
    async fn verification_uses_hop_identity_even_without_wire_sni() {
        check_hop_identity(IdentityPath::Tcp).await;
    }

    #[tokio::test]
    async fn udp_verification_uses_hop_identity_even_without_wire_sni() {
        check_hop_identity(IdentityPath::Udp).await;
    }

    async fn check_hop_identity(path: IdentityPath) {
        use crate::address::NetLocation;
        use crate::async_stream::{AsyncFlushMessage, AsyncReadMessage, AsyncWriteMessage};
        use crate::tcp::tcp_client_handler_factory::create_tcp_client_handler;
        use std::future::poll_fn;
        use std::pin::Pin;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Debug)]
        struct CaptureName {
            inner: Arc<dyn rustls::server::ResolvesServerCert>,
            names: Arc<std::sync::Mutex<Vec<Option<String>>>>,
        }
        impl rustls::server::ResolvesServerCert for CaptureName {
            fn resolve(
                &self,
                hello: rustls::server::ClientHello<'_>,
            ) -> Option<Arc<rustls::sign::CertifiedKey>> {
                self.names
                    .lock()
                    .unwrap()
                    .push(hello.server_name().map(str::to_owned));
                self.inner.resolve(hello)
            }
        }

        let udp = matches!(path, IdentityPath::Udp);

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for nested in [false, true] {
                for (hop, sni, expected, wire_sni) in [
                    (
                        "localhost:443",
                        "",
                        "localhost",
                        if nested { None } else { Some("localhost") },
                    ),
                    ("localhost:443", "sni_hostname: null", "localhost", None),
                    (
                        "localhost.:443",
                        "",
                        "localhost",
                        if nested { None } else { Some("localhost") },
                    ),
                    ("localhost.:443", "sni_hostname: null", "localhost", None),
                    ("127.0.0.1:443", "", "127.0.0.1", None),
                    ("127.0.0.1:443", "sni_hostname: null", "127.0.0.1", None),
                    ("[::1]:443", "sni_hostname: null", "::1", None),
                    (
                        "localhost:443",
                        "sni_hostname: override.test",
                        "override.test",
                        Some("override.test"),
                    ),
                    (
                        "127.0.0.1:443",
                        "sni_hostname: override.test",
                        "override.test",
                        Some("override.test"),
                    ),
                    (
                        "127.0.0.1:443",
                        "sni_hostname: override.test.",
                        "override.test",
                        Some("override.test"),
                    ),
                ] {
                    for correct in [true, false] {
                        let certificate_name = if correct { expected } else { "wrong.test" };
                        let cert = rcgen::generate_simple_self_signed(vec![
                            certificate_name.into(),
                            "outer.test".into(),
                        ])
                        .unwrap();
                        let mut roots = rustls::RootCertStore::empty();
                        roots.add(cert.cert.der().clone()).unwrap();
                        let mut server = rustls::ServerConfig::builder_with_provider(aerobox_crypto::shared_provider()).with_safe_default_protocol_versions().unwrap()
                            .with_no_client_auth()
                            .with_single_cert(
                                vec![cert.cert.der().clone()],
                                rustls::pki_types::PrivatePkcs8KeyDer::from(
                                    cert.signing_key.serialize_der(),
                                )
                                .into(),
                            )
                            .unwrap();
                        let names = Arc::new(std::sync::Mutex::new(Vec::new()));
                        server.cert_resolver = Arc::new(CaptureName {
                            inner: server.cert_resolver,
                            names: names.clone(),
                        });
                        let hop = NetLocation::from_str(hop, None).unwrap();
                        let protocol = if udp {
                            "{type: vless, user_id: '00000000-0000-4000-8000-000000000000', udp_enabled: true}"
                        } else {
                            "{type: noop}"
                        };
                        let yaml = format!("type: tls\nverify: true\ntls_buffer_size: 1024\n{sni}\nprotocol: {protocol}");
                        let yaml = if nested {
                            format!(
                                "type: tls\nverify: true\nsni_hostname: outer.test\nprotocol:\n{}",
                                yaml.lines()
                                    .map(|line| format!("  {line}\n"))
                                    .collect::<String>()
                            )
                        } else {
                            yaml
                        };
                        let handler = crate::rustls_config_util::with_test_roots(roots, || {
                            let resolver = Arc::new(crate::resolver::NativeResolver::new());
                            create_tcp_client_handler(
                                crate::config::test_support::from_yaml(&yaml).unwrap(),
                                &hop,
                                resolver,
                            ).unwrap()
                        });
                        let (io, peer) = tokio::io::duplex(65536);
                        let server_task = tokio::spawn(async move {
                            let server = Arc::new(server);
                            let mut stream: Box<dyn AsyncStream> = Box::new(peer);
                            for _ in 0..if nested { 2 } else { 1 } {
                                let conn = TlsConnection::new(
                                    rustls::ServerConnection::new(server.clone()).unwrap(),
                                );
                                let Ok(tls) = CryptoTlsStream::handshake(
                                    stream,
                                    conn,
                                    TlsReadMode::Stream,
                                    &[],
                                )
                                .await
                                else {
                                    return false;
                                };
                                stream = Box::new(tls);
                            }
                            if udp {
                                let mut request = [0; 29];
                                stream.read_exact(&mut request).await.unwrap();
                                assert_eq!(
                                    &request[..18],
                                    &[0, 0, 0, 0, 0, 0, 0, 64, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0],
                                );
                                assert_eq!(&request[18..], &[2, 0, 53, 1, 192, 0, 2, 1, 0, 1, 42]);
                                stream.write_all(&[0, 0, 0, 1, 43]).await.unwrap();
                                stream.flush().await.unwrap();
                            } else {
                                let mut byte = [0];
                                stream.read_exact(&mut byte).await.unwrap();
                                assert_eq!(byte, [42]);
                            }
                            true
                        });
                        if udp {
                            let result = handler
                                .setup_client_udp_bidirectional(
                                    Box::new(io),
                                    NetLocation::from_str("192.0.2.1:53", None).unwrap().into(),
                                )
                                .await;
                            assert_eq!(result.is_ok(), correct, "hop {hop}, SNI {sni:?}");
                            if let Ok(mut stream) = result {
                                poll_fn(|cx| Pin::new(&mut stream).poll_write_message(cx, &[42]))
                                    .await
                                    .unwrap();
                                poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
                                    .await
                                    .unwrap();
                                let mut response = [0; 1];
                                let mut response = tokio::io::ReadBuf::new(&mut response);
                                poll_fn(|cx| Pin::new(&mut stream).poll_read_message(cx, &mut response))
                                    .await
                                    .unwrap();
                                assert_eq!(response.filled(), &[43]);
                            }
                            assert_eq!(server_task.await.unwrap(), correct);
                        } else {
                            let result = handler
                                .setup_client_tcp_stream(
                                    Box::new(io),
                                    NetLocation::from_str("not-the-certificate.test:80", None)
                                        .unwrap()
                                        .into(),
                                )
                                .await;
                            assert_eq!(result.is_ok(), correct, "hop {hop}, SNI {sni:?}");
                            let mut result = result.ok();
                            if let Some(result) = &mut result {
                                result.client_stream.write_all(&[42]).await.unwrap();
                                result.client_stream.flush().await.unwrap();
                            }
                            assert_eq!(server_task.await.unwrap(), correct);
                        }
                        let mut expected_names = Vec::new();
                        if nested {
                            expected_names.push(Some("outer.test".to_owned()));
                        }
                        expected_names.push(wire_sni.map(str::to_owned));
                        assert_eq!(*names.lock().unwrap(), expected_names);
                    }
                }
            }
        })
        .await
        .unwrap();
    }

    #[derive(Debug)]
    struct RejectReuse;

    #[async_trait]
    impl TcpClientHandler for RejectReuse {
        async fn prepare_target(
            &self,
            _: ResolvedLocation,
            _: &Arc<dyn crate::resolver::Resolver>,
        ) -> std::io::Result<ResolvedLocation> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "target rejected",
            ))
        }

        async fn try_reuse_tcp_stream(
            &self,
            _: &ResolvedLocation,
        ) -> std::io::Result<Option<TcpClientSetupResult>> {
            Err(std::io::Error::other("CONNECT rejected"))
        }
        async fn setup_client_tcp_stream(
            &self,
            _: Box<dyn AsyncStream>,
            _: ResolvedLocation,
        ) -> std::io::Result<TcpClientSetupResult> {
            panic!("reuse must not acquire a new transport")
        }
    }

    #[tokio::test]
    async fn only_default_tls_and_reality_handlers_forward_reuse() {
        use crate::reality::RealityClientHandler;
        let config = Arc::new(
            rustls::ClientConfig::builder_with_provider(aerobox_crypto::shared_provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        let target = crate::address::NetLocation::from_str("example.com:443", None)
            .unwrap()
            .into();
        let defaults: Vec<Box<dyn TcpClientHandler>> = vec![
            Box::new(TlsClientHandler::new(
                config.clone(),
                None,
                "localhost".try_into().unwrap(),
                Box::new(RejectReuse),
            )),
            Box::new(RealityClientHandler::new(
                [0; 32],
                [0; 8],
                "localhost".try_into().unwrap(),
                vec![],
                Box::new(RejectReuse),
            )),
        ];
        let resolver: Arc<dyn crate::resolver::Resolver> =
            Arc::new(crate::resolver::NativeResolver::new());
        for handler in &defaults {
            assert_eq!(
                handler
                    .try_reuse_tcp_stream(&target)
                    .await
                    .err()
                    .unwrap()
                    .to_string(),
                "CONNECT rejected"
            );
        }
        let wrappers: Vec<Box<dyn TcpClientHandler>> = vec![
            Box::new(crate::websocket::WebsocketTcpClientHandler::new(
                "localhost:443".into(),
                None,
                None,
                Default::default(),
                Box::new(RejectReuse),
            )),
        ];
        for handler in defaults.into_iter().chain(wrappers) {
            assert_eq!(
                handler
                    .prepare_target(target.clone(), &resolver)
                    .await
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        let vision: Vec<Box<dyn TcpClientHandler>> = vec![
            Box::new(TlsClientHandler::new_vision_vless(
                config,
                None,
                "localhost".try_into().unwrap(),
                Box::new([0; 16]),
                false,
            )),
            Box::new(RealityClientHandler::new_vision_vless(
                [0; 32],
                [0; 8],
                "localhost".try_into().unwrap(),
                vec![],
                Box::new([0; 16]),
                false,
            )),
        ];
        for handler in vision {
            assert!(!handler.has_session_pool());
            assert_eq!(
                handler
                    .prepare_target(target.clone(), &resolver)
                    .await
                    .unwrap()
                    .location(),
                target.location()
            );
            assert!(
                handler
                    .try_reuse_tcp_stream(&target)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
