//! Compile the actual HTTP/2 session/stream sources without the unrelated protocol engine.
//! The adapters below supply only address types, the stream trait, and task spawning.
#![allow(dead_code, private_interfaces)]
use std::io;

#[path = "../../../vendor/shoes/src/http2/client.rs"]
pub mod client;
#[path = "../../../vendor/shoes/src/naiveproxy/options.rs"]
pub mod header_options;
pub use header_options as options;
#[path = "../../../vendor/shoes/src/naiveproxy/h2_multi_stream.rs"]
pub mod h2_multi_stream;
#[path = "../../../vendor/shoes/src/naiveproxy/naive_client_session.rs"]
pub mod naive_client_session;
#[path = "../../../vendor/shoes/src/naiveproxy/naive_padding_stream.rs"]
pub mod naive_padding_stream;
#[path = "../../../vendor/shoes/src/naiveproxy/request.rs"]
pub mod request;
#[path = "../../../vendor/shoes/src/stream_transport/mod.rs"]
pub mod stream_transport;
#[path = "../../../vendor/shoes/src/websocket/early_data.rs"]
mod websocket_options;
pub mod naiveproxy {
    pub use crate::{
        h2_multi_stream, header_options as options, naive_client_session, naive_padding_stream,
        request,
    };
}
mod uot {
    pub const UOT_V1_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";
    pub const UOT_V2_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
}
#[path = "../../../vendor/shoes/src/http2/stream.rs"]
pub mod stream;
#[path = "../../../vendor/shoes/src/http2/transport.rs"]
pub mod transport;

pub mod http2 {
    pub use crate::{client, stream, transport};
}
const STREAM_WINDOW: u32 = 256 * 1024;
const CONNECTION_WINDOW: u32 = 2 * 1024 * 1024;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
mod util {
    pub fn allocate_vec(size: usize) -> Vec<u8> {
        vec![0; size]
    }
    pub const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
}
mod network_tasks {
    pub fn spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::spawn(future)
    }
}
pub mod address {
    use std::{
        fmt,
        net::{Ipv4Addr, Ipv6Addr},
    };
    pub enum Address {
        Ipv4(Ipv4Addr),
        Ipv6(Ipv6Addr),
        Hostname(String),
    }
    impl fmt::Display for Address {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Ipv4(ip) => ip.fmt(f),
                Self::Ipv6(ip) => ip.fmt(f),
                Self::Hostname(host) => host.fmt(f),
            }
        }
    }
    pub struct ResolvedLocation(NetLocation);
    impl From<NetLocation> for ResolvedLocation {
        fn from(value: NetLocation) -> Self {
            Self(value)
        }
    }
    pub struct NetLocation(Address, u16);
    impl fmt::Display for NetLocation {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}", self.0, self.1)
        }
    }
    impl NetLocation {
        pub fn new(address: Address, port: u16) -> Self {
            Self(address, port)
        }
        pub fn address(&self) -> &Address {
            &self.0
        }
        pub fn port(&self) -> u16 {
            self.1
        }
    }
}
pub mod async_stream {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    pub trait AsyncPing {
        fn supports_ping(&self) -> bool;
        fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>>;
    }
    pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send + Sync {
        fn peer_addr(&self) -> Option<std::net::SocketAddr> { None }
        fn tcp_socket_control(
            &self,
        ) -> io::Result<Option<crate::tcp::socket_control::TcpSocketControl>> {
            Ok(None)
        }
    }
    impl<T: AsyncPing + Unpin + ?Sized> AsyncPing for Box<T> {
        fn supports_ping(&self) -> bool {
            (**self).supports_ping()
        }
        fn poll_write_ping(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<bool>> {
            Pin::new(&mut **self).poll_write_ping(cx)
        }
    }
    pub trait AsyncMessageStream: Send {}
    impl AsyncPing for tokio::io::DuplexStream {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }
    impl AsyncStream for tokio::io::DuplexStream {}
}

pub async fn open(
    io: tokio::io::DuplexStream,
    timeouts: Option<(std::time::Duration, std::time::Duration)>,
) -> io::Result<(client::H2ClientSession, Box<dyn async_stream::AsyncStream>)> {
    let session = if let Some((idle, ping)) = timeouts {
        client::H2ClientSession::new_transport(Box::new(io), idle, ping).await?
    } else {
        client::H2ClientSession::new(Box::new(io)).await?
    };
    let request = http::Request::builder()
        .method("PUT")
        .uri("https://peer.example/tunnel")
        .body(())
        .unwrap();
    let stream = session.reserve().open_late(request, false).await?;
    Ok((session, Box::new(stream)))
}

mod config {
    pub mod quic_client {
        #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
        pub enum CongestionControl {
            #[default]
            Cubic,
        }
    }
}
// Duration decoding is tested by the real App/config path. This harness only uses
// None defaults, so reject any duration input instead of supplying another parser.
mod dial_options {
    #[derive(Clone, Copy, Debug)]
    pub struct DialDuration(pub std::time::Duration);
    impl serde::Serialize for DialDuration {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&format!("{}ns", self.0.as_nanos()))
        }
    }
    impl<'de> serde::Deserialize<'de> for DialDuration {
        fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
            Err(serde::de::Error::custom(
                "duration decoding is outside this IO harness",
            ))
        }
    }
}
mod resolver {
    pub trait Resolver: Send + Sync {}
}
mod tcp {
    pub mod socket_control {
        pub struct TcpSocketControl;
    }
    pub mod tcp_handler {
        use crate::{
            address::ResolvedLocation,
            async_stream::{AsyncMessageStream, AsyncStream},
        };
        use std::{io, sync::Arc};
        pub struct ClientTransport<'a>(std::marker::PhantomData<&'a ()>);
        impl<'a> ClientTransport<'a> {
            pub fn wrap<F, R>(self, _: F) -> Self
            where
                F: FnOnce(Box<dyn AsyncStream>) -> R,
            {
                // Tests call setup_client_tcp_stream with the real in-memory carrier.
                unimplemented!("outbound dialing is outside this IO harness")
            }
        }
        pub struct TcpClientSetupResult {
            pub stream: Box<dyn AsyncStream>,
        }
        #[async_trait::async_trait]
        pub trait TcpClientHandler: std::fmt::Debug + Send + Sync {
            fn has_session_pool(&self) -> bool {
                false
            }
            fn supports_udp_over_tcp(&self) -> bool {
                false
            }
            async fn prepare_target(
                &self,
                target: ResolvedLocation,
                _: &Arc<dyn crate::resolver::Resolver>,
            ) -> io::Result<ResolvedLocation> {
                Ok(target)
            }
            async fn connect_client_tcp(
                &self,
                _: ClientTransport<'_>,
                _: ResolvedLocation,
            ) -> io::Result<TcpClientSetupResult> {
                Err(io::ErrorKind::Unsupported.into())
            }
            async fn connect_client_udp(
                &self,
                _: ClientTransport<'_>,
                _: ResolvedLocation,
            ) -> io::Result<Box<dyn AsyncMessageStream>> {
                Err(io::ErrorKind::Unsupported.into())
            }
            async fn setup_client_tcp_stream(
                &self,
                stream: Box<dyn AsyncStream>,
                _: ResolvedLocation,
            ) -> io::Result<TcpClientSetupResult> {
                Ok(TcpClientSetupResult { stream })
            }
            async fn setup_client_udp_bidirectional(
                &self,
                _: Box<dyn AsyncStream>,
                _: ResolvedLocation,
            ) -> io::Result<Box<dyn AsyncMessageStream>> {
                Err(io::ErrorKind::Unsupported.into())
            }
        }
    }
}
#[derive(Debug)]
struct Payload;
#[async_trait::async_trait]
impl tcp::tcp_handler::TcpClientHandler for Payload {}

pub async fn wrap_transport(
    config: serde_json::Value,
    io: tokio::io::DuplexStream,
) -> io::Result<Box<dyn async_stream::AsyncStream>> {
    use tcp::tcp_handler::TcpClientHandler;
    let config: stream_transport::Config<()> =
        serde_json::from_value(config).map_err(io::Error::other)?;
    let handler =
        stream_transport::Handler::new(config, "origin.example:443".into(), Box::new(Payload))?;
    Ok(handler
        .setup_client_tcp_stream(
            Box::new(io),
            address::NetLocation::new(address::Address::Hostname("target.example".into()), 443)
                .into(),
        )
        .await?
        .stream)
}

pub fn validate_websocket_headers(headers: serde_json::Value, early_data: bool) -> io::Result<()> {
    let headers = serde_json::from_value(headers).map_err(io::Error::other)?;
    websocket_options::validate_client_early_data(
        Some("/ws"),
        Some(&headers),
        if early_data { 1024 } else { 0 },
        if early_data {
            Some("Sec-WebSocket-Protocol")
        } else {
            None
        },
    )
}
