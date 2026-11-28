//! Test-only bridge to the actual production asynchronous TLS implementation.
#![allow(dead_code)]
mod crypto;
mod fixture;
#[path = "../../../../../vendor/shoes/src/sync_adapter.rs"]
mod sync_adapter;
pub use crypto::{CryptoTlsStream, TlsConnection, TlsReadMode};
pub use fixture::config;
pub mod tcp {
    pub mod socket_control {
        pub struct TcpSocketControl;
    }
}
// Only the carrier trait surface is scaffolding. TLS I/O, framing, buffering,
// key transitions and wakeup logic come from the production modules.
pub mod async_stream {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite};
    pub trait AsyncPing {
        fn supports_ping(&self) -> bool;
        fn poll_write_ping(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>>;
    }
    pub trait AsyncStream: AsyncRead + AsyncWrite + AsyncPing + Unpin + Send + Sync {
        fn tcp_socket_control(
            &self,
        ) -> std::io::Result<Option<crate::tcp::socket_control::TcpSocketControl>> {
            Ok(None)
        }
        fn local_addr(&self) -> Option<std::net::SocketAddr> {
            None
        }
        fn peer_addr(&self) -> Option<std::net::SocketAddr> {
            None
        }
        fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
            None
        }
    }
    impl AsyncPing for tokio::net::TcpStream {
        fn supports_ping(&self) -> bool {
            false
        }
        fn poll_write_ping(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<std::io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }
    impl AsyncStream for tokio::net::TcpStream {}
}
pub use crypto::handshaking;
