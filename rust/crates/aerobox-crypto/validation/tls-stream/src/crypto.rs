#[path = "../../../../../vendor/shoes/src/crypto/crypto_handshake.rs"]
mod crypto_handshake;
#[path = "../../../../../vendor/shoes/src/crypto/crypto_tls_stream.rs"]
mod crypto_tls_stream;
#[path = "../../../../../vendor/shoes/src/crypto/tls_connection.rs"]
mod tls_connection;
#[path = "../../../../../vendor/shoes/src/crypto/tls_deframer.rs"]
mod tls_deframer;
#[path = "../../../../../vendor/shoes/src/crypto/tls_reader_writer.rs"]
mod tls_reader_writer;
pub use crypto_tls_stream::{CryptoTlsStream, TlsReadMode};
pub use tls_connection::TlsConnection;
pub fn handshaking<IO: crate::async_stream::AsyncStream>(stream: &CryptoTlsStream<IO>) -> bool {
    stream.session.is_handshaking()
}
