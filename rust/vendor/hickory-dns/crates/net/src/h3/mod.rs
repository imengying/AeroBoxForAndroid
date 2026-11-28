// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over HTTP/3 (DoH3)

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Buf;
use futures_util::Stream;
use quinn::{TransportConfig, VarInt};

use crate::NetError;

mod h3_client_stream;
pub use h3_client_stream::{H3ClientStream, H3ClientStreamBuilder};
pub mod h3_server;

const ALPN_H3: &[u8] = b"h3";

/// Returns a default endpoint configuration for DNS-over-QUIC
fn transport() -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    transport_config.datagram_receive_buffer_size(None);
    transport_config.datagram_send_buffer_size(0);
    // clients never accept new bidirectional streams
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(3));
    // - SETTINGS
    // - QPACK encoder
    // - QPACK decoder
    // - RESERVED (GREASE)
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(4));

    transport_config
}

/// [`Stream`] adapter for h3 body streaming.
pub struct BodyStream<T>(T);

impl<T, B> Stream for BodyStream<T>
where
    T: FnMut(&mut Context<'_>) -> Poll<Result<Option<B>, h3::error::StreamError>> + Unpin,
    B: Buf,
{
    type Item = Result<B, NetError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let Poll::Ready(result) = (this.0)(cx) else {
            return Poll::Pending;
        };

        Poll::Ready(match result {
            Ok(Some(buf)) => Some(Ok(buf)),
            Ok(None) => None,
            Err(e) => Some(Err(NetError::from(e))),
        })
    }
}

impl<T, B> From<T> for BodyStream<T>
where
    T: FnMut(&mut Context<'_>) -> Poll<Result<Option<B>, h3::error::StreamError>> + Unpin,
    B: Buf,
{
    fn from(stream: T) -> Self {
        Self(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use h3::error::{ConnectionError, StreamError};
    use h3::quic::ConnectionErrorIncoming;

    #[tokio::test]
    async fn body_preserves_typed_connection_close() {
        let mut body = BodyStream::from(|_: &mut Context<'_>| {
            Poll::Ready(Err::<Option<bytes::Bytes>, _>(
                StreamError::ConnectionError(ConnectionError::Remote(
                    ConnectionErrorIncoming::ApplicationClose { error_code: 0x10c },
                )),
            ))
        });
        let error = body.next().await.unwrap().unwrap_err();
        assert!(matches!(&error, NetError::H3(_)), "{error:?}");
        assert!(error.is_connection_closed());
    }
}
