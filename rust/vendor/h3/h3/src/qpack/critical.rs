//! Receive critical QPACK streams with optional dynamic response decoding.
//!
//! The default decoder advertises zero capacity; an enabled dynamic decoder
//! consumes encoder instructions through the bounded shared receiver. Our own
//! encoder remains stateless, so only cancellations are valid on the peer's
//! decoder stream. Always observe FIN/reset on both critical streams.

use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Buf;

use crate::{
    error::{
        internal_error::{ErrorOrigin, InternalConnectionError},
        Code,
    },
    quic::{RecvStream, StreamErrorIncoming},
    stream::BufRecvStream,
};

use super::prefix_int;

pub(crate) struct StatelessStream<S, B> {
    stream: BufRecvStream<S, B>,
    encoder: bool,
    cancellation: [u8; 10],
    cancellation_len: usize,
    decoder: Option<Arc<super::receive::Receiver>>,
}

impl<S: RecvStream, B> StatelessStream<S, B> {
    pub(crate) fn new(stream: BufRecvStream<S, B>, encoder: bool) -> Self {
        Self {
            stream,
            encoder,
            cancellation: [0; 10],
            cancellation_len: 0,
            decoder: None,
        }
    }

    pub(crate) fn with_decoder(
        stream: BufRecvStream<S, B>,
        decoder: Option<Arc<super::receive::Receiver>>,
    ) -> Self {
        Self {
            decoder,
            ..Self::new(stream, true)
        }
    }

    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Result<(), ErrorOrigin> {
        // Do not let an always-readable peer monopolize the connection driver.
        for _ in 0..16 {
            match self.stream.poll_data(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(Ok(Some(mut data))) => {
                    if let Some(decoder) = &self.decoder {
                        decoder.receive(&mut data)?;
                    } else {
                        while data.has_remaining() {
                            self.instruction_byte(data.get_u8())?;
                        }
                    }
                }
                Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error,
                })) => {
                    return Err(connection_error.into());
                }
                Poll::Ready(Ok(None) | Err(_)) => {
                    return Err(InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        "peer closed a QPACK critical stream".into(),
                    )
                    .into());
                }
            }
        }
        cx.waker().wake_by_ref();
        Ok(())
    }

    fn instruction_byte(&mut self, byte: u8) -> Result<(), InternalConnectionError> {
        if self.encoder {
            // Set Dynamic Table Capacity(0). Every insertion or nonzero
            // capacity exceeds the zero capacity advertised in our SETTINGS.
            return if byte == 0x20 {
                Ok(())
            } else {
                Err(self.invalid_instruction())
            };
        }

        // A cancellation is valid even if there are no outstanding references.
        // Section acknowledgements and insert-count increments are invalid:
        // this encoder has never sent an entry or a dynamic reference.
        if self.cancellation_len == 0 && byte & 0xc0 != 0x40 {
            return Err(self.invalid_instruction());
        }
        self.cancellation[self.cancellation_len] = byte;
        self.cancellation_len += 1;
        let mut encoded = &self.cancellation[..self.cancellation_len];
        match prefix_int::decode(6, &mut encoded) {
            Ok((_, stream_id)) if stream_id <= (1u64 << 62) - 1 => {
                self.cancellation_len = 0;
                Ok(())
            }
            Err(prefix_int::Error::UnexpectedEnd)
                if self.cancellation_len < self.cancellation.len() =>
            {
                Ok(())
            }
            _ => Err(self.invalid_instruction()),
        }
    }

    fn invalid_instruction(&self) -> InternalConnectionError {
        InternalConnectionError::new(
            if self.encoder {
                Code::QPACK_ENCODER_STREAM_ERROR
            } else {
                Code::QPACK_DECODER_STREAM_ERROR
            },
            "invalid instruction for stateless QPACK".into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use bytes::Bytes;

    use super::*;

    struct Fragmented {
        chunks: VecDeque<Option<Bytes>>,
    }

    impl RecvStream for Fragmented {
        type Buf = Bytes;
        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
            match self.chunks.pop_front().flatten() {
                Some(bytes) => Poll::Ready(Ok(Some(bytes))),
                None => Poll::Pending,
            }
        }
        fn stop_sending(&mut self, _: u64) {
            unreachable!()
        }
        fn recv_id(&self) -> crate::quic::StreamId {
            3u64.try_into().unwrap()
        }
    }

    #[test]
    fn cancellation_survives_pending_between_each_byte_and_rejects_overflow() {
        let mut encoded = Vec::new();
        prefix_int::encode(6, 1, (1u64 << 62) - 1, &mut encoded);
        encoded.push(0x40); // Followed by a second cancellation.
        let stream = Fragmented {
            chunks: encoded
                .iter()
                .flat_map(|byte| [Some(Bytes::copy_from_slice(&[*byte])), None])
                .collect(),
        };
        let mut receiver: StatelessStream<_, Bytes> =
            StatelessStream::new(BufRecvStream::new(stream), false);
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        for _ in &encoded {
            receiver.poll(&mut cx).unwrap();
        }
        assert_eq!(receiver.cancellation_len, 0);

        let mut overflow = Vec::new();
        prefix_int::encode(6, 1, 1u64 << 62, &mut overflow);
        let stream = Fragmented {
            chunks: [Some(Bytes::from(overflow))].into(),
        };
        let mut receiver: StatelessStream<_, Bytes> =
            StatelessStream::new(BufRecvStream::new(stream), false);
        assert!(
            matches!(receiver.poll(&mut cx), Err(ErrorOrigin::Internal(error)) if error.code == Code::QPACK_DECODER_STREAM_ERROR)
        );
    }
}
