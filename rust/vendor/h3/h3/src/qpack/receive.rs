//! Bounded dynamic QPACK decoding shared by the driver and response streams.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::task::AtomicWaker;

use super::{
    decoder::Decoder,
    prefix_int,
    stream::{HeaderAck, StreamCancel},
    Decoded, DecoderError,
};
use crate::error::{
    internal_error::{ErrorOrigin, InternalConnectionError},
    Code,
};

const MAX_FEEDBACK: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct Receiver {
    state: Mutex<State>,
    driver: AtomicWaker,
    max_instruction: usize,
    max_blocked: usize,
}

#[derive(Debug)]
struct State {
    decoder: Decoder,
    input: BytesMut,
    feedback: BytesMut,
    blocked: HashMap<u64, (usize, Waker)>,
    error: Option<InternalConnectionError>,
    connection_error: Option<ErrorOrigin>,
}

impl State {
    fn feedback(&mut self, bytes: &[u8]) -> Result<(), InternalConnectionError> {
        if self.feedback.len() + bytes.len() > MAX_FEEDBACK {
            let error = InternalConnectionError::new(
                Code::H3_EXCESSIVE_LOAD,
                "peer is not consuming QPACK decoder instructions".into(),
            );
            self.error = Some(error.clone());
            return Err(error);
        }
        self.feedback.extend_from_slice(bytes);
        Ok(())
    }
}

impl Receiver {
    pub(crate) fn new(capacity: u32, blocked: u16) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                decoder: Decoder::new(capacity as usize),
                input: BytesMut::new(),
                feedback: BytesMut::new(),
                blocked: HashMap::new(),
                error: None,
                connection_error: None,
            }),
            driver: AtomicWaker::new(),
            // Huffman can use up to 30 bits per input byte. No valid insertion
            // can be larger than this bound for the advertised table capacity.
            max_instruction: (capacity as usize).saturating_mul(4).saturating_add(64),
            max_blocked: blocked as usize,
        })
    }

    pub(crate) fn receive(&self, data: &mut impl Buf) -> Result<(), InternalConnectionError> {
        let mut state = self.state.lock().unwrap();
        while data.has_remaining() {
            let count = data
                .remaining()
                .min(4096)
                .min(self.max_instruction - state.input.len());
            if count == 0 {
                return Err(InternalConnectionError::new(
                    Code::QPACK_ENCODER_STREAM_ERROR,
                    "QPACK instruction exceeds table capacity".into(),
                ));
            }
            state.input.extend_from_slice(&data.copy_to_bytes(count));
            let State { decoder, input, .. } = &mut *state;
            // Locate complete instructions without allocating or Huffman
            // decoding an incomplete name repeatedly on each network fragment.
            let complete = complete_instructions(input, self.max_instruction)?;
            let mut cursor = &input[..complete];
            let mut feedback = Vec::new();
            decoder
                .on_encoder_recv(&mut cursor, &mut feedback)
                .map_err(|error| {
                    InternalConnectionError::new(
                        Code::QPACK_ENCODER_STREAM_ERROR,
                        error.to_string(),
                    )
                })?;
            debug_assert!(cursor.is_empty());
            input.advance(complete);
            state.feedback(&feedback)?;
        }
        let total = state.decoder.total_inserted();
        let ready: Vec<_> = state
            .blocked
            .iter()
            .filter(|(_, (required, _))| *required <= total)
            .map(|(id, _)| *id)
            .collect();
        let wakers: Vec<_> = ready
            .into_iter()
            .map(|id| state.blocked.remove(&id).unwrap().1)
            .collect();
        drop(state);
        for waker in wakers {
            waker.wake();
        }
        self.driver.wake();
        Ok(())
    }

    pub(crate) fn feedback(
        &self,
        cx: &Context<'_>,
    ) -> Result<Option<Bytes>, InternalConnectionError> {
        self.driver.register(cx.waker());
        let mut state = self.state.lock().unwrap();
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        Ok((!state.feedback.is_empty()).then(|| state.feedback.split().freeze()))
    }

    pub(crate) fn check_error(&self, cx: &Context<'_>) -> Result<(), InternalConnectionError> {
        self.driver.register(cx.waker());
        self.state.lock().unwrap().error.clone().map_or(Ok(()), Err)
    }

    pub(crate) fn fail(&self, error: ErrorOrigin) {
        let mut state = self.state.lock().unwrap();
        state.connection_error.get_or_insert(error);
        let wakers: Vec<_> = state.blocked.drain().map(|(_, (_, waker))| waker).collect();
        drop(state);
        for waker in wakers {
            waker.wake();
        }
    }

    pub(crate) fn guard(self: &Arc<Self>, id: u64) -> ReceiveGuard {
        ReceiveGuard {
            receiver: self.clone(),
            id,
            prefix: None,
            active: true,
        }
    }

    #[cfg(test)]
    pub(crate) fn is_blocked(&self, id: u64) -> bool {
        self.state.lock().unwrap().blocked.contains_key(&id)
    }
}

fn complete_instructions(data: &[u8], limit: usize) -> Result<usize, InternalConnectionError> {
    fn integer(data: &mut &[u8], bits: u8) -> Result<u64, prefix_int::Error> {
        prefix_int::decode(bits, data).map(|(_, value)| value)
    }
    fn string(data: &mut &[u8], bits: u8, limit: usize) -> Result<(), prefix_int::Error> {
        let length = integer(data, bits)?;
        if length > limit as u64 {
            return Err(prefix_int::Error::Overflow);
        }
        if length > data.len() as u64 {
            return Err(prefix_int::Error::UnexpectedEnd);
        }
        data.advance(length as usize);
        Ok(())
    }
    let mut consumed = 0;
    while consumed < data.len() {
        let mut cursor = &data[consumed..];
        let result = match cursor[0] {
            first if first & 0x80 != 0 => {
                integer(&mut cursor, 6).and_then(|_| string(&mut cursor, 7, limit))
            }
            first if first & 0x40 != 0 => {
                string(&mut cursor, 5, limit).and_then(|_| string(&mut cursor, 7, limit))
            }
            _ => integer(&mut cursor, 5).map(|_| ()),
        };
        match result {
            Ok(()) => consumed = data.len() - cursor.len(),
            Err(prefix_int::Error::UnexpectedEnd) => break,
            Err(error) => {
                return Err(InternalConnectionError::new(
                    Code::QPACK_ENCODER_STREAM_ERROR,
                    error.to_string(),
                ))
            }
        }
    }
    Ok(consumed)
}

#[derive(Debug)]
pub(crate) enum DecodeError {
    HeaderTooLong(u64),
    Connection(InternalConnectionError),
    Closed(ErrorOrigin),
}

/// Owned by the receiving half, so dropping a pending read cancels its QPACK
/// references even after the bidirectional stream is split.
pub(crate) struct ReceiveGuard {
    receiver: Arc<Receiver>,
    id: u64,
    // Resolve the wrapping Required Insert Count exactly once per field section.
    prefix: Option<((usize, usize), usize)>,
    active: bool,
}

impl ReceiveGuard {
    pub(crate) fn poll_decode(
        &mut self,
        cx: &Context<'_>,
        encoded: &Bytes,
        limit: u64,
    ) -> Poll<Result<Decoded, DecodeError>> {
        let mut state = self.receiver.state.lock().unwrap();
        if let Some(error) = &state.connection_error {
            return Poll::Ready(Err(DecodeError::Closed(error.clone())));
        }
        if let Some(error) = &state.error {
            return Poll::Ready(Err(DecodeError::Connection(error.clone())));
        }
        let mut fields = encoded.clone();
        let result = (|| {
            let (prefix, offset) = match self.prefix {
                Some(prefix) => prefix,
                None => {
                    let prefix = state.decoder.header_prefix(&mut fields)?;
                    let value = (prefix, encoded.len() - fields.len());
                    self.prefix = Some(value);
                    value
                }
            };
            fields = encoded.slice(offset..);
            state.decoder.decode_fields(&mut fields, prefix, limit)
        })();
        match result {
            Err(DecoderError::MissingRefs(required)) => {
                if !state.blocked.contains_key(&self.id)
                    && state.blocked.len() >= self.receiver.max_blocked
                {
                    return Poll::Ready(Err(DecodeError::Connection(
                        InternalConnectionError::new(
                            Code::QPACK_DECOMPRESSION_FAILED,
                            "QPACK blocked stream limit exceeded".into(),
                        ),
                    )));
                }
                state
                    .blocked
                    .insert(self.id, (required, cx.waker().clone()));
                Poll::Pending
            }
            result => {
                state.blocked.remove(&self.id);
                self.prefix = None;
                let result = match result {
                    Ok(decoded) => {
                        if decoded.dyn_ref {
                            let mut ack = Vec::new();
                            HeaderAck(self.id).encode(&mut ack);
                            state.feedback(&ack).map_err(DecodeError::Connection)?;
                        }
                        Ok(decoded)
                    }
                    Err(DecoderError::HeaderTooLong(size)) => Err(DecodeError::HeaderTooLong(size)),
                    Err(error) => Err(DecodeError::Connection(InternalConnectionError::new(
                        Code::QPACK_DECOMPRESSION_FAILED,
                        error.to_string(),
                    ))),
                };
                drop(state);
                self.receiver.driver.wake();
                Poll::Ready(result)
            }
        }
    }

    pub(crate) fn finish(&mut self) {
        self.active = false;
        self.receiver.state.lock().unwrap().blocked.remove(&self.id);
    }

    pub(crate) fn cancel(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let mut state = self.receiver.state.lock().unwrap();
        state.blocked.remove(&self.id);
        let mut cancel = Vec::new();
        StreamCancel(self.id).encode(&mut cancel);
        let _ = state.feedback(&cancel); // Driver observes a bounded-queue error.
        drop(state);
        self.receiver.driver.wake();
    }
}

impl Drop for ReceiveGuard {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        block::{HeaderPrefix, Indexed, IndexedWithPostBase},
        stream::{DynamicTableSizeUpdate, InsertWithoutNameRef},
    };
    use super::*;
    use futures_util::task::{waker, ArcWake};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Wake(AtomicUsize);
    impl ArcWake for Wake {
        fn wake_by_ref(arc: &Arc<Self>) {
            arc.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn block(required: usize, base: usize, post_base: bool) -> Bytes {
        let mut bytes = Vec::new();
        HeaderPrefix::new(required, base, required, 256).encode(&mut bytes);
        if post_base {
            IndexedWithPostBase(0).encode(&mut bytes);
        } else {
            Indexed::Dynamic(0).encode(&mut bytes);
        }
        Bytes::from(bytes)
    }

    #[test]
    fn fragmented_insert_unblocks_once_acknowledges_and_cancel_releases_slot() {
        let receiver = Receiver::new(256, 1);
        let wake = Arc::new(Wake::default());
        let waker = waker(wake.clone());
        let cx = Context::from_waker(&waker);
        let mut first = receiver.guard(0);
        let encoded = block(1, 0, true);
        assert!(first.poll_decode(&cx, &encoded, 1024).is_pending());
        let mut second = receiver.guard(4);
        assert!(matches!(
            second.poll_decode(&cx, &encoded, 1024),
            Poll::Ready(Err(DecodeError::Connection(_)))
        ));
        first.cancel();
        assert!(second.poll_decode(&cx, &encoded, 1024).is_pending());
        let mut instructions = Vec::new();
        DynamicTableSizeUpdate(128).encode(&mut instructions);
        InsertWithoutNameRef::new("x-test", "value")
            .encode(&mut instructions)
            .unwrap();
        for byte in instructions {
            receiver.receive(&mut &[byte][..]).unwrap();
        }
        assert!(wake.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(Ok(decoded)) = second.poll_decode(&cx, &encoded, 1024) else {
            panic!("not decoded")
        };
        assert_eq!(decoded.fields[0].value.as_ref(), b"value");
        // cancel(0), increment(1), acknowledgement(4)
        assert_eq!(
            receiver.feedback(&cx).unwrap().unwrap().as_ref(),
            &[0x40, 1, 0x84]
        );
        second.finish();
        drop(second);
        assert!(receiver.feedback(&cx).unwrap().is_none());
    }

    #[test]
    fn connection_error_before_or_after_registration_resolves_waiters() {
        for fail_first in [false, true] {
            let receiver = Receiver::new(256, 1);
            let wake = Arc::new(Wake::default());
            let waker = waker(wake.clone());
            let cx = Context::from_waker(&waker);
            let mut guard = receiver.guard(0);
            if !fail_first {
                assert!(guard
                    .poll_decode(&cx, &block(1, 1, false), 1024)
                    .is_pending());
            }
            receiver.fail(
                InternalConnectionError::new(Code::H3_CLOSED_CRITICAL_STREAM, "closed".into())
                    .into(),
            );
            assert!(matches!(
                guard.poll_decode(&cx, &block(1, 1, false), 1024),
                Poll::Ready(Err(DecodeError::Closed(_)))
            ));
            if !fail_first {
                assert_eq!(wake.0.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[test]
    fn rejects_capacity_overflow_zero_capacity_insertion_and_oversized_string_prefix() {
        let mut capacity = Vec::new();
        DynamicTableSizeUpdate(257).encode(&mut capacity);
        assert!(Receiver::new(256, 1).receive(&mut &capacity[..]).is_err());
        let mut insertion = Vec::new();
        InsertWithoutNameRef::new("name", "value")
            .encode(&mut insertion)
            .unwrap();
        assert!(Receiver::new(256, 1).receive(&mut &insertion[..]).is_err());
        let mut oversized = Vec::new();
        prefix_int::encode(5, 2, 100_000, &mut oversized);
        assert!(Receiver::new(256, 1).receive(&mut &oversized[..]).is_err());
    }

    #[test]
    fn feedback_queue_is_bounded_when_peer_never_reads() {
        let receiver = Receiver::new(256, 1);
        let wake = Arc::new(Wake::default());
        let waker = waker(wake.clone());
        let cx = Context::from_waker(&waker);
        // The driver can be backpressured before ever draining feedback.
        receiver.check_error(&cx).unwrap();
        for _ in 0..=MAX_FEEDBACK {
            receiver.guard(0).cancel();
        }
        assert!(wake.0.load(Ordering::SeqCst) > 0);
        assert!(receiver.check_error(&cx).is_err());
        assert!(receiver.feedback(&cx).is_err());
        assert!(receiver.state.lock().unwrap().feedback.len() <= MAX_FEEDBACK);
    }
}
