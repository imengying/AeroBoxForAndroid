use super::*;

use indexmap::{self, IndexMap};

use std::convert::Infallible;
use std::fmt;
use std::marker::PhantomData;
use std::ops;

/// Storage for streams
#[derive(Debug)]
pub(super) struct Store {
    slab: slab::Slab<Stream>,
    ids: IndexMap<StreamId, SlabIndex>,
    chromium_flush_pending: bool,
}

/// "Pointer" to an entry in the store
pub(super) struct Ptr<'a> {
    key: Key,
    store: &'a mut Store,
}

/// References an entry in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Key {
    index: SlabIndex,
    /// Keep the stream ID in the key as an ABA guard, since slab indices
    /// could be re-used with a new stream.
    stream_id: StreamId,
}

// We can never have more than `StreamId::MAX` streams in the store,
// so we can save a smaller index (u32 vs usize).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlabIndex(u32);

pub(super) struct Queue<N> {
    indices: Option<store::Indices>,
    _p: PhantomData<N>,
}

pub(super) trait Next {
    fn next(stream: &Stream) -> Option<Key>;

    fn set_next(stream: &mut Stream, key: Option<Key>);

    fn take_next(stream: &mut Stream) -> Option<Key>;

    fn is_queued(stream: &Stream) -> bool;

    fn set_queued(stream: &mut Stream, val: bool);
}

/// A linked list
#[derive(Debug, Clone, Copy)]
struct Indices {
    pub head: Key,
    pub tail: Key,
}

pub(super) enum Entry<'a> {
    Occupied(OccupiedEntry<'a>),
    Vacant(VacantEntry<'a>),
}

pub(super) struct OccupiedEntry<'a> {
    ids: indexmap::map::OccupiedEntry<'a, StreamId, SlabIndex>,
}

pub(super) struct VacantEntry<'a> {
    ids: indexmap::map::VacantEntry<'a, StreamId, SlabIndex>,
    slab: &'a mut slab::Slab<Stream>,
}

pub(super) trait Resolve {
    fn resolve(&mut self, key: Key) -> Ptr<'_>;
}

// ===== impl Store =====

impl Store {
    pub fn new() -> Self {
        Store {
            slab: slab::Slab::new(),
            ids: IndexMap::new(),
            chromium_flush_pending: false,
        }
    }

    pub(crate) fn mark_chromium_flush_pending(&mut self) {
        self.chromium_flush_pending = true;
    }

    pub(crate) fn complete_chromium_flush(&mut self, counts: &mut Counts) -> bool {
        if !std::mem::take(&mut self.chromium_flush_pending) {
            return false;
        }
        self.for_each(|stream| {
            if stream.chromium_pending_flush {
                counts.transition(stream, |_, stream| {
                    stream.chromium_pending_flush = false;
                });
            }
        });
        true
    }

    pub(crate) fn chromium_parent(&self, id: StreamId) -> StreamId {
        self.slab
            .iter()
            .map(|(_, stream)| stream)
            .filter(|stream| {
                stream.id < id
                    && stream.chromium_headers_sent
                    && !stream.is_closed()
                    && !stream.state.is_reset()
                    && !stream.state.is_scheduled_reset()
            })
            .map(|stream| stream.id)
            .max()
            .unwrap_or(StreamId::ZERO)
    }

    pub fn find_mut(&mut self, id: &StreamId) -> Option<Ptr<'_>> {
        let index = {
            let key = self.ids.get(id)?;
            *key
        };

        Some(Ptr {
            key: Key {
                index,
                stream_id: *id,
            },
            store: self,
        })
    }

    pub fn insert(&mut self, id: StreamId, val: Stream) -> Ptr<'_> {
        let index = SlabIndex(self.slab.insert(val) as u32);
        assert!(self.ids.insert(id, index).is_none());

        Ptr {
            key: Key {
                index,
                stream_id: id,
            },
            store: self,
        }
    }

    pub fn find_entry(&mut self, id: StreamId) -> Entry<'_> {
        use self::indexmap::map::Entry::*;

        match self.ids.entry(id) {
            Occupied(e) => Entry::Occupied(OccupiedEntry { ids: e }),
            Vacant(e) => Entry::Vacant(VacantEntry {
                ids: e,
                slab: &mut self.slab,
            }),
        }
    }

    #[allow(clippy::blocks_in_conditions)]
    pub(crate) fn for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(Ptr),
    {
        match self.try_for_each(|ptr| {
            f(ptr);
            Ok::<_, Infallible>(())
        }) {
            Ok(()) => (),
            #[allow(unused)]
            Err(infallible) => match infallible {},
        }
    }

    pub fn try_for_each<F, E>(&mut self, mut f: F) -> Result<(), E>
    where
        F: FnMut(Ptr) -> Result<(), E>,
    {
        let mut len = self.ids.len();
        let mut i = 0;

        while i < len {
            // Get the key by index, this makes the borrow checker happy
            let (stream_id, index) = {
                let entry = self.ids.get_index(i).unwrap();
                (*entry.0, *entry.1)
            };

            f(Ptr {
                key: Key { index, stream_id },
                store: self,
            })?;

            // TODO: This logic probably could be better...
            let new_len = self.ids.len();

            if new_len < len {
                debug_assert!(new_len == len - 1);
                len -= 1;
            } else {
                i += 1;
            }
        }

        Ok(())
    }
}

impl Resolve for Store {
    fn resolve(&mut self, key: Key) -> Ptr<'_> {
        Ptr { key, store: self }
    }
}

impl ops::Index<Key> for Store {
    type Output = Stream;

    fn index(&self, key: Key) -> &Self::Output {
        self.slab
            .get(key.index.0 as usize)
            .filter(|s| s.id == key.stream_id)
            .unwrap_or_else(|| {
                panic!("dangling store key for stream_id={:?}", key.stream_id);
            })
    }
}

impl ops::IndexMut<Key> for Store {
    fn index_mut(&mut self, key: Key) -> &mut Self::Output {
        self.slab
            .get_mut(key.index.0 as usize)
            .filter(|s| s.id == key.stream_id)
            .unwrap_or_else(|| {
                panic!("dangling store key for stream_id={:?}", key.stream_id);
            })
    }
}

impl Store {
    #[cfg(feature = "unstable")]
    pub fn num_active_streams(&self) -> usize {
        self.ids.len()
    }

    #[cfg(feature = "unstable")]
    pub fn num_wired_streams(&self) -> usize {
        self.slab.len()
    }
}

// While running h2 unit/integration tests, enable this debug assertion.
//
// In practice, we don't need to ensure this. But the integration tests
// help to make sure we've cleaned up in cases where we could (like, the
// runtime isn't suddenly dropping the task for unknown reasons).
#[cfg(feature = "unstable")]
impl Drop for Store {
    fn drop(&mut self) {
        use std::thread;

        if !thread::panicking() {
            debug_assert!(self.slab.is_empty());
        }
    }
}

// ===== impl Queue =====

impl<N> Queue<N>
where
    N: Next,
{
    pub fn new() -> Self {
        Queue {
            indices: None,
            _p: PhantomData,
        }
    }

    pub fn take(&mut self) -> Self {
        Queue {
            indices: self.indices.take(),
            _p: PhantomData,
        }
    }

    /// Queue the stream.
    ///
    /// If the stream is already contained by the list, return `false`.
    pub fn push(&mut self, stream: &mut store::Ptr) -> bool {
        tracing::trace!("Queue::push_back");

        if N::is_queued(stream) {
            tracing::trace!(" -> already queued");
            return false;
        }

        N::set_queued(stream, true);

        // The next pointer shouldn't be set
        debug_assert!(N::next(stream).is_none());

        // Queue the stream
        match self.indices {
            Some(ref mut idxs) => {
                tracing::trace!(" -> existing entries");

                // Update the current tail node to point to `stream`
                let key = stream.key();
                N::set_next(&mut stream.resolve(idxs.tail), Some(key));

                // Update the tail pointer
                idxs.tail = stream.key();
            }
            None => {
                tracing::trace!(" -> first entry");
                self.indices = Some(store::Indices {
                    head: stream.key(),
                    tail: stream.key(),
                });
            }
        }

        true
    }

    /// Queue the stream
    ///
    /// If the stream is already contained by the list, return `false`.
    pub fn push_front(&mut self, stream: &mut store::Ptr) -> bool {
        tracing::trace!("Queue::push_front");

        if N::is_queued(stream) {
            tracing::trace!(" -> already queued");
            return false;
        }

        N::set_queued(stream, true);

        // The next pointer shouldn't be set
        debug_assert!(N::next(stream).is_none());

        // Queue the stream
        match self.indices {
            Some(ref mut idxs) => {
                tracing::trace!(" -> existing entries");

                // Update the provided stream to point to the head node
                let head_key = stream.resolve(idxs.head).key();
                N::set_next(stream, Some(head_key));

                // Update the head pointer
                idxs.head = stream.key();
            }
            None => {
                tracing::trace!(" -> first entry");
                self.indices = Some(store::Indices {
                    head: stream.key(),
                    tail: stream.key(),
                });
            }
        }

        true
    }

    pub fn pop<'a, R>(&mut self, store: &'a mut R) -> Option<store::Ptr<'a>>
    where
        R: Resolve,
    {
        if let Some(mut idxs) = self.indices {
            let mut stream = store.resolve(idxs.head);

            if idxs.head == idxs.tail {
                assert!(N::next(&stream).is_none());
                self.indices = None;
            } else {
                idxs.head = N::take_next(&mut stream).unwrap();
                self.indices = Some(idxs);
            }

            debug_assert!(N::is_queued(&stream));
            N::set_queued(&mut stream, false);

            return Some(stream);
        }

        None
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_none()
    }

    pub fn pop_if<'a, R, F>(&mut self, store: &'a mut R, f: F) -> Option<store::Ptr<'a>>
    where
        R: Resolve,
        F: Fn(&Stream) -> bool,
    {
        if let Some(idxs) = self.indices {
            let should_pop = f(&store.resolve(idxs.head));
            if should_pop {
                return self.pop(store);
            }
        }

        None
    }
}

impl<N> fmt::Debug for Queue<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Queue")
            .field("indices", &self.indices)
            // skip phantom data
            .finish()
    }
}

// ===== impl Ptr =====

impl<'a> Ptr<'a> {
    /// Returns the Key associated with the stream
    pub fn key(&self) -> Key {
        self.key
    }

    pub fn store_mut(&mut self) -> &mut Store {
        self.store
    }

    /// Remove the stream from the store
    pub fn remove(self) -> StreamId {
        // The stream must have been unlinked before this point
        debug_assert!(!self.store.ids.contains_key(&self.key.stream_id));

        // Remove the stream state
        let stream = self.store.slab.remove(self.key.index.0 as usize);
        assert_eq!(stream.id, self.key.stream_id);
        stream.id
    }

    /// Remove the StreamId -> stream state association.
    ///
    /// This will effectively remove the stream as far as the H2 protocol is
    /// concerned.
    pub fn unlink(&mut self) {
        let id = self.key.stream_id;
        self.store.ids.swap_remove(&id);
    }
}

impl<'a> Resolve for Ptr<'a> {
    fn resolve(&mut self, key: Key) -> Ptr<'_> {
        Ptr {
            key,
            store: &mut *self.store,
        }
    }
}

impl<'a> ops::Deref for Ptr<'a> {
    type Target = Stream;

    fn deref(&self) -> &Stream {
        &self.store[self.key]
    }
}

impl<'a> ops::DerefMut for Ptr<'a> {
    fn deref_mut(&mut self) -> &mut Stream {
        &mut self.store[self.key]
    }
}

impl<'a> fmt::Debug for Ptr<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        (**self).fmt(fmt)
    }
}

// ===== impl OccupiedEntry =====

impl<'a> OccupiedEntry<'a> {
    pub fn key(&self) -> Key {
        let stream_id = *self.ids.key();
        let index = *self.ids.get();
        Key { index, stream_id }
    }
}

// ===== impl VacantEntry =====

impl<'a> VacantEntry<'a> {
    pub fn insert(self, value: Stream) -> Key {
        // Insert the value in the slab
        let stream_id = value.id;
        let index = SlabIndex(self.slab.insert(value) as u32);

        // Insert the handle in the ID map
        self.ids.insert(index);

        Key { index, stream_id }
    }
}

#[cfg(test)]
mod chromium_dependency_tests {
    use super::*;
    #[test]
    fn chromium_dependencies_ignore_unsent_closed_and_reset_streams() {
        let mut store = Store::new();
        for id in [1, 3, 5] {
            let mut stream = Stream::new(id.into(), 65535, 65535);
            stream.state.send_open(false).unwrap();
            stream.chromium_headers_sent = id != 5;
            store.insert(id.into(), stream);
        }
        assert_eq!(store.chromium_parent(7.into()), StreamId::from(3));
        store.find_mut(&3.into()).unwrap().state.set_reset(
            3.into(),
            crate::Reason::CANCEL,
            crate::proto::Initiator::User,
        );
        assert_eq!(store.chromium_parent(7.into()), StreamId::from(1));
        store
            .find_mut(&1.into())
            .unwrap()
            .state
            .set_scheduled_reset(crate::Reason::CANCEL);
        assert_eq!(store.chromium_parent(7.into()), StreamId::ZERO);
        store.find_mut(&5.into()).unwrap().chromium_headers_sent = true;
        assert_eq!(store.chromium_parent(7.into()), StreamId::from(5));
        assert_eq!(store.chromium_parent(5.into()), StreamId::ZERO);
    }
}

#[cfg(test)]
mod chromium_flush_tests {
    use super::*;

    fn counts() -> Counts {
        Counts::new(
            crate::proto::peer::Dyn::Client,
            &Config {
                initial_max_send_streams: 1,
                local_max_buffer_size: 65535,
                local_next_stream_id: StreamId::from(1),
                local_push_enabled: false,
                extended_connect_protocol_enabled: false,
                local_reset_duration: std::time::Duration::ZERO,
                local_reset_max: 0,
                remote_reset_max: 0,
                remote_init_window_sz: 65535,
                remote_max_initiated: None,
                local_max_error_reset_streams: None,
                data_frame_budget: crate::proto::DataFrameBudget::Auto,
            },
        )
    }
    #[test]
    fn chromium_final_flush_retains_then_releases_stream_slot_and_storage() {
        for reset in [false, true] {
            let mut counts = counts();
            let mut store = Store::new();
            let mut stream = Stream::new(StreamId::from(1), 65535, 65535);
            stream.state.send_open(false).unwrap();
            let response = crate::frame::Headers::new(
                StreamId::from(1),
                crate::frame::Pseudo::response(http::StatusCode::OK),
                http::HeaderMap::new(),
            );
            stream.state.recv_open(&response).unwrap();
            stream.state.recv_close().unwrap();
            stream.state.send_close();
            stream.chromium_headers_sent = true;
            stream.chromium_pending_flush = true;
            let mut stream = store.insert(StreamId::from(1), stream);
            counts.inc_num_send_streams(&mut stream);
            counts.transition(stream, |_, _| {});
            store.mark_chromium_flush_pending();
            assert!(counts.has_streams());
            assert_eq!(store.chromium_parent(StreamId::from(3)), StreamId::from(1));
            if reset {
                counts.transition(store.find_mut(&StreamId::from(1)).unwrap(), |_, stream| {
                    stream.set_reset(crate::Reason::CANCEL, crate::proto::Initiator::User);
                });
                assert!(!counts.has_streams());
            }
            assert!(store.complete_chromium_flush(&mut counts));
            assert!(!counts.has_streams());
            assert!(store.find_mut(&StreamId::from(1)).is_none());
            assert_eq!(store.chromium_parent(StreamId::from(3)), StreamId::ZERO);
            assert!(!store.complete_chromium_flush(&mut counts));
        }
    }
}
