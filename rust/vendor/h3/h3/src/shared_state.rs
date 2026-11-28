//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    sync::{atomic::AtomicBool, Arc, OnceLock},
};

use futures_util::task::AtomicWaker;

use crate::{config::Settings, error::internal_error::ErrorOrigin};

#[derive(Debug)]
/// This struct represents the shared state of the h3 connection and the stream structs
pub struct SharedState {
    pub(crate) qpack_decoder: Option<Arc<crate::qpack::receive::Receiver>>,
    /// The settings, sent by the peer
    settings: OnceLock<Settings>,
    /// Authenticated handshake settings, superseded by control-stream SETTINGS.
    peer_alps: Option<Settings>,
    /// The connection error
    connection_error: OnceLock<ErrorOrigin>,
    /// The connection is closing
    closing: AtomicBool,
    closing_notify: tokio::sync::Notify,
    /// Waker for the connection
    waker: AtomicWaker,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            qpack_decoder: None,
            settings: OnceLock::new(),
            peer_alps: None,
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            closing_notify: tokio::sync::Notify::new(),
            waker: AtomicWaker::new(),
        }
    }
}

impl SharedState {
    pub(crate) fn with_peer_alps(peer_alps: Option<Settings>) -> Self {
        Self {
            peer_alps,
            ..Self::default()
        }
    }

    pub(crate) async fn wait_closing(&self) {
        let notified = self.closing_notify.notified();
        tokio::pin!(notified);
        // Register before inspecting the flag so a concurrent GOAWAY cannot
        // be lost between that check and the first poll of the notification.
        notified.as_mut().enable();
        if !self.is_closing() {
            notified.await;
        }
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
    }
}

/// This trait can be implemented for all types which have a shared state
pub trait ConnectionState {
    /// Get the shared state
    fn shared_state(&self) -> &SharedState;
    /// Get the connection error if the connection is in error state because of another task
    ///
    /// Return the error as an Err variant if it is set in order to allow using ? in the calling function
    fn get_conn_error(&self) -> Option<ErrorOrigin> {
        self.shared_state().connection_error.get().cloned()
    }

    /// tries to set the connection error
    fn set_conn_error(&self, error: ErrorOrigin) -> ErrorOrigin {
        let err = self
            .shared_state()
            .connection_error
            .get_or_init(move || error);
        if let Some(decoder) = &self.shared_state().qpack_decoder {
            decoder.fail(err.clone());
        }
        err.clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<'_, Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .or(self.shared_state().peer_alps.as_ref())
            .map(Cow::Borrowed)
            .unwrap_or_default()
    }
    /// Set the connection to closing
    fn set_closing(&self) {
        self.shared_state()
            .closing
            .store(true, std::sync::atomic::Ordering::Release);
        self.shared_state().closing_notify.notify_waiters();
    }
    /// Check if the connection is closing
    fn is_closing(&self) -> bool {
        self.shared_state()
            .closing
            .load(std::sync::atomic::Ordering::Acquire)
    }
    /// Set the settings
    fn set_settings(&self, settings: Settings) {
        let _ = self.shared_state().settings.set(settings);
    }

    /// Returns the waker for the connection
    fn waker(&self) -> &AtomicWaker {
        &self.shared_state().waker
    }
}
