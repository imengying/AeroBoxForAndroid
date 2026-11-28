use alloc::boxed::Box;
use core::cmp::min;

use crate::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
use crate::log::trace;
use crate::msgs::message::{InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage};

#[derive(PartialEq)]
enum DirectionState {
    /// No keying material.
    Invalid,

    /// Keying material present, but not yet in use.
    Prepared,

    /// Keying material in use.
    Active,
}

/// Record layer that tracks decryption and encryption keys.
pub(crate) struct RecordLayer {
    message_encrypter: Box<dyn MessageEncrypter>,
    message_decrypter: Box<dyn MessageDecrypter>,
    pending_encrypter: Option<(Box<dyn MessageEncrypter>, u64)>,
    // Content bytes only: TLS1.3's inner content type is deducted by negotiation.
    outgoing_plaintext_limit: usize,
    pending_outgoing_plaintext_limit: Option<usize>,
    // TLS1.0 CBC mitigation belongs to the active write epoch. A renegotiated
    // suite can change before old-key records have finished being transmitted.
    split_tls10: bool,
    pending_split_tls10: Option<bool>,
    pending_decrypter: Option<Box<dyn MessageDecrypter>>,
    write_seq_max: u64,
    write_seq: u64,
    read_seq: u64,
    has_decrypted: bool,
    encrypt_state: DirectionState,
    decrypt_state: DirectionState,
    // An encrypter may enforce a byte/block budget that is tighter than the
    // suite's record-count limit. Never reuse its state after a failed attempt,
    // including after a subsequent key update or TLS 1.2 renegotiation.
    encryption_error: Option<Error>,

    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,
}

impl RecordLayer {
    /// Create new record layer with no keys.
    pub(crate) fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            pending_encrypter: None,
            outgoing_plaintext_limit: crate::msgs::fragmenter::MAX_FRAGMENT_LEN,
            pending_outgoing_plaintext_limit: None,
            split_tls10: true,
            pending_split_tls10: None,
            pending_decrypter: None,
            write_seq_max: 0,
            write_seq: 0,
            read_seq: 0,
            has_decrypted: false,
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            encryption_error: None,
            trial_decryption_len: None,
        }
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if self.decrypt_state != DirectionState::Active {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        }

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let want_close_before_decrypt = self.read_seq == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        match self
            .message_decrypter
            .decrypt(encr, self.read_seq)
        {
            Ok(plaintext) => {
                self.read_seq += 1;
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Encrypt a TLS message.
    ///
    /// The first error permanently disables encryption on this connection.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage<'_>,
    ) -> Result<OutboundOpaqueMessage, Error> {
        self.check_plaintext_limit(plain.payload.len(), 0)?;
        let seq = self.next_write_seq()?;
        self.message_encrypter
            .encrypt(plain, seq)
            .map_err(|err| self.set_encryption_error(err))
    }

    pub(crate) fn encrypt_outgoing_with_padding(
        &mut self,
        plain: OutboundPlainMessage<'_>,
        padding: usize,
    ) -> Result<OutboundOpaqueMessage, Error> {
        self.check_encryption_error()?;
        if self.next_pre_encrypt_action() != PreEncryptAction::Nothing {
            return Err(self.set_encryption_error(Error::EncryptError));
        }
        crate::reality::padded_plaintext_len(plain.payload.len(), padding)?;
        self.check_plaintext_limit(plain.payload.len(), padding)?;
        let seq = self.next_write_seq()?;
        self.message_encrypter
            .encrypt_with_padding(plain, seq, padding)
            .map_err(|err| self.set_encryption_error(err))
    }

    pub(crate) fn max_outgoing_plaintext_len(&self) -> usize {
        self.outgoing_plaintext_limit
    }

    pub(crate) fn set_outgoing_plaintext_limit(&mut self, limit: usize) {
        debug_assert!((63..=16384).contains(&limit));
        self.outgoing_plaintext_limit = limit;
    }

    pub(crate) fn prepare_outgoing_plaintext_limit(&mut self, limit: usize) {
        debug_assert!((64..=16384).contains(&limit));
        self.pending_outgoing_plaintext_limit = Some(limit);
    }

    fn check_plaintext_limit(&mut self, length: usize, padding: usize) -> Result<(), Error> {
        self.check_encryption_error()?;
        if length.checked_add(padding).is_none_or(|length| length > self.outgoing_plaintext_limit) {
            return Err(self.set_encryption_error(Error::EncryptError));
        }
        Ok(())
    }

    fn next_write_seq(&mut self) -> Result<u64, Error> {
        self.check_encryption_error()?;
        if self.encrypt_state != DirectionState::Active
            || self.next_pre_encrypt_action() == PreEncryptAction::Refuse
        {
            return Err(self.set_encryption_error(Error::EncryptError));
        }
        let seq = self.write_seq;
        // Consume the sequence number before invoking the cipher. A failed
        // invocation must never make a nonce or CBC chaining state reusable.
        self.write_seq += 1;
        Ok(seq)
    }

    pub(crate) fn check_encryption_error(&self) -> Result<(), Error> {
        match &self.encryption_error {
            Some(err) => Err(err.clone()),
            None => Ok(()),
        }
    }

    pub(crate) fn set_encryption_error(&mut self, err: Error) -> Error {
        self.encryption_error
            .get_or_insert(err)
            .clone()
    }

    /// Prepare to use the given `MessageEncrypter` for future message encryption.
    /// It is not used until you call `start_encrypting`.
    pub(crate) fn prepare_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        // TLS 1.2 renegotiation still protects records with the current epoch
        // until ChangeCipherSpec. Preparing the next keys must not reset it.
        self.pending_encrypter = Some((cipher, min(SEQ_SOFT_LIMIT, max_messages)));
        if self.encrypt_state == DirectionState::Invalid {
            self.encrypt_state = DirectionState::Prepared;
        }
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.pending_decrypter = Some(cipher);
        if self.decrypt_state == DirectionState::Invalid {
            self.decrypt_state = DirectionState::Prepared;
        }
    }

    pub(crate) fn prepare_tls10_record_splitting(&mut self, enabled: bool) {
        self.pending_split_tls10 = Some(enabled);
    }

    pub(crate) fn tls10_record_splitting(&self) -> bool {
        self.split_tls10
    }

    /// Start using the `MessageEncrypter` previously provided to the previous
    /// call to `prepare_message_encrypter`.
    pub(crate) fn start_encrypting(&mut self) {
        let (cipher, max_messages) = self
            .pending_encrypter
            .take()
            .expect("prepared encryption key");
        self.message_encrypter = cipher;
        if let Some(split) = self.pending_split_tls10.take() {
            self.split_tls10 = split;
        }
        if let Some(limit) = self.pending_outgoing_plaintext_limit.take() {
            self.outgoing_plaintext_limit = limit;
        }
        self.write_seq = 0;
        self.write_seq_max = max_messages;
        self.encrypt_state = DirectionState::Active;
    }

    /// Start using the `MessageDecrypter` previously provided to the previous
    /// call to `prepare_message_decrypter`.
    pub(crate) fn start_decrypting(&mut self) {
        self.message_decrypter = self
            .pending_decrypter
            .take()
            .expect("prepared decryption key");
        self.read_seq = 0;
        self.decrypt_state = DirectionState::Active;
    }

    /// Set and start using the given `MessageEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_message_encrypter(
        &mut self,
        cipher: Box<dyn MessageEncrypter>,
        max_messages: u64,
    ) {
        self.prepare_message_encrypter(cipher, max_messages);
        self.start_encrypting();
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = None;
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = Some(max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    pub(crate) fn next_pre_encrypt_action(&self) -> PreEncryptAction {
        self.pre_encrypt_action(0)
    }

    /// Return a remedial action when we are near to encrypting too many messages.
    ///
    /// `add` is added to the current sequence number.  `add` as `0` means
    /// "the next message processed by `encrypt_outgoing`"
    pub(crate) fn pre_encrypt_action(&self, add: u64) -> PreEncryptAction {
        if self.encryption_error.is_some() {
            return PreEncryptAction::Refuse;
        }
        match self.write_seq.saturating_add(add) {
            SEQ_HARD_LIMIT.. => PreEncryptAction::Refuse,
            v if v >= self.write_seq_max => PreEncryptAction::RefreshOrClose,
            _ => PreEncryptAction::Nothing,
        }
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn write_seq(&self) -> u64 {
        self.write_seq
    }

    pub(crate) fn read_seq(&self) -> u64 {
        self.read_seq
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        self.message_encrypter
            .encrypted_payload_len(payload_len)
    }

    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(requested))
        {
            Some(remaining) => {
                self.trial_decryption_len = Some(remaining);
                true
            }
            _ => false,
        }
    }
}

/// Result of decryption.
#[derive(Debug)]
pub(crate) struct Decrypted<'a> {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub(crate) want_close_before_decrypt: bool,
    /// The decrypted message.
    pub(crate) plaintext: InboundPlainMessage<'a>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PreEncryptAction {
    /// No action is needed before calling `encrypt_outgoing`
    Nothing,

    /// A `key_update` request should be sent ASAP.
    ///
    /// If that is not possible (for example, the connection is TLS1.2), a `close_notify`
    /// alert should be sent instead.
    RefreshOrClose,

    /// Further calls to `encrypt_outgoing` return an error without using the key.
    Refuse,
}

const SEQ_SOFT_LIMIT: u64 = 0xffff_ffff_ffff_0000u64;
const SEQ_HARD_LIMIT: u64 = 0xffff_ffff_ffff_fffeu64;

#[cfg(test)]
mod tests {
    use super::*;

    struct RejectingEncrypter;

    impl MessageEncrypter for RejectingEncrypter {
        fn encrypt(
            &mut self,
            _: OutboundPlainMessage<'_>,
            _: u64,
        ) -> Result<OutboundOpaqueMessage, Error> {
            Err(Error::General("fixture encryption budget".into()))
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len
        }
    }

    fn application() -> OutboundPlainMessage<'static> {
        OutboundPlainMessage {
            typ: crate::ContentType::ApplicationData,
            version: crate::ProtocolVersion::TLSv1_2,
            payload: b"secret".as_slice().into(),
        }
    }

    #[test]
    fn encrypter_failure_is_permanent_across_epochs() {
        let mut layer = RecordLayer::new();
        layer.set_message_encrypter(Box::new(RejectingEncrypter), 100);
        let expected = Error::General("fixture encryption budget".into());
        assert_eq!(
            layer
                .encrypt_outgoing(application())
                .unwrap_err(),
            expected
        );
        assert_eq!(layer.write_seq(), 1);
        assert_eq!(layer.next_pre_encrypt_action(), PreEncryptAction::Refuse);
        assert_eq!(
            layer
                .encrypt_outgoing(application())
                .unwrap_err(),
            expected
        );
        assert_eq!(layer.write_seq(), 1, "do not call the cipher again");
        layer.set_message_encrypter(<dyn MessageEncrypter>::invalid(), 100);
        assert_eq!(
            layer
                .encrypt_outgoing(application())
                .unwrap_err(),
            expected
        );
        assert_eq!(
            layer.write_seq(),
            0,
            "new key must not revive the connection"
        );
        assert_eq!(layer.check_encryption_error(), Err(expected));
    }

    #[test]
    fn unprepared_and_hard_limit_encryptions_fail_without_panicking() {
        let mut layer = RecordLayer::new();
        assert_eq!(
            layer
                .encrypt_outgoing(application())
                .unwrap_err(),
            Error::EncryptError
        );
        assert_eq!(layer.write_seq(), 0);
        let mut layer = RecordLayer::new();
        layer.set_message_encrypter(Box::new(RejectingEncrypter), SEQ_SOFT_LIMIT);
        layer.write_seq = SEQ_HARD_LIMIT;
        assert_eq!(
            layer
                .encrypt_outgoing(application())
                .unwrap_err(),
            Error::EncryptError
        );
        assert_eq!(layer.write_seq(), SEQ_HARD_LIMIT);
    }

    #[test]
    fn padded_encryption_failure_is_also_permanent() {
        let mut layer = RecordLayer::new();
        layer.set_message_encrypter(Box::new(RejectingEncrypter), 100);
        let expected = Error::General("fixture encryption budget".into());
        assert_eq!(
            layer
                .encrypt_outgoing_with_padding(application(), 0)
                .unwrap_err(),
            expected
        );
        assert_eq!(
            layer
                .encrypt_outgoing_with_padding(application(), 0)
                .unwrap_err(),
            expected
        );
        assert_eq!(layer.write_seq(), 1);
    }

    #[test]
    fn pre_encrypt_action_checks_limits() {
        let action = |write_seq_max, write_seq, add| {
            let mut record_layer = RecordLayer::new();
            record_layer.write_seq_max = write_seq_max;
            record_layer.write_seq = write_seq;
            record_layer.pre_encrypt_action(add)
        };

        assert_eq!(action(10, 8, 1), PreEncryptAction::Nothing);
        assert_eq!(action(10, 8, 2), PreEncryptAction::RefreshOrClose);
        assert_eq!(action(10, 11, 0), PreEncryptAction::RefreshOrClose);
        assert_eq!(
            action(SEQ_SOFT_LIMIT, SEQ_HARD_LIMIT - 1, 0),
            PreEncryptAction::RefreshOrClose
        );
        assert_eq!(
            action(SEQ_SOFT_LIMIT, SEQ_HARD_LIMIT - 1, 1),
            PreEncryptAction::Refuse
        );
    }

    #[test]
    fn test_has_decrypted() {
        use crate::{ContentType, ProtocolVersion};

        struct PassThroughDecrypter;
        impl MessageDecrypter for PassThroughDecrypter {
            fn decrypt<'a>(
                &mut self,
                m: InboundOpaqueMessage<'a>,
                _: u64,
            ) -> Result<InboundPlainMessage<'a>, Error> {
                Ok(m.into_plain_message())
            }
        }

        // A record layer starts out invalid, having never decrypted.
        let mut record_layer = RecordLayer::new();
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Invalid
        ));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Preparing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        record_layer.prepare_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Prepared
        ));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Starting decryption should update the decrypt state, but not affect whether it has decrypted.
        record_layer.start_decrypting();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming(InboundOpaqueMessage::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &mut [0xC0, 0xFF, 0xEE],
            ))
            .unwrap();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer.set_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.read_seq, 0);
        assert!(record_layer.has_decrypted());
    }
}
