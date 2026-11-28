use alloc::boxed::Box;
use alloc::vec::Vec;

use pki_types::CertificateDer;

use crate::conn::kernel::KernelState;
use crate::crypto::SupportedKxGroup;
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, error, warn};
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{AlertLevel, KeyUpdateRequest};
use crate::msgs::fragmenter::MessageFragmenter;
use crate::msgs::handshake::{CertificateChain, HandshakeMessagePayload, ProtocolName};
use crate::msgs::message::{
    Message, MessagePayload, OutboundChunks, OutboundOpaqueMessage, OutboundPlainMessage,
    PlainMessage,
};
use crate::record_layer::PreEncryptAction;
use crate::suites::{PartiallyExtractedSecrets, SupportedCipherSuite};
#[cfg(feature = "tls12")]
use crate::tls12::ConnectionSecrets;
use crate::unbuffered::{EncryptError, InsufficientSizeError};
use crate::vecbuf::ChunkVecBuffer;
use crate::{quic, record_layer};

/// Connection state common to both client and server connections.
pub struct CommonState {
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    pub(crate) handshake_kind: Option<HandshakeKind>,
    pub(crate) side: Side,
    pub(crate) record_layer: record_layer::RecordLayer,
    pub(crate) suite: Option<SupportedCipherSuite>,
    pub(crate) kx_state: KxState,
    pub(crate) alpn_protocol: Option<ProtocolName>,
    pub(crate) application_settings: Option<crate::client::alps::NegotiatedApplicationSettings>,
    pub(crate) aligned_handshake: bool,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_receive_application_data: bool,
    pub(crate) early_traffic: bool,
    pub(crate) tls12_renegotiating: bool,
    sent_fatal_alert: bool,
    /// If we signaled end of stream.
    pub(crate) has_sent_close_notify: bool,
    /// If the peer has signaled end of stream.
    pub(crate) has_received_close_notify: bool,
    #[cfg(feature = "std")]
    pub(crate) has_seen_eof: bool,
    pub(crate) peer_certificates: Option<CertificateChain<'static>>,
    message_fragmenter: MessageFragmenter,
    // Negotiated in ServerHello, applied only with the new TLS1.2 write keys.
    pub(crate) pending_tls12_record_size_limit: usize,
    pub(crate) received_plaintext: ChunkVecBuffer,
    pub(crate) sendable_tls: ChunkVecBuffer,
    queued_key_update_message: Option<Vec<u8>>,

    /// Protocol whose key schedule should be used. Unused for TLS < 1.3.
    pub(crate) protocol: Protocol,
    pub(crate) quic: quic::Quic,
    pub(crate) enable_secret_extraction: bool,
    temper_counters: TemperCounters,
    pub(crate) refresh_traffic_keys_pending: bool,
    pub(crate) fips: bool,
    pub(crate) tls13_tickets_received: u32,
}

impl CommonState {
    pub(crate) fn new(side: Side) -> Self {
        Self {
            negotiated_version: None,
            handshake_kind: None,
            side,
            record_layer: record_layer::RecordLayer::new(),
            suite: None,
            kx_state: KxState::default(),
            alpn_protocol: None,
            application_settings: None,
            aligned_handshake: true,
            may_send_application_data: false,
            may_receive_application_data: false,
            early_traffic: false,
            tls12_renegotiating: false,
            sent_fatal_alert: false,
            has_sent_close_notify: false,
            has_received_close_notify: false,
            #[cfg(feature = "std")]
            has_seen_eof: false,
            peer_certificates: None,
            message_fragmenter: MessageFragmenter::default(),
            pending_tls12_record_size_limit: 16384,
            received_plaintext: ChunkVecBuffer::new(Some(DEFAULT_RECEIVED_PLAINTEXT_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            queued_key_update_message: None,
            protocol: Protocol::Tcp,
            quic: quic::Quic::default(),
            enable_secret_extraction: false,
            temper_counters: TemperCounters::default(),
            refresh_traffic_keys_pending: false,
            fips: false,
            tls13_tickets_received: 0,
        }
    }

    /// Returns true if the caller should call [`Connection::write_tls`] as soon as possible.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time plaintext written to the connection is buffered in memory. After
    /// [`Connection::process_new_packets()`] has been called, this might start to return `false`
    /// while the final handshake packets still need to be extracted from the connection's buffers.
    ///
    /// [`Connection::process_new_packets()`]: crate::Connection::process_new_packets
    pub fn is_handshaking(&self) -> bool {
        !(self.may_send_application_data && self.may_receive_application_data)
    }

    /// Retrieves the certificate chain or the raw public key used by the peer to authenticate.
    ///
    /// The order of the certificate chain is as it appears in the TLS
    /// protocol: the first certificate relates to the peer, the
    /// second certifies the first, the third certifies the second, and
    /// so on.
    ///
    /// When using raw public keys, the first and only element is the raw public key.
    ///
    /// This is made available for both full and resumed handshakes.
    ///
    /// For clients, this is the certificate chain or the raw public key of the server.
    ///
    /// For servers, this is the certificate chain or the raw public key of the client,
    /// if client authentication was completed.
    ///
    /// The return value is None until this value is available.
    ///
    /// Note: the return type of the 'certificate', when using raw public keys is `CertificateDer<'static>`
    /// even though this should technically be a `SubjectPublicKeyInfoDer<'static>`.
    /// This choice simplifies the API and ensures backwards compatibility.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.peer_certificates.as_deref()
    }

    /// Authenticated peer ALPS settings, or settings associated with the PSK
    /// while sending early data. An empty value differs from no ALPS negotiation.
    pub fn peer_application_settings(&self) -> Option<&[u8]> {
        self.application_settings
            .as_ref()
            .map(|settings| settings.peer.as_slice())
    }

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of `None` after handshake completion means no protocol
    /// was agreed (because no protocols were offered or accepted by the peer).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.get_alpn_protocol()
    }

    /// Retrieves the ciphersuite agreed with the peer.
    ///
    /// This returns None until the ciphersuite is agreed.
    pub fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.suite
    }

    /// Retrieves the key exchange group agreed with the peer.
    ///
    /// This function may return `None` depending on the state of the connection,
    /// the type of handshake, and the protocol version.
    ///
    /// If [`CommonState::is_handshaking()`] is true this function will return `None`.
    /// Similarly, if the [`CommonState::handshake_kind()`] is [`HandshakeKind::Resumed`]
    /// and the [`CommonState::protocol_version()`] is TLS 1.2, then no key exchange will have
    /// occurred and this function will return `None`.
    pub fn negotiated_key_exchange_group(&self) -> Option<&'static dyn SupportedKxGroup> {
        match self.kx_state {
            KxState::Complete(group) => Some(group),
            _ => None,
        }
    }

    pub(crate) fn record_version(&self) -> ProtocolVersion {
        match self.negotiated_version {
            Some(v @ (ProtocolVersion::TLSv1_0 | ProtocolVersion::TLSv1_1)) => v,
            _ => ProtocolVersion::TLSv1_2,
        }
    }

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns `None` until the version is agreed.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.negotiated_version
    }

    /// Which kind of handshake was performed.
    ///
    /// This tells you whether the handshake was a resumption or not.
    ///
    /// This will return `None` before it is known which sort of
    /// handshake occurred.
    pub fn handshake_kind(&self) -> Option<HandshakeKind> {
        self.handshake_kind
    }

    pub(crate) fn is_tls13(&self) -> bool {
        matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
    }

    pub(crate) fn process_main_protocol<Data>(
        &mut self,
        msg: Message<'_>,
        mut state: Box<dyn State<Data>>,
        data: &mut Data,
        sendable_plaintext: Option<&mut ChunkVecBuffer>,
    ) -> Result<Box<dyn State<Data>>, Error> {
        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if self.may_receive_application_data && !self.is_tls13() {
            let reject_ty = match self.side {
                Side::Client => HandshakeType::HelloRequest,
                Side::Server => HandshakeType::ClientHello,
            };
            if msg.is_handshake_type(reject_ty) {
                if !state.can_handle_renegotiation()
                    || self.has_sent_close_notify
                    || self.has_received_close_notify
                {
                    self.temper_counters
                        .received_renegotiation_request()?;
                    self.send_warning_alert(AlertDescription::NoRenegotiation);
                    return Ok(state);
                }
            }
        }

        // In-flight application records from the preceding TLS 1.2 epoch
        // remain valid until the peer changes keys. They do not enter the new
        // handshake transcript; the normal bounded receive buffer still applies.
        if self.tls12_renegotiating && self.may_receive_application_data {
            if let MessagePayload::ApplicationData(payload) = msg.payload {
                self.take_received_plaintext(payload);
                return Ok(state);
            }
        }
        let mut cx = Context {
            common: self,
            data,
            sendable_plaintext,
        };
        match state.handle(&mut cx, msg) {
            Ok(next) => {
                state = next.into_owned();
                Ok(state)
            }
            Err(e @ Error::InappropriateMessage { .. })
            | Err(e @ Error::InappropriateHandshakeMessage { .. }) => {
                Err(self.send_fatal_alert(AlertDescription::UnexpectedMessage, e))
            }
            Err(e) => Err(e),
        }
    }

    /// Ask for a TLS 1.3 key update before encrypting `payload`, if one of its records would
    /// take the last sequence number allowed by the current keys.
    ///
    /// The key update then takes that sequence number instead.
    pub(crate) fn request_key_update_for(&mut self, payload: OutboundChunks<'_>) {
        let records = self
            .record_fragmenter()
            .fragment_payload(ContentType::ApplicationData, self.record_version(), payload)
            .len();

        if records > 0
            && self.negotiated_version == Some(ProtocolVersion::TLSv1_3)
            && self.record_layer.write_seq() > 0
            && self
                .record_layer
                .pre_encrypt_action(records as u64)
                != PreEncryptAction::Nothing
        {
            // driven by caller, as we don't have the `State` here
            self.refresh_traffic_keys_pending = true;
        }
    }

    pub(crate) fn write_plaintext(
        &mut self,
        payload: OutboundChunks<'_>,
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        if let Err(error) = self
            .record_layer
            .check_encryption_error()
        {
            outgoing_tls.fill(0);
            return Err(EncryptError::EncryptFailed {
                error,
                plaintext_consumed: 0,
                tls_bytes_written: 0,
            });
        }
        if payload.is_empty() {
            return Ok(0);
        }

        let fragments = self
            .record_fragmenter()
            .fragment_payload(
                ContentType::ApplicationData,
                self.record_version(),
                payload.clone(),
            );

        for f in 0..fragments.len() {
            match self
                .record_layer
                .pre_encrypt_action(f as u64)
            {
                PreEncryptAction::Nothing => {}
                PreEncryptAction::RefreshOrClose => match self.negotiated_version {
                    Some(ProtocolVersion::TLSv1_3) => {
                        // driven by caller, as we don't have the `State` here
                        self.refresh_traffic_keys_pending = true;
                    }
                    _ => {
                        error!(
                            "traffic keys exhausted, closing connection to prevent security failure"
                        );
                        self.send_close_notify();
                        self.record_layer
                            .set_encryption_error(Error::EncryptError);
                        outgoing_tls.fill(0);
                        return Err(EncryptError::EncryptExhausted);
                    }
                },
                PreEncryptAction::Refuse => {
                    self.record_layer
                        .set_encryption_error(Error::EncryptError);
                    outgoing_tls.fill(0);
                    return Err(EncryptError::EncryptExhausted);
                }
            }
        }

        self.perhaps_write_key_update();

        self.check_required_size(outgoing_tls, fragments)?;

        let fragments = self
            .record_fragmenter()
            .fragment_payload(ContentType::ApplicationData, self.record_version(), payload);

        self.write_fragments(outgoing_tls, fragments)
    }

    // Changing the keys must not span any fragmented handshake
    // messages.  Otherwise the defragmented messages will have
    // been protected with two different record layer protections,
    // which is illegal.  Not mentioned in RFC.
    pub(crate) fn check_aligned_handshake(&mut self) -> Result<(), Error> {
        if !self.aligned_handshake {
            Err(self.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::KeyEpochWithPendingFragment,
            ))
        } else {
            Ok(())
        }
    }

    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    pub(crate) fn send_msg_encrypt(&mut self, m: PlainMessage) {
        let iter = self
            .record_fragmenter()
            .fragment_message(&m);
        for m in iter {
            if self.send_single_fragment(m).is_err() {
                break;
            }
        }
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.
    ///
    /// If `stop_for_key_update` is true, this stops before a TLS 1.3 record that would take
    /// the last sequence number allowed by the current keys, so that the caller can first send
    /// a `key_update` request with that sequence number. In that case, the return value is the
    /// number of bytes sent so far.
    fn send_appdata_encrypt(
        &mut self,
        payload: OutboundChunks<'_>,
        limit: Limit,
        stop_for_key_update: bool,
    ) -> usize {
        // Here, the limit on sendable_tls applies to encrypted data,
        // but we're respecting it for plaintext data -- so we'll
        // be out by whatever the cipher+record overhead is.  That's a
        // constant and predictable amount, so it's not a terrible issue.
        let len = match limit {
            #[cfg(feature = "std")]
            Limit::Yes => self
                .sendable_tls
                .apply_limit(payload.len()),
            Limit::No => payload.len(),
        };

        let iter = self
            .record_fragmenter()
            .fragment_payload(
                ContentType::ApplicationData,
                self.record_version(),
                payload.split_at(len).0,
            );

        // Check the record limit for the last fragment before encrypting any of them, so
        // that a write crossing the limit is not sent in part.
        if let Some(last) = (iter.len() as u64).checked_sub(1) {
            if !self.check_pre_encrypt_action(last) {
                return 0;
            }
        }

        let mut sent = 0;
        for m in iter {
            // The key update takes the last sequence number allowed by the current keys,
            // unless they have not been used yet (as updating them would not help then).
            if stop_for_key_update
                && self.negotiated_version == Some(ProtocolVersion::TLSv1_3)
                && self.record_layer.write_seq() > 0
                && self.record_layer.pre_encrypt_action(1) != PreEncryptAction::Nothing
            {
                // driven by caller, as we don't have the `State` here
                self.refresh_traffic_keys_pending = true;
                return sent;
            }

            let fragment_len = m.payload.len();
            if self.send_single_fragment(m).is_err() {
                return sent;
            }
            sent += fragment_len;
        }

        sent
    }

    fn send_single_fragment(&mut self, m: OutboundPlainMessage<'_>) -> Result<(), Error> {
        self.record_layer
            .check_encryption_error()?;
        // Alerts may use the space reserved above the soft record-count limit,
        // but must obey both the hard limit and the cipher's own block budget.
        if m.typ != ContentType::Alert && !self.check_pre_encrypt_action(0) {
            return Err(self
                .record_layer
                .set_encryption_error(Error::EncryptError));
        }

        let em = self.record_layer.encrypt_outgoing(m)?;
        self.queue_tls_message(em);
        Ok(())
    }

    /// Take the remedial action needed before encrypting the record `add` records after the next.
    ///
    /// Returns `false` if that record must not be encrypted.
    fn check_pre_encrypt_action(&mut self, add: u64) -> bool {
        match self
            .record_layer
            .pre_encrypt_action(add)
        {
            PreEncryptAction::Nothing => true,

            // Close connection once we start to run out of
            // sequence space.
            PreEncryptAction::RefreshOrClose => match self.negotiated_version {
                Some(ProtocolVersion::TLSv1_3) => {
                    // driven by caller, as we don't have the `State` here
                    self.refresh_traffic_keys_pending = true;
                    true
                }
                _ => {
                    error!(
                        "traffic keys exhausted, closing connection to prevent security failure"
                    );
                    self.send_close_notify();
                    self.record_layer
                        .set_encryption_error(Error::EncryptError);
                    false
                }
            },

            // Refuse to wrap counter at all costs.  This
            // is basically untestable unfortunately.
            PreEncryptAction::Refuse => {
                self.record_layer
                    .set_encryption_error(Error::EncryptError);
                false
            }
        }
    }

    fn send_plain_non_buffering(
        &mut self,
        payload: OutboundChunks<'_>,
        limit: Limit,
        stop_for_key_update: bool,
    ) -> usize {
        debug_assert!(self.may_send_application_data);
        debug_assert!(self.record_layer.is_encrypting());

        if payload.is_empty() {
            // Don't send empty fragments.
            return 0;
        }

        self.send_appdata_encrypt(payload, limit, stop_for_key_update)
    }

    /// Mark the connection as ready to send application data.
    ///
    /// Also flush `sendable_plaintext` if it is `Some`.
    pub(crate) fn start_outgoing_traffic(
        &mut self,
        sendable_plaintext: &mut Option<&mut ChunkVecBuffer>,
    ) {
        self.may_send_application_data = true;
        if let Some(sendable_plaintext) = sendable_plaintext {
            self.flush_plaintext(sendable_plaintext);
        }
    }

    /// Mark the connection as ready to send and receive application data.
    ///
    /// Also flush `sendable_plaintext` if it is `Some`.
    pub(crate) fn start_traffic(&mut self, sendable_plaintext: &mut Option<&mut ChunkVecBuffer>) {
        self.may_receive_application_data = true;
        self.start_outgoing_traffic(sendable_plaintext);
    }

    /// Send any buffered plaintext.  Plaintext is buffered if
    /// written during handshake.
    fn flush_plaintext(&mut self, sendable_plaintext: &mut ChunkVecBuffer) {
        if !self.may_send_application_data {
            return;
        }

        while let Some(mut buf) = sendable_plaintext.pop() {
            self.send_plain_non_buffering(buf.as_slice().into(), Limit::No, false);
            if self
                .record_layer
                .check_encryption_error()
                .is_err()
            {
                // A write accepted before the handshake can fail when its
                // encryption is finally attempted. The handshake boundary
                // reports that fatal error; never retry the remaining plaintext.
                use zeroize::Zeroize;
                buf.zeroize();
                while let Some(mut pending) = sendable_plaintext.pop() {
                    pending.zeroize();
                }
                break;
            }
        }
    }

    // Put m into sendable_tls for writing.
    fn queue_tls_message(&mut self, m: OutboundOpaqueMessage) {
        self.perhaps_write_key_update();
        self.sendable_tls.append(m.encode());
    }

    pub(crate) fn send_reality_record(
        &mut self,
        content: &[u8],
        typ: ContentType,
        wire_len: usize,
    ) -> Result<(), Error> {
        if self.is_quic() || !self.is_tls13() {
            return Err(crate::reality::incompatible());
        }
        let padding = crate::reality::padding_for(content.len(), wire_len)?;
        let message = self
            .record_layer
            .encrypt_outgoing_with_padding(
                OutboundPlainMessage {
                    typ,
                    version: ProtocolVersion::TLSv1_2,
                    payload: content.into(),
                },
                padding,
            )?;
        if message.payload.as_ref().len() + 5 != wire_len {
            return Err(crate::reality::incompatible());
        }
        self.queue_tls_message(message);
        Ok(())
    }

    pub(crate) fn perhaps_write_key_update(&mut self) {
        if let Some(message) = self.queued_key_update_message.take() {
            self.sendable_tls.append(message);
        }
    }

    /// Send a raw TLS message, fragmenting it if needed.
    pub(crate) fn send_msg(&mut self, mut m: Message<'_>, must_encrypt: bool) {
        if self
            .record_layer
            .check_encryption_error()
            .is_err()
        {
            return;
        }
        if matches!(
            self.negotiated_version,
            Some(ProtocolVersion::TLSv1_0 | ProtocolVersion::TLSv1_1)
        ) {
            m.version = self.record_version();
        }
        {
            if let Protocol::Quic = self.protocol {
                if let MessagePayload::Alert(alert) = m.payload {
                    self.quic.alert = Some(alert.description);
                } else {
                    debug_assert!(
                        matches!(
                            m.payload,
                            MessagePayload::Handshake { .. } | MessagePayload::HandshakeFlight(_)
                        ),
                        "QUIC uses TLS for the cryptographic handshake only"
                    );
                    let mut bytes = Vec::new();
                    m.payload.encode(&mut bytes);
                    self.quic
                        .hs_queue
                        .push_back((must_encrypt, bytes));
                }
                return;
            }
        }
        if !must_encrypt {
            let msg = &m.into();
            let iter = self
                .message_fragmenter
                .fragment_message(msg);
            for m in iter {
                self.queue_tls_message(m.to_unencrypted_opaque());
            }
        } else {
            self.send_msg_encrypt(m.into());
        }
    }

    pub(crate) fn take_received_plaintext(&mut self, bytes: Payload<'_>) {
        self.temper_counters.received_app_data();
        self.received_plaintext
            .append(bytes.into_vec());
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn start_encryption_tls12(&mut self, secrets: &ConnectionSecrets, side: Side) {
        let (dec, enc) = secrets.make_cipher_pair(side);
        let rc4 = matches!(u16::from(secrets.suite().common.suite), 0xc007 | 0xc011 | 0x0005);
        self.record_layer.prepare_tls10_record_splitting(!rc4);
        self.record_layer
            .prepare_message_encrypter(
                enc,
                secrets
                    .suite()
                    .common
                    .confidentiality_limit,
            );
        self.record_layer
            .prepare_outgoing_plaintext_limit(self.pending_tls12_record_size_limit);
        self.record_layer
            .prepare_message_decrypter(dec);
    }

    pub(crate) fn missing_extension(&mut self, why: PeerMisbehaved) -> Error {
        self.send_fatal_alert(AlertDescription::MissingExtension, why)
    }

    fn send_warning_alert(&mut self, desc: AlertDescription) {
        warn!("Sending warning alert {desc:?}");
        self.send_warning_alert_no_log(desc);
    }

    pub(crate) fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        // Reject unknown AlertLevels.
        if let AlertLevel::Unknown(_) = alert.level {
            return Err(self.send_fatal_alert(
                AlertDescription::IllegalParameter,
                Error::AlertReceived(alert.description),
            ));
        }

        // If we get a CloseNotify, make a note to declare EOF to our
        // caller.  But do not treat unauthenticated alerts like this.
        if self.may_receive_application_data && alert.description == AlertDescription::CloseNotify {
            self.has_received_close_notify = true;
            return Ok(());
        }

        // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3
        // (except, for no good reason, user_cancelled).
        let err = Error::AlertReceived(alert.description);
        if alert.level == AlertLevel::Warning {
            self.temper_counters
                .received_warning_alert()?;
            if self.is_tls13() && alert.description != AlertDescription::UserCanceled {
                return Err(self.send_fatal_alert(AlertDescription::DecodeError, err));
            }

            // Some implementations send pointless `user_canceled` alerts, don't log them
            // in release mode (https://bugs.openjdk.org/browse/JDK-8323517).
            if alert.description != AlertDescription::UserCanceled || cfg!(debug_assertions) {
                warn!("TLS alert warning received: {alert:?}");
            }

            return Ok(());
        }

        Err(err)
    }

    pub(crate) fn send_cert_verify_error_alert(&mut self, err: Error) -> Error {
        self.send_fatal_alert(
            match &err {
                Error::InvalidCertificate(e) => e.clone().into(),
                Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
                _ => AlertDescription::HandshakeFailure,
            },
            err,
        )
    }

    pub(crate) fn send_fatal_alert(
        &mut self,
        desc: AlertDescription,
        err: impl Into<Error>,
    ) -> Error {
        if !self.sent_fatal_alert {
            self.sent_fatal_alert = true;
            let m = Message::build_alert(AlertLevel::Fatal, desc);
            self.send_msg(m, self.record_layer.is_encrypting());
        }
        err.into()
    }

    /// Queues a `close_notify` warning alert to be sent in the next
    /// [`Connection::write_tls`] call.  This informs the peer that the
    /// connection is being closed.
    ///
    /// Does nothing if any `close_notify` or fatal alert was already sent.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn send_close_notify(&mut self) {
        if self.sent_fatal_alert {
            return;
        }
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.sent_fatal_alert = true;
        self.send_warning_alert_no_log(AlertDescription::CloseNotify);
        self.has_sent_close_notify = self
            .record_layer
            .check_encryption_error()
            .is_ok();
    }

    pub(crate) fn eager_send_close_notify(
        &mut self,
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.send_close_notify();
        if let Err(error) = self
            .record_layer
            .check_encryption_error()
        {
            outgoing_tls.fill(0);
            return Err(EncryptError::EncryptFailed {
                error,
                plaintext_consumed: 0,
                tls_bytes_written: 0,
            });
        }
        self.check_required_size(outgoing_tls, [].into_iter())?;
        self.write_fragments(outgoing_tls, [].into_iter())
    }

    fn send_warning_alert_no_log(&mut self, desc: AlertDescription) {
        let m = Message::build_alert(AlertLevel::Warning, desc);
        self.send_msg(m, self.record_layer.is_encrypting());
    }

    fn check_required_size<'a>(
        &self,
        outgoing_tls: &mut [u8],
        fragments: impl Iterator<Item = OutboundPlainMessage<'a>>,
    ) -> Result<(), EncryptError> {
        let mut required_size = self.sendable_tls.len();

        for m in fragments {
            required_size += m.encoded_len(&self.record_layer);
        }

        if required_size > outgoing_tls.len() {
            return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size,
            }));
        }

        Ok(())
    }

    fn write_fragments<'a>(
        &mut self,
        outgoing_tls: &mut [u8],
        fragments: impl Iterator<Item = OutboundPlainMessage<'a>>,
    ) -> Result<usize, EncryptError> {
        let mut written = 0;
        let mut plaintext_consumed = 0;

        // Any pre-existing encrypted messages in `sendable_tls` must
        // be output before encrypting any of the `fragments`.
        while let Some(message) = self.sendable_tls.pop() {
            let len = message.len();
            outgoing_tls[written..written + len].copy_from_slice(&message);
            written += len;
        }

        for m in fragments {
            let fragment_len = m.payload.len();
            let em = match self.record_layer.encrypt_outgoing(m) {
                Ok(em) => em.encode(),
                Err(error) => {
                    // Keep only complete, authenticated records. Explicitly
                    // invalidate the rest of the caller's output buffer so a
                    // stale tail cannot be mistaken for this write's output.
                    outgoing_tls[written..].fill(0);
                    return Err(EncryptError::EncryptFailed {
                        error,
                        plaintext_consumed,
                        tls_bytes_written: written,
                    });
                }
            };

            let len = em.len();
            outgoing_tls[written..written + len].copy_from_slice(&em);
            written += len;
            plaintext_consumed += fragment_len;
        }

        Ok(written)
    }

    fn record_fragmenter(&self) -> MessageFragmenter {
        self.message_fragmenter
            .with_limit(self.record_layer.max_outgoing_plaintext_len())
            .with_tls10_splitting(self.record_layer.tls10_record_splitting())
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter
            .set_max_fragment_size(new)
    }

    pub(crate) fn get_alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol
            .as_ref()
            .map(AsRef::as_ref)
    }

    /// Returns true if the caller should call [`Connection::read_tls`] as soon
    /// as possible.
    ///
    /// If there is pending plaintext data to read with [`Connection::reader`],
    /// this returns false.  If your application respects this mechanism,
    /// only one full TLS message will be buffered by rustls.
    ///
    /// [`Connection::reader`]: crate::Connection::reader
    /// [`Connection::read_tls`]: crate::Connection::read_tls
    pub fn wants_read(&self) -> bool {
        // We want to read more data all the time, except when we have unprocessed plaintext.
        // This provides back-pressure to the TCP buffers. We also don't want to read more after
        // the peer has sent us a close notification.
        //
        // In the handshake case we don't have readable plaintext before the handshake has
        // completed, but also don't want to read if we still have sendable tls.
        self.received_plaintext.is_empty()
            && !self.has_received_close_notify
            && (self.may_send_application_data || self.sendable_tls.is_empty())
    }

    pub(crate) fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
            peer_has_closed: self.has_received_close_notify,
        }
    }

    pub(crate) fn is_quic(&self) -> bool {
        self.protocol == Protocol::Quic
    }

    pub(crate) fn should_update_key(
        &mut self,
        key_update_request: &KeyUpdateRequest,
    ) -> Result<bool, Error> {
        self.temper_counters
            .received_key_update_request()?;

        match key_update_request {
            KeyUpdateRequest::UpdateNotRequested => Ok(false),
            KeyUpdateRequest::UpdateRequested => Ok(self.queued_key_update_message.is_none()),
            _ => Err(self.send_fatal_alert(
                AlertDescription::IllegalParameter,
                InvalidMessage::InvalidKeyUpdate,
            )),
        }
    }

    pub(crate) fn enqueue_key_update_notification(&mut self) {
        let message = PlainMessage::from(Message::build_key_update_notify());
        if let Ok(encrypted) = self
            .record_layer
            .encrypt_outgoing(message.borrow_outbound())
        {
            self.queued_key_update_message = Some(encrypted.encode());
        }
    }

    pub(crate) fn received_tls13_change_cipher_spec(&mut self) -> Result<(), Error> {
        self.temper_counters
            .received_tls13_change_cipher_spec()
    }
}

#[cfg(feature = "std")]
impl CommonState {
    /// Send plaintext application data, fragmenting and
    /// encrypting it as it goes out.
    ///
    /// If internal buffers are too small, or if the traffic keys must be
    /// updated first, this function will not accept all the data.
    pub(crate) fn buffer_plaintext(
        &mut self,
        payload: OutboundChunks<'_>,
        sendable_plaintext: &mut ChunkVecBuffer,
    ) -> usize {
        if self
            .record_layer
            .check_encryption_error()
            .is_err()
        {
            return 0;
        }
        self.perhaps_write_key_update();
        self.send_plain(payload, Limit::Yes, sendable_plaintext)
    }

    pub(crate) fn send_early_plaintext(&mut self, data: &[u8]) -> std::io::Result<usize> {
        debug_assert!(self.early_traffic);
        debug_assert!(self.record_layer.is_encrypting());

        self.record_layer
            .check_encryption_error()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        if data.is_empty() {
            // Don't send empty fragments.
            return Ok(0);
        }

        let len = self.send_appdata_encrypt(data.into(), Limit::Yes, false);
        if len == 0 {
            self.record_layer
                .check_encryption_error()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        }
        Ok(len)
    }

    /// Encrypt and send some plaintext `data`.  `limit` controls
    /// whether the per-connection buffer limits apply.
    ///
    /// Returns the number of bytes written from `data`: this might
    /// be less than `data.len()` if buffer limits were exceeded.
    fn send_plain(
        &mut self,
        payload: OutboundChunks<'_>,
        limit: Limit,
        sendable_plaintext: &mut ChunkVecBuffer,
    ) -> usize {
        if !self.may_send_application_data {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            let len = match limit {
                Limit::Yes => sendable_plaintext.append_limited_copy(payload),
                Limit::No => sendable_plaintext.append(payload.to_vec()),
            };
            return len;
        }

        self.send_plain_non_buffering(payload, limit, true)
    }
}

/// Describes which sort of handshake happened.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HandshakeKind {
    /// A full handshake.
    ///
    /// This is the typical TLS connection initiation process when resumption is
    /// not yet unavailable, and the initial `ClientHello` was accepted by the server.
    Full,

    /// A full TLS1.3 handshake, with an extra round-trip for a `HelloRetryRequest`.
    ///
    /// The server can respond with a `HelloRetryRequest` if the initial `ClientHello`
    /// is unacceptable for several reasons, the most likely if no supported key
    /// shares were offered by the client.
    FullWithHelloRetryRequest,

    /// A resumed handshake.
    ///
    /// Resumed handshakes involve fewer round trips and less cryptography than
    /// full ones, but can only happen when the peers have previously done a full
    /// handshake together, and then remember data about it.
    Resumed,
}

/// Values of this structure are returned from [`Connection::process_new_packets`]
/// and tell the caller the current I/O state of the TLS connection.
///
/// [`Connection::process_new_packets`]: crate::Connection::process_new_packets
#[derive(Debug, Eq, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
    peer_has_closed: bool,
}

impl IoState {
    /// How many bytes could be written by [`Connection::write_tls`] if called
    /// right now.  A non-zero value implies [`CommonState::wants_write`].
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be obtained via [`std::io::Read`]
    /// without further I/O.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }

    /// True if the peer has sent us a close_notify alert.  This is
    /// the TLS mechanism to securely half-close a TLS connection,
    /// and signifies that the peer will not send any further data
    /// on this connection.
    ///
    /// This is also signalled via returning `Ok(0)` from
    /// [`std::io::Read`], after all the received bytes have been
    /// retrieved.
    pub fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }
}

pub(crate) trait State<Data>: Send + Sync {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut Context<'_, Data>,
        message: Message<'m>,
    ) -> Result<Box<dyn State<Data> + 'm>, Error>
    where
        Self: 'm;

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn send_key_update_request(&mut self, _common: &mut CommonState) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn can_handle_renegotiation(&self) -> bool {
        false
    }

    fn handle_decrypt_error(&self) {}

    fn into_external_state(self: Box<Self>) -> Result<Box<dyn KernelState + 'static>, Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn into_owned(self: Box<Self>) -> Box<dyn State<Data> + 'static>;
}

pub(crate) struct Context<'a, Data> {
    pub(crate) common: &'a mut CommonState,
    pub(crate) data: &'a mut Data,
    /// Buffered plaintext. This is `Some` if any plaintext was written during handshake and `None`
    /// otherwise.
    pub(crate) sendable_plaintext: Option<&'a mut ChunkVecBuffer>,
}

/// Side of the connection.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Side {
    /// A client initiates the connection.
    Client,
    /// A server waits for a client to connect.
    Server,
}

impl Side {
    pub(crate) fn peer(&self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum Protocol {
    Tcp,
    Quic,
}

impl Protocol {
    pub(crate) fn supports_version(&self, version: ProtocolVersion) -> bool {
        match self {
            Self::Quic => version == ProtocolVersion::TLSv1_3,
            Self::Tcp => true,
        }
    }
}

enum Limit {
    #[cfg(feature = "std")]
    Yes,
    No,
}

/// Tracking technically-allowed protocol actions
/// that we limit to avoid denial-of-service vectors.
struct TemperCounters {
    allowed_warning_alerts: u8,
    allowed_renegotiation_requests: u8,
    allowed_key_update_requests: u8,
    allowed_middlebox_ccs: u8,
}

impl TemperCounters {
    fn received_warning_alert(&mut self) -> Result<(), Error> {
        match self.allowed_warning_alerts {
            0 => Err(PeerMisbehaved::TooManyWarningAlertsReceived.into()),
            _ => {
                self.allowed_warning_alerts -= 1;
                Ok(())
            }
        }
    }

    fn received_renegotiation_request(&mut self) -> Result<(), Error> {
        match self.allowed_renegotiation_requests {
            0 => Err(PeerMisbehaved::TooManyRenegotiationRequests.into()),
            _ => {
                self.allowed_renegotiation_requests -= 1;
                Ok(())
            }
        }
    }

    fn received_key_update_request(&mut self) -> Result<(), Error> {
        match self.allowed_key_update_requests {
            0 => Err(PeerMisbehaved::TooManyKeyUpdateRequests.into()),
            _ => {
                self.allowed_key_update_requests -= 1;
                Ok(())
            }
        }
    }

    fn received_tls13_change_cipher_spec(&mut self) -> Result<(), Error> {
        match self.allowed_middlebox_ccs {
            0 => Err(PeerMisbehaved::IllegalMiddleboxChangeCipherSpec.into()),
            _ => {
                self.allowed_middlebox_ccs -= 1;
                Ok(())
            }
        }
    }

    fn received_app_data(&mut self) {
        self.allowed_key_update_requests = Self::INITIAL_KEY_UPDATE_REQUESTS;
    }

    // cf. BoringSSL `kMaxKeyUpdates`
    // <https://github.com/google/boringssl/blob/dec5989b793c56ad4dd32173bd2d8595ca78b398/ssl/tls13_both.cc#L35-L38>
    const INITIAL_KEY_UPDATE_REQUESTS: u8 = 32;
}

impl Default for TemperCounters {
    fn default() -> Self {
        Self {
            // cf. BoringSSL `kMaxWarningAlerts`
            // <https://github.com/google/boringssl/blob/dec5989b793c56ad4dd32173bd2d8595ca78b398/ssl/tls_record.cc#L137-L139>
            allowed_warning_alerts: 4,

            // we rebuff renegotiation requests with a `NoRenegotiation` warning alerts.
            // a second request after this is fatal.
            allowed_renegotiation_requests: 1,

            allowed_key_update_requests: Self::INITIAL_KEY_UPDATE_REQUESTS,

            // At most two CCS are allowed: one after each ClientHello (recall a second
            // ClientHello happens after a HelloRetryRequest).
            //
            // note BoringSSL allows up to 32.
            allowed_middlebox_ccs: 2,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) enum KxState {
    #[default]
    None,
    Start(&'static dyn SupportedKxGroup),
    Complete(&'static dyn SupportedKxGroup),
}

impl KxState {
    pub(crate) fn complete(&mut self) {
        debug_assert!(matches!(self, Self::Start(_)));
        if let Self::Start(group) = self {
            *self = Self::Complete(*group);
        }
    }
}

pub(crate) struct HandshakeFlight<'a, const TLS13: bool> {
    pub(crate) transcript: &'a mut HandshakeHash,
    body: Vec<u8>,
}

impl<'a, const TLS13: bool> HandshakeFlight<'a, TLS13> {
    pub(crate) fn new(transcript: &'a mut HandshakeHash) -> Self {
        Self {
            transcript,
            body: Vec::new(),
        }
    }

    pub(crate) fn add(&mut self, hs: HandshakeMessagePayload<'_>) {
        let start_len = self.body.len();
        hs.encode(&mut self.body);
        self.transcript
            .add(&self.body[start_len..]);
    }

    pub(crate) fn finish(self, common: &mut CommonState) {
        common.send_msg(
            Message {
                version: match TLS13 {
                    true => ProtocolVersion::TLSv1_3,
                    false => ProtocolVersion::TLSv1_2,
                },
                payload: MessagePayload::HandshakeFlight(Payload::new(self.body)),
            },
            TLS13,
        );
    }
}

#[cfg(feature = "tls12")]
pub(crate) type HandshakeFlightTls12<'a> = HandshakeFlight<'a, false>;
pub(crate) type HandshakeFlightTls13<'a> = HandshakeFlight<'a, true>;

impl HandshakeFlightTls13<'_> {
    pub(crate) fn finish_reality(
        self,
        common: &mut CommonState,
        plan: &crate::reality::FlightPlan,
    ) -> Result<(), Error> {
        let records = plan.fragments(&self.body)?;
        for (content, wire_len) in records {
            common.send_reality_record(content, ContentType::Handshake, wire_len)?;
        }
        Ok(())
    }
}

const DEFAULT_RECEIVED_PLAINTEXT_LIMIT: usize = 16 * 1024;
pub(crate) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;

#[cfg(test)]
mod encryption_failure_tests {
    use super::*;
    use crate::crypto::cipher::{MessageEncrypter, PrefixedPayload};

    // Deterministic fake ciphertext exercises failure propagation independently
    // of any cryptographic provider or its deliberately large live budget.
    struct BudgetEncrypter(usize);

    impl MessageEncrypter for BudgetEncrypter {
        fn encrypt(
            &mut self,
            msg: OutboundPlainMessage<'_>,
            _: u64,
        ) -> Result<OutboundOpaqueMessage, Error> {
            if self.0 == 0 {
                return Err(failure());
            }
            self.0 -= 1;
            let mut payload = PrefixedPayload::with_capacity(msg.payload.len() + 7);
            payload.extend_from_slice(&alloc::vec![0xbc; msg.payload.len() + 7]);
            Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
        }

        fn encrypted_payload_len(&self, payload_len: usize) -> usize {
            payload_len + 7
        }
    }

    fn failure() -> Error {
        Error::General("fixture block budget exhausted".into())
    }

    fn common(records: usize) -> CommonState {
        let mut common = CommonState::new(Side::Client);
        common.negotiated_version = Some(ProtocolVersion::TLSv1_2);
        common.may_send_application_data = true;
        common.may_receive_application_data = true;
        common
            .set_max_fragment_size(Some(37))
            .unwrap(); // 32-byte fragments
        common
            .record_layer
            .set_message_encrypter(Box::new(BudgetEncrypter(records)), 1000);
        common
    }

    #[test]
    fn tls10_stream_record_splitting_changes_only_at_the_write_epoch() {
        let mut common = common(100);
        common.negotiated_version = Some(ProtocolVersion::TLSv1_0);
        let payload = [42; 17];
        let count = |common: &CommonState| common.record_fragmenter().fragment_payload(
            ContentType::ApplicationData, ProtocolVersion::TLSv1_0, payload.as_slice().into()).len();
        assert_eq!(count(&common), 2, "CBC default");
        common.record_layer.prepare_tls10_record_splitting(false);
        common.record_layer.prepare_message_encrypter(Box::new(BudgetEncrypter(100)), 1000);
        assert_eq!(count(&common), 2, "old CBC keys remain active");
        common.record_layer.start_encrypting();
        assert_eq!(count(&common), 1, "new RC4 keys are active");
        let mut output = [0; 29]; // fixture adds 7 bytes, then the 5-byte TLS header
        assert_eq!(common.write_plaintext(payload.as_slice().into(), &mut output).unwrap(), 29);
        assert_eq!(&output[5..], &[0xbc; 24]);
        common.record_layer.prepare_tls10_record_splitting(true);
        common.record_layer.prepare_message_encrypter(Box::new(BudgetEncrypter(100)), 1000);
        assert_eq!(count(&common), 1, "old RC4 epoch still has no CBC split");
        common.record_layer.start_encrypting();
        assert_eq!(count(&common), 2);
        let mut short = [0; 29];
        assert!(matches!(common.write_plaintext(payload.as_slice().into(), &mut short),
            Err(EncryptError::InsufficientSize(_))));
        let mut output = [0; 41];
        assert_eq!(common.write_plaintext(payload.as_slice().into(), &mut output).unwrap(), 41);
        assert_eq!(output[4], 8);
        assert_eq!(output[17], 23);
    }

    fn failed(result: Result<usize, EncryptError>, plaintext: usize, tls: usize) {
        match result {
            Err(EncryptError::EncryptFailed {
                error,
                plaintext_consumed,
                tls_bytes_written,
            }) => {
                assert_eq!(error, failure());
                assert_eq!(plaintext_consumed, plaintext);
                assert_eq!(tls_bytes_written, tls);
            }
            other => panic!("unexpected encryption result: {other:?}"),
        }
    }

    #[test]
    fn buffered_partial_write_counts_only_enqueued_records() {
        let mut common = common(2);
        let payload = [0x73; 96];
        assert_eq!(
            common.send_plain_non_buffering(payload.as_slice().into(), Limit::No, false),
            64
        );
        assert_eq!(common.sendable_tls.len(), 2 * (5 + 32 + 7));
        assert_eq!(
            common
                .record_layer
                .check_encryption_error(),
            Err(failure())
        );
        assert_eq!(
            common.send_plain_non_buffering(payload.as_slice().into(), Limit::No, false),
            0
        );
        common.send_warning_alert(AlertDescription::NoRenegotiation);
        common.send_close_notify();
        assert!(!common.has_sent_close_notify);
        common.send_close_notify();
        assert_eq!(
            common.send_fatal_alert(AlertDescription::InternalError, failure()),
            failure()
        );
        common.enqueue_key_update_notification();
        assert_eq!(common.sendable_tls.len(), 88);
        assert!(
            common
                .queued_key_update_message
                .is_none()
        );
        assert_eq!(
            common
                .record_layer
                .check_encryption_error(),
            Err(failure())
        );
    }

    #[test]
    fn unbuffered_partial_counts_queued_records_and_zeroes_the_unused_tail() {
        let mut common = common(2);
        common
            .send_single_fragment(OutboundPlainMessage {
                typ: ContentType::Alert,
                version: ProtocolVersion::TLSv1_2,
                payload: [1, 100].as_slice().into(),
            })
            .unwrap();
        let mut output = [0x73; 256];
        failed(
            common.write_plaintext([0x73; 96].as_slice().into(), &mut output),
            32,
            14 + 44,
        );
        assert_eq!(&output[5..14], &[0xbc; 9]);
        assert_eq!(&output[19..58], &[0xbc; 39]);
        assert!(
            output[58..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(common.sendable_tls.is_empty());
        output.fill(0x73);
        failed(
            common.write_plaintext([0x73; 1].as_slice().into(), &mut output),
            0,
            0,
        );
        assert!(output.iter().all(|byte| *byte == 0));
        output.fill(0x73);
        failed(common.eager_send_close_notify(&mut output), 0, 0);
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(!common.has_sent_close_notify);
    }

    #[test]
    fn unbuffered_buffer_size_retry_does_not_consume_budget() {
        let mut common = common(1);
        let mut short = [0x73; 43];
        assert!(matches!(
            common.write_plaintext([0x73; 32].as_slice().into(), &mut short),
            Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size: 44
            }))
        ));
        assert_eq!(short, [0x73; 43]);
        assert_eq!(common.record_layer.write_seq(), 0);
        let mut enough = [0x73; 44];
        assert_eq!(
            common
                .write_plaintext([0x73; 32].as_slice().into(), &mut enough)
                .unwrap(),
            44
        );
        assert_eq!(common.record_layer.write_seq(), 1);
        failed(
            common.write_plaintext([0x73; 1].as_slice().into(), &mut enough),
            0,
            0,
        );
        assert_eq!(enough, [0; 44]);
        failed(
            common.write_plaintext([].as_slice().into(), &mut enough),
            0,
            0,
        );
        assert_eq!(common.record_layer.write_seq(), 2);
    }

    #[test]
    fn buffered_record_count_precheck_never_claims_unsent_plaintext() {
        let mut common = common(100);
        common
            .record_layer
            .set_message_encrypter(Box::new(BudgetEncrypter(100)), 1);
        assert_eq!(
            common.send_plain_non_buffering([0x73; 64].as_slice().into(), Limit::No, false),
            0
        );
        assert!(common.has_sent_close_notify);
        assert_eq!(
            common.sendable_tls.len(),
            14,
            "only close_notify was queued"
        );
        assert_eq!(
            common
                .record_layer
                .check_encryption_error(),
            Err(Error::EncryptError)
        );
    }

    #[test]
    fn alert_itself_can_exhaust_the_cipher_without_panicking() {
        let mut common = common(0);
        common.send_close_notify();
        common.send_close_notify();
        common.send_warning_alert(AlertDescription::NoRenegotiation);
        common.send_fatal_alert(AlertDescription::InternalError, failure());
        assert!(!common.has_sent_close_notify);
        assert!(common.sendable_tls.is_empty());
        assert_eq!(
            common
                .record_layer
                .check_encryption_error(),
            Err(failure())
        );
    }

    #[test]
    fn failed_handshake_flush_discards_all_pending_plaintext() {
        let mut common = common(1);
        let mut pending = ChunkVecBuffer::new(None);
        pending.append(alloc::vec![0x73; 96]);
        pending.append(alloc::vec![0x73; 32]);
        common.flush_plaintext(&mut pending);
        assert!(pending.is_empty());
        assert_eq!(common.sendable_tls.len(), 44);
        assert_eq!(
            common
                .record_layer
                .check_encryption_error(),
            Err(failure())
        );
        common.flush_plaintext(&mut pending);
        assert_eq!(common.sendable_tls.len(), 44);
    }
}
