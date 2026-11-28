use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use pki_types::ServerName;
pub(super) use server_hello::CompleteServerHelloHandling;
use subtle::ConstantTimeEq;

use super::client_conn::ClientConnectionData;
use super::hs::ClientContext;
use crate::check::{inappropriate_handshake_message, inappropriate_message};
use crate::client::common::{ClientAuthDetails, ServerCertDetails};
use crate::client::{hs, ClientConfig};
use crate::common_state::{CommonState, HandshakeKind, KxState, Side, State};
use crate::conn::kernel::{Direction, KernelContext, KernelState};
use crate::conn::ConnectionRandoms;
use crate::crypto::KeyExchangeAlgorithm;
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warn};
use crate::msgs::base::{Payload, PayloadU16, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::handshake::{
    CertificateChain, ClientDhParams, ClientEcdhParams, ClientKeyExchangeParams,
    HandshakeMessagePayload, HandshakePayload, NewSessionTicketPayload,
    NewSessionTicketPayloadTls13, ServerKeyExchangeParams, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::sign::Signer;
use crate::suites::{PartiallyExtractedSecrets, SupportedCipherSuite};
use crate::sync::Arc;
use crate::tls12::{self, ConnectionSecrets, Tls12CipherSuite};
use crate::verify::{self, DigitallySignedStruct};
use crate::ConnectionTrafficSecrets;

// Allocated only for opt-in pre-TLS1.3 connections able to renegotiate; freed
// after the single renegotiation. TLS 1.3 connections retain no such state.
#[derive(Debug)]
pub(super) struct Renegotiation {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    pub(super) client_verify: [u8; 12],
    server_verify: [u8; 12],
    using_ems: bool,
    pub(super) resumed: bool,
    previous_leaf: Option<pki_types::CertificateDer<'static>>,
    hello: Option<Box<crate::msgs::handshake::ClientHelloPayload>>,
}

mod server_hello {
    use super::*;
    use crate::client::hs::{ClientHelloInput, ClientSessionValue};
    use crate::msgs::handshake::ServerHelloPayload;

    pub(in crate::client) struct CompleteServerHelloHandling {
        pub(in crate::client) randoms: ConnectionRandoms,
        pub(in crate::client) transcript: HandshakeHash,
        pub(in crate::client) input: ClientHelloInput,
    }

    impl CompleteServerHelloHandling {
        pub(in crate::client) fn handle_server_hello(
            mut self,
            cx: &mut ClientContext<'_>,
            suite: &'static Tls12CipherSuite,
            server_hello: &ServerHelloPayload,
            tls13_supported: bool,
        ) -> hs::NextStateOrError<'static> {
            self.randoms
                .server
                .clone_from_slice(&server_hello.random.0[..]);

            // Look for TLS1.3 downgrade signal in server random
            // both the server random and TLS12_DOWNGRADE_SENTINEL are
            // public values and don't require constant time comparison
            let has_downgrade_marker = self.randoms.server[24..] == tls12::DOWNGRADE_SENTINEL;
            let old = crate::client::legacy::is_legacy(cx.common.record_version());
            let old_marker = self.randoms.server[24..] == *b"DOWNGRD\0";
            let offered12 = self
                .input
                .config
                .supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol);
            if (tls13_supported && (has_downgrade_marker || old_marker))
                || (old && (offered12 || tls13_supported) && old_marker)
            {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported,
                    )
                });
            }

            // If we didn't have an input session to resume, and we sent a session ID,
            // that implies we sent a TLS 1.3 legacy_session_id for compatibility purposes.
            // In this instance since we're now continuing a TLS 1.2 handshake the server
            // should not have echoed it back: it's a randomly generated session ID it couldn't
            // have known.
            if self.input.resuming.is_none()
                && !self.input.session_id.is_empty()
                && self.input.session_id == server_hello.session_id
            {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::ServerEchoedCompatibilitySessionId,
                    )
                });
            }

            let ClientHelloInput {
                config,
                server_name,
                renegotiation_hello,
                ..
            } = self.input;

            let resuming_session = self
                .input
                .resuming
                .and_then(|resuming| match resuming.value {
                    ClientSessionValue::Tls12(inner) => Some(inner),
                    ClientSessionValue::Tls13(_) => None,
                });

            // Doing EMS?
            let using_ems = server_hello
                .extended_master_secret_ack
                .is_some();
            if config.require_ems && !using_ems {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::ExtendedMasterSecretExtensionRequired,
                    )
                });
            }

            if cx.common.tls12_renegotiating {
                let previous = cx
                    .data
                    .tls12_renegotiation
                    .as_ref()
                    .expect("renegotiation context");
                let mut binding = [0; 24];
                binding[..12].copy_from_slice(&previous.client_verify);
                binding[12..].copy_from_slice(&previous.server_verify);
                if (previous.using_ems && !using_ems)
                    || server_hello
                        .renegotiation_info
                        .as_ref()
                        .map(|p| p.0.as_slice())
                        != Some(binding.as_slice())
                {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        Error::General(
                            "TLS 1.2 renegotiation changed EMS or the previous Finished binding"
                                .into(),
                        ),
                    ));
                }
            } else {
                if server_hello
                    .renegotiation_info
                    .as_ref()
                    .is_some_and(|p| !p.0.is_empty())
                {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        Error::General(
                            "initial TLS 1.2 renegotiation binding must be empty".into(),
                        ),
                    ));
                }
                if config.enable_tls12_renegotiation
                    && server_hello
                        .renegotiation_info
                        .is_some()
                {
                    cx.data.tls12_renegotiation = Some(Box::new(Renegotiation {
                        config: config.clone(),
                        server_name: server_name.clone(),
                        client_verify: [0; 12],
                        server_verify: [0; 12],
                        using_ems,
                        resumed: false,
                        previous_leaf: None,
                        hello: renegotiation_hello,
                    }));
                }
            }

            // Might the server send a ticket?
            let must_issue_new_ticket = if server_hello
                .session_ticket_ack
                .is_some()
            {
                debug!("Server supports tickets");
                true
            } else {
                false
            };

            // Might the server send a CertificateStatus between Certificate and
            // ServerKeyExchange?
            let may_send_cert_status = server_hello
                .certificate_status_request_ack
                .is_some();
            if may_send_cert_status {
                debug!("Server may staple OCSP response");
            }

            // See if we're successfully resuming.
            if let Some(resuming) = resuming_session {
                if resuming.session_id == server_hello.session_id {
                    debug!("Server agreed to resume");
                    // RFC7627 section 5.4 forbids renegotiation after an
                    // abbreviated handshake without extended master secret.
                    if !using_ems {
                        cx.data.tls12_renegotiation = None;
                    }

                    // Is the server telling lies about the ciphersuite?
                    if resuming.suite() != suite {
                        return Err(PeerMisbehaved::ResumptionOfferedWithVariedCipherSuite.into());
                    }

                    // And about EMS support?
                    if resuming.extended_ms() != using_ems {
                        return Err(PeerMisbehaved::ResumptionOfferedWithVariedEms.into());
                    }

                    let secrets =
                        ConnectionSecrets::new_resume(self.randoms, suite, resuming.secret());
                    config.key_log.log(
                        "CLIENT_RANDOM",
                        &secrets.randoms.client,
                        &secrets.master_secret,
                    );
                    cx.common
                        .start_encryption_tls12(&secrets, Side::Client);

                    let cert_verified = hs::verify_resumed_certificate_chain(
                        &config, cx, resuming.server_cert_chain(), &server_name,
                    )?;
                    cx.common.peer_certificates =
                        Some(resuming.server_cert_chain().clone().into_owned());
                    cx.common.handshake_kind = Some(HandshakeKind::Resumed);
                    let sig_verified = verify::HandshakeSignatureValid::assertion();

                    return if must_issue_new_ticket {
                        Ok(Box::new(ExpectNewTicket {
                            config,
                            secrets,
                            resuming_session: Some(resuming),
                            session_id: server_hello.session_id,
                            server_name,
                            using_ems,
                            transcript: self.transcript,
                            resuming: true,
                            cert_verified,
                            sig_verified,
                        }))
                    } else {
                        Ok(Box::new(ExpectCcs {
                            config,
                            secrets,
                            resuming_session: Some(resuming),
                            session_id: server_hello.session_id,
                            server_name,
                            using_ems,
                            transcript: self.transcript,
                            ticket: None,
                            resuming: true,
                            cert_verified,
                            sig_verified,
                        }))
                    };
                }
            }

            cx.common.handshake_kind = Some(HandshakeKind::Full);
            Ok(Box::new(ExpectCertificate {
                config,
                resuming_session: None,
                session_id: server_hello.session_id,
                server_name,
                randoms: self.randoms,
                using_ems,
                transcript: self.transcript,
                suite,
                may_send_cert_status,
                must_issue_new_ticket,
            }))
        }
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    pub(super) suite: &'static Tls12CipherSuite,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectCertificate {
    fn handle<'m>(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        self.transcript.add_message(&m);
        let server_cert_chain = require_handshake_msg_move!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::Certificate
        )?;

        if self.may_send_cert_status {
            Ok(Box::new(ExpectCertificateStatusOrServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        } else {
            let server_cert = ServerCertDetails::new(server_cert_chain, vec![]);

            Ok(Box::new(ExpectServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert,
                must_issue_new_ticket: self.must_issue_new_ticket,
            }))
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectCertificateStatusOrServerKx<'m> {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_chain: CertificateChain<'m>,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectCertificateStatusOrServerKx<'_> {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        // A static RSA server has no ServerKeyExchange. CertificateStatus is
        // still optional, followed by CertificateRequest or ServerHelloDone.
        if self.suite.kx == KeyExchangeAlgorithm::RSA
            && !matches!(
                m.payload,
                MessagePayload::Handshake {
                    parsed: HandshakeMessagePayload(HandshakePayload::CertificateStatus(..)),
                    ..
                }
            )
        {
            return Box::new(ExpectServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: ServerCertDetails::new(self.server_cert_chain, vec![]),
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m);
        }
        match m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerKeyExchange(..)),
                ..
            } => Box::new(ExpectServerKx {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: ServerCertDetails::new(self.server_cert_chain, vec![]),
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateStatus(..)),
                ..
            } => Box::new(ExpectCertificateStatus {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert_chain: self.server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m),
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::ServerKeyExchange,
                    HandshakeType::CertificateStatus,
                ],
            )),
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(ExpectCertificateStatusOrServerKx {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert_chain: self.server_cert_chain.into_owned(),
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

struct ExpectCertificateStatus<'a> {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_chain: CertificateChain<'a>,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectCertificateStatus<'_> {
    fn handle<'m>(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        self.transcript.add_message(&m);
        let server_cert_ocsp_response = require_handshake_msg_move!(
            m,
            HandshakeType::CertificateStatus,
            HandshakePayload::CertificateStatus
        )?
        .into_inner();

        trace!(
            "Server stapled OCSP response is {:?}",
            server_cert_ocsp_response
        );

        let server_cert = ServerCertDetails::new(self.server_cert_chain, server_cert_ocsp_response);

        Ok(Box::new(ExpectServerKx {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(ExpectCertificateStatus {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert_chain: self.server_cert_chain.into_owned(),
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

struct ExpectServerKx<'a> {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails<'a>,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectServerKx<'_> {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        if self.suite.kx == KeyExchangeAlgorithm::RSA {
            return Box::new(ExpectServerDoneOrCertReq {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: None,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m);
        }
        let opaque_kx = require_handshake_msg!(
            m,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;
        self.transcript.add_message(&m);

        let kx = if crate::client::legacy::is_legacy(cx.common.record_version()) {
            opaque_kx.unwrap_given_kxa_version(
                self.suite.kx,
                cx.common.record_version(),
                crate::client::legacy::signature_algorithm(self.suite)?,
            )
        } else {
            opaque_kx.unwrap_given_kxa(self.suite.kx)
        }
        .ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::DecodeError,
                InvalidMessage::MissingKeyExchange,
            )
        })?;

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        kx.params.encode(&mut kx_params);
        let server_kx = ServerKxDetails::new(kx_params, kx.dss);

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        {
            match &kx.params {
                ServerKeyExchangeParams::Ecdh(ecdhe) => {
                    debug!("ECDHE curve is {:?}", ecdhe.curve_params)
                }
                ServerKeyExchangeParams::Dh(dhe) => {
                    debug!("DHE params are p = {:?}, g = {:?}", dhe.dh_p, dhe.dh_g)
                }
            }
        }

        Ok(Box::new(ExpectServerDoneOrCertReq {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: Some(server_kx),
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(ExpectServerKx {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert.into_owned(),
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

fn emit_certificate(
    transcript: &mut HandshakeHash,
    cert_chain: CertificateChain<'static>,
    common: &mut CommonState,
) {
    let cert = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Certificate(
            cert_chain,
        ))),
    };

    transcript.add_message(&cert);
    common.send_msg(cert, common.record_layer.is_encrypting());
}

fn emit_client_kx(
    transcript: &mut HandshakeHash,
    kxa: KeyExchangeAlgorithm,
    common: &mut CommonState,
    pub_key: &[u8],
) {
    let mut buf = Vec::new();
    match kxa {
        KeyExchangeAlgorithm::ECDHE => ClientKeyExchangeParams::Ecdh(ClientEcdhParams {
            public: PayloadU8::new(pub_key.to_vec()),
        }),
        KeyExchangeAlgorithm::DHE => ClientKeyExchangeParams::Dh(ClientDhParams {
            public: PayloadU16::new(pub_key.to_vec()),
        }),
        KeyExchangeAlgorithm::RSA => {
            ClientKeyExchangeParams::Rsa(PayloadU16::new(pub_key.to_vec()))
        }
    }
    .encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ClientKeyExchange(pubkey),
        )),
    };

    transcript.add_message(&ckx);
    common.send_msg(ckx, common.record_layer.is_encrypting());
}

fn emit_certverify(
    transcript: &mut HandshakeHash,
    signer: &dyn Signer,
    common: &mut CommonState,
) -> Result<(), Error> {
    let message = transcript
        .take_handshake_buf()
        .ok_or_else(|| Error::General("Expected transcript".to_owned()))?;

    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            if crate::client::legacy::is_legacy(common.record_version()) {
                use crate::msgs::codec::Codec;
                HandshakePayload::Unknown((
                    HandshakeType::CertificateVerify,
                    Payload::new(
                        PayloadU16::<crate::msgs::base::MaybeEmpty>::new(body.signature().to_vec())
                            .get_encoding(),
                    ),
                ))
            } else {
                HandshakePayload::CertificateVerify(body)
            },
        )),
    };

    transcript.add_message(&m);
    common.send_msg(m, common.record_layer.is_encrypting());
    Ok(())
}

fn emit_ccs(common: &mut CommonState) {
    let ccs = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    common.send_msg(ccs, common.record_layer.is_encrypting());
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    cx: &mut ClientContext<'_>,
) {
    let vh = transcript.current_hash();
    let verify_data = secrets.client_verify_data(&vh);
    if let Some(previous) = cx.data.tls12_renegotiation.as_mut() {
        previous
            .client_verify
            .copy_from_slice(&verify_data);
    }
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            verify_data_payload,
        ))),
    };

    transcript.add_message(&f);
    cx.common.send_msg(f, true);
}

enum PreparedClientKx {
    Dh {
        active: Box<dyn crate::crypto::ActiveKeyExchange>,
        peer: Vec<u8>,
    },
    Rsa {
        ciphertext: Vec<u8>,
        premaster: crate::crypto::SharedSecret,
    },
}
impl PreparedClientKx {
    fn public(&self) -> &[u8] {
        match self {
            Self::Dh { active, .. } => active.pub_key(),
            Self::Rsa { ciphertext, .. } => ciphertext,
        }
    }
}

struct ServerKxDetails {
    kx_params: Vec<u8>,
    kx_sig: DigitallySignedStruct,
}

impl ServerKxDetails {
    fn new(params: Vec<u8>, sig: DigitallySignedStruct) -> Self {
        Self {
            kx_params: params,
            kx_sig: sig,
        }
    }
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
struct ExpectServerDoneOrCertReq<'a> {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails<'a>,
    server_kx: Option<ServerKxDetails>,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectServerDoneOrCertReq<'_> {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        if matches!(
            m.payload,
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequest(_)),
                ..
            }
        ) {
            Box::new(ExpectCertificateRequest {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
        } else {
            self.transcript.abandon_client_auth();

            Box::new(ExpectServerDone {
                config: self.config,
                resuming_session: self.resuming_session,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                client_auth: None,
                must_issue_new_ticket: self.must_issue_new_ticket,
            })
            .handle(cx, m)
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(ExpectServerDoneOrCertReq {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert.into_owned(),
            server_kx: self.server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

struct ExpectCertificateRequest<'a> {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails<'a>,
    server_kx: Option<ServerKxDetails>,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectCertificateRequest<'_> {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let certreq = require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequest
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {certreq:?}");

        // The RFC jovially describes the design here as 'somewhat complicated'
        // and 'somewhat underspecified'.  So thanks for that.
        //
        // We ignore certreq.certtypes as a result, since the information it contains
        // is entirely duplicated in certreq.sigschemes.

        // Filter out signature schemes that don't have an associated `SignatureAlgorithm`;
        // we use this to select only signature schemes that are allowed on 1.2.
        let signature_schemes = certreq
            .sigschemes
            .iter()
            .copied()
            .filter(|scheme| scheme.algorithm().is_some())
            .collect::<Vec<_>>();

        const NO_CONTEXT: Option<Vec<u8>> = None; // TLS 1.2 doesn't use a context.
        let no_compression = None; // or compression
        let client_auth = if crate::client::legacy::is_legacy(cx.common.record_version()) {
            match crate::client::legacy::resolve_client_auth(
                &self.config,
                &certreq.canames,
                &certreq.certtypes,
            ) {
                Some((certkey, signer)) => ClientAuthDetails::Verify {
                    certkey,
                    signer,
                    auth_context_tls13: None,
                    compressor: None,
                },
                None => ClientAuthDetails::Empty {
                    auth_context_tls13: None,
                },
            }
        } else {
            ClientAuthDetails::resolve(
                self.config.client_auth_cert_resolver.as_ref(),
                Some(&certreq.canames),
                &signature_schemes,
                NO_CONTEXT,
                no_compression,
            )
        };

        Ok(Box::new(ExpectServerDone {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
            must_issue_new_ticket: self.must_issue_new_ticket,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(ExpectCertificateRequest {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert.into_owned(),
            server_kx: self.server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

struct ExpectServerDone<'a> {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails<'a>,
    server_kx: Option<ServerKxDetails>,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectServerDone<'_> {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHelloDone),
                ..
            } => {}
            payload => {
                return Err(inappropriate_handshake_message(
                    &payload,
                    &[ContentType::Handshake],
                    &[HandshakeType::ServerHelloDone],
                ));
            }
        }

        let mut st = *self;
        st.transcript.add_message(&m);

        cx.common.check_aligned_handshake()?;

        trace!("Server cert is {:?}", st.server_cert.cert_chain);
        debug!("Server DNS name is {:?}", st.server_name);

        let suite = st.suite;

        // 1. Verify the cert chain.
        // 2. Verify that the top certificate signed their kx.
        // 3. If doing client auth, send our Certificate.
        // 4. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) derive the shared keys
        //    e) emit a CCS
        //    f) use the derived keys to start encryption
        // 5. emit a Finished, our first encrypted message under the new keys.

        // 1.
        let (end_entity, intermediates) = st
            .server_cert
            .cert_chain
            .split_first()
            .ok_or(Error::NoCertificatesPresented)?;

        if cx.common.tls12_renegotiating
            && cx
                .data
                .tls12_renegotiation
                .as_ref()
                .and_then(|p| p.previous_leaf.as_ref())
                != Some(end_entity)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                Error::General("TLS 1.2 peer certificate changed during renegotiation".into()),
            ));
        }
        let now = st.config.current_time()?;

        let cert_verified = st
            .config
            .verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                &st.server_name,
                &st.server_cert.ocsp_response,
                now,
            )
            .map_err(|err| cx.common.send_cert_verify_error_alert(err))?;

        // 2.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sig_verified = if let Some(server_kx) = &st.server_kx {
            // Check the signature is compatible with the ciphersuite.
            let sig = &server_kx.kx_sig;
            if !crate::client::legacy::is_legacy(cx.common.record_version())
                && st
                    .config
                    .client_hello_layout
                    .is_some_and(|p| !p.permits_signature(sig.scheme))
            {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
                ));
            }
            if !crate::client::legacy::is_legacy(cx.common.record_version())
                && matches!(st.config.client_hello_layout, Some(super::ClientHelloLayout::Browser360_7_5 | super::ClientHelloLayout::Randomized))
                && !cx.data.sent_signature_schemes.contains(&sig.scheme)
            {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
                ));
            }
            let Some(sig_alg) = sig.scheme.algorithm() else {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SignedKxWithWrongAlgorithm,
                ));
            };

            let mut message = Vec::new();
            message.extend_from_slice(&st.randoms.client);
            message.extend_from_slice(&st.randoms.server);
            message.extend_from_slice(&server_kx.kx_params);

            if !SupportedCipherSuite::from(suite).usable_for_signature_algorithm(sig_alg) {
                warn!(
                    "peer signed kx with wrong algorithm (got {:?} expect {:?})",
                    sig.scheme.algorithm(),
                    suite.sign
                );
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SignedKxWithWrongAlgorithm,
                ));
            }

            if crate::client::legacy::is_legacy(cx.common.record_version()) {
                st.config
                    .legacy_tls
                    .as_ref()
                    .ok_or_else(crate::client::legacy::invalid_config)?
                    .provider
                    .verify_signature(&message, end_entity, sig_alg, sig.signature())
                    .map_err(|err| cx.common.send_cert_verify_error_alert(err))?
            } else {
                st.config
                    .verifier
                    .verify_tls12_signature(&message, end_entity, sig)
                    .map_err(|err| cx.common.send_cert_verify_error_alert(err))?
            }
        } else if suite.kx == KeyExchangeAlgorithm::RSA {
            // Static RSA has no SKE signature. Authentication is completed by
            // the server Finished, which proves possession of the private key
            // needed to recover our fresh premaster. No application data is
            // released before that Finished is verified.
            verify::HandshakeSignatureValid::assertion()
        } else {
            return Err(InvalidMessage::MissingKeyExchange.into());
        };

        // 3.
        if let Some(client_auth) = &st.client_auth {
            let certs = match client_auth {
                ClientAuthDetails::Empty { .. } => CertificateChain::default(),
                ClientAuthDetails::Verify { certkey, .. } => CertificateChain(certkey.cert.clone()),
            };
            emit_certificate(&mut st.transcript, certs, cx.common);
        }

        // 4a. Static RSA encrypts a fresh premaster to the certified key;
        // ephemeral DH exchanges use the authenticated ServerKeyExchange.
        let kx = if let Some(server_kx) = &st.server_kx {
            let params = tls12::decode_kx_params::<ServerKeyExchangeParams>(
                st.suite.kx,
                cx.common,
                &server_kx.kx_params,
            )?;
            let group = match &params {
                ServerKeyExchangeParams::Ecdh(ecdh) => st
                    .config
                    .find_kx_group(ecdh.curve_params.named_group, ProtocolVersion::TLSv1_2),
                ServerKeyExchangeParams::Dh(dh) => st
                    .config
                    .provider
                    .kx_groups
                    .iter()
                    .find(|group| group.ffdhe_group() == Some(dh.as_ffdhe_group()))
                    .copied(),
            }
            .ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedKxGroup,
                )
            })?;
            cx.common.kx_state = KxState::Start(group);
            PreparedClientKx::Dh {
                active: group.start()?,
                peer: params.pub_key().to_vec(),
            }
        } else {
            let (ciphertext, premaster) = st
                .config
                .provider
                .key_provider
                .encrypt_tls12_rsa_premaster(
                    end_entity,
                    if st.config.legacy_enabled() {
                        st.config.legacy_client_version()
                    } else {
                        ProtocolVersion::TLSv1_2
                    },
                )
                .map_err(|err| cx.common.send_cert_verify_error_alert(err))?;
            // The TLS 1.3 offer may have prepared a share. It did not become
            // the negotiated key exchange when the server selected RSA.
            cx.common.kx_state = KxState::None;
            PreparedClientKx::Rsa {
                ciphertext,
                premaster,
            }
        };
        cx.common.peer_certificates = Some(st.server_cert.cert_chain.into_owned());

        // 4b.
        let mut transcript = st.transcript;
        emit_client_kx(&mut transcript, st.suite.kx, cx.common, kx.public());
        // Note: EMS handshake hash only runs up to ClientKeyExchange.
        let ems_seed = st
            .using_ems
            .then(|| transcript.current_hash());

        // 4c.
        if let Some(ClientAuthDetails::Verify { signer, .. }) = &st.client_auth {
            emit_certverify(&mut transcript, signer.as_ref(), cx.common)?;
        }

        // 4d. Derive secrets.
        // An alert at this point will be sent in plaintext.  That must happen
        // prior to the CCS, or else the peer will try to decrypt it.
        let secrets = match kx {
            PreparedClientKx::Dh { active, peer } => {
                let secrets = ConnectionSecrets::from_key_exchange(
                    active, &peer, ems_seed, st.randoms, suite,
                )
                .map_err(|err| {
                    cx.common
                        .send_fatal_alert(AlertDescription::IllegalParameter, err)
                })?;
                cx.common.kx_state.complete();
                secrets
            }
            PreparedClientKx::Rsa { premaster, .. } => {
                ConnectionSecrets::from_rsa_premaster(&premaster, ems_seed, st.randoms, suite)
            }
        };

        // 4e. CCS. We are definitely going to switch on encryption.
        emit_ccs(cx.common);

        // 4f. Now commit secrets.
        st.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            &secrets.master_secret,
        );
        cx.common
            .start_encryption_tls12(&secrets, Side::Client);
        cx.common
            .record_layer
            .start_encrypting();

        // 5.
        emit_finished(&secrets, &mut transcript, cx);

        if st.must_issue_new_ticket {
            Ok(Box::new(ExpectNewTicket {
                config: st.config,
                secrets,
                resuming_session: st.resuming_session,
                session_id: st.session_id,
                server_name: st.server_name,
                using_ems: st.using_ems,
                transcript,
                resuming: false,
                cert_verified,
                sig_verified,
            }))
        } else {
            Ok(Box::new(ExpectCcs {
                config: st.config,
                secrets,
                resuming_session: st.resuming_session,
                session_id: st.session_id,
                server_name: st.server_name,
                using_ems: st.using_ems,
                transcript,
                ticket: None,
                resuming: false,
                cert_verified,
                sig_verified,
            }))
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        Box::new(ExpectServerDone {
            config: self.config,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert.into_owned(),
            server_kx: self.server_kx,
            client_auth: self.client_auth,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

struct ExpectNewTicket {
    config: Arc<ClientConfig>,
    secrets: ConnectionSecrets,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    using_ems: bool,
    transcript: HandshakeHash,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl State<ClientConnectionData> for ExpectNewTicket {
    fn handle<'m>(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        self.transcript.add_message(&m);

        let nst = require_handshake_msg_move!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicket
        )?;

        Ok(Box::new(ExpectCcs {
            config: self.config,
            secrets: self.secrets,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: Some(nst),
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// -- Waiting for their CCS --
struct ExpectCcs {
    config: Arc<ClientConfig>,
    secrets: ConnectionSecrets,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: Option<NewSessionTicketPayload>,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl State<ClientConnectionData> for ExpectCcs {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::ChangeCipherSpec(..) => {}
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ChangeCipherSpec],
                ));
            }
        }
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        cx.common.check_aligned_handshake()?;

        // After this CCS, application records must wait for authenticated Finished.
        if cx.common.tls12_renegotiating {
            cx.common.may_receive_application_data = false;
        }
        // Note: msgs layer validates trivial contents of CCS.
        cx.common
            .record_layer
            .start_decrypting();

        Ok(Box::new(ExpectFinished {
            config: self.config,
            secrets: self.secrets,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: self.ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

struct ExpectFinished {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: Option<NewSessionTicketPayload>,
    secrets: ConnectionSecrets,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    // -- Waiting for their finished --
    fn save_session(&mut self, cx: &ClientContext<'_>) {
        if self.config.legacy_enabled() {
            return;
        }
        // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
        // original ticket again.
        let (mut ticket, lifetime) = match self.ticket.take() {
            Some(nst) => (nst.ticket, nst.lifetime_hint),
            None => (Arc::new(PayloadU16::empty()), 0),
        };

        if ticket.0.is_empty() {
            if let Some(resuming_session) = &mut self.resuming_session {
                ticket = resuming_session.ticket();
            }
        }

        if self.session_id.is_empty() && ticket.0.is_empty() {
            debug!("Session not saved: server didn't allocate id or ticket");
            return;
        }

        let Ok(now) = self.config.current_time() else {
            debug!("Could not get current time");
            return;
        };

        let session_value = persist::Tls12ClientSessionValue::new(
            self.secrets.suite(),
            self.session_id,
            ticket,
            self.secrets.master_secret(),
            cx.common
                .peer_certificates
                .clone()
                .unwrap_or_default(),
            &self.config.verifier,
            &self.config.client_auth_cert_resolver,
            now,
            lifetime,
            self.using_ems,
        );

        self.config
            .resumption
            .store
            .set_tls12_session(self.server_name.clone(), session_value);
    }
}

impl State<ClientConnectionData> for ExpectFinished {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        cx.common.check_aligned_handshake()?;

        // Work out what verify_data we expect.
        let vh = st.transcript.current_hash();
        let expect_verify_data = st.secrets.server_verify_data(&vh);

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let _fin_verified =
            match ConstantTimeEq::ct_eq(&expect_verify_data[..], finished.bytes()).into() {
                true => verify::FinishedMessageVerified::assertion(),
                false => {
                    return Err(cx
                        .common
                        .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
                }
            };

        if let Some(previous) = cx.data.tls12_renegotiation.as_mut() {
            previous
                .server_verify
                .copy_from_slice(finished.bytes());
            previous.resumed = st.resuming;
        }
        // Hash this message too.
        st.transcript.add_message(&m);

        st.save_session(cx);

        if st.resuming {
            emit_ccs(cx.common);
            cx.common
                .record_layer
                .start_encrypting();
            emit_finished(&st.secrets, &mut st.transcript, cx);
        }

        if cx.common.tls12_renegotiating {
            cx.common.tls12_renegotiating = false;
            cx.data.tls12_renegotiation = None;
        }
        cx.common
            .start_traffic(&mut cx.sendable_plaintext);
        Ok(Box::new(ExpectTraffic {
            can_renegotiate: cx.data.tls12_renegotiation.is_some(),
            using_ems: st.using_ems,
            secrets: st.secrets,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified,
        }))
    }

    // we could not decrypt the encrypted handshake message with session resumption
    // this might mean that the ticket was invalid for some reason, so we remove it
    // from the store to restart a session from scratch
    fn handle_decrypt_error(&self) {
        if self.resuming {
            self.config
                .resumption
                .store
                .remove_tls12_session(&self.server_name);
        }
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

// -- Traffic transit state --
struct ExpectTraffic {
    can_renegotiate: bool,
    using_ems: bool,
    secrets: ConnectionSecrets,
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl State<ClientConnectionData> for ExpectTraffic {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> hs::NextStateOrError<'m>
    where
        Self: 'm,
    {
        if m.is_handshake_type(HandshakeType::HelloRequest) && self.can_renegotiate {
            cx.common.check_aligned_handshake()?;
            let previous = cx
                .data
                .tls12_renegotiation
                .as_mut()
                .expect("renegotiation context");
            previous.previous_leaf = cx
                .common
                .peer_certificates
                .as_ref()
                .and_then(|p| p.first())
                .cloned();
            let mut config = (*previous.config).clone();
            config.resumption = crate::client::Resumption::disabled();
            config.enable_early_data = false;
            let server_name = previous.server_name.clone();
            let cached_hello = previous.hello.take();
            let extra = crate::msgs::handshake::ClientExtensionsInput {
                protocols: Some(
                    config
                        .alpn_protocols
                        .iter()
                        .cloned()
                        .map(crate::msgs::handshake::ProtocolName::from)
                        .collect(),
                ),
                ..Default::default()
            };
            cx.common.may_send_application_data = false;
            cx.common.tls12_renegotiating = true;
            cx.common.handshake_kind = None;
            cx.common.kx_state = KxState::default();
            cx.data.pending_application_settings = None;
            cx.data.send_application_settings = false;
            if let Some(hello) = cached_hello {
                return hs::start_cached_renegotiation(hello, server_name, Arc::new(config), cx);
            }
            let input = hs::ClientHelloInput::new(server_name, &extra, cx, Arc::new(config))?;
            return input.start_handshake(extra, cx);
        }
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx
                .common
                .take_received_plaintext(payload),
            payload => {
                return Err(inappropriate_message(
                    &payload,
                    &[ContentType::ApplicationData],
                ));
            }
        }
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        if !self.using_ems {
            return Err(Error::General(
                "TLS 1.2 key exporters require extended master secret".into(),
            ));
        }
        self.secrets
            .export_keying_material(output, label, context);
        Ok(())
    }

    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        self.secrets
            .extract_secrets(Side::Client)
    }

    fn can_handle_renegotiation(&self) -> bool {
        self.can_renegotiate
    }

    fn into_external_state(self: Box<Self>) -> Result<Box<dyn KernelState + 'static>, Error> {
        if self.can_renegotiate {
            return Err(Error::General(
                "TLS 1.2 renegotiation prevents kernel handoff".into(),
            ));
        }
        Ok(self)
    }

    fn into_owned(self: Box<Self>) -> hs::NextState<'static> {
        self
    }
}

impl KernelState for ExpectTraffic {
    fn update_secrets(&mut self, _: Direction) -> Result<ConnectionTrafficSecrets, Error> {
        Err(Error::General(
            "TLS 1.2 connections do not support traffic secret updates".into(),
        ))
    }

    fn handle_new_session_ticket(
        &mut self,
        _cx: &mut KernelContext<'_>,
        _message: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        Err(Error::General(
            "TLS 1.2 session tickets may not be sent once the handshake has completed".into(),
        ))
    }
}
