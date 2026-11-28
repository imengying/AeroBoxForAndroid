//! RFC 8449 client negotiation. Receive capacity is the full protocol limit;
//! existing authenticated record decoders enforce it, including TLS1.3 padding.
use crate::{CommonState, Error};
use crate::enums::AlertDescription;

pub(super) fn receive(common: &mut CommonState, offered: Option<u16>) -> Result<(), Error> {
    let tls13 = common.is_tls13();
    let maximum = if tls13 { 16385 } else { 16384 };
    let limit = usize::from(offered.unwrap_or(maximum));
    if !(64..=usize::from(maximum)).contains(&limit) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            Error::General("invalid peer record_size_limit".into()),
        ));
    }
    if tls13 {
        // The current handshake key, subsequent application keys, and KeyUpdate
        // epochs all retain this content limit. There is no permitted 0-RTT.
        common.record_layer.set_outgoing_plaintext_limit(limit - 1);
    } else {
        // Keep the previous epoch's limit for renegotiation until outgoing CCS.
        // An omitted extension restores the default only for the new keys.
        common.pending_tls12_record_size_limit = limit;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec, vec::Vec};
    use crate::common_state::Side;
    use crate::crypto::cipher::{MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload};
    use crate::msgs::message::OutboundChunks;
    use crate::{ContentType, ProtocolVersion};

    struct PassThrough;
    impl MessageEncrypter for PassThrough {
        fn encrypt(&mut self, msg: OutboundPlainMessage<'_>, _: u64) -> Result<OutboundOpaqueMessage, Error> {
            let mut payload = PrefixedPayload::with_capacity(msg.payload.len());
            payload.extend_from_chunks(&msg.payload);
            Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
        }
        fn encrypted_payload_len(&self, n: usize) -> usize { n }
    }
    fn state(version: ProtocolVersion) -> CommonState {
        let mut common = CommonState::new(Side::Client);
        common.negotiated_version = Some(version);
        common
    }
    fn plain(bytes: &[u8]) -> OutboundPlainMessage<'_> {
        OutboundPlainMessage { typ: ContentType::ApplicationData, version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(bytes) }
    }

    #[test]
    fn tls13_limit_includes_content_type_and_survives_key_epochs() {
        for limit in [64u16, 65, 512, 16384, 16385] {
            let mut common = state(ProtocolVersion::TLSv1_3);
            common.record_layer.set_message_encrypter(Box::new(PassThrough), 100);
            receive(&mut common, Some(limit)).unwrap();
            for _ in 0..3 {
                assert_eq!(common.record_layer.max_outgoing_plaintext_len(), usize::from(limit) - 1);
                common.record_layer.encrypt_outgoing(plain(&vec![0; usize::from(limit) - 1])).unwrap();
                common.record_layer.set_message_encrypter(Box::new(PassThrough), 100);
            }
            assert_eq!(common.record_layer.encrypt_outgoing(plain(&vec![0; usize::from(limit)])).unwrap_err(), Error::EncryptError);
            common.record_layer.set_message_encrypter(Box::new(PassThrough), 100);
            assert_eq!(common.record_layer.encrypt_outgoing(plain(b"x")).unwrap_err(), Error::EncryptError);
        }
    }

    #[test]
    fn tls12_changed_or_omitted_limit_waits_for_outgoing_ccs() {
        for next in [None, Some(64), Some(512), Some(16384)] {
            let mut common = state(ProtocolVersion::TLSv1_2);
            common.record_layer.set_message_encrypter(Box::new(PassThrough), 100);
            common.record_layer.set_outgoing_plaintext_limit(64);
            receive(&mut common, next).unwrap();
            let expected = usize::from(next.unwrap_or(16384));
            assert_eq!(common.pending_tls12_record_size_limit, expected);
            assert_eq!(common.record_layer.max_outgoing_plaintext_len(), 64);
            common.record_layer.prepare_message_encrypter(Box::new(PassThrough), 100);
            common.record_layer.prepare_outgoing_plaintext_limit(common.pending_tls12_record_size_limit);
            assert_eq!(common.record_layer.max_outgoing_plaintext_len(), 64);
            common.record_layer.encrypt_outgoing(plain(&[0; 64])).unwrap();
            common.record_layer.start_encrypting();
            assert_eq!(common.record_layer.max_outgoing_plaintext_len(), expected);
            common.record_layer.encrypt_outgoing(plain(&vec![0; expected])).unwrap();
        }
    }

    #[test]
    fn invalid_values_fail_with_illegal_parameter_and_no_limit_change() {
        for version in [ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3] {
            let maximum = if version == ProtocolVersion::TLSv1_3 { 16385 } else { 16384 };
            for limit in [0, 1, 63, maximum + 1, u16::MAX] {
                let mut common = state(version);
                assert!(receive(&mut common, Some(limit)).is_err());
                assert_eq!(common.record_layer.max_outgoing_plaintext_len(), 16384);
                let mut output = [0u8; 128];
                let n = common.sendable_tls.read(&mut output).unwrap();
                assert_eq!(&output[..n], &[21, 3, 3, 0, 2, 2, 47]);
            }
        }
    }

    #[test]
    fn missing_tls13_extension_keeps_full_capacity() {
        let mut common = state(ProtocolVersion::TLSv1_3);
        receive(&mut common, None).unwrap();
        assert_eq!(common.record_layer.max_outgoing_plaintext_len(), 16384);
    }

    #[test]
    fn unbuffered_size_retry_counts_negotiated_fragments_and_preserves_local_cap() {
        for (local, cap) in [(None, 63usize), (Some(37), 32)] {
            let mut common = state(ProtocolVersion::TLSv1_3);
            common.may_send_application_data = true;
            common.record_layer.set_message_encrypter(Box::new(PassThrough), 100);
            common.set_max_fragment_size(local).unwrap();
            receive(&mut common, Some(64)).unwrap();
            let bytes = [7; 190];
            let records = bytes.len().div_ceil(cap);
            let required = bytes.len() + records * 5;
            let mut short = vec![0xa5; required - 1];
            match common.write_plaintext(bytes.as_slice().into(), &mut short) {
                Err(crate::unbuffered::EncryptError::InsufficientSize(error)) => assert_eq!(error.required_size, required),
                other => panic!("incorrect size result: {other:?}"),
            }
            assert!(short.iter().all(|value| *value == 0xa5));
            assert_eq!(common.record_layer.write_seq(), 0);
            let mut output = vec![0; required];
            assert_eq!(common.write_plaintext(bytes.as_slice().into(), &mut output).unwrap(), required);
            assert_eq!(common.record_layer.write_seq(), records as u64);
            let mut remaining = output.as_slice();
            let mut plaintext = Vec::new();
            while !remaining.is_empty() {
                let length = usize::from(u16::from_be_bytes([remaining[3], remaining[4]]));
                assert!(length <= cap);
                plaintext.extend_from_slice(&remaining[5..5 + length]);
                remaining = &remaining[5 + length..];
            }
            assert_eq!(plaintext, bytes);
        }
    }

    #[test]
    fn key_update_record_prediction_uses_negotiated_fragment_size() {
        let mut common = state(ProtocolVersion::TLSv1_3);
        common.record_layer.set_message_encrypter(Box::new(PassThrough), 4);
        receive(&mut common, Some(64)).unwrap();
        common.record_layer.encrypt_outgoing(plain(b"x")).unwrap();
        common.request_key_update_for([7; 190].as_slice().into());
        assert!(common.refresh_traffic_keys_pending);
    }

    #[test]
    fn padded_record_cannot_bypass_limit_and_failure_is_permanent() {
        let mut common = state(ProtocolVersion::TLSv1_3);
        common.record_layer.set_message_encrypter(Box::new(PassThrough), 100);
        receive(&mut common, Some(64)).unwrap();
        assert_eq!(common.record_layer.encrypt_outgoing_with_padding(plain(&[0; 63]), 1).unwrap_err(), Error::EncryptError);
        common.record_layer.set_message_encrypter(Box::new(PassThrough), 100);
        assert_eq!(common.record_layer.encrypt_outgoing(plain(b"x")).unwrap_err(), Error::EncryptError);
        assert_eq!(common.record_layer.write_seq(), 0);
    }

}
