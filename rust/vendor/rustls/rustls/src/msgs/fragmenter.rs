use crate::enums::{ContentType, ProtocolVersion};
use crate::msgs::message::{OutboundChunks, OutboundPlainMessage, PlainMessage};
use crate::Error;
pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;
pub(crate) const PACKET_OVERHEAD: usize = 1 + 2 + 2;
pub(crate) const MAX_FRAGMENT_SIZE: usize = MAX_FRAGMENT_LEN + PACKET_OVERHEAD;

pub struct MessageFragmenter {
    max_frag: usize,
    split_tls10: bool,
}

impl Default for MessageFragmenter {
    fn default() -> Self {
        Self {
            max_frag: MAX_FRAGMENT_LEN,
            split_tls10: true,
        }
    }
}

impl MessageFragmenter {
    /// Combine the local write preference with the active key epoch's peer
    /// receive limit. The caller has already removed the TLS1.3 content type.
    pub(crate) fn with_limit(&self, content_limit: usize) -> Self {
        debug_assert!(content_limit > 0);
        Self { max_frag: self.max_frag.min(content_limit), split_tls10: self.split_tls10 }
    }

    /// The record owner selects this from the negotiated suite. CBC keeps its
    /// TLS1.0 first-byte split; a stream cipher does not need that CBC mitigation.
    pub(crate) fn with_tls10_splitting(mut self, enabled: bool) -> Self {
        self.split_tls10 = enabled;
        self
    }

    /// Take `msg` and fragment it into new messages with the same type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `msg`.
    pub fn fragment_message<'a>(
        &self,
        msg: &'a PlainMessage,
    ) -> impl Iterator<Item = OutboundPlainMessage<'a>> + 'a {
        self.fragment_payload(msg.typ, msg.version, msg.payload.bytes().into())
    }

    /// Take `payload` and fragment it into new messages with given type and version.
    ///
    /// Each returned message size is no more than `max_frag`.
    ///
    /// Return an iterator across those messages.
    ///
    /// Payloads are borrowed from `payload`.
    pub(crate) fn fragment_payload<'a>(
        &self,
        typ: ContentType,
        version: ProtocolVersion,
        payload: OutboundChunks<'a>,
    ) -> impl ExactSizeIterator<Item = OutboundPlainMessage<'a>> {
        Chunker::new(
            payload,
            self.max_frag,
            self.split_tls10 && typ == ContentType::ApplicationData && version == ProtocolVersion::TLSv1_0,
        )
        .map(move |payload| OutboundPlainMessage {
            typ,
            version,
            payload,
        })
    }

    /// Set the maximum fragment size that will be produced.
    ///
    /// This includes overhead. A `max_fragment_size` of 10 will produce TLS fragments
    /// up to 10 bytes long.
    ///
    /// A `max_fragment_size` of `None` sets the highest allowable fragment size.
    ///
    /// Returns BadMaxFragmentSize if the size is smaller than 32 or larger than 16389.
    pub fn set_max_fragment_size(&mut self, max_fragment_size: Option<usize>) -> Result<(), Error> {
        self.max_frag = match max_fragment_size {
            Some(sz @ 32..=MAX_FRAGMENT_SIZE) => sz - PACKET_OVERHEAD,
            None => MAX_FRAGMENT_LEN,
            _ => return Err(Error::BadMaxFragmentSize),
        };
        Ok(())
    }
}

/// An iterator over borrowed fragments of a payload
struct Chunker<'a> {
    payload: OutboundChunks<'a>,
    limit: usize,
    first_byte: bool,
}

impl<'a> Chunker<'a> {
    fn new(payload: OutboundChunks<'a>, limit: usize, first_byte: bool) -> Self {
        let first_byte = first_byte && payload.len() > 1;
        Self {
            payload,
            limit,
            first_byte,
        }
    }
}

impl<'a> Iterator for Chunker<'a> {
    type Item = OutboundChunks<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.payload.is_empty() {
            return None;
        }

        let limit = if core::mem::take(&mut self.first_byte) {
            1
        } else {
            self.limit
        };
        let (before, after) = self.payload.split_at(limit);
        self.payload = after;
        Some(before)
    }
}

impl ExactSizeIterator for Chunker<'_> {
    fn len(&self) -> usize {
        if self.first_byte {
            1 + (self.payload.len() - 1).div_ceil(self.limit)
        } else {
            self.payload.len().div_ceil(self.limit)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::prelude::v1::*;
    use std::vec;

    use super::{MessageFragmenter, PACKET_OVERHEAD};
    use crate::enums::{ContentType, ProtocolVersion};
    use crate::msgs::base::Payload;
    use crate::msgs::message::{OutboundChunks, OutboundPlainMessage, PlainMessage};

    fn msg_eq(
        m: &OutboundPlainMessage<'_>,
        total_len: usize,
        typ: &ContentType,
        version: &ProtocolVersion,
        bytes: &[u8],
    ) {
        assert_eq!(&m.typ, typ);
        assert_eq!(&m.version, version);
        assert_eq!(m.payload.to_vec(), bytes);

        let buf = m.to_unencrypted_opaque().encode();

        assert_eq!(total_len, buf.len());
    }

    #[test]
    fn stream_cipher_fragments_have_exact_unsplit_counts() {
        for limit in [27, 1019, 16384] {
            for length in [0, 1, 2, limit, limit+1, limit*2+1] {
                let bytes = vec![42; length];
                let fragmenter = MessageFragmenter::default().with_limit(limit).with_tls10_splitting(false);
                let mut parts = fragmenter.fragment_payload(ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_0, bytes.as_slice().into());
                assert_eq!(parts.len(), length.div_ceil(limit));
                let mut received = Vec::new();
                while let Some(part) = parts.next() {
                    assert_eq!(part.payload.len(), (length-received.len()).min(limit));
                    part.payload.copy_to_vec(&mut received);
                    assert_eq!(parts.len(), (length-received.len()).div_ceil(limit));
                }
                assert_eq!(received, bytes);
            }
        }
    }

    #[test]
    fn tls10_application_splitting_preserves_exact_sizes_and_payloads() {
        for length in [0, 1, 2, 16384, 16385, 32769] {
            let data = vec![7; length];
            let frag = MessageFragmenter::default();
            for version in [
                ProtocolVersion::TLSv1_0,
                ProtocolVersion::TLSv1_1,
                ProtocolVersion::TLSv1_2,
            ] {
                for typ in [ContentType::ApplicationData, ContentType::Handshake] {
                    let mut parts = frag.fragment_payload(typ, version, data.as_slice().into());
                    let expected = if length > 1
                        && version == ProtocolVersion::TLSv1_0
                        && typ == ContentType::ApplicationData
                    {
                        1 + (length - 1).div_ceil(16384)
                    } else {
                        length.div_ceil(16384)
                    };
                    assert_eq!(parts.len(), expected);
                    let mut combined = Vec::new();
                    for index in 0..expected {
                        assert_eq!(parts.len(), expected - index);
                        let part = parts.next().unwrap();
                        if index == 0
                            && expected > 1
                            && version == ProtocolVersion::TLSv1_0
                            && typ == ContentType::ApplicationData
                        {
                            assert_eq!(part.payload.len(), 1);
                        }
                        assert_eq!(part.version, version);
                        combined.extend(part.payload.to_vec());
                    }
                    assert!(parts.next().is_none());
                    assert_eq!(combined, data);
                }
            }
        }
    }

    #[test]
    fn smoke() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let data: Vec<u8> = (1..70u8).collect();
        let m = PlainMessage {
            typ,
            version,
            payload: Payload::new(data),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 3);
        msg_eq(
            &q[0],
            32,
            &typ,
            &version,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27,
            ],
        );
        msg_eq(
            &q[1],
            32,
            &typ,
            &version,
            &[
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                49, 50, 51, 52, 53, 54,
            ],
        );
        msg_eq(
            &q[2],
            20,
            &typ,
            &version,
            &[55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
        );
    }

    #[test]
    fn non_fragment() {
        let m = PlainMessage {
            typ: ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(b"\x01\x02\x03\x04\x05\x06\x07\x08".to_vec()),
        };

        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(32))
            .unwrap();
        let q = frag
            .fragment_message(&m)
            .collect::<Vec<_>>();
        assert_eq!(q.len(), 1);
        msg_eq(
            &q[0],
            PACKET_OVERHEAD + 8,
            &ContentType::Handshake,
            &ProtocolVersion::TLSv1_2,
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
        );
    }

    #[test]
    fn fragment_multiple_slices() {
        let typ = ContentType::Handshake;
        let version = ProtocolVersion::TLSv1_2;
        let payload_owner: Vec<&[u8]> = vec![&[b'a'; 8], &[b'b'; 12], &[b'c'; 32], &[b'd'; 20]];
        let borrowed_payload = OutboundChunks::new(&payload_owner);
        let mut frag = MessageFragmenter::default();
        frag.set_max_fragment_size(Some(37)) // 32 + packet overhead
            .unwrap();

        let fragments = frag
            .fragment_payload(typ, version, borrowed_payload)
            .collect::<Vec<_>>();
        assert_eq!(fragments.len(), 3);
        msg_eq(
            &fragments[0],
            37,
            &typ,
            &version,
            b"aaaaaaaabbbbbbbbbbbbcccccccccccc",
        );
        msg_eq(
            &fragments[1],
            37,
            &typ,
            &version,
            b"ccccccccccccccccccccdddddddddddd",
        );
        msg_eq(&fragments[2], 13, &typ, &version, b"dddddddd");
    }
}
