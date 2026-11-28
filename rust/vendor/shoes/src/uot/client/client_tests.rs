use super::*;
use futures::future::poll_fn;
use tokio::io::{AsyncReadExt,AsyncWriteExt};

#[derive(Debug)]
struct Plain(u8);
#[async_trait]
impl TcpClientHandler for Plain {
    async fn setup_client_tcp_stream(&self,stream:Box<dyn AsyncStream>,target:ResolvedLocation)->io::Result<TcpClientSetupResult> {
        assert_eq!(target.location().to_string(),if self.0==1 {"sp.udp-over-tcp.arpa:0"}else{"sp.v2.udp-over-tcp.arpa:0"});
        Ok(TcpClientSetupResult{client_stream:stream,early_data:None})
    }
}

#[tokio::test]
async fn v1_and_v2_match_wire_fixtures_and_preserve_empty_packets() {
    for version in [1,2] {
        let (client,mut peer)=tokio::io::duplex(256);
        let handler=Handler::new(version,Box::new(Plain(version))).unwrap();
        let target=ResolvedLocation::new(NetLocation::from_str("dns.test:53",None).unwrap());
        let mut stream=handler.setup_client_udp_bidirectional(Box::new(client),target).await.unwrap();
        let job=tokio::spawn(async move {
            if version==2 {
                let mut request=[0;13];peer.read_exact(&mut request).await.unwrap();
                assert_eq!(&request,b"\x01\x03\x08dns.test\x00\x35");
            }
            for payload in [b"query".as_slice(),b""] {
                if version==1 {
                    let mut address=[0;12];peer.read_exact(&mut address).await.unwrap();
                    assert_eq!(&address,b"\x02\x08dns.test\x00\x35");
                }
                assert_eq!(peer.read_u16().await.unwrap() as usize,payload.len());
                let mut received=vec![0;payload.len()];peer.read_exact(&mut received).await.unwrap();assert_eq!(received,payload);
                // A domain request legitimately returns the resolved source IP.
                if version==1 {peer.write_all(b"\x00\xc0\x00\x02\x01\x00\x35").await.unwrap();}
                peer.write_u16(payload.len() as u16).await.unwrap();peer.write_all(payload).await.unwrap();
            }
        });
        for payload in [b"query".as_slice(),b""] {
            poll_fn(|cx|Pin::new(&mut *stream).poll_write_message(cx,payload)).await.unwrap();
            poll_fn(|cx|Pin::new(&mut *stream).poll_flush_message(cx)).await.unwrap();
            let mut storage=[0;64];let mut out=ReadBuf::new(&mut storage);
            poll_fn(|cx|Pin::new(&mut *stream).poll_read_message(cx,&mut out)).await.unwrap();assert_eq!(out.filled(),payload);
            assert!(!stream.read_message_eof_on_empty());
        }
        job.await.unwrap();
        let mut storage=[0;64];let mut out=ReadBuf::new(&mut storage);
        poll_fn(|cx|Pin::new(&mut *stream).poll_read_message(cx,&mut out)).await.unwrap();assert!(out.filled().is_empty());
        assert!(stream.read_message_eof_on_empty());
    }
}

#[tokio::test]
async fn malformed_or_truncated_packet_addresses_return_errors_without_panics() {
    for (wire,capacity) in [
        (b"\x00\xc0\x00\x02\x01\x00\x35\x00\x04data".as_slice(),2),
        (b"\x00\xc0\x00\x02\x01\x00\x35\x00\x04d".as_slice(),16),
        (b"\x00\xc0\x00\x02\x01\x00\x36\x00\x01x".as_slice(),16),
    ] {
        let (client,mut peer)=tokio::io::duplex(256);
        peer.write_all(wire).await.unwrap();drop(peer);
        let mut stream=Handler::new(1,Box::new(Plain(1))).unwrap()
            .setup_client_udp_bidirectional(Box::new(client),NetLocation::from_str("192.0.2.1:53",None).unwrap().into()).await.unwrap();
        let mut storage=vec![0;capacity];let mut out=ReadBuf::new(&mut storage);
        assert!(poll_fn(|cx|Pin::new(&mut *stream).poll_read_message(cx,&mut out)).await.is_err());
    }
}
