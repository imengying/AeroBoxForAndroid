use super::*;

#[async_trait]
impl TcpClientHandler for VmessTcpClientHandler {
    async fn setup_client_tcp_stream(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<TcpClientSetupResult> {
        Ok(TcpClientSetupResult {
            client_stream: Box::new(
                self.setup_stream(stream, target.into_location(), COMMAND_TCP)
                    .await?,
            ),
            early_data: None,
        })
    }

    fn supports_udp_over_tcp(&self) -> bool {
        self.udp_enabled
    }

    async fn setup_client_udp_bidirectional(
        &self,
        stream: Box<dyn AsyncStream>,
        target: ResolvedLocation,
    ) -> std::io::Result<Box<dyn AsyncMessageStream>> {
        use crate::packet_encoding::PacketEncoding;
        if !self.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "VMess UDP is disabled",
            ));
        }
        match self.packet_encoding {
            PacketEncoding::PacketAddr => {
                let endpoint =
                    crate::packet_encoding::packet_addr_target(target, self.resolver.as_ref())
                        .await?;
                let stream = self
                    .setup_stream(
                        stream,
                        crate::packet_encoding::packet_addr_destination(),
                        COMMAND_UDP,
                    )
                    .await?;
                Ok(Box::new(crate::packet_encoding::PacketAddrStream::new(
                    Box::new(stream),
                    endpoint,
                )))
            }
            PacketEncoding::Xudp => {
                let target = target.into_location();
                let stream = self
                    .setup_stream(stream, target.clone(), COMMAND_MUX)
                    .await?;
                Ok(Box::new(crate::xudp::client_stream::XudpClientStream::new(
                    Box::new(stream),
                    target,
                )))
            }
            PacketEncoding::Native => Ok(Box::new(
                self.setup_stream(stream, target.into_location(), COMMAND_UDP)
                    .await?,
            )),
        }
    }
}

impl VmessTcpClientHandler {
    async fn setup_stream(
        &self,
        mut stream: Box<dyn AsyncStream>,
        target: NetLocation,
        command: u8,
    ) -> std::io::Result<VmessStream> {
        let legacy = self.alter_id != 0;
        // The legacy authenticator is deterministic within a second. The
        // reference client always uses the current second; AEAD keeps its
        // independent random auth ID and accepted timestamp window.
        let timestamp = if legacy {
            unix_time_secs(crate::clock::now()?)?
        } else {
            random_auth_id_timestamp()?
        };
        let mut header = vec![0u8; 38];
        header[0] = 1;
        rand::rng().fill_bytes(&mut header[1..34]);
        let request_iv: [u8; 16] = header[1..17].try_into().unwrap();
        let request_key: [u8; 16] = header[17..33].try_into().unwrap();
        let response_authentication_v = header[33];
        let response_iv: [u8; 16] = if legacy {
            compute_md5(&request_iv)
        } else {
            super::super::sha2::compute_sha256(&request_iv)[..16]
                .try_into()
                .unwrap()
        };
        let response_key: [u8; 16] = if legacy {
            compute_md5(&request_key)
        } else {
            super::super::sha2::compute_sha256(&request_key)[..16]
                .try_into()
                .unwrap()
        };
        let cipher = match self.data_cipher {
            DataCipher::Any => DataCipher::ChaCha20Poly1305,
            ref cipher => cipher.clone(),
        };
        let security = match cipher {
            DataCipher::Aes128Cfb => 1,
            DataCipher::Aes128Gcm => 3,
            DataCipher::ChaCha20Poly1305 => 4,
            DataCipher::None => 5,
            DataCipher::Any => unreachable!(),
        };
        let aead_data = matches!(cipher, DataCipher::Aes128Gcm | DataCipher::ChaCha20Poly1305);
        let chunked = cipher != DataCipher::None || command == COMMAND_UDP;
        let padding = aead_data && self.global_padding;
        let authenticated_length = aead_data && self.authenticated_length;
        header[34] = u8::from(chunked)
            | (u8::from(aead_data) << 2)
            | (u8::from(padding) << 3)
            | (u8::from(authenticated_length) << 4);
        let margin_len = usize::from(rand::random::<u8>() & 15);
        header[35] = ((margin_len as u8) << 4) | security;
        header[37] = command;
        if command != COMMAND_MUX {
            let (address, port) = target.unwrap_components();
            header.extend_from_slice(&port.to_be_bytes());
            match address {
                Address::Ipv4(address) => {
                    header.push(1);
                    header.extend_from_slice(&address.octets());
                }
                Address::Ipv6(address) => {
                    header.push(3);
                    header.extend_from_slice(&address.octets());
                }
                Address::Hostname(name) => {
                    let length = u8::try_from(name.len()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "VMess target hostname exceeds 255 bytes",
                        )
                    })?;
                    header.extend_from_slice(&[2, length]);
                    header.extend_from_slice(name.as_bytes());
                }
            }
        }
        let padding_start = header.len();
        header.resize(padding_start + margin_len, 0);
        rand::rng().fill_bytes(&mut header[padding_start..]);
        let mut checksum = Fnv1aHasher::new();
        checksum.write(&header);
        header.extend_from_slice(&checksum.finish().to_be_bytes());
        let request = if legacy {
            super::super::legacy::seal_request(
                &self.instruction_key,
                &self.alter_key,
                timestamp,
                &header,
            )
        } else {
            self.seal_aead_request(timestamp, header)?
        };
        write_all(&mut stream, &request).await?;
        stream.flush().await?;

        let data_keys = match cipher {
            DataCipher::Aes128Gcm | DataCipher::ChaCha20Poly1305 => {
                let (algorithm, read_key, write_key) = if cipher == DataCipher::Aes128Gcm {
                    (&AES_128_GCM, response_key.to_vec(), request_key.to_vec())
                } else {
                    (
                        &CHACHA20_POLY1305,
                        create_chacha_key(&response_key).to_vec(),
                        create_chacha_key(&request_key).to_vec(),
                    )
                };
                Some((
                    OpeningKey::new(
                        UnboundKey::new(algorithm, &read_key).unwrap(),
                        VmessNonceSequence::new(&response_iv),
                    ),
                    SealingKey::new(
                        UnboundKey::new(algorithm, &write_key).unwrap(),
                        VmessNonceSequence::new(&request_iv),
                    ),
                ))
            }
            _ => None,
        };
        let (read_mask, write_mask) = if aead_data {
            let mut read = Shake128::default();
            read.update(&response_iv);
            let mut write = Shake128::default();
            write.update(&request_iv);
            (Some(read.finalize_xof()), Some(write.finalize_xof()))
        } else {
            (None, None)
        };
        let mut stream = VmessStream::new(
            stream,
            command == COMMAND_UDP,
            data_keys,
            read_mask,
            write_mask,
            padding,
            None,
            Some(ReadHeaderInfo {
                response_header_key: response_key,
                response_header_iv: response_iv,
                response_authentication_v,
            }),
        )
        .with_raw_body(!chunked)
        .with_authenticated_length(
            authenticated_length,
            security == 4,
            &request_key,
            &request_iv,
        );
        if cipher == DataCipher::Aes128Cfb {
            stream = stream.with_cfb(&response_key, &response_iv, &request_key, &request_iv);
        }
        Ok(stream.with_legacy_response(legacy))
    }

    fn seal_aead_request(&self, timestamp: u64, mut header: Vec<u8>) -> std::io::Result<Vec<u8>> {
        let mut auth = [0u8; 16];
        auth[..8].copy_from_slice(&timestamp.to_be_bytes());
        rand::rng().fill_bytes(&mut auth[8..12]);
        let crc = super::super::crc32::crc32c(&auth[..12]).to_be_bytes();
        auth[12..].copy_from_slice(&crc);
        self.aead_encrypting_key
            .less_safe_encrypt(&mut auth, EncryptionContext::None)
            .map_err(|_| std::io::Error::other("VMess auth ID encryption failed"))?;
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);
        let seal = |label_key: &[u8],
                    label_nonce: &[u8],
                    bytes: &mut Vec<u8>|
         -> std::io::Result<()> {
            let key = super::super::sha2::kdf(&self.instruction_key, &[label_key, &auth, &nonce]);
            let iv = super::super::sha2::kdf(&self.instruction_key, &[label_nonce, &auth, &nonce]);
            let mut cipher = SealingKey::new(
                UnboundKey::new(&AES_128_GCM, &key[..16]).unwrap(),
                SingleUseNonce::new(&iv[..12]),
            );
            let tag = cipher
                .seal_in_place_separate_tag(Aad::from(&auth), bytes)
                .map_err(|_| std::io::Error::other("VMess request header encryption failed"))?;
            bytes.extend_from_slice(tag.as_ref());
            Ok(())
        };
        let mut length = (header.len() as u16).to_be_bytes().to_vec();
        seal(
            b"VMess Header AEAD Key_Length",
            b"VMess Header AEAD Nonce_Length",
            &mut length,
        )?;
        seal(
            b"VMess Header AEAD Key",
            b"VMess Header AEAD Nonce",
            &mut header,
        )?;
        let mut request = Vec::with_capacity(16 + 18 + 8 + header.len());
        request.extend_from_slice(&auth);
        request.extend_from_slice(&length);
        request.extend_from_slice(&nonce);
        request.extend_from_slice(&header);
        Ok(request)
    }
}
