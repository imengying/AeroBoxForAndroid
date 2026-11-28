//! Control-only handle for a single, owned TCP carrier. This never exposes raw
//! I/O through encrypted or framed wrappers and is not inherited by mux streams.
use std::io;

#[derive(Debug)]
pub struct TcpSocketControl {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fd: std::os::fd::OwnedFd,
}

#[derive(Debug)]
pub(crate) enum BrutalStatus {
    Enabled,
    Unavailable(io::Error),
}

impl TcpSocketControl {
    pub(crate) fn from_tcp(stream: &tokio::net::TcpStream) -> io::Result<Option<Self>> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsFd;
            return Ok(Some(Self {
                fd: stream.as_fd().try_clone_to_owned()?,
            }));
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = stream;
            Ok(None)
        }
    }

    pub(crate) fn enable_brutal(&self, rate: u64) -> io::Result<BrutalStatus> {
        if rate < 65_536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP Brutal rate is too small",
            ));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            let fd = self.fd.as_raw_fd();
            let mut old = [0u8; 64];
            let mut old_len = old.len() as libc::socklen_t;
            // SAFETY: the owned descriptor is live; both output buffers have
            // the stated sizes and the kernel writes at most old_len bytes.
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_CONGESTION,
                    old.as_mut_ptr().cast(),
                    &mut old_len,
                )
            } != 0
            {
                return Ok(BrutalStatus::Unavailable(io::Error::last_os_error()));
            }
            let old_len = (old_len as usize).min(old.len());
            let old = &old[..old_len];
            let name_len = old.iter().position(|byte| *byte == 0).unwrap_or(old.len());
            if name_len == 0 {
                return Ok(BrutalStatus::Unavailable(io::Error::other(
                    "missing current TCP congestion algorithm",
                )));
            }
            let set = |name: &[u8]| {
                // SAFETY: this input slice lives through setsockopt and its
                // exact length is supplied; the descriptor remains owned.
                let result = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_CONGESTION,
                        name.as_ptr().cast(),
                        name.len() as libc::socklen_t,
                    )
                };
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            };
            if let Err(error) = set(b"brutal") {
                return Ok(BrutalStatus::Unavailable(error));
            }
            // Keep the kernel ABI's target-dependent trailing padding, initialized
            // to zero. ARM32 and ARM64 need not have the same sizeof this struct.
            #[repr(C)]
            struct Parameters {
                rate: u64,
                cwnd_gain: u32,
            }
            let mut bytes = [0u8; std::mem::size_of::<Parameters>()];
            bytes[..8].copy_from_slice(&rate.to_ne_bytes());
            bytes[8..12].copy_from_slice(&20u32.to_ne_bytes());
            // SAFETY: bytes encodes the repr(C) layout and all padding bytes
            // are initialized, preventing memory disclosure to the syscall.
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    23301,
                    bytes.as_ptr().cast(),
                    bytes.len() as libc::socklen_t,
                )
            };
            if result == 0 {
                return Ok(BrutalStatus::Enabled);
            }
            let error = io::Error::last_os_error();
            // A parameter error must not leave a half-configured controller.
            // Failure to restore is fatal; the caller closes this carrier.
            set(&old[..name_len]).map_err(|restore| io::Error::other(format!(
                "TCP Brutal setup failed ({error}); restoring congestion algorithm failed ({restore})")))?;
            Ok(BrutalStatus::Unavailable(error))
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            Ok(BrutalStatus::Unavailable(io::Error::new(
                io::ErrorKind::Unsupported,
                "TCP Brutal requires Linux or Android",
            )))
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd};

    fn algorithm(fd: std::os::fd::RawFd) -> Vec<u8> {
        let mut name = [0u8; 64];
        let mut length = name.len() as libc::socklen_t;
        // SAFETY: live socket and correctly sized output buffer.
        assert_eq!(
            unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_CONGESTION,
                    name.as_mut_ptr().cast(),
                    &mut length,
                )
            },
            0
        );
        name[..length as usize].to_vec()
    }

    #[tokio::test]
    async fn control_duplicates_fd_and_kernel_failure_preserves_a_working_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let control = TcpSocketControl::from_tcp(&client).unwrap().unwrap();
        assert_ne!(control.fd.as_raw_fd(), client.as_raw_fd());
        let before = algorithm(client.as_raw_fd());
        assert_eq!(
            control.enable_brutal(1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(algorithm(client.as_raw_fd()), before);
        if let BrutalStatus::Unavailable(_) = control.enable_brutal(1_000_000).unwrap() {
            assert_eq!(algorithm(client.as_raw_fd()), before);
        }
        drop(control);
        client.write_all(b"still-open").await.unwrap();
        let mut bytes = [0; 10];
        peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still-open");
        // A non-TCP fd is never emitted by from_tcp; exercise the syscall-error
        // branch without requiring privileges or a loaded Brutal module.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let invalid = TcpSocketControl {
            fd: udp.as_fd().try_clone_to_owned().unwrap(),
        };
        assert!(matches!(
            invalid.enable_brutal(1_000_000).unwrap(),
            BrutalStatus::Unavailable(_)
        ));
    }
}
