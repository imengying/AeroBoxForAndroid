//! Per-outbound socket policy. Android uses the same Linux socket options;
//! unsupported requested capabilities fail before a connection is created.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::{io, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialDuration(pub Duration);

impl DialDuration {
    /// Parse positive Go-style duration components without floating point.
    /// Zero means the dialer's default; negative settings are rejected.
    pub fn parse(value: &str) -> io::Result<Self> {
        let value = value.strip_prefix('+').unwrap_or(value);
        if value == "0" {
            return Ok(Self(Duration::ZERO));
        }
        if value.is_empty() || value.len() > 256 || value.starts_with('-') {
            return Err(invalid("expected a non-negative duration with units"));
        }
        let mut remaining = value;
        let mut total = 0u128;
        while !remaining.is_empty() {
            let digits = remaining.bytes().take_while(u8::is_ascii_digit).count();
            let whole: u128 = if digits == 0 {
                0
            } else {
                remaining[..digits]
                    .parse()
                    .map_err(|_| invalid("duration overflow"))?
            };
            remaining = &remaining[digits..];
            let mut fraction = 0u128;
            let mut scale = 1u128;
            let mut fractional_digits = 0;
            if let Some(after_dot) = remaining.strip_prefix('.') {
                fractional_digits = after_dot.bytes().take_while(u8::is_ascii_digit).count();
                if fractional_digits == 0 {
                    return Err(invalid("missing digits after decimal point"));
                }
                for digit in after_dot.bytes().take(fractional_digits.min(18)) {
                    fraction = fraction * 10 + u128::from(digit - b'0');
                    scale *= 10;
                }
                remaining = &after_dot[fractional_digits..];
            }
            if digits == 0 && fractional_digits == 0 {
                return Err(invalid("missing duration number"));
            }
            let (unit, multiplier) = [
                ("ns", 1u128),
                ("us", 1_000),
                ("µs", 1_000),
                ("μs", 1_000),
                ("ms", 1_000_000),
                ("s", 1_000_000_000),
                ("m", 60_000_000_000),
                ("h", 3_600_000_000_000),
            ]
            .into_iter()
            .find(|(unit, _)| remaining.starts_with(unit))
            .ok_or_else(|| invalid("expected ns/us/µs/ms/s/m/h duration unit"))?;
            remaining = &remaining[unit.len()..];
            let component = whole
                .checked_mul(multiplier)
                .and_then(|value| value.checked_add(fraction * multiplier / scale))
                .ok_or_else(|| invalid("duration overflow"))?;
            total = total
                .checked_add(component)
                .filter(|total| *total <= i64::MAX as u128)
                .ok_or_else(|| invalid("duration exceeds Go's signed nanosecond range"))?;
        }
        Ok(Self(Duration::from_nanos(total as u64)))
    }
}

impl Serialize for DialDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}ns", self.0.as_nanos()))
    }
}
impl<'de> Deserialize<'de> for DialDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DialOptions {
    pub connect_timeout: Option<DialDuration>,
    pub disable_tcp_keep_alive: bool,
    pub tcp_keep_alive: Option<DialDuration>,
    pub tcp_keep_alive_interval: Option<DialDuration>,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    /// None uses the platform's ordinary outbound default (no fragmentation
    /// on Linux/Android). Some requires the requested behavior to be supported.
    pub udp_fragment: Option<bool>,
    pub network_strategy: Option<crate::network_dial::NetworkStrategy>,
    pub network_type: Vec<crate::embedding::PhysicalNetworkKind>,
    pub fallback_network_type: Vec<crate::embedding::PhysicalNetworkKind>,
    pub fallback_delay: Option<DialDuration>,
}

impl DialOptions {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
    pub fn has_network_policy(&self) -> bool {
        self.network_strategy.is_some()
            || !self.network_type.is_empty()
            || !self.fallback_network_type.is_empty()
            || self.fallback_delay.is_some()
    }

    pub fn validate_binding(&self, interface: Option<&str>) -> io::Result<()> {
        if self.has_network_policy() && interface.is_some() {
            return Err(invalid("network strategy conflicts with bind_interface"));
        }
        Ok(())
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.has_network_policy() && self.tcp_fast_open {
            return Err(invalid("network strategy conflicts with tcp_fast_open"));
        }
        for kinds in [&self.network_type, &self.fallback_network_type] {
            if kinds.len() > 4
                || kinds
                    .iter()
                    .enumerate()
                    .any(|(i, kind)| kinds[..i].contains(kind))
            {
                return Err(invalid(
                    "network types must be unique wifi/cellular/ethernet/other values",
                ));
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        if self.tcp_fast_open || self.tcp_multi_path || self.udp_fragment.is_some() {
            return Err(unsupported(
                "TCP Fast Open, MPTCP and explicit UDP fragmentation require Linux or Android",
            ));
        }
        // Kernel keepalive APIs operate on signed whole seconds. Match Go's
        // upward rounding for fractional values rather than truncating to zero.
        if !self.disable_tcp_keep_alive {
            self.keepalive_period(self.tcp_keep_alive, 300)?;
            self.keepalive_period(self.tcp_keep_alive_interval, 75)?;
        }
        Ok(())
    }

    pub fn validate_transport(&self, tcp: bool, anytls: bool) -> io::Result<()> {
        if !tcp
            && (self.tcp_fast_open
                || self.tcp_multi_path
                || self.disable_tcp_keep_alive
                || self.tcp_keep_alive.is_some()
                || self.tcp_keep_alive_interval.is_some())
        {
            return Err(invalid("TCP dial options require a TCP transport"));
        }
        if anytls && self.tcp_fast_open {
            return Err(invalid("AnyTLS cannot use TCP Fast Open"));
        }
        Ok(())
    }

    pub fn timeout(&self) -> Duration {
        self.connect_timeout
            .map(|duration| duration.0)
            .filter(|duration| !duration.is_zero())
            .unwrap_or(Duration::from_secs(10))
    }

    pub async fn connect<T>(
        &self,
        operation: impl std::future::Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        tokio::time::timeout(self.timeout(), operation)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "outbound connect timeout"))?
    }

    pub fn tcp_socket(&self, is_ipv6: bool) -> io::Result<Socket> {
        self.validate()?;
        let protocol = if self.tcp_multi_path {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                Protocol::from(libc::IPPROTO_MPTCP)
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            return Err(unsupported(
                "MPTCP sockets are unavailable on this platform",
            ));
        } else {
            Protocol::TCP
        };
        let socket = Socket::new(
            if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 },
            Type::STREAM,
            Some(protocol),
        )?;
        socket.set_nonblocking(true)?;
        self.apply_tcp(SockRef::from(&socket))?;
        Ok(socket)
    }

    /// Apply before connect; errors propagate rather than logging and dialing
    /// a socket with different policy.
    pub fn apply_tcp(&self, socket: SockRef<'_>) -> io::Result<()> {
        self.validate()?;
        if self.disable_tcp_keep_alive {
            socket.set_keepalive(false)?;
        } else {
            let settings = TcpKeepalive::new()
                .with_time(self.keepalive_period(self.tcp_keep_alive, 300)?)
                .with_interval(self.keepalive_period(self.tcp_keep_alive_interval, 75)?);
            socket.set_tcp_keepalive(&settings)?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.tcp_fast_open {
            set_int(&socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT, 1)?;
        }
        Ok(())
    }

    pub fn apply_udp(&self, socket: SockRef<'_>, is_ipv6: bool) -> io::Result<()> {
        self.validate()?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let discovery = if self.udp_fragment.unwrap_or(false) {
                libc::IP_PMTUDISC_DONT
            } else {
                libc::IP_PMTUDISC_DO
            };
            // IPv6 sockets may also send IPv4-mapped packets, so configure both.
            set_int(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, discovery)?;
            if is_ipv6 {
                set_int(
                    &socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    discovery,
                )?;
                set_int(
                    &socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_DONTFRAG,
                    i32::from(!self.udp_fragment.unwrap_or(false)),
                )?;
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = (socket, is_ipv6);
        Ok(())
    }

    /// Quinn initializes its own PMTU/DF policy while wrapping a socket. Apply
    /// explicit overrides afterwards, through a temporary duplicate, and keep
    /// the reported fragmentation capability consistent with the OS state.
    pub fn wrap_quic_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> io::Result<std::sync::Arc<dyn quinn::AsyncUdpSocket>> {
        self.validate()?;
        let Some(fragmentation) = self.udp_fragment else {
            return quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket);
        };
        socket.set_nonblocking(true)?;
        let policy_socket = socket.try_clone()?;
        let is_ipv6 = policy_socket.local_addr()?.is_ipv6();
        let inner = quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)?;
        self.apply_udp(SockRef::from(&policy_socket), is_ipv6)?;
        Ok(std::sync::Arc::new(QuicPolicySocket {
            inner,
            fragmentation,
        }))
    }

    fn keepalive_period(
        &self,
        configured: Option<DialDuration>,
        default_secs: u64,
    ) -> io::Result<Duration> {
        let value = configured
            .map(|duration| duration.0)
            .filter(|duration| !duration.is_zero())
            .unwrap_or(Duration::from_secs(default_secs));
        let seconds = value.as_secs() + u64::from(value.subsec_nanos() != 0);
        if seconds > i32::MAX as u64 {
            return Err(invalid("TCP keepalive period exceeds the platform limit"));
        }
        Ok(Duration::from_secs(seconds))
    }
}

#[derive(Debug)]
struct QuicPolicySocket {
    inner: std::sync::Arc<dyn quinn::AsyncUdpSocket>,
    fragmentation: bool,
}
impl quinn::AsyncUdpSocket for QuicPolicySocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buffers: &mut [io::IoSliceMut<'_>],
        metadata: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, buffers, metadata)
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.fragmentation
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_int(
    socket: &SockRef<'_>,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: socket owns a live descriptor; value is an initialized c_int,
    // and its pointer/length remain valid for the synchronous OS call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_components_and_fractional_units_are_exact() {
        for (value, expected) in [
            ("0", 0),
            ("+1h2m3.004005006s", 3_723_004_005_006),
            (".5s", 500_000_000),
            ("50ms20us1ns", 50_020_001),
            ("1µs1μs", 2_000),
        ] {
            let duration = DialDuration::parse(value).unwrap();
            assert_eq!(duration.0.as_nanos(), expected);
            let json = serde_json::to_string(&duration).unwrap();
            assert_eq!(
                serde_json::from_str::<DialDuration>(&json).unwrap(),
                duration
            );
        }
        for value in [
            "",
            "-1s",
            "1",
            "1.s",
            "1s garbage",
            "NaNs",
            "1d",
            "9223372036854775808ns",
        ] {
            assert!(DialDuration::parse(value).is_err(), "{value}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn keepalive_policy_is_applied_to_the_real_socket() {
        let options = DialOptions {
            tcp_keep_alive: Some(DialDuration::parse("1500ms").unwrap()),
            tcp_keep_alive_interval: Some(DialDuration::parse("3s").unwrap()),
            ..Default::default()
        };
        let socket = options.tcp_socket(false).unwrap();
        assert!(socket.keepalive().unwrap());
        assert_eq!(socket.tcp_keepalive_time().unwrap(), Duration::from_secs(2));
        assert_eq!(
            socket.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(3)
        );
        let disabled = DialOptions {
            disable_tcp_keep_alive: true,
            ..Default::default()
        };
        disabled.apply_tcp(SockRef::from(&socket)).unwrap();
        assert!(!socket.keepalive().unwrap());
        DialOptions::default()
            .apply_tcp(SockRef::from(&socket))
            .unwrap();
        assert_eq!(
            socket.tcp_keepalive_time().unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            socket.tcp_keepalive_interval().unwrap(),
            Duration::from_secs(75)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn fragmentation_policy_changes_both_address_families() {
        for ipv6 in [false, true] {
            let socket = Socket::new(
                if ipv6 { Domain::IPV6 } else { Domain::IPV4 },
                Type::DGRAM,
                Some(Protocol::UDP),
            )
            .unwrap();
            for enabled in [true, false] {
                let options = DialOptions {
                    udp_fragment: Some(enabled),
                    ..Default::default()
                };
                options.apply_udp(SockRef::from(&socket), ipv6).unwrap();
                let expected = if enabled {
                    libc::IP_PMTUDISC_DONT
                } else {
                    libc::IP_PMTUDISC_DO
                };
                assert_eq!(
                    get_int(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER),
                    expected
                );
                if ipv6 {
                    assert_eq!(
                        get_int(&socket, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
                        expected
                    );
                    assert_eq!(
                        get_int(&socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
                        i32::from(!enabled)
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn connect_timeout_drops_the_pending_operation() {
        struct PendingOperation(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for PendingOperation {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resource = PendingOperation(dropped.clone());
        let options = DialOptions {
            connect_timeout: Some(DialDuration(Duration::from_millis(10))),
            ..Default::default()
        };
        let result: io::Result<()> = options
            .connect(async move {
                let _resource = resource;
                std::future::pending().await
            })
            .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn quic_wrapping_preserves_explicit_fragmentation() {
        for enabled in [false, true] {
            let socket = std::net::UdpSocket::bind("[::1]:0").unwrap();
            let observed = socket.try_clone().unwrap();
            let observed = Socket::from(observed);
            let options = DialOptions {
                udp_fragment: Some(enabled),
                ..Default::default()
            };
            let wrapped = options.wrap_quic_socket(socket).unwrap();
            assert_eq!(wrapped.may_fragment(), enabled);
            assert_eq!(
                get_int(&observed, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG),
                i32::from(!enabled)
            );
            assert_eq!(
                get_int(&observed, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER),
                if enabled {
                    libc::IP_PMTUDISC_DONT
                } else {
                    libc::IP_PMTUDISC_DO
                }
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn tfo_and_mptcp_request_real_kernel_capabilities() {
        let options = DialOptions {
            tcp_fast_open: true,
            ..Default::default()
        };
        match options.tcp_socket(false) {
            Ok(socket) => assert_eq!(
                get_int(&socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT),
                1
            ),
            Err(error) => assert!(matches!(
                error.raw_os_error(),
                Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::EINVAL)
            )),
        }
        let options = DialOptions {
            tcp_multi_path: true,
            ..Default::default()
        };
        match options.tcp_socket(false) {
            Ok(socket) => assert_eq!(
                get_int(&socket, libc::SOL_SOCKET, libc::SO_PROTOCOL),
                libc::IPPROTO_MPTCP
            ),
            Err(error) => assert!(matches!(
                error.raw_os_error(),
                Some(libc::ENOPROTOOPT | libc::EPROTONOSUPPORT | libc::EINVAL)
            )),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn get_int(socket: &Socket, level: libc::c_int, option: libc::c_int) -> libc::c_int {
        use std::os::fd::AsRawFd;
        let mut value: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: initialized output and length have matching sizes; descriptor is live.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                option,
                std::ptr::from_mut(&mut value).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0, "{}", io::Error::last_os_error());
        value
    }
}
