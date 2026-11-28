//! v2ray-plugin QUIC carries one SS TCP connection in each bidirectional stream.
//! There is no HTTP or Xray-mux header. SS UDP still uses the native UDP port.
use super::Config;
use crate::{
    async_stream::AsyncStream,
    config::{
        ClientConfig, ClientProxyConfig, ClientQuicConfig, ResolvedClientConfig,
        ResolvedClientProxyConfig, Transport,
    },
    option_util::{NoneOrOne, NoneOrSome},
    tcp::carrier_dialer::{CarrierDialer, QuicCarrier},
};
use std::{io, sync::Arc};

macro_rules! locate {
    ($name:ident, $kind:ident) => {
        pub(crate) fn $name(protocol: &$kind) -> Option<&Config> {
            match protocol {
                $kind::Shadowsocks {
                    plugin: Some(plugin),
                    ..
                } if plugin.is_quic() => Some(plugin),
                $kind::Multiplex(config) => $name(&config.protocol),
                $kind::Uot(config) => $name(&config.protocol),
                _ => None,
            }
        }
    };
}
locate!(source, ClientProxyConfig);
locate!(resolved, ResolvedClientProxyConfig);

fn validate_fields(transport: &Transport, tcp: bool, quic: bool, first: bool) -> io::Result<()> {
    if !first || *transport != Transport::Quic || tcp || quic {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "v2ray-plugin QUIC requires transport: quic at hop 0; TLS is configured by the plugin, without TCP/quic_settings overrides",
        ));
    }
    Ok(())
}
pub(crate) fn validate(config: &ClientConfig, first: bool) -> io::Result<()> {
    if source(&config.protocol).is_some() {
        validate_fields(
            &config.transport,
            config.tcp_settings.is_some(),
            config.quic_settings.is_some(),
            first,
        )?;
    }
    Ok(())
}
pub(crate) fn validate_resolved(config: &ResolvedClientConfig, first: bool) -> io::Result<()> {
    if resolved(&config.protocol).is_some() {
        validate_fields(
            &config.transport,
            config.tcp_settings.is_some(),
            config.quic_settings.is_some(),
            first,
        )?;
    }
    Ok(())
}

pub(crate) fn settings(plugin: &Config) -> io::Result<ClientQuicConfig> {
    plugin.validate()?;
    let Config::V2rayPlugin {
        sni_hostname,
        root_certificates,
        ..
    } = plugin
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected v2ray-plugin QUIC",
        ));
    };
    Ok(ClientQuicConfig {
        sni_hostname: sni_hostname
            .clone()
            .map_or(NoneOrOne::Unspecified, NoneOrOne::One),
        alpn_protocols: NoneOrSome::One("h3".into()),
        options: crate::config::tls::TlsClientOptions {
            root_certificates: root_certificates.clone(),
            ..Default::default()
        },
        ..Default::default()
    })
}

struct Session(QuicCarrier);
impl Drop for Session {
    fn drop(&mut self) {
        self.0
            .connection
            .close(0u32.into(), b"plugin session released");
    }
}
struct Slot {
    route: Arc<dyn CarrierDialer>,
    session: tokio::sync::Mutex<Option<Arc<Session>>>,
}
#[derive(Default)]
pub(crate) struct Pool {
    slots: parking_lot::Mutex<Vec<Arc<Slot>>>,
}
impl std::fmt::Debug for Pool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginQuicPool")
            .field("routes", &self.slots.lock().len())
            .finish()
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        for slot in self.slots.get_mut().iter() {
            if let Ok(stored) = slot.session.try_lock() {
                if let Some(session) = stored.as_ref() {
                    session
                        .0
                        .connection
                        .close(0u32.into(), b"plugin client stopped");
                }
            }
        }
    }
}
impl Pool {
    pub(crate) async fn open(
        &self,
        route: Arc<dyn CarrierDialer>,
    ) -> io::Result<Box<dyn AsyncStream>> {
        let slot = {
            let mut slots = self.slots.lock();
            if let Some(index) = slots
                .iter()
                .position(|s| s.route.route_key() == route.route_key())
            {
                let slot = slots.remove(index);
                slots.push(slot.clone());
                slot
            } else {
                let slot = Arc::new(Slot {
                    route,
                    session: tokio::sync::Mutex::new(None),
                });
                if slots.len() == 16 {
                    slots.remove(0);
                }
                slots.push(slot.clone());
                slot
            }
        };
        let session = {
            let mut stored = slot.session.lock().await;
            if let Some(session) = stored
                .as_ref()
                .filter(|s| s.0.connection.close_reason().is_none())
            {
                session.clone()
            } else {
                let session = Arc::new(Session(slot.route.open_quic().await?));
                *stored = Some(session.clone());
                session
            }
        };
        let (send, recv) = session
            .0
            .connection
            .open_bi()
            .await
            .map_err(io::Error::other)?;
        let peer = session.0.connection.remote_address();
        Ok(Box::new(
            crate::quic_stream::QuicStream::from(send, recv)
                .with_peer(peer)
                .with_owner(session),
        ))
    }
}
