//! Naive uses one UDP socket per zero-CID QUIC connection. Connection reuse
//! belongs to the Naive session cache, so opening a replacement must leave an
//! older connection's four-tuple available until its active tunnels finish.
use super::{QuicEndpoint, wrap_quic_socket};
use crate::{
    dial_options::DialOptions,
    network_dial::{NetworkBinding, NetworkKey},
    socket_util::new_udp_socket_on_network,
};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Weak},
};

#[derive(Debug)]
pub(super) struct Endpoints {
    config: quinn::ClientConfig,
    memory_bytes: usize,
    socket_buffer: usize,
    dial_options: DialOptions,
    network: parking_lot::Mutex<NetworkEndpoints>,
}

#[derive(Debug, Default)]
struct NetworkEndpoints {
    snapshot: Option<NetworkKey>,
    // Carriers own endpoints. This list must not retain closed sockets or
    // allocate in proportion to the configured Naive concurrency.
    active: Vec<Weak<QuicEndpoint>>,
}

impl NetworkEndpoints {
    fn select(&mut self, key: NetworkKey) -> io::Result<()> {
        if let Some(previous) = self.snapshot
            && !previous.same_snapshot(key)
        {
            if key.is_older_than(previous) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Naive QUIC physical-network snapshot has expired",
                ));
            }
            for endpoint in self.active.drain(..).filter_map(|entry| entry.upgrade()) {
                endpoint.close(0_u32.into(), b"physical network changed");
            }
        }
        self.snapshot = Some(key);
        self.active.retain(|endpoint| endpoint.strong_count() != 0);
        Ok(())
    }
}

impl Endpoints {
    pub(super) fn new(
        config: quinn::ClientConfig,
        memory_bytes: usize,
        socket_buffer: usize,
        dial_options: DialOptions,
    ) -> Self {
        Self {
            config,
            memory_bytes,
            socket_buffer,
            dial_options,
            network: Default::default(),
        }
    }

    pub(super) fn open(
        &self,
        address: SocketAddr,
        bind_interface: Option<String>,
        binding: Option<&NetworkBinding>,
    ) -> io::Result<Arc<QuicEndpoint>> {
        if let Some(binding) = binding {
            self.network.lock().select(binding.key())?;
        }
        let socket = new_udp_socket_on_network(address.is_ipv6(), bind_interface, binding)?;
        let socket = wrap_quic_socket(
            socket.into_std()?,
            self.socket_buffer,
            None,
            &self.dial_options,
        )?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        // Chromium's QUIC client identifies each connection by its socket's
        // four-tuple; do not advertise connection IDs that it does not use.
        endpoint_config
            .cid_generator(|| Box::new(quinn_proto::RandomConnectionIdGenerator::new(0)))
            .grease_quic_bit(false);
        let mut endpoint = QuicEndpoint::with_endpoint_config(
            endpoint_config,
            None,
            socket,
            self.memory_bytes,
            None,
        )?;
        endpoint.set_default_client_config(self.config.clone());
        let endpoint = Arc::new(endpoint);
        if let Some(binding) = binding {
            let mut network = self.network.lock();
            // Binding may race a newer network selection. Never register an
            // obsolete socket after a new generation has already been chosen.
            network.select(binding.key())?;
            network.active.push(Arc::downgrade(&endpoint));
        }
        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests;
