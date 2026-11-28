//! Wire contract for the host's non-VPN physical-network inventory.
use serde::{Deserialize, Serialize};
use std::{io, net::SocketAddr};

const MAX_NETWORKS: usize = 64;
const MAX_DNS_SERVERS: usize = 64;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalNetworkKind {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhysicalNetwork {
    pub handle: u64,
    pub kind: PhysicalNetworkKind,
    pub interface: String,
    pub dns: Vec<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhysicalNetworkSnapshot {
    pub generation: u64,
    pub default_handle: Option<u64>,
    /// Stable unsigned-handle ordering, with no duplicate or zero handles.
    pub networks: Vec<PhysicalNetwork>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireNetwork {
    handle: u64,
    kind: PhysicalNetworkKind,
    interface: String,
    dns: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot {
    generation: u64,
    default_handle: Option<u64>,
    networks: Vec<WireNetwork>,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

impl PhysicalNetworkSnapshot {
    /// Parse integer identifiers directly into u64, including values > 2^53 and
    /// > i64::MAX. No JSONObject/JavaScript/float representation is involved.
    pub fn from_json(input: &str) -> io::Result<Self> {
        if input.len() > MAX_SNAPSHOT_BYTES {
            return Err(invalid("physical network snapshot exceeds 256 KiB"));
        }
        let wire: WireSnapshot = serde_json::from_str(input)
            .map_err(|error| invalid(format!("invalid physical network snapshot: {error}")))?;
        if wire.networks.len() > MAX_NETWORKS {
            return Err(invalid("physical network snapshot exceeds 64 networks"));
        }
        let mut networks = wire
            .networks
            .into_iter()
            .map(|wire| {
                if wire.dns.len() > MAX_DNS_SERVERS {
                    return Err(invalid("physical network exceeds 64 DNS servers"));
                }
                let mut dns = Vec::with_capacity(wire.dns.len());
                for text in wire.dns {
                    let endpoint = text
                        .parse::<SocketAddr>()
                        .or_else(|_| text.parse().map(|ip| SocketAddr::new(ip, 53)))
                        .map_err(|_| invalid(format!("invalid physical DNS endpoint: {text}")))?;
                    if !dns.contains(&endpoint) {
                        dns.push(endpoint);
                    }
                }
                Ok(PhysicalNetwork {
                    handle: wire.handle,
                    kind: wire.kind,
                    interface: wire.interface,
                    dns,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        networks.sort_by_key(|network| network.handle);
        let snapshot = Self {
            generation: wire.generation,
            default_handle: wire.default_handle,
            networks,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Also validate snapshots supplied by non-JNI hosts. An absent default is
    /// valid: hybrid/fallback may still have explicitly usable physical networks.
    pub fn validate(&self) -> io::Result<()> {
        if self.generation == 0 || self.networks.len() > MAX_NETWORKS {
            return Err(invalid(
                "invalid physical network generation or network count",
            ));
        }
        let mut previous = 0;
        for network in &self.networks {
            if network.handle <= previous {
                return Err(invalid(
                    "physical network handles must be nonzero, unique and sorted",
                ));
            }
            previous = network.handle;
            if network.interface.is_empty()
                || network.interface.len() > 256
                || network.interface.chars().any(char::is_control)
            {
                return Err(invalid("invalid physical network interface name"));
            }
            if network.dns.len() > MAX_DNS_SERVERS
                || network.dns.iter().any(|endpoint| {
                    endpoint.port() == 0
                        || endpoint.ip().is_unspecified()
                        || endpoint.ip().is_multicast()
                        || endpoint.ip() == std::net::Ipv4Addr::BROADCAST
                })
            {
                return Err(invalid("physical network contains an invalid DNS endpoint"));
            }
        }
        if self
            .default_handle
            .is_some_and(|handle| !self.networks.iter().any(|network| network.handle == handle))
        {
            return Err(invalid(
                "default physical network is absent from the snapshot",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn wire(handle: u64) -> serde_json::Value {
        json!({"handle":handle,"kind":"wifi","interface":"wlan0","dns":["192.0.2.53","[2001:db8::53]:5353"]})
    }

    #[test]
    fn snapshot_keeps_unsigned_ids_exact_and_sorts_networks() {
        let text = json!({"generation":u64::MAX,"default_handle":u64::MAX,"networks":[wire(u64::MAX),wire(9_007_199_254_740_993)]}).to_string();
        let snapshot = PhysicalNetworkSnapshot::from_json(&text).unwrap();
        assert_eq!(snapshot.generation, u64::MAX);
        assert_eq!(snapshot.default_handle, Some(u64::MAX));
        assert_eq!(snapshot.networks[0].handle, 9_007_199_254_740_993);
        assert_eq!(snapshot.networks[1].handle, u64::MAX);
        assert_eq!(
            snapshot.networks[0].dns[0],
            "192.0.2.53:53".parse().unwrap()
        );
        assert_eq!(
            snapshot.networks[0].dns[1],
            "[2001:db8::53]:5353".parse().unwrap()
        );
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert_eq!(
            PhysicalNetworkSnapshot::from_json(&encoded).unwrap(),
            snapshot
        );
    }

    #[test]
    fn snapshot_rejects_ambiguous_or_unusable_bindings() {
        for value in [
            json!({"generation":0,"default_handle":null,"networks":[]}),
            json!({"generation":1,"default_handle":1,"networks":[]}),
            json!({"generation":1,"default_handle":null,"networks":[wire(0)]}),
            json!({"generation":1,"default_handle":1,"networks":[wire(1),wire(1)]}),
            json!({"generation":1,"default_handle":null,"networks":vec![wire(1);65]}),
        ] {
            assert!(
                PhysicalNetworkSnapshot::from_json(&value.to_string()).is_err(),
                "{value}"
            );
        }
        for (key, value) in [
            ("handle", json!(1.5)),
            ("handle", json!("18446744073709551615")),
            ("kind", json!("vpn")),
            ("interface", json!("")),
            ("dns", json!(["0.0.0.0"])),
            ("dns", json!(["192.0.2.53:0"])),
            ("dns", json!(["ff02::1"])),
        ] {
            let mut network = wire(1);
            network[key] = value;
            let snapshot = json!({"generation":1,"default_handle":1,"networks":[network]});
            assert!(
                PhysicalNetworkSnapshot::from_json(&snapshot.to_string()).is_err(),
                "{snapshot}"
            );
        }
        assert!(
            PhysicalNetworkSnapshot::from_json(
                r#"{"generation":1,"default_handle":null,"networks":[]}"#
            )
            .is_ok()
        );
    }
}
