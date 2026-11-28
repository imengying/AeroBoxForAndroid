//! Validated resolution policy, independent of configuration file formats.

use std::{collections::HashSet, sync::Arc};

use anyhow::{Result, ensure};
use hickory_proto::rr::Name;

use crate::{names::canonical_name, protocol::Secret};

/// A private namespace and its symmetric encryption key.
#[derive(Clone)]
pub struct Discovery {
    pub domain: Name,
    pub key: Arc<Secret>,
}

/// Immutable namespace selection and publication-cache limits.
///
/// Construct a new policy and resolver when keys change. Resolver caches are
/// deliberately not shared between upstreams or policy generations.
#[derive(Clone)]
pub struct Policy {
    discovery: Vec<Discovery>,
    hex_zones: Vec<Name>,
    ttl: u32,
    cache_capacity: usize,
}

impl Policy {
    /// Validates and canonicalizes namespaces. More-specific discovery domains
    /// take precedence; hexadecimal zones cannot overlap any other namespace.
    pub fn new(
        mut discovery: Vec<Discovery>,
        hex_zones: Vec<Name>,
        ttl: u32,
        cache_capacity: usize,
    ) -> Result<Self> {
        ensure!(ttl > 0, "ttl must be positive");
        ensure!(
            (1..=65_536).contains(&cache_capacity),
            "cache_capacity must be 1-65536"
        );
        for item in &mut discovery {
            item.domain = canonical_name(&item.domain.to_ascii())?;
        }
        discovery.sort_by_key(|d| std::cmp::Reverse(d.domain.num_labels()));
        let mut seen = HashSet::new();
        for item in &discovery {
            ensure!(seen.insert(&item.domain), "duplicate discovery domain");
        }
        let mut canonical_hex: Vec<Name> = Vec::new();
        for zone in hex_zones {
            let zone = canonical_name(&zone.to_ascii())?;
            ensure!(
                !canonical_hex
                    .iter()
                    .any(|d| d.zone_of(&zone) || zone.zone_of(d)),
                "hex zones must not overlap"
            );
            ensure!(
                !discovery
                    .iter()
                    .any(|d| d.domain.zone_of(&zone) || zone.zone_of(&d.domain)),
                "hex and discovery domains must not overlap"
            );
            canonical_hex.push(zone);
        }
        Ok(Self {
            discovery,
            hex_zones: canonical_hex,
            ttl,
            cache_capacity,
        })
    }

    /// Whether a name belongs to a private or hexadecimal namespace.
    ///
    /// Checks only the supplied labels; it does not expand search domains or NSS
    /// aliases. Use absolute names when this check determines a security boundary.
    pub fn claims(&self, name: &Name) -> bool {
        self.discovery_for(name).is_some() || self.hex_zones.iter().any(|zone| zone.zone_of(name))
    }

    /// Selects the most-specific configured discovery domain.
    pub fn discovery_for(&self, name: &Name) -> Option<&Discovery> {
        self.discovery.iter().find(|d| d.domain.zone_of(name))
    }

    pub fn discovery(&self) -> &[Discovery] {
        &self.discovery
    }

    pub fn hex_zones(&self) -> &[Name] {
        &self.hex_zones
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity
    }
}
