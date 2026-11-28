//! Encrypted TXT discovery and hexadecimal IPv4 resolution.
//!
//! Disable default features to embed the resolver without the CLI, HTTP servers,
//! Cloudflare client, or built-in network transport. Supply an [`Exchange`]
//! implementation backed by the application's existing DNS resolver.
//!
//! ```
//! use std::sync::Arc;
//! use tendns::{Discovery, Exchange, Policy, Resolver};
//! use tendns::{names::canonical_name, protocol::Secret};
//!
//! fn make_resolver(upstream: Arc<dyn Exchange>, encoded_key: &str)
//!     -> anyhow::Result<Resolver>
//! {
//!     let policy = Policy::new(
//!         vec![Discovery {
//!             domain: canonical_name("example.com")?,
//!             key: Arc::new(Secret::decode(encoded_key)?),
//!         }],
//!         vec![canonical_name("hex.internal")?],
//!         60,
//!         1024,
//!     )?;
//!     Ok(Resolver::new(Arc::new(policy), upstream))
//! }
//! ```

#[cfg(feature = "cli")]
pub mod cloudflare;
#[cfg(feature = "cli")]
pub mod config;
mod deadline;
pub mod names;
pub mod policy;
pub mod protocol;
pub mod resolver;
#[cfg(feature = "cli")]
pub mod server;
pub mod upstream;

pub use deadline::TimeoutError;
pub use hickory_proto;
pub use policy::{Discovery, Policy};
pub use resolver::{IpStrategy, LookupError, Resolver};
pub use upstream::Exchange;
