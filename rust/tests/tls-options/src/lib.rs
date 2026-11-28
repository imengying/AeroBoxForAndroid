//! Exercise the actual client configuration without compiling unrelated proxies.
//! TLS policy, certificate verification, key exchange and browser configuration
//! are production modules. Only unused application services are stubbed below.
#![allow(dead_code)]

#[path = "../../../vendor/shoes/src/crypto/rustcrypto_kx.rs"]
pub mod rustcrypto_kx;
include!(concat!(env!("OUT_DIR"), "/production.rs"));
#[path = "../../../vendor/shoes/src/config/types/tls.rs"]
pub mod tls;

pub use rustls_config_util::{try_create_client_config_with_options, try_create_server_config};

pub fn naive_config(
    options: &tls::TlsClientOptions,
    quic: bool,
) -> std::io::Result<rustls::ClientConfig> {
    rustls_config_util::naive::create_config(options, quic)
}

mod config {
    pub use crate::tls;
    pub use tls::TlsKeyExchangeGroups;
}
mod crypto {
    pub use crate::rustcrypto_kx;
}

mod clock {
    use std::{sync::Arc, time::Duration};
    #[derive(Debug)]
    struct FixtureTime;
    impl rustls::time_provider::TimeProvider for FixtureTime {
        fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
            Some(rustls::pki_types::UnixTime::since_unix_epoch(
                Duration::from_secs(1893456000),
            ))
        }
    }
    pub fn time_provider() -> Arc<dyn rustls::time_provider::TimeProvider> {
        Arc::new(FixtureTime)
    }
}

// These services are outside ordinary TLS configuration. Fail if a test reaches
// them, rather than replacing their security decisions with successful stubs.
mod certificates {
    #[derive(Debug)]
    pub struct Source;
    impl rustls::server::ResolvesServerCert for Source {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
            panic!("certificate hot reload is outside this validation crate")
        }
    }
}
mod ech {
    #[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
    pub struct EchOptions;
    impl EchOptions {
        pub fn embed(&mut self) -> std::io::Result<()> {
            panic!("ECH acquisition is outside this validation crate")
        }
        pub fn static_config(&self) -> std::io::Result<Option<rustls::client::EchConfig>> {
            panic!("ECH acquisition is outside this validation crate")
        }
    }
}
mod reality {
    pub enum CipherSuite {}
    impl CipherSuite {
        pub fn id(&self) -> u16 {
            match *self {}
        }
    }
}
