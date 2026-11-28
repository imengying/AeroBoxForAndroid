//! ACME is a server provisioning feature, outside the AeroBox Android kernel.
//! Reject it before binding listeners or making any outbound requests.
use std::{fs::File, io, path::Path, sync::Arc};
use super::{AcmeConfig, Source};
fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "ACME certificate provisioning is not included in the AeroBox Android kernel; supply a certificate file")
}
pub(super) fn validate_url(_: &str) -> io::Result<url::Url> { Err(unavailable()) }
pub(super) fn client_tls(_: Option<&Path>) -> io::Result<Arc<rustls::ClientConfig>> { Err(unavailable()) }
pub(super) fn lock_state(_: &AcmeConfig) -> io::Result<File> { Err(unavailable()) }
pub(super) fn validate_state(_: &AcmeConfig) -> io::Result<()> { Err(unavailable()) }
pub(super) fn state_error(_: &AcmeConfig, _: io::Error) -> io::Error { unavailable() }
pub(super) fn load_cached(_: &Source, _: &AcmeConfig) -> io::Result<()> { Err(unavailable()) }
pub(super) async fn run(_: Arc<Source>, _: &AcmeConfig) { log::error!("{}", unavailable()); }
