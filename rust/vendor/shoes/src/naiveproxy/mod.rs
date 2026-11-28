#[cfg(test)]
mod client_compat_tests;
#[cfg(test)]
mod reference_capture_tests;
mod h2_multi_stream;
mod naive_client_handler;
mod naive_client_session;
mod naive_hyper_service;
mod naive_padding_stream;
mod naive_server_handler;
#[cfg(test)]
mod route_tests;
mod user_lookup;
mod request;

pub use naive_client_handler::NaiveProxyTcpClientHandler;
pub use naive_server_handler::setup_naive_server_stream;
pub use user_lookup::UserLookup;

pub mod options;
pub(crate) mod quic;
#[cfg(test)]
mod quic_tests;
#[cfg(test)]
mod quic_capture_tests;

#[cfg(test)]
mod window_tests;
#[cfg(test)]
mod quic_window_tests;
