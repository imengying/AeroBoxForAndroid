#[path = "../../../../../vendor/shoes/src/reality/reality_cipher_suite.rs"]
mod reality_cipher_suite;
pub use reality_cipher_suite::{CipherSuite, DEFAULT_CIPHER_SUITES};
#[path = "../../../../../vendor/shoes/src/reality/reality_auth.rs"]
mod reality_auth;
#[path = "../../../../../vendor/shoes/src/reality/reality_certificate_verify.rs"]
mod reality_certificate_verify;
#[path = "../../../../../vendor/shoes/src/reality/reality_hello.rs"]
mod reality_hello;
#[path = "../../../../../vendor/shoes/src/reality/reality_mldsa.rs"]
mod reality_mldsa;
#[path = "../../../../../vendor/shoes/src/reality/reality_rustls_adapter.rs"]
mod reality_rustls_adapter;
pub struct RealityClientConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub mldsa65_verify: Option<reality_mldsa::VerifyKey>,
}
pub fn authentication(
    schemes: Vec<rustls::SignatureScheme>,
) -> (
    Box<dyn rustls::reality::ClientHooks>,
    std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
) {
    use aerobox_primitives::agreement;
    let public = agreement::PrivateKey::from_private_key(&agreement::X25519, &[42; 32])
        .unwrap()
        .compute_public_key()
        .unwrap();
    let config = RealityClientConfig {
        public_key: public.as_ref().try_into().unwrap(),
        short_id: [1; 8],
        mldsa65_verify: None,
    };
    let (hooks, verifier) = reality_rustls_adapter::browser_client_authentication(&config, schemes);
    (Box::new(hooks), std::sync::Arc::new(verifier))
}
