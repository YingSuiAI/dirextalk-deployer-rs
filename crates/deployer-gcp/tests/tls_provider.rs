use deployer_gcp::ReqwestTransport;

#[test]
fn default_transport_installs_ring_in_a_fresh_process() {
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    let _transport = ReqwestTransport::default();
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
}
