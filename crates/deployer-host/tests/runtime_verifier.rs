#[test]
fn caddy_identity_query_requests_the_full_container_id() {
    let script = include_str!("../../../runtime/verify-runtime.sh");

    assert!(script.contains("docker ps --no-trunc --quiet"));
    assert!(!script.contains("docker ps --quiet"));
}
