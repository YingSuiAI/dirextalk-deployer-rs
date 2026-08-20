use deployer_host::{
    BundleBuildRequest, CADDY_DIGEST, COTURN_DIGEST, DigestHex, ImageReference, ImageRole,
    POSTGRES_UTILITY_DIGEST, canonical_json,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn builder_reads_seed_from_restrictive_file_and_emits_redacted_report() {
    let directory = tempfile::tempdir().unwrap();
    let compose = directory.path().join("docker-compose.yml");
    let caddyfile = directory.path().join("Caddyfile");
    let message_server_initializer = directory.path().join("initialize-message-server.sh");
    let agent_secret_materializer = directory.path().join("materialize-agent-secrets.sh");
    let message_server_entrypoint = directory.path().join("message-server-entrypoint.sh");
    let capability_ca_initializer = directory.path().join("initialize-capability-ca.sh");
    let postgres_entrypoint = directory.path().join("postgres-entrypoint.sh");
    let postgres_initializer = directory.path().join("initialize-postgres.sh");
    let updater = directory.path().join("dirextalk-updater");
    let unit = directory.path().join("dirextalk-updater.service");
    let seed = directory.path().join("release-signing.seed");
    let request_path = directory.path().join("request.json");
    let output_path = directory.path().join("release-bundle.tar");
    fs::write(&compose, b"services: {}").unwrap();
    fs::write(&caddyfile, b"{$DOMAIN}").unwrap();
    for helper in [
        &message_server_initializer,
        &agent_secret_materializer,
        &message_server_entrypoint,
        &capability_ca_initializer,
        &postgres_entrypoint,
        &postgres_initializer,
    ] {
        fs::write(helper, b"#!/bin/sh\nexit 0\n").unwrap();
    }
    fs::write(&updater, b"updater-binary").unwrap();
    fs::write(&unit, b"[Service]").unwrap();
    fs::write(&seed, [7; 32]).unwrap();
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
    let images = ImageRole::required()
        .iter()
        .map(|role| ImageReference {
            role: *role,
            repository: role.allowed_repository().into(),
            tag: match role {
                ImageRole::Postgres | ImageRole::Utility => Some("pg18".into()),
                ImageRole::MessageServer | ImageRole::Agent => Some("v1.2.3".into()),
                ImageRole::Caddy => None,
                ImageRole::Coturn => Some("4.6.3-alpine".into()),
            },
            digest: DigestHex::parse(match role {
                ImageRole::Postgres | ImageRole::Utility => POSTGRES_UTILITY_DIGEST,
                ImageRole::Caddy => CADDY_DIGEST,
                ImageRole::Coturn => COTURN_DIGEST,
                ImageRole::MessageServer | ImageRole::Agent => {
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })
            .unwrap(),
            source_revision: if matches!(role, ImageRole::MessageServer | ImageRole::Agent) {
                Some("0123456789abcdef0123456789abcdef01234567".into())
            } else {
                None
            },
        })
        .collect();
    let request = BundleBuildRequest {
        schema_version: 1,
        release: "stable-2026-08-20".into(),
        images,
        compose_path: compose,
        caddyfile_path: caddyfile,
        message_server_initializer_path: message_server_initializer,
        agent_secret_materializer_path: agent_secret_materializer,
        message_server_entrypoint_path: message_server_entrypoint,
        capability_ca_initializer_path: capability_ca_initializer,
        postgres_entrypoint_path: postgres_entrypoint,
        postgres_initializer_path: postgres_initializer,
        updater_binary_path: updater.clone(),
        updater_unit_path: unit,
        updater_version: "v1.0.0".into(),
        updater_source_url: "https://releases.example/dirextalk-updater".into(),
        updater_sha256: DigestHex::calculate(&fs::read(updater).unwrap()),
        output_bundle_path: output_path.clone(),
    };
    fs::write(&request_path, canonical_json(&request).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dirextalk-bundle-builder"))
        .args(["--request", request_path.to_str().unwrap()])
        .env("DIREXTALK_BUNDLE_SIGNING_SEED_FILE", &seed)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_path.is_file());
    assert!(!output.stdout.windows(32).any(|window| window == [7; 32]));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["output_path"], output_path.to_str().unwrap());
    assert_eq!(report["bundle_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(report["manifest_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        report["release_signing_public_key"].as_str().unwrap().len(),
        64
    );
}
