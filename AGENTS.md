# Dirextalk GCP Deployer

This repository owns the fresh-only Rust GCP BYOC deployer. Read
`references/gcp-v0.1-contract.md` before changing public commands, schemas,
cloud effects, host installation, local wiring, or destroy behavior.

## Product boundary

- The only cloud is GCP. Do not add AWS dependencies, AWS state readers,
  migrations, provider abstractions, or compatibility shims.
- The official installed `gcloud` CLI is the sole authentication broker. Run
  it only with the deployer's private, isolated Dirextalk `CLOUDSDK_CONFIG`;
  never inherit or mutate the operator's default gcloud configuration. GCP
  discovery, pricing, and resource lifecycle calls remain in-process APIs; do
  not use gcloud resource commands.
- The target host is Ubuntu 24.04 `linux/amd64` and receives a fixed one-shot
  Rust installer; no runtime shell state machine or arbitrary remote command
  surface is allowed.
- Existing paid GCP projects and existing long-lived domains are prerequisites.
  v0.1 does not create projects, link billing accounts, create DNS zones, or buy
  domains.
- `dirextalk-updater` remains the resident update/recovery boundary. Do not add
  a second daemon with overlapping lifecycle authority.
- Cloud Worker is disabled by product scope. Never substitute a GCP zone for
  the AWS-only `core_cloud_worker_host_region` contract.

## Safety

- Persist an authenticated `PendingEffect` before every cloud mutation. Resume
  the recorded operation and re-read the resource; never retry by name alone.
- Before every sensitive cloud read/write/delete, SSH connection, retry, or
  postcondition, revalidate project number plus the strongest immutable
  resource identity available.
- Never log or copy gcloud credentials or access tokens, Matrix tokens, agent
  tokens, private keys, the App initialization code, or conversation content
  into deployment state, JSON/JSONL, or reports. Restrict the isolated
  Dirextalk `CLOUDSDK_CONFIG` to its owning user.
- A dry plan never mutates GCP. Apply and destroy require the exact current
  SHA-256 plan approval.
- Keep generated files under `~/.dirextalk/nodes/<service_id>/`, use atomic
  same-directory replacement, and restrict permissions where supported.

## Development and finish

- Use Rust 2024, the pinned toolchain, and no unsafe Rust.
- Keep one writer per crate. Prefer narrow API traits for testing, not cloud
  portability.
- Before committing, run:

```text
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo run --locked -p deployer-cli -- --help
git diff --check
```
