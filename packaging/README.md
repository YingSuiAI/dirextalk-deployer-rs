# Release artifacts

Stable releases are created only from exact `vX.Y.Z` tags whose version matches
the workspace package version. The release workflow builds these archives:

| Component | Target | Archive |
| --- | --- | --- |
| CLI | Windows amd64 | `.zip` |
| CLI | Linux amd64 | `.tar.gz` |
| CLI | macOS amd64 | `.tar.gz` |
| CLI | macOS arm64 | `.tar.gz` |
| Host installer | Ubuntu 24.04 / Linux amd64 | bare executable |
| Signed runtime bundle | Ubuntu 24.04 / Linux amd64 | deterministic `.tar` |
| Signed runtime manifest | Ubuntu 24.04 / Linux amd64 | canonical `.json` |

The workflow refuses an incomplete or additional asset set. It then writes
`SHA256SUMS` and `release-manifest.json`. The manifest binds every asset hash to
its component, target, release tag, repository, and full source revision. It
also records the Ed25519 runtime signing public key and the exact Message
Server, Agent, updater, Compose, Caddy, and container-helper provenance. Its
format is defined by `release-manifest.schema.json`.

The runtime bundle contains no image layers and no legacy cloud lifecycle
scripts. `deployer_host::build_bundle` creates its canonical tar and signature
from the root-owned `runtime/` Compose/Caddy/container-helper files, the
root-owned updater unit, the checksum-verified updater binary, and six
allowlisted tag-and-digest image references.

## Required stable-release configuration

The tag workflow fails closed until release maintainers configure all of these
GitHub variables with audited immutable values:

- `DIREXTALK_GOOGLE_OAUTH_CLIENT_ID`
- `DIREXTALK_GOOGLE_OAUTH_CLIENT_ID_AUDITED_SHA256`
- `DIREXTALK_GOOGLE_OAUTH_CONSENT_AUDIT_REVISION`
- `DIREXTALK_GOOGLE_OAUTH_CONSENT_REVIEWED` (exactly `true`)
- `DIREXTALK_GOOGLE_OAUTH_SCOPE_REVIEWED_SHA256`
- `DIREXTALK_RELEASE_ED25519_PUBLIC_KEY_HEX` and
  `DIREXTALK_RELEASE_ED25519_PUBLIC_KEY_AUDITED_SHA256`
- `DIREXTALK_UPDATER_VERSION`, `DIREXTALK_UPDATER_SOURCE_REVISION`,
  `DIREXTALK_UPDATER_BINARY_URL`, and `DIREXTALK_UPDATER_BINARY_SHA256`
- Message Server and Agent `VERSION`, `DIGEST`, and `SOURCE_REVISION` variables
  named in `.github/workflows/release.yml`

The reviewed OAuth scope hash is SHA-256 over these newline-terminated lines in
this exact order:

```text
installed-public-client
loopback-redirect
pkce-s256
openid
https://www.googleapis.com/auth/cloud-platform
```

This exact scope-review input hashes to
`fa675cfc945cff1bba0f69617589fe3d867947d7af61e065926b320252d8e50e`.

The only release secret is
`DIREXTALK_RELEASE_ED25519_SEED_HEX`: one raw 32-byte Ed25519 seed encoded as
64 lowercase hexadecimal characters. CI materializes it in a same-owner `0600`
temporary file, passes only that file path to the host-owned builder, and
deletes the file in an unconditional cleanup step. Never store the seed in a
repository variable, request JSON, artifact, log, or command argument.

The public-key audit hash is SHA-256 over the decoded 32 public-key bytes, not
over its 64-character hexadecimal representation. Every CLI embeds the audited
public key, and CI requires the bundle builder to derive that exact key from the
protected seed. Rotate the key only through a new CLI release with a newly
reviewed public-key identity and audit hash; never silently accept a second key
or fall back to a key supplied only beside the runtime manifest.

For each Message Server and Agent pin, CI also proves that the exact version tag
selects the supplied Linux amd64 manifest digest, hashes the registry manifest
and config bytes, and requires `org.opencontainers.image.revision` to equal the
supplied full source revision. The short-lived registry bearer token remains in
memory and is never printed or uploaded.

Publishing fails if the GitHub release already exists. This prevents a rerun
from replacing assets or the manifest under an existing stable version.
