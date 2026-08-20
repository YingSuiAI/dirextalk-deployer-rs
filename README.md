# Dirextalk GCP Deployer

`dirextalk-deployer` creates one fresh production Dirextalk node in an existing
Google Cloud project. It uses built-in browser OAuth and in-process Google APIs;
`gcloud`, AWS credentials, and the legacy Bash deployer are not used.

The v0.1 contract is intentionally narrow: one Ubuntu 24.04 amd64 VM, one
long-lived domain, and no migration or adoption of an existing node.

## Before you begin

You need:

- a Google account with access to an existing, billing-enabled GCP project;
- the required GCP APIs already enabled, plus permission to create the
  resources shown by the plan;
- an existing long-lived domain and control of its DNS; and
- an operator public IPv4 address expressed as a `/32` SSH CIDR.

The deployer does not create a project, link a billing account, create a DNS
zone, or register a domain. A deployment creates paid resources. They continue
to incur charges until a destroy finishes, and the boot disk retained by the
normal destroy plan can continue billing afterward. Set a GCP budget and alerts
independently; the plan estimate is a guardrail, not a bill or price guarantee.

## Install a stable release

Download the archive for Windows amd64, Linux amd64, macOS amd64, or macOS
arm64 from the GitHub release. Download `SHA256SUMS` and
`release-manifest.json` from the same release, verify the archive hash, and
confirm that the manifest names the expected release tag and source revision
before placing `dirextalk-deployer` on `PATH`.

Each release also contains the bare Linux amd64 host installer, deterministic
runtime bundle, and canonical Ed25519-signed runtime manifest. The outer release
manifest binds their SHA-256 values, signing public key, application/updater
source revisions, and audited OAuth configuration hash. Do not use a release
with a missing or mismatched trust-chain field.

The audited runtime-signing public key is compiled into each CLI. A key rotation
therefore requires a new CLI release with an explicitly reviewed key identity;
the CLI never trusts a replacement key merely because it appears beside a
downloaded runtime manifest.

Stable release publication accepts only an exact `vX.Y.Z` tag. Release assets
are documented in [`packaging/README.md`](packaging/README.md).

## Configure

Copy [`examples/deployment.toml`](examples/deployment.toml) outside the source
tree and replace every example value. Configuration version 1 rejects unknown
fields. It contains identifiers and preferences only—never put OAuth tokens,
Matrix or agent tokens, SSH private keys, the App initialization code, or other
secrets in this file.

`release = "stable"` resolves to an exact stable release during planning. Use
an exact supported release identifier when reproducibility requires a specific
version. `maximum_monthly_usd` makes planning fail when the estimate exceeds
the operator's limit; it does not cap the GCP bill.

`connect_agent = "auto"` detects one supported local Agent runtime. Detection
fails closed when the result is ambiguous or unknown; it never guesses or
generates a generic fallback. Resolve the ambiguity or set the exact supported
Agent name, then rerun. `install_connect = true` installs and verifies the
service-scoped `dirextalk-connect` bridge; set it to `false` only when local
installation is intentionally deferred.

## Authenticate and inspect the project

```text
dirextalk-deployer auth login
dirextalk-deployer auth status
dirextalk-deployer project inspect --project <project-id>
```

`auth login` prints a clickable Google authorization URL and then tries to open
it in the default browser. If the browser does not appear, open the printed URL
manually while the CLI is still waiting. Complete Google authentication only in
that browser. Do not paste authorization codes or tokens into chat,
configuration, shell arguments, or issue reports. Tokens are kept in the
operating-system credential facility, not deployment state.
The product-owned OAuth client ID is compiled into the release; end users
supply neither an OAuth client ID nor a client secret, and source builds do not
read an OAuth client ID from the environment. Authorization requests only
`openid` and Google Cloud access—never email, name, or profile scopes. The
opaque Google subject is retained only for account continuity and is not
emitted by CLI output.
Use `dirextalk-deployer auth logout` to remove the local OAuth session.

## Plan and apply

Planning is read-only. Review the authentication status, project id and number,
location, observed DNS, exact releases, estimated cost, and every resource
effect before approving it.

```text
dirextalk-deployer deploy plan --config <deployment.toml>
dirextalk-deployer deploy apply --config <deployment.toml> --approve sha256:<plan-id>
```

Apply accepts only the digest from the current plan. A changed configuration,
principal, project identity, DNS observation, release, price input, or effect
set requires a new plan and a new approval. Never approve a digest you have not
just reviewed.

The deployer records each cloud mutation before executing it. If it stops or
reports an infrastructure error, preserve the node state and resume it; do not
start another same-name deployment.

```text
dirextalk-deployer deploy status --config <deployment.toml>
dirextalk-deployer deploy resume --config <deployment.toml>
```

## DNS waiting

`dns_mode = "auto"` uses the longest matching existing public Cloud DNS zone
when one is available. Otherwise, or with `dns_mode = "external"`, deployment
stops with exit code `2` and prints exactly one required record:

```text
<domain>  A  <reserved-static-ipv4>
```

Create that direct A record at the existing DNS provider, wait for authoritative
and public-recursive resolution, and run `deploy resume` with the same config.
Do not delete state or create a replacement VM while waiting. A conflicting A
record is never overwritten under an old approval; review and approve a new
plan if replacement is intended.

## Verify and connect locally

After apply or resume completes, run the product verification and install the
service-scoped local `dirextalk-connect` bridge enabled by `install_connect`:

```text
dirextalk-deployer deploy verify --config <deployment.toml>
dirextalk-deployer connect install --config <deployment.toml>
dirextalk-deployer connect status --config <deployment.toml>
dirextalk-deployer connect doctor --config <deployment.toml>
```

Verification covers HTTPS, Matrix, TURN, the real Agent room, HTTP MCP
initialization, tool discovery, and a read-only MCP call. It never sends a
normal chat message. The Cloud Worker is reported as
`disabled_by_product_scope`.

Local credentials and generated state live under
`~/.dirextalk/nodes/<service_id>/`. Do not copy that directory into a
repository, support ticket, or chat. Reports and structured output are
redacted; treat any unexpected secret in output as a failure and stop sharing
the output.

## Destroy

Destroy is also plan-bound. The first command is dry and returns the destroy
plan digest; inspect the exact identities and retained resources before
approving it.

```text
dirextalk-deployer deploy destroy --config <deployment.toml>
dirextalk-deployer deploy destroy --config <deployment.toml> --approve sha256:<destroy-plan-id>
dirextalk-deployer deploy status --config <deployment.toml>
```

The normal approved plan removes deployer-owned DNS, VM, firewall, address,
subnet, and network resources while retaining the boot disk. Purging that disk
requires its own numeric-id-bound plan and approval:

```text
dirextalk-deployer deploy destroy --config <deployment.toml> --purge-disk <numeric-disk-id>
dirextalk-deployer deploy destroy --config <deployment.toml> --purge-disk <numeric-disk-id> --approve sha256:<purge-plan-id>
```

External DNS and other user-owned DNS resources remain the operator's
responsibility. Do not assume billing has stopped until status and GCP
read-back confirm every intended deletion.

## Output and exit codes

Every command accepts `--output human|json|jsonl`. Structured output is useful
for automation but is not a secret transport.

- `0`: success.
- `2`: expected `waiting_user`, commonly external DNS or browser action.
- `1`: contract or infrastructure failure; inspect status and resume safely.

The frozen public behavior is in
[`references/gcp-v0.1-contract.md`](references/gcp-v0.1-contract.md). Developer
verification commands are in [`COMMANDS.md`](COMMANDS.md).
