# Dirextalk GCP Deployer

`dirextalk-deployer` creates one fresh production Dirextalk node in an existing
Google Cloud project. The official installed `gcloud` CLI is its sole
authentication broker. Cloud discovery, pricing, and resource lifecycle use
in-process Google APIs; AWS credentials and the legacy Bash deployer are not
used.

The v0.1 contract is intentionally narrow: one Ubuntu 24.04 amd64 VM, one
long-lived domain, and no migration or adoption of an existing node.

## Before you begin

You need:

- a Google account with access to an existing, billing-enabled GCP project;
- the official Google Cloud CLI, installed on Linux or WSL from the
  [Google Cloud instructions](https://cloud.google.com/sdk/docs/install-sdk#linux)
  and confirmed with `gcloud version`;
- permission to enable the five fixed Dirextalk GCP APIs and create the
  resources shown by later deployment plans;
- an existing long-lived domain and control of its DNS; and
- an explicit canonical IPv4 SSH source CIDR. The supplied configuration uses
  `0.0.0.0/0` so SSH remains reachable when the operator's public IP changes.

The deployer does not create a project, link a billing account, create a DNS
zone, or register a domain. A deployment creates paid resources. They continue
to incur charges until a destroy finishes, and the boot disk retained by the
normal destroy plan can continue billing afterward. Set a GCP budget and alerts
independently; the plan estimate is a guardrail, not a bill or price guarantee.

## Install a stable release

Install the current multi-platform CLI package from npm using the Rust
project's distinct package name (the historical `dirextalk-deployer` package
is unrelated and must not be used):

```text
npm install --global dirextalk-deployer-rs@latest
dirextalk-deployer --version
```

Download the archive for Windows amd64, Linux amd64, macOS amd64, or macOS
arm64 from the GitHub release. Download `SHA256SUMS` and
`release-manifest.json` from the same release, verify the archive hash, and
confirm that the manifest names the expected release tag and source revision
before placing `dirextalk-deployer` on `PATH`.

Each release also contains the bare Linux amd64 host installer, deterministic
runtime bundle, and canonical Ed25519-signed runtime manifest. The outer release
manifest binds their SHA-256 values, signing public key, application/updater
source revisions, and immutable runtime inputs. Do not use a release with a
missing or mismatched trust-chain field.

The audited runtime-signing public key is compiled into each CLI. A key rotation
therefore requires a new CLI release with an explicitly reviewed key identity;
the CLI never trusts a replacement key merely because it appears beside a
downloaded runtime manifest.

Stable release publication accepts only an exact `vX.Y.Z` tag. Release assets
are documented in [`packaging/README.md`](packaging/README.md).

## Configure

Copy [`examples/deployment.toml`](examples/deployment.toml) outside the source
tree and replace every example value. Configuration version 1 rejects unknown
fields. It contains identifiers and preferences only—never put gcloud
credentials or access tokens, Matrix or agent tokens, SSH private keys, the App
initialization code, or other secrets in this file.

`release = "stable"` resolves to an exact stable release during planning. Use
an exact supported release identifier when reproducibility requires a specific
version. `maximum_monthly_usd` makes planning fail when the estimate exceeds
the operator's limit; it does not cap the GCP bill.

`operator_ssh_cidr = "0.0.0.0/0"` deliberately allows SSH from any IPv4
source so a changing operator address does not lock out recovery. A canonical
narrower IPv4 CIDR remains supported when the operator has a stable range. The
configured value is included in both the SSH firewall effect and the internal
plan binding, so changing it requires a new user-facing deployment review.

Every deployment chooses one of two supported machine profiles. The default
economy profile is `e2-small`: two shared guest vCPUs, 2 GiB memory, and 0.5
sustained vCPU in aggregate. It is priced from 365 monthly E2 core-hours plus
1,460 GiB-hours at the 730-hour planning horizon and still requires two units
of regional `CPUS` quota. Choose `e2-custom-2-4096` for the standard profile
with two fully billable vCPUs and 4 GiB memory. Other machine types are
rejected before cloud planning.

`connect_agent = "auto"` detects one supported local Agent runtime. An
orchestrator that already knows its runtime should set
`DIREXTALK_CONNECT_AGENT` to the canonical Agent token before planning and
applying; an explicit non-`auto` config value takes precedence. PATH detection
still fails closed when the result is ambiguous or unknown. `install_connect =
true` installs and verifies the service-scoped `dirextalk-connect` bridge; set
it to `false` only when local installation is intentionally deferred.

## Authenticate and inspect the project

```text
dirextalk-deployer auth login
dirextalk-deployer auth status
dirextalk-deployer project inspect --project <project-id>
dirextalk-deployer project prepare --project <project-id>
```

The `auth login`, `auth status`, and `auth logout` commands broker
authentication through the official installed `gcloud` CLI. They always set a
private, isolated Dirextalk `CLOUDSDK_CONFIG`; they neither read nor change the
operator's default gcloud configuration. On Linux and Unix, `auth login` prints
gcloud's Google authorization URL so it can be opened explicitly; on Windows,
gcloud retains its normal browser behavior. Complete sign-in only at that URL
or in the browser opened by gcloud, and never paste authorization codes or
tokens into chat, configuration, shell arguments, or issue reports.
Credentials remain in that restricted isolated gcloud configuration and are
never copied into deployment state. `auth logout` removes the session from the
isolated configuration only.

Only authentication and broker identity cross the gcloud process boundary.
Project discovery, pricing, planning, and resource lifecycle calls remain
in-process API operations; the deployer does not run gcloud resource commands.

`project prepare` first reports the complete fixed prerequisite set plus the
currently missing subset: Service Usage, Resource Manager, Cloud Billing,
Compute Engine, and Cloud DNS. The Skill verifies the immutable project
identity and passes the plan's opaque binding internally; it does not ask the
user to copy a machine token. The prepared run enables only the missing
services, recording and resuming each Service Usage operation before moving to
the next. It does not create a project, link billing, or create paid resources.

## Plan and apply

Planning is read-only. The user-facing review contains the project, location,
domain and DNS behavior, one of the two supported machine profiles, disk,
estimated monthly cost, budget and continuing-billing warning. One natural-
language confirmation authorizes that unchanged deployment intent.

```text
dirextalk-deployer deploy plan --config <deployment.toml>
```

The Skill passes the current plan binding to `deploy apply` internally and does
not display it. A changed configuration, principal, project identity, DNS
observation, release, price input, or effect set is not covered by the user's
confirmation and must be summarized again.

The deployer records each cloud mutation before executing it. If it stops or
reports an infrastructure error, preserve the node state and resume it; do not
start another same-name deployment.

```text
dirextalk-deployer deploy status --config <deployment.toml>
dirextalk-deployer deploy resume --config <deployment.toml>
```

To stop immediately after recovering only the currently journaled cloud
effect, use `deploy resume --config <deployment.toml> --pending-only`. It
revalidates the original approved plan and identities, reconciles that one
effect through the normal recovery path, and returns
`DEPLOY_PENDING_EFFECT_RECONCILED` before any later effect or host installation.
It requires an existing pending effect; it never advances an idle deployment.

## DNS waiting

`dns_mode = "auto"` uses the longest matching existing public Cloud DNS zone
when one is available. The initial plan binds that zone and the observed A
record values; after the reserved address is known, the deployer derives the
exact A-record effect and continues without another user approval. A concurrent
record change still fails closed.

When no matching zone exists, or with `dns_mode = "external"`, deployment stops
with exit code `2` and prints exactly one required record:

```text
<domain>  A  <reserved-static-ipv4>
```

Create that direct A record at the existing DNS provider, wait for authoritative
and public-recursive resolution, and run `deploy resume` with the same config.
Do not delete state or create a replacement VM while waiting. This is an
external action request, not another deployment approval; resume the unchanged
deployment after the record resolves.

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

Destroy is also plan-bound. The first command is dry; inspect the exact
identities and retained resources, obtain one natural-language destroy
confirmation, then let the Skill pass the opaque plan binding internally.

```text
dirextalk-deployer deploy destroy --config <deployment.toml>
dirextalk-deployer deploy status --config <deployment.toml>
```

The normal approved plan removes deployer-owned DNS, VM, firewall, address,
subnet, and network resources, then uninstalls the service-scoped local Connect
daemon, while retaining the boot disk. Purging that disk requires its own
numeric-id-bound plan and approval:

```text
dirextalk-deployer deploy destroy --config <deployment.toml> --purge-disk <numeric-disk-id>
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
