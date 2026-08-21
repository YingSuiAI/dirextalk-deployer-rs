---
name: dirextalk-deployer-rs
description: Deploy, resume, inspect, verify, connect, or destroy a fresh Dirextalk production node in an existing billing-enabled GCP project. Use for the GCP Rust deployer; do not use for AWS or existing-node migration.
---

# Dirextalk GCP Deployer

Use the installed Rust `dirextalk-deployer` CLI. Read `README.md` only when the
operator flow needs detail, and read `references/gcp-v0.1-contract.md` before
changing public behavior.

## Preflight

Linux and WSL are the primary operator environments. Install the official
Google Cloud CLI from
<https://cloud.google.com/sdk/docs/install-sdk#linux>. Require `gcloud version`
to succeed.

Once per task, inspect `dirextalk-deployer --help`. Require the Rust command
surface `auth`, `project`, `deploy`, and `connect`, and reject a legacy `skill`
workflow or missing command. Do not repair a mismatch with the historical npm
package `dirextalk-deployer` or legacy AWS tooling.

```text
gcloud version
dirextalk-deployer --help
```

## Boundary

This deployer supports one fresh GCP node and an existing long-lived domain. It
does not create projects, attach billing, create DNS zones, buy domains, adopt
old state, or use gcloud for resource operations. The official installed
`gcloud` CLI is the sole authentication broker and must run only with the
deployer's private, isolated Dirextalk `CLOUDSDK_CONFIG`; the operator's default
gcloud configuration remains untouched. Discovery, pricing, and resource
lifecycle remain in-process API calls.

Before the first paid mutation, establish that the operator controls the
selected billing-enabled project and domain. Show one concise deployment
summary with region, machine profile, disk, DNS behavior, monthly estimate and
budget, explain that resources bill until destroyed, and obtain one
natural-language confirmation for that deployment intent. Plan identifiers are
machine-only state-binding values: consume them internally and never display
them or ask the user to copy them. The confirmation covers deterministic Cloud
DNS continuation and resumptions that preserve the same intent; it does not
cover a changed domain, project, region, machine profile, budget, unexpected
DNS replacement, or a later destroy.

## Lifecycle

1. Ask only for missing user decisions. Always offer economy `e2-small`
   (default; two shared vCPUs, 2 GiB) and standard `e2-custom-2-4096` (two fully
   billable vCPUs, 4 GiB), ask for the monthly budget, and ask which long-lived
   domain to use when none was supplied. Select or confirm the GCP region when
   it is not already clear. Copy `examples/deployment.toml` outside the
   repository and replace all example values. Use
   `operator_ssh_cidr = "0.0.0.0/0"` unless the user chooses a stable narrower
   IPv4 CIDR. Never add secrets to the config.
2. Resolve the local Agent before planning. When the active runtime is known,
   set `DIREXTALK_CONNECT_AGENT` to its exact supported token; for this Skill in
   Codex, use `codex`. An explicit config value takes precedence. Ask an Agent
   choice up front only when the active runtime is genuinely unknown; do not
   wait until paid resources exist or infer intent from every executable on
   `PATH`.
3. Run `auth login`, let the operator finish gcloud-brokered authentication only
   at the URL printed by gcloud or in its browser, then use `auth status` and
   `project inspect` to verify authentication and immutable project identity.
4. Prepare only the deployer's fixed prerequisite API set. Treat the plan
   identifier as internal, enable the exact missing set without a separate user
   prompt, and preserve its state for recovery. Never substitute arbitrary
   services or gcloud resource commands; enabling APIs is not authorization to
   create paid infrastructure.
5. Run `deploy plan --config <deployment.toml>`. Review identity, location,
   managed or external DNS behavior, exact release, estimate, budget and
   effects. Present the concise user summary and obtain the single deployment
   confirmation. After confirmation, pass the current plan identifier to
   `deploy apply` internally without printing it.
6. Continue the unchanged deployment until complete. A matching public Cloud
   DNS managed zone in the authenticated project authorizes the deployer to
   create or replace the reviewed A record automatically with its reserved
   static IP. If no matching zone exists, let infrastructure finish, give the
   user only the required external A record, wait for propagation, and resume;
   this is an external action request, not another deployment approval.
7. On interruption, preserve state, inspect `deploy status`, and run
   `deploy resume` for the same config. Never retry a mutation by resource name
   or create a same-name replacement. When explicitly asked to reconcile only
   the currently journaled effect and stop, use `deploy resume --pending-only`;
   it must not start a later effect or host installation, and an idle state is
   an action-required result rather than permission to advance.
8. Run `deploy verify`, then `connect install`, `connect status`, and
   `connect doctor` when `install_connect = true`. Verification must remain
   read-only and must not send normal chat.
9. To stop the node, generate the destroy plan, explain retained resources,
   obtain one natural-language destroy confirmation, and pass its internal plan
   identifier without exposing it. Confirm deletion with status and GCP
   read-back.

Exit `2` is expected `waiting_user`; continue the same state after the external
action. Exit `1` is a contract or infrastructure failure; inspect status rather
than resetting state.

## Secrets and billing

Never ask the user to paste authorization codes or tokens, SSH private keys,
Matrix or agent tokens, the App initialization code, service-account keys, or
payment data. Do not print, persist, or place secrets in arguments, config,
reports, or chat. Authentication credentials remain in the restricted isolated
Dirextalk gcloud configuration; generated node secrets remain in the restricted
service directory.

`maximum_monthly_usd` limits the accepted estimate, not the GCP bill. Normal
destroy retains the boot disk, which can keep billing until a separate
identity-bound purge is approved. External DNS and user-owned zones remain the
operator's responsibility.
