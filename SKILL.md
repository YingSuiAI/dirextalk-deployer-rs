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

Before a mutating operation, establish that the operator controls the selected
billing-enabled project and domain, show the current plan and estimate, explain
that resources bill until destroyed, and obtain authorization for that exact
plan digest. Never infer approval from an older plan, and never automatically
run apply or an approved destroy.

## Lifecycle

1. Before writing the config, ask the user to choose between economy
   `e2-small` (default; two shared vCPUs, 2 GiB) and standard
   `e2-custom-2-4096` (two fully billable vCPUs, 4 GiB). Copy
   `examples/deployment.toml` outside the repository and replace all example
   values. Use `operator_ssh_cidr = "0.0.0.0/0"` unless the user explicitly
   chooses a stable narrower IPv4 CIDR. Never add secrets to the config.
   `connect_agent = "auto"` must fail closed when local Agent detection is
   ambiguous or unknown; resolve the ambiguity or use one exact supported
   Agent name instead of guessing.
2. Run `auth login`, let the operator finish gcloud-brokered authentication only
   at the URL printed by gcloud or in its browser, then use `auth status` and
   `project inspect` to verify authentication and immutable project identity.
3. Run `project prepare --project <project-id>` without approval. Review the
   complete fixed prerequisite service set, the missing enable effects, and
   project identity. Only after authorization, rerun it with the exact current
   `--approve sha256:<plan-id>`. Preserve its project state and use the same
   command and digest to resume an interruption; never substitute arbitrary
   services or gcloud resource commands.
4. Run `deploy plan --config <deployment.toml>`. Review identity, location,
   DNS, exact release, estimate, and effects.
5. Only after authorization, run `deploy apply` with the unchanged config and
   its exact `sha256:<plan-id>` approval digest.
6. On interruption, preserve state, inspect `deploy status`, and run
   `deploy resume` for the same config. Never retry a mutation by resource name
   or create a same-name replacement. When explicitly asked to reconcile only
   the currently journaled effect and stop, use `deploy resume --pending-only`;
   it must not start a later effect or host installation, and an idle state is
   an action-required result rather than permission to advance.
7. When external DNS is required, give the operator only the displayed A
   record, wait for propagation, and resume. A conflicting record requires a
   new plan and approval.
8. Run `deploy verify`, then `connect install`, `connect status`, and
   `connect doctor` when `install_connect = true`. Verification must remain
   read-only and must not send normal chat.
9. To stop the node, run unapproved `deploy destroy` to obtain the destroy
   plan, explain retained resources, then use its exact digest only after
   authorization. Confirm deletion with status and GCP read-back.

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
