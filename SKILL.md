---
name: dirextalk-deployer
description: Deploy, resume, inspect, verify, connect, or destroy a fresh Dirextalk production node in an existing billing-enabled GCP project. Use for the GCP Rust deployer; do not use for AWS or existing-node migration.
---

# Dirextalk GCP Deployer

Use the installed `dirextalk-deployer` CLI. Read `README.md` for the operator
flow and `references/gcp-v0.1-contract.md` before changing public behavior.

## Boundary

This deployer supports one fresh GCP node and an existing long-lived domain. It
does not create projects, attach billing, create DNS zones, buy domains, adopt
old state, or invoke `gcloud`. Do not route GCP work through the retired AWS
Bash deployer.

Before a mutating operation, establish that the operator controls the selected
billing-enabled project and domain, show the current plan and estimate, explain
that resources bill until destroyed, and obtain authorization for that exact
plan digest. Never infer approval from an older plan.

## Lifecycle

1. Copy `examples/deployment.toml` outside the repository and replace all
   example values. Never add secrets to the config. `connect_agent = "auto"`
   must fail closed when local Agent detection is ambiguous or unknown; resolve
   the ambiguity or use one exact supported Agent name instead of guessing.
2. Run `auth login`, let the operator finish OAuth only in Google's browser,
   then use `auth status` and `project inspect` to verify the principal and
   immutable project identity.
3. Run `deploy plan --config <deployment.toml>`. Review identity, location,
   DNS, exact release, estimate, and effects.
4. Only after authorization, run `deploy apply` with the unchanged config and
   its exact `sha256:<plan-id>` approval digest.
5. On interruption, preserve state, inspect `deploy status`, and run
   `deploy resume` for the same config. Never retry a mutation by resource name
   or create a same-name replacement.
6. When external DNS is required, give the operator only the displayed A
   record, wait for propagation, and resume. A conflicting record requires a
   new plan and approval.
7. Run `deploy verify`, then `connect install`, `connect status`, and
   `connect doctor` when `install_connect = true`. Verification must remain
   read-only and must not send normal chat.
8. To stop the node, run unapproved `deploy destroy` to obtain the destroy
   plan, explain retained resources, then use its exact digest only after
   authorization. Confirm deletion with status and GCP read-back.

Exit `2` is expected `waiting_user`; continue the same state after the external
action. Exit `1` is a contract or infrastructure failure; inspect status rather
than resetting state.

## Secrets and billing

Never ask the user to paste OAuth codes or tokens, SSH private keys, Matrix or
agent tokens, the App initialization code, service-account keys, or payment
data. Do not print, persist, or place secrets in arguments, config, reports, or
chat. OAuth belongs in OS credentials; generated node secrets remain in the
restricted service directory.

`maximum_monthly_usd` limits the accepted estimate, not the GCP bill. Normal
destroy retains the boot disk, which can keep billing until a separate
identity-bound purge is approved. External DNS and user-owned zones remain the
operator's responsibility.
