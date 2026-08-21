# Command map

All cloud mutation commands are dry unless the current machine-generated plan
binding is supplied. Orchestration Skills keep that binding internal: users
confirm the displayed deployment or destroy intent in natural language and are
never asked to copy a hash. Examples use portable paths and never place
credentials in arguments.

The official Google Cloud CLI is a prerequisite and the sole authentication
broker. On Linux and WSL, install it from
<https://cloud.google.com/sdk/docs/install-sdk#linux> and run `gcloud version`
before using the deployer. The `auth` commands below run gcloud only
against a private, isolated Dirextalk `CLOUDSDK_CONFIG`; they never reuse the
operator's default configuration. Project inspection and resource lifecycle
remain in-process API calls, not gcloud resource commands.

```text
dirextalk-deployer auth login
dirextalk-deployer auth status
dirextalk-deployer auth logout

dirextalk-deployer project list
dirextalk-deployer project inspect --project <project-id>
dirextalk-deployer project prepare --project <project-id>
dirextalk-deployer project prepare --project <project-id> --approve "$DIREXTALK_INTERNAL_PLAN_ID"

dirextalk-deployer deploy plan --config <deployment.toml>
dirextalk-deployer deploy apply --config <deployment.toml> --approve "$DIREXTALK_INTERNAL_PLAN_ID"
dirextalk-deployer deploy resume --config <deployment.toml>
dirextalk-deployer deploy resume --config <deployment.toml> --pending-only
dirextalk-deployer deploy status --config <deployment.toml>
dirextalk-deployer deploy verify --config <deployment.toml>
dirextalk-deployer deploy destroy --config <deployment.toml>
dirextalk-deployer deploy destroy --config <deployment.toml> --approve "$DIREXTALK_INTERNAL_PLAN_ID"
dirextalk-deployer deploy destroy --config <deployment.toml> --purge-disk <numeric-id>
dirextalk-deployer deploy destroy --config <deployment.toml> --purge-disk <numeric-id> --approve "$DIREXTALK_INTERNAL_PLAN_ID"

dirextalk-deployer connect install --config <deployment.toml>
dirextalk-deployer connect status --config <deployment.toml>
dirextalk-deployer connect doctor --config <deployment.toml>
```

Every command supports `--output human|json|jsonl`. Exit `0` is success, `2`
is an expected `waiting_user` condition, and `1` is a contract or
infrastructure failure.

`deploy resume --pending-only` requires an existing journaled effect from the
original approved plan. It reconciles exactly that effect and returns
`DEPLOY_PENDING_EFFECT_RECONCILED` without starting a later effect or host
installation. If no effect is pending, it exits `waiting_user` instead of
advancing the deployment.

For an initial plan bound to a matching public Cloud DNS managed zone, apply
derives the exact A-record mutation from the recorded static-address receipt
and continues automatically. External DNS still exits `waiting_user` with the
single required A record. Set `DIREXTALK_CONNECT_AGENT` when the calling
orchestrator already knows the active local Agent; an explicit non-`auto`
configuration remains authoritative.
