# Frozen GCP v0.1 contract

## Scope

The product is a new GCP-only Rust deployer. It contains no AWS code, state
migration, multi-cloud abstraction, domain purchase, project creation, billing
linking, GKE, multi-node topology, GUI, or GCP Cloud Worker implementation.

The supported local releases are Windows amd64, Linux amd64, macOS amd64 and
macOS arm64. The only server target is Ubuntu 24.04 amd64 with systemd 254 or
newer. The default VM is `e2-custom-2-4096` with a 50 GiB `pd-balanced` boot
disk.

## Public behavior

The CLI command and exit-code contract is frozen in `COMMANDS.md`. A plan binds
the canonical deployment spec, gcloud-brokered Google principal, project id and
number, location, observed DNS, exact stable release, cost estimate, resource
effects, and any explicit DNS overwrite. Apply accepts only that plan digest.

Configuration schema version 1 contains deployment name, project id, region,
zone, domain, DNS mode (`auto`, `cloud_dns`, or `external`), machine type,
boot-disk size/type, operator SSH CIDR, maximum monthly USD, stable or exact
release selection, and local connect agent. Unknown fields are rejected.

State lives under `~/.dirextalk/nodes/<service_id>/state.json`. It is sealed,
locked, and atomically replaced. It records project identity, phase,
`PendingEffect`, exact release, GCP resource references, SSH host identity,
host receipt, redacted local-wiring status, and integrity digest. Secrets live
only in their owning restrictive credential stores and are excluded from
state, reports, stdout, and JSONL.

The official installed `gcloud` CLI is the sole authentication broker and runs
with a private, isolated Dirextalk `CLOUDSDK_CONFIG`. The deployer never reads
or changes the operator's default gcloud configuration. Only authentication
and broker identity operations cross that process boundary; GCP discovery,
pricing, and resource lifecycle use in-process APIs. The product has no OAuth
client, consent-screen, or scope-review configuration of its own.

## Effects and identity

The deployer creates one custom VPC, `10.42.0.0/24` subnet, tag-scoped public
web and TURN firewall rules, `/32` operator SSH rule, regional static IPv4,
Ubuntu VM, and 50 GiB boot disk. The VM has no project service account.

Every resource reference records project number, location, numeric id,
self-link, deployment UUID and observed attributes. Every mutation follows:

```text
persist PendingEffect -> call API -> persist operation -> poll original
operation -> GET resource -> validate immutable identity -> persist receipt ->
clear PendingEffect
```

Destroy revalidates exact identity and DNS value. Its default approved plan
removes DNS, VM, firewall, address, subnet and network while retaining the boot
disk. `deploy destroy --purge-disk <numeric-id>` creates a distinct plan bound
to that exact numeric id and deletes it only after approval of that plan.

## Host and product completion

The deployer revalidates project, instance and address immediately before SSH,
pins the first host key, then requires it on every later connection. It uploads
digest-bound host installer and release bundle. The one-shot installer accepts
only a strict request, invokes fixed programs with typed argv, writes a signed
receipt, installs the canonical production topology, and installs the pinned
`dirextalk-updater` with its resident watchdog disabled.

Cloud DNS auto mode selects the longest matching existing public managed zone;
otherwise deployment stops in `waiting_user` with exactly one required A
record. Conflicting records require a new explicit plan. Authoritative and
independent public-recursive DNS proof must run on the verified server before
TLS integration.

Completion requires PostgreSQL, Message Server, Agent, Matrix, HTTPS, TURN,
the eight-digit App initialization code, real `agent_room_id`, a service-scoped
`dirextalk-connect` daemon, HTTP MCP initialization, tool discovery, and a
read-only MCP call. Cloud Worker is reported as
`disabled_by_product_scope`. Normal chat messages are never sent by validation.
