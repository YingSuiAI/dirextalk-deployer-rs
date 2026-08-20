# Signed GCP runtime assets

These files are the root-owned, GCP v0.1 production topology embedded in the
signed Linux runtime bundle. They are not host lifecycle scripts. The six shell
files are mounted only as fixed Compose `configs` and execute inside their
declared containers.

The Compose project is always `dirextalk-p2p` and contains PostgreSQL, coturn,
Message Server initialization/runtime, Agent secret initialization/migration/
runtime, and Caddy. AWS Cloud Worker, GCP Cloud Worker, extension runner, and
Core runner services are intentionally absent in v0.1. Cloud Worker remains
`disabled_by_product_scope`.

The deployer writes a protected `.env`, `agent-config.yaml`, and `secrets/`
beside the installed `/var/dirextalk-message-server/docker-compose.yml` only
after immutable project/host identity validation. `MESSAGE_SERVER_IMAGE`,
`AGENT_IMAGE`, `POSTGRES_IMAGE`, `UTILITY_IMAGE`, `CADDY_IMAGE`, and
`COTURN_IMAGE` must be the exact tag-and-digest references from the signed
manifest. `DOMAIN` is the reviewed production domain. Secrets never belong in
the `.env` file.

Release CI parses the Compose template without interpolation and requires every
service to use exactly one of those signed image variables. Local builds and
unallowlisted images are rejected. Image layers are pulled by digest on the
verified server and are never embedded in the release bundle.
