# Signed GCP runtime assets

`split-agent/` is the single production runtime source used by the Rust GCP
deployer. Release packaging creates a deterministic signed archive from this
tree; the host installer expands that archive under
`/var/dirextalk-message-server/deploy/split-agent`.

The application Compose project contains PostgreSQL, coturn, Message Server,
the main Agent, `extension-runner`, `core-runner`, and their fixed initialization
services. The two runners retain the original socket, persistent-volume,
delegated cgroup-v2, systemd, UID and AppArmor contracts. The independent edge
Compose project uses `Caddyfile` and `edge-compose.override.yaml` so it can reach
the Message Server, Agent, static-site root and updater Unix socket.

`provision-local.sh` enables local extensions, workloads, static sites and
knowledge. AWS Cloud Worker remains disabled for the GCP product scope; the
protected `disabled` receipt is retained solely so Agent updates preserve that
decision.

`read-product-bootstrap.sh` and `verify-runtime.sh` are fixed root-owned host
entrypoints used by connect and verify. They resolve the generated split stack
only from its protected `.env` and `.manifest`; callers cannot supply a Compose
path, project or command.

Release CI validates both Compose projects and requires every service image to
come from the signed six-role image manifest. Application images are pulled by
digest and bound to their exact version tags because the updater records and
checks those immutable release identities.
