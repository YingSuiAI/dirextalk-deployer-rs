#!/usr/bin/env python3
"""Fetch and pin the non-secret inputs for the canonical host bundle builder."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import tempfile
import urllib.parse
import urllib.request


POSTGRES_UTILITY_DIGEST = "691673308c99d2161ba298736f3147f1f22d79de2fb7ec93ae9b4afcab870b62"
CADDY_DIGEST = "844f60b64e4724a5aa8245e019dace0d3f199f7433ce6c57676cb30a920dbad9"
COTURN_DIGEST = "e2bca2f79a4269d7240de5872ab60a9305013ad37296d2acf14f9510874346be"
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def fail(message: str) -> None:
    raise SystemExit(message)


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        fail(f"{name} is required")
    return value


def exact(value: str, pattern: re.Pattern[str], name: str) -> str:
    if not pattern.fullmatch(value) or set(value) == {"0"}:
        fail(f"{name} has an invalid immutable value")
    return value


def updater_release_url(value: str, version: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    expected = (
        f"/YingSuiAI/dirextalk-updater/releases/download/{version}/"
        "dirextalk-updater-linux-amd64"
    )
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected
    ):
        fail("DIREXTALK_UPDATER_BINARY_URL must name the exact YingSuiAI release asset")
    return value


def download(url: str, destination: pathlib.Path, expected_sha256: str, maximum: int) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "dirextalk-release-builder/1"})
    digest = hashlib.sha256()
    size = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(request, timeout=60) as response:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
            temporary_path = pathlib.Path(temporary.name)
            try:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > maximum:
                        fail(f"download exceeded fixed size limit: {url}")
                    digest.update(chunk)
                    temporary.write(chunk)
                temporary.flush()
                os.fsync(temporary.fileno())
            except BaseException:
                temporary_path.unlink(missing_ok=True)
                raise
    if size == 0 or digest.hexdigest() != expected_sha256:
        temporary_path.unlink(missing_ok=True)
        fail(f"download did not match its pinned SHA-256: {url}")
    temporary_path.replace(destination)


def write_json(path: pathlib.Path, value: object, mode: int = 0o644) -> None:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary_path = pathlib.Path(temporary.name)
        temporary.write(encoded)
        temporary.flush()
        os.fsync(temporary.fileno())
    temporary_path.chmod(mode)
    temporary_path.replace(path)


def inputs() -> dict[str, object]:
    release = exact(required("RELEASE_TAG"), VERSION, "RELEASE_TAG")
    source_revision = exact(required("SOURCE_REVISION"), HEX_40, "SOURCE_REVISION")
    release_public_key = exact(
        required("DIREXTALK_RELEASE_ED25519_PUBLIC_KEY_HEX"),
        HEX_64,
        "DIREXTALK_RELEASE_ED25519_PUBLIC_KEY_HEX",
    )
    release_public_key_audit_hash = exact(
        required("DIREXTALK_RELEASE_ED25519_PUBLIC_KEY_AUDITED_SHA256"),
        HEX_64,
        "DIREXTALK_RELEASE_ED25519_PUBLIC_KEY_AUDITED_SHA256",
    )
    if (
        hashlib.sha256(bytes.fromhex(release_public_key)).hexdigest()
        != release_public_key_audit_hash
    ):
        fail("release Ed25519 public key does not match its audited SHA-256")
    updater_version = exact(
        required("DIREXTALK_UPDATER_VERSION"), VERSION, "DIREXTALK_UPDATER_VERSION"
    )
    updater_revision = exact(
        required("DIREXTALK_UPDATER_SOURCE_REVISION"),
        HEX_40,
        "DIREXTALK_UPDATER_SOURCE_REVISION",
    )
    updater_url = updater_release_url(
        required("DIREXTALK_UPDATER_BINARY_URL"), updater_version
    )
    updater_sha = exact(
        required("DIREXTALK_UPDATER_BINARY_SHA256"),
        HEX_64,
        "DIREXTALK_UPDATER_BINARY_SHA256",
    )
    message_version = exact(
        required("DIREXTALK_MESSAGE_SERVER_VERSION"),
        VERSION,
        "DIREXTALK_MESSAGE_SERVER_VERSION",
    )
    message_digest = exact(
        required("DIREXTALK_MESSAGE_SERVER_DIGEST"),
        HEX_64,
        "DIREXTALK_MESSAGE_SERVER_DIGEST",
    )
    message_revision = exact(
        required("DIREXTALK_MESSAGE_SERVER_SOURCE_REVISION"),
        HEX_40,
        "DIREXTALK_MESSAGE_SERVER_SOURCE_REVISION",
    )
    agent_version = exact(
        required("DIREXTALK_AGENT_VERSION"), VERSION, "DIREXTALK_AGENT_VERSION"
    )
    agent_digest = exact(
        required("DIREXTALK_AGENT_DIGEST"), HEX_64, "DIREXTALK_AGENT_DIGEST"
    )
    agent_revision = exact(
        required("DIREXTALK_AGENT_SOURCE_REVISION"),
        HEX_40,
        "DIREXTALK_AGENT_SOURCE_REVISION",
    )
    return {
        "release": release,
        "release_signing_public_key": release_public_key,
        "release_signing_public_key_audited_sha256": release_public_key_audit_hash,
        "source_revision": source_revision,
        "updater": {
            "version": updater_version,
            "source_revision": updater_revision,
            "binary_url": updater_url,
            "binary_sha256": updater_sha,
        },
        "message_server": {
            "version": message_version,
            "digest": message_digest,
            "source_revision": message_revision,
        },
        "agent": {
            "version": agent_version,
            "digest": agent_digest,
            "source_revision": agent_revision,
        },
    }


def image_references(values: dict[str, object]) -> list[dict[str, object]]:
    message = values["message_server"]
    agent = values["agent"]
    assert isinstance(message, dict) and isinstance(agent, dict)
    return [
        {
            "role": "postgres",
            "repository": "docker.io/pgvector/pgvector",
            "tag": "pg18",
            "digest": POSTGRES_UTILITY_DIGEST,
            "source_revision": None,
        },
        {
            "role": "utility",
            "repository": "docker.io/pgvector/pgvector",
            "tag": "pg18",
            "digest": POSTGRES_UTILITY_DIGEST,
            "source_revision": None,
        },
        {
            "role": "message_server",
            "repository": "docker.io/dirextalk/message-server",
            "tag": message["version"],
            "digest": message["digest"],
            "source_revision": message["source_revision"],
        },
        {
            "role": "agent",
            "repository": "docker.io/dirextalk/agent",
            "tag": agent["version"],
            "digest": agent["digest"],
            "source_revision": agent["source_revision"],
        },
        {
            "role": "caddy",
            "repository": "docker.io/library/caddy",
            "tag": None,
            "digest": CADDY_DIGEST,
            "source_revision": None,
        },
        {
            "role": "coturn",
            "repository": "docker.io/coturn/coturn",
            "tag": "4.6.3-alpine",
            "digest": COTURN_DIGEST,
            "source_revision": None,
        },
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=pathlib.Path)
    parser.add_argument("--release-dir", type=pathlib.Path)
    parser.add_argument("--validate-only", action="store_true")
    arguments = parser.parse_args()
    repository_root = pathlib.Path(__file__).resolve().parent.parent
    values = inputs()
    compose_path = repository_root / "runtime/docker-compose.yml"
    updater_unit_path = repository_root / "packaging/dirextalk-updater.service"
    helper_paths = {
        "caddyfile_path": repository_root / "runtime/Caddyfile",
        "message_server_initializer_path": repository_root / "runtime/initialize-message-server.sh",
        "agent_secret_materializer_path": repository_root / "runtime/materialize-agent-secrets.sh",
        "message_server_entrypoint_path": repository_root / "runtime/message-server-entrypoint.sh",
        "capability_ca_initializer_path": repository_root / "runtime/initialize-capability-ca.sh",
        "postgres_entrypoint_path": repository_root / "runtime/postgres-entrypoint.sh",
        "postgres_initializer_path": repository_root / "runtime/initialize-postgres.sh",
    }
    static_paths = {
        "compose_file": compose_path,
        "caddyfile": helper_paths["caddyfile_path"],
        "message_server_initializer": helper_paths["message_server_initializer_path"],
        "agent_secret_materializer": helper_paths["agent_secret_materializer_path"],
        "message_server_entrypoint": helper_paths["message_server_entrypoint_path"],
        "capability_ca_initializer": helper_paths["capability_ca_initializer_path"],
        "postgres_entrypoint": helper_paths["postgres_entrypoint_path"],
        "postgres_initializer": helper_paths["postgres_initializer_path"],
        "updater_unit": updater_unit_path,
    }
    for label, path in static_paths.items():
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            fail(f"root-owned runtime asset is missing or unsafe: {label}")
    static_receipts = {
        label: {"path": str(path.relative_to(repository_root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for label, path in static_paths.items()
    }
    if arguments.validate_only:
        return
    if arguments.work_dir is None or arguments.release_dir is None:
        fail("--work-dir and --release-dir are required unless --validate-only is used")

    work_dir = arguments.work_dir.resolve()
    release_dir = arguments.release_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    release_dir.mkdir(parents=True, exist_ok=True)
    updater_path = work_dir / "dirextalk-updater"
    updater = values["updater"]
    assert isinstance(updater, dict)
    download(
        str(updater["binary_url"]),
        updater_path,
        str(updater["binary_sha256"]),
        64 * 1024 * 1024,
    )
    updater_path.chmod(0o755)

    bundle_path = release_dir / f"dirextalk-runtime-bundle-{values['release']}-linux-amd64.tar"
    request = {
        "schema_version": 1,
        "release": values["release"],
        "images": image_references(values),
        "compose_path": str(compose_path),
        "caddyfile_path": str(helper_paths["caddyfile_path"]),
        "message_server_initializer_path": str(helper_paths["message_server_initializer_path"]),
        "agent_secret_materializer_path": str(helper_paths["agent_secret_materializer_path"]),
        "message_server_entrypoint_path": str(helper_paths["message_server_entrypoint_path"]),
        "capability_ca_initializer_path": str(helper_paths["capability_ca_initializer_path"]),
        "postgres_entrypoint_path": str(helper_paths["postgres_entrypoint_path"]),
        "postgres_initializer_path": str(helper_paths["postgres_initializer_path"]),
        "updater_binary_path": str(updater_path),
        "updater_unit_path": str(updater_unit_path),
        "updater_version": updater["version"],
        "updater_source_revision": updater["source_revision"],
        "updater_source_url": updater["binary_url"],
        "updater_sha256": updater["binary_sha256"],
        "output_bundle_path": str(bundle_path),
    }
    write_json(work_dir / "bundle-request.json", request, 0o600)
    provenance = {
        "schema_version": 1,
        **values,
        "runtime_assets": static_receipts,
        "images": image_references(values),
    }
    write_json(release_dir / "_runtime-provenance.json", provenance)


if __name__ == "__main__":
    main()
