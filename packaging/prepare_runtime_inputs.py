#!/usr/bin/env python3
"""Fetch and pin the non-secret inputs for the canonical host bundle builder."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import tempfile
import tarfile
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


def build_split_runtime_archive(
    source: pathlib.Path, destination: pathlib.Path, source_revision: str
) -> None:
    files = sorted(
        path for path in source.rglob("*") if path.is_file() and path.name != ".gitignore"
    )
    if len(files) < 20 or any(path.is_symlink() for path in files):
        fail("split runtime source tree is incomplete or unsafe")
    receipts: list[str] = []
    payloads: list[tuple[str, bytes, int]] = []
    for path in files:
        relative = path.relative_to(source).as_posix()
        data = path.read_bytes()
        if not data:
            fail(f"split runtime source file is empty: {relative}")
        mode = 0o755 if relative.startswith("scripts/") and relative.endswith(".sh") else 0o644
        payloads.append((relative, data, mode))
        receipts.append(f"{hashlib.sha256(data).hexdigest()}  ./{relative}\n")
    revision = (source_revision + "\n").encode()
    payloads.append(("SOURCE_REVISION", revision, 0o644))
    receipts.append(f"{hashlib.sha256(revision).hexdigest()}  ./SOURCE_REVISION\n")
    manifest = "".join(sorted(receipts)).encode()
    payloads.append(("SOURCE_FILES.sha256", manifest, 0o644))

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for relative, data, mode in sorted(payloads):
            info = tarfile.TarInfo(f"deploy/split-agent/{relative}")
            info.size = len(data)
            info.mode = mode
            info.uid = info.gid = info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
        temporary_path = pathlib.Path(temporary.name)
        with gzip.GzipFile(
            filename="", fileobj=temporary, mode="wb", mtime=0
        ) as compressed:
            compressed.write(raw.getvalue())
        temporary.flush()
        os.fsync(temporary.fileno())
    temporary_path.chmod(0o600)
    temporary_path.replace(destination)


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
    split_runtime_source = repository_root / "runtime/split-agent"
    updater_unit_path = repository_root / "packaging/dirextalk-updater.service"
    helper_paths = {
        "caddyfile_path": repository_root / "runtime/Caddyfile",
        "edge_compose_override_path": repository_root / "runtime/edge-compose.override.yaml",
        "product_bootstrap_reader_path": repository_root / "runtime/read-product-bootstrap.sh",
        "runtime_verifier_path": repository_root / "runtime/verify-runtime.sh",
    }
    static_paths = {
        "caddyfile": helper_paths["caddyfile_path"],
        "edge_compose_override": helper_paths["edge_compose_override_path"],
        "product_bootstrap_reader": helper_paths["product_bootstrap_reader_path"],
        "runtime_verifier": helper_paths["runtime_verifier_path"],
        "updater_unit": updater_unit_path,
    }
    for label, path in static_paths.items():
        if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
            fail(f"root-owned runtime asset is missing or unsafe: {label}")
    required_split_paths = [
        split_runtime_source / "compose.yaml",
        split_runtime_source / "compose.production.yaml",
        split_runtime_source / "edge-compose.yaml",
        split_runtime_source / "scripts/provision-local.sh",
        split_runtime_source / "scripts/start-local.sh",
        split_runtime_source / "scripts/update-agent-local.sh",
        split_runtime_source / "scripts/prepare-runner-cgroups.sh",
    ]
    if any(not path.is_file() or path.is_symlink() for path in required_split_paths):
        fail("canonical split runtime source tree is incomplete or unsafe")
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
    split_runtime_archive = work_dir / "split-agent-runtime.tar.gz"
    build_split_runtime_archive(
        split_runtime_source, split_runtime_archive, str(values["source_revision"])
    )
    static_receipts["split_runtime_archive"] = {
        "path": "runtime/split-agent",
        "sha256": hashlib.sha256(split_runtime_archive.read_bytes()).hexdigest(),
    }
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
        "caddyfile_path": str(helper_paths["caddyfile_path"]),
        "edge_compose_override_path": str(helper_paths["edge_compose_override_path"]),
        "product_bootstrap_reader_path": str(helper_paths["product_bootstrap_reader_path"]),
        "runtime_verifier_path": str(helper_paths["runtime_verifier_path"]),
        "split_runtime_archive_path": str(split_runtime_archive),
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
