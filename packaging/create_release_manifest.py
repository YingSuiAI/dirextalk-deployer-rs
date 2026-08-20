#!/usr/bin/env python3
"""Create deterministic checksums and a source-bound release manifest."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: create_release_manifest.py <release-assets-directory>")

    release_tag = os.environ.get("RELEASE_TAG", "")
    source_revision = os.environ.get("SOURCE_REVISION", "")
    source_repository = os.environ.get("SOURCE_REPOSITORY", "")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", release_tag):
        fail("RELEASE_TAG must be an exact vX.Y.Z tag")
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        fail("SOURCE_REVISION must be a full lowercase Git revision")
    if not source_repository:
        fail("SOURCE_REPOSITORY is required")

    release_dir = pathlib.Path(sys.argv[1])
    expected = {
        f"dirextalk-deployer-{release_tag}-windows-amd64.zip": (
            "cli",
            "x86_64-pc-windows-msvc",
        ),
        f"dirextalk-deployer-{release_tag}-linux-amd64.tar.gz": (
            "cli",
            "x86_64-unknown-linux-gnu",
        ),
        f"dirextalk-deployer-{release_tag}-macos-amd64.tar.gz": (
            "cli",
            "x86_64-apple-darwin",
        ),
        f"dirextalk-deployer-{release_tag}-macos-arm64.tar.gz": (
            "cli",
            "aarch64-apple-darwin",
        ),
        f"dirextalk-host-installer-{release_tag}-linux-amd64": (
            "host-installer",
            "x86_64-unknown-linux-gnu",
        ),
        f"dirextalk-runtime-bundle-{release_tag}-linux-amd64.tar": (
            "runtime-bundle",
            "x86_64-unknown-linux-gnu",
        ),
        f"dirextalk-runtime-manifest-{release_tag}-linux-amd64.json": (
            "runtime-manifest",
            "x86_64-unknown-linux-gnu",
        ),
    }
    internal_metadata = {"_runtime-build.json", "_runtime-provenance.json"}
    inputs = [
        path
        for path in release_dir.iterdir()
        if path.name not in {"SHA256SUMS", "release-manifest.json"}
    ]
    unsafe = sorted(
        path.name for path in inputs if not path.is_file() or path.is_symlink()
    )
    if unsafe:
        fail(f"release inputs must be regular non-symlink files: {unsafe}")
    actual = {path.name for path in inputs}
    allowed_inputs = set(expected) | internal_metadata
    if actual != allowed_inputs:
        fail(
            "release artifact set mismatch: "
            f"missing={sorted(allowed_inputs - actual)}, "
            f"unexpected={sorted(actual - allowed_inputs)}"
        )

    artifacts = []
    checksum_lines = []
    for filename, (component, target) in sorted(expected.items()):
        path = release_dir / filename
        if path.stat().st_size == 0:
            fail(f"release artifact is empty: {filename}")
        with path.open("rb") as asset:
            digest = hashlib.file_digest(asset, "sha256").hexdigest()
        checksum_lines.append(f"{digest}  {filename}\n")
        artifacts.append(
            {
                "component": component,
                "file": filename,
                "sha256": digest,
                "size_bytes": path.stat().st_size,
                "target": target,
            }
        )

    runtime_report_path = release_dir / "_runtime-build.json"
    runtime_provenance_path = release_dir / "_runtime-provenance.json"
    try:
        runtime_report = json.loads(runtime_report_path.read_text())
        runtime_provenance = json.loads(runtime_provenance_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"runtime bundle metadata is missing or invalid: {error}")
    expected_report_fields = {
        "output_path",
        "bundle_sha256",
        "manifest_sha256",
        "release_signing_public_key",
    }
    if set(runtime_report) != expected_report_fields:
        fail("runtime builder report has an unexpected schema")
    expected_provenance_fields = {
        "schema_version",
        "release",
        "oauth_client_id_sha256",
        "oauth_consent_audit_revision",
        "oauth_scope_review_sha256",
        "source_revision",
        "updater",
        "message_server",
        "agent",
        "runtime_assets",
        "images",
    }
    if set(runtime_provenance) != expected_provenance_fields:
        fail("runtime provenance has an unexpected schema")
    bundle_name = f"dirextalk-runtime-bundle-{release_tag}-linux-amd64.tar"
    signed_manifest_name = f"dirextalk-runtime-manifest-{release_tag}-linux-amd64.json"
    artifact_digests = {item["file"]: item["sha256"] for item in artifacts}
    if (
        runtime_report.get("bundle_sha256") != artifact_digests[bundle_name]
        or runtime_report.get("manifest_sha256") != artifact_digests[signed_manifest_name]
        or not re.fullmatch(
            r"[0-9a-f]{64}", runtime_report.get("release_signing_public_key", "")
        )
        or runtime_provenance.get("release") != release_tag
        or runtime_provenance.get("source_revision") != source_revision
    ):
        fail("runtime metadata does not match the immutable release artifacts")

    (release_dir / "SHA256SUMS").write_text("".join(checksum_lines), encoding="utf-8")
    manifest = {
        "artifacts": artifacts,
        "release": release_tag,
        "runtime_bundle": {
            "bundle_file": bundle_name,
            "bundle_sha256": runtime_report["bundle_sha256"],
            "manifest_sha256": runtime_report["manifest_sha256"],
            "provenance": runtime_provenance,
            "release_signing_public_key": runtime_report["release_signing_public_key"],
            "signed_manifest_file": signed_manifest_name,
        },
        "schema_version": 1,
        "source_repository": source_repository,
        "source_revision": source_revision,
    }
    (release_dir / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    runtime_report_path.unlink()
    runtime_provenance_path.unlink()


if __name__ == "__main__":
    main()
