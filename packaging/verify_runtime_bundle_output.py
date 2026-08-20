#!/usr/bin/env python3
"""Verify public bundle outputs against the host builder report and pinned inputs."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import sys


HEX_64 = re.compile(r"[0-9a-f]{64}")
HEX_128 = re.compile(r"[0-9a-f]{128}")


def fail(message: str) -> None:
    raise SystemExit(message)


def digest(path: pathlib.Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: verify_runtime_bundle_output.py <release-dir> <builder-report>")
    release = os.environ.get("RELEASE_TAG", "")
    release_dir = pathlib.Path(sys.argv[1]).resolve()
    report_path = pathlib.Path(sys.argv[2])
    bundle = release_dir / f"dirextalk-runtime-bundle-{release}-linux-amd64.tar"
    signed_manifest = release_dir / f"dirextalk-runtime-manifest-{release}-linux-amd64.json"
    provenance_path = release_dir / "_runtime-provenance.json"
    report = json.loads(report_path.read_text())
    provenance = json.loads(provenance_path.read_text())
    signed = json.loads(signed_manifest.read_text())
    if set(report) != {
        "output_path",
        "bundle_sha256",
        "manifest_sha256",
        "release_signing_public_key",
    }:
        fail("host builder report has an unexpected schema")
    if pathlib.Path(report["output_path"]).resolve() != bundle:
        fail("host builder reported an unexpected bundle path")
    if not HEX_64.fullmatch(report.get("release_signing_public_key", "")):
        fail("host builder returned an invalid Ed25519 public key")
    if report.get("bundle_sha256") != digest(bundle):
        fail("runtime bundle does not match the host builder report")
    if report.get("manifest_sha256") != digest(signed_manifest):
        fail("signed runtime manifest does not match the host builder report")
    if set(signed) != {"manifest", "ed25519_signature"} or not HEX_128.fullmatch(
        signed.get("ed25519_signature", "")
    ):
        fail("signed runtime manifest has an invalid envelope")
    manifest = signed.get("manifest")
    if not isinstance(manifest, dict):
        fail("signed runtime manifest payload is missing")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("release") != release
        or manifest.get("target") != "linux_amd64"
        or manifest.get("images") != provenance.get("images")
    ):
        fail("signed runtime manifest does not match pinned release provenance")
    updater = provenance.get("updater")
    if not isinstance(updater, dict) or manifest.get("updater") != {
        "version": updater.get("version"),
        "source_url": updater.get("binary_url"),
        "sha256": updater.get("binary_sha256"),
    }:
        fail("signed runtime manifest does not match the pinned updater")
    runtime_assets = provenance.get("runtime_assets")
    files = manifest.get("files")
    if not isinstance(runtime_assets, dict) or not isinstance(files, list):
        fail("signed runtime manifest file receipts are missing")
    expected_files = {
        role: receipt.get("sha256")
        for role, receipt in runtime_assets.items()
        if isinstance(receipt, dict)
    }
    expected_files["updater_binary"] = updater.get("binary_sha256")
    actual_files = {
        item.get("role"): item.get("sha256") for item in files if isinstance(item, dict)
    }
    if len(files) != len(expected_files) or actual_files != expected_files:
        fail("signed runtime file receipts do not match pinned input checksums")


if __name__ == "__main__":
    main()
