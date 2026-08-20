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
        f"dirextalk-host-installer-{release_tag}-linux-amd64.tar.gz": (
            "host-installer",
            "x86_64-unknown-linux-gnu",
        ),
    }
    actual = {
        path.name
        for path in release_dir.iterdir()
        if path.is_file() and (path.name.endswith(".tar.gz") or path.name.endswith(".zip"))
    }
    if actual != set(expected):
        fail(
            "release artifact set mismatch: "
            f"missing={sorted(set(expected) - actual)}, "
            f"unexpected={sorted(actual - set(expected))}"
        )

    artifacts = []
    checksum_lines = []
    for filename, (component, target) in sorted(expected.items()):
        path = release_dir / filename
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

    (release_dir / "SHA256SUMS").write_text("".join(checksum_lines), encoding="utf-8")
    manifest = {
        "artifacts": artifacts,
        "release": release_tag,
        "schema_version": 1,
        "source_repository": source_repository,
        "source_revision": source_revision,
    }
    (release_dir / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
