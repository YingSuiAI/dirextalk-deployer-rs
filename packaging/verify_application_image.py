#!/usr/bin/env python3
"""Verify a Docker Hub tag's linux/amd64 digest and source-revision label."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
REPOSITORIES = {"dirextalk/message-server", "dirextalk/agent"}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.config.v1+json",
}


def fail(message: str) -> None:
    raise ValueError(message)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward the short-lived registry bearer token to another host."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        redirected = super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )
        if redirected is not None:
            target = urllib.parse.urlsplit(new_url)
            if target.scheme != "https":
                fail("registry redirect is not HTTPS")
            if urllib.parse.urlsplit(request.full_url).hostname != target.hostname:
                redirected.remove_header("Authorization")
        return redirected


OPENER = urllib.request.build_opener(SafeRedirectHandler())


def fetch(url: str, maximum: int, headers: dict[str, str] | None = None) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "dirextalk-release-builder/1", **(headers or {})},
    )
    with OPENER.open(request, timeout=60) as response:
        body = response.read(maximum + 1)
    if not body or len(body) > maximum:
        fail("registry response is empty or exceeds its fixed size limit")
    return body


def object_json(body: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def validate_tag(
    tag: dict[str, object], version: str, expected_digest: str
) -> None:
    images = tag.get("images")
    if tag.get("name") != version or not isinstance(images, list):
        fail("Docker Hub returned an invalid exact tag")
    linux_amd64 = {
        image.get("digest")
        for image in images
        if isinstance(image, dict)
        and image.get("os") == "linux"
        and image.get("architecture") == "amd64"
        and image.get("status") in {None, "", "active"}
    }
    if linux_amd64 != {f"sha256:{expected_digest}"}:
        fail("Docker Hub tag does not bind the pinned linux/amd64 digest")


def validate_manifest(body: bytes, expected_digest: str) -> str:
    if hashlib.sha256(body).hexdigest() != expected_digest:
        fail("registry manifest body does not match the pinned digest")
    manifest = object_json(body, "registry manifest")
    config = manifest.get("config")
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") not in MANIFEST_MEDIA_TYPES
        or not isinstance(config, dict)
        or config.get("mediaType") not in CONFIG_MEDIA_TYPES
        or not isinstance(config.get("digest"), str)
    ):
        fail("pinned digest is not a supported single-platform image manifest")
    config_digest = str(config["digest"])
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest):
        fail("image config descriptor has an invalid digest")
    return config_digest


def validate_config(body: bytes, config_digest: str, source_revision: str) -> None:
    if hashlib.sha256(body).hexdigest() != config_digest.removeprefix("sha256:"):
        fail("image config body does not match its manifest descriptor")
    image_config = object_json(body, "image config")
    runtime_config = image_config.get("config")
    labels = runtime_config.get("Labels") if isinstance(runtime_config, dict) else None
    if image_config.get("os") != "linux" or image_config.get("architecture") != "amd64":
        fail("image config is not linux/amd64")
    if not isinstance(labels, dict) or labels.get("org.opencontainers.image.revision") != source_revision:
        fail("image source-revision label does not match the pinned revision")


def verify(repository: str, version: str, digest: str, source_revision: str) -> None:
    if repository not in REPOSITORIES:
        fail("application image repository is not allowlisted")
    if not VERSION.fullmatch(version):
        fail("application image version is not canonical")
    if not HEX_64.fullmatch(digest) or not HEX_40.fullmatch(source_revision):
        fail("application image digest or source revision is invalid")

    repository_path = urllib.parse.quote(repository, safe="/")
    version_path = urllib.parse.quote(version, safe="")
    tag = object_json(
        fetch(
            f"https://hub.docker.com/v2/repositories/{repository_path}/tags/{version_path}",
            2 * 1024 * 1024,
        ),
        "Docker Hub tag",
    )
    validate_tag(tag, version, digest)

    token_query = urllib.parse.urlencode(
        {
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        }
    )
    token_response = object_json(
        fetch(f"https://auth.docker.io/token?{token_query}", 256 * 1024),
        "registry authorization",
    )
    token = token_response.get("token") or token_response.get("access_token")
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 16 * 1024
        or not token.isascii()
        or any(character.isspace() for character in token)
    ):
        fail("registry authorization did not return a bounded bearer token")
    authorization = {"Authorization": f"Bearer {token}"}
    manifest = fetch(
        f"https://registry-1.docker.io/v2/{repository_path}/manifests/sha256:{digest}",
        4 * 1024 * 1024,
        {
            **authorization,
            "Accept": ", ".join(sorted(MANIFEST_MEDIA_TYPES)),
        },
    )
    config_digest = validate_manifest(manifest, digest)
    config = fetch(
        f"https://registry-1.docker.io/v2/{repository_path}/blobs/{config_digest}",
        16 * 1024 * 1024,
        authorization,
    )
    validate_config(config, config_digest, source_revision)


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: verify_application_image.py <repository> <version> <digest> <source-revision>"
        )
    try:
        verify(*sys.argv[1:])
    except (ValueError, urllib.error.URLError, TimeoutError) as error:
        raise SystemExit(f"application image verification failed: {error}") from None
    print(f"verified immutable linux/amd64 image provenance: {sys.argv[1]}")


if __name__ == "__main__":
    main()
