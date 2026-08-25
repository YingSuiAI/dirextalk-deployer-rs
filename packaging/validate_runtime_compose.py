#!/usr/bin/env python3
"""Reject runtime Compose templates that escape the signed image allowlist."""

from __future__ import annotations

import json
import pathlib
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


IMAGE_VARIABLES = {
    "postgres": "${DIREXTALK_POSTGRES_IMAGE_IMMUTABLE:?set an immutable PostgreSQL image reference}",
    "utility": "${DIREXTALK_UTILITY_IMAGE_IMMUTABLE:?set an immutable utility image reference}",
    "message_server": "${DIREXTALK_MESSAGE_SERVER_IMAGE:?set the message-server release channel}",
    "agent": "${DIREXTALK_AGENT_IMAGE:?set the Agent release channel}",
    "caddy": "${DIREXTALK_CADDY_IMAGE_IMMUTABLE:?set an immutable Caddy image reference}",
    "coturn": "${DIREXTALK_COTURN_IMAGE_IMMUTABLE:?set an immutable coturn image reference}",
}


def main() -> None:
    if len(sys.argv) != 4:
        fail(
            "usage: validate_runtime_compose.py <split-compose-json> "
            "<edge-compose-json> <bundle-request-json>"
        )
    composes = [
        json.loads(pathlib.Path(sys.argv[1]).read_text()),
        json.loads(pathlib.Path(sys.argv[2]).read_text()),
    ]
    request = json.loads(pathlib.Path(sys.argv[3]).read_text())
    images = request.get("images")
    services = {}
    for compose in composes:
        current = compose.get("services")
        if not isinstance(current, dict) or not current:
            fail("runtime Compose is incomplete")
        duplicate = set(services) & set(current)
        if duplicate:
            fail(f"runtime Compose contains duplicate services: {sorted(duplicate)}")
        services.update(current)
    if not isinstance(images, list):
        fail("runtime Compose or bundle request is incomplete")
    roles = {image.get("role") for image in images if isinstance(image, dict)}
    if roles != set(IMAGE_VARIABLES):
        fail("bundle image allowlist does not contain the canonical roles")
    allowed = set(IMAGE_VARIABLES.values())
    used = set()
    for name, service in services.items():
        if not isinstance(service, dict) or service.get("build") is not None:
            fail(f"Compose service {name} must use a prebuilt immutable image")
        image = service.get("image")
        if image not in allowed:
            fail(f"Compose service {name} is outside the signed image allowlist")
        used.add(image)
    if used != allowed:
        fail(f"Compose does not use the complete signed image allowlist: missing={sorted(allowed - used)}")


if __name__ == "__main__":
    main()
