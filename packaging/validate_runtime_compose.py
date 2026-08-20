#!/usr/bin/env python3
"""Reject runtime Compose templates that escape the signed image allowlist."""

from __future__ import annotations

import json
import pathlib
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


IMAGE_VARIABLES = {
    "postgres": "POSTGRES_IMAGE",
    "utility": "UTILITY_IMAGE",
    "message_server": "MESSAGE_SERVER_IMAGE",
    "agent": "AGENT_IMAGE",
    "caddy": "CADDY_IMAGE",
    "coturn": "COTURN_IMAGE",
}


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: validate_runtime_compose.py <compose-json> <bundle-request-json>")
    compose = json.loads(pathlib.Path(sys.argv[1]).read_text())
    request = json.loads(pathlib.Path(sys.argv[2]).read_text())
    images = request.get("images")
    services = compose.get("services")
    if not isinstance(images, list) or not isinstance(services, dict) or not services:
        fail("runtime Compose or bundle request is incomplete")
    roles = {image.get("role") for image in images if isinstance(image, dict)}
    if roles != set(IMAGE_VARIABLES):
        fail("bundle image allowlist does not contain the canonical roles")
    allowed = {
        f"${{{variable}:?set {variable} from the signed runtime manifest}}"
        for variable in IMAGE_VARIABLES.values()
    }
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
