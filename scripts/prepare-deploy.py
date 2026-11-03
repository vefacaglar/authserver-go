#!/usr/bin/env python3
"""Build a private deployment bundle from GitHub secrets without shell evaluation."""

import os
from pathlib import Path
import re
import shutil
import sys


def prepare(destination: Path) -> None:
    runtime = os.environ.get("AUTH_ENV", "").replace("\r\n", "\n")
    values = {}
    for line in runtime.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError("AUTH_ENV must contain raw NAME=value lines")
        if key in values:
            raise ValueError("AUTH_ENV contains a duplicate setting")
        values[key] = value
    for key in ("AUTH_DB_DSN", "AUTH_ADMIN_TOKEN"):
        if not values.get(key, "").strip():
            raise ValueError(f"AUTH_ENV must include {key}")

    network = os.environ.get("AUTH_DOCKER_NETWORK", "databases_default")
    port = os.environ.get("AUTH_BIND_PORT", "5175")
    image = os.environ.get("AUTH_IMAGE", "")
    actor = os.environ.get("REGISTRY_USER", "")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", network):
        raise ValueError("Invalid AUTH_DOCKER_NETWORK")
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("Invalid AUTH_BIND_PORT")
    if not re.fullmatch(r"ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}", image):
        raise ValueError("Invalid image digest")
    if not re.fullmatch(r"[a-zA-Z0-9_-]+(?:\[bot\])?", actor):
        raise ValueError("Invalid registry user")

    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent.parent / "deploy"
    for name in ("compose.yml", "deploy.sh", "receive.sh"):
        shutil.copyfile(source / name, destination / name)
        (destination / name).chmod(0o600)
    for name, content in {
        "authserver.env": runtime.rstrip("\n") + "\n",
        ".env": f"AUTH_DOCKER_NETWORK={network}\nAUTH_BIND_PORT={port}\n",
        "image": image + "\n",
        "registry-user": actor + "\n",
    }.items():
        path = destination / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)


if __name__ == "__main__":
    try:
        prepare(Path(sys.argv[1]))
    except (ValueError, OSError) as error:
        sys.exit(str(error))
