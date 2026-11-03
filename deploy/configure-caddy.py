#!/usr/bin/env python3
"""Add the auth route to an existing persistent Caddyfile and reload safely."""

import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile


DOMAIN = "auth.vefacaglar.com"
BEGIN = "# BEGIN authserver-go managed route"
END = "# END authserver-go managed route"


def run(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True)
    if result.returncode:
        # Caddy configuration/diagnostics may contain other applications' secrets.
        raise RuntimeError(f"{arguments[0]} command failed while configuring Caddy")
    return result.stdout


def routed(config):
    if isinstance(config, dict):
        if DOMAIN in config.get("host", []):
            return True
        return any(routed(value) for value in config.values())
    if isinstance(config, list):
        return any(routed(value) for value in config)
    return False


def updated_config(original, upstream, already_routed):
    if BEGIN in original or END in original:
        if original.count(BEGIN) != 1 or original.count(END) != 1:
            raise RuntimeError("Invalid authserver managed-route markers")
        before, tail = original.split(BEGIN, 1)
        if END not in tail:
            raise RuntimeError("Invalid authserver managed-route marker order")
        _, after = tail.split(END, 1)
        original = before.rstrip() + after
    elif already_routed or DOMAIN in original:
        raise RuntimeError("An unmanaged auth route already exists; refusing to overwrite it")
    return original.rstrip() + "\n\n" + f"""{BEGIN}
{DOMAIN} {{
    reverse_proxy {upstream} {{
        header_up -True-Client-IP
        header_up X-Real-IP {{remote_host}}
        header_up X-Forwarded-For {{remote_host}}
    }}
}}
{END}
"""


def mounted_config(mounts, config):
    target = PurePosixPath(config)
    if not target.is_absolute() or ".." in target.parts:
        raise RuntimeError("Caddy must use an absolute configuration path")
    matches = []
    for mount in mounts:
        try:
            relative = target.relative_to(mount["Destination"])
        except ValueError:
            continue
        matches.append((len(mount["Destination"]), Path(mount["Source"]) / str(relative)))
    if not matches:
        raise RuntimeError("Caddyfile is not on a persistent mount; refusing an ephemeral edit")
    return max(matches, key=lambda item: item[0])[1]


def target(settings, network, port):
    rows = run(["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"]).splitlines()
    containers = [row.split("\t") for row in rows if row.strip()]
    requested = settings.get("container", "")
    candidates = [row for row in containers if (
        requested in (row[0], row[2]) if requested else "caddy" in row[1].lower()
    )]
    if len(candidates) > 1:
        raise RuntimeError("Multiple Caddy containers found; set AUTH_CADDY_CONTAINER in GitHub variables")
    if candidates:
        container, image, _ = candidates[0]
        if "docker-proxy" in image:
            raise RuntimeError("Caddy Docker Proxy uses generated configuration; this setup requires a Caddyfile")
        arguments = json.loads(run(["docker", "inspect", "--format", "{{json .Config.Cmd}}", container])) or []
        config = settings.get("config_path") or "/etc/caddy/Caddyfile"
        if "--resume" in arguments:
            raise RuntimeError("Caddy runs with --resume; refusing to edit an unused Caddyfile")
        if "--watch" in arguments or "-w" in arguments:
            raise RuntimeError("Caddy watches its config; refusing to write before explicit validation")
        if not settings.get("config_path"):
            for index, value in enumerate(arguments):
                if value in ("--config", "-c") and index + 1 < len(arguments):
                    config = arguments[index + 1]
                elif value.startswith("--config="):
                    config = value.partition("=")[2]
        mounts = json.loads(run(["docker", "inspect", "--format", "{{json .Mounts}}", container]))
        source = mounted_config(mounts, config)
        networks = json.loads(run(["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container]))
        if network not in networks:
            run(["docker", "network", "connect", network, container])
        return source, ["docker", "exec", container, "caddy"], config, "authserver:5175"
    if requested:
        raise RuntimeError("The configured Caddy container is not running")
    binary = shutil.which("caddy")
    config = settings.get("config_path") or "/etc/caddy/Caddyfile"
    if not binary or not Path(config).is_file():
        raise RuntimeError("No supported running Caddy installation found")
    run(["systemctl", "is-active", "--quiet", "caddy"])
    return Path(config), [binary], config, f"127.0.0.1:{port}"


def apply_config(source, command, config, upstream, backup_directory):
    original = source.read_text()
    adapted = json.loads(run(command + ["adapt", "--config", config, "--adapter", "caddyfile"]))
    replacement = updated_config(original, upstream, routed(adapted))
    directory = Path(tempfile.mkdtemp(prefix=".caddy-backup-", dir=backup_directory))
    keep_backup = False
    try:
        backup = directory / "Caddyfile"
        backup.write_text(original)
        backup.chmod(0o600)
        try:
            # Preserve the inode: Caddy may have the file itself bind-mounted.
            source.write_text(replacement)
            run(command + ["validate", "--config", config, "--adapter", "caddyfile"])
            run(command + ["reload", "--config", config, "--adapter", "caddyfile", "--force"])
        except (RuntimeError, OSError):
            try:
                source.write_text(original)
            except OSError:
                keep_backup = True
                raise RuntimeError(f"Could not restore Caddyfile; original retained at {backup}") from None
            raise RuntimeError("Caddy validation/reload failed; the original Caddyfile was restored") from None
    finally:
        if not keep_backup:
            shutil.rmtree(directory)
    print("Caddy auth route configured; automatic HTTPS is enabled.")


def main():
    os.umask(0o077)
    bundle = Path(__file__).resolve().parent
    directory = Path(os.environ["AUTH_DEPLOY_DIR"])
    settings = json.loads((bundle / "proxy.json").read_text())
    values = dict(line.split("=", 1) for line in (directory / ".env").read_text().splitlines())
    with (directory / ".proxy.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        source, command, config, upstream = target(
            settings, values["AUTH_DOCKER_NETWORK"], values["AUTH_BIND_PORT"]
        )
        if not source.is_file():
            raise RuntimeError("The persistent Caddyfile was not found")
        apply_config(source, command, config, upstream, directory)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        sys.exit(str(error))
