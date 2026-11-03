"""Verify secret transfer and deployment failure paths without a live VPS."""

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "prepare_deploy", Path(__file__).with_name("prepare-deploy.py")
)
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)
OLD_IMAGE = "ghcr.io/vefacaglar/authserver-go@sha256:" + "a" * 64
NEW_IMAGE = "ghcr.io/vefacaglar/authserver-go@sha256:" + "b" * 64
OLD_WEB_IMAGE = "ghcr.io/vefacaglar/authserver-go-web@sha256:" + "c" * 64
NEW_WEB_IMAGE = "ghcr.io/vefacaglar/authserver-go-web@sha256:" + "d" * 64


class DeployTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / ".incoming-test"
        self.runtime = (
            "AUTH_DB_DSN=postgres://example/db?sslmode=require\r\n"
            "AUTH_ADMIN_TOKEN=literal-$value-`echo secret`\r\n"
            "AUTH_SMTP_PASSWORD=spaces and $dollars='quotes'\r\n"
        )
        self.environment = {
            **dict.fromkeys(PREPARE.INDIVIDUAL_SECRETS, ""),
            "AUTH_ENV": self.runtime,
            "AUTH_IMAGE": NEW_IMAGE,
            "AUTH_WEB_IMAGE": NEW_WEB_IMAGE,
            "AUTH_DOCKER_NETWORK": "existing-network",
            "AUTH_BIND_PORT": "5175",
            "REGISTRY_USER": "vefacaglar",
        }

    def prepare(self):
        with patch.dict(os.environ, self.environment):
            PREPARE.prepare(self.bundle)

    def test_raw_secrets_preserved_and_private(self):
        self.prepare()
        self.assertEqual(
            (self.bundle / "authserver.env").read_text(),
            self.runtime.replace("\r\n", "\n"),
        )
        self.assertEqual(stat.S_IMODE(self.bundle.stat().st_mode), 0o700)
        for path in self.bundle.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_rejects_invalid_configuration_before_writing(self):
        for key, value in (
            ("AUTH_ENV", "AUTH_DB_DSN=secret\n"),
            ("AUTH_ENV", "AUTH_DB_DSN=x\nAUTH_ADMIN_TOKEN=x\nAUTH_ADMIN_TOKEN=y\n"),
            ("AUTH_ENV", "export AUTH_DB_DSN=secret\n"),
            ("AUTH_DOCKER_NETWORK", "network\nINJECT=value"),
            ("AUTH_BIND_PORT", "65536"),
            ("AUTH_IMAGE", "ghcr.io/vefacaglar/authserver-go:latest"),
            ("AUTH_WEB_IMAGE", "ghcr.io/vefacaglar/authserver-go-web:latest"),
            ("AUTH_WEB_BIND_PORT", "65536"),
            ("AUTH_WEB_BIND_PORT", "5175"),
            ("AUTH_WEB_BIND_PORT", "05175"),
            ("AUTH_ADMIN_TOKEN", "token\nINJECTED=value"),
        ):
            with self.subTest(key=key):
                with patch.dict(os.environ, self.environment | {key: value}):
                    with self.assertRaises(ValueError):
                        PREPARE.prepare(self.bundle)
                self.assertFalse(self.bundle.exists())

    def test_individual_secrets_without_auth_env(self):
        self.environment.update(
            AUTH_ENV="",
            AUTH_DB_DSN="postgres://example/new-db?sslmode=require",
            AUTH_ADMIN_TOKEN="literal-$value-`echo secret`",
            AUTH_SMTP_PASSWORD="spaces and $dollars='quotes'",
        )
        self.prepare()
        content = (self.bundle / "authserver.env").read_text()
        self.assertEqual(content, (
            "AUTH_DB_DSN=postgres://example/new-db?sslmode=require\n"
            "AUTH_ADMIN_TOKEN=literal-$value-`echo secret`\n"
            "AUTH_SMTP_PASSWORD=spaces and $dollars='quotes'\n"
        ))

    def test_individual_secret_overrides_bundle_without_duplicate_setting(self):
        self.environment["AUTH_DB_DSN"] = "postgres://example/new-db"
        self.prepare()
        content = (self.bundle / "authserver.env").read_text()
        self.assertIn("AUTH_DB_DSN=postgres://example/new-db\n", content)
        self.assertEqual(content.count("AUTH_DB_DSN="), 1)
        self.assertIn("AUTH_ADMIN_TOKEN=literal-$value-`echo secret`\n", content)

    def run_receiver(self, failure=""):
        bindir = self.root / "bin"
        bindir.mkdir()
        # The real Linux deployment uses flock; tests only exercise control flow.
        (bindir / "flock").write_text("#!/bin/sh\nexit 0\n")
        (bindir / "python3").write_text(
            '#!/bin/sh\nprintf "configure-caddy\\n" >> "$TEST_LOG"\n'
            'if [ "$FAILURE" = proxy ]; then exit 1; fi\n'
        )
        (bindir / "docker").write_text('''#!/usr/bin/env bash
set -eu
printf '%s|%s\\n' "${AUTH_IMAGE:-}" "$*" >> "$TEST_LOG"
if [[ "$1" == login ]]; then
  token=$(cat)
  [[ "$token" == ci-registry-token ]]
  printf '%s' "$DOCKER_CONFIG" > "$TEST_CONFIG_PATH"
  printf '%s' "$token" > "$DOCKER_CONFIG/config.json"
fi
if [[ "$FAILURE" == migration && "$*" == *'run --rm'* ]]; then exit 1; fi
if [[ "$*" == *'up -d'* && "$AUTH_IMAGE" == "$OLD_IMAGE" ]]; then
  [[ "$AUTH_WEB_IMAGE" == "$OLD_WEB_IMAGE" ]]
  cmp authserver.env "$OLD_ENV_FILE"
fi
if [[ "$FAILURE" == health && "$*" == *'up -d'* ]]; then
  if [[ "$AUTH_IMAGE" == "$NEW_IMAGE" ]]; then exit 1; fi
  cmp authserver.env "$OLD_ENV_FILE"
fi
''')
        for path in bindir.iterdir():
            path.chmod(0o700)
        environment = os.environ | {
            "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
            "TEST_LOG": str(self.root / "calls"),
            "TEST_CONFIG_PATH": str(self.root / "registry-config-path"),
            "NEW_IMAGE": NEW_IMAGE,
            "OLD_IMAGE": OLD_IMAGE,
            "OLD_WEB_IMAGE": OLD_WEB_IMAGE,
            "FAILURE": failure,
            "OLD_ENV_FILE": str(self.root / "old-env"),
        }
        result = subprocess.run(
            ["bash", str(self.bundle / "receive.sh")],
            input="ci-registry-token",
            text=True,
            capture_output=True,
            env=environment,
        )
        self.assertFalse(self.bundle.exists())
        config_path = Path((self.root / "registry-config-path").read_text())
        self.assertFalse(config_path.exists())
        self.assertFalse(list(self.root.glob(".deploy-backup.*")))
        self.assertNotIn("ci-registry-token", result.stdout + result.stderr)
        return result, (self.root / "calls").read_text()

    def test_first_deployment_needs_no_preexisting_env_or_registry_login(self):
        self.prepare()
        result, calls = self.run_receiver()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / ".current-image").read_text().strip(), NEW_IMAGE)
        self.assertEqual((self.root / ".current-web-image").read_text().strip(), NEW_WEB_IMAGE)
        self.assertEqual(
            (self.root / "authserver.env").read_text(), self.runtime.replace("\r\n", "\n")
        )
        self.assertLess(calls.index("login"), calls.index("pull authserver web"))
        self.assertLess(calls.index("run --rm"), calls.index("up -d"))
        self.assertLess(calls.index("up -d"), calls.index("configure-caddy"))

    def setup_previous_release(self):
        (self.root / ".current-image").write_text(OLD_IMAGE + "\n")
        (self.root / ".current-web-image").write_text(OLD_WEB_IMAGE + "\n")
        (self.root / "authserver.env").write_text("AUTH_ADMIN_TOKEN=previous-secret\n")
        (self.root / "old-env").write_bytes((self.root / "authserver.env").read_bytes())
        (self.root / ".env").write_text("AUTH_DOCKER_NETWORK=previous-network\n")
        (self.root / "compose.yml").write_text("previous compose configuration\n")
        (self.root / ".last-good-compose.yml").write_bytes((self.root / "compose.yml").read_bytes())

    def assert_previous_release(self):
        self.assertEqual((self.root / ".current-image").read_text().strip(), OLD_IMAGE)
        self.assertEqual((self.root / ".current-web-image").read_text().strip(), OLD_WEB_IMAGE)
        self.assertEqual((self.root / "authserver.env").read_bytes(), (self.root / "old-env").read_bytes())
        self.assertEqual((self.root / ".env").read_text(), "AUTH_DOCKER_NETWORK=previous-network\n")
        self.assertEqual((self.root / "compose.yml").read_text(), "previous compose configuration\n")

    def test_failed_migration_restores_previous_environment_without_restart(self):
        self.setup_previous_release()
        self.prepare()
        result, calls = self.run_receiver("migration")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("up -d", calls)
        self.assert_previous_release()

    def test_failed_health_check_rolls_back_with_previous_environment(self):
        self.setup_previous_release()
        self.prepare()
        result, calls = self.run_receiver("health")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(OLD_IMAGE + "|compose --env-file .env -f .last-good-compose.yml up", calls)
        self.assert_previous_release()

    def test_failed_proxy_configuration_rolls_back_both_images(self):
        self.setup_previous_release()
        self.prepare()
        result, calls = self.run_receiver("proxy")
        self.assertNotEqual(result.returncode, 0)
        rollback = OLD_IMAGE + "|compose --env-file .env -f .last-good-compose.yml up"
        self.assertLess(calls.index("configure-caddy"), calls.index(rollback))
        self.assertIn("authserver web", calls[calls.index(rollback):])
        self.assert_previous_release()
        self.assertFalse((self.root / ".previous-image").exists())

    def test_failed_first_deployment_removes_candidate(self):
        self.prepare()
        result, calls = self.run_receiver("proxy")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("compose --env-file .env -f compose.yml down", calls)
        self.assertFalse((self.root / ".current-image").exists())
        self.assertFalse((self.root / ".last-good-compose.yml").exists())
        self.assertFalse((self.root / "authserver.env").exists())

    def check_ssh_transfer(self, use_key, fail_upload=False):
        bindir = self.root / "ssh-bin"
        bindir.mkdir()
        self.prepare()
        self.bundle.rename(self.root / "authserver-bundle")
        if use_key:
            (self.root / "authserver-ssh-key").write_text("test-key")
        for command in ("ssh", "scp"):
            (bindir / command).write_text('''#!/usr/bin/env bash
set -eu
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$SSH_TEST_LOG"
if [[ "$0" == */scp && "$FAIL_UPLOAD" == true ]]; then exit 1; fi
if [[ "$*" == *'/receive.sh' ]]; then
  [[ "$(cat)" == ci-registry-token ]]
fi
''')
        (bindir / "sshpass").write_text('''#!/usr/bin/env bash
set -eu
[[ "$1" == -e && "$SSHPASS" == ci-ssh-password ]]
echo sshpass >> "$SSH_TEST_LOG"
shift
exec "$@"
''')
        for path in bindir.iterdir():
            path.chmod(0o700)
        environment = os.environ | {
            "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
            "VPS_HOST": "example.test",
            "VPS_PORT": "22",
            "VPS_USER": "deployer",
            "VPS_PASSWORD": "ci-ssh-password",
            "REGISTRY_TOKEN": "ci-registry-token",
            "DEPLOY_ID": "123-1",
            "RUNNER_TEMP": str(self.root),
            "SSH_TEST_LOG": str(self.root / "ssh-calls"),
            "FAIL_UPLOAD": "true" if fail_upload else "false",
        }
        result = subprocess.run(
            ["bash", str(Path(__file__).with_name("ssh-deploy.sh"))],
            env=environment, capture_output=True, text=True,
        )
        calls = (self.root / "ssh-calls").read_text()
        self.assertIn("rm -rf ~/authserver/.incoming-123-1", calls)
        self.assertIn("StrictHostKeyChecking=yes", calls)
        self.assertNotIn("ci-ssh-password", calls + result.stdout + result.stderr)
        self.assertNotIn("ci-registry-token", calls + result.stdout + result.stderr)
        if fail_upload:
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("bash ~/authserver/.incoming-123-1/receive.sh", calls)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("authserver-bundle/.env", calls)
            self.assertIn("bash ~/authserver/.incoming-123-1/receive.sh", calls)
        if use_key:
            self.assertIn("BatchMode=yes", calls)
            self.assertNotIn("sshpass", calls)
        else:
            self.assertIn("sshpass", calls)

    def test_ssh_password_transfer(self):
        self.check_ssh_transfer(use_key=False)

    def test_ssh_key_transfer(self):
        self.check_ssh_transfer(use_key=True)

    def test_failed_upload_cleans_remote_bundle(self):
        self.check_ssh_transfer(use_key=False, fail_upload=True)


if __name__ == "__main__":
    unittest.main()
