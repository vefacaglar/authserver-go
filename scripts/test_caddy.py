"""Check Caddy route preservation, persistent paths and failed-reload recovery."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "configure_caddy", Path(__file__).resolve().parent.parent / "deploy/configure-caddy.py"
)
CADDY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CADDY)


class CaddyTest(unittest.TestCase):
    def test_preserves_existing_sites_and_is_idempotent(self):
        original = "{\n    email ops@example.test\n}\n\nother.example.test {\n    reverse_proxy other:3000\n}\n"
        first = CADDY.updated_config(original, "authserver-go-api:5175", "authserver-go-web:8080", False)
        self.assertIn(original.rstrip(), first)
        self.assertIn("reverse_proxy authserver-go-api:5175", first)
        self.assertIn("reverse_proxy authserver-go-web:8080", first)
        self.assertIn("@api path /api/* /admin/api/* /connect/* /.well-known/* /healthz", first)
        self.assertIn("header_up -True-Client-IP", first)
        second = CADDY.updated_config(first, "authserver-go-api:5175", "authserver-go-web:8080", True)
        self.assertEqual(first, second)
        changed = CADDY.updated_config(second, "127.0.0.1:5176", "127.0.0.1:5177", True)
        self.assertEqual(changed.count(CADDY.DOMAIN), 1)
        self.assertIn("reverse_proxy 127.0.0.1:5176", changed)
        self.assertIn("reverse_proxy 127.0.0.1:5177", changed)

    def test_refuses_existing_unmanaged_or_imported_auth_route(self):
        for original, routed in (
            ("auth.vefacaglar.com {\n    respond old\n}\n", False),
            ("import sites/*", True),
        ):
            with self.assertRaises(RuntimeError):
                CADDY.updated_config(original, "authserver-go-api:5175", "authserver-go-web:8080", routed)
        self.assertTrue(CADDY.routed({"routes": [{"match": [{"host": [CADDY.DOMAIN]}]}]}))

    def test_persistent_mount_resolution(self):
        mounts = [
            {"Destination": "/etc/caddy", "Source": "/srv/proxy"},
            {"Destination": "/etc/caddy/Caddyfile", "Source": "/srv/specific.conf"},
        ]
        self.assertEqual(CADDY.mounted_config(mounts, "/etc/caddy/Caddyfile"), Path("/srv/specific.conf"))
        self.assertEqual(CADDY.mounted_config(mounts[:1], "/etc/caddy/Caddyfile"), Path("/srv/proxy/Caddyfile"))
        with self.assertRaises(RuntimeError):
            CADDY.mounted_config([], "/etc/caddy/Caddyfile")
        with self.assertRaises(RuntimeError):
            CADDY.mounted_config(mounts, "/etc/caddy/../elsewhere")

    def test_validation_and_reload_failures_restore_original_file(self):
        for failure in ("validate", "reload"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "Caddyfile"
                original = "other.example.test {\n    respond ok\n}\n"
                source.write_text(original)
                inode = source.stat().st_ino
                reloaded = []

                def command(arguments):
                    if "adapt" in arguments:
                        return "{}"
                    if "reload" in arguments:
                        reloaded.append(source.read_text())
                        if len(reloaded) == 2:
                            self.assertEqual(source.read_text(), original)
                            return ""
                    self.assertIn(CADDY.DOMAIN, source.read_text())
                    if failure in arguments:
                        raise RuntimeError("test failure")
                    return ""

                with patch.object(CADDY, "run", side_effect=command):
                    with self.assertRaisesRegex(RuntimeError, "original Caddyfile was restored"):
                        CADDY.apply_config(source, ["caddy"], str(source), "authserver-go-api:5175", "authserver-go-web:8080", directory)
                self.assertEqual(source.read_text(), original)
                self.assertEqual(source.stat().st_ino, inode)
                self.assertEqual(len(reloaded), 2 if failure == "reload" else 0)

    def test_failed_recovery_reload_retains_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Caddyfile"
            original = "other.example.test {\n    respond ok\n}\n"
            source.write_text(original)

            def command(arguments):
                if "adapt" in arguments:
                    return "{}"
                if "reload" in arguments:
                    raise RuntimeError("reload failed")
                return ""

            with patch.object(CADDY, "run", side_effect=command):
                with self.assertRaisesRegex(RuntimeError, "reloading it failed; backup retained"):
                    CADDY.apply_config(source, ["caddy"], str(source), "api:5175", "web:8080", directory)
            self.assertEqual(source.read_text(), original)
            backups = list(Path(directory).glob(".caddy-backup-*/Caddyfile"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), original)

    def test_detects_container_config_and_connects_shared_network(self):
        calls = []

        def command(arguments):
            calls.append(arguments)
            if "ps" in arguments:
                return "abc\tcaddy:2\tproxy\n"
            if "{{json .Config.Cmd}}" in arguments:
                return json.dumps(["caddy", "run", "--config", "/etc/caddy/Caddyfile"])
            if "{{json .Mounts}}" in arguments:
                return json.dumps([{"Destination": "/etc/caddy", "Source": "/srv/caddy"}])
            if "{{json .NetworkSettings.Networks}}" in arguments:
                return '{"other-network": {}}'
            return ""

        with patch.object(CADDY, "run", side_effect=command):
            source, cmd, config, upstream, web_upstream = CADDY.target({}, "auth-network", "5175", "5176")
        self.assertEqual(source, Path("/srv/caddy/Caddyfile"))
        self.assertEqual(cmd, ["docker", "exec", "abc", "caddy"])
        self.assertEqual(config, "/etc/caddy/Caddyfile")
        self.assertEqual(upstream, "authserver-go-api:5175")
        self.assertEqual(web_upstream, "authserver-go-web:8080")
        self.assertIn(["docker", "network", "connect", "auth-network", "abc"], calls)

    def test_multiple_containers_require_explicit_selection(self):
        with patch.object(CADDY, "run", return_value="a\tcaddy:2\tproxy1\nb\tcaddy:2\tproxy2\n"):
            with self.assertRaisesRegex(RuntimeError, "Multiple Caddy containers"):
                CADDY.target({}, "network", "5175", "5176")

    def test_host_service_uses_loopback_port(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "Caddyfile"
            config.write_text("other.example.test {\n    respond ok\n}\n")
            with patch.object(CADDY, "run", return_value="") as command, patch.object(CADDY.shutil, "which", return_value="/usr/bin/caddy"):
                source, cmd, _, upstream, web_upstream = CADDY.target({"config_path": str(config)}, "network", "5176", "5177")
            self.assertEqual(source, config)
            self.assertEqual(cmd, ["/usr/bin/caddy"])
            self.assertEqual(upstream, "127.0.0.1:5176")
            self.assertEqual(web_upstream, "127.0.0.1:5177")
            command.assert_any_call(["systemctl", "is-active", "--quiet", "caddy"])

    def test_successful_apply_validates_before_reload_and_preserves_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Caddyfile"
            source.write_text("other.example.test {\n    respond ok\n}\n")
            inode = source.stat().st_ino
            with patch.object(CADDY, "run", side_effect=["{}", "", ""]) as command:
                CADDY.apply_config(source, ["caddy"], str(source), "authserver-go-api:5175", "authserver-go-web:8080", directory)
            self.assertEqual(command.call_args_list[1].args[0][1], "validate")
            self.assertEqual(command.call_args_list[2].args[0][1], "reload")
            self.assertIn(CADDY.DOMAIN, source.read_text())
            self.assertIn("other.example.test", source.read_text())
            self.assertEqual(source.stat().st_ino, inode)


if __name__ == "__main__":
    unittest.main()
