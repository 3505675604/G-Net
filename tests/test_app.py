import importlib.util
import json
import pathlib
import shlex
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("server_manager_test", ROOT / "server-manager" / "app.py")
manager = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = manager
spec.loader.exec_module(manager)
from local_security import decrypt_secret, encrypt_secret, validate_host, validate_port


class ImmediateThread:
    def __init__(self, target, **kwargs):
        self.target = target

    def start(self):
        self.target()


class AppTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.servers = pathlib.Path(self.directory.name) / "servers.json"
        self.settings = pathlib.Path(self.directory.name) / "settings.json"
        self.patches = [patch.object(manager, "SERVERS_FILE", str(self.servers)),
                        patch.object(manager, "SETTINGS_FILE", str(self.settings))]
        for replacement in self.patches:
            replacement.start()
        manager.jobs.clear()
        manager.app.config["TESTING"] = True
        self.client = manager.app.test_client()

    def tearDown(self):
        for replacement in reversed(self.patches):
            replacement.stop()
        self.directory.cleanup()

    def request(self, method, path, **kwargs):
        return self.client.open(path, method=method, base_url="http://127.0.0.1:8620",
                                headers={"X-CSRF-Token": manager.CSRF_TOKEN}, **kwargs)

    def add(self, **extra):
        body = {"host": "example.com", "user": "root", "password": "dummy-password", **extra}
        return self.request("POST", "/api/servers", json=body)

    def test_local_origin_host_and_token_guards(self):
        self.assertEqual(self.client.get("/api/servers", base_url="http://127.0.0.1:8620").status_code, 403)
        self.assertEqual(self.client.get("/", base_url="http://attacker.test:8620").status_code, 403)
        self.assertEqual(self.client.get("/api/health", base_url="http://127.0.0.1:8620",
                                        headers={"Origin": "https://attacker.test"}).status_code, 403)
        health = self.client.get("/api/health", base_url="http://127.0.0.1:8620")
        self.assertEqual(health.json["app"], "server-manager")
        self.assertEqual(health.json["project_root"], str(ROOT))

    def test_home_render_and_local_dependencies(self):
        response = self.request("GET", "/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(manager.CSRF_TOKEN.encode(), response.data)
        self.assertNotIn(b"cdn.jsdelivr.net", response.data)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_add_returns_unique_id_and_keeps_password_private(self):
        first, second = self.add(), self.add(port=2222)
        self.assertEqual(first.status_code, 200)
        self.assertNotEqual(first.json["id"], second.json["id"])
        listed = self.request("GET", "/api/servers").json
        self.assertEqual(len(listed), 2)
        self.assertNotIn("password", listed[0])
        stored = self.servers.read_text(encoding="utf-8")
        self.assertNotIn("dummy-password", stored)
        self.assertIn("dpapi:v1:", stored)

    def test_settings_only_status_preserves_blank_and_can_clear(self):
        self.request("POST", "/api/settings", json={"openai_key": "dummy-key"})
        result = self.request("GET", "/api/settings")
        self.assertEqual(result.json["openai_key_set"], True)
        self.assertNotIn("dummy-key", result.get_data(as_text=True))
        self.request("POST", "/api/settings", json={"openai_key": ""})
        self.assertEqual(manager.load_json(str(self.settings), {})["openai_key"], "dummy-key")
        self.request("POST", "/api/settings", json={"clear_keys": ["openai_key"]})
        self.assertFalse(self.request("GET", "/api/settings").json["openai_key_set"])

    def test_legacy_encryption_migrates_once(self):
        self.settings.write_text(json.dumps({"deepseek_key": "dummy-legacy"}), encoding="utf-8")
        self.assertEqual(manager.load_json(str(self.settings), {})["deepseek_key"], "dummy-legacy")
        first = self.settings.read_bytes()
        self.assertNotIn(b"dummy-legacy", first)
        manager.load_json(str(self.settings), {})
        self.assertEqual(first, self.settings.read_bytes())

    def test_invalid_parameters_never_connect(self):
        with patch.object(manager, "connect") as connect:
            self.assertEqual(self.add(host="127.0.0.1; rm -rf /").status_code, 400)
            self.assertEqual(self.add(port="22junk").status_code, 400)
            self.assertEqual(self.request("POST", "/api/servers", json=[]).status_code, 400)
            self.assertEqual(self.request("GET", "/api/servers/none/info").status_code, 400)
            connect.assert_not_called()

    def test_concurrent_server_updates_are_not_lost(self):
        def add_one(number):
            with manager.app.test_client() as client:
                return client.post("/api/servers", base_url="http://127.0.0.1:8620",
                                   headers={"X-CSRF-Token": manager.CSRF_TOKEN},
                                   json={"host": "example.com", "user": "root", "password": "dummy", "name": str(number)}).status_code
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(list(pool.map(add_one, range(8))), [200] * 8)
        self.assertEqual(len(manager.load_json(str(self.servers), [])), 8)

    def test_failed_tool_is_error_and_ssh_always_closes(self):
        sid = self.add().json["id"]
        ssh = MagicMock()
        with patch.object(manager, "connect", return_value=ssh), \
             patch.object(manager.threading, "Thread", ImmediateThread), \
             patch.object(manager, "run_checked", side_effect=["0", RuntimeError("exit 42")]):
            response = self.request("POST", f"/api/servers/{sid}/run", json={"action": "install_node"})
        self.assertEqual(manager.jobs[response.json["job"]]["status"], "error")
        ssh.close.assert_called_once()

    def test_legacy_xray_tool_uses_incremental_deployment(self):
        sid = self.add().json["id"]
        with patch.object(manager, "_deploy_direct", return_value={"links": ["dummy-link"]}) as deploy, \
             patch.object(manager.threading, "Thread", ImmediateThread), patch.object(manager, "connect") as connect:
            response = self.request("POST", f"/api/servers/{sid}/run", json={"action": "install_xray", "port": 443})
        self.assertEqual(manager.jobs[response.json["job"]]["status"], "done")
        self.assertEqual(deploy.call_args.args[1]["port"], 443)
        connect.assert_not_called()

    def test_file_failure_closes_sftp_and_ssh(self):
        ssh, sftp = MagicMock(), MagicMock()
        sftp.listdir_attr.side_effect = OSError("denied")
        with patch.object(manager, "_sftp", return_value=(ssh, sftp)):
            response = self.request("GET", "/api/servers/fake/files?path=/root")
        self.assertFalse(response.json["ok"])
        sftp.close.assert_called_once()
        ssh.close.assert_called_once()

    def test_deleting_running_server_is_blocked(self):
        sid = self.add().json["id"]
        manager.new_job("working", server_ids=[sid])
        self.assertEqual(self.request("DELETE", f"/api/servers/{sid}").status_code, 409)

    def test_credentials_roundtrip(self):
        encrypted = encrypt_secret("dummy-密码")
        self.assertEqual(decrypt_secret(encrypted), "dummy-密码")
        self.assertEqual(encrypt_secret(encrypted), encrypted)

    def test_terminal_shell_failure_releases_ssh_even_if_ws_send_fails(self):
        ssh, ws = MagicMock(), MagicMock()
        ssh.invoke_shell.side_effect = RuntimeError("shell denied")
        ws.send.side_effect = RuntimeError("browser left")
        with patch.object(manager, "get_server", return_value={"id": "fake"}), \
             patch.object(manager, "connect", return_value=ssh):
            with self.assertRaises(RuntimeError):
                manager.app.view_functions["terminal"].__wrapped__(ws, "fake")
        ssh.close.assert_called_once()
        ws.close.assert_called_once()

    def test_sftp_close_failure_still_releases_ssh(self):
        ssh, sftp = MagicMock(), MagicMock()
        sftp.close.side_effect = OSError("close failed")
        with patch.object(manager, "_sftp", return_value=(ssh, sftp)):
            with self.assertRaises(OSError):
                with manager.sftp_connection("fake"):
                    pass
        ssh.close.assert_called_once()

    def test_sftp_channel_has_read_timeout(self):
        ssh, sftp = MagicMock(), MagicMock()
        ssh.open_sftp.return_value = sftp
        with patch.object(manager, "get_server", return_value={"id": "fake"}), patch.object(manager, "connect", return_value=ssh):
            self.assertEqual(manager._sftp("fake"), (ssh, sftp))
        sftp.get_channel().settimeout.assert_called_once_with(60)

    def test_remote_pipe_is_rejected_before_opening(self):
        ssh, sftp = MagicMock(), MagicMock()
        sftp.stat.return_value.st_mode = 0o010600
        with patch.object(manager, "_sftp", return_value=(ssh, sftp)):
            response = self.request("GET", "/api/servers/fake/file?path=/tmp/pipe")
        self.assertFalse(response.json["ok"])
        sftp.open.assert_not_called()

    def test_api_key_payload_is_literal_and_written_to_private_file(self):
        key = "dummy' $(touch /tmp/SHOULD_NOT_EXIST); `id`"
        script = manager._private_api_key("OPENAI_API_KEY", key)
        printf_line = next(line for line in script.splitlines() if line.startswith("printf "))
        tokens = shlex.split(printf_line)
        self.assertEqual(shlex.split(tokens[2]), ["export", "OPENAI_API_KEY=" + key])
        self.assertIn('chmod 600 "$HOME/.server-manager/OPENAI_API_KEY.env"', script)
        self.assertNotIn(key + " >> ~/.bashrc", script)


if __name__ == "__main__":
    unittest.main()
