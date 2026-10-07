"""Desktop backend checks use isolated profiles and mocked SSH only."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "server-manager" / "app.py"


def import_manager(data_dir):
    name = "desktop_backend_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, APP_PATH)
    manager = importlib.util.module_from_spec(spec)
    sys.modules[name] = manager
    with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": str(data_dir)}):
        spec.loader.exec_module(manager)
    return manager


class DesktopBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.profile = Path(self.temporary.name) / "user-data"
        self.manager = import_manager(self.profile)
        self.manager.app.config["TESTING"] = True
        self.manager.configure_local_access(47631)
        self.client = self.manager.app.test_client()
        # A regression must never contact an external server during these tests.
        self.network = patch.object(self.manager, "connect_ssh", side_effect=AssertionError("real SSH is forbidden"))
        self.network.start()

    def tearDown(self):
        self.manager.shutdown_resources()
        self.network.stop()
        self.temporary.cleanup()

    def request(self, method, path, **kwargs):
        kwargs.setdefault("base_url", "http://127.0.0.1:47631")
        kwargs.setdefault("headers", {"X-CSRF-Token": self.manager.CSRF_TOKEN})
        return self.client.open(path, method=method, **kwargs)

    def test_new_profile_has_no_source_credentials_or_known_hosts(self):
        manager = self.manager
        self.assertEqual(Path(manager.BASE), APP_PATH.parent)
        self.assertEqual(Path(manager.SERVERS_FILE), self.profile / "servers.json")
        self.assertEqual(Path(manager.SETTINGS_FILE), self.profile / "settings.json")
        self.assertEqual(Path(manager.KNOWN_HOSTS_FILE), self.profile / "known_hosts")
        self.assertEqual(list(self.profile.iterdir()), [])
        self.assertEqual(self.request("GET", "/api/servers").json, [])
        self.assertEqual(self.request("GET", "/api/settings").json,
                         {**{key + "_set": False for key in manager.KEY_FIELDS},
                          "ssh_auto_update_host_key": True})
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_explicit_profile_writes_are_dpapi_protected_and_user_isolated(self):
        response = self.request("POST", "/api/servers", json={
            "host": "example.invalid", "name": "Desktop test", "user": "root", "password": "test-only-secret"})
        self.assertEqual(response.status_code, 200)
        response = self.request("POST", "/api/settings", json={"openai_key": "test-only-key"})
        self.assertEqual(response.status_code, 200)
        servers = json.loads((self.profile / "servers.json").read_text(encoding="utf-8"))
        settings = json.loads((self.profile / "settings.json").read_text(encoding="utf-8"))
        self.assertTrue(servers[0]["password"].startswith("dpapi:v1:"))
        self.assertTrue(settings["openai_key"].startswith("dpapi:v1:"))
        self.assertNotIn("test-only-secret", (self.profile / "servers.json").read_text())
        self.assertNotIn("test-only-key", (self.profile / "settings.json").read_text())
        self.assertNotIn("password", self.request("GET", "/api/servers").json[0])
        other_profile = Path(self.temporary.name) / "other-user"
        other = import_manager(other_profile)
        try:
            self.assertEqual(other.load_json(other.SERVERS_FILE, []), [])
            self.assertEqual(other.load_json(other.SETTINGS_FILE, {}), {})
            self.assertEqual(list(other_profile.iterdir()), [])
        finally:
            other.shutdown_resources()

    def test_ssh_refresh_preference_is_boolean_and_preserved_by_api_key_edits(self):
        self.assertTrue(self.request("GET", "/api/settings").json["ssh_auto_update_host_key"])
        result = self.request("POST", "/api/settings", json={"ssh_auto_update_host_key": False})
        self.assertEqual(result.status_code, 200)
        self.assertFalse(self.request("GET", "/api/settings").json["ssh_auto_update_host_key"])
        self.assertEqual(self.request("POST", "/api/settings", json={"openai_key": "test-only"}).status_code, 200)
        settings = self.request("GET", "/api/settings").json
        self.assertTrue(settings["openai_key_set"])
        self.assertFalse(settings["ssh_auto_update_host_key"])
        before = (self.profile / "settings.json").read_bytes()
        for invalid in ("true", 1, 0, None, [], {}):
            with self.subTest(invalid=invalid):
                response = self.request("POST", "/api/settings", json={"ssh_auto_update_host_key": invalid})
                self.assertEqual(response.status_code, 400)
                self.assertEqual((self.profile / "settings.json").read_bytes(), before)

    def test_saved_refresh_preference_reaches_ssh_connection_and_connection_status(self):
        server = {"id": "offline", "host": "example.invalid", "port": 2222,
                  "user": "root", "password": "fake-password-only"}
        identity = {"updated": True, "previous_fingerprint": "SHA256:old-test-only"}
        ssh = MagicMock()
        ssh._host_identity = identity
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                self.request("POST", "/api/settings", json={"ssh_auto_update_host_key": enabled})
                with patch.object(self.manager, "get_server", return_value=server), \
                     patch.object(self.manager, "connect_ssh", return_value=ssh) as connect, \
                     patch.object(self.manager, "sh", return_value="offline-host"):
                    response = self.request("POST", "/api/servers/offline/test")
                self.assertEqual(response.status_code, 200)
                self.assertIs(connect.call_args.kwargs["auto_update_host_key"], enabled)
                self.assertEqual(response.json["identity"], identity)
                self.assertIn("旧 SSH 指纹已自动更新", response.json["msg"])

    def test_dynamic_port_accepts_only_exact_loopback_host_and_origin(self):
        for host in ("127.0.0.1", "localhost"):
            with self.subTest(host=host):
                response = self.request("GET", "/api/servers", base_url=f"http://{host}:47631",
                                        headers={"Origin": f"http://{host}:47631", "X-CSRF-Token": self.manager.CSRF_TOKEN})
                self.assertEqual(response.status_code, 200)
        for host in ("127.0.0.1:8620", "localhost:8620", "127.0.0.2:47631", "127.0.0.1.:47631",
                     "evil.example:47631", "127.0.0.1", "localhost"):
            with self.subTest(forbidden_host=host):
                self.assertEqual(self.request("GET", "/api/health", base_url="http://" + host).status_code, 403)
        for origin in ("http://127.0.0.1:8620", "http://localhost:8620", "https://127.0.0.1:47631",
                       "http://evil.example:47631", "http://127.0.0.1:47631.evil.example", "null"):
            with self.subTest(forbidden_origin=origin):
                self.assertEqual(self.request("GET", "/api/servers",
                                 headers={"Origin": origin, "X-CSRF-Token": self.manager.CSRF_TOKEN}).status_code, 403)

    def test_desktop_port_keeps_csrf_and_websocket_origin_guards(self):
        self.assertEqual(self.request("GET", "/api/servers", headers={}).status_code, 403)
        self.assertEqual(self.request("POST", "/api/settings", json={"openai_key": "test"},
                                     headers={"X-CSRF-Token": "wrong"}).status_code, 403)
        self.assertEqual(self.request("GET", "/ws/terminal/none", headers={}).status_code, 403)
        self.assertEqual(self.request("GET", "/ws/terminal/none?token=" + self.manager.CSRF_TOKEN,
                                     headers={"Origin": "http://evil.example"}).status_code, 403)

    def test_port_validation_does_not_enable_ranges_or_wildcards(self):
        for port in (None, True, False, 0, 65536, "47631", "*", 47631.0):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.manager.configure_local_access(port)
        self.assertEqual(self.manager.app.config["LOCAL_ACCESS_PORT"], 47631)

    def test_health_keeps_browser_launcher_identity_without_user_profile(self):
        data = self.request("GET", "/api/health", headers={}).json
        self.assertEqual(data, {"app": "server-manager", "project_root": str(ROOT)})
        self.assertNotIn(str(self.profile), json.dumps(data))

    def test_ssh_uses_user_known_hosts_and_shutdown_closes_it(self):
        ssh = MagicMock()
        server = {"host": "example.invalid", "user": "root", "password": "test-only", "port": 22}
        with patch.object(self.manager, "connect_ssh", return_value=ssh) as connect:
            self.assertIs(self.manager.connect(server), ssh)
            self.assertEqual(connect.call_args.kwargs["known_hosts_path"], str(self.profile / "known_hosts"))
            self.manager.shutdown_resources()
            ssh.close.assert_called_once()
            self.manager.shutdown_resources()
            ssh.close.assert_called_once()
            with self.assertRaises(RuntimeError):
                self.manager.connect(server)
            self.assertEqual(connect.call_count, 1)

    def test_shutdown_closes_late_connection_before_exposing_it(self):
        ssh = MagicMock()
        server = {"host": "example.invalid", "user": "root", "password": "test-only", "port": 22}
        def connect_then_close(*args, **kwargs):
            self.manager.shutdown_resources()
            return ssh
        with patch.object(self.manager, "connect_ssh", side_effect=connect_then_close), self.assertRaises(RuntimeError):
            self.manager.connect(server)
        ssh.close.assert_called_once()

    def test_idle_close_blocks_new_jobs_without_skipping_resource_cleanup(self):
        ssh = MagicMock()
        self.manager._track_resource(ssh)
        self.assertTrue(self.manager.prepare_shutdown())
        self.assertFalse(self.manager._SHUTTING_DOWN)
        with self.assertRaises(ValueError):
            self.manager.new_job("must not start")
        self.assertEqual(self.manager.jobs, {})
        self.manager.shutdown_resources()
        ssh.close.assert_called_once()

    def test_busy_close_keeps_job_queue_usable(self):
        first = self.manager.new_job("running")
        self.assertFalse(self.manager.prepare_shutdown())
        second = self.manager.new_job("still permitted")
        self.assertIn(second, self.manager.jobs)
        self.manager.jobs[first]["status"] = "done"
        self.manager.jobs[second]["status"] = "done"
        self.assertTrue(self.manager.prepare_shutdown())
        with self.assertRaises(ValueError):
            self.manager.new_job("too late")

    def test_new_job_and_close_are_serialized_under_one_lock(self):
        ready = threading.Barrier(3)
        outcomes = {}
        def start_job():
            ready.wait(timeout=5)
            try:
                outcomes["job"] = self.manager.new_job("concurrent")
            except ValueError:
                outcomes["job"] = None
        def close_window():
            ready.wait(timeout=5)
            outcomes["close"] = self.manager.prepare_shutdown()
        starter = threading.Thread(target=start_job)
        closer = threading.Thread(target=close_window)
        starter.start()
        closer.start()
        ready.wait(timeout=5)
        starter.join(timeout=5)
        closer.join(timeout=5)
        self.assertFalse(starter.is_alive())
        self.assertFalse(closer.is_alive())
        if outcomes["close"]:
            self.assertIsNone(outcomes["job"])
            self.assertEqual(self.manager.jobs, {})
        else:
            self.assertIn(outcomes["job"], self.manager.jobs)
            self.assertEqual(self.manager.jobs[outcomes["job"]]["status"], "running")

    def test_download_buffer_uses_user_profile_and_is_cleaned(self):
        sftp = MagicMock()
        sftp.stat.return_value.st_mode = stat.S_IFREG | 0o600
        sftp.stat.return_value.st_size = 4
        sftp.open.return_value = io.BytesIO(b"demo")
        original_temporary_file = tempfile.TemporaryFile
        with patch.object(self.manager, "sftp_connection") as connection, \
             patch.object(self.manager.tempfile, "TemporaryFile", wraps=original_temporary_file) as temporary_file:
            connection.return_value.__enter__.return_value = sftp
            response = self.request("GET", "/api/servers/none/download?path=/demo.txt")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, b"demo")
            self.assertEqual(temporary_file.call_args.kwargs["dir"], str(self.profile))
            response.close()
        self.manager.shutdown_resources()
        self.assertEqual(list(self.profile.iterdir()), [])

    def test_profile_path_must_be_explicit_and_absolute(self):
        for invalid_path in ("", "relative\\data"):
            with self.subTest(path=invalid_path), self.assertRaises(ValueError):
                import_manager(invalid_path)

    def test_browser_source_mode_retains_existing_default_locations(self):
        name = "browser_backend_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, APP_PATH)
        browser = importlib.util.module_from_spec(spec)
        sys.modules[name] = browser
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FL_NETWORK_DATA_DIR", None)
            spec.loader.exec_module(browser)
        try:
            self.assertEqual(Path(browser.SERVERS_FILE), APP_PATH.parent / "servers.json")
            self.assertEqual(Path(browser.SETTINGS_FILE), APP_PATH.parent / "settings.json")
            self.assertEqual(Path(browser.KNOWN_HOSTS_FILE), ROOT / "known_hosts")
            self.assertEqual(browser.app.config["LOCAL_ACCESS_PORT"], 8620)
            self.assertEqual(browser.app.test_client().get("/api/health", base_url="http://127.0.0.1:8620").status_code, 200)
        finally:
            browser.shutdown_resources()


if __name__ == "__main__":
    unittest.main()
