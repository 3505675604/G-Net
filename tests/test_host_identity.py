"""Offline SSH identity checks: temporary stores, no authentication or sockets."""
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import MagicMock, patch

import paramiko

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import script_common

REAL_SSH_CLIENT = paramiko.SSHClient


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class OfflineIdentityCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.first_key = paramiko.RSAKey.generate(1024)
        cls.changed_key = paramiko.RSAKey.generate(1024)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.profile = Path(self.temporary.name)
        self.known_hosts = self.profile / "known_hosts"
        self.clients = []
        # Even real Paramiko key-store parsing must never inspect system keys.
        self.system_keys = self.enterContext(patch.object(REAL_SSH_CLIENT, "load_system_host_keys"))
        self.client_factory = self.enterContext(patch.object(script_common.paramiko, "SSHClient", side_effect=self.make_client))
        self.socket_guard = self.enterContext(patch.object(script_common.socket, "create_connection",
                                             side_effect=AssertionError("real network is forbidden")))
        self.transport_guard = self.enterContext(patch.object(script_common.paramiko, "Transport",
                                                side_effect=AssertionError("real transport is forbidden")))

    def make_client(self):
        client = REAL_SSH_CLIENT()
        client.close = MagicMock(wraps=client.close)
        client.save_host_keys = MagicMock(wraps=client.save_host_keys)
        client.connect = MagicMock(side_effect=AssertionError("real authentication is forbidden"))
        self.clients.append(client)
        return client

    def save_known(self, token, key=None):
        keys = paramiko.HostKeys()
        keys.add(token, (key or self.first_key).get_name(), key or self.first_key)
        keys.save(str(self.known_hosts))

    def identity(self, host="example.invalid", port=22, **kwargs):
        return script_common.host_identity(host, port, known_hosts_path=self.known_hosts, **kwargs)

    def assert_no_authentication(self):
        for client in self.clients:
            client.connect.assert_not_called()
            client.close.assert_called_once()


class HostIdentityTests(OfflineIdentityCase):
    def test_unknown_get_reports_fingerprint_without_saving_key_or_authentication(self):
        with patch.object(script_common, "_probe_host_key", return_value=self.first_key) as probe:
            result = self.identity()
        self.assertEqual(result, {"host": "example.invalid", "port": 22,
                                  "algorithm": self.first_key.get_name(), "fingerprint": fingerprint(self.first_key),
                                  "known": False, "changed": False, "updated": False,
                                  "previous_fingerprint": None, "auto_update_enabled": False})
        self.assertFalse(self.known_hosts.exists())
        self.clients[0].save_host_keys.assert_not_called()
        probe.assert_called_once_with("example.invalid", 22, (), timeout=10)
        self.assert_no_authentication()

    def test_confirmation_reprobes_then_saves_only_the_fresh_matching_key(self):
        with patch.object(script_common, "_probe_host_key", return_value=self.first_key) as probe:
            observed = self.identity()
            confirmed = self.identity(expected_fingerprint=observed["fingerprint"])
        self.assertEqual(probe.call_count, 2)
        self.assertTrue(confirmed["known"])
        self.assertFalse(confirmed["changed"])
        stored = paramiko.HostKeys(str(self.known_hosts))
        self.assertEqual(stored.lookup("example.invalid")[self.first_key.get_name()], self.first_key)
        self.assertEqual(len(list(self.profile.glob("known_hosts.*.tmp"))), 0)
        self.assert_no_authentication()

    def test_changed_between_get_and_confirm_is_not_enrolled(self):
        with patch.object(script_common, "_probe_host_key", side_effect=[self.first_key, self.changed_key]) as probe:
            observed = self.identity()
            with self.assertRaisesRegex(ValueError, "不一致"):
                self.identity(expected_fingerprint=observed["fingerprint"])
        self.assertEqual(probe.call_count, 2)
        self.assertFalse(self.known_hosts.exists())
        self.assert_no_authentication()

    def test_known_changed_key_is_reported_on_get_and_never_overwritten_by_post(self):
        self.save_known("example.invalid")
        before = self.known_hosts.read_bytes()
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key) as probe:
            result = self.identity()
            self.assertTrue(result["known"])
            self.assertTrue(result["changed"])
            with self.assertRaises(script_common.HostIdentityError) as rejected:
                self.identity(expected_fingerprint=fingerprint(self.changed_key))
        self.assertEqual(rejected.exception.code, "host_key_changed")
        self.assertEqual(self.known_hosts.read_bytes(), before)
        self.assertEqual(probe.call_args.args[2], (self.first_key.get_name(),))
        self.assert_no_authentication()

    def test_known_matching_confirmation_leaves_store_unchanged(self):
        self.save_known("example.invalid")
        before = self.known_hosts.read_bytes()
        with patch.object(script_common, "_probe_host_key", return_value=self.first_key):
            result = self.identity(expected_fingerprint=fingerprint(self.first_key))
        self.assertTrue(result["known"])
        self.assertEqual(self.known_hosts.read_bytes(), before)
        self.clients[0].save_host_keys.assert_not_called()
        self.assert_no_authentication()

    def test_nonstandard_port_and_ipv6_use_correct_known_host_tokens(self):
        cases = (("example.invalid", 2222, "[example.invalid]:2222"),
                 ("2001:db8::1", 22, "2001:db8::1"),
                 ("2001:db8::2", 2222, "[2001:db8::2]:2222"))
        with patch.object(script_common, "_probe_host_key", return_value=self.first_key):
            for host, port, token in cases:
                with self.subTest(host=host, port=port):
                    result = self.identity(host, port, expected_fingerprint=fingerprint(self.first_key))
                    self.assertTrue(result["known"])
                    self.assertEqual(paramiko.HostKeys(str(self.known_hosts)).lookup(token)[self.first_key.get_name()], self.first_key)
        self.assert_no_authentication()

    def test_probe_failure_closes_identity_client_without_saving_key(self):
        with patch.object(script_common, "_probe_host_key", side_effect=ValueError("offline failure")):
            with self.assertRaisesRegex(ValueError, "offline failure"):
                self.identity()
        self.assertFalse(self.known_hosts.exists())
        self.assert_no_authentication()

    def test_invalid_fingerprint_is_rejected_before_handshake(self):
        with patch.object(script_common, "_probe_host_key") as probe:
            for invalid in ("", "SHA256:short", "SHA256:" + "?" * 43, "A" * 43, 123, False):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    self.identity(expected_fingerprint=invalid)
        probe.assert_not_called()
        self.client_factory.assert_not_called()
        self.assertFalse(self.known_hosts.exists())


class AutomaticHostRefreshTests(OfflineIdentityCase):
    def test_refresh_keeps_other_hosts_ports_aliases_and_comments(self):
        ecdsa_key = paramiko.ECDSAKey.generate()
        hashed = paramiko.HostKeys.hash_host("example.invalid")
        self.known_hosts.write_text(
            "# keep this comment exactly\n"
            + f"example.invalid,alias.invalid {self.first_key.get_name()} {self.first_key.get_base64()}\n"
            + f"{hashed} {ecdsa_key.get_name()} {ecdsa_key.get_base64()}\n"
            + f"[example.invalid]:2222 {self.first_key.get_name()} {self.first_key.get_base64()}\n",
            encoding="utf-8")
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key):
            result = self.identity(auto_update_host_key=True)
        self.assertTrue(result["updated"])
        self.assertFalse(result["changed"])
        self.assertEqual(result["previous_fingerprint"], fingerprint(self.first_key))
        stored = paramiko.HostKeys(str(self.known_hosts))
        self.assertEqual(stored.lookup("example.invalid").keys(), [self.changed_key.get_name()])
        self.assertEqual(stored.lookup("example.invalid")[self.changed_key.get_name()], self.changed_key)
        self.assertEqual(stored.lookup("alias.invalid")[self.first_key.get_name()], self.first_key)
        self.assertEqual(stored.lookup("[example.invalid]:2222")[self.first_key.get_name()], self.first_key)
        self.assertTrue(self.known_hosts.read_text().startswith("# keep this comment exactly\n"))
        self.assertEqual(list(self.profile.glob("known_hosts.*.tmp")), [])
        self.assert_no_authentication()

    def test_unknown_target_still_requires_first_confirmation_with_refresh_enabled(self):
        with patch.object(script_common, "_probe_host_key", return_value=self.first_key):
            result = self.identity(auto_update_host_key=True)
        self.assertFalse(result["known"])
        self.assertFalse(result["updated"])
        self.assertFalse(self.known_hosts.exists())
        self.assert_no_authentication()

    def test_confirmation_mismatch_does_not_refresh_known_target(self):
        self.save_known("example.invalid")
        before = self.known_hosts.read_bytes()
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key):
            with self.assertRaisesRegex(ValueError, "不一致"):
                self.identity(auto_update_host_key=True, expected_fingerprint=fingerprint(self.first_key))
        self.assertEqual(self.known_hosts.read_bytes(), before)
        self.assert_no_authentication()

    def test_probe_failure_does_not_refresh_known_target(self):
        self.save_known("example.invalid")
        before = self.known_hosts.read_bytes()
        with patch.object(script_common, "_probe_host_key", side_effect=ValueError("offline probe failure")):
            with self.assertRaisesRegex(ValueError, "offline probe failure"):
                self.identity(auto_update_host_key=True)
        self.assertEqual(self.known_hosts.read_bytes(), before)
        self.assert_no_authentication()

    def test_concurrent_store_edit_is_preserved_and_refresh_is_rejected(self):
        self.save_known("example.invalid")
        concurrently_written = self.known_hosts.read_bytes() + b"# concurrent owner edit\n"

        def change_store(*args, **kwargs):
            self.known_hosts.write_bytes(concurrently_written)
            return self.changed_key

        with patch.object(script_common, "_probe_host_key", side_effect=change_store):
            with self.assertRaisesRegex(ValueError, "其他程序修改"):
                self.identity(auto_update_host_key=True)
        self.assertEqual(self.known_hosts.read_bytes(), concurrently_written)
        self.assert_no_authentication()

    def test_atomic_replace_failure_preserves_previous_store_and_removes_temp(self):
        self.save_known("example.invalid")
        before = self.known_hosts.read_bytes()
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key), \
             patch.object(script_common.os, "replace", side_effect=OSError("offline disk failure")):
            with self.assertRaises(OSError):
                self.identity(auto_update_host_key=True)
        self.assertEqual(self.known_hosts.read_bytes(), before)
        self.assertEqual(list(self.profile.glob("known_hosts.*.tmp")), [])
        self.assert_no_authentication()

    def test_changed_system_key_gets_app_override_without_writing_system_store(self):
        system_store = self.profile / "fake-system-known-hosts"
        system_store.write_text(f"example.invalid {self.first_key.get_name()} {self.first_key.get_base64()}\n")
        before = system_store.read_bytes()
        client = self.make_client()
        client._system_host_keys.load(str(system_store))
        self.client_factory.side_effect = None
        self.client_factory.return_value = client
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key):
            result = self.identity(auto_update_host_key=True)
        self.assertTrue(result["updated"])
        self.assertEqual(system_store.read_bytes(), before)
        self.assertEqual(paramiko.HostKeys(str(self.known_hosts)).lookup("example.invalid")
                         [self.changed_key.get_name()], self.changed_key)
        self.assert_no_authentication()

    def test_invalid_refresh_policy_is_rejected_before_probe_or_file_creation(self):
        with patch.object(script_common, "_probe_host_key") as probe:
            for value in ("true", 1, 0, None, [], {}):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.identity(auto_update_host_key=value)
        probe.assert_not_called()
        self.assertFalse(self.known_hosts.exists())


class HostHandshakeTests(OfflineIdentityCase):
    def fake_handshake(self):
        sock, transport = MagicMock(), MagicMock()
        transport.get_remote_server_key.return_value = self.first_key
        return sock, transport

    def assert_closed_without_auth(self, sock, transport):
        sock.close.assert_called_once()
        transport.close.assert_called_once()
        for operation in ("auth_none", "auth_password", "auth_publickey", "auth_interactive", "connect"):
            getattr(transport, operation).assert_not_called()

    def test_probe_only_negotiates_key_and_closes_transport_and_socket(self):
        sock, transport = self.fake_handshake()
        with patch.object(script_common.socket, "create_connection", return_value=sock) as connection, \
             patch.object(script_common.paramiko, "Transport", return_value=transport) as factory:
            key = script_common._probe_host_key("2001:db8::1", 2222, timeout=7)
        self.assertIs(key, self.first_key)
        connection.assert_called_once_with(("2001:db8::1", 2222), timeout=7)
        sock.settimeout.assert_called_once_with(7)
        factory.assert_called_once_with(sock)
        transport.start_client.assert_called_once_with(timeout=7)
        self.assert_closed_without_auth(sock, transport)

    def test_failed_handshake_is_sanitized_and_closes_both_resources(self):
        sock, transport = self.fake_handshake()
        transport.start_client.side_effect = RuntimeError("sensitive-internal-error")
        with patch.object(script_common.socket, "create_connection", return_value=sock), \
             patch.object(script_common.paramiko, "Transport", return_value=transport):
            with self.assertRaises(ValueError) as error:
                script_common._probe_host_key("example.invalid", 22)
        self.assertNotIn("sensitive-internal-error", str(error.exception))
        self.assert_closed_without_auth(sock, transport)

    def test_transport_construction_failure_still_closes_socket(self):
        sock = MagicMock()
        with patch.object(script_common.socket, "create_connection", return_value=sock), \
             patch.object(script_common.paramiko, "Transport", side_effect=RuntimeError("constructor failed")):
            with self.assertRaises(ValueError):
                script_common._probe_host_key("example.invalid", 22)
        sock.close.assert_called_once()

    def test_known_rsa_key_prefers_compatible_sha2_negotiation(self):
        sock, transport = self.fake_handshake()
        options = transport.get_security_options.return_value
        options.key_types = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512")
        with patch.object(script_common.socket, "create_connection", return_value=sock), \
             patch.object(script_common.paramiko, "Transport", return_value=transport):
            script_common._probe_host_key("example.invalid", 22, algorithms=("ssh-rsa",))
        self.assertEqual(options.key_types[:3], ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"))
        self.assert_closed_without_auth(sock, transport)


class StrictHostConnectionTests(OfflineIdentityCase):
    def connect(self, **kwargs):
        return script_common.connect_ssh("example.invalid", password="fake-password-only",
                                         known_hosts_path=self.known_hosts, trust_new_host=False, **kwargs)

    def test_unknown_strict_connection_is_rejected_without_persisting_key_and_client_closes(self):
        client = self.make_client()
        self.client_factory.side_effect = None
        self.client_factory.return_value = client

        def reject_unknown(*args, **kwargs):
            client._policy.missing_host_key(client, "example.invalid", self.first_key)

        client.connect.side_effect = reject_unknown
        with self.assertRaises(script_common.HostIdentityError) as error:
            self.connect()
        self.assertEqual(error.exception.code, "host_key_required")
        self.assertEqual(self.known_hosts.read_text(), "")
        self.assertIsInstance(client._policy, script_common._RequireConfirmedHostKey)
        client.save_host_keys.assert_not_called()
        client.close.assert_called_once()
        self.assertFalse(client.connect.call_args.kwargs["allow_agent"])
        self.assertFalse(client.connect.call_args.kwargs["look_for_keys"])

    def test_changed_strict_connection_is_rejected_without_overwriting_known_key_and_client_closes(self):
        self.save_known("example.invalid")
        before = self.known_hosts.read_bytes()
        client = self.make_client()
        self.client_factory.side_effect = None
        self.client_factory.return_value = client
        client.connect.side_effect = paramiko.BadHostKeyException("example.invalid", self.changed_key, self.first_key)
        with self.assertRaises(script_common.HostIdentityError) as error:
            self.connect()
        self.assertEqual(error.exception.code, "host_key_changed")
        self.assertEqual(self.known_hosts.read_bytes(), before)
        client.close.assert_called_once()
        client.save_host_keys.assert_not_called()

    def test_confirmed_connection_loads_only_temporary_store_and_leaves_client_open_for_caller(self):
        self.save_known("[example.invalid]:2222")
        client = self.make_client()
        self.client_factory.side_effect = None
        self.client_factory.return_value = client
        client.connect.side_effect = None
        result = self.connect(port=2222, user="admin")
        self.assertIs(result, client)
        self.assertEqual(client.get_host_keys().lookup("[example.invalid]:2222")[self.first_key.get_name()], self.first_key)
        self.assertEqual(client.connect.call_args.kwargs["port"], 2222)
        self.assertEqual(client.connect.call_args.kwargs["username"], "admin")
        client.close.assert_not_called()
        client.close()

    def test_refresh_persists_then_pins_exact_observed_key_before_authentication(self):
        self.save_known("example.invalid")
        client = self.make_client()
        client._system_host_keys.add("example.invalid", self.first_key.get_name(), self.first_key)
        client._system_host_keys.add("other.invalid", self.first_key.get_name(), self.first_key)
        client._system_host_keys.add("[example.invalid]:2222", self.first_key.get_name(), self.first_key)
        self.client_factory.side_effect = None
        self.client_factory.return_value = client

        def check_pin(*args, **kwargs):
            self.assertEqual(paramiko.HostKeys(str(self.known_hosts)).lookup("example.invalid")
                             [self.changed_key.get_name()], self.changed_key)
            self.assertIsNone(client._system_host_keys.lookup("example.invalid"))
            self.assertEqual(client._system_host_keys.lookup("other.invalid")[self.first_key.get_name()], self.first_key)
            self.assertEqual(client._system_host_keys.lookup("[example.invalid]:2222")[self.first_key.get_name()], self.first_key)
            self.assertEqual(client.get_host_keys().lookup("example.invalid").keys(), [self.changed_key.get_name()])
            self.assertEqual(client.get_host_keys().lookup("example.invalid")[self.changed_key.get_name()], self.changed_key)
            self.assertIsInstance(client._policy, script_common._RequireConfirmedHostKey)

        client.connect.side_effect = check_pin
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key) as probe:
            self.assertIs(self.connect(auto_update_host_key=True), client)
        probe.assert_called_once()
        self.assertTrue(client._host_identity["updated"])
        self.assertEqual(client._host_identity["previous_fingerprint"], fingerprint(self.first_key))
        client.close()

    def test_refresh_does_not_authenticate_unknown_host(self):
        with patch.object(script_common, "_probe_host_key", return_value=self.first_key):
            with self.assertRaises(script_common.HostIdentityError) as error:
                self.connect(auto_update_host_key=True)
        self.assertEqual(error.exception.code, "host_key_required")
        self.assertEqual(self.known_hosts.read_bytes(), b"")
        self.assert_no_authentication()

    def test_probe_failure_does_not_authenticate_or_modify_store(self):
        self.save_known("example.invalid")
        before = self.known_hosts.read_bytes()
        with patch.object(script_common, "_probe_host_key", side_effect=ValueError("offline failure")):
            with self.assertRaisesRegex(ValueError, "offline failure"):
                self.connect(auto_update_host_key=True)
        self.assertEqual(self.known_hosts.read_bytes(), before)
        self.assert_no_authentication()

    def test_actual_handshake_changed_after_probe_is_rejected_before_authentication(self):
        self.save_known("example.invalid")
        client = self.make_client()
        self.client_factory.side_effect = None
        self.client_factory.return_value = client
        client.connect = MagicMock(wraps=REAL_SSH_CLIENT.connect.__get__(client, REAL_SSH_CLIENT))
        client._auth = MagicMock(side_effect=AssertionError("credentials must not be sent"))
        client._families_and_addresses = MagicMock(return_value=[(2, ("example.invalid", 22))])
        sock, transport = MagicMock(), MagicMock()
        transport.get_security_options.return_value.key_types = ["ssh-rsa", "rsa-sha2-512"]
        transport.get_remote_server_key.return_value = self.first_key
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key), \
             patch("paramiko.client.socket.socket", return_value=sock), \
             patch("paramiko.client.Transport", return_value=transport):
            with self.assertRaises(script_common.HostIdentityError) as error:
                self.connect(auto_update_host_key=True)
        self.assertEqual(error.exception.code, "host_key_changed")
        client._auth.assert_not_called()
        self.assertEqual(paramiko.HostKeys(str(self.known_hosts)).lookup("example.invalid")
                         [self.changed_key.get_name()], self.changed_key)
        client.close.assert_called_once()


class HostIdentityApiTests(OfflineIdentityCase):
    def setUp(self):
        super().setUp()
        name = "host_identity_api_test_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, ROOT / "server-manager" / "app.py")
        self.manager = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.manager
        self.addCleanup(lambda: sys.modules.pop(name, None))
        with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": str(self.profile)}):
            spec.loader.exec_module(self.manager)
        self.addCleanup(self.manager.shutdown_resources)
        self.manager.app.config["TESTING"] = True
        self.manager.configure_local_access(47631)
        self.client = self.manager.app.test_client()
        self.server = {"id": "fake-server", "host": "example.invalid", "port": 2222,
                       "user": "admin", "password": "fake-password-only"}
        self.server_lookup = self.enterContext(patch.object(self.manager, "get_server", return_value=self.server))
        # Existing strict-policy cases explicitly opt out; other cases below
        # exercise the new application default.
        self.enterContext(patch.object(self.manager, "auto_update_ssh_identity", return_value=False))
        self.enterContext(patch.object(self.manager, "connect_ssh", side_effect=AssertionError("identity API must not authenticate")))

    def request(self, method="GET", **kwargs):
        kwargs.setdefault("base_url", "http://127.0.0.1:47631")
        kwargs.setdefault("headers", {"X-CSRF-Token": self.manager.CSRF_TOKEN})
        return self.client.open("/api/servers/fake-server/identity", method=method, **kwargs)

    def test_get_api_does_not_save_and_post_reprobes_matching_fingerprint(self):
        with patch.object(script_common, "_probe_host_key", return_value=self.first_key) as probe:
            observed = self.request()
            self.assertEqual(observed.status_code, 200)
            self.assertFalse(observed.json["known"])
            self.assertFalse(self.known_hosts.exists())
            confirmed = self.request("POST", json={"fingerprint": observed.json["fingerprint"]})
        self.assertEqual(confirmed.status_code, 200)
        self.assertTrue(confirmed.json["known"])
        self.assertEqual(probe.call_count, 2)
        self.assertIn("[example.invalid]:2222", paramiko.HostKeys(str(self.known_hosts)))
        self.assertNotIn("fake-password-only", confirmed.get_data(as_text=True))
        self.assert_no_authentication()

    def test_api_post_rejects_key_changed_since_get_without_saving(self):
        with patch.object(script_common, "_probe_host_key", side_effect=[self.first_key, self.changed_key]):
            observed = self.request()
            rejected = self.request("POST", json={"fingerprint": observed.json["fingerprint"]})
        self.assertEqual(rejected.status_code, 400)
        self.assertFalse(self.known_hosts.exists())
        self.assert_no_authentication()

    def test_api_known_changed_key_returns_conflict_and_does_not_overwrite(self):
        self.save_known("[example.invalid]:2222")
        before = self.known_hosts.read_bytes()
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key):
            observed = self.request()
            self.assertTrue(observed.json["changed"])
            rejected = self.request("POST", json={"fingerprint": observed.json["fingerprint"]})
        self.assertEqual(rejected.status_code, 409)
        self.assertEqual(rejected.json["code"], "host_key_changed")
        self.assertEqual(self.known_hosts.read_bytes(), before)
        self.assert_no_authentication()

    def test_api_enabled_policy_refreshes_known_target_and_reports_change(self):
        self.save_known("[example.invalid]:2222")
        self.manager.auto_update_ssh_identity.return_value = True
        with patch.object(script_common, "_probe_host_key", return_value=self.changed_key):
            response = self.request()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["updated"])
        self.assertFalse(response.json["changed"])
        self.assertTrue(response.json["known"])
        self.assertEqual(response.json["previous_fingerprint"], fingerprint(self.first_key))
        self.assertEqual(paramiko.HostKeys(str(self.known_hosts)).lookup("[example.invalid]:2222")
                         [self.changed_key.get_name()], self.changed_key)
        self.assert_no_authentication()

    def test_api_only_accepts_fingerprint_and_never_client_key_host_or_store_path(self):
        invalid = ({}, [], {"fingerprint": None},
                   {"fingerprint": fingerprint(self.first_key), "key": "forged-public-key"},
                   {"fingerprint": fingerprint(self.first_key), "known_hosts_path": "C:/forbidden"},
                   {"fingerprint": fingerprint(self.first_key), "host": "other.invalid"})
        with patch.object(self.manager, "host_identity") as identity:
            for body in invalid:
                with self.subTest(body=body):
                    self.assertEqual(self.request("POST", json=body).status_code, 400)
        identity.assert_not_called()
        self.assertFalse(self.known_hosts.exists())

    def test_api_csrf_host_and_origin_guards_run_before_probe(self):
        with patch.object(self.manager, "host_identity") as identity:
            self.assertEqual(self.request(headers={}).status_code, 403)
            self.assertEqual(self.request(base_url="http://attacker.invalid:47631").status_code, 403)
            self.assertEqual(self.request(headers={"X-CSRF-Token": self.manager.CSRF_TOKEN,
                                                  "Origin": "https://attacker.invalid"}).status_code, 403)
        identity.assert_not_called()

    def test_missing_server_is_rejected_before_handshake(self):
        self.server_lookup.return_value = None
        with patch.object(self.manager, "host_identity") as identity:
            response = self.request()
        self.assertEqual(response.status_code, 400)
        identity.assert_not_called()


if __name__ == "__main__":
    unittest.main()
