"""Offline SSH authentication, editing, and capability regressions.

All secrets are generated fake fixtures, configuration paths are temporary,
SSH clients are mocked, and no listener or remote command is started.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
import local_security
import script_common

with tempfile.TemporaryDirectory(prefix="auth-module-") as directory:
    with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": str(Path(directory) / "profile")}):
        spec = importlib.util.spec_from_file_location("ssh_auth_test_app", ROOT / "server-manager" / "app.py")
        manager = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = manager
        spec.loader.exec_module(manager)

PASSPHRASE = "FAKE-key-passphrase-only"
KEYS = {"rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ecdsa": ec.generate_private_key(ec.SECP256R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate()}

def private_text(kind="rsa", fmt=serialization.PrivateFormat.OpenSSH, encrypted=False):
    encryption = serialization.BestAvailableEncryption(PASSPHRASE.encode()) if encrypted else serialization.NoEncryption()
    return KEYS[kind].private_bytes(serialization.Encoding.PEM, fmt, encryption).decode("ascii")

def capability_text(**overrides):
    values = {"kernel": "Linux", "arch": "x86_64", "uid": "0", "user": "root",
              "os_ID": "ubuntu", "os_ID_LIKE": "debian", "os_VERSION_ID": "24.04", "os_PRETTY_NAME": "Ubuntu Test",
              "systemd": "1", "sudo": "1", "package_arch": "amd64", "node_version": "v22.12.0",
              "npm_version": "10.9.0", "bbr_algorithms": "reno cubic bbr", "sysctl_writable": "1", "xray": "1"}
    for name in ("bash", "apt-get", "dpkg", "dnf", "yum", "zypper", "pacman", "emerge", "curl", "wget",
                 "systemctl", "sysctl", "npm", "node", "flock", "ss", "sha256sum", "base64", "cat", "head", "tail",
                 "nproc", "free", "df"):
        values["cmd_" + name] = "1"
    values.update(overrides)
    return "\n".join(f"{key}={value}" for key, value in values.items())

class ImmediateThread:
    def __init__(self, target, **kwargs):
        self.target = target
    def start(self):
        self.target()

class AuthValidationTests(unittest.TestCase):
    def test_old_password_default_agent_and_metadata_missing_credentials(self):
        self.assertEqual(local_security.validate_auth({"password": "FAKE-password-only"})["auth_type"], "password")
        self.assertEqual(local_security.validate_auth({"auth_type": "agent"}),
                         {"auth_type": "agent", "credential_required": False})
        for mode in ("password", "private_key"):
            self.assertTrue(local_security.validate_auth({"auth_type": mode}, allow_missing=True)["credential_required"])
            with self.assertRaises(ValueError):
                local_security.validate_auth({"auth_type": mode})

    def test_edit_preserves_same_mode_but_changing_mode_drops_other_credentials(self):
        old = {"auth_type": "private_key", "private_key": private_text(), "key_passphrase": PASSPHRASE}
        same = local_security.validate_auth({"private_key": "", "key_passphrase": ""}, previous=old)
        self.assertEqual((same["private_key"], same["key_passphrase"]), (old["private_key"], PASSPHRASE))
        password = local_security.validate_auth({"auth_type": "password", "password": "new-fake"}, previous=old)
        self.assertNotIn("private_key", password)
        self.assertNotIn("key_passphrase", password)
        agent = local_security.validate_auth({"auth_type": "agent"}, previous=password)
        self.assertFalse(any(field in agent for field in local_security.SSH_SECRET_FIELDS))
        with self.assertRaises(ValueError):
            local_security.validate_auth({"auth_type": "agent", "password": "must-not-be-used"})

    def test_paths_unknown_modes_ciphertext_and_invalid_types_are_rejected(self):
        invalid = [{"auth_type": "other", "password": "fake"}, {"auth_type": []},
                   {"password": "dpapi:v1:fake"}, {"password": None}, {"password": "\ud800"},
                   {"password": "x" * 4097}, {"auth_type": "private_key", "private_key": "C:\\id_rsa"},
                   {"auth_type": "private_key", "private_key": "/home/user/id_rsa"},
                   {"password": "fake", "key_filename": "/tmp/key"}, {"password": "fake", "private_key_path": "key"}]
        for data in invalid:
            with self.subTest(data=list(data)), self.assertRaises(ValueError):
                local_security.validate_auth(data)

    def test_dpapi_encrypts_every_ssh_secret_and_roundtrips_only_fake_data(self):
        data = [{"auth_type": "private_key", "password": "FAKE-unused-only",
                 "private_key": private_text(), "key_passphrase": PASSPHRASE}]
        protected = local_security.transform_secrets(data, "servers.json", encrypt=True)
        for field in local_security.SSH_SECRET_FIELDS:
            self.assertTrue(protected[0][field].startswith(local_security.PREFIX))
            self.assertNotEqual(protected[0][field], data[0][field])
        self.assertEqual(local_security.transform_secrets(protected, "servers.json"), data)

    def test_cli_modes_pass_text_without_writing_private_key_files_and_repr_omits_secrets(self):
        env = {"SSH_HOST": "example.invalid", "SSH_AUTH_TYPE": "private_key",
               "SSH_PRIVATE_KEY": private_text(encrypted=True), "SSH_KEY_PASSPHRASE": PASSPHRASE}
        options = script_common.ssh_options(env)
        self.assertEqual(options.auth_type, "private_key")
        self.assertNotIn("BEGIN", repr(options))
        self.assertNotIn(PASSPHRASE, repr(options))
        agent = script_common.ssh_options({"SSH_HOST": "example.invalid", "SSH_AUTH_TYPE": "agent"})
        self.assertEqual((agent.auth_type, agent.password), ("agent", ""))

class MemoryPrivateKeyTests(unittest.TestCase):
    def test_rsa_ecdsa_ed25519_openssh_keys_plain_and_encrypted(self):
        for kind in KEYS:
            for encrypted in (False, True):
                with self.subTest(kind=kind, encrypted=encrypted):
                    key = script_common.parse_private_key(private_text(kind, encrypted=encrypted),
                                                          PASSPHRASE if encrypted else "")
                    self.assertTrue(key.can_sign())

    def test_traditional_pem_and_pkcs8_are_parsed_without_disk_io(self):
        for kind in KEYS:
            formats = [serialization.PrivateFormat.PKCS8]
            if kind != "ed25519":
                formats.append(serialization.PrivateFormat.TraditionalOpenSSL)
            for fmt in formats:
                for encrypted in (False, True):
                    with self.subTest(kind=kind, fmt=fmt, encrypted=encrypted):
                        text = private_text(kind, fmt, encrypted)
                        with patch("builtins.open", side_effect=AssertionError("private key disk I/O")):
                            key = script_common.parse_private_key(text, PASSPHRASE if encrypted else "")
                        self.assertTrue(key.can_sign())

    def test_wrong_missing_passphrase_and_unknown_algorithm_use_fixed_nonsecret_errors(self):
        text = private_text(encrypted=True)
        expected = "私钥格式、算法或口令无效；请使用 RSA、Ed25519 或 ECDSA 的完整私钥文本"
        for phrase in ("", "FAKE-wrong-only"):
            with self.assertRaises(ValueError) as error:
                script_common.parse_private_key(text, phrase)
            self.assertEqual(str(error.exception), expected)
            self.assertNotIn(phrase or "BEGIN", str(error.exception))
        unsupported = x25519.X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        with self.assertRaisesRegex(ValueError, "私钥格式、算法或口令无效"):
            script_common.parse_private_key(unsupported)

    def test_each_explicit_connection_mode_disables_implicit_key_discovery(self):
        for mode in local_security.SSH_AUTH_TYPES:
            with tempfile.TemporaryDirectory() as directory:
                client = Mock()
                client._system_host_keys = paramiko.HostKeys()
                client.get_host_keys.return_value = paramiko.HostKeys()
                arguments = {"password": "FAKE-password-only"} if mode == "password" else (
                    {"private_key": private_text(encrypted=True), "key_passphrase": PASSPHRASE} if mode == "private_key" else {})
                with patch("script_common.paramiko.SSHClient", return_value=client):
                    result = script_common.connect_ssh("example.invalid", auth_type=mode,
                        known_hosts_path=Path(directory) / "known_hosts", **arguments)
                self.assertIs(result, client)
                kw = client.connect.call_args.kwargs
                self.assertEqual(kw["allow_agent"], mode == "agent")
                self.assertFalse(kw["look_for_keys"])
                self.assertNotIn("key_filename", kw)
                self.assertEqual(kw["password"], "FAKE-password-only" if mode == "password" else None)
                self.assertEqual(kw["pkey"] is not None, mode == "private_key")
                self.assertNotIn("key_passphrase", kw)

    def test_invalid_key_never_constructs_client_or_creates_known_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "known_hosts"
            with patch("script_common.paramiko.SSHClient") as client, self.assertRaises(ValueError):
                script_common.connect_ssh("example.invalid", auth_type="private_key",
                    private_key="-----BEGIN OPENSSH PRIVATE KEY-----\ninvalid\n-----END OPENSSH PRIVATE KEY-----", known_hosts_path=path)
            client.assert_not_called()
            self.assertFalse(path.exists())

    def test_authentication_failure_is_sanitized_and_client_is_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client._system_host_keys = paramiko.HostKeys()
            client.get_host_keys.return_value = paramiko.HostKeys()
            client.connect.side_effect = paramiko.AuthenticationException("FAKE-secret-must-not-echo")
            with patch("script_common.paramiko.SSHClient", return_value=client), self.assertRaises(ValueError) as error:
                script_common.connect_ssh("example.invalid", password="FAKE-password-only",
                                         known_hosts_path=Path(directory) / "known_hosts")
            self.assertNotIn("FAKE-secret", str(error.exception))
            client.close.assert_called_once()

class AuthApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="auth-api-")
        base = Path(self.directory.name)
        self.paths = [patch.object(manager, "SERVERS_FILE", str(base / "servers.json")),
                      patch.object(manager, "SETTINGS_FILE", str(base / "settings.json")),
                      patch.object(manager, "KNOWN_HOSTS_FILE", str(base / "known_hosts"))]
        for item in self.paths:
            item.start()
        manager.jobs.clear()
        manager._ACCEPTING_JOBS = True
        manager._SHUTTING_DOWN = False
        manager.app.config["TESTING"] = True
        self.client = manager.app.test_client()
    def tearDown(self):
        manager.jobs.clear()
        for item in reversed(self.paths):
            item.stop()
        self.directory.cleanup()
    def request(self, method, path, **kwargs):
        return self.client.open(path, method=method, base_url="http://127.0.0.1:8620",
                                headers={"X-CSRF-Token": manager.CSRF_TOKEN}, **kwargs)
    def add(self, **auth):
        response = self.request("POST", "/api/servers", json={"host": "example.invalid", "user": "root", **auth})
        self.assertEqual(response.status_code, 200, response.json)
        return response.json["id"]

    def test_add_and_list_only_safe_fields_no_key_passphrase_or_unknown_metadata(self):
        key_text = private_text(encrypted=True)
        sid = self.add(auth_type="private_key", private_key=key_text, key_passphrase=PASSPHRASE)
        raw = Path(manager.SERVERS_FILE).read_text(encoding="utf-8")
        self.assertNotIn("BEGIN", raw)
        self.assertNotIn(PASSPHRASE, raw)
        listed = self.request("GET", "/api/servers").json[0]
        self.assertEqual(set(listed), {"id", "name", "host", "port", "user", "auth_type", "credential_required"})
        self.assertEqual(listed["auth_type"], "private_key")
        self.assertFalse(listed["credential_required"])
        self.assertEqual(manager.get_server(sid)["private_key"], key_text)

    def test_edit_keeps_empty_secrets_and_mode_change_removes_old_secrets(self):
        sid = self.add(auth_type="private_key", private_key=private_text(encrypted=True), key_passphrase=PASSPHRASE)
        old = manager.get_server(sid)
        result = self.request("PUT", f"/api/servers/{sid}", json={"name": "Renamed", "private_key": "", "key_passphrase": ""})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(manager.get_server(sid)["private_key"], old["private_key"])
        self.assertEqual(manager.get_server(sid)["key_passphrase"], PASSPHRASE)
        result = self.request("PUT", f"/api/servers/{sid}", json={"auth_type": "agent"})
        self.assertEqual(result.status_code, 200)
        stored = manager.get_server(sid)
        self.assertEqual(stored["auth_type"], "agent")
        self.assertFalse(any(field in stored for field in local_security.SSH_SECRET_FIELDS))

    def test_metadata_missing_credentials_requires_edit_before_connect(self):
        server = {"id": "imported", "host": "example.invalid", "port": 22, "user": "root", "name": "Imported",
                  **local_security.validate_auth({"auth_type": "password"}, allow_missing=True)}
        manager.save_json(manager.SERVERS_FILE, [server])
        self.assertTrue(self.request("GET", "/api/servers").json[0]["credential_required"])
        with patch.object(manager, "connect_ssh") as connect, self.assertRaisesRegex(ValueError, "先编辑服务器"):
            manager.connect(server)
        connect.assert_not_called()
        self.assertEqual(self.request("PUT", "/api/servers/imported", json={"name": "Still missing"}).status_code, 400)
        self.assertEqual(self.request("PUT", "/api/servers/imported", json={"password": "FAKE-new-only"}).status_code, 200)
        self.assertFalse(self.request("GET", "/api/servers").json[0]["credential_required"])

    def test_edit_blocks_running_tasks_revokes_tunnels_exports_and_preserves_host_trust(self):
        sid = self.add(password="FAKE-only")
        manager.jobs["busy"] = {"status": "running", "server_ids": [sid]}
        old = Path(manager.SERVERS_FILE).read_bytes()
        self.assertEqual(self.request("PUT", f"/api/servers/{sid}", json={"host": "new.invalid"}).status_code, 409)
        self.assertEqual(Path(manager.SERVERS_FILE).read_bytes(), old)
        manager.jobs.clear()
        Path(manager.KNOWN_HOSTS_FILE).write_text("FAKE-preserved-host-trust", encoding="utf-8")
        with patch.object(manager, "stop_forwarders") as stop, patch.object(manager.CLASH_EXPORTS, "revoke_scope") as revoke:
            self.assertEqual(self.request("PUT", f"/api/servers/{sid}", json={"host": "new.invalid"}).status_code, 200)
        stop.assert_called_once_with(sid)
        self.assertEqual(revoke.call_count, 2)
        self.assertEqual(Path(manager.KNOWN_HOSTS_FILE).read_text(), "FAKE-preserved-host-trust")

    def test_private_key_and_agent_manual_targets_and_common_connection_are_explicit(self):
        for mode in ("private_key", "agent"):
            credentials = {"auth_type": mode, **({"private_key": private_text(), "key_passphrase": ""} if mode == "private_key" else {})}
            srv = manager._resolve_server({"server": {"host": "example.invalid", "user": "root", "port": 2222, **credentials}}, "server")
            self.assertIsNotNone(srv)
            self.assertEqual(srv["auth_type"], mode)
            ssh = Mock()
            with patch.object(manager, "connect_ssh", return_value=ssh) as connect:
                self.assertIs(manager.connect(srv), ssh)
            self.assertEqual(connect.call_args.kwargs["auth_type"], mode)
            self.assertFalse(connect.call_args.kwargs["trust_new_host"])
            self.assertEqual(connect.call_args.kwargs["password"], "")

    def test_terminal_and_sftp_share_private_key_connection_without_exposing_secret(self):
        sid = self.add(auth_type="private_key", private_key=private_text())
        ssh, ws = Mock(), Mock()
        ssh.invoke_shell.return_value.recv.return_value = b""
        ws.receive.return_value = None
        with patch.object(manager, "connect_ssh", return_value=ssh) as connect, patch.object(manager.threading, "Thread", ImmediateThread):
            manager.app.view_functions["terminal"].__wrapped__(ws, sid)
        self.assertEqual(connect.call_args.kwargs["auth_type"], "private_key")
        ssh.close.assert_called()
        self.assertFalse(any("BEGIN" in str(call) for call in ws.send.call_args_list))
        with patch.object(manager, "connect_ssh", return_value=ssh) as connect:
            result = manager._sftp(sid)
        self.assertEqual(connect.call_args.kwargs["auth_type"], "private_key")
        self.assertIs(result[0], ssh)
        result[1].get_channel.return_value.settimeout.assert_called_with(60)

    def test_wrong_private_key_passphrase_returns_fixed_error_without_echoing_it(self):
        response = self.request("POST", "/api/servers", json={"host": "example.invalid", "auth_type": "private_key",
                                  "private_key": private_text(encrypted=True), "key_passphrase": "FAKE-wrong-secret-only"})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("FAKE-wrong-secret", response.get_data(as_text=True))
        self.assertNotIn("BEGIN", response.get_data(as_text=True))

    def test_rdp_does_not_reuse_agent_or_private_key_as_a_password(self):
        sid = self.add(auth_type="agent")
        with patch.object(manager.subprocess, "run") as run:
            result = self.request("POST", f"/api/servers/{sid}/rdp")
        self.assertEqual(result.status_code, 400)
        self.assertIn("RDP", result.json["msg"])
        run.assert_not_called()

class CapabilityTests(unittest.TestCase):
    setUp = AuthApiTests.setUp
    tearDown = AuthApiTests.tearDown
    request = AuthApiTests.request
    add = AuthApiTests.add
    def inspect(self, **changes):
        with patch.object(manager, "run_checked", return_value=capability_text(**changes)) as run:
            result = manager.inspect_capabilities(Mock())
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["timeout"], 20)
        return result

    def test_readonly_probe_detects_os_arch_permission_and_never_sources_release_file(self):
        c = self.inspect()
        self.assertEqual((c["distro"], c["arch"], c["uid"]), ("ubuntu", "x86_64", 0))
        self.assertTrue(c["has_apt"])
        self.assertFalse(c["network_verified"])
        self.assertTrue(c["tools"]["check_env"]["available"])
        self.assertNotIn(". /etc/os-release", manager.CAPABILITY_PROBE)
        self.assertNotIn("apt-get install", manager.CAPABILITY_PROBE)
        self.assertNotIn("modprobe", manager.CAPABILITY_PROBE)

    def test_nonroot_sudo_does_not_implicitly_enable_system_installation(self):
        c = self.inspect(uid="1000", user="ecs-user", sudo="1")
        self.assertTrue(c["has_sudo"])
        self.assertTrue(c["tools"]["check_env"]["available"])
        self.assertTrue(all(not state["available"] for action, state in c["tools"].items() if action != "check_env"))

    def test_alibaba_linux_management_allowed_but_apt_install_requires_existing_node(self):
        changes = {"os_ID": "alinux", "os_ID_LIKE": "rhel fedora", "cmd_apt-get": "0", "cmd_dpkg": "0",
                   "package_arch": "", "node_version": "", "cmd_npm": "0"}
        c = self.inspect(**changes)
        self.assertTrue(c["tools"]["check_env"]["available"])
        self.assertFalse(c["tools"]["install_node"]["available"])
        self.assertIn("Debian/Ubuntu", c["tools"]["install_dsh"]["reason"])
        ready = self.inspect(**{**changes, "node_version": "v24.1.0", "cmd_npm": "1"})
        self.assertTrue(ready["tools"]["install_node"]["available"])
        self.assertTrue(ready["tools"]["install_dsh"]["available"])
        self.assertFalse(ready["tools"]["install_node"]["requires_network"])

    def test_systemctl_presence_without_running_systemd_and_arm_desktop_are_blocked(self):
        c = self.inspect(systemd="0")
        self.assertTrue(c["commands"]["systemctl"])
        self.assertFalse(c["tools"]["install_xray"]["available"])
        self.assertFalse(c["tools"]["install_desktop"]["available"])
        arm = self.inspect(arch="aarch64", package_arch="arm64")
        self.assertTrue(arm["tools"]["install_node"]["available"])
        self.assertFalse(arm["tools"]["install_desktop"]["available"])

    def test_bbr_unknown_kernel_or_readonly_sysctl_blocks_only_the_tuning_action(self):
        c = self.inspect(bbr_algorithms="reno cubic", bbr_module="0", sysctl_writable="0")
        self.assertFalse(c["tools"]["enable_bbr"]["available"])
        self.assertTrue(c["tools"]["check_env"]["available"])
        not_linux = self.inspect(kernel="Darwin")
        self.assertTrue(all(not result["available"] for result in not_linux["tools"].values()))

    def test_sufficient_node_without_npm_is_blocked_instead_of_downgraded(self):
        c = self.inspect(node_version="v24.0.0", cmd_npm="0")
        self.assertFalse(c["tools"]["install_node"]["available"])
        self.assertIn("不会自动降级", c["tools"]["install_node"]["reason"])
        self.assertIn("需要 Node >=22.12.0", manager._node())

    def test_capabilities_route_and_worker_enforce_fresh_checks_before_mutation(self):
        sid = self.add(password="FAKE-only")
        ssh = Mock()
        incompatible = capability_text(os_ID="alinux", os_ID_LIKE="rhel", node_version="",
                                       **{"cmd_apt-get": "0", "cmd_dpkg": "0", "cmd_npm": "0"})
        with patch.object(manager, "connect", return_value=ssh), patch.object(manager, "run_checked", return_value=incompatible):
            response = self.request("GET", f"/api/servers/{sid}/capabilities")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["tools"]["install_node"]["available"])
        ssh.close.assert_called()
        with patch.object(manager, "connect", return_value=ssh), patch.object(manager.threading, "Thread", ImmediateThread), \
             patch.object(manager, "run_checked", return_value=incompatible) as checked:
            result = self.request("POST", f"/api/servers/{sid}/run", json={"action": "install_node"})
        self.assertEqual(result.status_code, 200)
        job = manager.jobs[result.json["job"]]
        self.assertEqual(job["status"], "error")
        self.assertIn("Debian/Ubuntu", job["output"])
        self.assertEqual(checked.call_count, 1)
        self.assertEqual(checked.call_args.args[1], manager.CAPABILITY_PROBE)

    def test_nodes_and_service_mutation_require_permissions_and_desktop_keeps_swap_and_sandbox(self):
        with patch.object(manager, "run_checked", return_value=capability_text(uid="1000")), \
             patch.object(manager, "apply_xray_config") as apply, self.assertRaises(ValueError):
            manager._apply_xray_cfg(Mock(), {"inbounds": []})
        apply.assert_not_called()
        with patch.object(manager, "run_checked", return_value=capability_text(kernel="Darwin")) as checked, self.assertRaises(ValueError):
            manager._ensure_xray(Mock(), "fake-job")
        self.assertEqual(checked.call_count, 1)
        desktop = manager._desktop()
        self.assertIn("[ -e /swapfile ] || [ -L /swapfile ]", desktop)
        self.assertIn("set -o noclobber", desktop)
        self.assertIn("已有未启用的 swap 配置", desktop)
        self.assertNotIn("--no-sandbox", desktop)
        self.assertNotIn("sed -i", desktop)
        self.assertIn("普通用户", desktop)

    def test_pinned_node_targets_changed_before_worker_are_rejected_before_ssh(self):
        entry_id = self.add(password="FAKE-entry-only")
        exit_id = self.add(password="FAKE-exit-only")
        entry = manager._resolve_server({"target": entry_id}, "target")
        exit_target = manager._resolve_server({"target": exit_id}, "target")
        manager._require_current_target(entry)
        self.assertEqual(self.request("PUT", f"/api/servers/{entry_id}", json={"host": "changed.invalid"}).status_code, 200)
        with patch.object(manager, "connect") as connect:
            with self.assertRaisesRegex(ValueError, "信息已改变"):
                manager._deploy_direct("fake", {"server_id": entry})
            with self.assertRaisesRegex(ValueError, "信息已改变"):
                manager._deploy_relay("fake", {"entry_id": entry, "exit_id": exit_target,
                                               "entry_port": 600, "exit_port": 700})
        connect.assert_not_called()

if __name__ == "__main__":
    unittest.main()
