"""Offline regression tests: no credentials read and no real SSH/deployment."""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import paramiko
import deploy_xray
import fix_xrdp
import install_desktop
import install_dsh
import launch_manager
import script_common
import tune_xray

ENV = {"SSH_HOST": "example.invalid", "SSHPASS": "dummy-only", "SSH_USER": "admin", "SSH_PORT": "2222"}
LIVE = {
    "log": {"loglevel": "info", "access": "/tmp/xray-access.log"},
    "inbounds": [{"tag": "old", "port": 5555, "protocol": "vless",
                  "settings": {"clients": [{"id": "old-id", "email": "keep"}]},
                  "streamSettings": {"network": "ws", "security": "tls",
                                     "tlsSettings": {"certificates": [{"certificateFile": "/keep.pem"}]},
                                     "sockopt": {"mark": 17, "tcpNoDelay": False}}}],
    "outbounds": [{"tag": "proxy", "protocol": "socks",
                   "settings": {"servers": [{"address": "127.0.0.1", "port": 1080}]},
                   "streamSettings": {"sockopt": {"dialerProxy": "upstream"}}},
                  {"tag": "deny", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}],
    "routing": {"rules": [{"type": "field", "inboundTag": ["old"], "outboundTag": "proxy"}]},
    "dns": {"servers": ["1.1.1.1"]},
    "custom-extension": {"keep": True},
}


@contextmanager
def fake_connection(client):
    try:
        yield client
    finally:
        client.close()


class ImportAndEnvironmentTests(unittest.TestCase):
    def test_importing_tools_needs_no_environment_and_starts_no_ssh(self):
        with patch.dict(os.environ, {}, clear=True), patch("paramiko.SSHClient") as client:
            for name in ("deploy_xray", "tune_xray", "install_desktop", "install_dsh", "fix_xrdp", "launch_manager"):
                spec = importlib.util.spec_from_file_location("offline_" + name, ROOT / (name + ".py"))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
        client.assert_not_called()

    def test_ssh_user_and_port_are_supported(self):
        options = script_common.ssh_options(ENV)
        self.assertEqual((options.user, options.port), ("admin", 2222))

    def test_invalid_ssh_port_and_missing_password_fail_before_connect(self):
        for env in ({**ENV, "SSH_PORT": "65536"}, {**ENV, "SSH_PORT": "oops"},
                    {**ENV, "SSH_PORT": "022"}, {**ENV, "SSHPASS": ""},
                    {**ENV, "SSH_HOST": "host;echo injected"}, {**ENV, "SSH_USER": "root;echo injected"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                script_common.ssh_options(env)

    def test_failed_connection_is_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client._system_host_keys = paramiko.HostKeys()
            client.get_host_keys.return_value = paramiko.HostKeys()
            client.connect.side_effect = RuntimeError("offline handshake failure")
            with patch("script_common.paramiko.SSHClient", return_value=client):
                with self.assertRaises(RuntimeError):
                    script_common.connect_ssh("example.invalid", port=2222, user="admin", password="dummy",
                                               known_hosts_path=Path(directory) / "known_hosts")
            client.close.assert_called_once()
            self.assertEqual(client.connect.call_args.kwargs["port"], 2222)
            self.assertEqual(client.connect.call_args.kwargs["username"], "admin")
            client.load_host_keys.assert_called_once()

    def test_first_key_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "known_hosts"
            path.touch()
            client = paramiko.SSHClient()
            client.load_host_keys(str(path))
            key = paramiko.RSAKey.generate(1024)
            with patch("sys.stdout", new=io.StringIO()):
                script_common._PersistFirstHostKey().missing_host_key(client, "[example.invalid]:2222", key)
            saved = paramiko.HostKeys(str(path))
            self.assertEqual(saved["[example.invalid]:2222"]["ssh-rsa"], key)
            client.close()

    def test_changed_known_key_is_not_reenrolled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "known_hosts"
            old_key, new_key = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
            keys = paramiko.HostKeys()
            keys.add("example.invalid", old_key.get_name(), old_key)
            keys.save(str(path))
            before = path.read_bytes()
            real_client = paramiko.SSHClient()
            def reject_changed(*args, **kwargs):
                self.assertEqual(real_client.get_host_keys()["example.invalid"]["ssh-rsa"], old_key)
                raise paramiko.BadHostKeyException("example.invalid", new_key, old_key)
            with patch("script_common.paramiko.SSHClient", return_value=real_client), \
                    patch.object(real_client, "load_system_host_keys"), \
                    patch.object(real_client, "connect", side_effect=reject_changed), \
                    patch.object(real_client, "close") as close:
                with self.assertRaises(paramiko.BadHostKeyException):
                    script_common.connect_ssh("example.invalid", password="dummy", known_hosts_path=path)
                close.assert_called_once()
            self.assertEqual(path.read_bytes(), before)

    def test_remote_failure_is_propagated_and_pipeline_failures_are_checked(self):
        with patch("script_common.run_checked", side_effect=RuntimeError("exit 4")) as checked:
            with self.assertRaisesRegex(RuntimeError, "exit 4"):
                script_common.run(Mock(), "false | tail -1")
        self.assertIn("bash -e -o pipefail -c", checked.call_args.args[1])

    def test_sudo_connection_wraps_command_safely(self):
        client = Mock()
        with patch("script_common.run_checked", side_effect=["1000", ""]):
            elevated = script_common.elevated_ssh(client)
        elevated.exec_command("printf '%s' \"a'b\"", timeout=5)
        command = client.exec_command.call_args.args[0]
        self.assertEqual(shlex.split(command)[:4], ["sudo", "-n", "bash", "-c"])
        self.assertEqual(shlex.split(command)[4], "printf '%s' \"a'b\"")


class XrayScriptTests(unittest.TestCase):
    def test_tuning_preserves_live_fields_clients_routing_and_custom_sockopt(self):
        before = deepcopy(LIVE)
        cfg = tune_xray.tuned_config(LIVE)
        self.assertEqual(LIVE, before)
        for field in ("log", "routing", "dns", "custom-extension"):
            self.assertEqual(cfg[field], LIVE[field])
        self.assertEqual(cfg["inbounds"][0]["settings"], LIVE["inbounds"][0]["settings"])
        stream = cfg["inbounds"][0]["streamSettings"]
        self.assertEqual(stream["tlsSettings"], LIVE["inbounds"][0]["streamSettings"]["tlsSettings"])
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["sockopt"]["mark"], 17)
        self.assertTrue(stream["sockopt"]["tcpNoDelay"])
        self.assertEqual(cfg["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"], "upstream")
        self.assertEqual(cfg["outbounds"][1], LIVE["outbounds"][1])

    def test_tuning_rejects_missing_and_malformed_config(self):
        for cfg in ({}, {"inbounds": None}, {"inbounds": [{"streamSettings": "invalid"}]}):
            with self.subTest(cfg=cfg), self.assertRaises(ValueError):
                tune_xray.tuned_config(cfg)

    def test_deployment_is_incremental(self):
        before = deepcopy(LIVE)
        cfg = deploy_xray.append_inbounds(LIVE, [8443], "www.example.com", "new-id", "new-private", "deadbeef")
        self.assertEqual(LIVE, before)
        self.assertEqual(cfg["inbounds"][0], LIVE["inbounds"][0])
        self.assertEqual(cfg["outbounds"], LIVE["outbounds"])
        self.assertEqual(cfg["routing"], LIVE["routing"])
        self.assertEqual(cfg["inbounds"][1]["port"], 8443)

    def test_deployment_rejects_existing_ports_and_duplicate_tags(self):
        for live in (LIVE, {"inbounds": [{"port": "5555"}]}, {"inbounds": [{"port": 6666, "tag": "vless-reality-5555"}]}):
            with self.subTest(live=live), self.assertRaises(ValueError):
                deploy_xray.append_inbounds(live, [5555], "www.example.com", "u", "p", "s")

    def test_ports_validate_ranges_duplicates_and_empty_fields(self):
        self.assertEqual(deploy_xray.parse_ports("443, 8443"), [443, 8443])
        for value in ("", "0", "65536", "abc", "0443", "+443", "443,443", "443,", ",443", "443;echo bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                deploy_xray.parse_ports(value)

    def test_sni_rejects_shell_payload(self):
        self.assertEqual(deploy_xray.validate_sni("www.example.com"), "www.example.com")
        for value in ("example.com;echo bad", "-bad.example.com", "localhost", "a..com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                deploy_xray.validate_sni(value)

    def test_tune_failure_closes_connection_and_never_reports_completion(self):
        client = Mock()
        output = io.StringIO()
        with patch("tune_xray.ssh_connection", side_effect=lambda _: fake_connection(client)), \
                patch("tune_xray.elevated_ssh", return_value=client), \
                patch("tune_xray.read_xray_config", return_value=deepcopy(LIVE)), \
                patch("tune_xray.run"), \
                patch("tune_xray.apply_xray_config", side_effect=RuntimeError("rolled back")), \
                patch("sys.stdout", new=output):
            with self.assertRaisesRegex(RuntimeError, "rolled back"):
                tune_xray.main(ENV)
        client.close.assert_called_once()
        self.assertNotIn("tuning done", output.getvalue())

    def test_deploy_failure_does_not_write_result_and_closes_connection(self):
        client = Mock()
        with patch("deploy_xray.ssh_connection", side_effect=lambda _: fake_connection(client)), \
                patch("deploy_xray.elevated_ssh", return_value=client), \
                patch("deploy_xray.read_xray_config", return_value=deepcopy(LIVE)), \
                patch("deploy_xray.listening_ports", return_value=set()), \
                patch("deploy_xray.reality_keys", return_value=("private", "public")), \
                patch("deploy_xray.run"), \
                patch("deploy_xray.write_json") as write, \
                patch("deploy_xray.apply_xray_config", side_effect=RuntimeError("validation failure")):
            with self.assertRaisesRegex(RuntimeError, "validation failure"):
                deploy_xray.main({**ENV, "XRAY_PORTS": "8443"})
        write.assert_not_called()
        client.close.assert_called_once()

    def test_deploy_keeps_per_host_result_file_convention(self):
        client = Mock()
        with patch("deploy_xray.ssh_connection", side_effect=lambda _: fake_connection(client)), \
                patch("deploy_xray.elevated_ssh", return_value=client), \
                patch("deploy_xray.read_xray_config", return_value=deepcopy(LIVE)), \
                patch("deploy_xray.listening_ports", return_value=set()), \
                patch("deploy_xray.reality_keys", return_value=("private", "public")), \
                patch("deploy_xray.run"), patch("sys.stdout", new=io.StringIO()), \
                patch("deploy_xray.write_json") as write, \
                patch("deploy_xray.apply_xray_config") as apply:
            deploy_xray.main({**ENV, "XRAY_PORTS": "8443"})
        self.assertEqual(write.call_args_list[1].args[0].name, "xray_result_example_invalid.json")
        self.assertEqual(write.call_args_list[1].args[1]["ports"], [8443])
        self.assertEqual(apply.call_args.kwargs["expected"], LIVE)


class DesktopAndDshTests(unittest.TestCase):
    def test_root_browser_shortcuts_allow_root_startup_only(self):
        root = install_desktop.root_browser_launchers("/root", "root")
        self.assertIn("--no-sandbox", root)
        self.assertIn("/root/.local/share/applications", root)
        self.assertIn("/root/Desktop", root)
        self.assertEqual(install_desktop.root_browser_launchers("/home/admin", "admin"), "")

    def test_remote_shell_scripts_parse_without_executing_them(self):
        bash = shutil.which("bash")
        if os.name == "nt":
            candidate = Path("C:/Program Files/Git/bin/bash.exe")
            bash = str(candidate) if candidate.is_file() else None
        if not bash:
            self.skipTest("No local bash available for syntax-only verification")
        commands = [install_desktop.root_browser_launchers("/root", "root")]
        client = Mock()
        for module in (deploy_xray, tune_xray, install_desktop, install_dsh, fix_xrdp):
            with patch.object(module, "ssh_connection", side_effect=lambda _: fake_connection(client)), \
                    patch.object(module, "elevated_ssh", return_value=client), \
                    patch.object(module, "run", side_effect=lambda ssh, command, **kw: commands.append(command)), \
                    patch("sys.stdout", new=io.StringIO()):
                if module in (deploy_xray, tune_xray):
                    with patch.object(module, "read_xray_config", return_value=deepcopy(LIVE)), \
                            patch.object(module, "apply_xray_config"):
                        if module is deploy_xray:
                            with patch.object(module, "listening_ports", return_value=set()), \
                                    patch.object(module, "reality_keys", return_value=("private", "public")), \
                                    patch.object(module, "write_json"):
                                module.main({**ENV, "XRAY_PORTS": "8443"})
                        else:
                            module.main(ENV)
                elif module is install_desktop:
                    with patch.object(module, "require_amd64_debian"), \
                            patch.object(module, "user_home", return_value="/home/test user"), \
                            patch.object(module, "listening_ports", return_value={3389}):
                        module.main(ENV)
                elif module is install_dsh:
                    with patch.object(module, "user_home", return_value="/home/test user"):
                        module.main({**ENV, "DEEPSEEK_API_KEY": "a'b; $(touch /tmp/nope)"})
                else:
                    with patch.object(module, "user_home", return_value="/home/test user"), \
                            patch.object(module, "listening_ports", return_value={3389}):
                        module.main(ENV)
        self.assertGreater(len(commands), 15)
        for command in commands:
            with self.subTest(script=command.splitlines()[0]):
                check = subprocess.run([bash, "-n"], input=command, text=True, encoding="utf-8",
                                       capture_output=True, timeout=5)
                self.assertEqual(check.returncode, 0, check.stderr)

    def test_arm_desktop_is_rejected_before_modification(self):
        client = Mock()
        with patch("install_desktop.ssh_connection", side_effect=lambda _: fake_connection(client)), \
                patch("install_desktop.elevated_ssh", return_value=client), \
                patch("install_desktop.run_checked", side_effect=["Linux", "aarch64"]), \
                patch("install_desktop.run") as run:
            with self.assertRaisesRegex(RuntimeError, "amd64"):
                install_desktop.main(ENV)
        run.assert_not_called()
        client.close.assert_called_once()

    def test_api_key_shell_quoting_keeps_payload_literal(self):
        key = "a'b; $(touch /tmp/nope) \"quoted\""
        command = install_dsh.credentials_script("/home/test user", "admin", key)
        printf = next(line for line in command.splitlines() if line.startswith("printf"))
        tokens = shlex.split(printf)
        assignment = tokens[2]
        self.assertEqual(shlex.split(assignment), ["export", "DEEPSEEK_API_KEY=" + key])
        self.assertIn("chmod 600 '/home/test user/.dsh-env'", command)

    def test_dsh_failure_closes_connection_and_does_not_report_done(self):
        client = Mock()
        output = io.StringIO()
        with patch("install_dsh.ssh_connection", side_effect=lambda _: fake_connection(client)), \
                patch("install_dsh.elevated_ssh", return_value=client), \
                patch("install_dsh.run", side_effect=RuntimeError("apt failed")), \
                patch("sys.stdout", new=output):
            with self.assertRaisesRegex(RuntimeError, "apt failed"):
                install_dsh.main(ENV)
        client.close.assert_called_once()
        self.assertNotIn(">>> done", output.getvalue())

    def test_xrdp_failure_on_one_host_continues_and_returns_failure(self):
        clients = [Mock(), Mock()]
        with patch("fix_xrdp.ssh_connection", side_effect=[fake_connection(clients[0]), fake_connection(clients[1])]), \
                patch("fix_xrdp.elevated_ssh", side_effect=lambda c: c), \
                patch("fix_xrdp.user_home", return_value="/home/admin"), \
                patch("fix_xrdp.run", side_effect=RuntimeError("compositor failed")), \
                patch("sys.stdout", new=io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "部分服务器修复失败"):
                fix_xrdp.main({**ENV, "SSH_HOSTS": "one.invalid,two.invalid"})
        for client in clients:
            client.close.assert_called_once()


class LauncherTests(unittest.TestCase):
    def test_health_identity_requires_this_project(self):
        self.assertTrue(launch_manager.health_matches({"app": "server-manager", "project_root": str(ROOT)}))
        self.assertFalse(launch_manager.health_matches({"app": "server-manager", "project_root": str(ROOT.parent)}))
        self.assertFalse(launch_manager.health_matches({"app": "other", "project_root": str(ROOT)}))

    def test_existing_project_is_opened_without_starting_new_process(self):
        with patch("launch_manager.launch_lock", return_value=nullcontext()), \
                patch("launch_manager.read_health", return_value={"app": "server-manager", "project_root": str(ROOT)}), \
                patch("launch_manager.subprocess.Popen") as start, \
                patch("launch_manager.webbrowser.open") as browser, patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(launch_manager.main(), 0)
        start.assert_not_called()
        browser.assert_called_once_with(launch_manager.PANEL_URL)

    def test_foreign_port_owner_is_never_started_or_terminated(self):
        with patch("launch_manager.launch_lock", return_value=nullcontext()), \
                patch("launch_manager.read_health", return_value={"app": "server-manager", "project_root": str(ROOT.parent)}), \
                patch("launch_manager.port_available", return_value=False), \
                patch("launch_manager.subprocess.Popen") as start, \
                patch("launch_manager.webbrowser.open") as browser:
            with self.assertRaisesRegex(RuntimeError, "端口 8620"):
                launch_manager.main()
        start.assert_not_called()
        browser.assert_not_called()

    def test_new_process_is_hidden_and_browser_opens_after_health(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server-manager").mkdir()
            (root / "server-manager" / "app.py").touch()
            (root / "work").mkdir()
            child = Mock()
            child.poll.return_value = None
            health = {"app": "server-manager", "project_root": str(root)}
            with patch("launch_manager.PROJECT_ROOT", root), \
                    patch("launch_manager.launch_lock", return_value=nullcontext()), \
                    patch("launch_manager.read_health", side_effect=[None, health]), \
                    patch("launch_manager.port_available", return_value=True), \
                    patch("launch_manager.subprocess.Popen", return_value=child) as start, \
                    patch("launch_manager.webbrowser.open") as browser, patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(launch_manager.main(), 0)
            self.assertEqual(start.call_args.kwargs["env"]["SERVER_MANAGER_NO_BROWSER"], "1")
            if os.name == "nt":
                self.assertEqual(start.call_args.kwargs["creationflags"], launch_manager.subprocess.CREATE_NO_WINDOW)
            child.terminate.assert_not_called()
            browser.assert_called_once()

    def test_failed_start_stops_only_the_process_it_created(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server-manager").mkdir()
            (root / "server-manager" / "app.py").touch()
            (root / "work").mkdir()
            child = Mock()
            child.poll.return_value = None
            with patch("launch_manager.PROJECT_ROOT", root), \
                    patch("launch_manager.launch_lock", return_value=nullcontext()), \
                    patch("launch_manager.read_health", return_value=None), \
                    patch("launch_manager.port_available", return_value=True), \
                    patch("launch_manager.subprocess.Popen", return_value=child), \
                    patch("launch_manager.time.monotonic", side_effect=[0, 16]):
                with self.assertRaisesRegex(RuntimeError, "健康响应"):
                    launch_manager.main()
            child.terminate.assert_called_once()
            child.wait.assert_called_once()

    def test_batch_files_use_safe_launcher_and_never_kill_port_owners(self):
        for name in ("启动-服务器管家.bat", "一键安装.bat"):
            content = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("launch_manager.py", content)
            self.assertNotIn("taskkill", content.lower())
            self.assertNotIn("netstat -ano", content.lower())


if __name__ == "__main__":
    unittest.main()
