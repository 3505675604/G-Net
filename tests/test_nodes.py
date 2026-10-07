import copy
import base64
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch


APP_PATH = Path(__file__).resolve().parents[1] / "server-manager" / "app.py"
spec = importlib.util.spec_from_file_location("nodes_test_app", APP_PATH)
panel = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = panel
spec.loader.exec_module(panel)


class FakeSSH:
    def __init__(self, host, cfg):
        self.host, self.cfg, self.closed = host, copy.deepcopy(cfg), False

    def close(self):
        self.closed = True


class NodeTests(unittest.TestCase):
    def setUp(self):
        self.servers = {
            "entry": {"id": "entry", "host": "entry.example.com", "name": "Entry", "port": 22,
                      "user": "root", "password": "test-only"},
            "exit": {"id": "exit", "host": "exit.example.com", "name": "Exit", "port": 22,
                     "user": "root", "password": "test-only"},
        }
        self.original = {"inbounds": [{"tag": "old", "port": 9000, "protocol": "vless"}],
                         "outbounds": [{"protocol": "freedom", "tag": "custom"}],
                         "routing": {"rules": [{"outboundTag": "custom"}]}}
        self.connections = {s["host"]: FakeSSH(s["host"], self.original) for s in self.servers.values()}
        self.applies = []
        self.client = panel.app.test_client()
        panel.jobs.clear()
        panel.jobs["test"] = {"status": "running", "output": ""}
        for name, replacement in (
            ("get_server", lambda sid: self.servers.get(sid)),
            ("load_json", lambda path, default: list(self.servers.values())),
            ("connect", lambda srv, timeout=15: self.connections[srv["host"]]),
            ("_ensure_xray", lambda ssh, jid: None),
            ("_read_xray_cfg", lambda ssh: copy.deepcopy(ssh.cfg)),
            ("_used_ports", lambda ssh, cfg: [x["port"] for x in cfg.get("inbounds", [])]),
            ("_apply_xray_cfg", self.apply),
            ("run_checked", lambda ssh, command, timeout=180: "OK\n"),
        ):
            mock = patch.object(panel, name, side_effect=replacement)
            mock.start()
            self.addCleanup(mock.stop)

    def apply(self, ssh, cfg, expected=None):
        self.assertEqual(expected, ssh.cfg, "every update must compare its original snapshot")
        self.applies.append((ssh.host, copy.deepcopy(cfg)))
        ssh.cfg = copy.deepcopy(cfg)

    def post(self, path, data):
        return self.client.post(path, json=data, base_url="http://127.0.0.1:8620",
                                headers={"X-CSRF-Token": panel.CSRF_TOKEN}).get_json()

    def direct(self, **kwargs):
        return {"mode": "direct", "protocol": "vless-ws", "server_id": "entry", "port": 600, **kwargs}

    def relay(self, **kwargs):
        return {"mode": "relay", "protocol": "vless-ws", "entry_id": "entry", "exit_id": "exit",
                "entry_port": 600, "exit_port": 1600, **kwargs}

    def test_request_validation_all_uuid_protocols_and_even_short_id(self):
        for protocol in ("vless-reality", "vless-ws", "vmess-ws"):
            self.assertTrue(panel._validate_node_req(self.direct(protocol=protocol, uuid="not-a-uuid")))
        self.assertTrue(panel._validate_node_req(self.direct(protocol="vless-reality", sid="abc")))
        self.assertFalse(panel._validate_node_req(self.direct(protocol="vless-reality", sid="abcd")))
        self.assertFalse(panel._validate_node_req(self.direct()))
        for body in ([], {"protocol": {}}, self.direct(port=True), self.direct(port=600.1),
                     self.direct(uuid=[]), self.direct(remark="x" * 201)):
            self.assertTrue(panel._validate_node_req(body))

    def test_ss2022_password_strict_base64(self):
        request = self.direct(protocol="shadowsocks", ss_method="2022-blake3-aes-128-gcm")
        self.assertTrue(panel._validate_node_req({**request, "ss_password": "%%%AAAAAAAAAAAAAAAAAAAAAA=="}))

    def test_ipv6_uri_hosts_have_brackets_but_vmess_json_address_does_not(self):
        for protocol in ("vless-ws", "vmess-ws", "shadowsocks"):
            request = self.direct(protocol=protocol, ss_method="aes-128-gcm")
            ib, link, _ = panel._build_inbound_and_link(None, "test", {}, request, 600, "2001:db8::1", 600, "")
            recovered = panel._node_link_for_inbound(None, ib, "2001:db8::1", 600)
            for value in (link, recovered):
                if protocol == "vmess-ws":
                    self.assertEqual(json.loads(base64.b64decode(value[len("vmess://"):]))["add"], "2001:db8::1")
                else:
                    self.assertIn("@[2001:db8::1]:600", value)

    def test_manual_host_shell_injection_and_ssh_port_rejected(self):
        for bad in ("host;true", "host&true", "host|true", "host>target", "host$(true)"):
            srv = {**self.servers["entry"], "host": bad}
            self.assertIsNone(panel._resolve_server({"server": srv}, "server"))
        self.assertIsNone(panel._resolve_server({"server": {**self.servers["entry"], "port": "bad"}}, "server"))

    def test_direct_preserves_config_and_closes_connection(self):
        result = panel._deploy_direct("test", self.direct())
        ssh = self.connections[self.servers["entry"]["host"]]
        self.assertEqual(ssh.cfg["routing"], self.original["routing"])
        self.assertEqual(ssh.cfg["inbounds"][0], self.original["inbounds"][0])
        self.assertIn(":600?", result["links"][0])
        self.assertTrue(ssh.closed)

    def test_occupied_port_closes_connection_without_apply(self):
        with self.assertRaisesRegex(RuntimeError, "已被占用"):
            panel._deploy_direct("test", self.direct(port=9000))
        self.assertTrue(self.connections[self.servers["entry"]["host"]].closed)
        self.assertFalse(self.applies)

    def test_same_server_parallel_deployments_keep_both_nodes(self):
        failures = []

        def worker(port):
            try:
                panel._deploy_direct("test", self.direct(port=port))
            except Exception as error:
                failures.append(error)

        workers = [threading.Thread(target=worker, args=(p,)) for p in (600, 601)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertFalse(failures)
        cfg = self.connections[self.servers["entry"]["host"]].cfg
        self.assertEqual({x["port"] for x in cfg["inbounds"]}, {9000, 600, 601})

    def test_relay_failed_connectivity_removes_only_own_exit_inbound(self):
        exit_ssh = self.connections[self.servers["exit"]["host"]]

        def probe(ssh, command, timeout=180):
            # Simulate a different cooperating process adding a node after our
            # exit commit; rollback must preserve it.
            exit_ssh.cfg["inbounds"].append({"tag": "other-job", "port": 7000, "protocol": "vless"})
            raise RuntimeError("entry-to-exit unreachable")

        with patch.object(panel, "run_checked", side_effect=probe):
            panel._deploy_node_worker("test", self.relay())
        self.assertEqual(panel.jobs["test"]["status"], "error")
        self.assertEqual({x["tag"] for x in exit_ssh.cfg["inbounds"]}, {"old", "other-job"})
        self.assertEqual(exit_ssh.cfg["routing"], self.original["routing"])
        self.assertTrue(all(ssh.closed for ssh in self.connections.values()))

    def test_relay_failed_entry_apply_removes_exit_inbound(self):
        def apply(ssh, cfg, expected=None):
            if ssh.host == self.servers["entry"]["host"]:
                raise RuntimeError("entry restart failed and transaction rolled back")
            self.apply(ssh, cfg, expected)

        with patch.object(panel, "_apply_xray_cfg", side_effect=apply):
            with self.assertRaisesRegex(RuntimeError, "entry restart"):
                panel._deploy_relay("test", self.relay())
        self.assertEqual(self.connections[self.servers["exit"]["host"]].cfg["inbounds"], self.original["inbounds"])
        self.assertTrue(all(ssh.closed for ssh in self.connections.values()))

    def test_shadowsocks_relay_forwards_tcp_and_udp(self):
        panel._deploy_relay("test", self.relay(protocol="shadowsocks", ss_method="aes-128-gcm"))
        entry_cfg = self.connections[self.servers["entry"]["host"]].cfg
        self.assertEqual(entry_cfg["inbounds"][-1]["settings"]["network"], "tcp,udp")

    def test_delete_rejects_missing_token_before_connecting(self):
        with patch.object(panel, "connect") as connect:
            result = self.post("/api/nodes/delete", {"server": "entry", "tag": "old"})
        self.assertFalse(result["ok"])
        connect.assert_not_called()

    def test_token_cannot_delete_same_tag_on_another_server(self):
        token = panel._node_token(self.servers["entry"], self.original["inbounds"][0])
        result = self.post("/api/nodes/delete", {"server": "exit", "tag": "old", "token": token})
        self.assertFalse(result["ok"])
        self.assertFalse(self.applies)
        self.assertTrue(self.connections[self.servers["exit"]["host"]].closed)

    def test_token_detects_changed_inbound_and_valid_token_removes_one(self):
        ssh = self.connections[self.servers["entry"]["host"]]
        old = ssh.cfg["inbounds"][0]
        token = panel._node_token(self.servers["entry"], old)
        old["port"] = 9002
        self.assertFalse(self.post("/api/nodes/delete", {"server": "entry", "tag": "old", "token": token})["ok"])
        token = panel._node_token(self.servers["entry"], old)
        ssh.cfg["inbounds"].append({"tag": "old", "port": 9003, "protocol": "vless"})
        self.assertTrue(self.post("/api/nodes/delete", {"server": "entry", "tag": "old", "token": token})["ok"])
        self.assertEqual([x["port"] for x in ssh.cfg["inbounds"]], [9003])

    def test_list_closes_primary_and_exit_connection_after_exit_read_failure(self):
        entry_ssh = self.connections[self.servers["entry"]["host"]]
        entry_ssh.cfg["inbounds"] = [{"tag": "relay", "port": 600, "protocol": "dokodemo-door",
                                     "settings": {"address": self.servers["exit"]["host"], "port": 1600}}]

        def read(ssh):
            if ssh.host == self.servers["exit"]["host"]:
                raise RuntimeError("bad exit config")
            return copy.deepcopy(ssh.cfg)

        with patch.object(panel, "_read_xray_cfg", side_effect=read):
            result = self.post("/api/nodes/list", {"server": "entry"})
        self.assertTrue(result["ok"])
        self.assertIsNotNone(result["inbounds"][0]["token"])
        self.assertTrue(all(ssh.closed for ssh in self.connections.values()))


if __name__ == "__main__":
    unittest.main()
