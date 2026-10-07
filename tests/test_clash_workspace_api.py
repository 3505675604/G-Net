"""Offline workspace API and cache invalidation checks, with isolated profiles."""
import copy
import importlib.util
import logging
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from clash_export import ExportCache, WorkspaceSnapshots


def server(number):
    return {"id": str(number) * 32, "name": f"测试服务器 {number}", "host": f"192.0.2.{number}",
            "port": 22, "user": "root", "password": "fake-SSH-never-export"}


def inbound(port=600, tag="重名节点"):
    return {"tag": tag, "port": port, "protocol": "shadowsocks",
            "settings": {"method": "aes-128-gcm", "password": "fake-client-password", "network": "tcp,udp"}}


class WorkspaceApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clash-workspace-api-")
        self.addCleanup(self.temporary.cleanup)
        name = "clash_workspace_api_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, ROOT / "server-manager" / "app.py")
        self.panel = importlib.util.module_from_spec(spec)
        sys.modules[name] = self.panel
        self.addCleanup(lambda: sys.modules.pop(name, None))
        with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": self.temporary.name}):
            spec.loader.exec_module(self.panel)
        self.addCleanup(self.panel.shutdown_resources)
        self.panel.configure_local_access(50778)
        self.panel.app.config["TESTING"] = True
        self.client = self.panel.app.test_client()
        self.base = "http://127.0.0.1:50778"
        self.now = [100.0]
        self.panel.CLASH_EXPORTS = ExportCache(clock=lambda: self.now[0])
        self.panel.CLASH_SNAPSHOTS = WorkspaceSnapshots(clock=lambda: self.now[0])
        self.servers = [server(1), server(2)]
        self.cfgs = {self.servers[0]["id"]: {"inbounds": [inbound(), inbound(601)]},
                     self.servers[1]["id"]: {"inbounds": [inbound(602)]}}
        self.connections = []
        for target, replacement in (
                ("get_server", lambda sid: next((copy.deepcopy(s) for s in self.servers if s["id"] == sid), None)),
                ("load_json", lambda path, default: copy.deepcopy(self.servers) if path == self.panel.SERVERS_FILE else {}),
                ("save_json", self.save), ("connect", self.connect),
                ("_read_xray_cfg", lambda ssh: copy.deepcopy(self.cfgs[ssh.sid])),
                ("_apply_xray_cfg", lambda ssh, cfg, **kwargs: self.cfgs.__setitem__(ssh.sid, copy.deepcopy(cfg))),
                ("run_checked", lambda *args, **kwargs: "OK"),
                ("connect_ssh", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("real SSH forbidden")))):
            self.enterContext(patch.object(self.panel, target, side_effect=replacement))

    def save(self, path, value):
        if path == self.panel.SERVERS_FILE:
            self.servers = copy.deepcopy(value)

    def connect(self, srv, **kwargs):
        ssh = SimpleNamespace(sid=srv["id"], close=MagicMock())
        self.connections.append(ssh)
        return ssh

    def request(self, method, path, **kwargs):
        kwargs.setdefault("base_url", self.base)
        kwargs.setdefault("headers", {"X-CSRF-Token": self.panel.CSRF_TOKEN})
        return self.client.open(path, method=method, **kwargs)

    def read(self, ids=None):
        return self.request("POST", "/api/clash-workspace/read", json={"server_ids": ids or [s["id"] for s in self.servers]})

    def export(self, inventory, ids=None, profile=None):
        return self.request("POST", "/api/clash-workspace/export", json={"snapshot_id": inventory["snapshot_id"],
                            "node_ids": ids or [n["id"] for n in inventory["nodes"] if n["available"]],
                            "profile": profile or {}})

    def download(self, exported):
        path = urllib.parse.urlsplit(exported["clash"]["url"]).path
        return self.client.get(path, base_url=self.base)

    def test_multiple_servers_nodes_unique_names_and_ordered_routing(self):
        inventory = self.read().json
        self.assertTrue(inventory["ok"])
        self.assertEqual(len(inventory["nodes"]), 3)
        ids = [n["id"] for n in inventory["nodes"]]
        profile = {"name": "优雅配置", "template": "custom", "groups": [
            {"name": "灵活分流", "type": "select", "members": ids + ["DIRECT"]}],
            "rules": [{"type": "DOMAIN-SUFFIX", "value": "example.com", "target": "灵活分流"},
                      {"type": "IP-CIDR", "value": "10.0.0.0/8", "target": "DIRECT", "no_resolve": True}],
            "fallback": "灵活分流"}
        result = self.export(inventory, profile=profile)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json["node_count"], 3)
        self.assertEqual(len(set(result.json["names"].values())), 3)
        yaml = result.json["clash"]["yaml"]
        self.assertIn("192.0.2.1", yaml)
        self.assertIn("192.0.2.2", yaml)
        self.assertLess(yaml.index("DOMAIN-SUFFIX,example.com"), yaml.index("IP-CIDR,10.0.0.0/8"))
        self.assertIn("MATCH,灵活分流", yaml)
        self.assertNotIn("fake-SSH-never-export", yaml)
        downloaded = self.download(result.json)
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.get_data(as_text=True), yaml)
        self.assertEqual(downloaded.headers["Cache-Control"], "no-store")
        disposition = downloaded.headers["Content-Disposition"]
        self.assertIn("filename*=UTF-8''" + urllib.parse.quote("优雅配置.yaml", safe=""), disposition)
        self.assertTrue(disposition.isascii())
        for ssh in self.connections:
            ssh.close.assert_called_once()

    def test_partial_read_failure_is_explicit_and_good_nodes_can_export(self):
        def read(ssh):
            if ssh.sid == self.servers[1]["id"]:
                raise ValueError("offline second server unavailable")
            return copy.deepcopy(self.cfgs[ssh.sid])
        with patch.object(self.panel, "_read_xray_cfg", side_effect=read):
            inventory = self.read().json
        self.assertEqual([s["status"] for s in inventory["servers"]], ["ok", "error"])
        self.assertEqual(len(inventory["nodes"]), 2)
        self.assertEqual(self.export(inventory).json["node_count"], 2)

    def test_invalid_server_ids_and_duplicate_physical_scope_rejected_before_ssh(self):
        for ids in ([self.servers[0]["id"]] * 2, ["unknown"], ["a" * 32], [False]):
            self.assertIn(self.read(ids).status_code, (400, 409))
        duplicate = {**server(3), "host": self.servers[0]["host"], "port": "22"}
        self.servers.append(duplicate)
        self.assertEqual(self.read([self.servers[0]["id"], duplicate["id"]]).status_code, 400)
        self.assertEqual(self.connections, [])

    def test_cross_snapshot_and_duplicate_node_ids_rejected(self):
        first = self.read([self.servers[0]["id"]]).json
        second = self.read([self.servers[1]["id"]]).json
        old_id = first["nodes"][0]["id"]
        current_id = second["nodes"][0]["id"]
        self.assertEqual(self.export(second, [old_id]).status_code, 400)
        self.assertEqual(self.export(second, [current_id, current_id]).status_code, 400)

    def test_snapshot_expiry_requires_rereading(self):
        inventory = self.read().json
        self.now[0] += self.panel.CLASH_SNAPSHOTS.ttl
        self.assertEqual(self.export(inventory).status_code, 409)

    def test_source_reread_revokes_merged_url_and_old_selection(self):
        inventory = self.read().json
        result = self.export(inventory).json
        self.read([self.servers[0]["id"]])
        self.assertEqual(self.download(result).status_code, 404)
        self.assertEqual(self.export(inventory).status_code, 409)

    def test_source_node_delete_revokes_merged_url_but_unselected_node_does_not(self):
        srv = self.servers[0]
        inventory = self.read([srv["id"]]).json
        result = self.export(inventory, [inventory["nodes"][0]["id"]]).json
        second = self.cfgs[srv["id"]]["inbounds"][1]
        body = {"server": srv["id"], "tag": second["tag"], "token": self.panel._node_token(srv, second)}
        self.assertTrue(self.request("POST", "/api/nodes/delete", json=body).json["ok"])
        self.assertEqual(self.download(result).status_code, 200)
        first = self.cfgs[srv["id"]]["inbounds"][0]
        body.update(tag=first["tag"], token=self.panel._node_token(srv, first))
        self.assertTrue(self.request("POST", "/api/nodes/delete", json=body).json["ok"])
        self.assertEqual(self.download(result).status_code, 404)

    def test_server_delete_revokes_merged_url(self):
        inventory = self.read().json
        result = self.export(inventory).json
        response = self.request("DELETE", "/api/servers/" + self.servers[0]["id"])
        self.assertTrue(response.json["ok"])
        self.assertEqual(self.download(result).status_code, 404)

    def relay_inventory(self):
        entry, exit_ = self.servers
        self.cfgs[entry["id"]] = {"inbounds": [{"tag": "relay", "port": 700, "protocol": "dokodemo-door",
            "settings": {"address": exit_["host"], "port": 602, "network": "tcp"}}]}
        return self.read([entry["id"]]).json

    def test_relay_inherits_exit_credentials_and_entry_udp_limit(self):
        inventory = self.relay_inventory()
        self.assertTrue(inventory["nodes"][0]["available"])
        result = self.export(inventory).json
        yaml = result["clash"]["yaml"]
        self.assertIn('server: "192.0.2.1"', yaml)
        self.assertIn("port: 700", yaml)
        self.assertIn("fake-client-password", yaml)
        self.assertIn("udp: false", yaml)

    def test_relay_exit_reread_revokes_merged_url(self):
        inventory = self.relay_inventory()
        result = self.export(inventory).json
        self.read([self.servers[1]["id"]])
        self.assertEqual(self.download(result).status_code, 404)

    def test_relay_exit_delete_and_server_delete_revoke_merged_url(self):
        inventory = self.relay_inventory()
        result = self.export(inventory).json
        exit_ = self.servers[1]
        actual = self.cfgs[exit_["id"]]["inbounds"][0]
        body = {"server": exit_["id"], "tag": actual["tag"], "token": self.panel._node_token(exit_, actual)}
        self.assertTrue(self.request("POST", "/api/nodes/delete", json=body).json["ok"])
        self.assertEqual(self.download(result).status_code, 404)
        self.cfgs[exit_["id"]] = {"inbounds": [actual]}
        result = self.export(self.relay_inventory()).json
        self.request("DELETE", "/api/servers/" + exit_["id"])
        self.assertEqual(self.download(result).status_code, 404)

    def test_exit_change_during_relay_read_prevents_stale_capability_publication(self):
        self.relay_inventory()
        exit_ = self.servers[1]
        original = self.panel._read_xray_cfg.side_effect
        def change(ssh):
            cfg = original(ssh)
            if ssh.sid == exit_["id"]:
                self.panel.CLASH_EXPORTS.revoke_scope(self.panel._clash_scope(exit_))
            return cfg
        with patch.object(self.panel, "_read_xray_cfg", side_effect=change):
            inventory = self.read([self.servers[0]["id"]]).json
        self.assertFalse(inventory["nodes"][0]["available"])

    def test_primary_scope_invalidation_during_read_cannot_recreate_revoked_tokens(self):
        srv = self.servers[0]
        original = self.panel._read_xray_cfg.side_effect
        def read(ssh):
            cfg = original(ssh)
            self.panel.CLASH_EXPORTS.revoke_scope(self.panel._clash_scope(srv))
            return cfg
        with patch.object(self.panel, "_read_xray_cfg", side_effect=read):
            inventory = self.read([srv["id"]]).json
        self.assertEqual(inventory["nodes"], [])
        self.assertEqual(inventory["servers"][0]["status"], "error")
        self.assertIn("来源已变化", inventory["servers"][0]["msg"])

    def test_profile_reexport_rotates_only_profile_url_and_keeps_source_selections(self):
        inventory = self.read().json
        first = self.export(inventory).json
        second = self.export(inventory).json
        self.assertEqual(self.download(first).status_code, 404)
        self.assertEqual(self.download(second).status_code, 200)
        self.assertTrue(all(self.panel.CLASH_EXPORTS.get_proxy(n["id"]) is not None for n in inventory["nodes"]))

    def test_concurrent_reads_of_same_scope_publish_serial_inventories(self):
        srv = self.servers[0]
        started, release, second_started = threading.Event(), threading.Event(), threading.Event()
        count, guard = [0], threading.Lock()
        def read(ssh):
            with guard:
                count[0] += 1
                number = count[0]
            if number == 1:
                started.set()
                if not release.wait(3):
                    raise AssertionError("test read was not released")
            else:
                second_started.set()
            return copy.deepcopy(self.cfgs[ssh.sid])
        with patch.object(self.panel, "_read_xray_cfg", side_effect=read), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.panel._read_node_items, srv)
            self.assertTrue(started.wait(2))
            second = pool.submit(self.panel._read_node_items, srv)
            try:
                self.assertFalse(second_started.wait(0.1))
            finally:
                release.set()
            old, new = first.result(timeout=3), second.result(timeout=3)
        self.assertTrue(old["ok"] and new["ok"])
        for node in old["inbounds"]:
            self.assertIsNone(self.panel.CLASH_EXPORTS.get(node["clash"]["selection_token"]))
        for node in new["inbounds"]:
            self.assertIsNotNone(self.panel.CLASH_EXPORTS.get(node["clash"]["selection_token"]))

    def test_workspace_csrf_origin_host_guards_and_capability_log_redaction(self):
        path = "/api/clash-workspace/read"
        body = {"server_ids": [self.servers[0]["id"]]}
        self.assertEqual(self.request("POST", path, json=body, headers={}).status_code, 403)
        self.assertEqual(self.request("POST", path, json=body, base_url="http://attacker.invalid:50778").status_code, 403)
        self.assertEqual(self.request("POST", path, json=body, headers={"X-CSRF-Token": self.panel.CSRF_TOKEN,
                         "Origin": "https://attacker.invalid"}).status_code, 403)
        self.assertEqual(self.connections, [])
        result = self.export(self.read().json).json
        url = result["clash"]["url"]
        record = logging.LogRecord("werkzeug", logging.INFO, __file__, 1, "%s", (url,), None)
        self.panel._ClashCapabilityLogFilter().filter(record)
        self.assertNotIn(url, record.getMessage())
        self.assertIn("[redacted]", record.getMessage())


class CacheDependencyTests(unittest.TestCase):
    def test_transitive_dependency_invalidation_and_capacity_protection(self):
        cache = ExportCache(capacity=4)
        source = cache.register("source", "a", "a", "a.yaml", proxy={"name": "fake"})
        parent = cache.register("parent", "b", "b", "b.yaml", dependencies=[source])
        unused = cache.register("unused", "x", "x", "x.yaml")
        child = cache.register("child", "c", "c", "c.yaml", dependencies=[parent])
        newest = cache.register("new", "d", "d", "d.yaml", dependencies=[child])
        self.assertIsNotNone(cache.get(newest))
        self.assertIsNone(cache.get(unused))
        cache.revoke_scope("a")
        self.assertIsNone(cache.get(newest))

    def test_clear_and_scope_invalidation_reject_captured_epoch(self):
        cache = ExportCache()
        captured = cache.scope_epochs(["a"])
        cache.clear()
        with self.assertRaisesRegex(ValueError, "来源已变化"):
            cache.register("stale", "a", "node", "a.yaml", expected_epochs=captured)
        captured = cache.scope_epochs(["a"])
        cache.revoke_scope("a")
        with self.assertRaisesRegex(ValueError, "来源已变化"):
            cache.register("stale", "a", "node", "a.yaml", expected_epochs=captured)


if __name__ == "__main__":
    unittest.main()
