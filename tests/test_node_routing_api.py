"""Node-specific routing API checks with fake nodes and isolated local profiles."""
import copy
import importlib.util
import json
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
from node_routing_store import NodeRoutingStore


class NodeRoutingApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="node-routing-api-")
        self.addCleanup(self.temporary.cleanup)
        self.panel = self.load_panel()
        self.client = self.panel.app.test_client()
        self.base = "http://127.0.0.1:50779"
        self.now = [100.0]
        self.panel.CLASH_EXPORTS = ExportCache(clock=lambda: self.now[0])
        self.panel.CLASH_SNAPSHOTS = WorkspaceSnapshots(clock=lambda: self.now[0])
        self.server = {"id": "1" * 32, "name": "隔离测试服务器", "host": "192.0.2.10",
                       "port": 22, "user": "root", "password": "fake-ssh-never-export"}
        self.inbounds = [{"tag": "测试节点 A", "port": 600, "protocol": "shadowsocks",
                          "settings": {"method": "aes-128-gcm", "password": "fake-client-a"}},
                         {"tag": "测试节点 B", "port": 601, "protocol": "shadowsocks",
                          "settings": {"method": "aes-128-gcm", "password": "fake-client-b"}}]
        self.connections = []
        self.install_fake_sources(self.panel)

    def load_panel(self):
        name = "node_routing_api_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, ROOT / "server-manager" / "app.py")
        panel = importlib.util.module_from_spec(spec)
        sys.modules[name] = panel
        self.addCleanup(lambda: sys.modules.pop(name, None))
        with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": self.temporary.name}):
            spec.loader.exec_module(panel)
        self.addCleanup(panel.shutdown_resources)
        panel.configure_local_access(50779)
        panel.app.config["TESTING"] = True
        return panel

    def install_fake_sources(self, panel):
        def connect(*args, **kwargs):
            ssh = SimpleNamespace(close=MagicMock())
            self.connections.append(ssh)
            return ssh
        for target, replacement in (
            ("get_server", lambda sid: copy.deepcopy(self.server) if sid == self.server["id"] else None),
            ("load_json", lambda path, default: [copy.deepcopy(self.server)] if path == panel.SERVERS_FILE else {}),
            ("connect", connect), ("run_checked", lambda *args, **kwargs: "OK"),
            ("_read_xray_cfg", lambda ssh: {"inbounds": copy.deepcopy(self.inbounds)}),
            ("connect_ssh", lambda *a, **k: (_ for _ in ()).throw(AssertionError("real SSH forbidden"))),
        ):
            self.enterContext(patch.object(panel, target, side_effect=replacement))

    def request(self, method, path, **kwargs):
        kwargs.setdefault("base_url", self.base)
        kwargs.setdefault("headers", {"X-CSRF-Token": self.panel.CSRF_TOKEN})
        return self.client.open(path, method=method, **kwargs)

    def read(self):
        response = self.request("POST", "/api/clash-workspace/read", json={"server_ids": [self.server["id"]]})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertTrue(response.json["ok"], response.json)
        return response.json

    def save(self, inventory, index=0, domains=None, enabled=True, revision=None):
        node = inventory["nodes"][index]
        return self.request("POST", "/api/node-routing/save", json={
            "snapshot_id": inventory["snapshot_id"], "node_id": node["id"], "enabled": enabled,
            "direct_domains": ["example.com"] if domains is None else domains,
            "expected_revision": node["routing"]["revision"] if revision is None else revision,
        })

    def export(self, inventory, index=0, **extra):
        return self.request("POST", "/api/node-routing/export", json={
            "snapshot_id": inventory["snapshot_id"], "node_id": inventory["nodes"][index]["id"], **extra})

    def download(self, exported):
        return self.client.get(urllib.parse.urlsplit(exported["clash"]["url"]).path, base_url=self.base)

    def test_domains_saved_and_only_selected_node_exported(self):
        inventory = self.read()
        self.assertEqual(inventory["nodes"][0]["routing"], {"enabled": False, "direct_domains": [], "revision": 0})
        saved = self.save(inventory, domains=["EXAMPLE.COM", "example.net"])
        self.assertEqual(saved.status_code, 200, saved.json)
        self.assertEqual(saved.json["routing"], {"enabled": True, "direct_domains": ["example.com", "example.net"], "revision": 1})
        result = self.export(inventory)
        self.assertEqual(result.status_code, 200, result.json)
        self.assertTrue(result.json["xray"]["available"])
        text = result.json["clash"]["yaml"]
        self.assertIn("DOMAIN-SUFFIX,example.com,DIRECT", text)
        self.assertIn("fake-client-a", text)
        self.assertNotIn("fake-client-b", text)
        self.assertNotIn("GEOIP,CN", text)
        self.assertNotIn("IP-CIDR,", text)
        self.assertEqual(self.download(result.json).get_data(as_text=True), text)
        self.assertEqual(len(self.connections), 1, "save/export must not open SSH")
        self.connections[0].close.assert_called_once()

    def test_node_a_preferences_do_not_affect_node_b_or_generic_workspace(self):
        inventory = self.read()
        self.save(inventory)
        b = self.export(inventory, 1)
        self.assertEqual(b.json["routing"], {"enabled": False, "direct_domains": [], "revision": 0})
        self.assertNotIn("DOMAIN-SUFFIX,example.com", b.json["clash"]["yaml"])
        merged = self.request("POST", "/api/clash-workspace/export", json={
            "snapshot_id": inventory["snapshot_id"], "node_ids": [n["id"] for n in inventory["nodes"]],
            "profile": {"template": "custom"}})
        self.assertEqual(merged.status_code, 200, merged.json)
        self.assertNotIn("DOMAIN-SUFFIX,example.com", merged.json["clash"]["yaml"])

    def test_reread_retains_preferences_and_rejects_old_token(self):
        before = self.read()
        self.save(before)
        after = self.read()
        self.assertNotEqual(before["nodes"][0]["id"], after["nodes"][0]["id"])
        self.assertEqual(after["nodes"][0]["routing"]["direct_domains"], ["example.com"])
        self.assertEqual(self.export(before).status_code, 409)
        self.assertEqual(self.save(before, revision=1).status_code, 409)
        self.assertEqual(self.export(after).status_code, 200)

    def test_saved_preferences_persist_across_process_restart(self):
        inventory = self.read()
        self.save(inventory)
        old_panel = self.panel
        old_panel.shutdown_resources()
        self.panel = self.load_panel()
        self.install_fake_sources(self.panel)
        self.client = self.panel.app.test_client()
        after = self.read()
        self.assertEqual(after["nodes"][0]["routing"], {"enabled": True, "direct_domains": ["example.com"], "revision": 1})
        self.assertEqual(self.export(inventory).status_code, 409)

    def test_label_changes_keep_identity_but_credentials_create_distinct_identity(self):
        self.save(self.read())
        self.inbounds[0]["tag"] = "改名后的节点 A"
        renamed = self.read()
        self.assertEqual(renamed["nodes"][0]["routing"]["revision"], 1)
        self.inbounds[0]["settings"]["password"] = "replacement-fake-client-a"
        replaced = self.read()
        self.assertEqual(replaced["nodes"][0]["routing"]["revision"], 0)

    def test_persistent_file_contains_no_proxy_credentials_or_capabilities(self):
        inventory = self.read()
        self.save(inventory)
        payload = Path(self.panel.NODE_ROUTING_FILE).read_text(encoding="utf-8")
        for forbidden in ("fake-client-a", "fake-client-b", "fake-ssh", "192.0.2.10", inventory["snapshot_id"], inventory["nodes"][0]["id"]):
            self.assertNotIn(forbidden, payload)
        stored = json.loads(payload)
        self.assertEqual(set(stored), {"version", "routes"})
        self.assertEqual(set(next(iter(stored["routes"].values()))), {"enabled", "direct_domains", "revision"})

    def test_same_content_save_is_idempotent_and_conflict_is_409(self):
        inventory = self.read()
        self.assertEqual(self.save(inventory).json["routing"]["revision"], 1)
        exported = self.export(inventory).json
        again = self.save(inventory, revision=1)
        self.assertEqual(again.json["routing"]["revision"], 1)
        self.assertEqual(self.download(exported).status_code, 200)
        self.assertEqual(self.save(inventory, domains=["other.example"], revision=0).status_code, 409)
        self.assertEqual(self.download(exported).status_code, 200)

    def test_save_revokes_only_own_derived_url_keeps_sources_and_other_node_url(self):
        inventory = self.read()
        self.save(inventory)
        a, b = self.export(inventory).json, self.export(inventory, 1).json
        self.assertEqual(self.save(inventory, domains=["changed.example"], revision=1).status_code, 200)
        self.assertEqual(self.download(a).status_code, 404)
        self.assertEqual(self.download(b).status_code, 200)
        self.assertTrue(all(self.panel.CLASH_EXPORTS.get_proxy(n["id"]) for n in inventory["nodes"]))
        self.assertEqual(self.export(inventory).status_code, 200)

    def test_derived_reexport_rotates_only_same_node_url(self):
        inventory = self.read()
        a, b = self.export(inventory).json, self.export(inventory, 1).json
        latest = self.export(inventory).json
        self.assertEqual(self.download(a).status_code, 404)
        self.assertEqual(self.download(b).status_code, 200)
        self.assertEqual(self.download(latest).status_code, 200)

    def test_source_node_revocation_invalidates_only_dependent_routing_url(self):
        inventory = self.read()
        a, b = self.export(inventory).json, self.export(inventory, 1).json
        self.panel.CLASH_EXPORTS.revoke_node(self.panel._clash_scope(self.server),
                                            self.panel._node_token(self.server, self.inbounds[0]))
        self.assertEqual(self.download(a).status_code, 404)
        self.assertEqual(self.download(b).status_code, 200)
        self.assertEqual(self.export(inventory).status_code, 409)
        self.assertEqual(self.export(inventory, 1).status_code, 200)

    def test_legacy_vmess_explicitly_marks_xray_unavailable_preserves_clash_export(self):
        self.inbounds[0] = {"tag": "legacy-vmess", "port": 600, "protocol": "vmess",
                            "settings": {"clients": [{"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "alterId": 64}]},
                            "streamSettings": {"network": "tcp", "security": "none"}}
        inventory = self.read()
        self.save(inventory)
        exported = self.export(inventory)
        self.assertEqual(exported.status_code, 200, exported.json)
        self.assertTrue(exported.json["clash"]["available"])
        self.assertFalse(exported.json["xray"]["available"])
        self.assertIn("notice", exported.json["xray"])
        self.assertNotIn("json", exported.json["xray"])

    def test_unavailable_wrong_snapshot_and_multi_id_rejected(self):
        first = self.read()
        unknown = "a" * 43
        for node_id in (unknown, [n["id"] for n in first["nodes"]], True):
            response = self.request("POST", "/api/node-routing/export", json={"snapshot_id": first["snapshot_id"], "node_id": node_id})
            self.assertEqual(response.status_code, 400)
        wrong = self.request("POST", "/api/node-routing/export", json={"snapshot_id": unknown, "node_id": first["nodes"][0]["id"]})
        self.assertEqual(wrong.status_code, 409)

    def test_expired_snapshot_or_source_cannot_save_or_export(self):
        inventory = self.read()
        self.now[0] += self.panel.CLASH_SNAPSHOTS.ttl
        self.assertEqual(self.save(inventory).status_code, 409)
        self.assertEqual(self.export(inventory).status_code, 409)
        inventory = self.read()
        self.panel.CLASH_EXPORTS.revoke_scope(self.panel._clash_scope(self.server))
        self.assertEqual(self.save(inventory).status_code, 409)
        self.assertEqual(self.export(inventory).status_code, 409)
        self.assertFalse(Path(self.panel.NODE_ROUTING_FILE).exists())

    def test_csrf_origin_host_guards_apply(self):
        inventory = self.read()
        data = {"snapshot_id": inventory["snapshot_id"], "node_id": inventory["nodes"][0]["id"]}
        for path in ("/api/node-routing/save", "/api/node-routing/export"):
            self.assertEqual(self.request("POST", path, json=data, headers={}).status_code, 403)
            self.assertEqual(self.request("POST", path, json=data, headers={"X-CSRF-Token": self.panel.CSRF_TOKEN, "Origin": "https://malicious.example"}).status_code, 403)
            self.assertEqual(self.request("POST", path, json=data, base_url="http://malicious.example:50779").status_code, 403)

    def test_invalid_domains_and_field_types_cannot_write_preferences(self):
        inventory = self.read()
        for domains in (["https://example.com"], ["example.com/path"], ["*.example.com"], ["1.2.3.4"], [False], "example.com"):
            self.assertEqual(self.save(inventory, domains=domains).status_code, 400, domains)
        for enabled in (0, 1, "true", None):
            self.assertEqual(self.save(inventory, enabled=enabled).status_code, 400)
        for revision in (-1, True, "0", 1.5, 2 ** 53):
            self.assertEqual(self.save(inventory, revision=revision).status_code, 400)
        self.assertFalse(Path(self.panel.NODE_ROUTING_FILE).exists())

    def test_disabled_routing_retains_list_without_domain_rules(self):
        inventory = self.read()
        self.save(inventory, enabled=False)
        result = self.export(inventory)
        self.assertEqual(result.json["routing"]["direct_domains"], ["example.com"])
        self.assertNotIn("DOMAIN-SUFFIX,example.com", result.json["clash"]["yaml"])

    def test_export_validates_distinct_loopback_ports_and_xray_json_not_bearer_url(self):
        inventory = self.read()
        for options in ({"mixed_port": True}, {"socks_port": 0}, {"http_port": 65536}, {"socks_port": 10809, "http_port": 10809}):
            self.assertEqual(self.export(inventory, **options).status_code, 400, options)
        result = self.export(inventory, mixed_port=7891, socks_port=10810, http_port=10811).json
        self.assertNotIn("url", result["xray"])
        config = json.loads(result["xray"]["json"])
        self.assertTrue(all(node["listen"] == "127.0.0.1" for node in config["inbounds"]))
        self.assertEqual({node["port"] for node in config["inbounds"]}, {10810, 10811})

    def test_save_during_export_prevents_stale_publication(self):
        inventory = self.read()
        self.save(inventory)
        entered, proceed = threading.Event(), threading.Event()
        original = self.panel.build_node_routing
        def build(*args, **kwargs):
            result = original(*args, **kwargs)
            entered.set()
            if not proceed.wait(5):
                raise AssertionError("timed out awaiting concurrent save")
            return result
        with patch.object(self.panel, "build_node_routing", side_effect=build), ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.export, inventory)
            self.assertTrue(entered.wait(5))
            try:
                self.assertEqual(self.save(inventory, domains=["changed.example"], revision=1).status_code, 200)
            finally:
                proceed.set()
            self.assertEqual(pending.result(timeout=5).status_code, 409)
        scope = ("node-routing", self.panel.CLASH_EXPORTS.get_routing_key(inventory["nodes"][0]["id"]))
        self.assertFalse(any(entry["scope"] == scope for entry in self.panel.CLASH_EXPORTS._entries.values()))

    def test_source_revoked_during_build_prevents_export(self):
        inventory = self.read()
        original = self.panel.build_node_routing
        def build(*args, **kwargs):
            result = original(*args, **kwargs)
            self.panel.CLASH_EXPORTS.revoke_scope(self.panel._clash_scope(self.server))
            return result
        with patch.object(self.panel, "build_node_routing", side_effect=build):
            self.assertEqual(self.export(inventory).status_code, 409)

    def test_source_revoked_between_authorization_and_guard_cannot_save(self):
        inventory = self.read()
        original = self.panel.CLASH_EXPORTS.get_proxy
        def proxy(token):
            result = original(token)
            self.panel.CLASH_EXPORTS.revoke_scope(self.panel._clash_scope(self.server))
            return result
        with patch.object(self.panel.CLASH_EXPORTS, "get_proxy", side_effect=proxy):
            self.assertEqual(self.save(inventory).status_code, 409)
        self.assertFalse(Path(self.panel.NODE_ROUTING_FILE).exists())

    def test_corrupt_or_oversized_store_is_preserved_and_rejected(self):
        inventory = self.read()
        path = Path(self.panel.NODE_ROUTING_FILE)
        for content in (b"broken-json", b" " * (NodeRoutingStore.MAX_BYTES + 1)):
            path.write_bytes(content)
            self.assertEqual(self.save(inventory).status_code, 400)
            self.assertEqual(self.export(inventory).status_code, 400)
            self.assertEqual(path.read_bytes(), content)

    def test_record_capacity_is_bounded_without_overwriting_existing_data(self):
        inventory = self.read()
        path = Path(self.panel.NODE_ROUTING_FILE)
        routes = {f"{i:064x}": {"enabled": False, "direct_domains": [], "revision": 0} for i in range(512)}
        content = json.dumps({"version": 1, "routes": routes}).encode("utf-8")
        path.write_bytes(content)
        response = self.save(inventory)
        self.assertEqual(response.status_code, 400, response.json)
        self.assertIn("512", response.json["msg"])
        self.assertEqual(path.read_bytes(), content)

    def test_two_editors_saving_same_revision_yield_one_conflict(self):
        inventory = self.read()
        self.save(inventory)
        with ThreadPoolExecutor(max_workers=2) as pool:
            replies = list(pool.map(lambda domain: self.save(inventory, domains=[domain], revision=1),
                                    ("first.example", "second.example")))
        self.assertEqual(sorted(reply.status_code for reply in replies), [200, 409])
        saved = self.export(inventory).json["routing"]
        self.assertEqual(saved["revision"], 2)
        self.assertIn(saved["direct_domains"], (["first.example"], ["second.example"]))

    def test_atomic_write_failure_preserves_previous_revision_and_export_url(self):
        inventory = self.read()
        self.save(inventory)
        previous = Path(self.panel.NODE_ROUTING_FILE).read_bytes()
        exported = self.export(inventory).json
        with patch("node_routing_store.atomic_json_write", side_effect=OSError("fake write failure")):
            response = self.save(inventory, domains=["changed.example"], revision=1)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("fake write failure", response.json["msg"])
        self.assertEqual(Path(self.panel.NODE_ROUTING_FILE).read_bytes(), previous)
        self.assertEqual(self.download(exported).status_code, 200)


if __name__ == "__main__":
    unittest.main()
