"""Offline studio workflows; encrypted drafts use an isolated Windows profile."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from clash_studio import ImportPreviews

PASSWORD = "fake-import-secret-not-in-metadata"


def document(*, chain=False, unknown=False):
    nodes = [{"name": "入口", "type": "ss", "server": "192.0.2.11", "port": 8443,
              "cipher": "aes-128-gcm", "password": PASSWORD},
             {"name": "出口", "type": "trojan", "server": "192.0.2.12", "port": 443,
              "password": "fake-trojan-secret", "sni": "example.com", "skip-cert-verify": False}]
    if chain:
        nodes[1]["dialer-proxy"] = "入口"
    data = {"mixed-port": 7891, "mode": "rule", "proxies": nodes,
            "proxy-groups": [{"name": "业务策略", "type": "select", "proxies": ["出口", "入口", "DIRECT"]}],
            "rules": ["DOMAIN-SUFFIX,example.cn,DIRECT", "MATCH,业务策略"],
            "dns": {"enable": True, "listen": "127.0.0.1:1053", "nameserver": ["https://dns.alidns.com/dns-query"]}}
    if unknown:
        data["proxy-providers"] = {"external": {"type": "http", "url": "https://example.invalid/subscription"}}
    return json.dumps(data, ensure_ascii=False)


class StudioApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clash-studio-api-")
        self.addCleanup(self.temporary.cleanup)
        self.base = "http://127.0.0.1:50781"
        self.panel = self.load_panel()
        self.client = self.panel.app.test_client()
        self.enterContext(patch.object(self.panel, "connect_ssh", side_effect=AssertionError("real SSH forbidden")))

    def load_panel(self):
        name = "studio_api_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, ROOT / "server-manager" / "app.py")
        panel = importlib.util.module_from_spec(spec)
        sys.modules[name] = panel
        self.addCleanup(lambda: sys.modules.pop(name, None))
        with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": self.temporary.name}):
            spec.loader.exec_module(panel)
        panel.configure_local_access(50781)
        panel.app.config["TESTING"] = True
        self.addCleanup(panel.shutdown_resources)
        return panel

    def post(self, path, data):
        return self.client.post("/api/clash-workspace/" + path, json=data, base_url=self.base,
                                headers={"X-CSRF-Token": self.panel.CSRF_TOKEN})

    def imported(self, text=None, mode="replace", snapshot=None):
        preview = self.post("import-preview", {"text": text or document(), "format": "auto"})
        self.assertEqual(preview.status_code, 200, preview.json)
        self.assertNotIn(PASSWORD, preview.get_data(as_text=True))
        result = self.post("import", {"import_token": preview.json["import_token"], "mode": mode, "snapshot_id": snapshot})
        self.assertEqual(result.status_code, 200, result.json)
        return result.json

    def draft(self, imported):
        return {"snapshot_id": imported["snapshot_id"], "node_ids": imported["imported_ids"], "profile": imported["profile"]}

    def test_complete_import_export_preserves_dns_group_and_secure_tls(self):
        imported = self.imported()
        self.assertEqual([node["origin"] for node in imported["nodes"]], ["import", "import"])
        self.assertNotIn(PASSWORD, json.dumps(imported))
        response = self.post("export", self.draft(imported))
        self.assertEqual(response.status_code, 200, response.json)
        yaml = response.json["clash"]["yaml"]
        for value in (PASSWORD, "fake-trojan-secret", "业务策略", "DOMAIN-SUFFIX,example.cn,DIRECT", "dns:"):
            self.assertIn(value, yaml)
        self.assertIn("skip-cert-verify: false", yaml)
        self.assertIn("mixed-port: 7891", yaml)

    def test_dialer_import_becomes_editable_chain(self):
        imported = self.imported(document(chain=True))
        self.assertEqual(imported["profile"]["chains"][0]["name"], "出口")
        self.assertEqual(imported["profile"]["chains"][0]["hops"], imported["imported_ids"])
        response = self.post("export", self.draft(imported))
        self.assertEqual(response.status_code, 200, response.json)
        self.assertIn("dialer-proxy", response.json["clash"]["yaml"])

    def test_merge_keeps_capabilities_and_distinct_credentials(self):
        first = self.imported()
        same = self.imported(mode="merge", snapshot=first["snapshot_id"])
        self.assertEqual([node["id"] for node in first["nodes"]], [node["id"] for node in same["nodes"]])
        raw = json.loads(document())
        raw["proxies"][0]["password"] = "another-fake-password-same-port"
        merged = self.imported(json.dumps(raw), "merge", first["snapshot_id"])
        self.assertEqual(len(merged["nodes"]), 3)
        self.assertNotEqual(merged["imported_ids"][0], first["imported_ids"][0])

    def test_renamed_reimport_exports_new_name_without_revoking_old_alias(self):
        first = self.imported()
        raw = json.loads(document())
        raw["proxies"][0]["name"] = "入口新名称"
        raw["proxy-groups"][0]["proxies"] = ["出口", "入口新名称", "DIRECT"]
        renamed = self.imported(json.dumps(raw))
        result = self.post("export", self.draft(renamed))
        self.assertEqual(result.status_code, 200, result.json)
        self.assertIn("入口新名称", result.json["clash"]["yaml"])
        self.assertIsNotNone(self.panel.CLASH_EXPORTS.get_proxy(first["imported_ids"][0]))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI draft encryption")
    def test_distinct_names_same_connection_survive_import_save_and_open(self):
        raw = json.loads(document())
        alias = {**raw["proxies"][0], "name": "入口别名"}
        raw["proxies"].append(alias)
        raw["proxy-groups"][0]["proxies"].append(alias["name"])
        imported = self.imported(json.dumps(raw))
        self.assertEqual(len(imported["nodes"]), 3)
        self.assertEqual(len(set(imported["imported_ids"])), 3)
        saved = self.post("profiles/save", self.draft(imported))
        self.assertEqual(saved.status_code, 200, saved.json)
        self.panel.CLASH_EXPORTS.clear()
        reopened = self.post("profiles/open", {"profile_id": saved.json["profile"]["id"]})
        self.assertEqual(reopened.status_code, 200, reopened.json)
        self.assertEqual(len(set(reopened.json["imported_ids"])), 3)
        result = self.post("export", self.draft(reopened.json))
        self.assertEqual(result.status_code, 200, result.json)
        self.assertIn("入口别名", result.json["clash"]["yaml"])

    def test_unknown_provider_blocks_replace_but_allows_explicit_merge(self):
        preview = self.post("import-preview", {"text": document(unknown=True), "format": "yaml"})
        self.assertEqual(preview.status_code, 200, preview.json)
        self.assertFalse(preview.json["can_replace"])
        self.assertIn("proxy-providers", preview.json["omitted_fields"])
        body = {"import_token": preview.json["import_token"], "mode": "replace"}
        self.assertEqual(self.post("import", body).status_code, 400)
        body["mode"] = "merge"
        self.assertEqual(self.post("import", body).status_code, 200)

    def test_expired_preview_and_snapshot_require_fresh_input(self):
        now = [0.0]
        self.panel.CLASH_IMPORT_PREVIEWS = ImportPreviews(clock=lambda: now[0])
        preview = self.post("import-preview", {"text": document()}).json
        now[0] = 600
        self.assertEqual(self.post("import", {"import_token": preview["import_token"], "mode": "replace"}).status_code, 409)
        imported = self.imported()
        self.panel.CLASH_SNAPSHOTS.clear()
        self.assertEqual(self.post("profiles/save", self.draft(imported)).status_code, 409)

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI draft encryption")
    def test_encrypted_save_restart_open_and_export(self):
        imported = self.imported(document(chain=True))
        saved = self.post("profiles/save", self.draft(imported))
        self.assertEqual(saved.status_code, 200, saved.json)
        key = saved.json["profile"]["id"]
        data_file = Path(self.temporary.name) / "clash-profiles.json"
        raw = data_file.read_bytes()
        for secret in (PASSWORD, "fake-trojan-secret", "192.0.2.11"):
            self.assertNotIn(secret.encode(), raw)
        self.assertIn(b"dpapi:v1:", raw)
        self.panel = self.load_panel()
        self.client = self.panel.app.test_client()
        opened = self.post("profiles/open", {"profile_id": key})
        self.assertEqual(opened.status_code, 200, opened.json)
        self.assertNotEqual(imported["snapshot_id"], opened.json["snapshot_id"])
        self.assertNotIn(PASSWORD, opened.get_data(as_text=True))
        self.assertTrue(all(node["origin"] == "saved" for node in opened.json["nodes"]))
        exported = self.post("export", self.draft(opened.json))
        self.assertEqual(exported.status_code, 200, exported.json)
        self.assertIn(PASSWORD, exported.json["clash"]["yaml"])

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI draft encryption")
    def test_save_revision_conflict_and_delete(self):
        imported = self.imported()
        body = self.draft(imported)
        saved = self.post("profiles/save", body).json["profile"]
        body.update(profile_id=saved["id"], expected_revision=1)
        self.assertEqual(self.post("profiles/save", body).json["profile"]["revision"], 2)
        self.assertEqual(self.post("profiles/save", body).status_code, 409)
        self.assertEqual(self.post("profiles/delete", {"profile_id": saved["id"], "expected_revision": 1}).status_code, 409)
        self.assertEqual(self.post("profiles/delete", {"profile_id": saved["id"], "expected_revision": 2}).status_code, 200)
        self.assertEqual(self.post("profiles/open", {"profile_id": saved["id"]}).status_code, 409)

    def test_imported_node_exclusive_routing_is_supported(self):
        imported = self.imported()
        data = {"snapshot_id": imported["snapshot_id"], "node_id": imported["imported_ids"][1]}
        saved = self.client.post("/api/node-routing/save", json={**data, "enabled": True, "direct_domains": ["example.cn"],
                                  "expected_revision": 0}, base_url=self.base, headers={"X-CSRF-Token": self.panel.CSRF_TOKEN})
        self.assertEqual(saved.status_code, 200, saved.json)
        exported = self.client.post("/api/node-routing/export", json=data, base_url=self.base,
                                    headers={"X-CSRF-Token": self.panel.CSRF_TOKEN})
        self.assertEqual(exported.status_code, 200, exported.json)
        self.assertIn("DOMAIN-SUFFIX,example.cn,DIRECT", exported.json["clash"]["yaml"])
        self.assertNotIn(PASSWORD, exported.json["clash"]["yaml"])

    def test_guards_errors_and_import_size_do_not_expose_credentials(self):
        for path in ("import-preview", "import", "profiles/save", "profiles/open", "profiles/delete"):
            response = self.client.post("/api/clash-workspace/" + path, json={}, base_url=self.base)
            self.assertEqual(response.status_code, 403, path)
        for body in ({"text": PASSWORD}, {"text": "x" * (512 * 1024 + 1)}, {"text": document(), "format": "execute"},
                     {"text": "!!python/object/apply:os.system ['echo forbidden']", "format": "yaml"}):
            response = self.post("import-preview", body)
            self.assertEqual(response.status_code, 400, response.json)
            self.assertNotIn(PASSWORD, response.get_data(as_text=True))

    def test_server_refresh_keeps_imported_nodes_even_when_old_server_capability_changed(self):
        imported = self.imported()
        srv = {"id": "1" * 32, "name": "隔离服务器", "host": "192.0.2.20", "port": 22, "user": "root"}
        old_proxy = {"name": "旧服务器节点", "type": "ss", "server": srv["host"], "port": 600,
                     "cipher": "aes-128-gcm", "password": "fake-server-only"}
        token = self.panel.CLASH_EXPORTS.register("fake", self.panel._clash_scope(srv), "old", "fake.yaml", proxy=old_proxy)
        combined = self.panel.CLASH_SNAPSHOTS.register(imported["nodes"] + [{"id": token, "origin": "server", "available": True}])
        self.panel.CLASH_EXPORTS.revoke_scope(self.panel._clash_scope(srv))
        with patch.object(self.panel, "get_server", return_value=srv), patch.object(self.panel, "_read_node_items", return_value={"ok": True, "inbounds": []}):
            result = self.post("read", {"server_ids": [srv["id"]], "snapshot_id": combined})
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual([node["id"] for node in result.json["nodes"]], imported["imported_ids"])

    def test_source_change_during_save_cannot_persist_obsolete_draft(self):
        imported = self.imported()
        import clash_studio
        build = clash_studio.build_workspace_configuration
        def source_changed(*args, **kwargs):
            result = build(*args, **kwargs)
            self.panel.CLASH_EXPORTS.clear()
            return result
        with patch.object(clash_studio, "build_workspace_configuration", side_effect=source_changed):
            result = self.post("profiles/save", self.draft(imported))
        self.assertEqual(result.status_code, 409, result.json)
        self.assertFalse((Path(self.temporary.name) / "clash-profiles.json").exists())


if __name__ == "__main__":
    unittest.main()
