import base64
import copy
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.parse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from clash_export import (ExportCache, TOKEN_PATTERN, UnsupportedExport, compatibility,
                          configuration, proxy_from_inbound, proxy_from_uri, yaml_configuration)

_PROFILE = tempfile.TemporaryDirectory(prefix="flnetwork-clash-tests-")
with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": _PROFILE.name}):
    spec = importlib.util.spec_from_file_location("clash_export_test_panel", ROOT / "server-manager" / "app.py")
    panel = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = panel
    spec.loader.exec_module(panel)

UID = "11111111-2222-4333-8444-555555555555"
PUBLIC = base64.urlsafe_b64encode(b"P" * 32).decode().rstrip("=")


def tearDownModule():
    _PROFILE.cleanup()


def vless_uri(security="none", network="ws", **extra):
    options = {"encryption": "none", "security": security, "type": network,
               "path": "/a b?x=1&z=2", **extra}
    return f"vless://{UID}@[2001:db8::1]:600?" + urllib.parse.urlencode(options) + "#" + urllib.parse.quote("测试: # 节点")


def inbound(protocol="vless", security="none", network="ws"):
    return {"tag": "test-node", "port": 600, "protocol": protocol,
            "settings": {"clients": [{"id": UID, "alterId": 0}], "decryption": "none"},
            "streamSettings": {"network": network, "security": security,
                               "wsSettings": {"path": "/actual", "headers": {"Host": "cdn.example.test"}}}}


class ClashConversionTests(unittest.TestCase):
    def test_vless_ws_ipv6_and_percent_encoded_path_host(self):
        proxy = proxy_from_uri(vless_uri(host="cdn.example.test"))
        self.assertEqual(proxy["server"], "2001:db8::1")
        self.assertEqual(proxy["port"], 600)
        self.assertEqual(proxy["uuid"], UID)
        self.assertFalse(proxy["tls"])
        self.assertEqual(proxy["ws-opts"], {"path": "/a b?x=1&z=2", "headers": {"Host": "cdn.example.test"}})
        self.assertEqual(compatibility(proxy)[0], "mihomo")

    def test_reality_public_short_id_sni_fingerprint_and_flow(self):
        proxy = proxy_from_uri(vless_uri("reality", "tcp", pbk=PUBLIC, sid="01ab", sni="www.example.test",
                                         fp="chrome", flow="xtls-rprx-vision"))
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")
        self.assertEqual(proxy["servername"], "www.example.test")
        self.assertEqual(proxy["client-fingerprint"], "chrome")
        self.assertEqual(proxy["reality-opts"], {"public-key": PUBLIC, "short-id": "01ab"})
        self.assertNotIn("skip-cert-verify", proxy)

    def test_vmess_ws_preserves_tls_sni_alterid_and_host(self):
        data = {"ps": "VMess", "add": "2001:db8::2", "port": "7443", "id": UID,
                "aid": "0", "net": "ws", "path": "/x?a=1", "host": "cdn.example.test",
                "tls": "tls", "sni": "tls.example.test"}
        proxy = proxy_from_uri("vmess://" + base64.b64encode(json.dumps(data).encode()).decode())
        self.assertEqual(proxy["alterId"], 0)
        self.assertEqual(proxy["cipher"], "auto")
        self.assertEqual(proxy["server"], "2001:db8::2")
        self.assertEqual(proxy["ws-opts"]["headers"]["Host"], "cdn.example.test")
        self.assertEqual(proxy["servername"], "tls.example.test")
        self.assertTrue(proxy["tls"])
        self.assertEqual(compatibility(proxy)[0], "classic")

    def test_sip002_all_six_methods_and_password_colon(self):
        methods = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                   "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]
        for method in methods:
            with self.subTest(method=method):
                size = 16 if method.endswith("128-gcm") else 32
                password = base64.b64encode(b"K" * size).decode() if method.startswith("2022") else "a:b #?%"
                credential = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
                proxy = proxy_from_uri(f"ss://{credential}@[2001:db8::3]:600#ss")
                self.assertEqual(proxy["cipher"], method)
                self.assertEqual(proxy["password"], password)
                self.assertEqual(compatibility(proxy)[0], "mihomo" if method.startswith("2022") else "classic")

    def test_sip002_percent_encoded_plain_userinfo(self):
        proxy = proxy_from_uri("ss://aes-128-gcm:a%3Ab%20%23%3F@198.51.100.1:600#SS")
        self.assertEqual(proxy["password"], "a:b #?")

    def test_actual_inbound_retains_ws_headers_and_tls_even_if_legacy_uri_drops_them(self):
        actual = inbound(security="tls")
        actual["streamSettings"]["tlsSettings"] = {"serverName": "certificate.example.test", "alpn": ["http/1.1"]}
        before = copy.deepcopy(actual)
        proxy = proxy_from_inbound(actual, "192.0.2.1", 8443, uri=vless_uri())
        self.assertTrue(proxy["tls"])
        self.assertEqual(proxy["servername"], "certificate.example.test")
        self.assertEqual(proxy["ws-opts"]["path"], "/actual")
        self.assertEqual(proxy["ws-opts"]["headers"], {"Host": "cdn.example.test"})
        self.assertNotIn("skip-cert-verify", proxy)
        self.assertEqual(actual, before)

    def test_actual_reality_never_exports_private_key_or_ssh_credentials(self):
        actual = inbound(security="reality", network="tcp")
        actual["settings"]["clients"][0]["flow"] = "xtls-rprx-vision"
        actual["streamSettings"]["realitySettings"] = {"privateKey": "PRIVATE-NEVER-EXPORT",
                                                       "serverNames": ["www.example.test"], "shortIds": ["12ab"]}
        proxy = proxy_from_inbound(actual, "192.0.2.1", 600,
                                  uri=vless_uri("reality", "tcp", pbk=PUBLIC, sid="12ab", fp="chrome"))
        text = yaml_configuration(proxy)
        self.assertNotIn("PRIVATE-NEVER-EXPORT", text)
        self.assertIn(PUBLIC, text)
        self.assertIn('short-id: "12ab"', text)

    def test_relay_exports_entry_address_and_exit_credentials(self):
        actual = inbound(protocol="vmess")
        proxy = proxy_from_inbound(actual, "entry.example.test", 1600)
        self.assertEqual((proxy["server"], proxy["port"], proxy["uuid"]), ("entry.example.test", 1600, UID))

    def test_special_strings_are_quoted_yaml_not_injected_documents(self):
        actual = {"tag": "x\n---\nproxies: [] #", "protocol": "shadowsocks",
                  "settings": {"method": "aes-128-gcm", "password": 'p\n"# null: true\\suffix'}}
        proxy = proxy_from_inbound(actual, "192.0.2.1", 600)
        text = yaml_configuration(proxy)
        self.assertIn('name: "x\\n---\\nproxies: [] #"', text)
        self.assertIn('password: "p\\n\\"# null: true\\\\suffix"', text)
        config = configuration(proxy)
        self.assertFalse(config["allow-lan"])
        self.assertEqual(config["bind-address"], "127.0.0.1")
        self.assertEqual(config["rules"], ["MATCH,FL Network"])
        self.assertNotIn("proxy-providers", config)

    def test_builtin_policy_names_are_not_used_as_node_name(self):
        actual = inbound()
        for name in ("DIRECT", "REJECT", "GLOBAL", "FL Network"):
            with self.subTest(name=name):
                proxy = proxy_from_inbound(actual, "192.0.2.1", 600, name=name)
                self.assertNotEqual(proxy["name"], name)

    def test_invalid_uris_and_unsupported_features_fail_safely(self):
        cases = ["trojan://secret@example.test:443", "vless://bad@example.test:600?type=ws",
                 vless_uri("reality", "tcp", pbk="bad", sid="01ab"),
                 vless_uri("reality", "tcp", pbk=PUBLIC, sid="abc"),
                 vless_uri(network="grpc"), vless_uri(flow="xtls-rprx-vision"),
                 "ss://bad@192.0.2.1:600", "vmess://%%%%",
                 "vless://" + UID + "@example.test:70000?type=ws",
                 "vless://" + UID + ":secret@example.test:600?type=ws",
                 "ss://aes-128-gcm:password@example.test:600?plugin=obfs"]
        for uri in cases:
            with self.subTest(uri=uri):
                with self.assertRaises((UnsupportedExport, ValueError)):
                    proxy_from_uri(uri)
        duplicate = vless_uri().replace("security=none", "security=none&security=tls")
        with self.assertRaises(UnsupportedExport):
            proxy_from_uri(duplicate)

    def test_unknown_xray_transport_and_tcp_headers_do_not_become_usable_configs(self):
        for actual in (inbound(network="grpc"), {"protocol": "dokodemo-door"},
                       {**inbound(network="tcp"), "streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "http"}}}}):
            with self.subTest(actual=actual):
                with self.assertRaises(UnsupportedExport):
                    proxy_from_inbound(actual, "192.0.2.1", 600)

    def test_invalid_ss2022_key_is_refused(self):
        actual = {"protocol": "shadowsocks", "settings": {"method": "2022-blake3-aes-128-gcm", "password": "bad"}}
        with self.assertRaises(UnsupportedExport):
            proxy_from_inbound(actual, "192.0.2.1", 600)


class ExportCacheTests(unittest.TestCase):
    def test_expiry_rotation_and_missing_tokens(self):
        now = [10.0]
        cache = ExportCache(ttl=5, clock=lambda: now[0])
        token = cache.register("fake yaml", "scope", "node", "test.yaml")
        self.assertRegex(token, "^" + TOKEN_PATTERN + "$")
        self.assertEqual(cache.get(token), {"yaml": "fake yaml", "filename": "test.yaml"})
        newer = cache.register("new yaml", "scope", "node", "test.yaml")
        self.assertNotEqual(newer, token)
        self.assertIsNone(cache.get(token))
        now[0] = 15
        self.assertIsNone(cache.get(newer))
        self.assertIsNone(cache.get("garbage"))

    def test_capacity_and_targeted_revoke(self):
        cache = ExportCache(capacity=2)
        first = cache.register("one", "a", "1", "one.yaml")
        second = cache.register("two", "a", "2", "two.yaml")
        third = cache.register("three", "b", "3", "three.yaml")
        self.assertIsNone(cache.get(first))
        cache.revoke_scope("a")
        self.assertIsNone(cache.get(second))
        self.assertIsNotNone(cache.get(third))
        cache.clear()
        self.assertIsNone(cache.get(third))


class ClashPanelTests(unittest.TestCase):
    def setUp(self):
        panel.CLASH_EXPORTS.clear()
        panel._SHUTTING_DOWN = False
        panel._ACCEPTING_JOBS = True
        panel.jobs.clear()
        panel.configure_local_access(50777)
        self.srv = {"id": "fake", "name": "Fake", "host": "192.0.2.1", "port": 22,
                    "user": "root", "password": "SSH-NEVER-EXPORT"}
        self.actual = {"tag": "test-ss", "port": 600, "protocol": "shadowsocks",
                       "settings": {"method": "aes-128-gcm", "password": "fake-export-password", "network": "tcp,udp"}}
        self.client = panel.app.test_client()
        self.base = "http://127.0.0.1:50777"
        # Every possible disk read / network entry in these integration tests is
        # replaced. No saved project or user server credentials are accessed.
        for name, replacement in (("get_server", lambda sid: self.srv if sid == "fake" else None),
                                  ("load_json", lambda path, default: [self.srv]),
                                  ("save_json", lambda *args: None),
                                  ("connect", lambda *args, **kwargs: MagicMock()),
                                  ("_read_xray_cfg", lambda ssh: {"inbounds": [copy.deepcopy(self.actual)]}),
                                  ("_apply_xray_cfg", lambda *args, **kwargs: None),
                                  ("run_checked", lambda *args, **kwargs: "OK")):
            mocked = patch.object(panel, name, side_effect=replacement)
            mocked.start()
            self.addCleanup(mocked.stop)

    def export(self):
        return panel._register_clash_export(self.srv, self.actual, self.srv["host"], 600)

    def get_export(self, result, **kwargs):
        path = urllib.parse.urlsplit(result["url"]).path
        return self.client.get(path, base_url=self.base, **kwargs)

    def post(self, path, body):
        return self.client.post(path, json=body, base_url=self.base,
                                headers={"X-CSRF-Token": panel.CSRF_TOKEN})

    def test_download_no_csrf_uses_bearer_and_safe_response_headers(self):
        result = self.export()
        self.assertTrue(result["available"])
        self.assertEqual(result["compatibility"], "classic")
        self.assertTrue(result["url"].startswith(self.base + "/api/clash-export/"))
        self.assertEqual(result["import_url"], "clash://install-config?url=" + urllib.parse.quote(result["url"], safe=""))
        self.assertNotIn("SSH-NEVER-EXPORT", result["yaml"])
        response = self.get_export(result)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), result["yaml"])
        self.assertIn("yaml", response.content_type)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)
        self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_export_host_origin_and_other_csrf_routes_remain_protected(self):
        result = self.export()
        path = urllib.parse.urlsplit(result["url"]).path
        self.assertEqual(self.client.get(path, base_url="http://attacker.test:50777").status_code, 403)
        self.assertEqual(self.client.get(path, base_url="http://127.0.0.1:8620").status_code, 403)
        self.assertEqual(self.get_export(result, headers={"Origin": "https://attacker.test"}).status_code, 403)
        self.assertEqual(self.client.get("/api/servers", base_url=self.base).status_code, 403)
        self.assertEqual(self.client.post(path, base_url=self.base).status_code, 403)
        self.assertEqual(self.client.head(path, base_url=self.base).status_code, 403)
        self.assertEqual(self.client.get("/api/clash-export/not-a-token.yaml", base_url=self.base).status_code, 403)

    def test_unknown_expired_and_rotated_exports_return_404(self):
        result = self.export()
        self.export()
        self.assertEqual(self.get_export(result).status_code, 404)
        response = self.client.get("/api/clash-export/" + "A" * 43 + ".yaml", base_url=self.base)
        self.assertEqual(response.status_code, 404)

    def test_node_list_adds_clash_preserves_share_and_rotates_exports(self):
        first = self.post("/api/nodes/list", {"server": "fake"}).get_json()
        item = first["inbounds"][0]
        self.assertTrue(item["link"].startswith("ss://"))
        self.assertTrue(item["clash"]["available"])
        self.assertEqual(self.get_export(item["clash"]).status_code, 200)
        second = self.post("/api/nodes/list", {"server": "fake"}).get_json()["inbounds"][0]
        self.assertEqual(second["link"], item["link"])
        self.assertNotEqual(second["clash"]["url"], item["clash"]["url"])
        self.assertEqual(self.get_export(item["clash"]).status_code, 404)
        self.assertEqual(self.get_export(second["clash"]).status_code, 200)

    def test_delete_node_revokes_only_successful_target_export(self):
        result = self.export()
        token = panel._node_token(self.srv, self.actual)
        rejected = self.post("/api/nodes/delete", {"server": "fake", "tag": "wrong", "token": token}).get_json()
        self.assertFalse(rejected["ok"])
        self.assertEqual(self.get_export(result).status_code, 200)
        deleted = self.post("/api/nodes/delete", {"server": "fake", "tag": self.actual["tag"], "token": token}).get_json()
        self.assertTrue(deleted["ok"])
        self.assertEqual(self.get_export(result).status_code, 404)

    def test_delete_server_revokes_exports(self):
        result = self.export()
        response = self.client.delete("/api/servers/fake", base_url=self.base,
                                      headers={"X-CSRF-Token": panel.CSRF_TOKEN})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.get_export(result).status_code, 404)

    def test_unsupported_configs_have_no_fake_download_link(self):
        result = panel._register_clash_export(self.srv, inbound(network="grpc"), self.srv["host"], 600)
        self.assertFalse(result["available"])
        self.assertNotIn("url", result)
        self.assertNotIn("yaml", result)

    def test_reality_notice_explains_core_and_version_compatibility(self):
        actual = inbound(security="reality", network="tcp")
        actual["settings"]["clients"][0]["flow"] = "xtls-rprx-vision"
        actual["streamSettings"]["realitySettings"] = {"serverNames": ["www.example.test"], "shortIds": ["12ab"]}
        result = panel._register_clash_export(self.srv, actual, self.srv["host"], 600,
                                             vless_uri("reality", "tcp", pbk=PUBLIC, sid="12ab", fp="chrome"))
        self.assertTrue(result["available"])
        self.assertEqual(result["compatibility"], "mihomo")
        self.assertIn("旧版 Clash", result["notice"])
        self.assertIn("新版 Xray", result["notice"])
        self.assertIn("24 小时", result["notice"])

    def test_shutdown_clears_capabilities(self):
        result = self.export()
        panel.shutdown_resources()
        self.assertEqual(self.get_export(result).status_code, 404)

    def test_capability_is_redacted_in_source_access_logs(self):
        token = "A" * 43
        record = logging.LogRecord("werkzeug", logging.INFO, __file__, 1, "%s", (f"GET /api/clash-export/{token}.yaml HTTP/1.1",), None)
        panel._ClashCapabilityLogFilter().filter(record)
        self.assertNotIn(token, record.getMessage())
        self.assertIn("[redacted]", record.getMessage())


if __name__ == "__main__":
    unittest.main()
