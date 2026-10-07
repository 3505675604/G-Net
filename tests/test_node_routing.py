"""No-network domain routing and faithful single-node export checks."""
import base64
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from clash_export import UnsupportedExport
from node_routing import (MAX_DIRECT_DOMAINS, NODE_GROUP, build_node_routing,
                          normalize_direct_domains, normalize_routing, stable_routing_key)

UID = "11111111-2222-4333-8444-555555555555"
PUBLIC = base64.urlsafe_b64encode(b"P" * 32).decode().rstrip("=")


def proxy(protocol="vless"):
    common = {"name": "测试节点", "type": protocol, "server": "192.0.2.12", "port": 443, "udp": True}
    if protocol == "ss":
        return {**common, "cipher": "aes-128-gcm", "password": "fake-password"}
    common.update(uuid=UID, network="tcp", tls=False)
    if protocol == "vmess":
        common.update(alterId=0, cipher="auto")
    return common


class DirectDomainTests(unittest.TestCase):
    def test_multiple_idn_case_trailing_dot_and_deduplication(self):
        self.assertEqual(normalize_direct_domains(["Example.COM", "例子.测试", "example.com.", "WWW.Example.COM"]),
                         ["example.com", "xn--fsqu00a.xn--0zwm56d", "www.example.com"])

    def test_empty_list_and_no_alias_to_input(self):
        values = ["example.com"]
        result = normalize_direct_domains(values)
        result.append("other.example")
        self.assertEqual(values, ["example.com"])
        self.assertEqual(normalize_direct_domains([]), [])

    def test_limits(self):
        self.assertEqual(len(normalize_direct_domains([f"d{n}.example" for n in range(MAX_DIRECT_DOMAINS)])), 128)
        for values in (["example.com"] * 129, ["a" * 64 + ".com"], ["a." * 127 + "a"]):
            with self.subTest(values=values):
                with self.assertRaises(UnsupportedExport):
                    normalize_direct_domains(values)

    def test_rejects_ip_url_paths_wildcards_controls_and_rule_injection(self):
        invalid = ["", "localhost", "192.168.0.1", "2001:db8::1", "[::1]", "1.2.3.999",
                   "https://example.com", "example.com/a", "example.com\\a", "example.com:443",
                   "*.example.com", "example.com,DIRECT", "example.com\nMATCH,REJECT", "exam\u200bple.com",
                   " example.com", "example.com ", "x..example.com", "-bad.example", "bad-.example", ".com",
                   "example.com..", "user@example.com", "example.com?x=1", "example.com#x", "\ud800.com"]
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises(UnsupportedExport):
                    normalize_direct_domains([value])
        for values in (None, {}, "example.com", [None], [True], [123]):
            with self.assertRaises(UnsupportedExport):
                normalize_direct_domains(values)

    def test_strict_policy_types(self):
        self.assertEqual(normalize_routing({}), {"enabled": False, "direct_domains": [], "revision": 0})
        self.assertEqual(normalize_routing({"enabled": True, "direct_domains": ["Example.COM"], "revision": 2}),
                         {"enabled": True, "direct_domains": ["example.com"], "revision": 2})
        for value in (None, [], {"enabled": 1}, {"enabled": "true"}, {"revision": True},
                      {"revision": -1}, {"revision": "1"}, {"revision": 1.5}):
            with self.assertRaises(UnsupportedExport):
                normalize_routing(value)


class StableIdentityTests(unittest.TestCase):
    def test_key_stable_across_reordering_and_display_renames(self):
        original = proxy()
        key = stable_routing_key("a" * 32, ("EXAMPLE.COM", "22"), original)
        changed = {key: value for key, value in reversed(list(original.items()))}
        changed["name"] = "其他名称"
        self.assertEqual(key, stable_routing_key("A" * 32, ("example.com", 22), changed))
        self.assertRegex(key, "^[0-9a-f]{64}$")
        self.assertNotIn(UID, key)

    def test_changes_server_scope_protocol_credentials_and_transport(self):
        original = proxy()
        baseline = stable_routing_key("a" * 32, ("192.0.2.1", 22), original)
        for node in ({**original, "server": "192.0.2.13"}, {**original, "port": 444},
                     {**original, "uuid": "21111111-2222-4333-8444-555555555555"},
                     {**original, "network": "ws"}, proxy("ss")):
            self.assertNotEqual(baseline, stable_routing_key("a" * 32, ("192.0.2.1", 22), node))
        self.assertNotEqual(baseline, stable_routing_key("b" * 32, ("192.0.2.1", 22), original))
        self.assertNotEqual(baseline, stable_routing_key("a" * 32, ("192.0.2.2", 22), original))
        self.assertNotEqual(baseline, stable_routing_key("a" * 32, ("192.0.2.1", 23), original))

    def test_ipv6_scope_canonicalization_and_invalid_identity(self):
        self.assertRegex(stable_routing_key("manual", ("192.0.2.1", 22), proxy()), "^[0-9a-f]{64}$")
        self.assertEqual(stable_routing_key("a" * 32, ("2001:db8::1", 22), proxy()),
                         stable_routing_key("a" * 32, ("2001:0db8:0:0:0:0:0:1", 22), proxy()))
        for sid, scope, node in (("bad", ("example.com", 22), proxy()), ("a" * 32, (), proxy()),
                                 ("a" * 32, ("host/path", 22), proxy()),
                                 ("a" * 32, ("example.com", True), proxy()),
                                 ("a" * 32, ("example.com", 22), []),
                                 ("a" * 32, ("example.com", 22), {"x": float("nan")})):
            with self.assertRaises(UnsupportedExport):
                stable_routing_key(sid, scope, node)


class NodeRoutingExportTests(unittest.TestCase):
    def build(self, node=None, **routing):
        return build_node_routing(node or proxy(), {"enabled": True, "direct_domains": ["example.com", "other.example"], **routing})

    def test_exact_node_allowlist_and_fixed_fallback(self):
        result = self.build()
        clash = result["clash"]["config"]
        self.assertEqual(len(clash["proxies"]), 1)
        self.assertEqual(clash["proxy-groups"], [{"name": NODE_GROUP, "type": "select", "proxies": ["测试节点"]}])
        self.assertEqual(clash["rules"], ["DOMAIN-SUFFIX,example.com,DIRECT", "DOMAIN-SUFFIX,other.example,DIRECT", "MATCH,专属节点"])
        xray = result["xray"]["config"]
        self.assertEqual(xray["routing"]["rules"], [
            {"type": "field", "domain": ["domain:example.com", "domain:other.example"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}])
        self.assertEqual([item["tag"] for item in xray["outbounds"]], ["proxy", "direct"])
        self.assertEqual(xray["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"], UID)

    def test_omitted_or_disabled_allowlist_is_all_proxy_without_geoip_lan(self):
        for settings in ({"direct_domains": []}, {"enabled": False}, {"enabled": False, "direct_domains": []}):
            result = self.build(**settings)
            self.assertEqual(result["clash"]["config"]["rules"], ["MATCH,专属节点"])
            self.assertEqual(result["xray"]["config"]["routing"]["rules"],
                             [{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}])
            self.assertNotIn("GEOIP", result["clash"]["yaml"])
            self.assertNotIn("geoip:", result["xray"]["json"])

    def test_two_nodes_are_isolated_and_inputs_are_not_mutated(self):
        node_a, node_b = proxy(), {**proxy(), "server": "198.51.100.2", "name": "另一节点"}
        routing_a = {"enabled": True, "direct_domains": ["a.example"]}
        routing_b = {"enabled": True, "direct_domains": ["b.example"]}
        original = copy.deepcopy((node_a, node_b, routing_a, routing_b))
        a, b = build_node_routing(node_a, routing_a), build_node_routing(node_b, routing_b)
        for text in (a["clash"]["yaml"], a["xray"]["json"]):
            self.assertNotIn("b.example", text)
            self.assertNotIn("198.51.100.2", text)
        for text in (b["clash"]["yaml"], b["xray"]["json"]):
            self.assertNotIn("a.example", text)
            self.assertNotIn("192.0.2.12", text)
        self.assertEqual((node_a, node_b, routing_a, routing_b), original)
        a["clash"]["config"]["proxies"][0]["name"] = "mutated"
        self.assertEqual(node_a["name"], "测试节点")

    def test_local_only_ports_and_sniffing_no_network_controller(self):
        result = build_node_routing(proxy(), {}, mixed_port=7900, socks_port=11080, http_port=11081)
        clash, xray = result["clash"]["config"], result["xray"]["config"]
        self.assertEqual(clash["mixed-port"], 7900)
        self.assertFalse(clash["allow-lan"])
        self.assertEqual(clash["bind-address"], "127.0.0.1")
        self.assertNotIn("external-controller", clash)
        self.assertEqual([item["port"] for item in xray["inbounds"]], [11080, 11081])
        for inbound in xray["inbounds"]:
            self.assertEqual(inbound["listen"], "127.0.0.1")
            self.assertTrue(inbound["sniffing"]["enabled"])
            self.assertTrue(inbound["sniffing"]["routeOnly"])
        self.assertTrue(xray["inbounds"][0]["settings"]["udp"])
        self.assertNotIn("api", xray)

    def test_json_and_yaml_syntax_unicode_and_name_rule_injection(self):
        for name in ("DIRECT", "REJECT", "GLOBAL", "专属节点", "x,DIRECT\nMATCH,REJECT"):
            result = self.build({**proxy(), "name": name})
            clean = result["clash"]["config"]["proxies"][0]["name"]
            self.assertNotIn(",", clean)
            self.assertNotIn("\n", clean)
            self.assertNotIn(clean, ("DIRECT", "REJECT", "GLOBAL", "专属节点"))
            self.assertEqual(len(result["clash"]["config"]["rules"]), 3)
            self.assertEqual(json.loads(result["xray"]["json"]), result["xray"]["config"])
            self.assertTrue(result["xray"]["json"].endswith("\n"))
        result = self.build(direct_domains=["例子.测试"])
        self.assertIn("DOMAIN-SUFFIX,xn--fsqu00a.xn--0zwm56d,DIRECT", result["clash"]["yaml"])
        self.assertIn("domain:xn--fsqu00a.xn--0zwm56d", result["xray"]["json"])

    def test_reality_tls_vision_are_preserved_without_server_private_key(self):
        node = {**proxy(), "tls": True, "servername": "www.example.test", "client-fingerprint": "chrome",
                "reality-opts": {"public-key": PUBLIC, "short-id": "01ab"}, "flow": "xtls-rprx-vision"}
        result = self.build(node)
        outbound = result["xray"]["config"]["outbounds"][0]
        reality = outbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["password"], PUBLIC)
        self.assertEqual(reality["publicKey"], PUBLIC)
        self.assertEqual(reality["shortId"], "01ab")
        self.assertEqual(reality["fingerprint"], "chrome")
        self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        for text in (result["clash"]["yaml"], result["xray"]["json"]):
            self.assertNotIn("privateKey", text)
            self.assertNotIn("skip-cert-verify", text)
            self.assertNotIn("allowInsecure", text)

    def test_ws_path_headers_tls_sni_and_alpn_are_preserved(self):
        node = {**proxy("vmess"), "network": "ws", "tls": True, "servername": "tls.example.test",
                "alpn": ["http/1.1"], "ws-opts": {"path": "/a?x=1&y=2", "headers": {"Host": "cdn.example.test", "X-Test": "value"}}}
        result = self.build(node)
        stream = result["xray"]["config"]["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["wsSettings"], {"path": "/a?x=1&y=2", "host": "cdn.example.test", "headers": {"X-Test": "value"}})
        self.assertEqual(stream["tlsSettings"], {"allowInsecure": False, "serverName": "tls.example.test", "alpn": ["http/1.1"]})

    def test_shadowsocks_all_supported_ciphers_credentials_and_udp_notice(self):
        methods = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
                   "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]
        for method in methods:
            password = base64.b64encode(b"K" * (16 if method.endswith("128-gcm") else 32)).decode() if method.startswith("2022") else "fake:p #?%"
            result = self.build({**proxy("ss"), "cipher": method, "password": password, "udp": False})
            out = result["xray"]["config"]["outbounds"][0]
            self.assertEqual(out["protocol"], "shadowsocks")
            self.assertEqual(out["settings"]["servers"][0]["password"], password)
            self.assertEqual(out["settings"]["servers"][0]["method"], method)
            self.assertFalse(result["clash"]["config"]["proxies"][0]["udp"])
            self.assertTrue(any("UDP" in message for message in result["warnings"]))

    def test_legacy_vmess_is_explicitly_clash_only(self):
        result = self.build({**proxy("vmess"), "alterId": 64})
        self.assertTrue(result["clash"]["available"])
        self.assertEqual(result["clash"]["config"]["proxies"][0]["alterId"], 64)
        self.assertFalse(result["xray"]["available"])
        self.assertNotIn("json", result["xray"])
        self.assertNotIn("config", result["xray"])
        self.assertIn("alterId", result["xray"]["notice"])
        self.assertTrue(self.build(proxy("vmess"))["xray"]["available"])

    def test_rejects_unsafe_extensions_invalid_nodes_and_ports(self):
        bad = [{**proxy(), "privateKey": "do-not-export"}, {**proxy(), "skip-cert-verify": "true"},
               {**proxy(), "network": "invalid"}, {**proxy(), "tls": "true"}, {**proxy(), "uuid": "bad"},
               {**proxy(), "port": True}, {**proxy(), "udp": 1}, {**proxy(), "flow": "unknown"},
               {**proxy("vmess"), "alterId": True}, {**proxy("ss"), "cipher": "unknown"},
               {**proxy("ss"), "cipher": "2022-blake3-aes-128-gcm", "password": "invalid"},
               {**proxy(), "tls": True, "reality-opts": {"public-key": "bad", "short-id": "0"}},
               {**proxy(), "network": "ws", "ws-opts": {"headers": {"X-Test": "line\nsecond"}}}, []]
        for node in bad:
            with self.subTest(node=node):
                with self.assertRaises(UnsupportedExport):
                    build_node_routing(node, {})
        for ports in ({"mixed_port": True}, {"socks_port": 0}, {"http_port": 65536}, {"socks_port": 8080, "http_port": 8080}):
            with self.assertRaises(UnsupportedExport):
                build_node_routing(proxy(), {}, **ports)


if __name__ == "__main__":
    unittest.main()
