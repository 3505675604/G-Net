"""No-network studio contracts: independent chain copies and exact parameters."""
import base64
import copy
import unittest

from clash_export import UnsupportedExport
from clash_workspace import build_workspace_configuration, validate_advanced
from node_routing import build_node_routing


IDS = [chr(65 + index) * 43 for index in range(8)]
UID = "11111111-2222-4333-8444-555555555555"
KEY = base64.urlsafe_b64encode(b"P" * 32).decode().rstrip("=")


def fixture(protocol, name=None):
    item = {"name": name or protocol, "type": protocol, "server": "192.0.2.1", "port": 443, "udp": True}
    if protocol == "ss":
        item.update(cipher="aes-128-gcm", password="fake-password")
    elif protocol in ("vmess", "vless"):
        item.update(uuid=UID, network="tcp", tls=True, servername="example.test")
        if protocol == "vmess":
            item.update(cipher="auto", alterId=0)
    elif protocol == "trojan":
        item.update(password="fake-password", network="tcp", sni="example.test")
    elif protocol == "hysteria2":
        item.update(password="fake-password", sni="example.test", alpn=["h3"])
    elif protocol == "tuic":
        item.update(uuid=UID, password="fake-password", sni="example.test", alpn=["h3"], congestion_controller="bbr")
        item["congestion-controller"] = item.pop("congestion_controller")
    return item


def profile(chains=None, members=None, rules=None, **fields):
    return {"template": "custom", "groups": [{"name": "出口选择", "type": "select", "members": members or IDS[:2]}],
            "rules": rules or [], "fallback": "出口选择", "chains": chains or [], **fields}


class StudioConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [fixture("ss", "中转"), fixture("vless", "落地")]

    def build(self, settings, nodes=None, ids=None):
        return build_workspace_configuration(nodes or self.nodes, ids or IDS[:2], settings)

    def test_all_six_protocols_are_retained_in_one_configuration(self):
        nodes = [fixture(kind) for kind in ("ss", "vmess", "vless", "trojan", "hysteria2", "tuic")]
        result = self.build(profile(members=IDS[:6]), nodes, IDS[:6])
        self.assertEqual([p["type"] for p in result["config"]["proxies"]], [p["type"] for p in nodes])
        self.assertEqual([p["name"] for p in result["config"]["proxies"]], [p["name"] for p in nodes])

    def test_chain_copies_include_first_hop_and_leave_standalone_nodes_untouched(self):
        settings = profile([{"name": "专属链", "hops": IDS[:2]}], members=[IDS[0], IDS[1], "专属链"],
                           rules=[{"type": "DOMAIN-SUFFIX", "value": "media.example", "target": "专属链"}])
        before = copy.deepcopy((self.nodes, settings))
        result = self.build(settings)
        base_a, base_b, chain_a, chain_b = result["config"]["proxies"]
        self.assertNotIn("dialer-proxy", base_a)
        self.assertNotIn("dialer-proxy", base_b)
        self.assertNotIn("dialer-proxy", chain_a)
        self.assertEqual(chain_b["dialer-proxy"], chain_a["name"])
        self.assertEqual(chain_b["name"], "专属链")
        self.assertEqual(chain_b["uuid"], base_b["uuid"])
        self.assertEqual(result["config"]["proxy-groups"][0]["proxies"], ["中转", "落地", "专属链"])
        self.assertEqual(result["config"]["rules"][0], "DOMAIN-SUFFIX,media.example,专属链")
        self.assertEqual((self.nodes, settings), before)
        chain_b["servername"] = "changed.test"
        self.assertEqual(self.nodes[1]["servername"], "example.test")

    def test_chain_name_priority_renames_base_and_globally_unique_helpers(self):
        nodes = [fixture("ss", "链路"), fixture("ss", "链路 · 跳 1")]
        result = self.build(profile([{"name": "链路", "hops": IDS[:2]}], members=[IDS[0], "链路"]), nodes)
        names = [p["name"] for p in result["config"]["proxies"]]
        self.assertEqual(len(set(names)), 4)
        self.assertEqual(names[-1], "链路")
        self.assertNotEqual(result["names"][IDS[0]], "链路")
        self.assertEqual(result["config"]["proxy-groups"][0]["proxies"], [names[0], "链路"])

    def test_multiple_chains_keep_independent_copies_and_hidden_hops(self):
        result = self.build(profile([{"name": "一号链", "hops": IDS[:2]}, {"name": "二号链", "hops": IDS[1::-1]}]))
        self.assertEqual(len(result["config"]["proxies"]), 6)
        self.assertEqual(result["chain_names"], ["一号链", "二号链"])
        self.assertEqual(result["config"]["proxy-groups"][0]["proxies"], ["中转", "落地"])
        first_copy, exit_one, second_copy, exit_two = result["config"]["proxies"][2:]
        self.assertEqual(exit_one["dialer-proxy"], first_copy["name"])
        self.assertEqual(exit_two["dialer-proxy"], second_copy["name"])

    def test_invalid_chain_does_not_silently_drop_missing_or_repeated_hops(self):
        bad = [{"name": "链", "hops": [IDS[0]]}, {"name": "链", "hops": [IDS[0], IDS[0]]},
               {"name": "链", "hops": [IDS[0], IDS[2]]}, {"name": "出口选择", "hops": IDS[:2]},
               {"name": "DIRECT", "hops": IDS[:2]}, {"name": "链", "hops": IDS[:2], "enabled": 1},
               {"name": IDS[0], "hops": IDS[:2]}, {"name": "链", "hops": IDS[:2], "dialer-proxy": "x"}]
        for chain in bad:
            with self.subTest(chain=chain), self.assertRaises(UnsupportedExport):
                self.build(profile([chain]))
        with self.assertRaises(UnsupportedExport):
            self.build(profile([{"name": "链", "hops": IDS[:2]}] * 2))

    def test_chain_limits_and_disabled_chain_are_explicit(self):
        with self.assertRaises(UnsupportedExport):
            self.build(profile([{"name": str(index), "hops": IDS[:2]} for index in range(17)]))
        chain = {"name": "关闭链", "hops": IDS[:2], "enabled": False}
        self.assertEqual(len(self.build(profile([chain]))["config"]["proxies"]), 2)
        with self.assertRaises(UnsupportedExport):
            self.build(profile([chain], members=["关闭链"]))
        with self.assertRaises(UnsupportedExport):
            self.build(profile([{"name": "关闭链", "hops": [IDS[0], IDS[2]], "enabled": False}]))
        nodes = [fixture("ss", f"node-{index}") for index in range(8)]
        result = self.build(profile([{"name": "八跳", "hops": IDS}], members=["八跳"]), nodes, IDS)
        self.assertEqual(len(result["config"]["proxies"]), 16)

    def test_imported_vless_encryption_flow_ws_and_grpc_are_preserved(self):
        for network, transport in (("ws", {"ws-opts": {"path": "/abc", "headers": {"Host": "example.test"}}}),
                                   ("grpc", {"grpc-opts": {"grpc-service-name": "GunService"}})):
            node = {**fixture("vless"), "network": network, "encryption": "mlkem768x25519plus.native.1rtt." + KEY,
                    "flow": "xtls-rprx-vision", "packet-encoding": "xudp", "alpn": ["h2"], **transport}
            result = self.build(profile(members=IDS[:1]), [node], IDS[:1])
            exported = result["config"]["proxies"][0]
            for field in ("encryption", "flow", "network", "packet-encoding", "alpn", *transport):
                self.assertEqual(exported[field], node[field])

    def test_advanced_dns_and_tun_are_copied_without_overriding_topology(self):
        advanced = {"dns": {"enable": True, "listen": "127.0.0.1:1053", "respect-rules": True,
                            "nameserver": ["https://dns.alidns.com/dns-query"],
                            "proxy-server-nameserver": ["223.5.5.5"], "direct-nameserver": ["system"]},
                    "tun": {"enable": False, "stack": "system", "auto-route": False},
                    "sniffer": {"enable": True, "sniff": {"TLS": {"ports": [443]}}},
                    "ipv6": False, "profile": {"store-selected": True}, "tcp-concurrent": True}
        result = self.build(profile(advanced=advanced))
        for key, value in advanced.items():
            self.assertEqual(result["config"][key], value)
        result["config"]["dns"]["nameserver"].append("1.1.1.1")
        self.assertEqual(advanced["dns"]["nameserver"], ["https://dns.alidns.com/dns-query"])

    def test_advanced_rejects_unbounded_or_topology_and_provider_fields(self):
        values = [{"proxies": []}, {"proxy-groups": []}, {"rules": []}, {"mixed-port": 9000},
                  {"mode": "global"}, {"external-controller": "0.0.0.0:9090"},
                  {"proxy-providers": {}}, {"rule-providers": {}}, {"dns": []}, {"ipv6": 1},
                  {"dns": {"nameserver": [float("nan")]}}, {"dns": {"x": "bad\nline"}},
                  {"dns": {"respect-rules": "true"}}, {"dns": {"respect-rules": True}},
                  {"dns": {"respect-rules": True, "proxy-server-nameserver": []}},
                  {"profile": {"x": "x" * 8193}}, {"hosts": {"x": object()}}]
        for value in values:
            with self.subTest(value=value), self.assertRaises(UnsupportedExport):
                validate_advanced(value)
        nested = {}
        for _ in range(10):
            nested = {"x": nested}
        with self.assertRaises(UnsupportedExport):
            validate_advanced({"dns": nested})

    def test_imported_rule_extensions_preserve_order_and_exact_match_kind(self):
        rules = [{"type": "GEOSITE", "value": "category-ads-all", "target": "REJECT"},
                 {"type": "DOMAIN-REGEX", "value": r"^api\d+\.example\.com$", "target": "出口选择"},
                 {"type": "PROCESS-NAME", "value": "example.exe", "target": "DIRECT"},
                 {"type": "PROCESS-PATH", "value": r"C:\Apps\example.exe", "target": "DIRECT"},
                 {"type": "SRC-PORT", "value": "8000-8010", "target": "出口选择"},
                 {"type": "SRC-IP-CIDR6", "value": "2001:db8::1/64", "target": "DIRECT", "no_resolve": True},
                 {"type": "NETWORK", "value": "udp", "target": "REJECT"}]
        output = self.build(profile(rules=rules))["config"]["rules"]
        self.assertEqual(output[0], "GEOSITE,category-ads-all,REJECT")
        self.assertEqual(output[1], r"DOMAIN-REGEX,^api\d+\.example\.com$,出口选择")
        self.assertEqual(output[3], r"PROCESS-PATH,C:\Apps\example.exe,DIRECT")
        self.assertEqual(output[-3], "SRC-IP-CIDR6,2001:db8::/64,DIRECT,no-resolve")
        self.assertEqual(output[-2], "NETWORK,UDP,REJECT")

    def test_imported_final_match_to_exact_node_does_not_validate_unused_fallback(self):
        settings = profile(rules=[{"type": "MATCH", "value": "", "target": IDS[1]}], fallback=IDS[1])
        output = self.build(settings)["config"]["rules"]
        self.assertEqual(output, ["MATCH,落地"])


class ExtendedNodeRoutingTests(unittest.TestCase):
    def test_new_protocols_export_clash_and_explicitly_disable_xray(self):
        for kind in ("trojan", "hysteria2", "tuic"):
            node = fixture(kind)
            result = build_node_routing(node, {"enabled": True, "direct_domains": ["example.com"]})
            self.assertEqual(result["clash"]["config"]["proxies"][0], node)
            self.assertFalse(result["xray"]["available"])
            self.assertNotIn("json", result["xray"])
            self.assertIn("忠实转换", result["xray"]["notice"])

    def test_supported_clash_extras_are_never_silently_dropped_into_xray(self):
        nodes = [{**fixture("ss"), "plugin": "obfs", "plugin-opts": {"mode": "http", "host": "example.com"}},
                 {**fixture("vless"), "encryption": "mlkem768x25519plus.native.1rtt." + KEY,
                  "flow": "xtls-rprx-vision", "network": "ws", "ws-opts": {"path": "/abc"}},
                 {**fixture("vless"), "network": "grpc", "grpc-opts": {"grpc-service-name": "GunService"}},
                 {**fixture("vmess"), "skip-cert-verify": True}]
        for node in nodes:
            with self.subTest(node=node):
                result = build_node_routing(node, {})
                self.assertEqual(result["clash"]["config"]["proxies"][0], node)
                self.assertFalse(result["xray"]["available"])
                self.assertNotIn("config", result["xray"])

    def test_node_with_dialer_cannot_export_an_incomplete_independent_profile(self):
        with self.assertRaises(UnsupportedExport):
            build_node_routing({**fixture("ss"), "dialer-proxy": "missing-hop"}, {})


if __name__ == "__main__":
    unittest.main()
