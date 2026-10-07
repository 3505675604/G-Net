import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from clash_export import UnsupportedExport, proxy_from_uri
from clash_workspace import build_workspace_configuration


IDS = ["A" * 42 + "0", "B" * 42 + "1", "C" * 42 + "2"]
UID = "11111111-2222-4333-8444-555555555555"


def node(name="测试节点", protocol="ss"):
    if protocol == "vless":
        result = proxy_from_uri(f"vless://{UID}@192.0.2.1:443?encryption=none&type=tcp")
    else:
        result = proxy_from_uri("ss://aes-128-gcm:fake-password@192.0.2.1:600")
    result["name"] = name
    return result


def group(name="代理", kind="select", members=None, **extra):
    return {"name": name, "type": kind, "members": members or IDS[:2], **extra}


def custom(rules=None, groups=None, **extra):
    return {"template": "custom", "groups": groups if groups is not None else [group()],
            "rules": rules if rules is not None else [], "fallback": "代理", **extra}


class WorkspaceConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.nodes = [node("香港 · 01"), node("日本 · 02")]

    def build(self, profile=None, nodes=None, ids=None):
        return build_workspace_configuration(self.nodes if nodes is None else nodes,
                                             IDS[:2] if ids is None else ids,
                                             {} if profile is None else profile)

    def rejects(self, profile=None, nodes=None, ids=None):
        with self.assertRaises(UnsupportedExport):
            self.build(profile, nodes, ids)

    def test_default_configuration_combines_all_nodes_and_three_real_groups(self):
        result = self.build()
        config = result["config"]
        self.assertEqual(config["proxies"], self.nodes)
        self.assertEqual(result["names"], dict(zip(IDS[:2], ["香港 · 01", "日本 · 02"])))
        self.assertEqual([item["name"] for item in config["proxy-groups"]], ["自动选择", "故障转移", "节点选择"])
        self.assertEqual([item["type"] for item in config["proxy-groups"]], ["url-test", "fallback", "select"])
        self.assertEqual(config["proxy-groups"][0]["proxies"], ["香港 · 01", "日本 · 02"])
        self.assertEqual(config["proxy-groups"][2]["proxies"], ["自动选择", "故障转移", "香港 · 01", "日本 · 02", "DIRECT"])
        self.assertEqual(config["rules"][-2:], ["GEOIP,CN,DIRECT", "MATCH,节点选择"])
        self.assertIn("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", config["rules"])
        self.assertIn("IP-CIDR6,fc00::/7,DIRECT,no-resolve", config["rules"])
        self.assertTrue(any("地理数据库" in warning for warning in result["warnings"]))

    def test_local_listener_and_rule_mode_are_fixed(self):
        config = self.build({"mixed_port": "7901"})["config"]
        self.assertEqual(config["mixed-port"], 7901)
        self.assertEqual(config["mode"], "rule")
        self.assertEqual(config["bind-address"], "127.0.0.1")
        self.assertFalse(config["allow-lan"])
        self.assertEqual(config["log-level"], "warning")
        self.assertNotIn("external-controller", config)
        self.assertNotIn("rule-providers", config)
        self.assertNotIn("proxy-providers", config)

    def test_global_template_uses_single_match_without_geography_dependency(self):
        result = self.build({"template": "global"})
        self.assertEqual(result["config"]["mode"], "rule")
        self.assertEqual(result["config"]["rules"], ["MATCH,节点选择"])
        self.assertFalse(any("地理数据库" in warning for warning in result["warnings"]))

    def test_profile_and_proxies_are_not_mutated_or_aliased(self):
        profile = custom(groups=[group("代理", "url-test", tolerance=150)])
        self.nodes[0] = {"name": "香港 · 01", "type": "vmess", "server": "192.0.2.1", "port": 443,
                         "uuid": UID, "cipher": "auto", "alterId": 0, "network": "ws", "tls": True,
                         "ws-opts": {"path": "/test", "headers": {"Host": "example.test"}}}
        before = copy.deepcopy((self.nodes, profile))
        result = self.build(profile)
        self.assertEqual((self.nodes, profile), before)
        result["config"]["proxies"][0]["ws-opts"]["headers"]["Host"] = "changed.test"
        self.assertEqual(self.nodes[0]["ws-opts"]["headers"]["Host"], "example.test")

    def test_duplicate_and_reserved_names_are_unique_and_references_follow_ids(self):
        nodes = [node("代理"), node("代理"), node("DIRECT")]
        profile = custom(groups=[group(members=IDS)], rules=[{"type": "DOMAIN", "value": "example.test", "target": IDS[1]}])
        result = self.build(profile, nodes=nodes, ids=IDS)
        names = [item["name"] for item in result["config"]["proxies"]]
        self.assertEqual(len(set(names)), 3)
        self.assertNotIn("代理", names)
        self.assertNotIn("DIRECT", names)
        self.assertEqual(result["config"]["proxy-groups"][0]["proxies"], names)
        self.assertEqual(result["config"]["rules"][0], f"DOMAIN,example.test,{names[1]}")
        self.assertEqual(result["names"][IDS[1]], names[1])

    def test_comma_control_and_line_separators_are_filtered_but_unicode_is_retained(self):
        result = self.build(nodes=[node("🚀香港,Premium\n\x00\u0085\u2028\u2029"), node("\n,\t")])
        self.assertEqual(result["names"][IDS[0]], "🚀香港，Premium")
        self.assertEqual(result["names"][IDS[1]], "，")
        self.assertNotIn("\x00", result["yaml"])
        self.assertNotIn("\u2028", result["yaml"])
        self.assertIn("🚀香港，Premium", result["yaml"])

    def test_blank_name_gets_safe_visible_default(self):
        result = self.build(nodes=[node("\n\t"), node("")])
        self.assertEqual(list(result["names"].values()), ["节点 1", "节点 2"])

    def test_yaml_quotes_scalar_secrets_and_name_and_header_cannot_inject_documents(self):
        self.nodes[0]["password"] = 'p\n---\nproxies: [] # "quoted"'
        self.nodes[0]["name"] = "': # quoted"
        result = self.build({"name": "安全\n---\r伪标题"})
        self.assertEqual(result["yaml"].splitlines()[0], "# G-Network - 安全---伪标题")
        self.assertIn('password: "p\\n---\\nproxies: [] # \\"quoted\\""', result["yaml"])
        self.assertNotIn("\n---\n", result["yaml"])
        self.assertIn('mixed-port: 7890', result["yaml"])
        self.assertIn('rules:', result["yaml"])

    def test_all_four_group_types_and_tunable_fields(self):
        groups = [group("选择", "select"), group("测速", "url-test", interval="20", tolerance="0"),
                  group("故障", "fallback", interval=86400),
                  group("均衡", "load-balance", strategy="round-robin", interval=10)]
        result = self.build(custom(groups=groups, fallback="均衡"))
        outputs = result["config"]["proxy-groups"]
        self.assertNotIn("url", outputs[0])
        self.assertEqual(outputs[1]["tolerance"], 0)
        self.assertEqual(outputs[1]["interval"], 20)
        self.assertEqual(outputs[2]["interval"], 86400)
        self.assertEqual(outputs[3]["strategy"], "round-robin")
        self.assertEqual(result["config"]["rules"], ["MATCH,均衡"])

    def test_group_forward_references_are_resolved_without_reordering(self):
        groups = [group("前组", members=["后组", "DIRECT"]), group("后组")]
        result = self.build(custom(groups=groups, fallback="前组"))
        self.assertEqual([item["name"] for item in result["config"]["proxy-groups"]], ["前组", "后组"])
        self.assertEqual(result["config"]["proxy-groups"][0]["proxies"], ["后组", "DIRECT"])

    def test_direct_fallback_can_be_used_without_groups(self):
        result = self.build(custom(groups=[], fallback="DIRECT"))
        self.assertEqual(result["config"]["proxy-groups"], [])
        self.assertEqual(result["config"]["rules"], ["MATCH,DIRECT"])

    def test_group_cycles_and_self_reference_are_rejected(self):
        for groups in ([group("代理", members=["代理"])],
                       [group("代理", members=["二组"]), group("二组", members=["三组"]), group("三组", members=["代理"]) ]):
            with self.subTest(groups=groups):
                self.rejects(custom(groups=groups))

    def test_invalid_group_names_members_and_references_are_rejected(self):
        for groups in ([group("DIRECT")], [group("GLOBAL")], [group("代理"), group("代理")],
                       [group("代,理")], [group("代\n理")], [group(" 代理")],
                       [group(IDS[0])], [group("Z" * 43)], [group(members=["unknown"])],
                       [{"name": "代理", "type": "select", "members": []}],
                       [group(members=[IDS[0], IDS[0]])]):
            with self.subTest(groups=groups):
                self.rejects(custom(groups=groups))

    def test_numeric_group_ranges_and_wrong_type_fields_are_rejected(self):
        for kind, extra in (("url-test", {"interval": 9}), ("fallback", {"interval": 86401}),
                            ("load-balance", {"interval": True}), ("url-test", {"tolerance": -1}),
                            ("url-test", {"tolerance": 3001}), ("select", {"url": "https://example.test"}),
                            ("select", {"interval": 300}), ("select", {"tolerance": 50}),
                            ("select", {"strategy": "round-robin"}),
                            ("fallback", {"tolerance": 50}), ("url-test", {"strategy": "round-robin"}),
                            ("load-balance", {"strategy": "invalid"}), ("relay", {}), ([], {})):
            with self.subTest(kind=kind, extra=extra):
                self.rejects(custom(groups=[group(kind=kind, **extra)]))

    def test_url_validation_has_no_fetch_and_rejects_unsupported_userinfo_control_and_fragment(self):
        for url in ("ftp://example.test", "file:///etc/passwd", "https://name:password@example.test",
                    "https://example.test/#fragment", "https://example.test:0", "https://example.test:70000",
                    "https://example.test/\nextra", "https://exa mple.test", "https://example.test\\bad", "https://"):
            with self.subTest(url=url):
                self.rejects(custom(groups=[group(kind="url-test", url=url)]))
        self.assertEqual(self.build(custom(groups=[group(kind="url-test", url="https://[2001:db8::1]:8443/204?q=x")]))["config"]["proxy-groups"][0]["url"],
                         "https://[2001:db8::1]:8443/204?q=x")
        self.assertEqual(self.build(custom(groups=[group(kind="url-test", url="http://www.gstatic.com/generate_204")]))["config"]["proxy-groups"][0]["url"],
                         "http://www.gstatic.com/generate_204")

    def test_custom_rules_keep_priority_and_append_final_fallback(self):
        rules = [{"type": "DOMAIN", "value": "blocked.test", "target": "REJECT"},
                 {"type": "DOMAIN-SUFFIX", "value": "example.test", "target": "代理"},
                 {"type": "DOMAIN-KEYWORD", "value": "media", "target": IDS[1]}]
        result = self.build(custom(rules=rules))
        self.assertEqual(result["config"]["rules"], ["DOMAIN,blocked.test,REJECT", "DOMAIN-SUFFIX,example.test,代理",
                                                     "DOMAIN-KEYWORD,media,日本 · 02", "MATCH,代理"])

    def test_existing_final_match_is_kept_and_not_duplicated(self):
        result = self.build(custom(rules=[{"type": "DOMAIN", "value": "example.test", "target": "代理"},
                                         {"type": "MATCH", "value": "", "target": "REJECT"}]))
        self.assertEqual(result["config"]["rules"][-1], "MATCH,REJECT")
        self.assertEqual(sum(rule.startswith("MATCH,") for rule in result["config"]["rules"]), 1)

    def test_explicit_rule_list_overrides_template_defaults(self):
        self.assertEqual(self.build({"template": "balanced", "rules": []})["config"]["rules"], ["MATCH,节点选择"])

    def test_match_in_middle_duplicate_value_or_no_resolve_is_rejected(self):
        for rules in ([{"type": "MATCH", "target": "代理"}, {"type": "DOMAIN", "value": "example.test", "target": "DIRECT"}],
                      [{"type": "MATCH", "target": "代理"}, {"type": "MATCH", "target": "DIRECT"}],
                      [{"type": "MATCH", "value": "anything", "target": "代理"}],
                      [{"type": "MATCH", "target": "代理", "no_resolve": True}]):
            with self.subTest(rules=rules):
                self.rejects(custom(rules=rules))

    def test_all_ip_and_geo_rules_preserve_no_resolve_and_normalize_values(self):
        rules = [{"type": "IP-CIDR", "value": "192.168.1.1/24", "target": "DIRECT", "no_resolve": True},
                 {"type": "IP-CIDR6", "value": "2001:db8::1/64", "target": "代理", "no_resolve": True},
                 {"type": "SRC-IP-CIDR", "value": "10.0.0.4/16", "target": "DIRECT", "no_resolve": True},
                 {"type": "GEOIP", "value": "cn", "target": "DIRECT", "no_resolve": True}]
        self.assertEqual(self.build(custom(rules=rules))["config"]["rules"], ["IP-CIDR,192.168.1.0/24,DIRECT,no-resolve",
                          "IP-CIDR6,2001:db8::/64,代理,no-resolve", "SRC-IP-CIDR,10.0.0.0/16,DIRECT,no-resolve",
                          "GEOIP,CN,DIRECT,no-resolve", "MATCH,代理"])

    def test_dst_port_ranges_and_idna_domain_rules_are_validated(self):
        rules = [{"type": "DST-PORT", "value": "080/443/8000-8010", "target": "代理"},
                 {"type": "DOMAIN", "value": "例子.测试", "target": "DIRECT"},
                 {"type": "DOMAIN-SUFFIX", "value": "EXAMPLE.TEST.", "target": "代理"}]
        outputs = self.build(custom(rules=rules))["config"]["rules"]
        self.assertEqual(outputs[0], "DST-PORT,80/443/8000-8010,代理")
        self.assertEqual(outputs[1], "DOMAIN,xn--fsqu00a.xn--0zwm56d,DIRECT")
        self.assertEqual(outputs[2], "DOMAIN-SUFFIX,example.test,代理")

    def test_rule_injection_unsupported_types_and_missing_targets_are_rejected(self):
        for rule in ({"type": "DOMAIN", "value": "example.test,DIRECT", "target": "代理"},
                     {"type": "DOMAIN-KEYWORD", "value": "x\nMATCH,DIRECT", "target": "代理"},
                     {"type": "DOMAIN", "value": "https://example.test", "target": "代理"},
                     {"type": "DOMAIN-SUFFIX", "value": "*.example.test", "target": "代理"},
                     {"type": "DOMAIN", "value": "example.test", "target": "未知"},
                     {"type": "RULE-SET", "value": "https://example.test/rules", "target": "代理"},
                     {"type": "DOMAIN", "value": "example.test", "target": "代理", "no_resolve": True},
                     {"type": "GEOIP", "value": "CN", "target": "代理", "no_resolve": "true"}):
            with self.subTest(rule=rule):
                self.rejects(custom(rules=[rule]))

    def test_invalid_ip_geo_keyword_and_port_values_are_rejected(self):
        for kind, value in (("IP-CIDR", "300.1.1.1/24"), ("IP-CIDR", "1.1.1.1"),
                            ("IP-CIDR", "2001:db8::/32"), ("IP-CIDR6", "192.0.2.0/24"),
                            ("SRC-IP-CIDR", "10.0.0.0/33"), ("GEOIP", "CHINA"),
                            ("GEOIP", "C1"), ("DOMAIN-KEYWORD", "a/b"),
                            ("DST-PORT", "0"), ("DST-PORT", "65536"), ("DST-PORT", "90-80"),
                            ("DST-PORT", "80,443"), ("DST-PORT", "80-443-8000"),
                            ("DOMAIN", "a..test"), ("DOMAIN", "example.test..")):
            with self.subTest(kind=kind, value=value):
                self.rejects(custom(rules=[{"type": kind, "value": value, "target": "DIRECT"}]))

    def test_fallback_rejects_missing_group_and_node_id(self):
        for fallback in ("missing", IDS[0], "DIRECT,MATCH", "代理\n"):
            with self.subTest(fallback=fallback):
                self.rejects(custom(fallback=fallback))

    def test_protocol_compatibility_warnings_do_not_promise_all_clients(self):
        result = self.build(nodes=[node("经典"), node("VLESS", protocol="vless")])
        self.assertTrue(any("Mihomo" in warning and "旧版 Clash" in warning for warning in result["warnings"]))
        self.assertEqual(len(result["config"]["proxies"]), 2)

    def test_node_id_shape_uniqueness_and_alignment_are_enforced(self):
        for ids in ([IDS[0]], [IDS[0], IDS[0]], ["short", IDS[1]], ["*" * 43, IDS[1]],
                    [IDS[0], None], "not-a-list"):
            with self.subTest(ids=ids):
                self.rejects(ids=ids)

    def test_node_count_boundary_and_zero_selection(self):
        self.rejects(nodes=[], ids=[])
        nodes = [node(f"n-{index}") for index in range(129)]
        ids = [f"{index:043d}" for index in range(129)]
        self.rejects(nodes=nodes, ids=ids)
        result = self.build(nodes=nodes[:128], ids=ids[:128])
        self.assertEqual(len(result["config"]["proxies"]), 128)

    def test_group_count_boundary(self):
        groups = [group(f"g-{index}", members=[IDS[0]]) for index in range(17)]
        self.rejects(custom(groups=groups, fallback="g-0"))
        self.assertEqual(len(self.build(custom(groups=groups[:16], fallback="g-0"))["config"]["proxy-groups"]), 16)

    def test_rule_limit_includes_appended_match(self):
        rule = {"type": "DOMAIN", "value": "example.test", "target": "DIRECT"}
        self.assertEqual(len(self.build(custom(rules=[rule] * 199))["config"]["rules"]), 200)
        self.rejects(custom(rules=[rule] * 200))
        with_match = [rule] * 199 + [{"type": "MATCH", "target": "代理"}]
        self.assertEqual(len(self.build(custom(rules=with_match))["config"]["rules"]), 200)
        self.rejects(custom(rules=with_match + [rule]))

    def test_invalid_profile_port_mode_template_and_nonstring_name(self):
        for profile in (None, [], "profile", {"mixed_port": True}, {"mixed_port": 0}, {"mixed_port": 65536},
                        {"mixed_port": "7890.0"}, {"mixed_port": "9" * 10000}, {"mode": "global"},
                        {"template": "unknown"}, {"name": 12}):
            if profile is None:
                with self.assertRaises(UnsupportedExport):
                    build_workspace_configuration(self.nodes, IDS[:2], None)
            else:
                with self.subTest(profile=profile):
                    self.rejects(profile)

    def test_unsupported_or_incomplete_proxy_is_rejected(self):
        for proxy in ({"type": "trojan", "name": "x"}, {"type": "ss", "name": "x"}, {"type": [], "name": "x"}, None):
            with self.subTest(proxy=proxy):
                self.rejects(nodes=[proxy, self.nodes[1]])

    def test_malformed_rule_type_returns_validation_error(self):
        self.rejects(custom(rules=[{"type": [], "value": "example.test", "target": "DIRECT"}]))

    def test_unicode_line_break_profile_name_cannot_escape_yaml_comment(self):
        result = self.build({"template": "global", "name": "星网 🚀\u2028---\u2029rules:\u0085\x00\nMATCH,DIRECT"})
        self.assertEqual(result["yaml"].splitlines()[0], "# G-Network - 星网 🚀---rules:MATCH，DIRECT")
        self.assertEqual(result["config"]["rules"], ["MATCH,节点选择"])
        self.assertNotIn("\n---\n", result["yaml"])


if __name__ == "__main__":
    unittest.main()
