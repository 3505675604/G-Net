"""Import fixtures use reserved documentation IPs and synthetic credentials."""
import base64
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import yaml
from clash_export import UnsupportedExport, proxy_from_uri
from clash_import import import_clash_text, validate_import_proxy, MAX_TEXT_BYTES
from node_routing import stable_routing_key

UID = "11111111-2222-4333-8444-555555555555"
PUBLIC = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
ENC = "mlkem768x25519plus.native.0rtt." + PUBLIC


def b64(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def ss(name="入口", **extra):
    return {"name": name, "type": "ss", "server": "192.0.2.1", "port": 443,
            "cipher": "aes-128-gcm", "password": "synthetic-password", "udp": True, **extra}


def document(proxies=None, groups=None, rules=None, **extra):
    proxies = [ss()] if proxies is None else proxies
    groups = [{"name": "选择", "type": "select", "proxies": [proxies[0]["name"], "DIRECT"]}] if groups is None else groups
    return {"mixed-port": 7890, "mode": "rule", "proxies": proxies, "proxy-groups": groups,
            "rules": ["DOMAIN-SUFFIX,example.com,DIRECT", "MATCH,选择"] if rules is None else rules, **extra}


def load(data):
    return import_clash_text(yaml.safe_dump(data, allow_unicode=True), "yaml")


class ShareLinkImportTests(unittest.TestCase):
    def test_all_six_protocols_and_hy2_alias_are_imported(self):
        vmess = b64(json.dumps({"v": "2", "ps": "VMess", "add": "192.0.2.2", "port": "443",
            "id": UID, "aid": "0", "net": "ws", "path": "/edge", "host": "edge.example.com", "tls": "tls"}))
        links = [f"vless://{UID}@192.0.2.1:443?encryption=none&type=tcp#VLESS",
            f"vmess://{vmess}", "trojan://synthetic-password@192.0.2.3:443?sni=edge.example.com#Trojan",
            "hysteria2://synthetic-password@192.0.2.4:443?alpn=h3#Hy2",
            "hy2://synthetic-password@192.0.2.5:443#Hy2-alias",
            "ss://aes-128-gcm:synthetic-password@192.0.2.6:443#SS",
            f"tuic://{UID}:synthetic-password@192.0.2.7:443?congestion_control=bbr#TUIC"]
        result = import_clash_text("\n".join(links))
        self.assertEqual([p["type"] for p in result["proxies"]], ["vless", "vmess", "trojan", "hysteria2", "hysteria2", "ss", "tuic"])
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["can_replace"])
        self.assertNotIn("skip-cert-verify", result["proxies"][1])

    def test_encrypted_vless_ws_keeps_flow_and_encryption(self):
        result = import_clash_text(f"vless://{UID}@edge.example.com:443?encryption={ENC}&type=ws&security=tls&flow=xtls-rprx-vision&path=edge&host=cdn.example.com&alpn=h2,http/1.1")
        self.assertEqual(result["errors"], [])
        proxy = result["proxies"][0]
        self.assertEqual(proxy["encryption"], ENC)
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")
        self.assertEqual(proxy["ws-opts"], {"path": "/edge", "headers": {"Host": "cdn.example.com"}})
        self.assertEqual(proxy["alpn"], ["h2", "http/1.1"])

    def test_encrypted_vless_grpc_preserves_service(self):
        result = import_clash_text(f"vless://{UID}@192.0.2.1:443?encryption={ENC}&type=grpc&security=tls&flow=xtls-rprx-vision&serviceName=GunService")
        self.assertEqual(result["proxies"][0]["grpc-opts"], {"grpc-service-name": "GunService"})
        self.assertEqual(result["proxies"][0]["flow"], "xtls-rprx-vision")

    def test_plain_ws_vision_is_rejected_without_silently_deleting_flow(self):
        result = import_clash_text(f"vless://{UID}@192.0.2.1:443?encryption=none&type=ws&security=tls&flow=xtls-rprx-vision")
        self.assertEqual(result["proxies"], [])
        self.assertIn("flow", result["errors"][0]["msg"])

    def test_reality_fields_and_certificate_option_are_preserved(self):
        result = import_clash_text(f"vless://{UID}@192.0.2.1:443?security=reality&type=tcp&pbk={PUBLIC}&sid=abcd&fp=chrome&sni=edge.example.com&flow=xtls-rprx-vision&allowInsecure=1")
        proxy = result["proxies"][0]
        self.assertEqual(proxy["reality-opts"], {"public-key": PUBLIC, "short-id": "abcd"})
        self.assertTrue(proxy["skip-cert-verify"])

    def test_unsupported_encryption_fails_explicitly(self):
        result = import_clash_text(f"vless://{UID}@192.0.2.1:443?encryption=unsupported-secret-type&type=tcp")
        self.assertEqual(result["proxies"], [])
        self.assertIn("encryption", result["errors"][0]["msg"])
        self.assertNotIn("unsupported-secret-type", json.dumps(result["errors"]))

    def test_sip002_plain_encoded_and_legacy_with_ipv6(self):
        links = ["ss://aes-128-gcm:p%40ss%3Aword@192.0.2.1:443#plain",
            f"ss://{b64('aes-128-gcm:synthetic-password')}@192.0.2.2:443#encoded",
            f"ss://{b64('aes-128-gcm:synthetic-password@[2001:db8::1]:443')}#legacy"]
        result = import_clash_text("\n".join(links))
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["proxies"][0]["password"], "p@ss:word")
        self.assertEqual(result["proxies"][2]["server"], "2001:db8::1")

    def test_sip002_plugins_are_preserved_instead_of_dropped(self):
        encoded = urllib_quote("v2ray-plugin;mode=websocket;tls;host=cdn.example.com;path=/edge")
        result = import_clash_text("ss://aes-128-gcm:synthetic-password@192.0.2.1:443?plugin=" + encoded)
        proxy = result["proxies"][0]
        self.assertEqual(proxy["plugin"], "v2ray-plugin")
        self.assertEqual(proxy["plugin-opts"], {"mode": "websocket", "tls": True, "host": "cdn.example.com", "path": "/edge"})

    def test_unknown_plugin_and_link_parameters_are_errors(self):
        result = import_clash_text("ss://aes-128-gcm:synthetic-password@192.0.2.1:443?plugin=unknown-secret\n"
                                  f"vless://{UID}@192.0.2.1:443?encryption=none&unexpected=secret")
        self.assertEqual(len(result["errors"]), 2)
        self.assertNotIn("secret", json.dumps(result["errors"]))

    def test_base64_subscription_detected_and_partially_invalid_lines_reported(self):
        payload = "ss://aes-128-gcm:synthetic-password@192.0.2.1:443#A\ninvalid SECRET-CREDENTIAL\n"
        result = import_clash_text(b64(payload))
        self.assertEqual(result["source_format"], "base64")
        self.assertEqual(len(result["proxies"]), 1)
        self.assertEqual(result["errors"][0]["line"], 2)
        self.assertNotIn("SECRET-CREDENTIAL", json.dumps(result["errors"]))

    def test_markdown_escapes_are_accepted(self):
        result = import_clash_text(r"ss\://aes-128-gcm\:synthetic-password\@192.0.2.1:443\#A")
        self.assertEqual(len(result["proxies"]), 1)
        self.assertEqual(result["errors"], [])

    def test_duplicate_names_are_unique_without_changing_connections(self):
        result = import_clash_text("ss://aes-128-gcm:synthetic-password@192.0.2.1:443#A\nss://aes-128-gcm:synthetic-password@192.0.2.2:443#A")
        self.assertEqual([p["name"] for p in result["proxies"]], ["A", "A · 2"])
        self.assertEqual([p["server"] for p in result["proxies"]], ["192.0.2.1", "192.0.2.2"])

    def test_duplicate_queries_and_missing_ports_are_rejected(self):
        result = import_clash_text(f"vless://{UID}@192.0.2.1:443?type=tcp&type=ws\n"
                                  "ss://aes-128-gcm:synthetic-password@192.0.2.1#A")
        self.assertEqual(len(result["errors"]), 2)

    def test_http_subscription_is_never_downloaded(self):
        result = import_clash_text("https://subscription.example.com/private-token")
        self.assertEqual(result["proxies"], [])
        self.assertNotIn("private-token", json.dumps(result["errors"]))

    def test_hysteria_obfs_and_ports_and_tuic_options_round_trip(self):
        result = import_clash_text("hy2://synthetic-password@192.0.2.1:443?mport=443-8443&hop_interval=30&obfs=salamander&obfs-password=synthetic-obfs&insecure=1\n"
            f"tuic://{UID}:synthetic-password@192.0.2.2:443?udp_relay_mode=quic&reduce_rtt=1&disable_sni=true")
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["proxies"][0]["ports"], "443-8443")
        self.assertEqual(result["proxies"][0]["obfs-password"], "synthetic-obfs")
        self.assertTrue(result["proxies"][0]["skip-cert-verify"])
        self.assertTrue(result["proxies"][1]["reduce-rtt"])
        self.assertEqual(result["proxies"][1]["udp-relay-mode"], "quic")

    def test_128_proxy_cap_is_enforced(self):
        link = "ss://aes-128-gcm:synthetic-password@192.0.2.1:443#A"
        result = import_clash_text("\n".join([link] * 129))
        self.assertEqual(len(result["proxies"]), 128)
        self.assertEqual(len(result["errors"]), 1)


class DocumentImportTests(unittest.TestCase):
    def test_full_document_retains_groups_rules_and_advanced(self):
        original = document(dns={"enable": True, "enhanced-mode": "fake-ip", "nameserver": ["https://dns.example.com/dns-query"]},
            sniffer={"enable": True, "sniff": {"TLS": {"ports": [443]}}}, tun={"enable": True, "stack": "mixed"},
            ipv6=True, profile={"store-selected": True}, **{"unified-delay": True, "tcp-concurrent": True})
        result = load(original)
        self.assertTrue(result["can_replace"])
        self.assertEqual(result["profile"]["groups"], [{"name": "选择", "type": "select", "members": ["入口", "DIRECT"]}])
        self.assertEqual(result["profile"]["rules"][0], {"type": "DOMAIN-SUFFIX", "value": "example.com", "target": "DIRECT", "no_resolve": False})
        self.assertEqual(result["profile"]["advanced"]["dns"], original["dns"])

    def test_multiple_dialers_reconstruct_full_paths_and_remove_native_references(self):
        result = load(document([ss("A"), ss("B", **{"dialer-proxy": "A"}), ss("C", **{"dialer-proxy": "B"})],
                               [{"name": "选择", "type": "select", "proxies": ["C", "A"]}]))
        self.assertEqual(result["profile"]["chains"], [{"name": "B", "hops": ["A", "B"], "enabled": True},
                                                        {"name": "C", "hops": ["A", "B", "C"], "enabled": True}])
        self.assertEqual(result["profile"]["groups"][0]["members"], ["C", "A"])
        self.assertTrue(all("dialer-proxy" not in p for p in result["proxies"]))

    def test_dialer_to_group_is_explicitly_merge_only(self):
        result = load(document([ss("A"), ss("B", **{"dialer-proxy": "入口组"})],
            [{"name": "入口组", "type": "select", "proxies": ["A"]}, {"name": "选择", "type": "select", "proxies": ["B"]}]))
        self.assertFalse(result["can_replace"])
        self.assertIn("proxies.dialer-proxy", result["omitted_fields"])
        self.assertEqual(len(result["proxies"]), 2)
        self.assertTrue(all("dialer-proxy" not in p for p in result["proxies"]))

    def test_missing_and_cyclic_chain_dependencies_are_fatal(self):
        for proxies in ([ss("A", **{"dialer-proxy": "missing"})],
                        [ss("A", **{"dialer-proxy": "B"}), ss("B", **{"dialer-proxy": "A"})]):
            with self.subTest(proxies=len(proxies)), self.assertRaises(UnsupportedExport):
                load(document(proxies))

    def test_overlong_chain_is_never_truncated(self):
        proxies = [ss("P0")] + [ss(f"P{i}", **{"dialer-proxy": f"P{i-1}"}) for i in range(1, 9)]
        with self.assertRaises(UnsupportedExport):
            load(document(proxies))

    def test_duplicate_or_colliding_names_are_fatal(self):
        for value in (document([ss("A"), ss("A")]), document([ss("选择")]),
                      document(groups=[{"name": "选择", "type": "select", "proxies": ["入口"]}] * 2)):
            with self.subTest(value=len(value["proxies"])), self.assertRaises(UnsupportedExport):
                load(value)

    def test_missing_policy_and_group_cycles_are_fatal(self):
        for value in (document(rules=["MATCH,missing"]), document(groups=[{"name": "选择", "type": "select", "proxies": ["选择"]}])):
            with self.subTest(rules=value["rules"]), self.assertRaises(UnsupportedExport):
                load(value)

    def test_providers_unknown_top_level_and_unsupported_rules_are_not_silent(self):
        result = load(document(rules=["RULE-SET,private-provider,选择", "MATCH,选择"],
            **{"proxy-providers": {"remote": {"type": "http", "url": "https://subscription.example.com"}},
               "secret": "synthetic-controller-secret", "external-controller": "0.0.0.0:9090"}))
        self.assertFalse(result["can_replace"])
        self.assertEqual(set(result["omitted_fields"]), {"rules[0]", "proxy-providers", "secret", "external-controller"})
        self.assertNotIn("synthetic-controller-secret", json.dumps(result["warnings"]))
        self.assertNotIn("secret", result["profile"]["advanced"])

    def test_unknown_group_extension_prevents_full_replace(self):
        result = load(document(groups=[{"name": "选择", "type": "select", "proxies": ["入口"], "include-all": True}]))
        self.assertFalse(result["can_replace"])
        self.assertIn("proxy-groups[0]", result["omitted_fields"])

    def test_reference_rule_types_are_retained_in_order(self):
        rules = ["GEOSITE,cn,DIRECT", "PROCESS-NAME,client.exe,选择", "DOMAIN-REGEX,^api\\.example\\.com$,选择",
                 "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "MATCH,选择"]
        result = load(document(rules=rules))
        self.assertEqual([r["type"] for r in result["profile"]["rules"]], ["GEOSITE", "PROCESS-NAME", "DOMAIN-REGEX", "IP-CIDR", "MATCH"])
        self.assertTrue(result["profile"]["rules"][3]["no_resolve"])

    def test_invalid_yaml_never_falls_back_and_errors_do_not_echo_secrets(self):
        for text in ("proxies: [\n secret: very-secret-password", "proxies:\n - !!python/object/apply:os.system ['SECRET-CREDENTIAL']"):
            with self.subTest(text=len(text)), self.assertRaises(UnsupportedExport) as caught:
                import_clash_text(text, "yaml")
            self.assertNotIn("secret-password", str(caught.exception))
            self.assertNotIn("SECRET-CREDENTIAL", str(caught.exception))

    def test_duplicate_keys_anchors_and_non_string_keys_are_rejected(self):
        for text in ("proxies: []\nproxies: []", "proxies: &a [*a]", "proxies: []\n? [a, b]\n: value"):
            with self.subTest(text=text), self.assertRaises(UnsupportedExport):
                import_clash_text(text, "yaml")

    def test_deep_tree_nan_and_timestamp_objects_are_rejected(self):
        for text in ("x: " + "[" * 40 + "0" + "]" * 40, "x: .nan", "x: 2026-10-05"):
            with self.subTest(text=text[:20]), self.assertRaises(UnsupportedExport):
                import_clash_text(text, "yaml")

    def test_match_must_remain_last_and_no_resolve_is_not_dropped(self):
        for rules in (["MATCH,选择", "DOMAIN,example.com,DIRECT"], ["DOMAIN,example.com,DIRECT,no-resolve"]):
            with self.subTest(rules=rules), self.assertRaises(UnsupportedExport):
                load(document(rules=rules))

    def test_wrong_mode_reports_merge_only(self):
        value = document()
        value["mode"] = "global"
        result = load(value)
        self.assertFalse(result["can_replace"])
        self.assertIn("mode", result["omitted_fields"])

    def test_no_match_uses_group_fallback_explicitly(self):
        result = load(document(rules=["DOMAIN,example.com,DIRECT"]))
        self.assertEqual(result["profile"]["fallback"], "选择")
        self.assertTrue(result["warnings"])

    def test_http_test_url_is_retained_without_fetching(self):
        result = load(document(groups=[{"name": "选择", "type": "url-test", "proxies": ["入口"],
                                        "url": "http://www.gstatic.com/generate_204", "interval": 300}]))
        self.assertTrue(result["can_replace"])
        self.assertEqual(result["profile"]["groups"][0]["url"], "http://www.gstatic.com/generate_204")

    def test_rule_cidr_and_test_url_are_checked_before_replace(self):
        values = [document(rules=["IP-CIDR,2001:db8::/32,DIRECT", "MATCH,选择"]),
                  document(rules=["DST-PORT,70000,选择", "MATCH,选择"]),
                  document(groups=[{"name": "选择", "type": "url-test", "proxies": ["入口"], "url": "file:///private"}])]
        for value in values:
            with self.subTest(rules=value["rules"]), self.assertRaises(UnsupportedExport):
                load(value)


class ProxyValidationTests(unittest.TestCase):
    def test_old_exporter_valid_proxies_keep_shape(self):
        old = [proxy_from_uri("ss://aes-128-gcm:synthetic-password@192.0.2.1:443"),
            proxy_from_uri(f"vless://{UID}@192.0.2.1:443?encryption=none&type=ws&security=tls&path=/edge&host=cdn.example.com"),
            proxy_from_uri(f"vless://{UID}@192.0.2.1:443?security=reality&type=tcp&pbk={PUBLIC}&sid=abcd&flow=xtls-rprx-vision")]
        for proxy in old:
            with self.subTest(protocol=proxy["type"]):
                self.assertEqual(validate_import_proxy(proxy), proxy)

    def test_existing_password_newlines_survive_safe_serialization(self):
        proxy = ss(password="synthetic\npassword: #quoted")
        self.assertEqual(validate_import_proxy(proxy)["password"], proxy["password"])

    def test_unknown_handshake_fields_are_never_dropped(self):
        for extra in ({"unknown-auth": "synthetic-password"}, {"plugin-opts": {"mode": "tls"}}, {"skip-cert-verify": "false"}):
            with self.subTest(extra=extra), self.assertRaises(UnsupportedExport):
                validate_import_proxy(ss(**extra))

    def test_imported_policy_identity_survives_name_change_but_not_credential_change(self):
        proxy = validate_import_proxy(ss())
        initial = stable_routing_key("manual", (proxy["server"], proxy["port"]), proxy)
        changed = copy.deepcopy(proxy)
        changed["name"] = "改名"
        self.assertEqual(initial, stable_routing_key("manual", (changed["server"], changed["port"]), changed))
        changed["password"] = "different-synthetic-password"
        self.assertNotEqual(initial, stable_routing_key("manual", (changed["server"], changed["port"]), changed))

    def test_pure_json_cycles_and_unsafe_value_types_are_rejected(self):
        circular = ss()
        circular["smux"] = circular
        for value in (circular, ss(port=True), ss(password=b"fake"), ss(port=443.0), ss(**{"udp": 1})):
            with self.subTest(port=value.get("port")), self.assertRaises(UnsupportedExport):
                validate_import_proxy(value)

    def test_limits_and_empty_input(self):
        for value, fmt in (("", "auto"), ("x" * (MAX_TEXT_BYTES + 1), "auto"), ("x", "unknown")):
            with self.subTest(format=fmt), self.assertRaises(UnsupportedExport):
                import_clash_text(value, fmt)

    def test_non_tls_cert_skip_and_reality_on_quic_are_rejected(self):
        vless = {"name": "VLESS", "type": "vless", "server": "192.0.2.1", "port": 443,
                 "uuid": UID, "tls": False, "skip-cert-verify": True}
        hy2 = {"name": "Hy2", "type": "hysteria2", "server": "192.0.2.1", "port": 443,
               "password": "synthetic-password", "reality-opts": {"public-key": PUBLIC}}
        for value in (vless, hy2):
            with self.subTest(protocol=value["type"]), self.assertRaises(UnsupportedExport):
                validate_import_proxy(value)

    def test_oversized_vmess_nesting_is_credential_safe_error(self):
        result = import_clash_text("vmess://" + b64("[" * 1200 + "0" + "]" * 1200))
        self.assertEqual(result["proxies"], [])
        self.assertEqual(result["errors"][0]["msg"], "VMess 分享内容无效")


def urllib_quote(value):
    import urllib.parse
    return urllib.parse.quote(value, safe="")


if __name__ == "__main__":
    unittest.main()
