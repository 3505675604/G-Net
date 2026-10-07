"""Optional official-core syntax validation using documentation-only nodes.

Set GNETWORK_VALIDATE_MIHOMO / GNETWORK_VALIDATE_XRAY to existing official
binaries. Every invocation is parse-only and uses a fresh isolated directory.
No real node, user configuration, subscription or running proxy is touched.
"""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from clash_workspace import build_workspace_configuration
from node_routing import build_node_routing
from tests.test_clash_studio_configuration import IDS, KEY, fixture, profile


MIHOMO = os.environ.get("GNETWORK_VALIDATE_MIHOMO")
XRAY = os.environ.get("GNETWORK_VALIDATE_XRAY")


class OfficialCoreStudioTests(unittest.TestCase):
    records = []
    binaries = []

    @classmethod
    def setUpClass(cls):
        cls.records, cls.binaries = [], []
        for kind, path, argument in (("mihomo", MIHOMO, "-v"), ("xray", XRAY, "version")):
            if path and Path(path).is_file():
                result = subprocess.run([path, argument], capture_output=True, text=True, encoding="utf-8",
                                        errors="replace", timeout=10)
                digest = hashlib.sha256()
                with Path(path).open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
                cls.binaries.append({"core": kind, "version": (result.stdout + result.stderr).strip(),
                                     "sha256": digest.hexdigest(), "version_exit_code": result.returncode})

    @classmethod
    def tearDownClass(cls):
        report_path = os.environ.get("GNETWORK_VALIDATE_REPORT")
        if report_path:
            report = {"status": "passed" if cls.records and all(item["exit_code"] == 0 for item in cls.records) else "failed",
                      "binaries": cls.binaries, "invocations": len(cls.records), "checks": cls.records,
                      "scope": "Parse-only official-core checks using fake documentation nodes; no runtime starts, real node connections, user configs or GeoIP downloads.",
                      "coverage": ["six protocols", "two and three hop independent chain copies", "split DNS and respect-rules",
                                   "VLESS encryption + Vision over WS/gRPC", "SS obfs plugin", "new per-node Clash protocols", "existing Xray export"],
                      "limitations": "Successful parsing verifies syntax and accepted parameters, not network reachability or handshake success."}
            Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def validate_yaml(self, text):
        with tempfile.TemporaryDirectory(prefix="gnetwork-studio-core-") as temporary:
            path = Path(temporary) / "config.yaml"
            path.write_text(text, encoding="utf-8")
            result = subprocess.run([MIHOMO, "-t", "-d", temporary, "-f", str(path)],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
            self.records.append({"test": self.id().rsplit(".", 1)[-1], "core": "mihomo", "arguments": ["-t", "-d", "isolated-temp", "-f", "config.yaml"],
                                 "config_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                                 "exit_code": result.returncode, "diagnostics": (result.stdout + result.stderr)[-1500:]})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(MIHOMO and Path(MIHOMO).is_file(), "official Mihomo binary not configured")
    def test_six_protocols_two_hop_chain_and_split_dns(self):
        nodes = [fixture(kind) for kind in ("ss", "vmess", "vless", "trojan", "hysteria2", "tuic")]
        settings = profile([{"name": "测试链路", "hops": IDS[:2]}], members=[*IDS[:6], "测试链路"],
                           advanced={"dns": {"enable": True, "listen": "127.0.0.1:1053", "enhanced-mode": "fake-ip",
                                             "respect-rules": True, "nameserver": ["https://dns.alidns.com/dns-query"],
                                             "proxy-server-nameserver": ["223.5.5.5"], "direct-nameserver": ["system"]}})
        result = build_workspace_configuration(nodes, IDS[:6], settings)
        self.validate_yaml(result["yaml"])

    @unittest.skipUnless(MIHOMO and Path(MIHOMO).is_file(), "official Mihomo binary not configured")
    def test_three_hop_chain_keeps_all_connection_layers(self):
        nodes = [fixture("ss", "第一跳"), fixture("vmess", "第二跳"), fixture("ss", "落地")]
        result = build_workspace_configuration(nodes, IDS[:3], profile([{"name": "三跳链", "hops": IDS[:3]}], members=["三跳链"]))
        proxies = result["config"]["proxies"]
        self.assertEqual(len(proxies), 6)
        self.assertEqual(proxies[-1]["dialer-proxy"], proxies[-2]["name"])
        self.assertEqual(proxies[-2]["dialer-proxy"], proxies[-3]["name"])
        self.validate_yaml(result["yaml"])

    @unittest.skipUnless(MIHOMO and Path(MIHOMO).is_file(), "official Mihomo binary not configured")
    def test_vless_encryption_and_vision_preserved_for_ws_and_grpc(self):
        for network, transport in (("ws", {"ws-opts": {"path": "/demo", "headers": {"Host": "example.test"}}}),
                                   ("grpc", {"grpc-opts": {"grpc-service-name": "GunService"}})):
            with self.subTest(network=network):
                node = {**fixture("vless"), "network": network, "encryption": "mlkem768x25519plus.native.1rtt." + KEY,
                        "flow": "xtls-rprx-vision", **transport}
                result = build_node_routing(node, {"enabled": True, "direct_domains": ["example.com"]})
                self.assertFalse(result["xray"]["available"])
                self.validate_yaml(result["clash"]["yaml"])

    @unittest.skipUnless(MIHOMO and Path(MIHOMO).is_file(), "official Mihomo binary not configured")
    def test_ss_plugin_and_per_node_new_protocols(self):
        nodes = [fixture(kind) for kind in ("trojan", "hysteria2", "tuic")]
        nodes.append({**fixture("ss"), "plugin": "obfs", "plugin-opts": {"mode": "http", "host": "example.com"}})
        for node in nodes:
            with self.subTest(protocol=node["type"]):
                result = build_node_routing(node, {"enabled": True, "direct_domains": ["example.com"]})
                self.assertFalse(result["xray"]["available"])
                self.validate_yaml(result["clash"]["yaml"])

    @unittest.skipUnless(XRAY and Path(XRAY).is_file(), "official Xray binary not configured")
    def test_existing_xray_conversion_is_still_valid(self):
        nodes = [fixture(kind) for kind in ("ss", "vmess", "vless")]
        nodes.append({**fixture("vmess"), "network": "ws", "ws-opts": {"path": "/demo", "headers": {"Host": "example.test"}}})
        for node in nodes:
            with self.subTest(protocol=node["type"], network=node.get("network")):
                result = build_node_routing(node, {"enabled": True, "direct_domains": ["example.com"]})
                self.assertTrue(result["xray"]["available"])
                with tempfile.TemporaryDirectory(prefix="gnetwork-xray-core-") as temporary:
                    path = Path(temporary) / "client.json"
                    path.write_text(result["xray"]["json"], encoding="utf-8")
                    json.loads(path.read_text(encoding="utf-8"))
                    checked = subprocess.run([XRAY, "run", "-test", "-format", "json", "-config", str(path)],
                                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
                    self.records.append({"test": self.id().rsplit(".", 1)[-1], "core": "xray", "arguments": ["run", "-test", "-format", "json", "-config", "client.json"],
                                         "config_sha256": hashlib.sha256(result["xray"]["json"].encode("utf-8")).hexdigest(),
                                         "exit_code": checked.returncode, "diagnostics": (checked.stdout + checked.stderr)[-1500:]})
                    self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)


if __name__ == "__main__":
    unittest.main()
