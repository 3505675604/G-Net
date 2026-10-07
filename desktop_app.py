# -*- coding: utf-8 -*-
"""FL Network Windows desktop entry point and isolated frozen-bundle smoke test."""
from __future__ import annotations

import argparse
import contextlib
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

from app_metadata import APP_NAME, APP_VERSION, PRODUCT_NAME
WEBVIEW_DOWNLOAD = "https://developer.microsoft.com/microsoft-edge/webview2/"


def resource_root() -> Path:
    """PyInstaller resources are read-only; they never hold user credentials."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def user_data_dir(explicit: str | None = None) -> Path:
    selected = explicit if explicit is not None else os.environ.get("FL_NETWORK_DATA_DIR")
    if selected is not None:
        path = Path(selected).expanduser()
        if not selected or not path.is_absolute():
            raise ValueError("用户数据目录必须是绝对路径")
        return path.resolve()
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise RuntimeError("未找到 Windows 用户数据目录 LOCALAPPDATA")
    return Path(local).resolve() / "FLNetwork" / "data"


def setup_logging(data_dir: Path) -> None:
    log_dir = data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_dir / "desktop.log", maxBytes=512 * 1024,
                                  backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger = logging.getLogger("flnetwork.desktop")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    # Request URLs may carry WebSocket session tokens; do not retain access logs.
    logging.getLogger("werkzeug").setLevel(logging.ERROR)


def message_box(message: str, *, error: bool = False) -> None:
    if os.name == "nt":
        ctypes.windll.user32.MessageBoxW(None, message, APP_NAME, 0x10 if error else 0x40)
    elif sys.stderr:
        print(message, file=sys.stderr)


class SingleInstance:
    """One process per desktop profile, scoped to the current Windows session."""
    def __init__(self, data_dir: Path):
        digest = hashlib.sha256(os.path.normcase(str(data_dir)).encode()).hexdigest()[:24]
        self.name = "Local\\FLNetwork-" + digest
        self.handle = None
        self.kernel = None

    def acquire(self) -> bool:
        if os.name != "nt":
            raise RuntimeError("此桌面版本支持 Windows 10/11 x64")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        self.kernel.CreateMutexW.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        ctypes.set_last_error(0)
        self.handle = self.kernel.CreateMutexW(None, False, self.name)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            self.close()
            return False
        return True

    def close(self) -> None:
        if self.handle is not None:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def focus_existing_window() -> None:
    """A second shortcut click restores the existing app instead of spawning it."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowW.restype = wintypes.HWND
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    user32.SetForegroundWindow.restype = wintypes.BOOL
    handle = user32.FindWindowW(None, APP_NAME)
    if handle:
        user32.ShowWindow(handle, 9)
        user32.SetForegroundWindow(handle)


def load_backend(data_dir: Path):
    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ["FL_NETWORK_DATA_DIR"] = str(data_dir)
    source = resource_root() / "server-manager" / "app.py"
    if not source.is_file():
        raise RuntimeError("程序资源缺失，请重新安装 G-Network")
    spec = importlib.util.spec_from_file_location("flnetwork_desktop_backend", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载本地管理服务")
    backend = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = backend
    try:
        spec.loader.exec_module(backend)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return backend


class DesktopServer:
    def __init__(self, backend):
        from werkzeug.serving import WSGIRequestHandler, make_server

        class QuietRequestHandler(WSGIRequestHandler):
            def log_request(self, code="-", size="-"):
                pass

        self.backend = backend
        self.server = make_server("127.0.0.1", 0, backend.app, threaded=True,
                                  request_handler=QuietRequestHandler)
        self.port = self.server.server_port
        self.url = f"http://127.0.0.1:{self.port}"
        try:
            backend.configure_local_access(self.port)
        except BaseException:
            self.server.server_close()
            backend.shutdown_resources()
            raise
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name="FLNetwork-local-service", daemon=True)
        self.started = False
        self.closed = False
        self.lock = threading.Lock()

    def start(self):
        try:
            self.thread.start()
        except BaseException:
            self.close()
            raise
        self.started = True
        return self

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = True
            try:
                if self.started:
                    self.server.shutdown()
            finally:
                try:
                    self.server.server_close()
                finally:
                    try:
                        self.backend.shutdown_resources()
                    finally:
                        if self.started:
                            self.thread.join(timeout=3)


def has_running_jobs(backend) -> bool:
    with backend.JOB_LOCK:
        return any(job.get("status") == "running" for job in backend.jobs.values())


def allow_window_close(backend) -> bool:
    if not backend.prepare_shutdown():
        message_box("服务器任务正在执行。请等待工具安装或节点部署完成后再退出，避免中断操作。")
        return False
    return True


def check_webview_runtime() -> str:
    """Load the packaged .NET bridge and SDK without creating or showing a window."""
    if os.name != "nt":
        raise RuntimeError("此桌面版本支持 Windows 10/11 x64")
    import clr
    from webview.util import interop_dll_path
    clr.AddReference("System.Windows.Forms")
    clr.AddReference(interop_dll_path("Microsoft.Web.WebView2.Core.dll"))
    clr.AddReference(interop_dll_path("Microsoft.Web.WebView2.WinForms.dll"))
    from Microsoft.Web.WebView2.Core import CoreWebView2Environment
    version = str(CoreWebView2Environment.GetAvailableBrowserVersionString())
    if not version:
        raise RuntimeError("未检测到 Microsoft Edge WebView2 Runtime")
    return version


def main_window(service: DesktopServer, data_dir: Path) -> None:
    import webview
    check_webview_runtime()
    webview.settings["ALLOW_DOWNLOADS"] = True
    webview.settings["ALLOW_FILE_URLS"] = False
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
    webview.settings["IGNORE_SSL_ERRORS"] = False
    webview.settings["REMOTE_DEBUGGING_PORT"] = None
    window = webview.create_window(APP_NAME, service.url, width=1380, height=900,
                                   min_size=(1024, 700), background_color="#080c15",
                                   text_select=True, zoomable=False)
    window.events.closing += lambda: allow_window_close(service.backend)
    window.events.closed += service.close
    profile = data_dir.parent / "webview"
    profile.mkdir(parents=True, exist_ok=True)
    webview.start(gui="edgechromium", debug=False, private_mode=True,
                  storage_path=str(profile), icon=str(resource_root() / "packaging" / "fl-network.ico"),
                  localization={"global.quitConfirmation": "确定退出 G-Network？",
                                "global.ok": "确定", "global.cancel": "取消",
                                "global.saveFile": "保存文件", "global.openFile": "打开文件",
                                "global.selectFolder": "选择文件夹"})


def _probe(service: DesktopServer, path: str, *, token=None, method="GET", data=None, headers=None):
    actual_headers = dict(headers or {})
    if token:
        actual_headers["X-CSRF-Token"] = token
    payload = None if data is None else json.dumps(data).encode("utf-8")
    if payload is not None:
        actual_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(service.url + path, data=payload, headers=actual_headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as response:
        with response:
            return response.code, response.read()


def self_test(report_path: Path) -> int:
    """Exercise the exact installed bundle with a disposable, empty user profile."""
    report = {"app": PRODUCT_NAME, "version": APP_VERSION, "status": "failed",
              "data_isolated": True, "checks": []}
    service = None

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise RuntimeError("Self-test failed: " + name)

    try:
        with tempfile.TemporaryDirectory(prefix="flnetwork-selftest-") as scratch:
            data_dir = Path(scratch) / "profile"
            original_env = os.environ.get("FL_NETWORK_DATA_DIR")
            try:
                backend = load_backend(data_dir)
                service = DesktopServer(backend).start()
                check("loopback-random-port", service.server.server_address[0] == "127.0.0.1" and service.port > 0)
                check("bundled-window-icon", (resource_root() / "packaging" / "fl-network.ico").is_file())
                status, body = _probe(service, "/")
                check("bundled-template", status == 200 and "网络指挥中心".encode() in body)
                for asset in ("network-theme.css", "network-scene.js", "product-ui.js", "fl-network.svg",
                              "clash-workspace.js", "clash-workspace.css",
                              "vendor/xterm-5.3.0.min.js", "vendor/xterm-addon-fit-0.8.0.min.js",
                              "vendor/qrcode-1.0.0.min.js"):
                    status, body = _probe(service, "/static/" + asset)
                    check("bundled-" + asset, status == 200 and len(body) > 100)
                status, _ = _probe(service, "/api/servers")
                check("csrf-rejects-missing-token", status == 403)
                status, _ = _probe(service, "/api/servers", token=backend.CSRF_TOKEN,
                                   headers={"Host": "attacker.invalid"})
                check("host-rejects-rebinding", status == 403)
                status, _ = _probe(service, "/api/servers", token=backend.CSRF_TOKEN,
                                   headers={"Origin": "https://attacker.invalid"})
                check("origin-rejects-cross-site", status == 403)
                status, body = _probe(service, "/api/servers", token=backend.CSRF_TOKEN)
                check("empty-private-profile", status == 200 and json.loads(body) == [])
                password = "FAKE-selftest-password-only"
                status, _ = _probe(service, "/api/servers", token=backend.CSRF_TOKEN, method="POST",
                                   data={"host": "192.0.2.1", "name": "自检服务器", "password": password, "user": "root", "port": 22})
                check("per-user-profile-write", status == 200 and Path(backend.SERVERS_FILE).parent == data_dir)
                saved = Path(backend.SERVERS_FILE).read_text(encoding="utf-8")
                check("dpapi-protects-password", password not in saved and "dpapi:v1:" in saved)
                check("dpapi-roundtrip", backend.load_json(backend.SERVERS_FILE, [])[0]["password"] == password)
                status, body = _probe(service, "/api/servers", token=backend.CSRF_TOKEN)
                check("api-omits-password", status == 200 and "password" not in json.loads(body)[0])
                key = "FAKE-selftest-key-only"
                status, _ = _probe(service, "/api/settings", token=backend.CSRF_TOKEN, method="POST", data={"openai_key": key})
                status, body = _probe(service, "/api/settings", token=backend.CSRF_TOKEN)
                check("settings-expose-presence-only", status == 200 and json.loads(body)["openai_key_set"] and key.encode() not in body)
                check("dpapi-protects-api-key", key not in Path(backend.SETTINGS_FILE).read_text(encoding="utf-8"))
                status, body = _probe(service, "/api/product", token=backend.CSRF_TOKEN)
                product = json.loads(body)
                check("bundled-product-services", status == 200 and product["product"]["name"] == PRODUCT_NAME and product["product"]["version"] == APP_VERSION)
                check("first-use-onboarding", product["onboarding"]["completed"] is False)
                status, _ = _probe(service, "/api/product/onboarding", token=backend.CSRF_TOKEN,
                                   method="POST", data={"completed": True})
                status, body = _probe(service, "/api/product", token=backend.CSRF_TOKEN)
                check("persistent-onboarding", status == 200 and json.loads(body)["onboarding"]["completed"] is True)
                for page in ("help", "privacy", "license"):
                    status, body = _probe(service, "/" + page)
                    check("bundled-page-" + page, status == 200 and b"G-Network" in body)
                status, body = _probe(service, "/api/product/backup/export", token=backend.CSRF_TOKEN,
                                       method="POST", data={"mode": "metadata"})
                metadata_backup = json.loads(body)["backup"]
                check("metadata-backup-omits-secrets", status == 200 and password.encode() not in body and key.encode() not in body)
                status, body = _probe(service, "/api/product/backup/export", token=backend.CSRF_TOKEN,
                                       method="POST", data={"mode": "encrypted", "passphrase": "FAKE-selftest-backup-password-only"})
                encrypted_backup = json.loads(body)["backup"]
                check("bundled-cryptographic-backup", status == 200 and encrypted_backup["mode"] == "encrypted" and password.encode() not in body)
                status, body = _probe(service, "/api/product/backup/preview", token=backend.CSRF_TOKEN,
                                       method="POST", data={"backup": encrypted_backup, "passphrase": "FAKE-selftest-backup-password-only"})
                check("encrypted-backup-preview", status == 200 and json.loads(body)["server_count"] == 1)
                status, _ = _probe(service, "/api/product/backup/preview", token=backend.CSRF_TOKEN,
                                    method="POST", data={"backup": encrypted_backup, "passphrase": "FAKE-wrong-selftest-password-only"})
                check("backup-rejects-wrong-password", status == 400)
                status, body = _probe(service, "/api/product/diagnostics", token=backend.CSRF_TOKEN)
                check("diagnostics-redacted", status == 200 and all(secret.encode() not in body for secret in (password, key, "192.0.2.1", "自检服务器")))
                status, _ = _probe(service, "/api/product/backup/export", method="POST", data={"mode": "encrypted"})
                check("backup-requires-panel-token", status == 403)
                from script_common import parse_private_key
                import paramiko
                import io
                private = io.StringIO()
                paramiko.RSAKey.generate(2048).write_private_key(private, password="FAKE-selftest-key-passphrase")
                status, _ = _probe(service, "/api/servers", token=backend.CSRF_TOKEN, method="POST",
                                   data={"host": "192.0.2.2", "user": "root", "auth_type": "private_key",
                                         "private_key": private.getvalue(), "key_passphrase": "FAKE-selftest-key-passphrase"})
                check("bundled-private-key-parser", status == 200 and parse_private_key(private.getvalue(), "FAKE-selftest-key-passphrase").get_name() == "ssh-rsa")
                status, body = _probe(service, "/api/servers", token=backend.CSRF_TOKEN)
                check("server-list-omits-all-auth-secrets", status == 200 and all(field not in json.loads(body)[-1] for field in ("password", "private_key", "key_passphrase")))
                saved = Path(backend.SERVERS_FILE).read_text(encoding="utf-8")
                check("dpapi-protects-private-key-and-passphrase", private.getvalue() not in saved and "FAKE-selftest-key-passphrase" not in saved)
                exported = backend._register_clash_export(
                    {"host": "192.0.2.1", "port": 22, "user": "root"},
                    {"tag": "selftest-ss", "protocol": "shadowsocks", "port": 8388,
                     "settings": {"method": "aes-128-gcm", "password": "FAKE-node-password-only", "network": "tcp,udp"}},
                    "192.0.2.1", 8388)
                check("bundled-clash-export-module", exported.get("available") and exported["compatibility"] == "classic")
                export_path = urllib.parse.urlsplit(exported["url"]).path
                status, body = _probe(service, export_path)
                check("clash-client-download-without-panel-token", status == 200 and body.decode("utf-8") == exported["yaml"])
                check("clash-yaml-private-node-only", "FAKE-node-password-only" in exported["yaml"] and password not in exported["yaml"])
                status, _ = _probe(service, export_path, headers={"Origin": "https://attacker.invalid"})
                check("clash-download-keeps-origin-guard", status == 403)
                status, _ = _probe(service, "/api/clash-export/" + "A" * 43 + ".yaml")
                check("clash-invalid-export-token-rejected", status == 404)
                second = backend._register_clash_export(
                    {"host": "192.0.2.2", "port": 22, "user": "root"},
                    {"tag": "selftest-second", "protocol": "shadowsocks", "port": 8389,
                     "settings": {"method": "aes-128-gcm", "password": "FAKE-second-node", "network": "tcp,udp"}},
                    "192.0.2.2", 8389)
                selected = [exported["selection_token"], second["selection_token"]]
                snapshot = backend.CLASH_SNAPSHOTS.register([{"id": token, "available": True} for token in selected])
                status, body = _probe(service, "/api/clash-workspace/export", token=backend.CSRF_TOKEN, method="POST",
                                     data={"snapshot_id": snapshot, "node_ids": selected, "profile": {
                                         "name": "isolated-selftest", "template": "custom", "rules": [
                                             {"type": "DOMAIN-SUFFIX", "value": "example.com", "target": "DIRECT"}]}})
                combined = json.loads(body)
                check("bundled-multi-node-clash-workspace", status == 200 and combined.get("node_count") == 2 and
                      combined.get("group_count") == 3 and combined.get("rule_count") == 2)
                combined_path = urllib.parse.urlsplit(combined["clash"]["url"]).path
                status, body = _probe(service, combined_path)
                check("clash-workspace-download-contains-both-nodes", status == 200 and
                      b"FAKE-second-node" in body and b"FAKE-node-password-only" in body and password.encode() not in body)
                status, _ = _probe(service, "/api/clash-workspace/export", method="POST", data={})
                check("clash-workspace-keeps-csrf-guard", status == 403)
                status, body = _probe(service, "/api/node-routing/save", token=backend.CSRF_TOKEN,
                                     method="POST", data={"snapshot_id": snapshot, "node_id": selected[0],
                                         "enabled": True, "direct_domains": ["example.cn", "example.com"],
                                         "expected_revision": 0})
                routing_saved = json.loads(body)
                check("bundled-node-domain-save", status == 200 and routing_saved["routing"]["revision"] == 1)
                routing_file = Path(backend.NODE_ROUTING_FILE)
                routing_bytes = routing_file.read_bytes()
                check("node-routing-store-no-credentials", routing_file.parent == data_dir and
                      all(secret.encode() not in routing_bytes for secret in
                          (password, key, "FAKE-node-password-only", "FAKE-second-node")))
                status, body = _probe(service, "/api/node-routing/export", token=backend.CSRF_TOKEN,
                                     method="POST", data={"snapshot_id": snapshot, "node_id": selected[0]})
                node_routed = json.loads(body)
                check("bundled-node-routing-clash-xray-export", status == 200 and
                      node_routed["clash"]["available"] and node_routed["xray"]["available"])
                xray_client = json.loads(node_routed["xray"]["json"])
                client_rules = xray_client["routing"]["rules"]
                check("node-routing-domain-whitelist-and-proxy-default",
                      "DOMAIN-SUFFIX,example.cn,DIRECT" in node_routed["clash"]["yaml"] and
                      "FAKE-second-node" not in node_routed["clash"]["yaml"] and
                      any("domain:example.cn" in rule.get("domain", []) and rule.get("outboundTag") == "direct"
                          for rule in client_rules) and client_rules[-1].get("outboundTag") == "proxy")
                routed_path = urllib.parse.urlsplit(node_routed["clash"]["url"]).path
                status, body = _probe(service, "/api/node-routing/export", token=backend.CSRF_TOKEN,
                                     method="POST", data={"snapshot_id": snapshot, "node_id": selected[1]})
                other_routed = json.loads(body)
                check("node-routing-does-not-change-other-node", status == 200 and
                      other_routed["routing"]["direct_domains"] == [] and
                      "DOMAIN-SUFFIX,example.cn,DIRECT" not in other_routed["clash"]["yaml"])
                status, _ = _probe(service, "/api/node-routing/save", token=backend.CSRF_TOKEN,
                                   method="POST", data={"snapshot_id": snapshot, "node_id": selected[0],
                                       "enabled": True, "direct_domains": ["example.cn"], "expected_revision": 1})
                check("node-routing-save-keeps-source-selection-valid", status == 200 and
                      backend.CLASH_EXPORTS.get_proxy(selected[0]) is not None)
                status, _ = _probe(service, routed_path)
                check("node-routing-url-revoked-on-edit", status == 404)
                status, _ = _probe(service, "/api/node-routing/save", method="POST", data={})
                check("node-routing-keeps-csrf-guard", status == 403)
                # Frozen importer, YAML dependency, chain builder and encrypted
                # draft reopening are checked against disposable fake nodes.
                studio_doc = json.dumps({"mixed-port": 7891, "proxies": [
                    {"name": "selftest-entry", "type": "ss", "server": "192.0.2.21", "port": 443,
                     "cipher": "aes-128-gcm", "password": "FAKE-studio-entry"},
                    {"name": "selftest-exit", "type": "trojan", "server": "192.0.2.22", "port": 443,
                     "password": "FAKE-studio-exit", "sni": "example.test", "dialer-proxy": "selftest-entry"}],
                    "proxy-groups": [{"name": "studio-policy", "type": "select", "proxies": ["selftest-exit"]}],
                    "rules": ["DOMAIN-SUFFIX,example.cn,DIRECT", "MATCH,studio-policy"],
                    "dns": {"enable": True, "listen": "127.0.0.1:1053", "nameserver": ["https://dns.alidns.com/dns-query"]}})
                status, body = _probe(service, "/api/clash-workspace/import-preview", token=backend.CSRF_TOKEN,
                                     method="POST", data={"text": studio_doc, "format": "yaml"})
                preview = json.loads(body)
                check("bundled-safe-yaml-import", status == 200 and preview.get("can_replace") and
                      preview.get("node_count") == 2 and preview.get("chain_count") == 1)
                check("studio-preview-omits-node-credentials", b"FAKE-studio-entry" not in body and b"FAKE-studio-exit" not in body)
                status, body = _probe(service, "/api/clash-workspace/import", token=backend.CSRF_TOKEN, method="POST",
                                     data={"import_token": preview["import_token"], "mode": "replace"})
                imported = json.loads(body)
                check("bundled-studio-import-catalog", status == 200 and len(imported.get("nodes", [])) == 2)
                draft = {"snapshot_id": imported["snapshot_id"], "node_ids": imported["imported_ids"], "profile": imported["profile"]}
                status, body = _probe(service, "/api/clash-workspace/export", token=backend.CSRF_TOKEN, method="POST", data=draft)
                check("bundled-chain-and-dns-export", status == 200 and b"dialer-proxy" in body and b"dns:" in body)
                status, body = _probe(service, "/api/clash-workspace/profiles/save", token=backend.CSRF_TOKEN, method="POST", data=draft)
                saved_profile = json.loads(body)
                check("bundled-studio-profile-save", status == 200 and saved_profile["profile"]["revision"] == 1)
                profile_bytes = (data_dir / "clash-profiles.json").read_bytes()
                check("dpapi-protects-entire-clash-draft", b"dpapi:v1:" in profile_bytes and
                      b"FAKE-studio-entry" not in profile_bytes and b"FAKE-studio-exit" not in profile_bytes and
                      b"192.0.2.21" not in profile_bytes)
                backend.CLASH_SNAPSHOTS.clear()
                status, body = _probe(service, "/api/clash-workspace/profiles/open", token=backend.CSRF_TOKEN, method="POST",
                                     data={"profile_id": saved_profile["profile"]["id"]})
                reopened = json.loads(body)
                check("bundled-studio-profile-open-after-expiry", status == 200 and len(reopened["nodes"]) == 2 and
                      b"FAKE-studio-entry" not in body and reopened["profile"]["chains"][0]["hops"] == reopened["imported_ids"])
                status, _ = _probe(service, "/api/clash-workspace/import-preview", method="POST", data={"text": studio_doc})
                check("studio-import-keeps-csrf-guard", status == 403)
                backend.CLASH_EXPORTS.revoke_scope(("192.0.2.2", 22))
                status, _ = _probe(service, combined_path)
                check("clash-workspace-revokes-changed-source", status == 404)
                status, body = _probe(service, "/api/settings", token=backend.CSRF_TOKEN)
                check("ssh-auto-refresh-default-enabled", status == 200 and json.loads(body)["ssh_auto_update_host_key"] is True)
                status, _ = _probe(service, "/api/settings", token=backend.CSRF_TOKEN, method="POST",
                                   data={"ssh_auto_update_host_key": False})
                status, body = _probe(service, "/api/settings", token=backend.CSRF_TOKEN)
                check("ssh-auto-refresh-setting-persisted", status == 200 and json.loads(body)["ssh_auto_update_host_key"] is False)
                backend.jobs["smoke"] = {"status": "running"}
                check("active-task-close-guard", has_running_jobs(backend) and not backend.prepare_shutdown())
                backend.jobs.clear()
                report["webview_runtime"] = check_webview_runtime()
                check("packaged-dotnet-webview2", bool(report["webview_runtime"]))
                port = service.port
                check("idle-close-prepares-shutdown", backend.prepare_shutdown())
                try:
                    backend.new_job([])
                except ValueError:
                    check("closing-rejects-new-tasks", True)
                else:
                    check("closing-rejects-new-tasks", False)
                service.close()
                check("clash-links-revoked-on-close", backend.CLASH_EXPORTS.get(export_path.rsplit("/", 1)[-1][:-5]) is None)
                check("server-thread-stopped", not service.thread.is_alive())
                with socket.socket() as probe:
                    check("loopback-port-released", probe.connect_ex(("127.0.0.1", port)) != 0)
                service = None
            finally:
                if service is not None:
                    service.close()
                if original_env is None:
                    os.environ.pop("FL_NETWORK_DATA_DIR", None)
                else:
                    os.environ["FL_NETWORK_DATA_DIR"] = original_env
        report["status"] = "passed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if report["status"] == "passed" else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--self-test", type=Path, metavar="REPORT_JSON")
    parser.add_argument("--data-dir", help="独立用户数据目录（必须为绝对路径）")
    args = parser.parse_args(argv)
    if args.self_test is not None:
        return self_test(args.self_test)
    instance = None
    service = None
    try:
        data_dir = user_data_dir(args.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        instance = SingleInstance(data_dir)
        if not instance.acquire():
            focus_existing_window()
            return 0
        setup_logging(data_dir)
        logging.getLogger("flnetwork.desktop").info("Starting G-Network %s", APP_VERSION)
        backend = load_backend(data_dir)
        service = DesktopServer(backend).start()
        main_window(service, data_dir)
        return 0
    except Exception as error:
        logging.getLogger("flnetwork.desktop").exception("Desktop startup failed")
        message_box("G-Network 启动失败。\n\n" + str(error) +
                    "\n\n如提示 WebView2 或 .NET 组件缺失，请安装 Microsoft 官方 WebView2 Runtime 并重试。\n" + WEBVIEW_DOWNLOAD,
                    error=True)
        return 1
    finally:
        if service is not None:
            service.close()
        if instance is not None:
            instance.close()


if __name__ == "__main__":
    raise SystemExit(main())
