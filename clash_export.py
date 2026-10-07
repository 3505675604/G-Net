"""Clash / Mihomo configuration export, without network or filesystem access.

Clash configuration is YAML; scalar strings are JSON-quoted, which is also
valid YAML and prevents node names, WS paths and passwords becoming syntax.
The short-lived HTTP exports below are capabilities held only in memory.
"""
import base64
import copy
from contextlib import contextmanager
from collections import OrderedDict
import json
import re
import secrets
import threading
import time
import urllib.parse
import uuid

from local_security import validate_host, validate_port

TOKEN_PATTERN = r"[A-Za-z0-9_-]{43}"
EXPORT_PATH_PATTERN = rf"/api/clash-export/{TOKEN_PATTERN}\.yaml"
SS_CLASSIC = frozenset(("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"))
SS_2022 = frozenset(("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                     "2022-blake3-chacha20-poly1305"))
LOCAL_NOTICE = ("链接仅供同一台电脑的 Clash 导入，需保持本程序运行，最长 24 小时有效；"
                "重新读取、部署、删除节点或退出程序后旧链接会失效，可重新读取列表生成新链接。"
                "YAML 文件可保存后导入其他设备。")


class UnsupportedExport(ValueError):
    """The node cannot be represented faithfully by this exporter."""


class SourceCapabilityChanged(ValueError):
    """A cached source changed while a derived operation was in progress."""


def _text(value, label, *, empty=False, limit=8192):
    if not isinstance(value, str) or len(value) > limit or (not value and not empty):
        raise UnsupportedExport(f"{label}格式无效")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise UnsupportedExport(f"{label}格式无效") from error
    return value


def _number(value, label, low, high):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise UnsupportedExport(f"{label}格式无效")
    number = int(value)
    if not low <= number <= high:
        raise UnsupportedExport(f"{label}超出有效范围")
    return number


def _identifier(value):
    value = _text(value, "UUID", limit=64)
    try:
        return str(uuid.UUID(value))
    except ValueError as error:
        raise UnsupportedExport("UUID 格式无效") from error


def _base(name, protocol, host, port):
    try:
        host, port = validate_host(host), validate_port(port)
    except ValueError as error:
        raise UnsupportedExport("节点地址或端口无效") from error
    # Reserve built-in policy names and keep commas out of policy group rules.
    name = _text(name or f"{protocol}-{host}:{port}", "节点名称", limit=500)
    if name in {"DIRECT", "REJECT", "GLOBAL", "FL Network"}:
        name += " · 节点"
    return {"name": name, "type": protocol, "server": host, "port": port, "udp": True}


def _decode64(value):
    value = _text(value, "分享链接", limit=32768)
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise UnsupportedExport("分享链接的 Base64 内容无效") from error


def _query(parts):
    entries = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    if any(len(values) != 1 for values in entries.values()):
        raise UnsupportedExport("分享链接包含重复参数")
    return {key: values[0] for key, values in entries.items()}


def _tls(proxy, security, options):
    if security not in ("", "none", "tls", "reality"):
        raise UnsupportedExport("暂不支持此 TLS 安全类型")
    proxy["tls"] = security in ("tls", "reality")
    if not proxy["tls"]:
        return
    servername = options.get("sni") or options.get("servername") or ""
    if servername:
        proxy["servername"] = _text(servername, "SNI", limit=253)
    # Certificate verification stays enabled; no skip-cert-verify is emitted.
    alpn = options.get("alpn")
    if alpn:
        values = alpn.split(",") if isinstance(alpn, str) else alpn
        if not isinstance(values, list) or len(values) > 10:
            raise UnsupportedExport("ALPN 格式无效")
        proxy["alpn"] = [_text(item, "ALPN", limit=255) for item in values]
    if security == "reality":
        public = _text(options.get("pbk", ""), "Reality 公钥", limit=128)
        try:
            key = base64.b64decode(public + "=" * (-len(public) % 4), altchars=b"-_", validate=True)
        except ValueError as error:
            raise UnsupportedExport("Reality 公钥格式无效") from error
        if len(key) != 32:
            raise UnsupportedExport("Reality 公钥长度无效")
        short_id = _text(options.get("sid", ""), "Reality shortId", empty=True, limit=16)
        if short_id and not re.fullmatch(r"(?:[a-fA-F0-9]{2}){1,8}", short_id):
            raise UnsupportedExport("Reality shortId 格式无效")
        proxy["reality-opts"] = {"public-key": public, "short-id": short_id}
        fingerprint = options.get("fp")
        if fingerprint:
            proxy["client-fingerprint"] = _text(fingerprint, "TLS 指纹", limit=64)


def _transport(proxy, network, path="/", headers=None):
    network = network or "tcp"
    if network == "raw":
        network = "tcp"
    if network not in ("tcp", "ws"):
        raise UnsupportedExport(f"暂不支持 {network} 传输方式的 Clash 导出")
    proxy["network"] = network
    if network == "ws":
        ws = {"path": _text(path or "/", "WebSocket 路径")}
        if headers:
            if not isinstance(headers, dict) or len(headers) > 32:
                raise UnsupportedExport("WebSocket 请求头格式无效")
            ws["headers"] = {_text(key, "请求头名称", limit=255): _text(value, "请求头内容", empty=True)
                             for key, value in headers.items()}
        proxy["ws-opts"] = ws


def _ss(proxy, method, password):
    if method not in SS_CLASSIC | SS_2022:
        raise UnsupportedExport("暂不支持此 Shadowsocks 加密方式的 Clash 导出")
    password = _text(password, "Shadowsocks 密码")
    if method in SS_2022:
        size = 16 if method == "2022-blake3-aes-128-gcm" else 32
        for key in password.split(":"):
            try:
                data = base64.b64decode(key, validate=True)
            except ValueError as error:
                raise UnsupportedExport("SS2022 密钥格式无效") from error
            if len(data) != size:
                raise UnsupportedExport("SS2022 密钥长度无效")
    proxy.update(cipher=method, password=password)


def proxy_from_uri(uri):
    """Parse the project's VLESS, VMess and SIP002 SS share URIs safely."""
    uri = _text(uri, "分享链接", limit=32768)
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme == "vmess":
        try:
            data = json.loads(_decode64(uri[len("vmess://"):]))
        except (ValueError, TypeError) as error:
            raise UnsupportedExport("VMess 分享内容无效") from error
        if not isinstance(data, dict):
            raise UnsupportedExport("VMess 分享内容无效")
        proxy = _base(data.get("ps"), "vmess", data.get("add"), data.get("port"))
        proxy["uuid"] = _identifier(data.get("id"))
        proxy["alterId"] = _number(data.get("aid", 0), "alterId", 0, 65535)
        cipher = data.get("scy", "auto") or "auto"
        if cipher not in ("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"):
            raise UnsupportedExport("VMess 加密方式无效")
        proxy["cipher"] = cipher
        _tls(proxy, data.get("tls", ""), data)
        _transport(proxy, data.get("net", "tcp"), data.get("path", "/"),
                   {"Host": data["host"]} if data.get("host") else None)
        return proxy
    if parts.scheme not in ("vless", "ss"):
        raise UnsupportedExport("当前节点协议暂不支持 Clash 导出")
    try:
        host, port = parts.hostname, parts.port
    except ValueError as error:
        raise UnsupportedExport("分享链接的地址或端口无效") from error
    proxy = _base(urllib.parse.unquote(parts.fragment), parts.scheme, host, port)
    options = _query(parts)
    if parts.scheme == "ss":
        if options.get("plugin"):
            raise UnsupportedExport("暂不支持带插件的 Shadowsocks 分享链接")
        if parts.password is not None:
            credentials = urllib.parse.unquote(parts.username or "") + ":" + urllib.parse.unquote(parts.password)
        else:
            credentials = _decode64(urllib.parse.unquote(parts.username or ""))
        if ":" not in credentials:
            raise UnsupportedExport("Shadowsocks 分享内容缺少密码")
        _ss(proxy, *credentials.split(":", 1))
        return proxy
    if parts.password is not None:
        raise UnsupportedExport("VLESS 分享链接格式无效")
    if options.get("encryption", "none") != "none":
        raise UnsupportedExport("暂不支持此 VLESS 加密方式")
    proxy["uuid"] = _identifier(urllib.parse.unquote(parts.username or ""))
    security = options.get("security", "none")
    _tls(proxy, security, options)
    _transport(proxy, options.get("type", "tcp"), options.get("path", "/"),
               {"Host": options["host"]} if options.get("host") else None)
    flow = options.get("flow", "")
    if flow:
        if flow != "xtls-rprx-vision" or security != "reality" or proxy["network"] != "tcp":
            raise UnsupportedExport("暂不支持此 VLESS 流控组合")
        proxy["flow"] = flow
    return proxy


def proxy_from_inbound(inbound, host, port, uri=None, name=None):
    """Convert actual Xray fields; the share URI supplies its public Reality key.

    Never serialize server private keys. The first client is the same client
    selected by the existing share-link generator. Relay callers pass the
    entry address with the exit's inbound, preserving end-to-end credentials.
    """
    if not isinstance(inbound, dict):
        raise UnsupportedExport("节点配置无效")
    protocol = inbound.get("protocol")
    protocol = "ss" if protocol == "shadowsocks" else protocol
    if protocol not in ("ss", "vmess", "vless"):
        raise UnsupportedExport("当前入站类型没有可导出的客户端节点")
    proxy = _base(name or inbound.get("tag"), protocol, host, port)
    settings = inbound.get("settings") or {}
    stream = inbound.get("streamSettings") or {}
    if not isinstance(settings, dict) or not isinstance(stream, dict):
        raise UnsupportedExport("节点配置无效")
    if protocol == "ss":
        _ss(proxy, settings.get("method"), settings.get("password"))
        proxy["udp"] = "udp" in settings.get("network", "tcp,udp").split(",")
        if stream.get("network", "tcp") not in ("tcp", "raw") or stream.get("security", "none") != "none":
            raise UnsupportedExport("暂不支持 Shadowsocks 附加传输或 TLS 配置")
        return proxy
    clients = settings.get("clients") or []
    if not isinstance(clients, list) or not clients or not isinstance(clients[0], dict):
        raise UnsupportedExport("节点没有有效的客户端凭证")
    client = clients[0]
    proxy["uuid"] = _identifier(client.get("id"))
    security = stream.get("security", "none")
    tls = stream.get("tlsSettings") or {}
    options = {"sni": tls.get("serverName", ""), "alpn": tls.get("alpn")}
    if security == "reality":
        if not uri:
            raise UnsupportedExport("未能恢复 Reality 公钥，请重新读取节点列表")
        public_proxy = proxy_from_uri(uri)
        reality = stream.get("realitySettings") or {}
        options = {"sni": (reality.get("serverNames") or [""])[0],
                   "sid": (reality.get("shortIds") or [""])[0],
                   "pbk": (public_proxy.get("reality-opts") or {}).get("public-key", ""),
                   "fp": public_proxy.get("client-fingerprint", "")}
    _tls(proxy, security, options)
    ws = stream.get("wsSettings") or {}
    headers = dict(ws.get("headers") or {})
    if ws.get("host"):
        headers["Host"] = ws["host"]
    _transport(proxy, stream.get("network", "tcp"), ws.get("path", "/"), headers)
    if stream.get("tcpSettings", {}).get("header", {}).get("type", "none") != "none":
        raise UnsupportedExport("暂不支持 TCP 伪装头配置")
    if protocol == "vless":
        if settings.get("decryption", "none") != "none":
            raise UnsupportedExport("暂不支持此 VLESS 加密方式")
        flow = client.get("flow", "")
        if flow:
            if flow != "xtls-rprx-vision" or security != "reality" or proxy["network"] != "tcp":
                raise UnsupportedExport("暂不支持此 VLESS 流控组合")
            proxy["flow"] = flow
    else:
        proxy["alterId"] = _number(client.get("alterId", 0), "alterId", 0, 65535)
        proxy["cipher"] = "auto"
    return proxy


def compatibility(proxy):
    if proxy["type"] in ("hysteria2", "hy2", "tuic"):
        return "mihomo", "此节点使用 Hysteria2 / TUIC，需要支持该协议的 Mihomo（Clash Meta）内核。"
    if proxy["type"] == "vless":
        return "mihomo", "此节点使用 VLESS / Reality，需要 Mihomo（Clash Meta）内核；旧版 Clash 内核不支持。"
    if proxy["type"] == "ss" and proxy["cipher"] in SS_2022:
        return "mihomo", "此节点使用 Shadowsocks 2022，需要支持 SS2022 的 Mihomo（Clash Meta）内核。"
    return "classic", "此节点可用于支持该协议的经典 Clash 与 Mihomo（Clash Meta）内核；客户端版本仍需支持所选加密方式。"


def _scalar(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


def _yaml_lines(value, indent=0):
    pad = " " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            quoted = key if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key) else _scalar(key)
            if isinstance(item, (dict, list)) and item:
                yield f"{pad}{quoted}:"
                yield from _yaml_lines(item, indent + 2)
            else:
                yield f"{pad}{quoted}: {_scalar(item)}"
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)) and item:
                yield f"{pad}-"
                yield from _yaml_lines(item, indent + 2)
            else:
                yield f"{pad}- {_scalar(item)}"


def configuration(proxy):
    """Return a complete importable configuration, with no remote rule sources."""
    return {"mixed-port": 7890, "allow-lan": False, "bind-address": "127.0.0.1",
            "mode": "rule", "log-level": "warning", "proxies": [proxy],
            "proxy-groups": [{"name": "FL Network", "type": "select", "proxies": [proxy["name"], "DIRECT"]}],
            "rules": ["MATCH,FL Network"]}


def yaml_configuration(proxy):
    return "# FL Network - Clash / Mihomo\n" + "\n".join(_yaml_lines(configuration(proxy))) + "\n"


class ExportCache:
    """Bounded per-process credential cache; every registration rotates its URL."""
    def __init__(self, ttl=24 * 60 * 60, capacity=256, clock=time.monotonic):
        if ttl <= 0 or capacity <= 0:
            raise ValueError("导出缓存限制无效")
        self.ttl, self.capacity, self.clock = ttl, capacity, clock
        self._entries = OrderedDict()
        self._lock = threading.RLock()
        self._scope_epochs = OrderedDict()
        self._epoch = 0

    def _advance_scope(self, scope):
        self._epoch += 1
        self._scope_epochs[scope] = self._epoch
        self._scope_epochs.move_to_end(scope)
        while len(self._scope_epochs) > self.capacity * 4:
            self._scope_epochs.popitem(last=False)

    def scope_epochs(self, scopes):
        """Capture source versions before reading; invalidations refuse stale publication."""
        scopes = tuple(scopes)
        with self._lock:
            for scope in scopes:
                if scope not in self._scope_epochs:
                    self._advance_scope(scope)
            return {scope: self._scope_epochs[scope] for scope in scopes}

    def rotate_scope(self, scope, expected_epochs):
        """Finish a read only if no edit, delete, or shutdown raced that read."""
        with self._lock:
            if any(self._scope_epochs.get(key) != epoch for key, epoch in expected_epochs.items()):
                raise ValueError("节点来源已变化，请重新读取服务器节点")
            self.revoke_scope(scope)
            return self.scope_epochs((scope,))

    def _purge(self):
        now = self.clock()
        for token, item in list(self._entries.items()):
            if item["expires"] <= now:
                self._entries.pop(token, None)

    def register(self, yaml, scope, node, filename, *, proxy=None, dependencies=(),
                 source_scopes=(), source_nodes=(), expected_epochs=None, routing_key=None):
        if not isinstance(yaml, str) or len(yaml.encode("utf-8")) > 512 * 1024:
            raise ValueError("导出配置过大")
        if routing_key is not None and (not isinstance(routing_key, str) or
                                        not re.fullmatch(r"[a-f0-9]{64}", routing_key)):
            raise ValueError("节点分流身份无效")
        dependencies = tuple(dependencies)
        if len(dependencies) > 128 or any(not isinstance(value, str) or not re.fullmatch(TOKEN_PATTERN, value)
                                          for value in dependencies):
            raise ValueError("导出节点引用无效")
        with self._lock:
            self._purge()
            if (expected_epochs is not None and
                    any(self._scope_epochs.get(key) != epoch for key, epoch in expected_epochs.items())):
                raise ValueError("节点来源已变化，请重新读取服务器节点")
            if any(self._valid_entry(value) is None for value in dependencies):
                raise ValueError("节点已变化，请重新读取服务器节点")
            self._remove_node(scope, node)
            if any(self._valid_entry(value) is None for value in dependencies):
                raise ValueError("节点已变化，请重新读取服务器节点")
            protected = set(dependencies)
            pending = list(dependencies)
            while pending:
                for value in self._entries[pending.pop()]["dependencies"]:
                    if value not in protected:
                        protected.add(value)
                        pending.append(value)
            while len(self._entries) >= self.capacity:
                evict = next((value for value in self._entries if value not in protected), None)
                if evict is None:
                    raise ValueError("节点缓存已满，请减少所选节点")
                self._entries.pop(evict)
            token = secrets.token_urlsafe(32)
            self._entries[token] = {"yaml": yaml, "scope": scope, "node": node,
                                    "filename": filename, "expires": self.clock() + self.ttl,
                                    "proxy": copy.deepcopy(proxy), "dependencies": dependencies,
                                    "source_scopes": tuple(source_scopes), "source_nodes": tuple(source_nodes),
                                    "routing_key": routing_key}
            return token

    def _valid_entry(self, token):
        item = self._entries.get(token)
        if item and all(self._valid_entry(value) is not None for value in item["dependencies"]):
            return item
        self._entries.pop(token, None)
        return None

    def get_proxy(self, token):
        """Internal conversion data; never included in a public download response."""
        if not isinstance(token, str) or not re.fullmatch(TOKEN_PATTERN, token):
            return None
        with self._lock:
            self._purge()
            item = self._valid_entry(token)
            return copy.deepcopy(item["proxy"]) if item and item["proxy"] is not None else None

    def get_routing_key(self, token):
        """Return a source identity only while its capability remains valid."""
        if not isinstance(token, str) or not re.fullmatch(TOKEN_PATTERN, token):
            return None
        with self._lock:
            self._purge()
            item = self._valid_entry(token)
            return item["routing_key"] if item and item["proxy"] is not None else None

    @contextmanager
    def source_guard(self, token, routing_key):
        """Keep source revocation atomic with a local routing write/publication."""
        with self._lock:
            self._purge()
            item = self._valid_entry(token)
            if (not item or item["proxy"] is None or item["routing_key"] != routing_key):
                raise SourceCapabilityChanged("节点已重新读取、修改或删除，请重新读取服务器节点")
            yield

    def get(self, token):
        if not isinstance(token, str) or not re.fullmatch(TOKEN_PATTERN, token):
            return None
        with self._lock:
            self._purge()
            item = self._valid_entry(token)
            return {key: item[key] for key in ("yaml", "filename")} if item else None

    def _remove_node(self, scope, node, *, include_sources=False):
        for token, item in list(self._entries.items()):
            if ((item["scope"] == scope and item["node"] == node) or
                    (include_sources and (scope, node) in item["source_nodes"])):
                self._entries.pop(token, None)

    def revoke_node(self, scope, node):
        with self._lock:
            self._advance_scope(scope)
            self._remove_node(scope, node, include_sources=True)

    def revoke_scope(self, scope):
        with self._lock:
            self._advance_scope(scope)
            for token, item in list(self._entries.items()):
                if item["scope"] == scope or scope in item["source_scopes"]:
                    self._entries.pop(token, None)

    def clear(self):
        with self._lock:
            self._entries.clear()
            self._scope_epochs.clear()


class WorkspaceSnapshots:
    """Bounded inventories of opaque node capabilities; no disk persistence."""
    def __init__(self, ttl=30 * 60, capacity=16, clock=time.monotonic):
        self.ttl, self.capacity, self.clock = ttl, capacity, clock
        self._entries = OrderedDict()
        self._lock = threading.RLock()

    def _purge(self):
        for token, entry in list(self._entries.items()):
            if entry["expires"] <= self.clock():
                self._entries.pop(token, None)

    def register(self, nodes):
        if not isinstance(nodes, list) or len(nodes) > 256:
            raise ValueError("一次最多读取 256 个入站，请减少所选服务器")
        with self._lock:
            self._purge()
            while len(self._entries) >= self.capacity:
                self._entries.popitem(last=False)
            token = secrets.token_urlsafe(32)
            self._entries[token] = {"nodes": copy.deepcopy(nodes), "expires": self.clock() + self.ttl}
            return token

    def get(self, token):
        if not isinstance(token, str) or not re.fullmatch(TOKEN_PATTERN, token):
            return None
        with self._lock:
            self._purge()
            entry = self._entries.get(token)
            return copy.deepcopy(entry["nodes"]) if entry else None

    def clear(self):
        with self._lock:
            self._entries.clear()
