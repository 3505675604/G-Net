"""Pure per-node domain bypass profiles and complete client configurations.

These policies belong to a client profile, never to an Xray server inbound or
to the multi-node workspace's global rules. A saved key is a configuration
fingerprint, not an authorization capability; callers must resolve a current
node capability before reading, saving or exporting its policy.
"""
import base64
import copy
import hashlib
import ipaddress
import json
import re
import unicodedata
import uuid

from clash_export import SS_CLASSIC, SS_2022, UnsupportedExport, _yaml_lines
from clash_import import validate_import_proxy
from local_security import validate_host, validate_port


MAX_DIRECT_DOMAINS = 128
NODE_GROUP = "专属节点"
_RESERVED_NAMES = frozenset(("DIRECT", "REJECT", "GLOBAL", "PASS", "COMPATIBLE",
                             "REJECT-DROP", NODE_GROUP))
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_VMESS_CIPHERS = frozenset(("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"))


def _text(value, label, *, empty=False, limit=8192):
    if not isinstance(value, str) or (not value and not empty) or len(value) > limit:
        raise UnsupportedExport(f"{label}格式无效")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise UnsupportedExport(f"{label}格式无效") from error
    return value


def _has_control(value):
    return any(unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") for char in value)


def normalize_direct_domains(values):
    """Normalize a bounded domain-only list; suffixes include all subdomains.

IP literals, URLs, wildcard syntax and single-label names such as localhost
are deliberately rejected. Input order survives normalization and deduping.
"""
    if not isinstance(values, list) or len(values) > MAX_DIRECT_DOMAINS:
        raise UnsupportedExport(f"每个节点最多添加 {MAX_DIRECT_DOMAINS} 个直连域名")
    normalized, seen = [], set()
    for value in values:
        value = _text(value, "直连域名", limit=253)
        if (value != value.strip() or _has_control(value) or
                any(char.isspace() for char in value) or any(char in value for char in ":/\\*,;@?#")):
            raise UnsupportedExport("直连域名应填写域名，不含协议、路径、通配符、端口或逗号")
        bare = value[:-1] if value.endswith(".") else value
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            pass
        else:
            raise UnsupportedExport("直连名单只接受域名，不能填写 IP 地址")
        try:
            ascii_name = bare.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise UnsupportedExport("直连域名格式无效") from error
        labels = ascii_name.split(".")
        if (len(ascii_name) > 253 or len(labels) < 2 or labels[-1].isdigit() or
                any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)):
            raise UnsupportedExport("直连域名需要完整域名，例如 example.com，不支持 localhost 或 IP")
        if ascii_name not in seen:
            seen.add(ascii_name)
            normalized.append(ascii_name)
    return normalized


def normalize_routing(value):
    """Validate only policy fields; revisions are caller-managed integers."""
    if not isinstance(value, dict):
        raise UnsupportedExport("节点分流配置格式无效")
    enabled = value.get("enabled", False)
    revision = value.get("revision", 0)
    if not isinstance(enabled, bool):
        raise UnsupportedExport("节点分流开关必须是布尔值")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise UnsupportedExport("节点分流版本必须是非负整数")
    return {"enabled": enabled, "direct_domains": normalize_direct_domains(value.get("direct_domains", [])),
            "revision": revision}


def stable_routing_key(server_id, scope, proxy):
    """Bind a persistent policy to this server and exact client connection.

Display names and expiring capability tokens are excluded. Credentials are
hashed as part of the binding and are never returned or persisted here.
"""
    if not isinstance(server_id, str) or (server_id != "manual" and not re.fullmatch(r"[a-fA-F0-9]{32}", server_id)):
        raise UnsupportedExport("节点分流服务器标识无效")
    if not isinstance(scope, (list, tuple)) or len(scope) != 2 or not isinstance(proxy, dict):
        raise UnsupportedExport("节点分流身份无效")
    try:
        host = validate_host(scope[0]).lower()
        port = validate_port(scope[1])
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            pass
        connection = {key: value for key, value in proxy.items() if key != "name"}
        payload = json.dumps({"version": 1, "server_id": server_id.lower(), "scope": [host, port],
                              "proxy": connection}, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise UnsupportedExport("节点分流身份无效") from error
    if len(payload) > 128 * 1024:
        raise UnsupportedExport("节点分流身份过大")
    return hashlib.sha256(payload).hexdigest()


def _port(value, label):
    try:
        return validate_port(value)
    except ValueError as error:
        raise UnsupportedExport(f"{label}必须是 1–65535 的整数") from error


def _safe_name(value, protocol):
    value = _text(value, "节点名称", empty=True, limit=500)
    name = "".join(char for char in value if unicodedata.category(char) not in ("Cc", "Cf", "Zl", "Zp"))
    name = name.replace(",", "，").strip() or f"{protocol.upper()} 节点"
    if name in _RESERVED_NAMES:
        name += " · 节点"
    return name


def _validated_proxy(value):
    """Accept the existing exporter contract without copying unsafe extensions."""
    if not isinstance(value, dict) or value.get("type") not in ("vless", "vmess", "ss"):
        raise UnsupportedExport("此节点协议暂不支持独立分流导出")
    protocol = value["type"]
    allowed = {"name", "type", "server", "port", "udp"}
    allowed |= {"cipher", "password"} if protocol == "ss" else {
        "uuid", "tls", "network", "ws-opts", "servername", "alpn", "client-fingerprint", "reality-opts"
    } | ({"alterId", "cipher"} if protocol == "vmess" else {"flow"})
    if set(value) - allowed:
        raise UnsupportedExport("节点包含尚不能忠实转换的附加参数，请重新读取节点")
    try:
        host = validate_host(value.get("server"))
    except ValueError as error:
        raise UnsupportedExport("节点地址无效") from error
    proxy = {"name": _safe_name(value.get("name", ""), protocol), "type": protocol,
             "server": host, "port": _port(value.get("port"), "节点端口")}
    udp = value.get("udp", True)
    if not isinstance(udp, bool):
        raise UnsupportedExport("节点 UDP 设置必须是布尔值")
    proxy["udp"] = udp
    if protocol == "ss":
        method = value.get("cipher")
        if not isinstance(method, str) or method not in SS_CLASSIC | SS_2022:
            raise UnsupportedExport("Shadowsocks 加密方式暂不支持独立分流导出")
        password = _text(value.get("password"), "Shadowsocks 密码")
        if method in SS_2022:
            length = 16 if method.endswith("128-gcm") else 32
            for key in password.split(":"):
                try:
                    decoded = base64.b64decode(key, validate=True)
                except ValueError as error:
                    raise UnsupportedExport("SS2022 密钥格式无效") from error
                if len(decoded) != length:
                    raise UnsupportedExport("SS2022 密钥长度无效")
        proxy.update(cipher=method, password=password)
        return proxy
    try:
        proxy["uuid"] = str(uuid.UUID(_text(value.get("uuid"), "UUID", limit=64)))
    except ValueError as error:
        raise UnsupportedExport("UUID 格式无效") from error
    network = value.get("network", "tcp")
    if network == "raw":
        network = "tcp"
    if network not in ("tcp", "ws"):
        raise UnsupportedExport("此传输方式暂不支持独立分流导出")
    tls = value.get("tls", False)
    if not isinstance(tls, bool):
        raise UnsupportedExport("节点 TLS 设置必须是布尔值")
    proxy.update(network=network, tls=tls)
    if network == "ws":
        ws = value.get("ws-opts", {})
        if not isinstance(ws, dict) or set(ws) - {"path", "headers"}:
            raise UnsupportedExport("WebSocket 配置无效")
        path = _text(ws.get("path", "/"), "WebSocket 路径")
        headers = ws.get("headers", {})
        if not isinstance(headers, dict) or len(headers) > 32:
            raise UnsupportedExport("WebSocket 请求头配置无效")
        checked_headers = {}
        for key, item in headers.items():
            key = _text(key, "请求头名称", limit=255)
            item = _text(item, "请求头内容", empty=True)
            if _has_control(key) or _has_control(item):
                raise UnsupportedExport("WebSocket 请求头不能包含控制字符")
            checked_headers[key] = item
        proxy["ws-opts"] = {"path": path, **({"headers": checked_headers} if checked_headers else {})}
    if "servername" in value:
        sni = _text(value["servername"], "TLS SNI", limit=253)
        if _has_control(sni) or any(char.isspace() for char in sni):
            raise UnsupportedExport("TLS SNI 无效")
        proxy["servername"] = sni
    if "alpn" in value:
        alpn = value["alpn"]
        if not isinstance(alpn, list) or not 1 <= len(alpn) <= 10:
            raise UnsupportedExport("TLS ALPN 配置无效")
        proxy["alpn"] = [_text(item, "ALPN", limit=255) for item in alpn]
    if "client-fingerprint" in value:
        proxy["client-fingerprint"] = _text(value["client-fingerprint"], "TLS 指纹", limit=64)
    if "reality-opts" in value:
        reality = value["reality-opts"]
        if not tls or network != "tcp" or not isinstance(reality, dict) or set(reality) - {"public-key", "short-id"}:
            raise UnsupportedExport("Reality 配置无效")
        public = _text(reality.get("public-key"), "Reality 公钥", limit=128)
        try:
            decoded = base64.b64decode(public + "=" * (-len(public) % 4), altchars=b"-_", validate=True)
        except ValueError as error:
            raise UnsupportedExport("Reality 公钥格式无效") from error
        if len(decoded) != 32:
            raise UnsupportedExport("Reality 公钥长度无效")
        short = _text(reality.get("short-id", ""), "Reality shortId", empty=True, limit=16)
        if short and not re.fullmatch(r"(?:[a-fA-F0-9]{2}){1,8}", short):
            raise UnsupportedExport("Reality shortId 无效")
        proxy["reality-opts"] = {"public-key": public.rstrip("="), "short-id": short}
    if protocol == "vless":
        flow = value.get("flow", "")
        if flow:
            if flow != "xtls-rprx-vision" or not proxy.get("reality-opts") or network != "tcp":
                raise UnsupportedExport("VLESS 流控配置暂不支持独立分流导出")
            proxy["flow"] = flow
    else:
        alter_id = value.get("alterId", 0)
        if isinstance(alter_id, bool) or not isinstance(alter_id, int) or not 0 <= alter_id <= 65535:
            raise UnsupportedExport("VMess alterId 无效")
        cipher = value.get("cipher", "auto")
        if not isinstance(cipher, str) or cipher not in _VMESS_CIPHERS:
            raise UnsupportedExport("VMess 加密方式无效")
        proxy.update(alterId=alter_id, cipher=cipher)
    return proxy


def _xray_outbound(proxy):
    protocol = proxy["type"]
    if protocol == "ss":
        return {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [{
            "address": proxy["server"], "port": proxy["port"], "method": proxy["cipher"],
            "password": proxy["password"]}]}}
    user = {"id": proxy["uuid"]}
    if protocol == "vless":
        user["encryption"] = "none"
        if proxy.get("flow"):
            user["flow"] = proxy["flow"]
    else:
        user.update(alterId=proxy["alterId"], security=proxy["cipher"])
    outbound = {"tag": "proxy", "protocol": protocol, "settings": {"vnext": [{
        "address": proxy["server"], "port": proxy["port"], "users": [user]}]}}
    stream = {"network": proxy["network"], "security": "none"}
    if proxy["network"] == "ws":
        ws = proxy["ws-opts"]
        settings = {"path": ws["path"]}
        headers = copy.deepcopy(ws.get("headers", {}))
        # Xray accepts the old Host header alias but prefers its dedicated host.
        hosts = [(key, headers.pop(key)) for key in list(headers) if key.lower() == "host"]
        if len(hosts) > 1:
            raise UnsupportedExport("WebSocket Host 请求头不能重复")
        if hosts:
            settings["host"] = hosts[0][1]
        if headers:
            settings["headers"] = headers
        stream["wsSettings"] = settings
    if proxy.get("reality-opts"):
        reality = proxy["reality-opts"]
        stream["security"] = "reality"
        # Current Xray calls this password; publicKey remains an accepted alias.
        # Emitting both identical values also preserves older Xray compatibility.
        stream["realitySettings"] = {"serverName": proxy.get("servername", proxy["server"]),
                                     "fingerprint": proxy.get("client-fingerprint", "chrome"),
                                     "password": reality["public-key"], "publicKey": reality["public-key"],
                                     "shortId": reality["short-id"]}
    elif proxy["tls"]:
        stream["security"] = "tls"
        settings = {"allowInsecure": False}
        if proxy.get("servername"):
            settings["serverName"] = proxy["servername"]
        if proxy.get("alpn"):
            settings["alpn"] = copy.deepcopy(proxy["alpn"])
        if proxy.get("client-fingerprint"):
            settings["fingerprint"] = proxy["client-fingerprint"]
        stream["tlsSettings"] = settings
    outbound["streamSettings"] = stream
    return outbound


def build_node_routing(proxy, routing, *, mixed_port=7890, socks_port=10808, http_port=10809):
    """Export exactly one node with a domain-only DIRECT allowlist.

An empty or disabled allowlist sends all proxied traffic to this node. Legacy
VMess alterId remains exportable to Clash but is explicitly unavailable in the
modern Xray format rather than silently converting it to a different protocol.
"""
    if not isinstance(proxy, dict):
        raise UnsupportedExport("节点配置格式无效")
    # The Clash profile retains all validated supported protocol parameters.
    # Xray uses the stricter existing converter only if it can represent every
    # supplied field; unsupported fields never disappear during conversion.
    proxy = copy.deepcopy(proxy)
    proxy["name"] = _safe_name(proxy.get("name", ""), str(proxy.get("type", "")))
    proxy = validate_import_proxy(proxy)
    if proxy.get("dialer-proxy"):
        raise UnsupportedExport("独立节点分流不能遗漏链路，请在多节点工作区导出完整链式配置")
    xray_proxy = None
    xray_notice = ""
    try:
        xray_proxy = _validated_proxy(proxy)
    except UnsupportedExport as error:
        xray_notice = "此节点的协议或附加参数尚不能忠实转换为 Xray JSON；请使用完整 Clash / Mihomo 配置。" + str(error)
    routing = normalize_routing(routing)
    mixed_port = _port(mixed_port, "Clash 混合端口")
    socks_port, http_port = _port(socks_port, "SOCKS 端口"), _port(http_port, "HTTP 端口")
    if socks_port == http_port:
        raise UnsupportedExport("SOCKS 与 HTTP 端口不能相同")
    domains = routing["direct_domains"] if routing["enabled"] else []
    clash = {"mixed-port": mixed_port, "allow-lan": False, "bind-address": "127.0.0.1",
             "mode": "rule", "log-level": "warning", "proxies": [copy.deepcopy(proxy)],
             "proxy-groups": [{"name": NODE_GROUP, "type": "select", "proxies": [proxy["name"]]}],
             "rules": [*[f"DOMAIN-SUFFIX,{domain},DIRECT" for domain in domains], f"MATCH,{NODE_GROUP}"]}
    warnings = ["直连使用客户端所在电脑的网络；国内出口取决于电脑所在网络。",
                "此名单只在该节点的独立客户端配置中生效，不会合并到多节点配置或写入服务器。",
                "域名包含自身和子域名；网站使用的其他域名需分别添加。",
                "普通 VLESS / VMess / SS 分享链接不包含分流规则，请导入完整 YAML 或 Xray JSON。"]
    yaml = "# G-Network - independent node routing\n" + "\n".join(_yaml_lines(clash)) + "\n"
    if xray_proxy is None:
        warnings.append(xray_notice)
        xray_result = {"available": False, "notice": xray_notice}
    elif proxy["type"] == "vmess" and proxy.get("alterId", 0) != 0:
        notice = "新版 Xray 不支持 legacy VMess alterId 非 0；此节点请使用兼容该模式的 Clash 配置。"
        warnings.append(notice)
        xray_result = {"available": False, "notice": notice}
    else:
        sniffing = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
        xray_rules = []
        if domains:
            xray_rules.append({"type": "field", "domain": ["domain:" + domain for domain in domains],
                               "outboundTag": "direct"})
        xray_rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
        xray = {"log": {"loglevel": "warning"}, "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, "sniffing": copy.deepcopy(sniffing)},
            {"tag": "http-in", "listen": "127.0.0.1", "port": http_port, "protocol": "http",
             "settings": {}, "sniffing": copy.deepcopy(sniffing)}],
            "outbounds": [_xray_outbound(xray_proxy), {"tag": "direct", "protocol": "freedom", "settings": {}}],
            "routing": {"domainStrategy": "AsIs", "rules": xray_rules}}
        xray_result = {"available": True, "config": xray,
                       "json": json.dumps(xray, ensure_ascii=False, indent=2, allow_nan=False) + "\n"}
        if not proxy.get("udp", True):
            warnings.append("此节点未提供 UDP 转发；SOCKS 入站允许 UDP，但该节点的 UDP 请求可能失败。")
        if proxy["type"] == "vless" and not proxy.get("tls", False):
            warnings.append("此 VLESS 节点未启用 TLS / Reality；部分新版 Xray 限制公网明文 VLESS，请核对客户端版本。")
    return {"clash": {"available": True, "config": clash, "yaml": yaml}, "xray": xray_result,
            "warnings": warnings}
