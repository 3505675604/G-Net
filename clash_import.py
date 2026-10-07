"""Bounded, offline import of share links and editable Clash/Mihomo documents.

This module never opens a file, fetches a subscription, or starts a client.
Names in the returned profile are references; the HTTP layer replaces proxy
names with opaque capabilities before publishing an inventory.
"""
import base64
import copy
import ipaddress
import json
import math
import re
import unicodedata
import urllib.parse
import uuid

from clash_export import SS_CLASSIC, SS_2022, UnsupportedExport
from local_security import validate_host, validate_port

try:
    import yaml
except ImportError:
    yaml = None

MAX_TEXT_BYTES = 512 * 1024
MAX_PROXIES = 128
MAX_GROUPS = 16
MAX_RULES = 200
MAX_CHAINS = 16
MAX_HOPS = 8
MAX_TREE_DEPTH = 24
MAX_TREE_NODES = 40000
PROTOCOLS = frozenset(("ss", "vmess", "vless", "trojan", "hysteria2", "tuic"))
BUILTINS = frozenset(("DIRECT", "REJECT"))
RESERVED_NAMES = BUILTINS | frozenset(("GLOBAL", "PASS", "COMPATIBLE", "REJECT-DROP"))
GROUP_TYPES = frozenset(("select", "url-test", "fallback", "load-balance"))
GROUP_FIELDS = frozenset(("name", "type", "proxies", "url", "interval", "tolerance", "strategy"))
IMPORT_RULE_TYPES = frozenset(("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX",
    "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6", "GEOIP", "GEOSITE",
    "PROCESS-NAME", "PROCESS-PATH", "DST-PORT", "SRC-PORT", "NETWORK", "MATCH"))
ADVANCED_FIELDS = frozenset(("dns", "sniffer", "tun", "ipv6", "profile", "unified-delay",
    "tcp-concurrent", "find-process-mode", "allow-lan", "bind-address", "log-level"))
_BASE_PROXY_FIELDS = frozenset(("name", "type", "server", "port", "udp", "dialer-proxy",
    "tfo", "mptcp", "ip-version", "interface-name", "routing-mark", "smux"))
_TLS_FIELDS = frozenset(("tls", "servername", "sni", "alpn", "client-fingerprint", "fingerprint",
    "skip-cert-verify", "name-cert-verify", "reality-opts"))
_TRANSPORT_FIELDS = frozenset(("network", "ws-opts", "grpc-opts", "http-opts", "h2-opts"))
_PROXY_FIELDS = {
    "ss": _BASE_PROXY_FIELDS | frozenset(("cipher", "password", "plugin", "plugin-opts",
        "udp-over-tcp", "udp-over-tcp-version", "client-fingerprint")),
    "vmess": _BASE_PROXY_FIELDS | _TLS_FIELDS | _TRANSPORT_FIELDS | frozenset(("uuid", "alterId",
        "cipher", "packet-encoding", "global-padding", "authenticated-length")),
    "vless": _BASE_PROXY_FIELDS | _TLS_FIELDS | _TRANSPORT_FIELDS | frozenset(("uuid", "flow",
        "encryption", "packet-encoding")),
    "trojan": _BASE_PROXY_FIELDS | _TLS_FIELDS | _TRANSPORT_FIELDS | frozenset(("password", "ss-opts")),
    "hysteria2": _BASE_PROXY_FIELDS | _TLS_FIELDS | frozenset(("password", "ports", "hop-interval",
        "up", "down", "obfs", "obfs-password", "bbr-profile", "obfs-min-packet-size",
        "obfs-max-packet-size", "handshake-timeout", "initial-stream-receive-window",
        "max-stream-receive-window", "initial-connection-receive-window", "max-connection-receive-window")),
    "tuic": _BASE_PROXY_FIELDS | _TLS_FIELDS | frozenset(("uuid", "password", "token", "ip",
        "heartbeat-interval", "disable-sni", "reduce-rtt", "request-timeout", "udp-relay-mode",
        "congestion-controller", "bbr-profile", "max-udp-relay-packet-size", "fast-open", "max-open-streams")),
}
_BOOL_PROXY_FIELDS = frozenset(("udp", "tls", "skip-cert-verify", "tfo", "mptcp", "udp-over-tcp",
    "global-padding", "authenticated-length", "disable-sni", "reduce-rtt", "fast-open"))


def _fail(message):
    raise UnsupportedExport(message)


def _string(value, label, *, empty=False, limit=8192, allow_control=False):
    if (not isinstance(value, str) or len(value) > limit or (not value and not empty)
            or "\x00" in value or (not allow_control and
                any(unicodedata.category(char) in ("Cc", "Zl", "Zp") for char in value))):
        _fail(f"{label}必须是有效文本")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _fail(f"{label}包含无效字符")
    return value


def _name(value, label="名称"):
    value = _string(value, label, limit=180)
    if value != value.strip() or "," in value or value in RESERVED_NAMES:
        _fail(f"{label}不能使用保留名称、逗号或首尾空格")
    return value


def _integer(value, label, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not re.fullmatch(r"[0-9]{1,12}", str(value)):
        _fail(f"{label}必须为整数")
    number = int(value)
    if not low <= number <= high:
        _fail(f"{label}超出有效范围")
    return number


def _plain(value, label="配置", *, depth=0, budget=None):
    """Reject objects, cycles and oversized expansion before copying anything."""
    if budget is None:
        budget = [0, set()]
    budget[0] += 1
    if budget[0] > MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
        _fail(f"{label}结构过大或嵌套过深")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 2 ** 53:
            _fail(f"{label}整数超出精确表示范围")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail(f"{label}不能包含非有限数字")
        return value
    if isinstance(value, str):
        return _string(value, label, empty=True, limit=32768, allow_control=True)
    if not isinstance(value, (dict, list)):
        _fail(f"{label}必须只包含普通 JSON 数据")
    identity = id(value)
    if identity in budget[1]:
        _fail(f"{label}不能包含循环引用")
    if len(value) > 4096:
        _fail(f"{label}容器条目过多")
    budget[1].add(identity)
    try:
        if isinstance(value, list):
            return [_plain(item, label, depth=depth + 1, budget=budget) for item in value]
        return {_string(key, f"{label}字段名", limit=180):
                _plain(item, label, depth=depth + 1, budget=budget) for key, item in value.items()}
    finally:
        budget[1].remove(identity)


def _check_fields(mapping, allowed, label):
    if not isinstance(mapping, dict):
        _fail(f"{label}必须为对象")
    if set(mapping) - allowed:
        _fail(f"{label}包含暂不支持的字段，不能保证无损导入")


def _host(value, label):
    try:
        original = _string(value, label, limit=253)
        ascii_host = original.encode("idna").decode("ascii")
        host = validate_host(ascii_host)
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return host.lower()
    except (ValueError, UnicodeError):
        _fail(f"{label}必须是有效 IP 或域名")


def _uuid(value):
    try:
        return str(uuid.UUID(_string(value, "UUID", limit=64)))
    except ValueError:
        _fail("UUID 格式无效")


def _bool_fields(mapping, fields, label):
    for key in fields & mapping.keys():
        if not isinstance(mapping[key], bool):
            _fail(f"{label}布尔选项必须为 true 或 false")


def _string_list(value, label, *, maximum=64):
    if not isinstance(value, list) or len(value) > maximum:
        _fail(f"{label}必须是有界文本列表")
    return [_string(item, label, limit=2048) for item in value]


def _port_ranges(value, label, *, slash=False):
    value = _string(value, label, limit=512)
    separator = "/" if slash else ","
    segments = value.split(separator)
    if len(segments) > 32:
        _fail(f"{label}范围过多")
    for segment in segments:
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", segment):
            _fail(f"{label}格式无效")
        bounds = [_integer(part, label, 1, 65535) for part in segment.split("-")]
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            _fail(f"{label}起点不能大于终点")
    return value


def _validate_transport(proxy):
    network = proxy.get("network", "tcp") or "tcp"
    if network == "raw":
        network = "tcp"
    if network not in ("tcp", "ws", "grpc", "http", "h2"):
        _fail("此传输方式暂不支持无损导入")
    proxy["network"] = network
    option_for = {"ws": "ws-opts", "grpc": "grpc-opts", "http": "http-opts", "h2": "h2-opts"}
    for kind, key in option_for.items():
        if key not in proxy:
            continue
        if network != kind:
            _fail("传输配置与 network 不一致")
        options = proxy[key]
        if kind == "ws":
            _check_fields(options, {"path", "headers", "max-early-data", "early-data-header-name",
                "v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"}, "WebSocket 配置")
            path = options.get("path", "/")
            _string(path, "WebSocket 路径")
            if not path.startswith("/"):
                _fail("WebSocket 路径必须以 / 开头")
            if "headers" in options:
                headers = options["headers"]
                if not isinstance(headers, dict) or len(headers) > 32:
                    _fail("WebSocket 请求头格式无效")
                for name, value in headers.items():
                    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,255}", name):
                        _fail("WebSocket 请求头名称无效")
                    _string(value, "WebSocket 请求头内容", empty=True)
            if "max-early-data" in options:
                _integer(options["max-early-data"], "WebSocket early data", 0, 65535)
            if "early-data-header-name" in options:
                _string(options["early-data-header-name"], "WebSocket early data 请求头", limit=255)
            _bool_fields(options, {"v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"}, "WebSocket")
        elif kind == "grpc":
            _check_fields(options, {"grpc-service-name"}, "gRPC 配置")
            if "grpc-service-name" in options:
                _string(options["grpc-service-name"], "gRPC service name", empty=True, limit=1024)
        else:
            _check_fields(options, {"path", "headers", "method", "host"}, "HTTP 传输配置")
            for key, value in options.items():
                if key in ("host", "path"):
                    if isinstance(value, list):
                        _string_list(value, "HTTP 传输参数", maximum=32)
                    else:
                        _string(value, "HTTP 传输参数")
                elif key == "method":
                    _string(value, "HTTP 请求方法", limit=32)
                elif not isinstance(value, dict):
                    _fail("HTTP headers 必须为对象")


def validate_import_proxy(value):
    """Validate supported client fields without dropping handshake parameters."""
    proxy = _plain(value, "节点配置")
    if (not isinstance(proxy, dict) or not isinstance(proxy.get("type"), str)
            or proxy.get("type") not in PROTOCOLS):
        _fail("节点协议暂不支持导入")
    protocol = proxy["type"]
    _check_fields(proxy, _PROXY_FIELDS[protocol], "节点配置")
    proxy["server"] = _host(proxy.get("server"), "节点地址")
    try:
        proxy["port"] = validate_port(proxy.get("port"))
    except ValueError:
        _fail("节点端口必须为 1–65535 的整数")
    proxy["name"] = _name(proxy.get("name") or f"{protocol}-{proxy['server']}:{proxy['port']}", "节点名称")
    _bool_fields(proxy, _BOOL_PROXY_FIELDS, "节点")
    inherent_tls = protocol in ("trojan", "hysteria2", "tuic")
    if inherent_tls and proxy.get("tls") is False:
        _fail("此协议固有 TLS，不能使用 tls:false")
    if proxy.get("skip-cert-verify") is True and not inherent_tls and proxy.get("tls") is not True:
        _fail("未启用 TLS 的节点不能跳过证书验证")
    if "reality-opts" in proxy and protocol not in ("vless", "vmess", "trojan"):
        _fail("此协议不支持 Reality 配置")
    if "dialer-proxy" in proxy:
        _name(proxy["dialer-proxy"], "链式入口名称")
    if "routing-mark" in proxy:
        _integer(proxy["routing-mark"], "路由标记", 0, 2 ** 32 - 1)
    if "ip-version" in proxy and proxy["ip-version"] not in ("dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer"):
        _fail("IP 版本选项无效")
    if "interface-name" in proxy:
        _string(proxy["interface-name"], "网卡名称", limit=255)
    if "smux" in proxy:
        _check_fields(proxy["smux"], {"enabled", "protocol", "max-connections", "min-streams",
            "max-streams", "statistic", "only-tcp", "padding", "brutal-opts"}, "多路复用配置")
        _bool_fields(proxy["smux"], {"enabled", "statistic", "only-tcp", "padding"}, "多路复用")
        if "protocol" in proxy["smux"] and proxy["smux"]["protocol"] not in ("smux", "yamux", "h2mux"):
            _fail("多路复用协议无效")
    if "alpn" in proxy:
        _string_list(proxy["alpn"], "ALPN", maximum=16)
    for key in ("servername", "sni", "name-cert-verify"):
        if key in proxy:
            _string(proxy[key], "TLS 服务名称", limit=253)
    for key in ("client-fingerprint", "fingerprint"):
        if key in proxy:
            _string(proxy[key], "TLS 指纹", limit=255)
    if "reality-opts" in proxy:
        reality = proxy["reality-opts"]
        _check_fields(reality, {"public-key", "short-id"}, "Reality 配置")
        public = _string(reality.get("public-key"), "Reality 公钥", limit=128)
        try:
            decoded = base64.b64decode(public + "=" * (-len(public) % 4), altchars=b"-_", validate=True)
        except ValueError:
            _fail("Reality 公钥格式无效")
        if len(decoded) != 32:
            _fail("Reality 公钥长度无效")
        short = reality.get("short-id", "")
        _string(short, "Reality short-id", empty=True, limit=16)
        if short and not re.fullmatch(r"(?:[a-fA-F0-9]{2}){1,8}", short):
            _fail("Reality short-id 格式无效")
        if protocol in ("vless", "vmess") and proxy.get("tls") is not True:
            _fail("Reality 节点必须启用 TLS")
    if protocol in ("vless", "vmess", "trojan"):
        _validate_transport(proxy)
    if protocol in ("vless", "vmess"):
        proxy["uuid"] = _uuid(proxy.get("uuid"))
    if protocol in ("ss", "trojan", "hysteria2"):
        _string(proxy.get("password"), "节点认证密码", allow_control=True)
    if protocol == "ss":
        # The six ciphers generated by G-Network remain fully checked. Other
        # officially documented Mihomo ciphers are retained for imported nodes.
        extra = {"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
            "aes-128-ccm", "aes-256-ccm", "aes-128-gcm-siv", "aes-256-gcm-siv", "chacha20-ietf",
            "chacha20", "xchacha20", "xchacha20-ietf-poly1305", "chacha8-ietf-poly1305",
            "xchacha8-ietf-poly1305", "lea-128-gcm", "lea-192-gcm", "lea-256-gcm", "rabbit128-poly1305",
            "aegis-128l", "aegis-256", "aez-384", "deoxys-ii-256-128", "rc4-md5", "none"}
        if proxy.get("cipher") not in SS_CLASSIC | SS_2022 | extra:
            _fail("Shadowsocks 加密方式暂不支持")
        if proxy["cipher"] in SS_2022:
            size = 16 if proxy["cipher"] == "2022-blake3-aes-128-gcm" else 32
            for key in proxy["password"].split(":"):
                try:
                    decoded = base64.b64decode(key, validate=True)
                except ValueError:
                    _fail("SS2022 密钥格式无效")
                if len(decoded) != size:
                    _fail("SS2022 密钥长度无效")
        if "plugin" in proxy:
            if proxy["plugin"] not in ("obfs", "v2ray-plugin", "gost-plugin", "shadow-tls", "restls", "kcptun", "jls"):
                _fail("Shadowsocks 插件暂不支持")
            if not isinstance(proxy.get("plugin-opts", {}), dict):
                _fail("Shadowsocks 插件选项必须为对象")
        elif "plugin-opts" in proxy:
            _fail("Shadowsocks 插件选项缺少插件名称")
        if "udp-over-tcp-version" in proxy:
            _integer(proxy["udp-over-tcp-version"], "UDP over TCP 版本", 1, 2)
    elif protocol == "vmess":
        proxy["alterId"] = _integer(proxy.get("alterId", 0), "VMess alterId", 0, 65535)
        if proxy.get("cipher", "auto") not in ("auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"):
            _fail("VMess 加密方式无效")
        proxy.setdefault("cipher", "auto")
    elif protocol == "vless":
        encryption = proxy.get("encryption", "")
        _string(encryption, "VLESS encryption", empty=True, limit=32768)
        encrypted = encryption not in ("", "none")
        if encrypted and not re.fullmatch(r"mlkem768x25519plus\.(?:native|xorpub|random)\.(?:0rtt|1rtt)\.[A-Za-z0-9_+.=:/-]+", encryption):
            _fail("VLESS encryption 格式暂不支持，不能删除该参数后导入")
        flow = proxy.get("flow", "")
        if flow not in ("", "xtls-rprx-vision"):
            _fail("VLESS flow 暂不支持")
        if flow and not encrypted and (proxy["network"] != "tcp" or proxy.get("tls") is not True):
            _fail("普通 VLESS Vision 需要 TCP + TLS；原 flow 不会被自动删除")
    elif protocol == "trojan" and "ss-opts" in proxy:
        opts = proxy["ss-opts"]
        _check_fields(opts, {"enabled", "method", "password"}, "Trojan Shadowsocks 配置")
        _bool_fields(opts, {"enabled"}, "Trojan Shadowsocks")
        if opts.get("enabled"):
            if opts.get("method") not in SS_CLASSIC:
                _fail("Trojan Shadowsocks 加密方式无效")
            _string(opts.get("password"), "Trojan Shadowsocks 密码", allow_control=True)
    elif protocol == "hysteria2":
        if "ports" in proxy:
            _port_ranges(proxy["ports"], "Hysteria2 跳跃端口")
        if "hop-interval" in proxy:
            interval = proxy["hop-interval"]
            if isinstance(interval, str) and "-" in interval:
                if not re.fullmatch(r"[0-9]{1,5}-[0-9]{1,5}", interval):
                    _fail("Hysteria2 跳跃间隔无效")
                start, end = map(int, interval.split("-"))
                if not 1 <= start <= end <= 86400:
                    _fail("Hysteria2 跳跃间隔范围无效")
            else:
                _integer(interval, "Hysteria2 跳跃间隔", 1, 86400)
        if "obfs" in proxy and proxy["obfs"] not in ("salamander", "gecko"):
            _fail("Hysteria2 混淆方式暂不支持")
        if proxy.get("obfs"):
            _string(proxy.get("obfs-password"), "Hysteria2 混淆密码", allow_control=True)
    elif protocol == "tuic":
        if "token" in proxy:
            _string(proxy["token"], "TUIC token", allow_control=True)
            if "uuid" in proxy or "password" in proxy:
                _fail("TUIC v4 token 不能与 v5 UUID/password 同时使用")
        else:
            proxy["uuid"] = _uuid(proxy.get("uuid"))
            _string(proxy.get("password"), "TUIC 密码", allow_control=True)
        if "congestion-controller" in proxy and proxy["congestion-controller"] not in ("cubic", "new_reno", "bbr"):
            _fail("TUIC 拥塞控制算法无效")
        if "udp-relay-mode" in proxy and proxy["udp-relay-mode"] not in ("native", "quic"):
            _fail("TUIC UDP relay 模式无效")
        if "ip" in proxy:
            try:
                ipaddress.ip_address(proxy["ip"])
            except ValueError:
                _fail("TUIC 覆盖地址必须为 IP")
    if "packet-encoding" in proxy and proxy["packet-encoding"] not in ("", "packetaddr", "xudp"):
        _fail("UDP packet-encoding 暂不支持")
    # Validate numeric knobs without changing the user's explicit values.
    for key in ("heartbeat-interval", "request-timeout", "max-udp-relay-packet-size", "max-open-streams",
            "handshake-timeout", "obfs-min-packet-size", "obfs-max-packet-size",
            "initial-stream-receive-window", "max-stream-receive-window",
            "initial-connection-receive-window", "max-connection-receive-window"):
        if key in proxy:
            _integer(proxy[key], "协议数值选项", 0, 2 ** 32 - 1)
    return proxy


def _decode64(value, label="Base64 内容"):
    if not isinstance(value, str) or len(value) > MAX_TEXT_BYTES:
        _fail(f"{label}过大")
    value = re.sub(r"\s+", "", value)
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if len(raw) > MAX_TEXT_BYTES:
            _fail(f"{label}过大")
        return raw.decode("utf-8")
    except (ValueError, UnicodeError):
        _fail(f"{label}无效")


def _query(query):
    try:
        items = urllib.parse.parse_qsl(query, keep_blank_values=True, max_num_fields=64, errors="strict")
    except (ValueError, UnicodeError):
        _fail("分享链接查询参数无效")
    result = {}
    for key, value in items:
        if key in result:
            _fail("分享链接包含重复参数")
        result[key] = value
    return result


def _qbool(value):
    if value.lower() in ("1", "true", "yes"):
        return True
    if value.lower() in ("0", "false", "no", ""):
        return False
    _fail("分享链接布尔参数无效")


def _allow_query(query, allowed):
    if set(query) - set(allowed):
        _fail("分享链接含未支持参数，不能保证无损导入")


def _tls_from_query(proxy, query, security):
    if security not in ("none", "tls", "reality", ""):
        _fail("分享链接 TLS 类型暂不支持")
    if security in ("tls", "reality"):
        proxy["tls"] = True
    elif proxy["type"] in ("vless", "vmess"):
        proxy["tls"] = False
    for source in ("allowInsecure", "allow_insecure", "insecure", "skip-cert-verify"):
        if source in query:
            proxy["skip-cert-verify"] = _qbool(query[source])
    sni = query.get("sni") or query.get("peer") or query.get("servername")
    if sni:
        proxy["servername" if proxy["type"] in ("vless", "vmess") else "sni"] = sni
    if query.get("alpn"):
        proxy["alpn"] = query["alpn"].split(",")
    if query.get("fp"):
        proxy["client-fingerprint"] = query["fp"]
    if security == "reality":
        proxy["reality-opts"] = {"public-key": query.get("pbk", ""), "short-id": query.get("sid", "")}


def _transport_from_query(proxy, query):
    network = query.get("type", "tcp") or "tcp"
    if network == "raw":
        network = "tcp"
    proxy["network"] = network
    if network == "ws":
        path = query.get("path") or "/"
        # Unlike editing an existing YAML field, share links commonly omit the
        # leading slash. Preserve its path meaning using the standard spelling.
        if not path.startswith("/"):
            path = "/" + path
        proxy["ws-opts"] = {"path": path}
        if query.get("host"):
            proxy["ws-opts"]["headers"] = {"Host": query["host"]}
    elif network == "grpc":
        if query.get("mode", "gun") not in ("", "gun"):
            _fail("gRPC multi 模式暂不支持无损导入")
        proxy["grpc-opts"] = {"grpc-service-name": query.get("serviceName") or query.get("service-name") or ""}
    elif network in ("http", "h2"):
        opts = {}
        if query.get("path"):
            opts["path"] = [query["path"]] if network == "http" else query["path"]
        if query.get("host"):
            opts["headers" if network == "http" else "host"] = {"Host": [query["host"]]} if network == "http" else [query["host"]]
        proxy[network + "-opts"] = opts
    elif query.get("headerType", "none") not in ("", "none"):
        _fail("TCP headerType 暂不支持无损导入")


def _parse_plugin(value):
    parts = value.split(";")
    name = parts.pop(0)
    aliases = {"obfs-local": "obfs", "simple-obfs": "obfs"}
    name = aliases.get(name, name)
    if name not in ("obfs", "v2ray-plugin"):
        _fail("此 SIP002 插件链接暂不支持无损导入")
    options = {}
    for part in parts:
        if not part:
            continue
        key, separator, option = part.partition("=")
        if key in options:
            _fail("SIP002 插件参数重复")
        if name == "obfs":
            key = {"obfs": "mode", "obfs-host": "host"}.get(key, key)
            if key not in ("mode", "host") or not separator:
                _fail("SIP002 obfs 参数暂不支持")
        else:
            if key not in ("mode", "host", "path", "tls", "mux"):
                _fail("SIP002 v2ray-plugin 参数暂不支持")
            if key in ("tls", "mux"):
                option = True if not separator else _qbool(option)
            elif not separator:
                _fail("SIP002 插件参数缺少值")
        options[key] = option
    if name == "v2ray-plugin":
        options.setdefault("mode", "websocket")
    return name, options


def _parse_uri(uri):
    uri = re.sub(r"\\(?=[:@_?&#=])", "", uri.strip())
    _string(uri, "分享链接", limit=32768)
    scheme = uri.partition(":")[0].lower()
    if scheme == "vmess":
        try:
            data = json.loads(_decode64(uri.split("://", 1)[1]), object_pairs_hook=_unique_json)
        except (ValueError, IndexError, RecursionError):
            _fail("VMess 分享内容无效")
        _check_fields(data, {"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host",
            "path", "tls", "sni", "alpn", "fp", "allowInsecure", "insecure"}, "VMess 分享内容")
        query = {"type": str(data.get("net", "tcp")), "path": str(data.get("path", "")),
                 "host": str(data.get("host", "")), "sni": str(data.get("sni", ""))}
        for key in ("alpn", "fp", "allowInsecure", "insecure"):
            if key in data:
                query[key] = str(data[key])
        header_type = data.get("type", "none") or "none"
        if header_type not in ("none", ""):
            _fail("VMess 伪装参数暂不支持无损导入")
        proxy = {"name": data.get("ps") or "VMess 导入节点", "type": "vmess", "server": data.get("add"),
            "port": data.get("port"), "uuid": data.get("id"), "alterId": data.get("aid", 0),
            "cipher": data.get("scy", "auto") or "auto", "udp": True}
        security = "tls" if str(data.get("tls", "")).lower() in ("tls", "true", "1") else "none"
        if str(data.get("tls", "")).lower() not in ("", "none", "tls", "true", "1", "false", "0"):
            _fail("VMess TLS 参数无效")
        _tls_from_query(proxy, query, security)
        _transport_from_query(proxy, query)
        return validate_import_proxy(proxy)
    protocol = "hysteria2" if scheme == "hy2" else scheme
    if protocol not in PROTOCOLS:
        _fail("不支持此分享链接协议；订阅网址需要先取得内容再导入")
    if protocol == "ss" and "@" not in uri.split("?", 1)[0].split("#", 1)[0]:
        body, _, fragment = uri.split("://", 1)[1].partition("#")
        encoded, separator, query_string = body.partition("?")
        decoded = _decode64(encoded.rstrip("/"), "Shadowsocks 分享内容")
        credentials, at, address = decoded.rpartition("@")
        if not at:
            _fail("Shadowsocks 分享内容缺少地址")
        uri = "ss://" + urllib.parse.quote(credentials, safe=":") + "@" + address
        if separator:
            uri += "?" + query_string
        if fragment:
            uri += "#" + fragment
    try:
        parts = urllib.parse.urlsplit(uri)
        if parts.path not in ("", "/") or not parts.hostname or parts.port is None:
            _fail("分享链接地址或端口无效")
        proxy = {"type": protocol, "name": urllib.parse.unquote(parts.fragment) or f"{protocol}-{parts.hostname}:{parts.port}",
                 "server": parts.hostname, "port": parts.port, "udp": True}
    except (ValueError, UnicodeError):
        _fail("分享链接地址或端口无效")
    query = _query(parts.query)
    common = {"sni", "servername", "peer", "alpn", "fp", "allowInsecure", "allow_insecure", "insecure", "skip-cert-verify"}
    transport = {"type", "host", "path", "serviceName", "service-name", "mode", "headerType"}
    user = urllib.parse.unquote(parts.username or "")
    if protocol == "ss":
        _allow_query(query, {"plugin"})
        if parts.password is None:
            credentials = _decode64(user, "Shadowsocks 认证内容")
        else:
            credentials = user + ":" + urllib.parse.unquote(parts.password)
        cipher, separator, password = credentials.partition(":")
        if not separator:
            _fail("Shadowsocks 分享内容缺少密码")
        proxy.update(cipher=cipher, password=password)
        if query.get("plugin"):
            proxy["plugin"], proxy["plugin-opts"] = _parse_plugin(query["plugin"])
    elif protocol == "vless":
        _allow_query(query, common | transport | {"security", "pbk", "sid", "flow", "encryption", "packet-encoding", "packetEncoding"})
        if parts.password is not None:
            _fail("VLESS 用户信息无效")
        proxy["uuid"] = user
        for key in ("flow", "encryption"):
            if key in query:
                proxy[key] = query[key]
        if query.get("packet-encoding") or query.get("packetEncoding"):
            proxy["packet-encoding"] = query.get("packet-encoding") or query["packetEncoding"]
        _tls_from_query(proxy, query, query.get("security", "none"))
        _transport_from_query(proxy, query)
    elif protocol == "trojan":
        _allow_query(query, common | transport | {"security"})
        proxy["password"] = user + (":" + urllib.parse.unquote(parts.password) if parts.password is not None else "")
        if query.get("security", "tls") not in ("tls", ""):
            _fail("Trojan 分享链接安全参数暂不支持")
        _tls_from_query(proxy, query, "tls")
        _transport_from_query(proxy, query)
    elif protocol == "hysteria2":
        _allow_query(query, common | {"mport", "ports", "hop_interval", "hop-interval", "obfs", "obfs-password", "up", "down"})
        proxy["password"] = user + (":" + urllib.parse.unquote(parts.password) if parts.password is not None else "")
        _tls_from_query(proxy, query, "tls")
        for source, target in (("mport", "ports"), ("ports", "ports"), ("hop_interval", "hop-interval"),
                               ("hop-interval", "hop-interval"), ("obfs", "obfs"), ("obfs-password", "obfs-password"),
                               ("up", "up"), ("down", "down")):
            if query.get(source):
                if target in proxy and proxy[target] != query[source]:
                    _fail("Hysteria2 同义参数冲突")
                proxy[target] = query[source]
    elif protocol == "tuic":
        _allow_query(query, common | {"congestion_control", "congestion-controller", "udp_relay_mode", "udp-relay-mode",
                                    "disable_sni", "disable-sni", "reduce_rtt", "reduce-rtt"})
        if parts.password is None:
            _fail("TUIC v5 分享链接缺少密码")
        proxy.update(uuid=user, password=urllib.parse.unquote(parts.password))
        _tls_from_query(proxy, query, "tls")
        for source, target in (("congestion_control", "congestion-controller"), ("congestion-controller", "congestion-controller"),
                               ("udp_relay_mode", "udp-relay-mode"), ("udp-relay-mode", "udp-relay-mode"),
                               ("disable_sni", "disable-sni"), ("disable-sni", "disable-sni"),
                               ("reduce_rtt", "reduce-rtt"), ("reduce-rtt", "reduce-rtt")):
            if source in query:
                option = _qbool(query[source]) if target in ("disable-sni", "reduce-rtt") else query[source]
                if target in proxy and proxy[target] != option:
                    _fail("TUIC 同义参数冲突")
                proxy[target] = option
    return validate_import_proxy(proxy)


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON 含重复字段")
        result[key] = value
    return result


def _load_yaml(text):
    if yaml is None:
        _fail("完整 YAML 导入需要 PyYAML 依赖，请安装完整新版程序")

    class BoundedSafeLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self.node_budget = 0
            self.node_depth = 0

        def compose_node(self, parent, index):
            self.node_budget += 1
            self.node_depth += 1
            try:
                if self.node_budget > MAX_TREE_NODES or self.node_depth > MAX_TREE_DEPTH:
                    _fail("YAML 结构过大或嵌套过深")
                if self.check_event(yaml.AliasEvent):
                    _fail("YAML 锚点引用暂不支持，请先展开为普通配置")
                return super().compose_node(parent, index)
            finally:
                self.node_depth -= 1

        def construct_mapping(self, node, deep=False):
            if not isinstance(node, yaml.MappingNode):
                _fail("YAML 对象格式无效")
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    _fail("YAML 字段名称必须是文本，合并键不受支持")
                if key in result:
                    _fail("YAML 含重复字段")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    loader = BoundedSafeLoader(text)
    try:
        parsed = loader.get_single_data()
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        suffix = f"（第 {mark.line + 1} 行）" if mark is not None else ""
        _fail("YAML 语法或类型不受支持" + suffix)
    finally:
        loader.dispose()
    return _plain(parsed, "YAML 配置")


def _default_profile():
    # Missing groups/rules intentionally delegates to the workspace's defaults.
    return {"name": "G-Network 导入配置", "mixed_port": 7890, "template": "custom", "mode": "rule",
            "chains": [], "advanced": {}}


def _test_url(value):
    value = _string(value, "测速 URL", limit=2048)
    try:
        parts = urllib.parse.urlsplit(value)
        if (parts.scheme not in ("http", "https") or not parts.hostname or
                parts.username is not None or parts.password is not None or parts.fragment
                or parts.port == 0 or "\\" in value or any(char.isspace() for char in value)):
            raise ValueError()
        _host(parts.hostname, "测速 URL 地址")
    except (ValueError, UnicodeError):
        _fail("测速 URL 必须是有效 HTTP/HTTPS 地址，不含账户信息或片段")
    return value


def _validate_rule_value(kind, value):
    value = _string(value, "规则匹配内容", limit=1024)
    if kind in ("DOMAIN", "DOMAIN-SUFFIX"):
        _host(value[:-1] if value.endswith(".") else value, "规则域名")
    elif kind in ("IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6"):
        try:
            if "/" not in value:
                raise ValueError()
            network = ipaddress.ip_network(value, strict=False)
            if kind.endswith("6") and network.version != 6:
                raise ValueError()
            if kind in ("IP-CIDR", "SRC-IP-CIDR") and network.version != 4:
                raise ValueError()
        except ValueError:
            _fail("IP 规则需要对应 IPv4/IPv6 类型的有效 CIDR")
    elif kind in ("DST-PORT", "SRC-PORT"):
        _port_ranges(value, "端口规则", slash=True)
    elif kind == "GEOIP":
        if not re.fullmatch(r"(?i)[a-z]{2}|lan|private", value):
            _fail("GEOIP 匹配内容无效")
    elif kind == "GEOSITE":
        if not re.fullmatch(r"[A-Za-z0-9_!@.-]{1,253}", value):
            _fail("GEOSITE 匹配内容无效")
    elif kind == "NETWORK" and value.upper() not in ("TCP", "UDP"):
        _fail("NETWORK 规则仅支持 TCP/UDP")
    return value


def _result(proxies, profile, warnings, errors, source_format, can_replace=True, omitted_fields=None):
    return {"proxies": proxies, "profile": profile, "warnings": warnings, "errors": errors,
            "source_format": source_format, "can_replace": can_replace, "omitted_fields": omitted_fields or []}


def _import_links(text, source_format):
    proxies, errors, names = [], [], set()
    lines = text.splitlines()
    if len(lines) > 4096:
        _fail("分享链接文本行数过多")
    for index, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if len(proxies) >= MAX_PROXIES:
                _fail(f"一次最多导入 {MAX_PROXIES} 个节点")
            proxy = _parse_uri(line)
            original = proxy["name"]
            name, number = original, 2
            while name in names:
                name = f"{original} · {number}"
                number += 1
            proxy["name"] = name
            names.add(name)
            proxies.append(proxy)
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError) as error:
            message = str(error) if isinstance(error, UnsupportedExport) else "分享链接格式无效"
            errors.append({"line": index + 1, "kind": "link", "msg": message})
    warnings = ["部分分享链接未导入，请按行号检查错误。"] if errors else []
    return _result(proxies, _default_profile(), warnings, errors, source_format, can_replace=bool(proxies))


def _import_document(document):
    if not isinstance(document, dict):
        _fail("完整配置必须是 YAML/JSON 对象")
    raw_proxies = document.get("proxies")
    if not isinstance(raw_proxies, list) or not 1 <= len(raw_proxies) <= MAX_PROXIES:
        _fail(f"完整配置需要 1–{MAX_PROXIES} 个内联代理节点")
    proxies = []
    for index, value in enumerate(raw_proxies):
        try:
            proxies.append(validate_import_proxy(value))
        except (ValueError, TypeError, KeyError) as error:
            message = str(error) if isinstance(error, UnsupportedExport) else "节点格式无效"
            _fail(f"第 {index + 1} 个节点：{message}")
    node_names = [proxy["name"] for proxy in proxies]
    if len(set(node_names)) != len(node_names):
        _fail("完整配置存在重复节点名称，无法可靠还原引用")
    node_set = set(node_names)
    warnings, errors, omitted = [], [], []

    def omit(path, message):
        if path not in omitted:
            omitted.append(path)
            warnings.append(message)

    raw_groups = document.get("proxy-groups", [])
    if not isinstance(raw_groups, list) or len(raw_groups) > MAX_GROUPS:
        _fail(f"策略组必须是列表，最多 {MAX_GROUPS} 个")
    group_names = []
    for group in raw_groups:
        if not isinstance(group, dict):
            _fail("策略组必须为对象")
        group_names.append(_name(group.get("name"), "策略组名称"))
    if len(set(group_names)) != len(group_names) or set(group_names) & node_set:
        _fail("节点和策略组名称重复或发生碰撞，无法可靠还原引用")
    group_set = set(group_names)
    all_targets = node_set | group_set | BUILTINS
    groups = []
    graph = {}
    for index, group in enumerate(raw_groups):
        name = group["name"]
        if set(group) - GROUP_FIELDS:
            omit(f"proxy-groups[{index}]", "策略组含未支持的扩展选项，完整编辑已禁用；可单独合并基础节点。")
        group_type = group.get("type", "select")
        if group_type not in GROUP_TYPES:
            omit(f"proxy-groups[{index}].type", "此策略组类型暂不支持完整编辑；可单独合并基础节点。")
        members = group.get("proxies", [])
        if (not isinstance(members, list) or not members or len(members) > MAX_PROXIES + MAX_GROUPS + 2
                or any(not isinstance(member, str) or member not in all_targets for member in members)
                or len(set(members)) != len(members)):
            _fail("策略组成员缺失、重复或引用不存在")
        graph[name] = [member for member in members if member in group_set]
        editable = {"name": name, "type": group_type, "members": members}
        for key in ("url", "interval", "tolerance", "strategy"):
            if key in group:
                editable[key] = group[key]
        if "url" in editable:
            _test_url(editable["url"])
        if "interval" in editable:
            _integer(editable["interval"], "测速间隔", 10, 86400)
        if "tolerance" in editable:
            _integer(editable["tolerance"], "测速容差", 0, 3000)
        if "strategy" in editable and editable["strategy"] not in ("consistent-hashing", "round-robin"):
            _fail("负载均衡策略无效")
        if group_type == "select" and ("url" in editable or "interval" in editable):
            omit(f"proxy-groups[{index}]", "手动选择组包含测速参数，工作区无法原样编辑；可单独合并基础节点。")
        if group_type != "url-test" and "tolerance" in editable:
            omit(f"proxy-groups[{index}]", "非自动选择组包含测速容差，工作区无法原样编辑；可单独合并基础节点。")
        if group_type != "load-balance" and "strategy" in editable:
            omit(f"proxy-groups[{index}]", "非负载均衡组包含分配策略，工作区无法原样编辑；可单独合并基础节点。")
        groups.append(editable)

    def visit(name, visiting, done):
        if name in visiting:
            _fail("配置引用存在循环，不能缩短链路后导入")
        if name in done:
            return
        visiting.add(name)
        for dependency in graph[name]:
            visit(dependency, visiting, done)
        visiting.remove(name)
        done.add(name)

    done = set()
    for name in graph:
        visit(name, set(), done)

    by_name = {proxy["name"]: proxy for proxy in proxies}
    chains = []
    for proxy in proxies:
        if "dialer-proxy" not in proxy:
            continue
        name, current, seen, hops = proxy["name"], proxy["name"], set(), []
        unavailable = False
        while current:
            if current in seen:
                _fail("链式代理存在循环，不能缩短链路后导入")
            seen.add(current)
            if current in group_set:
                omit("proxies.dialer-proxy", "dialer-proxy 指向策略组，暂不支持完整编辑；合并仅保留基础节点。")
                unavailable = True
                break
            if current not in by_name:
                _fail("链式代理引用缺少节点，不能缩短链路后导入")
            hops.append(current)
            if len(hops) > MAX_HOPS:
                _fail(f"链式代理最多 {MAX_HOPS} 跳，不能截短后导入")
            current = by_name[current].get("dialer-proxy")
        if not unavailable:
            chains.append({"name": name, "hops": list(reversed(hops)), "enabled": True})
    if len(chains) > MAX_CHAINS:
        _fail(f"链式代理最多 {MAX_CHAINS} 条")
    for proxy in proxies:
        proxy.pop("dialer-proxy", None)

    raw_rules = document.get("rules", [])
    if not isinstance(raw_rules, list) or len(raw_rules) > MAX_RULES:
        _fail(f"路由规则必须是列表，最多 {MAX_RULES} 条")
    rules, has_match = [], False
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, str):
            _fail("路由规则必须为文本")
        _string(raw, "路由规则", limit=4096)
        parts = [item.strip() for item in raw.split(",")]
        kind = parts[0].upper() if parts else ""
        if kind not in IMPORT_RULE_TYPES:
            omit(f"rules[{index}]", "路由规则包含未支持类型，完整编辑已禁用；可单独合并基础节点。")
            continue
        if kind == "MATCH":
            if len(parts) != 2 or has_match or index != len(raw_rules) - 1:
                _fail("MATCH 必须为最后一条且只能出现一次")
            target = parts[1]
            rule = {"type": kind, "value": "", "target": target, "no_resolve": False}
            has_match = True
        else:
            if len(parts) not in (3, 4) or (len(parts) == 4 and parts[3] != "no-resolve"):
                _fail("路由规则参数格式无效")
            if len(parts) == 4 and kind not in ("IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6", "GEOIP"):
                _fail("no-resolve 仅适用于 IP 或 GEOIP 规则")
            target = parts[2]
            rule = {"type": kind, "value": parts[1], "target": target, "no_resolve": len(parts) == 4}
            if not parts[1]:
                _fail("路由规则匹配内容不能为空")
            _validate_rule_value(kind, parts[1])
        if target not in all_targets:
            _fail("路由规则目标引用不存在")
        rules.append(rule)
    known = {"proxies", "proxy-groups", "rules", "mixed-port", "port", "mode"} | ADVANCED_FIELDS
    for key in document.keys() - known:
        omit(key, "部分顶层字段无法在工作区完整编辑，已列出省略字段；可单独合并基础节点。")
    if document.get("mode", "rule") != "rule":
        omit("mode", "原配置不是规则模式；完整替换需先明确转换路由模式。")
    if "port" in document and "mixed-port" in document:
        omit("port", "原配置包含独立 HTTP 端口；工作区使用混合端口，完整编辑已禁用。")
    mixed_port = _integer(document.get("mixed-port", document.get("port", 7890)), "混合端口", 1, 65535)
    advanced = {key: copy.deepcopy(document[key]) for key in ADVANCED_FIELDS & document.keys()}
    for key in ("dns", "sniffer", "tun", "profile"):
        if key in advanced and not isinstance(advanced[key], dict):
            _fail("高级配置对象格式无效")
    _bool_fields(advanced, {"ipv6", "unified-delay", "tcp-concurrent", "allow-lan"}, "高级配置")
    if "find-process-mode" in advanced and advanced["find-process-mode"] not in ("always", "strict", "off"):
        _fail("find-process-mode 无效")
    if "log-level" in advanced and advanced["log-level"] not in ("debug", "info", "warning", "error", "silent"):
        _fail("日志级别无效")
    if "bind-address" in advanced:
        _string(advanced["bind-address"], "监听地址", limit=253)
    fallback = rules[-1]["target"] if has_match else (group_names[0] if group_names else "DIRECT")
    profile = {"name": "G-Network 导入配置", "mixed_port": mixed_port, "template": "custom", "mode": "rule",
               "groups": groups, "rules": rules, "fallback": fallback, "chains": chains, "advanced": advanced}
    if not has_match:
        warnings.append("原配置没有 MATCH，生成时会追加当前兜底策略。")
    return _result(proxies, profile, list(dict.fromkeys(warnings)), errors, "yaml", can_replace=not omitted, omitted_fields=omitted)


def import_clash_text(text, format="auto"):
    """Parse local text. Invalid syntax/unsafe structure raises UnsupportedExport.

    ``can_replace=False`` means the file cannot be faithfully reconstructed by
    this editor. Its validated base proxies can still be explicitly merged.
    Share-link errors are per line and deliberately never contain raw links.
    """
    if not isinstance(text, str) or format not in ("auto", "links", "base64", "yaml"):
        _fail("导入文本或格式无效")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        _fail("导入文本编码无效")
    if not 1 <= size <= MAX_TEXT_BYTES:
        _fail("导入文本为空或超过 512 KiB")
    text = text.lstrip("\ufeff").strip()
    if not text:
        _fail("导入文本不能为空")
    if format == "yaml":
        return _import_document(_load_yaml(text))
    if format == "base64":
        return _import_links(_decode64(text, "订阅 Base64 内容"), "base64")
    if format == "links":
        return _import_links(text, "links")
    normalized = re.sub(r"\\(?=[:@_?&#=])", "", text)
    if re.search(r"(?im)^\s*[A-Za-z][A-Za-z0-9+.-]*://", normalized):
        return _import_links(normalized, "links")
    if re.fullmatch(r"[A-Za-z0-9_+/=\s-]+", text):
        try:
            decoded = _decode64(text, "订阅 Base64 内容")
            if re.search(r"(?im)^\s*[A-Za-z][A-Za-z0-9+.-]*://", decoded):
                return _import_links(decoded, "base64")
        except UnsupportedExport:
            pass
    return _import_document(_load_yaml(text))
