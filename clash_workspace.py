"""Pure, bounded multi-node Clash / Mihomo workspace configuration builder.

Callers resolve opaque node IDs to proxies validated by ``clash_export``. This
module never reads user data, connects to a server, or fetches rule providers.
Group members and rule targets reference IDs, groups, or explicit built-ins;
node display names are never used as identifiers in the editing contract.
"""
import copy
import ipaddress
import json
import math
import re
import unicodedata
import urllib.parse

from clash_export import TOKEN_PATTERN, UnsupportedExport, _yaml_lines, compatibility
from clash_import import IMPORT_RULE_TYPES, validate_import_proxy


MAX_NODES = 128
MAX_GROUPS = 16
MAX_RULES = 200
MAX_CHAINS = 16
MAX_CHAIN_HOPS = 8
ADVANCED_FIELDS = frozenset(("dns", "sniffer", "tun", "ipv6", "profile", "unified-delay",
                            "tcp-concurrent", "find-process-mode", "allow-lan", "bind-address", "log-level",
                            "hosts", "authentication", "skip-auth-prefixes", "lan-allowed-ips",
                            "lan-disallowed-ips", "tcp-keep-alive-idle", "tcp-keep-alive-interval"))
BUILTINS = frozenset(("DIRECT", "REJECT"))
RESERVED_NAMES = BUILTINS | frozenset(("GLOBAL", "PASS", "COMPATIBLE", "REJECT-DROP"))
GROUP_TYPES = frozenset(("select", "url-test", "fallback", "load-balance"))
RULE_TYPES = IMPORT_RULE_TYPES
NO_RESOLVE_TYPES = frozenset(("IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6", "GEOIP"))
TEST_URL = "https://www.gstatic.com/generate_204"


def _text(value, label, *, empty=False, limit=500):
    if not isinstance(value, str) or len(value) > limit or (not value and not empty):
        raise UnsupportedExport(f"{label}格式无效")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise UnsupportedExport(f"{label}格式无效") from error
    return value


def _has_control(value):
    return any(unicodedata.category(char) in ("Cc", "Zl", "Zp") for char in value)


def _integer(value, label, low, high):
    if (isinstance(value, bool) or not isinstance(value, (str, int)) or len(str(value)) > 10
            or not re.fullmatch(r"[0-9]+", str(value))):
        raise UnsupportedExport(f"{label}必须为整数")
    number = int(value)
    if not low <= number <= high:
        raise UnsupportedExport(f"{label}必须在 {low}–{high} 之间")
    return number


def _policy_name(value, label):
    value = _text(value, label, limit=180)
    if value != value.strip() or "," in value or _has_control(value):
        raise UnsupportedExport(f"{label}不能包含逗号、控制字符或首尾空格")
    return value


def _node_name(value, index):
    value = _text(value, "节点名称", empty=True)
    # Full-width punctuation retains the user's visible label without becoming
    # a delimiter in comma-separated Clash rule expressions.
    value = "".join(char for char in value if unicodedata.category(char) not in ("Cc", "Zl", "Zp"))
    return value.replace(",", "，").strip() or f"节点 {index + 1}"


def _url(value):
    value = _text(value, "测速地址", limit=2048)
    if _has_control(value) or any(char.isspace() for char in value) or "\\" in value:
        raise UnsupportedExport("测速地址格式无效")
    try:
        parts = urllib.parse.urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username is not None or parts.password is not None:
            raise ValueError("HTTP(S) URL required")
        if parts.fragment or parts.port == 0:
            raise ValueError("invalid URL fragment or port")
        host = parts.hostname
        try:
            ipaddress.ip_address(host)
        except ValueError:
            _domain(host)
    except (ValueError, UnicodeError) as error:
        raise UnsupportedExport("测速地址必须为有效的 HTTP / HTTPS 地址，且不能包含账户信息或片段") from error
    return value


def _domain(value):
    value = _text(value, "域名规则", limit=253)
    if _has_control(value) or value != value.strip() or "," in value:
        raise UnsupportedExport("域名规则格式无效")
    try:
        ascii_name = (value[:-1] if value.endswith(".") else value).encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise UnsupportedExport("域名规则格式无效") from error
    if (not ascii_name or len(ascii_name) > 253 or
            any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in ascii_name.split("."))):
        raise UnsupportedExport("域名规则应填写域名，不含协议、路径、通配符或端口")
    return ascii_name


def _rule_value(rule_type, value):
    value = _text(value, "规则内容", limit=2048)
    if value != value.strip() or "," in value or _has_control(value):
        raise UnsupportedExport("规则内容不能包含逗号、控制字符或首尾空格")
    if rule_type in ("DOMAIN", "DOMAIN-SUFFIX"):
        return _domain(value)
    if rule_type == "DOMAIN-KEYWORD":
        if not all(char.isalnum() or char in "._-" for char in value):
            raise UnsupportedExport("域名关键词只允许文字、数字、点、下划线或连字符")
        return value
    if rule_type in ("IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6"):
        try:
            if "/" not in value:
                raise ValueError("prefix required")
            network = ipaddress.ip_network(value, strict=False)
            if rule_type == "IP-CIDR" and network.version != 4:
                raise ValueError("IPv4 required")
            if rule_type in ("IP-CIDR6", "SRC-IP-CIDR6") and network.version != 6:
                raise ValueError("IPv6 required")
        except ValueError as error:
            raise UnsupportedExport("IP 规则应填写有效的 CIDR 地址范围，并与 IPv4 / IPv6 类型一致") from error
        return str(network)
    if rule_type == "GEOIP":
        value = value.upper()
        if not re.fullmatch(r"[A-Z]{2}|LAN", value):
            raise UnsupportedExport("GEOIP 内容应为两位国家代码或 LAN")
        return value
    if rule_type in ("DST-PORT", "SRC-PORT"):
        segments = value.split("/")
        if len(segments) > 32:
            raise UnsupportedExport("目标端口规则范围过多")
        normalized = []
        for segment in segments:
            if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", segment):
                raise UnsupportedExport("目标端口应填写端口或端口范围，多个范围用 / 分隔")
            bounds = [_integer(part, "目标端口", 1, 65535) for part in segment.split("-")]
            if len(bounds) == 2 and bounds[0] > bounds[1]:
                raise UnsupportedExport("目标端口范围起点不能大于终点")
            normalized.append("-".join(str(bound) for bound in bounds))
        return "/".join(normalized)
    if rule_type == "GEOSITE":
        if not re.fullmatch(r"[A-Za-z0-9_@!-]{1,180}", value):
            raise UnsupportedExport("GEOSITE 内容应为客户端数据库中的有效分类名称")
        return value
    if rule_type == "NETWORK":
        if value.upper() not in ("TCP", "UDP"):
            raise UnsupportedExport("NETWORK 内容应为 TCP 或 UDP")
        return value.upper()
    if rule_type in ("PROCESS-NAME", "PROCESS-PATH", "DOMAIN-REGEX"):
        # RE2 expressions and platform process paths remain exact. Compiling
        # them with Python regex would reject valid Go/RE2 syntax or introduce
        # a different grammar; the client core checks the final document.
        return value
    raise UnsupportedExport("不支持此规则类型")


def _default_groups(node_ids):
    return [
        {"name": "自动选择", "type": "url-test", "members": list(node_ids), "tolerance": 50},
        {"name": "故障转移", "type": "fallback", "members": list(node_ids)},
        {"name": "节点选择", "type": "select",
         "members": ["自动选择", "故障转移", *node_ids, "DIRECT"]},
    ]


def _default_rules(template):
    if template != "balanced":
        return []
    return [
        {"type": "IP-CIDR", "value": "127.0.0.0/8", "target": "DIRECT", "no_resolve": True},
        {"type": "IP-CIDR", "value": "10.0.0.0/8", "target": "DIRECT", "no_resolve": True},
        {"type": "IP-CIDR", "value": "172.16.0.0/12", "target": "DIRECT", "no_resolve": True},
        {"type": "IP-CIDR", "value": "192.168.0.0/16", "target": "DIRECT", "no_resolve": True},
        {"type": "IP-CIDR6", "value": "::1/128", "target": "DIRECT", "no_resolve": True},
        {"type": "IP-CIDR6", "value": "fc00::/7", "target": "DIRECT", "no_resolve": True},
        {"type": "IP-CIDR6", "value": "fe80::/10", "target": "DIRECT", "no_resolve": True},
        {"type": "GEOIP", "value": "CN", "target": "DIRECT"},
    ]


def validate_advanced(value):
    """Retain explicitly supported runtime settings without rewriting topology.

    Values are plain bounded JSON; this function does not fetch DNS endpoints,
    read paths or enable a local runtime. Unsupported top-level settings are
    rejected rather than silently disappearing from an imported configuration.
    """
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - ADVANCED_FIELDS:
        raise UnsupportedExport("高级配置包含不支持的字段；节点、策略组、规则、端口和外部 providers 请使用对应编辑器")
    count = 0

    def check(item, depth=0):
        nonlocal count
        count += 1
        if depth > 8 or count > 4096:
            raise UnsupportedExport("高级配置层级或条目过多")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, (int, float)):
            if abs(item) > 2 ** 53 or not math.isfinite(item):
                raise UnsupportedExport("高级配置数字无效")
            return
        if isinstance(item, str):
            if len(item) > 8192 or _has_control(item):
                raise UnsupportedExport("高级配置字符串过长或包含控制字符")
            return
        if isinstance(item, list):
            if len(item) > 1024:
                raise UnsupportedExport("高级配置列表过长")
            for child in item:
                check(child, depth + 1)
            return
        if isinstance(item, dict):
            if len(item) > 512:
                raise UnsupportedExport("高级配置对象过大")
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 512 or _has_control(key):
                    raise UnsupportedExport("高级配置键名无效")
                check(child, depth + 1)
            return
        raise UnsupportedExport("高级配置只能使用 JSON 对象、数组和基本值")

    check(value)
    try:
        if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) > 65536:
            raise UnsupportedExport("高级配置不得超过 64 KiB")
    except (UnicodeError, ValueError) as error:
        raise UnsupportedExport("高级配置格式无效") from error
    for key in ("dns", "sniffer", "tun", "profile", "hosts"):
        if key in value and not isinstance(value[key], dict):
            raise UnsupportedExport(f"{key} 高级配置必须为对象")
    for key in ("ipv6", "unified-delay", "tcp-concurrent", "allow-lan"):
        if key in value and not isinstance(value[key], bool):
            raise UnsupportedExport(f"{key} 高级配置必须为布尔值")
    if value.get("find-process-mode", "off") not in ("always", "strict", "off"):
        raise UnsupportedExport("进程匹配模式无效")
    if value.get("log-level", "warning") not in ("debug", "info", "warning", "error", "silent"):
        raise UnsupportedExport("日志等级无效")
    if "bind-address" in value:
        address = value["bind-address"]
        if not isinstance(address, str) or not address or len(address) > 253 or any(c.isspace() for c in address):
            raise UnsupportedExport("监听地址无效")
    dns = value.get("dns", {})
    if "respect-rules" in dns and not isinstance(dns["respect-rules"], bool):
        raise UnsupportedExport("DNS respect-rules 必须为布尔值")
    if dns.get("respect-rules"):
        resolvers = dns.get("proxy-server-nameserver")
        if not isinstance(resolvers, list) or not resolvers or any(not isinstance(item, str) or not item for item in resolvers):
            raise UnsupportedExport("DNS respect-rules 需要非空 proxy-server-nameserver，避免节点解析循环")
    return copy.deepcopy(value)


def _validated_chains(value, node_ids, group_names):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_CHAINS:
        raise UnsupportedExport(f"链式代理最多 {MAX_CHAINS} 条")
    seen, result = set(), []
    for chain in value:
        if not isinstance(chain, dict) or set(chain) - {"name", "hops", "enabled", "id"}:
            raise UnsupportedExport("链式代理格式无效")
        name = _policy_name(chain.get("name"), "链路名称")
        if name in seen or name in RESERVED_NAMES or name in group_names or re.fullmatch(TOKEN_PATTERN, name):
            raise UnsupportedExport("链路名称重复、保留或与策略组 / 节点标识冲突")
        seen.add(name)
        enabled = chain.get("enabled", True)
        hops = chain.get("hops")
        if not isinstance(enabled, bool):
            raise UnsupportedExport("链路启用状态必须为布尔值")
        if (not isinstance(hops, list) or not 2 <= len(hops) <= MAX_CHAIN_HOPS
                or any(not isinstance(hop, str) or hop not in node_ids for hop in hops)):
            raise UnsupportedExport(f"链路需要 2–{MAX_CHAIN_HOPS} 个已选节点；缺失或未选节点不能跳过")
        if len(set(hops)) != len(hops):
            raise UnsupportedExport("链路中不能重复使用同一节点，以免循环")
        result.append({"name": name, "hops": list(hops), "enabled": enabled})
    return result


def build_workspace_configuration(proxies, node_ids, profile):
    """Build a complete YAML document from an immutable editing profile.

    ``names`` maps each opaque node ID to its unique final display name. Rules
    explicitly supplied by the user keep their order regardless of the starting
    template. A missing rules list uses that template's defaults. A final MATCH
    is kept if present, otherwise one is appended using ``fallback``.
    """
    if not isinstance(proxies, list) or not 1 <= len(proxies) <= MAX_NODES:
        raise UnsupportedExport(f"请选择 1–{MAX_NODES} 个节点")
    if not isinstance(node_ids, list) or len(node_ids) != len(proxies):
        raise UnsupportedExport("节点标识与所选节点不一致")
    if (any(not isinstance(node_id, str) or not re.fullmatch(TOKEN_PATTERN, node_id) for node_id in node_ids)
            or len(set(node_ids)) != len(node_ids)):
        raise UnsupportedExport("节点标识无效或重复，请重新读取节点")
    if not isinstance(profile, dict):
        raise UnsupportedExport("配置方案格式无效")
    template = profile.get("template", "balanced")
    if template not in ("balanced", "global", "custom") or profile.get("mode", "rule") != "rule":
        raise UnsupportedExport("配置模板或路由模式无效")
    profile_name = _node_name(profile.get("name", "G-Network 配置"), 0)
    mixed_port = _integer(profile.get("mixed_port", 7890), "本地混合端口", 1, 65535)
    input_groups = profile.get("groups")
    if input_groups is None:
        input_groups = _default_groups(node_ids)
    if not isinstance(input_groups, list) or len(input_groups) > MAX_GROUPS:
        raise UnsupportedExport(f"策略组最多 {MAX_GROUPS} 个")
    group_names = []
    for group in input_groups:
        if not isinstance(group, dict):
            raise UnsupportedExport("策略组格式无效")
        name = _policy_name(group.get("name"), "策略组名称")
        if name in RESERVED_NAMES or name in group_names or re.fullmatch(TOKEN_PATTERN, name):
            raise UnsupportedExport("策略组名称重复、保留或与节点标识冲突")
        group_names.append(name)
    group_name_set = set(group_names)
    chains = _validated_chains(profile.get("chains"), set(node_ids), group_name_set)
    chain_names = {chain["name"] for chain in chains if chain["enabled"]}
    advanced = validate_advanced(profile.get("advanced"))
    used_names = set(RESERVED_NAMES) | group_name_set | chain_names
    output_proxies, names, warnings = [], {}, []
    for index, (proxy, node_id) in enumerate(zip(proxies, node_ids)):
        if (not isinstance(proxy, dict) or not isinstance(proxy.get("type"), str)
                or proxy.get("type") not in ("vmess", "vless", "ss", "trojan", "hysteria2", "tuic")):
            raise UnsupportedExport("节点协议无效，请重新读取或导入节点")
        original_name = _text(proxy.get("name", ""), "节点名称", empty=True)
        base_name = _node_name(original_name, index)
        name, suffix = base_name, 2
        while name in used_names:
            name = f"{base_name} · {suffix}"
            suffix += 1
        used_names.add(name)
        names[node_id] = name
        item = copy.deepcopy(proxy)
        item["name"] = name
        item = validate_import_proxy(item)
        if item.get("dialer-proxy"):
            raise UnsupportedExport("节点的 dialer-proxy 请先还原为链式代理，不能作为独立基础节点导出")
        output_proxies.append(item)
        if name != original_name:
            notice = "部分节点名称已自动整理或去重；策略组和规则会使用对应的新名称。"
            if notice not in warnings:
                warnings.append(notice)
        try:
            notice = compatibility(item)[1]
        except (KeyError, TypeError) as error:
            raise UnsupportedExport("节点协议配置不完整，请重新读取或导入节点") from error
        if notice not in warnings:
            warnings.append(notice)
        if item.get("reality-opts"):
            notice = "Reality 节点还需核对服务端与 Mihomo 客户端版本；不保证所有 Clash 客户端或版本均可使用。"
            if notice not in warnings:
                warnings.append(notice)

    by_id = dict(zip(node_ids, output_proxies))
    chain_outputs = []
    for chain in chains:
        if not chain["enabled"]:
            continue
        previous = None
        for index, node_id in enumerate(chain["hops"]):
            is_exit = index == len(chain["hops"]) - 1
            name = chain["name"] if is_exit else f"{chain['name']} · 跳 {index + 1}"
            if not is_exit:
                base_name, suffix = name, 2
                while name in used_names:
                    name = f"{base_name} · {suffix}"
                    suffix += 1
                used_names.add(name)
            item = copy.deepcopy(by_id[node_id])
            item["name"] = name
            if previous is not None:
                item["dialer-proxy"] = previous
            chain_outputs.append(item)
            previous = name
    output_proxies.extend(chain_outputs)
    if chain_outputs:
        warnings.append("链路通过 dialer-proxy 生成独立副本；基础节点仍可单独使用，内部跳不会自动加入策略组。链路连通性和 UDP 能力还需实际核验。")

    def target_name(target, *, allow_node=True):
        target = _policy_name(target, "目标策略")
        if target in BUILTINS or target in group_name_set or target in chain_names:
            return target
        if allow_node and target in names:
            return names[target]
        raise UnsupportedExport("策略引用不存在，请检查所选节点和策略组")

    groups, graph = [], {}
    for source_group, name in zip(input_groups, group_names):
        group_type = source_group.get("type", "select")
        if not isinstance(group_type, str) or group_type not in GROUP_TYPES:
            raise UnsupportedExport("策略组类型无效")
        members = source_group.get("members")
        if (not isinstance(members, list) or not members or len(members) > MAX_NODES + MAX_GROUPS + MAX_CHAINS + 2
                or any(not isinstance(member, str) for member in members) or len(set(members)) != len(members)):
            raise UnsupportedExport("策略组至少需要一个有效成员，且成员不能重复")
        group = {"name": name, "type": group_type, "proxies": [target_name(member) for member in members]}
        graph[name] = [member for member in members if member in group_name_set]
        # User fields are copied only through this allowlist. They never become
        # providers, file paths, download directives, or runtime controllers.
        if group_type != "select":
            group["url"] = _url(source_group.get("url", TEST_URL))
            group["interval"] = _integer(source_group.get("interval", 300), "测速间隔", 10, 86400)
        elif "url" in source_group or "interval" in source_group:
            raise UnsupportedExport("手动选择组不使用测速地址或间隔")
        if group_type == "url-test":
            group["tolerance"] = _integer(source_group.get("tolerance", 50), "切换容差", 0, 3000)
        elif "tolerance" in source_group:
            raise UnsupportedExport("切换容差仅适用于自动选择组")
        if group_type == "load-balance":
            strategy = source_group.get("strategy", "consistent-hashing")
            if strategy not in ("consistent-hashing", "round-robin"):
                raise UnsupportedExport("负载均衡策略无效")
            group["strategy"] = strategy
        elif "strategy" in source_group:
            raise UnsupportedExport("负载均衡策略仅适用于负载均衡组")
        groups.append(group)
    visiting, visited = set(), set()

    def visit(name):
        if name in visiting:
            raise UnsupportedExport("策略组之间存在循环引用")
        if name in visited:
            return
        visiting.add(name)
        for member in graph[name]:
            visit(member)
        visiting.remove(name)
        visited.add(name)

    for name in group_names:
        visit(name)
    default_fallback = "节点选择" if "节点选择" in group_name_set else (group_names[0] if group_names else "DIRECT")
    input_rules = profile.get("rules")
    if input_rules is None:
        input_rules = _default_rules(template)
    if not isinstance(input_rules, list) or len(input_rules) > MAX_RULES:
        raise UnsupportedExport(f"路由规则最多 {MAX_RULES} 条（含最终兜底规则）")
    rules = []
    has_match = False
    for index, rule in enumerate(input_rules):
        if (not isinstance(rule, dict) or not isinstance(rule.get("type"), str)
                or rule.get("type") not in RULE_TYPES):
            raise UnsupportedExport("路由规则类型无效")
        rule_type = rule["type"]
        target = target_name(rule.get("target"))
        no_resolve = rule.get("no_resolve", False)
        if not isinstance(no_resolve, bool) or (no_resolve and rule_type not in NO_RESOLVE_TYPES):
            raise UnsupportedExport("no-resolve 仅适用于 IP 或 GEOIP 规则，并应为布尔值")
        if rule_type == "MATCH":
            if has_match or index != len(input_rules) - 1 or rule.get("value") not in (None, ""):
                raise UnsupportedExport("MATCH 必须是最后一条且只能出现一次，不填写匹配内容")
            has_match = True
            rules.append(f"MATCH,{target}")
            continue
        value = _rule_value(rule_type, rule.get("value"))
        rules.append(f"{rule_type},{value},{target}" + (",no-resolve" if no_resolve else ""))
        if rule_type in ("GEOIP", "GEOSITE"):
            notice = "GEOIP 规则需要客户端提供对应的地理数据库；此配置不附带或设置远程规则源。"
            if rule_type == "GEOSITE":
                notice = "GEOSITE 规则需要客户端提供对应的域名数据库；此配置不附带或设置远程规则源。"
            if notice not in warnings:
                warnings.append(notice)
    if not has_match:
        if len(rules) == MAX_RULES:
            raise UnsupportedExport(f"请预留一条兜底规则；规则总数最多 {MAX_RULES} 条")
        fallback = target_name(profile.get("fallback", default_fallback), allow_node=False)
        rules.append(f"MATCH,{fallback}")
    config = {"mixed-port": mixed_port, "allow-lan": False, "bind-address": "127.0.0.1",
              "mode": "rule", "log-level": "warning", "proxies": output_proxies,
              "proxy-groups": groups, "rules": rules}
    config.update(advanced)
    yaml = f"# G-Network - {profile_name}\n" + "\n".join(_yaml_lines(config)) + "\n"
    return {"config": config, "yaml": yaml, "warnings": warnings, "names": names,
            "chain_names": [chain["name"] for chain in chains if chain["enabled"]]}
