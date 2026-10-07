"""Clash import preview, capability registration and encrypted draft APIs."""
import base64
import copy
import contextlib
import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from functools import wraps

from flask import jsonify, request

from clash_export import SourceCapabilityChanged, compatibility, yaml_configuration
from clash_import import import_clash_text, validate_import_proxy
from clash_profile_store import ClashProfileStore, ProfileConflict
from clash_workspace import build_workspace_configuration
from node_routing import stable_routing_key


class StudioError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class ImportPreviews:
    def __init__(self, ttl=600, capacity=8, clock=time.monotonic):
        self.ttl, self.capacity, self.clock = ttl, capacity, clock
        self.entries = OrderedDict()
        self.lock = threading.RLock()

    def _purge(self):
        for token, entry in list(self.entries.items()):
            if entry[0] <= self.clock():
                self.entries.pop(token, None)

    def register(self, value):
        with self.lock:
            self._purge()
            while len(self.entries) >= self.capacity:
                self.entries.popitem(last=False)
            token = secrets.token_urlsafe(32)
            self.entries[token] = (self.clock() + self.ttl, copy.deepcopy(value))
            return token

    def get(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        with self.lock:
            self._purge()
            entry = self.entries.get(token)
            return copy.deepcopy(entry[1]) if entry else None

    def clear(self):
        with self.lock:
            self.entries.clear()


def _body(allowed):
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or set(data) - set(allowed):
        raise StudioError("Clash 工作区请求格式无效")
    return data


def _remap_profile(profile, mapping, *, preserve_targets=()):
    result = copy.deepcopy(profile)
    preserved = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", *preserve_targets}
    preserved.update(group["name"] for group in result.get("groups", []))
    preserved.update(chain["name"] for chain in result.get("chains", []))

    def target(value):
        if value in preserved:
            return value
        return mapping.get(value, value)

    for group in result.get("groups", []):
        group["members"] = [target(member) for member in group.get("members", [])]
    for rule in result.get("rules", []):
        rule["target"] = target(rule.get("target"))
    if "fallback" in result:
        result["fallback"] = target(result["fallback"])
    for chain in result.get("chains", []):
        chain["hops"] = [mapping.get(hop, hop) for hop in chain.get("hops", [])]
    return result


def _proxy_identity(proxy, routing_key=None):
    """Display aliases stay distinct; routing preferences can survive a rename."""
    representation = [routing_key, proxy] if routing_key is not None else proxy
    return hashlib.sha256(json.dumps(representation, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def register_clash_studio(panel):
    app = panel.app
    panel.CLASH_IMPORT_PREVIEWS = ImportPreviews()
    panel.CLASH_PROFILE_STORE = ClashProfileStore(os.path.join(panel.DATA_DIR, "clash-profiles.json"), panel.DATA_LOCK)
    manual_ids = {}
    manual_lock = threading.RLock()

    def api(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except (StudioError, ProfileConflict) as error:
                return jsonify(ok=False, error=str(error), msg=str(error)), getattr(error, "status", 409)
            except (ValueError, TypeError, KeyError, RuntimeError) as error:
                # Validators use fixed messages; parser errors must never contain a URI/credential.
                message = str(error) if isinstance(error, (ValueError, RuntimeError)) else "Clash 配置格式无效"
                return jsonify(ok=False, error=message, msg=message), 400
        return wrapped

    def inventory(snapshot_id, *, optional=False):
        if optional and snapshot_id is None:
            return []
        nodes = panel.CLASH_SNAPSHOTS.get(snapshot_id)
        if nodes is None:
            raise StudioError("节点读取记录已过期，请重新读取或导入配置", 409)
        if any(node.get("available") and panel.CLASH_EXPORTS.get_proxy(node["id"]) is None for node in nodes):
            raise StudioError("节点来源已修改或过期，请刷新节点后再操作", 409)
        return nodes

    def catalog_proxy(proxy, origin, *, key=None):
        proxy = validate_import_proxy(proxy)
        key = key or stable_routing_key("manual", (proxy["server"], proxy["port"]), proxy)
        identity = _proxy_identity(proxy, key)
        with manual_lock:
            for old_key, old_token in list(manual_ids.items()):
                if panel.CLASH_EXPORTS.get_proxy(old_token) is None:
                    manual_ids.pop(old_key, None)
            token = manual_ids.get(identity)
            if token is None:
                token = panel.CLASH_EXPORTS.register(yaml_configuration(proxy), ("import", identity), identity,
                                                    "G-Network-import.yaml", proxy=proxy, routing_key=key)
                manual_ids[identity] = token
        kind, notice = compatibility(proxy)
        return {"id": token, "origin": origin, "server_id": "", "server_name": "已保存配置" if origin == "saved" else "导入节点",
                "host": proxy["server"], "name": proxy["name"], "protocol": proxy["type"], "port": proxy["port"],
                "available": True, "compatibility": kind, "notice": notice, "routing": panel.NODE_ROUTING_STORE.get(key)}

    def snapshot_response(nodes, **extra):
        if len(nodes) > 256:
            raise StudioError("节点库最多 256 个节点，请减少导入内容")
        snapshot = panel.CLASH_SNAPSHOTS.register(nodes)
        return jsonify(ok=True, snapshot_id=snapshot, nodes=nodes, servers=extra.pop("servers", []),
                       expires_at=int(time.time() + panel.CLASH_SNAPSHOTS.ttl), **extra)

    @app.post("/api/clash-workspace/import-preview")
    @api
    def studio_import_preview():
        data = _body({"text", "format"})
        text = data.get("text")
        if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > 512 * 1024:
            raise StudioError("请输入或上传不超过 512 KiB 的节点配置")
        parsed = import_clash_text(text, data.get("format", "auto"))
        token = panel.CLASH_IMPORT_PREVIEWS.register(parsed)
        profile = parsed.get("profile", {})
        nodes = [{"name": proxy["name"], "protocol": proxy["type"], "host": proxy["server"], "port": proxy["port"]}
                 for proxy in parsed["proxies"]]
        return jsonify(ok=True, import_token=token, source_format=parsed["source_format"],
                       node_count=len(nodes), nodes=nodes, group_count=len(profile.get("groups", [])),
                       rule_count=len(profile.get("rules", [])), chain_count=len(profile.get("chains", [])),
                       can_replace=parsed["can_replace"], warnings=parsed["warnings"], errors=parsed["errors"],
                       omitted_fields=parsed["omitted_fields"])

    @app.post("/api/clash-workspace/import")
    @api
    def studio_import():
        data = _body({"import_token", "snapshot_id", "mode"})
        mode = data.get("mode")
        if mode not in ("merge", "replace"):
            raise StudioError("请选择合并节点或编辑完整配置")
        parsed = panel.CLASH_IMPORT_PREVIEWS.get(data.get("import_token"))
        if parsed is None:
            raise StudioError("导入预览已过期，请重新解析配置", 409)
        if mode == "replace" and not parsed["can_replace"]:
            raise StudioError("配置包含暂不能完整编辑的内容，请只合并节点或保留原文件")
        old_nodes = inventory(data.get("snapshot_id"), optional=True) if mode == "merge" else []
        if len(old_nodes) + len(parsed["proxies"]) > 256:
            raise StudioError("节点库最多 256 个节点，请减少导入内容")
        nodes, imported_ids, name_map = copy.deepcopy(old_nodes), [], {}
        existing_keys = {_proxy_identity(panel.CLASH_EXPORTS.get_proxy(node["id"])): node
                         for node in old_nodes if node.get("available")}
        for proxy in parsed["proxies"]:
            key = stable_routing_key("manual", (proxy["server"], proxy["port"]), proxy)
            identity = _proxy_identity(proxy)
            node = existing_keys.get(identity)
            if node is None:
                node = catalog_proxy(proxy, "import", key=key)
                # A repeated credential identity may have a different display label.
                if node["id"] not in {item["id"] for item in nodes}:
                    nodes.append(node)
                existing_keys[identity] = node
            name_map[proxy["name"]] = node["id"]
            if node["id"] not in imported_ids:
                imported_ids.append(node["id"])
        if not imported_ids:
            raise StudioError("没有可以导入的有效节点，请查看解析结果")
        extras = {"imported_ids": imported_ids, "warnings": parsed["warnings"], "errors": parsed["errors"]}
        if mode == "replace":
            profile = _remap_profile(parsed["profile"], name_map)
            proxies = [panel.CLASH_EXPORTS.get_proxy(token) for token in imported_ids]
            build_workspace_configuration(proxies, imported_ids, profile)
            extras["profile"] = profile
        return snapshot_response(nodes, **extras)

    @app.get("/api/clash-workspace/profiles")
    @api
    def studio_profiles():
        return jsonify(ok=True, profiles=panel.CLASH_PROFILE_STORE.list())

    @app.post("/api/clash-workspace/profiles/save")
    @api
    def studio_profile_save():
        data = _body({"snapshot_id", "node_ids", "profile", "profile_id", "expected_revision"})
        nodes = inventory(data.get("snapshot_id"))
        ids = data.get("node_ids")
        if (not isinstance(ids, list) or not 1 <= len(ids) <= 128 or any(not isinstance(value, str) for value in ids)
                or len(set(ids)) != len(ids)):
            raise StudioError("请选择 1-128 个节点，不可重复")
        by_id = {node["id"]: node for node in nodes if node.get("available")}
        if any(token not in by_id for token in ids):
            raise StudioError("所选节点不属于当前工作区")
        proxies = [panel.CLASH_EXPORTS.get_proxy(token) for token in ids]
        profile = data.get("profile")
        built = build_workspace_configuration(proxies, ids, profile)
        # Persist references independently of expiring capability tokens.
        mapping = {token: base64.urlsafe_b64encode(hashlib.sha256(f"saved-node:{index}".encode()).digest()).decode().rstrip("=")
                   for index, token in enumerate(ids)}
        stored_nodes = [{"id": mapping[token], "proxy": proxy,
                         "routing_key": panel.CLASH_EXPORTS.get_routing_key(token)} for token, proxy in zip(ids, proxies)]
        payload = {"profile": _remap_profile(profile, mapping), "nodes": stored_nodes,
                   "counts": {"node_count": len(ids), "group_count": len(built["config"]["proxy-groups"]),
                              "rule_count": len(built["config"]["rules"]), "chain_count": len(profile.get("chains", []))}}
        try:
            with panel.DATA_LOCK, contextlib.ExitStack() as guards:
                for token, node in zip(ids, stored_nodes):
                    guards.enter_context(panel.CLASH_EXPORTS.source_guard(token, node["routing_key"]))
                saved = panel.CLASH_PROFILE_STORE.save(payload, data.get("profile_id"), data.get("expected_revision"))
        except SourceCapabilityChanged:
            raise StudioError("节点在保存期间发生变化，请刷新节点后保存", 409) from None
        return jsonify(ok=True, profile=saved)

    @app.post("/api/clash-workspace/profiles/open")
    @api
    def studio_profile_open():
        data = _body({"profile_id"})
        payload, metadata = panel.CLASH_PROFILE_STORE.get(data.get("profile_id"))
        nodes, mapping = [], {}
        for item in payload["nodes"]:
            node = catalog_proxy(item["proxy"], "saved", key=item["routing_key"])
            mapping[item["id"]] = node["id"]
            nodes.append(node)
        profile = _remap_profile(payload["profile"], mapping)
        ids = [node["id"] for node in nodes]
        build_workspace_configuration([panel.CLASH_EXPORTS.get_proxy(token) for token in ids], ids, profile)
        return snapshot_response(nodes, imported_ids=ids, profile=profile, saved_profile=metadata,
                                 warnings=["已打开本机保存的配置快照；服务器修改后，请重新读取对应节点。"])

    @app.post("/api/clash-workspace/profiles/delete")
    @api
    def studio_profile_delete():
        data = _body({"profile_id", "expected_revision"})
        panel.CLASH_PROFILE_STORE.delete(data.get("profile_id"), data.get("expected_revision"))
        return jsonify(ok=True)
