"""Bounded node routing preferences, without storing proxy credentials."""
import copy
import json
import os
import re
import stat

from local_security import atomic_json_write
from node_routing import normalize_routing


class RoutingConflict(ValueError):
    """The editor's saved revision no longer matches the local preference."""


class NodeRoutingStore:
    MAX_RECORDS = 512
    MAX_BYTES = 4 * 1024 * 1024

    def __init__(self, path, lock):
        self.path, self.lock = path, lock

    @staticmethod
    def _key(key):
        if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key):
            raise ValueError("节点分流身份无效，请重新读取节点")
        return key

    def _load(self):
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            return {}
        if not stat.S_ISREG(info.st_mode) or info.st_size > self.MAX_BYTES:
            raise ValueError("节点分流文件无效或超过大小限制")
        try:
            with open(self.path, "rb") as stream:
                raw = stream.read(self.MAX_BYTES + 1)
            if len(raw) > self.MAX_BYTES:
                raise ValueError("over limit")
            payload = json.loads(raw.decode("utf-8"))
            if (not isinstance(payload, dict) or set(payload) != {"version", "routes"}
                    or type(payload["version"]) is not int or payload["version"] != 1
                    or not isinstance(payload["routes"], dict)
                    or len(payload["routes"]) > self.MAX_RECORDS):
                raise ValueError("invalid structure")
            records = {}
            for key, value in payload["routes"].items():
                self._key(key)
                if not isinstance(value, dict) or set(value) != {"enabled", "direct_domains", "revision"}:
                    raise ValueError("invalid record")
                normalized = normalize_routing(value)
                if normalized != value or normalized["revision"] > 2 ** 53 - 1:
                    raise ValueError("invalid normalized record")
                records[key] = normalized
            return records
        except (ValueError, TypeError, UnicodeError, KeyError, RecursionError) as error:
            raise ValueError("节点分流文件格式无效，请先保留文件并检查本机配置") from error

    def get(self, key):
        key = self._key(key)
        with self.lock:
            return copy.deepcopy(self._load().get(key, {"enabled": False, "direct_domains": [], "revision": 0}))

    def get_many(self, keys):
        """Read once for a workspace inventory instead of once per node."""
        keys = tuple(self._key(key) for key in keys)
        with self.lock:
            records = self._load()
            return {key: copy.deepcopy(records.get(key, {"enabled": False, "direct_domains": [], "revision": 0}))
                    for key in keys}

    def save(self, key, enabled, direct_domains, expected_revision):
        key = self._key(key)
        if type(expected_revision) is not int or not 0 <= expected_revision <= 2 ** 53 - 1:
            raise ValueError("缺少有效的节点分流版本，请重新读取节点")
        normalized = normalize_routing({"enabled": enabled, "direct_domains": direct_domains})
        with self.lock:
            records = self._load()
            before = records.get(key, {"enabled": False, "direct_domains": [], "revision": 0})
            if before["revision"] != expected_revision:
                raise RoutingConflict("节点分流已在其他编辑中更新，请重新读取节点后再保存")
            if all(before[field] == normalized[field] for field in ("enabled", "direct_domains")):
                return copy.deepcopy(before), False
            if key not in records and len(records) >= self.MAX_RECORDS:
                raise ValueError("最多保存 512 份节点专属分流，请先整理已有节点")
            if before["revision"] >= 2 ** 53 - 1:
                raise ValueError("节点分流版本已达到上限")
            after = {"enabled": normalized["enabled"], "direct_domains": normalized["direct_domains"],
                     "revision": before["revision"] + 1}
            records[key] = after
            payload = {"version": 1, "routes": records}
            # Account for the pretty encoding used by atomic_json_write.
            if len(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")) > self.MAX_BYTES:
                raise ValueError("节点分流文件超过 4 MiB 限制，请减少域名")
            atomic_json_write(self.path, payload)
            return copy.deepcopy(after), True
