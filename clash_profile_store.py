"""User-bound encrypted Clash drafts; no paths or cleartext credentials in APIs."""
import copy
import json
import os
import re
import stat
import time
import uuid

from local_security import PREFIX, atomic_json_write, decrypt_secret, encrypt_secret


class ProfileConflict(ValueError):
    pass


class ClashProfileStore:
    MAX_PROFILES = 16
    MAX_PAYLOAD = 768 * 1024
    MAX_FILE = 24 * 1024 * 1024

    def __init__(self, path, lock):
        self.path, self.lock = path, lock

    @staticmethod
    def _id(value):
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
            raise ValueError("配置记录标识无效")
        return value

    def _load(self):
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            return {}
        if not stat.S_ISREG(info.st_mode) or info.st_size > self.MAX_FILE:
            raise ValueError("本机 Clash 配置文件无效或超过大小限制")
        try:
            with open(self.path, "rb") as stream:
                raw = stream.read(self.MAX_FILE + 1)
            data = json.loads(raw.decode("utf-8"))
            if (len(raw) > self.MAX_FILE or not isinstance(data, dict)
                    or set(data) != {"version", "profiles"} or type(data["version"]) is not int
                    or data["version"] != 1 or not isinstance(data["profiles"], dict)
                    or len(data["profiles"]) > self.MAX_PROFILES):
                raise ValueError("structure")
            for key, record in data["profiles"].items():
                self._id(key)
                if (not isinstance(record, dict) or set(record) != {"revision", "updated_at", "payload"}
                        or type(record["revision"]) is not int or not 1 <= record["revision"] < 2 ** 53
                        or type(record["updated_at"]) is not int or record["updated_at"] < 0
                        or not isinstance(record["payload"], str) or not record["payload"].startswith(PREFIX)):
                    raise ValueError("record")
            return data["profiles"]
        except (ValueError, TypeError, UnicodeError, RecursionError, KeyError):
            raise ValueError("本机 Clash 配置文件损坏，请保留文件后检查") from None

    def _decode(self, record):
        plain = decrypt_secret(record["payload"])
        try:
            if len(plain.encode("utf-8")) > self.MAX_PAYLOAD:
                raise ValueError("size")
            payload = json.loads(plain)
            if (not isinstance(payload, dict) or set(payload) != {"profile", "nodes", "counts"}
                    or not isinstance(payload["profile"], dict) or not isinstance(payload["nodes"], list)
                    or not 1 <= len(payload["nodes"]) <= 128 or not isinstance(payload["counts"], dict)):
                raise ValueError("payload")
            return payload
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise ValueError("已保存的 Clash 配置内容损坏") from None

    @staticmethod
    def _metadata(key, record, payload):
        return {"id": key, "name": payload["profile"].get("name", "G-Network"),
                "revision": record["revision"], "updated_at": record["updated_at"],
                **payload["counts"]}

    def list(self):
        with self.lock:
            result = [self._metadata(key, record, self._decode(record)) for key, record in self._load().items()]
            return sorted(result, key=lambda value: value["updated_at"], reverse=True)

    def get(self, key):
        key = self._id(key)
        with self.lock:
            record = self._load().get(key)
            if record is None:
                raise ProfileConflict("配置已删除，请刷新已保存的配置列表")
            payload = self._decode(record)
            return copy.deepcopy(payload), self._metadata(key, record, payload)

    def save(self, payload, key=None, expected_revision=None):
        plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(plain.encode("utf-8")) > self.MAX_PAYLOAD:
            raise ValueError("单份配置超过 768 KiB，请减少节点或配置内容")
        key = self._id(key) if key is not None else uuid.uuid4().hex
        with self.lock:
            records = self._load()
            previous = records.get(key)
            if expected_revision is not None or previous is not None:
                if type(expected_revision) is not int or expected_revision < 0:
                    raise ValueError("缺少有效的已保存配置版本")
                if expected_revision != (previous["revision"] if previous else 0):
                    raise ProfileConflict("此配置已在其他编辑中更新，请重新打开后保存")
            if not previous and len(records) >= self.MAX_PROFILES:
                raise ValueError("最多保存 16 份 Clash 配置，请先整理已有配置")
            revision = previous["revision"] + 1 if previous else 1
            if revision >= 2 ** 53:
                raise ValueError("配置版本已达到上限")
            record = {"revision": revision, "updated_at": int(time.time()), "payload": encrypt_secret(plain)}
            if not record["payload"].startswith(PREFIX):
                raise RuntimeError("配置加密失败，未保存")
            records[key] = record
            data = {"version": 1, "profiles": records}
            if len(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")) > self.MAX_FILE:
                raise ValueError("本机 Clash 配置文件超过大小限制")
            atomic_json_write(self.path, data)
            return self._metadata(key, record, payload)

    def delete(self, key, expected_revision):
        key = self._id(key)
        if type(expected_revision) is not int or expected_revision < 1:
            raise ValueError("缺少有效的已保存配置版本")
        with self.lock:
            records = self._load()
            record = records.get(key)
            if not record or record["revision"] != expected_revision:
                raise ProfileConflict("配置已更新或删除，请刷新列表")
            del records[key]
            atomic_json_write(self.path, {"version": 1, "profiles": records})
