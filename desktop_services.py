"""Local product APIs: portable backups, diagnostics and opt-in signed updates.

The hosting backend owns credential storage and atomic import transactions. This
module never reads its files, trusts SSH identities from a backup, executes an
installer, or contacts a release server before an explicit update request.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from flask import Blueprint, jsonify, request, send_file

from local_security import KEY_FIELDS, atomic_json_write, validate_host, validate_port, validate_user

BACKUP_FORMAT = "flnetwork-backup"
MAX_BACKUP_BYTES = 512 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
MAX_SERVERS = 200
MAX_MANIFEST_BYTES = 64 * 1024
MAX_INSTALLER_BYTES = 512 * 1024 * 1024
VERSION_PATTERN = re.compile(r"(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\.(0|[1-9]\d{0,3})\Z")
TASK_KINDS = frozenset({"tool", "node", "file", "other", "script", "node_deploy", "node_delete", "backup", "connection", "maintenance"})
TASK_STATUSES = frozenset({"running", "success", "done", "completed", "error", "failed", "cancelled"})
KDF = {"name": "scrypt", "n": 32768, "r": 8, "p": 1}
BACKUP_AAD = b"FLNetwork portable backup v1; AES-256-GCM; scrypt n=32768 r=8 p=1"
_DNS_SLOTS = threading.BoundedSemaphore(4)


class ProductError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _compact(value):
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ProductError("JSON 格式无效") from None


def _strict_json(raw, maximum):
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise ProductError("文件或请求超过允许大小")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ProductError("JSON 包含重复字段")
            result[key] = value
        return result

    def reject_constant(value):
        raise ProductError("JSON 包含无效数值")

    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                            parse_constant=reject_constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ProductError("JSON 格式无效或层级过深") from None
    stack = [(parsed, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > 12:
            raise ProductError("JSON 层级过深")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
    return parsed


def _body(allowed):
    raw = request.get_data(cache=False)
    value = _strict_json(raw, MAX_REQUEST_BYTES)
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise ProductError("请求字段不正确")
    return value


def _text(value, label, maximum, *, multiline=False, empty=True):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value):
        raise ProductError(label + "格式不正确")
    forbidden = "\x00" if multiline else "\r\n\x00"
    if any(char in value for char in forbidden) or value.startswith("dpapi:v1:"):
        raise ProductError(label + "格式不正确")
    return value


def _passphrase(value):
    value = _text(value, "备份口令", 256, empty=False)
    if len(value) < 12:
        raise ProductError("备份口令至少需要 12 个字符")
    return value.encode("utf-8")


def _validated(function, value):
    try:
        return function(value)
    except ValueError as error:
        raise ProductError(str(error)) from None


def _file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(256 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _b64(value):
    return base64.b64encode(value).decode("ascii")


def _unb64(value, expected=None, maximum=MAX_BACKUP_BYTES + 16):
    if not isinstance(value, str) or len(value) > (maximum + 2) // 3 * 4:
        raise ProductError("加密备份格式不正确")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise ProductError("加密备份格式不正确") from None
    if len(decoded) > maximum or (expected is not None and len(decoded) != expected):
        raise ProductError("加密备份格式不正确")
    return decoded


def _backup_payload(servers, settings, *, credentials, importing=False):
    if not isinstance(servers, list) or len(servers) > MAX_SERVERS:
        raise ProductError("备份最多包含 200 台服务器")
    if not isinstance(settings, dict) or set(settings) - set(KEY_FIELDS):
        raise ProductError("备份设置字段不正确")
    clean_servers = []
    identities = set()
    allowed = {"name", "host", "port", "user", "auth_type"}
    if credentials:
        allowed |= {"password", "private_key", "key_passphrase"}
    for server in servers:
        if not isinstance(server, dict) or (importing and set(server) - allowed):
            raise ProductError("服务器备份字段不正确，不允许路径、主机指纹或未知字段")
        auth = server.get("auth_type", "password")
        if auth not in {"password", "private_key", "agent"}:
            raise ProductError("服务器认证方式不正确")
        clean = {
            "name": _text(server.get("name", ""), "服务器名称", 120),
            "host": _validated(validate_host, server.get("host")),
            "port": _validated(validate_port, server.get("port", 22)),
            "user": _validated(validate_user, server.get("user", "root")),
            "auth_type": auth,
        }
        identity = (clean["host"].casefold(), clean["port"], clean["user"])
        if identity in identities:
            raise ProductError("备份包含重复服务器")
        identities.add(identity)
        if credentials:
            clean["password"] = _text(server.get("password", ""), "SSH 密码", 4096)
            clean["private_key"] = _text(server.get("private_key", ""), "SSH 私钥", 65536, multiline=True)
            clean["key_passphrase"] = _text(server.get("key_passphrase", ""), "私钥口令", 4096)
            if auth == "password":
                clean["private_key"] = clean["key_passphrase"] = ""
            elif auth == "private_key":
                clean["password"] = ""
            else:
                clean["password"] = clean["private_key"] = clean["key_passphrase"] = ""
        if importing:
            clean["credential_required"] = not credentials or (
                auth == "password" and not clean.get("password") or
                auth == "private_key" and not clean.get("private_key"))
        clean_servers.append(clean)
    clean_settings = {
        key: _text(value, "API Key", 4096)
        for key, value in settings.items()
    } if credentials else {}
    payload = {"servers": clean_servers, "settings": clean_settings}
    if len(_compact(payload)) > MAX_BACKUP_BYTES:
        raise ProductError("备份数据超过 512 KB，请减少服务器数量")
    return payload


def encode_backup(servers, settings, *, mode="metadata", passphrase=None):
    if mode not in {"metadata", "encrypted"}:
        raise ProductError("请选择不含凭据的备份或口令加密备份")
    payload = _backup_payload(servers, settings, credentials=mode == "encrypted")
    envelope = {"format": BACKUP_FORMAT, "schema": 1, "mode": mode}
    if mode == "metadata":
        envelope["data"] = payload
        return envelope
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Scrypt(salt=salt, length=32, n=KDF["n"], r=KDF["r"], p=KDF["p"]).derive(_passphrase(passphrase))
    ciphertext = AESGCM(key).encrypt(nonce, _compact(payload), BACKUP_AAD)
    return {**envelope, "kdf": {**KDF, "salt": _b64(salt)}, "cipher": "AES-256-GCM",
            "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}


def decode_backup(backup, *, passphrase=None):
    if len(_compact(backup)) > MAX_REQUEST_BYTES - 8192 or not isinstance(backup, dict):
        raise ProductError("备份格式不正确或超过允许大小")
    if backup.get("format") != BACKUP_FORMAT or type(backup.get("schema")) is not int or backup["schema"] != 1:
        raise ProductError("不支持此备份格式或版本")
    mode = backup.get("mode")
    if mode == "metadata":
        if set(backup) != {"format", "schema", "mode", "data"}:
            raise ProductError("备份字段不正确")
        payload = backup["data"]
    elif mode == "encrypted":
        if set(backup) != {"format", "schema", "mode", "kdf", "cipher", "nonce", "ciphertext"}:
            raise ProductError("加密备份字段不正确")
        kdf = backup["kdf"]
        if (not isinstance(kdf, dict) or set(kdf) != set(KDF) | {"salt"} or
                any(type(kdf.get(key)) is not type(value) or kdf.get(key) != value for key, value in KDF.items()) or
                backup["cipher"] != "AES-256-GCM"):
            raise ProductError("备份加密参数不正确")
        salt, nonce = _unb64(kdf["salt"], 16), _unb64(backup["nonce"], 12)
        ciphertext = _unb64(backup["ciphertext"])
        key = Scrypt(salt=salt, length=32, n=KDF["n"], r=KDF["r"], p=KDF["p"]).derive(_passphrase(passphrase))
        try:
            payload = _strict_json(AESGCM(key).decrypt(nonce, ciphertext, BACKUP_AAD), MAX_BACKUP_BYTES)
        except InvalidTag:
            raise ProductError("备份口令不正确，或文件已被修改；未导入任何数据") from None
    else:
        raise ProductError("备份模式不正确")
    if not isinstance(payload, dict) or set(payload) != {"servers", "settings"}:
        raise ProductError("备份内容字段不正确")
    return _backup_payload(payload["servers"], payload["settings"],
                           credentials=mode == "encrypted", importing=True), mode == "encrypted"


def _version(value):
    if not isinstance(value, str) or not VERSION_PATTERN.fullmatch(value):
        raise ProductError("版本号必须为 major.minor.patch 格式")
    return tuple(int(part) for part in value.split("."))


def _https_url(value, *, origin=None, installer=False):
    if not isinstance(value, str) or len(value) > 2048 or any(char.isspace() or ord(char) < 32 for char in value):
        raise ProductError("发布地址必须是有效 HTTPS 地址")
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname, port = parsed.hostname, parsed.port or 443
    except ValueError:
        raise ProductError("发布地址格式不正确") from None
    if (parsed.scheme != "https" or not hostname or parsed.username is not None or parsed.password is not None or
            parsed.fragment or port != 443 or not re.fullmatch(r"[A-Za-z0-9.-]+", hostname) or
            hostname.endswith(".") or "%" in parsed.netloc or "\\" in value):
        raise ProductError("发布地址必须为 HTTPS，且不能包含账号、片段或非标准端口")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None or "." not in hostname or hostname.lower().endswith((".localhost", ".local", ".internal")):
        raise ProductError("发布地址必须使用公开域名")
    _validated(validate_host, hostname)
    current = ("https", hostname.lower(), port)
    if origin is not None and current != origin:
        raise ProductError("安装包必须与更新清单使用同一个 HTTPS 来源")
    if installer and (not parsed.path.lower().endswith(".exe") or "%" in parsed.path or ".." in parsed.path.split("/")):
        raise ProductError("此版本仅接受 Windows x64 的 EXE 安装包")
    return current


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProductError("更新服务发生重定向，请检查发布配置；未下载或执行文件")


def _resolve_update_host(hostname, port, *, timeout):
    # The OS DNS resolver has no per-call timeout. Do not let it hold a UI
    # request indefinitely; bounded daemon workers perform DNS only, never
    # connect sockets after a caller has timed out.
    if timeout <= 0:
        raise ProductError("更新服务地址解析超时，请稍后重试", 502)
    if not _DNS_SLOTS.acquire(blocking=False):
        raise ProductError("更新服务地址解析繁忙，请稍后重试", 502)
    finished = threading.Event()
    result = {}

    def resolve():
        try:
            result["addresses"] = socket.getaddrinfo(hostname, port, 0, socket.SOCK_STREAM)
        except OSError:
            result["failed"] = True
        finally:
            _DNS_SLOTS.release()
            finished.set()

    worker = threading.Thread(target=resolve, name="G-Network-update-DNS", daemon=True)
    try:
        worker.start()
    except RuntimeError:
        _DNS_SLOTS.release()
        raise ProductError("无法解析更新服务地址，请稍后重试", 502) from None
    if not finished.wait(timeout):
        raise ProductError("更新服务地址解析超时，请稍后重试", 502)
    if result.get("failed") or "addresses" not in result:
        raise ProductError("无法解析更新服务地址，请检查网络或稍后重试", 502)
    return result["addresses"]


def _public_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *, deadline=None):
    """Resolve once, reject every non-public result, connect to a checked IP.

    TLS still receives the original hostname from HTTPSConnection. Connecting
    directly to the checked sockaddr prevents a second DNS lookup from rebinding
    the update request to localhost, a cloud metadata endpoint, or a private LAN.
    """
    hostname, port = address
    if deadline is None:
        deadline = time.monotonic() + (timeout if isinstance(timeout, (int, float)) else 12)
    results = _resolve_update_host(hostname, port, timeout=min(12, deadline - time.monotonic()))
    if not results or len(results) > 32:
        raise ProductError("更新服务 DNS 响应无效", 502)
    for family, _, _, _, sockaddr in results:
        try:
            address_ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        except (ValueError, IndexError, TypeError):
            raise ProductError("更新服务 DNS 响应无效", 502) from None
        if (family not in (socket.AF_INET, socket.AF_INET6) or not address_ip.is_global or
                address_ip.is_multicast or address_ip.is_unspecified):
            raise ProductError("更新服务不能指向本机、内网或保留地址", 502)
    for family, kind, protocol, _, sockaddr in results:
        sock = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProductError("更新连接超时，请稍后重试", 502)
            sock = socket.socket(family, kind, protocol)
            sock.settimeout(min(timeout, remaining) if isinstance(timeout, (int, float)) else remaining)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError:
            if sock is not None:
                sock.close()
    raise ProductError("无法连接更新服务，请检查网络或稍后重试", 502)


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = lambda address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None: _public_connection(
            address, timeout, source_address, deadline=getattr(self._context, "_flnetwork_deadline", None))


class _DeadlineSSLSocket(ssl.SSLSocket):
    def read(self, *args, **kwargs):
        # SocketIO.recv_into ultimately uses SSLSocket.read. Bound every raw
        # read, including HTTP headers and chunk framing, by one absolute
        # deadline instead of repeatedly resetting an inactivity timeout.
        deadline = getattr(self.context, "_flnetwork_deadline", None)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("update deadline")
            current = self.gettimeout()
            self.settimeout(min(current, remaining) if current is not None else remaining)
        return super().read(*args, **kwargs)


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PublicHTTPSConnection, req, context=self._context)


def _read_chunk(response, maximum, *, remaining, timeout):
    # read1 returns after one underlying socket read. read(n) can wait to fill n
    # while a slow stream keeps resetting its inactivity timeout indefinitely.
    try:
        response.fp.raw._sock.settimeout(min(timeout, remaining))
    except AttributeError:
        pass  # Test doubles and non-socket streams do not need socket deadlines.
    reader = getattr(response, "read1", response.read)
    return reader(maximum)


def fetch_https(url, *, maximum, sink=None, timeout=12, total_timeout=90):
    """Read bounded HTTPS without ambient proxies, redirects or decompression."""
    _https_url(url)
    deadline = time.monotonic() + total_timeout
    context = ssl.create_default_context()
    context.sslsocket_class = _DeadlineSSLSocket
    context._flnetwork_deadline = deadline
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        _PublicHTTPSHandler(context=context),
                                        _RejectRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": "FLNetwork-Updater/1", "Accept-Encoding": "identity"})
    output, total = bytearray(), 0
    try:
        with opener.open(req, timeout=min(timeout, total_timeout)) as response:
            if response.status != 200 or response.geturl() != url:
                raise ProductError("更新服务返回了无效响应")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > maximum):
                raise ProductError("更新文件超过允许大小或长度无效")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ProductError("更新服务不支持压缩传输，请检查发布配置")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProductError("更新下载超时，请稍后重试")
                chunk = _read_chunk(response, min(256 * 1024, maximum - total + 1),
                                    remaining=remaining, timeout=timeout)
                if time.monotonic() > deadline:
                    raise ProductError("更新下载超时，请稍后重试")
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise ProductError("更新文件超过允许大小")
                if sink is None:
                    output.extend(chunk)
                else:
                    sink.write(chunk)
            if length is not None and total != int(length):
                raise ProductError("更新文件下载不完整，请重试")
    except ProductError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError):
        raise ProductError("无法连接更新服务，请检查网络或稍后重试", 502) from None
    return bytes(output) if sink is None else total


def validate_manifest(value, manifest_url):
    origin = _https_url(manifest_url)
    allowed = {"schema", "version", "platform", "url", "sha256", "size", "release_notes", "published_at"}
    if not isinstance(value, dict) or set(value) - allowed or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ProductError("更新清单格式或版本不正确")
    _version(value.get("version"))
    if value.get("platform") != "windows-x64":
        raise ProductError("此更新不适用于 Windows x64")
    _https_url(value.get("url"), origin=origin, installer=True)
    if not isinstance(value.get("sha256"), str) or not re.fullmatch(r"[a-fA-F0-9]{64}", value["sha256"]):
        raise ProductError("更新清单缺少有效的 SHA256 校验值")
    if type(value.get("size")) is not int or not 2 <= value["size"] <= MAX_INSTALLER_BYTES:
        raise ProductError("安装包大小不正确或超过 512 MB")
    notes = _text(value.get("release_notes", ""), "版本说明", 4000, multiline=True)
    published = _text(value.get("published_at", ""), "发布时间", 40)
    return {"version": value["version"], "platform": "windows-x64", "url": value["url"],
            "sha256": value["sha256"].lower(), "size": value["size"], "release_notes": notes,
            "published_at": published}


class ProductServices:
    def __init__(self, *, data_dir, version, read_servers, read_settings, import_data,
                 task_snapshot=None, has_running_jobs=None, update_manifest_url="", verify_installer=None,
                 product=None, update_download_enabled=False):
        _version(version)
        self.directory = Path(data_dir)
        if not self.directory.is_absolute():
            raise ValueError("产品数据目录必须是绝对路径")
        self.state_path = self.directory / "product-state.json"
        self.history_path = self.directory / "task-history.json"
        self.version = version
        self.read_servers, self.read_settings, self.import_data = read_servers, read_settings, import_data
        self.task_snapshot = task_snapshot or (lambda: [])
        self.has_running_jobs = has_running_jobs or (lambda: False)
        self.manifest_url = update_manifest_url
        self.verify_installer = verify_installer
        self.update_download_enabled = update_download_enabled is True and callable(verify_installer)
        self.product = {"name": "G-Network", "version": version, "platform": "windows-x64",
                        "publisher": "尚未配置发布者", "license": "以应用内使用许可为准",
                        "privacy_notice": "服务器凭据仅在本机保存；检查更新仅在主动点击时连接发布服务；诊断不包含服务器地址、用户名或密钥。"}
        for key in {"name", "publisher", "license", "privacy_notice"}:
            if product and key in product:
                self.product[key] = _text(product[key], "产品信息", 4000, multiline=True)
        self.lock = threading.RLock()
        self.operation_lock = threading.Lock()
        self.backup_lock = threading.Lock()
        self.release = None
        self.checked_at = None
        self.receipt = None
        self.update_state = "not_checked" if update_manifest_url else "unconfigured"
        self.configuration_error = None
        if update_manifest_url:
            try:
                _https_url(update_manifest_url)
            except ProductError:
                self.configuration_error = "更新发布地址配置无效，功能尚未启用"
                self.update_state = "unconfigured"

    def _read_local(self, path, default):
        if not path.exists():
            return copy.deepcopy(default)
        try:
            with path.open("rb") as stream:
                return _strict_json(stream.read(MAX_REQUEST_BYTES + 1), MAX_REQUEST_BYTES)
        except (OSError, ProductError):
            return copy.deepcopy(default)

    def onboarding(self):
        with self.lock:
            state = self._read_local(self.state_path, {})
            completed = isinstance(state, dict) and state.get("completed") is True
            when = state.get("completed_at") if completed else None
            return {"completed": completed, "completed_at": when if type(when) in (float, int) and math.isfinite(when) else None}

    def complete_onboarding(self):
        with self.lock:
            state = {"completed": True, "completed_at": time.time()}
            atomic_json_write(self.state_path, state)
            return state

    def info(self):
        public_release = None
        if self.release is not None:
            public_release = {key: self.release[key] for key in ("version", "platform", "sha256", "size", "published_at")}
            public_release.update(notes=self.release["release_notes"], downloadable=self.update_download_enabled)
        updates = {"enabled": bool(self.manifest_url) and not self.configuration_error,
                   "state": self.update_state, "checked_at": self.checked_at,
                   "download_enabled": self.update_download_enabled, "release": public_release,
                   "installer_ready": self.receipt is not None,
                   "msg": self.configuration_error or ("更新发布服务尚未配置" if not self.manifest_url else
                          "安装包签名验证尚未配置，下载更新未启用" if not self.update_download_enabled else "更新仅在主动点击时检查")}
        return {"product": self.product.copy(), "onboarding": self.onboarding(), "updates": updates}

    def check_update(self):
        if not self.manifest_url or self.configuration_error:
            raise ProductError(self.configuration_error or "更新发布服务尚未配置，暂时无法检查更新", 409)
        if not self.operation_lock.acquire(blocking=False):
            raise ProductError("更新检查或下载正在进行，请稍后重试", 409)
        try:
            self.release = None
            self.receipt = None
            self.update_state = "checking"
            raw = fetch_https(self.manifest_url, maximum=MAX_MANIFEST_BYTES, total_timeout=30)
            release = validate_manifest(_strict_json(raw, MAX_MANIFEST_BYTES), self.manifest_url)
            self.checked_at = time.time()
            if _version(release["version"]) <= _version(self.version):
                self.update_state = "up_to_date"
                return {"available": False, "msg": "当前已是最新版本", "release": None}
            self.release = release
            self.update_state = "available"
            return {"available": True, "msg": "发现新版本，请查看版本说明后下载", "release": release.copy()}
        except ProductError:
            self.update_state = "error"
            raise
        finally:
            self.operation_lock.release()

    def download_update(self, version, sha256):
        if not self.update_download_enabled:
            raise ProductError("安装包签名验证尚未配置，下载更新未启用", 403)
        if self.has_running_jobs():
            raise ProductError("有任务正在运行，请完成后再下载更新", 409)
        if not self.operation_lock.acquire(blocking=False):
            raise ProductError("更新检查或下载正在进行，请稍后重试", 409)
        temporary = None
        try:
            release = copy.deepcopy(self.release)
            if (release is None or self.checked_at is None or time.time() - self.checked_at > 1800 or
                    version != release["version"] or sha256 != release["sha256"]):
                raise ProductError("更新信息已失效，请先重新检查更新", 409)
            validate_manifest({"schema": 1, **release}, self.manifest_url)
            self.receipt = None
            self.update_state = "downloading"
            folder = self.directory / "updates"
            folder.mkdir(parents=True, exist_ok=True)
            temporary = folder / (".download-" + uuid.uuid4().hex + ".exe")
            with temporary.open("xb") as stream:
                size = fetch_https(release["url"], maximum=release["size"], sink=stream)
                stream.flush()
                os.fsync(stream.fileno())
            digest = hashlib.sha256()
            with temporary.open("rb") as stream:
                if stream.read(2) != b"MZ":
                    raise ProductError("下载文件不是 Windows 安装程序，已拒绝保存")
                stream.seek(0)
                for chunk in iter(lambda: stream.read(256 * 1024), b""):
                    digest.update(chunk)
            if size != release["size"] or digest.hexdigest() != release["sha256"]:
                raise ProductError("安装包 SHA256 或大小校验失败，已拒绝保存")
            try:
                valid_signature = self.verify_installer(temporary) is True
            except Exception:
                valid_signature = False
            if not valid_signature:
                raise ProductError("安装包签名验证失败，已拒绝保存")
            filename = f"G-Network-{release['version']}-windows-x64-Setup.exe"
            target = folder / filename
            os.replace(temporary, target)
            temporary = None
            self.receipt = {"version": release["version"], "sha256": release["sha256"], "size": size,
                            "filename": filename}
            self.update_state = "downloaded"
            return {**self.receipt, "msg": "安装包已完成 SHA256 与发布者签名校验，请保存后自行运行；程序不会自动安装"}
        except ProductError:
            self.update_state = "error"
            raise
        except OSError:
            self.update_state = "error"
            raise ProductError("无法保存更新文件，请检查磁盘空间和文件权限", 500) from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            self.operation_lock.release()

    def installer_file(self):
        if self.receipt is None or not self.update_download_enabled:
            raise ProductError("没有经过验证的更新安装包，请先检查并下载更新", 404)
        receipt = self.receipt.copy()
        filename = f"G-Network-{receipt['version']}-windows-x64-Setup.exe"
        if receipt["filename"] != filename or not VERSION_PATTERN.fullmatch(receipt["version"]):
            raise ProductError("更新回执无效", 409)
        path = self.directory / "updates" / filename
        try:
            if path.is_symlink() or path.stat().st_size != receipt["size"]:
                raise ProductError("安装包已被修改，请重新下载", 409)
            digest = _file_sha256(path)
            if digest != receipt["sha256"] or self.verify_installer(path) is not True:
                raise ProductError("安装包已被修改或签名验证失败，请重新下载", 409)
        except ProductError:
            self.receipt = None
            raise
        except Exception:
            self.receipt = None
            raise ProductError("无法读取或验证安装包，请重新下载", 409) from None
        return path, filename

    def history(self):
        with self.lock:
            values = self._read_local(self.history_path, [])
            if not isinstance(values, list):
                return []
            return [self._task(item) for item in values[-100:] if self._task(item) is not None]

    @staticmethod
    def _task(item):
        if not isinstance(item, dict) or item.get("kind") not in TASK_KINDS or item.get("status") not in TASK_STATUSES:
            return None
        safe = {"kind": item["kind"], "status": item["status"]}
        for key in ("created_at", "finished_at"):
            value = item.get(key)
            if type(value) in (int, float) and math.isfinite(value) and value >= 0:
                safe[key] = value
        return safe

    def record_task(self, kind, status, *, created_at=None, finished_at=None):
        task = self._task({"kind": kind, "status": status, "created_at": created_at, "finished_at": finished_at})
        if task is None:
            return False
        with self.lock:
            values = self.history()
            values.append(task)
            try:
                atomic_json_write(self.history_path, values[-100:])
            except OSError:
                logging.getLogger("flnetwork.desktop").warning("任务历史暂时无法保存；操作继续正常执行")
                return False
        return True

    def diagnostics(self):
        servers = self.read_servers()
        settings = self.read_settings()
        snapshot = self.task_snapshot()
        snapshot = list(snapshot.values()) if isinstance(snapshot, dict) else snapshot
        snapshot = snapshot if isinstance(snapshot, (tuple, list)) else []
        counts = {status: sum(isinstance(item, dict) and item.get("status") == status for item in snapshot)
                  for status in sorted(TASK_STATUSES)}
        machine = platform.machine().lower()
        return {"format": "flnetwork-diagnostics", "schema": 1, "generated_at": time.time(),
                "app": {"name": "G-Network", "version": self.version, "frozen": bool(getattr(__import__("sys"), "frozen", False))},
                "runtime": {"os": "windows" if os.name == "nt" else "other", "architecture": "x64" if machine in {"amd64", "x86_64"} else "other",
                            "python_version": platform.python_version()},
                "configuration": {"server_count": len(servers) if isinstance(servers, list) else 0,
                                  "api_key_count": sum(bool(settings.get(key)) for key in KEY_FIELDS)},
                "tasks": counts, "history_count": len(self.history()),
                "updates": {"configured": bool(self.manifest_url) and not self.configuration_error,
                            "signature_verification_configured": self.update_download_enabled, "state": self.update_state},
                "privacy": "未包含服务器地址、用户名、名称、密码、私钥、API Key、文件路径或日志正文"}


def register_product_api(app, **configuration):
    services = ProductServices(**configuration)
    app.extensions["flnetwork_product"] = services
    blueprint = Blueprint("flnetwork_product", __name__)

    @blueprint.errorhandler(ProductError)
    def product_error(error):
        return jsonify(ok=False, msg=str(error)), error.status

    @blueprint.get("/api/product")
    def product_info():
        return jsonify(ok=True, **services.info())

    @blueprint.post("/api/product/onboarding")
    def onboarding():
        body = _body({"completed"})
        if body.get("completed") is not True:
            raise ProductError("请完成引导后确认")
        return jsonify(ok=True, onboarding=services.complete_onboarding())

    @blueprint.post("/api/product/update/check")
    def check_update():
        _body(set())
        checked = services.check_update()
        return jsonify(ok=True, updates=services.info()["updates"], msg=checked["msg"])

    @blueprint.post("/api/product/update/download")
    def download_update():
        body = _body({"version", "sha256"})
        return jsonify(ok=True, **services.download_update(body.get("version"), body.get("sha256")))

    @blueprint.get("/api/product/update/installer")
    def installer():
        path, filename = services.installer_file()
        return send_file(path, as_attachment=True, download_name=filename, mimetype="application/octet-stream")

    @blueprint.get("/api/product/diagnostics")
    def diagnostics():
        response = jsonify(services.diagnostics())
        response.headers["Content-Disposition"] = 'attachment; filename="G-Network-diagnostics.json"'
        return response

    @blueprint.get("/api/product/history")
    def history():
        return jsonify(ok=True, history=services.history())

    @blueprint.post("/api/product/backup/export")
    def export_backup():
        body = _body({"mode", "passphrase"})
        if not services.backup_lock.acquire(blocking=False):
            raise ProductError("备份正在处理，请稍后重试", 409)
        try:
            mode = body.get("mode", "metadata")
            backup = encode_backup(services.read_servers(), services.read_settings(),
                                   mode=mode, passphrase=body.get("passphrase"))
            return jsonify(ok=True, filename=f"G-Network-backup-{mode}.json", backup=backup,
                           msg="此备份不含凭据，导入后需补录认证信息" if mode == "metadata" else "备份已使用口令加密，请妥善保管口令")
        finally:
            services.backup_lock.release()

    def parse_import_body():
        body = _body({"backup", "passphrase", "mode", "overwrite_api_keys"})
        if body.get("mode", "merge") != "merge":
            raise ProductError("当前仅支持安全合并导入，不会删除或覆盖已有服务器")
        overwrite = body.get("overwrite_api_keys", False)
        if type(overwrite) is not bool:
            raise ProductError("覆盖 API Key 选项必须为布尔值")
        payload, encrypted = decode_backup(body.get("backup"), passphrase=body.get("passphrase"))
        return payload, encrypted, overwrite

    @blueprint.post("/api/product/backup/preview")
    def preview_backup():
        if not services.backup_lock.acquire(blocking=False):
            raise ProductError("备份正在处理，请稍后重试", 409)
        try:
            payload, encrypted, _ = parse_import_body()
            return jsonify(ok=True, server_count=len(payload["servers"]), settings_count=len(payload["settings"]),
                           encrypted=encrypted, requires_credentials=any(s["credential_required"] for s in payload["servers"]))
        finally:
            services.backup_lock.release()

    @blueprint.post("/api/product/backup/import")
    def import_backup():
        if services.has_running_jobs():
            raise ProductError("有任务正在运行，请完成后再导入备份", 409)
        if not services.backup_lock.acquire(blocking=False):
            raise ProductError("备份正在处理，请稍后重试", 409)
        try:
            payload, encrypted, overwrite = parse_import_body()
            result = services.import_data(payload["servers"], payload["settings"], overwrite_api_keys=overwrite)
            imported = result.get("imported", 0) if isinstance(result, dict) else result
            skipped = result.get("skipped", 0) if isinstance(result, dict) else 0
            if type(imported) is not int or type(skipped) is not int or min(imported, skipped) < 0:
                raise ProductError("导入存储回执无效", 500)
            services.record_task("backup", "success", finished_at=time.time())
            return jsonify(ok=True, imported=imported, skipped=skipped,
                           requires_credentials=any(s["credential_required"] for s in payload["servers"]),
                           msg="备份已安全合并；已有服务器保留原配置，导入的服务器首次连接需重新确认 SSH 主机身份")
        finally:
            services.backup_lock.release()

    app.register_blueprint(blueprint)
    return services
