"""Validation and Windows user-bound encryption for local configuration."""
import base64
import ctypes
import ipaddress
import json
import os
import re
import tempfile
from ctypes import wintypes

PREFIX = "dpapi:v1:"
KEY_FIELDS = ("deepseek_key", "openai_key", "anthropic_key")
SSH_SECRET_FIELDS = ("password", "private_key", "key_passphrase")
SSH_AUTH_TYPES = ("password", "private_key", "agent")


def validate_auth(data, previous=None, allow_missing=False):
    """Normalize one explicit authentication mode; never accept a local key path.

    Empty secrets retain a previous secret only when editing the same mode.
    Metadata import may deliberately omit credentials with allow_missing=True.
    Parsing private-key algorithms is performed by the SSH helper, without I/O.
    """
    if not isinstance(data, dict) or (previous is not None and not isinstance(previous, dict)):
        raise ValueError("SSH 认证参数无效")
    if any(name in data for name in ("private_key_path", "key_filename", "key_path", "pkey")):
        raise ValueError("请提供私钥文本，不支持本机私钥路径")
    previous = previous or {}
    mode = data.get("auth_type", previous.get("auth_type", "password"))
    if mode not in SSH_AUTH_TYPES:
        raise ValueError("SSH 认证方式必须为 password、private_key 或 agent")
    same_mode = mode == previous.get("auth_type", "password")
    result = {"auth_type": mode}
    for field in SSH_SECRET_FIELDS:
        value = data.get(field, "")
        maximum = 128 * 1024 if field == "private_key" else 4096
        try:
            valid_size = isinstance(value, str) and len(value.encode("utf-8")) <= maximum
        except UnicodeError:
            valid_size = False
        if not valid_size or "\x00" in value or value.startswith(PREFIX):
            raise ValueError("SSH 凭据格式无效")
        active = field == "password" if mode == "password" else field in ("private_key", "key_passphrase") if mode == "private_key" else False
        if not active:
            if value:
                raise ValueError("当前 SSH 认证方式不使用这些凭据，请清空后重试")
            continue
        if not value and same_mode:
            value = previous.get(field, "")
        if not isinstance(value, str):
            raise ValueError("SSH 凭据格式无效")
        result[field] = value
    required = "password" if mode == "password" else "private_key" if mode == "private_key" else None
    missing = bool(required and not result.get(required))
    if missing and not allow_missing:
        raise ValueError("请填写 SSH 密码" if mode == "password" else "请提供 SSH 私钥文本")
    if result.get("private_key") and not re.match(r"^-----BEGIN (?:OPENSSH |RSA |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n", result["private_key"].strip()):
        raise ValueError("私钥格式无效，请粘贴或上传完整私钥文本，不支持本机文件路径")
    result["credential_required"] = missing
    return result


def validate_host(value):
    if not isinstance(value, str):
        raise ValueError("服务器地址必须是 IP 或域名")
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*", value
    ):
        raise ValueError("服务器地址必须是有效 IP 或域名，不能包含空格、路径或命令")
    return value


def validate_port(value):
    if isinstance(value, bool):
        raise ValueError("端口必须为 1-65535 的整数")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("端口必须为 1-65535 的整数") from None
    if str(port) != str(value).strip() or not 1 <= port <= 65535:
        raise ValueError("端口必须为 1-65535 的整数")
    return port


def validate_user(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?", value.strip()):
        raise ValueError("SSH 用户名格式不正确")
    return value.strip()


class _Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi(data, decrypt=False):
    if os.name != "nt":
        raise RuntimeError("当前凭据存储使用 Windows DPAPI，请在 Windows 用户账户下运行")
    source_buffer = ctypes.create_string_buffer(data)
    source = _Blob(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = _Blob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        fn = crypt32.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
        ok = fn(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target))
    else:
        fn = crypt32.CryptProtectData
        fn.argtypes = [ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
        ok = fn(ctypes.byref(source), "Server Manager credential", None, None, None, 1, ctypes.byref(target))
    fn.restype = wintypes.BOOL
    if not ok:
        raise RuntimeError("凭据加密或解密失败；请使用原 Windows 用户账户，不要直接复制加密配置到其他设备")
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel32.LocalFree(target.data)


def encrypt_secret(value):
    if not value or value.startswith(PREFIX):
        return value
    return PREFIX + base64.b64encode(_dpapi(value.encode("utf-8"))).decode("ascii")


def decrypt_secret(value):
    if not value or not value.startswith(PREFIX):
        return value
    try:
        return _dpapi(base64.b64decode(value[len(PREFIX):], validate=True), decrypt=True).decode("utf-8")
    except (ValueError, UnicodeError):
        raise RuntimeError("加密凭据格式损坏，请从安全备份恢复") from None


def transform_secrets(data, filename, encrypt=False):
    fn = encrypt_secret if encrypt else decrypt_secret
    if os.path.basename(filename) == "servers.json":
        return [{**server, **{field: fn(server[field]) for field in SSH_SECRET_FIELDS if field in server}} for server in data]
    if os.path.basename(filename) == "settings.json":
        return {key: fn(value) if key in KEY_FIELDS else value for key, value in data.items()}
    return data


def atomic_json_write(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".config-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
