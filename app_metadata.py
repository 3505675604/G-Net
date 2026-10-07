"""Shared desktop identity and trusted, bundled release settings."""
from __future__ import annotations

import json
from pathlib import Path
import re
import urllib.parse

APP_NAME = "G-Network · 服务器管家"
APP_VERSION = "0.4.0"
PRODUCT_NAME = "G-Network"
PLATFORM = "windows-x64"


def _https_url(value: object, field: str) -> str:
    if value == "":
        return ""
    if (not isinstance(value, str) or len(value) > 2048 or
            any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value):
        raise ValueError(f"发行配置 {field} 无效")
    try:
        parsed = urllib.parse.urlsplit(value)
        hostname, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError(f"发行配置 {field} 无效") from None
    if (parsed.scheme != "https" or not hostname or parsed.username is not None or parsed.password is not None
            or parsed.fragment or port not in (None, 443) or "%" in parsed.netloc or hostname.endswith(".") or
            not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+", hostname) or
            hostname.lower().endswith((".localhost", ".local", ".internal")) or
            re.fullmatch(r"[0-9.]+", hostname)):
        raise ValueError(f"发行配置 {field} 必须是 HTTPS 地址")
    return value


def load_release_config(root: Path) -> dict:
    """Only install-time resources can choose the update source and signer pins.

    Never use settings.json, backup contents or HTTP parameters as release
    configuration: these are user-controlled and cannot grant updater trust.
    """
    filename = root / "packaging" / "release-config.json"
    if filename.stat().st_size > 16384:
        raise ValueError("发行配置过大")
    data = json.loads(filename.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("发行配置必须是 JSON 对象")
    result = {}
    for key in ("publisher", "support_email"):
        value = data.get(key, "")
        if not isinstance(value, str) or len(value) > 200 or any(c in value for c in "\r\n\x00"):
            raise ValueError(f"发行配置 {key} 无效")
        result[key] = value
    for key in ("website_url", "support_url", "update_manifest_url"):
        result[key] = _https_url(data.get(key, ""), key)
    pins = data.get("signer_thumbprints", [])
    if not isinstance(pins, list) or len(pins) > 8 or any(
            not isinstance(p, str) or not re.fullmatch(r"[0-9A-Fa-f]{40}", p) for p in pins):
        raise ValueError("签名证书指纹格式无效")
    result["signer_thumbprints"] = [p.upper() for p in pins]
    channel = data.get("channel", "candidate")
    if channel not in ("candidate", "stable"):
        raise ValueError("发行通道无效")
    result["channel"] = channel
    result["privacy_version"] = "2026-10-04"
    return result
