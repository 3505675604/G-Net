"""Verify update installers against Windows trust and bundled publisher pins."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess


def verify_windows_installer(path: Path, allowed_thumbprints: list[str], *, require_timestamp=True) -> bool:
    if os.name != "nt":
        raise ValueError("此更新安装包仅支持 Windows x64")
    if (not isinstance(allowed_thumbprints, (list, tuple)) or not 1 <= len(allowed_thumbprints) <= 8 or
            any(not isinstance(pin, str) or not re.fullmatch(r"[0-9A-Fa-f]{40}", pin) for pin in allowed_thumbprints)):
        raise ValueError("发行者尚未配置更新签名，暂时无法下载更新；请使用已确认来源的安装包")
    pins = {pin.upper() for pin in allowed_thumbprints}
    try:
        path = Path(path)
        valid_file = not path.is_symlink() and path.is_file() and path.suffix.lower() == ".exe"
        absolute_path = str(path.resolve(strict=True))
    except (TypeError, ValueError, OSError):
        raise ValueError("更新安装包不存在或格式无效") from None
    if not valid_file:
        raise ValueError("更新安装包不存在或格式无效")
    # The path is passed as environment data, never interpolated as PowerShell
    # code. Use Windows' own Authenticode validation, including chain validity.
    command = (
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
        "$s=Get-AuthenticodeSignature -LiteralPath $env:FLNETWORK_VERIFY_FILE; "
        "[ordered]@{status=[string]$s.Status; "
        "thumbprint=$(if($s.SignerCertificate){$s.SignerCertificate.Thumbprint}else{''}); "
        "timestamped=[bool]$s.TimeStamperCertificate} "
        "| ConvertTo-Json -Compress"
    )
    env = os.environ.copy()
    env["FLNETWORK_VERIFY_FILE"] = absolute_path
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    try:
        result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", command],
                                capture_output=True, timeout=30, env=env,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
        if result.returncode != 0 or len(result.stdout) > 16384:
            raise ValueError("无法验证更新安装包签名")
        info = json.loads(result.stdout.decode("utf-8-sig"))
    except (OSError, subprocess.TimeoutExpired, UnicodeError, json.JSONDecodeError):
        raise ValueError("无法验证更新安装包签名，请稍后重试") from None
    if (not isinstance(info, dict) or set(info) != {"status", "thumbprint", "timestamped"} or
            not isinstance(info.get("status"), str) or not isinstance(info.get("thumbprint"), str) or
            type(info.get("timestamped")) is not bool):
        raise ValueError("无法验证更新安装包签名，验证结果格式无效")
    if (info["status"] != "Valid" or info["thumbprint"].upper() not in pins or
            (require_timestamp and not info["timestamped"])):
        raise ValueError("更新安装包签名无效或发布者与应用不符，已阻止使用")
    return True
