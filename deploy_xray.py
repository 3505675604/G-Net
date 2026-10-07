# -*- coding: utf-8 -*-
"""Incrementally deploy VLESS-Reality with BBR. Env: SSH_HOST, SSHPASS,
SSH_USER (root), SSH_PORT (22), XRAY_PORTS (443,8443,2087), XRAY_SNI.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys
import uuid

from remote_ops import apply_xray_config, listening_ports, read_xray_config, server_lock
from local_security import validate_port
from script_common import (BBR_TUNING, SOCKOPT, cli, elevated_ssh, run,
                           ssh_connection, ssh_options, write_json)

HERE = Path(__file__).resolve().parent


def parse_ports(value):
    try:
        parts = value.split(",")
        ports = [validate_port(p.strip()) for p in parts if p.strip()]
        if len(ports) != len(parts) or not ports or any(not 1 <= p <= 65535 for p in ports):
            raise ValueError
        if len(ports) != len(set(ports)):
            raise ValueError
    except (AttributeError, TypeError, ValueError):
        raise ValueError("XRAY_PORTS 必须为不重复的 1-65535 整数，用逗号分隔") from None
    return ports


def validate_sni(sni):
    if len(sni) > 253 or not re.fullmatch(
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
            r"[A-Za-z]{2,63}", sni):
        raise ValueError("XRAY_SNI 必须为有效域名")
    return sni


def reality_keys(ssh, cfg):
    private = next(((ib.get("streamSettings") or {}).get("realitySettings", {}).get("privateKey")
                    for ib in cfg.get("inbounds", [])
                    if (ib.get("streamSettings") or {}).get("realitySettings", {}).get("privateKey")), None)
    cmd = "/usr/local/bin/xray x25519" + (" -i " + shlex.quote(private) if private else "")
    from remote_ops import run_checked
    out = run_checked(ssh, cmd)
    m1 = re.search(r"Private\s*[Kk]ey:\s*(\S+)", out)
    m2 = re.search(r"(?:Public\s*[Kk]ey|Password)(?:\s*\(PublicKey\))?:\s*(\S+)", out)
    if not m2 or (not private and not m1):
        raise RuntimeError("无法解析 Xray Reality 密钥输出，未修改配置")
    return private or m1.group(1), m2.group(1)


def append_inbounds(live, ports, sni, identity, private, short_id):
    cfg = deepcopy(live)
    existing = cfg.setdefault("inbounds", [])
    if not isinstance(existing, list):
        raise ValueError("现有 Xray inbounds 不是数组，已中止")
    used = {ib.get("port") for ib in existing if isinstance(ib, dict)}
    tags = {ib.get("tag") for ib in existing if isinstance(ib, dict)}
    for port in ports:
        tag = f"vless-reality-{port}"
        if port in used or str(port) in used or tag in tags:
            raise ValueError(f"端口或入站标签 {port} 已存在，已中止（不覆盖旧节点）")
        existing.append({"tag": tag, "listen": "0.0.0.0", "port": port, "protocol": "vless",
                         "settings": {"clients": [{"id": identity, "flow": "xtls-rprx-vision"}],
                                      "decryption": "none"},
                         "streamSettings": {"network": "tcp", "security": "reality",
                                            "sockopt": deepcopy(SOCKOPT),
                                            "realitySettings": {"show": False, "dest": f"{sni}:443",
                                                                "xver": 0, "serverNames": [sni],
                                                                "privateKey": private, "shortIds": [short_id]}},
                         "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}})
    if not cfg.get("outbounds"):
        cfg["outbounds"] = [{"protocol": "freedom", "tag": "direct",
                             "settings": {"domainStrategy": "UseIP"},
                             "streamSettings": {"sockopt": deepcopy(SOCKOPT)}}]
    return cfg


def main(env=None):
    env = os.environ if env is None else env
    options = ssh_options(env)
    ports = parse_ports(env.get("XRAY_PORTS", "443,8443,2087"))
    sni = validate_sni(env.get("XRAY_SNI", "www.amazon.com").strip())
    with server_lock(options.host, options.port), ssh_connection(options) as raw_ssh:
        ssh = elevated_ssh(raw_ssh)
        live = read_xray_config(ssh)
        occupied = listening_ports(ssh) | listening_ports(ssh, udp=True)
        conflicts = set(ports) & occupied
        if conflicts:
            raise ValueError(f"端口已被占用：{sorted(conflicts)}")
        append_inbounds(live, ports, sni, "pending", "pending", "pending")
        run(ssh, "cat /etc/os-release; uname -m; nproc; free -m", label="检查服务器环境")
        run(ssh, """if command -v apt-get >/dev/null; then
apt-get update -y
apt-get install -y curl wget openssl
elif command -v dnf >/dev/null; then dnf install -y curl wget openssl
elif command -v yum >/dev/null; then yum install -y curl wget openssl
else echo '不支持的包管理器' >&2; exit 1; fi""", timeout=600, label="安装依赖")
        run(ssh, """if [ ! -x /usr/local/bin/xray ]; then
task_setup=$(mktemp)
trap 'rm -f -- "$task_setup"' EXIT
curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o "$task_setup"
bash "$task_setup" install
fi
/usr/local/bin/xray version""", timeout=600, label="检查或安装 Xray")
        live = read_xray_config(ssh)
        private, public = reality_keys(ssh, live)
        identity, short_id = str(uuid.uuid4()), secrets.token_hex(4)
        cfg = append_inbounds(live, ports, sni, identity, private, short_id)
        run(ssh, BBR_TUNING, label="启用 BBR / TCP 调优")
        pspace = " ".join(str(p) for p in ports)
        run(ssh, f"""if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
for p in {pspace}; do ufw allow "$p/tcp"; done
elif command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
for p in {pspace}; do firewall-cmd --permanent --add-port="$p/tcp"; done
firewall-cmd --reload
else echo '未发现启用的本机防火墙，请确认云平台安全组放行所需端口'; fi""", label="检查防火墙")
        apply_xray_config(ssh, cfg, expected=live)
        tag = re.sub(r"[^A-Za-z0-9_-]", "_", options.host)
        result = {"host": options.host, "uuid": identity, "publicKey": public,
                  "shortId": short_id, "sni": sni, "ports": ports}
        write_json(HERE / f"xray_config_{tag}.json", cfg)
        write_json(HERE / f"xray_result_{tag}.json", result)
        print("\n>>> RESULT " + json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    sys.exit(cli(main))
