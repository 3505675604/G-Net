# -*- coding: utf-8 -*-
"""Tune live Xray without rebuilding nodes or reading result files.
Env: SSH_HOST, SSHPASS, SSH_USER (root), SSH_PORT (22).
"""
from copy import deepcopy
import os
import sys

from remote_ops import apply_xray_config, read_xray_config, server_lock
from script_common import (BBR_TUNING, SOCKOPT, cli, elevated_ssh, run,
                           ssh_connection, ssh_options)


def tuned_config(live):
    if not live or getattr(live, "exists", True) is False:
        raise ValueError("远端 Xray 配置缺失或为空；请先部署节点")
    cfg = deepcopy(live)
    for field in ("inbounds", "outbounds"):
        endpoints = cfg.get(field, [])
        if not isinstance(endpoints, list):
            raise ValueError(f"现有 Xray {field} 不是数组，已中止")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                raise ValueError(f"现有 Xray {field} 包含无效对象，已中止")
            if endpoint.get("protocol") in ("blackhole", "dns"):
                continue
            stream = endpoint.setdefault("streamSettings", {})
            if not isinstance(stream, dict):
                raise ValueError("现有 streamSettings 不是对象，已中止")
            sockopt = stream.setdefault("sockopt", {})
            if not isinstance(sockopt, dict):
                raise ValueError("现有 sockopt 不是对象，已中止")
            sockopt.update(SOCKOPT)
    return cfg


def main(env=None):
    options = ssh_options(os.environ if env is None else env)
    with server_lock(options.host, options.port), ssh_connection(options) as raw_ssh:
        ssh = elevated_ssh(raw_ssh)
        live = read_xray_config(ssh)
        cfg = tuned_config(live)
        run(ssh, "sysctl net.ipv4.tcp_congestion_control net.ipv4.tcp_available_congestion_control net.core.default_qdisc",
            label="检查现有 TCP 配置")
        run(ssh, BBR_TUNING, label="应用 BBR / TCP 调优")
        apply_xray_config(ssh, cfg, expected=live)
        try:
            run(ssh, "curl -o /dev/null -fsSL --max-time 25 -w 'server download: %{speed_download} B/s\\n' https://speed.hetzner.de/100MB.bin",
                timeout=40, label="可选带宽检查")
        except Exception:
            print("带宽测试未完成；Xray 配置与监听检查已通过", flush=True)
    print("\n>>> tuning done", flush=True)


if __name__ == "__main__":
    sys.exit(cli(main))
