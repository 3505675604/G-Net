"""Checked SSH commands and transactional Xray configuration updates.

All remote commands use existing Linux utilities; this module adds no package
dependencies. The lock coordinates callers of this module. Administrators or
other tools which ignore the lock can still modify the remote file.
"""
import base64
from collections import deque
import contextlib
import codecs
import hashlib
import json
import re
import shlex
import threading
import time

CONFIG_PATH = "/usr/local/etc/xray/config.json"
_MISSING = "__SERVER_MANAGER_XRAY_CONFIG_MISSING__"
_locks = {}
_locks_guard = threading.Lock()


@contextlib.contextmanager
def server_lock(host, port=22):
    """Serialize read/modify/apply for one SSH endpoint in this process."""
    key = (str(host).strip().strip("[]").lower(), int(port))
    with _locks_guard:
        lock = _locks.setdefault(key, threading.RLock())
    with lock:
        yield


def run_checked(ssh, cmd, timeout=180, on_output=None):
    """Drain both channel streams before collecting the command exit status."""
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    channel = stdout.channel
    chunks, errors = deque(), deque()
    sizes = {"stdout": 0, "stderr": 0}
    total_bytes = 0
    out_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    err_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    deadline = time.monotonic() + timeout

    def retain(parts, chunk, stream):
        nonlocal total_bytes
        total_bytes += len(chunk)
        if on_output is None and total_bytes > 16 * 1024 * 1024:
            raise RuntimeError("远端命令输出超过 16 MiB，已关闭命令通道；请缩小读取范围")
        parts.append(chunk)
        sizes[stream] += len(chunk)
        if on_output is not None:
            # Streaming jobs already consume their output in the callback. Keep
            # bounded tails for return values and failure diagnostics only.
            while sizes[stream] > 512 * 1024:
                extra = sizes[stream] - 512 * 1024
                first = parts.popleft()
                if len(first) > extra:
                    parts.appendleft(first[extra:])
                    sizes[stream] -= extra
                else:
                    sizes[stream] -= len(first)
    try:
        stdin.close()
        while True:
            progressed = False
            # Alternate streams to avoid stderr filling the SSH channel window.
            if channel.recv_ready():
                chunk = channel.recv(65536)
                retain(chunks, chunk, "stdout")
                if on_output is not None:
                    on_output(out_decoder.decode(chunk))
                progressed = True
            if channel.recv_stderr_ready():
                chunk = channel.recv_stderr(65536)
                retain(errors, chunk, "stderr")
                if on_output is not None:
                    on_output(err_decoder.decode(chunk))
                progressed = True
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                status = channel.recv_exit_status()
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"远端命令超时（{timeout} 秒）")
            if not progressed:
                time.sleep(0.01)
        out = b"".join(chunks).decode("utf-8", errors="replace")
        err = b"".join(errors).decode("utf-8", errors="replace")
        if on_output is not None:
            for decoder in (out_decoder, err_decoder):
                tail = decoder.decode(b"", final=True)
                if tail:
                    on_output(tail)
        if status != 0:
            detail = (out + ("\n" if out and err else "") + err).strip()[-6000:]
            raise RuntimeError(f"远端命令失败（退出码 {status}）：{detail or '无错误输出'}")
        return out
    finally:
        channel.close()


class _ConfigSnapshot(dict):
    """Normal dict with a fingerprint of the exact bytes read from the server."""
    def __init__(self, value, raw=None):
        super().__init__(value)
        self.exists = raw is not None
        self.digest = hashlib.sha256(raw.encode("utf-8")).hexdigest() if raw is not None else None


def read_xray_config(ssh):
    path = shlex.quote(CONFIG_PATH)
    raw = run_checked(ssh, f"if [ -e {path} ]; then cat -- {path}; else printf %s {shlex.quote(_MISSING)}; fi")
    if raw == _MISSING:
        return _ConfigSnapshot({})
    try:
        cfg = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("远端 Xray 配置不是合法 JSON，已中止（未做改动）") from exc
    if not isinstance(cfg, dict):
        raise RuntimeError("远端 Xray 配置必须是 JSON 对象，已中止（未做改动）")
    for key in ("inbounds", "outbounds"):
        if key in cfg and (not isinstance(cfg[key], list) or any(not isinstance(x, dict) for x in cfg[key])):
            raise RuntimeError(f"远端 Xray 配置 {key} 格式无效，已中止（未做改动）")
    return _ConfigSnapshot(cfg, raw)


def listening_ports(ssh, udp=False):
    """Return exact IPv4/IPv6 TCP or UDP local listening port numbers."""
    out = run_checked(ssh, "ss -H -lnu" if udp else "ss -H -lnt")
    ports = set()
    for line in out.splitlines():
        columns = line.split()
        if len(columns) >= 4:
            match = re.search(r":(\d+)$", columns[3])
            if match and 0 < int(match.group(1)) <= 65535:
                ports.add(int(match.group(1)))
    return ports


def _required_ports(cfg):
    tcp, udp = set(), set()
    for ib in cfg.get("inbounds", []):
        port = ib.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            continue
        if ib.get("protocol") in ("shadowsocks", "dokodemo-door"):
            networks = str((ib.get("settings") or {}).get("network", "tcp")).split(",")
        else:
            network = (ib.get("streamSettings") or {}).get("network", "tcp")
            networks = ["udp" if network in ("kcp", "quic") else "tcp"]
        if "tcp" in networks:
            tcp.add(port)
        if "udp" in networks:
            udp.add(port)
    return tcp, udp


def apply_xray_config(ssh, cfg, expected=None):
    """Validate, replace atomically, restart and check listeners; roll back on failure.

    Pass the original result of read_xray_config as expected, and modify a copy.
    A plain expected dict is also accepted: it is compared to a fresh read, then
    that read's exact byte fingerprint is checked inside the remote flock.
    """
    if not isinstance(cfg, dict):
        raise ValueError("Xray 配置必须是字典")
    if expected is not None and not isinstance(expected, _ConfigSnapshot):
        current = read_xray_config(ssh)
        if current != expected:
            raise RuntimeError("远端 Xray 配置已被其他任务修改，请重新读取后重试")
        expected = current
    if expected is None:
        expected_check = ":"
    elif expected.exists:
        expected_check = f'''[ -f "$config" ] && [ "$(sha256sum -- "$config" | cut -d' ' -f1)" = {shlex.quote(expected.digest)} ] || {{ echo '配置并发冲突：请重新读取后重试' >&2; exit 73; }}'''
    else:
        expected_check = '''[ ! -e "$config" ] || { echo '配置并发冲突：配置已创建，请重新读取后重试' >&2; exit 73; }'''
    payload = base64.b64encode(json.dumps(cfg, ensure_ascii=False, allow_nan=False).encode("utf-8")).decode("ascii")
    tcp, udp = _required_ports(cfg)
    tcp_words = " ".join(map(str, sorted(tcp)))
    udp_words = " ".join(map(str, sorted(udp)))
    script = f'''set -Eeuo pipefail
umask 077
dir=/usr/local/etc/xray
mkdir -p "$dir"
command -v flock >/dev/null || {{ echo '缺少 flock，已中止配置更新' >&2; exit 72; }}
exec 9>"$dir/.server-manager.lock"
flock -x -w 120 9
config="$dir/config.json"
{expected_check}
candidate=''
backup=''
switched=0
had_config=0
prior_state="$(systemctl is-active xray 2>/dev/null || true)"
cleanup() {{
  code=$?
  trap - EXIT HUP INT TERM
  if [ "$code" -ne 0 ] && [ "$switched" -eq 1 ]; then
    rollback_ok=1
    if [ "$had_config" -eq 1 ]; then
      if cp -p -- "$backup" "$candidate" && mv -f -- "$candidate" "$config"; then :; else rollback_ok=0; fi
    else
      rm -f -- "$config" || rollback_ok=0
    fi
    if [ "$prior_state" = active ]; then
      systemctl restart xray || rollback_ok=0
      state="$(systemctl is-active xray 2>/dev/null || true)"
      [ "$state" = active ] || rollback_ok=0
    else
      systemctl stop xray || rollback_ok=0
      state="$(systemctl is-active xray 2>/dev/null || true)"
      [ "$state" != active ] || rollback_ok=0
    fi
    if [ "$rollback_ok" -eq 1 ]; then echo '配置更新失败，原配置和运行状态已恢复' >&2;
    else echo "自动回滚未完整成功，请人工检查；备份：$backup" >&2; fi
  fi
  [ -z "$candidate" ] || rm -f -- "$candidate" || true
  if [ "$switched" -eq 0 ] && [ -n "$backup" ]; then rm -f -- "$backup" || true; fi
  exit "$code"
}}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
candidate="$(mktemp "$dir/config.json.new.XXXXXXXX")"
if [ -e "$config" ]; then
  [ -f "$config" ] || {{ echo 'config.json 不是普通文件' >&2; exit 74; }}
  had_config=1
  backup="$(mktemp "$dir/config.json.bak.XXXXXXXX")"
  cp -p -- "$config" "$backup"
  cmp -s -- "$config" "$backup" || {{ echo '配置备份验证失败，未应用新配置' >&2; exit 74; }}
  cp -p -- "$backup" "$candidate"
else
  service_user="$(systemctl show -p User --value xray)"
  if [ -n "$service_user" ] && [ "$service_user" != root ]; then
    id "$service_user" >/dev/null || {{ echo 'Xray 服务用户不存在，已中止' >&2; exit 74; }}
    chown -- "$service_user" "$candidate"
  fi
  chmod 600 -- "$candidate"
fi
printf %s {shlex.quote(payload)} | base64 -d > "$candidate"
/usr/local/bin/xray run -test -format json -c "$candidate"
mv -f -- "$candidate" "$config"
switched=1
systemctl restart xray
healthy=0
healthy_streak=0
for attempt in {{1..10}}; do
  healthy=0
  state="$(systemctl is-active xray 2>/dev/null || true)"
  if [ "$state" = active ]; then
    healthy=1
    tcp_ports="$(ss -H -lnt | awk '{{n=split($4,a,":"); if (a[n] ~ /^[0-9]+$/) print a[n]}}')"
    udp_ports="$(ss -H -lnu | awk '{{n=split($4,a,":"); if (a[n] ~ /^[0-9]+$/) print a[n]}}')"
    for p in {tcp_words}; do printf '%s\\n' "$tcp_ports" | grep -Fxq -- "$p" || healthy=0; done
    for p in {udp_words}; do printf '%s\\n' "$udp_ports" | grep -Fxq -- "$p" || healthy=0; done
  fi
  if [ "$healthy" -eq 1 ]; then healthy_streak=$((healthy_streak + 1)); else healthy_streak=0; fi
  [ "$healthy_streak" -lt 2 ] || break
  sleep 1
done
[ "$healthy_streak" -ge 2 ] || {{ echo 'Xray 未稳定处于 active 或所需 TCP/UDP 端口未监听' >&2; exit 75; }}
echo 'Xray active，配置和监听检查通过'
'''
    run_checked(ssh, "bash -c " + shlex.quote(script), timeout=300)
