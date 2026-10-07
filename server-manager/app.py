# -*- coding: utf-8 -*-
"""服务器管家 —— Windows 本地 Web 面板，图形化管理多台 Linux 服务器。"""
import sys, os
# pythonw（无控制台）下 stdout/stderr 可能是 None，werkzeug 日志/print 会因此卡死或报错，兜底到 devnull
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8", errors="replace")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8", errors="replace")
import json, shlex, io, socket, subprocess, threading, uuid, time, copy
import atexit, contextlib, tempfile, codecs, stat, weakref, logging
import base64, re, secrets, urllib.parse
from flask import Flask, request, jsonify, render_template, send_file, Response
from flask_sock import Sock
import paramiko
from werkzeug.exceptions import HTTPException

BASE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
from local_security import KEY_FIELDS, SSH_SECRET_FIELDS, atomic_json_write, transform_secrets, validate_auth, validate_host, validate_port, validate_user
from script_common import (HostIdentityError, connect_ssh, host_identity,
                           microsoft_edge_repository_script, parse_private_key)
from remote_ops import run_checked, read_xray_config, apply_xray_config, listening_ports, server_lock
from clash_export import (ExportCache, WorkspaceSnapshots, EXPORT_PATH_PATTERN, LOCAL_NOTICE, UnsupportedExport,
                          SourceCapabilityChanged,
                          compatibility, proxy_from_inbound, yaml_configuration)
from clash_workspace import build_workspace_configuration
from node_routing import stable_routing_key, build_node_routing
from node_routing_store import NodeRoutingStore, RoutingConflict
from clash_studio import register_clash_studio
# Desktop builds keep bundled resources read-only. The launcher explicitly
# supplies an absolute per-user directory before importing this module. A new
# desktop profile starts empty; source-tree configurations are never copied.
_configured_data_dir = os.environ.get("FL_NETWORK_DATA_DIR")
DESKTOP_DATA = _configured_data_dir is not None
if DESKTOP_DATA:
    if not _configured_data_dir or not os.path.isabs(_configured_data_dir):
        raise ValueError("FL_NETWORK_DATA_DIR 必须是用户数据目录的绝对路径")
    DATA_DIR = os.path.realpath(_configured_data_dir)
    os.makedirs(DATA_DIR, exist_ok=True)
else:
    DATA_DIR = BASE
SERVERS_FILE = os.path.join(DATA_DIR, "servers.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
KNOWN_HOSTS_FILE = os.path.join(DATA_DIR if DESKTOP_DATA else PROJECT_ROOT, "known_hosts")

app = Flask(__name__)
sock = Sock(app)
jobs = {}
DATA_LOCK = threading.RLock()
NODE_ROUTING_FILE = os.path.join(DATA_DIR, "node-routing.json")
NODE_ROUTING_STORE = NodeRoutingStore(NODE_ROUTING_FILE, DATA_LOCK)
CSRF_TOKEN = secrets.token_urlsafe(32)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
app.config["LOCAL_ACCESS_PORT"] = 8620
JOB_LOCK = threading.RLock()
RESOURCE_LOCK = threading.RLock()
_OPEN_RESOURCES = weakref.WeakSet()
_SHUTTING_DOWN = False
_ACCEPTING_JOBS = True
CLASH_EXPORTS = ExportCache(capacity=512)
CLASH_SNAPSHOTS = WorkspaceSnapshots()
register_clash_studio(sys.modules[__name__])


class _ClashCapabilityLogFilter(logging.Filter):
    """Do not put bearer URLs in source-launcher's Werkzeug access logs."""
    def filter(self, record):
        def redact(value):
            if isinstance(value, str):
                return re.sub(EXPORT_PATH_PATTERN, "/api/clash-export/[redacted].yaml", value)
            return value
        record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(redact(value) for value in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: redact(value) for key, value in record.args.items()}
        return True


logging.getLogger("werkzeug").addFilter(_ClashCapabilityLogFilter())


def configure_local_access(port):
    """Allow one loopback port selected by the desktop launcher's bound socket.

    Call before serving requests. No wildcard hosts, origins, or port ranges are
    accepted; the ordinary browser launcher continues to use port 8620.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("本地面板端口必须为 1-65535 的整数")
    app.config["LOCAL_ACCESS_PORT"] = port


def _track_resource(resource):
    with RESOURCE_LOCK:
        if _SHUTTING_DOWN:
            resource.close()
            raise RuntimeError("应用正在退出，无法创建新的连接或下载")
        _OPEN_RESOURCES.add(resource)
    return resource


def new_job(output, **metadata):
    with JOB_LOCK:
        if not _ACCEPTING_JOBS:
            raise ValueError("应用正在退出，无法启动新的任务")
        if sum(j.get("status") == "running" for j in jobs.values()) >= 16:
            raise ValueError("运行中的任务过多，请等待现有任务完成")
        finished = [key for key, value in jobs.items() if value.get("status") != "running"]
        for key in finished[:-99]:
            jobs.pop(key, None)
        jid = uuid.uuid4().hex
        jobs[jid] = {"status": "running", "output": output, "created_at": time.time(), **metadata}
        return jid


def prepare_shutdown():
    """Atomically refuse closing a busy app, or stop accepting new work.

    Use in the desktop window's closing callback. A rejected close leaves the
    app usable; an accepted close seals the job queue before the window exits.
    Resource cleanup remains the separate shutdown_resources() step.
    """
    global _ACCEPTING_JOBS
    with JOB_LOCK:
        if any(job.get("status") == "running" for job in jobs.values()):
            return False
        _ACCEPTING_JOBS = False
        return True


def append_job_output(jid, chunk):
    with JOB_LOCK:
        jobs[jid]["output"] = (jobs[jid]["output"] + chunk)[-1024 * 1024:]


@app.before_request
def local_access_guard():
    # Restrict both Host and Origin to prevent DNS rebinding and cross-site WebSockets.
    port = app.config["LOCAL_ACCESS_PORT"]
    if request.host not in {f"127.0.0.1:{port}", f"localhost:{port}"}:
        return jsonify(ok=False, msg="仅允许从本机面板地址访问"), 403
    origin = request.headers.get("Origin")
    if origin and origin not in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}:
        return jsonify(ok=False, msg="拒绝跨站访问"), 403
    # Native Clash clients cannot add our panel header. Only this exact GET
    # capability route has a CSRF exception; Host and Origin checks above apply.
    clash_download = request.method == "GET" and re.fullmatch(EXPORT_PATH_PATTERN, request.path)
    if request.path.startswith(("/api/", "/ws/")) and request.path != "/api/health" and not clash_download:
        token = request.args.get("token", "") if request.path.startswith("/ws/") else request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token, CSRF_TOKEN):
            return jsonify(ok=False, msg="面板会话已失效，请刷新页面"), 403


@app.after_request
def response_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(Exception)
def api_error(error):
    if isinstance(error, HostIdentityError):
        return jsonify(ok=False, code=error.code, msg=str(error)), 409
    if isinstance(error, HTTPException):
        code, msg = error.code, error.description
    elif isinstance(error, (ValueError, KeyError, TypeError)):
        code, msg = 400, "请求参数无效：" + str(error)
    else:
        code, msg = 500, "操作失败：" + str(error)
    return jsonify(ok=False, msg=msg), code


def json_body():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValueError("请求体必须是 JSON 对象")
    return body

# ---------- 数据 ----------
def load_json(p, default):
    with DATA_LOCK:
        if not os.path.exists(p):
            return copy.deepcopy(default)
        with open(p, encoding="utf-8") as stream:
            stored = json.load(stream)
        data = transform_secrets(stored, p)
        # Legacy cleartext is migrated only on use, after successful encryption.
        protected = transform_secrets(stored, p, encrypt=True)
        if protected != stored:
            atomic_json_write(p, protected)
        return data

def save_json(p, data):
    with DATA_LOCK:
        atomic_json_write(p, transform_secrets(data, p, encrypt=True))

def get_server(sid):
    for s in load_json(SERVERS_FILE, []):
        if s["id"] == sid:
            return s
    return None


def auto_update_ssh_identity():
    value = load_json(SETTINGS_FILE, {}).get("ssh_auto_update_host_key", True)
    if not isinstance(value, bool):
        raise ValueError("SSH 自动更新身份设置必须是布尔值")
    return value

def connect(s, timeout=15):
    if not s:
        raise ValueError("服务器不存在，请重新选择")
    with RESOURCE_LOCK:
        if _SHUTTING_DOWN:
            raise RuntimeError("应用正在退出，无法创建新的连接")
    auth = validate_auth(s, allow_missing=True)
    if auth["credential_required"]:
        raise ValueError("这台服务器尚未配置 SSH 凭据，请先编辑服务器并补齐认证信息")
    ssh = connect_ssh(validate_host(s["host"]), port=validate_port(s.get("port", 22)),
                      user=validate_user(s["user"]), password=auth.get("password", ""), timeout=timeout,
                      auth_type=auth["auth_type"], private_key=auth.get("private_key", ""),
                      key_passphrase=auth.get("key_passphrase", ""),
                      known_hosts_path=KNOWN_HOSTS_FILE, trust_new_host=False,
                      auto_update_host_key=auto_update_ssh_identity())
    return _track_resource(ssh)


@contextlib.contextmanager
def ssh_connection(sid, timeout=15):
    server = get_server(sid)
    if not server:
        raise ValueError("服务器不存在，请重新选择")
    ssh = connect(server, timeout=timeout)
    try:
        yield ssh
    finally:
        ssh.close()

def sh(ssh, cmd, timeout=60):
    return run_checked(ssh, cmd, timeout=timeout).strip()

# ---------- 页面 ----------
@app.route("/")
def index():
    return render_template("index.html", csrf_token=CSRF_TOKEN, loopback_port=app.config["LOCAL_ACCESS_PORT"])


@app.route("/api/clash-export/<token>.yaml", methods=["GET"])
def clash_export_download(token):
    item = CLASH_EXPORTS.get(token)
    if item is None:
        return jsonify(ok=False, msg="Clash 导入链接已失效，请重新读取节点列表"), 404
    response = Response(item["yaml"], content_type="application/yaml; charset=utf-8")
    fallback_name = re.sub(r"[^A-Za-z0-9._-]", "_", item["filename"])[:100] or "G-Network.yaml"
    response.headers["Content-Disposition"] = ('attachment; filename="' + fallback_name +
                                                '"; filename*=UTF-8\'\'' + urllib.parse.quote(item["filename"], safe=""))
    return response


@app.route("/api/health")
def health():
    return jsonify(app="server-manager", project_root=PROJECT_ROOT)

# ---------- 服务器 CRUD ----------
@app.route("/api/servers", methods=["GET"])
def list_servers():
    out = []
    for server in load_json(SERVERS_FILE, []):
        safe = {key: server.get(key) for key in ("id", "name", "host", "port", "user")}
        mode = server.get("auth_type", "password")
        safe["auth_type"] = mode
        safe["credential_required"] = mode not in ("password", "private_key", "agent") or bool(
            mode != "agent" and not server.get("password" if mode == "password" else "private_key"))
        out.append(safe)
    return jsonify(out)


def _server_record(data, previous=None):
    previous = previous or {}
    auth = validate_auth(data, previous=previous)
    if auth["auth_type"] == "private_key":
        parse_private_key(auth["private_key"], auth.get("key_passphrase", ""))
    host = validate_host(data.get("host", previous.get("host")))
    name = data.get("name", previous.get("name")) or host
    if not isinstance(name, str) or len(name) > 120:
        raise ValueError("服务器名称最多 120 个字符")
    return {"id": previous.get("id") or uuid.uuid4().hex, "name": name, "host": host,
            "port": validate_port(data.get("port", previous.get("port", 22))),
            "user": validate_user(data.get("user", previous.get("user")) or "root"), **auth}


def _server_has_jobs(sid):
    return any((job.get("server_id") == sid or sid in job.get("server_ids", [])) and job.get("status") == "running"
               for job in jobs.values())

@app.route("/api/servers", methods=["POST"])
def add_server():
    d = json_body()
    server = _server_record(d)
    with DATA_LOCK:
        servers = load_json(SERVERS_FILE, [])
        servers.append(server)
        save_json(SERVERS_FILE, servers)
    return jsonify(ok=True, id=server["id"])


@app.route("/api/servers/<sid>", methods=["PUT"])
def edit_server(sid):
    data = json_body()
    with JOB_LOCK:
        if _server_has_jobs(sid):
            return jsonify(ok=False, msg="这台服务器有任务正在运行，请完成后再编辑"), 409
        with DATA_LOCK:
            servers = load_json(SERVERS_FILE, [])
            previous = next((s for s in servers if s.get("id") == sid), None)
            if previous is None:
                raise ValueError("服务器不存在")
            updated = _server_record(data, previous)
            save_json(SERVERS_FILE, [updated if s.get("id") == sid else s for s in servers])
    # Never remove/rewrite a trusted host key when a user edits a connection.
    # New authentication must not keep an old tunnel or exported node capability.
    CLASH_EXPORTS.revoke_scope(_clash_scope(previous))
    CLASH_EXPORTS.revoke_scope(_clash_scope(updated))
    stop_forwarders(sid)
    return jsonify(ok=True, id=sid, msg="服务器已更新，请重新连接并核对主机身份")


@app.route("/api/servers/<sid>/identity", methods=["GET", "POST"])
def server_identity(sid):
    server = get_server(sid)
    if not server:
        raise ValueError("服务器不存在")
    expected = None
    if request.method == "POST":
        data = json_body()
        if set(data) != {"fingerprint"}:
            raise ValueError("确认主机身份仅接受指纹，不接受公钥、主机地址或文件路径")
        expected = data["fingerprint"]
        if not isinstance(expected, str) or not expected:
            raise ValueError("请提供本次协商得到的 SHA256 主机指纹")
    result = host_identity(server["host"], server.get("port", 22),
                           known_hosts_path=KNOWN_HOSTS_FILE, expected_fingerprint=expected,
                           auto_update_host_key=auto_update_ssh_identity())
    return jsonify(ok=True, **result)

@app.route("/api/servers/<sid>", methods=["DELETE"])
def del_server(sid):
    if any((job.get("server_id") == sid or sid in job.get("server_ids", [])) and job["status"] == "running" for job in list(jobs.values())):
        return jsonify(ok=False, msg="这台服务器有任务正在运行，请完成后再删除"), 409
    with DATA_LOCK:
        servers = load_json(SERVERS_FILE, [])
        removed = next((s for s in servers if s["id"] == sid), None)
        save_json(SERVERS_FILE, [s for s in servers if s["id"] != sid])
    if removed:
        CLASH_EXPORTS.revoke_scope(_clash_scope(removed))
    stop_forwarders(sid)
    return jsonify(ok=True)

# ---------- 设置（API Keys） ----------
@app.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        d = json_body()
        if "ssh_auto_update_host_key" in d and not isinstance(d["ssh_auto_update_host_key"], bool):
            raise ValueError("SSH 自动更新身份设置必须是布尔值")
        clear_keys = d.get("clear_keys", [])
        if not isinstance(clear_keys, list) or any(key not in KEY_FIELDS for key in clear_keys):
            raise ValueError("清除密钥参数无效")
        with DATA_LOCK:
            st = load_json(SETTINGS_FILE, {})
            for key in KEY_FIELDS:
                value = d.get(key, "")
                if not isinstance(value, str) or len(value) > 4096 or any(c in value for c in "\r\n\x00") or value.startswith("dpapi:v1:"):
                    raise ValueError("API Key 格式不正确")
                if key in clear_keys:
                    st[key] = ""
                elif value.strip():
                    st[key] = value.strip()
            if "ssh_auto_update_host_key" in d:
                st["ssh_auto_update_host_key"] = d["ssh_auto_update_host_key"]
            save_json(SETTINGS_FILE, st)
        return jsonify(ok=True)
    st = load_json(SETTINGS_FILE, {})
    return jsonify({**{key + "_set": bool(st.get(key)) for key in KEY_FIELDS},
                    "ssh_auto_update_host_key": auto_update_ssh_identity()})

# ---------- 连接测试 & 系统信息 ----------
@app.route("/api/servers/<sid>/test", methods=["POST"])
def test(sid):
    try:
        with ssh_connection(sid) as ssh:
            host = sh(ssh, "hostname")
            identity = getattr(ssh, "_host_identity", None)
        if not isinstance(identity, dict):
            identity = None
        updated = bool(identity and identity.get("updated"))
        return jsonify(ok=True, identity=identity,
                       msg=f"连接成功（主机名 {host}）" + ("；旧 SSH 指纹已自动更新" if updated else ""))
    except HostIdentityError as e:
        return jsonify(ok=False, code=e.code, msg=str(e)), 409
    except Exception as e:
        return jsonify(ok=False, msg=str(e))

@app.route("/api/servers/<sid>/info")
def info(sid):
    with ssh_connection(sid) as ssh:
        d = {}
        d["os"] = sh(ssh, ". /etc/os-release; echo $PRETTY_NAME")
        d["kernel"] = sh(ssh, "uname -r")
        d["cpu"] = sh(ssh, "nproc") + " 核"
        d["load"] = sh(ssh, "cut -d' ' -f1-3 /proc/loadavg")
        d["mem"] = sh(ssh, "free -m | awk '/Mem:/{printf \"%s / %s MB (%d%%)\", $3,$2,$3*100/$2}'")
        d["disk"] = sh(ssh, "df -h / | awk 'NR==2{printf \"%s / %s (%s)\", $3,$2,$5}'")
        d["uptime"] = sh(ssh, "uptime -p")
        d["bbr"] = sh(ssh, "sysctl -n net.ipv4.tcp_congestion_control")
        installed = {}
        for name, cmd in {"node": "node -v", "dsh": "dsh --version", "claude": "claude --version",
                          "codex": "codex --version", "xray": "xray version 2>/dev/null | head -1 | awk '{print $2}'",
                          "python3": "python3 -V"}.items():
            v = sh(ssh, f"command -v {name} >/dev/null 2>&1 && {cmd} || echo NO")
            installed[name] = "" if v == "NO" else v
        d["tools"] = installed
    return jsonify(d)

# ---------- 一键工具箱 ----------
def _bbr():
    return r'''cat > /etc/sysctl.d/99-bbr-tune.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3
EOF
sysctl -p /etc/sysctl.d/99-bbr-tune.conf
echo "BBR 状态: $(sysctl -n net.ipv4.tcp_congestion_control)"'''

def _node():
    return r'''if ! command -v node >/dev/null || ! node -e 'var v=process.versions.node.split(".").map(Number); process.exit(v[0]>22 || (v[0]===22 && v[1]>=12) ? 0 : 1)'; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null 2>&1
  apt-get install -y nodejs 2>&1 | tail -1
fi
command -v npm >/dev/null || { echo 'Node 已安装但 npm 缺失，请先修复 npm；不会降级现有 Node'; exit 1; }
node -e 'var v=process.versions.node.split(".").map(Number); process.exit(v[0]>22 || (v[0]===22 && v[1]>=12) ? 0 : 1)' || { echo '需要 Node >=22.12.0'; exit 1; }
echo "node $(node -v) / npm $(npm -v)"'''

def _dsh(key):
    lines = [_node(), "npm install -g @deepseek-ai/dsh 2>&1 | tail -2"]
    if key:
        lines.append(_private_api_key("DEEPSEEK_API_KEY", key))
        lines.append('echo "API Key 已写入权限 600 的私有环境文件"')
    lines.append('echo "dsh $(dsh --version) 安装完成，用法: dsh --profile headless \\"你的任务\\""')
    return "\n".join(lines)

def _private_api_key(envname, key):
    export_line = f"export {envname}=" + shlex.quote(key)
    source_line = f'. "$HOME/.server-manager/{envname}.env"'
    return ("umask 077\nmkdir -p \"$HOME/.server-manager\"\nchmod 700 \"$HOME/.server-manager\"\n"
            f"printf '%s\\n' {shlex.quote(export_line)} > \"$HOME/.server-manager/{envname}.env\"\n"
            f"chmod 600 \"$HOME/.server-manager/{envname}.env\"\n"
            f"touch ~/.bashrc; sed -i '/^export {envname}=/d' ~/.bashrc\n"
            f"grep -qxF -- {shlex.quote(source_line)} ~/.bashrc || printf '%s\\n' {shlex.quote(source_line)} >> ~/.bashrc")

def _npm_tool(pkg, envname, key, binary):
    lines = [_node(), f"npm install -g {pkg} 2>&1 | tail -2"]
    if key:
        lines.append(_private_api_key(envname, key))
        lines.append(f'echo "{envname} 已写入权限 600 的私有环境文件"')
    else:
        lines.append(f'echo "未配置 {envname}，请到设置页填写后重装，或首次运行 {binary} 按提示登录"')
    lines.append(f'{binary} --version 2>/dev/null || true')
    return "\n".join(lines)

def _desktop():
    return r'''command -v apt-get >/dev/null || { echo '远程桌面安装需要 Debian/Ubuntu'; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo 'Chrome/Edge 桌面安装目前只支持 x86_64'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
if [ -z "$(swapon --show=NAME --noheadings)" ]; then
  if [ -e /swapfile ] || [ -L /swapfile ]; then
    echo '[拒绝] /swapfile 已存在，未覆盖；请先人工检查现有 swap 配置'; exit 1
  fi
  if grep -Eq '^[[:space:]]*[^#].*[[:space:]]swap[[:space:]]' /etc/fstab; then
    echo '[拒绝] 已有未启用的 swap 配置，保留原配置；请先人工检查'; exit 1
  fi
  (set -o noclobber; : > /swapfile) || { echo '[拒绝] 无法安全创建 /swapfile'; exit 1; }
  if ! { fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile; }; then
    echo '[失败] 新建 swap 未能启用，未写入 fstab；请人工检查保留的 /swapfile'; exit 1
  fi
  grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "[1/4] 2G Swap 已创建"
else echo "[1/4] Swap 已存在"; fi
apt-get update -y >/dev/null 2>&1
apt-get install -y xfce4 xfce4-terminal dbus-x11 xrdp curl wget gnupg ca-certificates 2>&1 | tail -1
echo "xfce4-session" > /root/.xsession
adduser xrdp ssl-cert >/dev/null 2>&1
systemctl enable xrdp >/dev/null 2>&1 && systemctl restart xrdp
echo "[2/4] XFCE + xrdp 完成: $(systemctl is-active xrdp)"
(
task_chrome_tmp="$(mktemp -d)"
trap 'rm -rf -- "$task_chrome_tmp"' EXIT
wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O "$task_chrome_tmp/chrome.deb"
apt-get install -y "$task_chrome_tmp/chrome.deb"
)
echo "[3/4] Chrome: $(google-chrome --version)"
''' + microsoft_edge_repository_script() + r'''
apt-get update -y
apt-get install -y microsoft-edge-stable
task_edge_version="$(microsoft-edge --version)"
echo "[4/4] Edge: $task_edge_version"
echo "[+] 浏览器保留官方 sandbox 配置。请使用普通用户桌面运行浏览器；不支持 root 下关闭 sandbox 启动。"
ss -tlnp | grep 3389 && echo "远程桌面端口 3389 已监听"
echo ""
echo "===== 连接方法 ====="
echo "Windows 按 Win+R 输入 mstsc，计算机填本服务器 IP，使用有桌面登录权限的普通用户与账号密码。"
echo "SSH 私钥/Agent 不等同于 RDP 密码；请单独配置桌面账号。"'''

ACTIONS = {
    "check_env": ("环境体检", "cat /etc/os-release | head -2; uname -m; nproc; free -m | head -2; df -h / | tail -1"),
    "enable_bbr": ("开启 BBR 加速", _bbr()),
    "install_node": ("安装 Node.js 22", _node()),
    "install_dsh": ("安装 DeepSeek Harness", None),
    "install_claude": ("安装 Claude Code", None),
    "install_codex": ("安装 Codex CLI (GPT)", None),
    "install_xray": ("安装 Xray Reality 节点", None),
    "install_desktop": ("安装远程桌面", _desktop()),
}

CAPABILITY_PROBE = r"""
printf 'kernel=%s\narch=%s\nuid=%s\nuser=%s\n' "$(uname -s 2>/dev/null)" "$(uname -m 2>/dev/null)" "$(id -u 2>/dev/null)" "$(id -un 2>/dev/null)"
awk -F= '$1 == "ID" || $1 == "ID_LIKE" || $1 == "VERSION_ID" || $1 == "PRETTY_NAME" { v=substr($0,index($0,"=")+1); gsub(/^"|"$/,"",v); printf "os_%s=%s\n",$1,v }' /etc/os-release 2>/dev/null || true
for name in bash apt-get dpkg dnf yum zypper pacman emerge curl wget systemctl sysctl npm node flock ss sha256sum base64 cat head tail nproc free df; do
  if command -v "$name" >/dev/null 2>&1; then printf 'cmd_%s=1\n' "$name"; else printf 'cmd_%s=0\n' "$name"; fi
done
if test -d /run/systemd/system && systemctl show --property=Version --value >/dev/null 2>&1; then echo 'systemd=1'; else echo 'systemd=0'; fi
if command -v sudo >/dev/null 2>&1 && test "$(sudo -n bash -c 'id -u' 2>/dev/null)" = 0; then echo 'sudo=1'; else echo 'sudo=0'; fi
printf 'package_arch=%s\n' "$(dpkg --print-architecture 2>/dev/null || true)"
printf 'node_version=%s\n' "$(node --version 2>/dev/null || true)"
printf 'npm_version=%s\n' "$(npm --version 2>/dev/null || true)"
printf 'bbr_algorithms=%s\n' "$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true)"
if command -v modinfo >/dev/null 2>&1 && modinfo tcp_bbr >/dev/null 2>&1; then echo 'bbr_module=1'; else echo 'bbr_module=0'; fi
if test -w /proc/sys/net/ipv4/tcp_congestion_control && test -w /etc/sysctl.d; then echo 'sysctl_writable=1'; else echo 'sysctl_writable=0'; fi
if test -x /usr/local/bin/xray; then echo 'xray=1'; else echo 'xray=0'; fi
"""


def inspect_capabilities(ssh):
    """Read fixed, bounded commands; never source OS metadata or mutate a host."""
    raw = run_checked(ssh, CAPABILITY_PROBE, timeout=20)
    if not isinstance(raw, str) or len(raw) > 20000:
        raise ValueError("服务器能力检查返回格式无效")
    values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if not values.get("kernel") or not re.fullmatch(r"\d{1,10}", values.get("uid", "")):
        raise ValueError("无法识别服务器系统或当前权限，未执行安装操作")
    commands = {name: values.get("cmd_" + name) == "1" for name in (
        "bash", "apt-get", "dpkg", "dnf", "yum", "zypper", "pacman", "emerge",
        "curl", "wget", "systemctl", "sysctl", "npm", "node", "flock", "ss",
        "sha256sum", "base64", "cat", "head", "tail", "nproc", "free", "df")}
    c = {"kernel": values["kernel"], "os": values.get("os_PRETTY_NAME", values["kernel"]),
         "distro": values.get("os_ID", ""), "distro_like": values.get("os_ID_LIKE", ""),
         "distro_version": values.get("os_VERSION_ID", ""), "arch": values.get("arch", ""),
         "package_arch": values.get("package_arch", ""), "user": values.get("user", ""),
         "uid": int(values["uid"]), "is_root": values["uid"] == "0",
         "has_sudo": values.get("sudo") == "1", "has_apt": commands["apt-get"],
         "has_systemd": values.get("systemd") == "1", "has_bash": commands["bash"],
         "has_curl": commands["curl"], "commands": commands,
         "node_version": values.get("node_version", ""), "npm_version": values.get("npm_version", ""),
         "has_xray": values.get("xray") == "1",
         "has_bbr": "bbr" in values.get("bbr_algorithms", "").split() or values.get("bbr_module") == "1",
         "sysctl_writable": values.get("sysctl_writable") == "1",
         "network_verified": False, "checked_at": time.time()}
    c["tools"] = {action: tool_capability(c, action) for action in ACTIONS}
    return c


def tool_capability(c, action):
    commands = c.get("commands", {})
    reasons = []
    network = action.startswith("install_")
    if c.get("kernel") != "Linux":
        reasons.append("当前工具仅支持 Linux；普通 SSH 管理仍可使用")
    if not c.get("has_bash"):
        reasons.append("缺少 Bash")
    if action != "check_env" and not c.get("is_root"):
        reasons.append("当前安装与系统调优需要 root 用户；检测到 sudo 也不会隐式提权")
    if action == "check_env":
        missing = [name for name in ("cat", "head", "tail", "nproc", "free", "df") if not commands.get(name)]
        if missing:
            reasons.append("缺少环境检查命令：" + "、".join(missing))
    elif action == "enable_bbr":
        network = False
        if not commands.get("sysctl") or not c.get("sysctl_writable"):
            reasons.append("缺少 sysctl 或网络内核参数/配置目录不可写")
        if not c.get("has_bbr"):
            reasons.append("未确认内核提供 BBR，需先核对内核或模块")
    elif action in ("install_node", "install_dsh", "install_claude", "install_codex"):
        version = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", c.get("node_version", ""))
        node_ready = bool(version and tuple(map(int, version.groups())) >= (22, 12, 0))
        if c.get("arch") not in ("x86_64", "aarch64", "arm64"):
            reasons.append("当前 Node / AI 工具安装仅支持已识别的 x64 或 ARM64 Linux")
        if node_ready and not commands.get("npm"):
            reasons.append("Node 版本足够但缺少 npm，请先修复 npm；不会自动降级现有 Node")
        if not node_ready:
            if c.get("distro") not in ("debian", "ubuntu") and not set(c.get("distro_like", "").split()) & {"debian", "ubuntu"}:
                reasons.append("当前 Node 安装流程需要 Debian/Ubuntu 系；其他发行版请先安装 Node >=22.12 与 npm")
            if not commands.get("apt-get") or not commands.get("dpkg") or not c.get("has_curl"):
                reasons.append("升级 Node 需要 apt-get、dpkg 与 curl")
            if c.get("package_arch") not in ("amd64", "arm64"):
                reasons.append("当前 NodeSource 安装流程仅支持 amd64/arm64 软件包")
        if action == "install_node" and node_ready and commands.get("npm"):
            network = False
    elif action in ("install_xray", "install_desktop"):
        if not c.get("has_systemd"):
            reasons.append("需要正在运行的 systemd，不能仅以 systemctl 命令存在判断")
        if action == "install_xray":
            missing = [name for name in ("flock", "ss", "sha256sum", "base64") if not commands.get(name)]
            if missing:
                reasons.append("节点配置事务缺少：" + "、".join(missing))
            if not c.get("has_xray"):
                if not c.get("has_curl"):
                    reasons.append("首次安装 Xray 需要 curl")
                if not any(commands.get(name) for name in ("apt-get", "dnf", "yum", "zypper", "pacman", "emerge")):
                    reasons.append("未识别 Xray 官方安装流程支持的包管理器")
                if c.get("arch") not in ("x86_64", "aarch64", "arm64"):
                    reasons.append("未验证该架构的 Xray 自动安装流程")
            else:
                network = False
        else:
            if c.get("distro") not in ("debian", "ubuntu") or not c.get("has_apt") or not commands.get("dpkg"):
                reasons.append("远程桌面安装需要 Debian/Ubuntu 与 apt-get/dpkg")
            if c.get("arch") != "x86_64" or c.get("package_arch") != "amd64":
                reasons.append("当前 Chrome/Edge 桌面软件包仅支持 x86_64/amd64")
            if not c.get("has_curl") or not commands.get("wget"):
                reasons.append("桌面安装需要 curl 与 wget")
    available = not reasons
    reason = "；".join(reasons) if reasons else ("系统条件满足；远端官方下载源的网络尚未检测" if network
                                                    else "系统条件满足")
    if available and action == "enable_bbr":
        reason = "基础条件满足；容器权限与 fq 队列支持仍以实际执行结果为准"
    return {"available": available, "state": "blocked" if reasons else "conditional" if network or action == "enable_bbr" else "available",
            "reason": reason, "requires_network": network}


def require_tool_capability(ssh, action):
    capabilities = inspect_capabilities(ssh)
    result = capabilities["tools"][action]
    if not result["available"]:
        raise ValueError("不能执行此操作：" + result["reason"])
    return capabilities


def require_service_permissions(ssh):
    c = inspect_capabilities(ssh)
    if c["kernel"] != "Linux" or not c["has_bash"] or not c["has_systemd"] or not c["is_root"]:
        raise ValueError("修改服务器服务或节点配置需要 Linux、Bash、正在运行的 systemd 与 root 用户")
    return c


@app.route("/api/servers/<sid>/capabilities")
def server_capabilities(sid):
    with ssh_connection(sid) as ssh:
        result = inspect_capabilities(ssh)
    return jsonify(ok=True, server_id=sid, **result)

@app.route("/api/servers/<sid>/run", methods=["POST"])
def run_action(sid):
    d = json_body()
    action = d.get("action")
    if action not in ACTIONS:
        raise ValueError("未知工具操作")
    server = get_server(sid)
    if not server:
        raise ValueError("服务器不存在")
    port = validate_port(d.get("port") or 600)
    sni = d.get("sni") or "www.amazon.com"
    if not isinstance(sni, str) or "." not in validate_host(sni):
        raise ValueError("伪装网址必须是域名")
    st = load_json(SETTINGS_FILE, {})
    if action == "install_dsh":
        script = _dsh(st.get("deepseek_key", ""))
    elif action == "install_claude":
        script = _npm_tool("@anthropic-ai/claude-code", "ANTHROPIC_API_KEY", st.get("anthropic_key", ""), "claude")
    elif action == "install_codex":
        script = _npm_tool("@openai/codex", "OPENAI_API_KEY", st.get("openai_key", ""), "codex")
    elif action == "install_xray":
        script = None
    else:
        script = ACTIONS[action][1]
    jid = new_job(f"$ 开始执行【{ACTIONS[action][0]}】...\n\n", server_id=sid)
    def worker():
        ssh = None
        def log(chunk):
            for key in KEY_FIELDS + SSH_SECRET_FIELDS:
                value = st.get(key) if key in KEY_FIELDS else server.get(key)
                if value:
                    chunk = chunk.replace(value, "[API Key 已隐藏]")
            append_job_output(jid, chunk)
        try:
            if action == "install_xray":
                # The legacy toolbox entry now uses the same incremental transaction.
                result = _deploy_direct(jid, {"mode": "direct", "protocol": "vless-reality",
                                             "server_id": sid, "port": port, "sni": sni})
                jobs[jid]["result"] = result
                append_job_output(jid, "\n" + "\n".join(result["links"]))
            else:
                with server_lock(server["host"], server.get("port", 22)):
                    if get_server(sid) != server:
                        raise ValueError("服务器信息已改变，请重新执行任务")
                    ssh = connect(server, timeout=20)
                    require_tool_capability(ssh, action)
                    run_checked(ssh, "bash -e -o pipefail -c " + shlex.quote(script), timeout=1800,
                                on_output=log)
            append_job_output(jid, "\n\n===== 执行成功（退出码 0）=====")
            jobs[jid]["status"] = "done"
        except Exception as e:
            log(f"\n\n[出错] {e}")
            jobs[jid]["status"] = "error"
        finally:
            if ssh is not None:
                ssh.close()
    threading.Thread(target=worker, daemon=True).start()
    return jsonify(job=jid)

@app.route("/api/jobs/<jid>")
def job_status(jid):
    return jsonify(jobs.get(jid, {"status": "error", "output": "任务不存在"}))

# ---------- 文件管理 ----------
def _sftp(sid):
    ssh = connect(get_server(sid))
    sftp = None
    try:
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(60)
        return ssh, sftp
    except Exception:
        try:
            if sftp is not None:
                sftp.close()
        finally:
            ssh.close()
        raise


@contextlib.contextmanager
def sftp_connection(sid):
    ssh, sftp = _sftp(sid)
    try:
        yield sftp
    finally:
        try:
            sftp.close()
        finally:
            ssh.close()


def remote_path(value):
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise ValueError("请使用有效的远程绝对路径")
    return value

@app.route("/api/servers/<sid>/files")
def list_files(sid):
    path = remote_path(request.args.get("path", "/root"))
    try:
        out = []
        with sftp_connection(sid) as sftp:
            for a in sftp.listdir_attr(path):
                is_dir = a.st_mode is not None and (a.st_mode & 0o170000) == 0o040000
                out.append({"name": a.filename, "dir": is_dir, "size": a.st_size,
                            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(a.st_mtime))})
        out.sort(key=lambda x: (not x["dir"], x["name"].lower()))
        return jsonify(ok=True, path=path, items=out)
    except Exception as e:
        return jsonify(ok=False, msg=str(e))

@app.route("/api/servers/<sid>/file")
def read_file(sid):
    path = remote_path(request.args.get("path", ""))
    try:
        with sftp_connection(sid) as sftp:
            attributes = sftp.stat(path)
            if not stat.S_ISREG(attributes.st_mode or 0):
                raise ValueError("只能预览普通文件，不能读取目录、设备或管道")
            size = attributes.st_size
            if size > 512 * 1024:
                return jsonify(ok=False, msg=f"文件 {size//1024} KB，太大不支持预览，请下载查看")
            with sftp.open(path, "rb") as f:
                content = f.read(512 * 1024 + 1)
            if len(content) > 512 * 1024:
                return jsonify(ok=False, msg="文件已增长，超过预览上限，请下载查看")
            content = content.decode("utf-8", errors="replace")
        return jsonify(ok=True, content=content)
    except Exception as e:
        return jsonify(ok=False, msg=str(e))

@app.route("/api/servers/<sid>/download")
def download_file(sid):
    path = remote_path(request.args.get("path", ""))
    buf = _track_resource(tempfile.TemporaryFile("w+b", dir=DATA_DIR if DESKTOP_DATA else None))
    limit = 2 * 1024 * 1024 * 1024
    try:
        with sftp_connection(sid) as sftp:
            attributes = sftp.stat(path)
            if not stat.S_ISREG(attributes.st_mode or 0):
                raise ValueError("只能下载普通文件，不能读取目录、设备或管道")
            if attributes.st_size > limit:
                raise ValueError("文件超过 2 GiB，请使用专门的 SFTP 客户端下载")
            total = 0
            with sftp.open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise ValueError("文件超过下载上限")
                    buf.write(chunk)
        buf.seek(0)
        response = send_file(buf, as_attachment=True, download_name=path.rsplit("/", 1)[-1] or "download")
        response.call_on_close(buf.close)
        return response
    except Exception:
        buf.close()
        raise

@app.route("/api/servers/<sid>/search", methods=["POST"])
def search_files(sid):
    d = json_body()
    base = remote_path(d.get("path") or "/root")
    kw = d.get("keyword", "")
    if not isinstance(kw, str) or len(kw) > 512 or "\x00" in kw:
        raise ValueError("关键词格式不正确")
    kw = kw.strip()
    mode = d.get("mode", "name")
    if not kw:
        return jsonify(ok=False, msg="请输入关键词")
    if mode == "content":
        excludes = " ".join("--exclude-dir=" + name for name in ("proc", "sys", "dev", "run", "node_modules", ".git"))
        cmd = f"grep -rIl -m 1 {excludes} -- {shlex.quote(kw)} {shlex.quote(base)} 2>/dev/null | head -200"
    else:
        cmd = f"find {shlex.quote(base)} -maxdepth 6 -iname {shlex.quote('*' + kw + '*')} 2>/dev/null | head -200"
    try:
        with ssh_connection(sid) as ssh:
            out = sh(ssh, cmd, timeout=120)
        return jsonify(ok=True, results=[l for l in out.splitlines() if l.strip()])
    except Exception as e:
        return jsonify(ok=False, msg=str(e))

# ---------- 节点搭建（增量部署，绝不覆盖现有配置） ----------
def _resolve_server(d, key):
    """Resolve saved IDs or explicit in-memory authentication on manual targets."""
    if not isinstance(d, dict):
        return None
    v = d.get(key)
    try:
        srv = dict(v) if isinstance(v, dict) else (get_server(v) if isinstance(v, str) and v else None)
        if not srv:
            return None
        raw_host = srv.get("host")
        host = validate_host(raw_host.strip().strip("[]") if isinstance(raw_host, str) else raw_host)
        user = validate_user(srv.get("user") or "root")
        raw_port = srv.get("port", 22)
        port = validate_port(22 if raw_port in (None, "") else raw_port)
        auth = validate_auth(srv)
        if auth["auth_type"] == "private_key":
            parse_private_key(auth["private_key"], auth.get("key_passphrase", ""))
        return {"id": srv.get("id", "manual"), "name": srv.get("name") or host,
                "host": host, "port": port, "user": user, **auth}
    except (TypeError, ValueError, KeyError):
        return None

NODE_PROTOCOLS = {
    "vless-reality": {"label": "VLESS + Reality + XTLS Vision", "desc": "抗封锁最强、速度最快（推荐）。借用真实网站 TLS 指纹，无需证书"},
    "vless-ws":      {"label": "VLESS + WebSocket",            "desc": "兼容性好，可套 CDN 中转；无 TLS，建议配合 CDN 使用"},
    "vmess-ws":      {"label": "VMess + WebSocket",            "desc": "经典老牌协议，老旧客户端兼容性最好"},
    "shadowsocks":   {"label": "Shadowsocks (AEAD / 2022)",    "desc": "轻量省资源，适合路由器与低配设备"},
}
SS_METHODS = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
              "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]

@app.route("/api/nodes/protocols")
def node_protocols():
    return jsonify({"protocols": NODE_PROTOCOLS, "ss_methods": SS_METHODS})

def _nlog(jid, msg):
    append_job_output(jid, msg + "\n")

def _read_xray_cfg(ssh):
    return read_xray_config(ssh)

def _used_ports(ssh, cfg):
    used = {ib.get("port") for ib in cfg.get("inbounds", [])
            if isinstance(ib.get("port"), int) and not isinstance(ib.get("port"), bool)}
    for ib in cfg.get("inbounds", []):
        port = ib.get("port")
        if isinstance(port, str):
            for group in port.split(","):
                match = re.fullmatch(r"(\d+)(?:-(\d+))?", group.strip())
                if match:
                    start, end = int(match[1]), int(match[2] or match[1])
                    if 1 <= start <= end <= 65535:
                        used.update(range(start, end + 1))
    used |= listening_ports(ssh) | listening_ports(ssh, udp=True)
    return sorted(used)

def _ensure_xray(ssh, jid):
    require_tool_capability(ssh, "install_xray")
    if run_checked(ssh, "if test -x /usr/local/bin/xray; then echo OK; else echo NO; fi").strip() == "NO":
        _nlog(jid, "  未检测到 Xray，自动安装官方最新版...")
        out = run_checked(ssh, "bash -c " + shlex.quote('set -Eeuo pipefail; installer=$(mktemp); trap \'rm -f -- "$installer"\' EXIT; curl --fail --silent --show-error --location https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o "$installer"; bash "$installer" install; test -x /usr/local/bin/xray'), timeout=300)
        _nlog(jid, "  " + out.replace("\n", "\n  "))
    else:
        _nlog(jid, "  Xray 已安装：" + run_checked(ssh, "/usr/local/bin/xray version").splitlines()[0])

def _apply_xray_cfg(ssh, cfg, expected=None):
    require_service_permissions(ssh)
    apply_xray_config(ssh, cfg, expected=expected)

def _reality_keys(ssh, cfg):
    """复用服务器现有 Reality 私钥（多入站共用一个服务器身份）；没有则新生成。返回 (priv, pub, reused)。"""
    for ib in cfg.get("inbounds", []):
        rs = (ib.get("streamSettings") or {}).get("realitySettings")
        if rs and rs.get("privateKey"):
            priv = rs["privateKey"]
            out = run_checked(ssh, f"/usr/local/bin/xray x25519 -i {shlex.quote(priv)}")
            for line in out.splitlines():
                if re.search(r"public|password", line, re.I):
                    return priv, line.split()[-1], True
    out = run_checked(ssh, "/usr/local/bin/xray x25519")
    priv = pub = ""
    for line in out.splitlines():
        if re.search(r"private", line, re.I):
            priv = line.split()[-1]
        if re.search(r"public|password", line, re.I):
            pub = line.split()[-1]
    if not priv or not pub:
        raise RuntimeError("Xray 未返回有效的 Reality 密钥对，已中止")
    return priv, pub, False

def _ss_gen_password(method):
    if method == "2022-blake3-aes-128-gcm":
        return base64.b64encode(secrets.token_bytes(16)).decode()
    if method.startswith("2022-blake3"):
        return base64.b64encode(secrets.token_bytes(32)).decode()
    return secrets.token_urlsafe(16)

def _uri_host(host):
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _build_inbound_and_link(ssh, jid, cfg, d, listen_port, link_host, link_port, remark):
    """按协议构造入站与分享链接。listen_port=本机监听端口；链接地址用 link_host:link_port（中继时=入口）。"""
    proto = d["protocol"]
    # URI authorities require brackets around IPv6 literals.
    uri_host = _uri_host(link_host)
    name = urllib.parse.quote(remark or f"{proto}-{link_host}:{link_port}")
    if proto == "vless-reality":
        priv, pub, reused = _reality_keys(ssh, cfg)
        _nlog(jid, "  Reality 密钥：" + ("复用服务器现有密钥对" if reused else "本机首个 Reality 入站，已新生成密钥对"))
        uid = d.get("uuid") or str(uuid.uuid4())
        sid = d.get("sid") or secrets.token_hex(4)
        sni = (d.get("sni") or "www.amazon.com").strip()
        ib = {"tag": f"vless-reality-{listen_port}", "listen": "0.0.0.0", "port": listen_port,
              "protocol": "vless",
              "settings": {"clients": [{"id": uid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
              "streamSettings": {"network": "tcp", "security": "reality",
                                 "realitySettings": {"dest": f"{sni}:443", "serverNames": [sni],
                                                     "privateKey": priv, "shortIds": [sid]}},
              "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}
        link = (f"vless://{uid}@{uri_host}:{link_port}?encryption=none&flow=xtls-rprx-vision"
                f"&security=reality&sni={sni}&fp=chrome&pbk={pub}&sid={sid}&type=tcp#{name}")
        params = {"协议": "VLESS+Reality+Vision", "地址": f"{uri_host}:{link_port}", "UUID": uid,
                  "SNI 伪装": sni, "shortId": sid, "Reality 公钥": pub, "流控": "xtls-rprx-vision", "指纹": "chrome"}
        return ib, link, params
    uid = d.get("uuid") or str(uuid.uuid4())
    if proto in ("vless-ws", "vmess-ws"):
        wp = (d.get("ws_path") or "/ray").strip()
        if proto == "vless-ws":
            ib = {"tag": f"vless-ws-{listen_port}", "listen": "0.0.0.0", "port": listen_port,
                  "protocol": "vless",
                  "settings": {"clients": [{"id": uid}], "decryption": "none"},
                  "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": wp}}}
            link = (f"vless://{uid}@{uri_host}:{link_port}?encryption=none&security=none"
                    f"&type=ws&path={urllib.parse.quote(wp, safe='')}#{name}")
        else:
            ib = {"tag": f"vmess-ws-{listen_port}", "listen": "0.0.0.0", "port": listen_port,
                  "protocol": "vmess",
                  "settings": {"clients": [{"id": uid, "alterId": 0}]},
                  "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": wp}}}
            vmj = {"v": "2", "ps": remark or f"vmess-{link_host}:{link_port}", "add": link_host,
                   "port": str(link_port), "id": uid, "aid": "0", "net": "ws", "type": "none",
                   "host": "", "path": wp, "tls": ""}
            link = "vmess://" + base64.b64encode(json.dumps(vmj, ensure_ascii=False).encode()).decode()
        params = {"协议": NODE_PROTOCOLS[proto]["label"], "地址": f"{uri_host}:{link_port}",
                  "UUID": uid, "WS 路径": wp, "TLS": "无（建议套 CDN）"}
        return ib, link, params
    # shadowsocks
    method = d["ss_method"]
    pwd = d.get("ss_password") or _ss_gen_password(method)
    ib = {"tag": f"ss-{listen_port}", "listen": "0.0.0.0", "port": listen_port, "protocol": "shadowsocks",
          "settings": {"method": method, "password": pwd, "network": "tcp,udp"}}
    link = ("ss://" + base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
            + f"@{uri_host}:{link_port}#{name}")
    params = {"协议": "Shadowsocks", "地址": f"{uri_host}:{link_port}", "加密": method, "密码": pwd}
    return ib, link, params

def _validate_node_req(d):
    if not isinstance(d, dict):
        return ["请求必须是 JSON 对象"]
    errs = []
    mode = d.get("mode")
    proto = d.get("protocol")
    if mode not in ("direct", "relay"):
        errs.append("搭建模式无效")
    if not isinstance(proto, str) or proto not in NODE_PROTOCOLS:
        errs.append("未选择有效协议")
    for field in ("uuid", "sid", "sni", "ws_path", "ss_method", "ss_password", "remark"):
        if d.get(field) is not None and not isinstance(d[field], str):
            errs.append(f"{field} 必须是文本")
    if errs:
        return errs
    if mode == "direct":
        if not _resolve_server(d, "server_id"):
            errs.append("目标服务器无效（选择列表服务器或完整填写手动输入）")
    elif mode == "relay":
        e1, e2 = _resolve_server(d, "entry_id"), _resolve_server(d, "exit_id")
        if not e1 or not e2:
            errs.append("中继模式需同时选择有效的入口与出口服务器")
        elif e1["host"].lower() == e2["host"].lower():
            errs.append("入口与出口不能是同一台服务器")
    ports = [d.get("port")] if mode == "direct" else [d.get("entry_port"), d.get("exit_port")]
    for p in ports:
        try:
            if isinstance(p, bool) or not re.fullmatch(r"\d+", str(p)):
                raise ValueError
            p = int(p)
            if not (1 <= p <= 65535):
                raise ValueError
        except (TypeError, ValueError):
            errs.append(f"端口「{p}」无效（1-65535，必须未被占用）")
    if proto in ("vless-reality", "vless-ws", "vmess-ws") and d.get("uuid"):
        if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", d["uuid"]):
            errs.append("UUID 格式不对（留空可自动生成）")
    if len(d.get("remark") or "") > 200:
        errs.append("节点备注最长 200 个字符")
    if proto == "vless-reality":
        sni = (d.get("sni") or "www.amazon.com").strip()
        labels = sni.split(".")
        if (len(sni) > 253 or len(labels) < 2
                or any(not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", x) for x in labels)
                or not re.fullmatch(r"[a-zA-Z]{2,63}", labels[-1])):
            errs.append(f"伪装网址「{sni}」格式不对（应为可访问的域名，如 www.amazon.com）")
        if d.get("sid") and not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,8}", d["sid"]):
            errs.append("shortId 需为 2-16 位且位数为偶数的十六进制（留空可自动生成）")
    if proto in ("vless-ws", "vmess-ws"):
        wp = (d.get("ws_path") or "/ray").strip()
        if not re.fullmatch(r"/[a-zA-Z0-9/_-]{0,64}", wp):
            errs.append("WS 路径需以 / 开头，仅含字母数字 / _ -")
    if proto == "shadowsocks":
        m = d.get("ss_method")
        if m not in SS_METHODS:
            errs.append("SS 加密方式不支持")
        elif d.get("ss_password") and m.startswith("2022-blake3"):
            try:
                need = 16 if m == "2022-blake3-aes-128-gcm" else 32
                if len(base64.b64decode(d["ss_password"], validate=True)) != need:
                    raise ValueError
            except Exception:
                errs.append(f"SS2022 密码需为 base64 编码的 {need} 字节密钥（留空可自动生成）")
    return errs

@app.route("/api/nodes/check_port", methods=["POST"])
def node_check_port():
    d = request.json or {}
    if not isinstance(d, dict):
        return jsonify(ok=False, msg="请求必须是 JSON 对象"), 400
    out = {}
    checked = {}
    for key in ("server_id", "entry_id", "exit_id"):
        if d.get(key) in (None, ""):
            continue
        srv = _resolve_server(d, key)
        if not srv:
            out[key] = {"ok": False, "msg": "服务器无效"}
            continue
        identity = (srv["host"].lower(), srv["port"])
        if identity in checked:
            out[key] = dict(checked[identity])
            continue
        ssh = None
        try:
            ssh = connect(srv, timeout=20)
            used = _used_ports(ssh, _read_xray_cfg(ssh))
            out[key] = {"ok": True, "host": srv["host"], "used": used}
            checked[identity] = out[key]
        except Exception as e:
            out[key] = {"ok": False, "host": srv["host"], "msg": str(e)}
        finally:
            if ssh is not None:
                ssh.close()
    return jsonify(out)

def _deploy_direct(jid, d):
    s = _resolve_server(d, "server_id")
    if not s:
        raise RuntimeError("目标服务器无效")
    with server_lock(s["host"], s["port"]):
        _require_current_target(s)
        ssh = None
        try:
            ssh = connect(s, timeout=20)
            _nlog(jid, f"[1/4] 已连接目标服务器 {s['name']}（{s['host']}）")
            _ensure_xray(ssh, jid)
            before = _read_xray_cfg(ssh)
            cfg = copy.deepcopy(before)
            _nlog(jid, f"[2/4] 读取现有配置：{len(cfg.get('inbounds', []))} 个入站")
            port = int(d["port"])
            used = _used_ports(ssh, cfg)
            if port in used:
                raise RuntimeError(f"端口 {port} 已被占用。当前已用端口：{', '.join(map(str, used))}")
            ib, link, params = _build_inbound_and_link(ssh, jid, cfg, d, port, s["host"], port,
                                                       (d.get("remark") or "").strip())
            _append_inbound(cfg, ib)
            _nlog(jid, f"[3/4] 追加「{params['协议']}」入站到 :{port}，验证配置并重启 Xray...")
            _apply_xray_cfg(ssh, cfg, expected=before)
            _nlog(jid, f"[4/4] Xray active，端口 {port} 监听检查通过 ✔")
            CLASH_EXPORTS.revoke_scope(_clash_scope(s))
            clash = _register_clash_export(s, ib, s["host"], port, link,
                                           name=(d.get("remark") or "").strip())
            return {"links": [link], "clash": clash, "params": params, "server": s["name"]}
        finally:
            if ssh is not None:
                ssh.close()


def _append_inbound(cfg, inbound):
    inbound["tag"] = inbound["tag"] + "-" + uuid.uuid4().hex[:8]
    cfg.setdefault("inbounds", []).append(inbound)
    if not cfg.get("outbounds"):
        cfg["outbounds"] = [{"protocol": "freedom", "tag": "direct"}]


def _require_current_target(server):
    sid = server.get("id")
    if sid and sid != "manual" and _resolve_server({"target": sid}, "target") != server:
        raise ValueError("服务器信息已改变，请重新执行任务")


def _rollback_added_inbound(ssh, inbound):
    """Remove only the exact inbound created by this job, preserving other edits."""
    before = _read_xray_cfg(ssh)
    cfg = copy.deepcopy(before)
    present = [x for x in cfg.get("inbounds", []) if x.get("tag") == inbound["tag"]]
    if not present:
        return
    if len(present) != 1 or present[0] != inbound:
        raise RuntimeError("本次新增入站已被其他任务修改，停止自动移除")
    cfg["inbounds"] = [x for x in cfg.get("inbounds", []) if x.get("tag") != inbound["tag"]]
    _apply_xray_cfg(ssh, cfg, expected=before)

def _deploy_relay(jid, d):
    entry, exit_ = _resolve_server(d, "entry_id"), _resolve_server(d, "exit_id")
    if not entry or not exit_:
        raise RuntimeError("入口或出口服务器无效")
    entry_port, exit_port = int(d["entry_port"]), int(d["exit_port"])
    identities = sorted([(entry["host"], entry["port"]), (exit_["host"], exit_["port"])])
    # Stable lock ordering prevents opposite-direction relay jobs deadlocking.
    with server_lock(*identities[0]), server_lock(*identities[1]):
        _require_current_target(entry)
        _require_current_target(exit_)
        esh = nsh = None
        exit_added = entry_added = None
        try:
            esh = connect(exit_, timeout=20)
            nsh = connect(entry, timeout=20)
            _nlog(jid, f"[1/6] 已连接入口 {entry['host']} 和出口 {exit_['host']}")
            _ensure_xray(esh, jid)
            _ensure_xray(nsh, jid)
            ebefore, nbefore = _read_xray_cfg(esh), _read_xray_cfg(nsh)
            if exit_port in _used_ports(esh, ebefore):
                raise RuntimeError(f"出口机端口 {exit_port} 已被占用")
            if entry_port in _used_ports(nsh, nbefore):
                raise RuntimeError(f"入口机端口 {entry_port} 已被占用")
            ecfg, ncfg = copy.deepcopy(ebefore), copy.deepcopy(nbefore)
            ib, link, params = _build_inbound_and_link(esh, jid, ecfg, d, exit_port,
                                                       entry["host"], entry_port,
                                                       (d.get("remark") or "").strip())
            _append_inbound(ecfg, ib)
            _nlog(jid, f"[2/6] 出口机追加「{params['协议']}」入站 :{exit_port}...")
            _apply_xray_cfg(esh, ecfg, expected=ebefore)
            exit_added = ib
            _nlog(jid, f"[3/6] 出口机 :{exit_port} 监听检查通过 ✔")
            # Probe TCP reachability before publishing the entry listener. A UDP
            # listener is checked separately; this probe is not a UDP data test.
            probe = f'exec 3<>"/dev/tcp/{exit_["host"]}/{exit_port}"'
            run_checked(nsh, "timeout 6 bash -c " + shlex.quote(probe), timeout=10)
            _nlog(jid, "[4/6] 入口到出口 TCP 连接成功 ✔")
            relay_ib = {"tag": f"relay-{entry_port}-to-{exit_port}", "listen": "0.0.0.0",
                        "port": entry_port, "protocol": "dokodemo-door",
                        "settings": {"address": exit_["host"], "port": exit_port,
                                     "network": "tcp,udp" if d["protocol"] == "shadowsocks" else "tcp"}}
            _append_inbound(ncfg, relay_ib)
            _nlog(jid, f"[5/6] 入口机追加转发 :{entry_port} → {exit_['host']}:{exit_port}...")
            _apply_xray_cfg(nsh, ncfg, expected=nbefore)
            entry_added = relay_ib
            _nlog(jid, "[6/6] 入口机 active，所需监听检查通过 ✔")
            params = dict(params)
            params["中继入口"] = f"{entry['host']}:{entry_port}"
            params["出口落地"] = f"{exit_['host']}:{exit_port}"
            params["说明"] = "客户端连接中继入口，流量端到端加密后在出口机解密出访"
            CLASH_EXPORTS.revoke_scope(_clash_scope(entry))
            CLASH_EXPORTS.revoke_scope(_clash_scope(exit_))
            clash = _register_clash_export(entry, ib, entry["host"], entry_port, link,
                                           name=(d.get("remark") or "").strip(), node=relay_ib,
                                           source=exit_)
            return {"links": [link], "clash": clash, "params": params, "server": f"{entry['name']} → {exit_['name']}"}
        except Exception as exc:
            rollback_errors = []
            for connection, added, label in ((nsh, entry_added, "入口"), (esh, exit_added, "出口")):
                if connection is not None and added is not None:
                    try:
                        _rollback_added_inbound(connection, added)
                        _nlog(jid, f"  {label}本次新增入站已移除，其他入站保留")
                    except Exception as rollback_exc:
                        rollback_errors.append(f"{label}移除失败：{rollback_exc}")
            if rollback_errors:
                raise RuntimeError(f"{exc}；回滚需要人工检查：{'；'.join(rollback_errors)}") from exc
            raise
        finally:
            for connection in (nsh, esh):
                if connection is not None:
                    connection.close()

def _deploy_node_worker(jid, d):
    try:
        result = _deploy_direct(jid, d) if d["mode"] == "direct" else _deploy_relay(jid, d)
        jobs[jid]["result"] = result
        _nlog(jid, "\n===== ✅ 部署完成，节点信息见结果卡片 =====")
        jobs[jid]["status"] = "done"
    except Exception as e:
        _nlog(jid, f"\n===== ❌ 部署失败：{e} =====")
        jobs[jid]["status"] = "error"

@app.route("/api/nodes/deploy", methods=["POST"])
def node_deploy():
    d = request.json or {}
    errs = _validate_node_req(d)
    if errs:
        return jsonify(ok=False, errs=errs)
    d = dict(d)
    server_ids = []
    for key in (("server_id",) if d["mode"] == "direct" else ("entry_id", "exit_id")):
        srv = _resolve_server(d, key)
        if srv.get("id") != "manual":
            server_ids.append(srv["id"])
        d[key] = srv  # Pin the validated server target for the entire job.
    jid = new_job(f"$ 开始节点搭建【{'直连' if d['mode']=='direct' else '中继'} · {NODE_PROTOCOLS[d['protocol']]['label']}】\n\n",
                  server_ids=server_ids)
    threading.Thread(target=_deploy_node_worker, args=(jid, d), daemon=True).start()
    return jsonify(ok=True, job=jid)

# ---------- 节点列表 / 删除 ----------
_NODE_TOKEN_KEY = secrets.token_bytes(32)


def _clash_scope(srv):
    # Same physical SSH target, even if the user saved it with several names.
    host, port = srv["host"], srv.get("port", 22)
    host = validate_host(host.strip().strip("[]") if isinstance(host, str) else host)
    return (host.lower(), validate_port(22 if port in (None, "") else port))


def _register_clash_export(srv, inbound, host, port, link=None, name=None, node=None,
                           source=None, expected_epochs=None):
    """Register one real node without allowing conversion errors to hide it."""
    try:
        proxy = proxy_from_inbound(inbound, host, port, uri=link, name=name)
        if proxy["type"] == "ss" and node and node.get("protocol") == "dokodemo-door":
            forwarding = (node.get("settings") or {}).get("network", "tcp")
            proxy["udp"] = proxy["udp"] and "udp" in forwarding.split(",")
        kind, notice = compatibility(proxy)
        text = yaml_configuration(proxy)
        filename = f"FLNetwork-{proxy['type']}.yaml"
        saved_id = srv.get("id")
        routing_identity = saved_id if isinstance(saved_id, str) and re.fullmatch(r"[a-fA-F0-9]{32}", saved_id) else "manual"
        token = CLASH_EXPORTS.register(text, _clash_scope(srv),
                                      _node_token(srv, node if node is not None else inbound), filename, proxy=proxy,
                                      source_scopes=(_clash_scope(source),) if source else (),
                                      source_nodes=((_clash_scope(source), _node_token(source, inbound)),) if source else (),
                                      expected_epochs=expected_epochs,
                                      routing_key=stable_routing_key(routing_identity, _clash_scope(srv), proxy))
        url = f"http://127.0.0.1:{app.config['LOCAL_ACCESS_PORT']}/api/clash-export/{token}.yaml"
        if proxy.get("reality-opts"):
            notice += " 新版 Xray Reality 可能与 Mihomo 不兼容，请核对双方版本；连接失败可选择 VMess 或普通 Shadowsocks。"
        return {"available": True, "yaml": text, "url": url, "selection_token": token,
                "import_url": "clash://install-config?url=" + urllib.parse.quote(url, safe=""),
                "filename": filename, "compatibility": kind, "notice": notice + " " + LOCAL_NOTICE}
    except (UnsupportedExport, ValueError, KeyError, TypeError, AttributeError):
        return {"available": False, "compatibility": "unsupported",
                "notice": "此节点配置暂不能完整转换为 Clash 配置，请检查协议、传输参数和客户端凭证；原分享链接仍保留。"}


def _node_token(srv, inbound):
    import hashlib
    import hmac
    bound = {"host": srv["host"].lower(), "ssh_port": srv["port"], "user": srv["user"], "inbound": inbound}
    payload = json.dumps(bound, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_NODE_TOKEN_KEY, payload, hashlib.sha256).hexdigest()


def _node_link_for_inbound(ssh, ib, link_host, link_port):
    """从入站配置恢复分享链接（尽力而为），失败返回 None。"""
    try:
        uri_host = _uri_host(link_host)
        proto = ib.get("protocol")
        st = ib.get("settings") or {}
        ss = ib.get("streamSettings") or {}
        tag = urllib.parse.quote(ib.get("tag") or f"{proto}-{link_port}")
        if proto == "vless":
            clients = st.get("clients") or []
            if not clients:
                return None
            uid = clients[0].get("id")
            flow = clients[0].get("flow", "")
            net, sec = ss.get("network", "tcp"), ss.get("security", "none")
            if sec == "reality":
                rs = ss.get("realitySettings") or {}
                sni = (rs.get("serverNames") or [""])[0]
                sid = (rs.get("shortIds") or [""])[0]
                priv = rs.get("privateKey", "")
                pub = ""
                if priv and ssh:
                    out = run_checked(ssh, f"/usr/local/bin/xray x25519 -i {shlex.quote(priv)}")
                    for line in out.splitlines():
                        if re.search(r"public|password", line, re.I):
                            pub = line.split()[-1]
                if not pub:
                    return None
                q = "encryption=none"
                if flow:
                    q += f"&flow={flow}"
                q += f"&security=reality&sni={sni}&fp=chrome&pbk={pub}&sid={sid}&type=tcp"
                return f"vless://{uid}@{uri_host}:{link_port}?{q}#{tag}"
            if net == "ws":
                wp = (ss.get("wsSettings") or {}).get("path", "/")
                return (f"vless://{uid}@{uri_host}:{link_port}?encryption=none&security=none"
                        f"&type=ws&path={urllib.parse.quote(wp, safe='')}#{tag}")
            return None
        if proto == "vmess":
            clients = st.get("clients") or []
            if not clients:
                return None
            uid = clients[0].get("id")
            wp = (ss.get("wsSettings") or {}).get("path", "/") if ss.get("network") == "ws" else ""
            vmj = {"v": "2", "ps": ib.get("tag") or f"vmess-{link_port}", "add": link_host,
                   "port": str(link_port), "id": uid, "aid": str(clients[0].get("alterId", 0)),
                   "net": ss.get("network", "tcp"), "type": "none", "host": "", "path": wp,
                   "tls": "tls" if ss.get("security") == "tls" else ""}
            return "vmess://" + base64.b64encode(json.dumps(vmj, ensure_ascii=False).encode()).decode()
        if proto == "shadowsocks":
            method, pwd = st.get("method", ""), st.get("password", "")
            return ("ss://" + base64.urlsafe_b64encode(f"{method}:{pwd}".encode()).decode().rstrip("=")
                    + f"@{uri_host}:{link_port}#{tag}")
    except Exception:
        return None
    return None

def _inbound_summary(ib):
    proto = ib.get("protocol")
    st = ib.get("settings") or {}
    ss_ = ib.get("streamSettings") or {}
    if proto == "vless" and ss_.get("security") == "reality":
        rs = ss_.get("realitySettings") or {}
        return "VLESS + Reality + Vision", f"SNI {(rs.get('serverNames') or ['?'])[0]}"
    if proto == "vless":
        return f"VLESS + {ss_.get('network', 'tcp').upper()}", ""
    if proto == "vmess":
        return f"VMess + {ss_.get('network', 'tcp').upper()}", ""
    if proto == "shadowsocks":
        return "Shadowsocks", st.get("method", "")
    if proto == "dokodemo-door":
        return "中继转发 (dokodemo-door)", f"→ {st.get('address')}:{st.get('port')}"
    return str(proto), ""

def _read_node_items(srv):
    srv = _resolve_server({"server": srv}, "server")
    if not srv:
        return {"ok": False, "msg": "服务器无效或尚未补齐认证信息"}
    # Serialize a whole inventory, including URL rotations, for one physical
    # target. Exit reads use epochs instead of acquiring a second scope lock.
    with server_lock(srv["host"], srv["port"]):
        return _read_node_items_locked(srv)


def _read_node_items_locked(srv):
    """Read real remote configuration once for either node cards or a workspace."""
    exit_conns = {}
    ssh = None
    try:
        _require_current_target(srv)
        reading_epochs = CLASH_EXPORTS.scope_epochs((_clash_scope(srv),))
        ssh = connect(srv, timeout=20)
        if run_checked(ssh, "if test -x /usr/local/bin/xray; then echo OK; else echo NO; fi").strip() == "NO":
            CLASH_EXPORTS.rotate_scope(_clash_scope(srv), reading_epochs)
            return {"ok": True, "host": srv["host"], "inbounds": [], "msg": "这台服务器未安装 Xray"}
        cfg = _read_xray_cfg(ssh)
        _require_current_target(srv)
        primary_epochs = CLASH_EXPORTS.rotate_scope(_clash_scope(srv), reading_epochs)
        inbounds = []
        for ib in cfg.get("inbounds", []):
            kind, extra = _inbound_summary(ib)
            item = {"tag": ib.get("tag"), "protocol": ib.get("protocol"), "port": ib.get("port"),
                    "kind": kind, "extra": extra, "link": None, "clash": None, "token": _node_token(srv, ib)}
            if ib.get("protocol") == "dokodemo-door":
                st = ib.get("settings") or {}
                th, tp = st.get("address"), st.get("port")
                exit_srv = next((x for x in load_json(SERVERS_FILE, []) if x["host"] == th), None)
                exit_srv = _resolve_server({"server": exit_srv}, "server") if exit_srv else None
                if exit_srv and tp:
                    try:
                        if th not in exit_conns:
                            _require_current_target(exit_srv)
                            source_epochs = CLASH_EXPORTS.scope_epochs((_clash_scope(exit_srv),))
                            esh = connect(exit_srv, timeout=15)
                            exit_conns[th] = (esh, {}, source_epochs)
                            ecfg = _read_xray_cfg(esh)
                            _require_current_target(exit_srv)
                            exit_conns[th] = (esh, ecfg, source_epochs)
                        esh, ecfg, source_epochs = exit_conns[th]
                        for eib in ecfg.get("inbounds", []):
                            if eib.get("port") == tp and eib.get("protocol") in ("vless", "vmess", "shadowsocks"):
                                item["link"] = _node_link_for_inbound(esh, eib, srv["host"], ib.get("port"))
                                item["clash"] = _register_clash_export(srv, eib, srv["host"], ib.get("port"),
                                                                        item["link"], name=ib.get("tag"), node=ib,
                                                                        source=exit_srv,
                                                                        expected_epochs={**primary_epochs, **source_epochs})
                                item["extra"] = f"→ {th}:{tp}（落地 {exit_srv['name']}）"
                                break
                    except Exception:
                        pass
            else:
                item["link"] = _node_link_for_inbound(ssh, ib, srv["host"], ib.get("port"))
                item["clash"] = _register_clash_export(srv, ib, srv["host"], ib.get("port"), item["link"],
                                                        expected_epochs=primary_epochs)
            if item["clash"] is None:
                item["clash"] = {"available": False, "compatibility": "unsupported",
                                 "notice": "此入站没有可恢复的 Clash 节点配置；中继节点需能读取落地服务器配置。"}
            inbounds.append(item)
        return {"ok": True, "host": srv["host"], "inbounds": inbounds}
    except Exception as e:
        return {"ok": False, "msg": str(e)}
    finally:
        for esh, _, _ in exit_conns.values():
            try:
                esh.close()
            except Exception:
                pass
        if ssh is not None:
            ssh.close()


@app.route("/api/nodes/list", methods=["POST"])
def node_list():
    srv = _resolve_server(request.json or {}, "server")
    if not srv:
        return jsonify(ok=False, msg="服务器无效")
    return jsonify(_read_node_items(srv))


@app.route("/api/clash-workspace/read", methods=["POST"])
def clash_workspace_read():
    data = request.json or {}
    kept_nodes = []
    if isinstance(data, dict) and data.get("snapshot_id") is not None:
        previous = CLASH_SNAPSHOTS.get(data["snapshot_id"])
        if previous is None:
            return jsonify(ok=False, msg="节点记录已过期，请重新导入后读取服务器"), 409
        kept_nodes = [node for node in previous if node.get("origin") in ("import", "saved")]
        if any(CLASH_EXPORTS.get_proxy(node["id"]) is None for node in kept_nodes):
            return jsonify(ok=False, msg="导入节点已过期，请重新导入后读取服务器"), 409
    ids = data.get("server_ids") if isinstance(data, dict) else None
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 16 or
            any(not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", value) for value in ids) or
            len(set(ids)) != len(ids)):
        return jsonify(ok=False, msg="请选择 1-16 台已保存的服务器，不可重复"), 400
    # Resolve every target before connecting; invalid selections cannot cause
    # an incomplete read disguised as a successful inventory.
    servers = [get_server(value) for value in ids]
    if any(not srv for srv in servers):
        return jsonify(ok=False, msg="服务器列表已变化，请刷新后重新选择"), 409
    scopes = [_clash_scope(srv) for srv in servers]
    if len(set(scopes)) != len(scopes):
        return jsonify(ok=False, msg="同一 SSH 地址和端口只需选择一次，请取消重复的服务器"), 400
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="clash-read") as pool:
        results = list(pool.map(_read_node_items, servers))
    nodes, summaries, routing_keys = kept_nodes, [], {}
    for srv, result in zip(servers, results):
        summaries.append({"id": srv["id"], "name": srv["name"],
                          "status": "ok" if result["ok"] else "error", "msg": result.get("msg", "")})
        for item in result.get("inbounds", []):
            clash = item.get("clash") or {}
            if clash.get("available") is True and CLASH_EXPORTS.get_proxy(clash.get("selection_token")) is None:
                clash = {"available": False, "compatibility": "unsupported",
                         "notice": "节点来源在读取期间已变化，请重新读取服务器节点。"}
            routing_key = CLASH_EXPORTS.get_routing_key(clash.get("selection_token"))
            if routing_key:
                routing_keys[clash["selection_token"]] = routing_key
            nodes.append({"id": clash.get("selection_token") or secrets.token_urlsafe(32),
                          "origin": "server",
                          "server_id": srv["id"], "server_name": srv["name"], "host": srv["host"],
                          "name": item.get("tag") or f"{item.get('protocol')}-{item.get('port')}",
                          "protocol": item.get("protocol"), "port": item.get("port"),
                          "available": clash.get("available") is True,
                          "compatibility": clash.get("compatibility", "unsupported"),
                          "notice": clash.get("notice", ""),
                          "routing": {"enabled": False, "direct_domains": [], "revision": 0}})
    stored_routing = NODE_ROUTING_STORE.get_many(routing_keys.values())
    for node in nodes:
        if node["id"] in routing_keys:
            node["routing"] = stored_routing[routing_keys[node["id"]]]
    try:
        snapshot = CLASH_SNAPSHOTS.register(nodes)
    except ValueError as exc:
        return jsonify(ok=False, msg=str(exc)), 400
    return jsonify(ok=True, snapshot_id=snapshot, nodes=nodes, servers=summaries,
                   expires_at=int(time.time() + CLASH_SNAPSHOTS.ttl))


@app.route("/api/clash-workspace/export", methods=["POST"])
def clash_workspace_export():
    data = request.json or {}
    if not isinstance(data, dict):
        return jsonify(ok=False, msg="Clash 配置请求无效"), 400
    snapshot_id, ids, profile = data.get("snapshot_id"), data.get("node_ids"), data.get("profile", {})
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 128 or
            any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value) for value in ids) or
            len(set(ids)) != len(ids)):
        return jsonify(ok=False, msg="请选择 1-128 个有效节点，不可重复"), 400
    inventory = CLASH_SNAPSHOTS.get(snapshot_id)
    if inventory is None:
        return jsonify(ok=False, msg="节点读取记录已过期，请重新读取所选服务器"), 409
    available = {node["id"] for node in inventory if node["available"]}
    if any(value not in available for value in ids):
        return jsonify(ok=False, msg="节点不属于当前读取记录或不能导出，请重新选择"), 400
    proxies = [CLASH_EXPORTS.get_proxy(value) for value in ids]
    if any(proxy is None for proxy in proxies):
        return jsonify(ok=False, msg="节点已重新读取、修改或删除，请重新读取服务器节点"), 409
    try:
        result = build_workspace_configuration(proxies, ids, profile)
        safe_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", profile.get("name", "G-Network"))[:80].strip(". ") or "G-Network"
        filename = safe_name + ".yaml"
        token = CLASH_EXPORTS.register(result["yaml"], ("workspace", snapshot_id), "profile", filename,
                                      dependencies=ids)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return jsonify(ok=False, msg=str(exc)), 400
    url = f"http://127.0.0.1:{app.config['LOCAL_ACCESS_PORT']}/api/clash-export/{token}.yaml"
    warnings = result["warnings"]
    clash = {"available": True, "yaml": result["yaml"], "url": url, "filename": filename,
             "import_url": "clash://install-config?url=" + urllib.parse.quote(url, safe=""),
             "compatibility": "mihomo" if any(compatibility(proxy)[0] == "mihomo" for proxy in proxies) else "classic",
             "notice": " ".join(warnings + [LOCAL_NOTICE])}
    return jsonify(ok=True, clash=clash, node_count=len(proxies), names=result["names"], warnings=warnings,
                   group_count=len(result["config"]["proxy-groups"]), rule_count=len(result["config"]["rules"]))


class _NodeRoutingSourceChanged(ValueError):
    pass


def _node_routing_source(data):
    node_id = data.get("node_id")
    if not isinstance(node_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", node_id):
        raise ValueError("请选择一个有效的节点")
    inventory = CLASH_SNAPSHOTS.get(data.get("snapshot_id"))
    if inventory is None:
        raise _NodeRoutingSourceChanged("节点读取记录已过期，请重新读取所选服务器")
    if not any(node["id"] == node_id and node["available"] for node in inventory):
        raise ValueError("节点不属于当前读取记录或不能导出，请重新选择")
    key = CLASH_EXPORTS.get_routing_key(node_id)
    proxy = CLASH_EXPORTS.get_proxy(node_id)
    if key is None or proxy is None:
        raise _NodeRoutingSourceChanged("节点已重新读取、修改或删除，请重新读取服务器节点")
    return node_id, key, proxy


@app.route("/api/node-routing/save", methods=["POST"])
def node_routing_save():
    data = json_body()
    if set(data) != {"snapshot_id", "node_id", "enabled", "direct_domains", "expected_revision"}:
        return jsonify(ok=False, msg="节点专属分流保存参数无效"), 400
    try:
        with DATA_LOCK:
            node_id, key, _ = _node_routing_source(data)
            with CLASH_EXPORTS.source_guard(node_id, key):
                # The cache guard prevents a concurrent node edit/re-read from
                # authorizing a preference write with an already revoked token.
                routing, changed = NODE_ROUTING_STORE.save(key, data["enabled"], data["direct_domains"],
                                                          data["expected_revision"])
                if changed:
                    CLASH_EXPORTS.revoke_scope(("node-routing", key))
        return jsonify(ok=True, routing=routing)
    except (RoutingConflict, _NodeRoutingSourceChanged, SourceCapabilityChanged) as error:
        return jsonify(ok=False, msg=str(error)), 409
    except (ValueError, TypeError, KeyError) as error:
        return jsonify(ok=False, msg=str(error)), 400
    except OSError:
        return jsonify(ok=False, msg="无法保存本机节点分流设置，请检查用户数据目录"), 500


@app.route("/api/node-routing/export", methods=["POST"])
def node_routing_export():
    data = json_body()
    if (not {"snapshot_id", "node_id"} <= set(data) or
            set(data) - {"snapshot_id", "node_id", "mixed_port", "socks_port", "http_port"}):
        return jsonify(ok=False, msg="节点专属分流导出参数无效"), 400
    try:
        with DATA_LOCK:
            node_id, key, proxy = _node_routing_source(data)
            with CLASH_EXPORTS.source_guard(node_id, key):
                routing = NODE_ROUTING_STORE.get(key)
                scope = ("node-routing", key)
                epochs = CLASH_EXPORTS.scope_epochs((scope,))
        result = build_node_routing(proxy, routing, mixed_port=data.get("mixed_port", 7890),
                                    socks_port=data.get("socks_port", 10808),
                                    http_port=data.get("http_port", 10809))
        with DATA_LOCK:
            current_id, current_key, _ = _node_routing_source(data)
            if (current_id, current_key) != (node_id, key):
                raise _NodeRoutingSourceChanged("节点来源已变化，请重新读取服务器节点")
            with CLASH_EXPORTS.source_guard(node_id, key):
                if NODE_ROUTING_STORE.get(key) != routing:
                    raise _NodeRoutingSourceChanged("节点分流在导出期间已更新，请重新导出")
                clash_result = result["clash"]
                filename = f"G-Network-{proxy['type']}-专属分流.yaml"
                token = CLASH_EXPORTS.register(clash_result["yaml"], scope, "profile", filename,
                                              dependencies=(node_id,), expected_epochs=epochs)
        url = f"http://127.0.0.1:{app.config['LOCAL_ACCESS_PORT']}/api/clash-export/{token}.yaml"
        kind, notice = compatibility(proxy)
        clash = {"available": True, "yaml": clash_result["yaml"], "url": url, "filename": filename,
                 "import_url": "clash://install-config?url=" + urllib.parse.quote(url, safe=""),
                 "compatibility": kind,
                 "notice": notice + " 仅本节点的域名名单参与此配置分流；Clash 请使用规则模式。 " + LOCAL_NOTICE}
        xray_result = result["xray"]
        if xray_result.get("available", True):
            xray = {"available": True, "json": xray_result["json"],
                    "filename": f"G-Network-{proxy['type']}-专属分流.json",
                    "notice": "完整 Xray 客户端配置，须由兼容客户端加载；单条分享链接不携带分流规则。"}
        else:
            xray = {"available": False, "notice": xray_result["notice"]}
        return jsonify(ok=True, routing=routing, clash=clash, xray=xray, warnings=result["warnings"])
    except (RoutingConflict, _NodeRoutingSourceChanged, SourceCapabilityChanged) as error:
        return jsonify(ok=False, msg=str(error)), 409
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        return jsonify(ok=False, msg=str(error)), 400
    except OSError:
        return jsonify(ok=False, msg="无法读取本机节点分流设置，请检查用户数据目录"), 500


@app.route("/api/nodes/delete", methods=["POST"])
def node_delete():
    import hmac
    d = request.json or {}
    srv = _resolve_server(d, "server")
    tag = d.get("tag") if isinstance(d, dict) else None
    token = d.get("token") if isinstance(d, dict) else None
    if not srv:
        return jsonify(ok=False, msg="服务器无效")
    if not isinstance(tag, str) or not tag:
        return jsonify(ok=False, msg="缺少节点标识 tag")
    if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
        return jsonify(ok=False, msg="缺少有效的节点列表凭据，请重新读取列表后删除")
    with server_lock(srv["host"], srv["port"]):
        ssh = None
        try:
            ssh = connect(srv, timeout=20)
            before = _read_xray_cfg(ssh)
            indices = [index for index, ib in enumerate(before.get("inbounds", []))
                       if ib.get("tag") == tag and hmac.compare_digest(_node_token(srv, ib), token)]
            if len(indices) != 1:
                return jsonify(ok=False, msg="服务器或入站配置已变化，请重新读取列表后删除")
            cfg = copy.deepcopy(before)
            del cfg["inbounds"][indices[0]]
            _apply_xray_cfg(ssh, cfg, expected=before)
            CLASH_EXPORTS.revoke_node(_clash_scope(srv), token)
            return jsonify(ok=True, msg=f"已删除 {tag}，配置已备份并重启生效")
        except Exception as e:
            return jsonify(ok=False, msg=str(e))
        finally:
            if ssh is not None:
                ssh.close()


forwarders = {}
FORWARD_LOCK = threading.RLock()


def stop_forwarders(sid=None):
    with FORWARD_LOCK:
        for key, state in list(forwarders.items()):
            if sid is not None and key[0] != sid:
                continue
            state["alive"] = False
            for resource in (state.get("socket"), state.get("ssh")):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass
            forwarders.pop(key, None)


def shutdown_resources():
    """Release only SSH clients, tunnels and download buffers owned by this app.

    The desktop launcher calls this after stopping its HTTP listener. It closes
    remote channels and prevents workers still connecting from reopening them;
    it does not terminate unrelated processes or delete saved user data.
    """
    global _SHUTTING_DOWN, _ACCEPTING_JOBS
    CLASH_EXPORTS.clear()
    CLASH_IMPORT_PREVIEWS.clear()
    CLASH_SNAPSHOTS.clear()
    with JOB_LOCK:
        _ACCEPTING_JOBS = False
    with RESOURCE_LOCK:
        if _SHUTTING_DOWN:
            return
        _SHUTTING_DOWN = True
        resources = list(_OPEN_RESOURCES)
        _OPEN_RESOURCES.clear()
    stop_forwarders()
    for resource in resources:
        try:
            resource.close()
        except Exception:
            pass


atexit.register(shutdown_resources)

def start_forward(sid, remote_port):
    """在本地开一个端口，把流量经 SSH 隧道转发到服务器的 127.0.0.1:remote_port。"""
    key = (sid, remote_port)
    old = forwarders.get(key)
    if old and old.get("alive") and old["ssh"].get_transport() and old["ssh"].get_transport().is_active():
        return old["port"]
    if old:
        stop_forwarders(sid)
    s = get_server(sid)
    ssh = connect(s)
    transport = ssh.get_transport()
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        lsock.bind(("127.0.0.1", 0))
    except Exception:
        lsock.close()
        ssh.close()
        raise
    lport = lsock.getsockname()[1]
    lsock.listen(50)
    lsock.settimeout(1)
    state = {"port": lport, "alive": True, "ssh": ssh, "socket": lsock}
    forwarders[key] = state
    def pipe(a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                b.sendall(data)
        except Exception:
            pass
        finally:
            for x in (a, b):
                try: x.close()
                except Exception: pass
    def accept_loop():
        while state["alive"]:
            try:
                client, _ = lsock.accept()
            except socket.timeout:
                if not transport.is_active():
                    break
                continue
            except Exception:
                break
            try:
                chan = transport.open_channel("direct-tcpip", ("127.0.0.1", remote_port), client.getpeername())
            except Exception:
                client.close()
                continue
            threading.Thread(target=pipe, args=(client, chan), daemon=True).start()
            threading.Thread(target=pipe, args=(chan, client), daemon=True).start()
        state["alive"] = False
        lsock.close()
        ssh.close()
    threading.Thread(target=accept_loop, daemon=True).start()
    return lport

@app.route("/api/servers/<sid>/open_dsh", methods=["POST"])
def open_dsh(sid):
    ssh = None
    try:
        ssh = connect(get_server(sid))
        binary = sh(ssh, "command -v dsh || echo NO")
        if binary == "NO":
            return jsonify(ok=False, msg="这台服务器还没装 dsh，请先到「一键工具箱」安装 DeepSeek Harness")
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", binary):
            raise ValueError("dsh 安装路径不支持，请使用系统级安装")
        if sh(ssh, "systemctl is-active dsh-web 2>/dev/null || true") != "active":
            require_service_permissions(ssh)
            key = load_json(SETTINGS_FILE, {}).get("deepseek_key", "")
            svc = ("[Unit]\nDescription=DeepSeek Harness Web UI\nAfter=network-online.target\n\n"
                   "[Service]\nEnvironment=" + json.dumps("DEEPSEEK_API_KEY=" + key, ensure_ascii=False) + "\n"
                   "ExecStart=" + binary + " web --no-open\nRestart=on-failure\nRestartSec=5\n\n"
                   "[Install]\nWantedBy=multi-user.target\n")
            encoded = base64.b64encode(svc.encode()).decode()
            sh(ssh, "printf '%s' '" + encoded + "' | base64 -d > /etc/systemd/system/dsh-web.service && "
                    "chmod 600 /etc/systemd/system/dsh-web.service && systemctl daemon-reload && "
                    "systemctl enable --now dsh-web && sleep 6 && systemctl is-active dsh-web", timeout=120)
        tok = sh(ssh, "journalctl -u dsh-web --no-pager | grep -oE 'token=[A-Za-z0-9_-]+' | tail -1 | cut -d= -f2")
        if not tok:
            return jsonify(ok=False, msg="dsh 服务未能产出登录 token，请到终端运行 journalctl -u dsh-web 查看原因")
        with FORWARD_LOCK:
            port = start_forward(sid, 3080)
        return jsonify(ok=True, url=f"http://127.0.0.1:{port}/?token={tok}")
    except Exception as e:
        return jsonify(ok=False, msg=str(e))
    finally:
        if ssh is not None:
            ssh.close()


@app.route("/api/servers/<sid>/close_dsh", methods=["POST"])
def close_dsh(sid):
    stop_forwarders(sid)
    return jsonify(ok=True)

@app.route("/api/servers/<sid>/rdp", methods=["POST"])
def rdp(sid):
    s = get_server(sid)
    if not s:
        raise ValueError("服务器不存在")
    if s.get("auth_type", "password") != "password" or not s.get("password"):
        raise ValueError("远程桌面需要账号密码；SSH 私钥或 Agent 不能作为 RDP 密码，请在远程桌面客户端单独登录")
    # 凭据预存进 Windows 凭据管理器，mstsc 自动带出
    result = subprocess.run(["cmdkey", f"/generic:TERMSRV/{s['host']}", f"/user:{s['user']}", f"/pass:{s['password']}"],
                            capture_output=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError("Windows 远程桌面凭据保存失败")
    subprocess.Popen(["mstsc", f"/v:{s['host']}"], creationflags=subprocess.CREATE_NO_WINDOW)
    return jsonify(ok=True)

@app.route("/api/servers/<sid>/rdp_logout", methods=["POST"])
def rdp_logout(sid):
    """注销远程桌面：先结束 xfce 会话让 sesman 正常收尾，再补刀清理残留 Xorg。"""
    try:
        s = get_server(sid)
        if not s:
            raise ValueError("服务器不存在")
        user = shlex.quote(validate_user(s["user"]))
        with ssh_connection(sid) as ssh:
            out = sh(ssh, f"pkill -u {user} -x xfce4-session 2>/dev/null || true; sleep 2; "
                          f"if pgrep -u {user} -x xfce4-session >/dev/null; then echo '仍有桌面会话'; exit 1; fi; echo '当前用户桌面会话已注销'")
        return jsonify(ok=True, msg=out)
    except Exception as e:
        return jsonify(ok=False, msg=str(e))

# ---------- Web 终端 ----------
@sock.route("/ws/terminal/<sid>")
def terminal(ws, sid):
    s = get_server(sid)
    if not s:
        ws.close()
        return
    ssh = None
    try:
        ssh = connect(s)
        chan = ssh.invoke_shell(term="xterm-256color", width=120, height=32)
    except Exception as e:
        try:
            ws.send(f"\r\n\x1b[31m连接失败: {e}\x1b[0m\r\n")
        finally:
            if ssh is not None:
                ssh.close()
            ws.close()
        return
    def pump():
        # 阻塞式读取：客户端断开时 finally 会关闭 chan，recv 自然返回 b'' 退出
        try:
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            while True:
                data = chan.recv(4096)
                if not data:
                    break
                try:
                    text = decoder.decode(data)
                    if text:
                        ws.send(text)
                except Exception:
                    break
        except Exception:
            pass
        finally:
            try:
                ws.close()
            except Exception:
                pass
    threading.Thread(target=pump, daemon=True).start()
    try:
        while True:
            msg = ws.receive()
            if msg is None:
                break
            try:
                j = json.loads(msg)
                if not isinstance(j, dict):
                    continue
                if j.get("type") == "input" and isinstance(j.get("data"), str):
                    if len(j["data"]) <= 65536:
                        chan.sendall(j["data"])
                elif j.get("type") == "resize":
                    cols, rows = int(j["cols"]), int(j["rows"])
                    if 2 <= cols <= 1000 and 2 <= rows <= 1000:
                        chan.resize_pty(width=cols, height=rows)
            except (json.JSONDecodeError, TypeError, ValueError, KeyError):
                continue
    finally:
        try:
            chan.close(); ssh.close()
        except Exception:
            pass

if DESKTOP_DATA:
    from product_integration import register_desktop_product
    register_desktop_product(sys.modules[__name__])

if __name__ == "__main__":
    import webbrowser
    if not os.environ.get("SERVER_MANAGER_NO_BROWSER"):
        threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:8620")).start()
    print("服务器管家已启动: http://127.0.0.1:8620")
    app.run(host="127.0.0.1", port=8620, debug=False)
