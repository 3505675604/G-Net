# -*- coding: utf-8 -*-
"""Shared import-safe helpers for standalone SSH tools."""
import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sys
import tempfile
import threading
import time

import paramiko
from local_security import validate_auth, validate_host, validate_port, validate_user
from remote_ops import run_checked

HERE = Path(__file__).resolve().parent
_known_hosts_thread_lock = threading.RLock()


class HostIdentityError(ValueError):
    def __init__(self, changed=False):
        self.code = "host_key_changed" if changed else "host_key_required"
        super().__init__("SSH 主机身份已变化，连接已停止；请检查自动更新设置或重新核对服务器指纹" if changed
                         else "SSH 主机身份尚未确认，请先核对并确认主机指纹")


class _RequireConfirmedHostKey(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        raise HostIdentityError()


def _host_key_name(host, port):
    return host if port == 22 else f"[{host}]:{port}"


def _fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")


def _identity_client(path):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if path.exists():
        client.load_host_keys(str(path))
    return client


def _known_identity(client, token, key):
    local = client.get_host_keys().lookup(token)
    system = client._system_host_keys.lookup(token)
    existing = local or system
    return bool(existing), bool(existing and (key.get_name() not in existing or existing[key.get_name()] != key))


def _matches_host_alias(token, alias):
    if alias == token:
        return True
    if alias.startswith("|1|"):
        try:
            return paramiko.HostKeys.hash_host(token, alias) == alias
        except (ValueError, TypeError):
            return False
    return False


def _store_observed_host_key(path, token, key, before):
    """Atomically replace only this application's exact host/port entry.

    Keep unrelated records, comments and combined aliases. A changed file
    means a concurrent writer was not participating in our lock: stop rather
    than silently overwrite that writer's changes.
    """
    output = []
    for line in before.decode("utf-8").splitlines(keepends=True):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            output.append(line)
            continue
        try:
            entry = paramiko.hostkeys.HostKeyEntry.from_line(stripped)
        except paramiko.SSHException:
            entry = None
        if entry is None or not any(_matches_host_alias(token, alias) for alias in entry.hostnames):
            output.append(line)
            continue
        entry.hostnames = [alias for alias in entry.hostnames if not _matches_host_alias(token, alias)]
        if entry.hostnames:
            output.append(entry.to_line())
    text = "".join(output)
    if text and not text.endswith(("\n", "\r")):
        text += "\n"
    payload = (text + paramiko.hostkeys.HostKeyEntry([token], key).to_line()).encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        current = path.read_bytes() if path.exists() else b""
        if current != before:
            raise ValueError("SSH 主机身份记录被其他程序修改，请重新读取后再连接")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _observed_identity(client, host, port, path, expected_fingerprint, timeout, auto_update_host_key,
                       before=None):
    token = _host_key_name(host, port)
    current = path.read_bytes() if path.exists() else b""
    before = current if before is None else before
    if current != before:
        raise ValueError("SSH 主机身份记录被其他程序修改，请重新读取后再连接")
    existing = client.get_host_keys().lookup(token) or client._system_host_keys.lookup(token)
    key = _probe_host_key(host, port, tuple(existing.keys()) if existing else (), timeout=timeout)
    if (path.read_bytes() if path.exists() else b"") != before:
        raise ValueError("SSH 主机身份记录被其他程序修改，请重新读取后再连接")
    fingerprint = _fingerprint(key)
    known, changed = _known_identity(client, token, key)
    previous_key = (existing.get(key.get_name()) or next(iter(existing.values()))) if existing else None
    previous_fingerprint = _fingerprint(previous_key) if changed else None
    if expected_fingerprint is not None and expected_fingerprint != fingerprint:
        raise ValueError("SSH 主机指纹与确认时不一致，请重新读取并核对")
    updated = False
    if changed and auto_update_host_key:
        _store_observed_host_key(path, token, key, before)
        known, changed, updated = True, False, True
    elif changed and expected_fingerprint is not None:
        raise HostIdentityError(changed=True)
    elif not known and expected_fingerprint is not None:
        _store_observed_host_key(path, token, key, before)
        known = True
    result = {"host": host, "port": port, "algorithm": key.get_name(), "fingerprint": fingerprint,
              "known": known, "changed": changed, "updated": updated,
              "previous_fingerprint": previous_fingerprint,
              "auto_update_enabled": auto_update_host_key}
    return result, key


def _without_host_token(keys, token):
    remaining = paramiko.HostKeys()
    for alias in keys.keys():
        if _matches_host_alias(token, alias):
            continue
        for algorithm, key in keys.lookup(alias).items():
            remaining.add(alias, algorithm, key)
    return remaining


def _pin_observed_key(client, token, key):
    # Paramiko normally prioritizes the system store over the application
    # store. Use a connection-local exact pin so a stale system entry cannot
    # override an app-managed replacement. The system file is never written.
    client._system_host_keys = _without_host_token(client._system_host_keys, token)
    client._host_keys = _without_host_token(client.get_host_keys(), token)
    client.get_host_keys().add(token, key.get_name(), key)


def _probe_host_key(host, port, algorithms=(), timeout=10):
    sock, transport = None, None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        transport = paramiko.Transport(sock)
        if algorithms:
            options = transport.get_security_options()
            preferred = set(algorithms)
            if "ssh-rsa" in preferred:
                preferred.update(("rsa-sha2-256", "rsa-sha2-512"))
            options.key_types = tuple(sorted(options.key_types, key=lambda name: name not in preferred))
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    except Exception:
        raise ValueError("无法读取 SSH 主机指纹，请检查地址、端口、网络与 SSH 服务") from None
    finally:
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()


def host_identity(host, port=22, known_hosts_path=None, expected_fingerprint=None, timeout=10,
                  auto_update_host_key=False):
    """Probe without authentication; enroll first use or refresh known targets."""
    host, port = validate_host(host), validate_port(port)
    path = Path(known_hosts_path or HERE / "known_hosts").expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(auto_update_host_key, bool):
        raise ValueError("SSH 自动更新身份设置必须是布尔值")
    if expected_fingerprint is not None and (not isinstance(expected_fingerprint, str)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", expected_fingerprint)):
        raise ValueError("SSH 主机指纹格式无效")
    with _known_hosts_lock(path):
        before = path.read_bytes() if path.exists() else b""
        client = _identity_client(path)
        try:
            result, _ = _observed_identity(client, host, port, path, expected_fingerprint, timeout,
                                           auto_update_host_key, before=before)
            return result
        finally:
            client.close()


@dataclass(frozen=True)
class SSHOptions:
    host: str
    password: str = field(repr=False)
    user: str = "root"
    port: int = 22
    known_hosts_path: str = None
    auth_type: str = "password"
    private_key: str = field(default="", repr=False)
    key_passphrase: str = field(default="", repr=False)


def ssh_options(env=None, host=None):
    env = os.environ if env is None else env
    host = validate_host(host if host is not None else env.get("SSH_HOST", ""))
    auth = validate_auth({"auth_type": env.get("SSH_AUTH_TYPE", "password"),
                          "password": env.get("SSHPASS", ""),
                          "private_key": env.get("SSH_PRIVATE_KEY", ""),
                          "key_passphrase": env.get("SSH_KEY_PASSPHRASE", "")})
    user = validate_user(env.get("SSH_USER", "root"))
    try:
        port = validate_port(env.get("SSH_PORT", "22"))
    except (TypeError, ValueError):
        raise ValueError("SSH_PORT 必须为 1-65535 的整数") from None
    if auth["auth_type"] == "private_key":
        parse_private_key(auth["private_key"], auth.get("key_passphrase", ""))
    return SSHOptions(host, auth.get("password", ""), user, port, env.get("SSH_KNOWN_HOSTS"),
                      auth["auth_type"], auth.get("private_key", ""), auth.get("key_passphrase", ""))


@contextmanager
def _known_hosts_lock(path):
    """Serialize first-use enrollment across threads and local processes."""
    with _known_hosts_thread_lock:
        lock_file = open(str(path) + ".lock", "a+b")
        acquired = False
        try:
            if os.name == "nt":
                import msvcrt
                lock_file.seek(0, os.SEEK_END)
                if not lock_file.tell():
                    lock_file.write(b"\0")
                    lock_file.flush()
                deadline = time.monotonic() + 60
                while True:
                    try:
                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                        acquired = True
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("SSH 主机身份文件被其他进程占用，请稍后重试")
                        time.sleep(0.05)
            else:
                import fcntl
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                acquired = True
            yield
        finally:
            if acquired:
                if os.name == "nt":
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()


class _PersistFirstHostKey(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        # Paramiko rejects changed known keys before calling this policy.
        client.get_host_keys().add(hostname, key.get_name(), key)
        path = Path(client._host_keys_filename)
        fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
        os.close(fd)
        try:
            client.save_host_keys(temporary)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print(f"首次保存 SSH 主机身份：{hostname} SHA256:{fingerprint}", flush=True)


def parse_private_key(text, passphrase=""):
    """Parse RSA/ECDSA/Ed25519 PEM or OpenSSH text entirely in memory.

    Error messages are fixed: cryptographic parsers may include input details.
    No key filename is accepted or temporarily created.
    """
    auth = validate_auth({"auth_type": "private_key", "private_key": text, "key_passphrase": passphrase})
    text, passphrase = auth["private_key"].strip() + "\n", auth["key_passphrase"] or None
    for key_type in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            return key_type.from_private_key(io.StringIO(text), password=passphrase)
        except Exception:
            pass
    # PKCS#8 PEM is also common in uploaded keys. Normalize it in memory to a
    # representation understood by Paramiko rather than accepting file paths.
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
        encoded = text.encode("utf-8")
        password_bytes = None if passphrase is None else passphrase.encode("utf-8")
        if text.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
            key = serialization.load_ssh_private_key(encoded, password=password_bytes)
        else:
            try:
                key = serialization.load_pem_private_key(encoded, password=password_bytes)
            except TypeError:
                # An unnecessary saved passphrase must not prevent importing an
                # unencrypted replacement key; this does not bypass encryption.
                key = serialization.load_pem_private_key(encoded, password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            target, fmt = paramiko.RSAKey, serialization.PrivateFormat.TraditionalOpenSSL
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            target, fmt = paramiko.ECDSAKey, serialization.PrivateFormat.TraditionalOpenSSL
        elif isinstance(key, ed25519.Ed25519PrivateKey):
            target, fmt = paramiko.Ed25519Key, serialization.PrivateFormat.OpenSSH
        else:
            raise ValueError("unsupported key")
        normalized = key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption()).decode("ascii")
        return target.from_private_key(io.StringIO(normalized))
    except Exception:
        raise ValueError("私钥格式、算法或口令无效；请使用 RSA、Ed25519 或 ECDSA 的完整私钥文本") from None


def connect_ssh(host, port=22, user="root", password="", timeout=15, known_hosts_path=None,
                auth_type="password", private_key="", key_passphrase="", trust_new_host=True,
                auto_update_host_key=False):
    """Verify identity before authentication, optionally refresh known targets."""
    host, port, user = validate_host(host), validate_port(port), validate_user(user)
    auth = validate_auth({"auth_type": auth_type, "password": password,
                          "private_key": private_key, "key_passphrase": key_passphrase})
    if not isinstance(auto_update_host_key, bool):
        raise ValueError("SSH 自动更新身份设置必须是布尔值")
    pkey = parse_private_key(private_key, key_passphrase) if auth_type == "private_key" else None
    path = Path(known_hosts_path or HERE / "known_hosts").expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    ssh = paramiko.SSHClient()
    try:
        with _known_hosts_lock(path):
            if not path.exists():
                fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            before = path.read_bytes()
            ssh.load_system_host_keys()
            ssh.load_host_keys(str(path))
            ssh.set_missing_host_key_policy(_PersistFirstHostKey() if trust_new_host else _RequireConfirmedHostKey())
            token = _host_key_name(host, port)
            if auto_update_host_key:
                identity, observed_key = _observed_identity(ssh, host, port, path, None, timeout, True,
                                                            before=before)
                if not identity["known"]:
                    raise HostIdentityError()
                # Revalidate on the actual authenticated connection. A second
                # change raises before Paramiko sends any authentication data.
                _pin_observed_key(ssh, token, observed_key)
                ssh._host_identity = identity
                ssh.set_missing_host_key_policy(_RequireConfirmedHostKey())
            elif ssh.get_host_keys().lookup(token):
                # App-managed exact host/port records win in this one client;
                # no system trust file is modified or globally bypassed.
                ssh._system_host_keys = _without_host_token(ssh._system_host_keys, token)
            ssh.connect(host, port=int(port), username=user,
                        password=auth.get("password") if auth_type == "password" else None,
                        pkey=pkey, allow_agent=auth_type == "agent", look_for_keys=False,
                        timeout=timeout, auth_timeout=timeout, banner_timeout=timeout)
        return ssh
    except paramiko.BadHostKeyException:
        ssh.close()
        if not trust_new_host:
            raise HostIdentityError(changed=True) from None
        raise
    except paramiko.AuthenticationException:
        ssh.close()
        raise ValueError("SSH 认证失败，请检查所选认证方式、用户名与凭据；Agent 模式需本机 Agent 中有可用身份") from None
    except BaseException:
        ssh.close()
        raise


@contextmanager
def ssh_connection(options):
    ssh = connect_ssh(options.host, port=options.port, user=options.user,
                      password=options.password, known_hosts_path=options.known_hosts_path,
                      timeout=20, auth_type=options.auth_type,
                      private_key=options.private_key, key_passphrase=options.key_passphrase)
    try:
        yield ssh
    finally:
        ssh.close()


class _SudoSSH:
    def __init__(self, ssh):
        self.ssh = ssh

    def exec_command(self, command, **kwargs):
        return self.ssh.exec_command("sudo -n bash -c " + shlex.quote(command), **kwargs)

    def __getattr__(self, name):
        return getattr(self.ssh, name)


def elevated_ssh(ssh):
    if run_checked(ssh, "id -u").strip() == "0":
        return ssh
    run_checked(ssh, "sudo -n true")
    return _SudoSSH(ssh)


def run(ssh, command, timeout=300, label=None):
    # Commands may contain API/private keys; only print descriptive labels.
    if label:
        print(f">>> {label}", flush=True)
    output = run_checked(ssh, "bash -e -o pipefail -c " + shlex.quote(command), timeout=timeout)
    if output.strip():
        print(output[-3000:], flush=True)
    return output


def microsoft_edge_repository_script():
    """Prepare Microsoft's APT key without prompts or truncating a live keyring."""
    return r'''(
set -Eeuo pipefail
umask 077
task_edge_keyring=/usr/share/keyrings/microsoft.gpg
task_edge_list=/etc/apt/sources.list.d/microsoft-edge.list
for task_edge_target in "$task_edge_keyring" "$task_edge_list"; do
  if [ -L "$task_edge_target" ] || { [ -e "$task_edge_target" ] && [ ! -f "$task_edge_target" ]; }; then
    echo 'Edge 仓库文件不是普通文件，未覆盖；请人工检查。' >&2; exit 1
  fi
done
task_edge_tmp="$(mktemp -d /usr/share/keyrings/.g-network-edge.XXXXXXXX)"
task_edge_list_tmp=''
trap 'rm -rf -- "$task_edge_tmp"; [ -z "$task_edge_list_tmp" ] || rm -f -- "$task_edge_list_tmp"' EXIT
mkdir -m 700 "$task_edge_tmp/gnupg"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 90 \
  https://packages.microsoft.com/keys/microsoft.asc --output "$task_edge_tmp/microsoft.asc"
gpg --homedir "$task_edge_tmp/gnupg" --batch --yes --no-tty --dearmor \
  --output "$task_edge_tmp/microsoft.gpg" "$task_edge_tmp/microsoft.asc"
test -s "$task_edge_tmp/microsoft.gpg" || { echo 'Microsoft 公钥转换结果为空，旧仓库配置保留。' >&2; exit 1; }
gpg --homedir "$task_edge_tmp/gnupg" --batch --yes --no-tty --with-colons \
  --show-keys "$task_edge_tmp/microsoft.gpg" > "$task_edge_tmp/key-info"
grep -q '^pub:' "$task_edge_tmp/key-info" || { echo 'Microsoft 下载内容不是有效公钥，旧仓库配置保留。' >&2; exit 1; }
task_edge_list_tmp="$(mktemp /etc/apt/sources.list.d/.g-network-edge.XXXXXXXX)"
printf '%s\n' 'deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/edge stable main' > "$task_edge_list_tmp"
chmod 644 "$task_edge_tmp/microsoft.gpg" "$task_edge_list_tmp"
for task_edge_target in "$task_edge_keyring" "$task_edge_list"; do
  if [ -L "$task_edge_target" ] || { [ -e "$task_edge_target" ] && [ ! -f "$task_edge_target" ]; }; then
    echo 'Edge 仓库文件在准备期间发生变化，停止覆盖。' >&2; exit 1
  fi
done
mv -f -- "$task_edge_tmp/microsoft.gpg" "$task_edge_keyring"
mv -f -- "$task_edge_list_tmp" "$task_edge_list"
)
'''


def user_home(ssh, user):
    parts = run_checked(ssh, "getent passwd " + shlex.quote(user)).strip().split(":")
    if len(parts) != 7 or not parts[5].startswith("/"):
        raise RuntimeError(f"无法确定远端用户 {user} 的主目录")
    return parts[5]


def write_json(path, data):
    path = Path(path)
    fd, temp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def cli(main):
    try:
        main()
        return 0
    except Exception as error:
        print(f"执行失败：{error}", file=sys.stderr, flush=True)
        return 1


BBR_TUNING = """cat > /etc/sysctl.d/99-bbr-tune.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fastopen = 3
EOF
sysctl --system
sysctl net.ipv4.tcp_congestion_control"""

SOCKOPT = {"tcpFastOpen": True, "tcpNoDelay": True, "tcpCongestion": "bbr",
           "tcpKeepAliveInterval": 30}
