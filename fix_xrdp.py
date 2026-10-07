# -*- coding: utf-8 -*-
"""Disable the XFCE compositor and verify xrdp on one or more VPS.
Env: SSH_HOSTS (comma separated, or SSH_HOST), SSHPASS, SSH_USER, SSH_PORT.
"""
import os
import shlex
import sys

from remote_ops import listening_ports
from script_common import cli, elevated_ssh, run, ssh_connection, ssh_options, user_home


def compositor_script(home, user):
    path = home + "/.config/xfce4/xfconf/xfce-perchannel-xml/xfwm4.xml"
    return f"""python3 - {shlex.quote(path)} {shlex.quote(user)} <<'PY'
import os, pwd, sys, tempfile
import xml.etree.ElementTree as ET
path, user = sys.argv[1:]
tree = ET.parse(path)
root = tree.getroot()
found = False
for item in root.iter('property'):
    if item.get('name') == 'use_compositing':
        item.set('type', 'bool')
        item.set('value', 'false')
        found = True
if not found:
    ET.SubElement(root, 'property', name='use_compositing', type='bool', value='false')
fd, temporary = tempfile.mkstemp(prefix='xfwm4-', suffix='.xml', dir=os.path.dirname(path))
try:
    with os.fdopen(fd, 'wb') as stream:
        tree.write(stream, encoding='utf-8', xml_declaration=True)
    user_info = pwd.getpwnam(user)
    os.chmod(temporary, os.stat(path).st_mode & 0o777)
    os.chown(temporary, user_info.pw_uid, user_info.pw_gid)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
print('XFCE compositor disabled')
PY"""


def main(env=None):
    env = os.environ if env is None else env
    hosts = [h.strip() for h in env.get("SSH_HOSTS", env.get("SSH_HOST", "")).split(",") if h.strip()]
    if not hosts:
        raise ValueError("请设置 SSH_HOSTS（多台用逗号分隔）或 SSH_HOST")
    # Validate all required environment values before contacting any host.
    options = [ssh_options(env, host) for host in hosts]
    errors = []
    for option in options:
        print("===== " + option.host, flush=True)
        try:
            with ssh_connection(option) as raw_ssh:
                ssh = elevated_ssh(raw_ssh)
                home = user_home(raw_ssh, option.user)
                run(ssh, "pgrep -af Xorg || echo no-xorg-left", label="检查 Xorg")
                run(ssh, compositor_script(home, option.user), label="关闭 XFCE 合成器")
                run(ssh, "test \"$(systemctl is-active xrdp)\" = active", label="检查 xrdp 服务")
                if 3389 not in listening_ports(ssh):
                    raise RuntimeError("xrdp 未监听 TCP 3389")
                run(ssh, "tail -5 /var/log/xrdp-sesman.log", label="检查 xrdp 日志")
        except Exception as error:
            errors.append(f"{option.host}: {error}")
    if errors:
        raise RuntimeError("部分服务器修复失败：\n" + "\n".join(errors))
    print(">>> xrdp checks done", flush=True)


if __name__ == "__main__":
    sys.exit(cli(main))
