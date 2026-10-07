# -*- coding: utf-8 -*-
"""Install XFCE, xrdp, Chrome and Edge on Debian/Ubuntu amd64.
Env: SSH_HOST, SSHPASS, SSH_USER (root), SSH_PORT (22).
"""
import os
import shlex
import sys

from remote_ops import listening_ports, run_checked
from script_common import (cli, elevated_ssh, microsoft_edge_repository_script,
                           run, ssh_connection, ssh_options, user_home)


def require_amd64_debian(ssh):
    system = run_checked(ssh, "uname -s").strip()
    machine = run_checked(ssh, "uname -m").strip()
    if system != "Linux" or machine not in ("x86_64", "amd64"):
        raise RuntimeError("桌面浏览器安装仅支持 Linux amd64/x86_64，已中止且未安装软件")
    run_checked(ssh, "command -v apt-get >/dev/null && command -v dpkg >/dev/null")
    if run_checked(ssh, "dpkg --print-architecture").strip() != "amd64":
        raise RuntimeError("Chrome / Edge 的安装包要求 Debian/Ubuntu amd64，已中止")


def root_browser_launchers(home, user):
    if user != "root":
        return ""
    # Keep flags in this user's copies; other users retain sandboxed launchers.
    return rf"""task_menu={shlex.quote(home + '/.local/share/applications')}
task_desktop={shlex.quote(home + '/Desktop')}
mkdir -p -- "$task_menu" "$task_desktop"
for task_browser in google-chrome microsoft-edge; do
task_source="/usr/share/applications/$task_browser.desktop"
test -f "$task_source"
task_target="$task_menu/$task_browser.desktop"
cp -- "$task_source" "$task_target"
sed -i -E '/^Exec=.*--no-sandbox/! s|^Exec=([^[:space:]]+)|Exec=\1 --no-sandbox|' "$task_target"
cp -- "$task_target" "$task_desktop/$task_browser.desktop"
chmod 755 "$task_desktop/$task_browser.desktop"
done"""


def main(env=None):
    options = ssh_options(os.environ if env is None else env)
    with ssh_connection(options) as raw_ssh:
        ssh = elevated_ssh(raw_ssh)
        require_amd64_debian(ssh)
        home = user_home(raw_ssh, options.user)
        run(ssh, "free -m; df -h /", label="检查资源")
        run(ssh, """if [ -z "$(swapon --noheadings --show)" ]; then
if [ -e /swapfile ]; then echo '/swapfile 已存在且未启用，请人工检查，避免覆盖现有文件' >&2; exit 1; fi
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
grep -qE '^/swapfile[[:space:]]' /etc/fstab || printf '%s\\n' '/swapfile none swap sw 0 0' >> /etc/fstab
fi
free -m""", label="检查或创建 2G swap")
        run(ssh, """export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y xfce4 xfce4-terminal dbus-x11 xrdp curl wget gnupg ca-certificates""",
            timeout=1800, label="安装 XFCE 与 xrdp")
        session = shlex.quote(home + "/.xsession")
        run(ssh, f"""printf '%s\\n' xfce4-session > {session}
chown {shlex.quote(options.user)} {session}
adduser xrdp ssl-cert
systemctl enable xrdp
systemctl restart xrdp
test "$(systemctl is-active xrdp)" = active""", label="配置桌面会话与 xrdp")
        run(ssh, """task_tmp=$(mktemp -d)
trap 'rm -rf -- "$task_tmp"' EXIT
wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O "$task_tmp/chrome.deb"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y "$task_tmp/chrome.deb"
google-chrome --version""", timeout=900, label="安装 Chrome")
        run(ssh, microsoft_edge_repository_script() + """export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y microsoft-edge-stable
microsoft-edge --version""", timeout=900, label="安装 Edge")
        launchers = root_browser_launchers(home, options.user)
        if launchers:
            run(ssh, launchers, label="配置 root 桌面的浏览器启动入口")
        if 3389 not in listening_ports(ssh):
            raise RuntimeError("xrdp 未监听 TCP 3389，安装未完成")
        run(ssh, "free -m; df -h /", label="复核安装资源")
    print("\n>>> desktop install done on " + options.host, flush=True)


if __name__ == "__main__":
    sys.exit(cli(main))
