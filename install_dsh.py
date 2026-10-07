# -*- coding: utf-8 -*-
"""Install DeepSeek Harness CLI. Env: SSH_HOST, SSHPASS, SSH_USER, SSH_PORT.
Optional DEEPSEEK_API_KEY is stored in the selected user's private shell profile.
"""
import os
import shlex
import sys

from script_common import cli, elevated_ssh, run, ssh_connection, ssh_options, user_home


def credentials_script(home, user, api_key):
    env_path, profile = home + "/.dsh-env", home + "/.bashrc"
    assignment = "export DEEPSEEK_API_KEY=" + shlex.quote(api_key)
    source = ". " + shlex.quote(env_path)
    return f"""umask 077
printf '%s\\n' {shlex.quote(assignment)} > {shlex.quote(env_path)}
chmod 600 {shlex.quote(env_path)}
touch {shlex.quote(profile)}
grep -qxF -- {shlex.quote(source)} {shlex.quote(profile)} || printf '%s\\n' {shlex.quote(source)} >> {shlex.quote(profile)}
chown {shlex.quote(user)} {shlex.quote(env_path)} {shlex.quote(profile)}"""


def main(env=None):
    env = os.environ if env is None else env
    options = ssh_options(env)
    with ssh_connection(options) as raw_ssh:
        ssh = elevated_ssh(raw_ssh)
        run(ssh, "command -v apt-get >/dev/null", label="检查 Debian/Ubuntu 包管理器")
        run(ssh, """export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl ca-certificates
task_setup=$(mktemp)
trap 'rm -f -- "$task_setup"' EXIT
curl -fsSL https://deb.nodesource.com/setup_22.x -o "$task_setup"
bash "$task_setup"
apt-get install -y nodejs
node -v
npm -v""", timeout=900, label="安装 Node.js 22")
        run(ssh, "npm install -g @deepseek-ai/dsh\ndsh --version", timeout=600, label="安装 DeepSeek Harness")
        key = env.get("DEEPSEEK_API_KEY", "")
        if key:
            home = user_home(raw_ssh, options.user)
            run(ssh, credentials_script(home, options.user, key), label="保存所选用户的 API Key")
        for command in ("dsh --help", "dsh --profile headless --help", "dsh tui --help"):
            try:
                run(ssh, command, label="检查可用 CLI 功能")
            except Exception:
                print("此版本未提供该可选帮助入口", flush=True)
    print("\n>>> done", flush=True)


if __name__ == "__main__":
    sys.exit(cli(main))
