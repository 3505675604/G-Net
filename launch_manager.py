# -*- coding: utf-8 -*-
"""Start this project's panel without terminating other programs."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser

PROJECT_ROOT = Path(__file__).resolve().parent
PANEL_URL = "http://127.0.0.1:8620"
HEALTH_URL = PANEL_URL + "/api/health"


def health_matches(data, project_root=None):
    if not isinstance(data, dict) or data.get("app") != "server-manager":
        return False
    root = data.get("project_root")
    if not isinstance(root, str) or not root:
        return False
    project_root = PROJECT_ROOT if project_root is None else project_root
    return os.path.normcase(str(Path(root).resolve())) == os.path.normcase(str(Path(project_root).resolve()))


def read_health():
    try:
        # Loopback requests must bypass user-configured proxies.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request = urllib.request.Request(HEALTH_URL, headers={"Accept": "application/json"})
        with opener.open(request, timeout=1) as response:
            return json.loads(response.read(8192).decode("utf-8"))
    except (OSError, ValueError):
        return None


def port_available():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("127.0.0.1", 8620))
            return True
        except OSError:
            return False


@contextmanager
def launch_lock():
    from script_common import _known_hosts_lock
    directory = PROJECT_ROOT / "work"
    directory.mkdir(exist_ok=True)
    with _known_hosts_lock(directory / "launcher"):
        yield


def _stop_owned_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def main():
    with launch_lock():
        if health_matches(read_health()):
            webbrowser.open(PANEL_URL)
            print("本项目服务器管家已运行，已打开页面")
            return 0
        if not port_available():
            raise RuntimeError("本地端口 8620 已被其他程序或其他项目占用；请先手动处理占用，本启动器不会结束它")
        panel = PROJECT_ROOT / "server-manager" / "app.py"
        if not panel.is_file():
            raise RuntimeError("未找到本项目 server-manager/app.py")
        python = PROJECT_ROOT / "venv" / ("Scripts/pythonw.exe" if os.name == "nt" else "bin/python")
        if not python.is_file():
            python = Path(sys.executable)
        log = PROJECT_ROOT / "work" / "server-manager.log"
        env = os.environ.copy()
        env["SERVER_MANAGER_NO_BROWSER"] = "1"
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        with log.open("a", encoding="utf-8") as output:
            process = subprocess.Popen([str(python), str(panel)], cwd=str(PROJECT_ROOT), env=env,
                                       stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                       creationflags=flags)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"服务器管家启动失败，详情见 {log}")
                if health_matches(read_health()):
                    webbrowser.open(PANEL_URL)
                    print("服务器管家启动成功")
                    return 0
                time.sleep(0.2)
            raise RuntimeError(f"未收到本项目的健康响应，详情见 {log}")
        except BaseException:
            _stop_owned_process(process)
            raise


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"启动失败：{error}", file=sys.stderr)
        sys.exit(1)
