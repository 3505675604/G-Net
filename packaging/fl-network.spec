# -*- mode: python ; coding: utf-8 -*-
"""Windows desktop bundle. Application resources are an explicit allowlist.

Do not replace this list with a recursive copy of the project directory:
the checkout can contain the developer's real SSH passwords and API keys.
"""
from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

if sys.platform != "win32":
    raise SystemExit("FLNetwork Windows packages must be built on Windows.")

ROOT = Path(SPECPATH).resolve().parent
PACKAGING = ROOT / "packaging"
for required in (ROOT / "desktop_app.py", PACKAGING / "fl-network.ico"):
    if not required.is_file():
        raise SystemExit(f"Required desktop build input is missing: {required}")

datas = [
    (str(ROOT / "server-manager" / "app.py"), "server-manager"),
    (str(PACKAGING / "fl-network.ico"), "packaging"),
    (str(ROOT / "README-DESKTOP.md"), "."),
    (str(PACKAGING / "THIRD-PARTY-NOTICES.md"), "."),
    (str(PACKAGING / "release-config.json"), "packaging"),
    (str(PACKAGING / "APP-LICENSE.txt"), "packaging"),
    (str(PACKAGING / "PRIVACY.txt"), "packaging"),
    (str(PACKAGING / "WEBVIEW2-LICENSE.txt"), "packaging"),
]
asset_extensions = {".html", ".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".txt"}
private_names = {"servers.json", "settings.json", "node-routing.json", "clash-profiles.json", "known_hosts", "known_hosts.lock", "xray_result.json", ".env", "id_rsa", "id_ed25519"}
for relative in ("server-manager/templates", "server-manager/static"):
    source_root = ROOT / relative
    for source in sorted(source_root.rglob("*")):
        if source.is_file():
            if source.name.lower() in private_names or source.suffix.lower() not in asset_extensions:
                raise SystemExit(f"Unexpected file in desktop asset allowlist: {source}")
            destination = str(source.parent.relative_to(ROOT))
            datas.append((str(source), destination))

# The maintained webview/pythonnet hooks collect Windows-native DLLs; JS is
# collected explicitly as well because it is read from disk at runtime.
datas += collect_data_files("webview", includes=["js/**", "lib/**"])
runtime_distributions = [
    "pywebview", "pythonnet", "clr_loader", "proxy_tools", "bottle", "typing_extensions",
    "bcrypt", "blinker", "cffi", "click", "cryptography", "Flask", "flask-sock",
    "h11", "invoke", "itsdangerous", "Jinja2", "MarkupSafe", "paramiko", "pycparser",
    "PyNaCl", "PyYAML", "simple-websocket", "Werkzeug", "wsproto",
]
for distribution in runtime_distributions:
    datas += copy_metadata(distribution)

python_license = Path(sys.base_prefix) / "LICENSE.txt"
if python_license.is_file():
    datas.append((str(python_license), "licenses/python"))

a = Analysis(
    [str(ROOT / "desktop_app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    # app.py is loaded with importlib, so its dependencies must be enumerated.
    hiddenimports=[
        "flask", "flask_sock", "simple_websocket", "paramiko", "werkzeug.exceptions",
        "local_security", "script_common", "remote_ops", "clash_export", "clash_workspace", "clash_import", "clash_studio", "clash_profile_store", "yaml", "node_routing", "node_routing_store",
        "app_metadata", "desktop_services", "release_security", "product_integration",
        "webview.platforms.winforms", "webview.platforms.edgechromium", "clr", "pythonnet",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PyQt5", "PyQt6", "PySide2", "PySide6", "qtpy", "cefpython3",
        "webview.platforms.qt", "webview.platforms.gtk", "webview.platforms.cocoa",
        "webview.platforms.cef", "tkinter", "pytest", "unittest",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="GNetwork",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(PACKAGING / "fl-network.ico"),
    version=str(PACKAGING / "version_info.txt"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="GNetwork",
)
