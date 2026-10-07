"""Build a self-contained release website without uploading or choosing a domain."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import urllib.parse

from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app_metadata import APP_VERSION, load_release_config
from desktop_services import validate_manifest


def build_site(destination: Path, *, base_url=""):
    config = load_release_config(ROOT)
    release = ROOT / "release"
    manifest = json.loads((release / "build-manifest.json").read_text(encoding="utf-8-sig"))
    if manifest.get("version") != APP_VERSION or manifest.get("self_test_passed") is not True:
        raise ValueError("必须先构建当前版本并通过冻结自检")
    destination = destination.resolve()
    if destination == ROOT or destination in ROOT.parents or destination == release:
        raise ValueError("下载站必须使用独立子目录")
    destination.mkdir(parents=True, exist_ok=True)
    downloads = destination / "downloads"
    downloads.mkdir(exist_ok=True)
    entries, checksums = [], []
    options = [
        ("installer", "STANDARD", "普通安装版", "体积较小。缺少 WebView2 时需要联网安装官方运行时。"),
        ("full_installer", "COMPLETE", "完整安装版", "包含官方 x64 WebView2 运行时，方便缺少该组件的电脑安装。远程管理仍需网络。"),
        ("portable", "PORTABLE", "便携版", "完整解压后运行 GNetwork.exe。保留 _internal 文件夹，系统需要 WebView2。"),
    ]
    installer = None
    for field, label, title, description in options:
        if not manifest.get(field):
            continue
        source = Path(manifest[field]).resolve()
        if source.parent != release.resolve() or not source.name.startswith(f"G-Network-{APP_VERSION}-windows-x64") or source.suffix not in {".exe", ".zip"}:
            raise ValueError("构建清单包含不允许发布的文件")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        size = source.stat().st_size
        shutil.copyfile(source, downloads / source.name)
        checksums.append(digest + "  downloads/" + source.name)
        entries.append({"label": label, "title": title, "description": description,
                        "size_label": f"{size / 1024 / 1024:.1f} MB", "filename": source.name,
                        "size": size, "sha256": digest})
        if field == "installer":
            installer = entries[-1]
    if not installer:
        raise ValueError("下载官网需要普通安装包")
    assets = destination / "assets"
    assets.mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "server-manager" / "static" / "fl-network.svg", assets / "fl-network.svg")
    environment = Environment(loader=FileSystemLoader(str(ROOT / "packaging")), autoescape=select_autoescape(["html"]))
    notice = ("当前为候选测试版本，安装包尚未代码签名。请先核对来源与校验值；公开更新服务尚未开通。"
              if manifest.get("signed") is not True else "安装包已签名。请核对发布来源，并在安装前阅读许可与隐私说明。")
    html = environment.get_template("download-site-template.html").render(
        version=APP_VERSION, files=entries, channel_label="正式版" if config["channel"] == "stable" else "候选测试版",
        release_notice=notice, support_url=config["support_url"])
    (destination / "index.html").write_text(html, encoding="utf-8")
    (destination / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    help_environment = Environment(loader=FileSystemLoader(str(ROOT / "server-manager" / "templates")), autoescape=select_autoescape(["html"]))
    help_template = help_environment.get_template("product-help.html")
    for filename, title, document in (
        ("help.html", "使用帮助", None),
        ("privacy.html", "隐私与本地数据", (ROOT / "packaging" / "PRIVACY.txt").read_text(encoding="utf-8-sig")),
        ("license.html", "使用许可", (ROOT / "packaging" / "installer-license.txt").read_text(encoding="utf-8-sig")),
        ("release-notes.html", f"{APP_VERSION} 版本说明", (ROOT / "packaging" / "RELEASE-NOTES.txt").read_text(encoding="utf-8-sig")),
    ):
        text = help_template.render(title=title, version=APP_VERSION, document=document)
        text = text.replace('href="/"', 'href="index.html"').replace('href="/help"', 'href="help.html"').replace('href="/privacy"', 'href="privacy.html"').replace('href="/license"', 'href="license.html"').replace('href="/static/fl-network.svg"', 'href="assets/fl-network.svg"')
        (destination / filename).write_text(text, encoding="utf-8")
    if base_url:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("请提供不含路径的 HTTPS 官网根地址")
        update_url = base_url.rstrip("/") + "/updates/latest.json"
        update = {"schema": 1, "version": APP_VERSION, "platform": "windows-x64",
                  "url": base_url.rstrip("/") + "/downloads/" + installer["filename"],
                  "sha256": installer["sha256"], "size": installer["size"],
                  "release_notes": "Clash 工作区支持批量节点导入、链式代理、业务分流、DNS 编辑与加密保存；保留节点专属直连域名配置。",
                  "published_at": "2026-10-05"}
        validate_manifest(update, update_url)
        updates = destination / "updates"
        updates.mkdir(exist_ok=True)
        (updates / "latest.json").write_text(json.dumps(update, ensure_ascii=False, indent=2), encoding="utf-8")
    (destination / "DEPLOY.txt").write_text(
        "此目录未自动上传或发布。完整复制到你控制的 HTTPS 下载站即可提供静态下载。\n"
        f"官网下载域名：{config['website_url'] or '尚未配置'}。当前候选版未代码签名，更新服务未启用。\n"
        "仅在签名、更新信任配置与正式发布资料完成后，重新构建并生成更新清单；签名会改变校验值。\n"
        "正式发布需确认最终许可、支持联系方式，并完成干净 Windows 电脑与授权服务器验收。\n",
        encoding="utf-8")
    return {"app": "G-Network", "version": APP_VERSION, "files": len(entries), "directory": str(destination), "uploaded": False, "updates_enabled": bool(base_url)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "release" / "download-site")
    parser.add_argument("--base-url", default="")
    args = parser.parse_args()
    print(json.dumps(build_site(args.output, base_url=args.base_url), ensure_ascii=False))
