"""Bind product services to protected desktop storage and application lifecycle."""
from __future__ import annotations

import copy
import json
import logging
import os
from pathlib import Path
import re
import threading
import time
import uuid

from flask import jsonify, render_template, request

from app_metadata import APP_VERSION, PRODUCT_NAME, load_release_config
from desktop_services import ProductError, _strict_json, register_product_api
from local_security import (KEY_FIELDS, SSH_SECRET_FIELDS, PREFIX, atomic_json_write, transform_secrets,
                            validate_auth, validate_host, validate_port, validate_user)
from release_security import verify_windows_installer
from script_common import parse_private_key


def register_desktop_product(manager):
    root = Path(manager.PROJECT_ROOT)
    config = load_release_config(root)
    journal = Path(manager.DATA_DIR) / "import-transaction.json"
    task_lock = threading.RLock()
    task_seen = {}
    transaction_unresolved = False

    def cleanup_committed_journal():
        try:
            journal.unlink(missing_ok=True)
        except OSError:
            # Committed records are never replayed. Leaving this encrypted file
            # after a transient scanner/file lock cannot undo later user edits.
            logging.getLogger("flnetwork.desktop").warning("已完成的导入恢复记录暂时无法清理；现有配置保持正常")

    def validate_server(value):
        if not isinstance(value, dict):
            raise ProductError("服务器备份格式无效")
        host = validate_host(value.get("host"))
        name = value.get("name") or host
        if not isinstance(name, str) or len(name) > 120 or any(c in name for c in "\r\n\x00"):
            raise ProductError("服务器名称格式无效")
        missing = value.get("credential_required", False)
        if type(missing) is not bool:
            raise ProductError("凭据状态格式无效")
        auth = validate_auth(value, allow_missing=missing)
        if auth.get("private_key"):
            parse_private_key(auth["private_key"], auth.get("key_passphrase", ""))
        if missing:
            auth["credential_required"] = True
        return {"id": uuid.uuid4().hex, "host": host, "name": name,
                "port": validate_port(value.get("port", 22)),
                "user": validate_user(value.get("user", "root")), **auth}

    def write_transaction(servers, settings):
        nonlocal transaction_unresolved
        # Encryption and validation finish before the first configuration write.
        # An encrypted redo journal makes a two-file commit recoverable after a
        # process/power interruption. It never stores plaintext login secrets.
        targets = {"servers.json": str(manager.SERVERS_FILE), "settings.json": str(manager.SETTINGS_FILE)}
        protected = {"servers.json": transform_secrets(servers, targets["servers.json"], encrypt=True),
                     "settings.json": transform_secrets(settings, targets["settings.json"], encrypt=True)}
        previous = {name: Path(path).read_bytes() if Path(path).exists() else None
                    for name, path in targets.items()}
        try:
            atomic_json_write(journal, {"schema": 1, "phase": "prepared", "files": protected})
            for name, path in targets.items():
                atomic_json_write(path, protected[name])
            # This barrier must finish before editing can resume. Recovery will
            # only clean up a terminal record and will not overwrite new edits.
            atomic_json_write(journal, {"schema": 1, "phase": "committed", "files": protected})
        except OSError:
            restored = True
            for name, path in targets.items():
                try:
                    raw = previous[name]
                    if raw is None:
                        Path(path).unlink(missing_ok=True)
                    else:
                        atomic_json_write(path, json.loads(raw.decode("utf-8-sig")))
                except (OSError, ValueError, UnicodeError):
                    restored = False
            if restored:
                try:
                    journal.unlink(missing_ok=True)
                except OSError:
                    try:
                        # The old snapshot is already restored. Mark the redo
                        # record terminal so it cannot resurrect this import.
                        atomic_json_write(journal, {"schema": 1, "phase": "committed", "files": protected})
                    except OSError:
                        transaction_unresolved = True
            else:
                transaction_unresolved = True
            message = ("导入保存失败，原配置已恢复；请检查磁盘空间后重试" if not transaction_unresolved else
                       "导入保存失败，恢复记录尚未完成；已暂停修改操作，请关闭并重新启动应用以恢复数据")
            raise ProductError(message, 500) from None
        cleanup_committed_journal()

    def recover_transaction():
        if not journal.exists():
            return
        try:
            if journal.is_symlink() or journal.stat().st_size > 1024 * 1024:
                raise ValueError("journal bounds")
            with journal.open("rb") as stream:
                payload = _strict_json(stream.read(1024 * 1024 + 1), 1024 * 1024)
            if (not isinstance(payload, dict) or set(payload) not in ({"schema", "files"}, {"schema", "phase", "files"})
                    or type(payload["schema"]) is not int or payload["schema"] != 1
                    or payload.get("phase", "prepared") not in {"prepared", "committed"}
                    or not isinstance(payload["files"], dict)
                    or set(payload["files"]) != {"servers.json", "settings.json"}):
                raise ValueError("journal schema")
            files = payload["files"]
            if (not isinstance(files["servers.json"], list) or len(files["servers.json"]) > 200 or
                    not isinstance(files["settings.json"], dict) or
                    set(files["settings.json"]) - (set(KEY_FIELDS) | {"ssh_auto_update_host_key"})):
                raise ValueError("journal configuration")
            if ("ssh_auto_update_host_key" in files["settings.json"] and
                    not isinstance(files["settings.json"]["ssh_auto_update_host_key"], bool)):
                raise ValueError("journal SSH identity preference")
            allowed = {"id", "name", "host", "port", "user", "auth_type", "password", "private_key",
                       "key_passphrase", "credential_required"}
            ids = set()
            for value in files["servers.json"]:
                if not isinstance(value, dict) or set(value) - allowed:
                    raise ValueError("journal server fields")
                sid = value.get("id")
                if not isinstance(sid, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", sid) or sid.casefold() in ids:
                    raise ValueError("journal server identity")
                ids.add(sid.casefold())
                for field in SSH_SECRET_FIELDS:
                    secret = value.get(field, "")
                    if not isinstance(secret, str) or (secret and not secret.startswith(PREFIX)):
                        raise ValueError("journal contains unprotected credentials")
            for key in KEY_FIELDS:
                secret = files["settings.json"].get(key, "")
                if not isinstance(secret, str) or (secret and not secret.startswith(PREFIX)):
                    raise ValueError("journal contains unprotected API keys")
            if payload.get("phase", "prepared") == "committed":
                cleanup_committed_journal()
                return
            servers = transform_secrets(files["servers.json"], "servers.json")
            settings = transform_secrets(files["settings.json"], "settings.json")
            clean_servers = []
            for value in servers:
                clean = validate_server(value)
                clean["id"] = value["id"]  # Stable existing identities survive a crash recovery.
                clean_servers.append(clean)
            for key in KEY_FIELDS:
                value = settings.get(key, "")
                if (not isinstance(value, str) or len(value) > 4096 or
                        any(c in value for c in "\r\n\x00") or value.startswith(PREFIX)):
                    raise ValueError("journal API key value")
            # All validation precedes either write. Only fixed local filenames
            # are used; a recovery record cannot select a destination path.
            protected_servers = transform_secrets(clean_servers, "servers.json", encrypt=True)
            protected_settings = transform_secrets(settings, "settings.json", encrypt=True)
            with manager.DATA_LOCK:
                atomic_json_write(manager.SERVERS_FILE, protected_servers)
                atomic_json_write(manager.SETTINGS_FILE, protected_settings)
                atomic_json_write(journal, {"schema": 1, "phase": "committed", "files": {
                    "servers.json": protected_servers, "settings.json": protected_settings}})
                cleanup_committed_journal()
        except Exception:
            raise RuntimeError("备份导入恢复记录无效或无法保存，请先保留个人数据并联系支持") from None

    recover_transaction()

    @manager.app.before_request
    def transaction_recovery_guard():
        if transaction_unresolved and request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path.startswith("/api/"):
            return jsonify(ok=False, msg="导入恢复记录尚未完成；修改操作已暂停，请关闭并重新启动应用以恢复数据"), 409

    def busy():
        with manager.JOB_LOCK:
            return not manager._ACCEPTING_JOBS or any(j.get("status") == "running" for j in manager.jobs.values())

    def snapshot():
        with manager.JOB_LOCK:
            return [{"status": j.get("status"), "created_at": j.get("created_at")}
                    for j in manager.jobs.values()]

    def import_data(servers, settings, *, overwrite_api_keys=False):
        if not isinstance(servers, list) or len(servers) > 200 or not isinstance(settings, dict) or set(settings) - set(KEY_FIELDS):
            raise ProductError("备份内容不符合导入要求")
        clean = [validate_server(value) for value in servers]
        if type(overwrite_api_keys) is not bool:
            raise ProductError("覆盖 API Key 选项无效")
        for value in settings.values():
            if not isinstance(value, str) or len(value) > 4096 or any(c in value for c in "\r\n\x00") or value.startswith("dpapi:v1:"):
                raise ProductError("备份 API Key 格式无效")
        # Block a racing new task, then reread the latest local data while holding
        # the shared data lock. Existing servers and host identities are retained.
        with manager.JOB_LOCK, manager.DATA_LOCK:
            if busy():
                raise ProductError("有任务正在运行或应用正在退出，请稍后再导入", 409)
            current = manager.load_json(manager.SERVERS_FILE, [])
            current_settings = manager.load_json(manager.SETTINGS_FILE, {})
            identities = {(s["host"].casefold(), int(s.get("port", 22)), s["user"]) for s in current}
            imported = skipped = 0
            for server in clean:
                identity = (server["host"].casefold(), server["port"], server["user"])
                if identity in identities:
                    skipped += 1
                    continue
                identities.add(identity)
                current.append(server)
                imported += 1
            if len(current) > 200:
                raise ProductError("本机合并后最多支持 200 台服务器，请分开管理")
            for key, value in settings.items():
                if value and (overwrite_api_keys or not current_settings.get(key)):
                    current_settings[key] = value
            if imported or any(settings.values()):
                write_transaction(current, current_settings)
            return {"imported": imported, "skipped": skipped}

    services = register_product_api(
        manager.app, data_dir=manager.DATA_DIR, version=APP_VERSION,
        read_servers=lambda: manager.load_json(manager.SERVERS_FILE, []),
        read_settings=lambda: {k: v for k, v in manager.load_json(manager.SETTINGS_FILE, {}).items() if k in KEY_FIELDS},
        import_data=import_data, task_snapshot=snapshot, has_running_jobs=busy,
        update_manifest_url=config["update_manifest_url"],
        verify_installer=lambda path: verify_windows_installer(path, config["signer_thumbprints"]),
        update_download_enabled=bool(config["signer_thumbprints"]),
        product={"name": PRODUCT_NAME, "publisher": config["publisher"] or "发布者待配置",
                 "license": "候选版使用许可；公开发行条款待确认" if config["channel"] == "candidate" else "见使用许可",
                 "privacy_notice": "凭据在本机加密保存；诊断不会自动上传；更新仅由你主动检查。"})

    def flush_history():
        with task_lock:
            with manager.JOB_LOCK:
                values = [(jid, j.get("status"), j.get("created_at"),
                           "node" if "server_ids" in j else "tool" if "server_id" in j else "other")
                          for jid, j in manager.jobs.items()]
            for jid, status, created, kind in values:
                if status not in {"running", "done", "error"} or task_seen.get(jid) == status:
                    continue
                try:
                    saved = services.record_task(kind, status, created_at=created,
                                                 finished_at=time.time() if status != "running" else None)
                except Exception:
                    saved = False
                if saved:
                    task_seen[jid] = status
                else:
                    # History is optional. A full disk must not prevent a newly
                    # allocated job from starting, break polling, or block exit.
                    logging.getLogger("flnetwork.desktop").warning("任务历史暂时无法保存；任务继续正常执行")
            live = {jid for jid, _, _, _ in values}
            for jid in set(task_seen) - live:
                task_seen.pop(jid, None)

    original_job = manager.new_job

    def tracked_job(output, **metadata):
        flush_history()  # Capture finished jobs before original_job prunes them.
        jid = original_job(output, **metadata)
        flush_history()
        return jid

    manager.new_job = tracked_job
    original_shutdown = manager.shutdown_resources

    def shutdown():
        try:
            flush_history()
        finally:
            original_shutdown()

    manager.shutdown_resources = shutdown

    @manager.app.before_request
    def product_history_refresh():
        if request.path.startswith(("/api/jobs/", "/api/product/history", "/api/product/diagnostics")):
            flush_history()

    @manager.app.get("/help")
    def product_help():
        return render_template("product-help.html", title="使用帮助", version=APP_VERSION, document=None)

    @manager.app.get("/privacy")
    def product_privacy():
        return render_template("product-help.html", title="隐私与本地数据", version=APP_VERSION,
                               document=(root / "packaging" / "PRIVACY.txt").read_text(encoding="utf-8-sig"))

    @manager.app.get("/license")
    def product_license():
        return render_template("product-help.html", title="使用许可", version=APP_VERSION,
                               document=(root / "packaging" / "APP-LICENSE.txt").read_text(encoding="utf-8-sig"))

    return services
