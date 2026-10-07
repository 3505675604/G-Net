"""Crash recovery/history failures with isolated fake desktop profiles only."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
import uuid
from unittest.mock import patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import product_integration
import desktop_services
from local_security import transform_secrets

SID = "a" * 32
SERVER = {"id": SID, "name": "private-name", "host": "private-host.example.test", "port": 22,
          "user": "private_user", "auth_type": "password", "password": "dummy-password-secret",
          "credential_required": False}


class ProductRecoveryAndHistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name) / "resources"
        self.profile = Path(self.folder.name) / "data"
        (self.root / "packaging").mkdir(parents=True)
        self.profile.mkdir()
        (self.root / "packaging" / "release-config.json").write_text(json.dumps({"publisher": "Gloria", "channel": "candidate"}))
        self.manager = self.fake_manager()
        self.journal = self.profile / "import-transaction.json"
        self.closed = 0

    def tearDown(self):
        self.folder.cleanup()

    def fake_manager(self):
        manager = types.SimpleNamespace(PROJECT_ROOT=str(self.root), DATA_DIR=str(self.profile),
                                        SERVERS_FILE=str(self.profile / "servers.json"),
                                        SETTINGS_FILE=str(self.profile / "settings.json"), DATA_LOCK=threading.RLock(),
                                        JOB_LOCK=threading.RLock(), jobs={}, _ACCEPTING_JOBS=True, app=Flask(__name__))

        def load_json(path, default):
            filename = Path(path)
            return transform_secrets(json.loads(filename.read_text()), filename.name) if filename.exists() else copy.deepcopy(default)

        def new_job(output, **metadata):
            with manager.JOB_LOCK:
                jid = uuid.uuid4().hex
                manager.jobs[jid] = {"status": "running", "created_at": time.time(), "output": output, **metadata}
                return jid

        def shutdown():
            self.closed += 1

        manager.load_json, manager.new_job, manager.shutdown_resources = load_json, new_job, shutdown
        return manager

    def protected_journal(self, *, servers=None, settings=None):
        return {"schema": 1, "files": {
            "servers.json": transform_secrets([copy.deepcopy(SERVER)] if servers is None else servers, "servers.json", encrypt=True),
            "settings.json": transform_secrets({"openai_key": "dummy-api-secret"} if settings is None else settings,
                                               "settings.json", encrypt=True)}}

    def write_journal(self, payload):
        self.journal.write_text(json.dumps(payload), encoding="utf-8")

    def assert_invalid_recovery_preserves_originals(self, payload):
        Path(self.manager.SERVERS_FILE).write_text("[]")
        Path(self.manager.SETTINGS_FILE).write_text("{}")
        before = {path: Path(path).read_bytes() for path in (self.manager.SERVERS_FILE, self.manager.SETTINGS_FILE)}
        self.write_journal(payload)
        with self.assertRaises(RuntimeError) as error:
            product_integration.register_desktop_product(self.manager)
        for value in ("private-name", "private-host", "private_user", "dummy-password", "dummy-api", str(self.profile)):
            self.assertNotIn(value, str(error.exception))
        for path, contents in before.items():
            self.assertEqual(Path(path).read_bytes(), contents)
        self.assertTrue(self.journal.exists())

    def test_valid_redo_journal_recovers_protected_data_with_original_ids(self):
        self.write_journal(self.protected_journal())
        product_integration.register_desktop_product(self.manager)
        recovered = self.manager.load_json(self.manager.SERVERS_FILE, [])
        self.assertEqual(recovered[0]["id"], SID)
        self.assertEqual(recovered[0]["password"], SERVER["password"])
        self.assertEqual(self.manager.load_json(self.manager.SETTINGS_FILE, {})["openai_key"], "dummy-api-secret")
        self.assertNotIn(SERVER["password"], Path(self.manager.SERVERS_FILE).read_text())
        self.assertFalse(self.journal.exists())

    def test_unknown_server_fields_ids_and_duplicate_identity_fail_before_any_write(self):
        seed = self.protected_journal()
        for field, value in (("known_hosts", "forged-trust"), ("path", "../settings.json"),
                             ("private_key_path", "C:/private-secret"), ("id", "../not-a-uuid"),
                             ("id", None), ("credential_required", "true"), ("host", "private-host;bad")):
            payload = copy.deepcopy(seed)
            payload["files"]["servers.json"][0][field] = value
            with self.subTest(field=field):
                self.assert_invalid_recovery_preserves_originals(payload)
        duplicate = copy.deepcopy(seed)
        duplicate["files"]["servers.json"].append(copy.deepcopy(duplicate["files"]["servers.json"][0]))
        self.assert_invalid_recovery_preserves_originals(duplicate)

    def test_unknown_settings_fields_and_unencrypted_or_broken_credentials_fail(self):
        seed = self.protected_journal()
        for field, value in (("path", "../private-secret"), ("openai_key", "plain-secret"),
                             ("openai_key", False), ("openai_key", "dpapi:v1:not-base64")):
            payload = copy.deepcopy(seed)
            payload["files"]["settings.json"][field] = value
            with self.subTest(field=field):
                self.assert_invalid_recovery_preserves_originals(payload)
        for secret in ("plaintext-private-secret", [], "dpapi:v1:garbage"):
            payload = copy.deepcopy(seed)
            payload["files"]["servers.json"][0]["password"] = secret
            self.assert_invalid_recovery_preserves_originals(payload)

    def test_duplicate_json_fields_and_unknown_destinations_are_rejected(self):
        self.journal.write_text('{"schema":1,"schema":1,"files":{"servers.json":[],"settings.json":{}}}')
        with self.assertRaises(RuntimeError):
            product_integration.register_desktop_product(self.manager)
        self.assertFalse(Path(self.manager.SERVERS_FILE).exists())
        payload = self.protected_journal()
        payload["files"]["../known_hosts"] = "must-not-write"
        self.assert_invalid_recovery_preserves_originals(payload)

    def test_server_limit_overlong_settings_and_invalid_authentication_fail(self):
        seed = self.protected_journal()
        cases = []
        too_many = copy.deepcopy(seed)
        too_many["files"]["servers.json"] *= 201
        cases.append(too_many)
        too_long = self.protected_journal(settings={"openai_key": "x" * 4097})
        cases.append(too_long)
        bad_auth = copy.deepcopy(seed)
        bad_auth["files"]["servers.json"][0]["auth_type"] = "unknown"
        cases.append(bad_auth)
        for payload in cases:
            self.assert_invalid_recovery_preserves_originals(payload)

    def test_history_disk_failure_never_prevents_new_job_or_state_polling(self):
        service = product_integration.register_desktop_product(self.manager)
        with patch.object(service, "record_task", side_effect=OSError("dummy-secret-path")), \
                self.assertLogs("flnetwork.desktop", level="WARNING") as logs:
            jid = self.manager.new_job("sensitive-output-secret", server_id=SID)
            self.assertEqual(self.manager.jobs[jid]["status"], "running")
            self.manager.jobs[jid]["status"] = "done"
            response = self.manager.app.test_client().get("/api/product/history")
            self.assertEqual(response.status_code, 200)
        for line in logs.output:
            self.assertNotIn("dummy-secret-path", line)
            self.assertNotIn("sensitive-output-secret", line)
        # A released history lock allows the next successful poll to persist.
        self.manager.app.test_client().get("/api/product/history")
        self.assertEqual(service.history()[0]["kind"], "tool")
        self.assertEqual(service.history()[0]["status"], "done")

    def test_history_failure_never_blocks_shutdown_resource_release(self):
        service = product_integration.register_desktop_product(self.manager)
        jid = self.manager.new_job("secret-output", server_ids=[SID])
        self.manager.jobs[jid]["status"] = "done"
        with patch.object(service, "record_task", side_effect=OSError("private-log-path")), \
                self.assertLogs("flnetwork.desktop", level="WARNING"):
            self.manager.shutdown_resources()
        self.assertEqual(self.closed, 1)

    def test_history_saved_kind_and_time_never_contain_ids_output_or_server_names(self):
        service = product_integration.register_desktop_product(self.manager)
        jid = self.manager.new_job("sensitive-output-secret", server_ids=[SID])
        self.manager.jobs[jid]["status"] = "done"
        self.manager.shutdown_resources()
        raw = service.history_path.read_text()
        for secret in (jid, SID, "sensitive-output-secret", SERVER["name"], SERVER["host"]):
            self.assertNotIn(secret, raw)
        self.assertEqual(service.history()[-1]["kind"], "node")

    def test_backup_import_success_is_returned_when_optional_history_cannot_save(self):
        service = product_integration.register_desktop_product(self.manager)
        backup = desktop_services.encode_backup([SERVER], {})
        original = desktop_services.atomic_json_write

        def fail_history(path, data):
            if Path(path).name == "task-history.json":
                raise OSError("private-secret-disk-error")
            return original(path, data)

        with patch.object(desktop_services, "atomic_json_write", side_effect=fail_history), \
                self.assertLogs("flnetwork.desktop", level="WARNING"):
            result = self.manager.app.test_client().post("/api/product/backup/import", json={"backup": backup})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json["imported"], 1)
        stored = self.manager.load_json(self.manager.SERVERS_FILE, [])
        self.assertTrue(stored[0]["credential_required"])

    def test_committed_journal_is_cleanup_only_and_preserves_later_edits(self):
        payload = self.protected_journal()
        payload["phase"] = "committed"
        self.write_journal(payload)
        later = {**SERVER, "name": "updated-after-import", "password": "newer-password-secret"}
        Path(self.manager.SERVERS_FILE).write_text(json.dumps(transform_secrets([later], "servers.json", encrypt=True)))
        Path(self.manager.SETTINGS_FILE).write_text(json.dumps(transform_secrets({"openai_key": "newer-api-secret"}, "settings.json", encrypt=True)))
        before = {path: Path(path).read_bytes() for path in (self.manager.SERVERS_FILE, self.manager.SETTINGS_FILE)}
        product_integration.register_desktop_product(self.manager)
        for path, raw in before.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        self.assertFalse(self.journal.exists())

    def test_unlink_failure_leaves_terminal_journal_and_does_not_roll_back_later_edit(self):
        product_integration.register_desktop_product(self.manager)
        backup = desktop_services.encode_backup([SERVER], {})
        original_unlink = Path.unlink

        def locked_journal(path, *args, **kwargs):
            if path == self.journal:
                raise OSError("private-lock-error")
            return original_unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", new=locked_journal), self.assertLogs("flnetwork.desktop", level="WARNING"):
            imported = self.manager.app.test_client().post("/api/product/backup/import", json={"backup": backup})
        self.assertEqual(imported.status_code, 200)
        self.assertEqual(json.loads(self.journal.read_text())["phase"], "committed")
        values = self.manager.load_json(self.manager.SERVERS_FILE, [])
        values[0]["name"] = "later-edit-must-remain"
        product_integration.atomic_json_write(self.manager.SERVERS_FILE, transform_secrets(values, "servers.json", encrypt=True))
        restored = self.fake_manager()
        product_integration.register_desktop_product(restored)
        self.assertEqual(restored.load_json(restored.SERVERS_FILE, [])[0]["name"], "later-edit-must-remain")
        self.assertFalse(self.journal.exists())

    def test_commit_marker_failure_rolls_back_both_files_and_removes_redo(self):
        product_integration.register_desktop_product(self.manager)
        original = product_integration.atomic_json_write
        original(self.manager.SERVERS_FILE, transform_secrets([SERVER], "servers.json", encrypt=True))
        original(self.manager.SETTINGS_FILE, transform_secrets({"openai_key": "original-api-secret"}, "settings.json", encrypt=True))
        before = {path: Path(path).read_bytes() for path in (self.manager.SERVERS_FILE, self.manager.SETTINGS_FILE)}
        backup = desktop_services.encode_backup([{**SERVER, "host": "new.example.test"}], {})

        def failed_barrier(path, data):
            if Path(path) == self.journal and data.get("phase") == "committed":
                raise OSError("private-commit-marker-secret")
            return original(path, data)

        with patch.object(product_integration, "atomic_json_write", side_effect=failed_barrier):
            result = self.manager.app.test_client().post("/api/product/backup/import", json={"backup": backup})
        self.assertEqual(result.status_code, 500)
        self.assertNotIn("private-commit-marker-secret", result.get_data(as_text=True))
        for path, raw in before.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        self.assertFalse(self.journal.exists())

    def test_failed_rollback_or_cleanup_blocks_mutations_until_restart_recovery(self):
        product_integration.register_desktop_product(self.manager)
        original = product_integration.atomic_json_write
        original(self.manager.SERVERS_FILE, transform_secrets([SERVER], "servers.json", encrypt=True))
        original(self.manager.SETTINGS_FILE, transform_secrets({"openai_key": "original-api-secret"}, "settings.json", encrypt=True))
        backup = desktop_services.encode_backup([{**SERVER, "host": "new.example.test"}], {})
        settings_writes = 0

        def unavailable_settings(path, data):
            nonlocal settings_writes
            if Path(path) == Path(self.manager.SETTINGS_FILE):
                settings_writes += 1
                raise OSError("private-settings-failure")
            return original(path, data)

        with patch.object(product_integration, "atomic_json_write", side_effect=unavailable_settings):
            result = self.manager.app.test_client().post("/api/product/backup/import", json={"backup": backup})
        self.assertEqual(result.status_code, 500)
        self.assertGreaterEqual(settings_writes, 2)
        self.assertEqual(json.loads(self.journal.read_text())["phase"], "prepared")
        denied = self.manager.app.test_client().post("/api/product/onboarding", json={"completed": True})
        self.assertEqual(denied.status_code, 409)
        self.assertIn("重新启动", denied.json["msg"])
        restored = self.fake_manager()
        product_integration.register_desktop_product(restored)
        self.assertEqual(len(restored.load_json(restored.SERVERS_FILE, [])), 2)
        self.assertFalse(self.journal.exists())

    def test_failed_barrier_and_locked_cleanup_still_freeze_edits_after_successful_rollback(self):
        product_integration.register_desktop_product(self.manager)
        original = product_integration.atomic_json_write
        original(self.manager.SERVERS_FILE, transform_secrets([SERVER], "servers.json", encrypt=True))
        before = Path(self.manager.SERVERS_FILE).read_bytes()
        original_unlink = Path.unlink
        backup = desktop_services.encode_backup([{**SERVER, "host": "new.example.test"}], {})

        def failed_barrier(path, data):
            if Path(path) == self.journal and data.get("phase") == "committed":
                raise OSError("private-marker-failure")
            return original(path, data)

        def locked_journal(path, *args, **kwargs):
            if path == self.journal:
                raise OSError("private-journal-lock")
            return original_unlink(path, *args, **kwargs)

        with patch.object(product_integration, "atomic_json_write", side_effect=failed_barrier), patch.object(Path, "unlink", new=locked_journal):
            result = self.manager.app.test_client().post("/api/product/backup/import", json={"backup": backup})
        self.assertEqual(result.status_code, 500)
        self.assertEqual(Path(self.manager.SERVERS_FILE).read_bytes(), before)
        self.assertEqual(self.manager.app.test_client().post("/api/product/onboarding", json={"completed": True}).status_code, 409)


if __name__ == "__main__":
    unittest.main()
