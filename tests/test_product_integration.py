"""Product integration uses temporary profiles, real Windows DPAPI and no SSH.

These exercise application APIs, persistence, merge policy and interrupted imports.
No developer configuration, trusted host file or external service is read.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import desktop_services
import product_integration
from local_security import atomic_json_write, transform_secrets

APP_PATH = ROOT / "server-manager" / "app.py"
PASSPHRASE = "test-only-portable-backup-passphrase"


@unittest.skipUnless(os.name == "nt", "Integration validates real Windows user-bound DPAPI")
class ProductIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # An offline disposable key verifies actual parsing without contacting a host.
        cls.private_key = ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
            serialization.BestAvailableEncryption(b"test-only-private-key-passphrase"),
        ).decode("ascii")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.managers = []
        self.module_names = []
        self.network_guards = [
            patch("script_common.connect_ssh", side_effect=AssertionError("real SSH is forbidden")),
            patch("script_common.host_identity", side_effect=AssertionError("real host probing is forbidden")),
            patch("desktop_services.fetch_https", side_effect=AssertionError("real update networking is forbidden")),
            patch("socket.getaddrinfo", side_effect=AssertionError("external DNS is forbidden")),
            patch("socket.create_connection", side_effect=AssertionError("external sockets are forbidden")),
        ]
        self.network_mocks = [guard.start() for guard in self.network_guards]
        self.source = self.make_manager("source")
        self.target = self.make_manager("target")

    def tearDown(self):
        try:
            for manager in reversed(self.managers):
                manager.jobs.clear()
                manager.shutdown_resources()
            for mock in self.network_mocks:
                mock.assert_not_called()
        finally:
            for guard in reversed(self.network_guards):
                guard.stop()
            for name in self.module_names:
                sys.modules.pop(name, None)
            self.directory.cleanup()

    def make_manager(self, profile):
        name = "product_integration_test_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, APP_PATH)
        manager = importlib.util.module_from_spec(spec)
        sys.modules[name] = manager
        self.module_names.append(name)
        with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": str(self.root / profile)}):
            spec.loader.exec_module(manager)
        manager.configure_local_access(47829)
        manager.app.config["TESTING"] = True
        self.managers.append(manager)
        return manager

    def request(self, manager, method, path, **kwargs):
        kwargs.setdefault("base_url", "http://127.0.0.1:47829")
        kwargs.setdefault("headers", {"X-CSRF-Token": manager.CSRF_TOKEN})
        return manager.app.test_client().open(path, method=method, **kwargs)

    def add(self, manager, **values):
        body = {"host": "ecs.example.invalid", "name": "Test server", "port": 22,
                "user": "ubuntu", "auth_type": "password", "password": "test-only-password"}
        body.update(values)
        response = self.request(manager, "POST", "/api/servers", json=body)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.json["id"]

    def settings(self, manager, **values):
        response = self.request(manager, "POST", "/api/settings", json=values)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))

    def export(self, manager, mode="metadata"):
        body = {"mode": mode}
        if mode == "encrypted":
            body["passphrase"] = PASSPHRASE
        response = self.request(manager, "POST", "/api/product/backup/export", json=body)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.json["backup"]

    def import_backup(self, manager, backup, **extra):
        body = {"backup": backup, "mode": "merge", **extra}
        if backup["mode"] == "encrypted":
            body.setdefault("passphrase", PASSPHRASE)
        return self.request(manager, "POST", "/api/product/backup/import", json=body)

    def stored_bytes(self, manager):
        return {name: Path(path).read_bytes() if Path(path).exists() else None
                for name, path in (("servers", manager.SERVERS_FILE), ("settings", manager.SETTINGS_FILE))}

    def journal_payload(self, *, servers=None, settings=None):
        servers = servers or [{"id": uuid.uuid4().hex, "host": "journal.example.invalid", "name": "Recovered server",
                               "port": 22, "user": "ubuntu", "auth_type": "password", "password": "test-only-journal-secret"}]
        settings = settings if settings is not None else {"openai_key": "test-only-journal-key"}
        return {"schema": 1, "files": {
            "servers.json": transform_secrets(servers, "servers.json", encrypt=True),
            "settings.json": transform_secrets(settings, "settings.json", encrypt=True),
        }}

    def test_encrypted_backup_migrates_password_private_key_and_keys_between_profiles(self):
        password_id = self.add(self.source)
        self.add(self.source, host="key.example.invalid", auth_type="private_key", password="",
                 private_key=self.private_key, key_passphrase="test-only-private-key-passphrase")
        self.settings(self.source, openai_key="test-only-openai-key")
        source_disk = self.stored_bytes(self.source)
        self.assertIn(b"dpapi:v1:", source_disk["servers"])
        self.assertNotIn(b"test-only-password", source_disk["servers"])
        backup = self.export(self.source, "encrypted")
        encoded = json.dumps(backup)
        for secret in ("test-only-password", "test-only-private-key-passphrase", "test-only-openai-key", "dpapi:v1:", "BEGIN OPENSSH"):
            self.assertNotIn(secret, encoded)
        response = self.import_backup(self.target, backup)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.json["imported"], 2)
        imported = self.target.load_json(self.target.SERVERS_FILE, [])
        self.assertEqual(imported[0]["password"], "test-only-password")
        self.assertEqual(imported[1]["private_key"], self.private_key)
        self.assertNotEqual(imported[0]["id"], password_id)
        self.assertEqual(self.target.load_json(self.target.SETTINGS_FILE, {})["openai_key"], "test-only-openai-key")
        target_disk = self.stored_bytes(self.target)
        self.assertIn(b"dpapi:v1:", target_disk["servers"])
        self.assertNotEqual(target_disk["servers"], source_disk["servers"])
        for secret in (b"test-only-password", b"BEGIN OPENSSH", b"test-only-openai-key"):
            self.assertNotIn(secret, target_disk["servers"] + target_disk["settings"])
        self.assertFalse(Path(self.target.KNOWN_HOSTS_FILE).exists())

    def test_metadata_import_excludes_secrets_and_requires_explicit_credential_edit(self):
        self.add(self.source)
        self.settings(self.source, anthropic_key="test-only-anthropic-secret")
        backup = self.export(self.source)
        encoded = json.dumps(backup)
        self.assertNotIn("password", backup["data"]["servers"][0])
        self.assertNotIn("test-only-password", encoded)
        self.assertNotIn("test-only-anthropic-secret", encoded)
        preview = self.request(self.target, "POST", "/api/product/backup/preview", json={"backup": backup})
        self.assertEqual(preview.status_code, 200)
        self.assertTrue(preview.json["requires_credentials"])
        self.assertEqual(preview.json["settings_count"], 0)
        self.assertEqual(self.import_backup(self.target, backup).status_code, 200)
        safe = self.request(self.target, "GET", "/api/servers").json[0]
        self.assertTrue(safe["credential_required"])
        # Missing credentials are rejected before the SSH helper is reached.
        rejected = self.request(self.target, "POST", f"/api/servers/{safe['id']}/test", json={})
        self.assertEqual(rejected.status_code, 200)
        self.assertFalse(rejected.json["ok"])
        self.assertIn("补齐认证信息", rejected.json["msg"])
        edited = self.request(self.target, "PUT", f"/api/servers/{safe['id']}", json={"password": "test-only-new-password"})
        self.assertEqual(edited.status_code, 200)
        updated = self.request(self.target, "GET", "/api/servers").json[0]
        self.assertFalse(updated["credential_required"])
        self.assertNotIn("password", updated)
        self.assertNotIn(b"test-only-new-password", Path(self.target.SERVERS_FILE).read_bytes())

    def test_merge_preserves_existing_identity_but_accepts_other_ports_and_users(self):
        original_id = self.add(self.target, host="ECS.EXAMPLE.INVALID", password="target-existing-password")
        self.add(self.source, password="source-other-password")
        self.add(self.source, port=2222)
        self.add(self.source, user="otheruser")
        response = self.import_backup(self.target, self.export(self.source, "encrypted"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual((response.json["imported"], response.json["skipped"]), (2, 1))
        values = self.target.load_json(self.target.SERVERS_FILE, [])
        self.assertEqual(len(values), 3)
        original = next(value for value in values if value["id"] == original_id)
        self.assertEqual(original["password"], "target-existing-password")
        self.assertEqual(original["host"], "ECS.EXAMPLE.INVALID")

    def test_api_keys_keep_existing_fill_empty_and_ignore_blank_imported_values(self):
        self.add(self.source)
        self.settings(self.source, openai_key="source-openai-key", deepseek_key="source-deepseek-key")
        self.settings(self.target, openai_key="target-openai-key", anthropic_key="target-anthropic-key")
        backup = self.export(self.source, "encrypted")
        self.assertEqual(self.import_backup(self.target, backup).status_code, 200)
        self.assertEqual(self.target.load_json(self.target.SETTINGS_FILE, {}), {
            "openai_key": "target-openai-key", "anthropic_key": "target-anthropic-key", "deepseek_key": "source-deepseek-key"})
        self.assertEqual(self.import_backup(self.target, backup, overwrite_api_keys=True).status_code, 200)
        self.assertEqual(self.target.load_json(self.target.SETTINGS_FILE, {})["openai_key"], "source-openai-key")
        blank = desktop_services.encode_backup([], {"openai_key": "", "anthropic_key": ""}, mode="encrypted", passphrase=PASSPHRASE)
        self.assertEqual(self.import_backup(self.target, blank, overwrite_api_keys=True).status_code, 200)
        self.assertEqual(self.target.load_json(self.target.SETTINGS_FILE, {})["anthropic_key"], "target-anthropic-key")
        self.assertEqual(self.target.load_json(self.target.SETTINGS_FILE, {})["openai_key"], "source-openai-key")

    def test_one_settings_write_failure_rolls_back_both_files_and_erases_journal(self):
        self.add(self.target, host="existing.example.invalid")
        self.settings(self.target, openai_key="existing-key")
        self.add(self.source)
        self.settings(self.source, deepseek_key="new-test-only-key")
        backup = self.export(self.source, "encrypted")
        previous = self.stored_bytes(self.target)
        original = product_integration.atomic_json_write
        failed = False
        inspected = []

        def fail_once(path, value):
            nonlocal failed
            if Path(path) == Path(self.target.SETTINGS_FILE) and not failed:
                failed = True
                raw = (Path(self.target.DATA_DIR) / "import-transaction.json").read_bytes()
                inspected.append(raw)
                self.assertIn(b"dpapi:v1:", raw)
                self.assertNotIn(b"test-only-password", raw)
                self.assertNotIn(b"new-test-only-key", raw)
                raise OSError("test-only simulated disk error")
            return original(path, value)

        with patch.object(product_integration, "atomic_json_write", side_effect=fail_once):
            response = self.import_backup(self.target, backup)
        self.assertEqual(response.status_code, 500)
        self.assertTrue(inspected)
        self.assertEqual(self.stored_bytes(self.target), previous)
        self.assertFalse((Path(self.target.DATA_DIR) / "import-transaction.json").exists())

    def test_interrupted_encrypted_journal_recovers_fixed_files_and_preserves_host_trust(self):
        trusted = Path(self.target.KNOWN_HOSTS_FILE)
        trusted.write_text("test-only trust sentinel", encoding="utf-8")
        payload = self.journal_payload()
        journal = Path(self.target.DATA_DIR) / "import-transaction.json"
        atomic_json_write(journal, payload)
        self.assertNotIn("test-only-journal-secret", journal.read_text())
        restored = self.make_manager("target")
        self.assertFalse(journal.exists())
        self.assertEqual(restored.load_json(restored.SERVERS_FILE, [])[0]["password"], "test-only-journal-secret")
        self.assertEqual(restored.load_json(restored.SETTINGS_FILE, {})["openai_key"], "test-only-journal-key")
        self.assertEqual(trusted.read_text(), "test-only trust sentinel")
        self.assertNotIn(b"test-only-journal-secret", Path(restored.SERVERS_FILE).read_bytes())

    def test_local_ssh_preference_survives_import_and_interrupted_recovery(self):
        self.settings(self.target, ssh_auto_update_host_key=False)
        self.settings(self.source, ssh_auto_update_host_key=True)
        self.add(self.source)
        backup = self.export(self.source, "encrypted")
        self.assertNotIn("ssh_auto_update_host_key", json.dumps(backup))
        response = self.import_backup(self.target, backup)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIs(self.target.load_json(self.target.SETTINGS_FILE, {})["ssh_auto_update_host_key"], False)
        payload = self.journal_payload(settings={"openai_key": "test-only-journal-key", "ssh_auto_update_host_key": False})
        atomic_json_write(Path(self.target.DATA_DIR) / "import-transaction.json", payload)
        restored = self.make_manager("target")
        self.assertIs(restored.load_json(restored.SETTINGS_FILE, {})["ssh_auto_update_host_key"], False)
        self.assertEqual(restored.load_json(restored.SETTINGS_FILE, {})["openai_key"], "test-only-journal-key")

    def test_recovery_rejects_non_boolean_ssh_preference(self):
        for value in ("true", 1, None, [], {}):
            with self.subTest(value=value):
                profile = "invalid-ssh-preference-" + uuid.uuid4().hex
                directory = self.root / profile
                directory.mkdir()
                atomic_json_write(directory / "import-transaction.json",
                                  self.journal_payload(settings={"ssh_auto_update_host_key": value}))
                with self.assertRaises(RuntimeError):
                    self.make_manager(profile)
                self.assertFalse((directory / "settings.json").exists())

    def test_failed_rollback_retains_encrypted_redo_journal_for_restart(self):
        self.add(self.target, host="existing.example.invalid")
        self.settings(self.target, openai_key="existing-key")
        self.add(self.source)
        self.settings(self.source, deepseek_key="new-test-only-key")
        backup = self.export(self.source, "encrypted")
        original = product_integration.atomic_json_write

        def unavailable_settings(path, value):
            if Path(path) == Path(self.target.SETTINGS_FILE):
                raise OSError("test-only persistent file error")
            return original(path, value)

        with patch.object(product_integration, "atomic_json_write", side_effect=unavailable_settings):
            response = self.import_backup(self.target, backup)
        self.assertEqual(response.status_code, 500)
        journal = Path(self.target.DATA_DIR) / "import-transaction.json"
        self.assertTrue(journal.exists())
        raw = journal.read_bytes()
        self.assertIn(b"dpapi:v1:", raw)
        self.assertNotIn(b"test-only-password", raw)
        self.assertNotIn(b"new-test-only-key", raw)
        restored = self.make_manager("target")
        self.assertFalse(journal.exists())
        self.assertEqual(len(restored.load_json(restored.SERVERS_FILE, [])), 2)
        self.assertEqual(restored.load_json(restored.SETTINGS_FILE, {})["deepseek_key"], "new-test-only-key")

    def test_journal_rejects_paths_unknown_nested_fields_and_invalid_record_ids(self):
        sentinel = self.root / "untouched.txt"
        sentinel.write_text("must remain unchanged", encoding="utf-8")
        valid = self.journal_payload()
        variants = []
        top_path = copy.deepcopy(valid)
        top_path["path"] = str(sentinel)
        variants.append(top_path)
        filename_path = copy.deepcopy(valid)
        filename_path["files"][str(sentinel)] = []
        variants.append(filename_path)
        server_path = copy.deepcopy(valid)
        server_path["files"]["servers.json"][0]["path"] = str(sentinel)
        variants.append(server_path)
        setting_path = copy.deepcopy(valid)
        setting_path["files"]["settings.json"]["private_key_path"] = str(sentinel)
        variants.append(setting_path)
        bad_id = copy.deepcopy(valid)
        bad_id["files"]["servers.json"][0]["id"] = "../settings.json"
        variants.append(bad_id)
        for index, value in enumerate(variants):
            with self.subTest(index=index):
                profile = self.root / ("bad-journal-" + str(index))
                profile.mkdir()
                journal = profile / "import-transaction.json"
                atomic_json_write(journal, value)
                with self.assertRaises((RuntimeError, ValueError)):
                    self.make_manager(profile.name)
                self.assertEqual(sentinel.read_text(), "must remain unchanged")
                self.assertTrue(journal.exists())
                self.assertFalse((profile / "servers.json").exists())
                self.assertFalse((profile / "settings.json").exists())

    def test_private_key_header_without_a_real_key_is_rejected_before_import(self):
        self.add(self.target)
        previous = self.stored_bytes(self.target)
        fake_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key\n-----END OPENSSH PRIVATE KEY-----\n"
        backup = desktop_services.encode_backup([
            {"host": "invalid-key.example.invalid", "name": "Invalid key", "port": 22, "user": "ubuntu",
             "auth_type": "private_key", "private_key": fake_key, "key_passphrase": ""}],
            {}, mode="encrypted", passphrase=PASSPHRASE)
        response = self.import_backup(self.target, backup)
        self.assertEqual(response.status_code, 400)
        self.assertIn("私钥", response.json["msg"])
        self.assertEqual(self.stored_bytes(self.target), previous)

    def test_every_product_api_requires_csrf_and_rejects_cross_origin_requests(self):
        routes = [(rule.rule, method) for rule in self.source.app.url_map.iter_rules()
                  if rule.rule.startswith("/api/product") for method in rule.methods & {"GET", "POST"}]
        self.assertGreaterEqual(len(routes), 9)
        for path, method in routes:
            with self.subTest(path=path, method=method):
                for headers in ({}, {"X-CSRF-Token": "wrong"}, {"X-CSRF-Token": self.source.CSRF_TOKEN, "Origin": "https://evil.example"}):
                    self.assertEqual(self.request(self.source, method, path, headers=headers, json={}).status_code, 403)

    def test_startup_readonly_product_and_unconfigured_update_never_contact_network(self):
        for path in ("/api/product", "/api/product/history", "/api/product/diagnostics", "/help", "/privacy", "/license"):
            self.assertEqual(self.request(self.source, "GET", path).status_code, 200)
        response = self.request(self.source, "POST", "/api/product/update/check", json={})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.request(self.source, "GET", "/api/product").json["updates"]["state"], "unconfigured")
        for mock in self.network_mocks:
            mock.assert_not_called()

    def test_onboarding_state_is_persisted_only_for_explicit_boolean_completion(self):
        self.assertFalse(self.request(self.source, "GET", "/api/product").json["onboarding"]["completed"])
        for invalid in (False, 1, "true", None):
            self.assertEqual(self.request(self.source, "POST", "/api/product/onboarding", json={"completed": invalid}).status_code, 400)
        response = self.request(self.source, "POST", "/api/product/onboarding", json={"completed": True})
        self.assertEqual(response.status_code, 200)
        restarted = self.make_manager("source")
        persisted = self.request(restarted, "GET", "/api/product").json["onboarding"]
        self.assertTrue(persisted["completed"])
        self.assertIsInstance(persisted["completed_at"], (int, float))
        self.assertFalse(self.request(self.target, "GET", "/api/product").json["onboarding"]["completed"])

    def test_history_and_diagnostics_contain_only_fixed_states_and_times(self):
        self.add(self.source, name="test-only-secret-name", host="private-address.example.invalid")
        self.settings(self.source, openai_key="test-only-secret-api-key")
        jid = self.source.new_job("test-only-secret-job-output", name="test-only-secret-name", host="private-address.example.invalid")
        running = self.request(self.source, "GET", "/api/product/history")
        self.assertEqual(running.status_code, 200)
        self.assertEqual(running.json["history"][-1]["status"], "running")
        self.source.jobs[jid]["status"] = "done"
        self.source.jobs[jid]["output"] += " test-only-final-output"
        history = self.request(self.source, "GET", "/api/product/history").json["history"]
        self.assertEqual(history[-1]["status"], "done")
        for event in history:
            self.assertLessEqual(set(event), {"kind", "status", "created_at", "finished_at"})
            self.assertIn(event["kind"], desktop_services.TASK_KINDS)
            self.assertIn(event["status"], desktop_services.TASK_STATUSES)
        diagnostic = self.request(self.source, "GET", "/api/product/diagnostics")
        self.assertEqual(diagnostic.json["configuration"], {"server_count": 1, "api_key_count": 1})
        raw = json.dumps(history) + diagnostic.get_data(as_text=True) + (Path(self.source.DATA_DIR) / "task-history.json").read_text()
        for secret in ("test-only-secret", "private-address.example.invalid", "test-only-final-output", "BEGIN OPENSSH", str(self.root)):
            self.assertNotIn(secret, raw)

    def test_running_tasks_and_shutdown_block_import_without_changing_data(self):
        self.add(self.source)
        backup = self.export(self.source)
        previous = self.stored_bytes(self.target)
        jid = self.target.new_job("test-only-task")
        self.assertEqual(self.import_backup(self.target, backup).status_code, 409)
        self.assertEqual(self.stored_bytes(self.target), previous)
        self.target.jobs[jid]["status"] = "done"
        self.assertTrue(self.target.prepare_shutdown())
        self.assertEqual(self.import_backup(self.target, backup).status_code, 409)
        self.assertEqual(self.stored_bytes(self.target), previous)

    def test_wrong_backup_passphrase_and_modified_ciphertext_never_change_data(self):
        self.add(self.source)
        self.add(self.target, host="existing.example.invalid")
        backup = self.export(self.source, "encrypted")
        previous = self.stored_bytes(self.target)
        response = self.import_backup(self.target, backup, passphrase="incorrect-test-only-passphrase")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.stored_bytes(self.target), previous)
        changed = copy.deepcopy(backup)
        replacement = "A" if changed["ciphertext"][0] != "A" else "B"
        changed["ciphertext"] = replacement + changed["ciphertext"][1:]
        self.assertEqual(self.import_backup(self.target, changed).status_code, 400)
        self.assertEqual(self.stored_bytes(self.target), previous)
        self.assertFalse((Path(self.target.DATA_DIR) / "import-transaction.json").exists())


if __name__ == "__main__":
    unittest.main()
