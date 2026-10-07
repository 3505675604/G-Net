"""Product security tests use fake configuration and mocked HTTPS only."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import threading
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import desktop_services as services


SERVER = {"id": "fake-source-id", "name": "private-customer-name", "host": "secret-host.example.test",
          "port": 22, "user": "private_user", "auth_type": "password", "password": "fake-SSH-secret"}
SETTINGS = {"openai_key": "fake-API-secret", "deepseek_key": "", "anthropic_key": ""}
PASSPHRASE = "仅供测试-dummy-strong-passphrase"
INSTALLER = b"MZ" + b"fake signed Windows installer for test" * 20
MANIFEST_URL = "https://release.example.test/update.json"


def manifest(**extra):
    return {"schema": 1, "version": "0.2.1", "platform": "windows-x64",
            "url": "https://release.example.test/downloads/G-Network-0.2.1-windows-x64-Setup.exe",
            "sha256": hashlib.sha256(INSTALLER).hexdigest(), "size": len(INSTALLER),
            "release_notes": "测试新版\n只验证下载，不运行", "published_at": "2026-10-04", **extra}


class FakeResponse:
    def __init__(self, data, *, url=MANIFEST_URL, headers=None, status=200):
        self.stream = io.BytesIO(data)
        self.headers = headers or {}
        self.status = status
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def geturl(self):
        return self.url

    def read(self, size):
        return self.stream.read(size)


class BackupTests(unittest.TestCase):
    def test_metadata_export_drops_all_secrets_ids_and_unknown_metadata(self):
        source = {**SERVER, "private_key": "secret private key", "key_passphrase": "key secret",
                  "known_hosts": "never trust identity", "file_path": "C:/fake"}
        backup = services.encode_backup([source], SETTINGS)
        serialized = json.dumps(backup)
        for secret in ("fake-SSH-secret", "fake-API-secret", "secret private key", "key secret", "fake-source-id", "never trust identity", "file_path"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(backup["data"]["settings"], {})
        restored, encrypted = services.decode_backup(backup)
        self.assertFalse(encrypted)
        self.assertEqual(restored["servers"][0]["auth_type"], "password")
        self.assertTrue(restored["servers"][0]["credential_required"])
        self.assertNotIn("password", restored["servers"][0])

    def test_encrypted_roundtrip_restores_credentials_without_local_bound_tokens(self):
        backup = services.encode_backup([SERVER], SETTINGS, mode="encrypted", passphrase=PASSPHRASE)
        serialized = json.dumps(backup)
        for secret in (SERVER["host"], SERVER["user"], SERVER["password"], SETTINGS["openai_key"], PASSPHRASE):
            self.assertNotIn(secret, serialized)
        restored, encrypted = services.decode_backup(backup, passphrase=PASSPHRASE)
        self.assertTrue(encrypted)
        self.assertEqual(restored["servers"][0]["password"], SERVER["password"])
        self.assertEqual(restored["settings"]["openai_key"], SETTINGS["openai_key"])
        self.assertFalse(restored["servers"][0]["credential_required"])

    def test_private_key_and_agent_credentials_only_keep_active_authentication(self):
        private = {**SERVER, "auth_type": "private_key", "private_key": "-----BEGIN PRIVATE KEY-----\nDUMMY\n-----END PRIVATE KEY-----",
                   "key_passphrase": "fake-key-passphrase"}
        agent = {**SERVER, "host": "agent.example.test", "auth_type": "agent", "private_key": "not-exported"}
        backup = services.encode_backup([private, agent], {}, mode="encrypted", passphrase=PASSPHRASE)
        restored, _ = services.decode_backup(backup, passphrase=PASSPHRASE)
        self.assertEqual(restored["servers"][0]["password"], "")
        self.assertEqual(restored["servers"][0]["private_key"], private["private_key"])
        for field in ("password", "private_key", "key_passphrase"):
            self.assertEqual(restored["servers"][1][field], "")

    def test_each_encryption_uses_distinct_salt_nonce_and_ciphertext(self):
        first = services.encode_backup([SERVER], {}, mode="encrypted", passphrase=PASSPHRASE)
        second = services.encode_backup([SERVER], {}, mode="encrypted", passphrase=PASSPHRASE)
        self.assertNotEqual(first["kdf"]["salt"], second["kdf"]["salt"])
        self.assertNotEqual(first["nonce"], second["nonce"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_wrong_password_and_tampered_ciphertext_cannot_import(self):
        backup = services.encode_backup([SERVER], SETTINGS, mode="encrypted", passphrase=PASSPHRASE)
        with self.assertRaisesRegex(services.ProductError, "口令不正确"):
            services.decode_backup(backup, passphrase="another-dummy-passphrase")
        changed = copy.deepcopy(backup)
        value = bytearray(base64.b64decode(changed["ciphertext"]))
        value[-1] ^= 1
        changed["ciphertext"] = base64.b64encode(value).decode()
        with self.assertRaisesRegex(services.ProductError, "文件已被修改"):
            services.decode_backup(changed, passphrase=PASSPHRASE)

    def test_malicious_kdf_is_rejected_before_expensive_derivation(self):
        backup = services.encode_backup([SERVER], {}, mode="encrypted", passphrase=PASSPHRASE)
        for changes in ({"n": 2 ** 40}, {"r": True}, {"p": 999999}, {"length": 999999}):
            bad = copy.deepcopy(backup)
            bad["kdf"].update(changes)
            with self.subTest(changes=changes), patch.object(services, "Scrypt") as kdf:
                with self.assertRaises(services.ProductError):
                    services.decode_backup(bad, passphrase=PASSPHRASE)
                kdf.assert_not_called()

    def test_unsupported_crypto_and_bad_base64_are_rejected(self):
        backup = services.encode_backup([SERVER], {}, mode="encrypted", passphrase=PASSPHRASE)
        for field, value in (("cipher", "AES-CBC"), ("nonce", "not base64"), ("nonce", "YWJj"),
                             ("ciphertext", ""), ("schema", True)):
            bad = copy.deepcopy(backup)
            bad[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(services.ProductError):
                services.decode_backup(bad, passphrase=PASSPHRASE)

    def test_import_rejects_identity_path_ids_unknown_auth_and_duplicates(self):
        backup = services.encode_backup([SERVER], {})
        for field, value in (("known_hosts", "fake identity"), ("id", "forged-id"), ("path", "../settings.json"),
                             ("auth_type", "unknown"), ("password", "plain-text-secret"), ("host", "bad;touch")):
            bad = copy.deepcopy(backup)
            bad["data"]["servers"][0][field] = value
            with self.subTest(field=field), self.assertRaises(services.ProductError):
                services.decode_backup(bad)
        repeated = copy.deepcopy(backup)
        repeated["data"]["servers"].append(copy.deepcopy(repeated["data"]["servers"][0]))
        with self.assertRaisesRegex(services.ProductError, "重复"):
            services.decode_backup(repeated)

    def test_settings_unknown_fields_dpapi_and_short_password_fail(self):
        for settings in ({"path": "../secret"}, {"openai_key": "dpapi:v1:dummy"}, {"openai_key": "line\nbreak"}):
            with self.subTest(settings=settings), self.assertRaises(services.ProductError):
                services.encode_backup([SERVER], settings, mode="encrypted", passphrase=PASSPHRASE)
        for password in (None, "short", 123, "x" * 257):
            with self.subTest(password=password), self.assertRaises(services.ProductError):
                services.encode_backup([SERVER], {}, mode="encrypted", passphrase=password)

    def test_backup_size_and_server_count_are_bounded(self):
        with self.assertRaises(services.ProductError):
            services.encode_backup([SERVER] * 201, {})
        unique = [{**SERVER, "host": f"host{i}.example.test", "auth_type": "private_key", "private_key": "x" * 65536}
                  for i in range(10)]
        with self.assertRaisesRegex(services.ProductError, "512 KB"):
            services.encode_backup(unique, {}, mode="encrypted", passphrase=PASSPHRASE)


class FetchSecurityTests(unittest.TestCase):
    def fake_opener(self, response):
        opener = Mock()
        opener.open.return_value = response
        return patch.object(services.urllib.request, "build_opener", return_value=opener)

    def test_fetch_checks_length_overflow_without_reading_oversized_body(self):
        response = FakeResponse(b"large", headers={"Content-Length": "1000000"})
        with self.fake_opener(response), self.assertRaisesRegex(services.ProductError, "大小"):
            services.fetch_https(MANIFEST_URL, maximum=10)

    def test_streaming_overflow_and_incomplete_download_are_rejected(self):
        for response in (FakeResponse(b"12345"), FakeResponse(b"12", headers={"Content-Length": "4"})):
            with self.subTest(headers=response.headers), self.fake_opener(response), self.assertRaises(services.ProductError):
                services.fetch_https(MANIFEST_URL, maximum=4)

    def test_content_encoding_and_redirected_final_address_are_rejected(self):
        for response in (FakeResponse(b"{}", headers={"Content-Encoding": "gzip"}),
                         FakeResponse(b"{}", url="http://release.example.test/update.json"),
                         FakeResponse(b"{}", status=302)):
            with self.subTest(headers=response.headers), self.fake_opener(response), self.assertRaises(services.ProductError):
                services.fetch_https(MANIFEST_URL, maximum=100)

    def test_https_request_uses_certificate_context_no_proxy_and_redirect_blocker(self):
        response = FakeResponse(b"{}", headers={"Content-Length": "2"})
        with self.fake_opener(response) as patched:
            self.assertEqual(services.fetch_https(MANIFEST_URL, maximum=100), b"{}")
            handlers = patched.call_args.args
            self.assertTrue(any(isinstance(handler, services.urllib.request.HTTPSHandler) for handler in handlers))
            proxy = next(handler for handler in handlers if isinstance(handler, services.urllib.request.ProxyHandler))
            self.assertEqual(proxy.proxies, {})
            redirect = next(handler for handler in handlers if isinstance(handler, services._RejectRedirect))
            with self.assertRaisesRegex(services.ProductError, "重定向"):
                redirect.redirect_request(None, None, 302, "", {}, "http://evil.test")

    def test_streaming_download_writes_sink_and_timeout_is_finite(self):
        sink = io.BytesIO()
        with self.fake_opener(FakeResponse(b"abcdef", headers={"Content-Length": "6"})):
            self.assertEqual(services.fetch_https(MANIFEST_URL, maximum=100, sink=sink), 6)
        self.assertEqual(sink.getvalue(), b"abcdef")
        with self.fake_opener(FakeResponse(b"abcdef")), patch.object(services.time, "monotonic", side_effect=[0, 1000]):
            with self.assertRaisesRegex(services.ProductError, "超时"):
                services.fetch_https(MANIFEST_URL, maximum=100)

    def test_network_errors_do_not_echo_sensitive_url_or_exception(self):
        opener = Mock()
        opener.open.side_effect = OSError("sensitive-private-url-secret")
        with patch.object(services.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(services.ProductError) as error:
                services.fetch_https(MANIFEST_URL, maximum=100)
        self.assertNotIn("sensitive-private", str(error.exception))

    def test_manifest_rejects_cross_origin_downgrade_credentials_local_or_wrong_platform(self):
        bad_urls = ["http://release.example.test/setup.exe", "https://other.example.test/setup.exe",
                    "https://admin:secret@release.example.test/setup.exe", "https://release.example.test:444/setup.exe",
                    "https://release.example.test/setup.exe#fragment", "https://release.example.test/setup.msi",
                    "https://release.example.test/path/%2e%2e/setup.exe", "https://127.0.0.1/setup.exe",
                    "https://release.example.test\\evil/setup.exe", "file:///C:/setup.exe"]
        for url in bad_urls:
            with self.subTest(url=url), self.assertRaises(services.ProductError):
                services.validate_manifest(manifest(url=url), MANIFEST_URL)
        for change in ({"platform": "windows-arm64"}, {"sha256": "oops"}, {"size": True},
                       {"size": services.MAX_INSTALLER_BYTES + 1}, {"schema": True}, {"version": "1.2.3/../../../"},
                       {"unknown": "field"}):
            with self.subTest(change=change), self.assertRaises(services.ProductError):
                services.validate_manifest(manifest(**change), MANIFEST_URL)

    def test_https_origin_rejects_local_and_invalid_domain_even_for_config(self):
        for url in ("https://localhost/config", "https://a.local/config", "https://a.internal/config",
                    "https://192.168.1.1/config", "https://[::1]/config", "https://foo..example.test/config",
                    "https://-foo.example.test/config", "https://example.test./config", "https://evil.test/\nconfig"):
            with self.subTest(url=url), self.assertRaises(services.ProductError):
                services._https_url(url)

    def test_strict_json_rejects_duplicates_infinity_deep_objects_and_big_body(self):
        for raw in (b'{"version":1,"version":2}', b'{"a":NaN}', b'{"a":Infinity}', b"[" * 14 + b"0" + b"]" * 14):
            with self.subTest(raw=raw), self.assertRaises(services.ProductError):
                services._strict_json(raw, 100)
        with self.assertRaises(services.ProductError):
            services._strict_json(b"x" * 101, 100)

    def test_public_dns_result_is_connected_once_without_second_hostname_lookup(self):
        result = [(services.socket.AF_INET, services.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                  (services.socket.AF_INET6, services.socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443, 0, 0))]
        socket_instance = Mock()
        with patch.object(services.socket, "getaddrinfo", return_value=result) as lookup, \
                patch.object(services.socket, "socket", return_value=socket_instance):
            self.assertIs(services._public_connection(("release.example.test", 443), timeout=12), socket_instance)
        lookup.assert_called_once_with("release.example.test", 443, 0, services.socket.SOCK_STREAM)
        socket_instance.connect.assert_called_once_with(("8.8.8.8", 443))
        self.assertLessEqual(socket_instance.settimeout.call_args.args[0], 12)

    def test_ipv6_public_dns_and_ipv4_fallback_keep_validated_addresses(self):
        result = [(services.socket.AF_INET, services.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                  (services.socket.AF_INET6, services.socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443, 0, 0))]
        first, second = Mock(), Mock()
        first.connect.side_effect = OSError("private failure detail")
        with patch.object(services.socket, "getaddrinfo", return_value=result), \
                patch.object(services.socket, "socket", side_effect=[first, second]):
            self.assertIs(services._public_connection(("release.example.test", 443), timeout=12), second)
        first.close.assert_called_once()
        second.connect.assert_called_once_with(("2001:4860:4860::8888", 443, 0, 0))

    def test_private_metadata_reserved_and_mixed_dns_answers_are_rejected_before_connect(self):
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1",
                   "224.0.0.1", "::1", "fe80::1", "fc00::1", "2001:db8::1"):
            family = services.socket.AF_INET6 if ":" in ip else services.socket.AF_INET
            private = (ip, 443, 0, 0) if family == services.socket.AF_INET6 else (ip, 443)
            results = [(services.socket.AF_INET, services.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                       (family, services.socket.SOCK_STREAM, 6, "", private)]
            with self.subTest(ip=ip), patch.object(services.socket, "getaddrinfo", return_value=results), \
                    patch.object(services.socket, "socket") as create:
                with self.assertRaises(services.ProductError) as error:
                    services._public_connection(("release.example.test", 443), timeout=12)
                self.assertNotIn(ip, str(error.exception))
                create.assert_not_called()

    def test_dns_error_expired_budget_and_empty_results_are_sanitized(self):
        with patch.object(services.socket, "getaddrinfo", side_effect=OSError("secret-host-ip")), \
                self.assertRaises(services.ProductError) as error:
            services._public_connection(("release.example.test", 443), timeout=12)
        self.assertNotIn("secret-host-ip", str(error.exception))
        with patch.object(services.socket, "getaddrinfo") as lookup, self.assertRaises(services.ProductError):
            services._public_connection(("release.example.test", 443), timeout=12, deadline=0)
        lookup.assert_not_called()
        with patch.object(services.socket, "getaddrinfo", return_value=[]), self.assertRaises(services.ProductError):
            services._public_connection(("release.example.test", 443), timeout=12)

    def test_slow_dns_has_finite_wait_and_never_starts_connection_after_timeout(self):
        release, finished = threading.Event(), threading.Event()

        def slow_dns(*args):
            try:
                release.wait(1)
                return [(services.socket.AF_INET, services.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
            finally:
                finished.set()

        try:
            with patch.object(services.socket, "getaddrinfo", side_effect=slow_dns), \
                    patch.object(services.socket, "socket") as create, self.assertRaises(services.ProductError):
                services._public_connection(("release.example.test", 443), timeout=0.02)
            create.assert_not_called()
        finally:
            release.set()
            self.assertTrue(finished.wait(1))

    def test_body_reader_uses_read1_and_absolute_deadline_even_for_slow_stream(self):
        response = FakeResponse(b"unused")
        response.read1 = Mock(return_value=b"slow partial body")
        with self.fake_opener(response), patch.object(services.time, "monotonic", side_effect=[0, 1, 91]):
            with self.assertRaisesRegex(services.ProductError, "超时"):
                services.fetch_https(MANIFEST_URL, maximum=100)
        response.read1.assert_called_once()

    def test_ssl_raw_reads_and_headers_share_absolute_deadline(self):
        context = services.ssl.create_default_context()
        context.sslsocket_class = services._DeadlineSSLSocket
        context._flnetwork_deadline = 100
        raw = services.socket.socket()
        encrypted = context.wrap_socket(raw, server_hostname="release.example.test", do_handshake_on_connect=False)
        try:
            encrypted.settimeout(12)
            with patch.object(services.time, "monotonic", return_value=97), \
                    patch.object(services.ssl.SSLSocket, "read", return_value=b"ok"):
                self.assertEqual(encrypted.read(2), b"ok")
                self.assertEqual(encrypted.gettimeout(), 3)
            with patch.object(services.time, "monotonic", return_value=101), \
                    patch.object(services.ssl.SSLSocket, "read") as reader:
                with self.assertRaises(TimeoutError):
                    encrypted.read(2)
                reader.assert_not_called()
        finally:
            encrypted.close()


class ProductApiTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.importer = Mock(return_value={"imported": 1, "skipped": 0})
        self.signer = Mock(return_value=True)
        self.running = False
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, MAX_CONTENT_LENGTH=services.MAX_REQUEST_BYTES)
        self.product = services.register_product_api(
            self.app, data_dir=Path(self.folder.name), version="0.2.0",
            read_servers=lambda: [copy.deepcopy(SERVER)], read_settings=lambda: SETTINGS.copy(),
            import_data=self.importer, task_snapshot=lambda: [{"status": "running", "output": "private-log-secret",
                                                              "host": SERVER["host"], "user": SERVER["user"]}],
            has_running_jobs=lambda: self.running)
        self.client = self.app.test_client()

    def tearDown(self):
        self.folder.cleanup()

    def post(self, endpoint, body):
        return self.client.post("/api/product/" + endpoint, json=body)

    def enable_update(self, *, downloadable=True):
        self.product.manifest_url = MANIFEST_URL
        self.product.verify_installer = self.signer
        self.product.update_download_enabled = downloadable

    def checked_update(self):
        self.enable_update()
        with patch.object(services, "fetch_https", return_value=json.dumps(manifest()).encode()):
            response = self.post("update/check", {})
        self.assertEqual(response.status_code, 200)
        return response

    @staticmethod
    def fake_download(url, *, maximum, sink):
        sink.write(INSTALLER)
        return len(INSTALLER)

    def test_first_launch_is_offline_and_updates_unconfigured(self):
        with patch.object(services, "fetch_https") as fetch:
            response = self.client.get("/api/product")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["product"]["name"], "G-Network")
            self.assertEqual(response.json["updates"]["state"], "unconfigured")
            self.assertFalse(response.json["onboarding"]["completed"])
            blocked = self.post("update/check", {})
            self.assertEqual(blocked.status_code, 409)
            fetch.assert_not_called()

    def test_onboarding_is_persisted_and_only_explicit_completion_is_accepted(self):
        for body in ({"completed": False}, {"completed": "true"}, {"completed": True, "path": "../evil"}):
            self.assertEqual(self.post("onboarding", body).status_code, 400)
        self.assertEqual(self.post("onboarding", {"completed": True}).status_code, 200)
        persisted = self.product.onboarding()
        self.assertTrue(persisted["completed"])
        self.assertGreater(persisted["completed_at"], 0)
        self.assertEqual(json.loads(self.product.state_path.read_text()), persisted)

    def test_diagnostics_contains_only_allowed_nonidentifying_fields(self):
        self.product.record_task("tool", "done", finished_at=time.time())
        response = self.client.get("/api/product/diagnostics")
        serialized = response.get_data(as_text=True)
        for secret in (SERVER["host"], SERVER["user"], SERVER["name"], SERVER["password"], SETTINGS["openai_key"],
                       "private-log-secret", self.folder.name):
            self.assertNotIn(secret, serialized)
        self.assertEqual(response.json["configuration"], {"server_count": 1, "api_key_count": 1})
        self.assertIn("attachment", response.headers["Content-Disposition"])

    def test_task_history_is_bounded_filters_unknown_keys_and_rejects_free_text(self):
        for _ in range(110):
            self.product.record_task("node", "done", created_at=10, finished_at=11)
        self.assertFalse(self.product.record_task("secret-host-command", "done"))
        raw = self.product.history()
        raw[0].update(output="raw-secret", name=SERVER["name"], host=SERVER["host"], path=self.folder.name)
        services.atomic_json_write(self.product.history_path, raw)
        response = self.client.get("/api/product/history")
        self.assertEqual(len(response.json["history"]), 100)
        self.assertNotIn("raw-secret", response.get_data(as_text=True))
        self.assertEqual(set(response.json["history"][0]), {"kind", "status", "created_at", "finished_at"})

    def test_preview_contains_counts_no_credentials_and_import_passes_validated_data(self):
        exported = self.post("backup/export", {"mode": "encrypted", "passphrase": PASSPHRASE})
        self.assertEqual(exported.status_code, 200)
        body = {"backup": exported.json["backup"], "passphrase": PASSPHRASE}
        preview = self.post("backup/preview", body)
        self.assertEqual(preview.status_code, 200)
        self.assertEqual(preview.json["server_count"], 1)
        self.assertTrue(preview.json["encrypted"])
        self.assertNotIn(SERVER["password"], preview.get_data(as_text=True))
        self.importer.assert_not_called()
        imported = self.post("backup/import", body)
        self.assertEqual(imported.status_code, 200)
        args, kwargs = self.importer.call_args
        self.assertNotIn("id", args[0][0])
        self.assertEqual(args[0][0]["password"], SERVER["password"])
        self.assertEqual(kwargs, {"overwrite_api_keys": False})

    def test_metadata_import_requires_credentials_and_no_overwrite_by_default(self):
        exported = self.post("backup/export", {})
        imported = self.post("backup/import", {"backup": exported.json["backup"]})
        self.assertEqual(imported.status_code, 200)
        self.assertTrue(imported.json["requires_credentials"])
        server = self.importer.call_args.args[0][0]
        self.assertTrue(server["credential_required"])
        self.assertNotIn("password", server)
        self.assertEqual(self.importer.call_args.args[1], {})

    def test_backup_import_is_all_validated_before_storage_and_busy_app_is_unchanged(self):
        exported = self.post("backup/export", {}).json["backup"]
        exported["data"]["servers"].append({"host": "bad command;", "name": "bad", "user": "root"})
        self.assertEqual(self.post("backup/import", {"backup": exported}).status_code, 400)
        self.importer.assert_not_called()
        self.running = True
        self.assertEqual(self.post("backup/import", {"backup": services.encode_backup([SERVER], {})}).status_code, 409)
        self.importer.assert_not_called()

    def test_backup_rejects_replace_mode_wrong_password_and_invalid_overwrite_boolean(self):
        backup = services.encode_backup([SERVER], {}, mode="encrypted", passphrase=PASSPHRASE)
        for body in ({"backup": backup, "passphrase": PASSPHRASE, "mode": "replace"},
                     {"backup": backup, "passphrase": "another-password-123"},
                     {"backup": backup, "passphrase": PASSPHRASE, "overwrite_api_keys": "true"}):
            with self.subTest(body_keys=list(body)):
                self.assertEqual(self.post("backup/import", body).status_code, 400)
        self.importer.assert_not_called()

    def test_request_rejects_duplicate_keys_oversize_and_unknown_paths(self):
        duplicate = self.client.post("/api/product/onboarding", data='{"completed":false,"completed":true}',
                                     content_type="application/json")
        self.assertEqual(duplicate.status_code, 400)
        large = self.client.post("/api/product/backup/import", data=b"x" * (services.MAX_REQUEST_BYTES + 1),
                                 content_type="application/json")
        self.assertEqual(large.status_code, 413)
        self.assertEqual(self.post("update/download", {"url": "https://evil.test/setup.exe"}).status_code, 400)

    def test_check_returns_public_schema_without_paths_and_manual_only(self):
        response = self.checked_update()
        self.assertEqual(response.json["updates"]["state"], "available")
        release = response.json["updates"]["release"]
        self.assertTrue(release["downloadable"])
        self.assertIn("notes", release)
        self.assertNotIn("url", release)
        self.assertNotIn(self.folder.name, response.get_data(as_text=True))

    def test_up_to_date_and_failed_check_dont_offer_stale_release(self):
        self.checked_update()
        with patch.object(services, "fetch_https", return_value=json.dumps(manifest(version="0.2.0")).encode()):
            response = self.post("update/check", {})
        self.assertEqual(response.json["updates"]["state"], "up_to_date")
        self.assertIsNone(self.product.release)
        with patch.object(services, "fetch_https", side_effect=services.ProductError("网络错误")):
            self.assertEqual(self.post("update/check", {}).status_code, 400)
        self.assertIsNone(self.product.release)

    def test_download_is_disabled_when_publisher_pin_missing_even_with_verifier(self):
        self.enable_update(downloadable=False)
        with patch.object(services, "fetch_https", return_value=json.dumps(manifest()).encode()):
            response = self.post("update/check", {})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["updates"]["release"]["downloadable"])
        with patch.object(services, "fetch_https") as fetch:
            response = self.post("update/download", {"version": "0.2.1", "sha256": manifest()["sha256"]})
            self.assertEqual(response.status_code, 403)
            fetch.assert_not_called()

    def test_valid_download_saved_then_served_only_after_revalidation(self):
        self.checked_update()
        with patch.object(services, "fetch_https", side_effect=self.fake_download):
            response = self.post("update/download", {"version": "0.2.1", "sha256": manifest()["sha256"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.product.update_state, "downloaded")
        self.assertNotIn("path", response.json)
        self.signer.assert_called_once()
        served = self.client.get("/api/product/update/installer")
        self.assertEqual(served.status_code, 200)
        self.assertEqual(served.data, INSTALLER)
        self.assertEqual(self.signer.call_count, 2)
        served.close()
        self.assertEqual(list((Path(self.folder.name) / "updates").glob(".download-*")), [])

    def test_new_check_revokes_previous_download_receipt(self):
        self.checked_update()
        with patch.object(services, "fetch_https", side_effect=self.fake_download):
            self.post("update/download", {"version": "0.2.1", "sha256": manifest()["sha256"]})
        self.assertIsNotNone(self.product.receipt)
        with patch.object(services, "fetch_https", return_value=json.dumps(manifest(version="0.2.2")).encode()):
            self.post("update/check", {})
        self.assertIsNone(self.product.receipt)
        self.assertEqual(self.client.get("/api/product/update/installer").status_code, 404)

    def test_wrong_password_cannot_call_store_even_if_preview_was_previously_valid(self):
        backup = services.encode_backup([SERVER], SETTINGS, mode="encrypted", passphrase=PASSPHRASE)
        self.assertEqual(self.post("backup/preview", {"backup": backup, "passphrase": PASSPHRASE}).status_code, 200)
        invalid = self.post("backup/import", {"backup": backup, "passphrase": "another-dummy-passphrase"})
        self.assertEqual(invalid.status_code, 400)
        self.importer.assert_not_called()

    def test_modified_installer_is_not_served_and_receipt_is_revoked(self):
        self.checked_update()
        with patch.object(services, "fetch_https", side_effect=self.fake_download):
            self.post("update/download", {"version": "0.2.1", "sha256": manifest()["sha256"]})
        file = Path(self.folder.name) / "updates" / self.product.receipt["filename"]
        file.write_bytes(b"MZ" + b"x" * (len(INSTALLER) - 2))
        self.assertEqual(self.client.get("/api/product/update/installer").status_code, 409)
        self.assertIsNone(self.product.receipt)

    def test_hash_signature_and_pe_failure_remove_partial_file_without_receipt(self):
        for payload, signer in ((b"ZZ" + INSTALLER[2:], True), (b"MZ" + b"x" * (len(INSTALLER) - 2), True), (INSTALLER, False)):
            with self.subTest(signer=signer, prefix=payload[:4]):
                self.checked_update()
                self.signer.return_value = signer

                def download(url, *, maximum, sink):
                    sink.write(payload)
                    return len(payload)

                with patch.object(services, "fetch_https", side_effect=download):
                    response = self.post("update/download", {"version": "0.2.1", "sha256": manifest()["sha256"]})
                self.assertEqual(response.status_code, 400)
                self.assertIsNone(self.product.receipt)
                self.assertEqual(list((Path(self.folder.name) / "updates").iterdir()), [])

    def test_download_rejects_busy_stale_or_changed_release_before_network(self):
        self.checked_update()
        body = {"version": "0.2.1", "sha256": manifest()["sha256"]}
        with patch.object(services, "fetch_https") as fetch:
            self.running = True
            self.assertEqual(self.post("update/download", body).status_code, 409)
            self.running = False
            self.assertEqual(self.post("update/download", {**body, "version": "9.0.0"}).status_code, 409)
            self.assertEqual(self.post("update/download", {**body, "sha256": "0" * 64}).status_code, 409)
            self.product.checked_at = time.time() - 1801
            self.assertEqual(self.post("update/download", body).status_code, 409)
            fetch.assert_not_called()

    def test_no_verified_installer_or_invalid_configuration_never_opens_network(self):
        self.assertEqual(self.client.get("/api/product/update/installer").status_code, 404)
        invalid = services.ProductServices(data_dir=Path(self.folder.name), version="0.2.0", read_servers=lambda: [],
                                           read_settings=lambda: {}, import_data=lambda *a, **kw: 0,
                                           update_manifest_url="http://localhost/untrusted")
        with patch.object(services, "fetch_https") as fetch, self.assertRaises(services.ProductError):
            invalid.check_update()
        fetch.assert_not_called()
        self.assertEqual(invalid.info()["updates"]["state"], "unconfigured")


if __name__ == "__main__":
    unittest.main()
