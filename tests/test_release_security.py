"""Fake signing/config checks; never call PowerShell or external services."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import app_metadata
import release_security

PIN = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
OTHER_PIN = "1111111111111111111111111111111111111111"


def response(payload=None, *, code=0, stdout=None):
    if stdout is None:
        payload = payload if payload is not None else {"status": "Valid", "thumbprint": PIN, "timestamped": True}
        stdout = json.dumps(payload).encode("utf-8")
    return types.SimpleNamespace(returncode=code, stdout=stdout, stderr=b"do-not-display-private-verifier-output")


class ReleaseSignatureTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "fake-setup.exe"
        self.path.write_bytes(b"MZdummy-test-only")

    def tearDown(self):
        self.folder.cleanup()

    def verify(self, result=None, *, path=None, pins=None, **kwargs):
        with patch.object(release_security.subprocess, "run", return_value=result or response()) as call:
            verified = release_security.verify_windows_installer(path or self.path, [PIN] if pins is None else pins, **kwargs)
            return verified, call

    def test_valid_chain_pinned_publisher_and_timestamp_are_required(self):
        verified, call = self.verify(pins=[PIN.lower()])
        self.assertTrue(verified)
        command = call.call_args.args[0]
        self.assertIn("-NonInteractive", command)
        self.assertIn("-NoProfile", command)
        self.assertIn("Get-AuthenticodeSignature", command[-1])
        self.assertIn("TimeStamperCertificate", command[-1])
        self.assertEqual(call.call_args.kwargs["timeout"], 30)

    def test_installer_path_is_environment_data_never_powershell_code(self):
        malicious = Path(self.folder.name) / "setup';$x='secret';$(Write-Output bad).exe"
        malicious.write_bytes(b"MZtest")
        verified, call = self.verify(path=malicious)
        self.assertTrue(verified)
        argv = call.call_args.args[0]
        self.assertNotIn(malicious.name, " ".join(argv))
        self.assertNotIn("Write-Output bad", argv[-1])
        self.assertIn("-LiteralPath $env:FLNETWORK_VERIFY_FILE", argv[-1])
        self.assertEqual(call.call_args.kwargs["env"]["FLNETWORK_VERIFY_FILE"], str(malicious.resolve()))

    def test_non_windows_and_missing_or_malformed_pins_never_spawn(self):
        with patch.object(release_security.os, "name", "posix"), patch.object(release_security.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "Windows"):
                release_security.verify_windows_installer(self.path, [PIN])
            run.assert_not_called()
        for pins in (None, [], ["short"], [PIN, "bad"], [True], PIN, [PIN] * 9):
            with self.subTest(pins_type=type(pins).__name__), patch.object(release_security.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    release_security.verify_windows_installer(self.path, pins)
                run.assert_not_called()

    def test_missing_wrong_extension_directory_and_null_path_are_rejected(self):
        plain = Path(self.folder.name) / "fake.bin"
        plain.write_bytes(b"MZtest")
        for path in (plain, Path(self.folder.name), self.path.parent / "missing.exe", "bad\x00path.exe"):
            with self.subTest(path_type=type(path).__name__), patch.object(release_security.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    release_security.verify_windows_installer(path, [PIN])
                run.assert_not_called()

    def test_unsigned_invalid_chain_mismatched_publisher_and_missing_timestamp_fail(self):
        for payload in ({"status": "NotSigned", "thumbprint": "", "timestamped": False},
                        {"status": "HashMismatch", "thumbprint": PIN, "timestamped": True},
                        {"status": "UnknownError", "thumbprint": PIN, "timestamped": True},
                        {"status": "Valid", "thumbprint": OTHER_PIN, "timestamped": True},
                        {"status": "Valid", "thumbprint": PIN, "timestamped": False}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.verify(response(payload))

    def test_timestamp_policy_can_only_be_relaxed_by_explicit_internal_argument(self):
        valid = response({"status": "Valid", "thumbprint": PIN, "timestamped": False})
        self.assertTrue(self.verify(valid, require_timestamp=False)[0])

    def test_malformed_verifier_payloads_are_rejected_without_echoing_values(self):
        bad_payloads = [None, [], "secret-private-result", 123,
                        {"status": "Valid", "thumbprint": PIN},
                        {"status": "Valid", "thumbprint": PIN, "timestamped": "true"},
                        {"status": "Valid", "thumbprint": PIN, "timestamped": True, "unknown": "secret-value"}]
        for payload in bad_payloads:
            raw = json.dumps(payload).encode()
            with self.subTest(payload_type=type(payload).__name__):
                with self.assertRaises(ValueError) as error:
                    self.verify(response(stdout=raw))
                self.assertNotIn("secret", str(error.exception))
                self.assertNotIn(PIN, str(error.exception))

    def test_invalid_encoding_json_oversize_and_nonzero_exit_fail(self):
        for result in (response(stdout=b"\xff"), response(stdout=b"not json"),
                       response(stdout=b" " * 16385), response(code=1)):
            with self.subTest(code=result.returncode), self.assertRaises(ValueError):
                self.verify(result)

    def test_os_error_and_timeout_are_sanitized(self):
        for failure in (OSError("secret-file-name-and-user"), subprocess.TimeoutExpired("secret-command", 30)):
            with self.subTest(error_type=type(failure).__name__), patch.object(release_security.subprocess, "run", side_effect=failure):
                with self.assertRaises(ValueError) as error:
                    release_security.verify_windows_installer(self.path, [PIN])
                self.assertNotIn("secret", str(error.exception))

    def test_symbolic_link_is_rejected_before_verification(self):
        with patch.object(Path, "is_symlink", return_value=True), patch.object(release_security.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                release_security.verify_windows_installer(self.path, [PIN])
            run.assert_not_called()


class ReleaseConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        (self.root / "packaging").mkdir()
        self.filename = self.root / "packaging" / "release-config.json"

    def tearDown(self):
        self.folder.cleanup()

    def config(self, **changes):
        data = {"publisher": "Gloria", "support_email": "", "website_url": "",
                "support_url": "", "update_manifest_url": "", "signer_thumbprints": [], "channel": "candidate", **changes}
        self.filename.write_text(json.dumps(data), encoding="utf-8")
        return app_metadata.load_release_config(self.root)

    def test_unconfigured_distribution_is_allowed_without_dummy_domain_or_secret(self):
        loaded = self.config()
        self.assertEqual(loaded["publisher"], "Gloria")
        self.assertEqual(loaded["website_url"], "")
        self.assertEqual(loaded["update_manifest_url"], "")
        self.assertEqual(loaded["signer_thumbprints"], [])

    def test_https_configuration_and_case_normalized_pins_are_accepted(self):
        loaded = self.config(website_url="https://release.example.test/", support_url="https://release.example.test/help",
                             update_manifest_url="https://release.example.test/update.json", signer_thumbprints=[PIN.lower()], channel="stable")
        self.assertEqual(loaded["signer_thumbprints"], [PIN])
        self.assertEqual(loaded["channel"], "stable")

    def test_malicious_url_and_port_errors_never_echo_credentials_or_input(self):
        bad = ["http://secret.example.test/", "https://username:password@secret.example.test/",
               "https://@secret.example.test/", "https://secret.example.test:password/",
               "https://secret.example.test:99999/", "https://secret.example.test:444/",
               "https://[private-secret-invalid]/", "https://secret.example.test\\@evil.test/",
               "https://secret.example.test/\x00credential", "https://secret.example.test/#credential",
               "https://127.0.0.1/private-secret", "https://localhost/private-secret",
               "https://bad.local/private-secret", "https://bad.internal/private-secret"]
        for url in bad:
            with self.subTest(url_kind=url.split(":")[0]):
                with self.assertRaises(ValueError) as error:
                    self.config(update_manifest_url=url)
                for private in ("password", "username", "credential", "secret.example.test", "private-secret"):
                    self.assertNotIn(private, str(error.exception))

    def test_config_sizes_invalid_pins_channel_and_unexpected_types_fail(self):
        for change in ({"publisher": "x\ny"}, {"support_email": False}, {"signer_thumbprints": ["invalid"]},
                       {"signer_thumbprints": [PIN] * 9}, {"channel": "nightly"}, {"website_url": 123}):
            with self.subTest(fields=list(change)), self.assertRaises(ValueError):
                self.config(**change)
        self.filename.write_text(" " * 16385)
        with self.assertRaisesRegex(ValueError, "过大"):
            app_metadata.load_release_config(self.root)
        self.filename.write_text("[]")
        with self.assertRaises(ValueError):
            app_metadata.load_release_config(self.root)


if __name__ == "__main__":
    unittest.main()
