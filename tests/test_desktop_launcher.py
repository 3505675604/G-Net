"""Desktop lifecycle checks never create a GUI or contact a remote SSH host."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import desktop_app as desktop


def fake_backend():
    app = Flask("desktop_launcher_test")

    @app.get("/")
    def index():
        return "isolated-local-test"

    return SimpleNamespace(app=app, jobs={}, JOB_LOCK=threading.RLock(),
                           configure_local_access=MagicMock(), shutdown_resources=MagicMock(),
                           prepare_shutdown=MagicMock(return_value=True))


class DesktopPathTests(unittest.TestCase):
    def test_default_profile_is_current_windows_user_local_app_data(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FL_NETWORK_DATA_DIR", None)
            os.environ["LOCALAPPDATA"] = directory
            self.assertEqual(desktop.user_data_dir(), Path(directory).resolve() / "FLNetwork" / "data")

    def test_explicit_and_environment_profiles_do_not_fall_back_to_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "isolated-user"
            explicit = Path(directory) / "explicit-user"
            with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": str(profile)}):
                self.assertEqual(desktop.user_data_dir(), profile.resolve())
                self.assertEqual(desktop.user_data_dir(str(explicit)), explicit.resolve())
            for invalid in ("", "relative-profile"):
                with self.subTest(path=invalid), self.assertRaises(ValueError):
                    desktop.user_data_dir(invalid)

    def test_missing_user_directory_does_not_write_beside_installed_program(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("FL_NETWORK_DATA_DIR", None)
            os.environ.pop("LOCALAPPDATA", None)
            with self.assertRaisesRegex(RuntimeError, "LOCALAPPDATA"):
                desktop.user_data_dir()

    def test_resource_root_supports_source_and_frozen_bundle(self):
        with patch.object(sys, "_MEIPASS", str(ROOT / "test-only-frozen-resources"), create=True):
            self.assertEqual(desktop.resource_root(), ROOT / "test-only-frozen-resources")
        self.assertEqual(desktop.resource_root(), ROOT)

    def test_missing_bundled_backend_fails_without_importing_source_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with patch.dict(os.environ, {}, clear=False), patch.object(desktop, "resource_root", return_value=path):
                with self.assertRaisesRegex(RuntimeError, "资源缺失"):
                    desktop.load_backend(path / "profile")
                self.assertEqual(list((path / "profile").iterdir()), [])


@unittest.skipUnless(os.name == "nt", "Windows named mutex lifecycle")
class DesktopInstanceTests(unittest.TestCase):
    def test_same_profile_rejects_second_process_then_releases_named_mutex(self):
        with tempfile.TemporaryDirectory() as directory:
            first = desktop.SingleInstance(Path(directory))
            second = desktop.SingleInstance(Path(directory))
            try:
                self.assertTrue(first.acquire())
                self.assertFalse(second.acquire())
                self.assertIsNone(second.handle)
                first.close()
                first.close()
                self.assertTrue(second.acquire())
            finally:
                second.close()
                first.close()

    def test_different_profiles_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            first = desktop.SingleInstance(Path(directory) / "first")
            second = desktop.SingleInstance(Path(directory) / "second")
            try:
                self.assertNotEqual(first.name, second.name)
                self.assertTrue(first.acquire())
                self.assertTrue(second.acquire())
            finally:
                second.close()
                first.close()

    def test_window_restore_declares_pointer_sized_windows_handles(self):
        user32 = MagicMock()
        user32.FindWindowW.return_value = 0x100001234
        with patch.object(ctypes, "WinDLL", return_value=user32):
            desktop.focus_existing_window()
        self.assertEqual(user32.FindWindowW.restype, wintypes.HWND)
        self.assertEqual(user32.ShowWindow.argtypes, [wintypes.HWND, ctypes.c_int])
        self.assertEqual(user32.SetForegroundWindow.argtypes, [wintypes.HWND])
        user32.ShowWindow.assert_called_once_with(0x100001234, 9)
        user32.SetForegroundWindow.assert_called_once_with(0x100001234)


class DesktopServerTests(unittest.TestCase):
    def test_local_http_lifecycle_uses_random_bound_port_and_releases_it(self):
        backend = fake_backend()
        service = desktop.DesktopServer(backend)
        self.assertEqual(service.server.server_address[0], "127.0.0.1")
        self.assertGreater(service.port, 0)
        backend.configure_local_access.assert_called_once_with(service.port)
        try:
            self.assertIs(service.start(), service)
            status, body = desktop._probe(service, "/")
            self.assertEqual((status, body), (200, b"isolated-local-test"))
        finally:
            service.close()
        service.close()
        self.assertFalse(service.thread.is_alive())
        backend.shutdown_resources.assert_called_once()
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", service.port)), 0)

    def test_unstarted_server_can_close_without_blocking_on_shutdown(self):
        backend = fake_backend()
        service = desktop.DesktopServer(backend)
        with patch.object(service.server, "shutdown") as shutdown:
            service.close()
        shutdown.assert_not_called()
        backend.shutdown_resources.assert_called_once()
        with socket.socket() as probe:
            self.assertNotEqual(probe.connect_ex(("127.0.0.1", service.port)), 0)

    def test_listener_and_backend_cleanup_survive_shutdown_error(self):
        backend = fake_backend()
        server = MagicMock(server_port=48219)
        worker = MagicMock()
        with patch("werkzeug.serving.make_server", return_value=server), \
             patch.object(desktop.threading, "Thread", return_value=worker):
            service = desktop.DesktopServer(backend).start()
        server.shutdown.side_effect = RuntimeError("test-only shutdown failure")
        with self.assertRaisesRegex(RuntimeError, "shutdown failure"):
            service.close()
        server.server_close.assert_called_once()
        backend.shutdown_resources.assert_called_once()
        worker.join.assert_called_once_with(timeout=3)

    def test_failed_worker_start_releases_already_bound_server(self):
        backend = fake_backend()
        server = MagicMock(server_port=48219)
        worker = MagicMock()
        worker.start.side_effect = RuntimeError("test-only thread failure")
        with patch("werkzeug.serving.make_server", return_value=server), \
             patch.object(desktop.threading, "Thread", return_value=worker):
            service = desktop.DesktopServer(backend)
        with self.assertRaisesRegex(RuntimeError, "thread failure"):
            service.start()
        server.shutdown.assert_not_called()
        server.server_close.assert_called_once()
        backend.shutdown_resources.assert_called_once()

    def test_invalid_access_configuration_releases_bound_listener(self):
        backend = fake_backend()
        backend.configure_local_access.side_effect = ValueError("test-only port failure")
        server = MagicMock(server_port=48219)
        with patch("werkzeug.serving.make_server", return_value=server):
            with self.assertRaisesRegex(ValueError, "port failure"):
                desktop.DesktopServer(backend)
        server.server_close.assert_called_once()
        backend.shutdown_resources.assert_called_once()

    def test_socket_close_error_still_releases_backend_resources_and_joins_worker(self):
        backend = fake_backend()
        server = MagicMock(server_port=48219)
        worker = MagicMock()
        with patch("werkzeug.serving.make_server", return_value=server), \
             patch.object(desktop.threading, "Thread", return_value=worker):
            service = desktop.DesktopServer(backend).start()
        server.server_close.side_effect = RuntimeError("test-only listener close failure")
        with self.assertRaisesRegex(RuntimeError, "listener close failure"):
            service.close()
        backend.shutdown_resources.assert_called_once()
        worker.join.assert_called_once_with(timeout=3)

    def test_running_install_task_cancels_window_close(self):
        backend = fake_backend()
        backend.jobs = {"done": {"status": "done"}, "install": {"status": "running"}}
        backend.prepare_shutdown.return_value = False
        with patch.object(desktop, "message_box") as message:
            self.assertTrue(desktop.has_running_jobs(backend))
            self.assertFalse(desktop.allow_window_close(backend))
        message.assert_called_once()
        backend.prepare_shutdown.assert_called_once()
        backend.shutdown_resources.assert_not_called()

    def test_idle_backend_can_close(self):
        backend = fake_backend()
        backend.jobs = {"done": {"status": "done"}, "failed": {"status": "error"}}
        with patch.object(desktop, "message_box") as message:
            self.assertFalse(desktop.has_running_jobs(backend))
            self.assertTrue(desktop.allow_window_close(backend))
        message.assert_not_called()
        backend.prepare_shutdown.assert_called_once()


class DesktopMainTests(unittest.TestCase):
    def test_gui_start_failure_stops_owned_service_and_releases_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = MagicMock()
            instance.acquire.return_value = True
            service = MagicMock()
            service.start.return_value = service
            with patch.object(desktop, "SingleInstance", return_value=instance), \
                 patch.object(desktop, "setup_logging"), patch.object(desktop, "load_backend"), \
                 patch.object(desktop, "DesktopServer", return_value=service), \
                 patch.object(desktop, "main_window", side_effect=RuntimeError("test-only GUI failure")), \
                 patch.object(desktop, "message_box") as message, \
                 patch.object(desktop.logging, "getLogger"):
                result = desktop.main(["--data-dir", directory])
            self.assertEqual(result, 1)
            service.close.assert_called_once()
            instance.close.assert_called_once()
            self.assertTrue(message.call_args.kwargs["error"])

    def test_second_launch_restores_window_without_starting_another_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = MagicMock()
            instance.acquire.return_value = False
            with patch.object(desktop, "SingleInstance", return_value=instance), \
                 patch.object(desktop, "load_backend") as backend, \
                 patch.object(desktop, "focus_existing_window") as focus, \
                 patch.object(desktop, "setup_logging") as logging_setup:
                result = desktop.main(["--data-dir", directory])
            self.assertEqual(result, 0)
            focus.assert_called_once()
            backend.assert_not_called()
            logging_setup.assert_not_called()
            instance.close.assert_called_once()

    def test_normal_gui_return_closes_only_owned_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            instance = MagicMock()
            instance.acquire.return_value = True
            service = MagicMock()
            service.start.return_value = service
            with patch.object(desktop, "SingleInstance", return_value=instance), \
                 patch.object(desktop, "setup_logging"), patch.object(desktop, "load_backend"), \
                 patch.object(desktop, "DesktopServer", return_value=service), \
                 patch.object(desktop, "main_window") as window, \
                 patch.object(desktop, "message_box") as message:
                result = desktop.main(["--data-dir", directory])
            self.assertEqual(result, 0)
            window.assert_called_once_with(service, Path(directory).resolve())
            service.close.assert_called_once()
            instance.close.assert_called_once()
            message.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Self-test validates real Windows DPAPI")
class DesktopSmokeTests(unittest.TestCase):
    def selftest_with_runtime(self, runtime):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            previous_profile = str(Path(directory) / "never-read-existing-profile")
            loaded = []
            original_loader = desktop.load_backend

            def isolated_load(path):
                backend = original_loader(path)
                backend.connect_ssh = MagicMock(side_effect=AssertionError("remote SSH is forbidden"))
                loaded.append(backend)
                return backend

            with patch.dict(os.environ, {"FL_NETWORK_DATA_DIR": previous_profile}), \
                 patch.object(desktop, "load_backend", side_effect=isolated_load), \
                 patch.object(desktop, "check_webview_runtime", **runtime), \
                 patch.object(desktop, "main_window") as window, \
                 patch.object(desktop, "message_box") as message:
                result = desktop.self_test(report_path)
                self.assertEqual(os.environ["FL_NETWORK_DATA_DIR"], previous_profile)
            self.assertEqual(len(loaded), 1)
            loaded[0].connect_ssh.assert_not_called()
            window.assert_not_called()
            message.assert_not_called()
            self.assertFalse(Path(previous_profile).exists())
            self.assertFalse(Path(loaded[0].DATA_DIR).exists())
            with socket.socket() as probe:
                self.assertNotEqual(probe.connect_ex(("127.0.0.1", loaded[0].app.config["LOCAL_ACCESS_PORT"])), 0)
            return result, json.loads(report_path.read_text(encoding="utf-8"))

    def test_selftest_checks_packaged_resources_dpapi_and_guards_without_gui_or_ssh(self):
        result, report = self.selftest_with_runtime({"return_value": "test-only-webview-runtime"})
        self.assertEqual(result, 0)
        self.assertEqual(report["status"], "passed")
        self.assertTrue(all(check["passed"] for check in report["checks"]))
        names = {check["name"] for check in report["checks"]}
        self.assertTrue({"bundled-template", "dpapi-protects-password", "api-omits-password",
                         "csrf-rejects-missing-token", "host-rejects-rebinding", "origin-rejects-cross-site",
                         "server-thread-stopped", "loopback-port-released"}.issubset(names))

    def test_selftest_runtime_failure_still_stops_listener_and_restores_profile(self):
        result, report = self.selftest_with_runtime({"side_effect": RuntimeError("test-only runtime unavailable")})
        self.assertEqual(result, 1)
        self.assertEqual(report["status"], "failed")
        self.assertIn("runtime unavailable", report["error"])


if __name__ == "__main__":
    unittest.main()
