import copy
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import remote_ops


class Channel:
    def __init__(self, out=(), err=(), status=0):
        self.out, self.err = list(out), list(err)
        self.status, self.closed = status, False
        self.order = []

    def recv_ready(self):
        return bool(self.out)

    def recv_stderr_ready(self):
        return bool(self.err)

    def recv(self, size):
        self.order.append("stdout")
        return self.out.pop(0)

    def recv_stderr(self, size):
        self.order.append("stderr")
        return self.err.pop(0)

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.status

    def close(self):
        self.closed = True


class SSH:
    def __init__(self, channel):
        self.channel = channel

    def exec_command(self, command, timeout):
        self.command = command
        stream = type("Stream", (), {"channel": self.channel})()
        return io.BytesIO(), stream, stream


class RemoteOpsTests(unittest.TestCase):
    def test_checked_drains_both_streams_before_exit_and_handles_split_utf8(self):
        channel = Channel([b"\xe4", b"\xb8\xad\n"], [b"notice\n"])
        seen = []
        self.assertEqual(remote_ops.run_checked(SSH(channel), "ignored", on_output=seen.append), "中\n")
        self.assertEqual(channel.order[:2], ["stdout", "stderr"])
        self.assertIn("中\n", seen)
        self.assertTrue(channel.closed)

    def test_nonzero_propagates_stderr_without_command_secrets(self):
        channel = Channel([b"out\n"], [b"failure\n"], status=2)
        with self.assertRaisesRegex(RuntimeError, "failure") as caught:
            remote_ops.run_checked(SSH(channel), "SECRET_PASSWORD")
        self.assertNotIn("SECRET_PASSWORD", str(caught.exception))
        self.assertTrue(channel.closed)

    def test_streaming_retains_bounded_tail_and_unstreamed_output_is_limited(self):
        blocks = [b"x" * 65536 for _ in range(257)]
        streamed = [0]
        channel = Channel(blocks)
        result = remote_ops.run_checked(SSH(channel), "ignored", on_output=lambda part: streamed.__setitem__(0, streamed[0] + len(part)))
        self.assertEqual(len(result), 512 * 1024)
        self.assertEqual(streamed[0], 257 * 65536)
        channel = Channel(blocks)
        with self.assertRaisesRegex(RuntimeError, "16 MiB"):
            remote_ops.run_checked(SSH(channel), "ignored")
        self.assertTrue(channel.closed)

    def test_missing_config_is_distinct_from_existing_empty_config(self):
        with patch.object(remote_ops, "run_checked", return_value=remote_ops._MISSING):
            missing = remote_ops.read_xray_config(None)
        with patch.object(remote_ops, "run_checked", return_value="{}\n"):
            existing = remote_ops.read_xray_config(None)
        self.assertEqual(missing, {})
        self.assertFalse(missing.exists)
        self.assertTrue(existing.exists)
        self.assertNotEqual(existing.digest, None)
        self.assertEqual(copy.deepcopy(existing).digest, existing.digest)

    def test_invalid_config_is_not_replaced_with_empty(self):
        for raw in ("bad JSON", "[]", '{"inbounds": {}}', '{"inbounds": [7]}'):
            with self.subTest(raw=raw), patch.object(remote_ops, "run_checked", return_value=raw):
                with self.assertRaises(RuntimeError):
                    remote_ops.read_xray_config(None)

    def test_exact_tcp_udp_ipv4_ipv6_ports(self):
        out = "LISTEN 0 128 0.0.0.0:600 0.0.0.0:*\nLISTEN 0 128 [::]:1600 [::]:*\nLISTEN 0 128 [::1]:443 [::]:*\n"
        with patch.object(remote_ops, "run_checked", return_value=out) as command:
            self.assertEqual(remote_ops.listening_ports(None), {600, 1600, 443})
            self.assertEqual(command.call_args.args[1], "ss -H -lnt")
            self.assertEqual(remote_ops.listening_ports(None, udp=True), {600, 1600, 443})
            self.assertEqual(command.call_args.args[1], "ss -H -lnu")

    def test_process_lock_serializes_same_endpoint_and_is_reentrant(self):
        count = [0]
        maximum = [0]

        def worker():
            with remote_ops.server_lock("EXAMPLE.com", 22), remote_ops.server_lock("example.com", 22):
                count[0] += 1
                maximum[0] = max(maximum[0], count[0])
                time.sleep(0.01)
                count[0] -= 1

        workers = [threading.Thread(target=worker) for _ in range(5)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(maximum[0], 1)


def _bash():
    return next((p for p in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ) if Path(p).exists()), None) or shutil.which("bash")


def _shell_path(path):
    value = str(path).replace("\\", "/")
    if len(value) > 1 and value[1] == ":":
        return "/" + value[0].lower() + value[2:]
    return value


@unittest.skipUnless(_bash(), "Bash unavailable: local transaction simulation skipped")
class TransactionSimulationTests(unittest.TestCase):
    """Run the real transaction shell against fake local Linux services only."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="server-manager-xray-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.cfgdir = self.root / "xray"
        self.cfgdir.mkdir()
        self.config = self.cfgdir / "config.json"
        self.original = {"inbounds": [{"port": 9000, "protocol": "vless", "tag": "old"}],
                         "routing": {"rules": [{"outboundTag": "custom"}]},
                         "outbounds": [{"tag": "custom", "protocol": "freedom"}]}
        self.config.write_text(json.dumps(self.original), encoding="utf-8")
        self.state = self.root / "state"
        self.state.write_text("active\n", encoding="utf-8")
        (self.root / "tcp").write_text("LISTEN 0 128 [::]:9000 [::]:*\nLISTEN 0 128 0.0.0.0:9001 0.0.0.0:*\n", encoding="utf-8")
        (self.root / "udp").write_text("UNCONN 0 0 [::]:9001 [::]:*\n", encoding="utf-8")
        self.env = os.environ.copy()
        self.env["PATH"] = _shell_path(self.bin) + ":/usr/bin:/bin"
        self.env["TEST_ROOT"] = _shell_path(self.root)
        self.stub("flock", "exit 0")
        self.stub("sleep", "exit 0")
        self.stub("id", 'exit "${FAIL_SERVICE_USER:-0}"')
        self.stub("chown", 'printf "%s\\n" "$*" >> "$TEST_ROOT/chowns"')
        self.stub("xray", '''format=auto
candidate=''
printf '%s\\n' "$@" >> "$TEST_ROOT/xray-args"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -format) format="$2"; shift 2;;
    -c|-config) candidate="$2"; shift 2;;
    *) shift;;
  esac
done
if [ "$format" = auto ]; then
  case "$candidate" in
    *.json) format=json;;
    *) echo "Failed to start: main: Failed to load config files: [$candidate] > core: Failed to get format of $candidate" >&2; exit 23;;
  esac
fi
[ "$format" = json ] || { echo 'unsupported format' >&2; exit 23; }
grep -q '"invalid": true' "$candidate" && exit 2
exit 0''')
        self.stub("ss", '''case "$*" in *-lnu*) cat "$TEST_ROOT/udp";; *) cat "$TEST_ROOT/tcp";; esac''')
        self.stub("cp", '''if [ "${FAIL_BACKUP:-0}" = 1 ] && [[ "${@: -1}" = *.bak.* ]]; then exit 2; fi
/usr/bin/cp "$@"
if [ "${CORRUPT_BACKUP:-0}" = 1 ] && [[ "${@: -1}" = *.bak.* ]]; then printf bad >> "${@: -1}"; fi
exit 0''')
        self.stub("systemctl", '''case "$1" in
show) printf '%s\\n' "${SERVICE_USER:-root}";;
is-active)
  if [ -f "$TEST_ROOT/xray/config.json" ] && grep -q '"transient": true' "$TEST_ROOT/xray/config.json"; then
    if [ -f "$TEST_ROOT/checks" ]; then echo inactive; exit 3; fi
    echo first > "$TEST_ROOT/checks"; echo active; exit 0
  fi
  cat "$TEST_ROOT/state"; grep -Fxq active "$TEST_ROOT/state";;
restart)
  echo restart >> "$TEST_ROOT/restarts"
  if grep -q '"restartFail": true' "$TEST_ROOT/xray/config.json"; then echo inactive > "$TEST_ROOT/state"; exit 1; fi
  if grep -q '"inactive": true' "$TEST_ROOT/xray/config.json"; then echo inactive > "$TEST_ROOT/state"; else echo active > "$TEST_ROOT/state"; fi;;
stop) echo inactive > "$TEST_ROOT/state";;
*) exit 2;;
esac''')
        self.run_patch = patch.object(remote_ops, "run_checked", side_effect=self.run_local)
        self.run_patch.start()
        self.addCleanup(self.run_patch.stop)

    def stub(self, name, source):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + source + "\n", encoding="utf-8", newline="\n")
        path.chmod(0o700)

    def run_local(self, ssh, command, timeout=180, **kwargs):
        command = command.replace("/usr/local/etc/xray", _shell_path(self.cfgdir))
        command = command.replace("/usr/local/bin/xray", _shell_path(self.bin / "xray"))
        if command.startswith("bash -c "):
            command = shlex.split(command)[2]
        command = "export PATH=" + shlex.quote(self.env["PATH"]) + "; " + command
        # Git Bash launches each stub as a Windows process. Allow the full
        # health/rollback loop while preserving shorter command deadlines.
        local_timeout = min(timeout, 90 if os.name == "nt" else 30)
        result = subprocess.run([_bash(), "-c", command], env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=local_timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
        return result.stdout.decode("utf-8", errors="replace")

    def candidate(self):
        cfg = copy.deepcopy(self.original)
        cfg["inbounds"].append({"tag": "new", "port": 9001, "protocol": "shadowsocks",
                                "settings": {"network": "tcp,udp"}})
        return cfg

    def assert_original(self):
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8")), self.original)
        self.assertEqual(self.state.read_text().strip(), "active")
        self.assertEqual(list(self.cfgdir.glob("*.new.*")), [])

    def test_success_preserves_routing_and_unique_backups(self):
        before = remote_ops.read_xray_config(None)
        cfg = self.candidate()
        remote_ops.apply_xray_config(None, cfg, expected=before)
        remote_ops.apply_xray_config(None, cfg, expected=remote_ops.read_xray_config(None))
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8")), cfg)
        self.assertEqual(len(list(self.cfgdir.glob("*.bak.*"))), 2)
        self.assertEqual(list(self.cfgdir.glob("*.new.*")), [])

    def test_reality_vision_temporary_configuration_has_explicit_json_format(self):
        cfg = self.candidate()
        cfg["inbounds"][-1] = {
            "tag": "reality-vision", "port": 9001, "protocol": "vless",
            "settings": {"clients": [{"id": "00000000-0000-4000-8000-000000000001",
                                       "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"dest": "example.com:443",
                                                   "serverNames": ["example.com"],
                                                   "privateKey": "offline-test-placeholder",
                                                   "shortIds": ["0123456789abcdef"]}},
        }
        remote_ops.apply_xray_config(None, cfg, expected=remote_ops.read_xray_config(None))
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8")), cfg)
        args = (self.root / "xray-args").read_text().splitlines()
        self.assertEqual(args[:5], ["run", "-test", "-format", "json", "-c"])
        self.assertIn("/config.json.new.", args[-1])
        self.assertEqual((self.root / "restarts").read_text().splitlines(), ["restart"])
        self.assertEqual(list(self.cfgdir.glob("*.new.*")), [])

    def test_format_loader_error_preserves_original_bytes_without_restart(self):
        original_bytes = self.config.read_bytes()
        self.stub("xray", '''candidate="${@: -1}"
echo "Failed to start: main: Failed to load config files: [$candidate] > core: Failed to get format of $candidate" >&2
exit 23''')
        with self.assertRaisesRegex(RuntimeError, "Failed to get format"):
            remote_ops.apply_xray_config(None, self.candidate(), expected=remote_ops.read_xray_config(None))
        self.assertEqual(self.config.read_bytes(), original_bytes)
        self.assert_original()
        self.assertFalse((self.root / "restarts").exists())
        self.assertEqual(list(self.cfgdir.glob("*.bak.*")), [])

    def test_inactive_is_failure_and_original_is_restored(self):
        cfg = self.candidate()
        cfg["inactive"] = True
        with self.assertRaisesRegex(RuntimeError, "已恢复"):
            remote_ops.apply_xray_config(None, cfg, expected=remote_ops.read_xray_config(None))
        self.assert_original()

    def test_restart_nonzero_is_rolled_back(self):
        cfg = self.candidate()
        cfg["restartFail"] = True
        with self.assertRaisesRegex(RuntimeError, "已恢复"):
            remote_ops.apply_xray_config(None, cfg, expected=remote_ops.read_xray_config(None))
        self.assert_original()

    def test_missing_udp_listener_is_failure_and_rolled_back(self):
        (self.root / "udp").write_text("", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "已恢复"):
            remote_ops.apply_xray_config(None, self.candidate(), expected=remote_ops.read_xray_config(None))
        self.assert_original()

    def test_validation_failure_does_not_touch_config_or_restart(self):
        cfg = self.candidate()
        cfg["invalid"] = True
        with self.assertRaises(RuntimeError):
            remote_ops.apply_xray_config(None, cfg, expected=remote_ops.read_xray_config(None))
        self.assert_original()
        self.assertFalse((self.root / "restarts").exists())

    def test_backup_failure_aborts_before_replace(self):
        self.env["FAIL_BACKUP"] = "1"
        with self.assertRaises(RuntimeError):
            remote_ops.apply_xray_config(None, self.candidate(), expected=remote_ops.read_xray_config(None))
        self.assert_original()
        self.assertFalse((self.root / "restarts").exists())

    def test_corrupt_backup_aborts_before_replace(self):
        self.env["CORRUPT_BACKUP"] = "1"
        with self.assertRaisesRegex(RuntimeError, "备份验证失败"):
            remote_ops.apply_xray_config(None, self.candidate(), expected=remote_ops.read_xray_config(None))
        self.assert_original()
        self.assertFalse((self.root / "restarts").exists())

    def test_transient_active_does_not_count_as_healthy(self):
        cfg = self.candidate()
        cfg["transient"] = True
        with self.assertRaisesRegex(RuntimeError, "已恢复"):
            remote_ops.apply_xray_config(None, cfg, expected=remote_ops.read_xray_config(None))
        self.assert_original()

    def test_optimistic_conflict_preserves_other_writer(self):
        before = remote_ops.read_xray_config(None)
        other = {**self.original, "log": {"loglevel": "info"}}
        self.config.write_text(json.dumps(other), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "并发冲突"):
            remote_ops.apply_xray_config(None, self.candidate(), expected=before)
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8")), other)
        self.assertFalse((self.root / "restarts").exists())

    def test_failed_first_configuration_removes_file_and_restores_stopped_service(self):
        self.config.unlink()
        self.state.write_text("inactive\n", encoding="utf-8")
        before = remote_ops.read_xray_config(None)
        cfg = {"inbounds": [], "restartFail": True}
        with self.assertRaises(RuntimeError):
            remote_ops.apply_xray_config(None, cfg, expected=before)
        self.assertFalse(self.config.exists())
        self.assertEqual(self.state.read_text().strip(), "inactive")
        self.assertTrue((self.root / "restarts").exists())

    def test_first_configuration_is_owned_by_nonroot_service_user(self):
        self.config.unlink()
        self.env["SERVICE_USER"] = "nobody"
        remote_ops.apply_xray_config(None, {"inbounds": []}, expected=remote_ops.read_xray_config(None))
        self.assertIn("nobody", (self.root / "chowns").read_text())
        self.assertEqual(json.loads(self.config.read_text()), {"inbounds": []})

    def test_nonexistent_service_user_aborts_first_config_without_restart(self):
        self.config.unlink()
        self.env["SERVICE_USER"] = "unknown-user"
        self.env["FAIL_SERVICE_USER"] = "1"
        with self.assertRaisesRegex(RuntimeError, "服务用户不存在"):
            remote_ops.apply_xray_config(None, {"inbounds": []}, expected=remote_ops.read_xray_config(None))
        self.assertFalse(self.config.exists())
        self.assertFalse((self.root / "restarts").exists())


if __name__ == "__main__":
    unittest.main()
