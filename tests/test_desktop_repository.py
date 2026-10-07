"""Execute desktop shell fragments against local fake commands, never SSH/APT."""
import ast
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import install_desktop
import script_common

ROOT = Path(__file__).resolve().parents[1]


def bash_binary():
    path = Path("C:/Program Files/Git/bin/bash.exe")
    return str(path) if path.is_file() else shutil.which("bash")


def shell_path(path):
    value = str(path).replace("\\", "/")
    return "/" + value[0].lower() + value[2:] if len(value) > 1 and value[1] == ":" else value


def ui_desktop_script():
    # Compile the actual function without importing the backend or real JSON.
    tree = ast.parse((ROOT / "server-manager/app.py").read_text(encoding="utf-8"))
    definition = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_desktop")
    namespace = {"microsoft_edge_repository_script": script_common.microsoft_edge_repository_script}
    exec(compile(ast.Module(body=[definition], type_ignores=[]), "offline-ui-desktop", "exec"), namespace)
    actions = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "ACTIONS" for target in node.targets))
    index = next(index for index, key in enumerate(actions.keys) if isinstance(key, ast.Constant) and key.value == "install_desktop")
    action = eval(compile(ast.Expression(actions.values[index]), "offline-ui-action", "eval"), namespace)
    return action[1]


@unittest.skipUnless(bash_binary(), "Bash unavailable: offline desktop shell simulation skipped")
class DesktopRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="offline-desktop-gpg-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("bin", "keyrings", "sources", "tmp", "home"):
            (self.root / name).mkdir()
        self.keyring = self.root / "keyrings/microsoft.gpg"
        self.source = self.root / "sources/microsoft-edge.list"
        self.keyring.write_bytes(b"old-valid-keyring")
        self.source.write_bytes(b"old-source-list\n")
        self.env = os.environ.copy()
        self.env["PATH"] = shell_path(self.root / "bin") + ":/usr/bin:/bin"
        self.env["TEST_ROOT"] = shell_path(self.root)
        self.env["TMPDIR"] = shell_path(self.root / "tmp")
        self.stub("curl", '''output=''
while [ "$#" -gt 0 ]; do
  case "$1" in --output|-o) output="$2"; shift 2;; *) shift;; esac
done
if [ "${FAIL_CURL:-0}" = 1 ]; then
  [ -z "$output" ] || printf partial > "$output"
  echo 'simulated HTTPS download failure' >&2; exit 22
fi
if [ -n "$output" ]; then printf 'fixture ASCII public key' > "$output"; else printf 'fixture ASCII public key'; fi''')
        self.stub("gpg", '''output=''; batch=0; yes=0; notty=0; show=0; dearmor=0
printf '%s\\n' "$*" >> "$TEST_ROOT/gpg-args"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output|-o) output="$2"; shift 2;;
    --homedir) shift 2;;
    --batch) batch=1; shift;;
    --yes) yes=1; shift;;
    --no-tty) notty=1; shift;;
    --show-keys) show=1; shift;;
    --dearmor) dearmor=1; shift;;
    *) shift;;
  esac
done
if [ "$dearmor" = 1 ]; then
  cat >/dev/null
  if [ -e "$output" ] && [ "$yes" = 0 ]; then
    echo "gpg: cannot open '/dev/tty': No such device or address" >&2; exit 2
  fi
  if [ "${FAIL_GPG:-0}" = 1 ]; then printf partial > "$output"; echo 'gpg: no valid OpenPGP data found.' >&2; exit 2; fi
  if [ "${EMPTY_GPG:-0}" = 1 ]; then : > "$output"; exit 0; fi
  printf 'new-valid-keyring' > "$output"
fi
if [ "$show" = 1 ]; then
  if [ "${FAIL_SHOW:-0}" = 1 ]; then echo 'gpg: invalid public key' >&2; exit 2; fi
  if [ "${NO_PUB:-0}" = 1 ]; then printf 'uid:::::::::fixture:\\n'; else printf 'pub:-:2048:1:FIXTURE::::::::\\n'; fi
fi
if [ "$batch" != 1 ] || [ "$yes" != 1 ] || [ "$notty" != 1 ]; then echo 'fixture requires batch/yes/no-tty' >&2; exit 2; fi''')
        self.stub("mv", '''if [ "${FAIL_MV:-0}" = 1 ]; then echo 'simulated atomic keyring commit failure' >&2; exit 1; fi
/usr/bin/mv "$@"''')
        self.stub("apt-get", '''printf '%s\\n' "$*" >> "$TEST_ROOT/apt-args"
for item in "$@"; do
  case "$item" in *.deb)
    printf '%s\\n' "$item" >> "$TEST_ROOT/chrome-paths"
    [ "$(cat "$item")" = 'fresh chrome package' ] || { echo 'stale Chrome package' >&2; exit 1; };; esac
done
if [ "${FAIL_EDGE_APT:-0}" = 1 ] && [[ "$*" = *microsoft-edge-stable* ]]; then echo 'simulated Edge APT error' >&2; exit 1; fi
exit 0''')
        self.stub("wget", '''output=''
while [ "$#" -gt 0 ]; do
  case "$1" in -O) output="$2"; shift 2;; *) shift;; esac
done
[ -n "$output" ] || { echo 'fixture requires explicit Chrome output' >&2; exit 1; }
printf 'fresh chrome package' > "$output"
if [ "${FAIL_WGET:-0}" = 1 ]; then echo 'simulated Chrome download failure' >&2; exit 8; fi
exit 0''')
        for name, body in (("uname", "echo x86_64"), ("swapon", "echo fixture-existing-swap"),
                           ("systemctl", "echo active"), ("adduser", "exit 0"),
                           ("google-chrome", "echo 'Google Chrome fixture'"),
                           ("microsoft-edge", "echo 'Microsoft Edge fixture'"),
                           ("ss", "echo 'LISTEN 0 128 0.0.0.0:3389 0.0.0.0:*'")):
            self.stub(name, body)

    def stub(self, name, body):
        path = self.root / "bin" / name
        path.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8", newline="\n")
        path.chmod(0o700)

    def local_script(self, source):
        source = source.replace("/usr/share/keyrings", shell_path(self.root / "keyrings"))
        source = source.replace("/etc/apt/sources.list.d", shell_path(self.root / "sources"))
        source = source.replace("/root/.xsession", shell_path(self.root / "home/.xsession"))
        return "export PATH=" + shlex.quote(self.env["PATH"]) + "; " + source

    def execute(self, script):
        return subprocess.run([bash_binary(), "-e", "-o", "pipefail", "-c", self.local_script(script)],
                              env=self.env, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, encoding="utf-8", timeout=30)

    def assert_old_repository(self):
        self.assertEqual(self.keyring.read_bytes(), b"old-valid-keyring")
        self.assertEqual(self.source.read_bytes(), b"old-source-list\n")

    def assert_temporaries_cleaned(self):
        self.assertEqual(list((self.root / "keyrings").glob(".g-network-edge.*")), [])
        self.assertEqual(list((self.root / "sources").glob(".g-network-edge.*")), [])
        self.assertEqual(list((self.root / "tmp").iterdir()), [])

    def test_legacy_overwrite_reproduces_user_no_tty_error_without_real_gpg(self):
        legacy = "curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg"
        result = self.execute(legacy)
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot open '/dev/tty'", result.stderr)
        self.assert_old_repository()

    def test_existing_keyring_can_be_updated_twice_without_tty_or_prompts(self):
        for _ in range(2):
            result = self.execute(script_common.microsoft_edge_repository_script())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.keyring.read_bytes(), b"new-valid-keyring")
            self.assertIn(b"signed-by=", self.source.read_bytes())
            self.assert_temporaries_cleaned()
        for line in (self.root / "gpg-args").read_text().splitlines():
            self.assertIn("--batch", line)
            self.assertIn("--yes", line)
            self.assertIn("--no-tty", line)

    def test_download_bad_key_empty_or_unparseable_key_preserves_original_and_skips_apt(self):
        for flag in ("FAIL_CURL", "FAIL_GPG", "EMPTY_GPG", "FAIL_SHOW", "NO_PUB"):
            with self.subTest(flag=flag):
                self.env[flag] = "1"
                result = self.execute(script_common.microsoft_edge_repository_script() + "apt-get install -y microsoft-edge-stable")
                self.env.pop(flag)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)
                self.assert_old_repository()
                self.assertFalse((self.root / "apt-args").exists())
                self.assert_temporaries_cleaned()

    def test_atomic_commit_failure_is_visible_and_does_not_report_completion(self):
        self.env["FAIL_MV"] = "1"
        result = self.execute(script_common.microsoft_edge_repository_script() + "echo COMPLETE")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated atomic", result.stderr)
        self.assertNotIn("COMPLETE", result.stdout)
        self.assert_old_repository()
        self.assert_temporaries_cleaned()

    def test_ui_desktop_repeat_uses_fresh_private_chrome_download_and_shared_key_stage(self):
        script = ui_desktop_script()
        self.assertIn(script_common.microsoft_edge_repository_script(), script)
        for _ in range(2):
            result = self.execute(script)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("[4/4] Edge:", result.stdout)
            self.assert_temporaries_cleaned()
        paths = (self.root / "chrome-paths").read_text().splitlines()
        self.assertEqual(len(paths), 2)
        self.assertNotEqual(paths[0], paths[1])
        self.assertTrue(all(name.endswith("/chrome.deb") for name in paths))

    def test_ui_chrome_download_failure_cleans_temporary_and_never_calls_gpg(self):
        self.env["FAIL_WGET"] = "1"
        result = self.execute(ui_desktop_script())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated Chrome", result.stderr)
        self.assertFalse((self.root / "gpg-args").exists())
        self.assert_temporaries_cleaned()

    def test_ui_edge_apt_error_is_visible_and_does_not_log_stage_success(self):
        self.env["FAIL_EDGE_APT"] = "1"
        result = self.execute(ui_desktop_script())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("simulated Edge APT error", result.stderr)
        self.assertNotIn("[4/4] Edge:", result.stdout)
        self.assert_temporaries_cleaned()

    def test_cli_desktop_uses_the_same_shared_repository_stage(self):
        commands = []
        client = Mock()
        from contextlib import nullcontext
        with patch.object(install_desktop, "ssh_connection", return_value=nullcontext(client)), \
                patch.object(install_desktop, "elevated_ssh", return_value=client), \
                patch.object(install_desktop, "require_amd64_debian"), \
                patch.object(install_desktop, "user_home", return_value="/home/fixture"), \
                patch.object(install_desktop, "listening_ports", return_value={3389}), \
                patch.object(install_desktop, "run", side_effect=lambda ssh, command, **kw: commands.append(command)), \
                patch("sys.stdout", new=io.StringIO()):
            install_desktop.main({"SSH_HOST": "example.invalid", "SSHPASS": "dummy-only"})
        edge = next(command for command in commands if "microsoft-edge-stable" in command)
        self.assertIn(script_common.microsoft_edge_repository_script(), edge)


if __name__ == "__main__":
    unittest.main()
