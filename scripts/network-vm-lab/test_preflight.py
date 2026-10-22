import contextlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("preflight", Path(__file__).with_name("preflight.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
BOOT = "12345678-1234-1234-1234-123456789abc"


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(p.platform, "system", return_value="Linux"))
        self.stack.enter_context(patch.object(p.platform, "machine", return_value="x86_64"))
        self.stack.enter_context(patch.object(p.platform, "release", return_value="fixture-kernel"))
        self.files = {"/etc/os-release": 'ID="rocky"\nVERSION_ID="10.0"\nSECRET=do-not-emit\n',
                      "/proc/sys/kernel/random/boot_id": BOOT + "\n"}
        self.stack.enter_context(patch.object(p, "read_small", side_effect=self.files.get))
        self.answers = {
            ("ip", "-Version"): ("0", "ip utility, iproute2-6.11.0, libbpf 1.4"),
            ("wg", "--version"): ("0", "wireguard-tools v1.0.20210914"),
            ("nmcli", "--version"): ("0", "nmcli tool, version 1.52.0"),
            ("systemctl", "--version"): ("0", "systemd 257 (fixture)\n+PAM"),
            ("systemctl", "is-active", "NetworkManager.service"): ("0", "active"),
            ("systemctl", "is-active", "systemd-networkd.service"): ("3", "inactive"),
            ("systemctl", "is-active", "heliopause-agent.service"): ("0", "active"),
        }
        self.calls = []
        def fake(argv):
            self.calls.append(argv)
            return self.answers[argv]
        self.stack.enter_context(patch.object(p, "probe", side_effect=fake))
        self.stack.enter_context(patch.object(p.subprocess, "Popen", side_effect=AssertionError("escaped process")))
        self.stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("escaped socket")))
        self.stack.enter_context(patch.object(Path, "open", side_effect=AssertionError("escaped file")))

    def test_observations_do_not_claim_backend_or_boot_readiness(self):
        r = p.collect()
        self.assertEqual(r["os"], {"ID": "rocky", "VERSION_ID": "10.0"})
        self.assertEqual(r["bootId"], BOOT)
        self.assertEqual(r["probes"]["networkManager"]["version"], "1.52.0")
        self.assertEqual(r["probes"]["networkdState"]["state"], "inactive")
        self.assertIsNone(r["backendSelected"])
        self.assertFalse(r["hostRebootVerified"])
        self.assertIn("actual-vm-reboot-not-verified", r["blockers"])
        self.assertNotIn("SECRET", json.dumps(r))
        self.assertEqual(self.calls, [
            ("ip", "-Version"), ("wg", "--version"), ("nmcli", "--version"),
            ("systemctl", "--version"), ("systemctl", "is-active", "NetworkManager.service"),
            ("systemctl", "is-active", "systemd-networkd.service"),
            ("systemctl", "is-active", "heliopause-agent.service")])

    def test_non_linux_performs_no_guest_reads_or_commands(self):
        with patch.object(p.platform, "system", return_value="Darwin"), patch.object(
                p, "read_small", side_effect=AssertionError("guest read")):
            self.assertEqual(p.collect()["blockers"], ["linux-guest-required"])
        self.assertEqual(self.calls, [])

    def test_wrong_os_and_missing_boot_are_explicit(self):
        self.files["/etc/os-release"] = "ID=rhel\nVERSION_ID=10\n"
        self.files.pop("/proc/sys/kernel/random/boot_id")
        r = p.collect()
        self.assertIn("rocky-10-guest-required", r["blockers"])
        self.assertIn("boot-id-unavailable", r["blockers"])

    def test_failed_nm_is_unknown_not_inactive(self):
        self.answers[("systemctl", "is-active", "NetworkManager.service")] = ("1", "inactive")
        self.answers[("nmcli", "--version")] = ("timeout", None)
        r = p.collect()
        self.assertIsNone(r["probes"]["networkManagerState"]["state"])
        self.assertEqual(r["probes"]["networkManager"]["reason"], "timeout")

    def test_unrecognized_tool_output_is_not_echoed(self):
        self.answers[("wg", "--version")] = ("0", "private-key=/fixture/secret")
        r = p.collect()
        self.assertIn("wireguard-unknown", r["blockers"])
        self.assertNotIn("/fixture/secret", json.dumps(r))

    def test_contradictory_service_status_is_unknown(self):
        self.answers[("systemctl", "is-active", "NetworkManager.service")] = ("3", "active")
        self.assertIsNone(p.collect()["probes"]["networkManagerState"]["state"])

    def test_cli_is_explicit_and_blocked_inventory_exits_two(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(p.main(["--collect"]), 2)
        self.assertFalse(json.loads(out.getvalue())["hostRebootVerified"])

    def test_cli_no_flag_or_remote_argument_never_probes(self):
        for argv in ([], ["--collect", "--host", "fixture"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
                p.main(argv)
            self.assertEqual(ctx.exception.code, 2)
        self.assertEqual(self.calls, [])


class BoundaryTests(unittest.TestCase):
    # These fixtures run only the local Python interpreter, not ip/wg/systemctl.
    def test_probe_discards_stderr_and_parent_environment(self):
        with patch.dict("os.environ", {"PRIVATE_FIXTURE": "do-not-emit"}):
            status, output = p.probe((sys.executable, "-c",
                "import os,sys;print(os.getenv('PRIVATE_FIXTURE','absent'));sys.stderr.write('private')"))
        self.assertEqual((status, output), ("0", "absent"))

    def test_probe_missing_binary(self):
        self.assertEqual(p.probe(("/nonexistent/heliopause-fixture",)), ("unavailable", None))

    def test_probe_caps_output(self):
        self.assertEqual(p.probe((sys.executable, "-c", "print('x'*1000000)")), ("invalid-output", None))

    def test_probe_times_out_hung_child(self):
        self.assertEqual(p.probe((sys.executable, "-c", "import time;time.sleep(30)")), ("timeout", None))

    def test_probe_rejects_invalid_utf8(self):
        self.assertEqual(p.probe((sys.executable, "-c", "import os;os.write(1,b'\\xff')")), ("invalid-output", None))

    def test_read_error_kills_and_reaps_started_child(self):
        children = []
        original = p.subprocess.Popen
        def record(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        # Popen also reads its exec-error pipe; fail only the fixture stdout.
        original_read = p.os.read
        def fail_stdout(fd, size):
            if children and fd == children[0].stdout.fileno():
                raise OSError("fixture private error path")
            return original_read(fd, size)
        started = time.monotonic()
        with patch.object(p.os, "read", side_effect=fail_stdout), patch.object(
                p.subprocess, "Popen", side_effect=record):
            result = p.probe((sys.executable, "-c", "import time;print('ready',flush=True);time.sleep(30)"))
        self.assertEqual(result, ("unavailable", None))
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())
        self.assertLess(time.monotonic() - started, 3)

    def test_read_small_missing_oversized_and_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture"
            self.assertIsNone(p.read_small(path))
            path.write_text("x" * 4097)
            self.assertIsNone(p.read_small(path))
            path.write_text("ID=rocky\n")
            self.assertEqual(p.read_small(path), "ID=rocky\n")


if __name__ == "__main__":
    unittest.main()
