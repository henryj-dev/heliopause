"""Only mock collectors/transports and benign Python children run in this suite."""
import importlib.util
from contextlib import ExitStack
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import network_discovery_lifecycle as lifecycle
import network_discovery_worker as worker


def fixture():
    at = "2026-01-01T00:00:00+00:00"
    return {"schemaVersion": 1, "startedAt": at, "completedAt": at,
            "observations": {"links": {"status": "success", "startedAt": at, "completedAt": at, "data": []}},
            "capabilities": {"links": {"available": True, "status": "success"}}}


class WorkerTests(unittest.TestCase):
    def test_worker_has_own_deadline_if_parent_exits(self):
        with mock.patch.object(worker.signal, "signal") as install, mock.patch.object(worker.signal, "alarm") as alarm, mock.patch.object(worker, "collect_report", return_value=fixture()), mock.patch.object(worker, "upload"):
            worker.main()
        install.assert_called_once()
        self.assertEqual(alarm.call_args_list, [mock.call(40), mock.call(0)])

    def test_exited_leader_still_cleans_its_live_child(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "child-survived")
            ready = str(Path(directory) / "child-started")
            # A detached session leader exits immediately while its descendant would
            # write a marker later. Cleanup must kill the surviving group, not only leader.
            child = "import time,pathlib;pathlib.Path(" + repr(ready) + ").write_text('ready');time.sleep(.5);pathlib.Path(" + repr(marker) + ").write_text('orphan')"
            command = "import subprocess,sys,time,pathlib;subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);\nwhile not pathlib.Path(" + repr(ready) + ").exists(): time.sleep(.01)"
            self.assertTrue(lifecycle.run_once(threading.Event(), [sys.executable, "-c", command], 2))
            self.assertTrue(Path(ready).exists())
            time.sleep(.7)
            self.assertFalse(Path(marker).exists())

    def test_worker_deadline_cleans_session_after_parent_is_gone(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "orphan-survived")
            ready = str(Path(directory) / "orphan-started")
            worker_path = str(Path(__file__).resolve().parent)
            child = "import time,pathlib;pathlib.Path(" + repr(ready) + ").write_text('ready');time.sleep(.7);pathlib.Path(" + repr(marker) + ").write_text('orphan')"
            # This benign session is orphaned by a short-lived launcher. The real worker
            # alarm handler must terminate its descendant after that launcher has exited.
            detached = "import sys,signal,subprocess,time;sys.path.insert(0," + repr(worker_path) + ");import network_discovery_worker as w;subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);signal.signal(signal.SIGALRM,w._hard_deadline);signal.setitimer(signal.ITIMER_REAL,.2);time.sleep(5)"
            launcher = "import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(detached) + "],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
            import subprocess
            subprocess.run([sys.executable, "-c", launcher], check=True, timeout=2)
            deadline = time.monotonic() + 1
            while not Path(ready).exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(Path(ready).exists())
            time.sleep(.9)
            self.assertFalse(Path(marker).exists())

    def test_standalone_deadline_does_not_signal_callers_group(self):
        with mock.patch.object(worker.os, "getpid", return_value=2), mock.patch.object(worker.os, "getsid", return_value=1), mock.patch.object(worker.os, "getpgrp", return_value=1), mock.patch.object(worker.os, "killpg") as kill, mock.patch.object(worker.os, "_exit", side_effect=SystemExit):
            with self.assertRaises(SystemExit): worker._hard_deadline()
            kill.assert_not_called()

    def test_default_disabled_never_launches(self):
        with mock.patch.object(lifecycle.subprocess, "Popen") as launch:
            self.assertIsNone(lifecycle.start_discovery_worker(threading.Event()))
            launch.assert_not_called()

    def test_start_returns_without_waiting_for_collection(self):
        began, release, stop = threading.Event(), threading.Event(), threading.Event()
        def blocked(*args):
            began.set()
            release.wait(2)
        with mock.patch.object(lifecycle, "run_once", blocked):
            thread = lifecycle.start_discovery_worker(stop, enabled=True)
            self.assertTrue(began.wait(1))
            self.assertTrue(thread.is_alive())
            stop.set(); release.set(); thread.join(1)
            self.assertFalse(thread.is_alive())

    def test_hung_child_does_not_block_heartbeat_or_rollback_timer_and_is_reaped(self):
        # These independent callbacks stand for the policy loop and its Timer; a real child is
        # held while both fire. This verifies scheduler isolation, not a real nftables rollback.
        stop = threading.Event(); heartbeat = threading.Event(); rollback = threading.Event()
        finished = threading.Event(); outcome = []
        def run():
            outcome.append(lifecycle.run_once(stop, [sys.executable, "-c", "import time; time.sleep(10)"], .4))
            finished.set()
        thread = threading.Thread(target=run); thread.start()
        timer = threading.Timer(.05, rollback.set); timer.start()
        heartbeat.set()
        self.assertTrue(heartbeat.wait(.2)); self.assertTrue(rollback.wait(.2))
        self.assertFalse(finished.is_set())
        thread.join(2); timer.join(1)
        self.assertFalse(thread.is_alive()); self.assertEqual(outcome, [False])

    def test_real_policy_main_heartbeats_while_discovery_is_held(self):
        spec = importlib.util.spec_from_file_location("isolated_policy_agent", Path(__file__).with_name("heliopause-pull.py"))
        agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)
        began, release, stop, heartbeated, timed = [threading.Event() for _ in range(5)]
        def held(*args):
            began.set(); release.wait(2)
        def beat(payload):
            self.assertTrue(began.wait(1)); heartbeated.set()
            self.assertTrue(timed.wait(1)); return {}
        timer = threading.Timer(.05, timed.set)
        with ExitStack() as patches:
            for name in ("CA_FILE", "CERT_FILE", "KEY_FILE", "TARGET", "MANAGER_SIGNING_KEYS_DIR", "BREAK_GLASS_KEYS_DIR"):
                patches.enter_context(mock.patch.object(agent, name, "fixture"))
            patches.enter_context(mock.patch.object(agent, "RELAY_URL", "https://relay.invalid"))
            patches.enter_context(mock.patch.object(agent, "INTERVAL_ERROR", ""))
            patches.enter_context(mock.patch.object(agent, "_stop", stop))
            patches.enter_context(mock.patch.dict(os.environ, {"HELIOPAUSE_NETWORK_DISCOVERY": "1"}))
            patches.enter_context(mock.patch.object(agent.signal, "signal"))
            patches.enter_context(mock.patch.object(agent, "load_artifact_trust", return_value={"managerKeyIds": [], "breakGlassKeyIds": [], "trustDigest": "fixture"}))
            for name in ("log", "backfill_current_authorization", "recover_commitment", "recover_workload_commitment", "reconcile_recovered_commitments", "_boot_restore", "monitor_loop", "handle_reply_safely"):
                patches.enter_context(mock.patch.object(agent, name))
            patches.enter_context(mock.patch.object(agent, "load_state", return_value={}))
            patches.enter_context(mock.patch.object(agent, "build_heartbeat", return_value={"host": "fixture"}))
            patches.enter_context(mock.patch.object(agent, "post_heartbeat", side_effect=beat))
            patches.enter_context(mock.patch.object(agent, "_has_live_commitment", return_value=False))
            patches.enter_context(mock.patch.object(agent, "sleep_interval", side_effect=stop.set))
            patches.enter_context(mock.patch.object(lifecycle, "run_once", side_effect=held))
            timer.start()
            try:
                self.assertEqual(agent.main(), 0)
                self.assertTrue(heartbeated.is_set()); self.assertTrue(timed.is_set())
                self.assertFalse(release.is_set())
            finally:
                stop.set(); release.set(); timer.join(1)

    def test_shutdown_terminates_running_child(self):
        stop = threading.Event()
        timer = threading.Timer(.05, stop.set); timer.start()
        self.assertFalse(lifecycle.run_once(stop, [sys.executable, "-c", "import time; time.sleep(10)"], 2))
        timer.join()

    def test_benign_child_success_and_failure(self):
        self.assertTrue(lifecycle.run_once(threading.Event(), [sys.executable, "-c", "pass"], 2))
        self.assertFalse(lifecycle.run_once(threading.Event(), [sys.executable, "-c", "raise SystemExit(1)"], 2))

    def test_report_budget_and_collection_identity(self):
        with mock.patch.object(worker, "collect_network_state", return_value=fixture()) as collect:
            report = worker.collect_report()
            self.assertEqual(len(report["collectionId"]), 36)
            collect.assert_called_once_with(timeout=2.0, total_timeout=30.0, output_limit=128 * 1024)

    def test_oversize_report_reports_failure_without_partial_success(self):
        value = fixture(); value["observations"]["links"]["data"] = [{"ifname": "x" * (128 * 1024)}]
        with mock.patch.object(worker, "collect_network_state", return_value=value):
            report = worker.collect_report()
        self.assertNotIn("data", report["observations"]["links"])
        self.assertEqual(report["observations"]["links"]["status"], "output-limit")
        self.assertFalse(report["capabilities"]["links"]["available"])

    def test_row_ceiling_preserves_other_queries_below_byte_limit(self):
        value = fixture()
        query = dict(value["observations"]["links"], data=[{"dst": "default"}] * 2049)
        value["observations"]["routes4"] = query
        value["capabilities"]["routes4"] = {"available": True, "status": "success"}
        self.assertLess(len(json.dumps(value).encode()), worker.MAX_REPORT_BYTES)
        with mock.patch.object(worker, "collect_network_state", return_value=value):
            report = worker.collect_report()
        self.assertEqual(report["observations"]["routes4"]["status"], "output-limit")
        self.assertNotIn("data", report["observations"]["routes4"])
        self.assertEqual(report["capabilities"]["routes4"], {"available": False, "status": "output-limit"})
        self.assertEqual(report["observations"]["links"]["data"], [])
        self.assertEqual(report["capabilities"]["links"], {"available": True, "status": "success"})

    def test_nested_array_ceiling_preserves_other_queries_below_byte_limit(self):
        for name, row in (
            ("addresses", {"ifindex": 1, "ifname": "example0", "addresses": [{"family": "inet6", "local": "::", "prefixlen": 128}] * 2049}),
            ("wg-allowed-ips", {"interface": "example0", "peerPublicKey": "A" * 43 + "=", "allowedIPs": ["::/0"] * 2049}),
            ("frr-routes6", {"addressFamily": "ipv6", "prefix": "::/0", "valid": True, "bestPath": True, "nextHops": ["::"] * 2049}),
        ):
            with self.subTest(query=name):
                value = fixture()
                value["observations"][name] = dict(value["observations"]["links"], data=[row])
                value["capabilities"][name] = {"available": True, "status": "success"}
                self.assertLess(len(json.dumps(value).encode()), worker.MAX_REPORT_BYTES)
                with mock.patch.object(worker, "collect_network_state", return_value=value):
                    report = worker.collect_report()
                self.assertEqual(report["observations"][name]["status"], "output-limit")
                self.assertNotIn("data", report["observations"][name])
                self.assertFalse(report["capabilities"][name]["available"])
                self.assertEqual(report["observations"]["links"]["status"], "success")
                self.assertTrue(report["capabilities"]["links"]["available"])

    def test_array_ceiling_allows_exactly_2048_rows(self):
        value = fixture()
        value["observations"]["links"]["data"] = [{"ifindex": 1, "ifname": "example0"}] * 2048
        with mock.patch.object(worker, "collect_network_state", return_value=value):
            report = worker.collect_report()
        self.assertEqual(report["observations"]["links"]["status"], "success")
        self.assertEqual(len(report["observations"]["links"]["data"]), 2048)

    def test_invalid_schedule_has_no_process_side_effect(self):
        with mock.patch.object(lifecycle.subprocess, "Popen") as launch:
            with self.assertRaises(ValueError): lifecycle.start_discovery_worker(threading.Event(), enabled=True, interval=0)
            with self.assertRaises(ValueError): lifecycle.start_discovery_worker(threading.Event(), enabled=True, budget=999)
            launch.assert_not_called()

    def test_agent_starts_worker_only_after_recovery_and_boot_restore(self):
        source = Path(__file__).with_name("heliopause-pull.py").read_text()
        main = source[source.index("def main():"):]
        self.assertLess(main.index("recover_commitment()"), main.index("start_discovery_worker("))
        self.assertLess(main.index("_boot_restore()"), main.index("start_discovery_worker("))
        self.assertIn('os.environ.get("HELIOPAUSE_NETWORK_DISCOVERY", "") == "1"', main)
        self.assertNotIn("network", source[source.index("def post_heartbeat("):source.index("# The envelope as text")])

    def test_auxiliary_files_are_in_npm_and_manual_install_paths(self):
        root = Path(__file__).resolve().parent.parent
        package = json.loads((root / "package.json").read_text())
        install = (root / "packaging/systemd/README.md").read_text()
        deploy = (root / "scripts/deploy-fleet.sh").read_text()
        for name in ("network_discovery.py", "network_discovery_worker.py", "network_discovery_lifecycle.py"):
            self.assertIn("agent/" + name, package["files"])
            self.assertIn("agent/" + name, install)
        self.assertIn('paths="agent"', deploy)

    def test_upload_uses_existing_pin_setting_and_no_raw_failures(self):
        env = {"HELIOPAUSE_RELAY_URL": "https://relay.invalid", "HELIOPAUSE_CA_FILE": "ca", "HELIOPAUSE_CERT_FILE": "cert", "HELIOPAUSE_KEY_FILE": "key", "HELIOPAUSE_HOST_ID": "host", "HELIOPAUSE_PINS": "wrong"}
        conn = mock.Mock(); conn.sock.getpeercert.return_value = b"untrusted"
        with mock.patch.dict(os.environ, env), mock.patch.object(worker.ssl, "create_default_context"), mock.patch.object(worker.http.client, "HTTPSConnection", return_value=conn):
            with self.assertRaises(ssl.SSLCertVerificationError): worker.upload(fixture())
            conn.request.assert_not_called(); conn.close.assert_called_once()

    def test_host_identity_falls_back_like_policy_agent(self):
        env = {"HELIOPAUSE_RELAY_URL": "https://relay.invalid", "HELIOPAUSE_CA_FILE": "ca", "HELIOPAUSE_CERT_FILE": "cert", "HELIOPAUSE_KEY_FILE": "key", "HELIOPAUSE_PINS": ""}
        conn = mock.Mock(); conn.getresponse.return_value.status = 200; conn.getresponse.return_value.read.return_value = b"{}"
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(worker.socket, "gethostname", return_value="fallback-host"), mock.patch.object(worker.ssl, "create_default_context"), mock.patch.object(worker.http.client, "HTTPSConnection", return_value=conn):
            worker.upload(fixture())
            self.assertEqual(json.loads(conn.request.call_args.args[2])["host"], "fallback-host")

    def test_upload_is_separate_authenticated_post_and_bounded_response(self):
        env = {"HELIOPAUSE_RELAY_URL": "https://relay.invalid/prefix", "HELIOPAUSE_CA_FILE": "ca", "HELIOPAUSE_CERT_FILE": "cert", "HELIOPAUSE_KEY_FILE": "key", "HELIOPAUSE_HOST_ID": "host", "HELIOPAUSE_PINS": ""}
        conn = mock.Mock(); conn.getresponse.return_value.status = 200; conn.getresponse.return_value.read.return_value = b"{}"
        with mock.patch.dict(os.environ, env), mock.patch.object(worker.ssl, "create_default_context") as context, mock.patch.object(worker.http.client, "HTTPSConnection", return_value=conn):
            worker.upload(fixture())
            context.return_value.load_cert_chain.assert_called_once_with("cert", "key")
            self.assertEqual(conn.request.call_args.args[:2], ("POST", "/prefix/network/observations"))
            self.assertEqual(json.loads(conn.request.call_args.args[2])["host"], "host")
            conn.getresponse.return_value.read.assert_called_once_with(4097)


if __name__ == "__main__":
    unittest.main()
