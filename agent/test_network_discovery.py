#!/usr/bin/env python3
"""Discovery tests use fixtures and harmless Python children, never host discovery."""
import base64
from datetime import datetime, timedelta, timezone
import json
import subprocess
import sys
import unittest
from unittest import mock

import network_discovery as discovery

PUBLIC_KEY = base64.b64encode(bytes(range(32))).decode()


class DiscoveryTests(unittest.TestCase):
    def test_fixed_allowlist_excludes_mutation_and_secrets(self):
        self.assertEqual(set(discovery.COMMANDS), {"links", "addresses", "routes4", "routes6", "rules4", "rules6", "frr-version", "frr-daemons", "frr-bgp-summary", "frr-routes4", "frr-routes6", "frr-bfd"} | {"wg-" + s for s in ("public-key", "listen-port", "peers", "endpoints", "allowed-ips", "latest-handshakes", "transfer", "persistent-keepalive")})
        for args in discovery.COMMANDS.values():
            self.assertNotIn("dump", args)
            self.assertNotIn("showconf", args)
            self.assertNotIn("private-key", args)
            self.assertNotIn("preshared-keys", args)
        with mock.patch.object(discovery, "_capture") as boundary:
            for name in ("links; echo unsafe", "wg-dump", "wg-private-key"):
                with self.assertRaises(ValueError): discovery.run_command(name)
            boundary.assert_not_called()

    def test_unsupported_platform_never_launches_process(self):
        with mock.patch.object(discovery.platform, "system", return_value="Darwin"), mock.patch.object(discovery, "_capture") as boundary:
            self.assertEqual(discovery.run_command("links"), ("unsupported", b""))
            boundary.assert_not_called()

    def test_missing_binary_is_distinct_from_permission_error(self):
        with mock.patch.object(discovery.platform, "system", return_value="Linux"), mock.patch.object(discovery.shutil, "which", return_value=None):
            self.assertEqual(discovery.run_command("links"), ("not-installed", b""))
        with mock.patch.object(discovery.platform, "system", return_value="Linux"), mock.patch.object(discovery.shutil, "which", return_value="/usr/sbin/ip"), mock.patch.object(discovery, "_capture", side_effect=PermissionError):
            self.assertEqual(discovery.run_command("links"), ("unavailable", b""))

    def test_command_resolution_uses_fixed_system_path_and_fixed_args(self):
        with mock.patch.object(discovery.platform, "system", return_value="Linux"), mock.patch.object(discovery.shutil, "which", return_value="/usr/bin/wg") as which, mock.patch.object(discovery, "_capture", return_value=("success", b"")) as capture:
            discovery.run_command("wg-public-key")
            which.assert_called_once_with("wg", path=discovery.SYSTEM_PATH)
            capture.assert_called_once_with(("/usr/bin/wg", "show", "all", "public-key"), 3.0, 1048576)

    def test_resource_limits_reject_invalid_inputs_before_launch(self):
        with mock.patch.object(discovery, "_capture") as boundary:
            for value in (0, -1, 31, True, float("nan"), "3"):
                with self.assertRaises(ValueError): discovery.run_command("links", timeout=value)
            for value in (0, -1, 17000000, True, "1"):
                with self.assertRaises(ValueError): discovery.run_command("links", output_limit=value)
            boundary.assert_not_called()

    def child(self, code, **limits):
        return discovery._capture((sys.executable, "-c", code), limits.get("timeout", 2), limits.get("output_limit", 4096))

    def test_process_stdout_success(self):
        status, raw = self.child("import os; os.write(1,b'[]')")
        self.assertEqual((status, raw), ("success", b"[]"))

    def test_zero_exit_with_stderr_is_unavailable_not_partial_success(self):
        self.assertEqual(self.child("import os; os.write(1,b'[]'); os.write(2,b'partial WireGuard failure')"), ("unavailable", b""))

    def test_process_failure_omits_both_streams(self):
        self.assertEqual(self.child("import os; os.write(1,b'secret'); os.write(2,b'secret'); raise SystemExit(2)"), ("unavailable", b""))

    def test_process_timeout_kills_and_reaps_child(self):
        real_popen = subprocess.Popen
        children = []
        def track(*args, **kwargs):
            self.assertFalse(kwargs["shell"])
            proc = real_popen(*args, **kwargs)
            children.append(proc)
            return proc
        with mock.patch.object(discovery.subprocess, "Popen", side_effect=track):
            self.assertEqual(self.child("import time; time.sleep(5)", timeout=0.1), ("timeout", b""))
        self.assertIsNotNone(children[0].returncode)
        self.assertNotEqual(children[0].returncode, 0)

    def test_live_stdout_and_stderr_limits_stop_unbounded_children(self):
        for fd in (1, 2):
            status, raw = self.child(f"import os\nwhile True: os.write({fd}, b'x'*2048)", output_limit=1024)
            self.assertEqual((status, raw), ("output-limit", b""))

    def test_pipe_eof_before_process_exit_still_has_timeout(self):
        self.assertEqual(self.child("import os,time; os.close(1); os.close(2); time.sleep(5)", timeout=0.1), ("timeout", b""))

    def test_interface_and_address_normalization_discards_unknown_fields(self):
        raw = json.dumps([{"ifindex": 2, "ifname": "example0", "mtu": 1420, "operstate": "UP", "flags": ["UP"], "private_key": "do-not-report", "addr_info": [{"family": "inet6", "local": "2001:db8::1", "prefixlen": 64, "scope": "global", "secret": "do-not-report"}]}])
        links = discovery.normalize_linux("links", raw)
        addresses = discovery.normalize_linux("addresses", raw)
        self.assertEqual(links[0]["mtu"], 1420)
        self.assertEqual(addresses[0]["addresses"], [{"family": "inet6", "local": "2001:db8::1", "prefixlen": 64, "scope": "global"}])
        self.assertNotIn("do-not-report", json.dumps(links + addresses))

    def test_routes_and_rules_only_report_observed_tables_and_fields(self):
        route = discovery.normalize_linux("routes4", '[{"dst":"192.0.2.0/24","gateway":"192.0.2.1","dev":"example0","table":100,"protocol":"bgp","secret":"omit"}]')
        self.assertEqual(route[0]["table"], 100)
        self.assertEqual(route[0]["protocol"], "bgp")
        self.assertNotIn("secret", route[0])
        rules = discovery.normalize_linux("rules6", '[{"priority":100,"src":"all","table":"main"}]')
        self.assertEqual(rules[0]["table"], "main")
        self.assertEqual(rules[0]["src"], "all")

    def test_unrepresented_route_semantics_and_missing_identity_never_report_success(self):
        for field in ("multipath", "nexthops", "via", "nhid", "encap"):
            with self.assertRaises(discovery.UnsupportedObservation):
                discovery.normalize_linux("routes4", json.dumps([{"dst": "default", field: []}]))
        with self.assertRaises(ValueError): discovery.normalize_linux("routes4", '[{"protocol":"bgp"}]')
        with self.assertRaises(ValueError): discovery.normalize_linux("rules4", '[{"table":"main"}]')
        with mock.patch.object(discovery, "run_command", return_value=("success", b'[{"dst":"default","nexthops":[]}]')):
            report = discovery.collect_network_state()
        self.assertEqual(report["observations"]["routes4"]["status"], "unsupported")
        self.assertNotIn("data", report["observations"]["routes4"])

    def test_invalid_linux_json_fields_fail_closed(self):
        for raw in ('{}', '[null]', '[{"ifindex":true,"ifname":"example0"}]', '[{"ifindex":1,"ifname":"unsafe name"}]'):
            with self.assertRaises((ValueError, KeyError)): discovery.normalize_linux("links", raw)
        with self.assertRaises(ValueError):
            discovery.normalize_linux("addresses", '[{"ifindex":2,"ifname":"example0","addr_info":[{"family":"inet","local":"2001:db8::1","prefixlen":64}]}]')

    def test_context_prefix_and_family_validation_reject_ambiguous_observations(self):
        for raw in ('[{"dst":"all"}]', '[{"dst":"2001:db8::/64"}]', '[{"dst":"default","gateway":"2001:db8::1"}]', '[{"dst":"default","gateway":1}]'):
            with self.assertRaises(ValueError): discovery.normalize_linux("routes4", raw)
        with self.assertRaises(ValueError): discovery.normalize_linux("rules4", '[{"priority":1,"src":"2001:db8::/64","table":100}]')
        for value in (True, 1):
            with self.assertRaises(ValueError): discovery.normalize_linux("addresses", json.dumps([{"ifindex":2,"ifname":"example0","addr_info":[{"family":"inet","local":value,"prefixlen":32}]}]))
        for value in ("all", "default"):
            with self.assertRaises(ValueError): discovery.normalize_wireguard("allowed-ips", f"example0\t{PUBLIC_KEY}\t{value}\n".encode())
        for field in ("fwmark", "l3mdev", "goto"):
            with self.assertRaises(discovery.UnsupportedObservation): discovery.normalize_linux("rules4", json.dumps([{"priority":1,"src":"all","table":100,field:1}]))

    def test_all_wireguard_public_fields_are_normalized(self):
        samples = {
            "public-key": (f"example0\t{PUBLIC_KEY}\n", {"publicKey": PUBLIC_KEY}),
            "listen-port": ("example0\t51820\n", {"listenPort": 51820}),
            "peers": (f"example0\t{PUBLIC_KEY}\n", {"peerPublicKey": PUBLIC_KEY}),
            "endpoints": (f"example0\t{PUBLIC_KEY}\t[2001:db8::1]:51820\n", {"endpoint": {"address": "2001:db8::1", "port": 51820}}),
            "allowed-ips": (f"example0\t{PUBLIC_KEY}\t192.0.2.1/32 2001:db8::/64\n", {"allowedIPs": ["192.0.2.1/32", "2001:db8::/64"]}),
            "latest-handshakes": (f"example0\t{PUBLIC_KEY}\t123\n", {"latestHandshake": 123}),
            "transfer": (f"example0\t{PUBLIC_KEY}\t4\t5\n", {"rxBytes": 4, "txBytes": 5}),
            "persistent-keepalive": (f"example0\t{PUBLIC_KEY}\toff\n", {"persistentKeepalive": 0}),
        }
        for field, (raw, expected) in samples.items():
            row = discovery.normalize_wireguard(field, raw.encode())[0]
            for key, value in expected.items(): self.assertEqual(row[key], value)

    def test_wireguard_empty_state_and_none_values(self):
        self.assertEqual(discovery.normalize_wireguard("peers", b""), [])
        self.assertIsNone(discovery.normalize_wireguard("public-key", b"example0\t(none)\n")[0]["publicKey"])
        self.assertIsNone(discovery.normalize_wireguard("endpoints", f"example0\t{PUBLIC_KEY}\t(none)\n".encode())[0]["endpoint"])

    def test_wireguard_rejects_secret_dump_shaped_or_malformed_output(self):
        for field, raw in (("public-key", b"example0\tprivate\tsecret\t51820\n"), ("public-key", b"example0\tnot-a-public-key\n"), ("transfer", f"example0\t{PUBLIC_KEY}\t-1\t2\n".encode()), ("endpoints", f"example0\t{PUBLIC_KEY}\tunsafe:51820\n".encode())):
            with self.assertRaises(ValueError): discovery.normalize_wireguard(field, raw)

    def test_report_omits_raw_error_data_and_includes_capability_timestamps(self):
        def command(name, **kwargs):
            return ("success", b"[]") if name == "links" else ("unavailable", b"SECRET")
        with mock.patch.object(discovery, "run_command", side_effect=command):
            report = discovery.collect_network_state()
        self.assertEqual(report["observations"]["links"]["data"], [])
        self.assertEqual(report["capabilities"]["links"], {"available": True, "status": "success"})
        self.assertNotIn("data", report["observations"]["addresses"])
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertTrue(discovery.is_fresh(report, 30))

    def test_parse_error_never_echoes_unknown_output(self):
        with mock.patch.object(discovery, "run_command", return_value=("success", b"SECRET")):
            report = discovery.collect_network_state()
        self.assertTrue(all(v["status"] == ("unsupported" if name in ("frr-version", "frr-daemons") else "error") and "data" not in v for name, v in report["observations"].items()))
        self.assertNotIn("SECRET", json.dumps(report))

    def test_freshness_rejects_stale_future_naive_and_invalid_timestamps(self):
        now = datetime.now(timezone.utc)
        for stamp in ((now - timedelta(seconds=31)).isoformat(), (now + timedelta(seconds=1)).isoformat(), "2026-01-01T00:00:00", "invalid"):
            self.assertFalse(discovery.is_fresh({"completedAt": stamp}, 30, now))
        self.assertFalse(discovery.is_fresh({}, 30, now))


class FRRDiscoveryTests(unittest.TestCase):
    # Shapes adapted from official FRR tagged regression expectations; addresses
    # replaced by documentation ranges. Upstream expectations are partial JSON
    # comparisons, not complete captured device replies.
    # https://github.com/FRRouting/frr/blob/frr-8.5.6/tests/topotests/bfd_topo1/r1/bgp_summary.json
    # https://github.com/FRRouting/frr/blob/frr-10.2.1/tests/topotests/bgp_features/r1/bgp_summary.json
    # https://github.com/FRRouting/frr/blob/frr-10.2.1/tests/topotests/bgp_features/r1/show_bgp.json
    # https://github.com/FRRouting/frr/blob/frr-10.2.1/tests/topotests/bgp_nexthop_ipv6/r1/show_bgp_ipv6_step1.json
    # https://github.com/FRRouting/frr/blob/frr-10.2.1/tests/topotests/bfd_topo1/r1/peers.json
    # Boolean flag omission and text commands verified against the same tag's
    # bgpd/bgp_route.c, lib/command.c and vtysh/vtysh.c (show_daemons).
    SUMMARY_8 = {"ipv4Unicast": {"as": 64512, "peers": {"192.0.2.2": {"remoteAs": 64513, "state": "Established"}}}}
    SUMMARY_10 = {"ipv4Unicast": {"as": 64512, "routerId": "192.0.2.1", "peers": {"192.0.2.2": {"remoteAs": 64513, "state": "Established", "pfxRcd": 7, "pfxSnt": 3}}}}
    RIB_10 = {"routerId": "192.0.2.1", "localAS": 64512, "routes": {"198.51.100.0/24": [
        {"valid": True, "bestpath": True, "peerId": "192.0.2.2", "nexthops": [{"ip": "192.0.2.2", "afi": "ipv4", "used": True}]},
        {"valid": True, "peerId": "192.0.2.3", "nexthops": [{"ip": "192.0.2.3", "afi": "ipv4", "used": True}]}]}}

    def parse(self, name, value):
        return discovery.normalize_frr(name, json.dumps(value).encode())

    def test_fixed_frr_command_allowlist_is_read_only(self):
        expected = {"frr-version": "show version", "frr-daemons": "show daemons", "frr-bgp-summary": "show bgp summary json", "frr-routes4": "show bgp ipv4 unicast json", "frr-routes6": "show bgp ipv6 unicast json", "frr-bfd": "show bfd peers json"}
        for name, command in expected.items():
            self.assertEqual(discovery.COMMANDS[name], ("vtysh", "-c", command))
        with mock.patch.object(discovery, "_capture") as capture:
            for command in ("configure terminal", "clear bgp *", "frr-show running-config"):
                with self.assertRaises(ValueError): discovery.run_command(command)
            capture.assert_not_called()

    def test_version_uses_source_verified_text_grammar_without_host_or_build_details(self):
        for version in ("8.5.6", "10.2.1", "10.2.1_git"):
            raw = f"FRRouting {version} (private-host) on Linux(private-kernel).\nconfigured with: private-path\n".encode()
            self.assertEqual(discovery.normalize_frr("frr-version", raw), [{"version": version}])
        with self.assertRaises(discovery.UnsupportedObservation): discovery.normalize_frr("frr-version", b"different vendor private raw reply")

    def test_daemons_are_connected_clients_not_process_liveness_or_installation(self):
        self.assertEqual(discovery.normalize_frr("frr-daemons", b" zebra bgpd bfdd\n"), [{"name": "zebra", "state": "connected"}, {"name": "bgpd", "state": "connected"}, {"name": "bfdd", "state": "connected"}])
        self.assertEqual(discovery.normalize_frr("frr-daemons", b"\n"), [])
        with self.assertRaises(discovery.UnsupportedObservation): discovery.normalize_frr("frr-daemons", b"secret arbitrary-output")

    def test_versioned_summary_shapes_keep_absent_counters_unknown(self):
        old = self.parse("frr-bgp-summary", self.SUMMARY_8)[0]
        new = self.parse("frr-bgp-summary", self.SUMMARY_10)[0]
        self.assertNotIn("prefixesReceived", old)
        self.assertNotIn("routerId", old)
        self.assertEqual(new["prefixesReceived"], 7)
        self.assertEqual(new["prefixesSent"], 3)
        self.assertEqual(new["localAs"], 64512)
        self.assertEqual(new["remoteAs"], 64513)

    def test_all_six_bgp_states_remain_distinct(self):
        for state in ("Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"):
            data = json.loads(json.dumps(self.SUMMARY_10))
            data["ipv4Unicast"]["peers"]["192.0.2.2"]["state"] = state
            self.assertEqual(self.parse("frr-bgp-summary", data)[0]["state"], state)

    def test_established_zero_received_prefixes_is_not_nonzero_or_connectivity(self):
        data = json.loads(json.dumps(self.SUMMARY_10))
        peer = data["ipv4Unicast"]["peers"]["192.0.2.2"]
        peer["pfxRcd"] = 0
        row = self.parse("frr-bgp-summary", data)[0]
        self.assertEqual(row["state"], "Established")
        self.assertEqual(row["prefixesReceived"], 0)
        self.assertNotIn("reachable", row)
        peer["pfxRcd"] = 4
        self.assertEqual(self.parse("frr-bgp-summary", data)[0]["prefixesReceived"], 4)

    def test_summary_ipv6_and_empty_peer_set(self):
        data = {"ipv6Unicast": {"as": 64512, "peers": {"2001:db8::2": {"remoteAs": 64513, "state": "Established"}}}}
        self.assertEqual(self.parse("frr-bgp-summary", data)[0]["addressFamily"], "ipv6")
        data["ipv6Unicast"]["peers"] = {}
        self.assertEqual(self.parse("frr-bgp-summary", data), [])
        self.assertEqual(self.parse("frr-bgp-summary", {}), [])

    def test_bestpath_is_distinct_from_other_candidates_and_kernel_fib(self):
        rows = self.parse("frr-routes4", self.RIB_10)
        self.assertEqual([r["bestPath"] for r in rows], [True, False])
        self.assertEqual([r["valid"] for r in rows], [True, True])
        self.assertEqual(rows[0]["nextHops"], ["192.0.2.2"])
        self.assertTrue(all("installed" not in r and "reachable" not in r for r in rows))
        # A separate Linux observation can be successfully empty while BGP selects
        # a path; no implicit merge converts this into installed state.
        self.assertEqual(discovery.normalize_linux("routes4", b"[]"), [])

    def test_ipv6_rib_and_false_omission_follow_official_source(self):
        data = {"routes": {"2001:db8::/64": [{"nexthops": [{"ip": "2001:db8::2", "afi": "ipv6", "used": True}]}]}}
        row = self.parse("frr-routes6", data)[0]
        self.assertEqual(row, {"addressFamily": "ipv6", "prefix": "2001:db8::/64", "valid": False, "bestPath": False, "nextHops": ["2001:db8::2"]})
        with self.assertRaises(ValueError): self.parse("frr-routes4", data)

    def test_bfd_down_is_a_state_not_a_collector_failure(self):
        rows = self.parse("frr-bfd", [{"peer": "192.0.2.2", "status": "down", "remote-receive-interval": 1000}])
        self.assertEqual(rows, [{"peer": "192.0.2.2", "state": "down"}])
        self.assertEqual(self.parse("frr-bfd", []), [])

    def test_unknown_variants_and_invalid_values_fail_closed(self):
        for name, value in (("frr-bgp-summary", {"default": self.SUMMARY_10}), ("frr-routes4", {"newRoutes": {}}), ("frr-bfd", {"peers": []})):
            with self.assertRaises(discovery.UnsupportedObservation): self.parse(name, value)
        data = json.loads(json.dumps(self.SUMMARY_10))
        data["ipv4Unicast"]["peers"]["192.0.2.2"]["pfxRcd"] = True
        with self.assertRaises(ValueError): self.parse("frr-bgp-summary", data)
        data = json.loads(json.dumps(self.RIB_10))
        data["routes"]["198.51.100.0/24"][0]["bestpath"] = {"overall": True}
        with self.assertRaises(ValueError): self.parse("frr-routes4", data)

    def test_secret_unknown_fields_never_enter_normalized_frr_results(self):
        data = json.loads(json.dumps(self.SUMMARY_10))
        data["ipv4Unicast"]["peers"]["192.0.2.2"]["password"] = "FRR_SECRET"
        self.assertNotIn("FRR_SECRET", json.dumps(self.parse("frr-bgp-summary", data)))
        data = json.loads(json.dumps(self.RIB_10))
        data["routes"]["198.51.100.0/24"][0]["secret"] = "FRR_SECRET"
        self.assertNotIn("FRR_SECRET", json.dumps(self.parse("frr-routes4", data)))

    def test_absent_bgpd_and_bfdd_are_unavailable_not_not_installed(self):
        calls = []
        def command(name, **kwargs):
            calls.append(name)
            if name == "frr-daemons": return "success", b" zebra\n"
            if name.startswith("frr-"): return "unavailable", b""
            return "success", b"[]" if not name.startswith("wg-") else b""
        with mock.patch.object(discovery, "run_command", side_effect=command): report = discovery.collect_network_state()
        self.assertEqual(report["observations"]["frr-daemons"]["data"], [{"name": "zebra", "state": "connected"}])
        for name in ("frr-bgp-summary", "frr-routes4", "frr-routes6", "frr-bfd"):
            self.assertEqual(report["observations"][name]["status"], "unavailable")
            self.assertNotIn(name, calls)

    def test_missing_vtysh_is_not_installed_and_never_launches(self):
        with mock.patch.object(discovery.platform, "system", return_value="Linux"), mock.patch.object(discovery.shutil, "which", return_value=None), mock.patch.object(discovery, "_capture") as capture:
            self.assertEqual(discovery.run_command("frr-version"), ("not-installed", b""))
            capture.assert_not_called()

    def test_total_budget_marks_unattempted_queries_timeout(self):
        with mock.patch.object(discovery.time, "monotonic", side_effect=[0, 0] + [5] * len(discovery.COMMANDS)), mock.patch.object(discovery, "run_command", return_value=("success", b"[]")) as command:
            report = discovery.collect_network_state(total_timeout=1)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(report["observations"]["links"]["status"], "success")
        self.assertTrue(all(r["status"] == "timeout" for key, r in report["observations"].items() if key != "links"))

    def test_frr_parse_failures_never_forward_raw_secret_or_diagnostics(self):
        def command(name, **kwargs):
            return ("success", b"FRR_SECRET") if name.startswith("frr-") else ("unavailable", b"ignored")
        with mock.patch.object(discovery, "run_command", side_effect=command): report = discovery.collect_network_state()
        self.assertTrue(all(o["status"] in ("unsupported", "error") for k, o in report["observations"].items() if k.startswith("frr-")))
        self.assertNotIn("FRR_SECRET", json.dumps(report))

    def test_total_budget_parameters_reject_unbounded_or_non_numeric_values(self):
        with mock.patch.object(discovery, "run_command") as command:
            for value in (0, -1, 121, True, float("inf"), float("nan"), "30"):
                with self.assertRaises(ValueError): discovery.collect_network_state(total_timeout=value)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
