#!/usr/bin/env python3
"""Read-only guest inventory; never chooses or enables a persistence backend."""
import argparse
import json
import os
import platform
import re
import selectors
import subprocess
import time
from pathlib import Path


COMMANDS = {
    "iproute2": ("ip", "-Version"),
    "wireguard": ("wg", "--version"),
    "networkManager": ("nmcli", "--version"),
    "systemd": ("systemctl", "--version"),
    "networkManagerState": ("systemctl", "is-active", "NetworkManager.service"),
    "networkdState": ("systemctl", "is-active", "systemd-networkd.service"),
    "agentState": ("systemctl", "is-active", "heliopause-agent.service"),
}
VERSION_PATTERNS = {
    "iproute2": r"ip utility, iproute2-([0-9][0-9A-Za-z.+_-]{0,63})(?:,|\s|$)",
    "wireguard": r"wireguard-tools v([0-9][0-9A-Za-z.+_-]{0,63})(?:\s|$)",
    "networkManager": r"nmcli tool, version ([0-9][0-9A-Za-z.+_-]{0,63})(?:\s|$)",
    "systemd": r"systemd ([0-9][0-9A-Za-z.+_-]{0,63})(?:\s|$)",
}
STATES = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance"}


def read_small(path):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(4097)
        return data.decode("utf-8") if len(data) <= 4096 else None
    except (OSError, UnicodeError):
        return None


def probe(argv):
    # Fixed argv only. Do not inherit NM logging/debug settings or use a shell.
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    data = bytearray()
                    deadline = time.monotonic() + 3
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            child.kill()
                            return "timeout", None
                        chunk = os.read(child.stdout.fileno(), 4097 - len(data))
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > 4096:
                            child.kill()
                            return "invalid-output", None
                    try:
                        code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        child.kill()
                        return "timeout", None
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait()
    except FileNotFoundError:
        return "unavailable", None
    except OSError:
        return "unavailable", None
    try:
        return str(code), data.decode("utf-8").strip()
    except UnicodeError:
        return "invalid-output", None


def collect():
    report = {"schemaVersion": 1, "kind": "heliopause-vm-readonly-inventory",
              "hostRebootVerified": False, "backendSelected": None,
              "architecture": platform.machine(), "os": {}, "bootId": None,
              "kernel": platform.release(), "probes": {}, "blockers": []}
    if platform.system() != "Linux":
        report["blockers"] = ["linux-guest-required"]
        return report
    release = read_small("/etc/os-release") or ""
    for key in ("ID", "VERSION_ID"):
        match = re.search(r"^" + key + r'="?([a-zA-Z0-9._-]{1,64})"?$', release, re.M)
        report["os"][key] = match.group(1) if match else None
    if report["os"].get("ID") != "rocky" or not re.fullmatch(
            r"10(?:\.[0-9]+)*", report["os"].get("VERSION_ID") or ""):
        report["blockers"].append("rocky-10-guest-required")
    boot = (read_small("/proc/sys/kernel/random/boot_id") or "").strip()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
        report["bootId"] = boot
    else:
        report["blockers"].append("boot-id-unavailable")
    for name, argv in COMMANDS.items():
        status, value = probe(argv)
        if name in VERSION_PATTERNS:
            match = re.match(VERSION_PATTERNS[name], value or "") if status == "0" else None
            entry = {"status": "observed" if match else "unknown",
                     "version": match.group(1) if match else None}
        else:
            # is-active legitimately exits 3 for an inactive service. Other errors
            # must not become evidence of inactivity or another manager's ownership.
            valid = (status == "0" and value in {"active", "reloading"}) or (
                status == "3" and value in STATES - {"active", "reloading"})
            state = value if valid else None
            entry = {"status": "observed" if state else "unknown", "state": state}
        if entry["status"] == "unknown":
            entry["reason"] = status if not status.lstrip("-").isdigit() else "unrecognized-result"
            report["blockers"].append(name + "-unknown")
        report["probes"][name] = entry
    # Active NM is only one prerequisite. Device ownership, paths, unit ordering,
    # isolated hypervisor and actual reboot still require separate evidence.
    report["blockers"].extend(["device-and-route-ownership-review-required",
                               "isolated-vm-and-console-evidence-required",
                               "persistent-backend-not-implemented",
                               "actual-vm-reboot-not-verified"])
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect", action="store_true", required=True,
                        help="print local read-only inventory JSON; no remote host access")
    parser.parse_args(argv)
    report = collect()
    print(json.dumps(report, sort_keys=True, indent=2))
    # Inventory is not a readiness or successful boot check. Blockers are explicit.
    return 2 if report["blockers"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
