#!/usr/bin/env python3
"""Opt-in, read-only Linux/WireGuard discovery. No heartbeat or configuration writer.

Only named fixed commands can cross the process boundary. Reports omit raw output,
errors and unrecognized fields. This module is not installed by the agent package yet.
"""
import base64
from datetime import datetime, timezone
import ipaddress
import json
import os
import platform
import re
import selectors
import shutil
import subprocess
import time

COMMANDS = {
    "links": ("ip", "-j", "link", "show"),
    "addresses": ("ip", "-j", "address", "show"),
    "routes4": ("ip", "-j", "-4", "route", "show", "table", "all"),
    "routes6": ("ip", "-j", "-6", "route", "show", "table", "all"),
    "rules4": ("ip", "-j", "-4", "rule", "show"),
    "rules6": ("ip", "-j", "-6", "rule", "show"),
    **{f"wg-{field}": ("wg", "show", "all", field) for field in (
        "public-key", "listen-port", "peers", "endpoints", "allowed-ips",
        "latest-handshakes", "transfer", "persistent-keepalive")},
}
SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULT_TIMEOUT = 3.0
DEFAULT_OUTPUT_LIMIT = 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def is_fresh(observation, max_age_seconds, now=None):
    """Freshness is local report age, not proof that kernel state is unchanged."""
    try:
        stamp = datetime.fromisoformat(observation["completedAt"])
        if stamp.tzinfo is None or not isinstance(max_age_seconds, (int, float)) or max_age_seconds < 0:
            return False
        age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
        return 0 <= age <= max_age_seconds
    except (KeyError, TypeError, ValueError):
        return False


def _capture(argv, timeout, output_limit):
    """Internal bounded process primitive; callers must validate argv before use.

    Drain both pipes while the process runs rather than buffering communicate().
    The limit counts stderr too; errors never enter a public observation.
    """
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, shell=False, env={"PATH": SYSTEM_PATH, "LC_ALL": "C"})
    output = bytearray()
    consumed = 0
    stderr_seen = False
    deadline = time.monotonic() + timeout
    status = "success"
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    break
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, min(65536, output_limit - consumed + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    consumed += len(chunk)
                    if consumed > output_limit:
                        status = "output-limit"
                        break
                    if key.fileobj is proc.stdout:
                        output.extend(chunk)
                    else:
                        stderr_seen = True
                if status != "success":
                    break
            if status == "success":
                try:
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    status = "timeout"
            if status == "success" and (proc.returncode != 0 or stderr_seen):
                status = "unavailable"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    return status, bytes(output) if status == "success" else b""


def run_command(name, timeout=DEFAULT_TIMEOUT, output_limit=DEFAULT_OUTPUT_LIMIT):
    """No caller-supplied arguments or executable paths are accepted."""
    if not isinstance(name, str) or name not in COMMANDS:
        raise ValueError("unknown discovery command")
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise ValueError("timeout must be positive and no greater than 30 seconds")
    if type(output_limit) is not int or not 0 < output_limit <= 16 * 1024 * 1024:
        raise ValueError("output limit must be a positive bounded byte count")
    if platform.system() != "Linux":
        return "unsupported", b""
    command = COMMANDS[name]
    binary = shutil.which(command[0], path=SYSTEM_PATH)
    if binary is None:
        return "not-installed", b""
    try:
        return _capture((binary, *command[1:]), timeout, output_limit)
    except FileNotFoundError:
        return "not-installed", b""
    except OSError:
        return "unavailable", b""


def _integer(value, maximum=4294967295):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid integer")
    return value


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.:@-]{1,64}", value):
        raise ValueError("invalid interface name")
    return value


def _label(value):
    if isinstance(value, int) and not isinstance(value, bool):
        return _integer(value)
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", value):
        raise ValueError("invalid label")
    return value


def _ip(value):
    if not isinstance(value, str):
        raise ValueError("invalid address")
    return str(ipaddress.ip_address(value))


def _prefix(value):
    if not isinstance(value, str):
        raise ValueError("invalid prefix")
    return str(ipaddress.ip_network(value, strict=False))


class UnsupportedObservation(ValueError):
    """Known kernel structures that this schema cannot represent without losing meaning."""


def normalize_linux(name, raw):
    """Normalize known iproute2 JSON fields; unknown fields are never copied."""
    if name not in COMMANDS or name.startswith("wg-"):
        raise ValueError("unknown Linux collector")
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError("invalid iproute2 rows")
    normalized = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid iproute2 row")
        result = {}
        if name in ("links", "addresses"):
            result = {"ifindex": _integer(row["ifindex"]), "ifname": _name(row["ifname"])}
            for field in ("mtu", "link_index"):
                if field in row:
                    result[field] = _integer(row[field])
            if "master" in row:
                result["master"] = _integer(row["master"]) if type(row["master"]) is int else _name(row["master"])
            if "operstate" in row:
                result["operstate"] = _label(row["operstate"])
            if "flags" in row:
                if not isinstance(row["flags"], list) or len(row["flags"]) > 64:
                    raise ValueError("invalid flags")
                result["flags"] = [_label(v) for v in row["flags"]]
            if name == "addresses":
                addresses = row.get("addr_info", [])
                if not isinstance(addresses, list) or len(addresses) > 10000:
                    raise ValueError("invalid addresses")
                result["addresses"] = []
                for address in addresses:
                    if not isinstance(address, dict) or address.get("family") not in ("inet", "inet6"):
                        raise ValueError("invalid address family")
                    ip = ipaddress.ip_address(_ip(address["local"]))
                    if ip.version != (4 if address["family"] == "inet" else 6):
                        raise ValueError("address family mismatch")
                    entry = {"family": address["family"], "local": str(ip), "prefixlen": _integer(address["prefixlen"], ip.max_prefixlen)}
                    if "scope" in address:
                        entry["scope"] = _label(address["scope"])
                    result["addresses"].append(entry)
        else:
            if any(field in row for field in ("multipath", "nexthops", "via", "nhid", "encap")):
                raise UnsupportedObservation("route structure unsupported")
            if name.startswith("rules") and any(field in row for field in ("fwmark", "fwmask", "tos", "ipproto", "sport", "dport", "uidrange", "suppress_prefixlength", "suppress_ifgroup", "l3mdev", "not", "goto", "tun_id")):
                raise UnsupportedObservation("rule selector unsupported")
            if name.startswith("routes") and "dst" not in row:
                raise ValueError("route destination missing")
            if name.startswith("rules") and ("priority" not in row or not any(f in row for f in ("src", "dst", "table", "action"))):
                raise ValueError("rule identity missing")
            fields = ({"dst": lambda v: "default" if v == "default" else _prefix(v), "gateway": _ip, "dev": _name, "protocol": _label,
                       "metric": _integer, "table": _label, "type": _label, "prefsrc": _ip, "scope": _label}
                      if name.startswith("routes") else
                      {"priority": _integer, "src": lambda v: "all" if v == "all" else _prefix(v), "dst": lambda v: "all" if v == "all" else _prefix(v), "table": _label,
                       "iif": _name, "oif": _name, "action": _label, "protocol": _label})
            if name not in ("routes4", "routes6", "rules4", "rules6"):
                raise ValueError("unknown Linux collector")
            for field, parser in fields.items():
                if field in row:
                    result[field] = parser(row[field])
            expected_version = 4 if name.endswith("4") else 6
            for field in ("src", "dst", "gateway", "prefsrc"):
                value = result.get(field)
                if value is not None and value not in ("default", "all"):
                    actual = ipaddress.ip_network(value, strict=False).version
                    if actual != expected_version:
                        raise ValueError("route or rule address family mismatch")
            if not result:
                raise ValueError("empty route or rule observation")
        normalized.append(result)
    return normalized


def _key(value):
    try:
        if len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError("invalid public key")
    except (ValueError, TypeError):
        raise ValueError("invalid public key") from None
    return value


def _decimal(value):
    if not re.fullmatch(r"[0-9]{1,20}", value):
        raise ValueError("invalid counter")
    return _integer(int(value), 18446744073709551615)


def _endpoint(value):
    if value == "(none)":
        return None
    host, port = value.rsplit(":", 1)
    ip = _ip(host.strip("[]"))
    return {"address": ip, "port": _integer(_decimal(port), 65535)}


def normalize_wireguard(field, raw):
    """Public subcommands only; no dump/showconf or key material is requested."""
    if "wg-" + field not in COMMANDS:
        raise ValueError("unknown WireGuard collector")
    result = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        columns = line.split("\t")
        expected = 4 if field == "transfer" else 2 if field in ("public-key", "listen-port", "peers") else 3
        if len(columns) != expected:
            raise ValueError("invalid WireGuard row")
        record = {"interface": _name(columns[0])}
        if field == "public-key":
            record["publicKey"] = None if columns[1] == "(none)" else _key(columns[1])
        elif field == "listen-port":
            record["listenPort"] = _integer(_decimal(columns[1]), 65535)
        else:
            record["peerPublicKey"] = _key(columns[1])
            if field == "endpoints": record["endpoint"] = _endpoint(columns[2])
            elif field == "allowed-ips": record["allowedIPs"] = [] if columns[2] == "(none)" else [_prefix(v) for v in columns[2].split(" ")]
            elif field == "latest-handshakes": record["latestHandshake"] = _decimal(columns[2])
            elif field == "transfer": record.update(rxBytes=_decimal(columns[2]), txBytes=_decimal(columns[3]))
            elif field == "persistent-keepalive": record["persistentKeepalive"] = 0 if columns[2] == "off" else _integer(_decimal(columns[2]), 65535)
            elif field != "peers": raise ValueError("unknown WireGuard collector")
        result.append(record)
    return result


def collect_network_state():
    """Explicit opt-in collection; importing this module performs no discovery."""
    report = {"schemaVersion": 1, "startedAt": utc_now(), "observations": {}, "capabilities": {}}
    for name in COMMANDS:
        started = utc_now()
        status, raw = run_command(name)
        data = None
        if status == "success":
            try:
                data = normalize_wireguard(name[3:], raw) if name.startswith("wg-") else normalize_linux(name, raw)
            except UnsupportedObservation:
                status = "unsupported"
            except (ValueError, TypeError, KeyError, UnicodeError):
                status = "error"
        observation = {"status": status, "startedAt": started, "completedAt": utc_now()}
        if status == "success":
            observation["data"] = data
        report["observations"][name] = observation
        report["capabilities"][name] = {"available": status == "success", "status": status}
    report["completedAt"] = utc_now()
    return report


if __name__ == "__main__":
    print(json.dumps(collect_network_state(), sort_keys=True))
