#!/usr/bin/env python3
"""Opt-in, read-only Linux/WireGuard discovery. No configuration writer.

Only named fixed commands can cross the process boundary. Reports omit raw output,
errors and unrecognized fields. Importing this module never starts collection.
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
    "frr-version": ("vtysh", "-c", "show version"),
    "frr-daemons": ("vtysh", "-c", "show daemons"),
    "frr-bgp-summary": ("vtysh", "-c", "show bgp summary json"),
    "frr-routes4": ("vtysh", "-c", "show bgp ipv4 unicast json"),
    "frr-routes6": ("vtysh", "-c", "show bgp ipv6 unicast json"),
    "frr-bfd": ("vtysh", "-c", "show bfd peers json"),
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
    if name not in ("links", "addresses", "routes4", "routes6", "rules4", "rules6"):
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


# Contract checked against FRRouting tags frr-8.5.6 and frr-10.2.1, not a claim
# of compatibility with every FRR release. Source URLs accompany the tests.
_BGP_STATES = {"Idle", "Connect", "Active", "OpenSent", "OpenConfirm", "Established"}
_DAEMONS = {"zebra", "bgpd", "bfdd", "ospfd", "ospf6d", "ripd", "ripngd", "isisd",
            "pimd", "pim6d", "ldpd", "nhrpd", "eigrpd", "babeld", "sharpd", "staticd",
            "pbrd", "vrrpd", "fabricd", "pathd", "mgmtd", "watchfrr"}


def _frr_map(value):
    if not isinstance(value, dict):
        raise UnsupportedObservation("unsupported FRR object layout")
    return value


def _frr_rows(value):
    if not isinstance(value, list) or len(value) > 10000:
        raise UnsupportedObservation("unsupported FRR row layout")
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ValueError("invalid FRR boolean")
    return value


def normalize_frr(name, raw):
    """Project supported FRR replies onto a secret-free observation schema.

    BGP bestpath is BGP's selection flag, never proof of kernel installation or
    reachability. show version / show daemons have no JSON form in FRR 10.2.1.
    Their deliberately narrow text grammars extract only release and client names.
    """
    if name not in {"frr-version", "frr-daemons", "frr-bgp-summary", "frr-routes4", "frr-routes6", "frr-bfd"}:
        raise ValueError("unknown FRR collector")
    text = raw.decode("utf-8", errors="strict") if isinstance(raw, bytes) else raw
    if name == "frr-version":
        first = text.splitlines()[0] if text.splitlines() else ""
        match = re.match(r"^FRRouting ([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+_][A-Za-z0-9_.-]+)?) \(", first)
        if not match or len(match[1]) > 64:
            raise UnsupportedObservation("unsupported FRR version reply")
        return [{"version": match[1]}]
    if name == "frr-daemons":
        names = text.split()
        if len(names) > len(_DAEMONS) or len(set(names)) != len(names) or any(n not in _DAEMONS for n in names):
            raise UnsupportedObservation("unsupported FRR daemon reply")
        return [{"name": n, "state": "connected"} for n in names]
    data = json.loads(text)
    if name == "frr-bgp-summary":
        root = _frr_map(data)
        if any(k not in ("ipv4Unicast", "ipv6Unicast") for k in root):
            raise UnsupportedObservation("unsupported FRR address family")
        result = []
        for key, group in root.items():
            group = _frr_map(group)
            if "as" not in group or "peers" not in group:
                raise UnsupportedObservation("unsupported FRR summary layout")
            peers = _frr_map(group["peers"])
            if len(peers) > 10000:
                raise ValueError("too many FRR peers")
            for peer, info in peers.items():
                info = _frr_map(info)
                state = info.get("state")
                if not isinstance(state, str) or state not in _BGP_STATES:
                    raise UnsupportedObservation("unsupported BGP state")
                row = {"addressFamily": "ipv4" if key == "ipv4Unicast" else "ipv6",
                       "localAs": _integer(group["as"]), "peer": _ip(peer),
                       "remoteAs": _integer(info["remoteAs"]), "state": state}
                if "routerId" in group:
                    row["routerId"] = _ip(group["routerId"])
                    if ipaddress.ip_address(row["routerId"]).version != 4:
                        raise ValueError("invalid router ID")
                for field, output in (("pfxRcd", "prefixesReceived"), ("pfxSnt", "prefixesSent")):
                    if field in info:
                        row[output] = _integer(info[field])
                result.append(row)
        return result
    if name in ("frr-routes4", "frr-routes6"):
        root = _frr_map(data)
        if "routes" not in root:
            raise UnsupportedObservation("unsupported FRR RIB layout")
        routes = _frr_map(root["routes"])
        if len(routes) > 10000:
            raise ValueError("too many FRR prefixes")
        result = []
        family = 4 if name == "frr-routes4" else 6
        for prefix, paths in routes.items():
            canonical = _prefix(prefix)
            if ipaddress.ip_network(canonical).version != family:
                raise ValueError("FRR route family mismatch")
            for path in _frr_rows(paths):
                path = _frr_map(path)
                # FRR bgp_route.c emits true flags, omitting them for false.
                row = {"addressFamily": "ipv4" if family == 4 else "ipv6", "prefix": canonical,
                       "valid": _boolean(path.get("valid", False)),
                       "bestPath": _boolean(path.get("bestpath", False)),
                       "nextHops": []}
                if "nexthops" not in path:
                    raise UnsupportedObservation("unsupported FRR nexthop layout")
                for hop in _frr_rows(path["nexthops"]):
                    hop = _frr_map(hop)
                    row["nextHops"].append(_ip(hop["ip"]))
                if "peerId" in path and path["peerId"] != "(unspec)":
                    row["peerId"] = _ip(path["peerId"])
                result.append(row)
                if len(result) > 10000:
                    raise ValueError("too many FRR paths")
        return result
    result = []
    for peer in _frr_rows(data):
        peer = _frr_map(peer)
        state = peer.get("status")
        if not isinstance(state, str) or state not in {"up", "down", "init", "admin-down"}:
            raise UnsupportedObservation("unsupported BFD state")
        row = {"peer": _ip(peer["peer"]), "state": state}
        for field in ("local", "interface", "vrf"):
            if field in peer:
                row[field] = _ip(peer[field]) if field == "local" else _name(peer[field])
        result.append(row)
    return result


def collect_network_state(*, timeout=DEFAULT_TIMEOUT, total_timeout=30.0, output_limit=DEFAULT_OUTPUT_LIMIT):
    """Explicit opt-in collection, with both per-command and total run deadlines.

    Budget exhaustion is a timeout observation for each unattempted query. JSON
    parsing also consumes the total budget but is bounded by the capture byte cap.
    Daemon availability describes vtysh connectivity, not installed packages.
    """
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise ValueError("invalid command timeout")
    if type(total_timeout) not in (int, float) or not 0 < total_timeout <= 120:
        raise ValueError("invalid collection timeout")
    if type(output_limit) is not int or not 0 < output_limit <= 16 * 1024 * 1024:
        raise ValueError("invalid output limit")
    deadline = time.monotonic() + total_timeout
    report = {"schemaVersion": 1, "startedAt": utc_now(), "observations": {}, "capabilities": {}}
    connected_daemons = None
    for name in COMMANDS:
        started = utc_now()
        remaining = deadline - time.monotonic()
        needed_daemon = "bgpd" if name in ("frr-bgp-summary", "frr-routes4", "frr-routes6") else "bfdd" if name == "frr-bfd" else None
        if remaining <= 0:
            status, raw = "timeout", b""
        elif needed_daemon and connected_daemons is not None and needed_daemon not in connected_daemons:
            status, raw = "unavailable", b""
        else:
            status, raw = run_command(name, timeout=min(timeout, remaining), output_limit=output_limit)
        data = None
        if status == "success":
            try:
                if name.startswith("frr-"):
                    data = normalize_frr(name, raw)
                elif name.startswith("wg-"):
                    data = normalize_wireguard(name[3:], raw)
                else:
                    data = normalize_linux(name, raw)
                if name == "frr-daemons":
                    connected_daemons = {d["name"] for d in data}
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
