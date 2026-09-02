#!/usr/bin/env python3
"""heliopause pull agent — heartbeats out to its gateway's relay and reports what the kernel holds.

This replaces the push agent (`heliopause-agent.py`) rather than extending it. The difference is
the direction of the connection, and everything else follows from that:

- **Nothing listens.** The push agent ran an authenticated HTTP server on every firewall host.
  That is an inbound attack surface on the one machine whose compromise is worth the most, and it
  had to be reachable by the control plane, so it could not be firewalled off either. This process
  opens sockets and never accepts them.
- **The heartbeat is the confirm.** Under push, the control plane had to verify reachability and
  send a confirm — but the thing it was testing was the path to itself, and if that path broke the
  confirm could not arrive to say so. Here a successful heartbeat *is* the evidence the path
  survived, so rollback does not depend on anything outside this host still working.
- **Mutual TLS, verified both ways.** The relay learns which host is reporting; this agent learns
  it is not taking a ruleset from something impersonating its gateway. The second direction is the
  one that matters — whoever the agent believes is its relay gets to set the firewall.

## Applying, and the three things that keep it survivable

**1. The artifact is nft JSON, and it is checked structurally.** The previous agent tried to
validate nft *text* with line-anchored regexes. That was measured against the real code and let
all of these through:

    table inet heliopause {}
    add rule ip filter INPUT drop              -- never examined: the check only inspected
                                                  statements starting with `table`
    table inet heliopause {} ; flush ruleset   -- `;` moves it off the line start, so `^\\s*flush`
                                                  never matches
    table inet heliopause {} ; include "/tmp/evil.nft"

`nft -c` is not a substitute — check mode was measured to accept a cross-table write and exit 0.
It validates syntax, not authority. With JSON the question stops being "can I out-parse nft" and
becomes "does every element name my family and my table", which is a field comparison.

**2. Anything outside our table is diffed after the fact.** Structure checking is a prediction
about what nft will do; the diff is an observation of what it did. The full ruleset is snapshotted
before and after, our own table is filtered out of both, and if the remainder moved at all the
generation is refused. This is the backstop for a bug in check 1 rather than the first line.

**3. Rollback is armed before the apply is trusted.** A timer starts at apply and is cancelled
only by a *subsequent* successful heartbeat. If the new ruleset severed the path to the relay, no
heartbeat arrives, the timer fires, and the previous table is restored — without needing the
control plane, the gateway, or anything else off this host to still be working.

## The workload half (schema 2)

On the one node the manager designates, an artifact also carries CiliumNetworkPolicy objects. That
layer exists because a packet to a pod or a ClusterIP is resolved in eBPF and **never reaches a
netfilter hook** — measured twice, from both sides (appendix A V15, V31). No nftables rule can
govern it, so for those policies this is the only enforcement point and there is nothing behind a
failure here.

Four things follow, and they are why this is not simply "also run kubectl":

**The two halves are reported separately.** They genuinely disagree: the ruleset confirms while the
`kubectl apply` fails, or the reverse. A single state field would have to pick one, and either
choice hides a half-enforced generation behind a clean status.

**A Kubernetes write returning 0 is not evidence the policy is in force.** It proves the API server
accepted the documents. Cilium will happily accept a policy that selects nothing. So the objects are
read back by name and exact content (`mustExist`) the way the nftables half re-reads the table, and a
missing or changed one rolls the half back.

**Its rollback timer is its own, and longer.** A bad ruleset severs SSH and the relay, so 60s there
bounds how long the host is unreachable. A bad CiliumNetworkPolicy breaks app traffic while node
access stays up, and Cilium converges *after* the API server returns — identity cache and eBPF maps
settle on their own schedule. Reusing the host figure would revert policy that was on its way to
healthy, which then reads as "the policy was bad".

**Rollback is identity-bound.** Before apply, an existing object must already carry heliopause's
managed-by/cluster/name identity; anything else is an external object and is never overwritten. The
agent snapshots its own prior object and records the apply generation. Rollback restores that prior
object with resourceVersion concurrency, or deletes a newly created object with API-server-enforced
UID/resourceVersion preconditions. A controller replacement under the same name is left untouched.

## Operating

Python 3 standard library only, plus the `nft` binary — and `kubectl` on the designated applier
only. Runs as root under systemd; `nft` needs it, and nothing here needs anything else.

    HELIOPAUSE_RELAY_URL     https://gw.dev.internal:8443   (required)
    HELIOPAUSE_TARGET        independently pinned relay/VPC name       (required)
    HELIOPAUSE_HOST_ID       name this host reports as; defaults to the system hostname
    HELIOPAUSE_TABLE         nft table to manage                     (default heliopause)
    HELIOPAUSE_CA_FILE       trust anchor for the relay              (required)
    HELIOPAUSE_CERT_FILE     this agent's client certificate         (required)
    HELIOPAUSE_KEY_FILE      its private key                         (required)
    HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR online manager Ed25519 public keys (required)
    HELIOPAUSE_BREAK_GLASS_KEYS_DIR offline emergency Ed25519 public keys (required)
    HELIOPAUSE_PINS          comma-separated `sha256/<base64>` certificate pins  (optional)
    HELIOPAUSE_INTERVAL_SEC  seconds between heartbeats              (default 15)
    HELIOPAUSE_STATE_FILE    where applied state is remembered       (default /var/lib/...)
    HELIOPAUSE_NFT_BIN       path to nft                             (default /usr/sbin/nft)
    HELIOPAUSE_KUBECTL_BIN   path to kubectl        (default /usr/local/bin/kubectl; applier only)
    HELIOPAUSE_KUBECONFIG    least-privilege kubeconfig (required on the applier; no admin default)
    HELIOPAUSE_K8S_NAMESPACES comma-separated namespaces this applier may manage (required there)
"""

import base64
import collections
import datetime
import hashlib
import http.client
import ipaddress
import json
import math
import os
import random
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

# Must match SCHEMA_VERSION in src/protocol.ts. A mismatch is not a warning: the relay refuses to
# hand work to an agent it cannot be sure will read it the same way.
#
# 4 adds routes to the signed manifest entry. A schema-3 agent validates that entry against an exact
# key set and refuses anything it does not know, so it would reject a routed artifact outright and
# stall the rollout with the reason only in its own journal. The bump moves that sentence to the
# relay's reply, and from there to the fleet view.
#
# 3 requires a signed host envelope. A schema-2 agent trusts hashes a compromised relay can replace.
# 2 added the workload half. A schema-1 agent would ignore `Artifact.workload` and apply only the
# nftables ruleset — enforcing half a generation while confirming cleanly, which is exactly what this
# number exists to prevent. So it was a bump rather than an additive change, and an agent below 2
# receives nothing until it is upgraded.
SCHEMA_VERSION = 5
AGENT_VERSION = "0.6.0-pull-signed-routes"

TABLE_FAMILY = "inet"
TABLE_NAME = os.environ.get("HELIOPAUSE_TABLE", "heliopause")

RELAY_URL = os.environ.get("HELIOPAUSE_RELAY_URL", "")
TARGET = os.environ.get("HELIOPAUSE_TARGET", "")
HOST_ID = os.environ.get("HELIOPAUSE_HOST_ID") or socket.gethostname()
CA_FILE = os.environ.get("HELIOPAUSE_CA_FILE", "")
CERT_FILE = os.environ.get("HELIOPAUSE_CERT_FILE", "")
KEY_FILE = os.environ.get("HELIOPAUSE_KEY_FILE", "")
MANAGER_SIGNING_KEYS_DIR = os.environ.get("HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR", "")
BREAK_GLASS_KEYS_DIR = os.environ.get("HELIOPAUSE_BREAK_GLASS_KEYS_DIR", "")
OPENSSL = os.environ.get("HELIOPAUSE_OPENSSL_BIN", "/usr/bin/openssl")
PINS = [p.strip() for p in os.environ.get("HELIOPAUSE_PINS", "").split(",") if p.strip()]

DEFAULT_INTERVAL_SEC = 15
MIN_INTERVAL_SEC = 1
# An hour. Past that the confirm window derived below would have to be longer than
# `NFT_CONFIRM_MAX_SEC`, so the two settings would contradict each other and the rollback promise
# would be the one that lost.
MAX_INTERVAL_SEC = 3600


def _interval_from_env(raw):
    """Read HELIOPAUSE_INTERVAL_SEC. Returns (seconds, error) and never raises.

    ## Why this does not just call int()

    It did, at module scope, and that put two failures in the wrong place:

      · A non-numeric value raised `ValueError` **during import** — before `main()` runs, so the
        agent died with a traceback instead of the "missing required environment" sentence it has
        for every other misconfiguration. The operator sees a stack trace naming `int()`.
      · `0` or a negative value was accepted. `sleep_interval` then returns immediately and the
        agent heartbeats in a loop as fast as the relay will answer — from every host at once.

    The value is also load-bearing beyond the loop: `NFT_CONFIRM_MIN_SEC` is derived from it, so a
    nonsense interval widens or narrows the window the rollback timer honours.

    Returning the default alongside the error keeps the derived constants below computable. Nothing
    acts on them, because `main()` refuses first — but a module that cannot finish importing cannot
    print a useful sentence either.
    """
    if raw is None or raw.strip() == "":
        return DEFAULT_INTERVAL_SEC, None
    try:
        value = int(raw.strip(), 10)
    except ValueError:
        return DEFAULT_INTERVAL_SEC, (
            f"HELIOPAUSE_INTERVAL_SEC must be a whole number of seconds between "
            f"{MIN_INTERVAL_SEC} and {MAX_INTERVAL_SEC} — got {raw.strip()!r}"
        )
    if value < MIN_INTERVAL_SEC or value > MAX_INTERVAL_SEC:
        return DEFAULT_INTERVAL_SEC, (
            f"HELIOPAUSE_INTERVAL_SEC must be between {MIN_INTERVAL_SEC} and {MAX_INTERVAL_SEC} "
            f"seconds — got {value}"
        )
    return value, None


INTERVAL_SEC, INTERVAL_ERROR = _interval_from_env(os.environ.get("HELIOPAUSE_INTERVAL_SEC"))
# `heliopause-agent`, not `heliopause`: on a gateway the relay also reads under
# /var/lib/heliopause, and the unit's StateDirectoryMode=0700 on a shared parent locks the relay
# out of it. Separate directories, no shared permission boundary. See the unit file.
STATE_FILE = os.environ.get("HELIOPAUSE_STATE_FILE", "/var/lib/heliopause-agent/state.json")
NFT = os.environ.get("HELIOPAUSE_NFT_BIN", "/usr/sbin/nft")
# Only the designated applier ever runs these. On every other host the workload half is absent from
# the artifact, so a missing kubectl is not a fault — see `apply_workload`.
KUBECTL = os.environ.get("HELIOPAUSE_KUBECTL_BIN", "/usr/local/bin/kubectl")
# There is deliberately no k3s-admin fallback. A workload assignment without an explicitly
# provisioned, least-privilege credential is refused before kubectl runs. The shared systemd unit
# also hides k3s.yaml; the applier drop-in exposes only the dedicated file.
KUBECONFIG = os.environ.get("HELIOPAUSE_KUBECONFIG", "")
WORKLOAD_NAMESPACES = frozenset(
    x.strip() for x in os.environ.get("HELIOPAUSE_K8S_NAMESPACES", "").split(",") if x.strip()
)
# Namespaces a *selector* may point at, beyond the ones we write objects in.
#
# The two are not the same privilege and were one list for as long as this file has existed. Writing
# a CiliumNetworkPolicy into a namespace lets heliopause **close** the pods there; naming one as a
# peer only requires that the enforcement gate can run `kubectl -n <ns> get pods` before it calls a
# generation confirmed. Conflating them made a closed egress posture impossible to express: every
# such posture needs DNS, DNS is CoreDNS in `kube-system`, and `toCIDR` can never reach a pod-backed
# destination — so the allow has to name `kube-system` as a peer. Granting write there to get it
# would hand this agent the ability to put CoreDNS into ingress default-deny, which is the outage the
# renderer's `applierNamespaces` exists to avoid.
#
# Empty by default, so a node that sets nothing behaves exactly as before.
WORKLOAD_PEER_NAMESPACES = WORKLOAD_NAMESPACES | frozenset(
    x.strip() for x in os.environ.get("HELIOPAUSE_K8S_PEER_NAMESPACES", "").split(",") if x.strip()
)
WORKLOAD_MANAGED_BY = os.environ.get("HELIOPAUSE_K8S_MANAGED_BY", "heliopause")
# Derived from STATE_FILE rather than configured separately: it has to land somewhere the unit can
# write, and the state directory is the one path that is guaranteed to be. See `kubectl`.
KUBE_CACHE_DIR = os.environ.get(
    "HELIOPAUSE_KUBE_CACHE_DIR", os.path.join(os.path.dirname(STATE_FILE), "kube-cache")
)

# Cilium's own namespace label. A selector crossing namespaces carries it, and it is a Cilium-side
# label rather than a Kubernetes one — so it scopes a `kubectl` query instead of being passed to
# `-l`. Must match `NS_LABEL` in src/cilium.ts.
NS_LABEL = "k8s:io.kubernetes.pod.namespace"
BASELINE_NEVER_NAMESPACE = "HELI0PAUSE-NEVER"
# The posture objects the renderer may emit, mapped to the object-name suffix each one carries.
# A baseline is the one shape whose spec is not a traffic flow, so it is checked against its own
# exact template rather than the direction rules below — and the template is stated here, on the
# agent, so a renderer that starts emitting a different one is refused instead of applied.
# Must match `BASELINE_KINDS` in src/cilium.ts.
BASELINE_SUFFIXES = {
    "namespace-ingress-default-deny": "-baseline",
    "selector-egress-default-deny": "-egress-baseline",
}

HTTP_TIMEOUT_SEC = 10
NFT_TIMEOUT_SEC = 20
# Longer than nft's: this one crosses the network to the API server, and on a node under load the
# apiserver's own admission path is slow before anything of ours runs.
KUBECTL_TIMEOUT_SEC = 60
# Bounded because a ruleset with geofeed sets attached is large but not unbounded, and this runs
# on hosts with under a gigabyte of RAM.
MAX_SIGNED_PAYLOAD_BYTES = 5 * 1024 * 1024
MAX_ARTIFACT_BYTES = ((MAX_SIGNED_PAYLOAD_BYTES + 2) // 3) * 4 + 1024
MAX_SIGNING_KEYS_PER_CLASS = 8
SIGNATURE_DOMAIN = b"heliopause-host-artifact-authorization-v1"
TRUST_DOMAIN = b"heliopause-host-artifact-trust-v1"
ENVELOPE_VERSION = "heliopause-ed25519-v1"
AUTH_CLOCK_SKEW_SEC = 60
AUTH_MIN_TTL_SEC = 15 * 60
AUTH_MANAGER_MAX_TTL_SEC = 7 * 24 * 60 * 60
AUTH_BREAK_GLASS_MAX_TTL_SEC = 24 * 60 * 60

# A reply is data from outside this host's trust boundary. Bounds here are independent of the
# publisher's matching bound in src/cilium.ts: a compromised relay cannot make one heartbeat fork
# thousands of kubectl processes even if it fabricates a reply instead of forwarding one.
MAX_WATCH_SELECTORS = 32
MAX_SELECTOR_BYTES = 512
MAX_SELECTOR_TERMS = 16
MEMBERSHIP_CACHE_SEC = 30
WORKLOAD_OBSERVE_SEC = 30
BACKGROUND_KUBECTL_BUDGET_SEC = 30
WORKLOAD_PREFLIGHT_BUDGET_SEC = 30
# Startup recovery runs before the first heartbeat. A large durable record against an unavailable
# API server must yield to a retry instead of serially spending 128 kubectl timeouts and keeping the
# agent offline for hours.
WORKLOAD_ROLLBACK_BUDGET_SEC = 60
ROLLBACK_RETRY_SEC = 5

# The publisher already constrains these values, but the relay is the party that serialises the
# artifact. Parse again at the last responsible boundary so a string, negative number or multi-year
# timer is a refused generation rather than an exception or a rollback promise that is effectively
# never honoured.
# A heartbeat is the confirmation. Accepting a shorter window than two beats, or than one normal
# nft observation plus the relay request, lets a syntactically valid but hostile reply manufacture
# a self-rollback. Five seconds of scheduling margin covers a busy sub-1GB node without pretending
# that arbitrarily slow control-plane work belongs on the critical path.
# The timer starts before the kernel changes. A worst-case accepted apply spends one nft timeout on
# the transaction and one on the post-apply structured snapshot. The main loop then makes an
# immediate confirmation heartbeat; allowing one failed HTTP attempt plus a short retry still needs
# more than the historical 60-second default. Ninety seconds is deliberately derived from those
# receiver-side bounds rather than trusting the publisher's interval invariant.
NFT_CONFIRM_MIN_SEC = max(
    90,
    2 * INTERVAL_SEC,
    (2 * NFT_TIMEOUT_SEC) + (2 * HTTP_TIMEOUT_SEC) + ROLLBACK_RETRY_SEC + 5,
)
NFT_CONFIRM_MAX_SEC = 600
# The workload promise covers API admission and Cilium convergence as well as a heartbeat. The
# publisher defaults this to 300 seconds; the receiver still owns a meaningful lower bound when the
# relay is compromised or buggy.
WORKLOAD_CONFIRM_MIN_SEC = max(120, 4 * INTERVAL_SEC)
WORKLOAD_CONFIRM_MAX_SEC = 3600

# Set by SIGTERM/SIGINT. Waited on instead of sleeping, so shutdown is immediate rather than up to
# one interval late — a unit that takes 15s to stop looks hung during a rolling restart.
_stop = threading.Event()


def log(msg):
    print(f"[heliopause] {msg}", file=sys.stderr, flush=True)


# ── nft ───────────────────────────────────────────────────────────────────────


def nft(args):
    """Run nft. Returns (rc, stdout, stderr); a timeout is reported as a failure, not raised.

    The push agent called subprocess.run without handling TimeoutExpired, so a wedged nft took the
    whole process down with a traceback. Here every failure mode has to come back as a value,
    because the caller is a loop that must keep heartbeating regardless.
    """
    try:
        p = subprocess.run(
            [NFT] + args,
            capture_output=True,
            text=True,
            timeout=NFT_TIMEOUT_SEC,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"nft timed out after {NFT_TIMEOUT_SEC}s"
    except OSError as e:
        return 127, "", f"cannot execute {NFT}: {e}"


def nft_json(args):
    """Run nft and parse its JSON output. Returns (elements, detail); elements is None on failure."""
    rc, out, err = nft(["-j"] + args)
    if rc != 0:
        return None, (err or out or f"nft exited {rc}").strip()
    try:
        return json.loads(out).get("nftables", []), ""
    except ValueError as e:
        return None, f"nft produced unparseable JSON: {e}"


def observed_state():
    """Digest the table as the kernel actually holds it. Returns (digest, detail).

    `-s` (stateless) is the point of this call: without it the dump carries counter values, the
    digest changes with every packet, and drift detection becomes noise that gets ignored.

    A missing table returns (None, reason) rather than a digest of empty output — "no table" and
    "an empty table" are different states, and only one of them means we have applied nothing.
    """
    items, detail = nft_json(["-s", "list", "ruleset"])
    if items is None:
        return None, detail
    ours = [item for item in items if isinstance(item, dict) and "metainfo" not in item and _is_ours(item)]
    if not ours:
        return None, f"table {TABLE_FAMILY} {TABLE_NAME} is absent"
    return _observed_digest(ours), ""


def _foreign_filters_from_items(items):
    """Pure parser shared by standalone diagnostics and the one-shot telemetry snapshot."""
    found = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        chain = item.get("chain")
        if not isinstance(chain, dict) or chain.get("hook") not in ("input", "forward"):
            continue
        family, table = chain.get("family"), chain.get("table")
        if family == TABLE_FAMILY and table == TABLE_NAME:
            continue
        if family and table:
            found.add(f"{family} {table}")
    return sorted(found)


# `proto static` and `proto boot` are the two the kernel records for "a person or a script ran
# `ip route add`". Everything else that names a protocol has an owner that can be asked; an **absent**
# protocol names nobody, and that is its own answer rather than a synonym for either.
ROUTE_PROTO_BY_A_PERSON = frozenset({"static", "boot"})


def _routes_from_json(rows):
    """Pure parser, so the shape can be tested without a kernel.

    Each route becomes `{dst, via, dev, proto, table, origin, handAdded}`.

    `origin` is the one judgement made here and it has three values, not two:

      "static"     proto static or boot -- a person or a script ran `ip route add`
      "automatic"  kernel, a DHCP lease, a routing daemon: something else owns it and can be asked
      "unstated"   no protocol at all. Names nobody, and is **not** a synonym for either of the above

    ## The third value is a correction

    The first version of this had two values and folded "no protocol" into "hand added". Four of the
    six routes it flagged on gw-01.dev were `wg0` routes with no protocol, and the test asserting that
    behaviour claimed they had "no other record".

    They do. Measured 2026-08-17: the peer's AllowedIPs is
    `10.255.0.0/16 10.254.0.0/16 10.16.0.0/16 10.253.0.0/16` and the four routes are exactly those --
    `wg-quick` installs them from that config. Two thirds of the column was a false positive and the
    comment justifying it claimed more than had been measured.

    **None of these values says "undeclared".** That question needs a declaration to compare against,
    which now exists in the site model (`src/routes.ts`); this function reports what the kernel said
    and nothing more.

    `handAdded` stays on the wire for managers older than this agent, and now carries the narrow
    meaning only -- proto static or boot. The manager prefers `origin` and does not read the old field
    when it is present, so the two eras never appear in the same column.
    """
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        proto = str(r.get("protocol") or "")
        origin = (
            "unstated" if proto == ""
            else "static" if proto in ROUTE_PROTO_BY_A_PERSON
            else "automatic"
        )
        out.append({
            "dst": str(r.get("dst") or ""),
            "via": str(r.get("gateway") or ""),
            "dev": str(r.get("dev") or ""),
            "proto": proto,
            "table": str(r.get("table") or "main"),
            "origin": origin,
            "handAdded": origin == "static",
        })
    out.sort(key=lambda x: (x["table"], x["dst"], x["dev"]))
    return out


def observed_routes():
    """The host's IPv4 routes, or None if they could not be read.

    ## Why the firewall reports routing

    A packet reaches a filter only if routing sent it there, so a ruleset and a route are two halves
    of one answer and only one of them was ever visible here. Measured on gw-01.dev on 2026-08-16:
    two `proto static` routes carry every packet bound for the cluster's pod and service ranges, and
    **neither is written down anywhere** — not in the policy repository, not in a manifest, nowhere
    but that kernel. Rebuild the host and they are gone; nothing in this system would notice until
    the gateway stopped reaching the cluster.

    ## None and [] are different answers

    The same contract as `foreign_filters`. None means the routes could not be read — a missing
    `ip`, a permission error, a parse failure — and [] would mean a host with no routes at all,
    which is not a state a reachable host is in. Collapsing the first into the second reports "no
    routing surprises here" on exactly the hosts where nothing could be checked.

    Read-only by construction: `ip -json -4 route show table all` changes nothing, needs no
    privilege, and is one subprocess on the observation path that already runs `nft`.
    """
    try:
        proc = subprocess.run(
            ["ip", "-json", "-4", "route", "show", "table", "all"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        log(f"route observation failed: {e}")
        return None
    if proc.returncode != 0:
        log(f"route observation failed: ip exited {proc.returncode}: {proc.stderr.strip()[:200]}")
        return None
    try:
        rows = json.loads(proc.stdout or "[]")
    except ValueError as e:
        log(f"route observation failed: {e}")
        return None
    if not isinstance(rows, list):
        return None
    return _routes_from_json(rows)


def foreign_filters():
    """Other nftables tables filtering on `input` or `forward`, as `family name`.

    Returns a sorted list, or None if the kernel could not be read. **None and [] are different
    answers** and the caller must keep them apart: None means "we could not see whether another
    firewall is running", [] means "we looked and there is none". Collapsing the first into the
    second reports the absence of a second firewall on exactly the hosts where we cannot tell.

    ## Why this exists

    Measured 2026-08-02: a generation was published, five hosts reported `confirmed`, the kernel
    held exactly the rendered rules, and not one of the newly declared ports was reachable —
    firewalld was hooked on the same chain and rejecting them. A packet must pass every table hooked
    on its path, so a ruleset can be perfectly applied and completely overridden while every check
    in this agent passes.

    ## Only input and forward

    Those are the hooks that can contradict an inbound decision. A table on `output`, `prerouting`
    or `postrouting` is doing egress or NAT work — real, but it cannot turn an allowed port into a
    refused one, and listing it would bury the case that matters in the ones that never do.

    Read from `nft -j list ruleset` rather than the text form: the text has to be parsed by
    indentation to know which table a chain belongs to, and that is a parser that silently mis-scopes
    when the format shifts.
    """
    items, _ = nft_json(["list", "ruleset"])
    if items is None:
        return None
    return _foreign_filters_from_items(items)


def _published_ports_from_items(items):
    """Pure parser shared by standalone diagnostics and the one-shot telemetry snapshot."""
    # chain key -> hook, so a rule can be attributed without re-parsing indentation.
    hooks = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        chain = item.get("chain")
        if isinstance(chain, dict) and chain.get("hook"):
            hooks[(chain.get("family"), chain.get("table"), chain.get("name"))] = chain["hook"]

    found = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if not isinstance(rule, dict):
            continue
        family, table = rule.get("family"), rule.get("table")
        if family == TABLE_FAMILY and table == TABLE_NAME:
            continue
        if hooks.get((family, table, rule.get("chain"))) != "prerouting":
            continue

        expr = rule.get("expr")
        if not isinstance(expr, list):
            continue
        dnat = None
        proto = None
        dport = None
        for e in expr:
            if not isinstance(e, dict):
                continue
            if "dnat" in e:
                dnat = e["dnat"]
            match = e.get("match")
            if isinstance(match, dict):
                left, right = match.get("left"), match.get("right")
                if isinstance(left, dict):
                    payload = left.get("payload")
                    if isinstance(payload, dict) and payload.get("field") == "dport":
                        dport = right
                        proto = payload.get("protocol") or proto
        if dnat is None:
            continue
        dest = ""
        if isinstance(dnat, dict):
            addr, port = dnat.get("addr"), dnat.get("port")
            dest = f" -> {addr}" + (f":{port}" if port else "") if addr else ""
        label = f"{proto or 'ip'}/{dport if dport is not None else '?'}{dest}"
        found.add(f"{family} {table}: {label}")
    return sorted(found)


def published_ports():
    """Ports another table redirects inbound (H36), as `proto/port -> destination` strings.

    Returns a sorted list, or None if the kernel could not be read. **None and [] are different**, for
    the same reason as `foreign_filters` above: None is "we could not look", [] is "we looked and there
    are none".

    ## Why this is reported rather than blocked

    A container runtime that publishes a port installs a DNAT rule in its own table on `prerouting`.
    The packet's destination is rewritten *before* it reaches any `input` hook, so it is never matched
    against this project's rules at all — a policy that declares port 8080 closed is not wrong, it is
    simply not consulted. **"I blocked it and it is still open" is the worst failure mode a firewall
    has**, and this is the one shape of it that is structurally outside our reach.

    So the honest thing is to say so on the host where it is true. The alternative — adding a rule to
    catch DNAT'd traffic — would mean this project contending with the container runtime over the same
    packets, and the runtime rewrites them first.

    ## What this does not see — measured, not assumed

    **Cilium NodePorts leave no netfilter trace.** Measured on k3s-01.dev 2026-08-04: NodePort 30444 is
    listening and reachable, and `nft -j list ruleset` on that host contains **zero** DNAT rules. With
    kube-proxy replaced, the redirection happens in eBPF, so there is nothing here to find — the same
    reason a packet to a ClusterIP never reaches a netfilter hook (appendix A V15, V31).

    So this covers container runtimes that use nftables (podman/netavark, docker) and misses eBPF
    service implementations entirely. Reporting `[]` on such a host is honest about what was looked at
    and dishonest about what it means, which is worth stating plainly: the workload layer
    (CiliumNetworkPolicy) is the only thing that governs those, and that is why it exists.

    ## Why only prerouting DNAT, and not our own table

    `prerouting` is where inbound redirection happens; DNAT elsewhere is egress or hairpin work that
    cannot expose a listener. Our own table is excluded because `forward`'s `ct status dnat accept` is
    a *consequence* of somebody else's DNAT, not a publication — reporting it would make every gateway
    accuse itself. Measured on gw-01: that rule is the only DNAT match in `inet heliopause`.
    """
    items, _ = nft_json(["list", "ruleset"])
    if items is None:
        return None
    return _published_ports_from_items(items)


_CILIUM_CACHE = None
_CILIUM_CACHE_AT = 0.0
_CILIUM_CACHE_LOCK = threading.Lock()
_CILIUM_REFRESHING = False
CILIUM_OBSERVE_SEC = 60
CILIUM_EXPOSURE_ENABLED = os.environ.get("HELIOPAUSE_CILIUM_EXPOSURE", "").lower() in {
    "1", "true", "yes",
}


def _read_cilium_exposure(deadline=None):
    """Return Cilium's host-facing eBPF frontends and address restriction.

    nftables cannot see these frontends. This is deliberately queried from Cilium's realized service
    map rather than inferred from Kubernetes Services: HostPort is present there too, and the exact
    failure that prompted this check was a HostPort silently disappearing when `nodeport-addresses`
    changed. None means we tried and could not read; non-cluster hosts do not call this function.
    """
    command_timeout = _deadline_timeout(deadline)
    if command_timeout is None:
        return None
    rc, raw, _ = kubectl(
        ["-n", "kube-system", "get", "configmap", "cilium-config", "-o", "json"],
        timeout_sec=command_timeout,
    )
    if rc != 0:
        return None
    try:
        cfg = json.loads(raw)
        value = (cfg.get("data") or {}).get("nodeport-addresses", "")
        addresses = sorted(x.strip() for x in value.split(",") if x.strip())
    except (ValueError, AttributeError, TypeError):
        return None

    command_timeout = _deadline_timeout(deadline)
    if command_timeout is None:
        return None
    rc, raw, _ = kubectl(
        ["-n", "kube-system", "get", "pods", "-l", "k8s-app=cilium", "-o", "json"],
        timeout_sec=command_timeout,
    )
    if rc != 0:
        return None
    try:
        pods = json.loads(raw).get("items") or []
        pod = pods[0]["metadata"]["name"]
    except (ValueError, IndexError, KeyError, TypeError):
        return None

    command_timeout = _deadline_timeout(deadline)
    if command_timeout is None:
        return None
    rc, raw, _ = kubectl(
        ["-n", "kube-system", "exec", pod, "--", "cilium-dbg", "service", "list", "-o", "json"],
        timeout_sec=command_timeout,
    )
    if rc != 0:
        return None
    try:
        rows = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(rows, list):
        return None

    found = set()
    for row in rows:
        try:
            spec = row["spec"]
            flags = spec["flags"]
            kind = flags.get("type")
            if kind not in ("HostPort", "NodePort"):
                continue
            front = spec["frontend-address"]
            ip, port = front["ip"], front["port"]
            proto = str(front.get("protocol") or "?").upper()
            namespace = flags.get("namespace") or "?"
            name = flags.get("name") or "?"
            # Pod-generated HostPort names contain a UUID. The frontend and namespace are stable;
            # keeping the UUID would manufacture a new observation on every rollout.
            if kind == "HostPort" and ":host-port:" in name:
                name = name.split(":host-port:", 1)[0]
            found.add(f"{kind} {ip}:{port}/{proto} {namespace}/{name}")
        except (KeyError, TypeError):
            continue
    return {"nodePortAddresses": addresses, "services": sorted(found)}


def _refresh_cilium_exposure():
    global _CILIUM_CACHE, _CILIUM_CACHE_AT, _CILIUM_REFRESHING
    try:
        value = _read_cilium_exposure(time.time() + BACKGROUND_KUBECTL_BUDGET_SEC)
        with _CILIUM_CACHE_LOCK:
            _CILIUM_CACHE = value
            _CILIUM_CACHE_AT = time.monotonic()
    except Exception as e:  # noqa: BLE001 — telemetry cannot take down the heartbeat loop
        log(f"Cilium exposure refresh failed: {e}")
    finally:
        with _CILIUM_CACHE_LOCK:
            _CILIUM_REFRESHING = False


def cilium_exposure():
    """Return cached exposure and refresh it off the heartbeat-critical thread."""
    global _CILIUM_REFRESHING
    now = time.monotonic()
    with _CILIUM_CACHE_LOCK:
        value = _CILIUM_CACHE
        fresh = _CILIUM_CACHE_AT and now - _CILIUM_CACHE_AT < CILIUM_OBSERVE_SEC
        if not fresh and not _CILIUM_REFRESHING:
            # This is three kubectl calls including an exec. Even one 60-second timeout is longer
            # than the heartbeat's job, which is also the nft confirmation signal.
            _CILIUM_REFRESHING = True
            threading.Thread(
                target=_refresh_cilium_exposure,
                name="cilium-exposure",
                daemon=True,
            ).start()
    return value


# ── kubectl ───────────────────────────────────────────────────────────────────
#
# Same contract as `nft` above: every failure mode returns a value. The caller is a loop that has to
# keep heartbeating, and the heartbeat is what confirms an apply and what carries the instruction to
# undo one — a traceback here would strand the host behind whatever it just applied.


def kubectl(args, stdin=None, timeout_sec=None):
    """Run kubectl. Returns (rc, stdout, stderr).

    `--cache-dir` is passed explicitly because it defaults to `$HOME/.kube/cache` and the unit sets
    `ProtectHome=yes`. Left to the default, kubectl cannot write its discovery cache and says so on
    stderr on every call — noise that would be indistinguishable from a real failure in the journal.
    It is pointed under the agent's own StateDirectory, the one path the unit can write.
    """
    try:
        # Created here rather than relied on. kubectl does create its cache directory when it needs
        # one, but only for the commands that perform discovery — and whether a given invocation does
        # is an implementation detail of the version installed. Making it ourselves costs one syscall
        # and removes the question. A failure is ignored: kubectl works without a cache, just noisily,
        # and refusing to apply a policy over a cache directory would be the wrong trade.
        try:
            os.makedirs(KUBE_CACHE_DIR, exist_ok=True)
        except OSError:
            pass
        timeout = KUBECTL_TIMEOUT_SEC if timeout_sec is None else max(
            0.001, min(KUBECTL_TIMEOUT_SEC, timeout_sec)
        )
        p = subprocess.run(
            [KUBECTL, "--kubeconfig", KUBECONFIG, "--cache-dir", KUBE_CACHE_DIR] + args,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"kubectl timed out after {timeout:.3g}s"
    except OSError as e:
        return 127, "", f"cannot execute {KUBECTL}: {e}"


def _deadline_timeout(deadline):
    """A per-command kubectl timeout that cannot extend an enclosing absolute deadline."""
    if deadline is None:
        return KUBECTL_TIMEOUT_SEC
    remaining = deadline - time.time()
    return None if remaining <= 0 else min(KUBECTL_TIMEOUT_SEC, remaining)


_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_K8S_ADMIN_KUBECONFIGS = frozenset(
    os.path.realpath(path)
    for path in ("/etc/rancher/k3s/k3s.yaml", "/etc/kubernetes/admin.conf")
)
MAX_WORKLOAD_OBJECTS = 128


def _parse_timeout(value, default, minimum, maximum, field):
    """Return a bounded integer timeout, or `(None, reason)` for untrusted artifact data."""
    if value is None:
        value = default
    # bool is an int in Python; accepting true as one second would turn a JSON type error into a
    # self-induced rollback loop.
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
        or int(value) != value
    ):
        return None, f"{field} must be an integer number of seconds"
    value = int(value)
    if value < minimum or value > maximum:
        return None, f"{field} must be between {minimum} and {maximum} seconds, got {value}"
    return value, ""


def _kubeconfig_error():
    """Why this credential is unsafe/unusable, or an empty string when it is fit for the applier."""
    if not KUBECONFIG:
        return "HELIOPAUSE_KUBECONFIG is required on the workload applier (there is no admin default)"
    path = os.path.realpath(KUBECONFIG)
    if path in _K8S_ADMIN_KUBECONFIGS:
        return f"refusing cluster-admin kubeconfig {path}; provision the scoped heliopause ServiceAccount"
    try:
        info = os.stat(path)
    except OSError as e:
        return f"cannot read HELIOPAUSE_KUBECONFIG {KUBECONFIG}: {e}"
    if not stat.S_ISREG(info.st_mode):
        return f"HELIOPAUSE_KUBECONFIG {KUBECONFIG} is not a regular file"
    if info.st_uid != os.geteuid():
        return f"HELIOPAUSE_KUBECONFIG {KUBECONFIG} must be owned by the agent service user"
    if info.st_mode & 0o077:
        return f"HELIOPAUSE_KUBECONFIG {KUBECONFIG} must not be group/world accessible"
    if not WORKLOAD_NAMESPACES:
        return "HELIOPAUSE_K8S_NAMESPACES is empty; the applier needs an explicit namespace allowlist"
    return ""


def _slug(value):
    return re.sub(r"^-+|-+$", "", re.sub(r"[^a-z0-9-]+", "-", value.lower()))


def _string_map(value, where, *, require_namespace=False):
    if not isinstance(value, dict) or not value:
        return None, f"{where} must be a non-empty matchLabels object"
    out = {}
    for key, val in value.items():
        if not isinstance(key, str) or not key or not isinstance(val, str):
            return None, f"{where} keys and values must be strings"
        if len(key) > 253 or len(val) > 253:
            return None, f"{where} contains an overlong label"
        out[key] = val
    ns = out.get(NS_LABEL)
    if require_namespace and not ns:
        return None, f"{where} does not pin {NS_LABEL}; an empty/unscoped selector is forbidden"
    # The peer set, not the writable one. This function checks selectors — an object's own
    # `endpointSelector` and a rule's peers alike — and a selector is a reference, not a write. Where
    # the object actually *lands* is checked separately against `WORKLOAD_NAMESPACES`
    # (`metadata.namespace`), and the endpoint selector is pinned to that namespace, so nothing here
    # widens where an object may be created.
    if ns is not None and ns not in WORKLOAD_PEER_NAMESPACES:
        return None, (
            f"{where} reaches namespace {ns!r}, outside HELIOPAUSE_K8S_NAMESPACES and "
            f"HELIOPAUSE_K8S_PEER_NAMESPACES"
        )
    return out, ""


def _validate_port_sets(value, where):
    if not isinstance(value, list) or len(value) != 1 or set(value[0] if isinstance(value[0], dict) else ()) != {"ports"}:
        return f"{where} must be the renderer's single ports wrapper"
    ports = value[0].get("ports")
    if not isinstance(ports, list) or not ports or len(ports) > 128:
        return f"{where}.ports must be a non-empty bounded array"
    for i, port in enumerate(ports):
        if not isinstance(port, dict) or set(port) - {"port", "endPort", "protocol"}:
            return f"{where}.ports[{i}] has unsupported fields"
        raw = port.get("port")
        if not isinstance(raw, str) or not raw.isdigit() or not 0 <= int(raw) <= 65535:
            return f"{where}.ports[{i}].port is invalid"
        protocol = port.get("protocol")
        if protocol not in {"TCP", "UDP", "ANY"}:
            return f"{where}.ports[{i}].protocol is invalid"
        end = port.get("endPort")
        # protocolOnlyPorts render one Cilium port 0 entry: it means every port for exactly one
        # transport protocol. No range, ANY, or neighbouring entry is renderer-produced, and each
        # would silently widen a manifest that appears more specific.
        if int(raw) == 0 and (
            len(ports) != 1 or end is not None or protocol not in {"TCP", "UDP"}
        ):
            return f"{where}.ports[{i}].port 0 is allowed only as one protocol-only TCP/UDP rule"
        if end is not None and (
            isinstance(end, bool) or not isinstance(end, int) or
            end < int(raw) or end > 65535
        ):
            return f"{where}.ports[{i}].endPort is invalid"
    return ""


def _validate_peer_selectors(value, where):
    if not isinstance(value, list) or len(value) != 1:
        return f"{where} must contain exactly one renderer-produced selector"
    item = value[0]
    if not isinstance(item, dict) or set(item) != {"matchLabels"}:
        return f"{where}[0] must contain only matchLabels"
    _, reason = _string_map(item.get("matchLabels"), f"{where}[0].matchLabels", require_namespace=True)
    return reason


def _validate_cidrs(value, where):
    if not isinstance(value, list) or not value or len(value) > 128:
        return f"{where} must be a non-empty bounded array"
    for raw in value:
        try:
            if not isinstance(raw, str):
                raise ValueError("not text")
            ipaddress.ip_network(raw, strict=True)
        except ValueError:
            return f"{where} contains invalid CIDR {raw!r}"
    return ""


def _validate_workload_rule(rule, direction, where):
    ingress = direction.startswith("ingress")
    peer_fields = (
        {"fromEndpoints", "fromCIDR", "fromEntities"}
        if ingress
        else {"toEndpoints", "toCIDR", "toEntities", "toServices"}
    )
    allowed = (
        {"fromEndpoints", "fromCIDR", "fromEntities", "toPorts"}
        if ingress
        else {"toEndpoints", "toCIDR", "toEntities", "toServices", "toPorts"}
    )
    if not isinstance(rule, dict) or not rule or set(rule) - allowed:
        return f"{where} has unsupported or empty rule fields"
    present_peers = set(rule) & peer_fields
    if len(present_peers) != 1:
        return f"{where} must carry exactly one renderer-produced peer field"
    for key, value in rule.items():
        if key in {"fromEndpoints", "toEndpoints"}:
            reason = _validate_peer_selectors(value, f"{where}.{key}")
        elif key in {"fromCIDR", "toCIDR"}:
            reason = _validate_cidrs(value, f"{where}.{key}")
        elif key in {"fromEntities", "toEntities"}:
            reason = "" if (
                isinstance(value, list) and len(value) == 1 and
                all(v in {"all", "world", "host"} for v in value)
            ) else f"{where}.{key} contains an unsupported entity"
        elif key == "toPorts":
            reason = _validate_port_sets(value, f"{where}.toPorts")
        else:  # toServices
            reason = ""
            if not isinstance(value, list) or len(value) != 1:
                reason = f"{where}.toServices must contain exactly one service"
            else:
                service = value[0]
                k8s = service.get("k8sService") if isinstance(service, dict) and set(service) == {"k8sService"} else None
                if not isinstance(k8s, dict) or set(k8s) != {"serviceName", "namespace"}:
                    reason = f"{where}.toServices[0] is not a renderer-produced k8sService"
                elif not isinstance(k8s.get("serviceName"), str) or not _DNS_LABEL.fullmatch(k8s["serviceName"]):
                    reason = f"{where}.toServices[0] has an invalid serviceName"
                elif k8s.get("namespace") not in WORKLOAD_PEER_NAMESPACES:
                    # A Service reference is a peer like any other — see `_string_map`.
                    reason = f"{where}.toServices[0] reaches a namespace this applier may not point at"
        if reason:
            return reason
    return ""


def validate_workload(text, *, cluster, applier, generation):
    """Parse the CNP document and check every object is one we are willing to apply.

    Returns (objects, reason); objects is None on refusal.

    The same reasoning as `validate_artifact`: an allowlist, checked before anything is applied, so an
    unexpected construct produces a refused generation rather than an applied surprise. It matters as
    much here — Kubernetes accepts many privileged manifest kinds, so an artifact that reached this function
    unchecked could create a ClusterRoleBinding as easily as a network policy.

    Namespace and name are required on every object because they are what `mustExist` looks for
    afterwards. An object with neither could be applied and then never verified.

    The document is a `v1/List`, which is the shape `kubectl apply -f` accepts — a bare JSON array is
    rejected before it reaches the API server, having no `apiVersion`/`kind` to dispatch on. The
    wrapper is checked rather than skipped past: this function's job is to be sure of what is about to
    be applied, and "it had some items in it somewhere" is not that.
    """
    try:
        doc = json.loads(text)
    except ValueError as e:
        return None, f"workload document is not JSON: {e}"
    if not isinstance(doc, dict):
        return None, "workload document is not a v1/List object"
    if doc.get("apiVersion") != "v1" or doc.get("kind") != "List":
        return None, (
            f"workload document is {doc.get('apiVersion')!r}/{doc.get('kind')!r}, expected v1/List"
        )
    if set(doc) != {"apiVersion", "kind", "items"}:
        return None, "workload v1/List wrapper has unsupported or missing fields"
    items = doc.get("items")
    if not isinstance(items, list):
        return None, "workload document has no items array"
    if not items:
        return None, "workload document has an empty items array"
    if len(items) > MAX_WORKLOAD_OBJECTS:
        return None, f"workload document has {len(items)} objects, limit is {MAX_WORKLOAD_OBJECTS}"
    if not isinstance(cluster, str) or not cluster or not _slug(cluster):
        return None, "workload cluster is empty or cannot form a safe object-name prefix"
    if not isinstance(applier, str) or not applier:
        return None, "workload applier is empty"
    if not isinstance(generation, str) or not generation or len(generation) > 253:
        return None, "workload generation is empty or overlong"
    if not WORKLOAD_NAMESPACES:
        return None, "HELIOPAUSE_K8S_NAMESPACES is empty; no workload namespace is authorised"
    doc = items

    seen_refs = set()
    for i, obj in enumerate(doc):
        where = f"object {i}"
        if not isinstance(obj, dict):
            return None, f"{where} is not an object"
        if set(obj) != {"apiVersion", "kind", "metadata", "spec"}:
            return None, f"{where} has unsupported or missing top-level fields"
        if obj.get("apiVersion") != "cilium.io/v2":
            return None, f"{where} has apiVersion {obj.get('apiVersion')!r}, expected cilium.io/v2"
        if obj.get("kind") != "CiliumNetworkPolicy":
            return None, f"{where} has kind {obj.get('kind')!r}, expected CiliumNetworkPolicy"
        meta = obj.get("metadata")
        if not isinstance(meta, dict):
            return None, f"{where} has no metadata"
        name = meta.get("name")
        namespace = meta.get("namespace")
        if not isinstance(name, str) or not isinstance(namespace, str) or not name or not namespace:
            # Without both, `mustExist` cannot name it and the apply could never be verified.
            return None, f"{where} is missing metadata.name or metadata.namespace"
        if set(meta) != {"name", "namespace", "labels", "annotations"}:
            return None, f"{where} metadata has unsupported or missing fields"
        if not _DNS_LABEL.fullmatch(name):
            return None, f"{where} metadata.name {name!r} is not a DNS-1123 label"
        if not _DNS_LABEL.fullmatch(namespace) or namespace not in WORKLOAD_NAMESPACES:
            return None, f"{where} namespace {namespace!r} is outside HELIOPAUSE_K8S_NAMESPACES"
        ref = f"{namespace}/{name}"
        if ref in seen_refs:
            return None, f"{where} duplicates workload object {ref}"
        seen_refs.add(ref)
        labels = meta.get("labels")
        if labels != {"managed-by": WORKLOAD_MANAGED_BY, "heliopause.io/cluster": cluster}:
            return None, f"{where} does not carry the exact heliopause ownership and cluster labels"
        annotations = meta.get("annotations")
        if not isinstance(annotations, dict):
            return None, f"{where} has no annotations"
        baseline_kind = annotations.get("heliopause.io/policy-kind")
        baseline_suffix = BASELINE_SUFFIXES.get(baseline_kind) if isinstance(baseline_kind, str) else None
        baseline = baseline_suffix is not None
        if baseline_kind is not None and not baseline:
            # An unknown posture kind is refused rather than falling through to the traffic-flow
            # rules, which would check the wrong template against it and could pass.
            return None, f"{where} carries an unsupported heliopause.io/policy-kind"
        expected_annotations = {"heliopause.io/policy-id", "heliopause.io/applier", "heliopause.io/generation"}
        if baseline:
            expected_annotations.add("heliopause.io/policy-kind")
        if set(annotations) != expected_annotations:
            return None, f"{where} annotations have unsupported or missing fields"
        if annotations.get("heliopause.io/applier") != applier:
            return None, f"{where} names a different applier"
        if annotations.get("heliopause.io/generation") != generation:
            return None, f"{where} names a different generation"
        policy_id = annotations.get("heliopause.io/policy-id")
        if not isinstance(policy_id, str) or not _slug(policy_id):
            return None, f"{where} has an invalid policy-id annotation"
        base_name = f"hp-{_slug(cluster)}-{_slug(policy_id)}"
        if name not in ({f"{base_name}{baseline_suffix}"} if baseline else {base_name, f"{base_name}-ingress"}):
            return None, f"{where} name {name!r} is not derived from cluster and policy-id"

        spec = obj.get("spec")
        if not isinstance(spec, dict) or set(spec) - {
            "description", "endpointSelector", "enableDefaultDeny",
            "ingress", "egress", "ingressDeny", "egressDeny",
        }:
            return None, f"{where} spec has unsupported fields"
        description = spec.get("description")
        if not isinstance(description, str) or not description or len(description) > 1024:
            return None, f"{where} spec.description is empty or overlong"
        endpoint = spec.get("endpointSelector")
        if not isinstance(endpoint, dict) or set(endpoint) != {"matchLabels"}:
            return None, f"{where} endpointSelector must contain only matchLabels"
        selected, reason = _string_map(
            endpoint.get("matchLabels"), f"{where} endpointSelector.matchLabels", require_namespace=True
        )
        if selected is None:
            return None, reason
        if selected.get(NS_LABEL) != namespace:
            return None, f"{where} endpoint selector namespace does not match metadata.namespace"

        if baseline_kind == "namespace-ingress-default-deny":
            if selected != {NS_LABEL: namespace}:
                return None, f"{where} baseline endpoint selector must select exactly its namespace"
            if spec.get("enableDefaultDeny") != {"ingress": True}:
                return None, f"{where} baseline enableDefaultDeny must be ingress true"
            if any(key in spec for key in ("egress", "ingressDeny", "egressDeny")):
                return None, f"{where} baseline carries an unsupported traffic direction"
            if spec.get("ingress") != [{"fromEndpoints": [{"matchLabels": {NS_LABEL: BASELINE_NEVER_NAMESPACE}}]}]:
                return None, f"{where} baseline ingress must be its exact unmatchable source rule"
            continue
        if baseline_kind == "selector-egress-default-deny":
            # The namespace-wide form is refused here as well as in the renderer, and for the reason
            # the renderer states: an egress baseline *closes* what it selects, and a selector holding
            # nothing but the namespace label closes every pod in that namespace. Both workloads this
            # object was built for share a namespace with pods nobody asked to contain, so the
            # difference between "the broker" and "everything beside the broker" is an outage.
            if len(selected) < 2:
                return None, f"{where} egress baseline selector names no label besides its namespace"
            if spec.get("enableDefaultDeny") != {"egress": True}:
                return None, f"{where} egress baseline enableDefaultDeny must be egress true"
            if any(key in spec for key in ("ingress", "ingressDeny", "egressDeny")):
                return None, f"{where} egress baseline carries an unsupported traffic direction"
            if spec.get("egress") != [{"toEndpoints": [{"matchLabels": {NS_LABEL: BASELINE_NEVER_NAMESPACE}}]}]:
                return None, f"{where} egress baseline egress must be its exact unmatchable destination rule"
            continue
        directions = [key for key in ("ingress", "egress", "ingressDeny", "egressDeny") if key in spec]
        if len(directions) != 1:
            return None, f"{where} must carry exactly one renderer-produced policy direction"
        direction = directions[0]
        rules = spec.get(direction)
        if not isinstance(rules, list) or len(rules) != 1:
            return None, f"{where} {direction} must contain exactly one rule"
        expected_default = {
            "ingress": {"ingress": True},
            "ingressDeny": {"ingress": False},
            "egress": {"egress": False},
            "egressDeny": {"egress": False},
        }[direction]
        if spec.get("enableDefaultDeny") != expected_default:
            return None, f"{where} enableDefaultDeny does not match its {direction} semantics"
        reason = _validate_workload_rule(rules[0], direction, f"{where} spec.{direction}[0]")
        if reason:
            return None, reason
    return doc, ""


def workload_objects(doc):
    """`namespace/name` for each object, in the form `mustExist` uses."""
    return [f"{o['metadata']['namespace']}/{o['metadata']['name']}" for o in doc]


def validate_watch_selectors(watch):
    """Return a bounded canonical watch request, or `(None, reason)` on an untrusted reply."""
    if watch is None:
        return None, ""
    if not isinstance(watch, dict) or set(watch) - {"namespaces", "labels"}:
        return None, "watchSelectors must be an object containing only namespaces and labels"
    namespaces = watch.get("namespaces", [])
    labels = watch.get("labels", [])
    if not isinstance(namespaces, list) or not isinstance(labels, list):
        return None, "watchSelectors namespaces and labels must be arrays"
    if len(namespaces) + len(labels) > MAX_WATCH_SELECTORS:
        return None, (
            f"watchSelectors asks for {len(namespaces) + len(labels)} queries, "
            f"limit is {MAX_WATCH_SELECTORS}"
        )
    if not namespaces and not labels:
        return None, ""
    for ns in namespaces:
        if not isinstance(ns, str) or not _DNS_LABEL.fullmatch(ns):
            return None, f"watchSelectors contains invalid namespace {ns!r}"
        if ns not in WORKLOAD_PEER_NAMESPACES:
            # A membership query is a read. It is bounded by what we may look at, not by where we may
            # write — the same split as `_string_map`.
            return None, f"watchSelectors namespace {ns!r} is outside the namespaces this applier may query"
    for selector in labels:
        if not isinstance(selector, str) or not selector or len(selector.encode()) > MAX_SELECTOR_BYTES:
            return None, "watchSelectors contains an empty, non-text or overlong selector"
        parts = [part.strip() for part in selector.split(",") if part.strip()]
        if not parts or len(parts) > MAX_SELECTOR_TERMS:
            return None, f"watch selector {selector!r} has too many or no terms"
        keys = []
        for part in parts:
            if "=" not in part or part.startswith("="):
                return None, f"watch selector term {part!r} is not key=value"
            key, _ = part.split("=", 1)
            keys.append(key)
        if len(set(keys)) != len(keys):
            return None, f"watch selector {selector!r} repeats a key"
        ns, _ = _split_selector(selector)
        # The renderer itself refuses unscoped workload labels. Requiring that invariant again here
        # removes the expensive `--all-namespaces` fallback from the heartbeat boundary.
        if not ns:
            return None, f"watch selector {selector!r} does not pin {NS_LABEL}"
        if ns not in WORKLOAD_PEER_NAMESPACES:
            return None, f"watch selector {selector!r} reaches an unauthorised namespace"
    if len(set(namespaces)) != len(namespaces) or len(set(labels)) != len(labels):
        return None, "watchSelectors contains duplicate queries"
    return {"namespaces": list(namespaces), "labels": list(labels)}, ""


def selector_membership(watch, deadline=None):
    """Which pods the manager's selectors currently match. Returns the heartbeat's `membership`, or None.

    `watch` is `{"namespaces": [...], "labels": [...]}` as the manager sent it. Only what was asked
    about is looked up — dumping every pod on every beat would cost a full listing per interval on a
    host with under a gigabyte of RAM, and answer a question nobody asked.

    Returns None when nothing was asked, which is the normal case on a host that is not the applier.

    A namespace or selector that cannot be read is **omitted** rather than reported as empty. The
    manager reads a missing key as "not known" and an empty list as "queried, and there are none" —
    and those justify different decisions. `arc-runners` is genuinely empty between CI jobs, so a
    failed query that reported `[]` would look exactly like a healthy idle runner set.
    """
    watch, reason = validate_watch_selectors(watch)
    if reason:
        log(f"refusing selector watch: {reason}")
        return None
    if not watch:
        return None
    namespaces = {}
    labels = {}
    failures = []

    for ns in watch.get("namespaces") or []:
        command_timeout = _deadline_timeout(deadline)
        if command_timeout is None:
            failures.append("selector membership refresh exceeded its total budget")
            break
        rc, out, err = kubectl(
            ["-n", ns, "get", "pods", "-o", "name"], timeout_sec=command_timeout
        )
        if rc != 0:
            failures.append(f"{ns}: {(err or '').strip() or f'kubectl exited {rc}'}")
            continue
        # `pod/name` → `name`. Bare names; the manager qualifies them with the namespace it asked
        # about, so a pod list can never be attributed to the wrong namespace.
        namespaces[ns] = [ln.split("/", 1)[1] for ln in out.split() if "/" in ln]

    for sel in watch.get("labels") or []:
        # The selector carries its namespace as a Cilium label (`k8s:io.kubernetes.pod.namespace=x`),
        # which kubectl does not understand — it is a Cilium-side label, not a Kubernetes one. Split
        # it back out: the namespace scopes the query, the rest is the label selector.
        ns, terms = _split_selector(sel)
        args = ["-n", ns] if ns else ["--all-namespaces"]
        command_timeout = _deadline_timeout(deadline)
        if command_timeout is None:
            failures.append("selector membership refresh exceeded its total budget")
            break
        rc, out, err = kubectl(
            args + ["get", "pods", "-l", terms, "-o", "name"],
            timeout_sec=command_timeout,
        )
        if rc != 0:
            failures.append(f"{sel}: {(err or '').strip() or f'kubectl exited {rc}'}")
            continue
        prefix = f"{ns}/" if ns else ""
        labels[sel] = [prefix + ln.split("/", 1)[1] for ln in out.split() if "/" in ln]

    out = {
        # When the cluster was read, not when the beat was sent. Pod membership goes stale in
        # seconds — a runner pod exists for the length of one job — so a count without the time it
        # was true is a number an operator will read as current.
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "namespaces": namespaces,
        "labelled": labels,
    }
    if failures:
        out["detail"] = "; ".join(failures[:5])
    return out


def _split_selector(sel):
    """`k8s:io.kubernetes.pod.namespace=util,app=idp` → `("util", "app=idp")`.

    Returns `(None, sel)` when the selector names no namespace. The renderer refuses such a selector
    for the endpoint it governs, but a *peer* selector reaches this code, and querying every
    namespace is the honest reading of a selector that names none.
    """
    ns = None
    terms = []
    for part in sel.split(","):
        part = part.strip()
        if part.startswith(NS_LABEL + "="):
            ns = part.split("=", 1)[1]
        elif part:
            terms.append(part)
    return ns, ",".join(terms)


def observed_objects(expected, deadline=None):
    """Which of `expected` the cluster actually holds. Returns (present, detail).

    `present` is None when the cluster could not be queried at all — distinct from an empty list,
    which means it was queried and holds none of them. Callers must not treat the first as the
    second: "I could not check" satisfying a check is how a policy governing zero pods passes as
    applied.

    Each object is asked for by name rather than listing the namespace, so an unrelated CNP — flux's,
    or an operator's — can neither satisfy nor break this.
    """
    present = []
    for ref in expected:
        ns, _, name = ref.partition("/")
        command_timeout = _deadline_timeout(deadline)
        if command_timeout is None:
            return None, "workload observation exceeded its total budget"
        rc, _, err = kubectl(
            ["-n", ns, "get", "ciliumnetworkpolicy", name, "-o", "name"],
            timeout_sec=command_timeout,
        )
        if rc == 0:
            present.append(ref)
            continue
        # A NotFound is an answer; anything else means we do not know, and not knowing must not be
        # reported as absence — that would roll back a healthy generation on a transient API error.
        if "not found" in (err or "").lower() or "notfound" in (err or "").lower():
            continue
        return None, f"cannot read {ref}: {(err or '').strip() or f'kubectl exited {rc}'}"
    return present, ""


# ── artifact validation ───────────────────────────────────────────────────────
#
# A strict allowlist. Anything not named here is refused, so an nft feature this agent has never
# heard of cannot arrive as a surprise capability — the failure mode of an unknown construct is a
# refused generation, which is visible, rather than an applied one, which is not.

ALLOWED_VERBS = {"add", "delete"}
ALLOWED_OBJECTS = {"table", "chain", "rule"}
# `forward` joined these on 2026-08-02, and the allowlist is why it had to be a deliberate change.
#
# It was added because "heliopause is the only firewall" is false on a router until forward is
# filtered: measured on three gateways, firewalld was refusing `public interface → VPC` and
# `public interface → wireguard` while heliopause filtered neither. Retiring firewalld there without
# this would have opened a path from the provider's shared public segment into the VPC and into the
# mesh — with every host's `input` rules still correct, and the exposure one hop upstream of
# anything they could report.
#
# The risk it adds is real and asymmetric: a wrong `input` rule breaks the host holding it, and a
# wrong `forward` rule breaks traffic belonging to machines *behind* it, which cannot be diagnosed
# from the host and does not show up in its own reachability checks. The renderer keeps this chain
# fixed and small for that reason (see `ForwardConfig`), and this list is what stops a forward chain
# arriving on a host whose agent was never meant to apply one.
ALLOWED_HOOKS = {"input", "output", "forward"}
ALLOWED_CHAIN_TYPES = {"filter"}


def validate_artifact(text):
    """Check an artifact is safe to apply. Returns (doc, reason); doc is None when refused."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        return None, f"artifact is not valid JSON: {e}"
    if not isinstance(doc, dict) or not isinstance(doc.get("nftables"), list):
        return None, "artifact is not an nft JSON document"
    commands = doc["nftables"]
    if not commands:
        return None, "artifact contains no commands"

    for i, cmd in enumerate(commands):
        where = f"command {i}"
        if not isinstance(cmd, dict) or len(cmd) != 1:
            return None, f"{where}: expected exactly one verb"
        verb, payload = next(iter(cmd.items()))
        if verb not in ALLOWED_VERBS:
            # `flush` is refused here rather than special-cased. `flush ruleset` would clear every
            # table on the host, and there is no operation this agent performs that needs it —
            # the table is replaced by delete-then-add, which is scoped to us.
            return None, f"{where}: verb {verb!r} is not permitted"
        if not isinstance(payload, dict) or len(payload) != 1:
            return None, f"{where}: expected exactly one object under {verb!r}"
        kind, obj = next(iter(payload.items()))
        if kind not in ALLOWED_OBJECTS:
            return None, f"{where}: object {kind!r} is not permitted"
        if not isinstance(obj, dict):
            return None, f"{where}: {kind} is not an object"

        family = obj.get("family")
        if family != TABLE_FAMILY:
            return None, f"{where}: {kind} targets family {family!r}, not {TABLE_FAMILY!r}"
        # A table names itself; chains and rules name the table they live in.
        owner = obj.get("name") if kind == "table" else obj.get("table")
        if owner != TABLE_NAME:
            return None, f"{where}: {kind} targets table {owner!r}, not {TABLE_NAME!r}"

        if kind == "chain" and "hook" in obj:
            hook = obj.get("hook")
            if hook not in ALLOWED_HOOKS:
                # `forward` would put us in the path of routed traffic — containers, VMs, anything
                # this host gateways for. `prerouting`/`postrouting` with a nat type would rewrite
                # addresses. Neither is in scope, and both break things this agent does not own.
                return None, f"{where}: hook {hook!r} is not permitted"
            ctype = obj.get("type")
            if ctype not in ALLOWED_CHAIN_TYPES:
                return None, f"{where}: chain type {ctype!r} is not permitted"

    return doc, ""


# ── ruleset snapshots ─────────────────────────────────────────────────────────


def _is_ours(element):
    obj = next(iter(element.values()), {})
    if not isinstance(obj, dict):
        return False
    if obj.get("family") != TABLE_FAMILY:
        return False
    owner = obj.get("name") if "table" in element else obj.get("table")
    return owner == TABLE_NAME


def _without_nft_runtime(value):
    """Remove dump-only identifiers while preserving the enforced ruleset shape."""
    if isinstance(value, list):
        return [_without_nft_runtime(item) for item in value]
    if isinstance(value, dict):
        # Handles/indices are allocation details and packet/byte values are live state. Keeping any
        # of them would report drift after a semantically identical re-apply or every packet.
        return {
            key: _without_nft_runtime(item)
            for key, item in value.items()
            if key not in {"handle", "index", "packets", "bytes"}
        }
    return value


def _observed_digest(ours):
    canonical = json.dumps(
        _without_nft_runtime(ours), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _comments_in_elements(elements):
    return {
        rule["comment"]
        for item in elements
        if isinstance(item, dict)
        for rule in [item.get("rule")]
        if isinstance(rule, dict) and isinstance(rule.get("comment"), str)
    }


def snapshot():
    """Split the whole ruleset into (ours, everyone else's). Returns (ours, others, detail).

    Structured rather than textual because the comparison this feeds decides whether to revert.
    Diffing `nft list ruleset` text would make whitespace and ordering churn indistinguishable
    from a real change, and an alarm that cries wolf gets muted.
    """
    elements, detail = nft_json(["-s", "list", "ruleset"])
    if elements is None:
        return None, None, detail
    ours, others = [], []
    for e in elements:
        if not isinstance(e, dict) or "metainfo" in e:
            continue
        (ours if _is_ours(e) else others).append(e)
    return ours, others, ""


def present_comments():
    """Rule comments currently in our table. Returns (set, detail); set is None on failure."""
    elements, detail = nft_json(["-s", "list", "table", TABLE_FAMILY, TABLE_NAME])
    if elements is None:
        return None, detail
    out = set()
    for e in elements:
        rule = e.get("rule") if isinstance(e, dict) else None
        if isinstance(rule, dict) and isinstance(rule.get("comment"), str):
            out.add(rule["comment"])
    return out, ""


def missing_assertions(expected):
    """Which required rules are not in the kernel. Returns (list, detail); list is None on failure.

    The heartbeat that confirms an apply proves the path *to the relay* survived — it is evidence
    that arrives by arriving. It says nothing about SSH. A ruleset that keeps the relay reachable
    while dropping the management baseline would confirm cleanly and still take the host away from
    whoever has to fix it.
    """
    if not expected:
        return [], ""
    have, detail = present_comments()
    if have is None:
        return None, detail
    return [c for c in expected if c not in have], ""


def local_addrs():
    """Addresses configured on this host. Returns (set, detail); set is None on failure.

    Read from `ip -j addr` rather than by resolving our own hostname: DNS can be stale, absent, or
    point at an address we no longer hold, and the question here is what this kernel has bound.
    """
    try:
        p = subprocess.run(
            ["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=NFT_TIMEOUT_SEC, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"cannot run ip addr: {e}"
    if p.returncode != 0:
        return None, (p.stderr or f"ip exited {p.returncode}").strip()
    try:
        links = json.loads(p.stdout)
    except ValueError as e:
        return None, f"ip produced unparseable JSON: {e}"
    out = set()
    for link in links:
        for info in link.get("addr_info", []) or []:
            addr = info.get("local")
            if isinstance(addr, str):
                out.add(addr)
    return out, ""


def wrong_addresses(expected):
    """Whether the policy targets an address this host does not hold. Returns (bad, detail).

    `bad` is None on failure to determine, [] when fine, else the expected addresses — meaning the
    ruleset was written for a different machine than the one applying it.

    ## Why this exists

    A site module resolves each host to an address and renders `ip daddr <addr>` matches from it.
    Nothing between there and here checks the host still answers on that address. When it changes,
    the publish succeeds, the rules render cleanly, `missing_assertions` passes — the baseline
    comments are all present — and every service rule matches traffic that will never arrive.

    Measured: mailer-01 rebooted, a NetworkManager profile conflict left it on 10.17.0.5 while
    policy/dev.ts still said 10.17.101.12, and nothing anywhere reported a problem. Under an
    accepting chain policy that cost nothing. Under default-deny it is every mail port refused
    while the control plane reports the host as confirmed.

    **Any** match is enough, not all. A host legitimately has several addresses and a generation may
    name only one of them; requiring all would refuse correct rulesets. What is being caught is the
    ruleset naming *none* of this host's addresses, which cannot be right.
    """
    if not expected:
        return [], ""
    have, detail = local_addrs()
    if have is None:
        return None, detail
    if have & set(expected):
        return [], ""
    return list(expected), ""


def restore_commands(elements):
    """Turn snapshot elements back into `add` commands. Verified round-trip against real nft."""
    return {"nftables": [{"add": e} for e in elements]}


# ── routes ──────────────────────────────────────────────────────────────────────────
#
# A packet reaches a filter only if routing sent it there, and heliopause now declares routes as well
# as rules. This is the half that writes them.
#
# ## Why this rides the ruleset's timer instead of getting its own
#
# A bad route and a bad ruleset fail the same way: the management path goes, the heartbeat stops, and
# the deadline puts everything back. Two timers would mean two ways to end up half restored -- a
# ruleset reverted while a route that severed the path stayed, or the reverse. So routes are applied
# inside the ruleset's transaction, recorded in the same durable commitment, and undone by the same
# `_restore`. The workload half has its own timer for the opposite reason: a CNP cannot cut SSH.
#
# ## What this refuses, in code
#
# The declaration is reviewed by a person and approved by a second one, and that is still not a reason
# to let this function run anything it is handed. Each refusal below is a class of route whose failure
# removes the way back rather than merely breaking traffic:
#
#   the default route      the host's only path to everything it has no specific route for
#   a prefix shorter       the same thing wearing a different mask -- /0.. /7 covers the internet
#     than /8
#   a table other          a non-main table is consulted only if a rule points at it. Applying to one
#     than main            nothing references is a no-op that looks like control
#   neither via nor dev    `ip` would reject it; saying so here names the mistake
#   a route covering       replacing the route that carries the heartbeat is the one action whose
#     the relay            failure takes away the mechanism that would undo it. The timer would still
#                          fire, but recovering in sixty seconds is worse than not doing it
#
# `ip route replace` rather than `add`: the declaration names where a destination must point, and a
# route that exists with the wrong next hop is the case worth fixing. `replace` also makes a repeat
# apply a no-op, which matters because every generation re-applies.
#
# **Nothing is ever deleted.** heliopause installs what it owns and does not remove what it does not
# -- see `RouteOwner` in the policy. Rollback deletes only destinations this process created.

ROUTE_TIMEOUT_SEC = 10

# The refusals above, as one list so the reasons are readable and testable together.
ROUTE_DEFAULT_DSTS = frozenset({"default", "0.0.0.0/0", "::/0"})
ROUTE_MIN_PREFIX = 8


def _relay_host():
    """The relay's host part, or "" when it cannot be read. Used only to refuse a route over it."""
    try:
        return urllib.parse.urlsplit(RELAY_URL).hostname or ""
    except ValueError:
        return ""


def _route_refusal(spec, relay=None, guard=()):
    """Why this declared route must not be applied, or None when it may be.

    Pure, so every refusal is testable without a kernel. `relay` and `guard` are injectable for the
    same reason.

    `guard` is the management baseline's source ranges, sent in the manifest as `routeGuard`. It is
    the routing half of `mustContain`: a heartbeat proves the **relay** path survived and says
    nothing about the operator's, so a route that redirects the management range locks everybody out
    and then confirms cleanly. The deadline would never fire, because nothing it can see broke.
    """
    dst = str(spec.get("dst") or "")
    if not dst:
        return "a route with no destination"
    if dst in ROUTE_DEFAULT_DSTS:
        return f"{dst} is the default route, and replacing it can remove every path off this host"
    table = str(spec.get("table") or "main")
    if table != "main":
        return f"table {table} is not main; a table no rule points at is a no-op that looks like control"
    via, dev = str(spec.get("via") or ""), str(spec.get("dev") or "")
    if not via and not dev:
        return f"{dst} names neither a next hop nor an interface"
    try:
        net = ipaddress.ip_network(dst, strict=False)
    except ValueError:
        return f"{dst} is not a network"
    if net.prefixlen < ROUTE_MIN_PREFIX:
        return f"{dst} is wider than /{ROUTE_MIN_PREFIX}, which is a default route under another name"
    relay = _relay_host() if relay is None else relay
    if relay:
        try:
            if ipaddress.ip_address(relay) in net:
                return f"{dst} covers the relay at {relay}, and replacing it would remove the way back"
        except ValueError:
            # A relay named by DNS rather than by address. Nothing to compare, and resolving here would
            # make a refusal depend on a lookup that can answer differently than the kernel's routing.
            pass
    for entry in guard or ():
        try:
            protected = ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            # A guard entry that will not parse is itself a finding, and refusing on it would let a
            # typo in the baseline block every route. Skipped, and the manifest that carried it is
            # reviewed by two people.
            continue
        if protected.version != net.version:
            continue
        # **Overlap, not containment.** A route wider than the guard swallows it; a route narrower
        # redirects part of it. Both take management away, and only one of them is caught by asking
        # whether the guard contains the route.
        if net.overlaps(protected):
            return (
                f"{dst} overlaps the management range {protected}, and the heartbeat cannot see that "
                f"path -- it would confirm while every operator was locked out"
            )
    return None


def _route_args(spec):
    """`ip route` arguments for one declared route, in a fixed order so two reads compare."""
    out = [str(spec.get("dst"))]
    if spec.get("via"):
        out += ["via", str(spec.get("via"))]
    if spec.get("dev"):
        out += ["dev", str(spec.get("dev"))]
    return out


def _route_present(spec, observed):
    """True when `observed` already holds this exact route. Decides whether anything is written."""
    table = str(spec.get("table") or "main")
    for r in observed or []:
        if r.get("dst") != spec.get("dst") or str(r.get("table") or "main") != table:
            continue
        if spec.get("via") and r.get("via") != spec.get("via"):
            continue
        if spec.get("dev") and r.get("dev") != spec.get("dev"):
            continue
        return True
    return False


def _route_prior(spec, observed):
    """The route currently occupying this destination, or None.

    What rollback puts back. `None` means the destination was empty, which restores by deleting -- the
    same two-valued distinction `_backup` needed, and the same trap: conflating "nothing was there"
    with "we did not look" deletes a route this process never took responsibility for. Here the caller
    only ever passes an observation it actually made.
    """
    table = str(spec.get("table") or "main")
    for r in observed or []:
        if r.get("dst") == spec.get("dst") and str(r.get("table") or "main") == table:
            return {"dst": r.get("dst"), "via": r.get("via") or "", "dev": r.get("dev") or "", "table": table}
    return None


def _ip_route(args):
    """Run one `ip route` command. Returns (rc, stderr)."""
    try:
        proc = subprocess.run(
            ["ip", "route"] + args,
            capture_output=True, text=True, timeout=ROUTE_TIMEOUT_SEC, check=False,
        )
        return proc.returncode, (proc.stderr or "").strip()
    except FileNotFoundError:
        return 127, "ip not found"
    except subprocess.TimeoutExpired:
        return 124, f"ip route timed out after {ROUTE_TIMEOUT_SEC}s"


def plan_routes(specs, observed, relay=None, guard=()):
    """Split declared routes into (to_write, prior, refused).

    Pure. `to_write` are the ones not already present, `prior` is what each of those destinations held
    so rollback can put it back, and `refused` carries a reason per route. Separated from the writing
    so the decisions can be tested against a real route table with no kernel involved.
    """
    to_write, prior, refused = [], [], []
    for spec in specs or []:
        if not isinstance(spec, dict):
            refused.append(("(not an object)", "route is not an object"))
            continue
        why = _route_refusal(spec, relay=relay, guard=guard)
        if why:
            refused.append((str(spec.get("dst") or "?"), why))
            continue
        if _route_present(spec, observed):
            continue
        to_write.append(spec)
        prior.append(_route_prior(spec, observed))
    return to_write, prior, refused


def apply_routes(specs, observed, relay=None, guard=()):
    """Write the declared routes. Returns (ok, restore, detail).

    `restore` is what `_restore_routes` needs in order to undo exactly what this call did -- recorded
    per route, in the order written, so a partial apply reverts to the state it started from rather
    than to a guess.
    """
    to_write, prior, refused = plan_routes(specs, observed, relay=relay, guard=guard)
    if refused:
        # Refusing is a refused generation, not a warning. A route the policy declared and this agent
        # decided not to write is a difference between what was approved and what is running, and this
        # project's whole shape says that must be loud.
        return False, [], "; ".join(f"{dst}: {why}" for dst, why in refused)
    restore = []
    for spec, before in zip(to_write, prior):
        rc, err = _ip_route(["replace"] + _route_args(spec))
        if rc != 0:
            return False, restore, f"ip route replace {' '.join(_route_args(spec))} failed: {err}"
        # Recorded after the write succeeded, so nothing claims to be undoable that was not done.
        restore.append({"spec": spec, "before": before})
    if to_write:
        log(f"routes: wrote {len(to_write)} of {len(specs)} declared")
    return True, restore, ""


def _restore_routes(restore):
    """Undo what `apply_routes` did, newest first. Returns (ok, detail)."""
    if not restore:
        return True, "no routes to restore"
    problems = []
    for item in reversed(restore):
        spec, before = item.get("spec") or {}, item.get("before")
        if before is None:
            # The destination was empty before, so putting it back means removing what we added.
            rc, err = _ip_route(["del"] + _route_args(spec))
            # An absent route is the desired end state, so a delete that finds nothing is a success.
            if rc != 0 and "No such process" not in err:
                problems.append(f"del {spec.get('dst')}: {err}")
        else:
            rc, err = _ip_route(["replace"] + _route_args(before))
            if rc != 0:
                problems.append(f"replace {before.get('dst')}: {err}")
    if problems:
        return False, "route restore incomplete: " + "; ".join(problems)
    return True, f"restored {len(restore)} route(s)"


# ── apply / rollback ──────────────────────────────────────────────────────────
#
# `_apply_lock` guards the backup, timer and kernel write together. The write is bounded by
# `NFT_TIMEOUT_SEC`; serialising it with restore is essential because a timer that restores first
# followed by a late nft commit would leave the unconfirmed table live after reporting rolled-back.

_apply_lock = threading.Lock()
_timer = None
# A failed rollback must not be heartbeat-confirmed merely because persisting its internal
# `rollback-failed` marker also failed.  The durable commitment makes a restart safe; this marker
# closes the in-process window until the idempotent retry has both restored and fsynced the result.
_nft_rollback_owed = None

# Distinct from None. `None` means "we captured a backup and there was no table at the time",
# which restores by deleting. `_NO_BACKUP` means "we have not captured anything" — nothing to
# restore, and restoring anyway would delete a table we never took responsibility for.
#
# These were the same value at first, and the bug that hides there is quiet: a second rollback
# reads the already-consumed backup as "there was no table" and deletes the live ruleset. It is
# not reachable through today's call paths, but two states sharing one value is the kind of thing
# that becomes reachable the moment someone adds a caller.
_NO_BACKUP = object()
_backup = _NO_BACKUP  # list of elements | None (no table existed) | _NO_BACKUP (nothing captured)

# What routes to put back, in the shape `_restore_routes` consumes: `[{"spec", "before"}]`.
#
# A plain list rather than a three-valued sentinel like `_backup` needs, because an empty plan and
# "we did not look" mean the same thing here -- nothing was written, so nothing has to be undone.
# The dangerous conflation `_NO_BACKUP` exists for does not arise: this list only ever contains
# destinations this process is about to write, each carrying what that destination held first.
_route_restore = []


# ── surviving our own death ───────────────────────────────────────────────────
#
# The timer above lives in this process, and under `nohup` — how this was first proven — that was
# enough, because nothing restarted the process. Under systemd with `Restart=always` it is not:
#
#   1. apply a ruleset that severs the management path; arm the timer; record `pending`
#   2. the process dies before the timer fires — OOM on a 948MB host, or a deploy restart
#   3. systemd starts a fresh process. The timer and the backup were in memory. Both are gone.
#   4. the path is severed, so every heartbeat fails, so the code that would notice never runs
#
# The host stays locked out forever, holding `pending` on disk, which is the exact outcome this
# whole design exists to prevent. Restarting the agent must not be able to cause it.
#
# So the commitment goes to disk **before** the kernel is touched: what to put back, and the
# absolute time by which the apply must have been confirmed. Absolute rather than remaining, so a
# crash loop re-arming on every start cannot postpone the deadline indefinitely.


def _persist_commitment(backup, deadline, generation=None, artifact_hash=None):
    """Record what to restore and when, before the apply that would need it."""
    def mutate(st):
        # `prepared` means the side effect may not have happened yet and must never be heartbeat-
        # confirmed. Only successful apply + local verification advances this to `pending`.
        st["state"] = "prepared"
        if generation is not None:
            st["generation"] = generation
        if artifact_hash is not None:
            st["artifactHash"] = artifact_hash
        st["detail"] = None
        st["pendingBackup"] = None if backup is _NO_BACKUP else {"elements": backup}
        st["rollbackAt"] = deadline

    _, saved = update_state(mutate)
    return saved


def _persist_route_commitment(plan):
    """Record what to put back for the routes about to be written, before writing any of them.

    Separate from `_persist_commitment` because the plan cannot be known until the ruleset has been
    applied and verified -- it is computed against the route table as it is at that moment. The
    discipline is the same one and it is the whole reason this host can be restarted mid-apply: what
    to undo reaches the disk before the thing that would need undoing happens.

    Persisting the **whole** plan up front rather than each route as it is written is deliberate and
    it is safe because every entry is idempotent in both directions. An entry whose write never
    happened restores by replacing a route with itself, or by deleting a destination that is already
    absent -- and `_restore_routes` treats "no such process" as the desired end state.
    """
    def mutate(st):
        st["pendingRoutes"] = plan

    _, saved = update_state(mutate)
    return saved


def _clear_commitment(st):
    """Drop the commitment. The apply is settled — confirmed or reverted — either way it is spent."""
    st["pendingBackup"] = None
    st["pendingRoutes"] = None
    st["rollbackAt"] = None


def recover_commitment():
    """Re-arm or fire a rollback left behind by a previous process. Called once, before heartbeating.

    This runs before the first heartbeat on purpose. If the previous process applied a ruleset that
    cut the relay path, heartbeating first would just block for the HTTP timeout, and the deadline
    it should be honouring might already have passed.
    """
    global _backup, _timer
    st = load_state()
    if st["state"] not in {"prepared", "pending", "rollback-failed"}:
        return

    saved = st.get("pendingBackup")
    if not isinstance(saved, dict):
        # A pending apply with nothing recorded to undo it: a state file written by an agent older
        # than this mechanism, or one that lost the field. All we know is that an unconfirmed
        # ruleset is live. Deleting our own table returns the host to the state it had before
        # heliopause ever touched it — which is reachable, and reachable is the whole objective.
        # It also means this host now has no policy at all, which `rolled-back` is meant to shout
        # about; recovery is a new generation, decided by a human.
        log("recovery: pending apply with no recorded backup — removing our table")
        _backup = None
        rollback("restarted with an unconfirmed apply and no recorded backup")
        return

    _backup = saved.get("elements")
    # The route plan travels with the ruleset backup and is recovered the same way. Without this a
    # restart would restore the table and leave a route that may be the reason the host is silent --
    # the half-restored state that keeping one timer was supposed to make impossible.
    recovered_routes = st.get("pendingRoutes")
    globals()["_route_restore"] = recovered_routes if isinstance(recovered_routes, list) else []
    if st["state"] in {"prepared", "rollback-failed"}:
        # Crash before the durable post-verify transition: the kernel may hold either the old or the
        # new table. Restoring the captured backup is idempotent in both cases and avoids confirming
        # an apply that may never have executed.
        phase = st["state"]
        log(f"recovery: {phase} nft commitment requires restore before heartbeat")
        rollback(
            "restarted before nft apply was durably verified"
            if phase == "prepared" else "retrying an incomplete nft rollback after restart"
        )
        return
    deadline = st.get("rollbackAt")
    remaining = (deadline - time.time()) if isinstance(deadline, (int, float)) else 0
    if remaining <= 0:
        log(f"recovery: confirm deadline passed {-remaining:.0f}s ago while we were not running")
        rollback("confirmation timed out while the agent was not running")
        return

    with _apply_lock:
        _timer = threading.Timer(
            remaining, rollback_generation,
            args=("nft confirmation timed out", st.get("generation"), "host", deadline),
        )
        _timer.daemon = True
        _timer.start()
    log(f"recovery: {st['generation']} was unconfirmed — rollback re-armed for {remaining:.0f}s")


def _nft_apply_json(doc):
    """Apply a JSON document. Records the child PID so the monitor can attribute the change to us."""
    payload = json.dumps(doc)
    try:
        proc = subprocess.Popen(
            [NFT, "-j", "-f", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as e:
        return 127, f"cannot execute {NFT}: {e}"
    # Recorded before waiting. The monitor can observe the change while nft is still running, and
    # an event that arrives before we know the PID would be misfiled as an intrusion.
    _remember_our_pid(proc.pid)
    try:
        out, err = proc.communicate(payload, timeout=NFT_TIMEOUT_SEC)
        return proc.returncode, (err or out).strip()
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return 124, f"nft timed out after {NFT_TIMEOUT_SEC}s"


def _restore(backup):
    """Put our table back the way it was. Never gated — blocking the way back is how you stay out."""
    if backup is _NO_BACKUP:
        # Nothing was captured, so there is nothing to put back. Deleting here would destroy a
        # ruleset this call never took responsibility for.
        return True, "nothing to restore"
    rc, err = _nft_apply_json({"nftables": [{"delete": {"table": {"family": TABLE_FAMILY, "name": TABLE_NAME}}}]})
    delete_ok = rc == 0 or "No such file" in err
    if not delete_ok:
        return False, f"rollback failed to remove current table: {err}"
    if backup is None:
        return True, "restored to: no table"
    rc, err = _nft_apply_json(restore_commands(backup))
    if rc != 0:
        return False, f"rollback failed to restore previous table: {err}"
    return True, "restored previous table"


def rollback(reason, expected_generation=None):
    global _timer, _backup, _nft_rollback_owed, _route_restore
    with _apply_lock:
        durable = load_state()
        if expected_generation is not None:
            if durable.get("state") not in {"prepared", "pending", "rollback-failed"} or durable.get("generation") != expected_generation:
                log(
                    f"ignoring stale nft rollback for {expected_generation}: durable state is "
                    f"{durable.get('generation')}/{durable.get('state')}"
                )
                # A callback from an older commitment may have been waiting on this lock while a
                # new apply armed its own timer. Never clear the new timer or consume its backup.
                return None
        generation = expected_generation or durable.get("generation")
        _nft_rollback_owed = generation
        if _timer is not None:
            _timer.cancel()
            _timer = None
        backup, _backup = _backup, _NO_BACKUP
        route_plan, _route_restore = _route_restore, []
        # Keep a new apply from starting between consuming this backup and recording that it was
        # consumed. The apply path never holds this lock across nft, so a wedged apply cannot keep
        # rollback out; only this bounded restore transaction is serialised.
        ok, detail = _restore(backup)
        # Routes after the ruleset, and both must succeed for this rollback to be spent. Reporting
        # `rolled-back` with a route still in place would say the host was returned to a state it is
        # not in -- and the route is the half that decides whether the ruleset is even consulted.
        route_ok, route_detail = _restore_routes(route_plan)
        if not route_ok:
            ok = False
        if route_plan:
            detail = f"{detail}; {route_detail}"
        log(f"ROLLBACK ({reason}): {detail}")

        def mutate(st):
            st["detail"] = f"{reason}: {detail}"
            st["referenceHash"] = None
            if ok:
                st["state"] = "rolled-back"
                _clear_commitment(st)
            else:
                # A transient nft failure must not spend the only copy of the way back. Retrying
                # delete+restore is idempotent, and startup recognises this internal state before it
                # sends a heartbeat. The wire maps it to rolled-back so the manager never treats it
                # as confirmable.
                st["state"] = "rollback-failed"
                st["pendingBackup"] = None if backup is _NO_BACKUP else {"elements": backup}
                # Kept for the same reason as the backup above: a transient `ip` failure must not
                # spend the only record of how to put the routes back.
                st["pendingRoutes"] = route_plan
                st["rollbackAt"] = time.time() + ROLLBACK_RETRY_SEC

        _, saved = update_state(mutate)
        if not ok or not saved:
            _backup = backup
            _route_restore = route_plan
            generation = expected_generation
            if generation is None:
                generation = load_state().get("generation")
            _timer = threading.Timer(
                ROLLBACK_RETRY_SEC,
                rollback,
                args=("retrying incomplete nft rollback", generation),
            )
            _timer.daemon = True
            _timer.start()
            if not saved:
                log("cannot persist nft rollback result; durable commitment retained for retry")
            return False
        _nft_rollback_owed = None
    return True


def _preflight_host_artifact(artifact):
    """Side-effect-free host validation shared by cross-layer ordering and the actual apply."""
    text = artifact.get("ruleset") or ""
    if not isinstance(text, str):
        return None, None, "artifact refused: ruleset must be text"
    doc, reason = validate_artifact(text)
    if doc is None:
        return None, None, f"artifact refused: {reason}"

    expected = artifact.get("rulesetHash")
    actual = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    if not isinstance(expected, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        return None, None, "artifact refused: rulesetHash is missing or malformed"
    if expected != actual:
        # The relay serves what the manager published; a mismatch means one of them is not what we
        # think it is. Applying anyway would enforce a ruleset nobody signed off on.
        return None, None, f"artifact digest {actual} does not match published {expected}"

    generation = artifact.get("generation")
    if not isinstance(generation, str) or not generation or len(generation) > 253:
        return None, None, "artifact refused: generation is empty, non-text or overlong"

    # Before the kernel is touched, not after. A ruleset written for a different machine's address is
    # not something to apply and then revert — under default-deny, applying it means every service
    # rule matches traffic that never arrives, and the rollback timer would not fire because the
    # relay stays reachable through the baseline. Refusing keeps whatever is currently live in place.
    bad, detail = wrong_addresses(artifact.get("expectAddrs") or [])
    if bad is None:
        # Could not read our own interfaces. Treated as a refusal rather than waved through: this is
        # a check on whether the artifact is for us at all, and guessing "probably" is how the
        # measured failure got as far as it did.
        return None, None, f"cannot determine this host's addresses: {detail}"
    if bad:
        return None, None, (
            f"artifact targets {', '.join(bad)}, which this host does not hold — "
            f"the policy was written for a different address. Nothing applied."
        )

    timeout, reason = _parse_timeout(
        artifact.get("confirmTimeoutSec"), NFT_CONFIRM_MIN_SEC,
        NFT_CONFIRM_MIN_SEC, NFT_CONFIRM_MAX_SEC,
        "confirmTimeoutSec",
    )
    if timeout is None:
        return None, None, f"artifact refused: {reason}"
    return doc, timeout, ""


def apply_artifact(artifact, validated=None):
    """Validate, apply, verify nothing else moved, and arm rollback. Returns (ok, state, detail)."""
    global _timer, _backup

    if validated is None:
        doc, timeout, reason = _preflight_host_artifact(artifact)
    else:
        doc, timeout = validated
        reason = ""
    if doc is None:
        return False, "unsupported", reason

    ours_before, others_before, detail = snapshot()
    if others_before is None:
        return False, "rolled-back", f"cannot snapshot ruleset before apply: {detail}"

    deadline = time.time() + timeout
    with _apply_lock:
        if _timer is not None or _nft_rollback_owed is not None:
            # A second apply while the first is unconfirmed would overwrite the backup and leave
            # no way back to a known-good state.
            return False, "pending", "an apply is already awaiting confirmation"
        _backup = ours_before if ours_before else None

        # Written and armed before the kernel is touched. Persisting the absolute deadline but
        # creating `Timer(timeout)` only after validation quietly extends the promise by however
        # long apply/verification took; a live process must honour the same time as a restarted one.
        if not _persist_commitment(
            _backup, deadline, artifact.get("generation"), artifact.get("rulesetHash")
        ):
            _backup = _NO_BACKUP
            return False, "rolled-back", "cannot persist rollback commitment; kernel was not changed"
        remaining = deadline - time.time()
        if remaining <= 0:
            _backup = _NO_BACKUP

            def expire(st):
                st["state"] = "rolled-back"
                st["detail"] = "confirmation deadline elapsed while persisting rollback commitment"
                _clear_commitment(st)

            update_state(expire)
            return False, "rolled-back", "confirmation deadline elapsed before kernel apply"
        _timer = threading.Timer(
            remaining, rollback_generation,
            args=(
                "nft confirmation timed out", artifact.get("generation"), "host", deadline,
            ),
        )
        _timer.daemon = True
        _timer.start()

    # Serialise the kernel transaction with restore. If the deadline fires while nft is still
    # running, rollback waits for this bounded subprocess and then removes what it committed. With
    # no lock here, restore can win first and a late nft commit can reinstall an unconfirmed table.
    with _apply_lock:
        if _timer is None:
            return False, "rolled-back", "confirmation deadline elapsed before kernel apply"
        rc, err = _nft_apply_json(doc)
    if rc != 0:
        failure_detail = f"nft rejected the ruleset, nothing changed: {err}"
        # Use the same captured-backup path as every other failure. Merely clearing the commitment
        # leaves a crash window in which durable state says prepared/pending with no backup.
        rollback(failure_detail)
        return False, "rolled-back", failure_detail

    ours_after, others_after, detail = snapshot()
    if others_after is None:
        rollback(f"cannot verify ruleset after apply: {detail}")
        return False, "rolled-back", f"cannot snapshot ruleset after apply: {detail}"

    if others_after != others_before:
        # Structural validation should have made this impossible, which is exactly why it is
        # checked: reaching here means the allowlist has a hole. Our own table is restored and the
        # generation refused. Other tables are deliberately **not** auto-repaired — re-creating
        # someone else's firewall from a snapshot is a larger and riskier action than the one that
        # caused the problem, and this needs a human either way.
        rollback("apply modified tables outside ours")
        return False, "rolled-back", "artifact changed tables outside ours — refused, see journal"

    # A ruleset missing its own management path is undone immediately rather than waiting for the
    # already-armed deadline. Waiting would leave the host unreachable despite knowing the answer.
    required = artifact.get("mustContain") or []
    if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
        rollback("mustContain is not an array of rule comments")
        return False, "rolled-back", "mustContain is not an array of rule comments"
    have = _comments_in_elements(ours_after)
    missing = [comment for comment in required if comment not in have]
    if missing:
        rollback(f"required rules absent after apply: {', '.join(missing)}")
        return False, "rolled-back", f"required rules absent after apply: {', '.join(missing)}"
    reference_hash = _observed_digest(ours_after)

    # ── the declared routes ───────────────────────────────────────────────────
    #
    # After the ruleset is applied and verified, and before `pending` -- which is what a heartbeat
    # confirms. A route written before the ruleset was known good would be undone by a path that had
    # not yet proved it works; a route written after confirmation would be outside the deadline that
    # exists to take it back.
    #
    # `manifest.routes` carries only what heliopause owns (see `ManifestEntry.routes`), so there is no
    # filtering to get wrong here. Absent means apply nothing, which is every host today.
    declared = artifact.get("routes") or []
    # Absent means no protected range was stated, and that is refused rather than treated as "none
    # to protect": a manifest that ships routes without a guard is one that lost the field, and the
    # difference between "nothing is protected" and "we did not say" is the whole lesson of this
    # file. A site with an empty baseline is a real configuration and `config.ts` already refuses to
    # start with it when the input hook drops.
    guard = artifact.get("routeGuard")
    # `not guard` rather than `not isinstance(guard, list)`. The old test accepted `[]`, and `[]` is
    # exactly what `managementGuard` returns for a baseline whose entries name no source — which is
    # what this site's baseline looks like. So the check that was meant to refuse "routes with no
    # stated protection" accepted the one shape that actually produces none.
    #
    # The signer refuses an empty guard too. Both ends, because one of them being replaced is the
    # case this whole path exists for.
    if declared and (not isinstance(guard, list) or not guard):
        rollback("routes were shipped without a management guard")
        return False, "rolled-back", "routes were shipped without a management guard"
    if declared:
        observed = observed_routes()
        if observed is None:
            # Cannot read the table, so cannot know what to put back. Writing anyway would install a
            # route with no recorded way to undo it, which is the one thing this whole mechanism is
            # built to prevent.
            rollback("cannot read the route table, so declared routes cannot be applied safely")
            return False, "rolled-back", "cannot read the route table before applying routes"
        to_write, prior, refused = plan_routes(declared, observed, guard=guard)
        if refused:
            reasons = "; ".join(f"{dst}: {why}" for dst, why in refused)
            rollback(f"refused a declared route: {reasons}")
            return False, "rolled-back", f"refused a declared route: {reasons}"
        if to_write:
            plan = [{"spec": s, "before": b} for s, b in zip(to_write, prior)]
            if not _persist_route_commitment(plan):
                rollback("cannot persist the route rollback plan")
                return False, "rolled-back", "cannot persist the route rollback plan"
            with _apply_lock:
                if _timer is None:
                    return False, "rolled-back", "confirmation deadline elapsed before routes"
                # Armed before the write, so a crash between the two still has the plan on disk and
                # `recover_commitment` puts it back.
                globals()["_route_restore"] = plan
                route_ok, written, route_detail = apply_routes(declared, observed, guard=guard)
                # What actually landed replaces the plan, so rollback undoes exactly that. A partial
                # apply keeps the entries it managed to write and drops the ones it never reached.
                globals()["_route_restore"] = written
            if not route_ok:
                rollback(f"route apply failed: {route_detail}")
                return False, "rolled-back", f"route apply failed: {route_detail}"

    expired = False
    pending_failed = False
    with _apply_lock:
        if _timer is None:
            return False, "rolled-back", "confirmation deadline elapsed during apply"
        remaining = deadline - time.time()
        if remaining <= 0:
            _timer.cancel()
            _timer = None
            expired = True
        else:
            def mark_pending(st):
                if st.get("generation") != artifact.get("generation") or st.get("state") != "prepared":
                    raise RuntimeError("nft commitment changed before verification completed")
                st["state"] = "pending"
                # Pin the exact post-apply dump. A TTL cache may still contain the previous
                # generation; confirmation must never turn that stale value into this generation's
                # drift baseline.
                st["referenceHash"] = reference_hash

            try:
                _, saved = update_state(mark_pending)
                pending_failed = not saved
            except RuntimeError:
                pending_failed = True
    if expired:
        rollback("confirmation deadline elapsed during apply")
        return False, "rolled-back", "confirmation deadline elapsed during apply"
    if pending_failed:
        rollback("cannot persist verified nft pending state")
        return False, "rolled-back", "cannot persist verified nft pending state"
    _invalidate_host_observation()
    log(f"applied generation {artifact.get('generation')}, rollback armed for {remaining:.0f}s")
    return True, "pending", ""


def confirm(state):
    """Cancel the rollback timer. Called when a heartbeat lands while an apply is pending."""
    global _timer, _backup
    # This heartbeat has already reached the relay, which is the confirmation evidence. The drift
    # baseline was captured from the verified post-apply snapshot before `pending` became durable;
    # never replace it with a potentially stale telemetry cache value here.
    if not isinstance(state.get("referenceHash"), str):
        log("cannot confirm nft apply without a durable post-apply observation; rollback remains armed")
        return False
    with _apply_lock:
        if _nft_rollback_owed is not None:
            log("cannot confirm nft apply while an incomplete rollback is owed")
            return False
        if _timer is None:
            return False
        # Commit the settled state before disarming the only in-process recovery path. If fsync or
        # rename fails, the timer and backup remain live and the next heartbeat may retry.
        def mutate(fresh):
            fresh["state"] = "confirmed"
            fresh["detail"] = None
            _clear_commitment(fresh)

        fresh, saved = update_state(mutate)
        if not saved:
            log("cannot persist nft confirmation; rollback remains armed")
            return False
        _timer.cancel()
        _timer = None
        _backup = _NO_BACKUP
    state.update(fresh)
    log(f"generation {fresh['generation']} confirmed — rollback disarmed")
    return True


# ── the workload half ─────────────────────────────────────────────────────────
#
# A separate lock and timer from the nftables half, deliberately. Sharing them would mean a
# CiliumNetworkPolicy apply could block or cancel a ruleset rollback, and the ruleset one is the one
# holding SSH open.

# Re-entrant deliberately: the apply transaction owns this lock from preflight through selector
# verification, and a failure in that same thread immediately enters `rollback_workload`. Timer
# callbacks run on another thread and therefore still block until the side-effecting transaction
# reaches a safe rollback point; RLock does not weaken cross-thread serialisation.
_wl_lock = threading.RLock()
_wl_timer = None
_wl_rollback_owed = None


def _workload_refs(applied):
    """Read both current identity records and the pre-hardening string-list state format."""
    out = []
    for item in applied or []:
        ref = item.get("ref") if isinstance(item, dict) else item
        if isinstance(ref, str) and "/" in ref:
            out.append(ref)
    return out


def _read_workload_object(ref, deadline=None):
    """Return (`object`, `missing`, `detail`) for one namespaced CNP."""
    ns, sep, name = ref.partition("/")
    if not sep or not ns or not name:
        return None, False, f"invalid workload object reference {ref!r}"
    command_timeout = _deadline_timeout(deadline)
    if command_timeout is None:
        return None, False, f"cannot read {ref}: workload operation deadline elapsed"
    rc, out, err = kubectl(
        ["-n", ns, "get", "ciliumnetworkpolicy", name, "-o", "json"],
        timeout_sec=command_timeout,
    )
    if rc != 0:
        detail = (err or out or f"kubectl exited {rc}").strip()
        if "not found" in detail.lower() or "notfound" in detail.lower():
            return None, True, ""
        return None, False, f"cannot read {ref}: {detail}"
    try:
        obj = json.loads(out)
    except (TypeError, ValueError) as e:
        return None, False, f"cannot read {ref}: kubectl returned invalid JSON: {e}"
    if not isinstance(obj, dict):
        return None, False, f"cannot read {ref}: kubectl returned a non-object"
    return obj, False, ""


def _owned_object_error(obj, ref, cluster, generation=None):
    """Refuse an object that is not unmistakably in this agent's ownership domain."""
    meta = obj.get("metadata")
    if not isinstance(meta, dict):
        return f"{ref} has no metadata"
    ns, _, name = ref.partition("/")
    if meta.get("name") != name or meta.get("namespace") != ns:
        return f"{ref} read back under a different name or namespace"
    labels = meta.get("labels")
    expected_labels = {
        "managed-by": WORKLOAD_MANAGED_BY,
        "heliopause.io/cluster": cluster,
    }
    if labels != expected_labels:
        if not isinstance(labels, dict) or labels.get("managed-by") != WORKLOAD_MANAGED_BY:
            return f"{ref} is not labelled managed-by={WORKLOAD_MANAGED_BY}; refusing external object"
        if labels.get("heliopause.io/cluster") != cluster:
            return f"{ref} belongs to cluster {labels.get('heliopause.io/cluster')!r}, expected {cluster!r}"
        return f"{ref} has labels outside the exact heliopause ownership set; refusing external object"
    if not name.startswith(f"hp-{_slug(cluster)}-"):
        return f"{ref} is outside the heliopause name prefix for cluster {cluster!r}"
    annotations = meta.get("annotations")
    policy_id = annotations.get("heliopause.io/policy-id") if isinstance(annotations, dict) else None
    expected_annotation_keys = {
        "heliopause.io/policy-id", "heliopause.io/applier", "heliopause.io/generation",
    }
    baseline_suffix = (
        BASELINE_SUFFIXES.get(annotations.get("heliopause.io/policy-kind"))
        if isinstance(annotations, dict) else None
    )
    baseline = baseline_suffix is not None
    if baseline:
        expected_annotation_keys.add("heliopause.io/policy-kind")
    if not isinstance(annotations, dict) or set(annotations) != expected_annotation_keys:
        return f"{ref} has unsupported or missing ownership annotations; refusing external object"
    if annotations.get("heliopause.io/applier") != HOST_ID:
        return (
            f"{ref} belongs to applier "
            f"{annotations.get('heliopause.io/applier') if isinstance(annotations, dict) else None!r}, "
            f"expected {HOST_ID!r}; refusing another applier's object"
        )
    if not isinstance(policy_id, str) or name not in (
        {f"hp-{_slug(cluster)}-{_slug(policy_id)}{baseline_suffix}"} if baseline else {
            f"hp-{_slug(cluster)}-{_slug(policy_id)}",
            f"hp-{_slug(cluster)}-{_slug(policy_id)}-ingress",
        }
    ):
        return f"{ref} name does not match its heliopause policy-id annotation"
    observed_generation = annotations.get("heliopause.io/generation")
    if (
        not isinstance(observed_generation, str)
        or not observed_generation
        or len(observed_generation) > 253
    ):
        return f"{ref} has an invalid heliopause generation annotation"
    if generation is not None and annotations.get("heliopause.io/generation") != generation:
        return (
            f"{ref} now belongs to generation {annotations.get('heliopause.io/generation')!r}, "
            f"not rollback generation {generation!r}"
        )
    if not isinstance(meta.get("uid"), str) or not meta.get("uid"):
        return f"{ref} has no Kubernetes UID"
    return ""


def _clean_workload_object(obj):
    """Persist only fields needed to restore an object, never status or server bookkeeping."""
    meta = obj["metadata"]
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": meta["name"],
            "namespace": meta["namespace"],
            "labels": dict(meta.get("labels") or {}),
            "annotations": dict(meta.get("annotations") or {}),
            "uid": meta["uid"],
        },
        "spec": obj.get("spec"),
    }


def _preflight_workload(doc, cluster, generation, deadline=None):
    """Capture our prior objects and refuse every external collision before applying anything.

    The UID and resourceVersion are not merely rollback metadata.  The subsequent write uses them
    as API-server preconditions, closing the gap between this read and the mutation: a missing object
    is created (never upserted), while an existing object is replaced only at this exact version.
    """
    records = []
    for ref in workload_objects(doc):
        current, missing, detail = _read_workload_object(ref, deadline)
        if detail:
            return None, detail
        if missing:
            records.append({
                "ref": ref, "uid": None, "cluster": cluster,
                "generation": generation, "previous": None,
            })
            continue
        reason = _owned_object_error(current, ref, cluster)
        if reason:
            return None, reason
        resource_version = current["metadata"].get("resourceVersion")
        if not isinstance(resource_version, str) or not resource_version:
            return None, f"{ref} has no resourceVersion for a conditional update"
        records.append({
            "ref": ref,
            "uid": current["metadata"]["uid"],
            "resourceVersion": resource_version,
            "cluster": cluster,
            "generation": generation,
            "previous": _clean_workload_object(current),
        })
    return records, ""


def _write_workload_objects(doc, records, deadline):
    """Create or conditionally replace each validated object without an upsert race.

    `kubectl apply` is create-or-update, so an external object appearing after a clean preflight can
    be overwritten before a post-apply ownership check notices.  Kubernetes POST create is atomic
    with respect to name collisions, and PUT replace with metadata.resourceVersion is an atomic
    lost-update check.  A List is not transactional, so every earlier successful item remains
    covered by the already-durable `prepared` records and is identity-bound rolled back on failure.
    """
    if len(doc) != len(records):
        return False, "validated workload object list changed after preflight"
    for obj, record in zip(doc, records):
        candidate = json.loads(json.dumps(obj))
        meta = candidate["metadata"]
        ref = f"{meta['namespace']}/{meta['name']}"
        if record.get("ref") != ref:
            return False, f"workload object order changed after preflight at {ref}"
        if record.get("previous") is None:
            verb = "create"
        else:
            uid = record.get("uid")
            resource_version = record.get("resourceVersion")
            if not isinstance(uid, str) or not uid or not isinstance(resource_version, str) or not resource_version:
                return False, f"{ref} lacks UID/resourceVersion for a conditional replace"
            # Both values came from the same preflight GET. The API server rejects a stale
            # resourceVersion (or an object identity change) rather than merging into it.
            meta["uid"] = uid
            meta["resourceVersion"] = resource_version
            verb = "replace"
        command_timeout = _deadline_timeout(deadline)
        if command_timeout is None:
            return False, f"workload deadline elapsed before conditional {verb} of {ref}"
        rc, out, err = kubectl(
            [verb, "--validate=strict", "-f", "-"],
            stdin=json.dumps(candidate, separators=(",", ":")),
            timeout_sec=command_timeout,
        )
        if rc != 0:
            detail = (err or out or f"kubectl exited {rc}").strip()
            return False, f"conditional {verb} of {ref} failed: {detail}"
    return True, ""


def _verify_workload_identity(doc, records, cluster, generation, deadline=None):
    """Pin UID and exact submitted content; reject a concurrent replacement or mutation."""
    if len(doc) != len(records):
        return False, "validated workload object list changed before read-back"
    for expected_obj, record in zip(doc, records):
        ref = record["ref"]
        current, missing, detail = _read_workload_object(ref, deadline)
        if detail:
            return False, detail
        if missing:
            return False, f"{ref} is absent after apply"
        reason = _owned_object_error(current, ref, cluster, generation)
        if reason:
            return False, reason
        uid = current["metadata"]["uid"]
        if record.get("uid") is not None and uid != record["uid"]:
            return False, f"{ref} was replaced during apply (UID changed); refusing to own the replacement"
        expected = json.loads(json.dumps(expected_obj))
        expected["metadata"]["uid"] = uid
        try:
            observed = _clean_workload_object(current)
            submitted = _clean_workload_object(expected)
        except (KeyError, TypeError) as e:
            return False, f"{ref} could not be compared with submitted content: {e}"
        if observed != submitted:
            return False, (
                f"{ref} content changed during apply; refusing to confirm a policy other than "
                "the validated document"
            )
        record["uid"] = uid
    return True, ""


def _kubernetes_selector(labels):
    """Turn renderer matchLabels into the namespace-scoped selector kubectl understands."""
    terms = []
    for key, value in labels.items():
        if key == NS_LABEL:
            continue
        # Cilium uses `k8s:` to mark labels imported from Kubernetes. kubectl sees the underlying
        # Kubernetes label name, not that source prefix.
        if key.startswith("k8s:"):
            key = key[4:]
        if not key or any(ch in key + value for ch in ",="):
            return None
        terms.append(f"{key}={value}")
    return ",".join(sorted(terms))


def _selector_enforcement_gate(doc, deadline=None):
    """Prove every endpoint selector currently selects at least one pod.

    This is intentionally fail-closed for an empty ephemeral namespace. Installing a policy early
    for pods that may appear later is useful, but it is not evidence that Cilium selected or enforced
    anything now. Operators must publish when a representative pod exists (or keep the prior
    generation) instead of receiving a false confirmation.
    """
    checked = set()
    empty = []
    for obj in doc:
        ns = obj["metadata"]["namespace"]
        ref = f"{ns}/{obj['metadata']['name']}"
        spec = obj["spec"]
        annotations = obj["metadata"].get("annotations", {})
        if annotations.get("heliopause.io/policy-kind") in BASELINE_SUFFIXES:
            # Its sole peer selector intentionally cannot resolve to a Kubernetes namespace. The
            # selected pods must still be observed before we claim enforcement — for the egress form
            # that is the whole check, since an egress baseline that selects nothing is a policy
            # closing nobody while reading as containment.
            selectors = [("endpointSelector", spec["endpointSelector"]["matchLabels"])]
        else:
            selectors = None
        direction = next(
            key for key in ("ingress", "egress", "ingressDeny", "egressDeny") if key in spec
        )
        rule = spec[direction][0]
        if selectors is None:
            selectors = [("endpointSelector", spec["endpointSelector"]["matchLabels"])]
            for peer_field in ("fromEndpoints", "toEndpoints"):
                for peer in rule.get(peer_field, []):
                    selectors.append((peer_field, peer["matchLabels"]))

        for role, labels in selectors:
            selector_ns = labels.get(NS_LABEL)
            selector = _kubernetes_selector(labels)
            if not selector_ns or selector is None:
                return None, f"{ref} has a {role} selector kubectl cannot verify"
            key = (selector_ns, selector)
            if key in checked:
                continue
            checked.add(key)
            args = ["-n", selector_ns, "get", "pods"]
            if selector:
                args += ["-l", selector]
            command_timeout = _deadline_timeout(deadline)
            if command_timeout is None:
                return None, "workload confirmation deadline elapsed during selector enforcement gate"
            rc, out, err = kubectl(args + ["-o", "name"], timeout_sec=command_timeout)
            if rc != 0:
                return None, (
                    f"cannot verify {role} selector for {ref}: "
                    f"{(err or out or f'kubectl exited {rc}').strip()}"
                )
            if not any(line.startswith("pod/") for line in out.split()):
                empty.append(f"{ref} {role}")
    return empty, ""


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP over one private Unix socket; kubectl proxy handles upstream TLS/auth."""

    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self._unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._unix_path)


def _delete_workload_object(ref, uid, resource_version, deadline=None):
    """Delete one CNP with API-server-enforced UID/resourceVersion preconditions.

    The proxy has no TCP listener. Its unique socket lives below the agent's 0700 StateDirectory,
    and its request filter is the exact escaped namespace/name path, so another unprivileged local
    process cannot borrow the ServiceAccount during the short rollback window.
    """
    ns, _, name = ref.partition("/")
    path = (
        "/apis/cilium.io/v2/namespaces/" + urllib.parse.quote(ns, safe="") +
        "/ciliumnetworkpolicies/" + urllib.parse.quote(name, safe="")
    )
    parent = os.path.dirname(STATE_FILE) or "."
    try:
        os.makedirs(parent, mode=0o700, exist_ok=True)
        private_dir = tempfile.mkdtemp(prefix=".kube-proxy-", dir=parent)
    except OSError as e:
        return False, f"cannot create private kubectl proxy directory: {e}"
    socket_path = os.path.join(private_dir, "proxy.sock")
    cmd = [
        KUBECTL, "--kubeconfig", KUBECONFIG, "--cache-dir", KUBE_CACHE_DIR,
        "proxy", f"--unix-socket={socket_path}", "--api-prefix=/",
        "--accept-hosts=^localhost$",
        f"--accept-paths=^{re.escape(path)}$",
        "--reject-methods=^(GET|POST|PUT|PATCH|HEAD|OPTIONS|CONNECT|TRACE)$",
    ]
    command_timeout = _deadline_timeout(deadline)
    if command_timeout is None:
        return False, "workload rollback deadline elapsed before preconditioned delete"
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as e:
        try:
            os.rmdir(private_dir)
        except OSError:
            pass
        return False, f"cannot start private kubectl proxy: {e}"
    body = json.dumps({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid, "resourceVersion": resource_version},
        "propagationPolicy": "Background",
    }).encode()
    try:
        ready_by = time.monotonic() + min(10, command_timeout)
        while not os.path.exists(socket_path) and proc.poll() is None and time.monotonic() < ready_by:
            time.sleep(0.01)
        if not os.path.exists(socket_path):
            detail = ""
            if proc.poll() is not None:
                _, detail = proc.communicate(timeout=1)
            return False, f"private kubectl proxy did not create its socket: {detail.strip()}"
        remaining = _deadline_timeout(deadline)
        if remaining is None:
            return False, "workload rollback deadline elapsed before Kubernetes API delete"
        conn = _UnixHTTPConnection(socket_path, min(HTTP_TIMEOUT_SEC, remaining))
        conn.request("DELETE", path, body=body, headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        response = conn.getresponse()
        raw = response.read(4096)
    except (OSError, http.client.HTTPException) as e:
        return False, f"preconditioned Kubernetes API delete failed: {e}"
    finally:
        if "conn" in locals():
            conn.close()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
        except OSError as e:
            log(f"cannot remove private kubectl proxy socket {socket_path}: {e}")
        try:
            os.rmdir(private_dir)
        except OSError as e:
            log(f"cannot remove private kubectl proxy directory {private_dir}: {e}")
    if response.status in {200, 202, 404}:
        return True, ""
    return False, f"API delete returned {response.status}: {raw[:300]!r}"


def _wl_persist(records, deadline, generation, policies_hash=None):
    """Record the workload commitment on disk before the cluster is touched.

    Same reasoning as `_persist_commitment`: between the apply and the timer being armed this process
    can die, and a commitment written afterwards would not cover the window it exists for. The worst
    case of writing first is a commitment whose generation labels do not exist yet; rollback checks
    those labels and UID preconditions and therefore leaves the prior objects unchanged.
    """
    def mutate(st):
        # Never heartbeat-confirm this phase. A crash before the post-apply verification marker is
        # recovered by identity-bound rollback, because the API side effect may or may not exist.
        st["workloadState"] = "prepared"
        st["workloadGeneration"] = generation
        if policies_hash is not None:
            st["workloadHash"] = policies_hash
        st["workloadDetail"] = None
        st["workloadApplied"] = records
        st["workloadRollbackAt"] = deadline

    _, saved = update_state(mutate)
    return saved


def _arm_workload_rollback_retry(generation):
    global _wl_timer
    _wl_timer = threading.Timer(
        ROLLBACK_RETRY_SEC,
        rollback_workload,
        # A cross-layer rollback may legitimately start from a confirmed workload. If persisting
        # its result fails, the retry must retain that authority instead of refusing the still-
        # confirmed durable state and silently dropping the only retry timer.
        args=("retrying incomplete workload rollback", generation, True),
    )
    _wl_timer.daemon = True
    _wl_timer.start()


def rollback_workload(reason, expected_generation=None, allow_confirmed=False):
    """Restore our prior objects and delete only creations whose UID/generation still match."""
    global _wl_timer, _wl_rollback_owed
    with _wl_lock:
        st = load_state()
        generation = st.get("workloadGeneration")
        if expected_generation is not None and generation != expected_generation:
            log(
                f"ignoring stale workload rollback for {expected_generation}: "
                f"state now belongs to {generation}"
            )
            return None
        allowed_states = {"prepared", "pending", "rollback-failed"}
        if allow_confirmed:
            allowed_states.add("confirmed")
        if expected_generation is not None and st.get("workloadState") not in allowed_states:
            log(
                f"ignoring stale workload rollback for settled {generation}/"
                f"{st.get('workloadState')}"
            )
            # As with the nft timer, a stale callback must not cancel a newer generation's timer.
            return None
        _wl_rollback_owed = generation
        if _wl_timer is not None:
            _wl_timer.cancel()
        _wl_timer = None
        records = st.get("workloadApplied") or []
        log(f"rolling back workload generation {generation}: {reason}")

        retryable = []
        incidents = []
        rollback_deadline = time.time() + WORKLOAD_ROLLBACK_BUDGET_SEC
        for record in records:
            if not isinstance(record, dict):
                # Older agents recorded only a name. That is insufficient to distinguish an object
                # deleted and recreated by flux; fail closed rather than delete by name.
                incidents.append(f"{record}: legacy state has no UID/generation proof; left untouched")
                continue
            ref = record.get("ref")
            if not isinstance(ref, str):
                incidents.append("invalid workload rollback record; left untouched")
                continue
            current, missing, detail = _read_workload_object(ref, rollback_deadline)
            if detail:
                retryable.append(f"{ref}: {detail}")
                continue
            if missing:
                continue
            previous = record.get("previous")
            if isinstance(previous, dict):
                # Persist can precede kubectl, and a retry can follow a partially successful restore.
                # In either case the exact prior snapshot means this record is already safe. A
                # changed object falls through to generation/UID checks and is restored only when it
                # is unmistakably the generation this agent attempted.
                try:
                    if _clean_workload_object(current) == previous:
                        continue
                except (KeyError, TypeError):
                    pass
            cluster = record.get("cluster")
            if not isinstance(cluster, str) or not cluster:
                incidents.append(f"{ref}: rollback record has no expected cluster; left untouched")
                continue
            owner_error = _owned_object_error(current, ref, cluster, generation)
            if owner_error:
                incidents.append(f"{ref}: {owner_error}; left untouched")
                continue
            uid = current["metadata"]["uid"]
            if record.get("uid") is not None and uid != record["uid"]:
                incidents.append(f"{ref}: UID changed since apply; replacement left untouched")
                continue
            rv = current["metadata"].get("resourceVersion")
            if not isinstance(rv, str) or not rv:
                incidents.append(f"{ref}: no resourceVersion; left untouched")
                continue
            if previous is None:
                ok, detail = _delete_workload_object(ref, uid, rv, rollback_deadline)
                if not ok:
                    retryable.append(f"{ref}: {detail}; left untouched")
                continue
            if not isinstance(previous, dict) or previous.get("metadata", {}).get("uid") != uid:
                incidents.append(f"{ref}: prior snapshot UID mismatch; left untouched")
                continue
            restore = json.loads(json.dumps(previous))
            restore["metadata"]["resourceVersion"] = rv
            command_timeout = _deadline_timeout(rollback_deadline)
            if command_timeout is None:
                retryable.append("workload rollback exceeded its total budget")
                break
            rc, out, err = kubectl(
                ["replace", "--validate=strict", "-f", "-"],
                stdin=json.dumps(restore),
                timeout_sec=command_timeout,
            )
            if rc != 0:
                retryable.append(
                    f"{ref}: restore failed: {(err or out or f'kubectl exited {rc}').strip()}"
                )

        target_state = (
            "rollback-failed" if retryable else "rollback-incident" if incidents else "rolled-back"
        )
        problems = retryable + incidents

        def mutate(fresh):
            # A newer generation cannot normally appear while `_wl_lock` is held, but retain the
            # identity check at the final write as a fail-closed invariant for future callers.
            if fresh.get("workloadGeneration") != generation:
                raise RuntimeError(
                    f"workload state changed to {fresh.get('workloadGeneration')!r} during rollback"
                )
            fresh["workloadState"] = target_state
            fresh["workloadDetail"] = (
                reason if not problems else f"{reason}; rollback incomplete: {'; '.join(problems)}"
            )
            # Keep incomplete records as incident evidence and for identity-checked transient
            # retries. An ownership/UID mismatch becomes rollback-incident and is never auto-deleted.
            fresh["workloadApplied"] = records if problems else None
            fresh["workloadRollbackAt"] = (
                time.time() + ROLLBACK_RETRY_SEC if retryable else None
            )

        try:
            _, saved = update_state(mutate)
        except RuntimeError as e:
            incidents.append(str(e))
            saved = False
        if not saved:
            retryable.append("cannot persist completed workload rollback state")
        if retryable:
            _arm_workload_rollback_retry(generation)
        elif saved:
            # `rollback-incident` is intentionally settled for automatic action: ownership changed,
            # so retaining authority to mutate would be less safe than leaving evidence for an
            # operator. Successful/incident persistence both make heartbeat confirmation impossible.
            _wl_rollback_owed = None
        if retryable or incidents:
            log(f"WORKLOAD ROLLBACK INCOMPLETE: {'; '.join(retryable + incidents)}")
        return saved and not retryable and not incidents


_generation_rollback_lock = threading.Lock()


def rollback_generation(reason, generation, source=None, expected_deadline=None):
    """Keep one generation's host and workload halves from surviving each other's rollback."""
    global _nft_rollback_owed, _wl_rollback_owed
    with _generation_rollback_lock:
        # Timer callbacks are coupled to the exact durable commitment, not only the generation.
        # A confirmed generation can be re-applied after reboot under the same generation id. An old
        # callback that was already waiting when `cancel()` ran must not roll back that new apply.
        if source == "host":
            with _apply_lock:
                source_state = load_state()
                if not (
                    source_state.get("generation") == generation
                    and source_state.get("state") in {"prepared", "pending", "rollback-failed"}
                    and source_state.get("rollbackAt") == expected_deadline
                ):
                    return False
                _nft_rollback_owed = generation
        elif source == "workload":
            with _wl_lock:
                source_state = load_state()
                if not (
                    source_state.get("workloadGeneration") == generation
                    and source_state.get("workloadState") in {
                        "prepared", "pending", "rollback-failed",
                    }
                    and source_state.get("workloadRollbackAt") == expected_deadline
                ):
                    return False
                _wl_rollback_owed = generation
        st = load_state()
        if st.get("generation") == generation and st.get("state") in {
            "prepared", "pending", "rollback-failed",
        }:
            host_result = rollback(reason, generation)
            if source == "host" and host_result is None:
                return False
        st = load_state()
        workload_state = st.get("workloadState")
        if st.get("workloadGeneration") == generation and (
            workload_state in {"prepared", "pending", "rollback-failed"}
            # The workload is confirmed first. If persisting the host confirmation then fails, the
            # host timer remains armed and must restore this already-confirmed counterpart too.
            or workload_state == "confirmed"
        ):
            workload_result = rollback_workload(reason, generation, allow_confirmed=True)
            if source == "workload" and workload_result is None:
                return False
        return True


def apply_workload(artifact):
    """Apply the workload half. Returns (ok, state, detail).

    Returns `(True, None, "")` when there is nothing assigned — every host but the designated applier.
    `None` rather than a state, so "not my job" never reads as a state the manager might gate on.
    """
    # Bound here, not inside the apply block: a host with no workload half never enters that block and
    # the success return below reads this. Bound late, it is a NameError on every non-applier.
    empty_detail = ""
    global _wl_timer

    wl = artifact.get("workload")
    if not wl:
        return True, None, ""

    # Addressed to someone else. The relay serves per-host artifacts and the certificate CN chooses
    # which, so this should be impossible — checked anyway, because the failure it catches is two
    # nodes fighting over one cluster-scoped object, and the cost is one comparison.
    if wl.get("applier") != HOST_ID:
        return False, "unsupported", (
            f"workload half is addressed to {wl.get('applier')!r}, this host is {HOST_ID!r} — "
            f"refusing to apply another node's cluster-scoped policy"
        )

    credential_error = _kubeconfig_error()
    if credential_error:
        return False, "unsupported", credential_error

    generation = artifact.get("generation")
    cluster = wl.get("cluster")
    text = wl.get("policies")
    if not isinstance(text, str):
        return False, "unsupported", "workload policies must be text"
    expected = wl.get("policiesHash")
    actual = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
    if not isinstance(expected, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        return False, "unsupported", "workload policiesHash is missing or malformed"
    if expected != actual:
        return False, "unsupported", (
            f"workload digest {actual} does not match published {expected}"
        )

    doc, reason = validate_workload(
        text, cluster=cluster, applier=wl.get("applier"), generation=generation
    )
    if doc is None:
        return False, "unsupported", f"workload document refused: {reason}"

    # Derived from the document, then cross-checked against what the manager said to expect. A
    # disagreement means the manifest and the artifact describe different things, and applying either
    # interpretation would leave the other side's check wrong.
    objects = workload_objects(doc)
    must_exist = wl.get("mustExist")
    if not isinstance(must_exist, list) or not all(isinstance(x, str) for x in must_exist):
        return False, "unsupported", "workload mustExist must be an array of object references"
    if sorted(must_exist) != sorted(objects):
        return False, "unsupported", (
            f"workload document holds {sorted(objects)} but the manifest expects "
            f"{sorted(must_exist)} — refusing rather than guessing which is right"
        )

    timeout, reason = _parse_timeout(
        wl.get("confirmTimeoutSec"), 300, WORKLOAD_CONFIRM_MIN_SEC,
        WORKLOAD_CONFIRM_MAX_SEC, "workload.confirmTimeoutSec",
    )
    if timeout is None:
        return False, "unsupported", f"workload document refused: {reason}"

    with _wl_lock:
        if _wl_timer is not None or _wl_rollback_owed is not None:
            return False, "pending", "a workload apply is already awaiting confirmation"
        preflight_deadline = time.time() + WORKLOAD_PREFLIGHT_BUDGET_SEC
        records, detail = _preflight_workload(doc, cluster, generation, preflight_deadline)
        if records is None:
            return False, "unsupported", f"workload preflight refused: {detail}"
        deadline = time.time() + timeout
        if not _wl_persist(records, deadline, generation, expected):
            return False, "rolled-back", "cannot persist workload rollback commitment; cluster was not changed"
        remaining = deadline - time.time()
        if remaining <= 0:
            rollback_workload("workload deadline elapsed before cluster apply", generation)
            return False, "rolled-back", "workload deadline elapsed before cluster apply"
        _wl_timer = threading.Timer(
            remaining, rollback_generation,
            args=("workload confirmation timed out", generation, "workload", deadline),
        )
        _wl_timer.daemon = True
        _wl_timer.start()

        written, write_error = _write_workload_objects(doc, records, deadline)
        if not written:
            # The API has no transaction spanning List items. Earlier creates/replaces are covered
            # by the durable prepared records, and rollback touches only this generation at the
            # captured UID. A collision or stale resourceVersion therefore fails closed without
            # overwriting the object that won the race.
            rollback_workload(write_error, generation)
            return False, "rolled-back", f"kubectl rejected the workload document: {write_error}"

        verified, detail = _verify_workload_identity(doc, records, cluster, generation, deadline)
        if not verified:
            rollback_workload(f"cannot verify applied object identity: {detail}", generation)
            return False, "rolled-back", f"cannot verify applied object identity: {detail}"
        empty, detail = _selector_enforcement_gate(doc, deadline)
        if empty is None:
            rollback_workload(f"selector enforcement gate could not run: {detail}", generation)
            return False, "rolled-back", f"selector enforcement gate could not run: {detail}"
        if empty:
            # ## Reported, not rolled back
            #
            # A selector matching zero pods is worth seeing and is **not** a failed apply. The
            # namespaces this fires on are ephemeral by design — `arc-runners` and `build-jobs` hold
            # pods only while a CI job runs, and the design says so in as many words: "파드 0은
            # '안전'이 아니라 '지금 작업이 없음'". Rolling back on it means the workload half can
            # never confirm while CI is idle, which is most of the time.
            #
            # Measured 2026-08-15 on k3s-01.dev: the first signed generation rolled back its workload
            # half four times in a row, with both namespaces legitimately empty and the objects
            # correctly applied. A gate that fires in the normal state is not a gate — it is an
            # outage that arrives on a schedule nobody chose.
            #
            # So the observation travels in `workloadDetail`, where the relay surfaces it and an
            # operator can tell "idle" from "inert" — the same call H30 makes for self-contradiction
            # and the same one the console's membership rows make for selection.
            log(
                "workload selectors match zero pods for " + ", ".join(empty) +
                " — applied and confirmed; ephemeral namespaces are empty between jobs"
            )
            empty_detail = "selectors matching no pods: " + ", ".join(empty)
        else:
            empty_detail = ""

        remaining = deadline - time.time()
        if remaining <= 0:
            detail = "workload apply exceeded its durable confirmation deadline"
            rollback_workload(detail, generation)
            return False, "rolled-back", detail
        # The post-apply UIDs and confirmable state land in one durable transaction. A crash before
        # this write leaves `prepared`, which recovery identity-rolls back and never confirms.
        def mark_pending(st):
            if st.get("workloadGeneration") != generation or st.get("workloadState") != "prepared":
                raise RuntimeError("workload commitment changed before verification completed")
            st["workloadApplied"] = records
            st["workloadState"] = "pending"

        try:
            _, saved = update_state(mark_pending)
        except RuntimeError as e:
            rollback_workload(str(e), generation)
            return False, "rolled-back", str(e)
        if not saved:
            rollback_workload("cannot persist verified workload pending state", generation)
            return False, "rolled-back", "cannot persist verified workload pending state"
    log(
        f"applied {len(objects)} workload object(s) to cluster {wl.get('cluster')}, "
        f"rollback armed for {remaining:.0f}s"
    )
    # `empty_detail` travels as the pending detail so the relay can surface a selector that matched
    # nothing without treating it as a failure. Empty string when every selector matched, which the
    # relay reads as "nothing to say" rather than as an absent field.
    return True, "pending", empty_detail


def confirm_workload(state):
    """Cancel the workload rollback timer. Returns True if one was armed."""
    global _wl_timer
    with _wl_lock:
        if _wl_rollback_owed is not None:
            log("cannot confirm workload apply while an incomplete rollback is owed")
            return False
        if _wl_timer is None:
            return False
        def mutate(fresh):
            if fresh.get("workloadState") != "pending":
                raise RuntimeError("workload is not durably pending and cannot be confirmed")
            fresh["workloadState"] = "confirmed"
            fresh["workloadDetail"] = None
            # The identity records are kept for drift reporting. No rollback timer is allowed to use
            # them once the commitment is cleared.
            fresh["workloadRollbackAt"] = None

        try:
            fresh, saved = update_state(mutate)
        except RuntimeError as e:
            log(str(e))
            return False
        if not saved:
            log("cannot persist workload confirmation; rollback remains armed")
            return False
        _wl_timer.cancel()
        _wl_timer = None
        state.update(fresh)
    log("workload half confirmed — rollback disarmed")
    return True


def _workload_objects_missing(st):
    """Objects this host confirmed that the cluster no longer holds, as a summary string, or "".

    Only for a **confirmed** half. While an apply is pending its own machinery owns the decision, and
    a host with no assignment has nothing to check.

    A cluster that cannot be read returns "" — not knowing must not trigger a re-apply. The nftables
    equivalent takes the same position: an unreadable dump is reported as drift, not acted on.
    """
    if st.get("workloadState") != "confirmed":
        return ""
    expected = _workload_refs(st.get("workloadApplied"))
    if not expected:
        return ""
    report = _workload_report(st).get("workload") or {}
    present = report.get("observed")
    if not isinstance(present, list):
        return ""
    missing = [o for o in expected if o not in present]
    return ", ".join(missing)


def recover_workload_commitment():
    """Honour a workload commitment that outlived the process. Mirrors `recover_commitment`.

    A restart inside the confirm window must not silently drop the timer: the objects are live in the
    cluster and nothing else would remove them. Past its deadline the rollback runs now; still inside
    it, the timer is re-armed for the remaining time.
    """
    global _wl_timer
    st = load_state()
    deadline = st.get("workloadRollbackAt")
    if deadline is None or not st.get("workloadApplied"):
        return
    generation = st.get("workloadGeneration")
    if st.get("workloadState") in {"prepared", "rollback-failed"}:
        phase = st.get("workloadState")
        log(f"{phase} workload commitment requires rollback before heartbeat")
        rollback_workload(
            "restarted before workload apply was durably verified"
            if phase == "prepared" else "retrying an incomplete workload rollback after restart",
            generation,
        )
        return
    if st.get("workloadState") != "pending":
        return
    remaining = deadline - time.time()
    if remaining <= 0:
        log("workload commitment is past its deadline — rolling back now")
        rollback_workload("confirmation window elapsed while the agent was not running", generation)
        return
    with _wl_lock:
        if _wl_timer is not None:
            return
        _wl_timer = threading.Timer(
            remaining, rollback_generation,
            args=("workload confirmation timed out", generation, "workload", deadline),
        )
        _wl_timer.daemon = True
        _wl_timer.start()
    log(f"re-armed workload rollback, {int(remaining)}s remaining")


def reconcile_recovered_commitments():
    """Settle same-generation halves together before the first post-restart heartbeat."""
    st = load_state()
    if st.get("generation") != st.get("workloadGeneration"):
        return
    generation = st.get("generation")
    if generation is None:
        return
    host_failed = st.get("state") in {
        "rolled-back", "rollback-failed", "rollback-incident",
    }
    workload_live = st.get("workloadState") in {
        "prepared", "pending", "confirmed", "rollback-failed",
    }
    if host_failed and workload_live:
        rollback_workload(
            "same-generation host half did not survive restart recovery",
            generation,
            allow_confirmed=True,
        )
        return
    workload_failed = st.get("workloadState") in {
        "rolled-back", "rollback-failed", "rollback-incident",
    }
    host_live = st.get("state") in {"prepared", "pending", "rollback-failed"}
    if workload_failed and host_live:
        rollback_generation(
            "same-generation workload half did not survive restart recovery", generation
        )


# ── change monitor (H28) ──────────────────────────────────────────────────────
#
# `nft monitor` streams every ruleset change as it happens. Drift detection already catches *that*
# our table changed, by comparing dump digests at heartbeat interval; this catches **when** and
# **by what**, which is the part an incident needs.
#
# ## Why the text stream and not `nft -j monitor`
#
# JSON monitor works and emits the same shape as our artifacts, which would let `_is_ours` be
# reused verbatim. It omits one thing: the `# new generation N by process <pid> (<name>)` line.
# That line is the entire point of H28 — a change to our table made by something other than this
# agent is unauthorised, and naming the process is what makes it actionable rather than merely
# alarming.
#
# So this parses text, which is the thing that was rejected for artifact validation. The two are
# not the same problem. There, a parser had to out-guess nft's *input grammar* against an attacker
# choosing the input, and losing meant applying a hostile ruleset. Here it reads nft's own *output*
# in a fixed comment format, and losing means an event is recorded without a tidy classification —
# it is never the difference between applying and not applying.

_MONITOR_GEN = re.compile(r"^# new generation \d+ by process (?P<pid>\d+) \((?P<name>[^)]*)\)")
MAX_BUFFERED_EVENTS = 200

_events_lock = threading.Lock()
_events = []
_events_dropped = 0

# PIDs of nft processes this agent started to change the ruleset.
#
# A time-based "am I applying right now" flag does not work, and the way it fails matters: the
# monitor reads its pipe asynchronously, so by the time an event is parsed the apply has long
# returned and our own change is attributed to nobody — reported as an intrusion on every
# legitimate deploy. An alarm that fires on correct behaviour gets switched off, and then the real
# one is missed too.
#
# Matching the PID nft reports against the PID we spawned is exact rather than approximate, and it
# uses the same attribution the monitor is built on. Bounded because this must not grow for the
# process lifetime; recent entries are all that can still be in flight.
#
# **This requires sharing the kernel's PID namespace.** `nft monitor` reports the PID carried in
# the netlink message, which is numbered in the initial namespace. Under systemd on a host that is
# what we see, and the match is exact — measured. Inside a container with its own PID namespace the
# numbers do not correspond, every apply looks like an intrusion, and the alarm becomes noise. The
# agent is meant to run as a host unit; if that ever changes, this needs a different signal.
_our_pids = collections.deque(maxlen=64)
_our_pids_lock = threading.Lock()


def _remember_our_pid(pid):
    with _our_pids_lock:
        _our_pids.append(pid)


def _was_us(pid):
    if pid is None:
        return False
    with _our_pids_lock:
        return pid in _our_pids


def _record_event(raw, table, pid, name):
    global _events_dropped
    with _events_lock:
        if len(_events) >= MAX_BUFFERED_EVENTS:
            # Drop and *count*. Silently discarding evidence would make a flood — which is itself a
            # signal — look like quiet.
            _events_dropped += 1
            return
        _events.append(
            {
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "table": table,
                "raw": raw[:400],
                "pid": pid,
                "process": name,
                "byAgent": _was_us(pid),
            }
        )


def take_events():
    """Hand over buffered events and clear the buffer. Called when a heartbeat is being built."""
    global _events_dropped
    with _events_lock:
        out = list(_events)
        dropped = _events_dropped
        _events.clear()
        _events_dropped = 0
    if dropped:
        out.append(
            {
                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "table": f"{TABLE_FAMILY} {TABLE_NAME}",
                "raw": f"[{dropped} further events dropped — buffer full]",
                "byAgent": False,
            }
        )
    return out


def monitor_loop():
    """Follow `nft monitor` and buffer changes. Runs on its own thread for the process lifetime."""
    ours = f"{TABLE_FAMILY} {TABLE_NAME}"
    while not _stop.is_set():
        try:
            proc = subprocess.Popen(
                [NFT, "monitor"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
        except OSError as e:
            log(f"cannot start nft monitor: {e}")
            _stop.wait(30)
            continue

        # Changes accumulate until the generation line that attributes them.
        #
        # One `nft -f` is one atomic transaction, and nft reports it as *every* change line
        # followed by a **single** `# new generation` line. An earlier version assumed the two
        # alternated, so a five-command apply produced four events with no PID — and the agent
        # reported its own deploy as five intrusions. The buffer is per transaction, not per line.
        pending: list[str] = []

        def flush(pid=None, name=None):
            for raw in pending:
                _record_event(raw, ours if ours in raw else "other", pid, name)
            pending.clear()

        try:
            for line in proc.stdout:
                if _stop.is_set():
                    break
                line = line.rstrip("\n")
                if not line:
                    continue
                gen = _MONITOR_GEN.match(line)
                if gen:
                    flush(int(gen.group("pid")), gen.group("name"))
                    continue
                if line.startswith("#"):
                    continue
                pending.append(line)
        except Exception as e:  # noqa: BLE001 — the monitor must never take the agent down
            log(f"nft monitor stream ended: {e}")
        finally:
            # A change whose generation line never arrived still happened; record it unattributed
            # rather than lose it.
            flush()
            proc.terminate()
        if not _stop.is_set():
            log("nft monitor exited, restarting in 5s")
            _stop.wait(5)


def unauthorised_events(events):
    """Changes to our table that this agent did not make. The reason H28 exists."""
    ours = f"{TABLE_FAMILY} {TABLE_NAME}"
    return [e for e in events if e.get("table") == ours and not e.get("byAgent")]


# ── persisted state ───────────────────────────────────────────────────────────

# nft rollback, workload rollback and the heartbeat loop all mutate different fields in this one
# document from different threads. Atomic rename protects readers from partial JSON; it does not
# protect a load→mutate→save sequence from lost updates. Every mutation therefore runs under this
# process-wide lock, and the lock is re-entrant so the small public helpers can compose safely.
_state_lock = threading.RLock()

_EMPTY_STATE = {
    "generation": None,
    "state": "none",
    "artifactHash": None,
    # Digest of the stateless dump captured immediately after the last successful apply. This is
    # the only sound thing to compare a later dump against — the artifact is input text, this is
    # nft's normalised rendering of it, and the two are never byte-equal.
    "referenceHash": None,
    "detail": None,
    # The rollback commitment, so it outlives this process. See "surviving our own death" above.
    # `{"elements": [...] | None}` while an apply is unconfirmed, `None` otherwise. The inner
    # `None` is meaningful and distinct from the outer one: it says a backup *was* captured and
    # there was no table at the time, so restoring means deleting.
    "pendingBackup": None,
    # Unix time by which the apply must be confirmed. Absolute rather than a remaining duration:
    # a crash loop re-arming a duration on every start would push the deadline back forever.
    "rollbackAt": None,
    # ── the workload half (schema 2) ──
    #
    # Tracked in its own fields rather than reusing the four above, because the two halves reach
    # different states independently and the manager gates on both. Folding them would make a
    # confirmed ruleset with a failed CNP apply indistinguishable from a clean generation.
    #
    # `None` throughout on any host that is not the designated applier, which is the normal case.
    "workloadState": None,
    "workloadHash": None,
    "workloadDetail": None,
    # Identity records for objects this generation applied: ref, UID, generation, cluster, and the
    # prior heliopause-owned object (if any). Rollback never acts on a name alone.
    "workloadApplied": None,
    "workloadGeneration": None,
    "workloadRollbackAt": None,
    # Latest signed authorization ever accepted and the one backing the current generation.
    # The watermark is written before *any* nft/kubectl commitment or side effect. Equal timestamps
    # are accepted only for the exact same payload/key/mode; older ones are relay replay attempts.
    "authorizationWatermark": None,
    "pendingAuthorization": None,
    "currentAuthorization": None,
    # ── selector membership (H14a) ──
    #
    # What the manager last asked this host to report membership for, as
    # `{"namespaces": [...], "labels": [...]}`. Persisted rather than held in memory so a restart
    # does not silently stop reporting until the next reply happens to carry the list again — the
    # manager would read that gap as "not known", which is true but needlessly.
    "watchSelectors": None,
}


def _load_state_unlocked():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
    except FileNotFoundError:
        return dict(_EMPTY_STATE)
    except (OSError, ValueError) as e:
        # Reporting `none` here would be a lie that reads as "this host was never configured",
        # and would invite a re-apply of something already live. Say the state is unreadable.
        log(f"state file unreadable ({e}) — reporting unknown")
        st = dict(_EMPTY_STATE)
        st["detail"] = f"state file unreadable: {e}"
        return st
    st = dict(_EMPTY_STATE)
    st.update({k: saved.get(k, v) for k, v in _EMPTY_STATE.items()})
    return st


def load_state():
    with _state_lock:
        return _load_state_unlocked()


def _save_state_unlocked(st):
    """Atomically and durably replace the state file; caller holds `_state_lock`."""
    directory = os.path.dirname(STATE_FILE) or "."
    fd = None
    tmp = None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(STATE_FILE)}.", suffix=".tmp", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None  # ownership transferred to the file object
            json.dump(st, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
        tmp = None
        # fsyncing the file makes its contents durable; fsyncing the containing directory makes the
        # rename durable as well. Without the latter, power loss can resurrect the old pathname even
        # though the temporary file itself reached storage.
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        dir_fd = os.open(directory, flags)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return True
    except (OSError, TypeError, ValueError) as e:
        log(f"cannot persist state: {e}")
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            except OSError as e:
                log(f"cannot remove failed state temporary {tmp}: {e}")


def save_state(st):
    """Write one complete state atomically, serialised with all other in-process writers."""
    with _state_lock:
        return _save_state_unlocked(st)


def update_state(mutator):
    """Run a load→mutate→durable-save transaction under the shared state lock.

    Returns `(state, saved)`. Callers that need to mirror the committed document into a heartbeat
    copy use the first value; security-critical apply paths fail closed when `saved` is false.
    """
    with _state_lock:
        st = _load_state_unlocked()
        mutator(st)
        return st, _save_state_unlocked(st)


# ── signed artifact authorization ────────────────────────────────────────────

_artifact_keys_cache = None


def _frame(value):
    if len(value) > 0xFFFFFFFF:
        raise ValueError("signed field exceeds uint32 framing limit")
    return len(value).to_bytes(4, "big") + value


def _b64url(value, label, max_bytes):
    if not isinstance(value, str) or not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError(f"envelope {label} is not canonical base64url")
    if len(value) > ((max_bytes + 2) // 3) * 4:
        raise ValueError(f"envelope {label} exceeds its byte limit")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as e:
        raise ValueError(f"envelope {label} is invalid base64url: {e}") from e
    if len(decoded) > max_bytes or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError(f"envelope {label} is non-canonical or overlong")
    return decoded


def _pairs_no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _reject_float(value):
    raise ValueError(f"non-integer JSON number {value!r}")


def _strict_json(encoded):
    text = encoded.decode("utf-8", errors="strict")
    value = json.loads(
        text,
        object_pairs_hook=_pairs_no_duplicates,
        parse_float=_reject_float,
        parse_constant=_reject_float,
    )
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if canonical != text:
        raise ValueError("signed payload is not canonical JSON")
    return value


def _exact_keys(value, required, label, optional=()):
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    keys = set(value)
    required = set(required)
    if not required.issubset(keys) or not keys.issubset(required | set(optional)):
        raise ValueError(f"{label} has unsupported or missing fields")


def _exact_iso(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", value):
        raise ValueError(f"{label} is not an exact ISO 8601 UTC timestamp")
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=datetime.timezone.utc
        ).timestamp()
    except ValueError as e:
        raise ValueError(f"{label} is not a valid timestamp") from e


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _load_artifact_key_dir(path, trust_class):
    if not path:
        raise ValueError(f"{trust_class} artifact public key directory is not configured")
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
        raise ValueError(f"{trust_class} artifact key directory must be non-symlink and not group/world writable")
    names = sorted(name for name in os.listdir(path) if not name.startswith("."))
    if len(names) > MAX_SIGNING_KEYS_PER_CLASS:
        raise ValueError(f"{trust_class} artifact key directory exceeds {MAX_SIGNING_KEYS_PER_CLASS} keys")
    keys = []
    for name in names:
        full = os.path.join(path, name)
        file_info = os.lstat(full)
        if not stat.S_ISREG(file_info.st_mode) or stat.S_ISLNK(file_info.st_mode) or file_info.st_mode & 0o022:
            raise ValueError(f"artifact public key {full} is not a protected regular file")
        if file_info.st_size > 64 * 1024:
            raise ValueError(f"artifact public key {full} is oversized")
        try:
            process = subprocess.run(
                [OPENSSL, "pkey", "-pubin", "-in", full, "-outform", "DER"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ValueError(f"cannot read artifact public key {full}: {e}") from e
        if process.returncode != 0 or not process.stdout or len(process.stdout) > 4096:
            raise ValueError(f"artifact public key {full} is not a bounded Ed25519 public key")
        # Ed25519 SubjectPublicKeyInfo is exactly 44 DER bytes and carries OID 1.3.101.112.
        if len(process.stdout) != 44 or b"\x06\x03\x2b\x65\x70" not in process.stdout:
            raise ValueError(f"artifact public key {full} is not Ed25519")
        key_id = "sha256:" + hashlib.sha256(process.stdout).hexdigest()
        keys.append((key_id, trust_class, full))
    return keys


def load_artifact_trust():
    global _artifact_keys_cache
    if _artifact_keys_cache is not None:
        return _artifact_keys_cache
    rows = _load_artifact_key_dir(MANAGER_SIGNING_KEYS_DIR, "manager")
    rows += _load_artifact_key_dir(BREAK_GLASS_KEYS_DIR, "break-glass")
    if not rows:
        raise ValueError("no artifact signing public key is configured")
    keys = {}
    for key_id, trust_class, path in rows:
        if key_id in keys:
            raise ValueError(f"artifact signing key {key_id} appears twice or in both trust classes")
        keys[key_id] = (trust_class, path)
    manager_ids = sorted(key for key, row in keys.items() if row[0] == "manager")
    break_ids = sorted(key for key, row in keys.items() if row[0] == "break-glass")
    material = _frame(TRUST_DOMAIN)
    for trust_class, ids in (("manager", manager_ids), ("break-glass", break_ids)):
        material += _frame(trust_class.encode())
        for key_id in ids:
            material += _frame(key_id.encode())
    _artifact_keys_cache = {
        "keys": keys,
        "managerKeyIds": manager_ids,
        "breakGlassKeyIds": break_ids,
        "trustDigest": "sha256:" + hashlib.sha256(material).hexdigest(),
    }
    return _artifact_keys_cache


def _verify_ed25519(public_key, message, signature):
    directory = os.path.dirname(STATE_FILE) or None
    os.makedirs(directory or ".", mode=0o700, exist_ok=True)
    sig_path = None
    try:
        fd, sig_path = tempfile.mkstemp(prefix=".artifact-signature.", dir=directory)
        with os.fdopen(fd, "wb") as sig_file:
            sig_file.write(signature)
            sig_file.flush()
            os.fsync(sig_file.fileno())
        # ## The message goes in a file, not on stdin
        #
        # `-rawin` is a oneshot operation: OpenSSL asks the input for its size before it starts, and a
        # pipe cannot answer. Feeding the message on stdin therefore fails **before any cryptography
        # happens**, with `unable to determine file size for oneshot operation` on stderr and a
        # non-zero exit that reads exactly like a bad signature.
        #
        # Measured 2026-08-15 on gw-01.util with OpenSSL 3.5.1: one Ed25519 signature verified from a
        # file and failed from a pipe. Every artifact the fleet fetched was refused as "signature is
        # invalid" while the signature was correct — the worst shape this bug could take, because the
        # message accuses the manager.
        msg_path = os.path.join(directory or ".", os.path.basename(sig_path) + ".msg")
        with open(os.open(msg_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as msg_file:
            msg_file.write(message)
            msg_file.flush()
            os.fsync(msg_file.fileno())
        try:
            process = subprocess.run(
                [OPENSSL, "pkeyutl", "-verify", "-pubin", "-inkey", public_key,
                 "-rawin", "-in", msg_path, "-sigfile", sig_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
        finally:
            try:
                os.unlink(msg_path)
            except FileNotFoundError:
                pass
        return process.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ValueError(f"artifact signature verification failed to run: {e}") from e
    finally:
        if sig_path is not None:
            try:
                os.unlink(sig_path)
            except FileNotFoundError:
                pass


def _validate_signed_routes(entry):
    """Shape-check the declared routes and their management guard.

    ## This is not the safety check

    `plan_routes` is, and it stays where it is: it refuses a default route, a prefix shorter than /8,
    a table other than main, a spec with neither `via` nor `dev`, and anything covering the relay or
    a guarded range. Only this host knows its own relay address, and a receiver that reads a valid
    signature as "safe to apply" has confused provenance with correctness.

    What this does is refuse a shape the applier would otherwise have to reason about — a `routes`
    that is not a list, a spec with keys nobody sends, a guard that is missing or empty.

    ## The guard is required, and empty is refused

    `routeGuard` names the ranges a route must not disturb, derived from `cfg.baseline`. It is the
    routing half of `mustContain`: the heartbeat proves the *relay* path survived and says nothing
    about the operator's, so a route that moves the management range confirms cleanly and locks
    everybody out, with the deadline never firing because nothing it can see went wrong.

    `managementGuard` returns `[]` for a baseline whose entries name no source, which is what this
    site's baseline looks like. An empty list would arrive as a value the old check accepted —
    `isinstance(guard, list)` — and protect nothing. The signer refuses it too; this is the receiver
    saying so independently, because "both ends check" is the only arrangement that survives one end
    being replaced.
    """
    routes = entry.get("routes")
    if routes is None:
        if entry.get("routeGuard") is not None:
            raise ValueError("signed entry carries a route guard with no routes")
        return
    if not isinstance(routes, list) or not routes or len(routes) > 64:
        raise ValueError("signed entry routes is not a list of 1..64 specs")
    for spec in routes:
        if not isinstance(spec, dict) or set(spec) - {"dst", "via", "dev", "table"} or "dst" not in spec:
            raise ValueError("signed entry route spec has unsupported or missing fields")
        for field in ("dst", "via", "dev", "table"):
            value = spec.get(field)
            if value is None:
                continue
            if not isinstance(value, str) or not value or len(value) > 128:
                raise ValueError(f"signed entry route {field} is empty, overlong, or not text")
    guard = entry.get("routeGuard")
    if not isinstance(guard, list) or not guard or not all(
        isinstance(item, str) and item and len(item) <= 128 for item in guard
    ):
        raise ValueError("signed entry routes need a non-empty management guard")


def _validate_signed_entry(entry):
    _exact_keys(
        entry,
        ["stage", "rulesetHash", "confirmTimeoutSec", "mustContain"],
        "signed entry",
        ["maintenance", "expectAddrs", "expectFilters", "workload", "routes", "routeGuard"],
    )
    if entry.get("stage") not in {"canary", "general", "gateway"} or not _digest(entry.get("rulesetHash")):
        raise ValueError("signed entry has invalid stage or rulesetHash")
    if not isinstance(entry.get("confirmTimeoutSec"), int) or isinstance(entry.get("confirmTimeoutSec"), bool):
        raise ValueError("signed entry confirmTimeoutSec is not an integer")
    for name in ("mustContain", "expectAddrs", "expectFilters"):
        value = entry.get(name, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"signed entry {name} is not a string array")
    _validate_signed_routes(entry)
    workload = entry.get("workload")
    if workload is not None:
        _exact_keys(
            workload,
            ["policiesHash", "cluster", "mustExist", "confirmTimeoutSec", "policyCount"],
            "signed workload entry",
            ["ingressDefaultDenyNamespaces", "ingressProtectedSelectors", "watchSelectors"],
        )
        if not _digest(workload.get("policiesHash")) or not isinstance(workload.get("cluster"), str):
            raise ValueError("signed workload entry has invalid digest or cluster")
        if not isinstance(workload.get("mustExist"), list) or not all(
            isinstance(item, str) for item in workload["mustExist"]
        ):
            raise ValueError("signed workload mustExist is not a string array")
        if not isinstance(workload.get("confirmTimeoutSec"), int) or isinstance(workload.get("confirmTimeoutSec"), bool):
            raise ValueError("signed workload confirmTimeoutSec is not an integer")
        baseline_namespaces = workload.get("ingressDefaultDenyNamespaces", [])
        if not isinstance(baseline_namespaces, list) or not all(
            isinstance(ns, str) and _DNS_LABEL.fullmatch(ns) and ns in WORKLOAD_NAMESPACES
            for ns in baseline_namespaces
        ) or len(set(baseline_namespaces)) != len(baseline_namespaces):
            raise ValueError("signed workload ingressDefaultDenyNamespaces is not a unique authorised namespace array")
    return workload


def verify_artifact_envelope(envelope, now=None):
    """Return (artifact, replay record, signed watchSelectors, expired) or raise before side effects."""
    _exact_keys(envelope, ["version", "algorithm", "keyId", "payload", "signature"], "artifact envelope")
    if envelope.get("version") != ENVELOPE_VERSION or envelope.get("algorithm") != "Ed25519":
        raise ValueError("unsupported artifact envelope version or algorithm")
    key_id = envelope.get("keyId")
    if not _digest(key_id):
        raise ValueError("artifact envelope keyId is not an SPKI sha256 digest")
    payload_bytes = _b64url(envelope.get("payload"), "payload", MAX_SIGNED_PAYLOAD_BYTES)
    signature = _b64url(envelope.get("signature"), "signature", 64)
    if len(signature) != 64:
        raise ValueError("artifact envelope signature is not 64 bytes")
    trust = load_artifact_trust()
    trusted = trust["keys"].get(key_id)
    if trusted is None:
        raise ValueError(f"artifact was signed by untrusted key {key_id}")
    signed_input = _frame(SIGNATURE_DOMAIN) + _frame(key_id.encode()) + _frame(payload_bytes)
    if not _verify_ed25519(trusted[1], signed_input, signature):
        raise ValueError("artifact authorization signature is invalid")

    payload = _strict_json(payload_bytes)
    _exact_keys(payload, [
        "version", "target", "planHash", "bundleHash", "authorizedAt", "expiresAt",
        "authorizationMode", "host", "manifest", "entry", "ruleset", "workload",
    ], "signed artifact payload")
    if payload.get("version") != 1 or payload.get("target") != TARGET or payload.get("host") != HOST_ID:
        raise ValueError("signed artifact target or host does not match this agent")
    if not _digest(payload.get("planHash")) or not _digest(payload.get("bundleHash")):
        raise ValueError("signed artifact planHash or bundleHash is malformed")
    plan_material = _frame(b"heliopause-plan-v1") + _frame(TARGET.encode()) + _frame(payload["bundleHash"].encode())
    if payload["planHash"] != "sha256:" + hashlib.sha256(plan_material).hexdigest():
        raise ValueError("signed artifact planHash does not bind target and bundleHash")
    mode = payload.get("authorizationMode")
    if mode not in {"two-person", "solo-otp", "break-glass"}:
        raise ValueError("signed artifact authorizationMode is unsupported")
    required_class = "break-glass" if mode == "break-glass" else "manager"
    if trusted[0] != required_class:
        raise ValueError(f"{mode} authorization requires a {required_class} trust key")

    authorized = _exact_iso(payload.get("authorizedAt"), "authorizedAt")
    expires = _exact_iso(payload.get("expiresAt"), "expiresAt")
    lifetime = expires - authorized
    max_lifetime = AUTH_BREAK_GLASS_MAX_TTL_SEC if mode == "break-glass" else AUTH_MANAGER_MAX_TTL_SEC
    if lifetime < AUTH_MIN_TTL_SEC or lifetime > max_lifetime:
        raise ValueError("signed artifact authorization lifetime is outside its protocol bounds")
    current = time.time() if now is None else now
    if authorized > current + AUTH_CLOCK_SKEW_SEC:
        raise ValueError("signed artifact authorization is from the future")

    header = payload.get("manifest")
    _exact_keys(header, ["generation", "issuedAt", "schemaVersion"], "signed manifest header")
    if header.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError(f"signed artifact schema {header.get('schemaVersion')} is unsupported")
    generation = header.get("generation")
    if not isinstance(generation, str) or not generation or len(generation) > 256:
        raise ValueError("signed artifact generation is empty or overlong")
    issued = _exact_iso(header.get("issuedAt"), "manifest.issuedAt")
    if issued > authorized + AUTH_CLOCK_SKEW_SEC:
        raise ValueError("signed manifest was issued after its authorization")
    entry = payload.get("entry")
    workload_entry = _validate_signed_entry(entry)
    ruleset = payload.get("ruleset")
    if not isinstance(ruleset, str) or "sha256:" + hashlib.sha256(ruleset.encode()).hexdigest() != entry["rulesetHash"]:
        raise ValueError("signed ruleset does not match its entry digest")
    workload_text = payload.get("workload")
    workload = None
    watch = None
    if workload_entry is not None:
        if not isinstance(workload_text, str) or "sha256:" + hashlib.sha256(workload_text.encode()).hexdigest() != workload_entry["policiesHash"]:
            raise ValueError("signed workload does not match its entry digest")
        watch, watch_error = validate_watch_selectors(workload_entry.get("watchSelectors"))
        if watch_error:
            raise ValueError(f"signed workload selector watch is invalid: {watch_error}")
        checked_doc, reason = validate_workload(
            workload_text, cluster=workload_entry["cluster"], applier=HOST_ID, generation=generation
        )
        if checked_doc is None:
            raise ValueError(f"signed workload document refused: {reason}")
        rendered_baselines = sorted({
            obj["metadata"]["namespace"] for obj in checked_doc
            if obj["metadata"]["annotations"].get("heliopause.io/policy-kind") == "namespace-ingress-default-deny"
        })
        if rendered_baselines != sorted(workload_entry.get("ingressDefaultDenyNamespaces", [])):
            raise ValueError("signed workload baseline namespace list does not match its CNP document")
        workload = {
            "policies": workload_text,
            "policiesHash": workload_entry["policiesHash"],
            "applier": HOST_ID,
            "cluster": workload_entry["cluster"],
            "mustExist": workload_entry["mustExist"],
            "confirmTimeoutSec": workload_entry["confirmTimeoutSec"],
        }
    elif workload_text is not None:
        raise ValueError("signed artifact carries workload without an assignment")

    artifact = {
        "generation": generation,
        "host": HOST_ID,
        "ruleset": ruleset,
        "rulesetHash": entry["rulesetHash"],
        "confirmTimeoutSec": entry["confirmTimeoutSec"],
        "mustContain": entry["mustContain"],
        "expectAddrs": entry.get("expectAddrs", []),
        "expectFilters": entry.get("expectFilters", []),
        # Only when the entry declares them. `apply_artifact` reads `artifact.get("routes")` and an
        # always-present empty list would be indistinguishable from "this host installs none" — which
        # it is, but stating it on every host's artifact would put a field on every entry that only
        # one host ever uses. Absent and `[]` mean the same thing to the applier; absent is what the
        # manifest sends.
        **({"routes": entry["routes"], "routeGuard": entry["routeGuard"]}
           if entry.get("routes") is not None else {}),
        **({"workload": workload} if workload is not None else {}),
    }
    record = {
        "authorizedAt": payload["authorizedAt"],
        "payloadHash": "sha256:" + hashlib.sha256(payload_bytes).hexdigest(),
        "keyId": key_id,
        "authorizationMode": mode,
        "target": TARGET,
        "host": HOST_ID,
        "planHash": payload["planHash"],
        "bundleHash": payload["bundleHash"],
        "generation": generation,
    }
    return artifact, record, watch, expires <= current


def accept_artifact_authorization(record, watch, expired):
    """Durably advance replay state before any nft/kubectl commitment or side effect."""
    result = {"error": None}

    def mutate(st):
        prior = st.get("authorizationWatermark")
        if isinstance(prior, dict):
            if record["authorizedAt"] < prior.get("authorizedAt", ""):
                result["error"] = "signed artifact is older than the durable authorization watermark"
                return
            if record["authorizedAt"] == prior.get("authorizedAt") and record != prior:
                result["error"] = "different signed artifacts share one authorization timestamp"
                return
        current = st.get("currentAuthorization")
        if expired and not (
            current == record
            and st.get("generation") == record["generation"]
            and st.get("state") == "confirmed"
        ):
            result["error"] = "signed artifact authorization has expired"
            return
        st["authorizationWatermark"] = record
        st["pendingAuthorization"] = record
        st["watchSelectors"] = watch

    fresh, saved = update_state(mutate)
    if result["error"]:
        return None, result["error"]
    if not saved:
        return None, "cannot persist signed authorization replay watermark"
    return fresh, ""


def artifact_trust_report(st):
    trust = load_artifact_trust()
    current = st.get("currentAuthorization") if isinstance(st.get("currentAuthorization"), dict) else {}
    return {
        "artifactTrust": {
            "managerKeyIds": trust["managerKeyIds"],
            "breakGlassKeyIds": trust["breakGlassKeyIds"],
            "trustDigest": trust["trustDigest"],
            "currentKeyId": current.get("keyId"),
            "currentPayloadHash": current.get("payloadHash"),
            "currentAuthorizationMode": current.get("authorizationMode"),
            "currentAuthorizedAt": current.get("authorizedAt"),
            "currentPlanHash": current.get("planHash"),
        }
    }


# ── transport ─────────────────────────────────────────────────────────────────


def ssl_context():
    """Client context: verify the relay against our anchor, and present our own certificate.

    `create_default_context` is used rather than a hand-built one so hostname checking and
    certificate verification are on by default. There is no unverified mode — a self-signed relay
    certificate is its own anchor, so `CA_FILE` covers that case through the normal path instead
    of by switching verification off.
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=CA_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx


def _pin_ok(der):
    digest = base64.b64encode(hashlib.sha256(der).digest()).decode()
    return any(p.removeprefix("sha256/") == digest for p in PINS)


def _remaining(deadline, what):
    """Seconds left before `deadline`, or a raise. Never returns zero or less.

    Sockets treat a timeout of zero as non-blocking rather than as expired, so a deadline that has
    already passed has to become an error here instead of being handed to `settimeout`.
    """
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError(f"relay exchange exceeded {HTTP_TIMEOUT_SEC}s before {what}")
    return left


def relay_request(method, suffix, payload=None):
    """One authenticated request to the relay. Raises on any failure.

    Raising rather than returning None is deliberate: to this agent a failed exchange is a
    meaningful event, not a missing value. It is the signal an armed rollback is waiting on.

    ## `HTTP_TIMEOUT_SEC` is a deadline here, not a socket timeout

    `HTTPSConnection(timeout=…)` sets the socket timeout, which Python applies to **each** operation:
    every `recv` that returns a byte resets it. A relay answering one byte at a time therefore stayed
    inside a ten-second timeout indefinitely.

    That matters because this number is load-bearing arithmetic elsewhere in this file.
    `NFT_CONFIRM_MIN_SEC` is derived as `(2 * NFT_TIMEOUT_SEC) + (2 * HTTP_TIMEOUT_SEC) +
    ROLLBACK_RETRY_SEC + 5`, from "allowing one failed HTTP attempt plus a short retry" — and the main
    loop's own comment says the rollback window during a hung request is "the full HTTP timeout rather
    than an instant". Both sentences assume a bound that was not enforced.

    **The rollback itself is not at risk**, and that is worth stating rather than leaving to the
    reader: it fires from a `threading.Timer` on another thread, and the heartbeat is sent holding no
    lock. What an unbounded attempt costs is the *retry* — a confirm window can elapse with one
    attempt still in flight, so a host that would have confirmed on the second rolls back a ruleset
    that was fine. Safe direction, real cost.

    The deadline covers connect, the pin check, the request and the body read, because all four are
    inside the window the arithmetic above is about. It is the same shape `_deadline_timeout` gives
    the kubectl calls, and the same `min(HTTP_TIMEOUT_SEC, remaining)` the private-proxy delete uses.
    """
    deadline = time.monotonic() + HTTP_TIMEOUT_SEC
    parts = urllib.parse.urlsplit(RELAY_URL)
    conn = http.client.HTTPSConnection(
        parts.hostname,
        parts.port or 443,
        context=ssl_context(),
        timeout=HTTP_TIMEOUT_SEC,
    )
    try:
        conn.connect()
        if PINS:
            der = conn.sock.getpeercert(binary_form=True)
            if not der or not _pin_ok(der):
                # The chain verified but this is not the certificate we were told to expect.
                # Refusing here is the whole reason pins exist: the anchor may legitimately sign
                # more than just our relay.
                raise ssl.SSLCertVerificationError("relay certificate does not match any pin")
        path = parts.path.rstrip("/") + suffix
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        conn.sock.settimeout(_remaining(deadline, "sending the request"))
        conn.request(method, path, body, headers)
        conn.sock.settimeout(_remaining(deadline, "reading the response status"))
        resp = conn.getresponse()
        # Read in pieces, re-arming the socket from the deadline before each one. A single
        # `read(MAX_ARTIFACT_BYTES)` is one call that keeps resetting the socket timeout internally,
        # which is the whole defect; the chunk size only decides how often the clock is consulted.
        raw = bytearray()
        while len(raw) < MAX_ARTIFACT_BYTES:
            conn.sock.settimeout(_remaining(deadline, "reading the response body"))
            piece = resp.read(min(65536, MAX_ARTIFACT_BYTES - len(raw)))
            if not piece:
                break
            raw += piece
        raw = bytes(raw)
        if resp.status != 200:
            raise RuntimeError(f"relay returned {resp.status}: {raw[:200]!r}")
        return json.loads(raw)
    finally:
        conn.close()


def post_heartbeat(payload):
    return relay_request("POST", "/heartbeat", payload)


def fetch_artifact():
    """Fetch this host's artifact. The relay derives the host from our certificate, not from us."""
    return relay_request("GET", "/artifact")


# ── loop ──────────────────────────────────────────────────────────────────────

HOST_OBSERVE_SEC = 15
_host_observe_lock = threading.Lock()
_host_observe_value = None
# Why the last refresh failed, or "". Carried so the pending path can name it instead of promising
# an answer that is not coming.
_host_observe_failure = ""
_host_observe_at = 0.0
_host_observe_refreshing = False


def _read_host_observation():
    """Read all nft heartbeat telemetry from one bounded structured ruleset snapshot."""
    items, detail = nft_json(["-s", "list", "ruleset"])
    if items is None:
        return {
            "observed": None,
            "detail": detail,
            "foreignFilters": None,
            "publishedPorts": None,
            "routes": observed_routes(),
        }
    ours = [
        item for item in items
        if isinstance(item, dict) and "metainfo" not in item and _is_ours(item)
    ]
    return {
        "observed": _observed_digest(ours) if ours else None,
        "detail": "" if ours else f"table {TABLE_FAMILY} {TABLE_NAME} is absent",
        "foreignFilters": _foreign_filters_from_items(items),
        "publishedPorts": _published_ports_from_items(items),
        # Read here rather than beside the nftables dump because it is a different subsystem: a
        # kernel that cannot be asked for its ruleset can usually still be asked for its routes, and
        # losing both because one failed would report less than was knowable.
        "routes": observed_routes(),
    }


def _refresh_host_observation():
    global _host_observe_value, _host_observe_at, _host_observe_refreshing
    global _host_observe_failure
    try:
        value = _read_host_observation()
        with _host_observe_lock:
            _host_observe_value = value
            _host_observe_at = time.monotonic()
            _host_observe_failure = ""
    except Exception as e:  # noqa: BLE001 — advisory observations cannot stop confirmation
        # The reason is kept, not only logged. Left in the journal alone, the next beat reports
        # "host observation refresh pending" — the word for an answer that is coming, on a failure
        # that will repeat. The workload half had the identical hole, and it is what made a permanent
        # reader failure on k3s-01.dev indistinguishable from a first beat.
        #
        # Only the detail is affected. `observed` stays null, which `hasDrifted` already reads as
        # drift, and no invented observation is cached in place of one that was never taken.
        log(f"host observation refresh failed: {e}")
        with _host_observe_lock:
            _host_observe_failure = f"host observation failed: {e}"
    finally:
        with _host_observe_lock:
            _host_observe_refreshing = False


def _invalidate_host_observation():
    """Do not let a prior generation's TTL entry describe a newly applied ruleset."""
    global _host_observe_value, _host_observe_at
    with _host_observe_lock:
        _host_observe_value = None
        _host_observe_at = 0.0


def _host_observation_report():
    """Cached nft observations; refresh all three away from the confirmation-critical loop."""
    global _host_observe_refreshing
    now = time.monotonic()
    start_failure = ""
    with _host_observe_lock:
        value = _host_observe_value
        failure = _host_observe_failure
        fresh = value is not None and now - _host_observe_at < HOST_OBSERVE_SEC
        if not fresh and not _host_observe_refreshing:
            # These are three nft subprocesses, each with its own 20-second timeout. The heartbeat
            # is the rollback confirmation signal, so none belongs on its foreground path.
            _host_observe_refreshing = True
            try:
                threading.Thread(
                    target=_refresh_host_observation,
                    name="host-observation",
                    daemon=True,
                ).start()
            except RuntimeError as e:
                # The sharpest of the three spawn sites; the others are the selector membership and
                # the workload observation. Sharpest because this one feeds the *host*
                # half: an uncaught spawn failure leaves `build_heartbeat` unbuilt, and the heartbeat
                # it would have sent is what confirms the nftables generation. A host mid-apply would
                # roll its firewall back because it could not start a thread to read `nft` with.
                _host_observe_refreshing = False
                start_failure = f"host observation could not start: {e}"
    if start_failure:
        log(start_failure)
    if value is not None:
        # A cached dump is a real observation and stays the answer — this function already serves one
        # while a refresh is in flight, and a spawn failure is not a reason to downgrade it to null.
        # `hasDrifted` reads null as drift, so discarding it here would report a healthy host as
        # having lost its ruleset. The reason for the failed refresh is in the journal.
        return value
    return {
        "observed": None,
        "detail": start_failure or failure or "host observation refresh pending",
        "foreignFilters": None,
        "publishedPorts": None,
        # Present and null on the pending path too. `build_heartbeat` reads this with `.get`, so a
        # missing key would send nothing at all — and "not reported" is the one thing this field is
        # not allowed to say by accident.
        "routes": None,
    }


def build_heartbeat(st):
    host_observation = _host_observation_report()
    observed, detail = host_observation["observed"], host_observation["detail"]
    if st.get("state") == "pending" and isinstance(st.get("referenceHash"), str):
        # This value was captured synchronously from the verified post-apply snapshot. It is the
        # only observation new enough to describe a pending generation; the TTL cache may still be
        # refreshing after invalidation.
        observed, detail = st["referenceHash"], ""
    reported_state = st["state"]
    if _nft_rollback_owed is not None:
        reported_state = "rolled-back"
    elif reported_state in {"prepared"}:
        reported_state = "pending"
    elif reported_state in {"rollback-failed", "rollback-incident"}:
        reported_state = "rolled-back"
    events = take_events()
    intruders = unauthorised_events(events)
    if intruders:
        log(f"UNAUTHORISED: {len(intruders)} change(s) to {TABLE_FAMILY} {TABLE_NAME} not made by us")
        for e in intruders[:5]:
            log(f"  {e['at']} pid={e.get('pid')} ({e.get('process')}): {e['raw'][:120]}")
    heartbeat = {
        "host": HOST_ID,
        "agentVersion": AGENT_VERSION,
        "schemaVersion": SCHEMA_VERSION,
        "applied": {
            "generation": st["generation"],
            "state": reported_state,
            "artifactHash": st["artifactHash"],
            "observedHash": observed,
            "detail": st["detail"] or detail or None,
        },
        # Buffered since the last successful heartbeat. Cleared by take_events() above, so a failed
        # send loses them — acceptable because the events are also in this host's journal, and
        # holding them would grow without bound while the relay is unreachable.
        "events": events,
        # Always sent, including as null. The relay distinguishes "not reported" from "reported
        # none" and it cannot do that if the key is simply absent on failure.
        "foreignFilters": host_observation["foreignFilters"],
        # Always sent, including as null — same null-versus-empty contract as foreignFilters (H36).
        "publishedPorts": host_observation["publishedPorts"],
        # Same null-versus-empty contract again. A packet reaches a filter only if routing sent it
        # there, so a ruleset without its routes is half an answer.
        "routes": host_observation.get("routes"),
        **_workload_report(st),
        **_membership_report(st),
    }
    # Only the workload applier has a usable kubeconfig. Absence on ordinary hosts is not a failed
    # observation; on the applier, null and an empty observation retain their distinct meanings.
    if CILIUM_EXPOSURE_ENABLED and st.get("workloadState") is not None and KUBECONFIG:
        heartbeat["ciliumExposure"] = cilium_exposure()
    return heartbeat


_membership_cache_lock = threading.Lock()
_membership_cache_key = None
_membership_cache_value = None
_membership_cache_at = 0.0
_membership_refreshing = False

_workload_cache_lock = threading.Lock()
_workload_cache_key = None
_workload_cache_observed = None
_workload_cache_detail = ""
_workload_cache_at = 0.0
_workload_refreshing = False


def _refresh_membership(watch, key):
    global _membership_cache_key, _membership_cache_value, _membership_cache_at
    global _membership_refreshing
    try:
        value = selector_membership(watch, time.time() + BACKGROUND_KUBECTL_BUDGET_SEC)
        if value is not None:
            with _membership_cache_lock:
                _membership_cache_key = key
                _membership_cache_value = value
                _membership_cache_at = time.monotonic()
    except Exception as e:  # noqa: BLE001 — this worker must never take down the heartbeat loop
        log(f"selector membership refresh failed: {e}")
    finally:
        with _membership_cache_lock:
            _membership_refreshing = False


def _membership_report(st):
    """The `membership` key of a heartbeat, or nothing at all (H14a).

    Only the applier is ever asked, and only about the selectors the manager named. Omitted entirely
    when nothing was asked — an empty object would say "queried, found nothing", which on a host that
    never runs kubectl is false.
    """
    global _membership_refreshing
    watch, reason = validate_watch_selectors(st.get("watchSelectors"))
    if reason:
        log(f"refusing persisted selector watch: {reason}")
        return {}
    if not watch:
        return {}
    key = json.dumps(watch, sort_keys=True, separators=(",", ":"))
    now = time.monotonic()
    start_failure = ""
    with _membership_cache_lock:
        value = _membership_cache_value if _membership_cache_key == key else None
        fresh = value is not None and now - _membership_cache_at < MEMBERSHIP_CACHE_SEC
        if not fresh and not _membership_refreshing:
            # Membership is advisory telemetry, never the heartbeat's critical path. The heartbeat
            # is also the nft confirm signal, so even one slow API query must not hold it behind a
            # 60-second kubectl timeout. At most one bounded worker exists; later beats use the
            # timestamped cached answer or omit the field while it catches up.
            _membership_refreshing = True
            try:
                threading.Thread(
                    target=_refresh_membership,
                    args=(watch, key),
                    name="selector-membership",
                    daemon=True,
                ).start()
            except RuntimeError as e:
                # Same two failures as the workload observation below, and for the same reason: this
                # runs inside `build_heartbeat`, which does not guard it, and the flag is raised
                # before the thread exists. Uncaught, a failed spawn costs the whole heartbeat; caught
                # but latched, it costs every later refresh. The field itself is advisory and simply
                # goes missing, which is honest — but it would go missing permanently, for a reason
                # nothing on the row could name.
                _membership_refreshing = False
                start_failure = f"selector membership could not start: {e}"
    if start_failure:
        log(start_failure)
    return {"membership": value} if value else {}


def _refresh_workload_observation(refs, key):
    global _workload_cache_key, _workload_cache_observed, _workload_cache_detail
    global _workload_cache_at, _workload_refreshing
    try:
        observed, detail = observed_objects(
            refs, time.time() + BACKGROUND_KUBECTL_BUDGET_SEC
        )
        with _workload_cache_lock:
            _workload_cache_key = key
            _workload_cache_observed = observed
            _workload_cache_detail = detail
            _workload_cache_at = time.monotonic()
    except Exception as e:  # noqa: BLE001 — telemetry cannot take down the heartbeat loop
        # ## A failure that only reaches the journal reads as "not yet" on the fleet row
        #
        # This used to log and return, leaving the cache unwritten. The next heartbeat then found
        # no entry for this key and sent `detail: "workload observation refresh pending"` — which
        # says the answer is coming. If the failure repeats, and the reason it failed the first time
        # usually makes it fail every time, that sentence is wrong on every beat after the first and
        # there is nothing on the row that says so.
        #
        # Measured 2026-08-25 on k3s-01.dev: `observed` was null while 61 of the expected objects
        # were in the cluster, so the relay reported all 70 of `mustExist` missing — the whole list,
        # because `missingObjects` returns it for a null observation. The row said "pending". An
        # operator has no way to tell that apart from a first beat, and the agent's own re-apply
        # path (`_workload_objects_missing`) stays quiet for exactly as long, because it declines to
        # act on an unknown. So the one thing that would have contradicted the applier was off, and
        # the one field that would have said why was in the journal.
        #
        # Cached under `key`, the same as the success path, so the reason is what the next beat
        # sends and a wedged reader cannot spin: this is a retry throttle as much as a report.
        log(f"workload observation refresh failed: {e}")
        with _workload_cache_lock:
            _workload_cache_key = key
            _workload_cache_observed = None
            _workload_cache_detail = f"workload observation failed: {e}"
            _workload_cache_at = time.monotonic()
    finally:
        with _workload_cache_lock:
            _workload_refreshing = False


def _workload_report(st):
    """The `workload` key of a heartbeat, or nothing at all.

    Omitted entirely on a host that was never assigned a half. The relay distinguishes "absent" from
    "reported as failing", and sending a null-filled object would turn every non-applier into a host
    with an unsatisfied workload state.
    """
    global _workload_refreshing
    if st.get("workloadState") is None:
        return {}
    refs = sorted(set(_workload_refs(st.get("workloadApplied"))))
    if not refs:
        observed, detail = [], ""
    else:
        identities = []
        for item in st.get("workloadApplied") or []:
            if isinstance(item, dict) and isinstance(item.get("ref"), str):
                identities.append((item["ref"], item.get("uid")))
            elif isinstance(item, str):
                identities.append((item, None))
        # Include the generation and Kubernetes UIDs, not only names. A missing object re-applied in
        # the same generation receives a new UID; reusing the old "missing" cache for it would cause
        # an immediate re-apply loop.
        key = (st.get("workloadGeneration"), tuple(sorted(identities)))
        now = time.monotonic()
        start_failure = ""
        with _workload_cache_lock:
            same = _workload_cache_key == key
            observed = _workload_cache_observed if same else None
            detail = _workload_cache_detail if same else "workload observation refresh pending"
            fresh = same and _workload_cache_at and now - _workload_cache_at < WORKLOAD_OBSERVE_SEC
            if not fresh and not _workload_refreshing:
                # At most one worker exists. A large legacy state can name 128 objects and each read
                # has a kubectl timeout; none of that telemetry is allowed to delay the heartbeat
                # that confirms (or rolls back) the host firewall.
                #
                # `start()` raising is worse than it looks, and worse than "telemetry goes quiet".
                # `build_heartbeat` does not guard this call, so the exception leaves the heartbeat
                # unbuilt — and the heartbeat is also the nft confirm signal. A host mid-apply would
                # roll its firewall back on a failed thread spawn. Measured: without the `try` the
                # new test does not fail, it errors, with the RuntimeError escaping `_workload_report`.
                #
                # Second, the flag is raised before the thread exists, so leaving it True latches the
                # observation off — no later beat starts another worker, and the cache freezes at
                # whatever it last held while every heartbeat reports it as current.
                #
                # Neither is hypothetical here: `MAX_SIGNED_PAYLOAD_BYTES` exists because these hosts
                # have under a gigabyte of RAM, and thread creation is among the first things to fail
                # there. Catching, lowering the flag, and saying so keeps it loud and retryable.
                _workload_refreshing = True
                try:
                    threading.Thread(
                        target=_refresh_workload_observation,
                        args=(refs, key),
                        name="workload-observation",
                        daemon=True,
                    ).start()
                except RuntimeError as e:
                    _workload_refreshing = False
                    start_failure = f"workload observation could not start: {e}"
                    detail = start_failure
        # Outside the lock: the journal write is not something to hold the cache behind.
        if start_failure:
            log(start_failure)
    return {
        "workload": {
            "state": (
                "rolled-back" if _wl_rollback_owed is not None
                else "pending" if st["workloadState"] == "prepared"
                else "rolled-back"
                if st["workloadState"] in {"rollback-failed", "rollback-incident"}
                else st["workloadState"]
            ),
            "policiesHash": st.get("workloadHash"),
            # None when the cluster could not be queried — distinct from `[]`, which means it was
            # queried and holds none of them. The manager must not read the first as the second.
            "observed": observed,
            "detail": st.get("workloadDetail") or detail or None,
        }
    }


def handle_reply(st, reply):
    """Act on a reply: confirm a pending apply, or start a new one."""
    if reply.get("schemaVersion") != SCHEMA_VERSION:
        log(
            f"relay speaks schema {reply.get('schemaVersion')}, we speak {SCHEMA_VERSION} — "
            "ignoring its instructions until versions agree"
        )
        return

    # ## The reply carries no selector watch, and reading one from it erased the signed request
    #
    # This is where `reply.get("watchSelectors")` used to be read and written to durable state. Three
    # facts made that wrong, and together they made it silent:
    #
    #   1. **The relay does not send the field.** `HeartbeatReply` is `{generation, gate,
    #      schemaVersion}` and nothing else (src/relay.ts). So the read returned `None` on every beat.
    #   2. **`None != {...}`**, so every ordinary heartbeat overwrote the durable value with `None` —
    #      including the one `accept_artifact_authorization` had just written from the *signed*
    #      manifest entry. The signed request survived about one interval.
    #   3. **Nothing tested it in either direction**, which is why it lasted. There was no test that
    #      drove `handle_reply` with a watch at all.
    #
    # The effect was that `_membership_report` returned `{}` forever: H14a selector membership never
    # reached the manager, `affectedPods` stayed "not known" for every `k8s-namespace` and
    # `k8s-label` policy, and `membershipJumps` — the guardrail for a selector quietly widening — had
    # nothing to compare.
    #
    # It was also the channel schema 3 says it closed. `protocol.ts` states that version "removes
    # unsigned relay selector instructions", and `SelectorMembership.labelled` says the keys "arrive
    # only inside the verified signed `ManifestEntry.workload.watchSelectors`". This line was the
    # exception to both. `validate_watch_selectors` bounded the damage — every namespace has to be
    # inside `HELIOPAUSE_K8S_NAMESPACES` — so it was never an escalation, but a compromised relay
    # could still choose among the queries this applier runs.
    #
    # `accept_artifact_authorization` is now the only writer, and it takes the value from the signed
    # envelope. A host that is not the applier keeps `None`; one that stops being the applier is
    # cleared by the next artifact, because the entry then carries no workload assignment.

    # This heartbeat succeeded, which is the evidence the applied ruleset did not sever the path.
    # That is the confirm — nothing off this host has to send one.
    #
    # The workload half is confirmed by the same evidence but tracked separately, and it is confirmed
    # *first*. If its durable write fails, the host half remains pending and the generation timer can
    # still restore both. This ordering prevents a confirmed host half from surviving a workload
    # rollback that was already owed.
    #
    # The evidence is weaker here and worth naming. A successful heartbeat proves the ruleset did not
    # cut the path to the relay; it proves nothing about whether the CiliumNetworkPolicy broke app
    # traffic, because that traffic does not run through this connection. What stands behind the
    # workload half is the `mustExist` read-back at apply time, not this.
    same_half = st.get("workloadGeneration") == st.get("generation")
    if st.get("state") == "prepared" or st.get("workloadState") == "prepared":
        generation = (
            st.get("generation") if st.get("state") == "prepared"
            else st.get("workloadGeneration")
        )
        rollback_generation("prepared generation reached reply handling", generation)
        return
    if st.get("state") in {"rollback-failed", "rollback-incident"} or st.get(
        "workloadState"
    ) in {"rollback-failed", "rollback-incident"}:
        # Retry timers/startup recovery own these internal states. Reporting maps them to
        # rolled-back, never pending, so a successful heartbeat cannot accidentally settle them.
        return

    if st.get("workloadState") == "pending":
        if same_half and st.get("state") in {"pending", "confirmed"}:
            if not confirm_workload(st):
                return
            st.update(load_state())
        else:
            rollback_workload(
                "workload half has no same-generation host half to confirm",
                st.get("workloadGeneration"),
            )
            return

    if st.get("state") == "pending":
        if (
            st.get("workloadGeneration") == st.get("generation")
            and st.get("workloadState") in {"rolled-back", "rollback-failed", "rollback-incident"}
        ):
            rollback_generation("workload half rolled back before host confirmation", st.get("generation"))
            return
        # nft-only artifacts have no workload state. A same-generation confirmed workload is the
        # expected intermediate state after the first durable confirmation write above.
        confirm(st)
        return

    if (
        st.get("state") == "rolled-back"
        and st.get("workloadState") == "confirmed"
        and same_half
    ):
        rollback_workload(
            "host half rolled back before the generation settled",
            st.get("workloadGeneration"),
            allow_confirmed=True,
        )
        return

    wanted = reply.get("generation")
    gate = reply.get("gate") or {}
    if wanted is None:
        return
    if wanted == st["generation"] and st["state"] == "confirmed":
        # Confirmed *and* still in the kernel. Those are different facts, and this used to check only
        # the first.
        #
        # An nftables table lives in kernel memory. A reboot destroys it, while the state file on
        # disk still says `confirmed` — so the agent read "already applied" and did nothing, forever.
        # Measured on mailer-01: after a reboot the host held only `table inet firewalld`, our table
        # was gone, and the fleet view reported `confirmed`. Under stage 1 that was harmless because
        # the ruleset blocks nothing; under default-deny the firewall silently ceases to exist while
        # the control plane insists it is there — the worst combination available, because the thing
        # that would tell you is the thing that is lying.
        #
        # Drift detection *noticed* (the dump no longer matched the reference) but drift only reports.
        # Re-applying is what closes the gap, and it is safe: the artifact is the same one already
        # confirmed, so this restores the state the host is supposed to be in rather than changing it.
        #
        # The workload half is checked by the same argument, and it was missing here at first. Its
        # objects live in the API server rather than kernel memory, so a reboot does not take them —
        # but `kubectl delete`, a flux prune that caught them, or a namespace being recreated all do,
        # and the state file would still read `confirmed`. Same shape of failure, same fix: notice the
        # objects are gone and re-apply. Checked before `observed_state` because the nftables table
        # being present is the common case and would otherwise return before ever asking.
        host_observation = _host_observation_report()
        observed, detail = host_observation["observed"], host_observation["detail"]
        wl_gone = _workload_objects_missing(st)
        if observed is not None and not wl_gone:
            return
        if observed is None and "refresh pending" in (detail or "") and not wl_gone:
            # Unknown is not absence. The single background snapshot will resolve this without
            # putting a bounded nft read back on the confirmation-critical thread.
            return
        if wl_gone:
            log(f"generation {wanted} is confirmed but workload objects are absent ({wl_gone}) — re-applying")
        if observed is None:
            log(f"generation {wanted} is confirmed but the table is absent ({detail}) — re-applying")
        # Fall through to the apply path below. `pending` while it re-confirms, which is correct:
        # the ruleset is being applied again and the rollback timer should cover it again.
    if wanted == st["generation"] and st["state"] in {
        "rolled-back", "rollback-failed", "rollback-incident",
    }:
        # This generation already cost us the path to the relay once. The relay keeps offering it
        # because gating is the manager's decision, not ours — but retrying on the next beat would
        # flap the host's firewall every interval forever. Recovery is a *new* generation, which
        # differs here and applies normally.
        return
    if wanted == st.get("workloadGeneration") and st.get("workloadState") in {
        "rolled-back", "rollback-failed", "rollback-incident",
    }:
        return
    if not gate.get("open", False):
        log(f"generation {wanted} is waiting on stage {gate.get('stage')}: {gate.get('reason')}")
        return

    try:
        envelope = fetch_artifact()
    except Exception as e:  # noqa: BLE001
        log(f"cannot fetch artifact for generation {wanted}: {e}")
        return

    # ## The relay hands over a signed envelope, and this is where it stops being one
    #
    # `verify_artifact_envelope` had **zero callers** — in the agent and in its tests — so the
    # signature the whole path exists for was never checked, and the unwrapped artifact never
    # appeared: `fetch_artifact()` returns `{version, algorithm, keyId, payload, signature}`, which
    # has no `generation`, so every beat logged "artifact is generation None" and applied nothing.
    # Measured 2026-08-15 on the first fleet-wide rollout of the signed path.
    #
    # The order below is the point. Verification raises **before any side effect**, then the replay
    # watermark is advanced **durably** before the kernel or kubectl is touched — otherwise a crash
    # between apply and record leaves a window where the same authorization can be replayed.
    try:
        artifact, record, watch, expired = verify_artifact_envelope(envelope)
    except Exception as e:  # noqa: BLE001 — a bad envelope is a refusal, never a crash of the loop
        log(f"refusing artifact for generation {wanted}: {e}")
        return
    if artifact.get("generation") != wanted:
        # The relay reloaded mid-exchange. Waiting for the next beat costs one interval; applying
        # a generation we were not gated for costs a staging decision.
        log(f"artifact is generation {artifact.get('generation')}, expected {wanted} — skipping")
        return
    accepted, accept_error = accept_artifact_authorization(record, watch, expired)
    if accepted is None:
        log(f"refusing authorization for generation {wanted}: {accept_error}")
        return

    # Validate the host half without touching the kernel, then apply the workload half first. A
    # workload apply can legitimately spend minutes in API admission/read-back; arming the host's
    # shorter timer before that work made healthy generations self-rollback. Once both halves have a
    # side effect, either one's timer restores both for the same generation.
    host_doc, host_timeout, host_error = _preflight_host_artifact(artifact)
    host_result = host_doc is None
    ok, state, detail = (False, "unsupported", host_error)
    wl_ok, wl_state, wl_detail = (True, None, "")
    if host_doc is not None:
        wl_ok, wl_state, wl_detail = apply_workload(artifact)
        if wl_ok:
            host_result = True
            ok, state, detail = apply_artifact(artifact, (host_doc, host_timeout))
            durable = load_state()
            workload_rolled = (
                durable.get("workloadGeneration") == wanted
                and durable.get("workloadState") in {
                    "rolled-back", "rollback-failed", "rollback-incident",
                }
            )
            if not ok or workload_rolled:
                rollback_generation(
                    detail or "workload half rolled back while host half was applying", wanted
                )
                durable = load_state()
                ok = False
                state = durable.get("state") or "rolled-back"
                detail = durable.get("detail") or detail
                if wl_state is not None:
                    wl_ok = False
                    wl_state = durable.get("workloadState") or "rolled-back"
                    wl_detail = durable.get("workloadDetail") or wl_detail
        else:
            # The host is still on its prior ruleset and has no rollback timer. Recording the
            # workload refusal is enough to stop this generation without creating a cross-layer
            # window in which the short host promise expires behind slow cluster work.
            detail = f"host half left untouched because workload apply failed: {wl_detail}"
            log(f"workload half of generation {wanted} not applied: {wl_detail}")

    # Re-read before writing. `st` was loaded *before* the apply, and the apply persisted the
    # rollback commitment to this same file — so writing the pre-apply copy back would erase the
    # commitment, silently returning the agent to the pre-V28 behaviour where a restart during the
    # confirm window strands the host behind a ruleset nothing will undo.
    #
    # Caught on a real host: immediately after applying, the state file read `"state": "pending"`
    # with `pendingBackup: null, rollbackAt: null` — armed in memory, unprotected on disk. The
    # in-process timer still worked, which is exactly why this had to be found by looking rather
    # than by anything failing. Same class of bug as the heartbeat loop's stale copy; this instance
    # was missed because the write looks like it only touches the four fields named below.
    def record_result(fresh):
        # A timer can fire while the workload half is still being applied. Never resurrect a
        # generation that its timer has already rolled back just because this handler started first.
        nft_timer_won = (
            fresh.get("generation") == wanted
            and fresh.get("state") in {
                "rolled-back", "rollback-failed", "rollback-incident",
            }
        ) or _nft_rollback_owed == wanted
        if host_result and not nft_timer_won:
            fresh["generation"] = wanted if ok else fresh["generation"]
            fresh["state"] = state
            fresh["artifactHash"] = artifact.get("rulesetHash") if ok else fresh["artifactHash"]
            fresh["detail"] = detail or None
        # `wl_state is None` means nothing was assigned, and the field stays as it was. Likewise, a
        # timer-owned rolled-back state always wins over this earlier handler's pending result.
        workload_timer_won = (
            fresh.get("workloadGeneration") == wanted and
            fresh.get("workloadState") in {
                "rolled-back", "rollback-failed", "rollback-incident",
            }
        ) or _wl_rollback_owed == wanted
        if wl_state is not None and not workload_timer_won:
            fresh["workloadGeneration"] = wanted
            fresh["workloadState"] = wl_state
            fresh["workloadHash"] = (
                (artifact.get("workload") or {}).get("policiesHash")
                if wl_ok else fresh.get("workloadHash")
            )
            fresh["workloadDetail"] = wl_detail or None

    fresh, _ = update_state(record_result)
    st.update(fresh)
    if host_result and not ok:
        log(f"generation {wanted} not applied: {detail}")


def handle_reply_safely(st, reply):
    """Keep one malformed or surprising reply from terminating the long-lived agent loop."""
    if not isinstance(reply, dict):
        log(f"relay reply is {type(reply).__name__}, expected an object — ignored")
        return False
    try:
        handle_reply(st, reply)
        return True
    except Exception as e:  # noqa: BLE001 — pending commitments remain durable and will roll back
        log(f"relay reply refused after an internal validation failure: {e}")
        return False


def sleep_interval():
    """Wait one interval, with jitter, unless we are stopping.

    The jitter matters at fleet scale: hosts brought up by the same cloud-init run would otherwise
    heartbeat in lockstep forever, turning a steady trickle into a periodic spike against a
    gateway that has under a gigabyte of RAM.
    """
    _stop.wait(INTERVAL_SEC + random.uniform(0, INTERVAL_SEC * 0.2))


def _has_live_commitment(st):
    return (
        _nft_rollback_owed is not None
        or _wl_rollback_owed is not None
        or st.get("state") in {"prepared", "pending", "rollback-failed"}
        or st.get(
        "workloadState"
        ) in {"prepared", "pending", "rollback-failed"}
    )


def main():
    missing = [
        name
        for name, val in (
            ("HELIOPAUSE_RELAY_URL", RELAY_URL),
            ("HELIOPAUSE_CA_FILE", CA_FILE),
            ("HELIOPAUSE_CERT_FILE", CERT_FILE),
            ("HELIOPAUSE_KEY_FILE", KEY_FILE),
            # These three are what the signed-artifact path needs, and the header has called them
            # required since it was written — the check had not caught up. Unset, the agent starts,
            # authenticates, heartbeats, and looks healthy while **refusing every generation**:
            # `TARGET` defaults to "" so the target comparison rejects any real bundle, and an
            # unconfigured key directory makes trust loading raise on first use. Both fail closed,
            # which is the right direction and the wrong signal — the error names the artifact, so
            # the operator reads "bad generation" for what is a missing line in agent.env.
            ("HELIOPAUSE_TARGET", TARGET),
            ("HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR", MANAGER_SIGNING_KEYS_DIR),
            ("HELIOPAUSE_BREAK_GLASS_KEYS_DIR", BREAK_GLASS_KEYS_DIR),
        )
        if not val
    ]
    if missing:
        log(f"missing required environment: {', '.join(missing)}")
        return 2
    # Beside the missing-variable check rather than at import, so a bad interval reads as the same
    # kind of problem it is — a line in agent.env — instead of a traceback. See `_interval_from_env`.
    if INTERVAL_ERROR:
        log(INTERVAL_ERROR)
        return 2
    if urllib.parse.urlsplit(RELAY_URL).scheme != "https":
        log(f"HELIOPAUSE_RELAY_URL must be https — got {RELAY_URL!r}")
        return 2

    # Loaded here rather than on the first artifact. Lazily, a directory with wrong permissions or a
    # key that is not Ed25519 surfaces only when a generation arrives — during a rollout, on the host
    # that was supposed to apply it, as a verification failure. Doing it at startup turns a
    # deployment mistake into an immediate exit naming the directory, and it costs one read of two
    # small directories.
    try:
        trust = load_artifact_trust()
    except (OSError, ValueError) as e:
        log(f"artifact signing trust is unusable: {e}")
        return 2
    log(
        f"artifact trust: {len(trust['managerKeyIds'])} manager key(s), "
        f"{len(trust['breakGlassKeyIds'])} break-glass key(s), {trust['trustDigest']}"
    )

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: _stop.set())

    log(f"{AGENT_VERSION} starting: host={HOST_ID} relay={RELAY_URL} table={TABLE_FAMILY} {TABLE_NAME}")
    log(f"pins: {len(PINS)} configured" if PINS else "pins: none (anchor verification only)")

    # Before the first heartbeat, and before the monitor. If the previous process left an
    # unconfirmed apply that severed the relay path, heartbeating first would block for the HTTP
    # timeout while a deadline this host owes went unhonoured.
    recover_commitment()
    # Same reasoning for the workload half, and it needs its own call because the two commitments have
    # separate deadlines. A no-op on every host that is not the applier.
    recover_workload_commitment()
    reconcile_recovered_commitments()

    # Watches the ruleset for changes this agent did not make. Daemon, so a wedged monitor can
    # never keep the process alive; the heartbeat loop is what must not stop.
    threading.Thread(target=monitor_loop, name="nft-monitor", daemon=True).start()

    failures = 0
    while not _stop.is_set():
        # Re-read every beat rather than holding one dict for the process lifetime. The rollback
        # timer fires on its own thread and writes state there; a long-lived copy here would go
        # stale exactly when it matters and report `pending` for a host that had already reverted.
        st = load_state()
        try:
            reply = post_heartbeat(build_heartbeat(st))
        except Exception as e:  # noqa: BLE001 — the loop must outlive every transport failure
            failures += 1
            # Logged every time rather than deduplicated: a heartbeat that stops landing is the
            # signal rollback will key on, so the record of when it stopped has to be complete.
            log(f"heartbeat failed ({failures} consecutive): {e}")
            if _has_live_commitment(load_state()):
                # Confirmation is the safety-critical job while a promise is live. Retry quickly
                # enough that one failed HTTP attempt plus the bounded apply path still fits the
                # receiver's minimum window; fleet jitter resumes after the state settles.
                _stop.wait(ROLLBACK_RETRY_SEC)
            else:
                sleep_interval()
            continue

        if failures:
            log(f"heartbeat recovered after {failures} failures")
            failures = 0

        # Re-read state before acting on the reply. The rollback timer runs on its own thread and
        # can fire *during* the request above — and with a `drop` rule the request does not fail,
        # it hangs, so the window is the full HTTP timeout rather than an instant. Acting on the
        # copy loaded before the request would see `pending` for a host that had already reverted,
        # and re-apply the very generation that just locked it out, every interval, forever.
        st = load_state()
        handle_reply_safely(st, reply)
        if _has_live_commitment(load_state()):
            continue
        sleep_interval()

    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
