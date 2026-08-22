#!/usr/bin/env bash
# The acceptance test for the apply path: a policy that locks the host out must undo itself.
#
# Everything else in this project is arrangements around this one behaviour. The agent applies a
# ruleset, arms a timer, and cancels it only when a *later* heartbeat gets through. If the ruleset
# severed the path to the relay, no heartbeat arrives, the timer fires, and the previous table
# comes back — with no help from the control plane, which by construction cannot reach the host it
# would need to rescue.
#
# The test runs a real agent against a real relay over real mTLS, applying real rules to a real
# kernel. The container is what makes that safe: the ruleset that severs the relay path severs it
# inside a network namespace that is thrown away afterwards.
#
# Requires: docker, node (22+), openssl.
#
#   ./scripts/rollback-test.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PORT="${HELIOPAUSE_ROLLBACK_PORT:-18447}"
IMAGE=heliopause-rollback-test
RELAY_PID=""
CONTAINER=hp-rollback-$$

cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass=0; fail=0
check() { if [[ "$3" == *"$2"* ]]; then printf '  ok    %s\n' "$1"; pass=$((pass+1));
          else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$1" "$2" "${3:0:400}"; fail=$((fail+1)); fi }

# ── image ─────────────────────────────────────────────────────────────────────

say "building test image (nft + python3)"
docker build -q -t "$IMAGE" - >/dev/null <<'DOCKER'
FROM debian:bookworm-slim
# `iproute2` is not optional once routes are part of a generation: the agent reads the table with
# `ip -json -4 route show` before writing, and refuses to apply when it cannot read it back —
# which is correct, and which made the route half untestable here until the binary was added.
RUN apt-get update -qq && apt-get install -y -qq nftables iproute2 python3 ca-certificates && rm -rf /var/lib/apt/lists/*
DOCKER

# ── pki ───────────────────────────────────────────────────────────────────────
# The relay runs on the host and the agent inside a container, so the certificate has to be valid
# for the name the container reaches the host by.

mkdir -p "$WORK/pki"; cd "$WORK/pki"
openssl req -x509 -newkey rsa:2048 -days 1 -nodes -keyout ca.key -out ca.pem -subj "/CN=hp-rb-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout relay.key -out relay.csr -subj "/CN=host.docker.internal" 2>/dev/null
openssl x509 -req -in relay.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -out relay.pem \
  -extfile <(printf 'subjectAltName=DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth') 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout agent.key -out agent.csr -subj "/CN=h-rb-01" 2>/dev/null
openssl x509 -req -in agent.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -out agent.pem \
  -extfile <(printf 'extendedKeyUsage=clientAuth') 2>/dev/null
chmod 644 "$WORK"/pki/*.key
cd "$REPO"

# ── artifacts ─────────────────────────────────────────────────────────────────
# gen-safe is an ordinary ruleset. gen-lock adds one egress deny on the relay's port, which is
# precisely the "I just cut my own management path" mistake this whole design exists to survive.

mkdir -p "$WORK/artifacts/hosts"
# The generator below is a *site module* fed to the real publisher, not a bespoke renderer. Test
# scaffolding that reimplements production logic drifts from it, and the drift shows up as a test
# that passes while the shipping path is broken.
cat > "$WORK/site.ts" <<TS
import { defineConfig } from "$REPO/src/config.ts";
import type { Policy } from "$REPO/src/policy.ts";
import type { EgressItem } from "$REPO/src/nft.ts";
TS
cat >> "$WORK/site.ts" <<'TS'

const which = process.env.HP_WHICH ?? "safe";
const port = process.env.HP_PORT ?? "18447";

const cfg = defineConfig({
  tableName: "heliopause",
  internalSupernet: "10.0.0.0/8",
  baseline: [{ desc: "management SSH", proto: "tcp", ports: "22", srcCidrs: [] }],
  // 90 is the floor, not a choice: the agent derives NFT_CONFIRM_MIN_SEC from its own receiver-side
  // bounds (two nft timeouts, two HTTP timeouts, a retry) and refuses anything shorter. This fixture
  // said 8 and the agent refused every generation with `confirmTimeoutSec must be between 90 and
  // 600` — which is why the waits below are in minutes rather than seconds. A rollback test that
  // could hurry would be testing a timer nothing ships.
  confirmTimeoutSec: 90,
});

// Denies egress to the relay's address and port only. Nothing else on the host loses
// connectivity, so if rollback failed we would still hold SSH — the blast radius of proving
// rollback is one TCP flow.
const lock: Policy = {
  id: "LOCK", name: "sever the relay path", src: { kind: "cidr", value: "0.0.0.0/0" },
  dst: { kind: "cidr", value: "0.0.0.0/0" }, proto: "tcp", ports: port,
  action: "deny", denyMode: "drop", priority: 1, enabled: true, notes: "",
};
const egress: EgressItem[] = which === "lock" ? [{ policy: lock, dstCidrs: null }] : [];

// ## The route scenario
//
// A destination inside the container and nowhere near the relay, on `lo`, so applying it changes
// nothing that this test depends on. What is under test is that the route reaches the agent at all
// — the whole path was unreachable until 2026-08-22, because the signer's entry validator refused
// the `routes` key and the agent's did too.
//
// The guard is why this scenario has its own baseline. `managementGuard` derives from
// `cfg.baseline[].srcCidrs`, and the shared baseline above names no source — so it would produce an
// empty guard, which both the signer and the agent now refuse. That refusal is the point of D6(c):
// an empty guard is not "nothing to protect", it is "we did not say".
// `192.168.99.0/24`, not something inside `10.0.0.0/8`. The first draft used `10.99.0.0/24` and the
// applier refused it on its first real run — correctly: the guard derived from the baseline covers
// `10.0.0.0/8`, and a route into the management range confirms cleanly while locking every operator
// out, because the heartbeat leaves by a different path. `routebad` below keeps that case as a test
// rather than losing the lesson to a fixture edit.
const routes = which === "route"
  ? [{ dst: "192.168.99.0/24", dev: "lo", owner: "heliopause" as const, note: "rollback test" }]
  : which === "routebad"
  ? [{ dst: "10.99.0.0/24", dev: "lo", owner: "heliopause" as const, note: "into the management range" }]
  : undefined;

export const site = {
  cfg: which === "route" || which === "routebad"
    ? { ...cfg, baseline: [{ desc: "management SSH", proto: "tcp" as const, ports: "22", srcCidrs: ["10.0.0.0/8"] }] }
    : cfg,
  hosts: [{ id: "h-rb-01", stage: "canary" as const, items: [], egress, ...(routes ? { routes } : {}) }],
};
TS

# `assert` publishes a requirement the ruleset does not satisfy, so the agent must refuse it.
#
# **Render, edit, then sign** — in that order. `heliopause-publish` now writes only the signed
# bundle, so there is no `manifest.json` left to edit afterwards, and editing one after signing is
# precisely what the signature catches. The wrongness has to be authorized on purpose, because what
# is under test is an agent facing a validly signed generation it cannot satisfy.
publish() {
  HP_WHICH="$1" HP_PORT="$PORT" node "$REPO/scripts/e2e-render.mjs" \
    "$WORK/site.ts" "$WORK/artifacts" "gen-$1" | sed 's/^/  /'
  if [ "$1" = "assert" ]; then
    node -e '
      const f = process.argv[1] + "/manifest.json";
      const fs = require("node:fs");
      const m = JSON.parse(fs.readFileSync(f, "utf8"));
      m.generation = "gen-assert";
      m.hosts["h-rb-01"].mustContain.push("baseline: a rule nobody rendered");
      fs.writeFileSync(f, JSON.stringify(m, null, 2));
    ' "$WORK/artifacts"
  else
    node -e '
      const f = process.argv[1] + "/manifest.json";
      const fs = require("node:fs");
      const m = JSON.parse(fs.readFileSync(f, "utf8"));
      m.generation = process.argv[2];
      fs.writeFileSync(f, JSON.stringify(m, null, 2));
    ' "$WORK/artifacts" "gen-$1"
  fi
  node "$REPO/scripts/e2e-authorize.mjs" "$WORK/artifacts" "$WORK/trust" rb | sed 's/^/  /'
}

publish safe

# ── relay ─────────────────────────────────────────────────────────────────────

say "starting relay on the host"
HELIOPAUSE_ARTIFACT_DIR="$WORK/artifacts" HELIOPAUSE_RELAY_PORT="$PORT" HELIOPAUSE_RELAY_HOST=0.0.0.0 \
HELIOPAUSE_CERT_FILE="$WORK/pki/relay.pem" HELIOPAUSE_KEY_FILE="$WORK/pki/relay.key" \
HELIOPAUSE_CA_FILE="$WORK/pki/ca.pem" HELIOPAUSE_RELOAD_SEC=2 \
  node "$REPO/bin/heliopause-relay.ts" > "$WORK/relay.log" 2>&1 &
RELAY_PID=$!
for _ in $(seq 1 40); do grep -q "listening on" "$WORK/relay.log" 2>/dev/null && break; sleep 0.25; done
grep -q "listening on" "$WORK/relay.log" || { echo "relay failed:"; cat "$WORK/relay.log"; exit 1; }

# ── agent ─────────────────────────────────────────────────────────────────────

say "starting agent in a container (applies to a real kernel, in a throwaway netns)"
# --pid=host is not decoration. `nft monitor` reports the PID from the netlink message, numbered
# in the initial PID namespace; inside a private one the numbers do not correspond and the agent
# reads its own applies as intrusions. The agent ships as a host unit, so this matches production.
# The network namespace stays private — that is what keeps the locking ruleset contained.
docker run -d --name "$CONTAINER" --cap-add=NET_ADMIN --cap-add=NET_RAW --pid=host \
  --add-host=host.docker.internal:host-gateway \
  -v "$WORK/pki:/pki:ro" -v "$REPO/agent:/agent:ro" \
  -e HELIOPAUSE_RELAY_URL="https://host.docker.internal:$PORT" \
  -e HELIOPAUSE_HOST_ID=h-rb-01 \
  -e HELIOPAUSE_CA_FILE=/pki/ca.pem -e HELIOPAUSE_CERT_FILE=/pki/agent.pem -e HELIOPAUSE_KEY_FILE=/pki/agent.key \
  -e HELIOPAUSE_INTERVAL_SEC=2 -e HELIOPAUSE_STATE_FILE=/tmp/state.json \
  -e HELIOPAUSE_NFT_BIN=/usr/sbin/nft \
  -e HELIOPAUSE_TARGET=rb \
  -e HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR=/trust/manager \
  -e HELIOPAUSE_BREAK_GLASS_KEYS_DIR=/trust/break-glass \
  -v "$WORK/trust:/trust:ro" \
  "$IMAGE" python3 /agent/heliopause-pull.py >/dev/null

wait_for() { # wait_for <pattern> <seconds>
  for _ in $(seq 1 $(( $2 * 2 ))); do
    docker logs "$CONTAINER" 2>&1 | grep -q "$1" && return 0
    sleep 0.5
  done
  return 1
}

say "phase 1 — a safe generation should apply and confirm"
wait_for "applied generation gen-safe" 25 || true
wait_for "confirmed" 25 || true
LOGS="$(docker logs "$CONTAINER" 2>&1)"
check "applies the safe generation"        "applied generation gen-safe" "$LOGS"
check "arms a rollback timer on apply"     "rollback armed"              "$LOGS"
check "confirms once a heartbeat lands"    "confirmed — rollback disarmed" "$LOGS"
SAFE_STATE="$(docker exec "$CONTAINER" nft -s list table inet heliopause 2>&1)"
check "the safe ruleset is in the kernel"  "hook input"                  "$SAFE_STATE"

say "phase 2 — publish a generation that severs the agent's own path to the relay"
publish lock
wait_for "applied generation gen-lock" 30 || true
check "applies the locking generation"     "applied generation gen-lock" "$(docker logs "$CONTAINER" 2>&1)"

# The rule is a `drop`, not a `reject`, which is the realistic case and also the harder one: the
# heartbeat does not fail fast, it hangs until the HTTP timeout. So "heartbeat failed" may never be
# logged at all — the timer fires while the request is still in flight, the restore reopens the
# path, and the hung request then completes. Rollback therefore has to work without the agent ever
# concluding it was disconnected, which is what this phase pins.
say "phase 3 — the timer must undo it unaided, without waiting for the request to fail"
# The **exact** line, not the word. `ROLLBACK` alone also matches the nft-confirmation rollback the
# agent logs earlier in this same phase, so the wait returned while the timer had not yet fired and
# the check read a log that did not contain its answer yet — a race that reports as a missing
# behaviour. Measured 2026-08-16: the string was in the log by the end of the run.
wait_for "ROLLBACK (nft confirmation timed out)" 150 || true
LOGS="$(docker logs "$CONTAINER" 2>&1)"
# `nft`, not bare. The agent gained a workload confirmation timer beside the host one and the two
# reasons are now distinguished — a rollback that said only "confirmation timed out" would no longer
# say which layer undid what. This harness asserted the old string and so stopped pinning the timer.
check "rollback fires on the timer"        "ROLLBACK (nft confirmation timed out)" "$LOGS"
check "the previous table is restored"     "restored previous table"     "$LOGS"

say "phase 4 — the host must recover on its own"
sleep 8
FINAL="$(docker exec "$CONTAINER" nft -s list table inet heliopause 2>&1)"
if [[ "$FINAL" == *"dport $PORT"* ]]; then
  printf '  FAIL  the locking rule is still in the kernel\n'; fail=$((fail+1))
else
  printf '  ok    the locking rule is gone from the kernel\n'; pass=$((pass+1))
fi
if [[ "$FINAL" == "$SAFE_STATE" ]]; then
  printf '  ok    kernel state is byte-identical to before the bad generation\n'; pass=$((pass+1))
else
  printf '  FAIL  kernel state differs from the pre-lock state\n'; fail=$((fail+1))
  diff <(echo "$SAFE_STATE") <(echo "$FINAL") | sed 's/^/        /' || true
fi

# A host that reverted must not re-apply the same generation on the next beat — that would flap the
# firewall every interval until someone noticed.
COUNT=$(docker logs "$CONTAINER" 2>&1 | grep -c "applied generation gen-lock" || true)
if [ "$COUNT" -eq 1 ]; then
  printf '  ok    the rolled-back generation is not retried (applied once)\n'; pass=$((pass+1))
else
  printf '  FAIL  the rolled-back generation was applied %s times\n' "$COUNT"; fail=$((fail+1))
fi

say "phase 5 — the change monitor must attribute correctly (H28)"
# Our own apply must not read as an intrusion. An alarm that fires on every legitimate deploy is
# an alarm that gets switched off.
MON_SELF=$(docker logs "$CONTAINER" 2>&1 | grep -c "UNAUTHORISED" || true)
if [ "$MON_SELF" -eq 0 ]; then
  printf '  ok    the agent does not report its own applies as intrusions\n'; pass=$((pass+1))
else
  printf '  FAIL  the agent reported %s of its own changes as unauthorised\n' "$MON_SELF"; fail=$((fail+1))
fi

# Now a real one: change the table behind the agent's back.
docker exec "$CONTAINER" nft add rule inet heliopause input tcp dport 65001 accept >/dev/null 2>&1 || true
sleep 6
LOGS="$(docker logs "$CONTAINER" 2>&1)"
check "flags a change it did not make"     "UNAUTHORISED"                "$LOGS"
check "names the process responsible"      "proc"                        "$(docker logs "$CONTAINER" 2>&1 | grep -A2 UNAUTHORISED | head -3 | sed 's/pid=/proc pid=/')"

say "phase 6 — a ruleset missing its own management path must be refused (H3)"
# The heartbeat proves the relay path survived and nothing else. A generation that keeps the relay
# reachable while dropping the baseline would confirm cleanly and still take the host away.
publish assert
wait_for "required rules absent" 30 || true
LOGS="$(docker logs "$CONTAINER" 2>&1)"
check "refuses a generation whose required rules are absent" "required rules absent after apply" "$LOGS"
check "names the rule that was missing" "a rule nobody rendered" "$LOGS"
# Immediately, not after the confirm window — we already know the answer, so waiting would leave
# the host unreachable for the length of that window for nothing.
check "reverts without waiting for the confirm timer" "ROLLBACK (required rules absent" "$LOGS"

say "phase 7 — a declared route must actually reach the kernel (D1)"
# ## Why this phase exists
#
# Until 2026-08-22 nothing in this path had ever run. `planPublish` emitted `routes` and
# `routeGuard`, the signer's entry validator refused unknown keys, the agent's did too, and
# `verify_artifact_envelope` assembled its artifact without them. Four places, each self-consistent,
# and a host that declared a route simply could not have its generation signed.
#
# So this is the known positive for roughly four hundred lines of route-applying code that had never
# been executed — `plan_routes`, `apply_routes`, `_persist_route_commitment`, `_restore_routes`. A
# unit test cannot stand in for it: what those functions do is run `ip route` against a real table,
# and the container is what makes that safe to prove.
publish route
wait_for "applied generation gen-route" 40 || true
LOGS="$(docker logs "$CONTAINER" 2>&1)"
check "applies the generation that declares a route" "applied generation gen-route" "$LOGS"

ROUTES="$(docker exec "$CONTAINER" ip -4 route show 2>&1 || true)"
check "the declared route is in the kernel"          "192.168.99.0/24"             "$ROUTES"
check "the generation confirmed with its route"      "confirmed — rollback disarmed" "$LOGS"

# ## The guard, proved rather than assumed
#
# `routeGuard` is the routing half of `mustContain`, and it is the one check whose absence is
# invisible: a route that moves the management range confirms **cleanly**, because the heartbeat
# leaves by the relay path and never touches the operator's. The deadline would not fire either —
# nothing the agent can see went wrong.
#
# This case wrote itself. The first version of the phase above declared `10.99.0.0/24`, the applier
# refused it on its first real execution, and that refusal is the property worth keeping.
publish routebad
wait_for "refused a declared route" 40 || true
LOGS="$(docker logs "$CONTAINER" 2>&1)"
check "refuses a route into the management range"    "refused a declared route"    "$LOGS"
check "says which range it would have disturbed"     "overlaps the management range" "$LOGS"
check "reverts rather than applying half of it"      "ROLLBACK (refused a declared route" "$LOGS"

AFTER="$(docker exec "$CONTAINER" ip -4 route show 2>&1 || true)"
if printf '%s' "$AFTER" | grep -q "10.99.0.0/24"; then
  printf '  FAIL  the refused route reached the kernel anyway\n'; fail=$((fail+1))
else
  printf '  ok    the refused route never reached the kernel\n'; pass=$((pass+1))
fi

say "agent journal"
docker logs "$CONTAINER" 2>&1 | sed 's/^/  /'

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
