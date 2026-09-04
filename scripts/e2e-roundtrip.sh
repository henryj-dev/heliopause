#!/usr/bin/env bash
# End-to-end check of the pull transport: python agent → mTLS → node relay.
#
# This exists because the properties it checks cannot be unit-tested. Identity binding depends on
# a real TLS handshake presenting a real client certificate, and the whole security argument for
# staged rollout rests on it: if the relay cannot tell which agent is calling, any host with a
# valid certificate can report as the canary and wave a bad generation through to the fleet.
#
# Everything is built in a temporary directory and torn down at exit. It touches no firewall and
# needs no privileges — the agent build it exercises cannot apply anything yet.
#
# Requires: openssl, node (22+), python3, curl.
#
#   ./scripts/e2e-roundtrip.sh

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
PORT="${HELIOPAUSE_E2E_PORT:-18446}"
RELAY_PID=""

cleanup() {
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

pass=0
fail=0
check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then
    printf '  ok    %s\n' "$1"; pass=$((pass + 1))
  else
    printf '  FAIL  %s\n        wanted substring: %s\n        got: %s\n' "$1" "$2" "$3"
    fail=$((fail + 1))
  fi
}

# ── PKI ───────────────────────────────────────────────────────────────────────
# A private CA, a relay certificate for localhost, and two agent certificates. The second agent is
# the whole point: it is legitimately enrolled, which is what makes its impersonation attempt a
# real test rather than a test of certificate validation.

mkdir -p "$WORK/pki"
cd "$WORK/pki"
openssl req -x509 -newkey rsa:2048 -days 1 -nodes -keyout ca.key -out ca.pem \
  -subj "/CN=heliopause-e2e-ca" 2>/dev/null

issue() { # issue <name> <subject-CN> <ext>
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -out "$1.pem" \
    -extfile <(printf '%b' "$3") 2>/dev/null
}
issue relay localhost "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth"
issue agent h-e2e-01 "extendedKeyUsage=clientAuth"
issue agent2 h-e2e-02 "extendedKeyUsage=clientAuth"
# A valid certificate for a host this generation does not carry. See the artifact-store note.
issue agent3 h-e2e-03 "extendedKeyUsage=clientAuth"
# An operator certificate is a client certificate like the agents' — the difference is only which
# CN the relay's allowlist names. That is exactly what the /status checks below have to prove: that
# holding a valid certificate is not sufficient.
issue operator ops-alice "extendedKeyUsage=clientAuth"

PIN="sha256/$(openssl x509 -in relay.pem -outform DER | openssl dgst -sha256 -binary | base64)"

# ── Artifact store ────────────────────────────────────────────────────────────
# Every host named in the manifest carries a ruleset. That is not tidiness: `signAuthorizedArtifact\
# Bundle` refuses a manifest naming a host the bundle has no ruleset for, and the relay refuses to
# load a bundle whose artifacts do not exactly match its manifest. **The relay's 500 "artifact
# unavailable" branch is therefore unreachable for any bundle it can load** — it is defence in depth
# against an inconsistency the format now prevents, and the harness used to produce it by writing
# the manifest by hand.
#
# `h-e2e-03` covers the reachable half instead: a caller holding a valid certificate for a host the
# manifest does not name. The property under test is unchanged — the refusal must name no path.
#
# `h-e2e-02` stays in the manifest and never reports, which is what the fleet-view case needs.

mkdir -p "$WORK/artifacts/hosts"
cat > "$WORK/artifacts/hosts/h-e2e-01.nft" <<'JSON'
{
  "nftables": [
    { "add": { "table": { "family": "inet", "name": "heliopause" } } },
    { "delete": { "table": { "family": "inet", "name": "heliopause" } } },
    { "add": { "table": { "family": "inet", "name": "heliopause" } } },
    { "add": { "chain": { "family": "inet", "table": "heliopause", "name": "input",
                          "type": "filter", "hook": "input", "prio": 0, "policy": "accept" } } }
  ]
}
JSON
# Read from the source rather than restated. This file hardcoded `1` and kept doing so after the
# protocol moved to 2, which made every relay-facing case fail with "agent speaks schema 1" — ten of
# eighteen, all at once, and none of them about what they were testing. A constant duplicated across
# a language boundary is one that drifts silently.
cp "$WORK/artifacts/hosts/h-e2e-01.nft" "$WORK/artifacts/hosts/h-e2e-02.nft"

SCHEMA=$(grep -oE 'SCHEMA_VERSION = [0-9]+' "$REPO/src/protocol.ts" | grep -oE '[0-9]+' | head -1)
[ -n "$SCHEMA" ] || { echo "cannot read SCHEMA_VERSION from src/protocol.ts"; exit 1; }

sha() { shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 || sha256sum "$1" | cut -d' ' -f1; }
cat > "$WORK/artifacts/manifest.json" <<JSON
{
  "generation": "e2e-gen-1",
  "issuedAt": "2026-01-01T00:00:00.000Z",
  "schemaVersion": $SCHEMA,
  "hosts": {
    "h-e2e-01": { "stage": "canary",  "rulesetHash": "sha256:$(sha "$WORK/artifacts/hosts/h-e2e-01.nft")", "confirmTimeoutSec": 90, "mustContain": [] },
    "h-e2e-02": { "stage": "general", "rulesetHash": "sha256:$(sha "$WORK/artifacts/hosts/h-e2e-02.nft")", "confirmTimeoutSec": 90, "mustContain": [] }
  }
}
JSON

# The fixture is signed the way a real authorization is — see `e2e-authorize.mjs`. The relay stopped
# loading a bare `manifest.json` when the signed path landed, and this harness kept writing one.
node "$REPO/scripts/e2e-authorize.mjs" "$WORK/artifacts" "$WORK/trust" e2e | sed 's/^/  /'

# ── An openssl that can read an Ed25519 public key ────────────────────────────
#
# The agent shells out to openssl to turn a trusted public key into DER, and **LibreSSL cannot** —
# macOS ships LibreSSL 3.3.6 at /usr/bin/openssl and it returns 26 bytes where the SPKI is 44. The
# agent then reports `artifact signing trust is unusable`, which reads as a protocol failure and is
# a missing tool. Measured 2026-08-16; the same shape cost this project a day once already, when a
# tool failed before the cryptography and looked like a bad signature.
#
# Pick one that works, or say plainly that the agent half cannot run here. Reporting those cases as
# failures would be reporting the wrong thing.
OPENSSL_BIN=""
for candidate in /usr/bin/openssl "$(command -v openssl 2>/dev/null)" /opt/homebrew/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
  [ -x "$candidate" ] || continue
  if [ "$("$candidate" pkey -pubin -in "$WORK/trust/break-glass/e2e.pem" -outform DER 2>/dev/null | wc -c | tr -d ' ')" = "44" ]; then
    OPENSSL_BIN="$candidate"; break
  fi
done
# 🔴 **This block used to set `SKIP_AGENT=1` and nothing ever read it.** One assignment, no
# readers, repository-wide — so the "SKIP" line printed and the agent half then ran anyway with an
# empty `HELIOPAUSE_OPENSSL_BIN`, failed to read the Ed25519 key, and reported as a *failure*. That
# is precisely what the comment above says must not happen ("Reporting those cases as failures
# would be reporting the wrong thing"): the guard was written, and then not wired.
#
# It is `0`/`1` and read at the two places below, so the variable now decides something. On CI
# (Linux, OpenSSL 3.x) the branch never fires — the agent half always runs there, which is what
# keeps this from becoming a check that quietly stops checking.
SKIP_AGENT=0
if [ -z "$OPENSSL_BIN" ]; then
  echo
  echo "  SKIP: no openssl here can read an Ed25519 public key (LibreSSL cannot)."
  echo "        The relay half runs; the agent half needs OpenSSL 3.x."
  echo "        On macOS: HELIOPAUSE_OPENSSL_BIN=\$(brew --prefix openssl@3)/bin/openssl"
  SKIP_AGENT=1
fi

# ── Relay ─────────────────────────────────────────────────────────────────────

HELIOPAUSE_ARTIFACT_DIR="$WORK/artifacts" \
HELIOPAUSE_RELAY_PORT="$PORT" \
HELIOPAUSE_RELAY_HOST=127.0.0.1 \
HELIOPAUSE_CERT_FILE="$WORK/pki/relay.pem" \
HELIOPAUSE_KEY_FILE="$WORK/pki/relay.key" \
HELIOPAUSE_CA_FILE="$WORK/pki/ca.pem" \
HELIOPAUSE_OPERATOR_CNS=ops-alice \
  node "$REPO/bin/heliopause-relay.ts" > "$WORK/relay.log" 2>&1 &
RELAY_PID=$!

for _ in $(seq 1 40); do
  grep -q "listening on" "$WORK/relay.log" 2>/dev/null && break
  sleep 0.25
done
if ! grep -q "listening on" "$WORK/relay.log"; then
  echo "relay failed to start:"; cat "$WORK/relay.log"; exit 1
fi

beat() {
  printf '{"host":"%s","agentVersion":"e2e","schemaVersion":%s,"applied":{"generation":%s,"state":"%s","artifactHash":null,"observedHash":%s}}' \
    "$1" "${2:-$SCHEMA}" "${3:-null}" "${4:-none}" "${5:-null}"
}
as() { # as <agent-name> <curl args...>
  local who="$1"; shift
  curl -s --cacert "$WORK/pki/ca.pem" --cert "$WORK/pki/$who.pem" --key "$WORK/pki/$who.key" "$@"
}
post() { as "$1" -H 'content-type: application/json' -d "$2" "https://localhost:$PORT/heartbeat"; }

echo "relay transport"
check "refuses a client with no certificate" "000" \
  "$(curl -s --cacert "$WORK/pki/ca.pem" "https://localhost:$PORT/healthz" -o /dev/null -w '%{http_code}' || echo 000)"

echo "identity binding"
check "accepts a host reporting as itself" '"open":true' "$(post agent "$(beat h-e2e-01)")"
check "refuses impersonation of the canary" 'but certificate is \"h-e2e-02\"' \
  "$(post agent2 "$(beat h-e2e-01)")"
check "holds general behind the unconfirmed canary" 'waiting on canary' \
  "$(post agent2 "$(beat h-e2e-02)")"

echo "artifacts"
check "serves the caller its own ruleset" 'heliopause' "$(as agent "https://localhost:$PORT/artifact")"
check "leaks no filesystem detail when an artifact is missing" 'no artifact for h-e2e-03' \
  "$(as agent3 "https://localhost:$PORT/artifact")"

echo "rollout gate"
check "opens general once the canary confirms" '"open":true' \
  "$(post agent "$(beat h-e2e-01 1 '"e2e-gen-1"' confirmed '"dump:1"')" >/dev/null; \
     post agent2 "$(beat h-e2e-02)")"
check "reports drift when a confirmed table changes underneath" 'DRIFT' \
  "$(post agent "$(beat h-e2e-01 1 '"e2e-gen-1"' confirmed '"dump:2"')" >/dev/null; \
     grep DRIFT "$WORK/relay.log" || echo none)"
echo "fleet status (/status)"
# The point of these four: a valid certificate is not sufficient. An agent holds one, and an agent
# that could read this would obtain every host's identity, generation and drift state — a target
# list, and a list of which hosts are currently unprotected.
check "refuses an agent certificate" "not authorised to read fleet status" \
  "$(as agent "https://localhost:$PORT/status")"
check "refuses a caller with no certificate" "000" \
  "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/pki/ca.pem" "https://localhost:$PORT/status")"
check "serves an operator certificate" '"generation":"e2e-gen-1"' \
  "$(as operator "https://localhost:$PORT/status")"
# Every host in the manifest appears, whatever its state. A view that omitted the hosts with
# nothing to say would make a host that failed to enrol indistinguishable from one that does not
# exist — and h-e2e-02 here never sends a heartbeat, so it is exactly that case.
check "lists every host in the manifest" 'h-e2e-02' \
  "$(as operator "https://localhost:$PORT/status")"
# Drift has to reach the fleet view, not just the relay's journal: it is the one problem that
# leaves every other field looking healthy.
check "reports the drifted host as a problem" 'no longer matches the dump' \
  "$(as operator "https://localhost:$PORT/status")"

check "refuses to instruct an agent on another schema" '"generation":null' \
  "$(post agent "$(beat h-e2e-01 99)")"

# Guarded as one block: launching a doomed agent and then not reading its log wastes seven
# seconds and leaves a log full of the tool failure this branch exists to explain.
if [ "$SKIP_AGENT" -eq 0 ]; then
echo "agent loop"
AGENT_LOG="$WORK/agent.log"
HELIOPAUSE_RELAY_URL="https://localhost:$PORT" HELIOPAUSE_HOST_ID=h-e2e-01 \
HELIOPAUSE_CA_FILE="$WORK/pki/ca.pem" HELIOPAUSE_CERT_FILE="$WORK/pki/agent.pem" \
HELIOPAUSE_KEY_FILE="$WORK/pki/agent.key" HELIOPAUSE_PINS="$PIN" \
HELIOPAUSE_TARGET=e2e HELIOPAUSE_OPENSSL_BIN="$OPENSSL_BIN" \
HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR="$WORK/trust/manager" \
HELIOPAUSE_BREAK_GLASS_KEYS_DIR="$WORK/trust/break-glass" \
HELIOPAUSE_INTERVAL_SEC=1 HELIOPAUSE_STATE_FILE="$WORK/state.json" \
  python3 "$REPO/agent/heliopause-pull.py" > "$AGENT_LOG" 2>&1 &
sleep 4; kill %2 2>/dev/null || true; wait %2 2>/dev/null || true
# This host has no nft binary, so the apply stops at the pre-apply snapshot. Reaching that point
# is the assertion: the heartbeat landed, the gate opened, the artifact was fetched, its digest
# matched the manifest, and structural validation passed. Rollback behaviour with a real kernel is
# covered by scripts/rollback-test.sh.
check "agent gets through fetch, digest and validation" "e2e-gen-1" "$(cat "$AGENT_LOG")"
check "agent stops safely where nft is unavailable" "cannot snapshot ruleset" "$(cat "$AGENT_LOG")"

HELIOPAUSE_RELAY_URL="https://localhost:$PORT" HELIOPAUSE_HOST_ID=h-e2e-01 \
HELIOPAUSE_CA_FILE="$WORK/pki/ca.pem" HELIOPAUSE_CERT_FILE="$WORK/pki/agent.pem" \
HELIOPAUSE_KEY_FILE="$WORK/pki/agent.key" HELIOPAUSE_PINS="sha256/$(printf 'x%.0s' {1..43})=" \
HELIOPAUSE_TARGET=e2e HELIOPAUSE_OPENSSL_BIN="$OPENSSL_BIN" \
HELIOPAUSE_MANAGER_SIGNING_KEYS_DIR="$WORK/trust/manager" \
HELIOPAUSE_BREAK_GLASS_KEYS_DIR="$WORK/trust/break-glass" \
HELIOPAUSE_INTERVAL_SEC=1 HELIOPAUSE_STATE_FILE="$WORK/state2.json" \
  python3 "$REPO/agent/heliopause-pull.py" > "$WORK/agent-badpin.log" 2>&1 &
sleep 3; kill %2 2>/dev/null || true; wait %2 2>/dev/null || true
check "agent refuses a relay that fails its pin" "does not match any pin" "$(cat "$WORK/agent-badpin.log")"
check "agent survives the failure and keeps trying" "2 consecutive" "$(cat "$WORK/agent-badpin.log")"
fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
# A skipped agent half must not read as a full pass. The count above is the honest answer either
# way, but the line below is what a person skims — and "4 checks did not run" is the thing they
# need to know before they trust it.
if [ "$SKIP_AGENT" -ne 0 ]; then
  echo "⚠️  the agent half did not run (no OpenSSL 3.x here) — 4 checks were not measured."
  echo "    CI runs them on Linux; this is not a full pass."
fi
[ "$fail" -eq 0 ]
