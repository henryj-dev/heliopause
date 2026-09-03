#!/usr/bin/env bash
# Roll the relay and agent code onto the fleet, one host at a time, with a backup and a check.
#
#   ./scripts/deploy-fleet.sh relay  gw-01.util
#   ./scripts/deploy-fleet.sh agent  k3s-01.dev
#   ./scripts/deploy-fleet.sh status
#
# ## Why this exists as a script rather than a runbook
#
# The manager ships as a container image and flux rolls it out. **The relay and the agent do not** —
# they are systemd units reading files under `/opt/heliopause`, and until now moving them was a
# sequence typed by hand. A sequence typed by hand is one that gets a step wrong at 3am, and the step
# that gets got wrong is the backup.
#
# ## What it does not do
#
# It does not decide the order, and it does not do more than one host. Both are deliberate: this is a
# protocol change (the relay serves signed envelopes and the agent verifies them), so the fleet spends
# the rollout in a mixed state and **which** hosts are mixed is a decision, not a detail. Run it once
# per host and look at the fleet between runs.
#
# ## The order that matters
#
# The signed-artifact path is a flag day. Publishing is refused while the manager and the relays
# disagree, and the agents are gated by `MIN_AGENT_SCHEMA` while they and the relay disagree. The
# firewall itself keeps running throughout — rules live in the kernel and an agent only touches them
# when a new generation arrives — so a mixed fleet is a fleet that cannot be *updated*, not one that
# is unprotected.
#
#   1. manager   (image, flux — already done when you are reading this)
#   2. relays    util → prod → dev        least entangled first; dev's gateway serves five hosts
#   3. agents    k3s-01.dev first          the canary the rollout stages already name
#   4. publish a generation and watch it confirm
#
# Rollback is the backup this script leaves beside the live directory:
#
#   sudo rsync -a --delete /opt/heliopause/bin.bak-<stamp>/ /opt/heliopause/bin/
#   sudo rsync -a --delete /opt/heliopause/src.bak-<stamp>/ /opt/heliopause/src/
#   sudo systemctl restart heliopause-relay      # or heliopause-agent
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_USER="${HELIOPAUSE_SSH_USER:-linuxuser}"

# name=address, one per line. Private addresses only: the public path is not reachable from the
# operator's Mac and is not the management path anyway.
#
# A plain list rather than an associative array — macOS ships bash 3.2, which has none, and a script
# an operator cannot run on the machine they are sitting at is a runbook with extra steps. Measured:
# the first version of this file failed with `gw: unbound variable` before doing anything.
HOSTS="
gw-01.dev=10.17.0.1
gw-01.prod=10.16.0.1
gw-01.util=10.253.0.1
k3s-01.dev=10.17.0.10
mailer-01.dev=10.17.101.12
mailer-02.dev=10.17.77.135
mailer-03.dev=10.17.82.134
web-01.dev=10.17.47.52
"

host_names() { echo "$HOSTS" | sed '/^$/d' | cut -d= -f1 | tr '\n' ' '; }
host_addr()  { echo "$HOSTS" | sed '/^$/d' | awk -F= -v n="$1" '$1==n {print $2}'; }

usage() {
  echo "usage: $0 {relay|agent} <host>    — one host, when the order is a decision" >&2
  echo "       $0 --all                   — relays then agents, documented order, stop on failure" >&2
  echo "       $0 status                  — what every host is running now" >&2
  echo >&2
  echo "hosts: $(host_names)" >&2
  exit 64
}

# `sha256sum | cut -c1-12` and not `SCHEMA_VERSION`.
#
# This used to print the schema number, and that number cannot see drift. Measured 2026-09-03: the
# eight hosts reported one `AGENT_VERSION` and one `SCHEMA_VERSION` while running **two different
# builds** — six on a revision with no peer-namespace support, one on another, and the fleet looked
# uniform the whole time. The agent's own `AGENT_BUILD` is the sha256 of its source truncated to 12,
# so the column below is the same value the fleet view shows and the two can be compared directly.
#
# `relay.ts` is deliberately named after the file it hashes rather than called a build id: the relay
# ships `bin src packages/i18n`, so one file's digest is an entry-point check, not a tree identity.
# A partial identity that reads like a whole one is the failure this column exists to stop.
status() {
  for name in $(host_names); do
    printf '%-16s ' "$name"
    ssh -o ConnectTimeout=6 -o BatchMode=yes "${SSH_USER}@$(host_addr "$name")" '
      sep=""
      for u in heliopause-relay heliopause-agent; do
        systemctl list-unit-files "$u.service" >/dev/null 2>&1 || continue
        case "$u" in
          heliopause-relay) f=/opt/heliopause/src/relay.ts ;;
          heliopause-agent) f=/opt/heliopause/agent/heliopause-pull.py ;;
        esac
        printf "%s%s %s %s %s" "$sep" "${u#heliopause-}" \
          "$(systemctl is-active "$u")" \
          "$(systemctl show -p ExecMainStartTimestamp --value "$u" | cut -d" " -f3)" \
          "$(sha256sum "$f" 2>/dev/null | cut -c1-12 || echo "-")"
        sep=" | "
      done
      echo' 2>/dev/null || echo "unreachable"
  done
}

deploy() {
  local what="$1" name="$2" addr; addr="$(host_addr "$2")"
  [ -n "$addr" ] || { echo "unknown host: $name" >&2; exit 64; }

  local unit paths
  case "$what" in
    # `packages/i18n` because `src/i18n.ts` imports `../packages/i18n/src/index.ts` by relative path,
    # so the running relay needs that file on the host — shipping `bin src` alone leaves it
    # ERR_MODULE_NOT_FOUND and the relay never starts. This was measured 2026-08-27: the first attempt
    # to roll a schema-4 relay onto the fleet failed exactly there, because i18n became a shared
    # package after the last relay deploy and this list did not follow. `src/deploy-fleet.test.ts`
    # holds it: every `packages/<x>` that a non-test `src` file imports must appear here.
    relay) unit=heliopause-relay; paths="bin src packages/i18n" ;;
    agent) unit=heliopause-agent; paths="agent" ;;
    *) usage ;;
  esac

  # The tree that gets shipped is the one that was tested. Refusing a dirty tree here is the same
  # reason `heliopause-publish` refuses one: two deployments claiming the same commit while shipping
  # different files is a state nothing downstream can describe.
  if [ -n "$(git -C "$REPO" status --porcelain -- $paths)" ]; then
    echo "refusing: $paths has uncommitted changes — commit or stash first" >&2
    exit 1
  fi
  local rev; rev="$(git -C "$REPO" rev-parse --short HEAD)"
  local stamp; stamp="$(date -u +%Y%m%d-%H%M%S)"

  echo "── $name: $what from $rev (backup suffix $stamp)"
  local tgz; tgz="$(mktemp -t hp-code.XXXXXX).tgz"
  tar czf "$tgz" -C "$REPO" $paths
  scp -q -o ConnectTimeout=10 "$tgz" "${SSH_USER}@${addr}:/tmp/hp-code.tgz"
  rm -f "$tgz"

  local remote_env
  printf -v remote_env 'HELIOPAUSE_DEPLOY_PATHS=%q HELIOPAUSE_DEPLOY_STAMP=%q HELIOPAUSE_DEPLOY_UNIT=%q' \
    "$paths" "$stamp" "$unit"
  ssh -o ConnectTimeout=10 -o BatchMode=yes "${SSH_USER}@${addr}" "$remote_env bash -s" <<'EOS'
set -euo pipefail
paths="$HELIOPAUSE_DEPLOY_PATHS"
stamp="$HELIOPAUSE_DEPLOY_STAMP"
unit="$HELIOPAUSE_DEPLOY_UNIT"
# A path may be shipped here for the first time — `packages/i18n` was, when the relay grew a shared
# package it had never needed before. Backing it up would `cp` a source that is not there yet and
# `set -e` would abort the whole deploy; a path with no prior version simply has no backup to make.
# And rsync writes into `/opt/heliopause/$p/` but does not create a missing *parent* (`packages/`),
# so a new nested path needs the tree made first. Both were measured on gw-01.util 2026-08-27.
for p in $paths; do
  if [ -e "/opt/heliopause/$p" ]; then sudo cp -a "/opt/heliopause/$p" "/opt/heliopause/$p.bak-$stamp"; else echo "  $p: new path, no backup"; fi
done
T=$(mktemp -d)
tar xzf /tmp/hp-code.tgz -C "$T"
for p in $paths; do sudo mkdir -p "/opt/heliopause/$p"; sudo rsync -a --delete "$T/$p/" "/opt/heliopause/$p/"; done
rm -rf "$T" /tmp/hp-code.tgz

# `is-active` was the whole check here, and it is not one.
#
# Measured 2026-09-03 on the dev relay: the tarball's xattr warnings filled the output, the restart
# line never ran, and the unit reported `active` while serving code from two days earlier. "Active"
# answers "is a process running", never "is it running what I just shipped" — the file on disk had
# already changed, so nothing downstream disagreed either.
#
# So the start timestamp is read before and after and compared. Monotonic, because the wall-clock
# form has second granularity and a fast restart can land inside the same second.
before="$(systemctl show -p ExecMainStartTimestampMonotonic --value "$unit" 2>/dev/null || echo 0)"
sudo systemctl restart "$unit"
sleep 5
after="$(systemctl show -p ExecMainStartTimestampMonotonic --value "$unit" 2>/dev/null || echo 0)"
state="$(systemctl is-active "$unit" || true)"
if [ "$after" = "$before" ] || [ "$after" = "0" ]; then
  echo "  FAILED: $unit did not restart (start timestamp unchanged) — state=$state" >&2
  exit 1
fi
if [ "$state" != "active" ]; then
  echo "  FAILED: $unit restarted but is $state" >&2
  sudo journalctl -u "$unit" -n 20 --no-pager | tail -20 >&2
  exit 1
fi
echo "  restarted, active"
sudo journalctl -u "$unit" -n 6 --no-pager | tail -6
EOS
  echo "── $name: done. Roll back with the .bak-$stamp directories if the journal above is wrong."
}

# The order is the one the header documents, and it is not a preference: relays least-entangled
# first, then the agent on the host the rollout stages already name as the canary. `--all` stops at
# the first host that fails its restart check, so a build that cannot come up costs one host rather
# than the fleet — the same property the staged rollout gives a generation.
#
# Do not use `--all` for a protocol change. The header explains why a schema bump wants a human
# looking at the fleet between hosts; this mode is for the ordinary case, where the code changed and
# the protocol did not.
RELAY_ORDER="gw-01.util gw-01.prod gw-01.dev"
AGENT_ORDER="k3s-01.dev gw-01.dev gw-01.prod gw-01.util mailer-01.dev mailer-02.dev mailer-03.dev web-01.dev"

deploy_all() {
  for name in $RELAY_ORDER; do deploy relay "$name"; done
  for name in $AGENT_ORDER; do deploy agent "$name"; done
  echo
  echo "── every host deployed. Fleet now:"
  status
}

case "${1:-}" in
  status) status ;;
  --all) [ $# -eq 1 ] || usage; deploy_all ;;
  relay|agent) [ $# -eq 2 ] || usage; deploy "$1" "$2" ;;
  *) usage ;;
esac
