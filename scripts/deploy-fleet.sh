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
"

host_names() { echo "$HOSTS" | sed '/^$/d' | cut -d= -f1 | tr '\n' ' '; }
host_addr()  { echo "$HOSTS" | sed '/^$/d' | awk -F= -v n="$1" '$1==n {print $2}'; }

usage() {
  echo "usage: $0 {relay|agent} <host>    — one host per run, on purpose" >&2
  echo "       $0 status                  — what every host is running now" >&2
  echo >&2
  echo "hosts: $(host_names)" >&2
  exit 64
}

status() {
  for name in $(host_names); do
    printf '%-16s ' "$name"
    ssh -o ConnectTimeout=6 -o BatchMode=yes "${SSH_USER}@$(host_addr "$name")" \
      "for u in heliopause-relay heliopause-agent; do
         systemctl list-unit-files \"\$u.service\" >/dev/null 2>&1 && printf '%s=%s ' \"\$u\" \"\$(systemctl is-active \$u)\"
       done
       printf 'agent-schema=%s' \"\$(grep -m1 '^SCHEMA_VERSION' /opt/heliopause/agent/heliopause-pull.py 2>/dev/null | tr -d ' ' | cut -d= -f2 || echo '-')\"
       echo" 2>/dev/null || echo "unreachable"
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
sudo systemctl restart "$unit"
sleep 5
systemctl is-active "$unit"
sudo journalctl -u "$unit" -n 6 --no-pager | tail -6
EOS
  echo "── $name: done. Roll back with the .bak-$stamp directories if the journal above is wrong."
}

case "${1:-}" in
  status) status ;;
  relay|agent) [ $# -eq 2 ] || usage; deploy "$1" "$2" ;;
  *) usage ;;
esac
