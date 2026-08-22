#!/usr/bin/env bash
# Sample who is connected to a public port on the fleet, and append one line per peer per sample.
#
#   ./scripts/observe-peers.sh [interval-sec]
#
# ## The question this exists for
#
# `P200`-style rules open `0.0.0.0/0` on the mail hosts. Narrowing one of those ports to a vendor's
# prefix list is only safe if the traffic actually arrives through that vendor — and on 2026-08-16
# it did not: the `mx`/`autoconfig`/`autodiscover`/`mta-sts` names all resolve to the origin's own
# public address, not to Cloudflare. So the port stays open, and the next question becomes **who is
# using it**, which nothing could answer: the service on 443 keeps no HTTP log.
#
# ## Why sampling rather than counters or a log rule
#
# `counter` was excluded from the ruleset on purpose (H27): rendering it changes every ruleset hash,
# and a hash that moves for an observability reason makes drift detection say something happened when
# nothing did. An nftables `log` statement has the same problem plus a second one — these hosts have
# volatile journals (no `/var/log/journal`), so the record disappears on the reboot that is often the
# interesting event.
#
# This reads `ss` over SSH and writes on the operator's machine. **It changes nothing on any host**
# and needs no privilege there: peer addresses are visible to an unprivileged `ss` (verified), only
# the process column needs root, and this does not ask for it.
#
# ## What it cannot see, stated because the gap decides how to read the log
#
# **Short connections between samples are invisible.** An autodiscover request is one HTTPS round
# trip; a scanner's probe is shorter. At a 60-second interval this catches sessions that are held,
# not requests that are made — so an empty log is **not** evidence that nobody connected. It answers
# "who sustains connections here", and treating it as an answer to "who ever connected" is the
# mistake this paragraph exists to prevent.
#
# For "who ever connected" the honest instruments are the application's own log (whoever owns that
# service) or packet capture. Both are decisions for the host's owner, not for this script.
set -uo pipefail

INTERVAL="${1:-60}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${HELIOPAUSE_PEERS_LOG:-$REPO/observe-peers.log}"
SSH_USER="${HELIOPAUSE_SSH_USER:-linuxuser}"

# Targets are configured, not hardcoded — this file is published and a site's addresses are not.
# `scripts/observe-peers.targets` is gitignored; one `name=address=port,port` per line.
TARGETS_FILE="${HELIOPAUSE_PEERS_TARGETS:-$REPO/scripts/observe-peers.targets}"
if [ ! -f "$TARGETS_FILE" ]; then
  cat >&2 <<EOF
no targets file at $TARGETS_FILE

Write one line per host:

    mailer-01.dev=10.0.0.1=80,443
    mailer-02.dev=10.0.0.2=80,443

The file is gitignored. Addresses are site data and do not belong in this repository.
EOF
  exit 64
fi

echo "# started $(date -u +%Y-%m-%dT%H:%M:%SZ) interval=${INTERVAL}s" >> "$LOG"
echo "sampling every ${INTERVAL}s → $LOG   (ctrl-c to stop)"

while true; do
  at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    name="${line%%=*}"; rest="${line#*=}"
    addr="${rest%%=*}"; ports="${rest#*=}"

    # **Peer is field 4, not 5.** `state established` removes the State column, so a row is
    # `Recv-Q Send-Q Local Peer` — reading `$5` gives an empty string on every line and the log
    # fills with well-formed rows whose address is blank. Found with a known positive: a connection
    # opened on purpose was counted and unidentified, which is worse than not being counted.
    # One SSH per host per sample, all ports in that one call: a connection per port would multiply
    # the login cost by the port count for a result that is one `ss` invocation's worth of work.
    # `-n` is load-bearing: without it ssh reads the targets file out from under the `while` loop and
    # every host after the first is silently never asked. The log still fills with plausible "none"
    # lines for the one host that was, which reads as "nobody is connected anywhere".
    peers="$(ssh -n -o ConnectTimeout=8 -o BatchMode=yes "${SSH_USER}@${addr}" \
      "for p in ${ports//,/ }; do
         ss -tn state established \"sport = :\$p\" 2>/dev/null | tail -n +2 |
           awk -v P=\$p '{ ip=\$4; sub(/^\[/, \"\", ip); sub(/\]:[0-9]+$/, \"\", ip);
                          sub(/:[0-9]+$/, \"\", ip); sub(/^::ffff:/, \"\", ip); print P, ip }'
       done" 2>/dev/null)"

    if [ -z "$peers" ]; then
      # Recorded rather than skipped. A sample with no peers and a sample that never ran look the
      # same in a log that only writes when it finds something, and only one of them is a fact.
      echo "$at $name - none" >> "$LOG"
      continue
    fi
    # Counted per (port, peer) so a client holding six connections does not read as six clients.
    echo "$peers" | sort | uniq -c | while read -r n port ip; do
      echo "$at $name $port $ip x$n" >> "$LOG"
    done
  done < "$TARGETS_FILE"
  sleep "$INTERVAL"
done
