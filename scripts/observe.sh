#!/usr/bin/env bash
# Sample the fleet on an interval and append one line per sample to a log.
#
#   ./scripts/observe.sh [relay-url] [interval-sec]
#
# This exists for the gap between applying a generation and trusting it. `heliopause-status` answers
# "what is true now"; a stage-1 soak needs "was anything ever not true", and those are different
# questions — a host that drifted at 03:00 and recovered by 09:00 leaves no trace in the first.
#
# ## Why the log lives here and not on the hosts
#
# Measured: all three dev hosts have volatile journals — no `/var/log/journal`, so `Storage=auto`
# keeps everything in `/run` and a reboot erases it. A soak whose record disappears exactly when
# something interesting happened (a reboot) is not a record. The relay's own state is memory-only
# for the same reason, by design.
#
# So samples are appended on the operator's machine, where they survive both.
#
# ## What it does not do
#
# It does not decide anything, and it cannot change the fleet — it calls a read-only endpoint with a
# read-only certificate. Deciding whether stage 2 may proceed is a human reading this log.

set -uo pipefail

INTERVAL="${2:-60}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="${HELIOPAUSE_OBSERVE_LOG:-$REPO/observe.log}"

# ── What is watched ───────────────────────────────────────────────────────────
#
# One relay per VPC, each with its own CA — so each needs its own PKI directory, and a single
# `--pki` would authenticate against exactly one of them.
#
# **Each VPC is sampled independently and a failure in one does not stop the others.** That is the
# whole point of the split: the relays are separate so a gateway outage is contained, and an observer
# that gave up on the first unreachable relay would report the opposite of what the design provides.
#
# Targets are configured, not hardcoded — this file is published and a site's relay addresses are
# not. Set them in `scripts/observe.targets` (gitignored) or the environment:
#
#     HELIOPAUSE_OBSERVE_TARGETS="dev=https://10.0.0.1:8443=./pki prod=https://10.0.1.1:8443=./pki-prod"
#
# One entry per VPC: `name=relay-url=pki-directory`. Each VPC has its own CA, so a single `--pki`
# would authenticate against exactly one of them.
#
# Passing a relay URL as $1 watches just that one (the old single-VPC behaviour, kept for debugging).
TARGETS_FILE="${HELIOPAUSE_OBSERVE_TARGETS_FILE:-$REPO/scripts/observe.targets}"
if [ -n "${HELIOPAUSE_OBSERVE_TARGETS:-}" ]; then
  TARGETS="$HELIOPAUSE_OBSERVE_TARGETS"
elif [ -f "$TARGETS_FILE" ]; then
  # Comments and blank lines so the file can say which VPC is which.
  TARGETS="$(grep -vE '^\s*#|^\s*$' "$TARGETS_FILE" | tr '\n' ' ')"
else
  TARGETS=""
fi

if [ "${1:-}" != "" ] && [ "${1:-}" != "--summary" ]; then
  TARGETS="single=$1=${HELIOPAUSE_PKI_DIR:-$REPO/pki}"
fi

# Refused rather than defaulted. An observer with nothing to watch would append nothing, and an empty
# log reads exactly like a clean one — the soak would report "no problem recorded" for a fleet it
# never contacted.
if [ "${1:-}" != "--summary" ] && [ -z "$TARGETS" ]; then
  cat >&2 <<EOF
[observe] no targets configured, so there is nothing to sample.

Create $TARGETS_FILE with one line per VPC:

    # name = relay url = pki directory (each VPC has its own CA)
    dev=https://10.0.0.1:8443=$REPO/pki

or set HELIOPAUSE_OBSERVE_TARGETS to the same, space-separated.
EOF
  exit 2
fi

# `--json` rather than the table: this is written to be grepped later, and the table's column
# padding and colour codes make that worse rather than better.
sample() {
  node "$REPO/bin/heliopause-status.ts" "$1" --pki="$2" --json 2>&1
}

# ── summary ───────────────────────────────────────────────────────────────────
#
# The question a soak has to answer is not "is it fine now" but "was it ever not fine", so the
# summary counts samples rather than showing the last one.

if [ "${1:-}" = "--summary" ]; then
  [ -f "$LOG" ] || { echo "no log at $LOG yet"; exit 1; }
  TOTAL=$(grep -c . "$LOG")
  BAD=$(grep -c 'PROBLEMS\|UNREACHABLE' "$LOG" || true)
  printf 'samples          %s\n' "$TOTAL"
  printf 'first            %s\n' "$(head -1 "$LOG" | cut -d' ' -f1)"
  printf 'last             %s\n' "$(tail -1 "$LOG" | cut -d' ' -f1)"
  printf 'clean            %s\n' "$((TOTAL - BAD))"
  printf 'with problems    %s\n' "$BAD"

  # Per VPC, because a fleet-wide count hides the case that matters most: one VPC failing while the
  # others are clean. That is what the per-gateway split is supposed to produce, and a single
  # "3 problems out of 900" line cannot tell it apart from a fleet-wide wobble.
  #
  # Lines written before the observer watched more than one VPC have no name in field 2 — they are
  # counted under `(pre-split)` rather than dropped. A per-VPC breakdown that silently omitted them
  # would not add up to the total above, and a summary whose parts do not sum to its whole is worse
  # than no breakdown: it invites the reader to trust an arithmetic that is not there.
  printf '\nby VPC:\n'
  ACCOUNTED=0
  for V in $(awk '{print $2}' "$LOG" | grep -E '^[a-z][a-z0-9-]*$' | sort -u; echo "(pre-split)"); do
    if [ "$V" = "(pre-split)" ]; then
      VT=$(awk '$2 !~ /^[a-z][a-z0-9-]*$/' "$LOG" | grep -c . || true)
      [ "$VT" -eq 0 ] && continue
      VB=$(awk '$2 !~ /^[a-z][a-z0-9-]*$/' "$LOG" | grep -c 'PROBLEMS\|UNREACHABLE' || true)
    else
      VT=$(awk -v v="$V" '$2==v' "$LOG" | grep -c . || true)
      VB=$(awk -v v="$V" '$2==v' "$LOG" | grep -c 'PROBLEMS\|UNREACHABLE' || true)
    fi
    ACCOUNTED=$((ACCOUNTED + VT))
    printf '  %-12s %4s samples  %4s clean  %4s with problems\n' "$V" "$VT" "$((VT - VB))" "$VB"
  done
  # The parts must sum to the whole. If they ever do not, the log has a shape this summary does not
  # know about, and saying so is more useful than a tidy table that is quietly wrong.
  [ "$ACCOUNTED" -ne "$TOTAL" ] &&
    printf '  \033[31mWARNING: %s of %s samples unaccounted for — unrecognised line shape\033[0m\n' \
      "$((TOTAL - ACCOUNTED))" "$TOTAL"

  # Generations seen: more than one means something was published mid-soak, which changes what the
  # rest of the log is evidence about. Listed per VPC because they publish independently.
  printf '\ngenerations      %s\n' "$(grep -oE 'gen=[^ ]+' "$LOG" | sort -u | tr '\n' ' ')"
  if [ "$BAD" -gt 0 ]; then
    printf '\nevery sample that was not clean:\n'
    grep 'PROBLEMS\|UNREACHABLE' "$LOG" | sed 's/^/  /'
  else
    printf '\nno problem was recorded in any sample\n'
  fi
  exit 0
fi

printf 'observing every %ss → %s\n' "$INTERVAL" "$LOG"
for T in $TARGETS; do printf '  %-6s %s\n' "${T%%=*}" "$(printf '%s' "$T" | cut -d= -f2-2)"; done
printf 'ctrl-c to stop. Summarise with: %s --summary\n\n' "$0"

while true; do
  TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for T in $TARGETS; do
    NAME="${T%%=*}"
    URL="$(printf '%s' "$T" | cut -d= -f2-2)"
    TPKI="$(printf '%s' "$T" | cut -d= -f3-)"

    # One line per VPC, each carrying its own name. Interleaving them under a single timestamp would
    # make it impossible to tell later which relay was unreachable.
    OUT="$(sample "$URL" "$TPKI")"
    if ! printf '%s' "$OUT" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{JSON.parse(s)})' 2>/dev/null; then
      # A relay that cannot be reached is itself an observation, and the most important kind — during
      # a soak it means agents in that VPC are not receiving anything either. Recorded, not skipped,
      # and the loop continues to the next VPC: one gateway being down is precisely the case the
      # per-VPC split exists to contain, so it must not stop the others being observed.
      printf '%s %s UNREACHABLE %s\n' "$TS" "$NAME" "$(printf '%s' "$OUT" | tr '\n' ' ' | cut -c1-200)" >> "$LOG"
      printf '%s  %-6s \033[31munreachable\033[0m\n' "$TS" "$NAME"
      continue
    fi

    LINE="$(printf '%s' "$OUT" | node -e '
      let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
        const v = JSON.parse(s);
        // One line, fixed shape: generation, then per-host state/age, then problems. Fixed shape is
        // what makes `grep -c` and `awk` on this file meaningful six hours later.
        //
        // The workload half is appended only where a host has one, so a line stays readable on the
        // hosts that do not — and its absence on the applier would be visible rather than assumed.
        const hosts = v.hosts.map((h) => {
          const wl = h.workload ? `/wl:${h.workload.state ?? "unreported"}` : "";
          return `${h.host}=${h.state ?? "unknown"}/${h.ageSec ?? "-"}s${wl}${h.drifted ? "/DRIFT" : ""}`;
        }).join(" ");
        const problems = v.problems.length ? ` PROBLEMS[${v.problems.join("; ")}]` : "";
        process.stdout.write(`gen=${v.generation} relayAge=${v.relayAgeSec ?? "-"}s ${hosts}${problems}`);
      });
    ')"
    printf '%s %s %s\n' "$TS" "$NAME" "$LINE" >> "$LOG"
    if printf '%s' "$LINE" | grep -q PROBLEMS; then
      printf '%s  %-6s \033[31m%s\033[0m\n' "$TS" "$NAME" "$(printf '%s' "$LINE" | grep -oE 'PROBLEMS\[.*\]')"
    else
      printf '%s  %-6s ok\n' "$TS" "$NAME"
    fi
  done
  sleep "$INTERVAL"
done
