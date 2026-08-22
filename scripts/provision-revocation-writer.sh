#!/usr/bin/env bash
# Install the privilege-separated revocation writer on a relay host.
#
#   ./scripts/provision-revocation-writer.sh gw-01.util
#
# ## Why the relay stopped being able to write its own denylist
#
# It owned the file it was defending. A relay that can rewrite the denylist is a relay whose
# compromise removes every revocation in it, and the network-facing process is exactly the one you
# assume can be taken. So the file moves to a dedicated account, the relay keeps only a socket to it,
# and the writer accepts snapshots that **add** — it refuses one that drops a fingerprint it already
# holds (L9, M1).
#
# The new relay refuses to start without `HELIOPAUSE_REVOCATION_WRITER_SOCKET`, so this has to be in
# place before the code moves. Measured 2026-08-15: the relay upgrade on gw-01.util restart-looped on
# exactly that, and rolled back cleanly.
#
# ## The step that must not be skipped
#
# **The existing denylist is migrated, not recreated.** A fresh empty file at the new path would
# silently un-revoke every certificate the relay is currently refusing — which is M1 itself, arriving
# through the fix for M1. This script copies the live snapshot across and refuses to continue if it
# cannot read one.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH_USER="${HELIOPAUSE_SSH_USER:-linuxuser}"

HOSTS="
gw-01.dev=10.17.0.1
gw-01.prod=10.16.0.1
gw-01.util=10.253.0.1
"
host_addr() { echo "$HOSTS" | sed '/^$/d' | awk -F= -v n="$1" '$1==n {print $2}'; }

name="${1:-}"
addr="$(host_addr "${name:-}")"
[ -n "$addr" ] || { echo "usage: $0 <relay-host>   (gw-01.dev|gw-01.prod|gw-01.util)" >&2; exit 64; }

echo "── $name: staging units"
tar czf /tmp/hp-revwriter.tgz -C "$REPO" \
  packaging/systemd/heliopause-revocation-writer.service \
  packaging/systemd/heliopause-revocation-writer.socket \
  packaging/systemd/heliopause-revocations.conf \
  packaging/systemd/heliopause-relay.service \
  bin/heliopause-revocation-writer.ts
scp -q -o ConnectTimeout=10 /tmp/hp-revwriter.tgz "${SSH_USER}@${addr}:/tmp/hp-revwriter.tgz"
rm -f /tmp/hp-revwriter.tgz

ssh -o ConnectTimeout=10 -o BatchMode=yes "${SSH_USER}@${addr}" "bash -s" <<'EOS'
set -euo pipefail
T=$(mktemp -d); tar xzf /tmp/hp-revwriter.tgz -C "$T"; rm -f /tmp/hp-revwriter.tgz

# 1. the account and group the socket is shared through
# `/etc/sysusers.d` does not exist on a host that has never shipped a sysusers snippet.
sudo install -d -m 0755 /etc/sysusers.d
sudo install -m 0644 "$T/packaging/systemd/heliopause-revocations.conf" /etc/sysusers.d/heliopause-revocations.conf
sudo systemd-sysusers

# 2. the denylist itself, migrated rather than recreated
sudo install -d -m 0755 -o heliopause-revocation-writer -g heliopause-revocation-writer /var/lib/heliopause-revocations
NEW=/var/lib/heliopause-revocations/revocations.json
if sudo test ! -f "$NEW"; then
  OLD=""
  for c in /var/lib/private/heliopause/revocations.json /var/lib/heliopause/revocations.json /var/lib/heliopause/relay-revocations.json; do
    sudo test -f "$c" && OLD="$c" && break
  done
  if [ -z "$OLD" ]; then
    echo "refusing: no existing revocation snapshot found — a fresh empty one would un-revoke everything" >&2
    exit 1
  fi
  echo "migrating $OLD -> $NEW ($(sudo python3 -c "import json,sys;print(len(json.load(open('$OLD'))['revocations']))" ) row(s))"
  sudo install -m 0644 -o heliopause-revocation-writer -g heliopause-revocation-writer "$OLD" "$NEW"
fi

# 3. the writer, and the relay unit that knows to join its group
sudo install -m 0644 "$T/packaging/systemd/heliopause-revocation-writer.service" /etc/systemd/system/
sudo install -m 0644 "$T/packaging/systemd/heliopause-revocation-writer.socket" /etc/systemd/system/
sudo install -m 0644 "$T/packaging/systemd/heliopause-relay.service" /etc/systemd/system/
sudo install -d -m 0755 /opt/heliopause/bin
sudo install -m 0755 "$T/bin/heliopause-revocation-writer.ts" /opt/heliopause/bin/

# 4. the two settings the new relay refuses to start without
F=/etc/heliopause/relay.env
sudo grep -q '^HELIOPAUSE_REVOCATION_WRITER_SOCKET=' "$F" \
  || echo 'HELIOPAUSE_REVOCATION_WRITER_SOCKET=/run/heliopause-revocation-writer.sock' | sudo tee -a "$F" >/dev/null
sudo sed -i 's|^HELIOPAUSE_REVOCATION_FILE=.*|HELIOPAUSE_REVOCATION_FILE=/var/lib/heliopause-revocations/revocations.json|' "$F"
sudo grep -q '^HELIOPAUSE_REVOCATION_FILE=' "$F" \
  || echo 'HELIOPAUSE_REVOCATION_FILE=/var/lib/heliopause-revocations/revocations.json' | sudo tee -a "$F" >/dev/null

sudo systemctl daemon-reload
sudo systemctl enable --now heliopause-revocation-writer.socket
sudo systemctl restart heliopause-revocation-writer
sleep 3
echo "writer: $(systemctl is-active heliopause-revocation-writer)  socket: $(systemctl is-active heliopause-revocation-writer.socket)"
sudo grep -E '^HELIOPAUSE_REVOCATION' "$F"
rm -rf "$T"
EOS
echo "── $name: writer provisioned. The relay code can move now."
