#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
docker build -t heliopause-network-transaction-lab scripts/network-transaction-lab
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
# Only explicit tracked source trees, never .git/untracked PKI/policy/site configuration.
git diff --quiet HEAD -- agent src examples scripts/network-transaction-lab package.json
git archive HEAD agent src examples scripts/network-transaction-lab package.json | tar -x -C "$staging"
# Only staged source is mounted read-only. Keys, journal, all namespaces and sockets are ephemeral.
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
  --mount "type=bind,src=$staging,dst=/source,readonly" \
  heliopause-network-transaction-lab
