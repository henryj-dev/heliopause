#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
docker build -t heliopause-network-transaction-lab scripts/network-transaction-lab
# Only source is mounted read-only. Keys, journal, all namespaces and sockets are ephemeral.
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
  --mount "type=bind,src=$(pwd),dst=/source,readonly" \
  heliopause-network-transaction-lab
