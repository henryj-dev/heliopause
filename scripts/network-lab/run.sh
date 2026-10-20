#!/usr/bin/env bash
# Starts only an isolated, network-less container. Never use host network/PID or host route commands.
set -euo pipefail
cd "$(dirname "$0")/../.."
version="${1:-10.2.1}"
case "$version" in 8.5.6|10.2.1) ;; *) echo 'FRR version must be 8.5.6 or 10.2.1' >&2; exit 2;; esac
output="${2:-/tmp/heliopause-network-lab-$version}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
node scripts/network-lab/build.ts "$output/input.json" "$version"
docker build --build-arg "FRR_VERSION=$version" -t "heliopause-network-lab:$version" scripts/network-lab
# NET_ADMIN and SYS_ADMIN permit kernel WireGuard, veth and namespace mounts. All namespaces,
# daemons and ephemeral private keys live inside a disposable container on a hosted runner.
# No production credentials, Docker socket, PID namespace, host network or repository write mount.
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --mount "type=bind,src=$output,dst=/results" \
  --mount "type=bind,src=$(pwd)/scripts/network-lab,dst=/lab,readonly" \
  "heliopause-network-lab:$version"
