#!/usr/bin/env bash
# Starts only an isolated, network-less container. Never use host network/PID or host route commands.
set -euo pipefail
cd "$(dirname "$0")/../.."
version="${1:-10.2.1}"
case "$version" in
  8.5.6) image='quay.io/frrouting/frr:8.5.6@sha256:c73f2f5e02d66b8ae0ef311d996226b8b56003578dd727c10429b1de29817b8d';;
  10.2.1) image='quay.io/frrouting/frr:10.2.1@sha256:e47e67bd612030cb1bedee2bde85b73913f2ea021573b749deb21d94940f03c1';;
  *) echo 'FRR version must be 8.5.6 or 10.2.1' >&2; exit 2;;
esac
output="${2:-/tmp/heliopause-network-lab-$version}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
node scripts/network-lab/build.ts "$output/input.json" "$version"
docker build --build-arg "FRR_IMAGE=$image" -t "heliopause-network-lab:$version" scripts/network-lab
# NET_ADMIN and SYS_ADMIN permit kernel WireGuard, veth and namespace mounts. All namespaces,
# daemons and ephemeral private keys live inside a disposable container on a hosted runner.
# No production credentials, Docker socket, PID namespace, host network or repository write mount.
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
  --mount "type=bind,src=$output,dst=/results" \
  --mount "type=bind,src=$(pwd)/scripts/network-lab,dst=/lab,readonly" \
  "heliopause-network-lab:$version"
