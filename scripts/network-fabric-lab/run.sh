#!/usr/bin/env bash
# Isolated BGP fabric lab: runs planBgpFabric output inside a disposable, network-less container.
# Same image and isolation as scripts/network-lab (no host network/PID, no repository write mount).
set -euo pipefail
cd "$(dirname "$0")/../.."
version="${1:-10.2.1}"
case "$version" in
  8.5.6) image='quay.io/frrouting/frr:8.5.6@sha256:c73f2f5e02d66b8ae0ef311d996226b8b56003578dd727c10429b1de29817b8d';;
  10.2.1) image='quay.io/frrouting/frr:10.2.1@sha256:e47e67bd612030cb1bedee2bde85b73913f2ea021573b749deb21d94940f03c1';;
  *) echo 'FRR version must be 8.5.6 or 10.2.1' >&2; exit 2;;
esac
output="${2:-/tmp/heliopause-fabric-lab-$version}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
node scripts/network-fabric-lab/build.ts "$output/input.json" "$version"
docker build --build-arg "FRR_IMAGE=$image" -t "heliopause-network-lab:$version" scripts/network-lab
docker run --rm --network none --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt systempaths=unconfined \
  --mount "type=bind,src=$output,dst=/results" \
  --mount "type=bind,src=$(pwd)/scripts/network-fabric-lab,dst=/lab,readonly" \
  --entrypoint python3 \
  "heliopause-network-lab:$version" /lab/run.py
