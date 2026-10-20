FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 procps iproute2 wireguard-tools iputils-ping openssl nftables && rm -rf /var/lib/apt/lists/*
WORKDIR /source
ENTRYPOINT ["python3", "scripts/network-transaction-lab/run.py"]
