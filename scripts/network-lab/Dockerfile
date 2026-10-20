ARG FRR_VERSION=10.2.1
FROM quay.io/frrouting/frr:${FRR_VERSION}
USER root
RUN apk add --no-cache python3 iproute2 wireguard-tools iputils
ENTRYPOINT ["python3", "/lab/run.py"]
