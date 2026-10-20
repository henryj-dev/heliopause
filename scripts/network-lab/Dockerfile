ARG FRR_IMAGE=quay.io/frrouting/frr:10.2.1@sha256:e47e67bd612030cb1bedee2bde85b73913f2ea021573b749deb21d94940f03c1
FROM ${FRR_IMAGE}
USER root
RUN apk add --no-cache python3 iproute2 wireguard-tools iputils
ENTRYPOINT ["python3", "/lab/run.py"]
