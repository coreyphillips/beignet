# One image for the endpoints, the relay and Tor: the engine from this
# checkout, the tools the fixture shapes and counts traffic with, and Tor.
# Build the engine and pack it into this directory as beignet-local.tgz first
# (see README.md).
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 tor && rm -rf /var/lib/apt/lists/*
COPY beignet-local.tgz /tmp/beignet-local.tgz
RUN mkdir -p /opt/beignet && cd /opt/beignet && npm init -y >/dev/null \
  && npm install --omit=dev --no-audit --no-fund /tmp/beignet-local.tgz \
  && rm /tmp/beignet-local.tgz
