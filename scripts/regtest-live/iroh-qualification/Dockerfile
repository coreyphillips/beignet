FROM ghcr.io/coreyphillips/beignet-app:0.27.0@sha256:96599fbcbad5423c408c959118dabc2d473ee08b530bb7803fb94c529c950528
USER root
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["node", "/fixture/node.cjs"]
