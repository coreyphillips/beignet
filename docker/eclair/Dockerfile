# Eclair built from the official release zip on a multi-arch JRE base.
#
# Why a local build: no upstream 0.14.x image runs natively on arm64
# (polarlightning/eclair stops at 0.13.1 and the amd64 acinq/eclair build
# SIGSEGVs under Rosetta). The official eclair-node zip is deterministic and
# GPG-signed, so we download it, pin its sha256, and run it on a Temurin JRE
# (eclair 0.14.x targets Java 21). The runtime contract matches the
# polarlightning image the compose service was written for: settings arrive
# via the JAVA_OPTS env var and data lives in ECLAIR_DATADIR.
FROM eclipse-temurin:21-jre-jammy

RUN apt-get update \
  && apt-get install -y --no-install-recommends bash jq curl unzip \
  && rm -rf /var/lib/apt/lists/*

ARG ECLAIR_VERSION=0.14.1
ARG ECLAIR_COMMIT=d769db0
ARG ECLAIR_SHA256=29ed5bc3a1190c5ee1ba1b968d4832ac1e292a14a26b660ccb2591e6d8e6dd3d

WORKDIR /app
RUN curl -fSL "https://github.com/ACINQ/eclair/releases/download/v${ECLAIR_VERSION}/eclair-node-${ECLAIR_VERSION}-${ECLAIR_COMMIT}-bin.zip" -o eclair-node.zip \
  && echo "${ECLAIR_SHA256}  eclair-node.zip" | sha256sum -c - \
  && unzip -q eclair-node.zip \
  && rm eclair-node.zip \
  && mv eclair-node-* eclair-node \
  && chmod +x eclair-node/bin/eclair-node.sh

# eclair-cli ships inside the verified zip; install it from there so
# `docker exec eclair eclair-cli ...` works without touching a mutable tag
RUN cp eclair-node/bin/eclair-cli /sbin/eclair-cli \
  && chmod +x /sbin/eclair-cli

ENV ECLAIR_DATADIR=/home/eclair
RUN mkdir -p "$ECLAIR_DATADIR"
VOLUME ["/home/eclair"]

EXPOSE 9735 9737 8080

CMD JAVA_OPTS="${JAVA_OPTS}" eclair-node/bin/eclair-node.sh "-Declair.datadir=${ECLAIR_DATADIR}"
