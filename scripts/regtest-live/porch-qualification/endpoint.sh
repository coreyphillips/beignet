#!/bin/sh
# An endpoint trusts the certificate authority Caddy made for the fixture.
# Node reads NODE_EXTRA_CA_CERTS once, as it starts, so wait for the file.
set -eu
until [ -s "$NODE_EXTRA_CA_CERTS" ]; do sleep 0.2; done
exec node /fixture/node.cjs
