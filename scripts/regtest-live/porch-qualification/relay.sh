#!/bin/sh
# The relay, run through the command an operator would use. It answers to
# three names: the one the fixture network gives it, the onion name Tor made
# for it (how the primary reaches it on the porch-tor path), and the name the
# TLS terminator serves (porch-tls), whose forwarded addresses it believes.
set -eu
until [ -s /onion/relay/hostname ]; do sleep 0.2; done
exec node /opt/beignet/node_modules/beignet/dist/cli/cli.js porch-relay \
	--host 0.0.0.0 --port 2114 \
	--url ws://relay:2114 \
	--url "ws://$(cat /onion/relay/hostname):2114" \
	--url wss://relay.test \
	--trusted-proxy "$(getent hosts caddy | cut -d' ' -f1)" \
	--stats 60
