# Porch: a link to your node that does not say where it is

A Lightning node at home is reached by an address, and an address says where
the node is. Give someone a TCP address or an Iroh link and they, and anyone
they pass it to, can learn your home IP address.

Porch puts a small relay in between. The node dials out to the relay and waits
there. The link you hand out names the relay, not the node:

```text
02ab...@wss://relay.example/v1/p/k3vq...
```

Whoever holds it connects to the relay, the relay pairs the two connections,
and the Lightning transport (BOLT 8) runs end to end through it. The relay
copies bytes it cannot read. Nothing new runs on the other side: the link is
an ordinary `wss://` peer address.

This guide covers running a relay, pointing a node at it, handing out links,
and what each choice costs in speed and in who learns what. The wire protocol
is in [PORCH-PROTOCOL.md](PORCH-PROTOCOL.md) and the measurements behind the
numbers are in [PORCH-QUALIFICATION-2026-11-11.md](PORCH-QUALIFICATION-2026-11-11.md).

## Which setup

| Setup                             | Who learns the node's address         | A payment in the laboratory                     |
| --------------------------------- | ------------------------------------- | ----------------------------------------------- |
| TCP listener, or an Iroh link     | everyone who holds the link           | 90 ms over TCP (111 ms up to 0.38.4)            |
| Iroh, relay-only                  | the Iroh relay's operator             | about 80 ms more than a direct Iroh path        |
| Porch, a relay somebody else runs | that relay's operator                 | 89 ms, and 90 ms with TLS in front of the relay |
| Porch, a relay you run            | you, and the server's hosting company | the same                                        |
| Porch, reached through Tor        | nobody                                | about 1.5 s, an upper bound                     |
| Tor onion service                 | nobody                                | not measured here; the phone needs Tor as well  |

The laboratory puts the relay next to both ends, so the Porch number is what
the relay itself adds: nothing that could be measured. The relay-only Iroh
figure is from its own qualification, through n0's public relay. Direct TCP
measured 111 ms in that run, slower than the relay, because of a delay the
engine's TCP sockets had up to 0.38.4 and its WebSocket ones never had
([#1989](https://github.com/coreyphillips/beignet/issues/1989)). With the
delay gone, as it is in every later release, TCP measured 90 ms.

On the Internet a payment through a relay gains about 4 ms for each
millisecond between the phone and the node, one way, which is the phone to the
relay plus the relay to the node. A relay 10 ms from the phone and 10 ms from
home makes a payment about 170 ms; one on another continent costs what the
detour costs. Direct TCP gains the same 4 ms per millisecond, and 8 on
0.38.4 and earlier, which have that delay.

The practical choice for most people is a relay they run on a small server
near where they live. The link then hides the node from everyone it is handed
to, and the one party that still sees the home address is a server they
control.

## Run a relay

A relay is one process with no wallet, no database and no keys. It needs a
server with a public address, a name that points at it, and TLS. It runs on
the Node versions the package supports: 22.23.4 or a later 22, 24.22.1 or a
later 24, or 26.12.1 and up.

```bash
npm install -g beignet
```

### Behind a TLS terminator

This is the least work, because the terminator gets and renews the
certificate. With Caddy, the whole configuration is:

```text
relay.example {
	reverse_proxy 127.0.0.1:2114
}
```

and the relay is started with the name people will dial and the address of
the proxy it should believe:

```bash
beignet porch-relay --url wss://relay.example --trusted-proxy 127.0.0.1
```

`--trusted-proxy` matters. The relay limits how much one source address may
do, and behind a proxy every connection arrives from the proxy. With the flag
the relay reads the client's address from `X-Forwarded-For`; without it the
limits do nothing.

nginx works the same way. It has to pass the WebSocket upgrade through, and
its read timeout has to be longer than the default minute so that a quiet
connection is not cut:

```text
location / {
	proxy_pass http://127.0.0.1:2114;
	proxy_http_version 1.1;
	proxy_set_header Host $host;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	proxy_read_timeout 15m;
}
```

### Serving TLS itself

With a certificate and key on disk, the relay needs nothing in front of it:

```bash
beignet porch-relay --url wss://relay.example:8443 --host 0.0.0.0 --port 8443 \
  --tls-cert /etc/letsencrypt/live/relay.example/fullchain.pem \
  --tls-key /etc/letsencrypt/live/relay.example/privkey.pem
```

The files are read at startup, so restart the relay when the certificate is
renewed.

### Keeping it running

A systemd unit is enough:

```ini
[Unit]
Description=Porch relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/env beignet porch-relay --url wss://relay.example --trusted-proxy 127.0.0.1
Restart=always
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

`GET /health` answers `{"ok":true}`, and `--stats 60` prints the relay's
counters to stderr every minute. The relay keeps no state: restarting it drops
the connections that were open, and the nodes dial back in. In the laboratory
a channel was usable again between 1 and 2 seconds after a relay restart.

### A relay for yourself only

By default anyone who knows the relay's name can have their node wait there.
To keep it to your own nodes, give it a token:

```bash
umask 077 && openssl rand -hex 32 > /etc/porch-token
beignet porch-relay --url wss://relay.example --trusted-proxy 127.0.0.1 \
  --token-file /etc/porch-token
```

Only a node that presents the token may register. Visitors need no token: the
link is what lets them in.

Under the systemd unit above the relay runs as a user that cannot read a file
only root can. Hand it over as a credential instead: add
`LoadCredential=porch-token:/etc/porch-token` to the `[Service]` section and
give the relay `--token-file %d/porch-token`.

### Limits

The defaults suit a small public relay and are listed in
[PORCH-PROTOCOL.md](PORCH-PROTOCOL.md#relay-limits). Each can be changed with
`--limit <name>=<n>`. On a machine with little memory, lower the socket limit
(`--limit connections=<n>`): 4,096 sockets can hold about 1 GiB between them
in the worst case.

## Point a node at it

One setting turns Porch on:

```bash
BEIGNET_PORCH_RELAYS=wss://relay.example beignet start
```

or `"porchRelays": ["wss://relay.example"]` in the config file. For a relay
with a token, add `BEIGNET_PORCH_TOKEN` (`porchToken`). Several relays can be
listed; a link is then handed out for each, and any of them reaches the node.
With several relays each token goes in its own entry,
`{ "url": "wss://relay.example", "token": "..." }`, because a token sent to
every relay would be disclosed to the others.

`beignet info` then shows the link and how the relay is doing:

```json
{
	"porch": {
		"uris": ["02ab...@wss://relay.example/v1/p/k3vq..."],
		"links": 1,
		"relays": [
			{
				"relay": "wss://relay.example",
				"state": "ready",
				"idle": 2,
				"circuits": 0,
				"proxied": false
			}
		]
	}
}
```

`state` is `ready` when links through that relay work. A relay that is away
shows as `unreachable` with the reason, and the node keeps dialing: the same
link works again when the relay is back. No inbound port, port forwarding or
public address is needed at home, and the TCP and Iroh listeners can stay off.

With Porch on, the node also stops dialing addresses that a peer chose. An
address a peer announces is dialed only through the Tor proxy, because a
direct dial to it would show that peer where the node is.

## Hand out links

Every node has one link from its seed, the one `beignet info` shows. It is the
same after a restore. For anything you hand to another person, make a link of
its own:

```bash
beignet porch links create --label "Dana's phone"
beignet porch links                 # every link, and which relays serve it
beignet porch links revoke 9d41...  # take one back
```

A revoked link stops resolving at the relays, and every peer connected through
it is disconnected. Their channels stay open; they reconnect once they are
given a link that works. The others are not touched, and `beignet peer list` shows
which link each peer came in through. A node serves up to 256 links.

Revoking is permanent and is written to the database before it takes effect.
Two things bring a revoked link back, because the record of the revocation is
not there: restoring from the seed alone, which returns the seed's link and
forgets the made ones, and restoring a database backup taken before the
revocation.

On the other side a link is used like any peer address:
`beignet peer connect '<link>'`, or as a primary in an app that takes a
`wss://` peer URI.

## Who learns what

|                      | Learns                                                                               | Does not learn                                  |
| -------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------- |
| Whoever holds a link | the relay's name, and the node's Lightning pubkey, which the link states             | the node's address                              |
| The relay            | the node's address, each visitor's address, when they connect and how much they send | what is sent; the Lightning pubkey, by watching |
| The node             | which link a visitor used                                                            | the visitor's address                           |

Three things follow.

- **The relay's operator is the one party that sees the home address.** Run
  the relay yourself and that party is you, plus the company that hosts the
  server. Use somebody else's relay and it is them.
- **The relay can test a guess.** It is not told which Lightning node waits
  behind a link, but it can dial the link itself and see whether a pubkey it
  suspects answers. For a link meant for strangers, use a relay you run or
  the Tor setup below.
- **A link is a way in, like a listening port.** Whoever holds one can open
  connections to the node's handshake. The relay's limits per address and the
  node's own inbound limits bound that. Revoking the link ends it.

## Hiding from the relay too

`BEIGNET_PORCH_VIA=tor` (`porchVia: "tor"`) makes the node reach every relay
through Tor. The relay then sees a Tor exit instead of the home address, and
nobody at all holds it. The phone still dials the relay directly and needs no
Tor.

```bash
BEIGNET_PORCH_RELAYS=wss://relay.example BEIGNET_PORCH_VIA=tor \
  BEIGNET_TOR_PROXY=127.0.0.1:9050 beignet start
```

`beignet info` shows `"proxied": true` for a relay reached this way. There is
no direct dial to fall back to: with Tor down the relay shows as
`unreachable`, and the node does not reach it another way.

The price is Tor's latency on every message, in both directions. In the
laboratory, over a Tor path twice as long as a public relay gets, a payment
took about 1.5 s and a channel was usable about 3 s after the phone restarted.
An earlier run the same day measured 2.2 s and 5 to 8.5 s: Tor circuits differ
from one hour to the next. That is without Tor on the phone, and the phone
does not wait for a circuit to be built: the node's connections to the relay
are already open when it arrives.

## What Porch does not hide

- **The Lightning pubkey.** It is in the link. Someone who holds a link knows
  which node it reaches.
- **A public channel graph entry.** A node with public channels is in the
  gossip graph under that pubkey. If `announceAddresses` holds a clearnet
  address, the node publishes its own address to the whole network, and
  startup logs a warning.
- **An address a peer already has.** A peer that connected by TCP or by an
  Iroh link before knows the address it used. Changing the home IP address,
  or having had only private links from the start, is the remedy.
- **Traffic volume and timing**, from the relay and from anyone who can watch
  the network at both ends.
- **Other software on the same machine.** Porch covers the node's peer
  connections. An Electrum server, a block explorer or anything else the
  machine talks to is its own question.
