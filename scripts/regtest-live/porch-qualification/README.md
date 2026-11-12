# Porch qualification

Manual regtest qualification for Porch links: a node that hands out a peer link
through a blind relay instead of an address. Two Lightning endpoints run the
engine packed from this checkout, with a Bitcoin-funded channel between them
and a relay started by `beignet porch-relay`, the command an operator runs. No
simulated funding and no stand-in for the relay is involved.

The same two endpoints and the same channel are measured on four paths:

| Path        | The primary is reached                                                           | The relay sees the primary's address |
| ----------- | -------------------------------------------------------------------------------- | ------------------------------------ |
| `tcp`       | directly, on its TCP listener. The control: nothing is hidden                    | not used                             |
| `porch`     | through the relay, which the primary dials directly, unencrypted `ws://`         | yes                                  |
| `porch-tls` | through the relay behind a TLS terminator, `wss://`, as a hosted relay is set up | yes                                  |
| `porch-tor` | through the relay, which the primary dials through Tor (`porchVia: 'tor'`)       | no                                   |

The phone is the same on every path. It dials the link it is handed, as anyone
holding one would, and uses no Tor.

The fixture requires Docker Desktop, Node 22, and the repository's local
regtest Bitcoin/Electrum pair. Bitcoin must be container `bitcoin` (override
with `BEIGNET_REGTEST_BITCOIN`) with its documented test RPC settings on port 43782. Electrum must be reachable at `host.docker.internal:60001`. Setup checks
Bitcoin's chain before funding or mining. Use only disposable regtest services.
The `porch-tor` path needs the Tor container to reach the Tor network.

## Run

From the repository root, then this directory:

```sh
npm run build
npm pack --pack-destination scripts/regtest-live/porch-qualification
cd scripts/regtest-live/porch-qualification
mv beignet-*.tgz beignet-local.tgz
mkdir -m 700 primary-data phone-data
docker compose up --build -d
node setup.cjs
node qualify.cjs porch
node qualify.cjs porch-tls
node qualify.cjs porch-tor
node qualify.cjs tcp
node final.cjs
```

Wait until both endpoints log `ready` before setup. `setup.cjs` funds the
primary, connects the phone through the relay, opens a 1,000,000 sat channel
over that connection and moves 300,000 sat to the phone. `qualify.cjs <path>`
starts the primary again when it is on a different path, hands the phone that
path's link and runs every phase; a second argument runs one of `baseline`,
`latency`, `restart` or `outages`. A full run of one path takes about half an
hour, most of it outages and the waits between scenarios. Scenarios are
sequential and must not run concurrently.

Run the Porch paths before `tcp` on fresh data directories, as above.
On the `tcp` path the phone is told the primary's address, and the checks
below are about a phone that never was.

The scripts write `results.jsonl`, phase snapshots and `channel.json` locally.
Wallet data and the disposable seeds stay in the ignored data directories. Do
not commit those directories. Use a fresh pair of data directories for a new
qualification. Setup refuses a wallet that already has channels.

Two variables shorten a trial run of the fixture itself: `QUALIFY_ROUNDS`
(restarts of each kind, default 3) and `QUALIFY_COOLDOWN_MS` (the wait between
scenarios, default 61000, which is what the engine's reconnect backoff needs
to reset). A qualification uses the defaults.

## Containers

One image runs the endpoints, the relay and Tor. Nothing is published to the
host.

- `primary` and `phone`: `node.cjs`, a Beignet daemon node and a control
  server on container loopback, called with `docker exec`.
- `relay`: `beignet porch-relay`, listening on the fixture network. It answers
  to three names: `ws://relay:2114`, `wss://relay.test` and the onion name
  below.
- `caddy`: Caddy as the TLS terminator of `wss://relay.test`, configured as
  the [hosting guide](../../../docs/PORCH.md) configures it. Its certificate
  comes from an authority Caddy makes for the fixture (`tls internal`), which
  the two endpoints are started to trust. The relay is started with
  `--trusted-proxy` set to Caddy's address.
- `tor`: a Tor client with a SOCKS port for the primary, and an onion service
  in front of the relay.

### What stands in for a public relay on the Tor path

A real relay has a public name, and a node with `porchVia: 'tor'` reaches it
through a Tor exit: three hops. A relay in a container has no public name, so
here Tor reaches it as an onion service: six hops, three from each side. The
primary is configured with the relay's onion name and hands out links that
carry it. The phone uses no Tor, so the fixture gives it the same link at
`relay:2114`. A route id does not depend on the relay's name, and one relay
process answers to both.

So the `porch-tor` numbers are an upper bound: the same engine, relay and
link, over a Tor path about twice as long as the one a public relay gets.

## Checks

What a link promises is checked three ways, after the baseline, around every
outage, after every restart and at the end. On the `tcp` path the same things
are recorded and nothing is required of them: it is the control.

- **Packets.** The phone and the primary each count every packet to and from
  the other's address, of any protocol. Both counts must be zero. On
  `porch-tor` the primary and the relay count each other the same way, and
  those must be zero too. Counting starts when the phone has been handed the
  path's link. Both ends of a pair count, so a container whose restart empties
  its rules is covered by the other end.
- **Connections.** Each endpoint records the destination of every outbound
  TCP connection its process makes, from before the engine is loaded. Since
  the run began the phone may have dialed the relay and nothing else, and the
  primary the relay (`porch`) or Tor (`porch-tor`) and nothing else. On
  `porch-tls` the relay is the terminator in front of it, for both. Electrum,
  the chain source, aside.
- **Records.** What each end holds for its peer may not contain the other
  end's address. The primary's names the relay and the link the peer used,
  and the phone's is the address the path's link names.

The counters have a control of their own: on `tcp` the phone and the primary
must have counted each other, and on `porch` the primary must have counted the
relay.

## Phases

- **baseline.** Ten payments to warm both processes up, then forty alternating
  1,000 sat payments. The sender must report COMPLETED and the recipient's
  invoice PAID. Times are the engine's own, from the call to pay until it
  resolves, without Docker control overhead, for all forty and for each
  payer's twenty.
- **latency** (every path but `porch-tor`). Twenty payments each with
  everything between the two ends held back by 0, 20 and 40 ms one way: at
  the relay on the Porch paths, where every frame passes once, and at both
  ends on the TCP path. The result is how many milliseconds a payment gains
  for each millisecond between the two ends, which is what turns these
  laboratory numbers into an estimate for a relay at some distance. It is
  taken from the means: a payment takes a whole number of trips across, not
  always the same number.
- **restart.** One process restarts and nothing is redialed by hand: the
  phone (what opening the app is), the primary, and on the Porch paths the
  relay. Three times each. Measured from the moment the container is back to
  the channel reading usable on both ends, and to the first completed payment.
- **outages.** The phone loses all network for 30, 120 and 300 seconds,
  including its Electrum connection, and gets it back. Recovery uses the
  engine's default timers. A payment in each direction must succeed after
  restoration. A channel can read usable on a connection that is no longer
  there, so the first completed payment is a separate measurement.

Every scenario checks that both endpoints keep the original channel, return to
NORMAL with zero pending HTLCs and emit no channel error, closure or void
event. `final.cjs` also checks mirrored balances and that the funding output
is unspent.

`QUALIFY_TCP_NODELAY=true node qualify.cjs tcp latency` runs a phase with
Nagle's algorithm off on both endpoints' TCP peer sockets, which the WebSocket
transports already have: the two endpoints are started again with the setting,
and back without it by the next run that does not ask for it. It is for
telling what that algorithm costs the `tcp` path apart from what the path
costs. An engine after 0.38.4 turns it off on those sockets itself
([#1990](https://github.com/coreyphillips/beignet/pull/1990)), so there the
switch changes nothing and the `tcp` path measures like the 2026-11-11
record's "Nagle's algorithm off" rows.

Payment time also moves with what else the machine is doing, on every path
alike, and each result records the host's load average beside it. To compare
paths, run their `baseline` phases in rotation rather than one path after
another.

## Teardown

```sh
docker compose down -v
```

This removes the containers, their network and the volumes that hold the Tor
state, the relay's onion key and the fixture's certificate authority. Data directories remain for local inspection.
The fixture has no published ports, host networking or access to the Docker
socket. NET_ADMIN applies only inside the test containers, and the network
helper checks a container's label and network before changing its rules.

## Limits

These are engine tests on one Docker bridge, where the relay is a fraction of
a millisecond from both ends. The `latency` phase is what relates them to a
relay on the Internet. They do not measure a handset's battery use, mobile OS
suspension or Wi-Fi/cellular handover, and the relay here serves one node:
this is not a load test of the relay.
