# Iroh network qualification

Manual regtest qualification for the released Beignet 0.26.0 engine in the
Beignet Umbrel 0.27.0 image. Both endpoints use the real native Iroh binding,
BOLT 8, a Bitcoin-funded channel, and the public n0 relay. No TCP proxy or
simulated funding is involved. Discovery is disabled and the phone dials the
primary URI with its relay hint, matching the mobile configuration.

The fixture requires Docker Desktop, Node 22, and the repository's local
regtest Bitcoin/Electrum pair. Bitcoin must be container `bitcoin` (override
with `BEIGNET_REGTEST_BITCOIN`) with its documented test RPC settings on port 43782. Electrum must be reachable at `host.docker.internal:60001`. Setup checks
Bitcoin's chain before funding or mining. Use only disposable regtest services.

## Run

From this directory, with no previous qualification containers running:

```sh
mkdir -m 700 primary-data phone-data
docker compose up --build -d
node setup.cjs
node balance.cjs
node qualify.cjs direct baseline
node qualify.cjs relay all
node qualify.cjs direct outages
node qualify.cjs direct cuts
node final.cjs
```

Wait until both containers log `ready` before setup. A complete run takes tens
of minutes, including six real outages and the normal recovery timers. The
optional phase argument is `baseline`, `outages`, or `cuts`; omitting it runs
all three phases. Scenarios are sequential and must not run concurrently.

The scripts write `results.jsonl`, phase snapshots, and `channel.json` locally.
Wallet data and the disposable seeds stay in the ignored data directories.
Do not commit those directories. Use a fresh pair of data directories for a
new qualification. Setup refuses a wallet that already has channels.

## Relay-only, on the engine from this checkout

`compose.local.yaml` runs the same two endpoints on the engine packed from the
working tree, and `QUALIFY_RELAY_ONLY=true` starts the primary with
`irohRelayOnly`. The phone stays an ordinary Iroh endpoint, as anyone holding
the primary's link would be.

From the repository root, then this directory:

```sh
npm run build
npm pack --pack-destination scripts/regtest-live/iroh-qualification
cd scripts/regtest-live/iroh-qualification
mv beignet-*.tgz beignet-local.tgz
mkdir -m 700 primary-data phone-data
QUALIFY_RELAY_ONLY=true docker compose -f compose.local.yaml up --build -d
node setup.cjs
node balance.cjs
node qualify.cjs relay-only baseline
node qualify.cjs relay-only outages
node qualify.cjs relay-only restart
node final.cjs
```

In `relay-only` mode the firewall is left open, so a direct path over the
Docker bridge would be taken if the primary offered one. The mode adds a leak
check, run after the baseline, around every outage, after every restart and
after the cuts:

- Path: each endpoint samples the path of its Iroh peers every 100 ms from
  the moment its process starts. No sample on either end may read `direct`.
- Addresses: the phone's own Iroh stack is asked what it holds for the
  primary's endpoint. It may hold no address other than loopback.
- Packets: the phone's firewall counts packets to and from the primary
  container's address, of any protocol, and the datagrams among them. Every
  count must be zero.

The `restart` phase restarts the primary process three times and redials
nothing by hand, so the two ends set up a connection from nothing while the
counters run. `QUALIFY_RESTART_ROLE=phone` restarts the phone instead, which is
what opening the app is. The phase is not part of `all`. It works in the other
modes too, as a comparison.

The strict checks need a phone that never met the primary with relay-only off:
start from fresh containers, or restart the phone container after any control
run. The results of 2026-11-11 are in
[docs/IROH-RELAY-ONLY-QUALIFICATION-2026-11-11.md](../../../docs/IROH-RELAY-ONLY-QUALIFICATION-2026-11-11.md).

For a control, start the same image without `QUALIFY_RELAY_ONLY` and run
`node qualify.cjs direct baseline`: every sample reads `direct` and the packet
counters in `baseline-passed` are far from zero.

### A phone that already knew the address

Relay-only cannot make a peer forget. A phone that connected while relay-only
was off holds the primary's addresses until its own process restarts, and it
keeps probing them. Switching the primary to relay-only under a running phone
reproduces that:

```sh
docker compose -f compose.local.yaml up -d            # relay-only off
node qualify.cjs direct baseline                       # the phone learns the address
QUALIFY_RELAY_ONLY=true docker compose -f compose.local.yaml up -d
QUALIFY_PHONE_KNOWS_PRIMARY=true node qualify.cjs relay-only restart
```

With `QUALIFY_PHONE_KNOWS_PRIMARY=true` the check is what a relay-only
endpoint owes such a peer: the phone may hold and probe the addresses it had
when the phase began and no others, no path sample reads `direct` after the
phase began, and the primary sends the phone no datagram from its own address.
Without the variable a phone that holds any address fails the phase at its
start.

The primary serves no link for its first twelve seconds (see the relay-only
section of the CLI README); setup and the restart phase wait for it. A Docker
bridge has no router that grants port mappings, so `loopback-pin` holds here.
That part of the design is not exercised by this fixture.

## What discovery publishes

`discovery-record.cjs` is a check for the host, not for the containers. It
binds two throwaway Iroh endpoints with fresh keys, one as Iroh binds by
default and one with its UDP sockets on loopback as relay-only binds them, and
reads each one's discovery record back from n0's DNS server three times over
half a minute. It prints kinds and counts and never an address.

```sh
node discovery-record.cjs
```

It exits 0 when no record carried an address, 1 when one did, and 2 when no
record could be read. A run shows something only where an endpoint holds an
address a stranger could route to (`anEndpointHeldARoutableAddress`), and a
home network with port mapping is such a place.

On 2026-11-11, with binding 1.1.0 on a home network with port mapping, the
default endpoint held two routable addresses and the loopback-bound one held
one. All six records read carried a relay URL and no address.

## Teardown

Either compose file:

```sh
docker compose down
```

This removes the fixture containers and their network, including the firewall
rules. Data directories remain for local inspection. The fixture has no
published ports, host networking, or access to the Docker socket. Its HTTP
control server listens only on container loopback and is called using
`docker exec`. NET_ADMIN applies only inside the test containers. The network
helper checks the container label and network before changing its rules.

## Checks and limits

- Twenty alternating 1,000 sat payments on each path. Both peers must report
  the requested direct or relay path. The sender must report COMPLETED and
  the recipient's invoice must report PAID.
- Relay mode drops non-DNS UDP in both directions for IPv4 and IPv6 on the
  phone container. DNS and loopback control traffic remain available.
  Firewall updates commit atomically so restoring an outage cannot briefly allow UDP.
  Firewall counters are recorded alongside path diagnostics.
- Outages drop all non-loopback traffic on the phone for 30, 120, and 300
  seconds, including its Electrum connection. Recovery uses the released
  engine's default reconnect behavior without a manual dial or process
  restart. A payment in each direction must succeed after restoration.
  Each outage is followed by 61 seconds online so the production stability
  window can reset the reconnect backoff. Reported channel usability and
  first completed payment are separate measurements; an existing QUIC
  connection can remain marked usable while its network is unavailable.
- Thirty observed in-flight cuts per path. Offsets cycle from 20 to 250 ms. Each target payment starts immediately after
  a warmup payment returns, using container-loopback control to avoid Docker
  round trips in that gap. The gap is recorded and must be under 100 ms.
  A cut counts only when the payment is unfinished, an HTLC exists, and the
  peer's live transport is Iroh. The fixture closes that duplex, without
  modifying channel state or protocol messages. A fresh reverse payment
  follows every attempt. Stress runs explicitly redial to keep the sweep
  bounded; automatic recovery is measured separately in the outage phase.
- Every scenario checks that both endpoints retain the original channel,
  return to NORMAL with zero pending HTLCs, and emit no channel error,
  closure, or void event. Final checks also verify mirrored balances and that the
  original funding output is still unspent. It fails if any interrupted payment remains
  unresolved or if too few in-flight cuts occur.

These are engine tests using two Linux containers. Direct traffic uses the
Docker bridge; relay traffic uses the live Internet relay. This does not
measure handset battery use, mobile OS suspension, or Wi-Fi/cellular handover.
