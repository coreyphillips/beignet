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

Afterward:

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
