# Iroh relay-only qualification

Date: 2026-11-11. Related issue: [#1980](https://github.com/coreyphillips/beignet/issues/1980).

This qualification runs Beignet 0.38.4 with the `irohRelayOnly` change (commit
`7778036a`), packed from the working tree, on the native `@number0/iroh` 1.1.0
binding, Linux arm64 and Node 22.23.4. Both endpoints are separate disposable
regtest containers on one Docker bridge, with a confirmed 1,000,000 sat channel
funded through Bitcoin Core and observed by Electrum. Discovery is disabled; the
phone-side engine dials the primary's URI with its relay hint. The relay is the
live n0 public relay, `use1-1.relay.n0.iroh.link`.

The primary runs with `irohRelayOnly`. This binding cannot remove the IP
transport, so the mode is `loopback-pin`. The phone is an ordinary Iroh
endpoint, as anyone holding the primary's link would be.

The [fixture](../scripts/regtest-live/iroh-qualification/README.md) contains
reproduction instructions.

## What would count as a leak

In relay-only mode the fixture leaves the firewall open. The two containers
share a bridge, so a direct path is one hop away and Iroh takes it whenever the
primary offers one. Three independent checks look for that:

- **Path.** Each endpoint samples the path of its Iroh peers every 100 ms from
  the moment its process starts. No sample on either end may read `direct`.
- **Addresses.** The phone's own Iroh stack is asked what it holds for the
  primary's endpoint. It may hold nothing but loopback.
- **Packets.** The phone's firewall counts packets to and from the primary
  container's address, of any protocol, and the datagrams among them. Every
  count must be zero.

The checks ran 20 times: after each baseline, before, during and after each
outage, and after every restart.

| Check                                       | Relay-only  | Control: same engine, relay-only off |
| ------------------------------------------- | ----------- | ------------------------------------ |
| Path samples reading `direct`               | 0           | every sample                         |
| Routable addresses the phone holds          | 0           | 1 to 4, read after two control runs  |
| Packets between the containers, 20 payments | 0 out, 0 in | 220 out, 224 in                      |
| `IROH_RELAY_ONLY_VIOLATED` raised           | never       | not applicable                       |

The control is what makes the zeros mean something: with the same image, the
same containers and the same channel, switching relay-only off puts every
sample on the direct path and hundreds of packets on the bridge.

One scenario is deliberately outside those zeros and has its own section below:
a phone that learned the address before relay-only was switched on.

## Payments

Twenty alternating 1,000 sat payments on each path. Sender records reported
COMPLETED and recipient invoices reported PAID. Engine payment times exclude
Docker control overhead. These are small laboratory samples, not handset
measurements.

| Path                                        | Payments | p50    | p90    | Maximum |
| ------------------------------------------- | -------- | ------ | ------ | ------- |
| Direct (relay-only off)                     | 20/20    | 92 ms  | 104 ms | 114 ms  |
| Direct, second run                          | 20/20    | 108 ms | 249 ms | 349 ms  |
| Relay forced by a firewall (relay-only off) | 20/20    | 170 ms | 174 ms | 174 ms  |
| Relay-only                                  | 20/20    | 171 ms | 179 ms | 180 ms  |
| Relay-only, second run                      | 20/20    | 192 ms | 341 ms | 409 ms  |

Relay-only costs what the relay path costs, about 80 ms a payment over the
direct path here. These numbers are not comparable with the
[October run](IROH-QUALIFICATION-2026-10-03.md), which measured engine 0.26.0.

## Recovery after outages

All non-loopback traffic was dropped on the phone for each outage, including
its Electrum connection, then restored. No manual dial, engine restart or
timer override was used, and 61 seconds passed between scenarios.

| Outage      | Channel after restore                       | First payment confirmed after restore |
| ----------- | ------------------------------------------- | ------------------------------------- |
| 30 seconds  | QUIC connection survived                    | 3.34 seconds                          |
| 120 seconds | Automatically reestablished in 24.0 seconds | 24.9 seconds                          |
| 300 seconds | Automatically reestablished in 63.7 seconds | 64.9 seconds                          |

The reconnect policy is the released one: a 10-second Iroh dial deadline and
exponential backoff with jitter. These runs do not separate backoff from the
relay's own reconnect time. The October run measured 29.3 and 47.1 seconds for
the same two outages on an ordinary relayed path.

## Restarts

The restarted process comes back with nothing in memory, so the two ends set
up a connection from nothing while the counters run. Times start when
`docker restart` returns. Three restarts each.

Restarting the phone, which is what opening the app is:

| Path                    | Usable channel        | First payment confirmed |
| ----------------------- | --------------------- | ----------------------- |
| Direct (relay-only off) | 0.73, 0.72 and 0.78 s | 1.65, 1.65 and 1.72 s   |
| Relay-only              | 1.25, 1.29 and 1.22 s | 2.24, 2.24 and 2.26 s   |

Restarting the primary:

| Path                    | Usable channel        | First payment confirmed |
| ----------------------- | --------------------- | ----------------------- |
| Direct (relay-only off) | 1.67, 2.17 and 1.69 s | 2.59, 3.07 and 2.62 s   |
| Relay-only              | 18.4, 16.9 and 19.8 s | 19.4, 17.8 and 20.7 s   |

Twelve of the primary's seconds are the silent watch `loopback-pin` keeps
before the endpoint accepts or makes a connection. Most of the rest is the
phone's reconnect backoff, since a dial that arrives during the watch is
refused. The `native` mode has no watch.

## A phone that already knew the address

Relay-only cannot make a peer forget. To see what it does owe such a peer, the
primary was started with relay-only off, the phone connected and paid over the
direct path, and the primary was then recreated with relay-only on while the
phone process kept running. The phone still held one address for the primary
when the phase began. The primary was then restarted three times.

| After restart | Addresses the phone holds | Datagrams phone to primary | Datagrams primary to phone | Path, both ends |
| ------------- | ------------------------- | -------------------------- | -------------------------- | --------------- |
| 1             | 1 (the old one)           | 1                          | 0                          | relay           |
| 2             | 0                         | 8                          | 0                          | relay           |
| 3             | 0                         | 0                          | 0                          | relay           |

The phone probed the address it remembered. The primary's endpoint sent it no
datagram, no path sample read `direct` after the phase began, and the phone
learned no new address. The any-protocol counter saw one packet from the
primary's address for each probe while the datagram counter stayed at zero,
which is what a kernel answering a closed port looks like. By the second
restart the phone's stack had dropped the old address.

So switching relay-only on protects the address from everyone who dials the
link afterwards. It does not take the address back from a peer that connected
before. Beignet does not store a peer's Iroh addresses, so such a peer holds
them only until its process restarts, but the safe order is to switch
relay-only on before the link is first handed out.

## Final state

Both endpoints retained channel
`e49ce2006bcfd31bf03581fb11f8ad393cfd0fb47fbed6c53f82d2c105cdd24b` in NORMAL
with zero pending HTLCs and mirrored balances of 703,000 and 297,000 sat. There
were no channel failures. Bitcoin Core confirmed that the original
1,000,000 sat funding output remains unspent, with 19 confirmations. The
[recorded evidence](IROH-RELAY-ONLY-QUALIFICATION-2026-11-11.json) holds the
payment timings, every leak check with its sample and packet counts, and the
restart and outage timings.

## Scope

- Only `loopback-pin` ran. No released `@number0/iroh` exposes
  `clearIpTransports`, which the `native` mode needs.
- A Docker bridge has no router that answers UPnP, NAT-PMP or PCP, so the guard
  that closes the endpoint when a port mapping adds a routable address did not
  fire here. Unit tests cover it (`tests/lightning/iroh-node.test.ts`).
- The relay operator sees both ends' addresses in any relayed mode. Nothing
  here measures or limits that.
- The repeated-cut phase of the October run was not repeated in relay-only
  mode.
- No handset, cellular or mobile OS suspension measurements.
