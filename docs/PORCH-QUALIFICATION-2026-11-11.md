# Porch qualification

Date: 2026-11-11. Related issue: [#1980](https://github.com/coreyphillips/beignet/issues/1980).

This qualification runs Beignet 0.38.4 with the Porch changes (commit
`5ccf0c11`), packed from the working tree, on Linux arm64 and Node 22.23.4.
Two endpoints are separate disposable regtest containers on one Docker bridge,
with a confirmed 1,000,000 sat channel funded through Bitcoin Core and observed
by Electrum. The relay between them is a third container started with
`beignet porch-relay`, the command an operator runs.

The primary is a node at home: it hands out a link. The phone is whoever holds
that link: it dials it, as an app would, and uses no Tor on any path.

The same two endpoints and the same channel were measured on four paths:

| Path               | The primary is reached                                                              | Who is shown the primary's address |
| ------------------ | ----------------------------------------------------------------------------------- | ---------------------------------- |
| TCP                | directly, on a TCP listener. The control                                            | the phone                          |
| Porch              | through the relay, over `ws://`                                                     | the relay                          |
| Porch behind TLS   | through the relay behind Caddy 2.10.2 as TLS terminator, over `wss://`              | the relay                          |
| Porch, through Tor | through the relay, which the primary dials through Tor 0.4.9.11 (`porchVia: 'tor'`) | nobody                             |

Porch behind TLS is how the [hosting guide](PORCH.md) sets a relay up, with
the same Caddy configuration but for the certificate, which here comes from an
authority of the fixture's own. The
[fixture](../scripts/regtest-live/porch-qualification/README.md) contains
reproduction instructions.

## In short

- Nothing passed between the phone and the primary on any Porch path: 72
  checks, zero packets either way, as each of the two counted them.
- The relay cost nothing that could be measured. A payment took 89 ms through
  it, 90 ms through it behind TLS, and 90 ms on a direct TCP connection with
  Nagle's algorithm off.
- Direct TCP as the engine shipped took 111 ms, and twice the round trips
  with distance. That is a finding of its own,
  [#1989](https://github.com/coreyphillips/beignet/issues/1989), fixed after
  this run by [#1990](https://github.com/coreyphillips/beignet/pull/1990).
- With the relay reached through Tor, a payment took 1.5 s and a channel was
  usable about 3 s after the phone restarted, over a Tor path twice as long as
  a public relay gets.
- All 18 phases passed, every payment completed, and the channel ended as it
  began.

## What would count as a leak

A link promises that whoever holds it is not shown where the node is. Three
independent checks look for that:

- **Packets.** The phone and the primary each count every packet to and from
  the other's address, of any protocol. Both counts must be zero. Through Tor
  the primary and the relay count each other the same way, and those must be
  zero too.
- **Connections.** Each endpoint records the destination of every outbound TCP
  connection its process makes, from before the engine is loaded. The phone
  may dial the relay and nothing else, and the primary the relay, or Tor, and
  nothing else. Electrum, the chain source, aside.
- **Records.** What each end holds for its peer may not contain the other
  end's address.

Counting starts when the phone has been handed the path's link, and the Porch
paths ran first, on data directories in which the phone had never been told
the primary's address. The checks ran after every baseline, after every
restart, before, during and after every outage, and at the end of each run.

| Check                              | Porch                         | Porch behind TLS              | Porch, through Tor            | Control: TCP                     |
| ---------------------------------- | ----------------------------- | ----------------------------- | ----------------------------- | -------------------------------- |
| Times checked                      | 26                            | 26                            | 20                            | 31                               |
| Packets between phone and primary  | 0 out, 0 in, at both ends     | 0 out, 0 in, at both ends     | 0 out, 0 in, at both ends     | 1,567 out, 1,480 in at the phone |
| Packets between primary and relay  | 1,761 out, 1,865 in           | none: Caddy is in between     | 0 out, 0 in, at both ends     | none                             |
| The phone dialed                   | `relay:2114`                  | `relay.test:443`              | `relay:2114`                  | `primary:9735`                   |
| The primary dialed                 | `relay:2114`                  | `relay.test:443`              | `tor:9050`                    | nothing                          |
| The primary holds for its peer     | the relay's name and the link | the relay's name and the link | the relay's name and the link | the phone's address and port     |
| The phone holds for its peer       | `relay:2114`                  | `relay.test:443`              | `relay:2114`                  | `primary:9735`                   |
| `proxied` in the primary's `/info` | `false`                       | `false`                       | `true`                        | not applicable                   |

Packet counts are from each path's full run. The control is what makes the
zeros mean something: with the same image, the same containers, the same
channel and the same rules, the TCP path put about 1,500 packets each way
between the two addresses, and left the phone's address and port in the
primary's peer list.

## Payments

Forty alternating 1,000 sat payments in each run, after ten to warm both
processes up. Sender records reported COMPLETED and recipient invoices
reported PAID. Times are the engine's own, from the call to pay until it
resolves, without Docker control overhead. These are small laboratory samples,
not handset measurements.

The machine was shared with other work throughout, and payment time moves with
that on every path alike. So the paths were compared in rotation: Porch, Porch
behind TLS, TCP, and TCP with Nagle's algorithm off, three rounds in seven
minutes, with the host's load average between 5.4 and 7 on 18 cores.

| Path                       | Payments | p50 of each round | p50 of all | p95 of all | Maximum |
| -------------------------- | -------- | ----------------- | ---------- | ---------- | ------- |
| Porch                      | 120/120  | 89, 88 and 90 ms  | 89 ms      | 103 ms     | 111 ms  |
| Porch behind TLS           | 120/120  | 90, 91 and 92 ms  | 90 ms      | 100 ms     | 113 ms  |
| TCP                        | 120/120  | 111, 111, 113 ms  | 111 ms     | 118 ms     | 126 ms  |
| TCP, Nagle's algorithm off | 120/120  | 89, 91 and 90 ms  | 90 ms      | 101 ms     | 114 ms  |

Two more hops and a relay process in the middle cost about nothing here, and
TLS with a terminator in front of the relay about one millisecond. The fair
comparison for the relay is the last row, not the third: see
[TCP and Nagle's algorithm](#tcp-and-nagles-algorithm).

Each path's own full run opened with the same baseline, at whatever the
machine was doing then:

| Path               | Payments | p50      | p95      | Maximum  | Host load |
| ------------------ | -------- | -------- | -------- | -------- | --------- |
| TCP                | 40/40    | 109 ms   | 116 ms   | 118 ms   | 8.1       |
| Porch              | 40/40    | 91 ms    | 120 ms   | 131 ms   | 6.1       |
| Porch behind TLS   | 40/40    | 134 ms   | 154 ms   | 167 ms   | 19        |
| Porch, through Tor | 40/40    | 1,475 ms | 1,786 ms | 1,963 ms | 9.1       |

The 134 ms is the load, not TLS: that run fell in the machine's busiest
quarter of an hour, and the same path measured 90 ms in the rotation.

## Distance

On one bridge the relay is a fraction of a millisecond from both ends. To
relate that to a relay on the Internet, everything between the two ends was
held back by a fixed time each way: at the relay on the Porch paths, where
every frame passes once, and at both ends on the TCP path. Twenty payments at
each point, the mean of each.

| Path                              | Nothing added | 20 ms each way | 40 ms each way | A payment gains, per ms |
| --------------------------------- | ------------- | -------------- | -------------- | ----------------------- |
| Porch                             | 90 ms         | 164 ms         | 246 ms         | 3.9 ms                  |
| Porch behind TLS                  | 128 ms        | 201 ms         | 290 ms         | 4.1 ms                  |
| TCP, Nagle's algorithm off        | 93 ms         | 165 ms         | 249 ms         | 3.9 ms                  |
| TCP                               | 108 ms        | 263 ms         | 439 ms         | 8.3 ms                  |
| TCP, a second run half an hour on | 113 ms        | 270 ms         | 428 ms         | 7.9 ms                  |

A payment through the relay gains about 4 ms for each millisecond between the
phone and the node: two round trips. That is what a direct connection gains
once Nagle's algorithm is off, so the relay adds its place on the path and
nothing of its own. With a relay, the distance is the phone to the relay plus
the relay to the node: one that is 10 ms from each makes a 90 ms payment about
170 ms, and one next to either end costs almost nothing.

## Restarts

One process restarts and nothing is redialed by hand. The restarted process
comes back with nothing in memory. Times start when `docker restart` returns,
and 61 seconds pass between scenarios. Three restarts each.

Restarting the phone, which is what opening the app is:

| Path               | Usable channel        | First payment confirmed |
| ------------------ | --------------------- | ----------------------- |
| TCP                | 0.70, 0.69 and 0.72 s | 1.54, 1.54 and 1.58 s   |
| Porch              | 0.73, 0.76 and 1.07 s | 1.54, 1.58 and 2.28 s   |
| Porch behind TLS   | 1.10, 0.98 and 0.77 s | 2.07, 1.88 and 1.64 s   |
| Porch, through Tor | 2.62, 3.11 and 3.16 s | 4.86, 5.37 and 4.93 s   |

Restarting the primary:

| Path               | Usable channel        | First payment confirmed |
| ------------------ | --------------------- | ----------------------- |
| TCP                | 0.68, 2.63 and 2.17 s | 1.48, 3.48 and 2.53 s   |
| Porch              | 1.04, 0.95 and 1.03 s | 1.98, 1.83 and 2.00 s   |
| Porch behind TLS   | 0.72, 0.73 and 0.73 s | 1.59, 1.56 and 1.56 s   |
| Porch, through Tor | 5.05, 4.65 and 5.04 s | 6.83, 6.46 and 6.80 s   |

On a Porch path the primary dials the relay and registers, and a phone that
dials its link first is held by the relay for up to three seconds while the
primary's connection is on its way. On the TCP path a dial that arrives before
the listener is up is refused, and the next comes when the phone's reconnect
backoff allows, which is most likely the two slower rows.

Restarting the relay, which drops every connection through it:

| Path               | Usable channel        | First payment confirmed |
| ------------------ | --------------------- | ----------------------- |
| Porch              | 1.97, 1.53 and 1.13 s | 2.87, 2.44 and 2.05 s   |
| Porch behind TLS   | 1.22, 1.71 and 1.73 s | 2.06, 2.54 and 2.54 s   |
| Porch, through Tor | 4.61, 4.63 and 5.08 s | 6.40, 6.45 and 37.3 s   |

The relay keeps no state, and nothing had to be done at either end. The 37 s
is one payment that took 31.5 s through Tor on a channel that read usable
after 5.1 s; the one after it took 6.6 s, and the next 1.3 s.

## Recovery after outages

All non-loopback traffic was dropped on the phone for each outage, including
its Electrum connection, then restored. No manual dial, engine restart or
timer override was used, and 61 seconds passed between scenarios.

| Outage      | TCP                         | Porch                       | Porch behind TLS            | Porch, through Tor          |
| ----------- | --------------------------- | --------------------------- | --------------------------- | --------------------------- |
| 30 seconds  | survived; payment in 7.18 s | survived; payment in 5.80 s | survived; payment in 7.11 s | survived; payment in 13.0 s |
| 120 seconds | usable 10.7 s; paid 11.6 s  | usable 8.42 s; paid 9.38 s  | usable 12.6 s; paid 13.4 s  | usable 4.44 s; paid 6.20 s  |
| 300 seconds | usable 8.78 s; paid 9.15 s  | usable 0.09 s; paid 0.99 s  | usable 0.55 s; paid 0.91 s  | usable 6.96 s; paid 8.76 s  |

Times are from the moment the network returned. The connection outlived the
30 second outage on every path: nothing was dialed, and the first payment
waited for TCP to send again what the outage had swallowed. After the longer
ones the phone dialed again by the engine's reconnect backoff (one second,
doubling, capped at five minutes), so the time is where that timer stood when
the network came back, with or without a relay. On the Porch path the 300
second outage ended with a dial in flight, which connected at once, and
behind TLS the next dial came half a second later. It can stand badly too: a
trial of the same fixture earlier the same day took 153 s after the 300
second outage on the Porch path, and 9.4 s on TCP.

## Through Tor

A public relay has a public name, and a node with `porchVia: 'tor'` reaches it
through a Tor exit: three hops. A relay in a container has no public name, so
here Tor reached it as an onion service: six hops, three from each side. The
primary was configured with the relay's onion name, and the phone, which uses
no Tor, was given the same link at the relay's name on the bridge. A link's id
does not depend on the relay's name. So the Tor figures are an upper bound:
the same engine, relay and link over a Tor path about twice as long as a
public relay gets.

The primary dialed nothing but the Tor proxy, the relay and the primary
exchanged no packet, and `/info` reported `proxied: true` at every check.

What it costs is in the tables above: 1.5 s a payment, about 3 s to a usable
channel after the phone restarts, about 5 s after the primary or the relay
does. Tor circuits differ from one hour to the next. A trial of the same
fixture earlier the same day measured a p50 of 2.2 s a payment, and 5.1 to
8.5 s to a usable channel after a phone restart.

The phone does not wait for a Tor circuit to be built. The primary's
connections to the relay are open before the phone arrives, and the phone
itself dials the relay directly.

## TCP and Nagle's algorithm

The control turned up something of its own. The engine's plain TCP peer
sockets leave Nagle's algorithm on, and its WebSocket sockets turn it off. A
Lightning message is one small write, and the next often follows before the
first is acknowledged, so on TCP that second write waits for the
acknowledgement. This is why a payment through the relay was faster than the
same payment on a direct connection: 89 ms against 111 ms next to each other,
and 4 ms against 8 ms for each millisecond of distance.

The rows marked "Nagle's algorithm off" were measured with
`QUALIFY_TCP_NODELAY=true`, which sets `TCP_NODELAY` on both endpoints' peer
sockets from outside the engine. The engine itself is unchanged in this run.
The fix is [#1990](https://github.com/coreyphillips/beignet/pull/1990), merged
after this run, where the patched engine was measured against master and gave
the same figures. It also covers the watchtower client's socket, which this
fixture does not exercise.

## Final state

Both endpoints retained channel
`b4c7692fcae00ae596dfcbd3d7f37201f39d591bb48ab117da3dfab0e54745d8` in NORMAL
with zero pending HTLCs and mirrored balances of 700,000 and 300,000 sat. There
were no channel failures. Bitcoin Core confirmed that the original
1,000,000 sat funding output remains unspent, with 6 confirmations. The
[recorded evidence](PORCH-QUALIFICATION-2026-11-11.json) holds every baseline
payment's time, every leak check with its packet counts, dialed destinations
and peer records, and the latency, restart and outage timings.

## Scope

- The relay served one node and one visitor. This is not a load test of the
  relay, and none of its limits was reached.
- One Docker bridge, with no loss and no distance but the fixed delay of the
  distance phase. A real path has both.
- The Tor path is the onion stand-in described above. A relay with a public
  name reached through a Tor exit was not measured.
- The TLS terminator used a certificate authority of the fixture's own
  (`tls internal`), which the two endpoints were started to trust. A public
  certificate differs in who signed it.
- The relay's operator sees both ends' addresses on the Porch and TLS paths.
  Nothing here measures or limits that.
- A link cannot take back an address a peer already has. The checks are about
  a phone that was only ever handed the link, which is why the Porch paths ran
  first, on fresh data, and the TCP control last.
- The machine was shared: the host's load average is recorded beside every
  measurement in the evidence.
- No handset, cellular or mobile OS suspension measurements.
