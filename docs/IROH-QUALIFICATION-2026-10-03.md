# Iroh qualification on the released engine

Date: 2026-10-03. Related issue: [#1311](https://github.com/coreyphillips/beignet/issues/1311).

This qualification uses Beignet 0.26.0 from the released Beignet Umbrel 0.27.0
image, with the native `@number0/iroh` 1.1.0 binding on Linux arm64 and Node
20.20.2. The engine and reconnect settings are unchanged. Both endpoints are
separate disposable regtest containers, with a confirmed 1,000,000 sat channel
funded through Bitcoin Core and observed by Electrum. Discovery is disabled;
the phone-side engine dials the primary's URI with a relay hint.

Image: `ghcr.io/coreyphillips/beignet-app:0.27.0@sha256:96599fbcbad5423c408c959118dabc2d473ee08b530bb7803fb94c529c950528`.

The [fixture](../scripts/regtest-live/iroh-qualification/README.md) contains
reproduction instructions. Direct traffic uses the Docker bridge. Relayed
traffic uses the live n0 public relay, `use1-1.relay.n0.iroh.link`.

## Relay-only payments

Both endpoints reported `transport: iroh` and `path: relay`. IPv4 and IPv6
firewall rules dropped non-DNS UDP in both directions on the phone container.
The rules remained active during payments and recovery. Firewall updates were
atomic, including restoration from a full outage, to prevent brief UDP leaks.
Loopback control traffic and DNS were exempt. UDP drop counters increased
while relay payments completed. No TCP proxy or simulated Lightning funding
was used.

Twenty alternating 1,000 sat payments passed on each path. Sender records
reported COMPLETED and recipient invoices reported PAID. Engine payment times
exclude Docker control overhead; these are small laboratory samples rather
than handset performance guarantees.

| Path   | Payments | p50    | p90    | Maximum |
| ------ | -------- | ------ | ------ | ------- |
| Direct | 20/20    | 177 ms | 284 ms | 383 ms  |
| Relay  | 20/20    | 306 ms | 444 ms | 528 ms  |

## Automatic recovery after outages

All non-loopback traffic was dropped on the phone for each outage, including
its Electrum connection. Traffic was restored to relay-only mode. No manual
dial, engine restart, retry timer override, or Tor fallback was used. There
was a 61-second online interval between scenarios to reset the normal
connection stability window.

| Outage      | Channel after restore                        | First payment confirmed after restore |
| ----------- | -------------------------------------------- | ------------------------------------- |
| 30 seconds  | QUIC connection survived                     | 2.46 seconds                          |
| 120 seconds | Automatically reestablished in 29.29 seconds | 31.30 seconds                         |
| 300 seconds | Automatically reestablished in 47.10 seconds | 49.29 seconds                         |

Each scenario passed a payment in both directions afterward. Times include
control and polling overhead and begin after the firewall restoration
finishes. The complete traffic blocks were slightly longer than their target
durations because status and drop-counter snapshots were taken before restore.

Automatic recovery works, but it is not consistently subsecond. The released
peer manager uses a 10-second Iroh dial deadline and exponential reconnect
backoff with jitter, resetting after 60 seconds of a stable connection. These
measurements retain that policy. They do not isolate every millisecond spent
in peer-manager backoff from the relay's own reconnect behavior. Do not infer
that the older, approximately 30-second recovery observation has disappeared.

## Repeated cuts during payments

Thirty observed in-flight cuts passed on each path, with **zero channel
failures in 60 cuts**. All 60 interrupted payments settled and all follow-up
payments succeeded. The relay path needed 30 attempts. The direct path needed
36 attempts because six payments finished before the timer could interrupt
them; those attempts are excluded from the cut count.

Warmup-to-target gaps were 0 to 56 ms on relay and 1 to 7 ms on direct. Timer
callbacks ran 90 to 408 ms after target start on relay and 75 to 356 ms on
direct, reflecting event-loop scheduling beyond the requested delays.

The sweep starts each target payment immediately after a warmup payment
returns, without waiting for the remaining channel commitment work. Control
runs inside the payer container so Docker round trips do not separate the
payments. The observed gap and cut offset are recorded. The sweep cycles
through offsets from 20 to 250 ms and counts a cut only when the target
payment is unfinished, an HTLC exists, and the socket is an Iroh transport.
The fixture closes the live duplex without changing channel state, signed
messages, or persistence.

Stress runs explicitly redial after the cut to keep repeated cuts bounded.
They qualify channel recovery and payment settlement. The outage scenarios
above independently qualify automatic reconnect with the production timers.
Every attempt is followed by a fresh payment in the reverse direction.

Both endpoints retained channel
`81b7f59a92e20122fc7586d396eae3072764c4c6e9b583ab090aab154e32c14a` in NORMAL,
with zero pending HTLCs, mirrored balances of 700,000 and 300,000 sat, and no
channel error, closure, or void events. Both Electrum connections recovered.
Bitcoin Core confirmed that the original 1,000,000 sat funding output remains
unspent, with six confirmations. The [recorded evidence](IROH-QUALIFICATION-2026-10-03.json)
includes payment timings, interruption offsets, firewall counters, and the
final channel state.

Fixture syntax checks, Prettier, ESLint, Compose configuration validation, and
`git diff --check` passed. No engine code, dependency, or release version was
changed for this qualification.

## Scope

These are finite engine tests, not a guarantee against every possible channel
failure. A separate empty-fixture restart check confirmed that its saved seed retains
the node and Iroh endpoint identities across a process restart. Earlier [native integration validation](https://github.com/coreyphillips/chicory/pull/36)
covered payments before and after a mobile engine restart. The
maintainer separately confirmed that Chicory connects to the released Umbrel
node on their own hardware.

This report does not claim new handset measurements for cellular CGNAT,
Wi-Fi/cellular handover, mobile OS suspension, battery drain, or repeated
cold-start comparisons against Tor. Those device checks remain distinct from
the relay and channel-safety qualification here.
