# Automatic offline receiving

The wallet integration prepares a one-payment FFOR reservation before displaying a fixed-amount Lightning invoice. Closing the app does not cancel it. On startup and while running, the wallet requests receipts, verifies each preimage against its stored invoice hash, and reconciles completed voucher receipts into its ordinary balance and Activity. An unpaid invoice stays payable until its expiry. The coordinator requests retirement after a two-minute settlement grace period and never force closes automatically. An expired invoice does not by itself release the underlying reservation.

This requires the accompanying wallet-core and portable-engine changes plus an upgraded settlement peer. Beignet 0.21.7 by itself does not implement the discovery and funding messages described below. An unsupported peer fails the receive preparation explicitly. The app does not silently issue an online-only invoice.

## Provider configuration

Settlement remains opt-in. Funding new receive channels requires a separate explicit policy, for example:

```json
{
  "fforSettle": { "enabled": true },
  "fforReceiveFunding": {
    "enabled": true,
    "maxChannels": 100,
    "maxChannelsPerPeer": 5,
    "maxChannelSats": 500000,
    "maxTotalSats": 5000000
  }
}
```

These are cumulative allocation limits, persisted before initiating funding. A failed or interrupted opening retains its allocation rather than risking a second spend on retry. Operators must budget for the funding transactions and channel liquidity. New channels contain the invoice amount plus 50,000 sats of headroom and use a 2 sat/vbyte funding rate. The open is zero-confirmation only when the operator has already put that client in the zero-conf trusted set (`POST /trusted-peer/add`); every other client gets an ordinary confirmed open. Earlier builds proposed the zero-conf channel type to every client regardless, which a peer that had not trusted this node back refuses outright. Allocation never adds a receiving peer to the inbound trust list.

Automatic offline receiving uses a channel that already exists with the peer and whose inbound capacity covers the amount. When both peers negotiate concurrent receive and the settlement peer offers concurrent terms, that channel may contain spendable local money. Ordinary payments remain available within its unreserved capacity while the wallet is online. Baseline receive still requires an empty inbound channel and pauses ordinary payments while its book is live. With no suitable channel, the request falls back to direct funding, where the payer's on-chain payment becomes this node's channel funding and the liquidity peer opens the channel to us. The receiver never sends the `allocate` message described below; the provider side still answers it for other clients.

## Concurrent receive

Concurrent receive defaults to enabled. `BEIGNET_FFOR_CONCURRENT` (configuration key `fforConcurrent`) controls advertisement; `BEIGNET_FFOR_SETTLE_CONCURRENT` (`fforSettleConcurrent`) controls acceptance of new books. Both default to true and accept explicit `false`. The settlement role still requires separate enablement. Disabling acceptance of new concurrent books does not change the persisted profile of existing books.

The automatic coordinator chooses version 2 from an upgraded peer's terms and saves that choice before creating an epoch. A retry cannot silently switch versions or fall back to a baseline book. Busy channel payments return `RECEIVE_PENDING`; retry the same request after those payments settle. If its 60-second quote expired, refresh `/receive/quote` with the same `requestId` so the quote reuses its reservation. One immutable book may be live per channel. Each invoice has a fixed amount.

`POST /ffor/sync` requests cumulative signed receipts without closing a concurrent book. A successful response reports the current epoch view; the reply and redemption may finish later. `POST /ffor/recover` reports `action: 'synced'` for connected concurrent recovery. Proof custody alone is not a completed payment. The epoch view distinguishes `settled` proof state from terminal `redeemed` or `cancelled` outcomes, and reports `concurrentVersion`, `snapshotSeq` (a decimal string, or null for unreadable retained evidence) and `capabilityHold`.

Explicit retirement, including the coordinator's expiry path, uses `/ffor/epoch/close`. Version 2 keeps unknown slots reserved in `DRAINING` until their outcomes can be resolved safely. Ordinary payments may continue with the remaining capacity. Fee updates, splices and cooperative channel close remain unavailable while reservations are live. Hosts must keep `reservedChannelIds` excluded from automatic channel changes while using `htlcUsable` and available capacity to decide whether ordinary payments are possible.

`ChannelInfo.ffor` and concurrent `/receive/status` requests report `reservedInboundSats` and `unresolvedSlots`. The SSE event `ffor:slot-resolved` carries `channelId`, `epochId`, `k`, `paymentHash`, decimal `amountMsat`, and `outcome` (`fulfilled` or `cancelled`). Refresh status after reconnect because events are not a durable replay log. Use payment records to deduplicate credited Activity. Offline receive does not make ordinary HTLCs safe to leave unattended beyond their deadlines.

## Peer messages

Custom message type 44069, version 1, subtypes 80 (request) and 81 (response), carries bounded UTF-8 JSON. Every request has a random 16-byte hex `id`. Replies must match both that id and the authenticated Lightning peer.

- `quote` returns protocol version, sender fee terms, and funding availability. Negotiated concurrent settlement adds `concurrent: true` and `concurrentVersion: 2`.
- `allocate` takes a stable 16-byte `allocationId` and `amountSats`, and returns a ready `channelId`. Retries refer to the same allocation. A beignet receiver no longer sends this: it falls back to direct funding instead. The provider side is kept for other clients that do.
- `receipts` takes `channelId` and `epochId`. The response echoes both and returns `{k, preimage}` entries only for durably SETTLED slots belonging to the requesting receiver. It does not close or mutate the reservation. UNUSED and SETTLING slots are never disclosed.

Direct receipt discovery requires the settlement peer to return. It does not replace independent FFOR witnesses or provide automatic force-close enforcement against an unavailable or dishonest settlement peer. Those remain separate protocol capabilities. This integration targets fixed-amount invoices supported by the underlying voucher book, not amountless or below-trim payments.

## Verification

The funded portable regression exercises ordinary app Receive, restart before payment, shutdown during payment, automatic reconciliation, a second cold reopen without duplicate Activity, and allocation of another channel while prior funds remain usable. The service tests cover reply authentication, hash verification, epoch changes, withholding unsettled preimages, durable funding caps, and cancellation. The coordinator tests cover unpaid retention, expiry grace, interrupted invoice creation, replacement epochs, and shutdown.

## Daemon API

The daemon now owns the same automatic receive lifecycle for HTTP clients. This
surface ships in 0.21.9 and uses the provider protocol shipped in 0.21.8.
App images can depend on it once 0.21.9 is published to npm.

Both routes take one of two routes, and say which in a `mode` (quote) or `kind`
(invoice) field. `bolt11` is the FFOR lane and needs a channel that already
exists with that peer, is NORMAL and usable, has concurrent settlement negotiated or holds no spendable local money, is
not already reserved, has no live epoch, and has at least `amountSats + 50000`
of inbound. `direct-funding` is the fallback for every other case. Nothing here
opens a channel to obtain inbound liquidity.

- `GET /receive/quote?peer=<compressed-pubkey>&amountSats=<integer>` returns
  `available`, `mode`, `peer`, `amountSats`, `feeSats` and a 60-second
  `expiresAt`. `peer` may be left out (issue #1922): then the ranked primaries
  choose. A `requestId` already under way keeps its own peer; otherwise the
  primaries are tried in the `selectionOrder` that `GET /primaries` reports,
  and the first one that is connected, serves the amount on the route it
  would take, and could be created against (an address is known for its
  relay) is quoted, with the others listed in `skipped` and their
  reasons. The coordinator never dials: a primary that is not connected is
  passed over. The answer's `peer` is what the create binds to. 503
  `NO_PRIMARY_AVAILABLE` names every reason when no primary qualifies, and
  400 `INVALID_PARAMS` answers when none is configured. A named `peer` is
  quoted as before, with no fallback. In `bolt11` mode it also returns the sender fee `terms` read from
  the peer. Pass `requestId` when refreshing an interrupted request to reuse its reserved channel. The minimum is 354 sats (the dust limit). In `direct-funding`
  mode it returns `minAmountSat`, the
  configured direct-funding minimum (5000 sats by default). A funded candidate may first query the peer's concurrent terms before selecting this fallback. An amount under the
  applicable minimum is refused with `AMOUNT_TOO_SMALL` naming it. The peer must
  be connected in either mode, otherwise `RECEIVE_UNAVAILABLE`. In `bolt11`
  mode, a peer that refuses (for example one that does not run the settlement
  role) or does not answer within 15 seconds is also reported as a 409
  `RECEIVE_UNAVAILABLE`, carrying the peer's own message when it gave one, and
  `POST /receive/invoice` answers the same way.
- `POST /receive/invoice` takes `peer`, `amountSats`, `description`, `quote`,
  and a stable `requestId` (16 to 160 letters, digits, underscores or hyphens).
  Use the same id on retries, including after a lost response. `peer` may be
  left out: then the one the reviewed `quote` named is used. The review bound
  it, and create never chooses another, so a changed rank between review and
  create cannot move the request. In `bolt11` mode
  success returns `kind: 'bolt11'`, `bolt11`, `paymentHash`, `amountSats`,
  `expiresAt` and `offlineReceive: true`, plus `concurrent: true` and `concurrentVersion` when selected. The invoice expires after ten minutes.
  In `direct-funding` mode success returns `kind: 'direct-funding'`, `request`
  (the base64url envelope a payer pays, also embeddable in a BIP 21 URI),
  `paymentHash` (the receipt hash), `expiresAt`, `amountSats`, `peer` and
  `offlineReceive: false`. Display either only after success.
- A direct-funding request is bound to the peer it was quoted at (issue
  #1922): the envelope's relay descriptors name that peer, at the address the
  primaries list stores for it, else the policy's address for it, else the
  one this node dialed it at (never the far end of a connection the peer
  opened, whose port is ephemeral), and the receiver negotiates the funding
  with that peer when the offer arrives, whatever `/direct-funding/config` names by
  then. An existing config is left exactly as the operator set it whichever
  peer it names, so `targetInboundSat`, `trusted` and the splice switches
  survive and the node's liquidity relationship is never retargeted behind
  their back. With no config yet, the first such request still configures the
  node for its peer, at the TCP address this node dialed it at when there is
  one, with every other setting at its default: that is the peer a `POST /direct-funding/request`
  naming no peer falls back to when no primaries are configured. A peer with
  no known address refuses with `RECEIVE_UNAVAILABLE`, and a steered quote
  passes such a primary over. Once a config exists, a named `peer` that is
  neither a primary nor the configured peer refuses with `RECEIVE_UNAVAILABLE`
  too: the peer a direct-funded channel opens with holds every payment it
  receives, so it comes from the operator's configuration and nowhere else.
- A direct-funding request is idempotent on `requestId` while it is unexpired:
  the same call returns the same envelope. Once it expires, the same id mints a
  replacement. It reserves nothing, starts no epoch and appears in no
  `reservedChannelIds`.
- `GET /receive/status` returns `available`, `reservedChannelIds` and durable
  `requests`, each carrying its `kind`. Hosts must exclude the reservations from
  automatic channel changes and leave their reconciliation to the daemon.

The GET routes accept readonly credentials. Creation requires admin access
because it reserves liquidity on an existing channel, or configures direct
funding and mints a payable request. There are no CLI wrappers for these
app-oriented routes.

Jobs live in the wallet's encrypted SQLite `wallet_data` table, both kinds in
the same list. A bolt11 job saves its invoice and expiry before returning them;
a direct-funding job saves the minted envelope, its receipt hash and its expiry
before returning them. A job persisted by an older build carries no `kind` and
loads as bolt11. The coordinator polls receipts every two seconds,
resumes after restart and stops with the node. A journal write failure disables
further preparation and reconciliation until restart. An unpaid, unexpired
invoice is never cancelled just because the wallet reopened.

Providers can set `BEIGNET_FFOR_RECEIVE_FUNDING` to the JSON funding policy
shown above (the inner object). Malformed policy refuses startup. The settlement
role must also be enabled. An existing suitable empty channel can be reused
without opting into additional funding.

The Umbrel regression in `scripts/lfbw-regtest/11-automatic-receive.mjs`
exercises this API through its manager with separate funded daemons: idempotent
creation, unpaid restart, payment while stopped, automatic balance credit and
another restart with exactly one paid invoice.
