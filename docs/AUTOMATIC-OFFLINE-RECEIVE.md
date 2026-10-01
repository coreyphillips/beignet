# Automatic offline receiving

The wallet integration prepares a one-payment FFOR reservation before displaying a fixed-amount Lightning invoice. Closing the app does not cancel it. On startup and while running, the wallet requests receipts, verifies each preimage against its stored invoice hash, and reconciles a paid reservation into its ordinary balance and Activity. An unpaid invoice stays payable until its expiry. The coordinator allows a two-minute settlement grace period before releasing an expired reservation and never force closes automatically.

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

Automatic offline receiving is only for a channel that ALREADY exists with the peer and whose inbound capacity covers the amount. The wallet reuses suitable empty inbound channels and never reserves a channel containing spendable local money. After receipt reconciliation, that channel becomes available for ordinary payments. This flow never opens a channel to obtain inbound liquidity: when no suitable channel exists, the request falls back to direct funding, where the payer's on-chain payment becomes this node's channel funding and the liquidity peer opens the channel to us. The receiver therefore never sends the `allocate` message described below; the provider side still answers it for other clients.

## Peer messages

Custom message type 44069, version 1, subtypes 80 (request) and 81 (response), carries bounded UTF-8 JSON. Every request has a random 16-byte hex `id`. Replies must match both that id and the authenticated Lightning peer.

- `quote` returns protocol version, sender fee terms, and funding availability.
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
exists with that peer, is NORMAL and usable, holds no spendable local money, is
not already reserved, has no live epoch, and has at least `amountSats + 50000`
of inbound. `direct-funding` is the fallback for every other case. Nothing here
opens a channel to obtain inbound liquidity.

- `GET /receive/quote?peer=<compressed-pubkey>&amountSats=<integer>` returns
  `available`, `mode`, `peer`, `amountSats`, `feeSats` and a 60-second
  `expiresAt`. In `bolt11` mode it also returns the sender fee `terms` read from
  the peer, and the minimum is 354 sats (the dust limit). In `direct-funding`
  mode it does not contact the peer at all, and returns `minAmountSat`, the
  configured direct-funding minimum (5000 sats by default). An amount under the
  applicable minimum is refused with `AMOUNT_TOO_SMALL` naming it. The peer must
  be connected in either mode, otherwise `RECEIVE_UNAVAILABLE`. In `bolt11`
  mode, a peer that refuses (for example one that does not run the settlement
  role) or does not answer within 15 seconds is also reported as a 409
  `RECEIVE_UNAVAILABLE`, carrying the peer's own message when it gave one, and
  `POST /receive/invoice` answers the same way.
- `POST /receive/invoice` takes `peer`, `amountSats`, `description`, `quote`,
  and a stable `requestId` (16 to 160 letters, digits, underscores or hyphens).
  Use the same id on retries, including after a lost response. In `bolt11` mode
  success returns `kind: 'bolt11'`, `bolt11`, `paymentHash`, `amountSats`,
  `expiresAt` and `offlineReceive: true`. The invoice expires after ten minutes.
  In `direct-funding` mode success returns `kind: 'direct-funding'`, `request`
  (the base64url envelope a payer pays, also embeddable in a BIP 21 URI),
  `paymentHash` (the receipt hash), `expiresAt`, `amountSats`, `peer` and
  `offlineReceive: false`. Display either only after success.
- Direct funding is negotiated with ONE liquidity peer. With no
  `/direct-funding/config` yet, the first such request configures the node for
  this peer using the host and port it is connected on and leaves every other
  setting at its default. An existing config naming the SAME peer is reused
  untouched, so an operator's `targetInboundSat`, `trusted` and splice switches
  survive. An existing config naming a DIFFERENT peer refuses with
  `RECEIVE_UNAVAILABLE` rather than retargeting the node silently.
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
