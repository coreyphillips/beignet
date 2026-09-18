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

These are cumulative allocation limits, persisted before initiating funding. A failed or interrupted opening retains its allocation rather than risking a second spend on retry. Operators must budget for the funding transactions and channel liquidity. New channels contain the invoice amount plus 50,000 sats of headroom, use a 2 sat/vbyte funding rate, and grant zero-confirmation permission only for the provider's own outgoing funding. They never add a receiving peer to the inbound trust list.

The wallet reuses suitable empty inbound channels. It never reserves a channel containing spendable local money. After receipt reconciliation, that channel becomes available for ordinary payments. Subsequent requests can need another channel until a suitable empty channel becomes available. Channel allocation limits do not reset automatically.

## Peer messages

Custom message type 44069, version 1, subtypes 80 (request) and 81 (response), carries bounded UTF-8 JSON. Every request has a random 16-byte hex `id`. Replies must match both that id and the authenticated Lightning peer.

- `quote` returns protocol version, sender fee terms, and funding availability.
- `allocate` takes a stable 16-byte `allocationId` and `amountSats`, and returns a ready `channelId`. Retries refer to the same allocation.
- `receipts` takes `channelId` and `epochId`. The response echoes both and returns `{k, preimage}` entries only for durably SETTLED slots belonging to the requesting receiver. It does not close or mutate the reservation. UNUSED and SETTLING slots are never disclosed.

Direct receipt discovery requires the settlement peer to return. It does not replace independent FFOR witnesses or provide automatic force-close enforcement against an unavailable or dishonest settlement peer. Those remain separate protocol capabilities. This integration targets fixed-amount invoices supported by the underlying voucher book, not amountless or below-trim payments.

## Verification

The funded portable regression exercises ordinary app Receive, restart before payment, shutdown during payment, automatic reconciliation, a second cold reopen without duplicate Activity, and allocation of another channel while prior funds remain usable. The service tests cover reply authentication, hash verification, epoch changes, withholding unsettled preimages, durable funding caps, and cancellation. The coordinator tests cover unpaid retention, expiry grace, interrupted invoice creation, replacement epochs, and shutdown.

## Daemon API

The daemon now owns the same automatic receive lifecycle for HTTP clients. This
surface ships in 0.21.9 and uses the provider protocol shipped in 0.21.8.
App images can depend on it once 0.21.9 is published to npm.

- `GET /receive/quote?peer=<compressed-pubkey>&amountSats=<integer>` returns
  sender fee terms with a 60-second expiry. The minimum is 354 sats.
- `POST /receive/invoice` takes `peer`, `amountSats`, `description`, `quote`,
  and a stable `requestId` (16 to 160 letters, digits, underscores or hyphens).
  Use the same id on retries, including after a lost response. Success returns
  `bolt11`, `paymentHash`, `amountSats`, `expiresAt` and `offlineReceive: true`.
  The invoice expires after ten minutes. Display it only after success.
- `GET /receive/status` returns `available`, `reservedChannelIds` and durable
  `requests`. Hosts must exclude these reservations from automatic channel
  changes and leave their reconciliation to the daemon.

The GET routes accept readonly credentials. Creation requires admin access
because it can allocate a channel and reserve liquidity. There are no CLI
wrappers for these app-oriented routes.

Jobs live in the wallet's encrypted SQLite `wallet_data` table. Allocation
identity is saved before requesting funding, and the invoice and expiry are
saved before returning it. The coordinator polls receipts every two seconds,
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
