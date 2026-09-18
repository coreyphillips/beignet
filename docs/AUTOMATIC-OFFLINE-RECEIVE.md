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
