# An MPP part on a channel that disconnected between parts is never fulfilled after reconnect, ending in a needless force close

Labels: bug

Found during a security audit of the receive pipeline. Traced through callers and callees; not executed (no existing test covers a disconnect between parts).

## What the code does

When a set completes, `handleMppPart` (`src/lightning/node/lightning-node.ts:20776-20783`) does:

```ts
for (const p of pending.receivedParts) {
    p.status = PaymentStatus.COMPLETED;
    this.channelManager.fulfillHtlc(p.channelId, p.htlcId, preimage);
}
this.pendingMppPayments.delete(hashHex);
```

ignoring each `ChannelResult`, then marks the payment COMPLETED with `settledHtlcs` listing every part. `Channel.fulfillHtlc` returns an ERROR action (manager result `ok: false`) when the channel is `AWAITING_REESTABLISH` (`src/lightning/channel/channel.ts:3628-3640`, `:13514-13520`). The only re-drive of a committed, unsettled received HTLC is `redispatchUnresolvedReceivedHtlcs`, wired to `channel:restore-ready` (`:4072-4076`), which fires once per channel restored from persistence and never for a channel that stayed live. The `channel:reestablished` handler (`:4102-4120`) re-drives forwards, held forwards and hold-invoice resolutions, but not plain received HTLCs of a completed payment.

## Failure scenario

A payer sends part 1 over peer A and part 2 over peer B within the 60 s MPP window. Peer A disconnects after part 1 is irrevocably committed (channel A goes `AWAITING_REESTABLISH`). Part 2 completes the set: part 2 is fulfilled, part 1's fulfill is refused and silently dropped, the payment is recorded COMPLETED (invoice settled, `payment:received` emitted, goods delivered). Peer A reconnects minutes later: nothing fulfills HTLC 1; it stays COMMITTED with the preimage known until the inbound claim backstop in `scanExpiringHtlcs` (`:25851`) force-closes channel A `claimBuffer` blocks before expiry to claim it on chain. An avoidable unilateral close (fees, a lost channel) on every such reconnect race, and the payer's node counts the HTLC as in flight for days.

## Suggested fix

Check the result of each `fulfillHtlc` and keep refused parts (as `advanceHeldResolution` does for hold invoices); on `channel:reestablished`, fulfill any COMMITTED received HTLC whose hash has a COMPLETED incoming payment listing it in `settledHtlcs` (the same predicate the restart redispatch already trusts).
