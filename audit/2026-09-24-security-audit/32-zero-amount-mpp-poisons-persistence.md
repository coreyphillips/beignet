# Paying a zero-amount invoice through the MPP fallback underpays the payee and then poisons every later channel-state persist in the process

Labels: bug

Found during a security audit of the payment pipeline. Reproduced for the serializer and the wire encoding:

```
serializePaymentInfo throws: Cannot read properties of undefined (reading 'toString')
part amt_to_forward: 40000000 total_msat on wire: 40000000
```

## What the code does

`sendPayment` resolves a zero-amount invoice's amount from the caller (`paymentAmountMsat = amountMsat`), but when the single-path route is unavailable (no route, or `firstHopChannel.getSpendableOutboundMsat() < route.totalAmountMsat`, a routine case for a two-channel wallet) it falls back to `sendPaymentMpp(invoiceStr, invoice, multiRoute, ...)` (`src/lightning/node/lightning-node.ts:15708`), which does (`:16473`):

```ts
const totalMsat = invoice.amountMsat!;
```

`undefined` for a zero-amount invoice. That value becomes `payment.amountMsat`, `mppState.totalMsat` and every part's `payload.totalMsat`. The onion encoder then falls back to `encodeTruncatedUint(payload.totalMsat ?? payload.amountToForwardMsat)` (`src/lightning/onion/hop-payload.ts:86`), so each part carries `total_msat == amt_to_forward`. `serializePaymentInfo` does `bigintToStr(p.amountMsat)` (`src/lightning/storage/serialization.ts:1474`) and throws on `undefined`.

## Failure scenario

1. A user pays a zero-amount, MPP-capable invoice (LND and CLN default) for 100k sats with two 60k-sat channels; the single route fails the spendable check; the payment is split into two 50k parts.
2. `commitMutations('persist mpp payment')` fails (the serializer throws inside the transaction; `RecoveryManager.commit` catches and returns `committed: false`), and the dispatch continues unpersisted.
3. The recipient sees part 1 as a standalone 50k payment for an any-amount invoice (LND behaves the same) and settles it; part 2 is refused as "payment already completed". The payee is underpaid by 50k while the payer's record flips to COMPLETED in `handleHtlcFulfilled`, so the payer's app reports a successful full payment.
4. `handleHtlcFulfilled` stages `{ type: 'payment_state', payment }` (the unserializable record) onto the channel transition (`:21912`). `persistChannelState` takes the stage, the commit throws, and on failure the code re-queues the staged mutations (`:3641`, `this.stagedMutations.unshift(...staged)`); `flushStagedMutations` (`:3765-3781`) re-stages on failure too. The poisoned mutation therefore rides EVERY later `persistChannelState` for EVERY channel and makes every commit throw. No channel state, including revocation secrets received from peers, is persisted for the rest of the process. On restart all channels come back stale: an honest peer triggers data-loss handling, and a malicious peer can broadcast a revoked commitment whose secret was never written, which we cannot punish.
5. The daemon's `payment:sent` listener does `Number(p.amountMsat / 1000n)` (`src/cli/beignet-node.ts:11078`) and throws on the mixed types; `peer.ts` treats a throwing message listener as a peer error and disconnects the peer.

## Suggested fix

Pass the resolved `paymentAmountMsat` (or `multiRoute.totalAmountMsat`) into `sendPaymentMpp` instead of `invoice.amountMsat!`, and validate that `amountMsat` is a bigint before building the record. Separately, make a mutation that fails to serialize non-poisoning: on a serializer error, drop or quarantine that mutation and report it, rather than re-staging it forever.
