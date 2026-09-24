# Reverse swap provider: a funding transaction that never relayed is still handed to the client by SWAP_STATUS after the hold invoice was cancelled, and retried broadcasts never re-judge the margins, so the client can claim the on-chain funds with nothing paid

Labels: bug

Found during a security audit of the swap engines. Both paths below were reproduced on the real `ReverseSwapEngine` with the project's test harness (`swaps.test.ts` shape): final state `EXPOSED`, preimage recorded, hold settled 0, funding bytes served by status.

## What the code does

- `processFunding` sets `fundingBroadcastAttemptedAt` and calls `broadcast()`. If the broadcast throws and the funding is not seen on chain, the row stays `FUNDING` and every later pass skips the "judge the hold again, live" block because the marker is already set (`src/lightning/swaps/reverse-engine.ts:1313-1348`, `if (!current.fundingBroadcastAttemptedAt) { ... admissionProblem ... }`), then rebroadcasts the same bytes (never fee-bumped).
- `handleStatus` returns the signed funding bytes whenever `fundingBroadcastAttemptedAt !== undefined` (`:834-839`), with no check of the row's state or whether the hold still exists:
  ```ts
  const fundingTx = record.fundingTxHex && record.fundingBroadcastAttemptedAt !== undefined && ... ? Buffer.from(record.fundingTxHex, 'hex') : undefined;
  ```
- When the held-invoice sweeper (or `POST /invoice/cancel-hold`, which has no swap awareness, `src/cli/daemon.ts:1980-1985`) cancels the hold, `onHoldCancelled` moves the `FUNDING` row to `EXPOSED` and keeps the bytes (`:915-937`, "one that threw may still have propagated: treat the bytes as out"). `EXPOSED` rows are watched but never rebroadcast, and their inputs stay pledged (`:1408-1414`, `:1507-1518`), which is exactly what keeps the signed transaction valid indefinitely.

## Failure scenarios

1. Create, client pays the hold invoice, funding is built, every broadcast is refused (mempool minimum fee above the funding's rate, chained-unconfirmed rejection, or a misbehaving backend). The sweeper cancels the hold at `cancelHeight` and the client's Lightning payment is failed back. The row is `EXPOSED`. The client sends `SWAP_STATUS_REQUEST`, receives the signed funding bytes, broadcasts them itself when fees drop, and claims with the preimage it owns. The provider is out `onchainSat`; the bytes stay valid while the inputs are pledged, and status keeps answering forever because the row is non-terminal.
2. Broadcasts fail until well past the refund height and then succeed in the same block the sweeper cancels the hold (the engine's block pass runs before the held sweeper, `src/lightning/node/lightning-node.ts:25318-25340`). The row goes `FUNDING_BROADCAST` -> `EXPOSED` with the coins in the mempool; an honest client's ordinary claim logic takes them. A fresh `validateReverseSwapAdmission` at that height would have refused (`refundHeight <= currentHeight + fundingSafetyBlocks`), but the retry never runs it.

The precondition is a funding that fails to relay for roughly the whole hold window (150+ blocks with defaults). The funding is never rebuilt at a higher fee and the daemon does not expose the 200 sat/vB clamp, so a prolonged fee spike or a backend outage is enough, and once it happens the loss is deterministic.

## Suggested fix

- In `handleStatus`, hand out `fundingTx` only while the hold is still open (never for `EXPOSED` rows or once `holdCancelledAt` is set), or once the chain shows the funding.
- On every retry whose funding is not seen on chain, re-run the live admission judgement; on refusal stop broadcasting and keep watching.
- On `FUNDING -> EXPOSED` with no funding seen, prefer a conflicting spend of the inputs back to the wallet over keeping them pledged.
