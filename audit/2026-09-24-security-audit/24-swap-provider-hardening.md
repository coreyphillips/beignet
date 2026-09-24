# Swap provider hardening: hold-invoice CLTV ignores the client's preferred refund delta, unpaid creates count toward the concurrency cap, stranded rows never resolve, and the client helper does not bound the hold invoice's final CLTV

Labels: bug

Found during a security audit of the swap engines. Four low-severity items, none with direct fund loss, all reproduced or traced.

## 1. `preferredRefundDelta` above ~152 is quoted, paid, then refused

The contract's `refundHeight` honours the client's preferred delta (clamped to [72, 288], `src/lightning/swaps/reverse-engine.ts:698`), but the hold invoice's `min_final_cltv_expiry` is computed from the fixed default (`:743-747`, `refundDeltaBlocks + resolutionSafetyBlocks + holdCancelSafetyBlocks + 8`). Admission needs `earliestExpiry - 18 > refundHeight + 24` (`:1096-1110`, `policy.ts:159-167`). With defaults, preferred deltas 144-152 are admitted; 160, 200 and 288 are `REFUSED: Reverse incoming HTLCs must outlive refund resolution and hold cancellation margins` after the client already paid the hold, and the swap is cancelled. A documented protocol feature never works.

Fix: derive the invoice's `minFinalCltvExpiry` from the actual `refundHeight - height`.

## 2. Any peer can exhaust `maxConcurrentSwaps` with unpaid creates

Every non-terminal row, quoted-but-unpaid ones included, counts toward `maxConcurrentSwaps` (default 8; `exposure.ts:123-129`, `ledger.ts:448-450`). The per-peer limit (4 CREATED) is per node id, which is free. Reverse CREATED rows clear after the 1800 s invoice expiry; a submarine CREATED row lives until the client's own invoice expires (`invoiceProblem` bounds expiry only from below). Two throwaway node ids with four one-year-expiry submarine creates each refuse every real user with `EXPOSURE_EXCEEDED` for about a day, repeatable at zero cost.

Fix: exclude CREATED rows from the concurrency cap (or cap them separately with a short TTL) and refuse invoices whose expiry exceeds a provider maximum.

## 3. Rows with nothing on chain can never resolve and leak exposure forever

An `EXPOSED` reverse row whose funding never relayed has a `fundingTxid`, so `processWatched` observes an absent funding and does nothing; a `FUNDED` row whose funding was reorged out and evicted is rebroadcast once and never again (`reverse-engine.ts:1403-1404`, `:1507-1518`, `:1572-1580`). Neither reaches a terminal state; both count in `isSwapExposure` and `unresolved()`. `ledger.forget()` (`ledger.ts:556-561`) exists but is unused, and `/swaps/cancel` only covers CREATED/HELD. Eight such rows and the provider refuses every swap until the database is edited by hand.

Fix: give such rows a terminal path after the refund height plus margin (inputs released or double-spent), and expose a guarded operator forget/resolve route.

## 4. `verifyReverseSwapTerms` does not bound the hold invoice's final CLTV

`src/lightning/swaps/client.ts:190-213` checks network, hash, amount and expiry only. A malicious provider sets `c = 2016`; a wallet using this helper as its only check pays the hold, the provider never funds, and the client's outgoing HTLC is locked for two weeks.

Fix: refuse `minFinalCltvExpiry` above `maxRefundDelta + margin`.
