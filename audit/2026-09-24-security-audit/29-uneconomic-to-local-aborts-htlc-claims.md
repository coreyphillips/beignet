# An uneconomic to_local output on OUR force-closed commitment throws out of the output resolver, so no HTLC-success or HTLC-timeout is ever built: an inbound HTLC whose preimage we hold is lost to the peer's timeout

Labels: bug

Found during a security audit of the chain layer. Reproduced with a script against `resolveOurCommitmentOutputs`:

```
our commitment outputs: [ 774, 100000, 849000 ]
tracked: [ 'TO_LOCAL=774', 'RECEIVED_HTLC=100000', 'TO_REMOTE=849000' ]
feeRate 2 sat/vB -> resolved [ 'TO_LOCAL:spend', 'RECEIVED_HTLC:spend', 'TO_REMOTE:none' ]
feeRate 10 sat/vB -> THREW: Fee exceeds available value for to_local sweep (no HTLC-success built for the 100000 sat inbound HTLC)
second-level (1000 sat output, 10 sat/vB) THREW: Fee exceeds available value for second-level sweep
```

## What the code does

The legacy `TO_LOCAL` branch of `resolveOurCommitmentOutputs` (`src/lightning/chain/output-resolver.ts:1717-1745`) computes `feeSatoshis = ceil(feeRatePerVbyte * 113)` and calls `buildToLocalSweepTx` directly, which throws `Fee exceeds available value for to_local sweep` when `amount - feeSatoshis <= 0` (`src/lightning/chain/sweep.ts:89-92`). Every sibling path (taproot to_local, their-commitment to_remote and HTLC claims, revoked to_remote, penalty batches) was retrofitted with a `sweepOutputValue()` guard and `declinedAsUneconomic` (`output-resolver.ts:1960`, `:2131`, `:2339`, `:2390`, ...); this branch was not, and neither was the legacy branch of `resolveSecondLevelHtlcOutput` (`:2032`).

The resolver builds every output before `_handleOurCommitment` (`src/lightning/chain/chain-monitor.ts:2185-2216`) schedules any, so the throw escapes before any HTLC-success or HTLC-timeout exists. `channel-manager.ts:3084` has no try/catch, and the watcher only logs (`chain-watcher.ts:2357`, `checkFundingSpent(...).catch(emitError)`). `_state` is already RESOLVING and `_commitmentBroadcast` is set, so later re-reports of the same funding spend go to `_reconcileRecordedSpend` (no re-resolution), and none of the retry paths (`_retryUnsweptRevokedSweeps`, `_retryUnsweptPeerCommitmentClaims`, `updateFeeRate`, `_rebuildHeldSweeps`) cover `OUR_COMMITMENT`. The manager's `monitor:updated` emit at `:3151` is skipped too, so nothing is persisted.

## Failure scenario

We are the opener with a 1000-sat local balance (a 774-sat to_local after the commitment fee, above the 354-sat dust limit) and a 100,000-sat inbound HTLC whose preimage we hold. The node force-closes, which is exactly what `scanExpiringHtlcs` does 18 blocks before expiry. At the watcher's default sweep feerate of 10 sat/vB (`chain-watcher.ts:2362`; the threshold is to_local below `ceil(rate * 113)`: 2260 sat at 20 sat/vB, 5650 sat at 50 sat/vB) the resolver throws, the error is logged, the 100k-sat HTLC-success is never built or broadcast, and at `cltv_expiry` the peer's HTLC-timeout takes the 100k sats. Offered HTLCs on the same commitment never get their HTLC-timeout either, so their value is stranded and the upstream fail is never issued, which cascades into an upstream force close. The second-level sibling drops that `handleOutputSpent` call's other actions (`WATCH_OUTPUT`, `PREIMAGE_LEARNED` for the same tx), so the CSV output is never tracked.

## Suggested fix

Guard the legacy `TO_LOCAL` branch and the legacy branch of `resolveSecondLevelHtlcOutput` with `sweepOutputValue()` and push `{ trackedOutput, declinedAsUneconomic: true }` like the sibling paths; wrap per-output resolution in `_handleOurCommitment` / `handleOutputSpent` so one output cannot abort the rest; add an `OUR_COMMITMENT` retry in `handleNewBlock` / `updateFeeRate` so a declined output is retried when fees fall.
