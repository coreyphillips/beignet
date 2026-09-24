# A restore racing a still-live writer with one guardian down deadlocks both devices until the third guardian returns

Labels: bug

Found during a security audit of the Recovery Protocol. Liveness only (the operator force close remains the exit, with the caveats of the fenced-device issue); traced through every branch, not executed.

## What the code does

- `acquireEpoch` (`src/lightning/recovery/restore-driver.ts:852-1020`) keeps a pending attempt verbatim while `acceptedSomewhere`; `repairLaggards` (`:727-784`) uses `SYNC_RECORD`.
- The guardian refuses `SYNC_RECORD` with `ERR_EPOCH_SUPERSEDED` when the record epoch differs from the lease epoch (`guardian.ts:1260-1275`).
- `resolveSupersession` (`guardian-replication.ts:1302-1355`) fences the live writer on ONE signed higher-epoch state.

## Failure scenario

A (epoch 42) commits frame N+1 while B restores; G3 is down. G1 accepts N+1 before B's `ACQUIRE(expected=N)` arrives (the CAS fails there); G2 accepts B's `ACQUIRE` first (lease 43, head N) and then refuses A's N+1 as fenced. A: `confirmOwnership` sees G2's signed epoch-43 state and is permanently fenced. B: `selectHead` adopts G1's (42, N+1); `repairLaggards` cannot bring G2 to N+1 (a `SYNC_RECORD` of an epoch-42 record is refused by a lease-43 guardian); the pending attempt is never abandoned (`certificates.length > 0`); G1 keeps failing the CAS until `cas-exhausted`. Neither device can write; both sit until G3 returns.

## Suggested fix

On retry, when the pending attempt's guard is stale and the same writer key already holds the epoch at some guardian, re-issue `ACQUIRE` with the same key against the new head and let `SYNC_EPOCH` accept a matching-key bundle whose superseded heads differ only by the minority tail; or abandon and re-target when the accepting guardians are provably a minority.
