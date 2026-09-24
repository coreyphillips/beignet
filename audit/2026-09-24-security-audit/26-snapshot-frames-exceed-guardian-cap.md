# Recovery snapshot frames are unbounded and never checked against the guardian's ciphertext cap: once a snapshot exceeds it, replication wedges permanently, and in quorum mode every safety-critical batch is refused forever

Labels: bug

Found during a security audit of the Recovery Protocol. Sizes measured with a script that builds snapshots from populated storage:

```
probe snapshot bytes (1 channel): 5860
snapshot with 10000 forwarding events: 3055628 bytes
snapshot with 20000 forwarding events: 6105628 bytes
snapshot with 100000 forwarding events: 30505628 bytes
snapshot with 10k payments: 2515609 bytes
```

## What the code does

- `captureSnapshot` (`src/lightning/recovery/journal.ts:1657`) embeds the whole forwarding-events ledger (retained up to `forwardingEventsMaxRows = 100_000`, `sqlite-storage.ts:172`), every payment, invoice, chain monitor and outbox row. A snapshot is written every 256 frames or 4 MiB of deltas AND on every process restart (re-base). `writeFrame` (`:1320`) has no size bound and the writer never consults `info().maxCiphertextBytes` (only the capsule composer bounds its own size).
- The guardian refuses `ciphertext.length > maxCiphertextBytes` with `ERR_TOO_LARGE` (`guardian.ts:1208`); the host default is 4 MiB (`guardian-host.ts:75`) and the protocol hard cap is 16 MiB (`guardian.ts:343`).
- A guardian accepts only `logHead.sequence + 1`, so once it refuses snapshot S it refuses every later record with `ERR_SEQUENCE_GAP`. In `streamToGuardian` (`guardian-replication.ts:1030-1108`) an `ERR_TOO_LARGE` answer carries no receipt and no `current`, so the pass ends with no progress and no distinct error (the replication code never mentions `ERR_TOO_LARGE` at all).

## Failure scenario

A wallet that has routed about 15k forwards (or sent about 10k payments) writes its next snapshot; every guardian answers `ERR_TOO_LARGE`; the watermark never advances again.

- Quorum mode: every safety-critical batch parks and is refused after 30 s (`transition:frozen`); the node disconnects and reconnects in a loop and can never again send `revoke_and_ack`, `update_fulfill_htlc` or `commitment_signed` on ANY channel. Incoming HTLCs can only be claimed by force-closing at the deadline. Above 16 MiB no configuration can fix it.
- Async-remote mode: replication silently stops (only an `under-replicated` event). A later device-loss restore lands at the last replicated head, so every later channel update is unrecoverable and all channels end in a data-loss close.

## Suggested fix

Bound snapshot content: drop the forwarding ledger and settled payments from snapshots, or page them into separate frames; check the encoded size against the advertised `maxCiphertextBytes` before writing and degrade loudly the way `composeRecoveryCapsule` does; in the replicator, surface `ERR_TOO_LARGE` as a distinct `node:error`.
