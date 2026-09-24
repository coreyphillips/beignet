# FFOR receipt witness: unauthenticated provisioning with an unbounded retention_until lets one peer permanently exhaust the witness's mailbox capacity

Labels: bug

Found during a security audit of the FFOR witness service. Reproduced against the real service with `MemoryLedgerStore`: 64 provisions from one peer with `tExp = 2^32-1-144`, `retentionUntil = 2^32-1` are all accepted; an honest receiver's provision answers `cannot reserve`; after `onBlock(2^32-1)` occupancy is unchanged.

## What the code does

`handleProvision` (`src/lightning/ffor/witness-service.ts:389-479`) accepts any peer's manifest after self-consistency checks; the only retention check is `manifest.retentionUntil < tExp + FF_WITNESS_RETENTION_MARGIN_BLOCKS` (refuse). Neither `tExp` nor `retentionUntil` is bounded against the current height. Capacity is `occupancy.mailboxes >= maxMailboxes (64) || reservedBytes + K*1024 > maxBytes (8 MiB)`, released only by `expire()` when `m.retentionUntil < height` (`witness-ledger.ts:260-283`, `witness-service.ts:629-645`). Rows are durable, so a restart changes nothing, and the daemon exposes provision, close and status routes but no operator drop (`src/cli/daemon.ts:2796-2834`).

## Failure scenario

One peer fills all 64 mailboxes (or, with K = 483 books, 17 mailboxes exhaust the byte cap) with retention far in the future. Every receiver relying on this witness, and the co-hosted issuer (which needs a mailbox), is denied for good.

## Suggested fix

Refuse `tExp` and `retentionUntil` beyond `tip + MAX_HTLC_CLTV_EXPIRY_DELTA` plus margin and require `tExp > tip`; add a per-peer mailbox quota; add an operator route to drop or expire a mailbox.
