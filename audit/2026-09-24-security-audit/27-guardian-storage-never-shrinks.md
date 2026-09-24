# Guardian storage never shrinks and the per-set byte quota is a shared hard stop that ordinary use reaches, after which every write in the set is refused

Labels: bug

Found during a security audit of the Recovery Protocol. Companion of the snapshot-size issue; the two share the failure mode (replication stops, quorum mode freezes the node).

## What the code does

The writer compacts deltas below each snapshot locally, but guardians keep every record ever accepted (there is no prune path in `guardian.ts`, only rollback and open-time archiving; they cannot tell a snapshot from a delta), and `SYNC_EPOCH` truncations are counted in the orphan archive against the same quota ("Quotas refuse, never delete"). The quota is per SET and shared by all namespaces in it (`guardian-host.ts:76`, `:193`, `:506`: 256 MiB), judged in `quotaGate` / `chargeOrRollBack` (`guardian.ts:1529-1567`). An `ERR_QUOTA_EXCEEDED` answer carries no receipt and no progress in `streamToGuardian` (`guardian-replication.ts:1030-1108`).

Measured probe frames are about 6 KB per delta plus a full snapshot per restart and per 256 frames; the default is exhausted after roughly 40k transitions (about 10k payments) shared across the three namespaces of a mutually-guarding trio, sooner as snapshots grow (a 3 MB snapshot times 85 restarts fills it).

## Failure scenario

The set crosses the quota; every `PUT_STATE` answers `ERR_QUOTA_EXCEEDED`. Quorum mode: the same node-wide freeze as the snapshot issue (all channels end force-closed at HTLC deadlines). Async-remote: replication stops. The only exits are the guardian operators raising `BEIGNET_GUARDIAN_MAX_BYTES` or a set rotation, whose own defects are tracked in #862, #937 and #938.

## Suggested fix

Let the writer declare snapshot positions (a flag on `PUT_STATE`) so a guardian can archive and free records below a receipted snapshot once the writer's retain floor has passed it; make the quota per namespace; raise a `guardian:quota-refused` event and a node-side alarm well before exhaustion.
