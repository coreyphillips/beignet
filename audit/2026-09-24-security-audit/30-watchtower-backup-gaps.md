# Watchtower backups skip revoked commitment #0 and every revocation that straddles a restart, leaving states the tower cannot punish

Labels: bug

Found during a security audit of the watchtower client.

## What the code does

The justice blob for a revoked remote commitment is built from a transaction cached at `signCommitment` time (`src/lightning/channel/channel.ts:4237-4266`, `_cacheRemoteCommitmentForWatchtower`, only called from `signCommitment` at `:4369`), keyed by the per-commitment point in an in-memory `Map` of at most 8 entries (`:1030-1031`). The cache is a private field that is never serialized (no reference in `storage/serialization.ts` or `channel-state.ts`). On `revoke_and_ack`, `takeRevokedCommitmentTx` (`:4271-4278`) returns null on a miss and the manager silently skips the backup (`src/lightning/channel/channel-manager.ts:4336-4343`, `if (revokedTx && revChannelId) emit('watchtower:backup')`). There is no catch-up on restart. The initial commitment (signed in the funding_created / funding_signed flow and the v2 equivalents) is never cached; `tests/lightning/watchtower.test.ts:578-581` documents that gap ("never signed via signCommitment, so never cached").

## Failure scenario

1. A peer opens an inbound channel to us; its commitment #0 pays it the full funding amount. After we receive payments, #0 is the most profitable state for it to breach with, and the tower never received a blob for it. If we are offline when it is broadcast, the breach succeeds.
2. We send `commitment_signed`, the daemon restarts (cache gone; reestablish retransmits from `lastSentCommitmentSigned` without re-running `signCommitment`), the peer's `revoke_and_ack` arrives, `takeRevokedCommitmentTx` returns null, and that revoked state is unprotected forever.

The tower's only purpose is to punish breaches while we are offline; both gaps leave revoked states it cannot punish.

## Suggested fix

Cache the initial remote commitment when it is signed; persist the pending-remote-commitment cache with channel state (or rebuild the revoked transaction from `revokedHtlcSnapshots` and the recorded balances at revoke time); on restart, back up any revoked state whose blob was never acknowledged by the tower.
