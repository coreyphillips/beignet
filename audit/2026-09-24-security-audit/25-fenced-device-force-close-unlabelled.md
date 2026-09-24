# A fenced (superseded) device admits the operator's force close with no acknowledgement, and the commitment it publishes is normally already revoked by the successor device

Labels: bug

Found during a security audit of the Recovery Protocol.

## What the code does

The recovery fence (startup gate `fenced`, or `_barrierFenced`) denies peer traffic and AUTOMATIC closes only. `_forceCloseWithReason` (`src/lightning/node/lightning-node.ts:11754`) explicitly exempts the operator:

```ts
if (reason !== 'user' && this.skipAutoCloseRecoveryGated(channelId, reason)) { ... }
```

The daemon's `requireForceCloseAcknowledgement` (`src/cli/beignet-node.ts:7978`) checks only the three recency-hold flags (`restoreRecencyUnproven`, `reestablishRecencyUnproven`, `reestablishSecretMissing`), which are set by the restore and reestablish paths (`channel.ts:9017`, `:10116`) and never by fencing; `hardFreezeTransports` only disconnects. `Channel.prepareForceClose` checks only `mustNotBroadcastCommitment`, also untouched by a fence. `durability-barrier.ts:273` records the intent: "Closing is deliberately left working, in both forms: it is the only exit an operator has." So on a fenced node, `POST /channel/forceclose {channelId}` with no `acceptStaleStateRisk` builds and broadcasts the stored local commitment; the only fenced-side message is the log line "this device must not send another channel message" (`beignet-node.ts:3386`). `docs/RECOVERY-PROTOCOL.md` section 5.6 describes the fenced node's exit as the labelled escape hatch; here it is unlabelled.

## Failure scenario

Quorum mode. Phone A is lost. Phone B restores through `RestoreDriver`, the wire-safety proof holds, channels RESUME (no `stateUncertain`), and B transacts for days: every commitment update revokes the commitment A still stores. A is found and booted: the startup gate (or the barrier recheck) fences it and it shows frozen channels. The operator runs `channel forceclose <id>` on A, the documented "only exit a fenced node has". A broadcasts a commitment B already revoked; the peer's justice path takes the entire channel balance. The same path is open on a QUARANTINED node (guardians unreachable), where supersession is merely unproven.

## Suggested fix

In `forceCloseChannel` / `_forceCloseWithReason`, when the gate is `fenced` or `_barrierFenced` (and arguably `quarantined`), refuse without `acceptStaleStateRisk: true`, with wording that names the takeover. Better: on fence latch, stamp every open channel with a hold flag so the existing acknowledgement machinery, `/recovery/status` and the cooperative-close refusal all fire, and prefer the peer-initiated close (channel_reestablish with data-loss protection) over broadcasting our own commitment.
