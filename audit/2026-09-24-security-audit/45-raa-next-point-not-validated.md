# revoke_and_ack.next_per_commitment_point is stored and persisted without curve validation, so every later signing attempt throws and the channel is wedged for good

Labels: bug

Found during a security audit of the channel state machine. Reproduced against `Channel`:

```
decoder accepted invalid point: true
handleRevokeAndAck actions: [ 'PERSIST_STATE' ]
stored remoteNextPerCommitmentPoint === invalid point: true
buildRemoteCommitment THROWS: Expected Point
```

## What the code does

`decodeRevokeAndAckMessage` takes the 33 bytes as-is (`src/lightning/message/channel-commitment.ts:212`). `handleRevokeAndAck` verifies the revealed secret against the current point but stores `next_per_commitment_point` unchecked (`src/lightning/channel/channel.ts:5002`, `this._state.remoteNextPerCommitmentPoint = msg.nextPerCommitmentPoint;`) and persists it (`:5148`). Only `channel_ready`'s point is validated (`:2848`). The next `autoSignAndSendCommitment` (`channel-manager.ts:1863`) reaches `deriveRevocationPubkey` (`src/lightning/keys/derivation.ts:95`, `pointMultiply(perCommitmentPoint, tweakB)`) through `buildRemoteCommitment` and throws `Expected Point`.

## Failure scenario

A peer answers one of our `commitment_signed` with a valid secret and an off-curve next point. From then on every signing attempt throws: inside `handleMessage` the throw is swallowed by the generic catch (`channel-manager.ts:3762`, a local `error` emit, no wire error, channel stays NORMAL); from the manager's `addHtlc` / `fulfillHtlc` / `failHtlc` / `updateFee` wrappers it propagates into node callers that do not catch (`lightning-node.ts:17202`, `:20781`). Because the point is persisted the wedge survives restart and reconnect (only another `revoke_and_ack` replaces it, which needs a `commitment_signed` we can no longer produce). Any inbound HTLC we fulfil has its preimage on the wire (`update_fulfill_htlc` is sent before the sign attempt) while the removal can never be committed, so every settlement ends in a force close. The peer can wedge every channel it has with us at zero cost.

## Suggested fix

`if (!isValidPublicKey(msg.nextPerCommitmentPoint)) return this._failChannelWithWireError(...)` before the store, and refuse a point equal to the current one. Apply the same check to `channel_reestablish.my_current_per_commitment_point` before it is stored as `dlpRemotePerCommitmentPoint` (`channel.ts:10160`).
