# Unsolicited reply_channel_range messages are accumulated without bound or state check: a connected peer grows the daemon's heap by ~12x its wire bytes until the process dies

Labels: bug

Found during a security audit of gossip sync. Reproduced with a script: 300 `reply_channel_range` messages (19.7 MB on the wire) added 247 MB to the heap while the sync manager's state stayed IDLE.

## What the code does

`GossipSyncManager.handleReplyChannelRange` (`src/lightning/gossip/gossip-sync.ts:117-127`):

```ts
const scids = decodeShortChannelIds(msg.encodedShortIds);
this._accumulatedScids.push(...scids);
if (!msg.syncComplete) {
    return [];
}
```

It never checks that the manager is in `AWAITING_RANGE_REPLY`, that the reply's `chain_hash` and range match a query we sent, or that the accumulated list has a ceiling. Each 65 KB message decodes into up to 8191 separate 8-byte Buffers. The node routes every `reply_channel_range` to the peer's sync manager whenever one exists (`src/lightning/node/lightning-node.ts:14769-14778`), and `getOrCreateSyncManager` creates one for ANY peer that sends a `query_channel_range` (`:14791-14797`, `:14912-14919`). There is no inbound message rate limit at the transport layer.

## Failure scenario

A peer completes the handshake (no channel needed), sends one `query_channel_range` to obtain a sync manager, then streams `reply_channel_range` with `sync_complete = 0`. A few hundred megabytes of traffic OOM-kills the daemon. A dead node cannot claim inbound HTLCs before their timeouts or react to a breach.

## Suggested fix

Drop `reply_channel_range` unless `_state === AWAITING_RANGE_REPLY` and the reply echoes our query's chain hash and range; cap `_accumulatedScids` (for example 200k entries, deduplicated) and abort the sync when exceeded; discard sync managers for peers that never initiated or received a sync.
