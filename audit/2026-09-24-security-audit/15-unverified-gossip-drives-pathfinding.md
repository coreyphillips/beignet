# Pathfinding routes over channel_updates and announcements whose signatures were never verified (lazy gossip mode, the default): any connected peer can rewrite the policy of any channel in our graph

Labels: bug

Found during a security audit of gossip handling. This is a consequence of the verify-on-serve design from #443 and the admission hardening of #446 that those issues do not appear to have weighed: deferred verification is fine for what we SERVE, but the router CONSUMES the deferred rows as if they were real.

## What the code does

- `eagerGossipVerify` defaults to `false` (`src/lightning/node/lightning-node.ts:1574`).
- `handleChannelUpdate` (`:15104-15150`) skips `verifyChannelUpdate` unless eager mode is on or the update names one of our own channels, and stores the row with `verified: 'deferred'`. `handleChannelAnnouncement` (`:14941-14980`) admits an announcement with no signature check and no funding-output check.
- `NetworkGraph.applyChannelUpdate` (`src/lightning/gossip/network-graph.ts:371-431`) lets a newer timestamp replace a slot even when the existing slot was verified; timestamps up to one hour in the future are accepted.
- `findRoute` reads `update1`/`update2` with no `*Verified` filter (`src/lightning/gossip/pathfinding.ts:494`, `:841`). Rows are persisted through `saveGossipChannel`, so forged rows survive restarts.

## Failure scenario

Peer P (any node we accept gossip from) sends unsigned `channel_update`s with `timestamp = now + 3599` for every channel adjacent to our usual destinations except its own, either with the disable bit set or with `fee_base_msat = 2^32 - 1`. Dijkstra now prefers P (fee extraction, privacy loss), or pays honest hops the forged inflated fee (they keep the excess; bounded only by the payer's fee cap, which has its own gaps in the companion issues), or finds no route at all. Real, signed updates with lower timestamps are refused as "not strictly newer" for up to an hour, and P re-forges hourly. Fake `channel_announcement`s with random signatures fill the graph to `MAX_CHANNELS = 100_000` and are persisted.

## Suggested fix

Verify a `channel_update`'s signature before it can displace a slot that pathfinding reads (one ECDSA per update for channels we already hold is cheap with the node:crypto fast path), or exclude `deferred` rows from routing until they are verified; rate-limit unverified admissions per peer; add a UTXO and amount check (or at least signature verification) before an announcement is persisted.
