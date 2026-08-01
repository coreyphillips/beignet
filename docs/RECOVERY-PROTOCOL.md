# Feature request: Beignet Recovery Protocol

Replicated, cryptographically versioned state continuity for Lightning channels, with channel-preserving restore and split-brain fencing.

Status: Phases 1 to 3 implemented (safety transition layer + durable outbox, PR #273; hash-chained journal with snapshots, compaction and deterministic reconstruction, PR #278; Recovery Capsule over peer_storage with validated multi-candidate restore, PR #279); Phases 4 to 7 not started
Revision 2 (2026-07-23): epoch acquisition is now a compare-and-swap takeover and restoration fences before reconstructing; reestablish is described as a consistency gate, not a proof of exact recovery; uncertain recovery states may never broadcast the stored local commitment
Revision 3 (2026-07-27): applied an external design review of revision 2. Guardians gain explicit durability obligations and the backfill verbs SYNC_RECORD and SYNC_EPOCH; restoration gains a head reconciliation algorithm over a read quorum with stale-guardian repair (5.7); the node-wide journal ordering question is decided with pipelined appends and cumulative receipts (5.3); ephemeral signing sessions get a nonce-reuse invariant and a four-way disposition classification (5.10); Phase 4 gains an exact wire specification deliverable and a written comparison against LDK's Versioned Storage Service; a prior art and standardization path section was added (12)
Revision 4 (2026-08-01): the Phase 4 gating deliverables. The guardian transport is decided and recorded (12.1): HTTP/protobuf over v3 onion services and HTTPS/protobuf over clearnet are both first-class normative transports, and BOLT 8 custom messages are not the v1 transport; the exact wire specification exists as docs/RECOVERY-GUARDIAN-WIRE.md; the written VSS comparison is completed (12.2) and concludes the guardian protocol ships as a VSS-compatible sibling with four semantic extensions VSS cannot express today; open questions 11.1, 11.2 and 11.7 are closed. Applied four external design review rounds of the wire draft: an explicit REGISTER_NODE genesis operation under a dedicated seed-derived recovery root (which is also the guardian namespace, keeping the Lightning node id out of the protocol, including out of the IV derivation), the writer lease separated from the log head so the post-takeover state is fully defined, an IMMUTABLE root-committed ChainOrigin inside the registration so an existing node enables guardians mid-journal without renumbering while a truncated store can never pass a surviving record off as its origin, a deterministic AES-GCM nonce construction keyed by recovery_id, an exact SYNC_EPOCH validation algorithm, per-verb protobuf responses with 32-byte x-only keys throughout, mandatory transport authentication for non-local deployments with credentials recoverable from the encrypted capsule, guardian-set replacement made a LITERAL v1 non-feature (one set per namespace ever; loss degrades to SCB/DLP; ROTATE_SET reserved), uncertain-store repair defined as rollback-then-replay anchored at the origin proof with re-entry to writability ONLY on quorum evidence (writer possession never proves recency), receipts certifying origin-through-head across epochs, and the obsolete 5.5 sketches replaced rather than annotated
Scope: beignet library (this repo), plus a companion integration issue in beignet-umbrel
Audience: an implementing agent or engineer. Every code reference below was verified against the codebase as of beignet 0.7.0 (2026-07-22). Re-verify line numbers before editing; file and symbol names are the stable anchors.

Style rules for all work on this feature: no em-dashes anywhere (code, comments, commits, PR text, docs). Follow existing repo conventions for everything else.

---

## 1. Summary

Today, restoring a beignet node from seed means force-closing every channel through the SCB/DLP path. This feature reframes recovery: instead of "backing up channel files", beignet maintains a replicated, versioned journal of safety-critical state, so that the normal restore path is to resume channels via `channel_reestablish`, with SCB/DLP demoted to a fallback for when exact state cannot be proven.

Recovery guarantee tiers after this feature ships:

```text
Tier 0: seed only
        recover on-chain wallet funds

Tier 1: seed + SCB
        recover Lightning funds via DLP force-close (exists today)

Tier 2: seed + recovery journal (peer_storage or guardian replicas)
        restore exact state and RESUME channels

Tier 3: seed + quorum-acknowledged recovery journal
        resume channels + distributed writer fencing
        (safe restore on a new device even if the old device comes back)
```

The headline user-facing outcome: destroy the phone or server, restore the mnemonic elsewhere, and channels continue operating without force-closing, provided the recovery replicas were reachable when the latest state was committed. If they were not, the node detects staleness during `channel_reestablish` and falls back to the existing safe DLP close. The backup system does not need to be perfect to be safe; it only needs to distinguish "I have exact state" from "I might not".

## 2. Why this is safe to build on penalty channels

With penalty (LN-penalty) channels, an active channel cannot be recreated from seed alone: once an old state is revoked, broadcasting it lets the counterparty take the channel funds. BOLT 2's `channel_reestablish` can detect that we have fallen behind (the peer proves knowledge of a revocation secret we should not have revealed yet if our state were current), and the mandated response is to not broadcast our stale commitment and let the peer fail the channel. That is exactly what `LightningNode.recoverFromStaticChannelBackup` implements today (see section 3.4).

This feature does not weaken that. It adds a better path above it:

```text
restore from seed
      |
retrieve latest recovery journal
      |
   +--+-----------------------+
   |                          |
exact state              state uncertain
   |                          |
channel_reestablish      existing DLP/SCB path
   |                          |
channels RESUME          safe force close
```

`channel_reestablish` is the protocol-consistency gate before any restored channel is allowed to transact, but it is not a generic proof that a recovered database is exact. The division of labor is precise: recovery storage certifies "this is the highest state this node was permitted to expose to the peer" (sections 5.5 and 5.6), and `channel_reestablish` verifies "this persisted protocol boundary is compatible with the peer's boundary". Only both together permit a channel to go Active. A restored node never sends anything except `channel_reestablish` until that check passes (section 5.7).

## 3. Verified current state of the codebase

These facts were audited directly and are the foundation the design builds on. The implementing agent should re-verify each before starting.

### 3.1 Storage layer

- Interface: `IStorageBackend` in `src/lightning/storage/types.ts`. Only implementation: `SqliteStorage` in `src/lightning/storage/sqlite-storage.ts` (better-sqlite3).
- Durability: `journal_mode = WAL`, `synchronous = FULL` by default (overridable to NORMAL), `busy_timeout = 5000`, `foreign_keys = ON`. `checkpoint()` runs `wal_checkpoint(TRUNCATE)`. `SqliteStorage.backup(destPath)` wraps the SQLite online backup API (concrete method, not on the interface).
- A `transaction<T>(fn)` wrapper exists on the interface (`types.ts` around line 132) and is implemented via `this.db.transaction(fn)()`.
- Safety-critical tables: `channels`, `chain_monitors`, `preimages`, `htlc_payment_map`, `forwarded_htlcs`, `htlc_shared_secrets`, `channel_key_indices`, `payments`, `payment_secrets`. Also relevant: `peer_storage_blobs`, `watchtower_sessions`, `watchtower_updates`. Schema version constant `CURRENT_SCHEMA_VERSION` was 9 when this was written; it reached 11 before Phase 1 landed, and Phase 1 took it to 12 by adding `recovery_outbox`.

### 3.2 Known atomicity gaps (must be fixed by Phase 1)

These describe the tree BEFORE Phase 1. All three are now closed: `persistChannel` routes through `RecoveryManager.commit`, monitor deltas caused by a channel action ride in that channel's transition, and causally linked caller-side writes are staged into the same transaction. The original text is kept because it is the problem statement the design answers.

- `LightningNode.persistChannel` (`src/lightning/node/lightning-node.ts`, around lines 1207-1230) calls `saveChannel(...)` then `saveChannelKeyIndex(...)` as two separate statements, not wrapped in `transaction()`.
- Chain monitor state is persisted through a completely independent path: the `monitor:updated` event listener calls `saveChainMonitor` (around lines 1552-1563). A channel and its chain monitor are never written atomically together.
- `transaction()` is used in some payment/forward paths (for example `persistPayment` + `saveHtlcPaymentMapping` around line 6850, and others near 7149, 7726, 8374, 8897, 9233), but no transaction spans `saveChannel` + `saveChainMonitor`.

### 3.3 The persist-before-send invariant is implicit, not structural

Also a pre-Phase-1 statement: it is structural as of Phase 1 (see the end of 5.1). Retained as the problem statement.

Channel handlers in `src/lightning/channel/channel.ts` return an ordered `ChannelAction[]`. `ChannelManager.processActions` (`src/lightning/channel/channel-manager.ts`, around lines 4224-4359) dispatches actions in array order: `SEND_MESSAGE` goes to the wire immediately; `PERSIST_STATE` emits `'channel:persist'`, which the node handles synchronously (`lightning-node.ts` around lines 1446-1448). So ordering safety depends entirely on each handler putting `PERSIST_STATE` before `SEND_MESSAGE` in the returned array plus synchronous EventEmitter dispatch. It works, but nothing enforces it structurally.

Key existing orderings:

- Receive `commitment_signed` -> send `revoke_and_ack`: the tail of `Channel.handleCommitmentSigned` (`channel.ts`, around lines 2911-2975) returns `[{PERSIST_STATE}, sendMsg(REVOKE_AND_ACK)]` with an explicit persist-before-send comment. Correct today.
- Send `update_fulfill_htlc`: `Channel.fulfillHtlc` (`channel.ts`, around lines 1983-2045) returns only the send action with no `PERSIST_STATE`. Preimage durability depends on the caller having called `storage.savePreimage` first (for example `handleOnChainPreimageLearned` saves at around `lightning-node.ts:8715` before calling `fulfillHtlc` at 8734). This is caller-discipline, not a structural guarantee.
- DLP detection: `Channel.handleReestablish` (`channel.ts`, around lines 5515-5890) validates `yourLastPerCommitmentSecret`, detects fallen-behind, sets `dataLossDetected = true` and `state = ERRORED`, and returns persist-first so a crash cannot forget the no-broadcast rule.
- After `handleRevokeAndAck`, the manager emits `'watchtower:backup'` with the just-revoked remote commitment (`channel-manager.ts`, around lines 2224-2230).

### 3.4 SCB (keep as fallback, unchanged in behavior)

`src/lightning/backup/scb.ts`: envelope `IStaticChannelBackup` (version 1) of `IScbChannelEntry` records (channelId, peerNodeId, peerAddresses, funding outpoint, capacity, channelKeyIndex, channelType, role, isTaproot, isAnchor, optional liquidity-ads lease fields). Encryption: HKDF-SHA256 (empty salt, info `'beignet-scb-v1'`) then AES-256-GCM, encoded as `'beignet-scb-v1:' + base64(iv || tag || ciphertext)`. Restore: `LightningNode.recoverFromStaticChannelBackup` (around lines 2468-2589) reconstructs minimal state with correct local keys from `channelKeyIndex` via `ChannelManager.getRecoveryChannelMaterial`, zeroes commitment numbers, sets `ERRORED` + `dataLossDetected`, arms the funding-outpoint watch, and contacts the peer so the honest peer force-closes and the monitor sweeps our output.

### 3.5 peer_storage (BOLT 1) transport exists, but the outgoing blob is unused

- Wire codec: `src/lightning/message/peer-storage.ts`. Message types `PEER_STORAGE = 7`, `PEER_STORAGE_RETRIEVAL = 9`. Feature bit `PROVIDE_STORAGE = 42`, advertised optional. `PEER_STORAGE_MAX_BYTES = 65531`.
- Server side (we hold peers' blobs): `handlePeerStorageMessage` with a 60 second min-persist interval, stored in `peer_storage_blobs`, returned on reconnect via `sendPeerStorageOnConnect`.
- Client side (peers hold our blob): `distributePeerStorage(blob)` (around `lightning-node.ts:2034-2068`) sets `ourPeerStorageBlob` and pushes to peers with the feature bit; re-pushed on connect. Retrieval handled in `handlePeerStorageRetrievalMessage`, exposed via the `'peer_storage:retrieved'` event and `getRetrievedPeerStorage()`.
- Own-blob privacy framing already exists: `padOwnPeerStorageBlob` frames as `['bPS1'(4)][big-endian length(4)][blob][zero padding]` padded to the full 65531 bytes so blob size leaks nothing.
- Critically: `ourPeerStorageBlob` is `null` by default. Beignet currently never composes an outgoing backup payload. The transport is ready; the payload is this feature.

### 3.6 Key derivation and HKDF info strings in use

All app-level keys go through `hkdfKey(secret, info)` = HKDF-SHA256, empty salt, 32-byte output (`src/lightning/storage/encryption.ts`). Info strings already claimed, which the new derivations must not collide with:

- `'beignet-storage-encryption-v1'` (storage at rest)
- `'beignet-scb-v1'` (SCB)
- `'beignet-wallet-storage-v1'` (on-chain wallet storage)
- `'beignet-taproot-verification-nonce'` (MuSig2)

Node/channel keys: BIP32 path `m/1017'/coinType'/channelIndex'/keyIndex` in `src/lightning/keys/wallet-keys.ts`; per-channel signers via `SignerFactory` keyed by `channelKeyIndex`.

### 3.7 Watchtower (stays separate)

`src/lightning/watchtower/` implements an LND-altruist watchtower client with encrypted justice kits, persisted sessions and unacked updates. A watchtower protects against the counterparty broadcasting a revoked state while we are offline. A recovery guardian protects against us losing our own state. These are logically distinct services and must remain so in this design. The same operator may later run both behind one daemon, but the protocols and trust assumptions stay separate.

## 4. Design overview

```text
                    BEIGNET LIGHTNING NODE
                            |
                            v
                 Safety Transition Layer          (Phase 1)
                            |
           +----------------+-----------------+
           |                                  |
           v                                  v
  Atomic SQLite transaction            Durable outbox        (Phase 1)
   channel state                        commitment_signed
   monitor state                        revoke_and_ack
   HTLC mappings                        fulfill / fail
   preimages                            splice messages
   payment state
                            |
                            v
                    RecoveryFrame N               (Phase 2)
                 AEAD + hash chain + sequence
                            |
                            v
                    Durability policy             (Phase 6)
                            |
            +---------------+---------------+
            |               |               |
          local          async            quorum
            |               |               |
            v               v               v
        continue        continue        wait for ACK
                            |               |
                            v               v
                       replicate      guardian quorum   (Phase 4)
                                            |
                                            v
                                  signed GuardianState
                                            |
                                            v
                                      send wire msg
```

Replication targets:

1. BOLT 1 `peer_storage`: carries a compact Recovery Capsule (SCB + latest journal head + guardian locators + inline journal state when it fits). Best-effort checkpoints. (Phase 3)
2. Beignet Guardians: dedicated blob stores with signed, monotonic receipts and writer-epoch fencing. 2-of-3 by default. (Phases 4-5)

## 5. Detailed design

### 5.1 Safety transitions and atomic persistence (Phase 1)

Introduce a single choke point for all safety-critical persistence. New module: `src/lightning/recovery/` (with `index.ts` and `types.ts`, following the existing subsystem layout, re-exported from `src/lightning/index.ts`).

```ts
export type RecoveryMutation =
  | { type: 'channel_state'; channelId: string; state: IChannelState; peerPubkey: string }
  | { type: 'channel_key_index'; channelId: string; channelIndex: number }
  | { type: 'chain_monitor'; channelId: string; state: IChainMonitorState }
  | { type: 'payment_preimage'; paymentHash: string; preimage: Buffer }
  | { type: 'htlc_payment_mapping'; htlcKey: string; paymentHash: string }
  | { type: 'delete_htlc_payment_mapping'; htlcKey: string }
  | { type: 'htlc_shared_secret'; key: string; secret: Buffer }
  | { type: 'delete_htlc_shared_secret'; key: string }
  | { type: 'forwarded_htlc'; outKey: string; inChannelId: Buffer; inHtlcId: bigint }
  | { type: 'delete_forwarded_htlc'; outKey: string }
  | { type: 'payment_state'; paymentHash: string; payment: IPaymentInfo }
  | { type: 'payment_secret'; paymentHash: string; secret: Buffer }
  | { type: 'delete_payment_secret'; paymentHash: string }
  | { type: 'channel_closed'; channelId: string };

export enum RecoveryCriticality {
  Reconstructable,   // gossip, mission control: never journaled
  Important,         // journaled, never blocks the protocol
  SafetyCritical,    // journaled, subject to the durability barrier
}

export interface SafetyTransition {
  criticality: RecoveryCriticality;
  mutations: RecoveryMutation[];
  outboundMessages: RecoveryOutboundMessage[];  // see 5.2
}
```

`RecoveryManager.commit(transition)` performs, in order:

1. One SQLite `transaction()` applying every mutation plus the outbox rows plus the journal frame row (section 5.3). This is the atomicity fix: channel state, its chain monitor delta, HTLC linkage, preimages, and the outbound message record become one crash-consistent unit.
2. The configured durability barrier (section 5.8).
3. Release of the outbound messages to the wire.

Refactor targets:

- `persistChannel` in `lightning-node.ts`: route through `RecoveryManager.commit` so `saveChannel` + `saveChannelKeyIndex` are atomic.
- The `monitor:updated` -> `saveChainMonitor` listener: when a monitor update is causally tied to a channel action (commitment advance, HTLC resolution), it must ride in the same transition. Standalone monitor updates (chain events) become their own transitions.
- `fulfillHtlc` call sites: the preimage mutation and the fulfill message must be one transition, removing the caller-discipline hazard in 3.3.
- `performForward`: the `forwarded_htlc` linkage and the outgoing `update_add_htlc` become one transition, so a node-wide consistent point always exists for in-flight forwards (incoming HTLC on A, linkage, outgoing HTLC on B).

Do not serialize unrelated channels through one lock. Each transition is atomic; only causally linked mutations share a transition. The journal (5.3) provides global ordering across transitions without global locking.

Backward compatibility requirement: with recovery disabled (default off until Phase 2 is proven), `RecoveryManager.commit` degrades to exactly today's behavior plus the atomicity fixes. The atomicity fixes land unconditionally; they are correct regardless of replication.

Two decisions taken when Phase 1 was implemented, recorded here because the code follows them rather than the original sketch:

1. **Typed mutations, not opaque buffers.** The state-bearing variants carry the library's own typed state objects (`IChannelState`, `IChainMonitorState`, `IPaymentInfo`) instead of `Buffer`. The storage backend already owns the serialization (bigint-safe JSON plus encryption at rest); encoding here would duplicate that serializer, and drift between the two copies would be a silently corrupt restore. Phase 2 encodes frames at the journal boundary, which is where a canonical byte format belongs. The sketch's `splice_state` variant is dropped for the same reason: splice state lives inside `IChannelState` and a second copy could only diverge from it.
2. **Staged mutations for caller-side state.** Removing the caller-discipline hazard needs a way for a caller to say "this preimage belongs to the fulfill I am about to trigger". `LightningNode.withStagedMutations(mutations, fn)` stages them; the next channel transition folds them into its transaction, and anything still staged when `fn` returns is committed on its own so no write is silently dropped. This is what makes the fulfill and forward transitions atomic without giving `ChannelManager` a storage handle.

Phase 1 also makes the invariant of 3.3 structural rather than conventional. `processActions` collects every retransmittable `SEND_MESSAGE` that follows the batch's `PERSIST_STATE`, hands the exact bytes to the persist listener for commit, and WITHHOLDS those sends if the transaction rolls back. A message whose justifying state is not on disk never reaches the peer, where previously a swallowed persistence error still let the send proceed.

### 5.2 Durable outbound message journal (Phase 1)

Restoring channel objects is not enough; recovery must reproduce the exact protocol boundary, including messages that BOLT 2 requires us to retransmit (`commitment_signed`, `revoke_and_ack`, with relative order preserved via the existing `lastSentWasRevoke` logic, plus splice retransmission).

```ts
export interface RecoveryOutboundMessage {
  peerId: string;
  channelId?: string;
  messageType: number;
  wireMessage: Buffer;   // exact encoded bytes
  disposition: 'pending_send' | 'sent_unacked' | 'superseded';
}
```

Transactional-outbox pattern: the message row commits in the same SQLite transaction as the state that makes it necessary; the socket write happens only after commit (and after the durability barrier, when one applies). On restart, `pending_send` rows for still-open channels are re-evaluated against reestablish state rather than blindly replayed: `channel_reestablish` counters decide retransmission per BOLT 2, and the outbox supplies the exact bytes when retransmission is required. Rows become `superseded` when the reestablish exchange proves the peer received them.

New table (schema migration to version 12, since the schema had already reached 11 by the time Phase 1 landed): `recovery_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, peer_pubkey, channel_id, message_type, wire_message, disposition, frame_sequence, created_at)`, indexed on `(channel_id, id)`. `wire_message` is in `ENCRYPTED_COLUMNS`: retained bytes are signed commitment material that reveals channel activity to anyone reading the database file. `frame_sequence` stays NULL until Phase 2.

Retention, decided during implementation: a superseded row is DELETED rather than parked in a terminal disposition. Its only consumer is retransmission, which by definition no longer needs it, and retaining it would reintroduce the unbounded growth the per-channel row cap exists to prevent. Rows are superseded when the peer's `revoke_and_ack` proves receipt of our updates and the `commitment_signed` that covered them (mirroring channel.ts clearing its in-memory `_lastSentBatch` on the same event), and a channel's rows are dropped with the channel. Our OWN `revoke_and_ack` rows are excluded from that sweep: the peer's revocation says nothing about whether it received ours. Instead, the types nothing else retires (`revoke_and_ack`, `channel_ready`, `splice_locked`) supersede their own kind as they are written, in the same transaction: only the newest of each can ever be retransmitted, so a channel holds one row per type rather than one per commitment round for the life of the channel. A fully resolved close clears the channel's rows outright, since a channel that can never reestablish can never retransmit. A per-channel cap prunes the oldest rows as a backstop, degrading that channel to reconstruct-from-state retransmission, which is exactly the pre-outbox behavior.

The concrete case this closes today: `_lastSentBatch` in `channel.ts` is in-memory only, and the reestablish fallback can rebuild an un-acked batch only by RE-SIGNING, which it explicitly refuses to do for a taproot channel because a fresh MuSig2 secret nonce must never sign material the peer may already hold under the old one. Before Phase 1 a restart mid-batch on a taproot channel therefore had nothing to retransmit. `Channel.restoreLastSentBatch`, fed from the outbox at channel restore, supplies the exact bytes and signs nothing.

### 5.3 Recovery journal (Phase 2)

Append-only, node-wide, monotonic journal of every `Important` and `SafetyCritical` transition.

```ts
export interface RecoveryFrame {
  version: 1;
  writerEpoch: bigint;      // changes only when a restored device takes ownership
  sequence: bigint;         // globally monotonic across the node
  previousFrameHash: Buffer;
  timestamp: number;
  mutations: RecoveryMutation[];
  outboundMessages: RecoveryOutboundMessage[];
}

export interface EncryptedRecoveryFrame {
  writerEpoch: bigint;
  sequence: bigint;
  frameHash: Buffer;        // hash of the plaintext frame
  ciphertext: Buffer;       // AES-256-GCM (decided, 11.2)
}
```

Key derivation (new info strings, verified non-colliding with 3.6):

```text
recovery_master_key = HKDF-SHA256(seed, info = 'beignet-recovery-v1')
per_epoch_key       = HKDF-SHA256(recovery_master_key, info = 'beignet-recovery-frame-v1' || nodeId || writerEpoch)
```

AEAD associated data must bind `(nodeId, writerEpoch, sequence, previousFrameHash)` so frames cannot be transplanted across epochs or positions.

Honest scoping of the hash chain: a hash chain detects tampering and reordering relative to a known tip. It does not by itself prevent rollback: a stale or malicious replica can serve a truncated but internally valid chain. Anti-rollback comes from the externally anchored `GuardianState` (guardian receipts, 5.6). Without guardians, peer_storage checkpoints give best-effort recency and `channel_reestablish` remains the safety net. Document this in the module docs exactly this way.

Snapshots and compaction: periodically emit a full-state snapshot frame (all safety-critical tables serialized), then prune deltas older than the last snapshot. Snapshot cadence adaptive: after N frames or M bytes of deltas.

New tables: `recovery_frames(sequence PRIMARY KEY, writer_epoch, frame_hash, previous_hash, ciphertext, created_at)` and `recovery_meta(key, value)` for the current epoch, tip hash, and snapshot sequence.

Deterministic reconstruction: `reconstructFromFrames(snapshot, deltas)` rebuilds every safety-critical table byte-identically. This must be property-tested (section 10).

Ordering decision (revision 3): the journal keeps a single node-wide sequence. Per-channel journals were considered and rejected for v1: a forward atomically links an incoming HTLC on one channel to an outgoing HTLC on another (5.1), so partitioned journals would need cross-journal transaction records, and reconstruction would become a partial-order merge instead of a linear replay. The cost of the single sequence is potential head-of-line coupling: guardians enforce sequence continuity (5.5), so frame N+1 cannot be accepted before frame N. Two requirements keep that coupling from becoming per-frame latency:

- Appends are pipelined. The writer streams frames to each guardian in sequence order without waiting for the previous receipt.
- Receipts are cumulative. A receipt for head sequence S certifies every stored record from the root-committed origin through S, across writer epochs, so one receipt can release many pending barriers at once.

With those two rules, a slow receipt for channel A's frame N does not add a round trip to channel B's frame N+1; the receipt covering N+1 satisfies both barriers. The residual coupling is real and documented: in quorum mode, when the quorum is genuinely unreachable, every SafetyCritical barrier on the node stalls, whatever the channel. That is inherent to quorum durability, not to the ordering choice; async-remote and local modes have no barrier and no cross-channel stall. If profiling under load ever shows barrier convoys beyond this, the revisit path is per-channel journals plus a node epoch journal with cross-journal forward records, and the frame format's sequence field would become a (stream, sequence) pair; the v1 format does not build this.

### 5.4 Recovery Capsule over peer_storage (Phase 3)

Do not put full snapshots in peer_storage by default. BOLT 1 limits the blob to 65531 bytes, stores only the latest blob, permits providers to rate-limit persistence (beignet's own server side already enforces 60 seconds), and explicitly warns not to expect the latest blob back. So peer_storage carries a capsule, not the journal:

```ts
export interface RecoveryCapsule {
  version: 1;
  encryptedScb: Buffer;            // always sufficient for Tier 1 emergency recovery
  writerEpoch: bigint;             // latest remotely durable head
  latestSequence: bigint;
  frameHash: Buffer;
  guardians: GuardianDescriptor[]; // how to find the real replicated state
  snapshotHash: Buffer;
  inlineRecoveryState?: Buffer;    // full snapshot + deltas, only when it fits
}
```

Encryption: HKDF info `'beignet-recovery-capsule-v1'`, then the existing `padOwnPeerStorageBlob` framing (no size leak). Push via the existing `distributePeerStorage`; refresh on every snapshot, on initial guardian enablement or descriptor and credential changes (set replacement does not exist in v1, see 12.1), and at most once per minute to respect provider rate limits.

For small wallets (one or two channels), the complete recovery state will often fit inline, making Tier 2 restore possible from peer_storage alone with zero new infrastructure. That alone justifies Phase 3 shipping before guardians exist.

Restore side: on reconnect after seed restore, collect `'peer_storage:retrieved'` blobs from all storage peers, decrypt all candidate capsules, and select the highest `(writerEpoch, sequence)` whose hash chain validates. BOLT 1 requires providers to return the blob early after reconnection, before normal channel recovery, which is exactly the window this needs.

### 5.5 Guardian protocol (Phase 4)

A guardian is a minimal blob store with one nontrivial duty: signed, monotonic receipts.

```ts
// Revision 4 shapes (exact bytes in docs/RECOVERY-GUARDIAN-WIRE.md).
// The namespace is recovery_id, an x-only key derived from a dedicated
// seed-derived recovery root, NEVER the public Lightning node id; a
// REGISTER_NODE operation signed by that root creates the namespace
// (no implicit creation, no squatting). Guardian state is two separable
// pieces: the writer LEASE (who may write now) and the LOG HEAD (the
// stored tip); a takeover changes the lease and leaves the log head
// untouched, so recordEpoch lawfully trails lease.epoch until the new
// writer's first append.

export interface WriterLease {
  epoch: bigint;
  writerPublicKey: Buffer;   // 32-byte x-only, fresh random per epoch (5.6)
}

export interface ChainOrigin {
  firstSequence: bigint;     // fresh node: 1; existing node: the retained
                             // journal base position. Immutable, committed
                             // inside the root-signed registration.
  previousHash: Buffer;      // 32 zero bytes for a fresh node
}

export interface LogHead {
  sequence: bigint;          // 0 at genesis ("no records stored yet")
  frameHash: Buffer;         // 32 zero bytes at genesis
  ciphertextHash: Buffer;    // 32 zero bytes at genesis
  recordEpoch: bigint;       // the epoch the tip record was written under
}

export interface GuardianState {
  recoveryId: Buffer;        // 32-byte x-only recovery root public key
  lease: WriterLease;
  origin: ChainOrigin;       // where the first record MUST land; a bare
                             // surviving record can never masquerade as
                             // an origin
  logHead: LogHead;
}

export interface GuardianRecord {
  recoveryId: Buffer;
  epoch: bigint;             // must equal lease.epoch at acceptance
  sequence: bigint;          // must equal logHead.sequence + 1
  previousHash: Buffer;      // must equal logHead.frameHash
  frameHash: Buffer;
  ciphertext: Buffer;        // opaque to the guardian
  writerSignature: Buffer;   // BIP340 over the RECORD transcript
}

export interface GuardianReceipt {
  guardianId: Buffer;
  state: GuardianState;      // guardians sign the COMPLETE state
  signature: Buffer;
}
```

Epoch acquisition is a compare-and-swap takeover, not a bare increment, authorized by the recovery root and proving possession of the fresh writer key:

```ts
export interface AcquireEpochRequest {
  expectedState: GuardianState; // CAS guard: the state the caller reconciled
  newEpoch: bigint;             // must equal expectedState.lease.epoch + 1
  newWriterPublicKey: Buffer;
  rootSignature: Buffer;        // recovery root authorizes the takeover
  newWriterSignature: Buffer;   // proves possession of the new key
}

export interface TakeoverCertificate {
  guardianId: Buffer;
  supersededState: GuardianState; // the superseded epoch's final state,
                                  // immutable forever
  newEpoch: bigint;
  newWriterPublicKey: Buffer;
  signature: Buffer;
}
```

Guardian invariants (enforced server-side):

```text
accept REGISTER_NODE iff:
  (recoveryId, guardian_set_id) not yet registered
  root signature verifies under recoveryId
  origin.firstSequence >= 1 (immutable for the namespace's life; the
  guardian durably persists the root-signed registration as the origin
  proof and returns it via GET_HEAD)
  logHead is genesis (a guardian never certifies a record it lacks)

accept PUT_STATE iff:
  record.epoch == lease.epoch for recoveryId
  writerSignature verifies under lease.writerPublicKey
  first record: sequence == origin.firstSequence
                previousHash == origin.previousHash
  later:        sequence == logHead.sequence + 1
                previousHash == logHead.frameHash
reject everything else, including any write from a superseded epoch

accept ACQUIRE_EPOCH iff:
  root signature verifies under recoveryId
  new-writer signature verifies under newWriterPublicKey
  expectedState == the guardian's current stored state, byte-exact
  newEpoch == expectedState.lease.epoch + 1
on mismatch: reject and return the current state so the caller can
refetch and retry the CAS

REGISTER_NODE, PUT_STATE and ACQUIRE_EPOCH for one recoveryId are
linearized through a single per-node state machine. A takeover and an old-epoch append can
never interleave, and once a takeover commits, the superseded epoch's
head is immutable forever. This is a hard requirement, not an
implementation detail: if the two verbs were independent database
operations, a still-live old writer could append a certified state
concurrently with a takeover, and the two sides would disagree about
the final head of the superseded epoch.
```

Acceptance is record-level, not connection-level: a record is valid because its writer signature, epoch binding, and chain position verify, not because of who delivered it. Transport authentication exists for anti-DoS and privacy, never as a substitute for record verification. This is what makes backfill by a restore device possible (below) after the original writer's ephemeral key is gone.

Guardian durability invariants (revision 3). Crash-fault tolerant means a crashed guardian retains every acknowledged receipt, head, and epoch after restart:

```text
a guardian makes the record, the updated head, and the epoch state
durable (fsync or equivalent) BEFORE issuing a GuardianReceipt or a
TakeoverCertificate

a guardian restart never loses an acknowledged record, head, epoch,
or issued receipt

a guardian that cannot prove its store is intact (corruption detected,
restored from its own backup, missing epoch state) refuses PUT_STATE
and ACQUIRE_EPOCH until repaired; repair is ROLLBACK THEN REPLAY, never
insert-behind-head: discard all per-namespace state after the last
internally consistent checkpoint, then replay SYNC_RECORD and
SYNC_EPOCH in chronological order (exact procedure:
docs/RECOVERY-GUARDIAN-WIRE.md 5.10); it may keep serving GET_HEAD and
GET_STATE with an explicit possibly-stale flag until repaired

receipts are cumulative: a receipt for head sequence S certifies every
stored record from the root-committed origin through S inclusive,
across every intervening writer epoch

guardians persist the receipts and takeover certificates they issue,
and GET_HEAD returns the current head together with the takeover
certificates the guardian knows for prior epochs
```

Backfill and epoch synchronization (revision 3). Two verbs let anyone holding valid artifacts repair a lagging guardian; both are needed because the superseded writer's private epoch key dies with the lost device:

- `SYNC_RECORD(record)`: relays an already-signed record to a guardian that missed it. The guardian applies the normal PUT_STATE acceptance rules (writer signature, epoch binding, sequence continuity from its own stored head) and appends. The submitter is not required to be the writer; records are self-authenticating.
- `SYNC_EPOCH(certificates)`: presents a quorum set of `TakeoverCertificate`s to a guardian that missed a takeover. The guardian verifies the threshold of guardian signatures, adopts the new epoch and writer key, fixes the superseded epoch's final head at `takeoverHead`, and discards any stored frames of the superseded epoch above `takeoverHead`. Discarding is safe in quorum mode: a frame above the certified final head reached at most `required - 1` receipts, so the wire message depending on it was never released. In async-remote mode such a frame may have escaped to the wire; that is the already-documented async fencing window (5.6), and the discarded tail is exactly what the `channel_reestablish` safety net exists for.

A threshold bundle of receipts for one head (a quorum certificate) is evidence that the head was committed. In the v1 crash-fault model it is used for restore diagnostics only; record acceptance rests on writer signatures and chain continuity. If the threat model is ever upgraded toward Byzantine tolerance, SYNC_RECORD and SYNC_EPOCH acceptance must additionally require quorum certificates, and the quorum geometry changes per the threat model note below.

Verbs: `PUT_STATE`, `GET_STATE`, `GET_HEAD`, `ACQUIRE_EPOCH`, `SYNC_RECORD`, `SYNC_EPOCH`. Transport: decided in revision 4 (12.1): HTTP/protobuf over a v3 onion service and HTTPS/protobuf over clearnet, both first-class; the exact bytes live in docs/RECOVERY-GUARDIAN-WIRE.md. The transport does not relax the per-node linearization above.

The signed `GuardianState` is the anti-rollback anchor missing from a bare hash chain: a restoring device fetches heads from the quorum and refuses any replica whose tip is behind the highest quorum-certified head.

Threat model, stated explicitly in code and docs:

- Guardians are assumed crash-faulty, not Byzantine. 2-of-3 prevents split-brain among compliant writers when at most one guardian is unavailable, and tolerates one unavailable guardian for liveness.
- 2-of-3 does not survive one actively equivocating guardian: a malicious G3 can co-sign conflicting epoch acquisitions with disjoint honest partners (A gets G1+G3, B gets G2+G3). If Byzantine tolerance of f=1 is later required, move to a quorum system with proper intersection (for example 3-of-4). The protocol structs must carry a quorum-config version so this can change without a format break.

### 5.6 Writer epochs and split-brain fencing (Phase 5)

Every running instance operates under a writer lease:

```ts
export interface WriterLease {
  nodeId: Buffer;
  epoch: bigint;
  writerPublicKey: Buffer;        // ephemeral key generated by this installation
  guardianCertificates: Buffer[]; // quorum attestation that this writer owns this epoch
}
```

First setup is `REGISTER_NODE` (5.5, revision 4): the recovery root registers the namespace with a fresh writer key at a genesis log head. `ACQUIRE_EPOCH` is used at every restore (and any later writer change): the device generates a fresh ephemeral writer key, queries states from the guardians, reconciles the highest quorum-consistent state, and issues `AcquireEpochRequest` with that state as the CAS guard, co-signed by the recovery root (5.5). If any guardian reports a newer state, the CAS fails, the device refetches, and retries. On quorum certification the device holds a set of `TakeoverCertificate`s fixing the superseded epoch's final state, and the guardians permanently reject all writes from prior epochs. Binding the epoch to a writer public key (not just a number) prevents a second device from racing into the same epoch; binding acquisition to `expectedState` prevents the fetch-then-fence race described in 5.7; requiring the root signature means possession of a fresh key alone never confers authority over the namespace.

The fencing story, precisely:

```text
Phone A runs as (epoch 42, writer KA)
Phone A is lost; Phone B restores from seed
Phone B acquires (epoch 43, writer KB) from 2-of-3 guardians
Guardians now reject epoch 42 forever

Phone A comes back online:
  in quorum mode: its next safety-critical barrier fails (epoch rejected)
                  -> channels freeze BEFORE any wire message depending on
                     the unacknowledged state is sent
  in async-remote mode: replication fails and the node must treat a
                        definitive epoch rejection as a hard freeze signal,
                        but there is a window before it learns this
  in local mode: no fencing at all
```

Additional startup rule (closes the pre-reestablish window): channels may not leave quarantine, and the node may not even connect to channel peers, until current writer ownership is confirmed with the quorum (or the operator explicitly runs in a mode without guardians). A stale device therefore discovers it was superseded before it can touch the Lightning protocol.

Honest limits, to be documented verbatim in user-facing docs: fencing is cooperative. It cannot revoke Bitcoin keys on the old device. A non-compliant or modified instance can still sign. What fencing guarantees is that two compliant beignet instances can never advance the same channels independently. And if a fenced stale device (or an attacker with the old device) broadcasts its stale commitment anyway, that commitment is revoked, so the standard penalty mechanism plus the existing watchtower protection applies: the broadcaster loses the channel funds to the peer, not to the new device's detriment beyond that channel closing.

### 5.7 Restoration flow and quarantine (Phase 5)

```text
restore mnemonic
      |
derive node keys + recovery keys
      |
retrieve peer_storage capsules from storage peers
      |
capsule -> guardian locators -> query guardian heads
      |
reconcile the highest quorum-consistent head
      |
ACQUIRE_EPOCH(expectedState): compare-and-swap takeover (5.5, 5.6)
      |     CAS failure: refetch the newer head, retry
      |
takeover certificates fix the superseded epoch's FINAL head
      |
download frames through takeoverHead
      |
verify: AEAD, sequence continuity, hash chain, head + certificate signatures
      |
reconstruct SQLite from snapshot + deltas (5.3)
      |
QUARANTINE: connect peers, send ONLY channel_reestablish
      |
per channel, classify the reestablish outcome
```

Head reconciliation and stale-guardian repair (revision 3). "Reconcile the highest quorum-consistent head" is an algorithm, not a hope:

```text
1. read heads from all reachable guardians; proceed only when at least
   `required` (default 2) respond. Any commit quorum intersects any
   read set of that size, so the highest committed head is always
   visible among the responses.

2. adopt the highest head whose writer signature verifies, and when
   epochs differ, the highest epoch backed by a quorum of takeover
   certificates. Higher-than-committed is safe to adopt: a frame that
   never reached quorum is still a state the writer produced, its
   outbox rows are pending_send, and reestablish reconciles it with
   the peer. Adopting anything lower than a committed head is never
   safe.

3. repair lagging guardians: replay missing frames with SYNC_RECORD
   (fetched from an up-to-date guardian) and missed takeovers with
   SYNC_EPOCH, until at least `required` guardians share the adopted
   head.

4. issue ACQUIRE_EPOCH with the now-common head as the CAS guard.

5. fewer than `required` reachable guardians: refuse the Tier 3
   takeover. Without a quorum there is no fencing and no recency
   proof. The operator waits, or falls back to the SCB/DLP path, or
   uses the explicitly-labeled escape hatch (below), which must state
   that it cannot fence the old writer.

6. two distinct records at the same (epoch, sequence), or conflicting
   takeover certificates for one epoch: outside the crash-fault model
   (a Byzantine writer or guardian). Halt the restore, surface both
   artifacts to the operator, take no channel action.
```

Worked example, the divergent-head case from the revision 3 design review. Guardians G1, G2, G3, quorum 2-of-3. Frame N was committed with receipts from G1 and G2; G3 was offline at N-1. The device dies; at restore time G1 is unreachable. The restore device reads G2 (head N) and G3 (head N-1): read set of 2 is met, N is adopted (highest valid head), N is replayed to G3 with SYNC_RECORD, and ACQUIRE_EPOCH(expectedState = N) then succeeds on both G2 and G3. Without SYNC_RECORD the CAS could never assemble a quorum: G3 would reject expectedState N, and G2 would reject expectedState N-1 as a rollback. Durability 2-of-3 therefore does not mean "the exact two guardians that acked the last frame must both be reachable"; it means any `required`-sized read set plus repair.

Fence before restore, never the reverse. If reconstruction happened before the takeover, a still-live old device could certify one more state between the restoring device's fetch and its epoch acquisition. The restored node would then hold a stale head while believing it is current. Quarantine keeps such a node from transacting, but a node that believes it is current may later make a unilateral force-close decision with what is actually a revoked commitment if the peer stays unreachable. With the CAS takeover first, the superseded epoch's head is immutable before any state is downloaded, so what the new device reconstructs is provably the final certified state of the old epoch.

Per-channel recovery status, richer than a binary exact/stale:

```ts
export enum ChannelRecoveryStatus {
  Quarantined,      // restored, reestablish not yet exchanged
  Reestablishing,   // counters agree, normal resume
  ReplayRequired,   // peer needs retransmission; serve exact bytes from the outbox
  LocalDataLoss,    // peer proved we are stale: existing DLP path, no broadcast
  StateUncertain,   // cannot prove our state is current: never broadcast, peer closes
  Active,
  ForceClosing,
}
```

`ReplayRequired` is where the outbox (5.2) pays off: BOLT 2's counters say what to retransmit; the outbox supplies exactly what was sent before the crash, preserving `commitment_signed` / `revoke_and_ack` relative order. `LocalDataLoss` and `StateUncertain` route into the existing, already-tested DLP/SCB machinery (3.4), with one invariant stated explicitly: a channel in either state must never broadcast the stored local commitment, even if the peer stays unreachable indefinitely. Unilateral force close from these states is forbidden; the only safe exits are the peer closing (DLP) or the operator explicitly accepting the risk through a separate, clearly-labeled escape hatch that is out of scope here. This matches BOLT 2's rule that a fallen-behind node shown a later revocation secret must not broadcast its commitment. Splice and funding reestablish disagreements route to the existing splice reestablish handling (`_handleReestablishSplice`).

### 5.8 Durability policies and barriers (Phase 6)

```ts
export type RecoveryDurability = 'local' | 'async-remote' | 'quorum';
```

- `local`: fsync (WAL + synchronous=FULL, as today), continue immediately, replicate opportunistically. Safety equals a normally persisted node. No fencing guarantee.
- `async-remote`: fsync, continue, replicate in the background. On catastrophic loss: latest replica resumes, slightly stale replica means DLP-closing only the channels that advanced after the last replicated frame. Recommended default for consumer wallets.
- `quorum`: fsync, replicate, wait for 2-of-3 receipts, only then release the dependent wire message. Guarantee: once a peer sees a new channel state from us, sufficient remote information already exists to restore that state. This is the same persistence-barrier concept LDK expresses with `ChannelMonitorUpdateStatus::InProgress` (channel frozen until persistence completes), adapted to this codebase's action model.

The barrier applies only where failure to recover the state would be unsafe, gated by `RecoveryCriticality`:

```text
must be SafetyCritical (barrier applies):
  new commitment persisted        -> before sending revoke_and_ack
  preimage + HTLC linkage         -> before sending update_fulfill_htlc
  forward linkage                 -> before the outgoing HTLC becomes irrevocable
  splice state transitions        -> before the corresponding splice message
  dataLossDetected flag           -> before sending the DLP error

Important (journaled, no barrier):
  payment metadata, invoices, forwarding events

Reconstructable (not journaled):
  gossip, graph, mission control
```

Never put gossip or graph writes behind WAN latency.

Implementation note: rather than sprinkling barrier calls through `channel.ts`, extend the action model. Add an action-level marker (for example `PERSIST_STATE` carrying a criticality) and let `processActions` in `channel-manager.ts` route persistence through `RecoveryManager.commit` and hold subsequent `SEND_MESSAGE` actions of the same batch until the barrier resolves. That makes persist-before-send structural instead of conventional, fixing 3.3 as a side effect. `processActions` becomes async-aware for barrier waits; audit every caller for ordering assumptions.

### 5.9 The safety transition matrix (the implementation spec)

Before writing Phase 1 code, produce `docs/RECOVERY-TRANSITION-MATRIX.md` (delivered with Phase 1) enumerating every site that sends or receives `commitment_signed`, `revoke_and_ack`, `update_add_htlc`, `update_fulfill_htlc`, `update_fail_htlc`, `update_fail_malformed_htlc`, `channel_reestablish`, and splice messages, and for each: what must be atomically persisted, at what criticality, before which wire message. The matrix must also classify every ephemeral signing session and transient state item in 5.10 with one of the four dispositions defined there. Starting anchor list (verified, re-check lines):

| Site | Location | Today | Required transition |
|---|---|---|---|
| recv commitment_signed -> send revoke_and_ack | `channel.ts` handleCommitmentSigned tail (~2911-2975) | persist-first via action order | SafetyCritical barrier between persist and send |
| send commitment_signed | `channel.ts` sendCommitmentSigned (~2486-2670) | persist via action order | SafetyCritical + outbox row |
| recv revoke_and_ack | `channel-manager.ts` handleRevokeAndAck (~2206-2243), emits watchtower:backup | persist via action order | SafetyCritical; watchtower kit generation stays out-of-band |
| send update_fulfill_htlc | `channel.ts` fulfillHtlc (~1983-2045), no PERSIST_STATE; callers save preimage first (e.g. `lightning-node.ts` ~8715 before ~8734) | caller discipline | preimage + mapping + message in one SafetyCritical transition |
| send update_fail_htlc | `channel.ts` failHtlc (~2181-2260) | queued for retransmit | Important transition + outbox row |
| forward linkage | `lightning-node.ts` performForward (~8617-8628), saves forwarded_htlc before addHtlc | ordered, non-atomic with the HTLC | linkage + outgoing add in one SafetyCritical transition |
| DLP detection | `channel.ts` handleReestablish (~5515-5890) | persist-first | SafetyCritical; dataLossDetected must never be lost |
| reestablish retransmit decision | same, uses lastSentWasRevoke | in-memory + persisted flags | outbox supplies exact retransmission bytes |
| splice transitions | `channel-manager.ts` handleSpliceMsg/Ack/Locked (~3391-3437), `channel.ts` _handleReestablishSplice (~5299) | persist via action order | SafetyCritical per irreversible splice step |
| channel restore | `lightning-node.ts` recoverFromStaticChannelBackup (~2468-2589) | existing SCB path | becomes the LocalDataLoss fallback branch |

### 5.10 Ephemeral signing sessions and transient state (revision 3)

The single invariant, from which everything in this section follows: a restored signer must never use a secret nonce to sign different material than the nonce was originally bound to. Every ephemeral signing session and every piece of transient state gets exactly one of four dispositions, recorded per item in the transition matrix (5.9):

```text
D1 persist-before-emit   the session state is journaled in the same
                         transition as the message that exposes it
                         (or is deterministically re-derivable from
                         state that is)
D2 retransmit-exact      the session is NOT restored; the outbox (5.2)
                         serves the exact prior bytes, so no secret is
                         ever reused on new material
D3 abandon-and-restart   the session dies with the process by design
                         and restarts with fresh randomness after
                         reestablish
D4 force-close           safe continuation cannot be demonstrated
```

Verified classifications as of 0.7.5 (re-verify before Phase 1):

- Taproot verification nonces (`localNonce` / `localNextNonce` in `channel-state.ts` around lines 444-464): deterministic per commitment height from the persisted per-commitment seed (`_deriveVerificationNonce` in `channel.ts` around line 798), re-derived identically on restart, each signs exactly one commitment once. D1 by determinism: no extra journaling needed beyond the channel state the derivation reads, which already rides in `channel_state` mutations.
- Commitment co-signing nonce (`signCommitmentPartial` in `channel-manager.ts` around line 741): fresh random, signs one sighash, discarded inside the same call; the partial signature and public nonce travel inside the `commitment_signed` wire bytes. D2: reestablish retransmission serves the exact bytes from the outbox, so the secret nonce is never needed again. This is a load-bearing reason the outbox stores encoded bytes rather than re-encoding from state.
- Taproot cooperative close session (`_ourClosingNonce`, `_remoteClosingNonce`, `_hasSignedClosing`, `_taprootClosingCache` in `channel.ts` around lines 474-491): in-memory only by explicit design; every shutdown (re)transmission carries a fresh closing nonce and the sign-once latch prevents one nonce from signing two sighashes. D3. The recovery journal must NOT persist these fields: persisting a secret closing nonce and reviving it after restart against a different closing fee would be exactly the nonce reuse this section forbids.
- `lastCooperativeCloseTxHex`: a fully-signed transaction, not a live session. D1 as an ordinary `channel_state` mutation, as today.

The matrix must additionally enumerate, each with a disposition and a Phase 7 kill-point test: interactive transaction construction and `tx_signatures` for splice (`src/lightning/message/interactive-tx.ts` and the splice paths in `channel-manager.ts`), splice RBF negotiation, on-chain wallet UTXO selection and change state backing a pending funding or splice, chain monitor pending sweep and justice transactions, temporary channel ID to permanent ID promotion, held or intercepted HTLC decisions, and every retransmittable message that is not covered by the commitment rows in 5.9. Prose classification is not acceptance; each disposition is enforced by a test that kills the process inside the session and asserts the disposition's outcome.

## 6. What this feature does and does not guarantee

Answering the key product question: does this allow safely restoring channels on a new device even if the old device might come back online?

Yes, in quorum mode, with these precise semantics:

1. The new device restores exact state and resumes channels without force-closes (Tier 2/3).
2. The old device, being a compliant beignet instance, is fenced: it cannot advance any channel past a state the guardians have certified for the new epoch, and with the startup quarantine rule it freezes before touching the Lightning protocol at all.
3. The guarantee is against split-brain between compliant instances, not against a malicious actor holding the old device's keys. If the old device maliciously broadcasts its stale (revoked) commitment, the standard penalty mechanism and the existing watchtower client punish it; the channel closes but the mechanism is the same one Lightning already relies on.
4. In async-remote mode the same recovery works but fencing is eventual: there is a window where a revived stale device could act before learning its epoch is dead. In local mode there is no fencing.

These distinctions must appear in user-facing documentation and in the API docs of `RecoveryDurability`.

## 7. Interactions with existing subsystems

- SCB: unchanged and always maintained. The capsule embeds it, so Tier 1 recovery never regresses.
- Storage encryption at rest (`'beignet-storage-encryption-v1'`): orthogonal; journal ciphertext is additionally encrypted with recovery keys because replicas leave the device.
- Watchtower: unchanged. Do not conflate guardian and watchtower trust models (3.7).
- peer_storage server side: unchanged; beignet keeps honoring `option_provide_storage` for peers.
- Forwarding: beignet forwards unconditionally today; forwarded HTLC consistency (5.1) is therefore not optional.

## 8. Public API and configuration surface

Library (all additive, default off):

```ts
interface RecoveryConfig {
  enabled: boolean;                    // default false
  durability: RecoveryDurability;      // default 'async-remote' when enabled
  guardians?: GuardianDescriptor[];    // absent = peer_storage checkpoints only
  profile?: 'crash-v1';                // the only accepted value in v1 (12.1)
  snapshotIntervalFrames?: number;
}

// LightningNode additions
node.getRecoveryStatus(): RecoveryStatus;    // tier, lastDurableSequence, guardian health, per-channel ChannelRecoveryStatus
node.restoreFromRecoveryReplicas(opts): Promise<RestoreReport>;
events: 'recovery:durable', 'recovery:guardian_unreachable', 'recovery:fenced', 'recovery:restored'
```

CLI daemon (`src/cli/`), for embedders such as beignet-umbrel, following the existing `BEIGNET_*` env convention:

```text
BEIGNET_RECOVERY_MODE = off | peer-storage | async-remote | quorum
BEIGNET_RECOVERY_GUARDIANS = comma-separated guardian URIs
BEIGNET_RECOVERY_PROFILE = crash-v1 (the only accepted value in v1; no
free-form quorum tuples, per 12.1)
```

Plus REST endpoints on the daemon: `GET /recovery/status`, `POST /recovery/restore`.

## 9. Implementation phases and acceptance criteria

Phase order is deliberate: crash-consistency foundations before replication, replication before fencing, fencing before strict barriers.

Phase 1: safety transitions + durable outbox.
Done when: every safety-critical write path routes through `RecoveryManager.commit`; `persistChannel` is atomic; monitor deltas ride with their causal channel transition; fulfill/forward transitions are atomic; outbox table exists and reestablish retransmission can serve exact bytes; all existing tests pass; new unit tests assert atomicity by crashing (throwing) mid-transition and verifying all-or-nothing visibility.

Phase 2: recovery journal + snapshots + deterministic reconstruction.
Done when: frames are emitted for every transition; property tests prove `reconstructFromFrames` rebuilds a byte-identical DB from any prefix ending at a snapshot boundary plus deltas; compaction never breaks reconstruction; a corrupted or reordered frame is detected.

Phase 3: Recovery Capsule over peer_storage.
Done when: capsules are composed, padded, distributed, and refreshed within rate limits; a restore integration test (model on `tests/lightning/scb-restore.test.ts` and the regtest interop tests) restores a small node from capsules alone and resumes a channel via reestablish; oversized state degrades gracefully to SCB + locator capsule.

Phase 4: guardian protocol + reference guardian.
Done when: a reference guardian implementation (usable in tests, runnable standalone) enforces the invariants in 5.5, including the durability invariants; receipts verify and are cumulative; a restore test resumes from guardian replicas; the truncation attack (stale replica serving a shorter valid chain) is defeated by head verification; a backfill test repairs a lagging guardian through SYNC_RECORD and a missed takeover through SYNC_EPOCH; durability tests SIGKILL the reference guardian between accept and receipt and again after receipt, restart it, and prove no acknowledged state was lost and that a guardian with a damaged store refuses writes until repaired; the exact wire specification exists as `docs/RECOVERY-GUARDIAN-WIRE.md` (canonical encodings and endianness, hash and signature algorithms, domain separation tags for every signed object, AEAD choice and nonce construction, version negotiation, request idempotency and replay rules, maximum object sizes, error codes, transport authentication); the written comparison against LDK's Versioned Storage Service (section 12) is completed before the transport decision.

Phase 5: writer epochs + startup quarantine.
Done when: epoch acquisition works as a CAS takeover; a two-instance test proves the stale instance freezes before sending any channel message; a takeover-race test has the old writer append a certified state between the restoring device's head fetch and its `ACQUIRE_EPOCH`, and asserts the CAS fails, the retry lands on the newer head, and the restored state includes it; a divergent-head restore test (one guardian unreachable, one guardian stale) proves head reconciliation, SYNC_RECORD repair, and CAS takeover on the repaired quorum per the 5.7 worked example; a lagging-guardian test proves SYNC_EPOCH adopts the certified takeover head and discards an uncommitted superseded-epoch tail above it; a sub-quorum restore attempt refuses the takeover; quarantine holds channels until ownership confirmation; all `ChannelRecoveryStatus` branches have tests, including `ReplayRequired` serving outbox bytes, `LocalDataLoss` routing to the existing DLP path, and `StateUncertain` provably never broadcasting the stored commitment.

Phase 6: quorum barriers.
Done when: in quorum mode, no revoke_and_ack, fulfill, or irreversible splice message precedes its quorum receipt; guardian latency does not stall unrelated channels or non-critical writes; appends pipeline and receipts are cumulative (a delayed receipt for frame N adds no per-frame round trip, and a single receipt at or above N releases every barrier at or below it); barrier timeout behavior (freeze, not proceed) is tested.

Phase 7: chaos testing.
Done when: a harness (extending the existing teardown/reconstruct restart pattern in the interop tests, plus process-level SIGKILL for the CLI daemon) kills the node before and after every DB commit, guardian ACK, and socket send around commitment_signed, revoke_and_ack, fulfill, fail, splice, and reconnect, and inside every ephemeral signing session classified in 5.10, across all three durability modes, and every run ends in exact resumption or provably safe DLP fallback, never a broadcastable stale state, never a lost preimage for a forwarded HTLC, and never a secret nonce signing two different sighashes across a restart.

Tests: mocha + ts-node under `tests/lightning/` per repo convention; interop scenarios under `tests/lightning/interop/` against real LND/CLN/Eclair peers, since reestablish/DLP behavior against other implementations is the actual acceptance bar.

## 10. Non-goals

- No change to SCB format or behavior (fallback only).
- No merging of guardian and watchtower protocols.
- No dependency on eltoo/ANYPREVOUT (BIP 118 remains Draft); this design targets penalty channels as they exist.
- No Byzantine fault tolerance in v1 (documented crash-fault model; format leaves room to upgrade).
- No multi-writer operation; exactly one writer per epoch, ever.

## 11. Open questions for design review

1. DECIDED (revision 4, see 12.1): guardian transport is HTTP/protobuf over v3 onion services plus HTTPS/protobuf over clearnet, both first-class and normative; BOLT 8 custom messages are not the v1 transport (a later optional adapter stays possible because the signed objects are transport-neutral). Unchanged either way: `PUT_STATE` and `ACQUIRE_EPOCH` are linearized per node through one state machine (5.5); no transport may relax that.
2. DECIDED (revision 4, recorded in docs/RECOVERY-GUARDIAN-WIRE.md section 3): AES-256-GCM everywhere, uniform with storage (3.6), the journal (5.3) and the capsule (5.4). XChaCha20-Poly1305 was acceptable but uniformity won, and nothing about the guardian protocol depends on the choice: guardians never decrypt.
3. Whether `async-remote` should auto-escalate specific transitions (first revocation after restore, splice commitment) to quorum semantics when guardians are configured.
4. Capsule refresh policy when a node has many storage peers: same capsule to all, or head-only to some to reduce write amplification.
5. Guardian economics and deployment (who runs them) is out of scope for the library but the descriptor format should not preclude LSP-hosted, self-hosted, or paid third-party guardians.
6. Guardian receipt-key rotation: how a guardian rotates its signing key without invalidating stored receipts and takeover certificates, and how the descriptor format carries key generations.
7. DECIDED (revision 4, docs/RECOVERY-GUARDIAN-WIRE.md 5.2): GET_HEAD always returns the bundle, the current cumulative receipt plus the takeover certificates for prior epochs. That is one receipt and at most one certificate per superseded epoch, small enough that a second round trip is never worth the ambiguity.

## 12. Prior art and standardization path

Added in revision 3, prompted by an external design review.

Prior art that must shape Phase 4, not be discovered after it:

- LDK's `ChannelMonitorUpdateStatus::InProgress` is the established form of the persistence barrier in 5.8: channel processing freezes until durable persistence completes. Already cited there; the quorum barrier is that contract with a remote acknowledgment added.
- LDK's Versioned Storage Service (VSS, `lightningdevkit/vss-server`) is the closest existing service to the guardian protocol: client-side encrypted, versioned key-value storage with a strongly consistent API, per-object versions, a global-version compare-and-swap, and atomic multi-item puts. What VSS does not provide today: signed monotonic receipts, quorum acknowledgment across independent operators, takeover certificates, and the record-level self-authentication that backfill requires. Before the Phase 4 transport decision, produce a written comparison that either expresses the guardian verbs as a VSS extension or states precisely which requirements VSS cannot express and why. Shipping an incompatible service without that analysis is the kind of ecosystem fragmentation reviewers will rightly object to. Completed in revision 4: see 12.2.

Standardization path, if any of this is later proposed upstream. Three separable pieces, deliberately not one monolith:

1. Recovery Capsule over BOLT 1 `peer_storage` (5.4): capsule versioning, encryption, padding, refresh semantics. Narrow, transport-level, interoperable.
2. Versioned guardian storage with writer-epoch fencing (5.5, 5.6): records, receipts, takeover certificates, backfill, durability obligations. Strongest standalone candidate, ideally aligned with or extending VSS.
3. An informational safety contract for exact-state recovery: persist before send, recover before connect, fence before signing, reconcile through `channel_reestablish`, never guess uncertain state, fall back to DLP when exactness is unprovable. Implementation-neutral by construction.

The `RecoveryMutation` schema, the SQLite reconstruction, and everything else in 5.1-5.3 stay implementation-specific and are explicitly out of scope for any standard; other implementations would journal their own opaque encrypted records through the same guardian protocol.

### 12.1 Decision record: guardian transport and architecture (revision 4)

Settled before Phase 4 implementation, as section 9 requires. Ratified on the tracking issue 2026-07-31; this section is the authoritative home. The exact bytes live in docs/RECOVERY-GUARDIAN-WIRE.md.

1. Transports, all first-class and normative: HTTP/protobuf over a v3 onion service, and HTTPS/protobuf over clearnet. BOLT 8 custom messages are NOT the guardian transport in v1: the 65535-byte message cap forces bespoke chunking, reassembly and flow control, and connection-level authentication adds nothing to a safety model that rests on writer signatures and epoch binding (5.5). A BOLT 8 adapter can come later precisely because the signed wire objects are transport-neutral. Onion endpoints keep Tor-only nodes (and beignet-umbrel) fully served with no exit relay: onion services provide end-to-end encryption and authenticate the service through the address itself, so TLS is not required inside Tor. Clearnet endpoints require TLS. Application-layer verification of receipts against the guardian's public key is the real gate on every transport; transport authentication is defense in depth, for anti-DoS and privacy.
2. Guardians advertise endpoint lists (onion-http, https, local-http). A Tor-enabled wallet strictly prefers the onion endpoint; reaching a clearnet-only guardian through an exit relay remains possible, with the payload protected by TLS and the destination visible to the exit. A local guardian (Umbrel: a listener on 127.0.0.1 behind a HiddenServicePort mapping) is a supported deployment. The reference 2-of-3 arrangement is the user's own Umbrel guardian plus an LSP onion guardian plus an independent onion guardian.
3. The signed wire objects (records, receipts, epoch acquisition requests, takeover certificates) never embed URLs or transport details: the same objects ride onion HTTP, clearnet HTTPS, a LAN connection, or a future BOLT 8 adapter.
4. The guardian is a VSS semantic extension, a VSS-compatible sibling service, never a client-side convention over generic VSS: a generic global-version compare-and-swap fences VERSIONS, not WRITERS; only a server-enforced epoch state machine revokes a superseded writer's lease permanently, and the receipt must be a signed, durable, cumulative object persisted in the same transaction as the record (see 12.2).
5. Fault model v1: the named profile crash-v1 (2-of-3, crash-fault) only. No free-form quorum tuples. Product language says CFT quorum recovery, never trustless.
6. Byzantine-ready encoding without Byzantine claims: guardian_set_id in every signed object, and certificate formats able to carry multiple signatures, so a future quorum system with proper intersection (for example 3-of-4) slots in without a wire break.
7. Signing: canonical fixed-width transcripts under BIP340 tagged hashes, all keys 32-byte x-only; protobuf bytes are never signed, because protobuf serialization is not canonical. Receipts bind the record's frame hash AND the ciphertext hash, so retention is provable and attributable. Writer keys are fresh random per-epoch keys, never the node identity key and never seed-derived: a superseded device's writer key must die with it, and the seed alone must not be able to forge records for old epochs. Every request type is semantically idempotent.
8. Registration and namespace (revision 4 review): a dedicated seed-derived recovery root (info string 'beignet-recovery-root-v1') owns the guardian namespace. Its x-only public key IS the recovery_id; it authorizes REGISTER_NODE and co-signs every ACQUIRE_EPOCH, and it never signs records. This closes the genesis gap (nothing was defined between an empty guardian and a usable node) and keeps the Lightning node id out of the guardian protocol entirely.
9. Guardian-set replacement is UNSUPPORTED in protocol v1, literally (third review round; docs/RECOVERY-GUARDIAN-WIRE.md 5.9). A node MUST NOT begin a journal for its recovery_id under a second guardian set while journaled state exists under a first; exactly one set ever carries a namespace's journal in v1, and loss or replacement of the configured set degrades recovery to the SCB/DLP path until ROTATE_SET exists. The structural reason beyond the transcript binding: writerEpoch and sequence order states WITHIN one set, peer_storage may serve stale capsules, so after any two-set period the restore selection could prefer a stale old-set capsule, and nothing fences the old set because a stale device holds the seed and therefore the recovery root. Only a root-signed monotonic set-generation object (ROTATE_SET, future version) resolves that. First-time enablement on an existing node is NOT a replacement and is supported via the wire spec's chain-origin rule. The earlier claims (revision 4 first draft: "a fresh epoch acquisition under the new set id"; second draft: non-genesis registration plus backfill; third draft: new-set genesis plus migration snapshot) were each unimplementable or unsound as stated and are superseded.

### 12.2 Versioned Storage Service comparison (revision 4)

The written comparison section 9 requires before the transport decision. Conclusion first: the guardian protocol cannot be expressed as a client-side convention over generic VSS, and ships as a VSS-compatible sibling: the same deployment shape (client-encrypted, versioned, strongly consistent storage), plus four semantic extensions VSS would have to adopt server-side.

Verb mapping:

```text
guardian verb     closest VSS operation      what VSS cannot express today
PUT_STATE         putObjects (atomic put)    a signed cumulative receipt issued
                                             durably and atomically with the
                                             write; epoch and writer-key
                                             acceptance; sequence and
                                             previous-hash continuity
GET_HEAD          getObject (head key)       a signed head; takeover
                                             certificates; possibly-stale
                                             signaling from an uncertain store
GET_STATE         listKeyVersions + get      nothing fundamental; pagination
                                             maps directly
ACQUIRE_EPOCH     global-version CAS         the CAS fences a VERSION, not a
                                             WRITER: nothing permanently
                                             revokes the superseded writer, and
                                             no signed takeover certificate
                                             exists
SYNC_RECORD       putObjects by a 3rd party  record-level VERIFICATION: a
                                             restored client may well hold the
                                             storage credentials, but generic
                                             VSS cannot check writer signature,
                                             epoch binding and chain position
                                             before accepting a repair, so it
                                             cannot safely accept third-party
                                             submissions
SYNC_EPOCH        (no equivalent)            threshold-verified adoption of a
                                             missed takeover
```

The four server-side extensions, precisely:

1. Signed monotonic cumulative receipts, made durable before the response leaves (5.5 durability invariants).
2. Writer-epoch fencing as a server-enforced state machine, linearized with writes per node, permanently rejecting superseded epochs and issuing signed takeover certificates (5.5, 5.6).
3. Record-level self-authentication, writer signatures over canonical transcripts, so backfill by a restore device works after the original writer's key is gone (5.5).
4. Quorum acknowledgment across INDEPENDENT operators as a client-side barrier discipline: the client counts receipts from distinct guardians of one committed set; VSS assumes a single service.

What stays deliberately VSS-shaped so upstream alignment remains realistic: the server is blind to plaintext; one keyspace per node; strongly consistent read-your-writes per store; atomic multi-item semantics (record plus head advance in one transaction); and a compare-and-swap at the center of ownership transfer. The reference guardian implementation SHOULD additionally reuse VSS deployment conventions where practical (HTTP service shape, authentication hooks, a transactional SQL store, rate limiting), and non-local deployments require authenticated access exactly as hosted VSS guidance does; open operation is reserved for local development. If VSS later grows the four extensions, the guardian verbs become a VSS profile and the transcripts in docs/RECOVERY-GUARDIAN-WIRE.md port unchanged, because they never depended on the envelope.
