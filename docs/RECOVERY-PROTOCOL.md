# Feature request: Beignet Recovery Protocol

Replicated, cryptographically versioned state continuity for Lightning channels, with channel-preserving restore and split-brain fencing.

Status: proposed, not started
Revision 2 (2026-07-23): epoch acquisition is now a compare-and-swap takeover and restoration fences before reconstructing; reestablish is described as a consistency gate, not a proof of exact recovery; uncertain recovery states may never broadcast the stored local commitment
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
- Safety-critical tables: `channels`, `chain_monitors`, `preimages`, `htlc_payment_map`, `forwarded_htlcs`, `htlc_shared_secrets`, `channel_key_indices`, `payments`, `payment_secrets`. Also relevant: `peer_storage_blobs`, `watchtower_sessions`, `watchtower_updates`. Schema version constant `CURRENT_SCHEMA_VERSION = 9`.

### 3.2 Known atomicity gaps (must be fixed by Phase 1)

- `LightningNode.persistChannel` (`src/lightning/node/lightning-node.ts`, around lines 1207-1230) calls `saveChannel(...)` then `saveChannelKeyIndex(...)` as two separate statements, not wrapped in `transaction()`.
- Chain monitor state is persisted through a completely independent path: the `monitor:updated` event listener calls `saveChainMonitor` (around lines 1552-1563). A channel and its chain monitor are never written atomically together.
- `transaction()` is used in some payment/forward paths (for example `persistPayment` + `saveHtlcPaymentMapping` around line 6850, and others near 7149, 7726, 8374, 8897, 9233), but no transaction spans `saveChannel` + `saveChainMonitor`.

### 3.3 The persist-before-send invariant is implicit, not structural

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
                                  signed RecoveryHead
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
  | { type: 'channel_state'; channelId: string; state: Buffer }
  | { type: 'channel_key_index'; channelId: string; channelIndex: number }
  | { type: 'chain_monitor'; channelId: string; state: Buffer }
  | { type: 'payment_preimage'; paymentHash: string; preimage: Buffer }
  | { type: 'htlc_payment_mapping'; htlcKey: string; paymentHash: string }
  | { type: 'htlc_shared_secret'; key: string; secret: Buffer }
  | { type: 'forwarded_htlc'; outKey: string; inChannelId: string; inHtlcId: bigint }
  | { type: 'delete_forwarded_htlc'; outKey: string }
  | { type: 'payment_state'; paymentHash: string; payment: Buffer }
  | { type: 'splice_state'; channelId: string; state: Buffer }
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

New table (schema migration to version 10): `recovery_outbox(id INTEGER PRIMARY KEY, peer_pubkey, channel_id, message_type, wire_message BLOB, disposition, frame_sequence)`.

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
  ciphertext: Buffer;       // XChaCha20-Poly1305 or AES-256-GCM
}
```

Key derivation (new info strings, verified non-colliding with 3.6):

```text
recovery_master_key = HKDF-SHA256(seed, info = 'beignet-recovery-v1')
per_epoch_key       = HKDF-SHA256(recovery_master_key, info = 'beignet-recovery-frame-v1' || nodeId || writerEpoch)
```

AEAD associated data must bind `(nodeId, writerEpoch, sequence, previousFrameHash)` so frames cannot be transplanted across epochs or positions.

Honest scoping of the hash chain: a hash chain detects tampering and reordering relative to a known tip. It does not by itself prevent rollback: a stale or malicious replica can serve a truncated but internally valid chain. Anti-rollback comes from the externally anchored `RecoveryHead` (guardian receipts, 5.6). Without guardians, peer_storage checkpoints give best-effort recency and `channel_reestablish` remains the safety net. Document this in the module docs exactly this way.

Snapshots and compaction: periodically emit a full-state snapshot frame (all safety-critical tables serialized), then prune deltas older than the last snapshot. Snapshot cadence adaptive: after N frames or M bytes of deltas.

New tables: `recovery_frames(sequence PRIMARY KEY, writer_epoch, frame_hash, previous_hash, ciphertext, created_at)` and `recovery_meta(key, value)` for the current epoch, tip hash, and snapshot sequence.

Deterministic reconstruction: `reconstructFromFrames(snapshot, deltas)` rebuilds every safety-critical table byte-identically. This must be property-tested (section 10).

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

Encryption: HKDF info `'beignet-recovery-capsule-v1'`, then the existing `padOwnPeerStorageBlob` framing (no size leak). Push via the existing `distributePeerStorage`; refresh on every snapshot, on guardian-set change, and at most once per minute to respect provider rate limits.

For small wallets (one or two channels), the complete recovery state will often fit inline, making Tier 2 restore possible from peer_storage alone with zero new infrastructure. That alone justifies Phase 3 shipping before guardians exist.

Restore side: on reconnect after seed restore, collect `'peer_storage:retrieved'` blobs from all storage peers, decrypt all candidate capsules, and select the highest `(writerEpoch, sequence)` whose hash chain validates. BOLT 1 requires providers to return the blob early after reconnection, before normal channel recovery, which is exactly the window this needs.

### 5.5 Guardian protocol (Phase 4)

A guardian is a minimal blob store with one nontrivial duty: signed, monotonic receipts.

```ts
export interface GuardianPut {
  nodeId: Buffer;
  epoch: bigint;
  writerPublicKey: Buffer;   // see 5.6
  sequence: bigint;
  previousHash: Buffer;
  frameHash: Buffer;
  ciphertext: Buffer;        // opaque to the guardian
  writerSignature: Buffer;
}

export interface RecoveryHead {
  nodeId: Buffer;
  writerEpoch: bigint;
  writerPublicKey: Buffer;
  sequence: bigint;
  frameHash: Buffer;
}

export interface GuardianReceipt {
  guardianId: Buffer;
  head: RecoveryHead;        // guardians sign exactly this tuple
  signature: Buffer;
}
```

Epoch acquisition is a compare-and-swap takeover, not a bare increment:

```ts
export interface AcquireEpochRequest {
  nodeId: Buffer;
  expectedHead: RecoveryHead;   // CAS guard: the head the caller reconciled
  newEpoch: bigint;             // must equal expectedHead.writerEpoch + 1
  newWriterPublicKey: Buffer;
}

export interface TakeoverCertificate {
  guardianId: Buffer;
  takeoverHead: RecoveryHead;   // the now-immutable FINAL head of the superseded epoch
  newEpoch: bigint;
  newWriterPublicKey: Buffer;
  signature: Buffer;
}
```

Guardian invariants (enforced server-side):

```text
accept PUT_STATE iff:
  epoch == current epoch for nodeId
  writerPublicKey == the writer bound to that epoch
  sequence == stored sequence + 1
  previousHash == stored frameHash
reject everything else, including any write from a superseded epoch

accept ACQUIRE_EPOCH iff:
  expectedHead == the guardian's current stored head for nodeId
  newEpoch == expectedHead.writerEpoch + 1
on mismatch: reject and return the current head so the caller can
refetch and retry the CAS

PUT_STATE and ACQUIRE_EPOCH for one nodeId are linearized through a
single per-node state machine. A takeover and an old-epoch append can
never interleave, and once a takeover commits, the superseded epoch's
head is immutable forever. This is a hard requirement, not an
implementation detail: if the two verbs were independent database
operations, a still-live old writer could append a certified state
concurrently with a takeover, and the two sides would disagree about
the final head of the superseded epoch.
```

Verbs: `PUT_STATE`, `GET_STATE`, `GET_HEAD`, `ACQUIRE_EPOCH`. Transport: either a dedicated authenticated protocol or BOLT 8 custom messages to a guardian node; decide during Phase 4 design review (open question 11.1). Whichever transport is chosen, it must preserve the per-node linearization above.

The signed `RecoveryHead` is the anti-rollback anchor missing from a bare hash chain: a restoring device fetches heads from the quorum and refuses any replica whose tip is behind the highest quorum-certified head.

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

`ACQUIRE_EPOCH` (used at first setup and at every restore): the device generates a fresh ephemeral writer key, queries heads from the guardians, reconciles the highest quorum-consistent head, and issues `AcquireEpochRequest` with that head as the CAS guard (5.5). If any guardian reports a newer head, the CAS fails, the device refetches, and retries. On quorum certification the device holds a set of `TakeoverCertificate`s fixing the superseded epoch's final head, and the guardians permanently reject all writes from prior epochs. Binding the epoch to a writer public key (not just a number) prevents a second device from racing into the same epoch; binding acquisition to `expectedHead` prevents the fetch-then-fence race described in 5.7.

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
ACQUIRE_EPOCH(expectedHead): compare-and-swap takeover (5.5, 5.6)
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

Before writing Phase 1 code, produce `docs/RECOVERY-TRANSITION-MATRIX.md` enumerating every site that sends or receives `commitment_signed`, `revoke_and_ack`, `update_add_htlc`, `update_fulfill_htlc`, `update_fail_htlc`, `update_fail_malformed_htlc`, `channel_reestablish`, and splice messages, and for each: what must be atomically persisted, at what criticality, before which wire message. Starting anchor list (verified, re-check lines):

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
  quorum?: { required: number; total: number };  // default 2-of-3
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
BEIGNET_RECOVERY_QUORUM = e.g. 2/3
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
Done when: a reference guardian implementation (usable in tests, runnable standalone) enforces the invariants in 5.5; receipts verify; a restore test resumes from guardian replicas; the truncation attack (stale replica serving a shorter valid chain) is defeated by head verification.

Phase 5: writer epochs + startup quarantine.
Done when: epoch acquisition works as a CAS takeover; a two-instance test proves the stale instance freezes before sending any channel message; a takeover-race test has the old writer append a certified state between the restoring device's head fetch and its `ACQUIRE_EPOCH`, and asserts the CAS fails, the retry lands on the newer head, and the restored state includes it; quarantine holds channels until ownership confirmation; all `ChannelRecoveryStatus` branches have tests, including `ReplayRequired` serving outbox bytes, `LocalDataLoss` routing to the existing DLP path, and `StateUncertain` provably never broadcasting the stored commitment.

Phase 6: quorum barriers.
Done when: in quorum mode, no revoke_and_ack, fulfill, or irreversible splice message precedes its quorum receipt; guardian latency does not stall unrelated channels or non-critical writes; barrier timeout behavior (freeze, not proceed) is tested.

Phase 7: chaos testing.
Done when: a harness (extending the existing teardown/reconstruct restart pattern in the interop tests, plus process-level SIGKILL for the CLI daemon) kills the node before and after every DB commit, guardian ACK, and socket send around commitment_signed, revoke_and_ack, fulfill, fail, splice, and reconnect, across all three durability modes, and every run ends in exact resumption or provably safe DLP fallback, never a broadcastable stale state and never a lost preimage for a forwarded HTLC.

Tests: mocha + ts-node under `tests/lightning/` per repo convention; interop scenarios under `tests/lightning/interop/` against real LND/CLN/Eclair peers, since reestablish/DLP behavior against other implementations is the actual acceptance bar.

## 10. Non-goals

- No change to SCB format or behavior (fallback only).
- No merging of guardian and watchtower protocols.
- No dependency on eltoo/ANYPREVOUT (BIP 118 remains Draft); this design targets penalty channels as they exist.
- No Byzantine fault tolerance in v1 (documented crash-fault model; format leaves room to upgrade).
- No multi-writer operation; exactly one writer per epoch, ever.

## 11. Open questions for design review

1. Guardian transport: dedicated TLS/Noise service vs BOLT 8 custom messages to guardian Lightning nodes. The latter reuses connection code and Tor routing; the former is simpler to host. Decided regardless of transport: `PUT_STATE` and `ACQUIRE_EPOCH` are linearized per node through one state machine (5.5); the transport choice may not relax that.
2. AEAD choice for frames: XChaCha20-Poly1305 vs staying uniform with the existing AES-256-GCM. Uniformity has maintenance value; either is acceptable.
3. Whether `async-remote` should auto-escalate specific transitions (first revocation after restore, splice commitment) to quorum semantics when guardians are configured.
4. Capsule refresh policy when a node has many storage peers: same capsule to all, or head-only to some to reduce write amplification.
5. Guardian economics and deployment (who runs them) is out of scope for the library but the descriptor format should not preclude LSP-hosted, self-hosted, or paid third-party guardians.
