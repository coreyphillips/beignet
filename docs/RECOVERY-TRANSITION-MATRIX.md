# Recovery Protocol: safety transition matrix

Companion to [RECOVERY-PROTOCOL.md](./RECOVERY-PROTOCOL.md), required by its
section 5.9 before Phase 1 code. It enumerates every site that sends or
receives a state-machine-critical message, what must be atomically persisted
there, at what criticality, and before which wire message; and it classifies
every ephemeral signing session and transient state item per section 5.10.

Line anchors are as of the Phase 1 implementation. They drift; the function
names are the durable reference.

## 1. How Phase 1 enforces the ordering

Before Phase 1, "persist before send" was an ordering convention: each handler
had to return `PERSIST_STATE` ahead of its `SEND_MESSAGE` actions, and
`processActions` dispatched them in array order. Nothing checked it, and
several handlers returned a send with no persist at all.

Phase 1 makes it structural, in three parts:

1. `ChannelManager.processActions` (`channel-manager.ts:4378`) collects every
   retransmittable `SEND_MESSAGE` that FOLLOWS the batch's `PERSIST_STATE` and
   hands the exact bytes to the persist listener as an `IChannelPersistRequest`.
2. `LightningNode.persistChannel` (`lightning-node.ts:1325`) commits the channel
   state, its key index, any chain monitor delta this same action produced, any
   mutations the caller staged, AND the outbox rows for those messages in ONE
   `RecoveryManager.commit` transaction.
3. If that transaction rolls back, the request comes back `committed: false` and
   `_dispatchActions` (`channel-manager.ts:4450`) withholds the sends it
   authorized. A message whose justifying state is not on disk never reaches
   the peer. The gate covers `BROADCAST_TX` and `FORCE_CLOSE` too: a splice or
   funding transaction whose justifying state missed disk must not reach the
   network either.

A batch commits exactly once, no matter how many `PERSIST_STATE` markers it
carries. Channel methods mutate state while BUILDING the action array, so every
marker in one batch describes identical state; the flows composed from helpers
that each lead with their own persist (v2 open, splice signing) would otherwise
re-commit the same outbound list per marker and duplicate its outbox rows.

Outbox rows are retired transactionally, never eagerly. The supersede that a
peer's `revoke_and_ack` proves is staged by `handleRevokeAndAck` and rides the
SAME commit as the revoke's channel state (an `outbox_supersede` mutation): on
rollback the rows survive alongside the pre-revoke state that still needs them.
`splice:complete` retires the splice negotiation rows (`splice`/`splice_ack`),
which nothing else ever acknowledges.

A blocked transition does not stall silently. The withheld messages are gone
from that connection (nothing re-queues them); the reestablish exchange after a
reconnect is what retries the persist and replays them from durable state. So
`transition:blocked` fires and the node forces the disconnect, rather than
leaving a live connection deadlocked on the peer's own timeout.

Causally linked caller-side state joins the transition through
`withStagedMutations` (`lightning-node.ts:1449`): a preimage staged before
`fulfillHtlc`, a forward linkage staged before `addHtlc`. Anything still staged
when the call returns is committed on its own, so nothing is silently dropped.

The gate covers RECONNECTS too, not only first sends. `handleReestablish`
returns a leading `PERSIST_STATE` whenever it retransmits, because its replays
are built from in-memory state: without it, a transition whose commit failed
would still reach the peer on the next reconnect, one connection later than the
gate that withheld it. Replayed sends are marked `replay` so they are withheld
on a failed persist like any other, but are not written to the outbox a second
time; the row from the original send is already there.

Failure has one more rule. When a channel transition rolls back, its chain
monitor delta is re-armed but explicitly NOT flushed on its own
(`monitorsAwaitingChannel`): committing it alone would put the revocation on
disk while the channel state that caused it stayed behind, which is the exact
disagreement 5.1 exists to prevent. The hold is not a dead end: the next
standalone monitor attempt (the next block, in practice) retries it as a
COMBINED channel+monitor commit, so one transient storage error on a closing
channel cannot park sweep and justice progress until a channel message that
never comes.

## 2. The matrix

Criticality per spec 5.1: `SafetyCritical` is journaled and, from Phase 6,
barrier-gated; `Important` is journaled but never blocks the protocol.

| Site | Location | Atomically persisted | Criticality | Before which message |
|---|---|---|---|---|
| recv `commitment_signed` → send `revoke_and_ack` | `channel.ts:2826` handleCommitmentSigned tail | channel state (advanced local commitment number, revealed secret cache, HTLC state transitions) + monitor delta + `revoke_and_ack` outbox row | SafetyCritical | `revoke_and_ack` |
| send `commitment_signed` | `channel.ts` sendCommitmentSigned tail (returns PERSIST_STATE as of Phase 1) | channel state (remote commitment number, `lastSentCommitmentSigned`, `lastSentPartialSignatureWithNonce`, signed-update count) + `commitment_signed` (and `start_batch` + splice half, when batched) outbox rows | SafetyCritical | `start_batch`, `commitment_signed` |
| recv `revoke_and_ack` | `channel-manager.ts:2244` handleRevokeAndAck | channel state (shachain secret, balance credit, HTLC removals) + monitor delta (revoked remote commitment) | SafetyCritical | any follow-up `commitment_signed`; watchtower kit generation stays out of band |
| send `update_add_htlc` | `channel.ts:1658` addHtlc | channel state (HTLC entry, `pendingLocalUpdates` retransmission entry, `needsCommitment`) + staged forward linkage + `update_add_htlc` outbox row | SafetyCritical | `update_add_htlc` |
| send `update_fulfill_htlc` | `channel.ts:2068` fulfillHtlc | staged preimage + staged linkage teardown + channel state + `update_fulfill_htlc` outbox row | SafetyCritical | `update_fulfill_htlc` |
| send `update_fail_htlc` | `channel.ts:2223` failHtlc | channel state (HTLC → FAILED, queued retransmission entry) + outbox row | Important | `update_fail_htlc` |
| send `update_fail_malformed_htlc` | `channel.ts:2302` failMalformedHtlc | same as `update_fail_htlc` | Important | `update_fail_malformed_htlc` |
| send `update_fee` | `channel.ts:3333` updateFee | channel state (pending feerate, queued retransmission entry) + outbox row | Important | `update_fee` |
| forward linkage | `lightning-node.ts:9820` performForward | `forwarded_htlc` linkage staged into the outgoing `addHtlc` transition | SafetyCritical | outgoing `update_add_htlc` |
| on-chain preimage → off-chain settle | `lightning-node.ts:9918` handleOnChainPreimageLearned | preimage staged into the fulfill transition | SafetyCritical | `update_fulfill_htlc` |
| receive-side settle | `lightning-node.ts:9537` fulfillPayment | payment record + consumed payment secret staged into the fulfill transition | SafetyCritical | `update_fulfill_htlc` |
| DLP detection | `channel.ts:5644` handleReestablish (`dataLossDetected` at 5696) | channel state with `dataLossDetected` + ERRORED | SafetyCritical | the wire `error`; the no-broadcast rule must survive any crash |
| reestablish retransmit decision | `channel.ts:5644` handleReestablish | channel state (restored state, adopted remote nonce, splice resumption) persists BEFORE any replay goes out; reads `pendingLocalUpdates` and `lastSentWasRevoke` from persisted state; exact batch bytes come from the outbox via `restoreLastSentBatch` (`channel.ts:2804`) | SafetyCritical | every retransmitted message |
| splice transitions | `channel-manager.ts:3442` handleSpliceMsg / Ack / Locked, `channel.ts:5428` _handleReestablishSplice | channel state (`spliceInFlight`, `spliceHistory`) + splice message outbox rows | SafetyCritical | `splice_ack`, `splice_locked`, splice `commitment_signed` |
| chain monitor, causally tied | `monitor:updated` inside an open `processActions` batch | rides in that channel's transition | SafetyCritical | whatever that batch sends |
| chain monitor, standalone | `monitor:updated` outside a batch (new block, funding spend) | own transition via `persistMonitorAlone` (`lightning-node.ts:1507`) | SafetyCritical | n/a |
| channel restore | `lightning-node.ts:2984` recoverFromStaticChannelBackup | unchanged; remains the `LocalDataLoss` fallback branch | SafetyCritical | n/a |

## 3. Ephemeral signing sessions and transient state (spec 5.10)

Dispositions: **D1** persist-before-emit (or deterministically re-derivable
from state that is), **D2** retransmit-exact (session not restored; the outbox
serves the prior bytes), **D3** abandon-and-restart (dies with the process by
design), **D4** force-close.

| Item | Location | Disposition | Why |
|---|---|---|---|
| Taproot verification nonces (`localNonce`, `localNextNonce`) | `channel-state.ts:454-464`, derived by `channel.ts:800` `_deriveVerificationNonce` | D1 by determinism | Deterministic per commitment height from the persisted per-commitment seed, re-derived identically on restart, each signing exactly one commitment once. No journaling beyond the `channel_state` mutation the derivation reads. |
| Commitment co-signing nonce | `channel-manager.ts:748` signCommitmentPartial | D2 | Fresh random, signs one sighash, discarded in the same call; the partial signature and public nonce travel inside the `commitment_signed` bytes. The outbox stores those bytes, so retransmission never needs the secret again. This is why the outbox stores encoded bytes rather than re-encoding from state. |
| Taproot cooperative close session (`_ourClosingNonce`, `_remoteClosingNonce`, `_hasSignedClosing`, `_taprootClosingCache`) | `channel.ts:480-493` | D3 | In-memory by explicit design: every shutdown (re)transmission carries a fresh closing nonce and the sign-once latch stops one nonce signing two sighashes. The journal MUST NOT persist these; reviving a secret closing nonce against a different closing fee is exactly the reuse 5.10 forbids. |
| `lastCooperativeCloseTxHex` | `channel.ts:643` | D1 | A fully signed transaction, not a live session; an ordinary `channel_state` mutation. |
| Un-acked commitment batch bytes (`_lastSentBatch`) | `channel.ts:395`, restored at `channel.ts:2804` | D2 | Not part of channel state. Before Phase 1 it died with the process, and the reestablish fallback could only rebuild it by re-signing, which it refuses to do for a taproot channel. The outbox now supplies the exact bytes, so a restart retransmits without signing anything. |
| Interactive tx construction and `tx_signatures` (splice) | `interactive-tx.ts`, splice paths in `channel-manager.ts` | D3 for an unfunded, unsigned session; D2 once `tx_signatures` has been sent (the bytes are in the outbox) | An in-progress negotiation with no signatures exchanged is safe to abandon and restart after reestablish; once our signatures are on the wire the exact bytes must be replayable. |
| Splice RBF negotiation | splice paths in `channel-manager.ts` | D3 | A new attempt starts from a fresh negotiation; nothing signed is reused. |
| Wallet UTXO selection / change backing a pending funding or splice | `src/lightning/wallet`, funding paths | D1 required | The selection lock and change state must be persisted with the funding they back, or a restart can put the same UTXO into a second funding. Phase 1 does not change these paths; the kill-point test is Phase 7. |
| Chain monitor pending sweeps and justice transactions | `chain-monitor.ts` | D1, implemented | Persisted as `chain_monitor` mutations, riding the causal channel transition where one exists and committing on their own otherwise. |
| Temporary → permanent channel id promotion | `channel-manager.ts` `_promoteV2ChannelIfReady` | D1 required | The promotion must be durable with the channel state that carries the permanent id. Unchanged by Phase 1; Phase 7 verifies it. |
| Held / intercepted HTLC decisions | `lightning-node.ts` heldHtlcs, heldForwards | D1 for the HTLC itself, D3 for the parking decision | The HTLC rides in channel state and is never lost; the in-memory parking is rebuilt on restart from the invoice's hold flag. Phase 7 verifies the rebuild. |

Prose classification is not acceptance. Each disposition gets a kill-point test
in Phase 7 (spec section 9); Phase 1 ships the transitions and the outbox that
make those tests meaningful.

## 4. What Phase 1 deliberately does not do

- No journal, frames, snapshots or reconstruction. (Since delivered by
  Phase 2: `src/lightning/recovery/journal.ts`, opt-in via the node's
  `recovery.enabled` config; frames append inside the same
  `RecoveryManager.commit` transaction this document describes.)
- No capsule, guardian, epoch or quorum barrier (Phases 3 to 6).
- No change to SCB behavior; it remains the Tier 1 fallback.
- `RecoveryCriticality` is recorded but not yet acted on: there is no durability
  barrier to gate until Phase 6.
