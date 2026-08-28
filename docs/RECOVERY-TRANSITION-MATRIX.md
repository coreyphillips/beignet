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
| Taproot verification nonces (`localNonce`, `localNextNonce`) | `channel-state.ts:454-464`, derived by `channel.ts:800` `_deriveVerificationNonce` | D1 by determinism | Deterministic per commitment height from the persisted per-commitment seed, re-derived identically on restart, each signing exactly one commitment once. No journaling beyond the `channel_state` mutation the derivation reads. Kill test: the taproot payment sweep in `tests/lightning/recovery-phase7-sessions.test.ts` (every boundary; found #293, the nonce-less revoke rebuild, fixed in #298). |
| Commitment co-signing nonce | `channel-manager.ts:748` signCommitmentPartial | D2 | Fresh random, signs one sighash, discarded in the same call; the partial signature and public nonce travel inside the `commitment_signed` bytes. The outbox stores those bytes, so retransmission never needs the secret again. This is why the outbox stores encoded bytes rather than re-encoding from state. Kill test: the same taproot sweep replays the cached 98-byte partial across a restart without re-signing. |
| Taproot cooperative close session (`_ourClosingNonce`, `_remoteClosingNonce`, `_hasSignedClosing`, `_taprootClosingCache`) | `channel.ts:480-493` | D3 | In-memory by explicit design: every shutdown (re)transmission carries a fresh closing nonce and the sign-once latch stops one nonce signing two sighashes. The journal MUST NOT persist these; reviving a secret closing nonce against a different closing fee is exactly the reuse 5.10 forbids. Kill test: the S6 close sweep in `recovery-phase7-sessions.test.ts` asserts on EVERY cell's disk that no closing-session field was serialized. |
| `lastCooperativeCloseTxHex` | `channel.ts:643` | D1 | A fully signed transaction, not a live session; an ordinary `channel_state` mutation. Kill test: the close-durability cell in `recovery-phase7-sessions.test.ts`. |
| Un-acked commitment batch bytes (`_lastSentBatch`) | `channel.ts:395`, restored at `channel.ts:2804` | D2 | Not part of channel state. Before Phase 1 it died with the process, and the reestablish fallback could only rebuild it by re-signing, which it refuses to do for a taproot channel. The outbox now supplies the exact bytes, so a restart retransmits without signing anything. Kill test: the resumed cells of the S4 splice sweep in `recovery-phase7-splice.test.ts`. |
| Interactive tx construction and `tx_signatures` (splice) | `interactive-tx.ts`, splice paths in `channel-manager.ts` | D3 for an unfunded, unsigned session; D2 once `tx_signatures` has been sent (the bytes are in the outbox) | An in-progress negotiation with no signatures exchanged is safe to abandon and restart after reestablish; once our signatures are on the wire the exact bytes must be replayable. Kill test: the S4 splice sweep in `recovery-phase7-splice.test.ts`, whose verdicts are derived from the disk (no in-flight record: both sides talked out of the splice; durable record: both sides still agree on the splice tx). The abandon exchange found #294, the unbounded tx_abort echo, fixed in #299. |
| Interactive tx construction and `tx_signatures` (v2 open) | `dual-funding.ts`, v2 paths in `channel.ts` | D3 before the initial `commitment_signed`; D1 from it onward (`v2InFlight`) | BOLT 2's remember-point for an interactive open is the initial `commitment_signed`: before it the negotiation dies with the connection (the tempChannels sweep aborts it), from it onward the exchange must resume over reestablish `next_funding` across disconnects AND restarts. The `v2InFlight` record persists the negotiated tx, our signed witnesses and the tx_signatures ordering in the same batch that sends the commitment; witnesses replay verbatim, the initial commitment re-signs byte-identically (RFC 6979; taproot is excluded by the fail-closed guard). Kill test: the S7 sweep in `recovery-phase7-splice.test.ts`, whose promoted cells must COMPLETE the open after the restart's reestablish; the reestablish contract itself is pinned in `dual-funding-reestablish.test.ts` (issues #288/#289). |
| Splice RBF negotiation | splice paths in `channel-manager.ts` | D3 | A new attempt starts from a fresh negotiation; nothing signed is reused. Splice RBF is refused on the wire today (`tx_abort`), and the S4 sweep's abandon regime covers the kill shape a refused negotiation shares. The v2 open RBF renegotiation itself is D3 the same way (a replacement negotiation that dies with the process rolls back to the previous attempt at restart), but its attempts are D1: the current attempt rides `v2InFlight` and superseded broadcastable attempts ride `v2PreviousAttempts` (issue #360), all persisted and chain-watched until one confirms and is adopted. Each record also carries the capacity, balances and both channel reserves its commitment #0 was built at (issues #376 and #379), since BOLT 2 lets the contribution differ per attempt; those amounts are restored with the record at every rollback, adoption and restart, so a crash between an accepted contribution change and the replacement's record leaves the row consistent with the attempt it rolls back to. Initiating or accepting a NEW replacement after a restart stays refused (the wallet closures die with the process). |
| Wallet UTXO selection / change backing a pending funding or splice | `src/lightning/wallet`, funding paths | D1, implemented | Implemented by the pledge mechanism in `wallet-funding-provider.ts`: selected inputs are frozen in the wallet under a tagged freeze BEFORE the signed transaction is handed to the node, the whole select-then-pledge section runs under a lock, and a restart adopts tagged freezes with their original timestamps (TTL-pruned). Kill test: `recovery-phase7-utxo-selection.test.ts` kills a wallet-funded open at every boundary and proves a second funding never selects the first funding's inputs wherever that funding exists durably, with coverage counters on the retained and frozen states. (An earlier revision of this row said "not yet implemented"; that note predated the pledge mechanism.) |
| Chain monitor pending sweeps and justice transactions | `chain-monitor.ts` | D1, implemented | Persisted as `chain_monitor` mutations, riding the causal channel transition where one exists and committing on their own otherwise. Kill test: the S9 force-close ladder in `recovery-phase7-sessions.test.ts` (the terminal path broadcasts before its persists by design; the ladder asserts the decision's durability behind the broadcast). |
| Temporary → permanent channel id promotion | `channel-manager.ts` `_promoteV2ChannelIfReady` | D1, verified | The promotion must be durable with the channel state that carries the permanent id; it now happens at the point of no return (the batch that creates the `v2InFlight` record), so in-memory residency matches the disk from the first persist. Kill test: the S7 sweep in `recovery-phase7-splice.test.ts` proves no boundary of a v2 open leaves an orphan temporary row (the disk holds nothing or exactly one permanent-id row, carrying the record) and that every promoted cell resumes to a completed open. Quorum mode exercises the SAME kill points behind the durability barrier: the quorum S7 sweep in the same file (real guardian trio, gated sends released only after replication, identical disk-derived verdicts), the guardian-only restore in `recovery-phase7-restore.test.ts` (device loss inside the open, record restored from the trio, open completed) and the process-level v2 sweeps in `recovery-phase7-sigkill.test.ts`. The phase 6 refusal that once made these cells unreachable is lifted: the durable record is what it was waiting for (issue #288). |
| Held / intercepted HTLC decisions | `lightning-node.ts` heldHtlcs, heldForwards | D1 for the HTLC itself, D3 for the parking decision | The HTLC rides in channel state and is never lost; the in-memory parking is rebuilt on restart from the invoice's hold flag. Kill test: the S3 held-HTLC sweeps in `recovery-phase7-commitment.test.ts` (the redispatch window they exposed became #291, fixed in #292) plus the standalone regressions beside those fixes. |
| JIT receive intents and intercept holds | `liquidity/jit-receive.ts`, metadata keys `jit:intents` / `jit:held` / `jit:fronted` | D1 for the intent, D3 for the hold, with a persisted FAIL disposition | An intent is durable and restored, because invoices carrying its intercept SCID are already out there and must stay payable, and because the outbound zero-conf authorization it lends is derived from it: persisting one and not the other is how the fork ended up intercepting an HTLC it could then not open a channel for. The funding session itself dies with the process and is never resumed, so each held part carries a record naming the only thing a restart can honestly do with it, `disposition: 'fail'`, plus the channel, htlc id, amount and inbound expiry needed to deliver that fail as the right kind of HTLC (blinded legs read their role back off the durable entry via `blindedRoleFor`). Undeliverable rows are retried per block rather than dropped. Kill test: the restart case in `jit-receive-node.test.ts` (a restored channel is AWAITING\_REESTABLISH, so the row survives the first sweep and is failed on the tick after the channel returns) and the restore cases in `jit-receive.test.ts`. |

Prose classification is not acceptance. Every disposition above is enforced by
the Phase 7 chaos matrix (spec section 9): the in-process sweeps under
`tests/lightning/recovery-phase7-*.test.ts` kill at every recorded commit and
send boundary across the durability modes, and the process-level SIGKILL
executor (`recovery-phase7-sigkill.test.ts`, `npm run test:sigkill`) replays
the same boundary vocabulary against a production LightningNode assembly in a
dedicated child process. The matrix found and drove the fixes for #291, #293,
#294 and #295 before any of these rows could be marked verified.

## 4. What Phase 1 deliberately does not do

- No journal, frames, snapshots or reconstruction. (Since delivered by
  Phase 2: `src/lightning/recovery/journal.ts`, opt-in via the node's
  `recovery.enabled` config; frames append inside the same
  `RecoveryManager.commit` transaction this document describes.)
- No capsule, guardian, epoch or quorum barrier (Phases 3 to 6).
- No change to SCB behavior; it remains the Tier 1 fallback.
- `RecoveryCriticality` is recorded but not yet acted on: there is no durability
  barrier to gate until Phase 6. (Since delivered by Phase 6: in quorum mode a
  `SafetyCritical` batch carrying `revoke_and_ack`, `update_fulfill_htlc`,
  `commitment_signed`, `tx_signatures`, `splice_locked` or the data-loss
  `error` holds the REST of its action list until the journal frame behind it
  has reached a guardian quorum. `Important` and `Reconstructable` transitions
  are never held, and outside quorum mode nothing is: the barrier answers
  synchronously and dispatch is unchanged. The gated set is
  `QUORUM_BARRIER_MESSAGE_TYPES` in `src/lightning/channel/channel-actions.ts`,
  one entry per row of spec 5.8, EXCEPT the data-loss `error`. That row is
  carried by the per-action `durabilityCritical` mark instead, because `error`
  is also BOLT 1's ordinary protocol-violation message and the two are
  different in kind: an ordinary error advances no commitment state, is not
  retransmittable, and drives the local force close from the same send, so
  holding it would cost a channel its on-chain close for no safety gain.
  Losing the record that broadcasting is FORBIDDEN, by contrast, re-enables
  broadcasting a commitment the peer has provably revoked. A gated message
  with no `PERSIST_STATE` ahead of it names no frame and is refused outright.
  The set plus the mark are versioned together by
  `WIRE_SAFETY_POLICY_VERSION`, stamped into every quorum frame, so a later
  release cannot read an older frame's `quorum` as a promise about messages
  its writer never gated.)
