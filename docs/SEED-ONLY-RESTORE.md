# Seed-only channel restore: import the mnemonic and the node springs back to life, with no servers we stand up

Zero-touch restore of a direct-funded channel from a BIP39 seed and one bootstrap peer, with the loss model stated and every automatic local broadcast still refused.

Status: design, tracked by #909; Phase 1 bug issues #905 #906 #907 #908

Scope: beignet library and daemon, plus beignet-umbrel as the first embedder

Audience: an implementing engineer. Every code reference was verified against master at commit 4c95e33 (2026-09-18); re-verify line numbers before editing, file and symbol names are the stable anchors

Style rules for all work on this feature: no em dashes anywhere (code, comments, commits, PR text, docs). Follow existing repo conventions for everything else.

Three decisions are already taken and are stated as decided throughout: the deliverable is one tracking issue (#909), four separate bug issues for the Phase 1 loss paths (#905 the revoked-commitment hatch, #906 the channel key index, #907 the all-zeroes secret, #908 the `POST /ffor/enforce` risk flag) and this document; Stage 1 trusts the beignet liquidity peer and is default-on at the embedder when `walletOrigin` is `imported`, while the daemon default stays off; and the production liquidity and settlement peer is a beignet node (the beignet-umbrel primary, the LFBW deployment), so beignet-umbrel is the first deployment.

---

## 1. Summary

The dream is: create a wallet, receive sats by direct funding, delete the node, come back a week later, import the seed phrase, and everything resumes. Today that fails at six independent points. Four of them are one-file fixes and two are protocol work.

- On an empty database the node dials nobody (`src/lightning/node/lightning-node.ts:6213-6245`, `:6294-6297`) and the daemon names no liquidity peer (`src/cli/beignet-node.ts:2429-2435`), so no capsule can ever arrive.
- `df:policy` lives in unjournaled `wallet_data` (`src/lightning/node/lightning-node.ts:757`, `:24411-24426`), so even a perfect Tier 2 restore comes back not knowing its LSP.
- The capsule is pushed on a 60 s trailing timer (`src/lightning/node/lightning-node.ts:5231`) while the reestablish tolerance is not one commitment but ZERO completed payment rounds (`src/lightning/channel/channel.ts:9828-9857` and `:9902-9923`), so a device lost inside a busy minute comes back CLOSED rather than HELD.
- `restoreRecencyUnproven` is stamped once and never cleared (`src/lightning/recovery/capsule.ts:1409`), so a Tier 2 channel that does come back refuses new HTLCs in both directions.

Before any of that, three live fund-loss paths exist independent of this feature and must close first. A bare-seed boot never seeds the channel key index (`src/lightning/channel/channel-manager.ts:648`), and a new or ACCEPTED channel then reuses a live channel's per-commitment seed, which is a BOLT 3 violation and, on taproot, a funding-key extraction. `restoreRecencyUnproven` is absent from `mustNotBroadcastCommitment` (`src/lightning/channel/channel-state.ts:1244-1249`) while `forceCloseChannel` is deliberately ungated, so one operator force close on a restored channel can publish a commitment the peer already holds the revocation for. And the DLP detector accepts an all-zeroes `your_last_per_commitment_secret` at any `next_revocation_number`, which lets a hostile peer suppress our own fell-behind detection for free. These are #906, #905 and #907.

The design that follows is Phoenix's proven shape (full state in the BOLT 1 blob, ordered pushes on the same connection, zero-touch restore) with the four things Phoenix does not have and beignet can add without a server: a signed provider acknowledgement so the lie is attributable, a second non-counterparty holder so the lie is catchable, a journaled LSP identity so the node can find its way home on every later boot, and a permanent refusal of every automatic local broadcast so the lie can never reach the justice path.

The commitment-number reanchor that two of the proposals put at the centre is demoted. The review refuted it as a unilateral move, showed that the `expectedIndex` pin at `src/lightning/channel/channel.ts:4913` is the blocker rather than the enabler, and identified a repeat-restore height-revisit hazard that turns a naive implementation into total loss, so it becomes an explicitly gated experiment rather than the default path.

The honest promise is therefore two-staged. Stage 1 is a live, funds-preserved, peer-enforced channel that can send and receive. Stage 2, self-enforcing again, is reachable today only through the guardian quorum tier, which is itself gated on hardening this design does not do. Penalty channels make that ceiling structural, not a beignet choice.

## 2. The dream, and the two-stage promise

The scenario the whole document is written against: a wallet is created from a mnemonic, receives sats by direct funding from its liquidity peer, is deleted with its data directory, and a week later the same mnemonic is imported into an empty directory. Nothing else survives: no database, no configuration, no operator. The node must find its peer, retrieve its backup, apply it, reestablish, and be usable again, with no HTTP call and no server that beignet stands up.

The headline promise, as decided: after a seed import the channel comes back able to send and receive, with every automatic local broadcast still refused. A lying LSP can hide payments it made after the last acknowledged head (bounded by its own money, and detectable with a second holder), but it cannot take the balance without operator action.

That promise has two stages, and the document keeps them apart because penalty channels force the split.

- **Stage 1, peer-attested live.** The channel resumes at the head the counterparty acknowledged, admits HTLCs in both directions under a cap, and keeps its funds. It is peer-enforced: on-chain enforcement of an in-flight HTLC or of a stalled peer needs the operator, because a state of unknown recency is never broadcast-safe. Stage 1 is what Parts A to E of section 6 build, and it is the default path for an imported wallet.
- **Stage 2, self-enforcing again.** The node can once more broadcast its own commitment without operator action. Today that has exactly one proven realisation, the guardian quorum tier, which is optional, cannot be found from a seed, and is gated on hosting and Sybil fixes tracked elsewhere (D22). The commitment-number reanchor is the only other candidate and is an experiment behind a hard gate (D20).

The tiers referred to throughout: Tier 0 is a seed-only `to_remote` sweeper that needs no backup at all (D21); Tier 1 is the static channel backup (SCB) embedded in every capsule, which yields a peer-initiated close; Tier 2 is the Recovery Capsule over BOLT 1 peer storage, which resumes the channel HELD today and lifted under Stage 1 after this design; the guardian tiers (async-remote and quorum) are the replicated-journal modes of RECOVERY-PROTOCOL.

Topology, as decided: the liquidity and settlement peer is a beignet node, the beignet-umbrel primary of the LFBW deployment, so the default path exists as designed and beignet-umbrel is the first deployment. Direct funding itself needs only `option_dual_fund`, so a CLN or Eclair counterparty is legal for the funding leg, but everything above Tier 1 needs a beignet peer for peer storage and the acknowledgement, and FFOR settlement needs beignet by construction. A Blocktank-on-LND counterparty would get Tier 1 only, because LND stores nothing; that is stated here as a note and is not the production case.

## 3. Where things stand (verified)

- **Only quorum mode resumes exactly.** A capsule restore stamps `restoreRecencyUnproven = true` on every non-terminal row at `src/lightning/recovery/capsule.ts:1409`, the single writer, with no `= false` anywhere in `src/`. The guardian RestoreDriver stamps `stateUncertain` unless the re-verified wire-safety proof holds (`src/lightning/recovery/restore-driver.ts:1092-1118`, `:1167-1184`), and async-remote therefore ends in a close.
- **A held channel keeps its funds and refuses everything else:** no new HTLCs out (`src/lightning/channel/channel.ts:3040-3058`, `:13122-13130`), inbound adds failed back (`src/lightning/node/lightning-node.ts:16356-16385`), no cooperative close without `acceptStaleStateRisk` (`src/lightning/channel/channel.ts:5763-5770`), no automatic force close (`src/lightning/node/lightning-node.ts:24838-24870`).
- **The reestablish tolerance is ZERO completed payment rounds, not one commitment.** The DLP arm at `src/lightning/channel/channel.ts:9828-9857` is a disjunction, so a capsule one full round behind fires it; the mirror half-round routes to `_heldReestablishGapFailure` at `:9902-9907`; only a single missing `revoke_and_ack` survives, and it survives onto a local commitment whose revocation secret the peer already holds.
- **"Closes" is the wrong word for the DLP arm.** It sets `dataLossDetected`, ERRORs and asks the PEER to force close (`src/lightning/channel/channel.ts:9834-9857`), after which `mustNotBroadcastCommitment` makes `prepareForceClose` refuse permanently (`src/lightning/channel/channel.ts:6212`). An unwilling or dead LSP leaves the funds frozen with no local exit and no deadline.
- **LIVE FUND-LOSS PATH, independent of this feature (#905):** `restoreRecencyUnproven` is not in `mustNotBroadcastCommitment` (`src/lightning/channel/channel-state.ts:1244-1249`) and `forceCloseChannel` is deliberately ungated (`src/lightning/node/lightning-node.ts:24841`), so one operator force close with `acceptStaleStateRisk` on the surviving half-round case publishes a revoked commitment: a certain loss labelled as a risk.
- **LIVE FUND-LOSS PATH (#906):** `_nextChannelIndex = 1` (`src/lightning/channel/channel-manager.ts:648`), `loadNextChannelIndex ?? 1` (`src/lightning/node/lightning-node.ts:2617`), and `deriveKeysForNewChannel` (`src/lightning/channel/channel-manager.ts:726-760`) is reached by the inbound acceptors too (`:3575`, `:6704`, `:6980`), so an LSP reconnecting to our seed-stable node id and opening for automatic receive burns index 1 with no user action.
- **LIVE DETECTION HOLE (#907):** the DLP arm requires a non-zero `your_last_per_commitment_secret` (`src/lightning/channel/channel.ts:9832`) while the validator accepts all-zeroes at any `next_revocation_number` (`:9803`), which BOLT 2 permits only at 0.
- **With an empty database the node dials nobody:** `autoReconnectPeers` filters to channel peers and calls `emitReady` with zero dials (`src/lightning/node/lightning-node.ts:6213-6245`, `:6294-6297`).
- **The LSP identity does not survive.** `df:policy` is written only to `wallet_data` (`src/lightning/node/lightning-node.ts:757`, `:24411-24426`), the journal has no key-value mutation (`src/lightning/recovery/types.ts:82-127`), `carryDaemonState` copies three things and reads the pre-restore database, which is empty in the dream case (`src/cli/beignet-node.ts:4617-4646`, `:4209`), and the daemon constructs `directFunding` with no `liquidityPeer` (`src/cli/beignet-node.ts:2429-2435`). Direct-funding receive then dies at `src/lightning/direct-funding/receiver/engine.ts:1032-1035`.
- **Peer storage is write-gated, pull-less and eviction-less:** `peerQualifiesForStorage` (`src/lightning/node/lightning-node.ts:5385-5395`) needs a non-CLOSED channel or explicit trust, retrieval happens only in `sendPeerStorageOnConnect` (`:5399-5450`), and `deletePeerStorageBlob` has zero callers in `src/`.
- **OPEN-TIME HOLE, verified:** `peerQualifiesForStorage` resolves the peer through the PERMANENT channel id, which is registered only at promotion (`src/lightning/channel/channel-manager.ts:8212`), while an open in progress is keyed by the temporary id (`:993`, `:1063`, `:3575`, `:6704`, `:6980`). A blob pushed before `funding_signed` or `tx_signatures` is dropped with a log line.
- **The provider keeps the freshest blob in memory but coalesces the DISK write** to one per 60 s with an `unref`ed timer (`src/lightning/node/lightning-node.ts:5252-5302`), so an honest provider restart inside the window loses the newest blob with no signal.
- **The gated set is six message types, not three:** `QUORUM_BARRIER_MESSAGE_TYPES` at `src/lightning/channel/channel-actions.ts:519-534` holds REVOKE_AND_ACK, UPDATE_FULFILL_HTLC, COMMITMENT_SIGNED, TX_SIGNATURES, SPLICE_LOCKED and FUNDING_SIGNED, versioned by `WIRE_SAFETY_POLICY_VERSION = 2` at `:548`.
- **The dispatch loop is synchronous and ordered, so a pre-send push is a real ordering barrier:** `_dispatchActions` at `src/lightning/channel/channel-manager.ts:8806-8860` calls `sendMessage` inline, which reaches `socket.write` in the same turn (`src/lightning/transport/peer.ts:398-418`). It swallows transport throws and reroutes to `message:outbound` (`src/lightning/channel/channel-manager.ts:10536-10551`), which is the one place ordering can be lost.
- **Guardian serving cannot be defaulted on:** no global byte or disk cap (`src/lightning/recovery/guardian-host.ts:75-77`, `:434`, `:506`), no rate limiting at any layer, free and permanent anonymous slot exhaustion, and `loadIndex` throws inside the constructor, which runs inside the LightningNode constructor (`:196-197`, `:547-569`, `src/lightning/node/lightning-node.ts:2096`). Issues #861 and #862 are open.
- **Rotation is not simply "unreachable at two losses":** the gate is a boot-time latch that `recheck` never downgrades, so a LIVE node can rotate with two outgoing guardians gone, but a restart with two gone quarantines the gate and blocks all peer traffic. Rotation is also refused outright in peer-storage mode, and #862 shows a rotation at `tip() === 0`, which is exactly a seed-only first boot, leaving the wallet unable to persist a channel.
- **Direct funding does NOT require a beignet counterparty:** the LSP leg is stock BOLT 2 dual funding or splice (`src/lightning/direct-funding/receiver/engine.ts:1892`, `:1913-1950`), gated only on `option_dual_fund`. FFOR settlement and the 44069 subtypes 80/81 DO require beignet. Blocktank drives LND (`blocktank-lsp-ln2/service/package.json:59`), which has no dual funding, no splicing acceptance and no peer storage.
- **Prior art pinned** (ACINQ/lightning-kmp at `43e4cf1e76caeb9af68478064d30906433ee57cd`): `RequirePeerStorageStore` guards SEVEN classes including the whole close flow (`wire/LightningMessages.kt:174-175`, `:495`, `:1284`, `:1375`, `:1697`, `:1734`, `:1770`, `:1824`); `maybeRestoreBackup` restores unconditionally when there is no local state and otherwise only while local is `Syncing` (`io/Peer.kt:1177-1194`); overflow drops lowest priority first and, past one oversized channel, sends an EMPTY blob that overwrites the stored one (`serialization/channel/Encryption.kt:62-71`). kmp does not pad; beignet already does (`src/lightning/node/lightning-node.ts:5352`).
- **No test binds mnemonic plus empty directory plus a live peer,** and the chaos verdict vocabulary is closed at `exact-resume | safe-dlp | skip` (`tests/lightning/helpers/chaos-harness.ts:1015`).

## 4. The gap, ranked

Ranked by what blocks the dream first, then by fund-safety impact per unit of work.

1. **Three silent loss paths are open today and gate everything else.** The channel key index is never seeded on a bare-seed boot and is burned by ACCEPTING an inbound open as much as by opening one (`src/lightning/channel/channel-manager.ts:648`, `:726-760`, `:3575`, `:6704`, `:6980`); the operator force close on a restored channel is ungated against a provably revoked local commitment (`src/lightning/channel/channel-state.ts:1244-1249`, `src/lightning/node/lightning-node.ts:24841`); and a peer can suppress our DLP detection with an all-zeroes secret (`src/lightning/channel/channel.ts:9803`, `:9832`). None of these needs new protocol. All three must land before any hold lift, and they are filed as #906, #905 and #907.
2. **The first hop does not exist.** No dial on an empty database, and no config key naming the LSP on the daemon path. Every other piece is reactive to a connection that never happens.
3. **The LSP identity is not carried by any tier.** `df:policy` is `wallet_data`; the journal has no variant that can hold it; `carryDaemonState` reads an empty source in the dream case.
4. **The staleness window is a full minute of payment activity against a tolerance of zero completed rounds.** The 60 s trailing refresh plus the DLP disjunction means a device lost after one payment comes back ERRORED and awaiting a peer close that may never come.
5. **The hold is permanent.** One stamping site, no clearing path, so even perfect later evidence cannot lift it. Without a lift, the dream's acceptance test can only assert a frozen balance.
6. **The capsule is the only backup and its holder is the counterparty.** Under direct funding the LSP is counterparty, sole capsule holder, FFOR settlement peer and, over bolt8 under ephemeral keys, an unidentifiable guardian candidate. Any evidence that comes only from that peer is a signed version of the same lie.
7. **The capsule can degrade silently.** 65523 bytes, unmeasured for a real wallet, an FFOR epoch record riding channel state, an `inlineError` that nothing surfaces to the user, and a decoder that fails closed on any version but 1.
8. **There is no chain-only backstop.** If the week ended in a force close and the blob is gone, nothing sweeps `to_remote` from the seed, even though BOLT 3 makes it derivable from the static payment basepoint alone.
9. **The guardian tier, the only proven self-enforcing route, cannot be found from a seed and cannot be defaulted on.** No feature bit, no advertisement, no directory, no degenerate profile, plus five unfixed hosting hazards.
10. **Unjournaled state is lost wholesale.** The automatic-receive job list, swaps, held forwards, hold-invoice parking, mid-flight direct-funding requests with random per-request keys, BOLT 12 offer `path_id`s, watchtower sessions, and the blobs this node held for others.
11. **The automatic-receive flow does not survive a week.** No witnesses provisioned, a 600 s invoice, a job list no tier carries, and `POST /ffor/enforce` hard-blocked on exactly the channel that needs it because it passes no `acceptStaleStateRisk` (#908).
12. **The production counterparty decides whether Tier 2 exists at all.** If a wallet's mainnet `liquidityPeer` were Blocktank on LND, Tier 2 would not exist there and the whole no-servers path would be gated on the counterparty, not on beignet. As decided, the production counterparty is a beignet node (the beignet-umbrel primary), so this gap is closed by topology for the first deployment and remains a note for any other LSP.

## 5. Threat model

Loss ladder used below: **L0** none; **L1** freeze (funds intact, only the peer can close); **L2** gap loss, the net inflow between the restored checkpoint and the true head plus in-flight HTLCs; **L3** a stale cooperative split; **L4** the whole balance through the justice path, reachable only if a commitment WE publish is revoked in the peer's view; **L5** stranded on chain.

Attackers: **A1** the LSP (counterparty, capsule holder, FFOR settlement peer); **A2** a stranger beignet node; **A3** infrastructure we do not run; **A4** the user's own stale device; **A5** a direct-funding payer; **A6** the FFOR settlement peer.

| Threat | Attacker | Loss | Detection | Mitigation | Status |
|---|---|---|---|---|---|
| Operator force-closes a restored channel whose local commitment the peer already revoked (the surviving half-round case) | A1 profits | L4, whole balance | none today | D1 `restoreRevokedRisk` set at reestablish when `next_revocation_number === localCommitmentNumber + 1` on a restored row; gate `forceCloseChannel` and the CLI route on it | UNSAFE today, Phase 1 (#905) |
| Bare-seed node opens or ACCEPTS a channel at a reused key index | A1 or any former counterparty | L4 silent (new channel pre-revoked for every height below the old head); on taproot, funding-key extraction from one reused verification nonce | none, no wire evidence | D2 fence at `deriveKeysForNewChannel` plus a monotone chain-tip floor; never accept a peer-supplied high-water mark | UNSAFE today, Phase 1 (#906) |
| Peer suppresses our fell-behind detection with an all-zeroes `your_last_per_commitment_secret` | A1 | resume onto a punishable state | none | D3 reject all-zeroes whenever `next_revocation_number > 0` per BOLT 2 | UNSAFE today, Phase 1 (#907) |
| Restored node answers `channel_reestablish` and admits HTLCs at chain height 0 | A1 | L2 sized to an HTLC (expired final-hop preimage leak) | none | D4 chain-sync gate: park reestablish under the existing hold and refuse HTLC admission until a header tip plus one merkle-checked funding answer | UNSAFE if the lift lands without it |
| LSP returns a stale capsule (rollback) | A1 | L2 bounded by gap inflow, or a DLP close it can trigger any time anyway | none with one holder; max-of-holders with two (`src/lightning/recovery/capsule.ts:880-897`) | D14 second holder plus D10 beacon plus D11 ack; D17 rule (d) refuses Stage 1 when out-headed | SAFE, bounded |
| LSP under-reports its reestablish counters while holding a newer state | A1 | L0 while held; L4 only if we broadcast | impossible from the wire (`src/lightning/channel/channel.ts:9860-9878`) | the permanent automatic-broadcast refusal (already built) plus D1 | SAFE |
| LSP withholds the capsule entirely, and can tell a restore from a reconnect because an empty node composes nothing (`src/lightning/node/lightning-node.ts:5574-5583`) | A1 | L1 freeze shading to L5 | none with one holder | D14 second holder; D21 seed-only `to_remote` sweeper as the floor | SAFE, liveness only |
| LSP force-closes at a gap state during the week | A1 | L2 bounded by its own post-checkpoint payments | chain | D10 shrinks the gap to one barrier; D21 sweeps `to_remote` via `classifyTheirFutureCommitmentOutputs` | SAFE |
| Provider crashes inside its 60 s disk-write window, or exits cleanly and drops the pending flush | A3 or fate | L2, and with a zero-round tolerance an ERRORED close | none, BOLT 1 has no ack | D13 synchronous persist for ack peers, flush on disconnect and on shutdown | UNSAFE today |
| Capsule pushed before `funding_signed` or `tx_signatures` is dropped by the provider's write gate | nobody, structural | L5 for the first channel: a 2-of-2 naming us exists on chain and the restore has no channel at all | a log line on the provider | D12 qualify a peer whose open is in flight, or register `channelPeers` under the permanent id as soon as it is derived | UNSAFE today |
| Two colluding guardians plus one honest guardian unreachable | A1 or A2 | L4: a quorum restore stamps NEITHER flag, so automatic closes stay armed | the third guardian, or the capsule's own head (`src/lightning/recovery/capsule.ts:621-624`) | D22 wait-for-all-reachable, refuse a guardian head below the capsule head, install HELD when uncorroborated | UNSAFE today, gates the guardian tier |
| The user's drawer phone returns; peer-storage mode has no fence at all | A4, honest software | L4 on the old device if an HTLC backstop fires while the LSP is unreachable | the capsule the provider returns to it on connect | D5 self-fence on a returned capsule whose head exceeds our own, in every mode; never push a head below one just returned | SAFE after D5; residual: a device that never reconnects cannot be fenced by any protocol |
| Capsule silently exceeds the ceiling and degrades to SCB plus locator | A1 or A6 inflating our state via HTLCs, splices or a large `IFforEpochRecord` | tier drop to a DLP close, or L5 without a txindexed backend | `inlineError` log only | D15 priority drop policy, refusal rather than an empty overwrite, `recovery:capsule-degraded` plus a readiness FAIL | UNSAFE today |
| Capsule format version bumps between write and restore | nobody | the backup is unreadable (`src/lightning/recovery/capsule.ts:791-792` fails closed) | none | D15 read-back rule (a writer of version N reads 1..N, and N ships one release behind the writer), fixture test per shipped version | UNSAFE today |
| Storage peer evicts, truncates or loses the blob; or a beignet home node restores and loses every blob it held for others | A2, A3 | L1 | none, retention is unadvertised | D13 retention advertisement; D14 two holders; journal `peer_storage_blobs` | SAFE, liveness |
| Peer replays a catch-up transcript and stops early | A1 | L4 if a completed catch-up were ever treated as exactness | none | never let catch-up clear a flag; it is a distance-shortener only | SAFE by exclusion (rejected) |
| A second restore from the same capsule revisits heights the peer already collected secrets and nonces for | A1 | L4 total, plus taproot funding-key extraction from one reused MuSig2 secnonce | none | D20's monotone floor carried in the capsule plus a never-revisit-a-height invariant; the experiment is gated on it | UNSAFE until D20's gate is met |
| Stranger floods the unknown-channel reestablish hold table (1024 global, 64 per peer, `src/lightning/channel/channel-manager.ts:5167-5173`) | A2 with inbound access | L1 close, or L2 at a gap state | table metrics | D6 per-peer stranger quota that cannot reach the global cap, oldest-spent eviction, reserved allowance for SCB-named peers | SAFE, liveness |
| LSP times its capsule to arrive after the 120 s auto-apply ceiling, or after the 10 minute hold | A1 | L1 or L2 | phase reporting | D6 re-arm auto-apply on any arrival while the target is still empty; renew the hold on arrival | SAFE |
| Guardian host DoS: anonymous permanent slot squat, byte exhaustion, corrupt `sets.json` bricking the host's own wallet | A2 | host wallet outage; every guarded wallet silently loses a slot | none | D22 global byte and disk cap, session cap, token bucket, admission tied to an existing relationship, quarantine instead of throw | UNSAFE today |
| FFOR settlement peer withholds preimages against a held receiver until `T_exp` | A6, usually A1 | the voucher amount, never the principal | the receipts fetch, if anything calls it | D18 FFOR-freeze lift; journal the job list; provision a witness; pass `acceptStaleStateRisk` through `POST /ffor/enforce` (#908); alarm on `min(cltvExpiry)` | UNSAFE today |
| Split brain at import under default-on auto-apply | A4 | L1: both ends converge on a close, never a penalty | the provider's advisory `lastAcceptedAt` and `otherSessionsLast10m` | D19 heuristic detector that can only ADD refusals; `assertEmptyTarget` stays the hard boundary | SAFE, detection not fencing |
| A single `recoveryId` flooded to strangers becomes a correlation handle and a restore-timing oracle | A2, A3 | no direct loss; enables the hold-table flood and lets the LSP time a gap-state close | none | D16 per-peer blinded ids; no stranger flooding on the default path | SAFE |
| Poisoned discovery answers (DNS seeds, gossip, a wrong configured URI) | A3 | L1 at worst | BOLT 8 authenticates the remote static key | dial by node id only (`src/lightning/node/lightning-node.ts:7966-8075`); a wrong URI degrades to "no capsule found" | SAFE |
| Malicious direct-funding payer: zero-conf credit, or an RBF-superseded funding the SCB still names | A5 | out-of-band value; L5 for the stranded watch | chain | bound zero-conf credit; carry attempt inputs and the funding script in the SCB entry so Tier 1 gets lineage discovery | SAFE, no L4 |

## 6. Design

This is the normative section. Every point is marked SAFE, UNSAFE or UNKNOWN with the reason. UNSAFE means "true of the code as built, and the point is the fix". UNKNOWN means "an experiment with a stated gate, deliberately outside the default path".

### Part A. Close the silent loss paths (no new protocol, no new wire)

**D1. A restored channel that is provably revoked must not be broadcastable, even by the operator.** (#905)

Mechanism. Add one durable field `restoreRevokedRisk` beside `restoreRecencyUnproven` on `IChannelState` (`src/lightning/channel/channel-state.ts:954`, serialized at `src/lightning/storage/serialization.ts:521`, `:984`, `:1410`). Set it in the reestablish handler when the channel carries `restoreRecencyUnproven` and the peer's `next_revocation_number === localCommitmentNumber + 1`, which is precisely the one stale case today's code lets resume (section 3): our stored local commitment is already revoked in the peer's view. Add it to `mustNotBroadcastCommitment` (`src/lightning/channel/channel-state.ts:1244-1249`), which every force-close, rebroadcast and fee-bump decision already consults through one predicate, and refuse `forceCloseChannel` (`src/lightning/node/lightning-node.ts:24841`) and `POST /channel/forceclose` for such a row regardless of `acceptStaleStateRisk`. The clean case (`L0, R0`) keeps the labelled operator exit exactly as RECOVERY-PROTOCOL revision 13 designed it.

Safety. SAFE. It is a refusal only, and it closes the one path in the current tree by which a restore can reach L4 without a guardian collusion. Residual, stated: such a channel now has no local exit at all and depends on the peer closing, which is the same position `dataLossDetected` already puts it in.

Trust. None.

Extends. `src/lightning/channel/channel-state.ts:1244-1249`, `src/lightning/channel/channel.ts:6206-6218`, `src/lightning/node/lightning-node.ts:24838-24870`, `src/cli/beignet-node.ts:7376-7391`.

**D2. Channel key index: fence during an unresolved restore, monotone floor on an empty database.** (#906)

Mechanism. Two changes at the one chokepoint every brand-new channel passes through, `deriveKeysForNewChannel` (`src/lightning/channel/channel-manager.ts:726-760`), beside the existing `_assertNamespaceCanRecordANewChannel` backstop.

1. FENCE: a new config predicate `newChannelsRefused?: () => string | null`, supplied by the daemon, returns a reason while the boot latched `_bootTargetEmpty` (`src/cli/beignet-node.ts:2005-2014`) and no restore verdict exists, or the chain tip is unknown. It covers the inbound acceptors (`src/lightning/channel/channel-manager.ts:3575` v1, `:6704` and `:6980` v2) as well as `openChannel`, which is what matters: the LSP reconnecting to our seed-stable node id and opening for automatic receive burns index 1 with no user action. `open_channel` during the window is answered with a BOLT 1 error naming the reason.
2. FLOOR: on any boot whose `channel_key_indices` table is empty, start `_nextChannelIndex` at `max(1, currentChainTipHeight)`. Block height is monotone across an unlimited number of device losses with no persistence and no randomness, which is the property that matters, and it stays far under the 2^31 hardened limit. It needs no storage: `loadNextChannelIndex` is `max(channel_key_indices) + 1` (`src/lightning/storage/sqlite-storage.ts:1201-1213`), so the floor is implied once the first row is journaled.

Safety. SAFE. The fence refuses a derivation, which the comment at `src/lightning/channel/channel-manager.ts:726-742` states cannot burn an index; restore never comes through this path (`:2232-2236`). The floor removes the only way a fresh channel can inherit a revoked history, including the taproot case where a shared `perCommitmentSeed` means one MuSig2 secnonce signs two different sighashes and leaks the funding key.

Trust. A chain tip, which D4 already requires before any channel work.

Extends. `src/lightning/channel/channel-manager.ts:648`, `:726-760`, `:2232-2236`, `:9128-9160` (the `namespaceLost` refusal shape), `src/lightning/keys/wallet-keys.ts:126-178`.

**D3. Reject an all-zeroes `your_last_per_commitment_secret` above revocation number 0.** (#907)

Mechanism. One condition in the DLP secret validator at `src/lightning/channel/channel.ts:9796-9812`. BOLT 2 permits all-zeroes only when `next_revocation_number` is 0; today any value is accepted, so a peer that wants to suppress our own fell-behind detection sends zeros with under-reported counters and gets a stale node to resume.

Safety. SAFE. It does not make the peer honest; it removes the cheapest free suppression and makes the DLP arm mean what RECOVERY-PROTOCOL revision 13 assumes it means.

Trust. None.

**D4. Chain-sync gate before reestablish answers and HTLC admission.**

Mechanism. Nothing gates peer traffic on chain height today (`recoveryPermitsPeerTraffic`, `src/lightning/node/lightning-node.ts:6012-6026`, covers guardian ownership only) and the persisted tip is a metadata row a bare restore lacks. Park every reestablish under the existing unknown-channel hold (`src/lightning/channel/channel-manager.ts:5133-5185`) and refuse HTLC admission until a header tip has arrived and one restore-critical Electrum answer (the funding transaction's position) is merkle-checked with the existing `getTransactionMerkleProof` (`src/lightning/chain/electrum-backend.ts:529-536`). Budget the wait inside the 10 minute hold.

Safety. SAFE, and a hard prerequisite for D17. Without it the lift trades an L4 protection for a new L2: a final-hop HTLC whose `cltv_expiry` is already below the true tip passes `min_final_cltv` at height 0, and revealing its preimage lets the peer claim the timeout branch while holding the preimage.

Trust. Electrum headers are not eclipsed for the duration of the restore; multiple public servers ship by default (`src/shapes/electrum.ts:31-55`).

**D5. Head-based self-fence on a returned capsule, in every recovery mode.**

Mechanism. `handleRetrievedPeerStorage` (`src/cli/beignet-node.ts:11914-12010`) already fences on `generation` in async-remote and quorum; peer-storage mode has no fence at all. Extend it: a running node that retrieves a capsule for its own seed whose `(generation, writerEpoch, latestSequence)` exceeds its own head, or whose `latestSequence` is not on its own journal chain, freezes exactly as the guardian fence does (`recovery:fenced`, gate `fenced`, no channel messages) and reports "superseded by another device". Paired rule: never push a capsule whose head is below one the peer just returned on that connection. BOLT 1 delivers `peer_storage_retrieval` before our push in `sendPeerStorageOnConnect` (`src/lightning/node/lightning-node.ts:5399-5450`), so the ordering is already right.

Safety. SAFE as a FREEZE. A freeze can never lose funds, and a holder cannot forge a newer capsule (AEAD under the node secret, `src/lightning/recovery/capsule.ts:683-685`). It must NOT be described as fencing: a withholding holder leaves the old device unfenced until its next reconnect, and a device that stays offline is invisible. It is also not a weapon: a holder that withholds and then returns the newest blob freezes a device that IS stale, which is the correct outcome.

Trust. The holder returns the newest blob it has; a holder that does not produces a freeze, never a loss.

Extends. `src/cli/beignet-node.ts:11946-11971`, `src/lightning/recovery/startup-gate.ts`, `src/lightning/node/lightning-node.ts:5399-5450`.

**D6. Restore-window liveness: stranger quota on the hold table, auto-apply re-arm.**

Mechanism. (a) The unknown-channel hold caps at 1024 globally and 64 per peer (`src/lightning/channel/channel-manager.ts:5167-5173`) and returns false past the cap, after which the real reestablish gets the BOLT 1 unknown-channel error and the LSP closes. Count strangers against a small per-peer stranger quota (default 4) that cannot reach the global cap, evict spent entries oldest first, and reserve an allowance for the peers the first retrieved capsule's SCB names. (b) Auto-apply arms only on the FIRST arrival and the latch is per boot (`src/cli/beignet-node.ts:2005-2014`, `:4432-4440`), so an LSP that answers after the 120 s ceiling wins for free. Re-arm on any capsule arrival while the database is still empty, and renew the reestablish hold on arrival.

Safety. SAFE. Liveness only; no state transition changes.

### Part B. Homing: how a seed-only node finds its way back

**D7. `recoveryBootstrapPeers` plus a homing pass that runs independently of `autoReconnectPeers`.**

Mechanism. Three layers, ordered by certainty, with the first as the default path.

1. A daemon option `recoveryBootstrapPeers` (`BEIGNET_RECOVERY_BOOTSTRAP_PEERS`, comma-separated node URIs, parsed by `src/lightning/transport/peer-uri.ts`, precedence exactly as `src/cli/config.ts:525-567`), consumed by a new `BeignetNode.homeToBootstrapPeers()` that runs right after `initNode` when the boot latched `_bootTargetEmpty`, and runs INDEPENDENTLY of `autoReconnectPeers`, which filters to channel peers and emits ready with zero dials (`src/lightning/node/lightning-node.ts:6213-6245`, `:6294-6297`). It dials through the existing `connectForRequest` shape (`src/lightning/node/lightning-node.ts:8077-8090`) with a per-URI budget (15 s clearnet, 45 s onion) and an error trail, reported under a new `homing` block on `GET /recovery/status`. Who supplies it: beignet-umbrel already holds the primary's pubkey, host and port outside the daemon (`manager/server/wallet-manager.js:2447-2449`, `:2478-2482`) and passes it in `_daemonEnv`; a mobile app ships a compiled-in LSP list exactly as `src/shapes/electrum.ts:31-55` ships Electrum servers, which is what Phoenix (a single ACINQ peer) and CLN's `recover` plugin (ten hardcoded nodes) do in production.
2. After the first restore the LSP identity is in the capsule (D8), so every later boot dials it through the ordinary DF path.
3. Gossip self-lookup as a bonus for announced channels only: RGS prime or `bootstrapPeers()`, then `getNodeChannels(ourNodeId)` (`src/lightning/gossip/network-graph.ts:588`), then `query_short_channel_ids` for the endpoint's `node_announcement` (`src/lightning/gossip/gossip-sync.ts:225-270`), then `connectPeerById`. Direct-funded non-zero-conf opens are announceable by default (`src/lightning/channel/channel.ts:1539`) but zero-conf forces private (`src/lightning/channel/channel-manager.ts:6610-6624`), so this is never relied on.

Safety. SAFE. A dial creates no channel state, an empty node composes no capsule so a mistaken URI cannot overwrite a provider's copy (`src/lightning/node/lightning-node.ts:5574-5583`), a wrong-network capsule is refused at retrieval (`src/cli/beignet-node.ts:11938-11946`), and BOLT 8 authenticates the remote static key so a poisoned address cannot impersonate the LSP.

Trust. The embedder or app supplies a correct URI. A stale URI degrades to "no capsule found", never to a wrong restore. This is the honest answer: no seed-derived pointer to the LSP exists today (section 3), so the first hop comes from outside.

UNKNOWN, stated: whether the mobile time budget (D9) holds over Tor. Measured in Phase 2 acceptance.

**D8. `kv_state`: a typed, closed, allowlisted journal variant carrying the LSP identity and the receive job list.**

Mechanism. One new `RecoveryMutation` variant `{type:'kv_state'; table:'wallet_data'|'metadata'; key: KvStateKey; value: Buffer|null}` (`src/lightning/recovery/types.ts:82-127`), where `KvStateKey` is a CLOSED union, not a string: v1 is exactly `'df:policy'` and `'automatic_receive_jobs_v1'`. Each key carries a shape validator run at commit AND at apply. Add a `kvState` array to `RecoverySnapshot` (`src/lightning/recovery/types.ts:300-337`) with `SNAPSHOT_SCHEMA_VERSION` bumped (absent reads as empty), a case in `applyMutation` (`src/lightning/recovery/recovery-manager.ts:339-444`), encode and decode in `src/lightning/recovery/frame-codec.ts:150-345`, capture in `captureSnapshot` (`src/lightning/recovery/journal.ts:1657-1730`), and a probe frame in `knownGoodProbeFrames` (`src/lightning/recovery/capsule.ts:227-530`) so the exhaustive probe stays exhaustive. Two write sites route through `recovery.commit`: `persistDirectFundingPolicy` (`src/lightning/node/lightning-node.ts:24411-24426`) and the OfflineReceive job list (`src/cli/beignet-node.ts:2485-2494`). `assertEmptyTarget` (`src/lightning/recovery/journal.ts:2073-2120`) treats allowlisted keys as configuration, so their presence does not dirty the target and the capsule's value wins at install with the overwrite logged.

Second, cheaper half: at Tier 1 and Tier 2 install, when the restored node has exactly one channel peer and no `liquidityPeer` is set, seed `df.policy.liquidityPeer` from the SCB entry's `peerNodeId` and the host and port from `parseScbAddress(peerAddresses[0])` (`src/lightning/backup/scb.ts:48-54`, `:90-120`), marked PROVISIONAL until confirmed, with `allowZeroConf` left off.

Safety. SAFE as specified. `df:policy` and the job list carry no keys and no commitment state; a stale value restores a stale address (retried) or an already-settled job (idempotent receipts, `src/cli/ffor-receive.ts:319-363`). The SCB-seeded value is material the node just authenticated. UNSAFE and explicitly rejected: an OPAQUE untyped key-value variant. The review is right that it would silently journal API key overrides and auth secrets into a blob replicated to peers and guardians, and would carry random per-request DF keys, swap outpoints and watchtower sessions with no restore semantics. The closed union with per-key shapes is the registry instead; every later subsystem opts in by adding a key, a shape and an idempotency argument.

Trust. None beyond the journal's existing AEAD and chain verification.

**D9. The boot state machine, the none-found terminal, and wrong-input detection.**

Mechanism. Seven phases on `GET /recovery/status.autoApply.phase`, mirrored by events: `searching` (NEW; armed at `emitReady` on an empty-target boot, 90 s window, because today `noteCapsuleForAutoApply` arms only on the first arrival so a seed that finds nothing sits in `idle` forever), `settling` (existing 15 s floor, 120 s ceiling), `applying`, `resuming`, `reestablishing`, then per-channel terminals `live` / `held` / `closing-safely`, plus two boot terminals `none-found` and `refused`. New events `capsule:searching`, `capsule:none`, and `capsule:channel {channelId, outcome}` so the embedder's "Channels resuming: N of M" and "closing safely, funds return on-chain" copy works for the capsule lane; new status block `restore.channels[]`. Startup validation extends the existing pattern (`src/cli/daemon.ts:830-854`) to `searching + ceiling + 60 s margin < hold`.

Quiescence: refuse invoice, pay, open and direct-funding-request routes with 503 `NODE_RESTORE_SETTLING` while an empty-target boot is searching, settling or applying, because `assertEmptyTarget` would otherwise refuse the whole restore later.

Wrong input: every wrong input presents today as a healthy empty node (testnet, regtest and signet share coinType 1, `src/lightning/keys/wallet-keys.ts:29-34`; the CLI passes no BIP39 passphrase). On an Import boot, `none-found` reports the four discovery facts (no capsule, no SCB, no on-chain history across all four address types, no gossip channel for our node id) and offers three actions: try another network, stop the old device and retry, or confirm "this is a new wallet", which writes the persisted marker that D2's fence consumes. A false `none-found` where all four signals were unreachable reports "could not check", not "nothing found".

Safety. SAFE. Every addition is reporting or a refusal.

Trust. The embedder polls or subscribes and stays quiescent.

### Part C. Durability: make the backup as fresh as the channel

**D10. A signed head beacon pushed before every barrier-class message on the counterparty's own connection.**

Mechanism. The review confirmed the ordering property and refuted the naive form. The object pushed per transition is NOT the capsule: composing a capsule is a synchronous journal rebase plus an SCB ECIES encode, and every push is padded to 65531 bytes (`src/lightning/node/lightning-node.ts:5347-5370`), which is roughly 128 to 256 KiB per forwarded HTLC. Push a small HEAD_BEACON instead: `{version u8, blindId 32, generation u64, writerEpoch u64, latestSequence u64, frameHash 32, sig 64}`, about 178 bytes, signed with `signTranscript` under the per-peer blinded key of D16 over a tagged hash.

Hook: `ChannelManager` config gains `beforeGatedSend?(peerPubkey, messageType, frameSequence): boolean`, called in `_dispatchActions` immediately before `this.sendMessage` in the SEND_MESSAGE case (`src/lightning/channel/channel-manager.ts:8827-8835`) when the action's type is in a NEW, separately versioned `BEACON_GATED_MESSAGE_TYPES`, and before the `AUTHORIZE_FUNDING_BROADCAST` and `fundingCritical` broadcast actions.

Ordering argument, verified: `PERSIST_STATE` is emitted synchronously and `persistRequest.committed` is checked before any later send (`src/lightning/channel/channel-manager.ts:9036-9053`), the loop is synchronous with no await, `sendMessage` reaches `socket.write` in the same turn (`src/lightning/transport/peer.ts:398-418`), and the receive side dispatches frames in order. Zero round trips.

Failure coupling: today `sendMessage` swallows a transport throw and reroutes to the `message:outbound` event (`src/lightning/channel/channel-manager.ts:10536-10551`), which breaks the single ordered stream. The beacon must go through the same path, and when it takes the fallback the hook returns false and the batch sets `sendsBlocked`, mirroring the failed-persist rule. `IWireDurabilityBarrier` is NOT implemented for this and is unchanged: it has no peer parameter (`src/lightning/channel/channel-actions.ts:465-495`) and is consulted before dispatch, and the guarantee here is ordering rather than a receipt.

Versioning: do NOT widen `QUORUM_BARRIER_MESSAGE_TYPES`. That set is pinned to `WIRE_SAFETY_POLICY_VERSION = 2` (`src/lightning/channel/channel-actions.ts:519-548`) with no implication table (`src/lightning/recovery/wire-safety.ts:150-166`), so widening it is a hard cut for every deployed quorum namespace. `BEACON_GATED_MESSAGE_TYPES` starts as a copy of the quorum set (REVOKE_AND_ACK, UPDATE_FULFILL_HTLC, COMMITMENT_SIGNED, TX_SIGNATURES, SPLICE_LOCKED, FUNDING_SIGNED) plus the two funding-broadcast actions, carries `BEACON_POLICY_VERSION = 1`, and is widened independently. The 60 s capsule refresh stays untouched as the full-state carrier, plus the existing fresh compose on connect.

Reconnect repair: unlike a channel message, a beacon has no outbox row and no BOLT 2 retransmission rule, and every queue-drop path runs the suffix with sends suppressed, so drop the `capsuleDirty` short-circuit in `sendPeerStorageOnConnect` and re-push the current beacon on every reconnect.

Safety. SAFE as an ORDERING invariant, and it must be described as exactly that. If the peer acts on the gated message, it had already read the beacon off the same socket. It is NOT durability: BOLT 1 has no ack, the receiver may drop or persist lazily. It shrinks the exposure from "up to 60 s and unbounded rounds behind" to "at most one batch behind on an honest durable peer", which is the difference between an ERRORED close and a hold. It does not by itself clear any flag.

Trust. TCP and Noise ordering on one connection; the provider processes frames in receipt order (beignet does, `src/lightning/node/lightning-node.ts:5252-5302`).

Cost. About 178 bytes ahead of each barrier-class send, two per payment round. `getRecoveryStatus().beaconPush` reports count, bytes, mean and p95, mirroring `barrierLatency` per RECOVERY-PROTOCOL 5.8 ("THE BARRIER IS MEASURED").

**D11. `HEAD_ACK`: a signed, counted, persisted-before-ack acknowledgement.**

Mechanism. New `BeignetCustomSubtype` `HEAD_BEACON = 34` and `HEAD_ACK = 35` in the free part of the reserved 32-47 recovery block of message 44069 (`src/lightning/message/custom.ts:18-40`), plus an odd experimental feature pair `OPTION_HEAD_ACK = 562/563` beside `OPTION_FF_RECEIVE = 560` (`src/lightning/features/flags.ts:92-113`).

Provider side: for a peer whose init carries the bit, verify the beacon under the blinded key the client registered, persist it SYNCHRONOUSLY (it is 178 bytes, so the 60 s disk coalescing that exists for 64 KiB blobs does not apply), keep a per-peer accept rate limit, increment a persisted monotone counter, and reply `{blobOrBeaconHash 32, counter u64, persistedAt u64, sig 64}` signed by the provider's NODE key over `guardianTaggedHash('beignet/head-ack/v1', providerNodeId || clientBlindId || beaconHash || counter || persistedAt)` using `signTranscript` / `verifyTranscript` (`src/lightning/recovery/guardian-wire.ts:610-650`). On connect, `sendPeerStorageOnConnect` sends `PEER_STORAGE_RETRIEVAL` and then the highest beacon it holds for this client plus its own ack, with `latest = 1`, `retentionBlocks`, `lastAcceptedAt` and `otherSessionsLast10m` (the last two feed D19).

Client side: verify, keep the latest ack per peer, log `head_unacked` after 30 s and `head_ack_regressed` on a counter that goes backwards.

What it proves. The provider received and persisted head H as its k-th accepted head, signed under the node key the client already relies on for the channel itself. What it cannot prove: that the provider holds nothing newer. It converts a silent under-report into a signed one and gives the restore a hash-bound identity for "the head P admits to", which D17 requires and D14 cross-checks. Crucially, because the beacon is OUR signature, no holder can inflate it. The maximum beacon head across holders is therefore a lower bound on our true head that no holder can fake upward, which is exactly the argument `selectHead` already makes (`src/lightning/recovery/restore-driver.ts:676-720`).

Safety. SAFE. Additive, never waited on by the client, so it cannot stall a transition; a missing or invalid ack only withholds the Stage 1 lift. LND, CLN, Eclair and older beignet peers ignore the subtype without disconnecting (`src/lightning/message/custom.ts:1-14`).

**D12. Fix the open-time storage gate.**

Mechanism. `peerQualifiesForStorage` (`src/lightning/node/lightning-node.ts:5385-5395`) resolves the peer through `getChannelId()` and `getPeerForChannel(permanentId)`, and `channelPeers` is keyed by the permanent id only at promotion (`src/lightning/channel/channel-manager.ts:8212`) while an open in flight is keyed by the temporary id (`:993`, `:1063`, `:3575`, `:6704`, `:6980`). So a beacon or capsule pushed immediately before `funding_signed` or `tx_signatures`, which are in the gated set precisely because a restore below them comes back with no channel at all, is dropped by the provider. Either register `channelPeers` under the permanent id as soon as it is derived, or qualify a peer with an in-flight open. Same fix on both sides.

Safety. SAFE. Without it no ordering rule protects the frame that creates the 2-of-2, which is the first channel of the dream.

**D13. Provider obligations a beignet peer takes on, with no new service.**

Mechanism. Three rules in `handlePeerStorageMessage` and its neighbours (`src/lightning/node/lightning-node.ts:5252-5320`): (1) for an ack peer, persist the beacon synchronously and ack after the write; (2) flush the pending capsule blob on peer DISCONNECT and on SHUTDOWN, because `stop()` clears the `unref`ed flush timers without flushing, which is the Eclair write-delay failure mode; (3) advertise `retentionBlocks` (0 meaning indefinite, which is beignet's current behaviour since `deletePeerStorageBlob` has zero callers in `src/`) so a restoring client can reason about "come back in a week", and document never-evict-while-open plus 2016 blocks after close in RECOVERY-PROTOCOL 5.4. Plus a per-peer accept rate limit and a cap on trusted storage peers (default 64).

Safety. SAFE. Making the disk write synchronous for small beacons narrows, never widens, the window a provider crash loses. The rate limit bounds the churn the 60 s coalescing exists to prevent.

### Part D. Redundancy without new wire

**D14. A second holder: the user's own beignet node through the existing trusted-peer hatch.**

Mechanism. The client already pushes to EVERY connected peer advertising PROVIDE_STORAGE (`distributePeerStorage`, `src/lightning/node/lightning-node.ts:5464-5499`), and the server already accepts a blob from a channel-less peer when `channelManager.isTrustedPeer(pubkey)` holds (`:5386`). The gap is that trust is in-memory only (`src/lightning/channel/zero-conf.ts:12-46`). Two additions: (1) a PERSISTED storage-trust list on the holder (a `storage_peers` table or `BEIGNET_PEER_STORAGE_TRUSTED`), consulted in `peerQualifiesForStorage` beside `isTrustedPeer`, exposed as `POST /peer-storage/trust` beside the existing route shape at `src/cli/daemon.ts:2281`; (2) the wallet lists the home node in `recoveryBootstrapPeers`. At restore, `restoreBestRecoveryCapsule` already picks the highest head across holders (`src/lightning/recovery/capsule.ts:880-897`, `:1462`), and the max-beacon rule of D11 catches a liquidity peer that returns a lower head than the home node.

Safety. SAFE. A second copy of an already-encrypted blob at a node the user controls. The holder's write gate stays closed to strangers; the trust list is explicit and per pubkey; a malicious home node can only return an old blob (which loses) or a forged one (which fails AEAD). This is the single highest-value delta over Phoenix, which has exactly one peer and therefore cannot detect rollback at all: lightning-kmp's `maybeRestoreBackup` restores unconditionally when there is no local state, verified at the pinned commit, and that is precisely the seed-only boot.

Trust. The user operates or trusts the second holder; it learns the wallet's node id, which it already knows as a peer.

Not default-on. The default path is single-holder like Phoenix; this is the upgrade for users who run a home node, and it directly answers the correlated-failure objection left open from #690.

**D15. Capsule v2: declared policy, a drop policy that refuses instead of erasing, and a read-back version rule.**

Mechanism. `decodeCapsule` fails closed on any version but 1 (`src/lightning/recovery/capsule.ts:791-792`). Add version 2 with two header fields written by the WRITER: `beaconPolicy: 'per-transition-v1' | 'none'` and `beaconSetVersion: number` (equal to `BEACON_POLICY_VERSION` at write time), so a restorer reads evidence rather than being told by configuration, the same rule RECOVERY-PROTOCOL 5.8 applies to frames.

Version rule: a release that writes version N must read every version 1..N, a writer never emits version N until the reader for it has shipped one beignet-umbrel `BEIGNET_VERSION` bump earlier, a fixture test decodes a pinned blob of every version ever shipped, and an unreadable future-version capsule is reported as "backup written by a newer version, update the app" on the status route and NEVER answered with an error to the peer.

Overflow: adopt lightning-kmp's priority ordering (Closed and future-commitment first, then Closing, Negotiating, ShuttingDown, the opening states, NORMAL last) and its filter-Closed-before-sizing trick, but REJECT its terminal: `Encryption.kt:67-70` sends an EMPTY blob that overwrites the stored one under BOLT 1's replace rule, which destroys a good backup silently. beignet refuses to push instead, emits `recovery:capsule-degraded`, and fails the `CHANNEL_BACKUP` readiness check. Couple `max_accepted_htlcs` and the FFOR voucher count to the remaining budget. Keep `padOwnPeerStorageBlob`: lightning-kmp violates BOLT 1's padding SHOULD and beignet is ahead here.

Safety. SAFE. Fail-closed decoding is preserved for unknown versions, v1 blobs restore exactly as today, and a forged header cannot pass AEAD under the seed-derived capsule key.

**D16. Per-peer blinded recovery identities.**

Mechanism. `deriveRecoveryRoot` yields ONE `recoveryId` (`src/lightning/recovery/guardian-wire.ts:84-90`), which flooded to N holders is a correlation handle and a restore-timing oracle. Derive `blind_P = HKDF(rootSecret, salt = P.nodeId, info = 'beignet-recovery-blind-v1')` reduced to a secp256k1 scalar exactly as `deriveRecoveryRoot` does; `blindId_P` is its x-only public key, is the record key at P, and is the key beacons are signed under. At restore the seed recomputes it for any candidate holder with no state.

Safety. SAFE. Two holders cannot link their records, a holder cannot forge a beacon without the seed, and a wrong derivation fails closed to "no record found", which is the existing seed-only failure mode.

Trust. None.

### Part E. Lifting the hold

**D17. Stage 1, "peer-attested live": lift ONLY the HTLC refusal.**

Mechanism. At install, `markCapsuleRestoredChannels` (`src/lightning/recovery/capsule.ts:1394-1412`) keeps stamping `restoreRecencyUnproven = true` on every non-terminal row and ADDITIONALLY records `restoreEvidence = {fromPeer, beaconHash, ackCounter, beaconPolicy, capsuleHead}` on a row when ALL of the following hold:

- (a) the winning capsule was returned by peer P and `row.peerPubkey === P` (the counterparty is the holder);
- (b) the capsule's own authenticated header declares `beaconPolicy = 'per-transition-v1'` at a `beaconSetVersion` this build understands (D15), read from the blob's plaintext the same way `src/lightning/recovery/wire-safety.ts:107-178` reads `quorum` from a frame;
- (c) the capsule's head equals the highest beacon head P returns, and that beacon carries a verified `HEAD_ACK` signed by P which P reports as `latest`;
- (d) no other holder returned a higher `(generation, writerEpoch, latestSequence)`; if one did, P under-reported, the row gets NO evidence, and `peer_storage_underreport` is logged with P's own signed ack as the exhibit;
- (e) the consent flag of D19 is on.

Then at reestablish, at the site of the issue #469 note (`src/lightning/channel/channel.ts:10251-10270`), after the DLP arm (`:9828-9857`) and both gap failures (`:9902`, `:9918`) have NOT fired, D1 did not set `restoreRevokedRisk`, D4's chain gate is satisfied, and `_lastReestablishOutcome` is clean, a channel whose `restoreEvidence.fromPeer` is this peer sets and persists `restoreHtlcHoldLifted = true`.

Changes: `addHtlc` (`src/lightning/channel/channel.ts:3040-3058`), `acceptsNewHtlcs` (`:13122-13130`), the admitted-while-unproven fail-back (`src/lightning/node/lightning-node.ts:16356-16385`) and the router exclusion (`src/lightning/advisor/liquidity-advisor.ts:185`) test `restoreRecencyUnproven === true && restoreHtlcHoldLifted !== true`. `_dropUnsignedLocalAddsIfHeld` (`src/lightning/channel/channel.ts:8264-8340`) runs inside the reestablish BEFORE the lift and is untouched.

Does not change: `isMutualCloseHeld` (`src/lightning/channel/channel.ts:5763-5770`) and the eight close-route sites, `skipAutoCloseRestoreUnproven` (`src/lightning/node/lightning-node.ts:24843-24853`), the central `_forceCloseWithReason` guard, and D1's refusal. Every automatic local broadcast stays refused exactly as RECOVERY-PROTOCOL revision 13 designed.

Guard: cap inbound HTLC value admitted on a lifted channel (`maxRestoredInflightMsat`), since the channel cannot enforce an HTLC on chain.

Safety. SAFE, with the loss model stated. Stage 1 admits HTLCs on a channel that already resumes and keeps its funds; the automatic-broadcast refusal that RECOVERY-PROTOCOL revision 13 identifies as THE defence is untouched. Under a lying LSP the loss is bounded to: (i) it cannot make us broadcast a revoked commitment, so justice-path theft of the balance needs operator action, which D1 now also refuses in the known-revoked case; (ii) it can hide payments IT made us after the admitted head, bounded by its own money in that window and caught when D14's second holder has a higher head; (iii) it can withhold settlement of an in-flight HTLC we cannot enforce on chain, bounded by the cap. Never the channel balance.

Trust. The liquidity peer does not withhold a newer head it signed for. That is exactly Phoenix's trust, made signed (D11), cross-checkable (D14), and non-escalating (D1). The user consents at seed import (D19).

**D18. A second, narrower Stage 1 route: the FFOR epoch freeze is a server-free exactness proof.**

Mechanism. An ACTIVE Variant D epoch FREEZES the channel: `_fforUpdateRefusal` refuses add, settle, fee, commit, stfu, shutdown and splice while ACTIVATING or ACTIVE, so R's commitment cannot advance for the life of the epoch. The epoch reestablish TLV already carries `epochId` and `H_act` and is compared on every reconnect (`src/lightning/channel/channel.ts:23086`, `:23150-23181`). Therefore: same `epochId` plus same `H_act` plus matching BOLT 2 `next_commitment_number` is a peer-verified proof that no commitment was signed since the capsule was written. Lift the HTLC hold for that channel while that condition holds, and RE-ARM the hold the instant the epoch leaves ACTIVE.

Also in this point, because they are the same subsystem: journal the automatic-receive job list (D8) and add a boot-time pass over restored channels with an ACTIVE role-R epoch that dials `f.remoteNodeId` and calls `receipts(channelId)`, because today the ONLY automatic caller is `OfflineReceive.sync` driven by a `wallet_data` job list no tier carries; pass `acceptStaleStateRisk` through `POST /ffor/enforce` (#908), which today calls `forceCloseChannel(channelId)` with no risk argument and the daemon route gives no way to supply one (`src/cli/beignet-node.ts:7279-7291`, `src/cli/daemon.ts:2768-2771`), so the one route named for on-chain enforcement cannot enforce on a restored channel; provision at least one witness at epoch start (`fforStartEpoch` already accepts `witnessPeers`); set the invoice expiry to the settlement window rather than 600 s; and raise a node-visible alarm keyed to `min(cltvExpiry)` over held inbound HTLCs with a known preimage, because the skipped `HTLC_CLAIM_FORCE_CLOSE` arm emits only a structured log while `T_exp` runs out.

Safety. SAFE, with the caveat stated: the proof holds only while the peer still reports that epoch ACTIVE under the same `epochId` and `H_act`. A later life that drained the epoch and opened N+1 produces a different `epochId` and the proof correctly fails. Also correct the framing: the record is NOT what makes a voucher claimable; under Variant D a voucher is an ordinary received HTLC with `cltv_expiry = T_exp` and the enforcing material is S's `htlc_signature` list in the commitment state, so what must survive is the whole commitment.

Trust. The peer implements FFOR, which by construction it does: FFOR settlement is beignet-only by feature bit. FIX REQUIRED: `peerSupportsFfor` fails OPEN when the peer init is unknown (`src/lightning/channel/channel-manager.ts:5638-5645`); fail CLOSED on the restore path.

**D19. Default-on consent at the seed import, with a split-brain detector.** (DECIDED)

Mechanism. The daemon default for `BEIGNET_RECOVERY_AUTO_APPLY` stays exact-true/false and OFF, as #690 review point 1 decided, because the daemon cannot tell an import from a create and library embedders have not consented. A new daemon option `walletOrigin: 'created' | 'imported'` (`BEIGNET_WALLET_ORIGIN`, precedence per `src/cli/config.ts:525-567`) lets the EMBEDDER move the default: when `walletOrigin === 'imported'` and `recoveryMode === 'peer-storage'`, `recoveryAutoApply` and a new `recoveryTrustLiquidityPeer` (the D17 consent) default to true, each overridable with an explicit false. Every refusal in the validation block (`src/cli/daemon.ts:786-855`) is unchanged, so the five refusal tests keep their meaning with the flag explicit. beignet-umbrel flips the Import tab (`manager/ui/src/pages/WalletsPage.jsx:311-334`) to peer-storage plus auto-apply with an OPT-OUT checkbox reading "The previous device may still be running: do not restore automatically". Consent text, one paragraph: "Your liquidity peer keeps your channel backup. Restoring trusts it to return the latest one. It can never take your funds without your action, but it could hide payments it made to you after the last backup it acknowledged."

Split-brain detector: a restoring node composes no capsule while empty, so any blob the provider accepted from this node id during the settle window came from ANOTHER device; the D11 ack-latest carries `lastAcceptedAt` and `otherSessionsLast10m`, and `evaluateAutoApplySettle` refuses with `autoApply.lastReason = 'SPLIT_BRAIN_SUSPECTED'` when either falls inside the window.

Safety. SAFE. Auto-apply already exists behind a flag and re-runs every manual refusal; the default moves, the checks do not. The detector is a heuristic that can only ADD refusals. It is detection, not fencing: peer-storage mode has no epoch, and a device offline for the whole window is invisible. D5 is what makes the default honest.

### Part F. Backstops, experiments and what stays optional

**D20. `channel_reanchor`: an EXPERIMENT with a hard gate, not the default path.**

Mechanism, as corrected by the review. The property people want is real but the jump is not its source: non-derivability follows from the shachain direction alone (`src/lightning/keys/shachain.ts:80-92` plus `index = MAX_INDEX - n` at `src/lightning/channel/channel.ts:309-321`), so head+1 is ALREADY non-derivable. The jump buys only margin when the true head is unknown. Three refutations change the shape of the work.

1. NOT UNILATERAL. The commitment number is XOR-stamped into the signed transaction (`src/lightning/script/commitment.ts:276-282`, `src/lightning/channel/commitment-builder.ts:586-591`) and verified at `src/lightning/channel/channel.ts:4674-4698`, and `src/lightning/channel/channel.ts:9828-9857`, `:9902-9907`, `:9918-9923` make beignet CLOSE any channel whose peer announces a jumped counter.
2. THE PIN IS THE BLOCKER, NOT THE ENABLER. `revoke_and_ack` carries no index, so the receiver files the secret at `MAX_INDEX - its own revocationCount` (`src/lightning/channel/channel.ts:4913`, `:1318-1325`); a decoupled jump either fails the channel with 'Invalid per-commitment secret' at `:4917-4922`, or silently poisons `ShaChainStore` and breaks every justice lookup at `src/lightning/chain/output-resolver.ts:277`, `:380`, which is direct loss.
3. REPEAT-RESTORE HAZARD. `perCommitmentSeed` is seed-derived and the index counter resets, so a fixed offset from the capsule head regenerates identical points, secrets and taproot nonces on a SECOND restore from the same capsule, at heights the peer already collected during the first, which is maximally toxic and, on taproot, funding-key extraction from one reused MuSig2 secnonce.

The corrected shape, if it is built at all. A bilateral, feature-bit-gated beignet-to-beignet verb with FIVE pieces: a `channel_reanchor` handshake carrying the agreed number; an explicit revocation index on `revoke_and_ack` (odd TLV or a derived-index rule) replacing the count pin on BOTH ends; gated relaxation of the three closing arms; refusal while any splice is in flight or unlocked and abort of any live FFOR epoch; and a hard entry cap plus a serialization bound on `ShaChainStore`, which today documents 49 entries and enforces nothing (`src/lightning/keys/shachain.ts:99-103`, `:135`). The target must be an ABSOLUTE floor chosen with zero peer input, monotone across restores (a new capsule field advanced and republished on every refresh), under 2^48, with a persisted never-revisit-a-height invariant.

Safety. UNKNOWN. Gate before it may be scheduled: (i) Phase 0 must confirm the pin arithmetic at `src/lightning/channel/channel.ts:4880-4925` and the shachain bound; (ii) a double-restore test from the same capsule must assert distinct heights and distinct taproot nonces; (iii) an interop test must assert that a reanchor attempt against a non-beignet peer degrades to the existing DLP close rather than a signature-verification failure; (iv) the production counterparty must be a beignet node, because the verb is worth nothing against LND (as decided, it is). It also does not do what was claimed: it removes only the risk that OUR new commitment is punishable. It does nothing about our lost ability to punish the peer's pre-restore revoked states (the received-secret store died with the database and `src/lightning/chain/output-resolver.ts:315-327` needs a stored secret) and nothing about the balance and HTLC set, which remain the peer's assertion. It therefore cannot clear `restoreRecencyUnproven` on its own.

**D21. Tier 0: a seed-only `to_remote` sweeper, the floor under every tier.**

Mechanism. A chantools-style scanner: for every funding transaction learned from the capsule, an SCB entry, or a gossip self-lookup, watch its spend; classify with the key-material-free classifier (the future-commitment arm of `classifyCommitmentTx`, `src/lightning/chain/output-resolver.ts:336-366`) and claim our `to_remote` across all four variants (plain static_remotekey P2WPKH, the anchor CSV-1 P2WSH, the taproot leaf, the liquidity-ads lease) from the static payment basepoint alone (`classifyTheirFutureCommitmentOutputs`, `:1150-1210`), enumerating channel key indices up to the journaled high-water mark or a bounded range when unknown. Also fix the SCB's chain evidence: carry the funding attempt inputs and the funding script in `IScbChannelEntry` so `watchRecoveredFundingOutput` (`src/lightning/node/lightning-node.ts:9489-9515`) gets the same lineage discovery the disk-restore path has (`:9256-9280`, `src/lightning/chain/chain-watcher.ts:2109`) and drops its txindex dependency.

Safety. SAFE. Only `to_remote` outputs paying our own static basepoint are claimed; nothing local is ever broadcast. This is the outcome when the LSP force-closed during the week and deleted its blob, and it is the reason a withholding LSP produces a freeze rather than a loss.

Trust. Electrum history answers; no SPV of the sweep is needed because the output pays only us.

**D22. The guardian tier: what must land before it can be recommended, let alone defaulted.**

Mechanism. Serving cannot be defaulted on as built, and the rotation story needs correcting. Prerequisites, all refusal-and-reporting changes on the host side: a GLOBAL byte and disk cap (today only `maxBytesPerSet` 256 MiB times `maxSets` 16, measured in content bytes with no VACUUM, `src/lightning/recovery/guardian-host.ts:75-77`, `:434`, `:506`, `:531-541`); a cap on the session map and on retained in-flight bodies (one responder per peer, about 64 times 4 MiB retained each, `:207-219`, `src/lightning/recovery/guardian-bolt8.ts:423`, `:705-708`); a real token bucket and a truthful `rate_limit_per_minute`, since 0 is the spec's "unspecified" and `ERR_RATE_LIMITED` is never returned; ADMISSION tied to an existing relationship or an explicit allowlist, because today 16 registrations from throwaway keypairs permanently close a host and there is no unregister verb; `loadIndex` quarantining a bad entry and reporting `indexProblems[]` instead of throwing inside the LightningNode constructor; and #861 (a failed bind must surface and disable serving) and #862 (never begin a rotation at `tip() === 0`, which is EVERY seed-only first boot) fixed.

Restore side, before any set may be trusted: `readHeads` waits for every dialable member up to a settle floor rather than proceeding on 2 (`src/lightning/recovery/restore-driver.ts:503-526`), a guardian head below the capsule's own head is refused (`src/lightning/recovery/capsule.ts:621-624`), an uncorroborated guardian head installs HELD rather than resumed, and a guardian answering for a namespace at a lower generation than any other answer is treated as retired evidence.

Rotation, corrected: fire on the first CONFIRMED loss (a signed non-answer or an operator-declared removal), never on silence, which is indistinguishable from a partition; make retirement a COMPLETION condition rather than fire-and-forget at `accepted > 0`, because an un-retired outgoing guardian keeps serving the old namespace under the old lease and a later restore reaching it takes over at epoch+1 on a stale journal while the live node commits to a disjoint set, which is split brain across guardian sets and a revoked-commitment penalty shape.

Safety. UNSAFE today, and this is the one path in the threat model that reaches L4 without an operator action: a quorum restore stamps NEITHER flag, so two colluding guardians plus one honest guardian unreachable yields a live channel with automatic closes armed at a stale head.

Consequence for this design. No seed-only tier may depend on ambient guardian availability. There is no guardian feature bit, no advertisement, no directory and no degenerate profile, so a seed-only restore cannot FIND three guardians in any case. The guardian tier stays the documented strongest OPTIONAL route and Stage 2's only proven realisation, tracked by its own issues.

**D23. Wire and configuration allocations.**

Message 44069 recovery block (`src/lightning/message/custom.ts:18-40`, 32 and 33 already used): **34 HEAD_BEACON**, **35 HEAD_ACK**, 36 to 47 reserved. Feature bits, experimental even/odd beside `OPTION_FF_RECEIVE = 560`: **562/563 OPTION_HEAD_ACK**, 570/571 reserved for `OPTION_REANCHOR` if D20's gate is ever met. New constants: `BEACON_GATED_MESSAGE_TYPES` and `BEACON_POLICY_VERSION`, independent of `QUORUM_BARRIER_MESSAGE_TYPES` and `WIRE_SAFETY_POLICY_VERSION`. New env: `BEIGNET_RECOVERY_BOOTSTRAP_PEERS`, `BEIGNET_WALLET_ORIGIN`, `BEIGNET_RECOVERY_TRUST_LIQUIDITY_PEER`, `BEIGNET_PEER_STORAGE_TRUSTED`. Docs: RECOVERY-PROTOCOL revision 16 amending 5.4 (capsule v2 header, retention policy, the drop policy, the version read-back rule), 5.6 (the two-stage lift and its single clearing counterpart), 5.8 (a "peer-ordered" row beside local, async-remote and quorum, explicitly NOT a barrier mode and explicitly minting no `IWireSafetyProof`), and section 9 Phase 3 per section 9 below. RECOVERY-GUARDIAN-WIRE unchanged.

Safety. SAFE. Odd types and unknown subtypes are ignored by every non-beignet peer without disconnecting.

## 7. The honest ceiling

A Tier 2 restore against a cooperating beignet liquidity peer comes back LIVE and funds-preserved, able to send and receive, but PEER-ENFORCED rather than self-enforcing: every automatic local broadcast stays refused, so on-chain enforcement of an in-flight HTLC or of a stalled peer needs the operator, and in the one case where our restored commitment is provably revoked in the peer's view even that is refused. Penalty channels make that structural, not a beignet choice: a state of unknown recency is never broadcast-safe without eltoo, and the counterparty is the one party that both knows the true head and profits from the answer being wrong.

Stage 2, self-enforcing again, has exactly one proven realisation today, the guardian quorum tier, and that tier is itself gated on hosting and Sybil fixes this design does not do and cannot find three members from a seed.

The default path trusts the liquidity peer not to withhold a head it signed for, which is exactly Phoenix's trust, made signed, cross-checkable and non-escalating; a lying LSP cannot take the balance without operator action, but it can hide payments it made us after the acknowledged head (bounded by its own money, detectable only with a second holder) and can time out capped in-flight HTLCs.

Everything above Tier 1 requires a beignet liquidity peer for peer storage and the ack: direct funding itself only needs `option_dual_fund`, so a CLN or Eclair counterparty is legal, but LND stores nothing, so a wallet whose `liquidityPeer` is Blocktank on LND has no no-servers path above Tier 1. As decided, the production counterparty is beignet (the beignet-umbrel primary), so the default path exists for the first deployment; the LND note stands for any other LSP. FFOR settlement additionally requires beignet by construction.

The capsule ceiling is 65523 bytes for one or two channels, unmeasured for a channel carrying a live `IFforEpochRecord`; over it the restore degrades to SCB plus locator and a DLP close, and the degraded case must refuse to push rather than overwrite a good backup.

Lag: only the per-transition beacon beats a tolerance of ZERO completed payment rounds, and even then an honest provider crash inside its own write window loses the newest head unless the synchronous-persist rule lands. A dead or unwilling LSP yields a permanently frozen channel with no local exit and no deadline, which no protocol here fixes.

Discovery: zero-conf direct-funded channels are private so gossip self-lookup cannot help the best UX, and the very first boot after import depends on the embedder or app supplying the LSP URI; no seed-derived pointer exists. Split brain is detected heuristically, never fenced, in peer-storage mode.

Unjournaled state outside the two-key allowlist is still lost: swaps, held forwards, hold-invoice parking, mid-flight direct-funding requests with random per-request keys, BOLT 12 offer `path_id`s, watchtower sessions, and the blobs this node held for others.

The commitment-number reanchor is an unfinished experiment, is not unilateral, is worthless against a non-beignet peer, and would be a total-loss bug if shipped without a monotone never-revisit-a-height floor.

## 8. Sequencing

Each phase is a set of mergeable, PR-sized deliverables. Phase 1 ships ahead of the feature as four separate bug issues (#905, #906, #907, #908) plus the remaining Phase 1 items under #909; the later phases are tracked by #909.

### Phase 0: measure and confirm (no code merged)

Delivers. The four numbers and the one topology fact the rest of the plan rests on.

Work items.

- Compose capsules in `tests/lightning/recovery-phase3.test.ts` for a 1-channel and a 2-channel wallet, with and without a live `IFforEpochRecord`, and record `blob.length` against `CAPSULE_MAX_BYTES` 65523 (`src/lightning/recovery/capsule.ts:537`).
- Time `composeRecoveryCapsuleBlob` on those fixtures, and separately measure the encode-plus-sign cost of a 178-byte HEAD_BEACON, so D10's per-round cost is a number and not a guess.
- Record the production counterparty. As decided, the mainnet `liquidityPeer` is a beignet node (the beignet-umbrel primary, the LFBW deployment), so the default path exists as designed and beignet-umbrel is the first deployment; the tracker states in one line that a Blocktank-on-LND counterparty would get Tier 1 only.
- Verify `src/lightning/channel/channel.ts:4880-4925` (the `expectedIndex` pin) and the unenforced 49-entry `ShaChainStore` bound, so D20 can be classified before it is ever scheduled.

Acceptance. Done when: a table in the tracker gives channels, FFOR present, capsule bytes and compose ms; a one-line statement names the production counterparty's implementation; and the pin arithmetic is written down with line numbers.

Depends on. Nothing.

### Phase 1: close the silent loss paths (D1, D2, D3, D4, D5, D6)

Delivers. A bare-seed boot can no longer inherit a revoked history, publish a provably revoked commitment, answer the chain at height 0, or leave a returning old device able to overwrite the newer backup. Nothing about the dream is built yet; this is the floor everything else stands on, and every item is independently shippable. D1, D2 and D3 are #905, #906 and #907; the `POST /ffor/enforce` fix from D18 is #908 and ships alongside them.

Work items.

- `restoreRevokedRisk` field, its reestablish setter, its addition to `mustNotBroadcastCommitment`, and the gate on `forceCloseChannel` and `POST /channel/forceclose` (D1, #905).
- `newChannelsRefused` predicate in `deriveKeysForNewChannel` covering the inbound acceptors, plus the monotone chain-tip floor for `_nextChannelIndex` on an empty `channel_key_indices` table (D2, #906).
- Reject an all-zeroes `your_last_per_commitment_secret` above revocation number 0 (D3, #907).
- `acceptStaleStateRisk` accepted and passed through by `POST /ffor/enforce` (D18, #908).
- Chain-sync gate: park reestablish under the existing hold and refuse HTLC admission until a header tip plus one merkle-checked funding answer (D4).
- Head-based self-fence in every recovery mode, plus the never-push-a-lower-head rule (D5).
- Per-peer stranger quota on the hold table, auto-apply re-arm and hold renewal on capsule arrival (D6).

Acceptance. Done when: a node booted from a seed against an empty directory that then opens OR accepts a channel derives an index no prior device could have used, and a test derives the old channel's keys at index 1 and asserts the new funding pubkey, revocation basepoint and per-commitment seed all differ; a restored channel whose peer reports `next_revocation_number === localCommitmentNumber + 1` refuses an operator force close with a named reason while a clean restored channel still permits one; a peer sending all-zeroes at a non-zero revocation number is rejected rather than silently trusted; `POST /ffor/enforce` with `acceptStaleStateRisk` force-closes a held channel and without it refuses with the same named reason as the close routes; a restored node receiving `channel_reestablish` at height 0 parks it and answers only after a tip, and a final-hop HTLC whose `cltv_expiry` is below the true tip is refused; two daemons on one mnemonic, where the second restores and the first reconnects to the storage peer, end with the first frozen before it pushes and the storage peer's blob never rolled back; a stranger with 16 connections cannot prevent the LSP's reestablish from being held; and all existing auto-apply refusal cells stay green.

Depends on. Nothing. Can run in parallel with Phase 0.

### Phase 2: the node comes home on its own (D7, D8, D9)

Delivers. Import the seed with the LSP URI supplied by the app and the channel comes back automatically, HELD exactly as today, with no HTTP call, and with the LSP identity carried in the capsule for every later boot.

Work items.

- `recoveryBootstrapPeers` config plus `BeignetNode.homeToBootstrapPeers` with the `homing` status block, across `src/cli/config.ts`, `src/cli/beignet-node.ts`, `src/cli/daemon.ts`, `src/cli/openapi.ts` (D7).
- `kv_state` mutation with a CLOSED key union and per-key shape validators, snapshot field, codec, apply, probe, `assertEmptyTarget` treatment; route `persistDirectFundingPolicy` and the OfflineReceive job list through `recovery.commit`; SCB-seeded provisional `liquidityPeer` at install (D8).
- The seven-phase boot machine, the `searching` and `none-found` terminals, per-channel outcome events and `restore.channels[]`, the 503 `NODE_RESTORE_SETTLING` quiescence refusal, and the three none-found actions including the confirmed-empty marker D2's fence consumes (D9).
- beignet-umbrel: pass `BEIGNET_RECOVERY_BOOTSTRAP_PEERS` from `lf.primary` and `BEIGNET_WALLET_ORIGIN` from the import tab in `_daemonEnv`; render searching, none-found and held.
- Tests: homing dial (dead URI then live), `kv_state` round trip plus allowlist and shape refusal, a recovery-surface cell where the capsule arrives over a REAL connection (extend `tests/lightning/peer-storage.test.ts:480-522` with `restoreBestRecoveryCapsule`), and a composeSource that carries a CHANNEL rather than only an invoice.

Acceptance. Done when: a wallet booted on an empty directory with one bootstrap URI and auto-apply on resumes its channel with no operator call and the LSP logs no unknown-channel error; the restored `wallet_data` holds `df:policy` from the capsule and `GET /direct-funding/policy` names the liquidity peer with no operator POST; a boot with an unreachable bootstrap peer ends in `none-found` inside the window, reports the four discovery facts and refuses `/channel/open`; an invoice requested during settling is refused with `NODE_RESTORE_SETTLING` and the restore still applies; and an import on the wrong network ends in `none-found` with the network named.

Depends on. Phase 1 (D2's fence consumes D9's marker).

### Phase 3: the beacon becomes evidence (D10, D11, D12, D13, D15, D16)

Delivers. Every barrier-class message to the liquidity peer is preceded on the same socket by a signed head that names the frame authorizing it; the peer persists it synchronously and signs an acknowledgement the restore gets back; the capsule header declares the policy; and the capsule can no longer degrade or version-bump silently.

Work items.

- `beforeGatedSend` hook in `ChannelManager` config and the single call in `_dispatchActions`, plus the two funding-broadcast actions; `LightningNode` implementation with per-peer dirty bits, the `sendsBlocked` coupling when the send takes the `message:outbound` fallback, and the `beaconPush` status block; `BEACON_GATED_MESSAGE_TYPES` and `BEACON_POLICY_VERSION` as separate constants (D10).
- HEAD_BEACON 34 and HEAD_ACK 35, feature pair 562/563, provider-side synchronous persist plus rate limit plus stored ack, ack-latest on connect with `retentionBlocks`, `lastAcceptedAt` and `otherSessionsLast10m`; client verification and bookkeeping (D11).
- Storage-gate fix for an open in flight, on both sides (D12).
- Flush pending blobs on disconnect and on shutdown; retention policy documented and advertised (D13).
- Capsule v2 header, a decoder accepting 1 and 2, the priority drop policy that REFUSES rather than overwriting, `recovery:capsule-degraded`, the `CHANNEL_BACKUP` readiness FAIL, and the version read-back rule with a fixture per shipped version (D15).
- Per-peer blinded ids (D16).
- Docs: RECOVERY-PROTOCOL revision 16 for 5.4 and 5.8.

Acceptance. Done when: over the recorded chaos schedules for `s1aSenderPays` and `s1bReceiverFulfills`, no barrier-class message to a beacon peer is delivered before the beacon covering its frame (a new `assertBeaconPrecedesGatedSend` modelled on `assertNoGatedSendBeforeCommit`, `tests/lightning/helpers/chaos-harness.ts:1082-1112`); a restore after two payments in the last minute comes back at the exact head with no DLP arm, where today it ERRORs; a capsule pushed immediately before `funding_signed` is ACCEPTED rather than logged and dropped; a provider killed between beacon receipt and ack loses nothing it acked, and a provider killed inside its 60 s capsule window still lands in the one-round DLP arm rather than resuming; ack sign, verify, tamper and counter-regression cells pass; a v1 capsule decodes after the version constant bumps; a capsule that exceeds the ceiling produces a degraded event and a FAIL readiness check and does NOT overwrite the stored blob; a peer without the ack bit gets the timer path unchanged; and `tests/lightning/recovery-phase6-exactness.test.ts` stays green because `WIRE_SAFETY_POLICY_VERSION` did not move, with a new pinned test asserting the beacon path mints no `IWireSafetyProof`.

Depends on. Phase 2 (homing and the journaled LSP identity are what make the restore reach the peer at all).

### Phase 4: springs back to life (D17, D18, D19, and the acceptance test)

Delivers. Import the seed, the node finds the peer, applies the capsule, reestablishes, and can receive and send again with no operator action, with every automatic broadcast still refused and the trust stated once at import.

Work items.

- `restoreEvidence` at install with the five-part predicate, `restoreHtlcHoldLifted` at reestablish, the four HTLC predicates, `attestedBy` on status, `maxRestoredInflightMsat` (D17).
- The FFOR-freeze lift and its re-arm; journal the receive job list; the boot-time receipts pass; witness provisioning; invoice expiry set to the settlement window; the `min(cltvExpiry)` alarm; `peerSupportsFfor` failing closed on the restore path (D18; the `POST /ffor/enforce` flag is #908 in Phase 1).
- `walletOrigin`-driven defaults, the consent text, and `SPLIT_BRAIN_SUSPECTED` in the settle logic (D19).
- The acceptance test file, the `attested-resume` chaos verdict and oracle, and the negative cells.
- Docs: 5.6 two-stage lift, section 9 Phase 3 amendment, README env table, `src/cli/openapi.ts` schema.

Acceptance. See section 9; in short, done when the end-to-end regtest flow passes including a post-restore receive AND send with `restoreRecencyUnproven` still true and zero non-alive broadcasts.

Depends on. Phase 3.

### Phase 5: redundancy without new wire (D14, D21)

Delivers. Rollback and withholding by the liquidity peer become survivable rather than undetectable, and a channel the LSP closed while we were gone is sweepable from the seed alone.

Work items.

- Persisted storage-trust list on the holder, consulted in `peerQualifiesForStorage`, and `POST /peer-storage/trust`; a "Pair a device" flow in beignet-umbrel that adds the phone's node id and hands back the home node's URI as a bootstrap peer (D14).
- Journal `peer_storage_blobs` so a home node that restores from its own seed does not lose every blob it held for others, plus a beignet-to-beignet re-upload-on-reconnect request.
- Tier 0 sweeper over `classifyTheirFutureCommitmentOutputs` with a bounded index enumeration; SCB entries carrying attempt inputs and the funding script so Tier 1 gets lineage discovery (D21).

Acceptance. Done when: a wallet whose LSP returns an older capsule while a second beignet holder returns the newer one installs the LSP's channel WITHOUT evidence, logs `peer_storage_underreport` with the LSP's own signed ack as the exhibit, and restores at the newer head; a wallet whose LSP force-closed and deleted the blob recovers its `to_remote` from the seed and Electrum alone across the plain and anchor CSV-1 variants; an SCB naming an RBF-superseded funding txid still finds the channel on chain; and a 65th trusted storage peer is refused.

Depends on. Phase 3 for the ack, Phase 2 for the bootstrap list.

### Phase 6: optional and gated (D20, D22)

Delivers. Either a route from Stage 1 to a fully self-enforcing channel without guardians, or a written rejection with the reason; and a guardian tier that could honestly be recommended to home-node users.

Work items.

- D20 design review against the Phase 0 findings, with the five required pieces and the monotone-floor rule; ship only behind `OPTION_REANCHOR` with a full chaos matrix, or reject it in the tracker.
- D22 host caps, session cap, token bucket, admission, index quarantine, #861 and #862 fixes, `readHeads` wait-for-all-reachable, the capsule-head cross-check, the HELD fallback for an uncorroborated guardian head, rotation on confirmed loss with retirement as a completion condition.
- Allowlist growth for `kv_state` (held forwards, the swap ledger) with per-key shapes and idempotency arguments.
- Delta beacons or delta capsule pushes if the Phase 0 numbers demand it.

Acceptance. Done when: two reference guardians serving a stale head plus one honest guardian reachable yields the honest head, and with the honest one unreachable and the capsule head higher the restore installs HELD; a registration flood cannot fill `maxSets` on a default-configured host and a corrupt index never prevents the host's own wallet from booting; a rotation at `lastDurableSequence 0` is never begun; and EITHER a reanchored channel force-closed by the restored device is never penalized in a matrix where the peer holds every secret the lost device released, with a double-restore cell proving no height is ever revisited and an interop cell proving graceful degradation against a non-beignet peer, OR the reanchor is rejected in the tracker with the reason recorded in RECOVERY-PROTOCOL 12.1.

Depends on. Phase 4, and for D20 the Phase 0 verification.

## 9. Acceptance

### The end-to-end scenario

New file `tests/lightning/interop/seed-restore-lsp-regtest.test.ts`, Docker-gated exactly like `tests/lightning/interop/taproot-scb-recovery-regtest.test.ts`, with `INTEROP_REQUIRE_BEIGNET_E2E=1` turning the skip into a failure per the README convention. It lives in `tests/lightning/interop/`, outside `test:lightning` and `test:chaos`, with a stated budget of eight cells.

Parents, both named in the tracker: `tests/lightning/recovery-phase3.test.ts:1137` (empty storage plus a live peer, but synthetic keys and an in-process blob) and `tests/cli/recovery-surface.test.ts:2257` (a BIP39 mnemonic plus an empty dataDir, but an injected capsule, an offline Electrum and no channel). No existing test has all three legs.

Topology. Two beignet daemons over the compose bitcoind and electrs (`docker/docker-compose.yml`), the LSP with `peerStorageEnabled` and `OPTION_HEAD_ACK`, the wallet in peer-storage mode, keys from `deriveLightningKeysFromMnemonic` through `createInteropNode` (`tests/lightning/interop/shared-helpers.ts`).

Flow.

1. Wallet booted with `walletOrigin: created`; `POST /direct-funding/configure` names the LSP; a direct-funded channel opens through `tests/lightning/helpers/df-sender.ts` and the wallet receives two payments. Assert on the wire, through a tap on the wallet's peer socket, that a HEAD_BEACON precedes every barrier-class message to the LSP and that each is acked.
2. Kill the wallet daemon, DELETE its data directory, mine 1008 blocks (the agreed "week" convention: a block gap only, with an injected clock for millisecond TTLs as `tests/lightning/recovery-phase7-restore.test.ts:64-65` already does).
3. Boot the wallet with the same mnemonic, an empty directory, `walletOrigin: imported` and `recoveryBootstrapPeers` set to the LSP URI, and make NO HTTP call. Assert `recovery:capsule-retrieved` fires with `fromPeer` equal to the LSP pubkey over a REAL connection, autoApply reaches `applied` at tier 2 with `restartRequired: false` and `resumed: true`, the channel is NORMAL with the pre-kill balance, the row carries `restoreRecencyUnproven: true` plus `restoreEvidence` naming the LSP and the acked head, plus `restoreHtlcHoldLifted: true` after reestablish, the LSP's log has no unknown-channel error, and `df:policy` and the receive job list are present in the restored `wallet_data` so `GET /direct-funding/policy` names the liquidity peer with no operator POST.
4. THE DREAM: receive one more payment and send one. Both settle.
5. Assert zero non-alive broadcasts throughout.

### Negative cells (same file)

- The LSP returns an older pinned blob while a third daemon, trusted via the persisted storage-trust list, returns the newer one: the LSP's channel installs WITHOUT evidence, stays held, and `peer_storage_underreport` is logged with the LSP's own signed ack.
- An LSP without the ack bit yields a held restore exactly as today (`tests/lightning/recovery-phase3.test.ts:1276`, "No route", still holds).
- A blob accepted from another session inside the settle window refuses auto-apply with `SPLIT_BRAIN_SUSPECTED`.
- An `open_channel` from the LSP during settling is refused with the named reason and succeeds after apply; a fresh database never derives channel index 1.
- A v1 capsule restores held; a wrong-network capsule is refused; a boot that finds nothing ends in `none-found` and refuses a channel open until confirmed.
- One hand-driven kill (the `killAt` shape at `tests/lightning/recovery-phase7-restore.test.ts:69-86`) between capsule install and rebuild, then a reboot that resumes via `finishStagedCapsuleRestore`.

### Harness change

A fourth `ChaosVerdict`, `attested-resume`, added to the closed set at `tests/lightning/helpers/chaos-harness.ts:1015`, with `assertAttestedResume` in `tests/lightning/helpers/chaos-oracle.ts` (NORMAL, `restoreRecencyUnproven` true, `restoreHtlcHoldLifted` true, `acceptsNewHtlcs` true, zero non-alive broadcasts). Used by this file only, so the existing `expected()` callbacks are untouched. Budget it: the verdict vocabulary is closed and each added kill boundary costs a full scenario replay.

### Unit and library cells

Beacon sign, verify, tamper and counter regression; `assertBeaconPrecedesGatedSend` over a recorded chaos schedule for `s1aSenderPays` and `s1bReceiverFulfills`; capsule v2 decode of v1 and v2 plus one fixture per shipped version; `kv_state` codec round trip, probe coverage, allowlist refusal and shape refusal; the channel-index fence and floor, including a cell that derives the old channel's keys at index 1 and asserts every derived value differs; `restoreRevokedRisk` set at the half-round reestablish and the force close refused; the all-zeroes secret rejected above revocation number 0; the chain-sync gate refusing an expired final-hop HTLC at height 0; a homing dial with a dead URI then a live one; a provider crash inside its 60 s capsule window landing in the one-round DLP arm; an oversized capsule refusing to push rather than overwriting a good blob.

### Amendments to docs/RECOVERY-PROTOCOL.md section 9

**Phase 3 (amended).** Done when: a seed-only restore integration test binds a BIP39 mnemonic, an empty data directory and a live storage peer over a real connection, with the capsule received through `sendPeerStorageOnConnect` rather than emitted; the daemon boots with no configuration beyond one bootstrap peer, passes `searching`, `settling`, `applying`, `resuming` and `restore:complete` with no HTTP call, rebuilds in-process, and the channel returns NORMAL with its balance while the peer logs no unknown-channel error and never force-closes; a channel the capsule's SCB names but its journal does not carry is reported `closing-safely` in a `capsule:channel` outcome; the same run over Tor lands inside the ceiling; a boot that finds nothing ends in `none-found` and refuses a channel open until confirmed; a boot on the wrong network reports `none-found` with the network named; and oversized state degrades by REFUSING to push rather than by replacing a good blob.

**Phase 7 (amended).** The daemon-level SIGKILL smoke test that section 9 already promises exists and kills once between `capsule:installed` and `capsule:resuming`, and the durable marker replays the install on restart.

**New Phase 8, peer-ordered durability.** Done when: no barrier-class message to a beacon peer is delivered before the beacon naming its frame, on every recorded chaos schedule; the beacon path mints no `IWireSafetyProof` and `WIRE_SAFETY_POLICY_VERSION` is unchanged (`tests/lightning/recovery-phase6-exactness.test.ts` stays green); a provider persists a beacon before acking it and loses nothing acked across a kill; a restore whose capsule head is below the highest beacon head any holder returns refuses to auto-apply rather than applying into a DLP close; and a restore against an under-reporting holder installs without evidence and names the holder.

**New Phase 9, the two-stage lift.** Done when: a Stage 1 lift is granted only under the full five-part predicate and is revoked when any part fails at a later reestablish; a lifted channel admits HTLCs in both directions and still refuses every automatic broadcast, with `tests/lightning/held-restore-unsigned-adds.test.ts` and the `acceptStaleStateRisk` cells in `tests/cli/recovery-surface.test.ts` unchanged; an FFOR-frozen channel lifts on the epoch match alone and re-arms the hold the instant the epoch leaves ACTIVE; and a restored FFOR receiver holding a preimage claims its voucher before `T_exp` after an explicit, labelled operator action, with an alarm raised well before the deadline.

## 10. Decisions

Three are decided and are marked DECIDED with the answer. The rest carry a recommendation and stay open for the maintainer.

1. **Does Phase 1 ship on its own, ahead of the feature?** DECIDED: yes. D1, D2 and D3 are live fund-safety bugs in the current tree, not prerequisites invented by this design, and holding them behind a feature branch is the wrong order. They ship as separate bug issues #905 (the revoked-commitment hatch), #906 (the channel key index) and #907 (the all-zeroes secret), with the `POST /ffor/enforce` risk flag as #908; this document is the living design, committed as `docs/SEED-ONLY-RESTORE.md`, and #909 carries the phases.
2. **Is the production `liquidityPeer` a beignet node?** DECIDED: yes. The liquidity and settlement peer is a beignet node, the beignet-umbrel primary of the LFBW deployment, so the default path exists as designed and beignet-umbrel is the first deployment. The design still states that the default path requires a beignet LSP for peer storage plus the ack, that direct funding itself needs only `option_dual_fund` so a CLN or Eclair counterparty is legal for the funding leg, and that LND stores nothing so a Blocktank-backed wallet would get Tier 1 only; that last sentence is a note, not the production case.
3. **Default-on when `walletOrigin === imported` (auto-apply plus the Stage 1 trust)?** DECIDED: yes at the embedder, no at the daemon. Stage 1 trusts the beignet liquidity peer and is default-on at the embedder when `walletOrigin` is `imported`; the daemon default stays off. Phoenix ships exactly this, the daemon's refusals are unchanged, consent is given at the one moment a person is present, and the daemon cannot tell an import from a create. Both flags stay explicit-false capable.
4. **Push the beacon or the capsule per gated message?** Recommend the BEACON. The review measured the alternative at roughly 128 to 256 KiB of padded blob per forwarded HTLC plus a synchronous journal rebase and an SCB ECIES encode inside the commitment-round latency path. The capsule stays on the 60 s cadence plus the fresh compose on connect.
5. **Separate `BEACON_GATED_MESSAGE_TYPES` from `QUORUM_BARRIER_MESSAGE_TYPES`?** Recommend YES, strongly. Widening the quorum set bumps `WIRE_SAFETY_POLICY_VERSION`, which `src/lightning/recovery/wire-safety.ts:150-166` makes a hard cut for every deployed quorum namespace with no implication table. Two sets, two version constants, one hook.
6. **Add lightning-kmp's close flow (shutdown, closing_signed, closing_complete, closing_sig) to the beacon set?** Recommend YES for the beacon set only, in Phase 3, since it is what lets Phoenix cooperatively close after a restore while beignet's Tier 2 cannot.
7. **Withhold the gated send when the beacon push fails?** Recommend YES, but only when the peer advertised the ack bit AND the send took the `message:outbound` fallback rather than the socket. Anything broader breaks interop with peers that never negotiated the bit.
8. **`kv_state` shape: closed typed union or opaque key-value?** Recommend the CLOSED union with per-key shape validators, v1 being exactly `df:policy` and `automatic_receive_jobs_v1`. The review is right that an opaque variant would journal auth secrets and random per-request keys into a blob replicated to peers and guardians.
9. **Seed `liquidityPeer` from the SCB's `peerNodeId` at install?** Recommend YES as a PROVISIONAL value when the restored node has exactly one channel peer, with `allowZeroConf` left off and operator confirmation required before the zero-conf latitude returns. It costs no new journal surface and it is material the node just authenticated.
10. **Channel index floor: chain tip or random?** Recommend the CHAIN TIP, `max(1, tipHeight)`, because it is monotone across an unlimited number of device losses, which is the property that also defeats the repeat-restore collision. A random 31-bit offset is not monotone and would need the same floor carried somewhere anyway.
11. **Does the Stage 1 consent also pre-authorise the cooperative close?** Recommend NO for v1, contrary to one proposal. The stale split can only be peer-favourable, `isMutualCloseHeld` is consulted at eight sites, and a user who has traded for months under Stage 1 can be handed a fresh `acceptStaleStateRisk` prompt at close time that names the amount. Revisit once the in-flight cap has real numbers behind it.
12. **In-flight cap on a lifted channel?** Recommend YES, defaulting to half the channel's own `max_htlc_value_in_flight`. It bounds the one loss the peer can realise without our broadcast.
13. **`channel_reanchor`: build, defer or reject?** Recommend DEFER behind the Phase 0 gate and treat the guardian quorum tier as the only currently proven Stage 2. The review refutes it as a unilateral move, identifies the `expectedIndex` pin as the blocker, and identifies a repeat-restore height-revisit hazard that is total loss on taproot. It is a wire-protocol change with a feature gate, not a restore-path tweak, and it is worth nothing against a non-beignet peer.
14. **Ship the FFOR-freeze lift (D18)?** Recommend YES. It is the only exactness proof in this design that needs no ack, no second holder and no new trust, it is self-limiting because it evaporates when the epoch leaves ACTIVE, and it covers precisely the "pay me while I am away" case.
15. **Fix `POST /ffor/enforce` to accept `acceptStaleStateRisk`?** Recommend YES, immediately and independently; filed as #908 under decision 1. As built, the one route named for on-chain enforcement is the one route that cannot enforce on a restored channel, including when the FFOR state machine itself escalates to `ffor:enforce`. That is a bug, not a design choice.
16. **Guardian tier in scope for this design?** Recommend NO beyond stating its prerequisites. The review confirms five blockers to default-on serving and shows rotation's real shape; a seed-only node also cannot FIND three guardians because no feature bit, advertisement or directory exists. Track D22 as its own issues and keep the guardian tier as the documented strongest OPTIONAL route.
17. **On-chain beacon in the direct-funding transaction?** Recommend NO. It permanently fingerprints the first beignet direct-funding transaction, is payer-visible, still does not yield the funding script, needs a scanner the wallet lacks, and whether the existing gap-limit scan would even see it is unverified.
18. **Locator records held by strangers?** Recommend NOT in the default path. It needs the same caps, rate limits and admission story as guardian hosting, which is exactly what the review found missing there. Keep the per-peer blinded id derivation, which is cheap and useful for the trusted second holder.
19. **Where does the acceptance test live and what is its budget?** Recommend `tests/lightning/interop/` with `INTEROP_REQUIRE_BEIGNET_E2E`, outside `test:lightning` and `test:chaos`, with a stated eight-cell budget and one new chaos verdict.
20. **Do we claim a standardization slot?** Recommend drafting ONE bLIP, "witnessed peer storage" (a signed, counted acknowledgement plus the ordered push rule ACINQ uses implicitly plus a retention advertisement), because no LSPS or bLIP covers backup today and CLN and Eclair could adopt it. Keep the rest proprietary on 44069 until it has shipped and been measured.

## 11. Rejected alternatives

- **A unilateral commitment-number jump as the hold lift.** The number is XOR-stamped into the signed transaction (`src/lightning/script/commitment.ts:276-282`) and verified at `src/lightning/channel/channel.ts:4674-4698`, and beignet itself closes any channel whose peer announces a jumped counter (`:9828-9857`, `:9902-9907`, `:9918-9923`). It is a bilateral negotiated verb or it is nothing. Demoted to a gated experiment (D20).
- **Sizing a reanchor off the peer's claimed head.** `src/lightning/channel/channel.ts:9860-9878` records in-tree that a peer can under-report without limit and still pass every reestablish check, so an adversary under-reports by more than the margin and the target lands at or below the true released head.
- **A fixed reanchor offset from the capsule head.** A second restore from the same capsule replays identical heights, whose secrets and taproot nonces the peer collected during the first restore. Total loss, and on taproot a funding-key extraction from one reused MuSig2 secnonce.
- **Treating the reanchor as making post-restore commitments "non-toxic".** It removes only the risk that OUR new commitment is punishable. It does nothing about our lost ability to punish the peer's pre-restore revoked states (the received-secret store died with the database) and nothing about the balance and HTLC set.
- **Pushing the full 64 KiB capsule before every gated message.** About 128 to 256 KiB per forwarded HTLC, padded to the wire maximum, plus a synchronous journal rebase and an SCB ECIES encode inside the commitment-round latency path, and it invites the receiver's own rate limiter to drop the head the scheme depends on.
- **Implementing the per-transition push as an `IWireDurabilityBarrier`.** The interface has no peer parameter (`src/lightning/channel/channel-actions.ts:465-495`), is consulted before dispatch, and would route every batch through the async queue; the guarantee here is ordering, not a receipt.
- **Treating the ordering barrier as a durability barrier or a recency proof.** BOLT 1 has no ack, the receiver may ignore the blob outright (no channel yet) or persist lazily, and the sender never learns which happened. It must not clear `stateUncertain` or `restoreRecencyUnproven`, and it must mint no `IWireSafetyProof`.
- **Widening `QUORUM_BARRIER_MESSAGE_TYPES` to carry the beacon set.** That bumps `WIRE_SAFETY_POLICY_VERSION`, which `src/lightning/recovery/wire-safety.ts:150-166` makes a hard cut for every deployed quorum namespace, with the implication table the comment anticipates still unbuilt.
- **Copying lightning-kmp's overflow terminal.** `Encryption.kt:67-70` sends an EMPTY blob past one oversized channel, and BOLT 1's replace rule then destroys a good backup silently, with only a log warning. beignet refuses to push instead.
- **Dropping beignet's blob padding.** lightning-kmp does not pad, against BOLT 1's SHOULD; beignet already does and is ahead.
- **An opaque, untyped key-value journal variant for all of `wallet_data` and `metadata`.** It would carry API key overrides and auth secrets into a blob replicated to peers and guardians, and random per-request DF keys, swap outpoints and watchtower sessions with no restore semantics.
- **Lifting the hold on a compatible reestablish alone, or on a counterparty-signed receipt alone.** RECOVERY-PROTOCOL revision 13 and the note at `src/lightning/channel/channel.ts:10251-10270` are right that compatibility is not recency, and the signer is the party that profits from the lie. Stage 1 requires the counterparty-holder, the declared policy, the signed and latest ack, the cross-holder check and a clean reestablish together.
- **Clearing `restoreRecencyUnproven` in Stage 1** (re-enabling automatic force closes and ungated coop close). That hands a lying LSP the justice path against the balance; the permanent refusal of automatic broadcasts IS the defence.
- **Peer-assisted transcript catch-up as an exactness proof.** A replayed transcript inherits the peer's choice of where to stop, which is the identical under-report attack `src/lightning/recovery/wire-safety.ts:7-13` refuses. It is at most a distance-shortener, and on taproot our own rounds can only be served as bytes because the MuSig2 co-signing nonce is fresh random.
- **An on-chain beacon, in the direct-funding transaction or as a self-payment.** The receiver contributes no input and no change, a beacon output leaks the receiver to the payer and to the chain permanently, the funding script still needs the counterparty's per-channel pubkey, whether the existing gap-limit scan would see it is unverified, and a direct-funding receiver may hold zero on-chain sats for the self-payment variant.
- **Making the LSP's per-channel funding pubkey derivable from our node id** so the funding script is chain-scannable. Changes key isolation with an unreviewed blast radius.
- **Nostr or hyperswarm rendezvous on the default path.** No relay client, no NIP-04/44, no DHT code exists; relays cap messages below the blob size and promise no durability or recency. Both remain possible later as opportunistic locator copies (#533, #795).
- **Gossip self-lookup as the primary hop.** Zero-conf direct funding forces the channel private (`src/lightning/channel/channel-manager.ts:6610-6624`) and `announcement_signatures` depends on the LSP, so it fails silently for exactly the flow with the best UX.
- **A locator service held by strangers on the default path.** It needs the same global caps, session caps, rate limits and admission story that the review shows are missing for guardian hosting, and it would make a free anonymous key-value store out of every wallet.
- **CLN-style random two-peer fanout to strangers.** Peer storage is write-gated to channel peers or explicit trust; LDK stores 1 KiB inbound; LND stores nothing. A chosen, trusted second holder is used instead.
- **A sub-1-KiB LDK-compatible capsule.** An SCB digest plus a locator cannot resume anything; LDK peers are simply not storage peers in this design, and the document says so.
- **Default-on guardian serving, automatic guardian selection, a degenerate crash-v2 profile, or a quorum auto-apply lane, in this design.** The review confirms five unfixed hosting hazards; there is no feature bit, advertisement or directory, so three guardians cannot be found from a seed at all; and rotation is refused outright in peer-storage mode and is destructive at `tip() === 0`, which is every seed-only first boot.
- **Deterministic guardian selection recomputed from the public graph.** A set recomputed a week later is not the set holding the records, and under direct funding every candidate the wallet hears about arrives through the LSP.
- **Firing guardian rotation on silence.** Unreachability is indistinguishable from a partition, and the current best-effort retirement leaves an un-retired outgoing guardian serving the old namespace, which a later restore can reach: split brain across disjoint guardian sets with a revoked-commitment penalty shape.
- **Widening the BOLT 2 one-commitment tolerance, or lengthening the capsule refresh window.** The tolerance is the sig-in-flight case consumed by any live disconnect (`src/lightning/channel/channel.ts:9909-9918`), not headroom.
- **Sharding the capsule across storage peers to raise the ceiling.** Adds a manifest, a multi-peer consistency problem and a new failure mode, for a wallet shape the ceiling already covers; the drop policy plus the degraded event is the honest answer instead.
- **Sending `acceptStaleStateRisk` automatically on a held channel.** It signs a split that can only be peer-favourable; the default exit stays the peer closing.
- **LSP dial-back to a restoring wallet.** A wallet has no announced address and beignet has no address autodiscovery, so every rendezvous must be outbound. LSPS5-style wakeup is noted as the adjacent standard, not built.
- **Making a failed listener bind fatal in general.** An outbound-only node is still useful; the refusal is scoped to `guardianServe` (#861).

## 12. Prior art and standardization

**Phoenix (ACINQ/lightning-kmp), pinned at commit `43e4cf1e76caeb9af68478064d30906433ee57cd`.** This is the shape the default path copies: the full serialized channel state rides the BOLT 1 `peer_storage` blob, it is pushed on the same ordered connection ahead of every message carrying a `RequirePeerStorageStore` marker, and a node with no local state restores from the returned blob with no operator action (`maybeRestoreBackup`, `io/Peer.kt:1177-1194`). Three facts about it shaped this design rather than being copied: the marker guards SEVEN message classes including the whole close flow (`wire/LightningMessages.kt:174-175`, `:495`, `:1284`, `:1375`, `:1697`, `:1734`, `:1770`, `:1824`), which is why decision 6 puts the close flow in the beacon set; `maybeRestoreBackup` overrides an existing local channel only while it is `Syncing`, never generally; and on overflow it drops channels lowest priority first and, past one oversized channel, sends an EMPTY blob that overwrites the stored one under BOLT 1's replace rule (`serialization/channel/Encryption.kt:62-71`), which D15 rejects in favour of refusing to push. kmp does not pad its blob; beignet already does. Phoenix has exactly one peer and so cannot detect rollback at a seed-only boot at all; D14's second holder is the highest-value delta over it.

**Core Lightning.** The `recover` plugin (`plugins/recover.c`) dials ten hardcoded bootstrap nodes and then does a gossip self-lookup, which is the pattern D7 layers 1 and 3 follow with the embedder-supplied URI as layer 1. The `chanbackup` plugin (`plugins/chanbackup.c`) fans the backup out to two random peers and refuses an overlength blob; the random fanout is rejected here (section 11) because beignet's write gate admits only channel peers or explicitly trusted ones.

**LDK (rust-lightning).** Inbound peer storage is capped at 1 KiB (`lightning/src/ln/channelmanager.rs`) and `send_peer_storage` is cfg-gated (`lightning/src/chain/chainmonitor.rs`). A sub-1-KiB capsule cannot resume anything, so LDK peers are not storage peers in this design (section 11).

**BOLT 1 peer storage** (`01-messaging.md:535-562`). The requirements this design leans on: the padding SHOULD (`:541`), the one-update-per-minute provider rate limit (`:550`), the replace-the-old-blob rule (`:551`), the retention text (`:556-558`), and the fact that retrieval-before-reestablish ordering is Rationale only, not a Requirement (`:574-575`). The last point is why beignet's reestablish hold (issue #462) is a real differentiator rather than defensive over-engineering, and the replace rule is why an empty push or an empty overflow blob destroys a good backup. BOLT 2 (`channel_reestablish`, data loss protect) and BOLT 3 (per-commitment secret requirements, `remotepubkey = payment_basepoint`) are the basis for D3 and D21 respectively.

**RECOVERY-PROTOCOL 12.2** already records the comparison against LDK's Versioned Storage Service; the guardian tier ships as a VSS-compatible sibling. Nothing in this design changes that.

**Standardization.** No LSPS or bLIP covers channel backup today. The one recommendation is a single bLIP, "witnessed peer storage": a signed, counted acknowledgement of a stored head (D11), the ordered push rule ACINQ uses implicitly (D10), and a retention advertisement (D13). CLN and Eclair could adopt it. Everything else stays proprietary on message 44069 until it has shipped and been measured (decision 20). LSPS5-style wakeup is noted as the adjacent standard for the dial-back problem and is not built.

## 13. Review record

Ten claims underlying the proposals were reviewed independently twice against the tree at commit 4c95e33. For each: the claim as reviewed, the outcome, and what changed in the design.

**C1. Claim:** a post-restore commitment-number jump (reanchor) chosen by the restored side makes every post-restore local commitment non-toxic, and it is implementable in beignet given the `expectedIndex` pin at `src/lightning/channel/channel.ts:4913`, `getPerCommitmentPoint`/`Secret` at `:309-321`, `ShaChainStore.addSecret` at `src/lightning/keys/shachain.ts:110-138`, BOLT 3 obscured commitment numbers, taproot verification nonces, and splices in flight. **Outcome: PARTLY.** The non-derivability property is real but follows from the shachain direction alone (`src/lightning/keys/shachain.ts:80-92` with `index = MAX_INDEX - n` at `src/lightning/channel/channel.ts:309-321`), so head+1 is already non-derivable and the jump buys only margin against an unknown head. The cited pin is the BLOCKER, not the enabler: `revoke_and_ack` carries no index, so the receiver files the secret at `MAX_INDEX - its own revocationCount`, and a jumped secret either fails the channel at `:4917-4922` or silently poisons the store and breaks justice lookups at `src/lightning/chain/output-resolver.ts:277` and `:380`. The number is XOR-stamped into the signed transaction and verified, and beignet itself closes any channel whose peer announces a jumped counter. The review also found a hazard no proposal had: a fixed offset makes a SECOND restore from the same capsule replay identical heights, secrets and taproot nonces, which is total loss and, on taproot, funding-key extraction. **Change:** the reanchor was removed from the default path entirely, became D20 as an explicitly gated experiment, and its mechanism was rewritten as a bilateral negotiated verb with five required pieces and a monotone floor carried in the capsule. Stage 2 therefore has exactly one proven realisation today, the guardian quorum tier, and section 7 says so.

**C2. Claim:** pushing the capsule or a signed head beacon on the same ordered BOLT 8 connection immediately BEFORE the gated message (`revoke_and_ack`, `commitment_signed`, `update_fulfill_htlc`, `tx_signatures`) guarantees the peer received the head before the message that makes the state authoritative, with no extra round trip, and the cases that break it (socket error mid-write, reconnect, the dispatch loop abandoning a queue) are already handled by reestablish. **Outcome: PARTLY.** The ordering property was CONFIRMED end to end from `_dispatchActions` through `socket.write` to `dispatchPeerMessage`, and the three named breakages do funnel into a forced disconnect and reestablish. Four refutations changed the mechanism: the pushed object must be a small signed beacon rather than the full padded capsule (128 to 256 KiB per forwarded HTLC otherwise, plus a synchronous journal rebase in the latency path); the gated set is six types in beignet and seven in lightning-kmp, not the four named; nothing today withholds the gated send when the push fails, because `sendMessage` swallows transport throws and reroutes to `message:outbound`, which breaks the single ordered stream; and `peerQualifiesForStorage` resolves through the permanent channel id, which is registered only at promotion (`src/lightning/channel/channel-manager.ts:8212` against `:993`, `:1063`, `:3575`, `:6704`, `:6980`), so a push before `funding_signed` or `tx_signatures` is DROPPED. Ordering is not durability and not recency: BOLT 1 has no ack and the receiver may persist lazily. **Change:** D10 (beacon, corrected gated set, `sendsBlocked` coupling, reconnect repair) plus a new D12 for the open-time hole; every claim that the ordering constitutes durability or recency was struck; a separate `BEACON_POLICY_VERSION` was introduced so `WIRE_SAFETY_POLICY_VERSION` never moves.

**C3. Claim:** a Tier 2 capsule restore survives a lag of exactly one commitment, the DLP arm at `src/lightning/channel/channel.ts:9828-9857` closes anything further behind, and the capsule refresh throttle at `src/lightning/node/lightning-node.ts:5231` is 60 s, so a per-transition push to a beignet peer removes a real DLP-close window. **Outcome: PARTLY.** The 60 s figure and the existence of a real DLP-close window were CONFIRMED. "Survives a lag of exactly one commitment" was refuted: the DLP predicate is a disjunction, so ONE completed payment round fires it, and the mirror half-round (a missing `commitment_signed`) is closed by `_heldReestablishGapFailure` at `src/lightning/channel/channel.ts:9902-9907`. The only stale state that survives is a single missing `revoke_and_ack`, and it survives onto a local commitment whose revocation secret the peer already holds. "Closes" is wrong: the DLP arm ERRORs and asks the PEER to close, after which `prepareForceClose` refuses permanently, so an unwilling LSP leaves funds frozen with no local exit. The review found two live fund-loss paths no proposal had: `restoreRecencyUnproven` is not in `mustNotBroadcastCommitment` while `forceCloseChannel` is deliberately ungated, so one operator force close on the surviving case publishes a revoked commitment; and the validator at `src/lightning/channel/channel.ts:9803` accepts an all-zeroes secret at any revocation number, which suppresses DLP for free. **Change:** Phase 1 was created ahead of everything else carrying D1, D3 and D4 (now #905 and #907 plus D4), and the summary and section 7 state the zero-round tolerance rather than the one-commitment one.

**C4. Claim:** on the daemon path the LSP identity (`df:policy` liquidityPeer/host/port) does not survive a database wipe or a Tier 2 install: it is persisted only to `wallet_data` via `persistDirectFundingPolicy`, the journal has no key-value mutation (`src/lightning/recovery/types.ts:82-127`), `carryDaemonState` (`src/cli/beignet-node.ts:4617-4646`) copies only three things, and the daemon constructs `directFunding` without a `liquidityPeer` (`src/cli/beignet-node.ts:2429-2435`). **Outcome: CONFIRMED,** at all four anchors, with two sharpenings adopted. An OPAQUE key-value journal variant is UNSAFE because it would carry auth secrets and random per-request keys into a replicated blob, so D8's `kv_state` is a CLOSED typed union with per-key shape validators. The review also supplied a cheaper half nobody proposed: seed `liquidityPeer` provisionally from the SCB entry's `peerNodeId` at install, which needs no new journal surface. Both reviews confirmed that `carryDaemonState` cannot help the dream case because its source database is empty. **Change:** D8 as specified, decisions 8 and 9.

**C5. Claim:** a bare-seed boot resets the per-channel key index to 1 (`src/lightning/channel/channel-manager.ts:648`, `src/lightning/node/lightning-node.ts:2617`) and a channel opened after a failed or partial restore would reuse a live channel's funding key, revocation basepoint and per-commitment seed. **Outcome: CONFIRMED,** and the severity went up. Reuse is triggered by ACCEPTING an inbound open as much as by opening one, so "an empty database dials nobody" is not a mitigation; the theft mechanism is the per-commitment seed rather than the funding key, so the new channel is born pre-revoked; and on taproot, reuse means one MuSig2 secnonce signs two different sighashes, which is funding-key extraction. The review also refuted the random-floor mitigation one proposal offered, because only a MONOTONE floor survives repeated restores. **Change:** D2 uses `max(1, tipHeight)` rather than a random offset, the fence covers the inbound acceptors, and decision 10 records why randomness was rejected. Filed as #906.

**C6. Claim:** guardian serving cannot be defaulted on as built: no global byte or disk cap (only `maxBytesPerSet` times `maxSets`), `rateLimitPerMinute` advertised 0 with no enforcement, a corrupt `sets.json` throws inside the `GuardianHost` constructor which runs inside the `LightningNode` constructor, and issue #861 shows a host reporting serving with nothing bound. **Outcome: CONFIRMED,** with five reasons rather than three. Two additions neither proposal had: unbounded session memory (one responder per peer with no cap on the map, roughly 64 times 4 MiB retained per peer) and free, anonymous, PERMANENT slot exhaustion (16 registrations from throwaway keypairs, no unregister verb). The honest phrasing is "no rate limiting exists at any layer" rather than "advertises a limit it fails to keep", since 0 is the spec's "unspecified" value; and there is no feature bit, gossip field or directory, so a seed-only restore cannot FIND three guardians at all. **Change:** crash-v2 profiles, automatic selection, quorum auto-apply and default-on hosting were all removed from the default path and collapsed into D22 as prerequisites tracked elsewhere; the guardian tier is presented as the strongest OPTIONAL route and Stage 2's only proven realisation.

**C7. Claim:** for the dream flow (direct funding plus automatic offline receive / FFOR), the liquidity and settlement peer must be a beignet node, because FFOR settlement and the 44069 receive messages are beignet-only; therefore designing the default path around a beignet LSP is justified. **Outcome: PARTLY.** Refuted: direct funding does NOT require a beignet liquidity peer. The LSP leg is stock BOLT 2 dual funding or splice (`src/lightning/direct-funding/receiver/engine.ts:1892`, `:1913-1950`), gated only on `option_dual_fund`, so CLN and Eclair qualify; what excludes Blocktank is LND, not 44069. Confirmed: FFOR settlement and the automatic-receive verbs do require beignet, by feature bit. **Change:** section 7 separates the two roles, the LSP identity to relearn is a SET of roles rather than a single pubkey, and a fix was adopted: `peerSupportsFfor` fails OPEN on an unknown peer init (`src/lightning/channel/channel-manager.ts:5638-5645`) and must fail CLOSED on the restore path (D18). One UNKNOWN was recorded rather than papered over: no direct-funding interop test exists, so a CLN or Eclair liquidity peer completing a direct-funded open is plausible and unproven. The production topology has since been decided (decision 2).

**C8. Claim:** rotation is unreachable exactly when two of three guardians are gone (`rotateGuardians` requires a confirmed writer gate, `src/cli/beignet-node.ts:4826-4838`; the gate requires 2 of 3, `src/lightning/recovery/startup-gate.ts:269-273`), and issue #862 shows a rotation attempted on an empty journal can leave the wallet unable to persist a channel, so automatic churn repair must fire on the first loss and never before the journal has content. **Outcome: PARTLY.** The #862 clause was confirmed; the first clause was refuted in both directions. The gate is a boot-time latch that `recheck` never downgrades, so a LIVE node can rotate with two outgoing guardians gone, while a RESTART with two gone quarantines the gate and blocks all peer traffic, which is worse than "cannot rotate". Rotation is also refused outright in peer-storage mode, so no Tier 2 wallet can ever rotate. And "fire on the first loss" does not follow: silence is indistinguishable from a partition, and the best-effort retirement leaves an un-retired guardian serving the old namespace, which a later restore can reach, producing split brain across disjoint sets with a revoked-commitment shape. **Change:** D22's rotation rule became "fire on the first CONFIRMED loss, hold until `tip() > 0`, and make retirement a completion condition", and "never rotate at `tip() === 0`" is a hard constraint because a seed-only first boot is always that state.

**C9. Claim:** the FFOR epoch record (`IFforEpochRecord`) rides `IChannelState` and is therefore journaled and capsuled, the receipts fetch (`src/cli/ffor-receive.ts:319-363`) needs only channel state, but the automatic receive flow provisions no witnesses (`src/cli/offline-receive.ts:234-241`), the invoice expires in 10 minutes while `T_exp` is tip+1296 blocks, and a held (`restoreRecencyUnproven`) receiver cannot force close to claim a voucher before `T_exp`. **Outcome: PARTLY.** Refuted on protocol grounds: the epoch record is not what makes a voucher claimable; under Variant D the enforcing material is the counterparty's HTLC signature list in the commitment state, so what must survive is the whole commitment. Narrowed: the receipts fetch also needs the peer dialable, the epoch ACTIVE on both sides (otherwise it is a silent no-op over real parked HTLCs), and a caller, which today is only a `wallet_data` job list. Refuted as an absolute: a held receiver CAN force close; what is true and worse is that no AUTOMATIC claim ever fires and that `POST /ffor/enforce` is hard-blocked with no flag to pass, which is a bug. The review also produced a design point nobody proposed: an ACTIVE Variant D epoch FREEZES the channel, and the epoch reestablish TLV carrying `epochId` and `H_act` is already compared on every reconnect, so a match plus matching BOLT 2 counters is a peer-verified, SERVER-FREE proof that no commitment was signed since the capsule was written. **Change:** D18, a second and narrower Stage 1 route needing no ack, no second holder and no new trust; the `POST /ffor/enforce` flag filed as #908.

**C10. Claim:** lightning-kmp (Phoenix) pushes the full serialized channel state into the BOLT 1 `peer_storage` blob before `commit_sig`, `revoke_and_ack` and `tx_signatures` on the same ordered connection via a `RequirePeerStorageStore` marker, restores automatically on reconnect when the local state is unknown or older (`maybeRestoreBackup`), and drops channels in priority order when the blob exceeds 65531 bytes. **Outcome: PARTLY,** pinned at commit `43e4cf1e76caeb9af68478064d30906433ee57cd`. The barrier, the priority drop and the zero-touch restore were confirmed and the design copies them. Three corrections: seven marker classes including the whole close flow, not three; `maybeRestoreBackup` overrides an existing local channel only while it is `Syncing`, not generally; and the overflow terminal sends an EMPTY blob that overwrites a good backup under BOLT 1's replace rule, which D15 rejects in favour of refusing to push. Two further findings were adopted as positioning: kmp does not pad and beignet already does; and the retrieval-before-reestablish ordering kmp relies on is BOLT 1 Rationale rather than a Requirement, which makes beignet's reestablish hold (#462) a real differentiator. Both reviews independently named the same highest-value delta over Phoenix: a non-counterparty second holder, because with one holder a rollback at a seed-only boot is undetectable by construction. **Change:** D14, D15 and decision 6.

**Contradictions between the proposals, and how they were resolved.**

- Reanchor as the lift versus guardians as Stage 2: resolved by C1 toward guardians; the reanchor is an experiment with a gate (D20).
- Capsule per gated message versus head beacon per gated message: resolved by C2 toward the beacon, merging one proposal's hook placement with another's beacon shape (D10).
- Daemon default-on auto-apply versus embedder-only: resolved toward embedder-only; the daemon default stays off and the embedder flips it at import via `walletOrigin`, which preserves the five pinned refusal tests and #690 review point 1 (D19, decision 3).
- Opaque `kv_state` versus typed variants: resolved by C4 toward a closed typed union (D8).
- Random index floor versus a monotone floor: resolved by C5 toward the chain tip (D2).
- On-chain beacon default-on versus reject: resolved toward reject; the visibility premise remains unverified and the privacy cost is permanent (decision 17).
- Stranger locator service versus the existing trusted-peer hatch: resolved by C6's reasoning toward the trusted hatch, which needs no new admission story (D14, decision 18).
- Self-fence marked SAFE versus UNKNOWN: resolved to SAFE as a FREEZE with the limits stated in D5: detection when the holder cooperates, never fencing.
- "Tier 2 comes back HELD" versus "comes back CLOSED past one round": resolved by C3 toward CLOSED, and sharpened further: past ZERO completed rounds, and the close is a request to the peer rather than a close we can perform.

## 14. References

### Repository files (all under the beignet repository root)

**The hold and the restore install**

- `src/lightning/recovery/capsule.ts:1394-1412` `markCapsuleRestoredChannels`, the single `restoreRecencyUnproven = true` at `:1409`; `:537` `CAPSULE_MAX_BYTES`; `:599-640` `RecoveryCapsule` and `GuardianDescriptor`; `:621-624` the head fields; `:683-685` `deriveCapsuleKey`; `:791-799` the fail-closed decoder; `:880-897` the candidate comparator; `:1462` `restoreBestRecoveryCapsule`; `:227-530` `knownGoodProbeFrames`
- `src/lightning/recovery/restore-driver.ts:503-526` `readHeads`; `:676-720` `selectHead`; `:1090-1226` the fence-then-install transaction
- `src/lightning/recovery/wire-safety.ts:7-13` the under-report argument; `:107-208` derive and verify; `:150-166` the missing implication table
- `src/lightning/recovery/types.ts:82-127` `RecoveryMutation`; `:300-337` `RecoverySnapshot`
- `src/lightning/recovery/recovery-manager.ts:339-444` `applyMutation`; `src/lightning/recovery/frame-codec.ts:150-345`; `src/lightning/recovery/journal.ts:1657-1730` `captureSnapshot`, `:2073-2120` `assertEmptyTarget`, `:1116-1142` the empty-store guard and `EMPTY_STORE_ALLOWED_META`
- `src/lightning/recovery/guardian-wire.ts:27-37` `CRASH_V1_PROFILE`; `:84-115` `deriveRecoveryRoot`; `:177-206` `computeGuardianSetId`; `:235-241` `LogHead`; `:282-300` `stateBytes`; `:44` `guardianTaggedHash`; `:610-650` `signTranscript`, `verifyTranscript`, `deriveFrameIv`
- `src/lightning/recovery/guardian-host.ts:75-77`, `:196-197`, `:251-264`, `:344-357`, `:418-485`, `:531-541`, `:547-569`; `src/lightning/recovery/guardian-bolt8.ts:17-25`, `:423`, `:705-708`; `src/lightning/recovery/guardian-client.ts:292-350`, `:699-719`, `:752-766`; `src/lightning/recovery/guardian-rotation.ts:60-101`; `src/lightning/recovery/startup-gate.ts:212`, `:269-276`; `src/lightning/recovery/assembly.ts:110-133`, `:331`, `:358-399`, `:401-509`

**The channel layer**

- `src/lightning/channel/channel.ts:309-321` per-commitment point and secret; `:1539` the announce bit; `:1594-1616` the taproot nonce derivation and its safety note; `:3040-3058` `addHtlc` refusal; `:4429-4449` `restoreLastSentBatch`; `:4674-4698` commitment-signature verification; `:4880-4925` the RAA point check and the `expectedIndex` pin at `:4913`; `:5624-5661` `getRecoveryStatus`; `:5677-5760` the restore-unproven disposition and `buildRecoveryCloseActions`; `:5763-5770` `isMutualCloseHeld`; `:5785-5799` `_heldReestablishGapFailure`; `:6206-6218` `prepareForceClose`; `:8264-8340` `_dropUnsignedLocalAddsIfHeld`; `:8839-8885` `createReestablish`; `:9796-9812` the DLP secret validator; `:9828-9857` the DLP arm; `:9860-9878` the under-report comment; `:9902-9923` the two gap failures; `:10251-10270` the issue #469 note; `:13122-13130` `acceptsNewHtlcs`; `:13135-13146` `canSettleHtlcs`; `:23086`, `:23150-23181` the FFOR epoch reestablish TLV
- `src/lightning/channel/channel-state.ts:718-730` the FFOR field; `:954` the restore flags; `:1244-1249` `mustNotBroadcastCommitment`
- `src/lightning/channel/channel-actions.ts:354-437` the outbox supersede rules; `:465-495` `IWireDurabilityBarrier`; `:519-534` `QUORUM_BARRIER_MESSAGE_TYPES`; `:548` `WIRE_SAFETY_POLICY_VERSION`
- `src/lightning/channel/channel-manager.ts:648` `_nextChannelIndex`; `:726-760` `deriveKeysForNewChannel`; `:879-894` `addTrustedPeer` and `isTrustedPeer`; `:993`, `:1063`, `:3575`, `:6704`, `:6980` `channelPeers.set(tempId, ...)`; `:2232-2236` the restore-side index advance; `:5133-5230` the unknown-channel hold with its caps at `:478`, `:486`, `:493`, `:5167-5173`; `:6610-6624` the zero-conf private forcing; `:8206-8218` promotion to the permanent id; `:8806-8860` `_dispatchActions`; `:9036-9053` the persist-before-send rule; `:9128-9160` the `namespaceLost` refusal; `:10536-10551` the swallowed transport throw
- `src/lightning/keys/shachain.ts:29-49`, `:80-92` `canDerive`, `:99-103` the documented and unenforced 49-entry bound, `:110-138` `addSecret`
- `src/lightning/keys/wallet-keys.ts:29-34` the shared coinType 1; `:66-110`; `:126-183` `deriveChannelKeys`
- `src/lightning/script/commitment.ts:35-52`, `:276-282` the obscured commitment number; `src/lightning/channel/commitment-builder.ts:586-591`
- `src/lightning/chain/output-resolver.ts:249-252`, `:277`, `:315-327`, `:336-366` the tail of `classifyCommitmentTx` (function at `:192`), `:380`, `:1150-1210` `classifyTheirFutureCommitmentOutputs`
- `src/lightning/chain/chain-monitor.ts:202-217`, `:733-757`, `:2106-2136`, `:2262-2314`; `src/lightning/chain/chain-watcher.ts:852`, `:2109` `discoverRestoredFunding`; `src/lightning/chain/electrum-backend.ts:529-536`

**The node and peer storage**

- `src/lightning/node/lightning-node.ts:757` `DF_POLICY_STORAGE_KEY`; `:2096` the GuardianHost construction; `:2617` `loadNextChannelIndex`; `:5231` `PEER_STORAGE_MIN_INTERVAL_MS`; `:5252-5320` `handlePeerStorageMessage` and `persistPeerStorageBlob`; `:5347-5370` `padOwnPeerStorageBlob`; `:5385-5395` `peerQualifiesForStorage`; `:5399-5450` `sendPeerStorageOnConnect`; `:5464-5499` `distributePeerStorage`; `:5500-5546` the refresh throttle and composer; `:5574-5583` the empty-node guard (#453); `:6012-6026` `recoveryPermitsPeerTraffic`; `:6084-6087` `bringUpChannelPeer`; `:6213-6245` and `:6294-6297` `autoReconnectPeers`; `:7331-7420` `recoverFromStaticChannelBackup`; `:7783` `recoverFallbackFunds`; `:7966-8090` `connectPeerById` and `connectForRequest`; `:9256-9280` and `:9489-9515` the funding watches; `:13384` the node-level restore status; `:16356-16385` the admitted-while-unproven fail-back; `:22945` `emitCustomMessage`; `:23713-23742` and `:23862` the DF descriptor path; `:24399-24453` the df:policy persist and restore; `:24838-24889` `skipAutoCloseRestoreUnproven` and the central guard
- `src/lightning/message/custom.ts:18-40` the envelope and the reserved ranges, `:41-100` the subtype enum; `src/lightning/message/peer-storage.ts:15` `PEER_STORAGE_MAX_BYTES`; `src/lightning/features/flags.ts:56`, `:92-113`, `:350-374`
- `src/lightning/transport/peer.ts:181`, `:398-432`; `src/lightning/transport/peer-manager.ts:140-158`, `:273-301`, `:1050-1075`, `:1525-1545`; `src/lightning/transport/peer-uri.ts`
- `src/lightning/backup/scb.ts:48-79`, `:90-120` `parseScbAddress`; `src/lightning/storage/sqlite-storage.ts:472-476`, `:1201-1213`, `:1487-1497`, `:1545-1575`; `src/lightning/storage/serialization.ts:521`, `:795-995`, `:1066-1129`, `:1410-1419`
- `src/lightning/direct-funding/receiver/engine.ts:1032-1035`, `:1598-1617`, `:1886-1950`; `src/lightning/direct-funding/transport/registry.ts`
- `src/lightning/gossip/network-graph.ts:588`; `src/lightning/gossip/gossip-sync.ts:225-270`; `src/lightning/gossip/rapid-sync.ts:14-30`, `:246-262`; `src/lightning/bootstrap/seeds.ts:18`, `src/lightning/bootstrap/dns.ts:123`
- `src/lightning/ffor/types.ts:13-27`, `:111-115`, `:141-235`; `src/lightning/ffor/messages.ts:320-359`
- `src/lightning/channel/zero-conf.ts:12-46`; `src/lightning/advisor/liquidity-advisor.ts:185`; `src/shapes/electrum.ts:31-55`; `src/transaction/index.ts:728`

**The daemon**

- `src/cli/beignet-node.ts:606-617` `parseRecoveryMode`; `:715-727` `defaultDataDirForMnemonic`; `:1597-1606` the hold and window constants; `:1907-2027` the boot order; `:2005-2014` the empty-target latch; `:2429-2435` the directFunding construction; `:2449-2471` the guardian host block; `:2485-2494` the receive job store; `:3106-3118` the swallowed listen bind (#861); `:3305-3330` `prepareRecovery`; `:3448` `followRotation`; `:3850-3886` `revealCapsuleGuardians`; `:3960-3995` the resume opts and `assertEmptyTarget` call; `:4067-4070` the network guard; `:4098-4160` the quorum and guardian refusals; `:4205-4300` the staged install; `:4432-4560` the auto-apply machine; `:4608-4646` `carryDaemonState`; `:4826-4838` `rotateGuardians` (the confirmed-gate check; the function begins at `:4802`); `:5018-5024` `getGuardianHostSurfaceStatus`; `:5032` `resolveGuardianUri`; `:6897-6960` `startFforEpoch`; `:7185-7194` and `:7279-7291` the FFOR recover and enforce routes; `:7376-7391` the force-close route; `:10166` `addTrustedPeer`; `:11856-11900` the SCB path; `:11914-12010` `handleRetrievedPeerStorage`
- `src/cli/daemon.ts:200-217` the restricted route sets; `:523-540` the SSE relay; `:786-870` the recovery validation block; `:800-855` the window validation; `:915-921` the guardianServe gate; `:1506-1540` `acceptStaleStateRisk`; `:2271` and `:2281` the bootstrap and trusted-peer routes; `:2768-2771` `POST /ffor/enforce`; `:2822-2895` the four confirm routes
- `src/cli/config.ts:28-37`, `:520-570`, `:605-630`; `src/cli/cli.ts:3080-3096`; `src/cli/openapi.ts:2025-2033`, `:2070-2104`; `src/cli/offline-receive.ts:180-289`, `:305-368`; `src/cli/ffor-receive.ts:179-209`, `:319-363`; `src/cli/README.md:439-445`, `:1809-1819`

**Tests and harness**

- `tests/lightning/recovery-phase3.test.ts:606`, `:744`, `:1136-1285`; `tests/cli/recovery-surface.test.ts:53-62`, `:1705-1999`, `:2095-2097`, `:2156-2196`, `:2205`, `:2257-2365`, `:2405`, `:2508`; `tests/lightning/peer-storage.test.ts:480-522`
- `tests/lightning/helpers/chaos-harness.ts:1015` the closed verdict set, `:1082-1112` `assertNoGatedSendBeforeCommit`; `tests/lightning/helpers/chaos-oracle.ts:50-124`; `tests/lightning/helpers/chaos-scenarios.ts`; `tests/lightning/helpers/chaos-quorum.ts`; `tests/lightning/helpers/df-sender.ts`, `tests/lightning/helpers/df-receiver.ts`
- `tests/lightning/recovery-phase6-exactness.test.ts` (the pinned gated set); `tests/lightning/recovery-phase7-restore.test.ts:60-86`; `tests/lightning/held-restore-unsigned-adds.test.ts`; `tests/lightning/scb-restore.test.ts:290`, `:1000`; `tests/lightning/taproot-scb-recovery.test.ts:564-571`
- `tests/lightning/interop/shared-helpers.ts`, `tests/lightning/interop/taproot-scb-recovery-regtest.test.ts`, `tests/lightning/interop/ffor-variant-d-regtest.test.ts`, `tests/lightning/interop/chaos-cln-v2open-txsigs.test.ts`, `tests/lightning/interop/chaos-eclair-v2open-txsigs.test.ts`; `docker/docker-compose.yml`

**Docs**

- `docs/RECOVERY-PROTOCOL.md`: the revision header (revisions 11 to 15 are the direct parents), 5.4 (capsule over peer_storage), 5.6 (restore dispositions), 5.7 (head reconciliation), 5.8 (durability barrier modes, "THE BARRIER IS MEASURED", the sticky rule), `:696` (the compaction retain floor), `:767` (section 8 env surface), `:1014` (section 9 acceptance criteria), `:1057` (section 11 item 5, economics out of scope), 12.2 (the VSS comparison)
- `docs/RECOVERY-GUARDIAN-WIRE.md` 2.7, 5.1, 5.9, 5.11, 9, `:1091` (`rate_limit_per_minute`, 0 meaning unspecified), `:1185-1190` (mandatory credential plus rate limiting)
- `docs/AUTOMATIC-OFFLINE-RECEIVE.md:5`

### Outside the repository

- beignet-umbrel (`/Users/coreyphillips/Documents/testing/beignet-umbrel`): `RECOVERY-PROTOCOL-INTEGRATION.md` (the embedder contract, already written); `manager/server/wallet-manager.js:726-772`, `:1060-1125`, `:2150-2156`, `:2185-2225`, `:2261-2280`, `:2411-2476`, `:2534`; `manager/server/recovery.js:110-163`; `manager/ui/src/pages/WalletsPage.jsx:311-334`; `manager/ui/src/components/RestorePanel.jsx:183-202`, `RecoveryAutoApplyField.jsx`, `GuardianServeField.jsx`; `manager/ui/src/lib/recovery.js:244-264`, `:321-367`; `scripts/lfbw-regtest/` (`lib.mjs`, `01-setup.mjs`, `04-direct-funding.mjs`, `07-recovery.mjs`, `11-automatic-receive.mjs`, README); `.github/workflows/build-image.yml:522`
- FFOR spec (`/Users/coreyphillips/Documents/synonym/specs/ffor-offline-receive.md`): `:62`, `:144`, `:222-223`, `:1278-1303`, `:1330`, `:1362-1375`, `:1409-1411`, `:1537-1538`, `:2505-2520`
- Blocktank (`/Users/coreyphillips/Documents/synonym/blocktank/blocktank-lsp-ln2`): `service/package.json:59`; `service/src/1_config/ILndNodeConfig.ts:14-41`

### GitHub issues (coreyphillips/beignet)

- #690 peer-storage zero-touch restore and the five peers-as-guardians objections; three retired, two remaining (counterparty motive, correlated failure)
- #692 guardian discovery and selection rules, ON HOLD; its "report, never adopt" rule and CI clause
- #699 bolt8 guardian transport and the beignet-umbrel pool as the target deployment; the register this document matches
- #701 and PR #705 guardian rotation, landed
- #702 quorum barrier latency and the rejected funds-only narrowing, with the sender-side in-flight race
- #861 a failed listener bind is swallowed while a guardian reports serving
- #862 a rotation on an empty journal leaves the wallet unable to persist a channel
- #533 hyperswarm DHT transport, reserved; #795 Nostr NWC key-derivation convention; #453, #457, #459, #462, #463, #469 the revision 8 to 13 lineage
- #909 this design's tracking issue; #905, #906, #907, #908 the Phase 1 bug issues

### External, pinned

- ACINQ/lightning-kmp at `43e4cf1e76caeb9af68478064d30906433ee57cd`: `modules/core/src/commonMain/kotlin/fr/acinq/lightning/wire/LightningMessages.kt:174-175`, `:495`, `:1284`, `:1375`, `:1697`, `:1734`, `:1770`, `:1824`; `io/Peer.kt:201-206`, `:906-912`, `:947-948`, `:1160-1194`, `:1287-1334`; `serialization/channel/Encryption.kt:20-26`, `:39-71`; `NodeParams.kt:158`, `:190-192`, `:281`
- ElementsProject/lightning `plugins/recover.c` (ten bootstrap nodes then gossip self-lookup) and `plugins/chanbackup.c` (two-peer fanout, overlength refusal)
- lightningdevkit/rust-lightning `lightning/src/ln/channelmanager.rs` (the 1 KiB inbound peer-storage cap) and `lightning/src/chain/chainmonitor.rs` (`send_peer_storage`, cfg-gated)
- BOLT 1 `01-messaging.md:535-562` (peer storage requirements), `:541` (padding SHOULD), `:550` (one update per minute), `:551` (replace the old blob), `:556-558` (retention), `:574-575` (the retrieval ordering, Rationale only); BOLT 2 (`channel_reestablish`, data loss protect); BOLT 3 (per-commitment secret requirements, `remotepubkey = payment_basepoint`)
