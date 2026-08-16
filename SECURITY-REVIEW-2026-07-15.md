# Beignet on-chain / lightning review, 2026-07-15

Full fund-safety and spec-compliance review of the beignet on-chain and lightning
implementation at `master` commit `45dfa3b`. Target repo: `coreyphillips/beignet`
(the maintained fork). No issues or PRs were opened; this document is the deliverable.

## How this was produced

- **Fund-safety audit** (loss of our funds only): the adversarial multi-agent harness
  at `.claude/workflows/precustody-fund-safety-audit.js`. Each finder dimension is
  attacked by three independent skeptics, and a finding is only kept if at least two
  of three judge it a real, current-code loss path (majority-refute). Twenty
  dimensions total: the eleven standing dimensions plus nine targeting everything that
  landed after the last clean audit (`77820aa`, 2026-07-03): watchtower client, SCB /
  DLP restore, on-chain wallet, storage encryption, ISigner, splice, fee control,
  two-phase update tracking, and the WebSocket transport.
- **Spec-compliance sweep**: five independent reviewers, each fetching the current spec
  text rather than working from memory: BOLT 1/2/3/4/5/7/8/9, bLIP-51 / LND wtwire
  watchtower parity (verified byte-level against LND's Go sources), and the wallet BIPs
  (174, 32/44/49/84/86, 380+, 67, 21, 173/350).
- **Baseline tests**: conformance suite green (43 passing); full lightning + CLI suite
  4533 passing / 89 pending / 1 failing, where the single failure is the live-LND-tower
  docker interop test (no container running here), not a code defect. The root
  `tests/transaction.test.ts` batch failures were live-Electrum flakiness and pass on an
  isolated rerun.

## Verdict

The core state machine is in good shape: BOLT 3 transaction/script/key formats pass the
official Appendix C/D/E vectors run live, sphinx construction is byte-identical to the
BOLT 4 vectors, and the LND watchtower wire and blob formats are an exact byte match.
The fund-loss findings cluster in **newer surfaces** that the prior clean audit predates,
above all **simple-taproot channels** and **splicing**, where several paths silently
no-op instead of protecting or sweeping funds. The **BOLT 12 offers** wire format and the
**liquidity-ads** wire format diverge enough that they currently interop only with
beignet itself.

### Severity counts

| Class | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Fund-safety (loss of our funds) | 2 | 5 | 2 | 0 | 9 |
| Spec-compliance | 0 | 9 | 21 | 40 | 70 |

Fund-safety finding FS-1 is the same defect as spec finding S-B2/H2 (unvalidated
`accept_channel`); it is counted once in each column and cross-referenced below.

---

## Part 1: Fund-safety findings (loss of our funds)

Ordered by severity. Every one survived three-skeptic majority-refute in the audit
harness and was re-verified against source at synthesis time.

### FS-1 (CRITICAL) Unvalidated `accept_channel` lets an acceptor trim our entire balance to fees
- **File:** `src/lightning/channel/channel.ts:816-841` (`handleAcceptChannel`, esp. line 833); validator `src/lightning/channel/validation.ts:151` exists but has zero call sites.
- **Scenario:** We open a 1,000,000-sat channel. The adversarial acceptor replies with `dustLimitSatoshis = 900,000` (raw uint64, unbounded) and a tiny reserve. `handleAcceptChannel` copies these into `remoteConfig` with no validation. Every remote commitment we build (`commitment-builder.ts:725`) then uses the attacker's 900,000-sat dust limit as the trim threshold, so `commitment.ts:306` omits our to_remote output entirely and we sign it. The acceptor force-closes with that commitment and our balance goes to miner fees. The opener side is exposed because only `handleOpenChannel` validates.
- **Fix:** Call `validateAcceptChannelParams(msg)` in `handleAcceptChannel` and fail the channel on violation. Add the two missing BOLT 2 checks: reject `dustLimitSatoshis` above a sane absolute cap, and reject `dustLimitSatoshis` greater than the reserve we proposed in `open_channel`. Regression test that such an `accept_channel` is rejected.
- **Cross-reference:** identical to spec finding **S-2.H2**.

### FS-2 (CRITICAL) Simple-taproot funding output is watched under a P2WSH scripthash, so breaches are never detected
- **File:** `src/lightning/node/lightning-node.ts:2914` (`restoreChainWatches`) and `src/lightning/chain/chain-watcher.ts:454` (`watch:funding` handler).
- **Scenario:** On a simple-taproot channel the funding output is a P2TR MuSig2 key-spend, but both watch-arming sites call `createFundingScript()` (witness-v0 2-of-2 P2WSH) with no taproot branch and subscribe Electrum to `SHA256(P2WSH)`, which never matches the real P2TR output. `getScriptHashHistory` is therefore always empty and `handleFundingSpent` never fires for taproot channels in production (interop tests mask this by calling it directly). After a taproot coop-close the funding watch is deliberately kept alive to catch a revoked-commitment broadcast, but it watches a script that cannot match: the peer broadcasts an old revoked commitment, no justice tx is ever built, the revoked to_local matures past `to_self_delay`, and the peer sweeps it. Even an honest remote force-close goes undetected, stranding our to_remote.
- **Fix:** Include the actual funding `scriptPubKey` (P2TR via `createTaprootFundingScript` for taproot, P2WSH otherwise) in the `WATCH_FUNDING` payload and subscribe both sites to its scripthash; or branch on `isTaprootChannel(state.channelType)` at both call sites. Regtest a taproot funding output spent by a revoked commitment through the real chain-watcher path.

### FS-3 (HIGH) `REBUILD_SWEEP` emits a `Transaction` where listeners require a `Buffer`, so every fee-bumped sweep rebuild fails
- **File:** `src/lightning/channel/channel-manager.ts:3924`; failure path `src/lightning/chain/chain-watcher.ts:473-476`.
- **Scenario:** A peer broadcasts a revoked commitment; the initial penalty (a Buffer) broadcasts fine. Fees spike, the penalty sits unconfirmed, and after `REBROADCAST_INTERVAL` (6 blocks) `chain-monitor` emits `REBUILD_SWEEP` with a bumped rate. `processChainActions` then does `emit('broadcast:tx', rebuilt)` where `rebuilt` is the `bitcoin.Transaction` returned by `rebuildSweep()`, while all eleven sibling emitters pass a `Buffer`. `ChainWatcher` calls `rawTx.toString('hex')`, which yields `"[object Object]"`; the backend rejects it, and the catch handler calls `Transaction.fromBuffer` on the Transaction object, throwing synchronously inside the `.catch` (an unhandled rejection, process-fatal under Node defaults, re-crashing every ~6 blocks while the breach is pending). The RBF ladder never reaches the network, the penalty stays pinned at its original feerate for the whole `to_self_delay`, and the cheater sweeps the revoked to_local. The same dead path loses HTLC-timeout preimage races and strands post-reorg sweeps.
- **Fix:** `emit('broadcast:tx', rebuilt.toBuffer())`. Harden the `ChainWatcher` failure path to accept only a Buffer / guard `Transaction.fromBuffer` so a malformed payload is logged and queued rather than crashing. Drive `processChainActions` to `ChainWatcher` end-to-end in a regression test (the current `sweep-rebroadcast.test.ts` calls `rebuildSweep` directly and never exercises the emit path).

### FS-4 (HIGH) Taproot force-close commitments can never be CPFP'd (anchor lookup uses the legacy P2WSH script)
- **File:** `src/lightning/channel/channel-manager.ts:4091` (`_maybeCpfpAnchorCommitment`); `src/lightning/chain/sweep.ts:651` (`buildAnchorCpfpTx`).
- **Scenario:** We hold the preimage for an inbound HTLC on a simple-taproot channel and force-close ~18 blocks before `cltv_expiry` to claim on-chain. `_maybeCpfpAnchorCommitment` locates our anchor via `buildAnchorOutput(...).script` (legacy witness-v0 P2WSH), but taproot commitments carry P2TR anchors from `buildTaprootAnchorOutput` (`commitment-builder.ts:108-117`). `findIndex` returns -1, the function returns as if the anchor were trimmed, so no CPFP child is built and `reCpfpStuckCommitments` / `rearmCommitmentCpfp` are permanent no-ops for every taproot channel. The commitment rides at its stale open-time feerate through the spike, our pre-signed HTLC-success is blocked behind the unconfirmed parent past `cltv_expiry`, the peer CPFPs their own commitment (LND does this natively) and claims via HTLC-timeout, and we lose the full HTLC amount. Even if the script matched, `buildAnchorCpfpTx` signs witness-v0 ECDSA, invalid for a P2TR spend.
- **Fix:** Branch on `isTaprootChannel`, compute the P2TR anchor script with the same commitment keys the builder used, and match on it. Add a taproot variant of `buildAnchorCpfpTx` that produces a Schnorr signature for the P2TR anchor spend. Regtest that a taproot force-close produces a broadcast CPFP child and that re-bumping works.

### FS-5 (HIGH) Taproot coop-close responder accepts a fee that burns our entire opener output
- **File:** `src/lightning/channel/channel.ts:3805` (`_handleTaprootClosingSigned`, responder branch).
- **Scenario:** We are the opener of a simple-taproot channel with a modest local balance. An HTLC is in flight when shutdown is exchanged, so `handleShutdown` leaves state `SHUTTING_DOWN` and the opener-proposes-first trigger (which needs `NEGOTIATING_CLOSING`) never fires, so `lastProposedClosingFeeSat` stays null. The HTLC resolves, then the adversarial non-opener sends `closing_signed` with a valid MuSig2 partial and `feeSatoshis` equal to our full local balance. The responder branch's `idealFee/5 .. idealFee*5` band passes for a small balance, and the only balance guard (`feeSatoshis > openerBalanceSat`) passes because `openerBalanceSat` is our full balance with no dust reservation. We sign, transition CLOSED, and `buildClosingTx` computes `localAmount = localBalance - fee < 546`, drops our output, and pays the entire balance to the miner as fee. 100 percent adversarial burn.
- **Fix:** In the taproot responder branch apply the dust reservation the legacy path uses in `initClosingFeeRange`: reject unless `openerBalanceSat - feeSatoshis >= dustLimit`. Tighten the acceptance band toward the legacy 2x cap so an accepted fee cannot silently consume most of our output.

### FS-6 (HIGH) In-flight-splice restore leaves the OLD funding output unwatched, so a revoked pre-splice commitment steals the channel
- **File:** `src/lightning/node/lightning-node.ts:2936` (`restoreChainWatches`, the `if (inflight)` branch, lines 2920-2951).
- **Scenario:** A live channel has accumulated updates, so the peer holds revoked pre-splice commitments spending the old funding output. We negotiate a splice, exchange `tx_signatures`, and broadcast the splice tx at a low feerate; `spliceInFlight` is persisted with `fundingTxid` still the OLD outpoint and `spliceFundingTxid` the NEW one. Our node restarts (routine) before the splice confirms. The `if (inflight)` branch calls `watchFundingOutput()` with only the NEW splice outpoint and `continue`s, never registering a watch on the OLD funding output (even though its script was already computed at line 2914). Because `checkFundingConfirmation` for the new outpoint waits for the splice tx to confirm before `watchFundingSpend` begins, the old output has no spend subscription after restart. The peer evicts our low-feerate splice tx from the mempool, broadcasts a revoked pre-splice commitment spending the OLD output, we never detect it, and the peer sweeps the entire balance after its to_local CSV. A non-revoked pre-splice force-close is likewise undetected.
- **Fix:** In the `if (inflight)` branch, watch BOTH funding outputs until the splice confirms. Add an immediate `watchFundingSpend` on the old funding output (already confirmed) alongside the confirmation-gated watch on the new outpoint, letting the chain watcher track more than one funding outpoint per channel during an in-flight splice, and tear down the old watch only once the splice reaches `minimumDepth`.

### FS-7 (HIGH) Static channel backup is never refreshed after a splice completes, so restore watches the spent pre-splice outpoint
- **File:** `src/lightning/node/lightning-node.ts:1200-1211` (`splice:complete` handler); premature refresh in `src/cli/beignet-node.ts:3918,3943`.
- **Scenario:** Open a channel; auto-SCB records funding outpoint A. The CLI wrappers call `refreshStaticChannelBackup()` immediately after `spliceIn`/`spliceOut` returns, i.e. at splice initiation when `fundingTxid` is still A, so the SCB is rewritten still pointing at A. The splice then locks and `completeSplice()` (`channel.ts:6807-6808`) sets `fundingTxid` to the new outpoint B, firing `splice:complete`, whose only handler persists the DB and re-arms announcement tracking but does not refresh the SCB. `refreshStaticChannelBackup()` is wired only to `channel:ready/closed/resolved`, `peer_storage:retrieved`, and the splice-initiation wrappers, so both the `channels.scb` file and the peer-storage blob permanently encode outpoint A. The node then loses its database (the exact scenario SCB exists for) and the operator restores: `recoverFromStaticChannelBackup` sets `fundingTxid = A` and watches output A, which the splice already spent. The peer's DLP force-close spends output B, which we never watch, and the post-splice balance is stranded.
- **Fix:** Refresh the SCB on splice completion, not initiation. From the `splice:complete` handler, re-emit an outward event that the CLI's `refreshStaticChannelBackup()` subscribes to (or invoke the refresh path directly) while `fundingTxid` holds outpoint B, and remove or duplicate the premature refresh in the wrappers. Verify `recoverFromStaticChannelBackup` then watches outpoint B.

### FS-8 (MEDIUM) `rebuildSweep` re-bumps only the first justice claim of a batched second-level tx
- **File:** `src/lightning/chain/chain-monitor.ts:1389,1429-1436`.
- **Scenario:** A peer breaches with a revoked commitment carrying two or more HTLC outputs, then confirms a single pre-signed second-level tx batching multiple HTLC claims (`SIGHASH_SINGLE|ANYONECANPAY` permits this) before our HTLC penalty. `handleOutputSpent` creates N separate justice claims sharing the same `secondLevelTxHex`. A fee spike leaves them unconfirmed; each emits `REBUILD_SWEEP`, but `rebuildSweep` passes the whole second-level tx to `resolveRevokedSecondLevelOutput` (which returns one entry per output) and then returns `resolved[0]` unconditionally, ignoring the triggering `output.outputIndex`. Claims for outputs 1..N-1 stay pinned at their stale initial feerate; if congestion persists through the cheater's `to_self_delay`, they never confirm, the cheater's delayed branch matures, and the cheater reclaims those HTLCs.
- **Fix:** Post-filter `resolved` to the entry whose input prevout matches the triggering tracked output's outpoint (as the sibling non-second-level branch does with `[output]`), or return all resolved claims and broadcast each. Unit test with a revoked second-level tx carrying two HTLC outputs.

### FS-9 (MEDIUM) Anchor commitment CPFP under-provisions wallet inputs, silently broadcasting the unbumped commitment
- **File:** `src/lightning/channel/channel-manager.ts:4006` (`_handleFeeBumpAndBroadcast`).
- **Scenario:** We force-close an anchor channel to claim an inbound HTLC during a mempool spike where `resolveForceCloseFeeRatePerVbyte` returns, say, 100 sat/vB. The commitment paid only its low baseline fee. `_handleFeeBumpAndBroadcast` computes the input-selection target as `ceil(feerate * parentVbytes)` (the parent-only fee), but `buildAnchorCpfpTx` actually needs the child fee `feerate*(parentVbytes + childVbytes) - parentFeeSats`, funding the child's own weight including the ~50-70 vB anchor witness. `selectFeeBumpInputs` adds only the marginal wallet-input fee on top of the too-small target, so with small P2WPKH UTXOs the change falls below dust and `buildAnchorCpfpTx` throws "insufficient funds". The catch block broadcasts the unbumped commitment at ~1 sat/vB; it does not confirm during the spike, our pre-signed HTLC-success cannot be mined, and at `cltv_expiry` the peer sweeps via HTLC-timeout. Every retry re-derives the same too-small target.
- **Fix:** Size the target to the child package deficit `ceil(feerate*(parentVbytes + estChildVbytes)) - parentFeeSats` and credit the 330-sat anchor value, so `selectFeeBumpInputs` funds the anchor input's weight. Treat a build failure as a hard fee-bump error that retries at a higher target rather than silently broadcasting the unbumped commitment.

### Investigated on the new surfaces but refuted (no change needed)
- Watchtower justice blob "frozen pre-signed fee" concern: refuted (1/3) — the blob/session fee handling does not invalidate the signature in the current code.
- Storage-encryption "decrypt/auth failure silently skipped" (`sqlite-storage.ts:67`): refuted (0/3) — a decrypt/auth failure does not silently drop fund-critical revocation state as claimed.
- ISigner boundary, two-phase-update desync (beyond FS covered by spec S-2.H1), and transport reorder/reestablish-secret-release: no surviving fund-loss finding. The transport layer computes reestablish state from persisted truth and did not yield an early-revocation path.

---

## Part 2: Spec-compliance findings

Grouped by area. Severity: HIGH = breaks interop or risks funds, MEDIUM = violates a MUST
but tolerated by common peers, LOW = SHOULD violation or hardening. File:line and the
spec basis are in each entry. None of these are contradicted by the conformance suite.

### BOLT 2 (peer protocol / channel state machine) and BOLT 5 (on-chain)

- **S-2.H1 (HIGH)** `update_fail_malformed_htlc` was not reworked for the #68 two-phase removal model: it sets `FAILED` and immediately credits `localBalanceMsat` with both phase flags undefined, so the revoke settlement loop credits the same HTLC **again** (double credit) and the removal never goes through a commitment round. Any peer relaying a corrupt onion (routine) desyncs the commitment with inflated local balance. `channel.ts:2016-2019` (handler 1982-2033), settlement loop `2729-2752`. Stale pin: `tests/lightning/htlc-safety.test.ts:347`. Fix: mirror `handleUpdateFailHtlc` exactly.
- **S-2.H2 (HIGH)** `accept_channel` parameters never validated (dead validator). Same defect as **FS-1**. `channel.ts:816-895`; `validation.ts:151`.
- **S-2.H3 (HIGH)** Interactive-tx `tx_add_input` receive-side validation missing, including the segwit-only anti-malleability MUST. A peer contributing a non-native-segwit input to a splice makes the broadcast txid differ from the txid both sides signed commitments against, so the confirmed splice holds the whole capacity at an outpoint with no valid commitment signature (no unilateral exit). Also missing: `sequence >= 0xFFFFFFFE` rejection, prevtx validity / vout-range checks, the 4096-message cap, and `tx_abort` on splice shared-input mismatch. `channel.ts:7786-7841`; `interactive-tx/builder.ts:95-122`.
- **S-2.H4 (HIGH)** Dual-funding stores `prevTxid: Buffer.alloc(32)` instead of extracting it (the splice branch does this correctly), so two peer inputs sharing a vout collide in `checkDuplicatePrevouts` and every dual-funded open where the peer contributes two or more colliding-vout inputs fails. `channel.ts:7823`; `interactive-tx/validation.ts:49-61`.
- **S-2.H5 (HIGH)** Uncommitted remote updates are not reversed on disconnect and the received-HTLC dedup is content-blind (id only). A peer that drops an uncommitted `update_add_htlc` per spec and reuses the id for a different HTLC has the new add silently ignored, causing signature-verification failure and force close; even without reuse the phantom entry permanently debits `remoteBalanceMsat` and leaks an HTLC slot. CLN drops uncommitted adds on reconnect, so this is reachable in normal operation. `channel.ts:4368-4444,1571-1574,1706-1717`.
- **S-2.M1 (MEDIUM)** Reestablish always retransmits `revoke_and_ack` before `commitment_signed`, ignoring the original relative order that the spec requires; a crossed round force-closes. `channel.ts:4920-5019`.
- **S-2.M3 (MEDIUM)** A forwarded HTLC resolved on-chain never fails the incoming HTLC off-chain (`output:resolved` has no consumer), so `scanForwardTimeouts` force-closes a healthy inbound channel instead of sending a clean `update_fail_htlc`. Fail-safe (no loss) but a needless force close. `chain-monitor.ts:452`, `channel-manager.ts:3905-3907`, `lightning-node.ts:8373,8404-8420`.
- **S-2.M4 (MEDIUM)** `tx_complete` receive-side limits missing (peer input < output sats, feerate sufficiency, 252 input / 252 output caps, 400k-weight cap) plus `tx_add_output` `MAX_MONEY` and negotiated-dust (a flat 546 is used). A peer can underpay fees or bloat past 400 kWU so the co-signed funding/splice can never confirm, stranding the channel. `interactive-tx/validation.ts:80-98,122`.
- **S-2.M5 (MEDIUM)** `tx_signatures` ordering skips the node_id lexicographic tie-break (acknowledged in a comment) and splices hard-code acceptor-first; equal contributions can deadlock. `channel.ts:8333-8377,6729-6735`.
- **S-2.M6 (MEDIUM)** Inbound `update_fee` is rejected during `SHUTTING_DOWN` although the spec allows it while HTLCs remain (CLN sends it), force-closing a cleanly shutting-down channel. `channel.ts:2927-2934`.
- **S-2.M7 (MEDIUM)** `open_channel` initial-commitment MUST-checks missing (funder can afford the fee; not both outputs below reserve). An opener pushing nearly everything is accepted and we sign `funding_signed` onto a commitment a conformant peer would reject. `channel.ts:1048-1180`; `validation.ts:83-145`.
- **S-2.M8 (MEDIUM)** `stfu` is rejected whenever committed HTLCs exist, so CLN/eclair-initiated quiescence (and therefore splicing) on a busy channel stalls 60 s and disconnects. Pinned as a deliberate simplification; a full fix needs HTLC-bearing splice commitment batches. `channel.ts:5152-5160`.
- **S-3.M2 (MEDIUM)** Commitment output ordering lacks the BOLT 3 `cltv_expiry` tie-break for identical HTLC outputs (same amount and payment_hash). The `htlc_signature` index mapping then diverges from LND/CLN/eclair/LDK and a valid `commitment_signed` is rejected, a deterministic, peer-inducible channel failure. Empirically reproduced. `script/commitment.ts:369-375` (field declared at 172, never used) and `sortCommitmentOutputs` at 412. Also recommended: add the official Appendix C "same amount and preimage" vector to the conformance suite.
- **S-2 LOW (11):** funding `2^24` boundary off-by-one (`types.ts:165`, `validation.ts:95`); missing `channel_type` defaulted instead of failed (`channel.ts:1130-1135`); `cltv_expiry >= 500000000` unenforced when block height unknown, no send-side check (`channel.ts:1675-1693,1420-1558`); reestablish `next_commitment_number == 0` and stale gaps not failed (`channel.ts:4888-4899,4985-4989`); basepoints/per-commitment points not secp256k1-validated on open/accept (`validation.ts:139-142`); acceptor reserve/dust not coupled to the opener's values (`channel.ts:198-212`); `channel_ready` retransmission keyed off local state not `next_commitment_number == 1` (`channel.ts:5033-5069`); `tx_abort` not echoed with an active session and several MUST-`tx_abort` failures send nothing (`channel.ts:8728-8760`); RBF floor and `channel_ready` guard missing, splice `tx_init_rbf` answered with a generic error (`dual-funding.ts:731-808`); splice-out external destination unvalidated against the interactive-tx script rules, a raw-Buffer caller can burn to `OP_RETURN` (`lightning-node.ts:3985-4060`, `cli/beignet-node.ts:3922+`); no fallback to separate per-output penalty transactions near expiry (`output-resolver.ts:2257-2307`).
- **Systemic:** `ChannelActionType.ERROR` (`channel-manager.ts:3793-3808`) only emits an app-level `error` event for established channels; it never sends a wire `error`/`warning` nor closes the connection, so every "MUST send an error and fail the channel" above depends on the embedding application. An invalid `commitment_signed` or bad revocation secret currently leaves the connection open and the channel wedged. The DLP fell-behind path (`channel.ts:4870-4879`) already sends a wire error itself and is the right pattern to generalize.

### BOLT 4 / 11 / 12 (onion, invoices, offers)

- **S-4.H1 (HIGH)** BOLT 12 signature hash uses the wrong merkle tree and tag: `offer/merkle.ts:67-90` builds leaves from `H("LnLeaf", tlv)` only (the per-TLV `LnNonce` leaves are missing) and signs with tag `"lightning"` instead of `"lightning" || messagename || fieldname`. Every offer/invoice_request/invoice signature is incompatible with CLN/eclair/LDK in both directions; `computeOfferId` inherits the same tree.
- **S-4.H2 (HIGH)** `invoice_request` wire encoding violates multiple MUSTs: no `invreq_metadata` (type 0), the signature (type 240) is computed but never serialized (no encode branch), and the receiver never verifies signature or metadata. Type 90 is the obsolete draft `payer_info`. `offer/tlv.ts:50-58,251-315`; `offer/offer-manager.ts:256-277,297-324`.
- **S-4.H3 (HIGH)** BOLT 12 invoice encoding does not mirror the invreq/offer fields, makes `invoice_paths`/`invoice_blindedpay` optional (often undefined), and encodes `invoice_relative_expiry` as a fixed u32 rather than `tu32` (readers MUST reject non-minimal integers). `offer/tlv.ts:380-437`; `offer/offer-manager.ts:367-383`.
- **S-4.H4 (HIGH)** BOLT 12 subtype layouts diverge: `blinded_path` / `blinded_payinfo` arrays carry a 1-byte count prefix the spec does not use; `blinded_payinfo` puts a u16 features-length placeholder between `htlc_minimum_msat` and `htlc_maximum_msat` and drops features; decoders assume a 33-byte `first_node_id`, so a spec peer using the scid-dir form mis-parses (including the onion-message `reply_path` decoder, which is spec-facing). `onion/blinded-path.ts:280-371`, `offer/tlv.ts:564-596`, `onion-message/codec.ts:119-158`.
- **S-4.M1 (MEDIUM)** Blinded relay computes `amt_to_forward` with the fee charged on the incoming amount instead of the spec's ceiling-inverted formula, so it forwards a few msat short and the downstream node fails the HTLC, breaking any foreign-built blinded route through us. `lightning-node.ts:7218-7226`.
- **S-4.M2 (MEDIUM)** Failures inside a blinded route never return `invalid_onion_blinding` (the constant does not exist in the repo); ordinary errors are used, violating the BOLT 4 MUST and de-anonymizing the blinded portion. `lightning-node.ts:7235-7259`. (Note: the recall memory's "invalid_onion_blinding SOLVED" concerned generation/pathing, not this receive-side error mapping.)
- **S-4.M3 (MEDIUM)** Keysend receive path fulfills before the final-hop CLTV/amount checks, so it will settle a keysend HTLC expiring next block (revealing the preimage without a safe claim window) and never compares `amt_to_forward`. `lightning-node.ts:6431-6483` vs `6532-6616`.
- **S-4.M4 (MEDIUM)** Final node never enforces `amount_msat >= amt_to_forward` (`final_incorrect_htlc_amount` is defined but unused); keysend and zero-amount invoices have no skim protection. `lightning-node.ts:6580-6616`.
- **S-4.M5 (MEDIUM)** Final-hop CLTV check requires exact equality instead of the spec inequality, rejecting a compliant sender that over-provisions the final expiry. `lightning-node.ts:6541-6557`.
- **S-4.M6 (MEDIUM)** BOLT 11 decode truncates an over-length `p`/`h`/`s`/`n` field instead of failing, so a malformed invoice yields a truncated payment hash we then try to pay. `invoice/decode.ts:200-220`.
- **S-4.M7 (MEDIUM)** Payer-side BOLT 11 MUSTs missing in `sendPayment`: it pays invoices with unknown even feature bits, pays secretless invoices, and never validates the recovered key against the `n` field while routing to `n`. `lightning-node.ts:5610-5796`.
- **S-4.M8 (MEDIUM)** MPP is attempted whenever a payment secret is present without checking the invoice offers `basic_mpp`; splitting to a non-MPP recipient locks funds for the `mpp_timeout`. `lightning-node.ts:5731-5760`.
- **S-4.M9 (MEDIUM)** Replying via a 1-hop blinded reply path drops the message body (the loop starts at index 1), so a BOLT 12 invoice reply arrives empty and the requester times out. `onion-message/construct.ts:264-288`.
- **S-4 LOW (6):** onion-message padding zero-initialized rather than from the `pad`-key stream (`onion-message/construct.ts:90`); hop-payload lengths 0/1 not rejected as `invalid_onion_payload` and TLV ordering/dup not enforced (`onion/hop-payload.ts:117-200`, `process.ts:71`); MPP `total_msat` of later parts never compared (`lightning-node.ts:7016-7080`); no `path_id` validation for final onion messages and unblinded direct sends with a plaintext `next_node_id` fallback (`onion-message/process.ts:99-105,176-186`); non-spec BOLT 11 tag 25 blinded paths with a fragile decoder that suppresses cleartext hints so foreign payers cannot route (`invoice/decode.ts:116-120`, `onion/blinded-path.ts:413-427`); `encodeTaggedField` silently corrupts a field longer than 1023 words (`invoice/words.ts:52-55`).

### BOLT 1 / 7 / 8 / 9 (framing, gossip, noise, features)

- **S-7.M1 (MEDIUM)** Gossip queries and replies hardcode the mainnet chain_hash and never echo the query's chain_hash, and `NetworkGraph.addChannelAnnouncement` rejects every non-mainnet announcement, so on regtest/testnet/signet our replies violate the MUST (peers ignore them) and our own sync returns nothing. `gossip/gossip-sync.ts:85,95,183,200,251`; `gossip/network-graph.ts:35`.
- **S-7.M2 (MEDIUM)** `node_announcement` advertises an almost-empty features field (only `large_channels`, only when wumbo is enabled) even though init advertises ~17 features. Remote nodes make decisions from the graph, so CLN/eclair/LDK will not route onion messages to us, making BOLT 12 offers unreachable for non-direct peers. `lightning-node.ts:4775-4781`.
- **S-7.M3 (MEDIUM)** `decodeShortChannelIds` still accepts the spec-removed zlib encoding type 1 and calls `zlib.inflateSync` with no output cap, a ~1032:1 decompression bomb reachable from any peer over `query_short_channel_ids`/`reply_channel_range`. `gossip/scid-encoding.ts:52-57`.
- **S-7 LOW (3):** `dont_forward` not set on `channel_update` for unannounced channels, leaking private-channel policy (`lightning-node.ts:3839`); the required-feature check compares against advertised local features rather than the implemented set, disconnecting peers that require `upfront_shutdown_script`(4) / `route_blinding`(24) which we implement (`features/flags.ts:294-312`, `peer.ts:455-463`); alias byte-truncation can split a UTF-8 codepoint and more than one DNS address is not rejected (`lightning-node.ts:4764-4770,469-471`).
- **Clean:** BigSize/TLV/framing, ping/pong (including the 65532 ignore rule), the full Noise_XK handshake and key rotation, error/warning semantics, BOLT 9 dependency pairs, TorV2/DNS address round-tripping.

### bLIP-51 liquidity ads, LND wtwire watchtower, peer storage

The "bLIP-51" label is a misnomer; the implemented protocol is bolts PR #878
`option_will_fund`, whose only deployed counterpart is CLN. Findings verified byte-level
against CLN `peer_wire.csv` / `lease_rates.c` and LND's watchtower Go sources.

- **S-L.H1 (HIGH)** `request_funds`/`will_fund` use TLV type 5; CLN and the spec use type 3. Both odd types are silently ignored, so leases never negotiate cross-implementation in either direction. `message/dual-funding.ts:57-59`.
- **S-L.H2 (HIGH)** `lease_rates` byte layout is wrong: field order (thousandths must be third) and `channel_fee_max_base_msat` must be `tu32`, not a fixed u32. CLN ads misparse or throw. `gossip/types.ts:71-96`.
- **S-L.H3 (HIGH)** `will_fund` signature is computed over the wrong preimage: the code signs `SHA256(funding_pubkey || blockheight || channel_type || rates)` but CLN signs `SHA256("option_will_fund" || funding_pubkey || (blockheight + 4032) || channel_fee_max_base_msat || channel_fee_max_proportional_thousandths)`. Every CLN `will_fund` is rejected and vice versa. `channel/liquidity-ads.ts:54-96`.
- **S-L.H4 (HIGH)** The lessor's `to_remote` output is never lease-locked (`leaseExpiry` is threaded only into `to_local`; no lease `to_remote` script exists), so a seller can escape the lease early by provoking a buyer force-close. `commitment-builder.ts:546,719`; `script/commitment.ts`.
- **S-W.H1 (HIGH)** The watchtower client uses `StateUpdateReply` codes 40/41/42 where LND uses 70/71/72. When a session fills (1024 updates), the real LND reply (71) never matches, so the session never rotates and every later revocation of that blob type queues forever and is never delivered: tower protection silently stops. A seq desync (70) never triggers resync, and 40 collides with LND's generic temporary-failure code, wrongly rewinding `seqNum`. The live-tower interop test only exercises the OK path. `watchtower/wtwire.ts:57-63`; `watchtower-client.ts:598-635`.
- **S-L/S-W MEDIUM (4):** seller accepts an unvalidated buyer `blockheight`, so a far-future or `>= 500,000,000` value freezes the lessor's own `to_local` (`channel.ts:7549-7571`); the lease proportional fee uses `requested_sats` instead of `min(funding_satoshis, requested_sats)`, desyncing balances against a compliant partial funder (`liquidity-ads.ts:25-35`); the signed `channel_fee_max_*` caps are never enforced on the lessor's own `channel_update` while the lease is active; peer-storage rate limiter discards the newest blob within 60 s instead of keeping the latest, losing the freshest backup exactly when state changes (`lightning-node.ts:1596-1605`).
- **S-W LOW (2) + peer-storage LOW (2):** no dust check on the justice sweep output, so tiny channels ship unredeemable blobs (`justice.ts:393-398`); the user-supplied sweep script length is not constrained to {22, 34}, so LND's tower errors at breach time (`lightning-node.ts:476,2224,2348`); `option_provide_storage` feature bit not set in `node_announcement` (overlaps S-7.M2); outbound peer-storage blob not padded to 65531 bytes.
- **Clean:** every wtwire message and blob byte layout matches LND exactly, including the preserved legacy weight `-1` bug, taproot type-10 reconstruction, breach-hint/key derivation, and the XChaCha20-Poly1305 envelope; lease `to_local` script; `node_announcement` TLV type 1; buyer-side ceilings; peer-storage wire types 7/9 and echo ordering.

### Wallet BIPs

- **S-B.H1 (HIGH)** PSBT `bip32_derivation` pairs a non-master fingerprint (the account node's `parentFingerprint`) with a from-master path, and neither is the master fingerprint the spec requires. Hardware cosigners (Coldcard/Ledger/BitBox) match by fingerprint and refuse to sign, defeating the watch-only (#51) and multisig (#57) external-signer flows. `wallet/index.ts:1077-1082,600-611`; `transaction/index.ts:884-947`.
- **S-B.M1 (MEDIUM)** Exported multisig descriptors put the parent fingerprint in a zero-path key origin, where BIP-380 requires the key's own fingerprint; Sparrow/Coldcard multisig registration is blocked even though address derivation round-trips. `wallet/index.ts:2525-2527`.
- **S-B.M2 (MEDIUM)** External-signer PSBTs omit `non_witness_utxo` for segwit v0 inputs; Ledger 2.x and Trezor >= 2.3.5 reject them (post-CVE-2020-14199). Taproot inputs are correctly exempt. `transaction/index.ts:998-1037`.
- **S-B.M3 (MEDIUM)** P2TR inputs are priced at 138 vB instead of ~57.5 vB in `getByteCount`, a ~2.4x fee overpay on every taproot spend (and `sendMax` pays the recipient correspondingly less); the `hasWitness` check on `indexOf('W')` also misses P2TR. `utils/transaction.ts:267,329`.
- **S-B.M4 (MEDIUM)** The change-chain gap-limit clamp uses the receive-chain variables (`currentGap`/`addressIndex.index` instead of the change equivalents), so change can land more than the gap past the last used change address (undiscoverable by a standard restore) or reuse an address. `wallet/index.ts:2055-2058`.
- **S-B LOW (1):** the bech32m fallback validates any well-checksummed string as an address without witness-version / program-length rules and never returns signet (`utils/wallet.ts:190-206`, `helpers.ts:118-123`).
- **Clean:** descriptor checksum (BIP-380), BIP-67 sortedmulti ordering, BIP-44/48/49/84/86 paths, SLIP-132 version bytes, BIP-21 encode, Electrum fee conversion and script-hash subscriptions.
- **Note:** S-B.H1, S-B.M1, S-B.M2 share one root cause (no way to give beignet a key's true master fingerprint / origin); one API addition addresses the fingerprint pair, the descriptor origin, and lets `non_witness_utxo` attach.

---

## Suggested remediation order

1. **Taproot on-chain safety (FS-2, FS-4, FS-5).** Taproot channels can be breached
   without detection, cannot fee-bump a force-close, and can have a coop-close burn our
   balance. These are the sharpest fund-loss edges and all sit in the same feature.
2. **Sweep rebroadcast (FS-3).** One-line root cause (`toBuffer()`), but it disables
   every RBF re-bump and can crash the process during an active breach. Cheap, high value.
3. **Channel-open and HTLC-removal safety (FS-1 / S-2.H2, S-2.H1, S-2.H5).** Unvalidated
   `accept_channel`, the malformed-HTLC double credit, and uncommitted-update reversal are
   all reachable by a normal peer.
4. **Splice / SCB recovery (FS-6, FS-7, S-2.H3, S-2.H4).** In-flight-splice watch gap,
   stale-after-splice SCB, missing `tx_add_input` validation, and the zeroed dual-fund
   prevtxid. Splicing is newer and several of its failure modes lose funds or brick opens.
5. **BOLT 3 HTLC ordering (S-3.M2).** Deterministic, peer-inducible force close; small fix.
6. **BOLT 12 offers and liquidity ads wire format (S-4.H1..H4, S-L.H1..H4).** Not
   fund-loss for us, but these features interop only with beignet today; worth a coordinated
   rewrite against the current spec text and CLN.
7. **The wire-error systemic gap** and the remaining MEDIUM/LOW items as follow-ups.

## Baseline test evidence

- `npm run test:conformance`: 43 passing (green).
- `npm run test:all`: 4533 passing, 89 pending, 1 failing; the failure is
  `watchtower client vs live LND tower` (needs a live LND container, not present here).
- Root wallet/onchain suites: green on isolated reruns; the batch-run
  `tests/transaction.test.ts` failures were live-Electrum flakiness.

No code was modified during this review.
