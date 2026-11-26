# Converting a channel between an asset channel and a plain channel

Proposed design for two Beignet peers, issue [#2151](https://github.com/coreyphillips/beignet/issues/2151). Nothing here is implemented.

A conversion splice spends a channel's funding output and creates a funding output of the other type in one transaction:
- an asset channel becomes a plain Taproot channel; or
- a plain Taproot channel becomes an asset channel.

The two peers trade the balance at figures they both agreed before either signs. If the transaction never confirms, the channel goes on at its old output with its old balances, as with any pending splice. Before it confirms a conversion can be cancelled, but neither peer can take one side of the trade without giving the other.

It builds on [asset splicing](ASSET-SPLICING.md) and keeps that design's exit rule: until both locks agree, either funding output can decide who gets paid, and each peer must already be able to close and recover its share on either. Three things are new:
- **Two channel types.** The two branches have different types. A wallet runs channels of both, and a peer holds the recovery data of both types at once.
- **Balances move by agreement.** Today they change only by what a peer puts in or takes out.
- **The trade is priced.** Who holds a complete transaction first, and who can cancel, matter.

## What it is for

A wallet behind a node that converts between bitcoin and an asset (its primary) holds one unit at a time, over one channel with that node. Changing the unit today takes three steps: open a channel of the other type, trade over Lightning, then close the old channel. That is two on-chain transactions, with both channels open in between.

A conversion does it in one. The peer whose host priced the trade is the **quote giver**, usually the primary, and the other is the **quote taker**.

**To bitcoin**
- Every unit of every issuance leaves the channel, by withdrawal, to outputs of the peer that buys them.
- The new funding output is a plain final Taproot output.
- The new channel's first commitment gives each peer the agreed bitcoin.

**To an asset**
- The peer that sells units adds them as asset inputs.
- The new funding output is an asset funding output.
- The first commitment gives each peer the agreed units of each issuance and the agreed bitcoin.

**Out of scope**
- **Not a conversion:**
  - a change from one asset to another (two conversions do it);
  - a partial conversion (an asset splice already moves units in or out of an asset channel).
- **Not supported:**
  - a conversion with any HTLC in flight;
  - a channel whose peer does not run this profile, such as a channel a Lightning Labs peer opened;
  - a wallet of an earlier generation;
  - an announced channel;
  - mainnet.

## A wallet that runs both types

Today a final wallet is one generation, chosen when it is made, and the generation decides what its channels can be.
- **Generations.** `finalWalletGeneration` (`src/lightning/storage/final-wallet-generation.ts`) refuses more than one capability:
  - generation 2 runs plain final Taproot channels;
  - generations 3, 4 and 5 run asset channels (dual-funded opening, asset splices, and asset splices with revoked-commitment recovery).
- **Gates that read the generation:**
  - plain updates, splices, cooperative close and claims need `canUpdateFinalCommitments`, which is generation 2 only (`src/lightning/storage/sqlite-storage.ts`, `src/lightning/channel/final-opening-transport.ts`, `src/lightning/chain/final-output-claims.ts`);
  - the plain update log is created only for generation 2 (`src/lightning/storage/final-wallet-format.ts`);
  - `finalOutputClaims` in `src/lightning/node/lightning-node.ts` wires asset claims for every final channel of an asset wallet, plain claims for a generation 2 wallet, and nothing otherwise;
  - `assetOpeningOutputClaims` (`src/lightning/chain/asset-opening-claims.ts`) returns no claim for a channel without asset evidence.
- **What follows.** No wallet today can hold the plain parent of a conversion to an asset, or run the plain channel a conversion to bitcoin makes.

**Generation 6.** A conversion therefore needs a wallet generation of its own, chosen at initialization (`beignet init --network regtest --asset-conversion`).
- **What it holds.** Everything generation 2 does for plain final channels, and everything generation 5 does for asset channels (`--asset-splice-recovery`).
- **Tables.** They are created when the wallet is made (`installWalletMarker`), so wallets of generations 1 to 5 and their schema are untouched. No existing wallet migrates.
- **Peers.** Both peers must be generation 6. The asset type of a conversion is `ASSET_SPLICE_RECOVERY_TYPE_HEX` only, since a generation 4 wallet has no remedy for a revoked asset commitment.
- **The downgrade fence.** A build without generation 6 refuses the whole wallet at its identity and generation check ("Final wallet binding does not match", `src/lightning/storage/final-wallet-format.ts`). So a converted channel never reaches a build that would misread it.

**The current type.** In a generation 6 wallet, a channel's type is a property of the channel and of each funding branch, not of the wallet.
- **The opening record does not change.** It is re-validated on every read against the wallet's enrollment, authenticated by the device, and a backup must keep it byte for byte.
- **The type is a record.** The opening fixes the first type. Adoption of a conversion appends a current-type record to the channel's journal.
- **Every reader consults it.** Each place that today decides a channel's type from the wallet generation or from the opening's asset evidence reads that record instead:
  - the journal and the transports;
  - `handleFundingSpent`, `observedFinalExit` and `updateFinalDepth` (`src/lightning/channel/channel-manager.ts`);
  - the commitment builders `buildFinalCommitmentView` and `buildAssetSpliceCommitment` (`src/lightning/channel/final-opening-commitment.ts`), whose opening validators (`src/lightning/storage/final-opening-candidate.ts`) check the opening's type today;
  - the update signer's type check (`src/lightning/storage/final-update-signing.ts`);
  - the gates that take a session with `updateLimits` for a plain channel, since asset sessions store `updateLimits` too: the plain ledger in `src/lightning/storage/sqlite-storage.ts`, and `updatesReady` and `collectCommitmentBatch` in `src/lightning/channel/final-opening-transport.ts`;
  - `IFinalSpliceTerms.assetFundingRoots` (`src/lightning/channel/final-splice-candidate.ts`), which requires a root on both sides;
  - the claim builders.

## Negotiation

**The feature.** A conversion has a feature of its own: optional init bit 463, pair 462/463.
- **Why this pair.** It continues the profile bits 456, 458 and 460, and clears every pair in `FOREIGN_PAIRS` (`tests/lightning/feature-bit-collisions.test.ts`). Pairs 446/447 and 448/449 stay in the block left for asset channel type modes.
- **When to update the bit comments.** The comment in `src/lightning/features/flags.ts` and the test's description of the beignet block, which already leave out 456 to 461, are updated when the bit lands.
- **What it requires:** quiescence, splicing, `OPTION_ASSET_SPLICE` (458/459) and `OPTION_ASSET_SPLICE_RECOVERY` (460/461).
- **What 463 stands for.** A node configured with asset channels sets LND's staging Taproot bit 180, which masks bit 81 and clears simple close (`src/lightning/node/lightning-node.ts`), and the final opening depends on simple close (`src/lightning/features/final-opening.ts`). A generation 6 node keeps those masks toward every peer, for the reasons they exist (LND's staging type, and its RBF close, #1929). Between two peers that both set 463, bit 463 alone stands for the plain final type and its simple close, for channels of generation 6 wallets only. The two predicates that read the masked bits accept 463 in their place between two generation 6 peers: `finalOpeningNegotiated` (`src/lightning/features/final-opening.ts`), which requires simple close and bit 80 or 81 on both inits, and `peerNegotiatedSimpleClose` (`src/lightning/channel/channel-manager.ts`). A generation 6 node opens or closes a plain channel only that way.
- **How the host is checked.** The build lists `assetConversion:v1` among its surfaces (`src/lightning/channel/auxiliary-api.ts`), and the engine probes the host with a `completeAssetConversionHost` predicate. The host's planner, exit views and confirmation calls all take a channel type per branch, since every existing member assumes an asset root on both. The node masks 462/463 unless the wallet is generation 6 and the predicate passes.
- **Before construction.** A peer missing a requirement declines. The wire encodings need test vectors before implementation.

**Preconditions.** Start with the BOLT 2 quiescence handshake and finish outstanding commitment rounds. A conversion then requires all of these, and either peer declines otherwise:
- no HTLC in either direction, plain or asset;
- no pending splice or unadopted candidate;
- no update round in flight.

With no HTLC, the candidate's commitments have two balance outputs and their anchors. A revoked commitment of the parent may still hold HTLCs, and keeps the old type's HTLC penalty claims.

**Binding the target type.** The funding script tells an output with an asset root from one without, but not one asset type from another, or an SCID alias from none.
- **On the wire.** The target channel type travels in an even TLV of `splice_init` and `splice_ack`. Today the splice codec (`src/lightning/message/splice.ts`) skips unknown odd TLVs, and the asset path requires the re-encoded messages to equal the bytes received, so the codec learns the new TLV. Every other splice path of the same build refuses a `splice_init` or `splice_ack` that carries it, including the legacy splice handling in `src/lightning/channel/channel-manager.ts` and the plain final transcript (`src/lightning/channel/final-splice-transcript.ts`).
- **In the digests.** The type is an explicit field of the layout and final manifest digests, under a domain of its own rather than `beignet/asset-splice/` or `asset-splice-agreement/v1`.
- **To the host.** It is passed to the host's verify call.
- **In storage.** It is persisted in each exit branch before the first candidate commitment signature.
- **The alias bit.** A plain target keeps the parent's choice of the SCID alias bit, and the asset type has none.

**The terms.** Bind these in `splice_init` and `splice_ack` and in the asset splice envelope (`ASSET_SPLICE` 98, `ASSET_SPLICE_CONSENT` 99), on top of everything an asset splice binds:
- **Roles.** Which peer is the quote giver and which the quote taker.
- **The target channel type,** as above.
- **The candidate's channel parameters,** stored per branch:
  - its dust limits and `max_accepted_htlcs`;
  - to an asset, a dust limit of exactly 354, which is both the engine's floor (`MIN_DUST_LIMIT_SATOSHIS`) and the asset carrier, and at most 83 HTLCs, as `applyAuxiliaryFunding` (`src/lightning/channel/auxiliary-funding.ts`) and the asset splice size check require. A plain parent opened at 483 HTLCs therefore takes a smaller limit on the candidate.
- **Units, by issuance:**
  - for each issuance, the debit owner, then the output serial, then the units;
  - to bitcoin, the whole of each issuance, to withdrawal outputs of the buyer;
  - to an asset, what the seller adds.
- **The first commitment of the new channel.** Each peer's bitcoin balance, and to an asset each peer's units of each issuance.
  - These are absolute figures, after the opener's commitment fee, the anchors and the carriers.
  - `relative_satoshis` keeps its meaning: the funding output equals the parent plus both relative contributions.
- **Fees.**
  - **Funding fee and budgets.** Who pays the funding fee, with each peer's fee budget. `feeBudgets` (`src/lightning/channel/asset-splice-manifest.ts`) already lets one peer pay all of it.
  - **The feerate.** The engine passes the feerate to the host's planner. Today the exit views carry it at exit signing, but the planner's `IAssetSpliceBitcoin` does not.
  - **Withdrawal outputs.** Who pays for them, to bitcoin.
- **The host's agreement.** An opaque reference, such as a quote ID, with its expiry.
- **Lock depth.** From three to six confirmations. A conversion takes no lock depth below three, since a one-block reorganisation and a double-spend after adoption would leave only revoked parent commitments.

**What the engine checks by itself.** These checks do not rely on either host:
- **Bitcoin.** It is conserved across the inputs, the outputs and the fee. Separately, the first commitment's balances add up to the new capacity times 1000 in millisatoshis.
- **Reserves.** Today the floor applies to a side that owns a surviving non-funding output (`src/lightning/channel/final-commitment-reserve.ts`). A conversion keeps that rule and adds one: a side whose bitcoin falls in the trade also keeps its reserve on the candidate, since in a trade a side's balance can fall without it owning such an output.
- **Carriers.** To an asset, each holder commitment meets the carrier rule of `src/lightning/channel/auxiliary-funding.ts`: the larger dust limit, with the opener's 354 sats counted after the commitment fee and both anchors.
- **Withdrawal outputs.** To bitcoin, each withdrawal output holds at least the larger of the dust limit and `DUST_LIMIT_SATS`.
- **Credits by serial parity.** Every output that credits a peer was added under that peer's own serial parity. The one exception is the shared funding output, which the initiator adds and which credits both. A peer's host then checks its recipients for exactly what the terms credit it, and a faulty host on one side cannot route the other peer's units.
- **The feerate floor.** A funding feerate below the engine's own estimate, less a margin the host sets so that two engines whose estimates differ do not deadlock, is refused. Today any feerate of at least 1 sat/kw is accepted (`src/lightning/channel/asset-splice-transport.ts`).
- **The opener.** The commitment fee stays with the peer that opened the channel. The opener drives the reserve, fee and carrier accounting and is fixed in the opening record.

Each host checks the terms against its own agreement before its node signs anything. The engine refuses the attempt when a host does not confirm the exact terms.

## From proposal to a spendable conversion

The five steps of [From proposal to a spendable splice](ASSET-SPLICING.md#from-proposal-to-a-spendable-splice) apply, with these differences.

1. **Agree on the move.** As above. A peer refuses before spending time on proofs when the preconditions fail or its host declines the terms.
2. **Agree on the layout.**
   - **Planners.** A conversion has a planner of its own. `planAssetSpliceBalances` (`src/lightning/channel/asset-splice-balances.ts`) refuses a candidate with no units ("Invalid candidate asset inventory") and a parent with none ("Missing parent asset inventory"). The layout's `parentRoot` is required today and checked against the parent's script.
   - **To bitcoin:** the candidate's channel output carries no asset root. The virtual transfer assigns every unit of the parent's funding asset to the agreed withdrawal outputs. For each issuance, `old funding + external asset inputs = withdrawals + change`, with nothing left in the channel.
   - **To an asset:** the parent has no root, and the candidate's channel output gets the root built from the added inputs, as a dual-funded asset opening builds it.
   - **Quiet starts here.** From the layout acknowledgement, the channel is quiet (see below), since the layout binds the state number.
3. **Authorize the assets, then freeze the Bitcoin transaction.** As for an asset splice. Each peer verifies every input history and every output commitment, and unrelated passive assets go to owner-authorized outputs or the input is declined.
4. **Secure both exits and the units before funding signatures.**
   - **Commitment views.** Each peer builds the candidate's first commitment views in the new type, at the state number the layout bound and at the agreed balances:
     - to bitcoin, the plain final Taproot commitment of Step 13;
     - to an asset, the asset commitment of Step 14, with its leaves and proof templates.
   - **Host check.** Each host verifies the candidate's commitment balances against its agreement before its node signs.
   - **What each peer persists:**
     - for the candidate: the signed funding transfer, a fully enforceable local exit of the new type, the matching remote view and, to an asset, the proof templates for its outputs;
     - for the parent: the current state of the old type, which stays live.
   - **The buyer's units.** To bitcoin, the buyer's whole side of the trade is its withdrawal outputs. Its host persists the signed transfer and proof of each withdrawal it receives before its node signs funding, and the engine checks that receipt as it checks `retainSpliceExits`. Without this, a crash or a peer that withholds the proof leaves the buyer having paid bitcoin for units it cannot spend.
5. **Sign and broadcast.**
   - **Expiry.** Immediately before a peer releases its funding witness, its host checks again that the agreement has not expired, beside the existing currency check of the attempt. If it has, the peer sends `tx_abort`.
   - **The order.** The order of `tx_signatures` is fixed by role, not by contribution: the quote giver sends first. The taker then holds the complete transaction, broadcasts it at once and sends its own. Today the splice initiator, whose contribution includes the shared input, almost always sends second.
   - **The giver's timeout.** It is longer than the taker's own work before it signs: today the second sender checks that the inputs are unspent only after the first sender's `tx_signatures` arrive, retrying for about 12 seconds (`src/lightning/channel/asset-splice-signature-round.ts`), then its host signs, and a disconnect delays delivery until replay on reconnect. When the timeout passes, the giver first looks for the candidate in its mempool and on chain, and takes the taker's witness from it if it is there. Only otherwise does it treat the candidate as publishable and cancel it (below).
   - **After a witness leaves.** The expiry has no force on chain, and hosts take a late confirmation as the trade agreed.

## While both outputs are live

**Quiet.** From the layout acknowledgement until both peers' `splice_locked` name the candidate, neither branch takes an update: no add, fee update, fulfil or fail. Quiet ends only:
- at adoption;
- when the attempt is aborted before any funding witness has left;
- when a conflict cancels the candidate (below);
- when the parent is closed unilaterally.

There is no cooperative close during quiet. Before a witness leaves, the attempt is aborted instead.

Updates would be unsafe for three reasons:
- the two branches hold different balances, so the asset splice rule of updates "within the intersection of all live views" does not apply;
- an update would need one batch to sign commitments of two types;
- a payment one branch could carry may be impossible on the other.

Today both kinds of splice take updates before adoption:
- `assetUpdateHeight` (`src/lightning/channel/channel-manager.ts`) releases asset updates once a single pending candidate is mined at current inclusion;
- a plain final splice takes updates while its funded candidate waits for its locks. `finalSpliceQuiescent` holds them only before funding, during a replacement, while an abort is echoed or its inputs are unreleased, and from the second lock to adoption.

A conversion keeps one persisted quiet flag that both consult. Inbound asset updates already park (`src/lightning/channel/asset-splice-update-transport.ts`). A payment asked for meanwhile is refused with a reason a host can show, so a wallet can say a switch is under way.

**Cancelling.** Any peer that added an input of its own can double-spend it before the candidate confirms, even with the candidate in the mempool:
- to an asset, the seller's asset inputs;
- in either direction, the fee payer's bitcoin inputs.

The design makes cancellation clean rather than trying to forbid it:
- **The revert.** A conversion takes the conflicted-splice revert of [Depth-locked splices](SPLICE-LOCK-DEPTH.md) section 2 (`splice_conflict`, `splice_conflict_ack`). Once both peers have each verified, on their own chain view, a conflict 6 blocks deep (`SPLICE_CONFLICT_DEPTH`) with no confirmed candidate, the channel returns to the parent and quiet ends. This is simple here, since neither branch took an update. Today the revert exists only for legacy channels.
- **The giver can always cancel.** The quote giver contributes at least one input of its own, so it can cancel by double-spending that input, never by having to close the channel. That bounds the taker's option to hold the complete transaction once the cancel confirms. If the taker has already broadcast, the cancel has to pay more than the candidate's whole fee to replace it.
- **The giver's own option.** It cuts both ways: until the candidate confirms, the giver can cancel after the price moves, at the cost of a double-spend that outbids the candidate. The engine cannot stop a wallet from spending its own coin. A taker's host prices that option, and the feerate floor keeps the window to about a block while fees hold.
- **What the taker risks.** A giver that cancels costs the taker the trade, not its balance: the parent stands with the old figures.
- **Only before adoption.** A revert is refused once the candidate is adopted, as that extension refuses one for a splice that is locked or confirmed. A reorganisation deeper than the lock depth that returns an adopted candidate to the mempool, followed by a double-spend, leaves both peers with only revoked commitments of the parent. Recovery then needs a fresh parent state that both peers sign. The floor of three confirmations narrows this, but does not remove it.
- **After a revert.** The candidate's exit data and watch are kept, and its claim builder reads the same secret store. As that extension says, a reorganisation deeper than 6 blocks that undoes the conflict can let the candidate confirm after the parent's next update has revoked the state they share.
  - **What settles.** Only the withdrawal outputs and asset inputs settle at the trade's figures. Neither peer then holds an unrevoked commitment on the candidate, and HTLCs added on the parent after the revert have no output there.
  - **What the kept data does.** It lets a peer punish the other's publication of a revoked candidate commitment.
  - **What recovers the balances.** A cooperative close, or a fresh candidate state that both peers sign, as that extension says for this case.

**Fees and a slow candidate**
- **The floor.** The funding feerate is at least each engine's own estimate.
- **Replacement.** An asset splice's replacement rules hold: only the quiescence initiator proposes one, while quiescent. A fee payer that is not the initiator first opens a new quiescence handshake as initiator, since the conversion's quiet is not BOLT quiescence. A conversion's replacement may only raise the fee, funded by the fee payer, and keeps every trade figure, recipient, allocation and the giver's cancel input. Any other replacement is declined. The revert treats every signed candidate as one splice, and quiet ends only when all of them are conflicted.
- **What the other peer can do.** It can raise the fee only by CPFP through a commitment of the new channel and its anchor, which means closing that channel. Its other choice is to wait.

## Lock and recovery

**At lock.** Each peer verifies the candidate's inclusion, its depth and, to an asset, its proofs before it sends `splice_locked`. Adopt only when both locks name the same txid on the local accepted chain.

Adoption is one journal event, in one scope: the current-type record. A journal append extends one scope's hash chain and claims its slot in the signer's database first (`src/lightning/storage/final-device-journal.ts`), and `appendAssetSpliceEvent` refuses to run inside an outer transaction. So the rest is derived from that event, again on every replay:
- to an asset, the new asset state is installed and the confirmed proofs imported;
- to bitcoin, the buyer's withdrawal receipts are confirmed.

The old type's state is **not** dropped at adoption.

**Until the reorg window closes**, at `IRREVOCABLE_DEPTH` (100 blocks, `src/lightning/chain/types.ts`) past adoption, each peer keeps for the parent:
- the old type's evidence, proofs, exit data, ledgers and watches;
- every remedy of a revoked parent commitment, including its HTLC penalty claims;
- on its host, the proofs and payout locators that the host's `recoverOutput` and `confirmAssetPayout` need for an asset parent (`src/lightning/chain/asset-opening-claims.ts`).

After a restart in that window, the parent's watch is armed again. Today `AssetSpliceConfirmation.restore` skips a channel with no asset state, which a parent of a conversion to an asset would not have. A deeper reorganisation after adoption needs chain resolution before updates resume, as for an asset splice.

**Revocation secrets cross the type change**
- **Numbering continues.** Commitment numbers and per-commitment points continue: same seed, and the obscured number from the opening's basepoints.
- **The ledgers do not continue today:**
  - the plain ledger starts at height 0 from the opening and enforces the BOLT 3 shachain buckets ("Missing preceding revocation secret", `src/lightning/storage/final-channel-updates.ts`);
  - the asset ledger expects the prior state's point (`src/lightning/channel/asset-splice-update-batch.ts`).
- **The rule.** The new type's ledger is seeded at the conversion's state number with the peer's current and next points and every secret the old ledger holds.
- **One store.** Each peer secret received after adoption is recorded in one store that both claim builders read. A plain revocation then also punishes an asset commitment of the parent published after a reorganisation, and the reverse.
- **Today.** Plain claims read secrets from `loadFinalResolutionStates`, and asset claims look for them only at the asset journal's `peer-revoke` stage (`src/lightning/chain/asset-splice-output-view.ts`).

**Claiming by branch**
- **The watcher.** It has one hook, which receives the spending transaction.
- **The claim builders.** They match the branch by prevout and txid, as `matchedAssetPayoutViews` does today. Then they build the claims of that branch's recorded type:
  - the parent's commitments, current or revoked, by the old type's claims;
  - the candidate's first commitment, which is never revoked before lock, by the new type's.
- **Asset-only reporting.** Today the asset builder marks every balance output as an asset balance (`assetOpeningOutputClaims`), and that drives the payout and collateral reporting. A plain branch must not trigger either.
- **Per-branch views.** `IAssetSpliceExitBranch` (`src/lightning/storage/asset-splice-exit-proofs.ts`) requires a `fundingRoot`, `fundingProofs` and asset proofs on both branches, and `spliceRecoveryView` (`src/lightning/storage/asset-splice-recovery.ts`) uses one opening type and root. In a generation 6 wallet, each branch records its type, a plain branch has no root or proofs, and the recovery view is built per branch.

## Restart and backups

**Restart.** As for an asset splice, persist these before the messages that depend on them:
- the manifests, signed transactions and proof material;
- both types' exits and the buyer's withdrawal receipts;
- the quiet flag, the locks and the outbound messages.

Then reconcile the full set of live outpoints on reestablish.

**Backups**
- **What does not apply.** Static channel backups and recovery capsules never cover final wallets (`requireLegacyWallet` in `src/lightning/node/lightning-node.ts` and `src/lightning/recovery/capsule.ts`), and a conversion changes nothing there.
- **What `beignet restore asset-channel` does today.** It needs a funded opening with asset evidence, and it authenticates only the opening and the asset splice journal prefix.
- **What a generation 6 wallet needs instead.** A restore that rebuilds each branch by its recorded type, and authenticates the stream that holds the new type's updates and the current-type record, with signing authority on the enrolled original device. It also restores the host's payout locators and, to bitcoin, the buyer's withdrawal receipts.
- **Which channels it covers.** A plain channel of such a wallet, a channel with a pending conversion in either direction, and a converted channel together with its parent's remedies through the reorg window.

## Checks before enabling the feature

Acceptance cases, each in both directions:
- **Shapes:**
  - a conversion with each peer as initiator;
  - one with each peer as quote giver;
  - one with each peer paying the fee;
  - one at the smallest balances that meet reserve and carrier.
- **Refusals before any signature:**
  - a host that declines the terms;
  - terms that differ by one unit or one sat;
  - an expired agreement at the final check;
  - a target type, alias bit, dust limit or HTLC limit that differs from what was bound;
  - a feerate below the estimate;
  - a pending HTLC of either kind;
  - a peer of generation 4 or 5;
  - a `splice_init` carrying the target type on a legacy or plain final splice path.
- **Interruptions:**
  - a disconnect, and a SIGKILL, on either side of each signature, with exact replay after restart;
  - a giver that never receives the taker's `tx_signatures`;
  - a taker that never broadcasts;
  - a crash of the buyer between the withdrawal receipt and its funding signature.
- **Cancellation and replacement:**
  - a double-spend of the giver's input, with the revert at 6 blocks on both chain views;
  - after a revert and a parent update, a reorganisation that lets the candidate confirm: the withdrawals and asset inputs settle, a revoked candidate commitment published by either peer is punished, and the balances are recovered by a cooperative close or a fresh candidate state;
  - a revert refused after adoption;
  - a giver whose timeout passes while the candidate is already in its mempool, which takes the taker's witness and does not cancel;
  - a fee-only replacement by the payer;
  - a candidate dropped from the mempool.
- **Reorganisations:**
  - a candidate mined and reorged out below lock depth;
  - one mined in a separate run after the parent's close.
- **Chain exits.** On each funding output before lock, each peer publishes:
  - its current commitment;
  - a revoked commitment of the parent, with HTLCs.

  The defender claims everything by the right type's rules.
- **After adoption:**
  - a unilateral close and a revoked commitment of the new type on the candidate's output;
  - a restart, which re-arms the parent's watch;
  - updates of the new type with revocations, then a reorganisation deeper than lock depth in which the peer publishes a revoked parent commitment that the new type's revocation covers. It must be punished.
- **Restore:**
  - from backups taken before the conversion, while it is pending in each direction, and after adoption and new-type updates, followed by a deep reorganisation;
  - payments, a further asset splice after a conversion to an asset, and a cooperative close.

In every case, compare the actual outpoints, the per-issuance receipts and the spendable balances of both peers against the agreed terms.

## Open questions for review

1. **Who sends `tx_signatures` first.** This design says the quote giver, so a user never depends on a primary to publish. A primary serving many wallets then carries the taker's option to hold the complete transaction, bounded by its own cancel, and the taker carries the giver's option to cancel until confirmation, priced by its host.
2. **Moving an existing generation 5 wallet to generation 6.** This design says no: a new wallet, as for every earlier generation.

The underlying protocols are those of [asset splicing](ASSET-SPLICING.md), [BOLT 2, channel splicing](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#channel-splicing) and [Depth-locked splices](SPLICE-LOCK-DEPTH.md).
