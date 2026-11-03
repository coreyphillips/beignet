# One-transaction splice-out from several channels (design note)

Step 4 of issue #1922. A wallet that keeps its funds with several ranked
primaries (steps 1 and 2) and pays Lightning invoices across them (step 3)
still pays an on-chain address from one channel at a time:
`BeignetNode.spliceOut` splices one channel with one peer and may send the
withdrawn amount to an address. An amount larger than any single channel's
balance has no on-chain path. The request in #1922 section 4 is one
transaction that splices out of two or more channels, pays the address once
and re-creates each channel's funding output with its reduced balance. This
note settles how that transaction is negotiated, signed, persisted and
recovered before any code is written (the "required protocol design" list in
#1924 section 4). Step 5 implements it.

Everything below is written against the splice code as it stands on master
after step 3. File references name the function so they survive line drift.

## 1. The transaction

### Shape

One transaction with, for a channel set C of size N:

- N inputs: the current funding outpoint of every channel in C. All are 2-of-2
  P2WSH outputs, all confirmed, all with sequence `0xfffffffd`.
- N funding outputs: one per channel, the same 2-of-2 script as that
  channel's funding today, at `old_capacity_i - debit_i - fee_i`.
- one destination output at `amount = sum(debit_i)`, the script the caller
  gave.
- no change output. The fee is implicit, `sum(fee_i)`, as in a
  single-channel splice-out (`Channel._computeSpliceContributions`, "the fee
  is implicit (input - outputs)").

Inputs and outputs are ordered by serial id, as every interactive
transaction is (`buildSpliceTx`, `InteractiveTxBuilder.buildTransaction`).

### Which channels take part

A channel joins the set only when all of these hold at planning time:

- it is NORMAL, not quiescing, with no splice pending, no RBF pending and no
  owed `tx_abort` (`Channel.spliceBusyReason`);
- its funding is confirmed. `require_confirmed_inputs` from any peer is then
  satisfied for every input, and a zero-conf channel whose funding is still
  unconfirmed never contributes an input another peer cannot see;
- its peer advertises `option_splice` and `option_quiesce`
  (`LightningNode.peerSupportsSplicing`) and the composite capability of
  section 8;
- it is not reserved by an offline receive, a direct-funding request or an
  automatic channelization (section 6);
- its post-splice balance stays at or above the reserve priced at the new
  capacity, with the commitment cost and dust floor the single-channel
  preflight already applies (`LightningNode.spliceOut`,
  `Channel._spliceBelowReserveRefusal`).

### Amounts and fees

The initiator pays the whole fee, as today (`splice-weight.ts`). The weight
of the composite is

```
SPLICE_TX_BASE_WEIGHT
+ N * SHARED_FUNDING_INPUT_WEIGHT
+ N * outputWeight(34)
+ outputWeight(destination script length)
```

`estimateSpliceTxWeight` counts exactly one shared input and one funding
output. Step 5b gave it `fundingInputCount` (default 0): further 2-of-2
inputs, each `SHARED_FUNDING_INPUT_WEIGHT`, which a single channel's
splice-in already uses for a P2WSH wallet input (`spliceWalletInputCounts` in
`channel.ts`). Step 5c adds the extra funding outputs so the wallet's quote,
the engine's preflight and each channel's contribution arithmetic keep using
the same function, as its header demands.

The acceptor's audit floor (`auditMinInputWeightWu`) priced every input that
is not P2TR at the P2WPKH weight. Since step 5b it floors a P2WSH input at
`SHARED_FUNDING_INPUT_WEIGHT`, the 2-of-2 spend being the only P2WSH form an
acceptor admits, so its fee check does not run lenient on a composite; the
initiator prices such an input with the same constant, so an exact-feerate
composite always passes.

The fee is apportioned to channels in proportion to their debit, rounded up
per channel so the sum never falls short:
`fee_i = ceil(total_fee * debit_i / amount)`. Each channel's
`splice_init.funding_contribution_satoshis` is `-(debit_i + fee_i)`, so a
peer's `new_funding = old + relative` arithmetic matches the output we add,
the condition CLN enforces on the splice `commitment_signed`.

Each peer audits the completed transaction on `tx_complete`
(`validateCompletedInteractiveTx`): our inputs it can see (the other N-1
funding inputs) must cover our outputs (the other N-1 funding outputs plus the
destination) plus our contribution, which is negative in its session. With
the values above that is `sum_{j != i} old_j >= sum_{j != i} old_j -
sum_j fee_j`, which holds. The fee check is on the whole transaction, so the
same total satisfies every peer. The reserve rule
(`_spliceBelowReserveRefusal`) is per channel and is the planning bound on
`debit_i`.

Debits are drawn largest balance first: the channel with the most spendable
balance gives up to its reserve bound, then the next, until the amount is
covered. This keeps the number of channels, and so the weight and the
exposure to a non-signing peer, as small as the amount allows, and it levels
the fuller channels down, which is the direction section 2 of the issue
levels receives up. Rank is not used for on-chain debits. (Open question 4 on
#1922; see section 9.)

## 2. Sessions that agree on one transaction

### Problem

A splice is one `SpliceSession` and one `InteractiveTxBuilder` per peer. Each
session knows exactly one shared input, the channel's own funding outpoint,
and aborts if the peer names another (`Channel.handleTxAddInput`). Each
session's transaction is fixed when both sides send `tx_complete`, and
nothing shares serial ids, contributions or a txid across channels.

### Design

The wallet is the initiator in every session and adds the identical
contribution list to each, with identical serial ids:

- in session i, channel i's funding outpoint is the shared input (empty
  `prev_tx`, `shared_input_txid` TLV);
- every other channel's funding outpoint is an ordinary initiator input with
  its full funding transaction as `prev_tx`;
- the N funding outputs and the destination output are ordinary initiator
  outputs.

Serial ids are allocated once by the composite, not per session, and are even
(initiator). Every session gets `locktime` and `funding_feerate_perkw` from
the composite record. Peers add nothing: a `splice_ack` with a nonzero
`funding_contribution_satoshis`, any `tx_add_input` or `tx_add_output` from a
peer, or a `tx_remove_*` naming one of our items, aborts the whole composite
(section 4) before any `commitment_signed` leaves. With identical inputs,
outputs, serial ids, locktime and version, every session's `tx_complete`
produces the same transaction; the composite checks the txids are equal
across sessions and aborts everything if they are not. Only then does any
session send its splice `commitment_signed`.

Requirements:

- The composite MUST allocate serial ids and MUST NOT let a session's builder
  allocate its own (`SpliceSession.nextSerialId` is bypassed for composite
  sessions).
- A session MUST refuse, with `tx_abort`, a peer contribution of any kind,
  and the composite MUST then abort every other session.
- No session MAY send `commitment_signed` until every session has completed
  negotiation with the same txid.
- The locktime MUST be the same in every `splice_init` and MUST be at most
  the current height, so no peer can hold the transaction back.

## 3. Other channels' funding inputs

### Problem

Three things stop another channel's funding outpoint from riding as an
ordinary input today:

1. It needs its funding transaction as `prev_tx`, and that is not stored.
   `pendingFundingTxHex` is only the open's broadcast obligation, and the
   spliced funding's hex is dropped when the splice is adopted
   (`Channel._withSpliceAdoptionTail` clears `spliceInFlight`).
2. Our ordinary inputs are signed when the splice transaction is built at the
   commitment round (`buildAndSignSpliceTx`), by a closure over our wallet
   key. A 2-of-2 funding input needs the other channel's peer's signature
   too, and that arrives only in that peer's `tx_signatures`, as its
   `shared_input_signature`.
3. Before step 5b a beignet acceptor refused any peer input that is not
   P2WPKH or P2TR (`_v2CheckInputSpendable` during the `tx_complete` audit),
   and the deferred-witness path refused P2WSH as well
   (`_validateWitnessForInput`). Both failed closed because a general P2WSH
   witness cannot be verified without running the script. Step 5b admits
   the one verifiable form, as point 3 of the design says.

### Design

1. Durable funding hex. `IChannelState` gains `fundingTxHex`, set when the
   funding transaction is built or received (v1 `funding_created`, v2 and
   splice `tx_signatures`) and replaced at splice adoption. For channels
   restored without it, the chain backend's transaction fetch fills it the
   first time a composite plans with that channel, and a channel whose hex
   cannot be obtained does not take part.
2. Deferred 2-of-2 witnesses. Composite sessions reuse the #592 mechanism:
   the other channels' funding inputs are external inputs
   (`ISpliceWalletInput.external`), listed in
   `ISpliceInFlight.externalInputIndices`, and the session withholds our
   `tx_signatures` while a slot is empty (`_maybeSendSpliceTxSigs`). The
   composite fills slot j in session i from our own signature on input j
   (signed with channel j's funding key, BIP 143 sighash over the shared
   transaction) and peer j's `shared_input_signature` from session j, in the
   order channel j's funding script lists the keys. The session then releases
   as the existing delivery path does (`provideSpliceExternalWitness`
   internally, no embedder involved).
3. Verifiable P2WSH. At `tx_complete` an acceptor sees only each input's
   prevout, and a P2WSH prevout is a 32-byte program that says nothing about
   the script behind it, so `_v2CheckInputSpendable` admits a P2WSH prevout in
   a splice session (a v2 open keeps refusing it) and the check moves to the
   witness. `_validateWitnessForInput` admits exactly one P2WSH form: a
   witness script of `OP_2 <33-byte key> <33-byte key> OP_2 OP_CHECKMULTISIG`
   whose SHA256 is the prevout's program, with a witness
   `[<>, sig, sig, script]` where both signatures verify under BIP 143
   against the key they correspond to, in script order. That is fully
   verifiable, like a P2TR key spend, so a beignet acceptor can accept another
   wallet's composite splice. Every other P2WSH shape stays refused where the
   refusal lives today, at witness time. An initiator that never delivers a
   verifiable witness leaves the acceptor where a third party that never
   delivers one does (#592): holding a splice it forgets at reestablish.

Requirements:

- A composite MUST NOT start unless every participating channel has
  `fundingTxHex`.
- The witness for input j in session i MUST be assembled only from a
  `shared_input_signature` received in session j that verified against
  channel j's funding script and the composite's txid.
- An acceptor MUST verify both signatures of a 2-of-2 P2WSH initiator input
  before accepting its witness, at `tx_signatures` or on external delivery,
  and MUST keep refusing every other P2WSH form.

## 4. Signatures and the point of no return

### Ordering

In the interactive-tx rule, the side with less input value signs first, and
on a tie the lower node id (`Channel._spliceShouldSignFirst`). A composite
peer contributes no input, so it signs first in every session, which is also
what CLN does when it contributes nothing (`cln-splice-matrix.test.ts`, tier
C2: "CLN contributes nothing, so its tx_signatures arrives FIRST"). The
composite therefore collects every peer's `shared_input_signature` while
holding all of its own `tx_signatures` back. Our first `tx_signatures`, in
any session, is the point of no return: from then on some peer can complete
and broadcast the transaction, exactly as `_maybeSendSpliceTxSigs` already
documents for one channel.

### Before the point of no return

Until our first `tx_signatures` leaves, nothing we have given any peer lets it
spend anything: a peer holds at most its own signature on one input and a
transaction missing N other witnesses. A refusal, a disconnect, a timeout, an
invalid signature or a crash in any session therefore aborts the composite:
`tx_abort` in every session, `preSpliceState` restored, quiescence released,
the composite record marked ABORTED, the spend-limit reservation released.

`Channel.abortSplice` refuses once `tx_signatures` crossed in either
direction. The composite needs the refusal only for the direction that
matters: a session that has received the peer's `tx_signatures` but has not
sent its own may still abort, because the peer cannot broadcast. The refusal
is kept for `sentTxSignatures`. Step 5c implements this (`abortSplice` admits
the received-only case for a composite session).

What the peer does with that `tx_abort` is the one residue of this design.
BOLT 2 forbids a side that sent `tx_signatures` to forget the transaction on
`tx_abort`, since the aborting side may hold enough to publish it, and a
beignet acceptor refuses its own abort past that point and keeps the splice
at reestablish too (`_handleReestablishSplice` forgets only a splice with no
signatures in either direction). A peer that signed before the composite
aborted therefore keeps its `spliceInFlight` with `sentTxSignatures` and
stays in SPLICING, although nothing of its can confirm: the initiator holds
every witness it lacks. `tests/lightning/composite-splice.test.ts` pins that
("a peer that never signs within the budget"). The window is one round trip
per peer, between the commitment release and the peers' `tx_signatures`,
and only a peer that crashes or stalls exactly then can open it. Closing it
needs an acceptor-side change outside step 5: on `tx_abort` after sending
`tx_signatures`, return the channel to NORMAL on the old funding while
remembering the transaction and watching for it, as the conflicted-splice
revert of `docs/SPLICE-LOCK-DEPTH.md` remembers a reverted splice. That is
a follow-up issue, not part of #1922.

### After the point of no return

Once our `tx_signatures` has left in one session it leaves in all of them in
the same tick, and the composite broadcasts the transaction itself as soon as
the first session completes (`_spliceCompletionTail`, `BROADCAST_TX`
fundingCritical). Every channel then carries its own `spliceInFlight` record
with `sentTxSignatures` and `receivedTxSignatures`, watches the pre-splice
spend and the new funding, and sends `splice_locked` at depth
(`markSpliceConfirmed`, `completeSplice`). A peer that never acknowledges
cannot undo anything: the transaction is valid and broadcast, and the channel
adopts the new funding at depth as a single-channel splice does.

A composite transaction can lose an input after release: a peer can force
close on its old funding (it co-signed that commitment), and once that spend
confirms the composite can never confirm. The engine does not watch the
chain for this itself; it ends the record CONFLICTED and lifts the
reservation when a participating channel force closes, errors, closes or
reverts its splice (`channel:force-closing`, `channel:errored`,
`channel:closed`, `splice:reverted`), and the surviving channels' own splice
records follow the single-channel rules from there. What can also go wrong
after broadcast is a fee too low to confirm. Fee bumping a composite is out
of scope for step 5: the quote refuses a feerate below the backend's estimate
for the target, and the operator may bump with the single-channel RBF path
later if one is added.

### Failure table

Stages: P planning, Q quiescence, N interactive negotiation (`splice_init`
to both `tx_complete`), C commitment round, S peers' `tx_signatures`, R our
`tx_signatures` released, B broadcast, L `splice_locked`.

| Event                                                | P, Q, N, C, S (before R)                                                                          | R, B (after R)                                                                                         | L                                                                                                    |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| Peer refuses (`tx_abort`, error, wrong `splice_ack`) | abort every session; nothing spent                                                                | ignore for that channel: the tx stands; channel resumes at reestablish with `next_funding_txid`        | none left                                                                                            |
| Peer disconnects                                     | abort every session at once (the manager's `peer:disconnected` reaches the engine before the channel forgets its splice; a session dropped behind the engine's back is caught at the commitment check) | channel keeps `spliceInFlight`; resume at reestablish                                                  | wait for `splice_locked`                                                                             |
| A participating channel closes or reverts its splice (a peer's force close of its old funding, an error) | abort every session                                                                               | the transaction can no longer confirm whole: the record ends CONFLICTED and the reservation lifts; the surviving channels' own records follow the single-channel rules | none                                                                                                 |
| Peer never signs within the budget                   | abort every session                                                                               | not possible: R needs every S                                                                          | peer's `splice_locked` missing; channel stays pending-lock, HTLCs flow via dual commitments as today |
| Our crash                                            | record says ABORTED on restore if any session had not reached S; `tx_abort` owed in every session | record says RELEASED or BROADCAST: rebroadcast from `spliceTxHex`, resume each channel from its record | per channel as today                                                                                 |
| Invalid peer signature                               | abort every session                                                                               | cannot happen: R only after every S verified                                                           | none                                                                                                 |
| Peer contributes an input or output                  | abort every session                                                                               | cannot happen: checked at N                                                                            | none                                                                                                 |
| Peer lacks the capability                            | not selected at P                                                                                 | none                                                                                                   | none                                                                                                 |
| Mobile suspension                                    | same as crash                                                                                     | same as crash                                                                                          | same as crash                                                                                        |

Requirements:

- A composite MUST NOT release any `tx_signatures` until every session has a
  verified peer `shared_input_signature`.
- A composite MUST release in every session in the same synchronous step and
  MUST persist RELEASED before the first message leaves.
- A session MUST be allowed to abort after receiving but before sending
  `tx_signatures` when its composite aborts; the single-channel refusal for
  that case is kept outside composites.

## 5. Restart and persistence

### The composite record

A new persisted record, `ICompositeSpliceRecord`, written in the same storage
transaction as channel state. `persistChannelState` builds one
`recovery.commit` per dispatch, so the record is a new `RecoveryMutation`
variant on the model of `ffor_voucher`, behind its own optional storage
interface, with stage changes queued through `withStagedMutations` so they
ride the channel save that causes them. It is not a wallet-data record:
wallet data sits outside that transaction, and the record has to be durable
before the first `tx_signatures` leaves.

```
id                 32 random bytes (the operation id the API returns)
channels           [{ channelId, debitSats, feeSats, oldCapacitySats, newCapacitySats, serialIds }]
destinationScript, amountSats, feeratePerkw, locktime
stage              PLANNED | NEGOTIATING | COMMITTED | PEERS_SIGNED | RELEASED | BROADCAST | LOCKED | ABORTED
txid, txHex        once every tx_complete agreed (COMMITTED and later)
spendCharge        { amountSats, feeSats, chargedAt } for the limits of section 7
createdAt, updatedAt
```

It is written at PLANNED before the first `splice_init`, and at every stage
change before the message that causes it leaves. Per-channel state stays in
each channel's `spliceInFlight`, created at that channel's `commitment_signed`
as today; the composite record only adds the cross-channel facts. Step 5c
adds `remoteSharedInputSig` to `spliceInFlight` (the peer's half of the
shared input, kept once verified) so the witness of input j can be
assembled in every other session after a restart as well.

The record is not a recovery snapshot table (`RecoverySnapshot` and its
schema versions are unchanged): it is operational state with a life of
minutes. A journal rebuilt from a snapshot drops records older than that
snapshot, which the missing-record rules below absorb. Storage carries it in
the optional `compositeSplices` capability group (`saveCompositeSplice`,
`loadCompositeSplice`, `loadAllCompositeSplices`; SQLite table
`composite_splices`, schema version 20), and a node whose storage lacks the
group, or that runs without a recovery journal, refuses to start a
composite (`STORAGE_REQUIRED`).

### On restore

| Stage on disk           | Action                                                                                                                                                                                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| PLANNED, NEGOTIATING    | Nothing was signed. Mark ABORTED; each channel's `markForReestablish` already forgets a pre-commitment splice and owes `tx_abort`. Release the spend reservation.                                                                                      |
| COMMITTED, PEERS_SIGNED | Our signatures never left. Mark ABORTED and owe `tx_abort` in every session (set `spliceAbortOwed` on each channel). A peer that signed holds nothing spendable.                                                                                       |
| RELEASED, BROADCAST     | The transaction may confirm. Rebroadcast `txHex` (fundingCritical), keep every channel's `spliceInFlight`, resume each at reestablish with `next_funding_txid` and `retransmit_flags` as `_handleReestablishSplice` does. Mark the spend charge final. |
| LOCKED, ABORTED         | Terminal. Kept for the operation's status until the retention window.                                                                                                                                                                                  |

Two or more channels whose `spliceInFlight` records name the same
transaction can only be a composite (a single splice is one channel's own).
When no record describes that txid (a journal rebuilt from a snapshot older
than the record), restore synthesizes one from the channel rows: RELEASED
when any session sent its `tx_signatures` (the slots still owed are filled
and the operation is tracked to LOCKED), ABORTED otherwise (every session is
forgotten). The debit and fee split cannot be recovered from the rows, so the
synthesized record carries each channel's whole relative change as its debit
and says so in its reason. A composite record naming a channel that has no
`spliceInFlight` and is NORMAL on the pre-splice funding is treated as
ABORTED for that channel.

ABORTED rides the first session unwind's persist and each later unwind is its
own commit, so a crash between them leaves a channel holding a splice its
record says is over; restore finishes the unwind of every such session whose
`tx_signatures` never left. A restored channel parks its live state in
`preReestablishState` until the peer is back; forgetting a splice at restore
resets a SPLICING parked there to the pre-splice state (the operator abort
path steps around the same trap), so reestablish does not bring the channel
back as a spliceless SPLICING. The reestablish that follows answers the
peers' `next_funding_txid` with a `tx_abort` whose acknowledgement latch can
stay armed until the next reconnect; it holds back a new splice on that
channel, not payments.

Restore does not rebroadcast a released composite from the record: every
participating channel holds the fully signed transaction in its own
in-flight record, and the node's splice rebroadcast path resumes it through
the durability barrier (`reauthorizeSpliceBroadcast`), as for a single
splice. Terminal records (LOCKED, ABORTED, CONFLICTED) are kept for seven
days (`COMPOSITE_SPLICE_RETENTION_MS`) and pruned at boot and when a later
record ends.

Requirements:

- The composite record MUST be persisted before the first `splice_init` and
  before the first `tx_signatures`.
- Restore MUST never rebuild a channel as if the other participating funding
  inputs were unchanged: the per-channel records carry the new funding, and
  the static channel backup is refreshed on `splice:complete` as today.

## 6. Locking and reservations

Today every guard is per channel: `_spliceInSelections`, `spliceBusyReason`,
one `_pendingSplice`, the per-channel quiescence watchdog. A composite holds
a reservation over its channel set from PLANNED to a terminal stage:

- a reserved channel refuses a second splice, a cooperative close, an
  automatic channelization splice (#688), an offline-receive reservation and
  a direct-funding request that would use it (the direct-funding receiver
  already declines while a splice with the liquidity peer is pending,
  `docs/SPLICE-LOCK-DEPTH.md`);
- a channel already reserved by any of those is not selected at planning;
- quiescence is requested on every channel of the set through each
  session's own splice start (`initiateSplice` sends `stfu` and parks the
  `splice_init` until the channel is quiescent with us as initiator), in
  input order. Step 5c does not quiesce every channel before the first
  `splice_init`: quiescence has no end message of its own, so a set
  quiesced ahead of time could not be released cleanly if a later channel
  failed to quiesce, whereas a session that has started can be ended with
  `tx_abort`, which releases quiescence on both sides. A channel whose peer
  wins the quiescence tie (`handleStfuMessage`) drops its parked splice
  with an error, which aborts the composite before any `commitment_signed`;
- one composite at a time per node. A second request while one is live is
  refused with a typed busy result, not queued.

The whole operation has one time budget (default 60 s, from the first `stfu`
to every peer's `tx_signatures`); when it lapses before R the composite
aborts. After R there is no budget: the transaction is on its way.

## 7. Routing an on-chain payment

### Funding sources

`sendOnchain` keeps spending the on-chain wallet only; nothing about it
changes. The channel path is a separate, reviewed operation:

1. `quoteChannelSend(address, amountSats, feeratePerkw)` returns a plan:
   `single` naming one channel when the amount plus fee fits a channel's
   reserve bound, else `composite` with the channel set, each channel's debit
   and fee, the total fee, the recreated capacities and a quote id; or a
   typed refusal naming, per channel, why it cannot take part (peer without
   the capability, reserve, busy, unconfirmed funding, no funding hex) and
   the single-channel alternative that is possible, if any.
2. `executeChannelSend(quoteId)` revalidates the plan against current
   balances and reservations, charges the spend limits, and runs the
   single-channel splice-out or the composite. A stale quote is refused with
   a typed result before any side effect.

An amount that fits one channel always takes the single-channel path, from
the channel with the largest spendable balance. Mixed transactions with
on-chain wallet inputs are out of scope for step 5 and a separate follow-up.
When one transaction is impossible the call refuses; it never splits the
payment into several transactions, force closes or substitutes a swap
(#1924 section 4).

### Spend limits

The amount plus the total fee counts once against the per-payment and daily
limits. Today `spliceOut` records the spend at initiation and holds it until
the UTC midnight reset even if the splice later fails. The composite does
better by using the existing reservation: `_pendingSpendSats` is reserved
when the composite starts, converted to a recorded spend at RELEASED (the
point past which the money leaves) and released at ABORTED or at a CONFLICTED
that comes before any charge (a charge already made stays, as the Lightning
claims treat an uncertain outcome as spent). Step 5d implements this in
`BeignetNode.executeChannelSend` and its `composite-splice:stage` listener;
the charge is written to the persisted daily ledger inside the RELEASED
stage event, which fires before the RELEASED record is staged, so a crash
between the two leaves the ledger charged and the record short of RELEASED,
and the restore table then aborts the record: the day's budget is consumed
by nothing, the safe direction. Nothing has to be re-added at boot:
`_pendingSpendSats` is not persisted, but the restore table (section 5)
closes every record short of RELEASED before `BeignetNode` loads its spend
state, and a record at RELEASED or later was charged before it was written.
The single-channel address splice-out keeps its current accounting in step
5, through `executeChannelSend` as well; moving it to the same reservation is
a separate change.

### API surface

Step 5d landed this surface:

- `BeignetNode.quoteChannelSend(address, amountSats, feeratePerkw)`,
  `executeChannelSend(quoteId)`, `getChannelSend(id)`, `listChannelSends()`,
  `abortChannelSend(id, reason?)`. A quote lasts two minutes
  (`CHANNEL_SEND_QUOTE_TTL_MS`); executing the same quote id again returns
  the first execution and runs nothing. The single path picks the channel
  with the largest spendable balance whose `spliceQuote` bound covers the
  amount plus fee; the composite path is the engine's plan. A composite's
  refusal keeps the engine's code (`BUSY` answers `SPLICE_BUSY`,
  `STORAGE_REQUIRED` answers `NOT_PERSISTED`, `NO_ELIGIBLE_CHANNELS` answers
  `SPLICE_REFUSED`) and carries each skipped channel's reason in its message.
- Daemon routes under `/channel-send/*` in `src/cli/routes.ts`: `quote`
  (POST), `status` and `list` (GET) at readonly scope, `execute` at admin
  scope and idempotent, `abort` at admin scope; the split
  `/channel/splice-quote` and `/channel/splice-out` use today (invoice scope
  covers receive-side routes only, `tests/cli/auth-scopes.test.ts`).
- CLI: `beignet channel send-quote|send|send-status|send-list|send-abort`.
- Event `channel-send:stage` with the quote id (or the composite id for a
  composite restored without a quote), the composite id, the stage, the
  txid from COMMITTED on and the abort reason; relayed on the SSE stream.
- OpenAPI paths and schemas (`ChannelSendQuote`, `ChannelSendStatus`), the
  CLI README tables, `npm run docs:tables` for the event.

## 8. Peer support

- Feature bits `option_quiesce` (34) and `option_splice` (62) are required of
  every peer, as for any splice.
- Composite inputs need the acceptor to admit a verifiable 2-of-2 P2WSH
  initiator input (section 3). A beignet acceptor advertises that with a new
  odd feature bit in beignet's custom range, `option_composite_splice_inputs`
  (bits 454/455, the next free pair after the ones in
  `src/lightning/features/flags.ts`), set optional. A beignet primary without
  the bit is not selected.
- CLN is the one third-party implementation that splices with beignet
  (`docker/docker-compose.yml`, `cln-splice-matrix.test.ts`). Tier C3 of
  that matrix, added in step 5b, has beignet splice in with a confirmed bare
  2-of-2 P2WSH third-party input against CLN v26.06.1: CLN admits the input
  at `tx_complete`, signs first, and adopts the spliced channel once the
  delivered 2-of-2 witness completes the transaction (regtest, 2026-11-03,
  capacity 500000 to 580000 sats). CLN does not advertise bits 454/455.
  Step 5c tells a CLN peer apart by its own `shutdown_wrong_funding` pair
  104/105 (`peerSupportsCompositeSpliceInputs`), but CLN sets that pair only
  when started with its experimental shutdown-wrong-funding flag: a default
  CLN v26.06.1 advertises the init features `800898882a8a59a1`, nothing
  above bit 63 (regtest, 2026-11-03, step 5e). Such a peer is not recognised
  and its channels are left out of a plan by name. The step 5e regtest case
  that composes across a beignet primary and CLN therefore vouches for the
  CLN peer in the test (the recognition is a method the test overrides for
  that one pubkey) and proves the protocol path: the composite completes
  and CLN runs on the new funding. Making a default CLN selectable needs an
  operator declaration per peer (for example a flag on the primaries entry);
  that is an open decision, not part of step 5. A peer that is neither a
  beignet with the bit nor a recognised CLN is not selected.
- eclair does not splice in our stack and LND does not splice at all; their
  channels are never selected and the refusal says so.

## 9. Decisions

Proposed in the sections above and confirmed on 2026-11-03 (issue #1922). The
alternatives are kept for the record.

1. Debit order: largest spendable balance first (section 1). Confirmed; rank
   order was the alternative.
2. Fee apportionment: proportional to debit, rounded up per channel
   (section 1). Confirmed; all from the largest channel was the alternative.
3. Mixed wallet-plus-channel transactions: out of scope, separate follow-up
   (section 7). Confirmed.
4. One composite at a time per node, refused not queued (section 6).
   Confirmed.
5. The composite reservation for spend limits replaces initiation-time
   recording for composites only; the single-channel splice-out keeps its
   accounting (section 7). Confirmed.
6. The capability is a feature bit rather than a custom-message probe
   (section 8). Confirmed; bits 454/455.
7. CLN peers are excluded until the matrix tier exists (section 8).
   Confirmed; the tier (C3) landed with step 5b and CLN v26.06.1 completes
   the splice, so step 5c may select CLN peers once it can tell one apart.

## 10. Implementation plan for step 5

Each lands alone, fund-relevant ones after the full matrix with interop:

- 5a. Durable `fundingTxHex` on channel state, filled at open, splice
  adoption and, for restored channels, from the chain backend.
- 5b. Acceptor admission of verifiable 2-of-2 P2WSH initiator inputs behind
  `option_composite_splice_inputs`, with the matrix tier that proves a
  beignet acceptor completes a composite and that CLN either does or does
  not.
- 5c. The composite engine in `LightningNode`
  (`src/lightning/node/composite-splice-engine.ts`): shared serial ids,
  identical contributions, the cross-session txid check with the held
  `commitment_signed` (`SPLICE_TX_NEGOTIATED`,
  `releaseCompositeSpliceCommitment`), the held `tx_signatures` through the
  #592 external slots, the abort rules, the composite record
  (`composite_splice` recovery mutation) and the restore table. Public
  surface: `planCompositeSpliceOut`, `startCompositeSpliceOut`,
  `abortCompositeSplice`, `getCompositeSplice`, `listCompositeSplices`,
  `peerSupportsCompositeSpliceInputs`, event `composite-splice:stage`.
  Tests in `tests/lightning/composite-splice.test.ts` (three in-process
  nodes with real funding transactions): the happy path, largest-first
  debits, the refusals, operator abort, a contributing peer, a peer that
  never signs, restart before and after release.
- 5d. `BeignetNode` quote and execute, spend-limit reservation, routes,
  OpenAPI, CLI, docs (section 7 above lists what landed). Tests in
  `tests/cli/channel-send.test.ts`: the single and composite quotes, every
  refusal, the single execution's accounting and idempotency, the
  composite's reservation through RELEASED, ABORTED and CONFLICTED, restored
  composites in the listing, and the daemon envelopes.
- 5e. Regtest qualification,
  `tests/lightning/interop/composite-splice-regtest.test.ts` on the docker
  stack (bitcoind, electrs, CLN v26.06.1; skipped when bitcoind is
  unreachable): a wallet daemon with channels to beignet primaries over TCP
  pays an address out of two channels in one transaction through
  `quoteChannelSend` and `executeChannelSend`; the transaction is read back
  from bitcoind (two 2-of-2 inputs with four witness items each, the
  destination and two funding outputs), both channels adopt it after
  `splice_locked`, one record and one spend charge remain. Then: an amount
  that fits one channel takes the single-channel splice-out from the fuller
  channel; a primary without `option_composite_splice_inputs` is left out
  of the plan by name; a restart between the broadcast and the locks keeps
  the record and the charge and the composite still locks; a primary that
  disconnects as the wallet's `splice_init` reaches it aborts the composite
  at once with every channel NORMAL again on both sides, no transaction
  agreed and nothing charged; and a composite across a beignet primary and
  CLN completes with CLN on the new funding (section 8 on how the CLN peer
  is recognised there). The failures a live stack cannot force (a peer that
  never signs, a contributing peer, a restart before release or at
  COMMITTED, a force close after release) stay with the in-process tests of
  step 5c.
