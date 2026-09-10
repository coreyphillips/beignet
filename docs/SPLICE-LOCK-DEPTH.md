# Depth-locked splices and conflicted-splice revert (beignet extensions)

Two beignet extensions to BOLT 2 splicing, introduced for issue #760 so a
lightning-first wallet can take an on-chain payment from a payer it has not
paired with as a splice of its existing channel, instead of a second channel.
Both are wire-compatible with peers that do not implement them: the first is
an odd TLV a peer may ignore (with the consequence described), the second
rides beignet's custom message type and is never sent to a peer that has not
spliced with a lock depth.

## 1. Per-splice lock depth

### Problem

On an `option_zeroconf` channel, `splice_locked` is sent the moment
`tx_signatures` completes, so a splice funded by a third party's coin becomes
the live funding at zero confirmations. If that third party double spends its
input, both sides sit on a funding output that will never exist. That is why
the direct-funding receiver used to keep every unpaired payer on the
new-channel path.

### Extension

`splice_init` carries an optional TLV:

| type  | name         | value | meaning |
|-------|--------------|-------|---------|
| 65537 | `lock_depth` | `u16` | the confirmations this splice must reach before either side sends `splice_locked`, whatever the channel type; 1 to 2016 |

The type is odd (a peer that does not know it ignores it) and in the
experimental range, so it cannot collide with a type the splicing spec assigns
later. The acceptor echoes the same TLV in `splice_ack` when it will honour
it. An initiator that asked and got no echo sends `tx_abort` before any
`tx_add_input` leaves: a peer that would lock at broadcast is exactly the peer
the depth exists to protect against.

Requirements:

- An acceptor MUST NOT honour a `lock_depth` larger than it is prepared to
  wait: until the lock the channel cannot cooperatively close, so the depth is
  how long it has only a unilateral exit. Beignet honours at most 6
  (`SPLICE_LOCK_DEPTH_ACCEPT_MAX`), asks for at most 6, and answers a larger
  request with `tx_abort` before any input is added.
- A node that sent or echoed `lock_depth` MUST NOT send `splice_locked` for
  that splice before the splice transaction has `lock_depth` confirmations,
  even if `option_zeroconf` was negotiated. (The splicing draft already says a
  zero-conf node MAY send `splice_locked` immediately; this makes the wait a
  MUST for that one splice.)
- The funding watch for the splice output MUST use at least `lock_depth` as
  its depth.
- Nothing changes for the pending-lock window itself: both commitments are
  kept in lockstep, HTLCs may flow, and the balance the splice adds is not
  usable until both sides have locked.

Beignet: `ISpliceInFlight.lockAtDepth`, set through
`LightningNode.spliceInWithInputs(..., { lockAtDepth })`; the direct-funding
receiver sets it for an unpaired payer (`unpairedSpliceDepth`, default 3).

### Closing inside the window (issue #764)

Being on chain and being locked are two facts, and the close paths need the
first one on its own. The moment the splice is mined the pre-splice funding
output is spent, so every commitment built against it is unconfirmable, while
`splice_locked` still owes the chain another `lock_depth - 1` blocks. An
ordinary splice has the same window, between its first confirmation and
`minimum_depth`.

- The funding watch reports both: `funding:seen` (in a block, at any depth,
  stamped on the record as `confirmedHeight`) and `funding:confirmed`
  (`max(minimum_depth, lock_depth)` reached, which is what sends the lock).
- A force close planned in the window is built against the SPLICE: the peer's
  signature over the post-splice commitment is on the in-flight record, so the
  commitment exists whether or not the lock was ever sent.
- It is a broadcast decision, not an adoption. The channel stays on the
  pre-splice funding, because a splice at one confirmation can still be reorged
  out, and only an unmoved channel can still build the pre-splice commitment.
  `closeSpendsSpliceTxid` records which of the two fundings the transaction on
  the network spends; `funding:unseen` retracts the sighting and re-drives the
  close on the old funding. The adoption proper still happens at the lock
  depth, and re-drives the same close onto identical bytes.
- Cooperative close still waits for the lock: `shutdown` is refused for the
  whole SPLICING window rather than negotiating against a funding that can
  change under the negotiation.

## 2. Conflicted-splice revert

### Problem

Past `tx_signatures` BOLT 2 offers no abort, only RBF, and beignet has no
splice RBF. If a depth-locked splice's third-party input is spent elsewhere
and that spend confirms, the splice can never confirm and the channel would
stay mid-splice: HTLCs still flow, but no further splice (channelize,
just-in-time splices, splice-out sends) can start.

### Extension

Both peers still hold valid commitments on the pre-splice funding (the live
state never left it: adoption happens at `splice_locked`, which never came).
So the recovery is to drop the splice candidate on both sides and continue on
the old funding, once BOTH have verified the conflict on their own chain view.
Neither side ever reverts on the other's word.

Detection: while a depth-locked splice is pending, BOTH sides watch every
splice input that is neither the shared 2-of-2 funding input nor one of their
own wallet inputs (the acceptor therefore watches the initiator's inputs too,
so a wallet that double spends and goes silent cannot pin the LSP). A
confirmed spend of such an outpoint by a transaction other than the splice,
at `SPLICE_CONFLICT_DEPTH` (6) confirmations, while the splice itself has no
confirmed entry, is a conflict. A mempool-only conflict is not.

Messages, on beignet's custom message type (44069):

| subtype | name                 | layout |
|---------|----------------------|--------|
| 64      | `splice_conflict`    | `[32 channel_id][32 splice_txid][32 conflict_txid][u16 input_index]` (98 bytes; txids in internal byte order) |
| 65      | `splice_conflict_ack`| `[32 channel_id][32 splice_txid][u8 agreed][u16 reason_len][reason utf8]` (`agreed` 0 or 1; reason at most 256 bytes) |

Flow. The exchange runs under quiescence, as every fundamental channel
change does: between one side's revert and the other's, no update may be in
flight, or a commitment round crossing that window would be signed against
one funding on one side and two on the other.

1. A node that observes the conflict records it durably on its in-flight
   record and opens a quiescence handshake (`stfu`, initiator) on the
   channel. Only once the channel is QUIESCENT with it as initiator does it
   send `splice_conflict`, naming the splice, the conflicting transaction and
   the splice input it spends. A handshake the peer owns is not contested:
   the peer is asking the same thing, and the node answers instead. The
   request is re-made on reconnect and on every block until the splice is
   reverted, with a backoff after a request that timed out.
2. The receiver requires the channel to be quiescent with the peer as
   initiator (else `agreed = 0`, "not quiescent", nothing changes), then
   verifies independently: the splice must be its own pending, unlocked,
   unconfirmed one; the named input must not be the shared 2-of-2 funding
   input; the conflicting transaction must spend that input and sit
   `SPLICE_CONFLICT_DEPTH` deep in the input's script history while the splice
   does not. If all of that holds it reverts, commits the revert to disk, and
   answers `agreed = 1`; a revert whose commit failed answers `agreed = 0` so
   the peer re-asks. Otherwise `agreed = 0` with a reason and nothing changes.
   One verification runs per channel at a time and a refuted claim is not
   re-fetched until the next block.
3. `splice_conflict_ack` ends the quiescence session on both sides, whatever
   it says: the receiver leaves it as it acks (the revert itself exits
   quiescence), the requester as it acts on the ack. A node whose request is
   answered `agreed = 1` reverts. `agreed = 0` keeps the record (the peer may
   be behind on the chain), leaves quiescence, and the next block re-asks.
   Ordered delivery makes the remaining window safe: the receiver's updates
   after its ack arrive after the ack, by which time the requester has
   reverted, and neither side sends an update before its own revert because
   both are quiescent. Both sides may detect and ask at once; the funder
   tie-break decides whose session it is, the other side answers, and an ack
   for a splice already reverted is ignored.
4. A requester that hears nothing within 60 seconds (a peer that does not
   speak the extension, or one whose handshake never completed) abandons the
   request and disconnects the peer: quiescence has no un-stfu, and a
   disconnect is the one reset the spec gives it. The reconnect re-asks
   after a backoff.
5. A node that has already reverted a splice answers `agreed = 1` to a late
   request about it, from a durable list, so a restart on one side cannot
   leave the other mid-splice.

Reverting: drop the in-flight record and session, return to the pre-splice
state, drop the splice's pre-splice spend watch and rebroadcast obligation,
re-arm the funding watch on the old outpoint (a splice watch replaces it),
persist, and emit `splice:reverted`. Signature material for the abandoned
splice is retained on the channel for the residual below.

Residuals. A depth-locked splice that never confirms and never sees a
confirmed conflict either (the payer's parent transaction reorged out and
replaced, an input the network will not relay, a mempool-only double spend
kept alive) leaves the channel SPLICING: HTLCs still flow and a force close on
the old funding still works, but no further splice can start until the
transaction confirms or a conflict does. The per-block rebroadcast covers
eviction only. A reorg deeper than `SPLICE_CONFLICT_DEPTH` that un-mines the
double spend and lets the splice confirm after both sides reverted would put
the channel's funds in the new 2-of-2. That funding is closeable
cooperatively, or with the retained signatures only if no update followed the
revert: the retained signature covers our spliced commitment at the
`commitmentNumber` recorded with it, and the channel keeps advancing (and
revoking) on the old funding with the shared commitment number, so after the
first post-revert update the retained commitment is a revoked state on the
new funding and broadcasting it would hand the peer a penalty. Beignet builds
no recovery path for this; it records the material and states the residual.
The same depth class the rest of the node treats as final.

## Interaction with the rest of the node

- Direct funding: an unpaired payer's offer is serviced as a depth-locked
  splice only when the operator allowed it (`allowUnpairedSplice`) and the
  offered coin is confirmed; while any splice with the liquidity peer is
  negotiating or waiting on depth, further offers are declined before the
  payer's witness leaves, so the payer falls back to a plain send instead of a
  second channel. A reverted splice fails the request behind it.
- Just-in-time receives: a held payment never rides a depth-locked splice; a
  hold arriving while any splice is pending fails fast with nothing fronted.
- HTLC deadlines: the per-block backstops that force close to claim an inbound
  HTLC whose preimage we hold, to time out an offered HTLC the peer sits on
  past its expiry, or to move an unresolved forward on chain all run on a
  SPLICING channel exactly as on NORMAL, in every phase of the splice (issue
  #774). The close is planned against whichever funding the chain has. The
  off-chain fail those scans prefer needs update traffic, which only the
  pending-lock window of an ECDSA splice carries; before that the scans wait
  for it rather than close, and the on-chain backstops stand behind them.
