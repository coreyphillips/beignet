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

Detection: while a depth-locked splice with external inputs is pending, the
chain watcher watches each external input's outpoint. A confirmed spend of it
by a transaction other than the splice, at `SPLICE_CONFLICT_DEPTH` (6)
confirmations, while the splice itself has no confirmed entry, is a conflict.
A mempool-only conflict is not.

Messages, on beignet's custom message type (44069):

| subtype | name                 | layout |
|---------|----------------------|--------|
| 64      | `splice_conflict`    | `[32 channel_id][32 splice_txid][32 conflict_txid][u16 input_index]` (98 bytes; txids in internal byte order) |
| 65      | `splice_conflict_ack`| `[32 channel_id][32 splice_txid][u8 agreed][u16 reason_len][reason utf8]` (`agreed` 0 or 1; reason at most 256 bytes) |

Flow:

1. A node that observes the conflict records it durably on its in-flight
   record, sends `splice_conflict` naming the splice, the conflicting
   transaction and the splice input it spends, and re-sends it on reconnect
   and on every block until the splice is reverted.
2. The receiver verifies independently: the splice must be its own pending,
   unlocked, unconfirmed one; the named input must not be the shared 2-of-2
   funding input; the conflicting transaction must spend that input and sit
   `SPLICE_CONFLICT_DEPTH` deep in the input's script history while the splice
   does not. If all of that holds it reverts and answers `agreed = 1`;
   otherwise `agreed = 0` with a reason and changes nothing.
3. A node whose request is answered `agreed = 1` reverts. `agreed = 0` keeps
   the record (the peer may be behind on the chain) and the next block
   re-asks. Both sides may detect and ask at once; each verifies, reverts and
   acks, and an ack for a splice already reverted is ignored.
4. A node that has already reverted a splice answers `agreed = 1` to a late
   request about it, from a durable list, so a restart on one side cannot
   leave the other mid-splice.

Reverting: drop the in-flight record and session, return to the pre-splice
state, drop the splice's pre-splice spend watch and rebroadcast obligation,
re-arm the funding watch on the old outpoint (a splice watch replaces it),
persist, and emit `splice:reverted`. Signature material for the abandoned
splice is retained on the channel for the residual below.

Residual: a reorg deeper than `SPLICE_CONFLICT_DEPTH` that un-mines the
double spend and lets the splice confirm after both sides reverted would put
the channel's funds in the new 2-of-2, closeable only with the retained
signatures or the peer's cooperation. The same depth class the rest of the
node treats as final.

## Interaction with the rest of the node

- Direct funding: an unpaired payer's offer is serviced as a depth-locked
  splice only when the operator allowed it (`allowUnpairedSplice`) and the
  offered coin is confirmed; while any splice with the liquidity peer is
  negotiating or waiting on depth, further offers are declined before the
  payer's witness leaves, so the payer falls back to a plain send instead of a
  second channel. A reverted splice fails the request behind it.
- Just-in-time receives: a held payment never rides a depth-locked splice; a
  hold arriving while any splice is pending fails fast with nothing fronted.
