# Experimental reserved retirement

Concurrent version 2 preserves unresolved voucher claims when a receiver closes
an offline receive book early. Ordinary online payments can continue using the
channel's remaining capacity. This extension is experimental. Feature bits
562/563 remain disabled by default pending full protocol and regtest qualification.

## Negotiation and retirement

The receiver requests `concurrent: true, concurrentVersion: 2`. Both peers must
negotiate the concurrent feature pair and the settlement peer must allow
concurrent books. Signed TLV 17 carries version 2 in `ff_init` and must be echoed
exactly in `ff_accept`. A missing or different echo aborts setup. Existing callers
that request concurrency without specifying a version still select version 1.

Version 2 changes retirement semantics:

- Sending a close request stops new invoice exposure immediately. Processing it
  stops new delegated payment admission at the settlement peer.
- A verified preimage permits fulfillment through the existing commitment flow.
  Invoice credit requires durable evidence that both commitment views removed
  the voucher as fulfilled.
- Every unknown voucher remains reserved, including slots for which no invoice
  exposure was recorded. An empty receipt report, negative close bitmap, elapsed
  invoice lifetime, settlement deadline or voucher expiry does not authorize an
  off-chain cancellation.
- A book can remain DRAINING while ordinary payments continue. It becomes CLOSED
  off chain only after every voucher has a committed fulfilled outcome.
- Chain resolution follows the existing channel enforcement paths. A final spend
  is retained in the archive separately from off-chain retirement.

Version 1 retains its existing negative-bitmap retirement contract. The extension
does not change signed commitments, retransmission bytes or completed historical
cancellations. A late proof of a cancelled voucher remains evidence without
creating payment credit. Issuer provisioning is refused for version 2 until an
independent issuer admission-stop contract is implemented.

## Custody and received value

Concurrent versions 1 and 2 support `LightningNode.fforSync(channelIdHex)`.
It sends a signed receipt request while the book remains ACTIVE. The receiver
persists one outstanding nonce and replays the same request after reconnect.
The sender persists each cumulative snapshot before publishing it. Quorum-mode
nodes also wait for the snapshot's recovery frame to reach the durability barrier.

The sender reports a slot after it has durably queued the delegated payer's
fulfillment, or after the voucher itself has a fulfilled outcome in both
commitment views. A SETTLING intent alone is not a receipt. The upstream fulfillment,
its proof and the book's SETTLED state commit in one recovery transaction.

Verified proof from sync, a payer or a witness starts live redemption through the
normal commitment flow. Receipt progress and proof custody are separate: an older
reply can supply proof without replacing the newest accepted snapshot. A signed
conflict is retained and holds further admission. Sync never cancels a voucher.

`rescueFforEpoch()` requests sync for a connected concurrent book and returns
`action: 'synced'`. The request may still be outstanding when it returns. Witness
mailboxes and version 1 issuers remain available for other slots after sync or
partial redemption. Version 2 issuer provisioning remains refused.

The voucher archive binds each slot to its channel, epoch, role, payment hash,
amount, HTLC id and expiry. Identity is immutable. Proof, off-chain terminal
outcome, chain observations, final chain resolutions and invoice-credit source
survive epoch replacement and channel deletion.

An index rebuilt from the archive reserves every adopted payment hash and
directional HTLC id for its original book. Retained channel books are backfilled
before startup exposes channels. An archived hash cannot become an ordinary
incoming payment or a slot in another book. The archive has no automatic pruning
policy; its size grows with adopted books.

Observed chain evidence binds the original outpoint to the exact spending
transaction and its success preimage when present. Observations survive a reorg
as evidence history. They do not authorize credit. Current, nonrevoked commitment
classification and the exact archived HTLC identity are required for receipt
attribution.

A final chain receipt uses the monitor's `IRREVOCABLE_DEPTH` threshold, currently
100 blocks after the recorded confirmation height. Restored nonfinal spends must
be reverified. A spend reorg or changed spender cannot inherit an earlier success
observation. For our own commitment, the HTLC-success transaction's delayed output
must also have a final sweep before the invoice is completed. This is the engine's
existing finality assumption, not a guarantee against deeper chain reorganizations.
The archived output amount is the gross claim value before transaction fees.

Archive changes commit atomically with their channel or monitor transition.
Invoice credit and its source attribution commit atomically before completion
events. Failed writes retry on later blocks, including after a monitor has stopped
receiving ordinary callbacks. Final custody can reconcile an unpaid invoice after
the original channel and monitor have been pruned.

Each receipt has a stable source identity. `getFforVoucherReceipts()` exposes those
identities, the credited source and uncredited sources requiring reconciliation.
A delayed output sweep continues its parent claim and is not a second receipt.
Additional verified sources do not emit another invoice completion. Competing
spends of the same outpoint require reconciliation and must not be summed as
independent value. Event consumers should still deduplicate by payment hash because
a crash can occur between a durable payment write and event delivery.

## Storage compatibility and qualification

Both concurrent versions require the complete voucher archive interface on configured storage:
`saveFforVoucher`, `loadFforVoucher` and `loadAllFforVouchers`. Adapters with none of
these methods retain baseline support but cannot persist concurrent books.
An incomplete interface is rejected. Nodes explicitly configured without storage
keep the same accounting rules in memory, with no restart durability.

Typed recovery mutations and both whole and paged snapshots include the archive.
Archive-bearing snapshots have an explicit schema marker so older recovery
readers reject them instead of silently omitting custody. Invalid archive rows or
identity changes fail explicitly. Contradictory or unsupported version metadata
preserves the strict reservation profile and quarantines new commitment updates.

Downgrading a live concurrent database to an older binary is unsupported. Older
direct database readers cannot be made safe by checks in the new binary.

Once a concurrent book is adopted, the channel persists revoked HTLC history as
a dictionary of complete `(paymentHash, amountMsat, cltvExpiry, direction)` tuples
and ordered changes between commitment snapshots. This encoding retains every
snapshot, including empty snapshots and repeated entries. It remains selected
after retirement and later baseline books. The in-memory snapshots and the chain
resolver continue to use independent HTLC entries with the original identities.
Channels that have never adopted concurrent receive retain their existing format.

Compact history uses recovery frame version 2 and snapshot schema
`2+ffor-vouchers+htlc-history`, with `+pages` when payment rows are paged. Earlier
recovery readers reject these formats. Version 1 frames still decode and re-encode
byte for byte, and their next channel write upgrades the history without removing
evidence. The frame key derivation and encrypted transport envelope do not change.

The positive growth check measures ten ordinary payments with 2, 16 and 128 live
vouchers. History growth falls from 9,641 / 51,361 / 385,121 bytes to
2,628 / 2,656 / 2,686 bytes respectively. This removes repeated voucher tuples
from each stored commitment. History still grows with channel activity, and its
expanded in-memory representation is unchanged. This is lossless compression,
not a pruning policy or a bound on a channel's lifetime storage.

Before enabling this profile by default, the remaining qualification includes the
full commitment and chain crash matrix on regtest, and daemon/coordinator integration.
The focused in-process checks do not substitute for those release gates.
