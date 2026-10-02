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

The voucher archive binds each slot to its channel, epoch, role, payment hash,
amount, HTLC id and expiry. Identity is immutable. Proof, off-chain terminal
outcome, chain observations, final chain resolutions and invoice-credit source
survive epoch replacement and channel deletion.

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

Version 2 requires the complete voucher archive interface on configured storage:
`saveFforVoucher`, `loadFforVoucher` and `loadAllFforVouchers`. Adapters with none of
these methods retain ordinary recovery support but cannot persist version 2.
An incomplete interface is rejected. Nodes explicitly configured without storage
keep the same accounting rules in memory, with no restart durability.

Typed recovery mutations and both whole and paged snapshots include the archive.
Archive-bearing snapshots have an explicit schema marker so older recovery
readers reject them instead of silently omitting custody. Invalid archive rows or
identity changes fail explicitly. Contradictory or unsupported version metadata
preserves the strict reservation profile and quarantines new commitment updates.

Downgrading a live version 2 database to an older binary is unsupported. Older
direct database readers cannot be made safe by checks in the new binary.

Before enabling this profile by default, the remaining qualification includes live
receipt synchronization and redemption, consumed-slot protection, the full
commitment and chain crash matrix on regtest, and daemon/coordinator integration.
The focused in-process checks do not substitute for those release gates.
