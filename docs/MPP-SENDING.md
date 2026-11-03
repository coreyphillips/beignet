# Multi-path payments across the wallet's channels

How `LightningNode.sendPayment` splits a BOLT 11 payment over several of the wallet's channels, and what bounds the split. The rules here are what step 3 of issue #1922 pinned, so a wallet holding channels with several primaries can pay an invoice larger than any one of them.

## When a payment splits

A payment is tried as a single path first. The router treats the wallet's own channels as the only possible first hops, each bounded by its spendable outbound balance (reserve, in-flight HTLCs and the commitment fee already subtracted), and the single path is dropped when the channel it would leave over cannot carry the whole amount.

Only then does the payment split, and only when the invoice carries a payment secret and advertises `basic_mpp`. Splitting to a recipient without `basic_mpp` would lock every part until the recipient's MPP timeout, so such a payment fails with `NO_ROUTE` instead, as it did before.

The parts may leave over channels to different peers. Nothing ties them to one next hop: each part is a route of its own, found over the same graph with the capacity earlier parts already use deducted per channel, so a wallet with channels to primaries P1 and P2 that both reach the recipient pays with one part through each.

## How parts are sized

Each part first tries the whole remaining amount. When no route carries it, the amount is halved, up to eight times, until a route is found. That route is then widened to the most its channels can still carry, fees included: the destination amount grows until the amount arriving on some hop would exceed that hop's remaining capacity, and the route is searched again at that amount. A part therefore takes what its first hop has left rather than a power-of-two fraction of the remainder.

Without the widening, two first hops of 100k and 20k sat paying 115k sat spent four parts on 57.5k, 28.75k, 14.375k and 7.1875k and failed with 7.1875k undelivered. With it, the first part takes the 100k channel's balance less fees and the second takes the rest over the 20k channel.

## How many parts

The caller of `findMultiPathRoute` may pass a bound. `sendPayment` passes none, and the bound is then the larger of 4 and the number of channels the wallet can send over. A payment that needs one part per channel is never refused by the default alone, and the bound still grows only with channels the wallet actually holds, so route search and HTLC fan-out stay proportional to them. A graph-only query with no local channels keeps the bound of 4.

The bound is a ceiling on parts, not a target: a payment that fits one channel is still sent as one part.

## What this does not cover

- Pay-all is single-part and does not fall back to MPP; see [PAY-ALL.md](PAY-ALL.md).
- BOLT 12 offers, keysend and blinded-path payments take their own single-path branches and never split.
- A part that fails after dispatch is not retried or re-split; the payment fails and the recipient releases the other parts at its MPP timeout.
- The router does not know a peer's `max_htlc_value_in_flight_msat` cap, which `addHtlc` still enforces locally.
