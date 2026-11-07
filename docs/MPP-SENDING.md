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

## When a part fails

A part that fails back with a temporary failure is replaced inside the same payment (issue #1942); the invoice is never sent again while sibling parts are held. Only the failed part's delivered amount is planned again, over the channels that remain, with the same payment hash, payment secret and `total_msat`, so the recipient never holds parts summing past the invoice. The failed part is irrevocably gone from the wallet's channel before the replacement is planned, so a channel's spendable balance counts the replacement and never the failed part as well.

The replacement is planned with the culpable channel excluded, and when the failure came from the wallet's own peer, that first hop excluded too, provided another channel of the wallet remains. A failure that re-prices a hop (`fee_insufficient` with a signed `channel_update`, say) excludes nothing: the replacement takes the hop at its real price. It is split the same way a payment is, so a replacement that fits no single route leaves as several parts. The fee cap applies to the live parts plus the replacement, judged once.

Replacements are bounded by the payment's retry count (`maxPaymentRetries`, default 3, counted per replaced part) and by a window of 45 seconds after the first part left, inside the 60 seconds BOLT 4 has the recipient hold a partial set, so a replacement does not reach the recipient after it has failed the siblings back. When the bound is hit, no route carries the amount, or the cap would be exceeded, the payment fails as a failed part failed it before: one `payment:failed`, the reason on the record, and the recipient releases the other parts at its MPP timeout. A permanent failure, `mpp_timeout` among them, is never replaced.

A part that fails back before the parts being sent, planned or a replacement's, have all left waits until they have: a replacement planned mid-dispatch would draw on balances the undispatched parts have not taken yet. The revised `sentMsat` is persisted before a replacement leaves, so a restart after its HTLC is durable keeps the debit the channels show; a record that cannot be written holds the replacement back, and the payment ends as one with no route does. The record's `retryCount` is the number of replacements sent, and each replacement is logged as `mpp_part_replaced` with the failed part's channel and HTLC id.

A restart during a payment keeps today's rule: retry contexts are not persisted, so nothing is replaced after a restart; the parts still out resolve through their persisted HTLC mappings and end the record, and no part whose outcome is unknown is ever sent again.

## What this does not cover

- Pay-all is single-part and does not fall back to MPP; see [PAY-ALL.md](PAY-ALL.md).
- BOLT 12 offers, keysend and blinded-path payments take their own single-path branches and never split, so their failures are retried whole, as before.
- The router does not know a peer's `max_htlc_value_in_flight_msat` cap, which `addHtlc` still enforces locally.
