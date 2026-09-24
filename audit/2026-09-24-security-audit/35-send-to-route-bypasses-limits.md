# sendToRoute (POST /payment/send-to-route) bypasses maxPaymentSats, dailySpendLimitSats and the daily ledger

Labels: bug

Found during a security audit of the spending rails. Same class as the closed #526 and #529; this is the remaining path. Reproduced with `BeignetNode.create` on regtest: `payInvoice` for the same amount is refused with `SPENDING_LIMIT_EXCEEDED`, `sendToRoute` passes admission and reaches the engine (`NO_CHANNEL_TO_HOP`), and `getDailySpendInfo()` reports 0 spent and 0 pending both after the call and after the engine's `payment:sent` for that hash.

## What the code does

Every other Lightning pay path (`payInvoice`, `payInvoiceSafe`, `sendPaymentAsync`, `sendKeysend`, `payOffer`, `l402Fetch` through `payInvoice`, the queue through `payInvoiceSafe`) runs `_checkMaxPayment`, `_checkSpendLimit` and opens an `AsyncSpendClaim` before dispatch. `sendToRoute` (`src/cli/beignet-node.ts:12398-12450`) runs only `this._checkDraining()` and then calls `this.node.sendPaymentToRoute({ hops }, hash, finalHop.outgoingCltvValue, secret, finalHop.amountToForwardMsat)` with the caller-supplied route; any hops and amounts are accepted by `jsonToRouteHops`, and the route need not come from `/route/query`. The engine comments that the duplicate-hash guard is "the only check on the explicit-route entry" (`src/lightning/node/lightning-node.ts:15774-15805`). On settlement the `create()` handler calls `_chargeAsyncSpendClaim(pi.paymentHash)`, which returns immediately when the hash holds no claim (`:9367-9397`), so the settled amount never reaches `_dailySpentSats` and `GET /spend-limit` under-reports.

## Failure scenario

Node configured with `maxPaymentSats: 500` and `dailySpendLimitSats: 1000`. `POST /payment/send-to-route {paymentHash, route: {hops: [..., {amountToForwardMsat: "5000000", ...}]}}` for a 5000-sat invoice is admitted, dispatched and, when it settles, leaves the ledger at 0. The same invoice through `POST /invoice/pay` is refused. An agent or operator key limited by the safety rails can drain all outbound liquidity by routing itself, any number of times per day.

## Suggested fix

In `sendToRoute`, compute the spend from the first hop's amount (which includes the fees) or at least `finalHop.amountToForwardMsat`, run `_checkMaxPayment`, `_checkSpendLimit` and `_openAsyncSpendClaim` before the engine call, close the claim when the engine throws and release it when the returned record is FAILED (mirror `sendPaymentAsync`). Document in `validatePayment` whichever paths it does not cover.
