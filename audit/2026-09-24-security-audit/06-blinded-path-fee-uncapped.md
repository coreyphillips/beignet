# A payee-controlled blinded-path fee is paid uncapped and invisibly to maxFeeSats, maxPaymentSats and the daily spend ledger: a 1000-sat offer can drain the payer's outbound liquidity

Labels: bug

Found during a security audit of the payment paths. Reproduced with a script against `findRouteToBlindedPath` and the payer admission code (a direct alice->bob channel, a 1000-sat offer whose `invoice_blindedpay` carries `fee_base_msat = fee_proportional_millionths = 4294967295`):

```
invoice amount (msat):       1000000
HTLC sent by payer (msat):   8590934590 = 8590934 sat
route.totalAmountMsat:       8590934590
route.totalFeeMsat (capped): 0
true fee paid (msat):        8589934590
```

## What the code does

1. `findRouteToBlindedPath` (`src/lightning/gossip/pathfinding.ts:1040-1043`) computes the aggregated blinded fee from the invoice's payinfo, which the payee wrote:
   ```ts
   const blindedFeeMsat =
       BigInt(payInfo.feeBaseMsat) +
       (amountMsat * BigInt(payInfo.feeProportionalMillionths)) / 1_000_000n;
   const amountAtIntro = amountMsat + blindedFeeMsat;
   ```
   and routes `amountAtIntro` to the introduction node. In the self-introduction branch (`:1077`) the returned `totalFeeMsat` includes `blindedFeeMsat`. In the normal grafted branch (`:1112`) it returns `totalFeeMsat: routeToIntro.totalFeeMsat`, i.e. only the public-hop fees, while `totalAmountMsat` and `hops[0].amountToForwardMsat` do include the blinded fee.
2. The BOLT 11 blinded-path branch of `sendPayment` (`src/lightning/node/lightning-node.ts:15614-15616`) caps on `effectiveFeeMsat = selfIntroForCap?.wireRoute.totalFeeMsat ?? blindedRoute.totalFeeMsat`, so an explicit `maxFeeSats` never sees the blinded fee.
3. `payBolt12Invoice` (`lightning-node.ts:27059`) has no fee-cap parameter at all, `BeignetNode.payOffer` does not accept one, and `POST /offer/pay` (`src/cli/daemon.ts:2739-2746`) takes only `{ offer, amountSats, timeoutMs }`.
4. Spend admission for offers opens the daily-budget claim on `paymentSpendSats(bolt12Invoice.amount, amountSats)` (`src/cli/beignet-node.ts:11534`), and `_chargeAsyncSpendClaim` records `charged.sats` (`:9396`), never the amount the HTLC actually carries. `maxPaymentSats` is checked against the same invoice amount.

The introduction node is chosen by the payee (the offer issuer), and a payee can be its own introduction node or collude with it, so the blinded fee is money the payee decides to take from the payer.

## Failure scenario

An agent configured with `maxPaymentSats: 100_000`, `dailySpendLimitSats: 500_000`, and even `maxFeeSats: 10`, calls `POST /offer/pay` for a 1000-sat offer (or pays a beignet-format BOLT 11 invoice carrying blinded paths in tag 25) from a malicious issuer. Every check passes on the 1000-sat figure, the node sends an HTLC of about 8.59 million sats to the introduction node, which claims it, and the daily ledger records 1000 sats spent. The loss is bounded only by outbound liquidity and the first hop's `htlc_maximum_msat`.

## Suggested fix

- Return `totalFeeMsat: routeToIntro.totalFeeMsat + blindedFeeMsat` in the grafted branch so every consumer of the route sees the real fee.
- Thread a `maxFeeMsat` through `payBolt12Invoice`, `BeignetNode.payOffer` and `POST /offer/pay`, with a default cap (see the companion issue on default fee caps) rather than none.
- Admit and charge spend on `route.totalAmountMsat` (amount plus fee), or at least on amount plus the fee cap, instead of the invoice amount alone.
- Add a regression test with an adversarial `invoice_blindedpay`.
