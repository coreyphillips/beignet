# Routing fees are outside maxPaymentSats and the daily spend ledger, and the pay routes apply no fee cap by default, so a route hint can spend millions of sats past the configured limits

Labels: bug

Found during a security audit of the spending-limit enforcement. This is a distinct root cause from the blinded-path issue (there the route's reported fee is wrong; here the fee is reported correctly but nothing bounds it by default and nothing charges it).

## What the code does

- `payInvoice` opens the daily-budget claim and checks `maxPaymentSats` on `paymentSpendSats(decoded.amountMsat, amountSats)` (`src/cli/beignet-node.ts:10117`), the invoice amount. The same holds for `sendPaymentAsync` (`:10436`, `:10463`) and `payOffer` (`:11534`). `_chargeAsyncSpendClaim` records `charged.sats` (`:9396`), never the settled `feeMsat`.
- `resolveMaxFeeMsat` (`:1255-1275`) returns `undefined` when the caller sends neither `maxFeeSats` nor `maxFeeMsat`, and every fee check in `LightningNode.sendPayment` is of the form `if (maxFeeMsat !== undefined && fee > maxFeeMsat)`. `POST /invoice/pay`, `/invoice/pay-safe` and `/invoice/pay-async` (`src/cli/daemon.ts:1992-2046`) make `maxFeeSats` optional. There is no default fee cap constant anywhere (`grep -rn "DEFAULT_MAX_FEE\|maxFeePercent" src` is empty). `POST /channel/rebalance` (`:1254`) deliberately requires a cap ("fee-spending endpoints never guess a cap"); the pay routes do not follow that rule.
- A BOLT 11 `r` route hint's `fee_base_msat` and `fee_proportional_millionths` are u32 fields decoded straight off the invoice (`src/lightning/invoice/decode.ts:275-276`) and become a synthetic edge the router must use to reach a hint-only destination; `findRoute` correctly includes that fee in `totalFeeMsat` (`pathfinding.ts:666`), so an explicit cap works, but nothing applies one by default.

`docs/AI_AGENT_GUIDE.md:230` promises `maxPaymentSats: 100_000, // Reject any single payment over 100k sats`, and the README lists the two limits as the recommended production safeguards. Fees are not covered by either.

## Failure scenario

Node configured with `maxPaymentSats: 10_000` and `dailySpendLimitSats: 50_000`. An agent pays a 1000-sat invoice (no `maxFeeSats`, as in every README example) whose route hint names the attacker's private channel with `fee_base_msat = 4294967295`. The hint is the only path to the destination, so the router builds a route with a 4,294,967-sat fee, the HTLC leaves, the attacker's hop keeps the fee, and both limits saw 1000 sats. Repeatable until liquidity runs out; the ledger never learns.

## Suggested fix

- Apply a default fee cap on every pay path when the caller does not supply one (other implementations default to a percentage of the amount with a small absolute floor, for example 1% with a 50-sat floor, or refuse fees above 5%), and document it.
- Include the fee in spend admission and in the ledger: open the claim on amount plus the fee cap, and charge the settled amount plus `feeMsat`, so `maxPaymentSats` and `dailySpendLimitSats` mean what the docs say.
- Consider bounding route-hint fees independently (for example refuse a hint whose fee exceeds the cap before routing), so a hostile invoice fails fast with a clear error.
