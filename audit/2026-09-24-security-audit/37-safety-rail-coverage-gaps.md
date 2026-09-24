# Safety-rail coverage gaps: rebalances spend fees outside the daily budget and ignore drain mode, and maxPaymentSats is enforced on Lightning payments only

Labels: bug

Found during a security audit of the spending rails. Two low-severity gaps between what the docs promise and what the rails cover.

## 1. Circular rebalances

`rebalanceChannel` (`src/cli/beignet-node.ts:12085-12135`) and `executeRebalances` (`:12136-12168`) go straight to the engine with no `_checkDraining`, `_checkSpendLimit` or `_recordSpend`. The principal returns, but the fee (bounded only by the caller's `maxFeeSats` or the advisor budget) is a real spend that never reaches `_dailySpentSats`, and a rebalance is a real outgoing payment a draining node still dispatches. With `dailySpendLimitSats` exhausted, `POST /rebalance {amountSats: 1000000, maxFeeSats: 50000}` still spends up to 50,000 sats of fees per call; `GET /spend-limit` shows nothing; during `/stop` drain a rebalance creates a PENDING payment the drain then waits on. The README's exclusion list (`src/cli/README.md:677-695`) does not mention rebalances.

Fix: `_checkDraining()` in both; charge the settled fee via `_recordSpend` (or reserve `maxFeeSats` and record the actual fee); document it either way.

## 2. `maxPaymentSats` is Lightning-only

`_checkMaxPayment` (`:9186-9194`) is called only from the Lightning pay paths (`:10152`, `:10466`, `:10527`, `:11543`). `sendOnchain` (`:6090-6134`), `sendMaxOnchain` (`:6478`), `spliceOut` (`:11339-11417`) and `sendDirectFunding` (`:8805-8910`) pass it for any amount. `docs/AI_AGENT_GUIDE.md:230` says "Reject any single payment over 100k sats"; `src/cli/README.md` does not document `maxPaymentSats` at all and the daemon has no flag for it (`config.ts` / `cli.ts` plumb only `dailySpendLimitSats`). An SDK user with `maxPaymentSats: 100_000` and no daily limit (the guide's first example) can `sendOnchain(addr, 5_000_000)` or `spliceOut(ch, 5_000_000, rate, addr)`.

Fix: call `_checkMaxPayment` on the external on-chain paths too, or state in both READMEs that the per-payment cap is Lightning-only and plumb it through the daemon config.
