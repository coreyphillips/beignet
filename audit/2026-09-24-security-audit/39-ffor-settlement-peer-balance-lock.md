# FFOR settlement peer: with the documented config any channel peer can lock the settlement peer's whole spendable balance in vouchers for an arbitrary number of blocks, and there is no exit from ACTIVE

Labels: bug

Found during a security audit of the FFOR protocol. The settlement role is opt-in (`fforSettle.enabled`), but the documented way to enable it (`docs/AUTOMATIC-OFFLINE-RECEIVE.md:13`, `"fforSettle": { "enabled": true }` or `BEIGNET_FFOR_SETTLE=true`) sets no bound.

## What the code does

- `handleFforInit` refuses on `maxBudgetMsat` / `maxEpochBlocks` only when the policy defines them (`src/lightning/channel/channel.ts:21755-21790`: `if (policy.maxBudgetMsat !== undefined && ...)`, `if (policy.maxEpochBlocks !== undefined && ...)`). The daemon forwards those bounds only when the operator set them (`src/cli/beignet-node.ts:2524-2538`, `src/cli/config.ts:584-597`).
- `checkVoucherBook` (`src/lightning/ffor/amounts.ts:189-273`) bounds `voucherExpiry` from below only (`voucherExpiry < settlementDeadline + 1008`) and the budget only by `sLocalBalanceMsat < sum + reserve`. A script confirmed it returns `null` (accepted) for `voucherExpiry = 0xfffffffe`.
- Once ACTIVE, `_fforAbortLocal` returns "cannot abort in state ACTIVE" (`channel.ts:22624-22637`), `_fforUpdateRefusal` refuses every add, fee update, shutdown, splice and stfu on the channel ("no ${kind} until it drains", `:21283-21286`), and only the receiver's `ff_close` or the on-chain HTLC timeout at `voucherExpiry` frees the vouchers. The vouchers are S's offered HTLCs whose preimages S generated, so R cannot claim them either. `MAX_HTLC_CLTV_EXPIRY_DELTA` (`:14605`) applies to received adds only, not to the HTLCs S offers here (`addHtlc`, `:3036`).

## Failure scenario

R, any peer with a channel in which S has balance, sends `ff_init` with `budgetMsat` = S's spendable balance, `settlementDeadline = tip + 1` and `voucherExpiry = 0xfffffffe` (about 76 years), completes the voucher round and `ff_activate` (a minute online), then disconnects. S's balance is now in K HTLCs S cannot fail; the channel carries no other traffic; a force close yields S nothing until block 2^32-2. Cost to R: zero (vouchers are S-funded and no fee is paid to reserve them). Even with a bound such as 2016 blocks the lock is a design property of the protocol, but the unbounded default turns an opt-in LSP role into an indefinite freeze by any client.

## Suggested fix

Apply defaults when the policy is enabled (`maxEpochBlocks <= MAX_HTLC_CLTV_EXPIRY_DELTA`, a `maxBudgetMsat` default such as a fraction of local balance); in `checkVoucherBook` / `handleFforInit` refuse `voucherExpiry - tip > MAX_HTLC_CLTV_EXPIRY_DELTA` unconditionally; consider letting S drain vouchers itself once `settlementDeadline` has passed.
