# Single-part Lightning pay-all

Pay-all pays an amountless BOLT 11 invoice using an approved debit and routing
fee cap, both in millisatoshis. It does not close the channel or remove its
reserve and commitment-cost requirements. Zero-reserve negotiation is separate.

`POST /invoice/pay-all/quote` accepts `bolt11` and `maxFeeMsat`. Amounts in the
HTTP API are decimal strings. The response contains:

- `debitMsat`: the usable local balance ceilings summed in msat.
- `minRecipientMsat`: the debit minus the approved fee cap.
- `maxFeeMsat`: the requested cap.
- `routeFound`: whether an admissible exact single-part route was found.
- `remainderMsat`: an unplaceable remainder when an exact debit was refused.
- `searchExhausted`: whether the bounded search could not prove a maximum.

Quoting changes no payment record and reserves no funds. Review the recipient
minimum, fee maximum and total debit as separate facts. Send the same debit and
cap to `POST /invoice/pay-all`, together with `bolt11` and optional `timeoutMs`.
The debit must be positive and the cap must be nonnegative and smaller than it.
The node reserves that debit exactly once against its spending limits.

The router maximizes the recipient amount over feasible simple paths. Each path
keeps an exact recipient interval so a high HTLC minimum cannot hide a feasible
route. It checks routing policies, CLTV bounds and the actual channel admission
rules. It uses private invoice hints and authoritative local channel balances.
Payment-scoped policy corrections apply to retries without changing gossip.

An unavoidable fee-rounding gap may be paid as extra fee to the first hop, within
the cap. A remainder caused by a downstream capacity limit cannot become an
extra fee. A direct payment has no forwarding hop on which to place a gap.
The engine refuses when it cannot spend the approved debit under these rules.
It never silently sends less. A search limit refusal also sends nothing.

This version supports a single part and unblinded BOLT 11 invoices only. It
does not fall back to MPP, keysend, offers or blinded routes. Multiple local
channels can make a quoted aggregate impossible to carry in one part, in which
case `routeFound` is false. A quote is advisory: remote liquidity can change.

If the reviewed debit is no longer spendable, the send returns
`PAY_ALL_REVIEW_EXPIRED`. `PAY_ALL_REMAINDER` names the unplaceable amount as
`remainderMsat` in its message. Ordinary no-route cases return `NO_ROUTE`.
Funds received after review are outside the approved debit and remain untouched.

The payment record and its HTLC mapping are persisted before dispatch. Temporary
failures can retry only after the previous HTLC has been irrevocably removed.
Every retry keeps the original debit and cap, although its recipient amount and
route can change. A local timeout leaves an unresolved attempt pending and
freezes automatic retries. After restart, the node reconciles the existing
attempt without reconstructing automatic retries. A late fulfillment can still
complete it. An explicit retry is permitted only after a definitive failure,
using the same invoice and its persisted budget. Changing that contract returns
`PAY_ALL_BUDGET_MISMATCH`, including after payment-cache pruning.

Payment history and proof expose a `payAll` object containing decimal strings
for `deliveredMsat`, `feeMsat`, `debitMsat`, `remainderMsat` and `maxFeeMsat`.
These describe the planned attempt while pending and the exact payment when
completed. A failed record describes its failed attempt, not a completed debit.
The remainder is the unspent part of the approved debit, normally zero; it does
not include reserves, commitment costs or later receipts. Existing `amountSats`
history keeps its total-debit meaning and rounding behavior.
