# The BOLT 12 payer accepts an invoice for any amount, signed by any key, and already expired, when it arrives over our reply path: the issuer can charge whatever it likes

Labels: bug

Found during a security audit of the BOLT 12 offer flow. Reproduced against `OfferManager` with a 1000-sat offer:

```
1000x overcharge signed by issuer: ACCEPTED (requested=1000000 msat, invoice amount=1000000000 msat)
invoice signed by a NON-issuer key:  ACCEPTED (nodeId==issuer? false)
invoice created 10 days ago:         ACCEPTED
```

## What the code does

`handleIncomingInvoice` (`src/lightning/offer/offer-manager.ts:1209-1290`) validates an invoice that arrives over one of our blinded reply paths with `settle()`, which runs only:

- `verifyInvoiceSignature` under the invoice's own `invoice_node_id` (so any key that signs its own invoice passes),
- `invoice_paths` non-empty and one `invoice_blindedpay` per path,
- `mirrorReason`: the invreq-range fields (types 0-159) byte-match what we sent.

It never compares `invoice_amount` (type 170) with the `invreq_amount` we sent (type 82) or with `offer_amount * quantity`; never checks `invoice_node_id` against the offer's issuer id or the blinded path's terminal key (`invoiceSignerMatchesOffer` at `:1064` is only consulted on the legacy no-path_id branch at `:1315`); and never checks `invoice_created_at + invoice_relative_expiry` against the current time. `BeignetNode.payOffer` (`src/cli/beignet-node.ts:11534-11598`) then admits and pays `bolt12Invoice.amount`.

BOLT 12, reader of an invoice: "if `invreq_amount` is present: MUST reject the invoice if `invoice_amount` is not equal to `invreq_amount`"; "MUST reject the invoice if `invoice_node_id` is not equal to `offer_issuer_id`" (or the final blinded node id when the offer uses paths); "MUST reject the invoice if the current time is after `invoice_created_at` plus `invoice_relative_expiry`". `requestInvoice` (`:636-648`) always sends `invreq_amount` when the offer has an amount, so the equality rule applies to every priced offer we pay.

## Failure scenario

An agent calls `POST /offer/pay` for a 1000-sat offer. The issuer answers with an invoice for 1,000,000 sats. The only thing between the payer and the loss is `maxPaymentSats` if the operator configured one, and the companion blinded-fee issue shows that even that check can be bypassed. A third party who can inject onion messages onto our reply path (the introduction node of our reply path, for instance) can also substitute its own invoice with its own payment hash, since the signer is not bound to the offer.

## Suggested fix

In `settle()` (or in `payOffer` before dispatch): reject when `invoice.amount !== sentInvreqAmount` (falling back to `offer.amount * quantity`, and requiring an explicit caller amount for amountless offers), reject when `!invoiceSignerMatchesOffer(invoice, offer)`, and reject when `now > createdAt + relativeExpiry`. Emit `invoice:error` with the reason as the legacy branch does.
