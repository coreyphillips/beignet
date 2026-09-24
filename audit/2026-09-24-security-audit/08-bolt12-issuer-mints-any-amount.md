# The BOLT 12 issuer mints an invoice for whatever invreq_amount the payer sends (1 msat on a 100k-sat offer) and ignores quantity and offer_quantity_max

Labels: bug

Found during a security audit of the BOLT 12 offer flow. Reproduced against `OfferManager.handleInvoiceRequest` with a 100k-sat offer, `quantity_max = 10`:

```
invreq_amount = 1 msat:                         ISSUED invoice amount=1 msat
no invreq_amount, quantity 5 (expect 500k sat): ISSUED invoice amount=100000000 msat (unit price)
invreq_amount 1 msat, quantity 1000 (> max 10): ISSUED invoice amount=1 msat
```

## What the code does

After the signature, offer_id, path_id and expiry checks, `handleInvoiceRequest` picks the amount with (`src/lightning/offer/offer-manager.ts:860`):

```ts
const amount = request.amount ?? matchedOffer.amount;
```

There is no lower bound against `offer_amount`, no multiplication by `invreq_quantity`, and no `offer_quantity_max` or `invreq_chain` checks (`quantity` appears in the file only on the payer side, `:636-648`). The issued invoice is registered through `invoice:issued` (`src/lightning/node/lightning-node.ts:27253-27300`) with `amountMsat: invoice.amount`, so the receive path later settles a 1-msat HTLC as full payment of the offer and emits the normal `payment:received`.

BOLT 12, writer of an invoice (the issuer): "MUST fail the request if `invreq_amount` is present and less than `offer_amount` times `invreq_quantity` (or 1)"; "if `offer_quantity_max` is present: MUST fail the request if there is no `invreq_quantity` field, or if `invreq_quantity` is greater than `offer_quantity_max`; otherwise MUST fail the request if there is an `invreq_quantity` field".

## Failure scenario

A merchant publishes a fixed-price offer for 100k sats. A payer sends an `invoice_request` with `invreq_amount = 1` msat. The merchant's node issues an invoice for 1 msat, receives 1 msat, and emits `payment:received` for that offer; any automation keyed on the offer id ships the goods. Quantity-priced offers likewise get paid the unit price for any quantity.

## Suggested fix

Refuse `request.amount < offer.amount * (request.quantity ?? 1n)`; when the request omits an amount, use `offer.amount * quantity`; enforce the `offer_quantity_max` rules and the chain rule; answer with an `invoice_error` on refusal, as the "Amount required" branch already does.
