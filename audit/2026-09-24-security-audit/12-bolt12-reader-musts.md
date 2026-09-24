# BOLT 12 invoice_request and invoice decoders skip the reader MUSTs the offer decoder already applies: no known-type set, no range check, unknown required features accepted, invoice_node_id not validated as a point

Labels: bug

Found during a security audit of the BOLT 12 codec. Spec conformance, no direct fund loss on its own; it is the same class of gap as the companion BOLT 1 TLV issue.

## What the code does

`decodeOfferTlv` passes `OFFER_KNOWN_TYPES` to `decodeTlvStream` and checks the offer type ranges. `decodeInvoiceRequestTlv` (`src/lightning/offer/tlv.ts:390-440`) and `decodeInvoiceTlv` (`:540-610`) call `decodeTlvStream(data)` with no known-type set, so an unknown even (required) type is accepted; neither checks that types fall in the invoice_request range (0-159 plus the experimental range) or the invoice range (0-239 plus experimental); neither rejects unknown even bits in `invreq_features` / `invoice_features`; and `invoice_node_id` is not checked to be a valid point before signature verification (a bad length throws inside `toXOnlyPubkey`, which `handleMessage`'s try/catch contains, so it is not a crash, only an unclear refusal).

BOLT 12 readers: "MUST fail the request/invoice if any non-signature TLV field is outside the allowed ranges", "MUST fail if any unknown even TLV field is present", "MUST fail if `invreq_features`/`invoice_features` contains unknown even bits".

## Failure scenario

We issue an invoice against, or pay an invoice carrying, a required feature or field we do not understand, where a conforming node would refuse and send `invoice_error`. The counterparty may then rely on semantics we silently ignore.

## Suggested fix

Mirror the offer decoder: define the known even-type sets for invoice_request and invoice, check the ranges, run `hasUnsupportedRequiredFeatures` on both feature fields, and `isValidPublicKey(nodeId)` before verifying the signature.
