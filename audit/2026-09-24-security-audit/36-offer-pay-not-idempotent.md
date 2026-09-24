# POST /offer/pay ignores X-Idempotency-Key, and a retried BOLT 12 payment cannot be de-duplicated by payment hash, so a client retry pays the offer twice

Labels: bug

Found during a security audit of the payment routes.

## What the code does

BOLT 11 routes are protected twice: the idempotency key (`IDEMPOTENT_ROUTES`, `src/cli/daemon.ts:87-108`; same key plus same body returns the cached response, concurrent same-key requests share the in-flight promise since #768) and the engine's duplicate-hash refusal (#975). `POST /l402/fetch` was added to the set with the comment "a retried fetch gets a fresh challenge with a fresh invoice, so an un-keyed retry pays twice". `POST /offer/pay` (`:2739-2746`) has exactly that shape and is not in the set: `payOffer` (`src/cli/beignet-node.ts:11497-11525`) awaits `this.node.requestInvoice(offer, ...)`, which sends a new `invoice_request` per call (`src/lightning/node/lightning-node.ts:27025-27051`; `offer-manager.ts:616`, `:725-739` key pending requests by a fresh request id, no per-offer cache), the payee mints a new invoice with a new payment hash, `assertHashUnpaid` (`:27067`) sees an unknown hash, and the payment goes out again. The header is silently dropped for routes outside the set (`daemon.ts:3281-3330`).

## Failure scenario

An agent following `docs/AI_AGENT_GUIDE.md` ("Use X-Idempotency-Key header on payment requests to prevent duplicates") calls `POST /offer/pay {offer, amountSats: 100000}` with `X-Idempotency-Key: order-1`. The HTTP client times out (`payOffer` blocks up to 60 s by default; the round trip to the payee plus routing often exceeds a 30 s client timeout) or the connection drops after the HTLC left. The agent retries with the same key and body; the second request obtains a second invoice and pays 100,000 sats again. Neither drain mode nor the daily limit stops it unless the limit happens to be exhausted.

The same gap exists, less acutely, for `POST /channel/splice-out` with an external `address` (a real external spend; a retry after the first splice locks moves the funds twice) and `POST /channel/open*` (a retry opens a second channel).

## Suggested fix

Add `POST /offer/pay` (and `POST /channel/splice-out`, `POST /channel/open`, `/open-v2`, `/open-zeroconf`, `/connect-and-open`) to `IDEMPOTENT_ROUTES`; answer 400 when a key is supplied on a route that does not honour it, so a caller cannot believe it is protected.
