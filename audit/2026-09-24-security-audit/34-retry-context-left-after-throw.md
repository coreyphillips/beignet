# A BOLT 11 dispatch that throws after registering its retry context leaves the context behind, so a re-send within 60 s inherits the previous amount, fee cap, CLTV ceiling and exclusions

Labels: bug

Found during a security audit of the payment pipeline. Narrow window, but the inherited amount is a real overpayment.

## What the code does

`sendPayment` registers `paymentRetryContexts[hash]` only `if (!has(hash))` (`src/lightning/node/lightning-node.ts:15735-15746`, `:15624`) and then calls `sendPaymentToRoute`, which can throw after registration: `NO_CHANNEL_TO_HOP` (`:15913`, a route found over the announced graph copy of our own channel while its peer is offline; `getLocalChannelEdges` excludes an `AWAITING_REESTABLISH` channel and the router keeps graph first hops, `pathfinding.ts:317-329`; the daemon maps it to `PEER_NOT_CONNECTED`) or the CLTV-ceiling error (`:15923`). No payment record exists and nothing deletes the context until the 60 s cleanup tick (`:10380-10388`, timer at `:1569`). A second `sendPayment` for the same hash passes `assertHashUnpaid` and keeps the OLD context; a retry re-enters with `retryCtx.invoiceStr, retryCtx.excludedChannels, retryCtx.maxFeeMsat, retryCtx.amountMsat, retryCtx.maxCltvExpiryHeight` (`:22978`), and the ceiling is inherited at `:15503-15507`. `dispatchBolt12Route` (`:27200-27229`) already deletes its context in a `catch`; the BOLT 11 path does not.

## Failure scenario

Zero-amount invoice. Call 1: `sendPayment(inv, amount = 100k sats, maxFee = 1000)` while the LSP peer is briefly offline throws `PEER_NOT_CONNECTED`. Call 2 within 60 s: `sendPayment(inv, amount = 1k sats, maxFee = 10)`. The first attempt uses the new values, but a temporary failure re-enters `sendPayment` with the stale context: 100k sats within a 1000-sat fee cap, 100x the requested amount. A stale `maxCltvExpiryHeight` also applies to the first attempt of call 2 and can make the invoice unpayable until the prune.

## Suggested fix

Mirror `dispatchBolt12Route`: wrap the dispatch in try/catch and delete a context this call created on throw; when a caller supplies new parameters and nothing is in flight, overwrite the existing context.
