# Direct funding: the ownership proof binds only (txid, vout, amount), so a proof harvested from one offer can be replayed against another receiver's request and burn its lifetime attempt budget

Labels: bug

Found during a security audit of direct funding. Reproduced: the same 64-byte digest signature and the same 65-byte message proof both verify (`ownershipProblem` returns `null`) on an offer carrying a different `receiptHash`, an attacker `changeScript` and `maxTotalFeeSat: 0`, after a codec round trip.

## What the code does

The signed statement is `lfbw-direct-funding-offer:<offerId>:<txid>:<vout>:<amountSat>` (`src/lightning/direct-funding/messages.ts:774-812`, `ownershipMessage` / `ownershipDigest`; the probe form adds only `sequence`). `receiptHash`, `changeScript`, `maxTotalFeeSat` and, for the digest and message forms, `sequence` are not covered. `docs/DIRECT-FUNDING-OWNERSHIP-PROOFS.md` says "Proofs authorize this offer only", but the offer id is derived from the coin and amount, not bound to the request. The receiver verifies the proof (`receiver/verify.ts:143-176`), then admits (`receiver/engine.ts:1076-1090`) and charges an attempt (`:1284`, `requests.ts:453-467`, "The COUNT stays charged"; `DF_MAX_REQUEST_ATTEMPTS = 3`).

## Failure scenario

Payer P offers coin C to receiver R1 (R1 declines or the exchange fails; C stays unspent). R1 now holds a valid proof for C. It takes any public envelope of receiver R2 and sends an offer for C with R2's receipt hash: admission passes (the chain says unspent, the proof is valid), R2 reserves C, charges an attempt, opens a dual-funded channel with its LSP, waits 120 s for the final transaction and 120 s for a witness that never comes, then aborts. Three replays make R2's request permanently unpayable ("too many funding attempts for this request"); while a replay is live, P's genuine offer for the same request is declined ("request already has an active funding attempt"); replays across requests pin R2's inflight slots and spam its LSP with aborted opens. No funds move.

## Suggested fix

Include the request binding (receipt hash or request id) in `ownershipMessage` and in the probe transaction's `OP_RETURN`, and have the receiver verify the proof against its record's receipt hash.
