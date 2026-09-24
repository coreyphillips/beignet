# Input validation gaps: invoice expiry accepts negative, fractional and NaN values, an over-long description is a scrubbed 500, and splice feerates accept any u32

Labels: bug

Found during a security audit of the HTTP surface. Two low-severity validation gaps, both reproduced or traced.

## 1. Invoice `expiry` / `expirySecs` is not validated

`POST /invoice/create` (`src/cli/daemon.ts:1720-1745`) and `/invoice/create-hold` (`:1936-1970`) pass `expirySecs` / `expiry` and `description` raw to `createInvoice` / `createHoldInvoice` (`src/cli/beignet-node.ts:8252-8285`, `:8945-8990`); the encoder's `encodeVarInt` loops `while (v > 0)` (`src/lightning/invoice/encode.ts:104-107`, `:179-190`). Repro: `expiry -1` decodes as 0, `1.5` as 1, `NaN` as 0, `1e15` is encoded as is; a 700-byte description throws a plain `Error('Tagged field data length ... exceeds ...')` which the daemon scrubs to `INTERNAL_ERROR`. `minFinalCltvExpiry` and amounts are validated (`requireFinalCltvExpiry`, `requireNonNegativeSafeInteger`); this is the one unguarded field. A hold invoice minted with `expiry: -1` is dead on arrival for the payer while the node reports it PENDING until its own `createdAt + expiry` check.

Fix: `requirePositiveSafeInteger(expiry)` with a sane ceiling in `createInvoice`, `createHoldInvoice` and `createJitInvoice`; refuse descriptions over 639 bytes with `INVALID_PARAMS`.

## 2. Splice feerates accept any u32

`requireU32(feeratePerkw)` for splice quote/in/out (`src/cli/beignet-node.ts:11304-11351`) and `validateU32(..., { min: 1 })` in the engine (`src/lightning/node/lightning-node.ts:12266`) have no upper bound, unlike `update_fee`, which refuses above 100,000 sat/kw (`channel.ts:5223`). An operator who mistakes sat/vB for sat/kw posts `POST /channel/splice-out {amountSats: 1000, feeratePerkw: 2500000, address}` on a 10M-sat channel: about 700 weight at 2500 sat/w, roughly 1.75M sats paid to miners from the channel balance with no refusal. `openChannel` is protected by the wallet's "fee exceeds half of inputs" guard; splices are built by the channel, not the wallet.

Fix: cap `feeratePerkw` (the update_fee bound of 100,000 is a reasonable ceiling) or refuse a fee above some fraction of the amount or balance.
