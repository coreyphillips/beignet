# BOLT Conformance Vectors — Provenance

These vectors are vendored **verbatim** from the official Lightning Network
specification so beignet can be asserted against the spec's canonical truth
rather than hand-written fixtures.

- **Upstream repo:** https://github.com/lightning/bolts
- **Commit:** `94eb038c42e664dd7862faeec6508ccd25f63ff8` (master, fetched 2026-06-25; re-verified still master 2026-07-17)

| File | Upstream source |
| --- | --- |
| `bolt01/bigsize.json` | `01-messaging.md` — Appendix A: BigSize Test Vectors |
| `bolt01/tlv-stream.json` | `01-messaging.md` — Appendix B: Type-Length-Value Test Vectors |
| `bolt03/derivation.json` | `03-transactions.md` — Appendix E: Key Derivation Test Vectors |
| `bolt03/commitment.json` | `03-transactions.md` — Appendix C: Commitment and HTLC Transaction Test Vectors (non-anchor) |
| `bolt03/per-commitment-secrets.json` | `03-transactions.md` — Appendix D: Per-commitment Secret Generation Test Vectors |
| `bolt04/onion.json` | `bolt04/onion-test.json` |
| `bolt04/route-blinding.json` | `bolt04/route-blinding-test.json` |
| `bolt04/blinded-payment-onion.json` | `bolt04/blinded-payment-onion-test.json` |
| `bolt07/extended-queries.json` | `bolt07/extended-queries.json` |
| `bolt08/transport.json` | `08-transport.md` — Appendix A: Transport Test Vectors |
| `bolt11/invoices.json` | `11-payment-encoding.md` — Examples / Examples of Invalid Invoices |

Each JSON carries a `_source` field naming its upstream origin. Values are the
spec's hex/decimal as published; the JSON wrappers only reshape them into
machine-loadable records (no values altered — uint64-range decimals are quoted
as strings so JSON.parse cannot lose precision). To re-sync, refetch the files
at a newer commit and update the hex in place.

## Known upstream vectors not vendored

- `bolt02/splicing-test.md` — prose message-sequence scenarios, no machine
  vectors to vendor.
- `bolt03/zero-fee-commitments-test.json` (Appendix H) — zero-fee (v3/P2A)
  commitments are not implemented in beignet; re-evaluate on the next re-sync.

## Findings surfaced — all resolved

The conformance run surfaced three spec divergences; all have been fixed and the
corresponding tests now pass (no skips):

1. **BOLT 4 onion construction padding** — FIXED. `constructOnionPacket` now
   initializes routing-info from the session-key-derived pad stream
   (`HMAC("pad", session_key)` → ChaCha20) per BOLT 4 Packet Construction,
   instead of zeros. The onion now reproduces the reference packet byte-for-byte
   (`bolt04-onion.test.ts` → "constructs the spec onion packet byte-for-byte").
2. **BOLT 11 unrecoverable signature** — FIXED. `decode()` now throws when the
   signature fails to recover (`src/lightning/invoice/decode.ts`), so the vector
   moved into "invalid invoices are rejected".
3. **BOLT 11 missing payment_secret** — RESOLVED by layering. The decoder stays
   lenient (parsing ≠ node policy); the compulsory-secret rule is enforced at the
   final-hop receive path (`lightning-node.ts`: an HTLC is failed when the
   invoice's `expectedSecret` is set and the onion omits/mismatches it). Pinned by
   the "payment_secret enforced at receive layer, not in decode" test.
