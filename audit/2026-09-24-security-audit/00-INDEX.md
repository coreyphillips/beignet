# Beignet security audit, 2026-09-24: findings index

Audit of master at commit 1086c09 (v0.22.0). Each file in this directory is a ready-to-file GitHub issue (title on the first line, body below). Every finding was verified against the code by the lead reviewer; where a reproduction script is quoted it was re-run by the lead. Findings already tracked in the issue tracker were excluded.

| # | Severity | Area | Title |
|---|----------|------|-------|
| 06 | Critical | Payments | Payee-controlled blinded-path fee paid uncapped and invisibly to every limit |
| 17 | Critical | On-chain wallet | Persisted staged send replayed into every later send after a restart (double payment) |
| 01 | High | Daemon | One unauthenticated request with an unparsable Host header crashes the daemon |
| 02 | High | CLI | beignet init writes the mnemonic and apiToken with default (world-readable) permissions |
| 03 | High | Daemon | Default no-token loopback daemon is CSRF-able from any web page |
| 07 | High | BOLT 12 | Payer accepts an invoice for any amount, any signer, or expired |
| 08 | High | BOLT 12 | Issuer mints an invoice for whatever invreq_amount the payer sends |
| 09 | High | Payments | Routing fees outside maxPaymentSats and the daily ledger; no default fee cap |
| 13 | High | Forwarding | Forwarder never applies expiry_too_soon; beignet downstream fails the channel |
| 18 | High | On-chain wallet | Server-reported UTXO value trusted while the signature commits to the real amount |
| 19 | High | On-chain wallet | sweepPrivateKey writes the swept private key into wallet storage |
| 23 | High | Swaps | Reverse provider hands a never-relayed funding to the client after the hold is cancelled |
| 25 | High | Recovery | Fenced device admits the operator's force close of a revoked commitment |
| 26 | High | Recovery | Snapshot frames exceed the guardian ciphertext cap; replication wedges, quorum node freezes |
| 29 | High | Chain | Uneconomic to_local aborts every HTLC claim on our own force close |
| 32 | High | Payments | Zero-amount invoice via the MPP fallback underpays and poisons all persistence |
| 35 | High | Spending rails | sendToRoute bypasses maxPaymentSats, dailySpendLimitSats and the ledger |
| 36 | High | Daemon | POST /offer/pay ignores X-Idempotency-Key; retries pay twice |
| 39 | High | FFOR | Any channel peer can lock the settlement peer's balance indefinitely |
| 44 | High | Channel | Funder never checks its own commitment fee on inbound adds; balance trimmed to zero |
| 04 | Medium | Transport | Half-open handshakes never count toward maxInboundPeers; no per-IP cap |
| 10 | Medium | L402 | /l402/fetch follows redirects into private targets (blind SSRF) |
| 14 | Medium | Gossip | Unsolicited reply_channel_range accumulated without bound |
| 15 | Medium | Gossip | Pathfinding routes over unverified channel_updates (lazy mode default) |
| 16 | Medium | Forwarding | Malformed-HTLC relay and five BOLT 4 failure-handling gaps |
| 20 | Medium | On-chain wallet | setupTransaction falls back to every coin; CPFP boost inherits it |
| 21 | Medium | On-chain wallet | PSBT external-signer flow: change unlabelled, import never verifies outputs |
| 27 | Medium | Recovery | Guardian storage never shrinks; shared quota is a hard stop |
| 30 | Medium | Watchtower | Backups skip commitment #0 and revocations across a restart |
| 31 | Medium | Coop close | Closing tx trims with hard-coded dust thresholds, not the negotiated limit |
| 33 | Medium | Payments | MPP part on a reconnecting channel never fulfilled; needless force close |
| 40 | Medium | FFOR | Witness provisioning lets one peer exhaust mailbox capacity forever |
| 45 | Medium | Channel | revoke_and_ack next point not curve-validated; permanent channel wedge |
| 46 | Medium | Channel | accept_channel minimum_depth unbounded; v2 opener ignores it |
| 05 | Low | Wire | BOLT 1 leniencies: unknown even TLVs accepted, init networks unchecked, error text unsanitized |
| 11 | Low | BOLT 11 | Mixed case accepted, other-network invoices paid, zero-amount HTLC |
| 12 | Low | BOLT 12 | invoice_request / invoice decoders skip reader MUSTs |
| 22 | Low | On-chain wallet | sendMax pricing and getRbfData dead guard |
| 24 | Low | Swaps | Provider hardening: CLTV mismatch, concurrency cap, stranded rows, client CLTV bound |
| 28 | Low | Recovery | Restore racing a live writer with one guardian down deadlocks both |
| 34 | Low | Payments | Retry context left after a throwing dispatch; re-send inherits old parameters |
| 37 | Low | Spending rails | Rebalance fees and drain mode; maxPaymentSats Lightning-only |
| 38 | Low | Daemon | Invoice expiry validation; splice feerate unbounded |
| 41 | Low | Direct funding | Ownership proof not request-bound; replayable to burn attempt budgets |
| 42 | Low | Daemon | Hardening bundle: rate-limiter prune, SSE backpressure, openapi, webhooks, five small items |
| 43 | Low | Hygiene | qs advisories under bip21, Electrum TLS never verified, CI permissions and pinning |
| 47 | Low | Channel | State-machine leniencies: trimmed-HTLC affordability, reestablish gaps, uncommitted settles, upfront script |

## Considered and not filed

- Force-closing on a peer's `error` message: deliberate, matches LND, CLN and Eclair; only the counterparty can trigger it.
- Electrum SPV trust (no header or merkle verification): documented design; filed only where the wallet can cross-check data it already holds (18).
- Outgoing payment preimages visible to `readonly` API keys: consistent with `GET /payment/proof` being readonly by design.
- `wire-capture` writing decrypted messages to disk: opt-in and documented.
- Open issue 796 (swap fee floor) and the open guardian-rotation issues (862, 937, 938) already cover their topics.

## Verified sound (high level)

BOLT 8 Noise handshake and cipher rotation, wire codec bounds, BOLT 3 scripts and key derivation (Appendix C/E/F vectors pass), shachain handling, commitment construction and fee trimming, commitment_signed / revoke_and_ack ordering and persist-before-send, interactive-tx validation, Sphinx processing, failure-onion attribution, forwarding fee arithmetic, payment_secret and MPP set handling, keysend, hold invoices, SQLite parameterization and WAL/FULL durability, serialization round trips, swap scripts and refund construction, recovery frame AEAD and writer lease, guardian verb authentication, watchtower blob format and justice construction, coin selection and fee tables, multisig and taproot signing, BIP 21 parsing, daemon auth and scope keying, idempotency for BOLT 11 routes.
