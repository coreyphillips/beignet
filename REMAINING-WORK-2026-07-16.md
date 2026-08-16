# Beignet audit remediation — remaining work (2026-07-16)

Tracking the 2026-07-15 review (`SECURITY-REVIEW-2026-07-15.md`): 9 fund-safety
findings + 70 spec-compliance findings. This file lists what is **still open**.
Local-only, not committed.

## Status summary

- **Fund-safety: 9 / 9 done.** FS-1…FS-9 all merged.
- **Spec-compliance: ~30 findings shipped, ~40 remaining** (many are LOW hardening).
- PRs #76–#101 opened. #76–#96 merged; #97–#101 open for review at time of writing.
- **This session (item 1 + item 2 + item 3 of the suggested order): PRs #96–#101**
  cover 6 BOLT 4 MEDIUMs, 4 BOLT 2 interactive-tx/channel MEDIUMs + S-2.H4, and the
  4 liquidity-ads/peer-storage MEDIUMs. `S-2.M3` verified real but DEFERRED — its
  `output:resolved` consumer must build on #98's `handleHtlcFailed` rewrite.
  `S-L.H4` deferred to its own PR (fund-critical on-chain to_remote script + needs
  live interop).

### Shipped (merged unless noted)
| PR | Finding(s) |
|----|-----------|
| #76 | FS-2 taproot funding watch |
| #77 | FS-4 taproot anchor CPFP |
| #78 | FS-5 taproot coop-close dust |
| #79 | FS-3 + FS-8 sweep rebroadcast / batched re-bump |
| #80 | FS-1 / S-2.H2 accept_channel validation |
| #81 | S-2.H1 malformed-HTLC double-credit |
| #82 | FS-6 + FS-7 splice / SCB recovery |
| #83 | FS-9 anchor CPFP provisioning |
| #84 | S-3.M2 BOLT 3 HTLC output ordering |
| #85 | S-4.H1 BOLT 12 merkle + signature tag |
| #86 | S-4.H2 BOLT 12 invoice_request signing/verify |
| #87 | S-4.H3 (part) invoice_relative_expiry tu32 |
| #88 | S-W.H1 watchtower StateUpdateReply codes |
| #89 | S-7.M3 gossip zlib decompression bomb |
| #90 | S-L.H1 + S-L.H2 + S-L.H3 liquidity-ads wire format |
| #91 | test regression fix (node.test.ts signed invreq) |
| #92 | S-7.M2 node_announcement features |
| #93 | S-7.M1 (part) gossip query/reply chain_hash |
| #94 | S-B.M3 + S-B.M4 wallet P2TR vbytes / change gap |
| #95 | S-4.M3 + S-4.M4 + S-4.M5 final-hop safety **(open)** |
| #96 | S-4.M6 + S-4.M7 + S-4.M8 BOLT 11 payer/decoder safety **(open)** |
| #97 | S-4.M9 1-hop blinded reply body **(open)** |
| #98 | S-4.M1 + S-4.M2 blinded relay amount formula + invalid_onion_blinding **(open)** |

---

## Session log 2026-07-16 (later session)

Item 1 of the suggested order (all six self-contained BOLT 4 payer/receiver
MEDIUMs) is DONE, PRs open awaiting review:
- **#96** S-4.M6 (over-length p/h/s/n fields skipped, not truncated),
  S-4.M7 (n-field vs recovered key, unknown even feature bits, secretless
  refusal), S-4.M8 (basic_mpp gate on the MPP fallback).
- **#97** S-4.M9 (1-hop blinded reply path now carries the message body).
- **#98** S-4.M1 (ceiling-inverted blinded relay amt_to_forward),
  S-4.M2 (invalid_onion_blinding constant + send-side
  update_fail_malformed_htlc + every blinded-route failure path mapped).

All verified against the code before fixing (all six were real). Each PR has
regression tests failing on its parent commit; scoped suites, conformance
(43), tsc and eslint green.

## Remaining — HIGH

### BOLT 12 offers (interop-only-with-beignet; needs live CLN to verify)
~~**S-4.H3 (remainder):** the invoice does not mirror the invreq/offer fields and
  makes `invoice_paths` / `invoice_blindedpay` optional. (tu32 part shipped in #87.)
  Byte-exact; validate against live CLN (docker `cln` 3010).~~
  **DONE — PR #110 (open)**, live-CLN validated (cln decode of a beignet invoice =
  valid:true with mirror + paths + payinfo all parsed; payer-side reader checks added).
- ~~**S-4.H4:** BOLT 12 subtype layouts diverge — the `blinded_path` /
  `blinded_payinfo` arrays carry a 1-byte count prefix the spec omits;
  `blinded_payinfo` puts a u16 features-length placeholder between
  `htlc_minimum_msat` and `htlc_maximum_msat` and drops features; decoders assume a
  33-byte `first_node_id` and mis-parse the scid-dir form (incl. the onion-message
  `reply_path` decoder). `onion/blinded-path.ts`, `offer/tlv.ts`,
  `onion-message/codec.ts`.~~
  **DONE — PR #109 (open)**, live-CLN validated (CLN decodes our pathed offer
  valid:true; we decode CLN's offer, pinned fixture). ALSO found+fixed live: BOLT 12
  strings must be checksum-LESS bech32 (`offer/bech32-nochecksum.ts`) — the old
  bech32m checksum blocked ALL string-level interop.

### Liquidity ads
- ~~**S-L.H4:** the lessor's `to_remote` output is never lease-locked (`leaseExpiry`
  is threaded only into `to_local`), so a seller can escape the lease early by
  provoking a buyer force-close. `commitment-builder.ts`, `script/commitment.ts`.~~
  **DONE — PR #104 MERGED** (LeaseCommitScriptToRemoteConfirmed threaded through
  builder/resolver/SCB; watchtower kit EXCLUDES it — blob v0 cannot express a
  lease; leases now anchors-only at negotiation). Follow-up before real leased
  funds: live CLN option_will_fund regtest (item 9).

### BOLT 2 (reestablish / interactive-tx — split out of earlier PRs, higher risk)
- ~~**S-2.H3:** `tx_add_input` receive-side validation missing (segwit-only
  anti-malleability MUST; `sequence` bound; prevtx/vout checks; 4096-message cap;
  `tx_abort` on splice shared-input mismatch). A non-segwit contributed input makes
  the confirmed splice txid differ from the one both sides signed against.~~
  **DONE — PR #107 (open)** (validatePeerInputPrevTx + sequence/4096 caps in the
  builder; splice invalid inputs + shared-input mismatch now tx_abort cleanly).
  Suggest a CLN splice interop run before the next mainnet splice.
- ~~**S-2.H4:** dual-funding stores `prevTxid: Buffer.alloc(32)` instead of extracting
  it, so two peer inputs sharing a vout collide in `checkDuplicatePrevouts`.~~ **DONE — PR #100 (open).**
- ~~**S-2.H5:** uncommitted remote updates not reversed on disconnect + received-HTLC
  dedup is id-only (content-blind). Reachable in normal operation (CLN drops
  uncommitted adds on reconnect). `channel.ts` markForReestablish + add-htlc dedup.~~
  **DONE — PR #105 (open)** (reversal in markForReestablish + content-aware dedup).

### Wallet BIPs (share one root cause: no way to supply a key's true master fingerprint/origin)
- ~~**S-B.H1:** PSBT `bip32_derivation` pairs a non-master fingerprint with a
  from-master path; hardware cosigners refuse to sign (breaks watch-only #51 +
  multisig #57 external-signer flows). One API addition fixes H1 + M1 + M2.~~
  **DONE — PR #103 MERGED** (masterFingerprint/originPath + cosigner objects).

---

## Remaining — MEDIUM

### BOLT 2 / BOLT 5
- ~~**S-2.M1:** reestablish always retransmits `revoke_and_ack` before
  `commitment_signed`, ignoring the original relative order (a crossed round
  force-closes). Split out of #81; reconnect-machinery.~~
  **DONE — PR #105 (open)** (persisted lastSentWasRevoke + ordered replay).
- ~~**S-2.M3:** a forwarded HTLC resolved on-chain never fails the incoming HTLC
  off-chain (`output:resolved` has no consumer), so `scanForwardTimeouts`
  force-closes a healthy inbound channel instead of a clean `update_fail_htlc`.~~
  **DONE — PR #102 MERGED** (enriched output:resolved + handleOnChainOutputResolved
  consumer built on #98's blinded-failure machinery).
- ~~**S-2.M4:** `tx_complete` receive-side limits missing (peer input<output, feerate
  sufficiency, 252/252 caps, 400k-weight cap) + `tx_add_output` MAX_MONEY /
  negotiated-dust (flat 546 used).~~ **DONE — PR #100 (open).**
- ~~**S-2.M5:** `tx_signatures` ordering skips the node_id lexicographic tie-break;
  splices hard-code acceptor-first; equal contributions can deadlock.~~ **DONE — PR #100 (open).**
- ~~**S-2.M6:** inbound `update_fee` rejected during `SHUTTING_DOWN` though the spec
  allows it while HTLCs remain (CLN sends it) — force-closes a clean shutdown.~~ **DONE — PR #99 (open).**
- ~~**S-2.M7:** `open_channel` initial-commitment MUST-checks missing (funder can
  afford the fee; not both outputs below reserve). Deferred from #80.~~ **DONE — PR #99 (open).**
- ~~**S-2.M8:** `stfu` rejected whenever committed HTLCs exist, so CLN/eclair-initiated
  quiescence (and splicing) on a busy channel stalls 60s and disconnects. Needs
  HTLC-bearing splice commitment batches — larger.~~
  **DONE — PR #116 MERGED (master 1d11b4a).** Gate now tests genuinely PENDING
  updates (needsCommitment + PENDING adds + in-flight removals + two-phase flags),
  not committed HTLCs. Splice HTLC-free assumptions lifted: _splicedState balance
  split excludes in-flight HTLC value (was mis-attributed to the peer on BOTH
  sides); mid-splice + pending-lock-batch receive paths verify AND persist the
  peer's second-level HTLC sigs (spliceInFlight.remoteHtlcSignatures, optional,
  no version bump); completeSplice adopts them instead of zeroing;
  verifyRemoteHtlcSignatures(+Taproot) take an optional commitment number (the
  mid-splice commitment is at the CURRENT number). New adds still refused while
  quiescent / pending-lock (allowed policy). FOLLOW-UP before the next mainnet
  splice on a busy channel: re-run the live CLN splice matrix (docker).

### Systemic (BOLT 2)
- ~~`ChannelActionType.ERROR` only emits an app-level `error` event for established
  channels; it never sends a wire `error`/`warning` nor closes the connection. Every
  "MUST send an error and fail the channel" path depends on the embedder. Generalize
  the DLP wire-error pattern (`channel.ts:~4870`). Sequence LATE — several earlier
  fixes assume a wire error is actually sent.~~
  **DONE — PR #108 (open)** (_failChannelWithWireError applied to the five
  peer-violation paths: bad commit sig, bad HTLC sig, revoke point-binding,
  revoke shachain, reestablish secret; also fixed splice.test.ts harness missing
  htlcBasepointSecret — payments were settling on UNVERIFIED sigs). Remaining
  MUST-send-error LOWs (tx_abort echo paths etc.) stay in the LOW batch.

### BOLT 4 / 11 / 12
- ~~**S-4.M1:** blinded relay computes `amt_to_forward` with the fee charged on the
  incoming amount instead of the ceiling-inverted formula → forwards a few msat
  short → downstream fails; breaks any foreign-built blinded route through us.~~ **DONE — PR #98 (open).**
- ~~**S-4.M2:** failures inside a blinded route never return `invalid_onion_blinding`
  (the constant does not exist in the repo); ordinary errors leak the blinded
  portion and violate the MUST.~~ **DONE — PR #98 (open).**
- ~~**S-4.M6:** BOLT 11 decode truncates an over-length `p`/`h`/`s`/`n` field instead
  of failing → a malformed invoice yields a truncated payment hash we try to pay.~~ **DONE — PR #96 (open).**
- ~~**S-4.M7:** payer-side BOLT 11 MUSTs missing in `sendPayment`: pays invoices with
  unknown even feature bits, pays secretless invoices, never validates the recovered
  key against the `n` field.~~ **DONE — PR #96 (open).**
- ~~**S-4.M8:** MPP attempted whenever a payment secret is present without checking the
  invoice offers `basic_mpp`; splitting to a non-MPP recipient locks funds for the
  mpp_timeout.~~ **DONE — PR #96 (open).**
- ~~**S-4.M9:** replying via a 1-hop blinded reply path drops the message body (loop
  starts at index 1) → a BOLT 12 invoice reply arrives empty → requester times out.~~ **DONE — PR #97 (open).**

### BOLT 7
- ~~**S-7.M1 (remainder):** `NetworkGraph` rejects every non-mainnet
  `channel_announcement`. Deferred from #93: the node also defaults its OWN
  `channel_announcement` chain_hash to mainnet even on non-mainnet
  (`acceptableChainHashes[0] ?? BITCOIN_CHAIN_HASH`), so making the graph
  chain-strict needs a coupled node-announcement-consistency change + ~13 fixture
  updates.~~ **DONE — PR #111 (open)** (graph chain-scoped + signed announcement
  digest + node defaults; 3 fixture files swept to REGTEST_CHAIN_HASH).

### Liquidity ads / wtwire / peer storage
- ~~Seller accepts an unvalidated buyer `blockheight` → a far-future or
  `>= 500,000,000` value freezes the lessor's own `to_local`. (`channel.ts:~7549`.)~~ **DONE — PR #101 (open).**
- ~~Lease proportional fee uses `requested_sats` instead of
  `min(funding_satoshis, requested_sats)` → balance desync vs a partial funder.~~ **DONE — PR #101 (open).**
- ~~Signed `channel_fee_max_*` caps never enforced on the lessor's own
  `channel_update` while the lease is active.~~ **DONE — PR #101 (open).**
- ~~Peer-storage rate limiter discards the NEWEST blob within 60s instead of keeping
  the latest → loses the freshest backup exactly when state changes.~~ **DONE — PR #101 (open).**

### Wallet BIPs
- ~~**S-B.M1:** exported multisig descriptors put the parent fingerprint in a
  zero-path key origin (BIP-380 wants the key's own fingerprint) — blocks
  Sparrow/Coldcard multisig registration. (Same root cause as S-B.H1.)~~ **DONE — PR #103 MERGED.**
- ~~**S-B.M2:** external-signer PSBTs omit `non_witness_utxo` for segwit v0 inputs;
  Ledger 2.x / Trezor >= 2.3.5 reject them. (Same root cause.)~~ **DONE — PR #103 MERGED.**

---

## Remaining — LOW (hardening; batchable)

- ~~**BOLT 2 LOW (11):** funding 2^24 boundary off-by-one; `channel_type` defaulted vs
  failed; `cltv_expiry >= 500000000` unenforced + no send-side check; reestablish
  `next_commitment_number == 0` / stale gaps not failed; basepoints not
  secp256k1-validated on open/accept (breaks ~15 fixtures using random points — do
  with fixture updates); acceptor reserve/dust not coupled to opener's;
  `channel_ready` retransmission keying; `tx_abort` echo + MUST-`tx_abort` paths;
  splice `tx_init_rbf` RBF floor / generic-error reply; splice-out external
  destination unvalidated (can burn to OP_RETURN); no fallback to separate per-output
  penalty txs near expiry.~~
  **DONE — PR #115 MERGED (master a7697aa), 10 of 11** (all 11 re-verified real
  first; only 4 harness files needed the curve-point fixture sweep, not ~15;
  MAX_FUNDING_SATOSHIS now 16777215 so every comparison site is fixed at once).
  ~~DEFERRED as feature-sized: per-output penalty tx fallback near expiry.~~
  **DONE — PR #119 MERGED (master 04cbaa2, 2026-07-17d).** resolveRevoked
  CommitmentOutputs (+ taproot variant) take currentHeight; any penalty HTLC
  input within PENALTY_SPLIT_DEADLINE_BLOCKS (18) of its cltv_expiry gets its
  own single-input penalty tx (deadline from classification cltvExpiry or the
  H2 snapshot entry); monitor passes height + broadcasts each distinct tx once;
  per-outpoint RBF re-bump (PR #79) bumps each split tx independently.
  5 regression tests (penalty-deadline-split.test.ts) fail on parent.
- ~~**BOLT 4 LOW (6):** onion-message padding zero-initialized (not from `pad` stream);
  hop-payload length 0/1 not rejected + TLV order/dup not enforced; MPP `total_msat`
  of later parts never compared; no `path_id` validation for final onion messages +
  plaintext `next_node_id` fallback; non-spec BOLT 11 tag-25 blinded paths suppress
  cleartext hints; `encodeTaggedField` corrupts a field > 1023 words.~~
  **DONE — PR #113 MERGED (2026-07-17)** (5 of 6; path_id surfaced on delivery via ERD type 6,
  cleartext hints now opt-in via includeCleartextHintsWithBlinded). DEFERRED: the
  plaintext next_node_id fallback removal — beignet's sendMultiHopOnionMessage
  builds UNENCRYPTED recipient data and depends on it, so the sender must adopt
  real blinding first (separate change).
  REVIEW PASS 2026-07-17 (commit e541982 on the PR): pad stream re-keyed from the
  SESSION key (was the first hop's shared secret — that hop could regenerate the
  stream and locate the padding boundary; sphinx-crypto now exports generateKey,
  both onion builders use it) + encodeHopPayload now sorts the FULL record set so
  a low-typed custom record cannot produce a stream our own strict decoder
  rejects. 3 new tests failing on the previous revision.
- ~~**BOLT 7 LOW (3):** `dont_forward` not set on `channel_update` for unannounced
  channels; required-feature check compares against advertised (not implemented)
  set; alias byte-truncation can split a UTF-8 codepoint + >1 DNS address not
  rejected.~~ **DONE — PR #112 MERGED** (verified on master 2026-07-17d:
  lightning-node.ts:~4053 dont_forward, features/flags.ts implementedFeatures(),
  lightning-node.ts:~4995 codepoint-safe alias trim, gossip/messages.ts:178 DNS cap).
- ~~**S-W LOW (2) + peer-storage LOW (2):** no dust check on the justice sweep
  output; user sweep-script length not constrained to {22,34};
  `option_provide_storage` bit; outbound peer-storage blob not padded.~~
  **DONE — PRs #112 + #114 MERGED** (verified on master 2026-07-17d:
  justice.ts:153 length guard, justice.ts:464 isDustOutput, bPS1 padding at
  lightning-node.ts:~1741 with the 65523 cap from #114, option_provide_storage
  covered by node_announcement reusing init features).
- ~~**S-B LOW (1):** bech32m fallback validates any well-checksummed string without
  witness-version/program-length rules and never returns signet.~~
  **DONE — PR #112 MERGED** (verified: src/utils/wallet.ts:198 BIP-350 rules).
- ~~**secp256k1 basepoint validation on accept_channel** (from the #80 discussion).~~
  **DONE — PR #115 MERGED** (verified: channel/validation.ts:100-127, on open AND
  accept; 4 harness fixture files swept).

## Follow-ups opened by the PR #118 review (2026-07-17)

- ~~**update_blockheight (wire type 137) is silently ignored.**~~
  **DONE — PR #122 MERGED (master ef096a6, 2026-07-17d).** Full CLN-parity handling
  (researched from CLN channeld: opener-only sender, sent whenever its tip
  advances, blockheight_states machine): MessageType 137 + codec + dispatch;
  Channel.handleUpdateBlockheight validates (NORMAL/SHUTTING_DOWN/splice-lock,
  acceptor-only receive, leased+isLessor, monotonic non-decrease, equal no-op,
  CLN's +1008 staleness bound) and stages pendingLeaseBlockheight through the
  SAME two-phase machine as update_fee (signable on covering commitment_signed
  + needsCommitment, committed when we sign, promoted on revoke completion,
  rolled back on reestablish unless signable); commitment-builder
  getLocal/getRemoteCommitmentLeaseBlockheight mirror the feerate phase
  helpers; lastSignedCommitLeaseBlockheight stamps force-close rebuilds;
  leaseHeightHistory records every promoted height and on-chain matchers
  (disambiguate our-to_local, classifyOur to_local, classifyTheir +
  future-commitment our-to_remote) try ALL candidate CSVs so OLD/revoked
  commitments still match; to_local sweep nSequence now PARSED from the stored
  witnessScript (csvFromToLocalScript); leaseCsvBlocks(bh >= expiry) now means
  lease-ran-out (plain scripts, CLN parity) instead of the legacy fallback.
  All persisted (serialization). 7 unit tests fail on parent.
- ~~**NEW (discovered during #122): live seller-side validation BLOCKED on
  acceptor-side funding contribution.**~~
  **DONE — PR #124 MERGED (master 0ad92ee, 2026-07-17e).**
  setDualFundingContribution + acceptor interactive-tx drive (mirrors the
  splice acceptor drive; legacy caller-driven flow untouched without a
  registered contribution) + auto-signed tx_signatures via wallet closures
  (released exactly once) + assembled/broadcast funding tx; accept_channel2
  echoes the opener's channel_type (CLN requires it); manager sources the
  contribution from fundingProvider.selectSpliceInputs BEFORE answering
  will_fund (withdraws the offer if selection fails); INodeConfig.leaseRates +
  option_will_fund advertised only when configured. **LIVE VALIDATED
  (cln-lease-seller.test.ts): CLN bought a 100000 sat lease from beignet
  (fundchannel request_amt + compact_lease = tu32 encodeLeaseRates hex),
  channel NORMAL both sides (capacity 500673 incl. 673 sat lease fee earned),
  and TWO live update_blockheight rounds advanced leaseCommitBlockheight with
  the channel staying NORMAL — the live validation of the #122 machine.**
  ~~Remaining seller-hardening niceties (non-blocking): payments + force-close
  sweep matrix on a beignet-lessor channel; multi-UTXO contributions.~~
  **DONE — PR #125 MERGED (master 5f00275, 2026-07-17f).** Multi-UTXO
  contribution unit-proven (per-turn inputs, opener re-sent tx_complete, both
  witnesses auto-signed). LIVE seller matrix complete: payments both ways over
  the leased channel; CLN force-close; beignet's LEASE-LOCKED to_remote swept
  with nSequence = remaining lease CSV (4019), no nLockTime, CONFIRMED on
  bitcoind (94550 sat home) — CONSENSUS-level validation of the CLN pure-CSV
  lease scripts + height-advanced classification candidates. Gotchas: interop
  node config MUST carry payment/revocation/delayed basepoint secrets (claim
  sig consensus-invalid without — bitcoind CHECKSIGVERIFY reject); CLN close
  needs an explicit v0 destination when the peer lacks anysegwit shutdown.

**NOTHING REMAINS OPEN IN THIS TRACKER. Campaign complete: PRs #76-#125.**
- ~~**classifyOurCommitmentOutputs never matches the peer's to_remote on OUR
  commitment.**~~ **DONE — PR #121 MERGED (master 51278ee)** (anchor CSV-1 +
  lessee-side leased variants matched with stored witnessScript; monitor
  full-resolution gate exempts the unspent peer-owned to_remote so a vanished
  peer cannot pin the channel in RESOLVING — also fixes the same latent hang
  for non-anchor channels; 3 regression tests fail on parent).

## Follow-ups opened by the 2026-07-17 review session

- **PR #114 MERGED (2026-07-17):** two defects found reviewing merged #112 — distributePeerStorage
  accepted blobs the 8-byte privacy framing made unsendable (65524..65531 threw or
  were silently dropped at encode; cap now 65523) + justice dust guard hardcoded
  294 for every script type (now isDustOutput: 294/330/354). Regression tests fail
  on master.
- ~~**Onion-message REAL route blinding (feature-sized, NOT a LOW tweak).**~~
  **FULLY DONE.** Sender+receiver blinding shipped in #117; the remainder
  shipped in **PR #120 MERGED (master 8b089ec, 2026-07-17d)**: path_id now
  VERIFIED end to end (pending invreq stores its reply-path path_id and only an
  invoice over that path resolves it; offers store the path_id of their blinded
  paths and handleInvoiceRequest rejects direct/forged requests; node asyncHold
  offer paths carry a generated path_id) AND the plaintext next_node_id
  forwarding fallback is REMOVED (constructMultiHopOnionMessage /
  sendMultiHopOnionMessage deleted; resolveNextHop requires decryptable ERD;
  raw key kept only for single-hop direct-send peel). Live-CLN validated:
  cln-paid-offer.test.ts passes with strict verification. Original text kept
  below for reference:
- **(historical) Onion-message REAL route blinding (feature-sized, NOT a LOW tweak):** the
  receive side never derives a blinded sphinx key for onion messages
  (deriveBlindedPrivkey's only caller is the payment HTLC path,
  lightning-node.ts:~6597; manager.handleMessage passes the raw key), so a hop
  addressed by its blinded node id cannot peel the packet — multi-hop blinded
  reply paths (2+ blinded hops) do not work today, and removing the plaintext
  next_node_id forwarding fallback would break beignet-to-beignet multi-hop
  messaging outright. Full fix: sender-side per-hop blinding in
  sendMultiHopOnionMessage (constructBlindedPath machinery exists), receiver
  blinded-sphinx ECDH, BOLT 4 TLV encrypted_data format (current blobs are
  beignet-compact, see blinded-path.ts note), path_id GENERATION + VERIFICATION
  (nothing sets or checks one in production yet — #113 only surfaces it), then
  remove the plaintext fallback. Needs live CLN validation (pairs with item 9).

---


## Live-CLN session 2026-07-17 (PR #117 MERGED, master f704cce)

- **CLN splice matrix re-run after #116: 7/7 GREEN** (beignet splice-out/repeat/
  post-payment, CLN-initiated splice, multi-UTXO splice-in, mid-splice disconnect
  resume). The #116 splice changes are live-validated.
- **PAID-OFFER MILESTONE DONE:** beignet pays a live CLN BOLT 12 offer end to end
  (tests/lightning/interop/cln-paid-offer.test.ts, PASSES). Six real bugs fixed to
  get there: onion messages now use REAL route blinding (sphinx to blinded node
  ids + receiver blinded-key peel with raw fallback — the receive half of the
  onion-message blinding gap is CLOSED); invreq carries a 1-hop blinded reply
  path (with path_id); invreq_chain defaulted from offer chains; payBolt12Invoice
  passes local channel edges; blinded final hop carries total_amount_msat
  (TLV 18); lease fee accounting moved to CLN's funding-tx model.
- ~~**option_will_fund LIVE VALIDATION (partial DONE):** ... REMAINING RESIDUAL:
  leased-commitment script parity — the lessor's to_remote on the buyer's
  commitment diverges ("Invalid commitment signature in v2 open").~~
  **FULLY DONE — PR #118 MERGED (master 24deec5).** CLN's will_fund decodes byte-exactly, sig
  VERIFIES, fee matches to the satoshi, AND (this PR) the leased-commitment
  scripts now match CLN's pure-CSV model, so a leased channel OPENS NORMAL vs
  CLN — the commitment signature verifies and cln-lease-willfund.test.ts drives
  the full signature exchange to a confirmed, locked-in channel (CLN leased
  100000 sat for a 1168 sat fee into a 601168 sat funding output). Implemented
  from CLN master source: to_local CSV number = max(to_self_delay,
  lease_remaining), no CLTV (bitcoin_wscript_to_local); anchored to_remote =
  <key> CHECKSIGVERIFY <lease_remaining> CHECKSEQUENCEVERIFY
  (bitcoin_wscript_to_remote_anchored); lease_remaining = lease_expiry -
  agreed_blockheight (4032 at open); second-level HTLC outputs NEVER lease-locked
  (CLN htlc_tx has no lease param). New IChannelState.leaseCommitBlockheight
  (persisted + SCB); leaseCsvBlocks() helper; commitment-builder / output-resolver
  / sweep / chain-monitor / watchtower all threaded; sweeps use the CSV as input
  nSequence with no nLockTime; lease script unit tests rewritten for CSV.
- Onion-message route blinding follow-up: SENDER+RECEIVER core DONE (#117);
  path_id VERIFICATION wiring + plaintext next_node_id fallback removal DONE
  (**PR #120 MERGED, master 8b089ec**, live-CLN validated).

## Suggested next order

1. Finish BOLT 4 payer/receiver MEDIUMs that are self-contained + unit-testable:
   S-4.M8 (basic_mpp gate), S-4.M6 (BOLT 11 over-length fail), S-4.M7 (payer MUSTs),
   S-4.M2 (`invalid_onion_blinding`), S-4.M1 (blinded amt formula), S-4.M9 (reply body).
2. BOLT 2 MEDIUMs that don't need the reestablish machinery: S-2.M6 (update_fee in
   SHUTTING_DOWN), S-2.M3 (output:resolved consumer), S-2.M5 (tx_signatures tie-break),
   S-2.M4 (tx_complete limits), S-2.M7 (open_channel checks).
3. Liquidity-ads / peer-storage MEDIUMs (buyer blockheight, proportional fee,
   fee caps, rate-limiter newest-blob) + S-L.H4 to_remote lease lock.
4. Wallet BIP fingerprint API (S-B.H1 + M1 + M2 in one).
5. Reestablish machinery cluster (S-2.H5, S-2.M1) — careful, its own PR(s).
6. Splice interactive-tx validation (S-2.H3, S-2.H4).
7. Wire-error systemic gap (sequence after the MUST-fail paths above).
8. LOW batches by area.
9. **Live-CLN session:** BOLT 12 S-4.H3-mirroring + S-4.H4 subtypes, and the
   S-7.M1 NetworkGraph half (validate byte-exact / non-mainnet against docker CLN).

## Verification baseline to preserve
- `npm run test:conformance`: 43 passing.
- Fund-safety + spec suites green; the one pre-existing `test:all` failure is the
  live-LND-tower docker interop test (infra, not code).
- Every PR: a regression test that fails on the parent commit + passes on the branch;
  scoped mocha green; lint + typecheck clean. No em-dashes / no AI attribution in
  commits or PR bodies.
