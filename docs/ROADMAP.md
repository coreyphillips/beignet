# Beignet Feature Roadmap

Working checklist from the full feature-completeness review (2026-07-09). Items get
checked off as they land on master. Each substantive item gets its own branch + PR.
One milestone per session is the default pace; smaller milestones can share a session.

Legend: `[ ]` open, `[x]` done (PR #), `[~]` in progress, `[?]` needs a decision first.

---

## M0. Docs and discrepancy quick wins (small, do first)

- [x] Fix stale taproot comments claiming funding "cannot complete" (PR #32, merged).
      README line 520 was already accurate (experimental because the feature bit
      is staging upstream), so only the two source comments changed.
- [x] Resolve the `/channel/update-fee` naming trap (PR #33, merged): renamed to
      `/channel/update-commitment-feerate` with the old path kept as a deprecated
      alias; OpenAPI, docstrings and README clarified. Routing policy control
      itself is M3.
- [x] DECIDED (Corey): advertise dual-fund (28) and zero-conf (50) by default
      (PR #35, merged). Includes a trusted-peer gate rejecting a zero_conf
      channel_type from untrusted peers on both v1 and v2 open paths.
- [x] Sweep other defined-but-never-advertised bits for intent (PR #32, merged): each of
      LARGE_CHANNELS(18), ANCHOR_OUTPUTS(20), GOSSIP_QUERIES_EX(10),
      UPFRONT_SHUTDOWN_SCRIPT(4), OPTION_WILL_FUND(112), ROUTE_BLINDING(24),
      OPTION_TAPROOT(180/181) now documented in defaultFeatures(). Wumbo wiring
      itself is an M3 item.
- [x] Legacy v1 `open_channel` path did not validate chain_hash (the v2 path
      already did). Same guard added to `handleOpenChannel` + test (PR #34, merged).
- [x] `decodeInvoiceRequestTlv` returned a zero-buffer offerId placeholder;
      now computed from the mirrored offer TLV records, and
      `handleInvoiceRequest` reuses the decoded value + tests (PR #34, merged).

## M1. Recovery and backup (highest fund-safety impact)

- [x] Static channel backup (SCB) equivalent (PR #38, merged): portable, versioned,
      encrypted per-channel backup blob (peer pubkey, funding outpoint,
      basepoints/channel key index) that is sufficient to trigger the
      data-loss-protect recovery path. Export via library + daemon endpoint + CLI;
      auto-refresh on every channel open/close.
- [x] "We fell behind" recovery flow (PR #36, merged): reestablish proof marks the
      channel dataLossDetected + ERRORED (persist-first), sends a BOLT 1 error,
      refuses all local broadcasts (forceClose + stuck-channel timer), and sweeps
      only to_remote from the peer's THEIR_FUTURE_COMMITMENT via the chain monitor.
- [x] Taproot to_remote sweep in SCB recovery (PR #63, merged): the taproot output
      resolver bailed without remote basepoints or a per-commitment point, so a
      restored simple-taproot channel tracked its to_remote but never swept it.
      The taproot to_remote leaf pays our STATIC payment basepoint (like the
      static_remotekey and anchor variants), so it now resolves with zero peer
      key material; the full taproot key set is derived only for HTLC leaves.
      No SCB format change needed (v1 entries already carry channelKeyIndex +
      channelType). Proven live on regtest: open, SCB export, wipe, peer
      MuSig2 force-close, restore, sweep confirms after the 1-block CSV.
- [x] Restore API (PR #39, merged): daemon endpoint + CLI command that ingests a DB
      backup or SCB blob and starts recovery (previously restore was manual file
      placement; `POST /backup` had no counterpart).
- [x] Encryption at rest for the node SQLite DB (PR #37, merged): AES-256-GCM
      envelope encryption of sensitive tables (htlc_shared_secrets included) keyed
      via HKDF from the seed, default-on in BeignetNode with in-place migration and
      an opt-out flag.
- [x] Onchain wallet (PR #41, merged): documented that persistence encryption is
      delegated to the host TStorage, plus an optional built-in encryption wrapper
      (`createEncryptedStorage`, AES-256-GCM keyed via HKDF from the seed, lazy
      plaintext migration). Daemon audit: BeignetNode passes no wallet storage at
      all; persistence item added under M4.
- [x] DECIDED (Corey): Peer storage (PR #42, merged): option_provide_storage bit 42
      advertised, peer_storage (7) / peer_storage_retrieval (9) messages, server
      stores one encrypted blob per channel/trusted peer (rate-limited, returned on
      every reconnect), client pushes our seed-encrypted SCB to capable peers on
      each refresh and keeps the newest valid retrieved copy; recovery stays
      explicit via POST /restore/scb. No auto-restore.

## M2. Watchtower

- [x] Watchtower client (PR #48, merged): LND altruist wtwire protocol (public-tower
      interop), XChaCha20-Poly1305 v0 justice blobs shipped at every revocation,
      per-session Noise keys, persisted sessions + un-acked backlog with retry,
      config watchtowers[] URIs. Deferred + documented: anchor to_remote and
      taproot (v1 blob) coverage, reward sessions.
- [~] Anchor + taproot tower coverage (this PR): LND v1 (taproot) justice kits
      (300-byte plaintext pinned byte-exact to LND justice_kit_packet.go, same
      XChaCha20 envelope), tower-side reconstruction cross-checked against a
      REAL revoked taproot commitment. FIXES a fund-safety gap: anchor blobs
      previously shipped under the legacy session type with the anchor
      to_local weight, so an LND tower's reconstructed sweep value differed
      and the signature could never verify (anchor breaches unpunishable);
      anchor backups now negotiate blob-type-6 sessions and pack the P2WSH
      1-CSV to_remote. Per-blob-type session slots per tower (own session
      keys, graceful REJECT_BLOB_TYPE queueing, MAX_UPDATES rotation), schema
      v9 (blob_type on updates, session-key dialing flag). Live vs LND v0.20:
      6/6 including anchor and taproot sessions acked (LND v0.20 accepts blob
      type 10). Reward sessions remain out of scope.
- [x] Live LND tower interop (PR #62, merged): session negotiation, real
      revoked-commitment backups acked with advancing sequence numbers, and
      per-identity sessions validated against a real LND v0.20 altruist tower
      (docker lnd now runs --watchtower.active on 9911;
      tests/lightning/interop/watchtower-lnd.test.ts). Found and fixed a live
      bug: the wtwire regtest chain_hash constant was stored in display byte
      order, so a real regtest LND tower rejected Init with "unknown chain
      hash" (mainnet/testnet/signet were correct); CI regression tests pin all
      chain hashes to the interop-proven channel-layer constants.
- [?] Watchtower server mode (lower priority; decide whether beignet should offer it).
- [x] Document the single-process online-requirement (PR #48, merged: README limitations
      table updated alongside the tower client).

## M3. Routing-node operations

- [x] Routing fee-policy control (PR #40, merged): set base_fee_msat, fee_proportional_millionths,
      cltv_expiry_delta, htlc_minimum/maximum_msat per channel (and a node-wide
      default), regenerating channel_update. Library method + daemon
      `/channel/update-policy` + CLI. Internal pieces exist privately
      (`refreshChannelUpdate`, `maybeAdoptPeerChannelPolicy` in lightning-node.ts).
- [x] Forwarding history and fee accounting (PR #43, merged): persist settled forwards
      with amounts, fees earned, timestamps, channel pair; `listforwards`-style API via
      library + daemon `/forwards` + CLI.
- [x] Graph query surface (PR #44, merged): describegraph, getnodeinfo(pubkey),
      getchaninfo(scid), queryroutes via daemon `/graph/info`, `/graph/node`,
      `/graph/channel`, `/graph/describe` (paged), `/route/query` + CLI
      `graph`/`route query` commands (library `getGraph()` already existed).
- [x] Expose `sendPaymentToRoute` (PR #44, merged): daemon
      `/payment/send-to-route` + CLI `payment send-to-route`, composing with
      `/route/query` output.
- [x] option_wumbo (PR #45, merged): largeChannels config flag advertises LARGE_CHANNELS and
      lifts the 2^24 sat cap (10 BTC absolute ceiling) at every enforcement site incl.
      v1/v2 opens and three new splice capacity checks; acceptor gated on flag AND
      the peer's advertised bit.
- [x] Connect by node id alone (PR #45, merged): connectPeer(pubkey) resolves addresses from
      gossip node_announcement in announced order (Tor skipped without socks5Proxy,
      .onion re-encoded for dialing), DNS bootstrap fallback, error lists every attempt.
- [~] Advisor execution, phase 1 (this PR): rebalanceChannel (first-hop-pinned route,
      final hop via our own invoice hint, strict maxFeeSats abort BEFORE sending,
      HTLC-cap clamping) + executeRebalanceRecommendations with a persisted UTC-day
      fee budget; off by default.
- [~] Advisor execution, phase 2 (this PR): autoTuneFees loop nudging per-channel ppm
      +/-25% (floor/ceil clamped, one adjustment per channel per interval) from
      depletion + the #43 forwarding ledger via the #40 policy API; off by default.
- [x] Fee estimator sanity clamp (PR #45, merged): estimateFee output clamped to 5000 sat/vB
      (floor 1) at all five consumer sites with a structured warning when adjusted;
      sweep MAX_FEE_BUMP_MULTIPLIER untouched.

## M4. Daemon / CLI surface gaps (library has it, surface does not)

- [x] Hold invoices end to end (PR #47, merged): createHoldInvoice (caller-supplied hash),
      settleHoldInvoice, cancelHoldInvoice (works pre-accept, restart-safe),
      listHoldInvoices; CLTV auto-cancel respected and the near-expiry claim
      backstop no longer force-closes on parked holds with unrevealed preimages.
- [x] Onchain power endpoints (PR #49, merged): POST /send-max, /tx/bump-fee, /tx/boost
      (auto RBF-else-CPFP), GET /transactions/boostable, POST /consolidate
      (send-max-to-self). Also fixes the daemon wallet never signalling BIP 125
      (rbf was off, bump-fee was permanently dead).
- [x] Persist the daemon's onchain wallet state (PR #49, merged): TStorage adapter over the
      encrypted SQLite (wallet_data table, schema v8, per-network scoped twice: db
      file + key prefix); boots load from disk and refresh incrementally. Note:
      dailySpendLimit remains LN-only by existing design; onchain routes mirror
      /send (no accounting) - flagged for a future decision.
      DECIDED + implemented (PR #54, merged): combined LN+onchain daily budget; external
      onchain sends count amount+fee (send, send-max), consolidate/channel
      funding/fee bumps excluded; /spend-limit gains a breakdown.
- [x] sign/verify message with the node key (PR #47, merged): LND-compatible construction
      (prefix, double-SHA256, compact recoverable ECDSA, zbase32); live lncli
      cross-check noted as an interop follow-up.
- [ ] Onchain message signing (BIP322 plus legacy fallback) in the wallet layer.
- [x] Expose existing methods with no route (PR #47, merged): syncGossip, syncRapidGossip,
      getChannelDiagnostics, validateAddress, recoverFallbackFunds, triggerBackup
      all routed + CLI.
- [~] CLI parity sweep (this PR): every one of the 114 daemon routes now has a CLI
      command or a documented intentionally-none entry (/events SSE, /openapi.json,
      deprecated /channel/update-fee alias); enforced by a source-derived
      regression test that fails on future drift either way.
- [~] Event granularity (this PR): invoice:settled (never fires on keysend),
      channel:opening / pending-close / force-closing (local and remote, deduped),
      htlc:forwarded/fulfilled/failed behind an htlcEvents flag; all wired through
      SSE + webhooks with wildcard coverage. invoice:expired skipped: no issued-
      invoice expiry sweep exists (payer-side scan only); would be new machinery.
- [~] Seed generation parity (this PR): documented (README + OpenAPI): seed creation
      is CLI init only; GET /mnemonic reveals it only when apiToken is configured.

## M5. Onchain wallet features

- [x] Watch-only wallets (PR #51, merged): Wallet.createWatchOnly from any SLIP-132
      xpub/ypub/zpub/tpub/upub/vpub, full read-only surface, byte-identical
      derivation to the full wallet, every signing path guarded with a typed
      WatchOnlySigningError. Library-only (the daemon always has the mnemonic).
- [x] External-signer PSBT flow (PR #51, merged): buildPsbt (unsigned, with witnessUtxo,
      bip32Derivation fingerprint/path/pubkey, taproot fields, legacy
      nonWitnessUtxo), importSignedPsbt (validates every signature before
      finalizing, no broadcast), wallet.broadcastTransaction; daemon /psbt/build,
      /psbt/import-signed, /psbt/combine + CLI psbt commands.
- [x] PSBT combine for multi-party signing (PR #51, merged): combinePsbts.
- [x] Multisig / P2WSH (PR #57, merged; re-land of PR #55 which merged with red CI
      and was reverted in PR #56): Wallet.createMultisig, BIP 48 derivation,
      wsh(sortedmulti()) with BIP 67 ordering, watch-only coordinator support,
      spending exclusively via the PSBT flow with fail-closed threshold
      enforcement, descriptor export with checksums. Library-only. Re-land fixed
      the coin-select regression (applyMultisigInputWeights assumed a wallet is
      always attached; autoCoinSelect must work without one) and pinned that
      property with a regression test.
(Tor support for Electrum: DEFERRED by Corey 2026-07-10, moved to M7.)
- [x] Fee estimation privacy (PR #53, merged): feeEstimationSource 'auto' (default,
      Electrum first) | 'electrum' (never HTTP) | 'http'; every remote rate
      clamped to 5000 sat/vB.
- [x] Robust multi-server Electrum failover (PR #53, merged): deterministic ordered
      rotation with per-server 60s cooldown, then network fallback peers (never
      for regtest); lightning reconnect monitor untouched.
- [x] BIP21 URI generation (PR #53, merged): encodeBip21 + POST /address/new bip21
      option + CLI address --bip21.
- [x] Public UTXO freeze/unfreeze API (PR #54, merged): freeze/unfreeze/listFrozen +
      getBalanceBreakdown; ALSO fixes a live gap where the blacklist was only
      applied when the caller passed no explicit UTXO list.
- [x] Per-address user labels (PR #54, merged): setAddressLabel/getAddressLabel/list +
      daemon/CLI; the legacy IAddressData.label field is untouched.
- [x] Signet network support (PR #53, merged): full onchain + lightning (chain hash,
      coin type 1, daemon --network signet, default signet Electrum peer).
- [x] Wallet birthday (PR #54, merged): validated, persisted, earliest-wins metadata
      exposed in descriptors. Candid finding: the Electrum protocol has no
      height-filtered scans, so nothing is boundable today; documented as
      forward-looking for bitcoind/compact-filter backends.
- [x] Multi-account support (PR #54, merged): account option threaded through derivation
      and storage keys (account 0 keeps the legacy format); library-only, daemon
      stays single-account.
- [x] Descriptor export (PR #54, merged): all four script types with BIP 380 checksums
      validated against Bitcoin Core vectors; watch-only supported, no private
      key material ever emitted.
- [?] Silent payments (BIP352) receive/send. Larger effort; decide priority.
- [?] Payjoin (BIP78/BIP77). Decide priority.
- [?] Alternate chain backends (bitcoind RPC, Esplora). IChainBackend exists for
      lightning; onchain wallet is Electrum-coupled. Decide priority.

## M6. Security and auth hardening

- [x] Scoped API auth (PR #58, merged): multiple named API keys (apiKeys config) with
      readonly/invoice/admin scopes alongside the legacy apiToken (implicit
      admin); explicit route-to-scope map with a source-derived drift test,
      unclassified routes fail closed to admin-only; SHA-256 +
      crypto.timingSafeEqual comparison for named keys and the legacy token;
      401 vs 403 distinction; runtime revocation by name (POST /auth/keys/revoke)
      plus durable removal via config.
- [x] Remote/external signer interface (PR #60, merged): ISigner + SignerFactory in
      keys/signer.ts covering every channel-state-machine signature (funding
      digest, commitment/closing ECDSA, MuSig2 partial, second-level HTLC with
      per-commitment derivation INSIDE the signer, taproot Schnorr HTLC);
      ChannelSigner stays the in-process default constructed from the raw key
      Buffers; signerFactory injectable via INodeConfig/IChannelManagerConfig;
      zero behavior change, byte-identity pinned against pre-refactor vectors.
      Deliberately synchronous (documented): remote implementations orchestrate
      above the state machine; sync-to-async conversion noted as a follow-up.
      Note: ChainMonitor sweep/justice paths still consume raw basepoint
      secrets directly (separate surface, future work).
- [?] mTLS / client certificates for the daemon. Decide priority. (Discussed
      2026-07-10: low value while deployments are localhost/Tor; if ever
      needed, server-side HTTPS first, client certs as an opt-in on top.)
- [x] Key rotation (PR #66, merged; DECIDED by Corey 2026-07-10: auth material only,
      zero breaking changes): optional expiresAt per API key (ISO 8601,
      expired = 401 like a bad key), admin POST /auth/keys/rotate + CLI
      beignet auth rotate (new 32-byte secret shown ONCE, digest-only
      storage), and durable rotation/revocation overrides persisted in the
      encrypted wallet_data table (no schema bump), which also fixes PR #58's
      documented restart-resurrection hole for revoked keys. Config stays the
      source of truth for the key set; a config re-key supersedes stale
      overrides. Legacy apiToken unchanged (no name, no expiry, no rotation).
      Node identity/channel keys explicitly out of scope (not rotatable in
      Lightning without closing channels).
- [x] Leveled logging (PR #61, merged): platform-neutral src/logger.ts (ILogger
      debug/info/warn/error, createConsoleLogger with level filtering,
      noopLogger), injectable via Wallet config, INodeConfig, and
      BeignetNodeOptions; daemon --log-level flag / BEIGNET_LOG_LEVEL env /
      logLevel config writing to stderr (stdout stays reserved for command
      output, default silent); LightningNode mirrors structured-log entries to
      logger.debug; the persisted SQLite action log is untouched; defaults
      preserve pre-existing output at every call site.

## M7. Deferred / decide-later protocol features

Explicitly parked. Revisit each quarter or on ecosystem demand.

- [ ] BOLT12 refunds and recurrence
- [ ] Attributable failures (attribution_data)
- [ ] Trampoline routing
- [ ] AMP
- [ ] LSPS0/1/2 (client side first if Blocktank integration wants it)
- [ ] Dynamic commitments
- [ ] PTLCs
- [~] WebSocket transport (PROMOTED from parked by Corey 2026-07-10; this PR):
      IDuplexTransport interface over the existing TCP/SOCKS5 path (types-only
      diff, zero behavior change), browser-clean WS client against the
      standard WebSocket API with injectable constructor, in-repo RFC 6455
      Node client AND opt-in server (zero new dependencies; CLN's ws upgrade
      parser is case-sensitive so undici's lowercased headers cannot connect,
      hence the RFC-cased in-repo client), pubkey@ws:// and wss:// peer URIs,
      daemon/CLI additive connect forms + websocketPort config. Live vs CLN
      v26 over bind-addr=ws: handshake, ping/pong, channel to NORMAL,
      payments both directions, reestablish (5/5). Browser-blockers
      assessment recorded in the PR (crypto shim, storage backend, Electrum
      over WSS, DNS bootstrap, Buffer/net shims).
- [ ] Tor hidden-service inbound provisioning (external today, document setup)
- [ ] Legacy option_anchor_outputs bit 20 (likely never; modern bit 22 shipped)
- [ ] Tor support for Electrum (deferred 2026-07-10): route TCP/SSL through a SOCKS5
      proxy like the lightning transport already does.

---

## Suggested session order

1. M0 (one small PR, immediate wins)
2. M1 (SCB + fell-behind recovery + restore + DB encryption)
3. M3 fee-policy control + forwarding history (unblocks routing-node use)
4. M4 hold invoices + onchain power endpoints + sign/verifymessage
5. M2 watchtower client
6. M5 watch-only + external signer PSBT flow, then remaining M5 items
7. M6, then re-triage M7

## Session log

- 2026-07-09: Roadmap created from the four-domain feature review. No code changes yet.
- 2026-07-09 (same session): M0 executed as three PRs awaiting review: #32 (roadmap +
  taproot comment corrections + feature-bit gating docs), #33 (update-fee endpoint
  rename with deprecated alias), #34 (v1 open_channel chain_hash validation +
  invoice_request offerId computation). Open decision for Corey: default advertising
  of dual_fund/zero_conf, see the [?] item above.
- 2026-07-09 (later): M0 PRs #32-#34 merged; decision made to advertise dual_fund +
  zero_conf by default, landed as PR #35 (merged, includes untrusted-peer zero_conf
  channel_type rejection). M1 started: PR #36 open (fell-behind DLP recovery, suite
  3094/0); storage encryption at rest in progress in a parallel worktree.
- 2026-07-09 (cont.): M1 core merged as #36-#39 (DLP fell-behind recovery, storage
  encryption, SCB export, restore API). M3 started: routing fee-policy control.
- 2026-07-09 (cont.): PR #40 merged. M1 closers queued: wallet storage encryption
  wrapper + peer storage (option_provide_storage).
- 2026-07-09 (cont.): PR #42 merged, M1 fully closed. M3 resumed: forwarding history.
- 2026-07-10: PR #66 merged (key rotation). WebSocket transport (this PR)
  lands the browser-peer prerequisite live-proven vs CLN v26. Two
  pre-existing transport-independent bugs surfaced during interop and are
  QUEUED for their own fix branches: (1) CLN-funded channels desync after
  CLN sends update_fee (beignet HTLC then yields "Bad commit_sig" at CLN and
  a stale per-commitment secret on reestablish - the reason cln-interop Tier
  4/8 assertions are lenient); (2) upstream CLN quirk: case-sensitive
  WebSocket upgrade parsing, worth reporting to CLN.
- 2026-07-10: PR #64 merged (anchor + taproot tower coverage) and v0.4.0
  released (PR #65, tag v0.4.0 at 1ca36cf). Corey decided: key rotation
  scoped to auth material only (PR #66) and WebSocket transport promoted
  from M7 toward browser support (in progress in a parallel worktree); mTLS
  stays deferred.
- 2026-07-10: PR #63 merged (taproot SCB-recovery sweep). Anchor + taproot
  tower coverage (this PR) closes the last queued interop follow-up and fixes
  the anchor-blob session-type fund-safety gap; only [?] decision items remain
  on the roadmap (mTLS, key rotation, silent payments, payjoin, alternate
  chain backends, watchtower server mode).
- 2026-07-10: PR #62 merged (regtest wtwire chain-hash fix + live LND tower
  interop). Taproot SCB-recovery sweep (PR #63) closes the M1 known
  limitation; watchtower v1 taproot blobs in progress in a parallel worktree.
- 2026-07-10: PR #61 merged (leveled logging), closing the buildable M6 items.
  Interop follow-ups (this PR): lncli verifymessage cross-check passed live in
  both directions vs LND v0.20 (beignet signature recovers our exact pubkey
  via lncli verifymessage; LND signature verifies in beignet and recovers
  LND's identity key; no code change needed). Live LND tower interop test
  added, which caught and fixed the regtest wtwire chain_hash byte-order bug.
- 2026-07-10: PR #60 merged (ISigner abstraction). Leveled logging (PR #61)
  closes the buildable M6 items; remaining M6 entries are the mTLS and key
  rotation [?] decisions.
- 2026-07-10: PR #58 merged (scoped API auth) and v0.3.0 released (PR #59,
  tag v0.3.0 at the multisig re-land point for npm publish). ISigner
  remote-signer abstraction (PR #60) is M6 item 2 of 3; leveled logging
  follows.
- 2026-07-10: PR #57 merged (multisig P2WSH re-land). M6 started with three
  parallel branches: scoped API auth (PR #58), ISigner remote-signer
  abstraction, and leveled logging.
- 2026-07-10: multisig P2WSH re-landed (PR #57). PR #55 had merged with a red
  unit-test job through a merge-gate hole and was reverted in PR #56: its
  applyMultisigInputWeights helper dereferenced the wallet unconditionally,
  breaking autoCoinSelect on wallet-less Transaction instances (the six
  deterministic coin-select tests). Re-land tolerates a missing wallet, adds a
  regression test pinning wallet-less autoCoinSelect, and the merge gate is now
  strict (>= 3 check lines, all pass, empty output blocks).
- 2026-07-10: PR #54 merged (batch C). Multisig P2WSH (this PR) completes the
  active M5 items; also repairs README merge markers PR #54 shipped.
- 2026-07-10: PR #53 merged (Electrum layer). Batch C (this PR): combined spend
  limit per Corey, UTXO freeze (+ selection-gap fix), labels, birthday,
  multi-account, descriptor export. Multisig P2WSH next as its own PR.
- 2026-07-10: PR #51 merged (watch-only + PSBT flow; CI now isolates the offline
  suites from live-Electrum tests). PR #52 merged (untracked a node_modules symlink
  #51 accidentally committed; .gitignore pattern hardened). Batch B (this PR):
  Electrum fee source, failover, signet, BIP21 encode.
- 2026-07-10: PRs #49/#50 completed M4. M5 started; Tor-for-Electrum deferred to M7
  (Corey). DECIDED: dailySpendLimit becomes a combined LN+onchain budget (external
  sends count; consolidate/channel-funding/fee-bumps excluded) - lands in batch C.
  Batch A (this PR): watch-only wallets + external-signer PSBT flow.
- 2026-07-09 (cont.): PR #49 merged (batch 2a). Batch 2b (this PR): CLI parity
  sweep + event granularity + seed-gen note; completes M4.
- 2026-07-09 (cont.): PR #48 merged (watchtower client, M2 core). M4 batch 2a
  (this PR): onchain power endpoints + daemon wallet persistence.
- 2026-07-09 (cont.): PR #47 merged (M4 batch 1). Watchtower client (this PR)
  lands the M2 core.
- 2026-07-09 (cont.): PR #46 merged, M3 complete. M2 watchtower client prioritized
  (in progress, parallel) per Corey; M4 batch 1 (this PR): hold invoices,
  sign/verifymessage, unrouted-method exposure.
- 2026-07-09 (cont.): PR #45 merged (wumbo, connect-by-id, fee clamp). Advisor
  execution (this PR) completes M3.
- 2026-07-09 (cont.): PR #44 merged (graph queries + send-to-route). M3 small items
  (wumbo, connect-by-id, fee clamp) this PR; advisor execution lands next.
- 2026-07-09 (cont.): forwarding history merged as PR #43. M3 continued: graph query
  surface (graph info/node/channel/describe + route query) and sendPaymentToRoute
  exposure, one branch/PR for both since send-to-route consumes route-query output.
