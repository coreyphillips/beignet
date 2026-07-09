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

- [ ] Watchtower client: encrypt and ship justice/penalty data per revoked state to a
      remote tower (LND altruist-tower wire protocol or a minimal custom protocol;
      decide at design time). Retry queue, tower health tracking.
- [?] Watchtower server mode (lower priority; decide whether beignet should offer it).
- [ ] Document the single-process online-requirement for penalty enforcement until the
      tower client ships (`chain-monitor.ts` justice path).

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

- [ ] Hold invoices end to end: createHoldInvoice(hash), settleInvoice(preimage),
      cancelInvoice(hash) on BeignetNode + daemon + CLI. Internal machinery exists
      (heldInvoiceHashes, restart-safe parking in lightning-node.ts).
- [ ] Onchain power endpoints: sweep-all/send-max, bump-fee (RBF), boost (CPFP),
      consolidate. Library already has sendMax, setupRbf, setupCpfp.
- [ ] Persist the daemon's onchain wallet state through encrypted storage: BeignetNode
      passes no storage to Wallet.create, so wallet state is in-memory and rebuilt from
      Electrum on every boot (startup cost grows with address history, full footprint
      re-queried against Electrum each start, labels/boost metadata forgotten). Fix is
      a small TStorage adapter over the encrypted SQLite (or createEncryptedStorage
      from PR #41) wired into beignet-node.ts. Correctness is unaffected today; this
      buys fast boots, less Electrum chatter, and durable metadata.
- [ ] sign/verify message with the node key (LND SignMessage compatible, zbase32) via
      library + daemon + CLI.
- [ ] Onchain message signing (BIP322 plus legacy fallback) in the wallet layer.
- [ ] Expose existing methods with no route: syncGossip, syncRapidGossip,
      getChannelDiagnostics, validateAddress, recoverFallbackFunds, triggerBackup.
- [ ] CLI parity sweep: wrap the ~25 daemon endpoints with no CLI command (keysend,
      webhooks, queue, route probe/estimate, payment proof/cancel/wait, update-fee,
      liquidity, logs, spend-limit, node/uri, channel health, can-send/can-receive,
      wallet/refresh).
- [ ] Event granularity: distinct invoice:settled event, channel:opening /
      channel:force-closing / channel:pending-close states, optional HTLC-level
      events; wire into SSE + webhooks.
- [ ] Seed generation endpoint parity check: document that seed creation is CLI-init
      only, or add a guarded daemon route.

## M5. Onchain wallet features

- [ ] Watch-only wallets: construct from xpub/ypub/zpub, address derivation and
      balance tracking without a mnemonic (constructor currently throws,
      `wallet/index.ts:184-185`).
- [ ] External-signer PSBT flow: build unsigned PSBT, export base64, import signed,
      combine, finalize as separate steps (today signPsbt always signs locally and
      finalizes, `transaction/index.ts:559-597`).
- [ ] PSBT combine for multi-party signing.
- [ ] Multisig / P2WSH address type (enum entry currently commented out,
      `types/wallet.ts:40`). Scope: descriptor-based multisig receive + spend.
- [ ] Tor support for Electrum: route TCP/SSL through the existing socks5Proxy config
      (socks dep already present; only lightning uses it today).
- [ ] Fee estimation privacy: optional Electrum-based estimatefee source so fee data
      does not leak to mempool.space/blocktank over clearnet.
- [ ] Robust multi-server Electrum failover: rotate through the provided server array
      on failure with health tracking.
- [ ] BIP21 URI generation (decode exists, encode does not).
- [ ] Public UTXO freeze/unfreeze API surfacing the internal blacklist.
- [ ] Per-address user labels (tx labels/tags exist; IAddressData.label is the type
      name, not user data).
- [ ] Signet network support (enums are bitcoin/testnet/regtest only).
- [ ] Wallet birthday / height checkpoint to bound rescans.
- [ ] Multi-account support (account index is hardwired to 0).
- [ ] Descriptor / backup export for the onchain wallet.
- [?] Silent payments (BIP352) receive/send. Larger effort; decide priority.
- [?] Payjoin (BIP78/BIP77). Decide priority.
- [?] Alternate chain backends (bitcoind RPC, Esplora). IChainBackend exists for
      lightning; onchain wallet is Electrum-coupled. Decide priority.

## M6. Security and auth hardening

- [ ] Scoped API auth: multiple named API keys with permission scopes (read-only,
      invoice-only, admin) replacing the single static bearer token; constant-time
      compare; key revocation.
- [ ] Remote/external signer interface for the node: abstract ChannelSigner behind an
      ISigner so keys can live out of process (raw Buffers in INodeConfig today,
      `node/types.ts:78-91`).
- [?] mTLS / client certificates for the daemon. Decide priority.
- [?] Key rotation strategy. Decide scope.
- [ ] Leveled logging (debug/info/warn/error) with injectable logger, alongside the
      existing structured action log.

## M7. Deferred / decide-later protocol features

Explicitly parked. Revisit each quarter or on ecosystem demand.

- [ ] BOLT12 refunds and recurrence
- [ ] Attributable failures (attribution_data)
- [ ] Trampoline routing
- [ ] AMP
- [ ] LSPS0/1/2 (client side first if Blocktank integration wants it)
- [ ] Dynamic commitments
- [ ] PTLCs
- [ ] WebSocket transport (relevant to the browser port)
- [ ] Tor hidden-service inbound provisioning (external today, document setup)
- [ ] Legacy option_anchor_outputs bit 20 (likely never; modern bit 22 shipped)

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
- 2026-07-09 (cont.): PR #45 merged (wumbo, connect-by-id, fee clamp). Advisor
  execution (this PR) completes M3.
- 2026-07-09 (cont.): PR #44 merged (graph queries + send-to-route). M3 small items
  (wumbo, connect-by-id, fee clamp) this PR; advisor execution lands next.
- 2026-07-09 (cont.): forwarding history merged as PR #43. M3 continued: graph query
  surface (graph info/node/channel/describe + route query) and sendPaymentToRoute
  exposure, one branch/PR for both since send-to-route consumes route-query output.
