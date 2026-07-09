# Beignet Feature Roadmap

Working checklist from the full feature-completeness review (2026-07-09). Items get
checked off as they land on master. Each substantive item gets its own branch + PR.
One milestone per session is the default pace; smaller milestones can share a session.

Legend: `[ ]` open, `[x]` done (PR #), `[~]` in progress, `[?]` needs a decision first.

---

## M0. Docs and discrepancy quick wins (small, do first)

- [~] Fix stale taproot comments claiming funding "cannot complete" (PR #32).
      README line 520 was already accurate (experimental because the feature bit
      is staging upstream), so only the two source comments changed.
- [~] Resolve the `/channel/update-fee` naming trap (PR #33): renamed to
      `/channel/update-commitment-feerate` with the old path kept as a deprecated
      alias; OpenAPI, docstrings and README clarified. Routing policy control
      itself is M3.
- [?] Decide: dual-fund (28) and zero-conf (50) are implemented but absent from
      `defaultFeatures()` (`lightning-node.ts:6347-6369`), so they never negotiate
      unless the host passes custom feature flags (config.localFeatures). Current
      gating documented in code (PR #32); Corey to confirm defaults or request
      config toggles.
- [~] Sweep other defined-but-never-advertised bits for intent (PR #32): each of
      LARGE_CHANNELS(18), ANCHOR_OUTPUTS(20), GOSSIP_QUERIES_EX(10),
      UPFRONT_SHUTDOWN_SCRIPT(4), OPTION_WILL_FUND(112), ROUTE_BLINDING(24),
      OPTION_TAPROOT(180/181) now documented in defaultFeatures(). Wumbo wiring
      itself is an M3 item.
- [~] Legacy v1 `open_channel` path did not validate chain_hash (the v2 path
      already did). Same guard added to `handleOpenChannel` + test (PR #34).
- [~] `decodeInvoiceRequestTlv` returned a zero-buffer offerId placeholder;
      now computed from the mirrored offer TLV records, and
      `handleInvoiceRequest` reuses the decoded value + tests (PR #34).

## M1. Recovery and backup (highest fund-safety impact)

- [ ] Static channel backup (SCB) equivalent: portable, versioned, encrypted per-channel
      backup blob (peer pubkey, funding outpoint, basepoints/channel key index) that is
      sufficient to trigger the data-loss-protect recovery path. Export via library +
      daemon endpoint + CLI; auto-refresh on every channel open/close.
- [ ] "We fell behind" recovery flow: on reestablish detecting our state is stale, do
      NOT broadcast; persist the peer's per-commitment point, wait for their unilateral
      close, sweep to_remote. Today the flow is protect-by-force-close only
      (`channel/channel.ts:4442-4496`).
- [ ] Restore API: daemon endpoint + CLI command that ingests a DB backup or SCB blob
      and starts recovery (today restore is manual file placement; `POST /backup` has
      no counterpart).
- [ ] Encryption at rest for the node SQLite DB (keys and preimages are currently
      cleartext). SQLCipher or app-level envelope encryption keyed from the seed.
- [ ] Onchain wallet: document that persistence encryption is delegated to the host
      TStorage, and provide an optional built-in encryption wrapper.
- [?] Peer storage (option_provide_storage, peer_storage/your_peer_storage messages):
      store an encrypted SCB with channel peers, retrieve on reconnect. Decide priority
      vs external backup targets.

## M2. Watchtower

- [ ] Watchtower client: encrypt and ship justice/penalty data per revoked state to a
      remote tower (LND altruist-tower wire protocol or a minimal custom protocol;
      decide at design time). Retry queue, tower health tracking.
- [?] Watchtower server mode (lower priority; decide whether beignet should offer it).
- [ ] Document the single-process online-requirement for penalty enforcement until the
      tower client ships (`chain-monitor.ts` justice path).

## M3. Routing-node operations

- [ ] Routing fee-policy control: set base_fee_msat, fee_proportional_millionths,
      cltv_expiry_delta, htlc_minimum/maximum_msat per channel (and a node-wide
      default), regenerating channel_update. Library method + daemon
      `/channel/update-policy` + CLI. Internal pieces exist privately
      (`refreshChannelUpdate`, `maybeAdoptPeerChannelPolicy` in lightning-node.ts).
- [ ] Forwarding history and fee accounting: persist settled forwards with amounts,
      fees earned, timestamps, channel pair; `listforwards`-style API via library +
      daemon `/forwards` + CLI.
- [ ] Graph query surface: describegraph, getnodeinfo(pubkey), getchaninfo(scid),
      queryroutes via daemon + CLI (library `getGraph()` already exists,
      `lightning-node.ts:1636`).
- [ ] Expose `sendPaymentToRoute` (`lightning-node.ts:3884`) through daemon + CLI.
- [ ] option_wumbo: advertise LARGE_CHANNELS, lift the 2^24 sat funding cap behind a
      config flag (`validation.ts:91-93`, MAX_FUNDING_SATOSHIS in types.ts).
- [ ] Connect by node id alone: resolve dial address from gossip node_announcement
      (NetworkGraph.getNode) with DNS bootstrap fallback.
- [ ] Advisor execution, phase 1: circular rebalancing (self-payment out one channel,
      in another) with budget caps, driven by existing REBALANCE recommendations.
- [ ] Advisor execution, phase 2: routing-fee auto-tuning loop (off by default).
- [ ] Fee estimator sanity clamp: upper-bound check on estimator output for LN ops
      (today only the sweep rebroadcast path has MAX_FEE_BUMP_MULTIPLIER).

## M4. Daemon / CLI surface gaps (library has it, surface does not)

- [ ] Hold invoices end to end: createHoldInvoice(hash), settleInvoice(preimage),
      cancelInvoice(hash) on BeignetNode + daemon + CLI. Internal machinery exists
      (heldInvoiceHashes, restart-safe parking in lightning-node.ts).
- [ ] Onchain power endpoints: sweep-all/send-max, bump-fee (RBF), boost (CPFP),
      consolidate. Library already has sendMax, setupRbf, setupCpfp.
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
