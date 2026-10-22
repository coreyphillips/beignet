# Beignet Lightning Module

A pure-TypeScript Lightning Network implementation covering BOLTs 1-5 and 7-12, plus bLIP-51 liquidity ads. Built on `bitcoinjs-lib` for Node.js.

This is the protocol layer. For the higher-level, satoshi-denominated API (`BeignetNode`), the HTTP daemon, and the project's current limitations, see the [root README](../../README.md).

The [swaps module](swaps/README.md) provides P2WSH contracts, signed claim/refund transactions, direction-specific admission checks, the durable swap ledger and chain resolver, the swap wire protocol, and the reverse swap provider engine (Lightning to on-chain) through `beignet/lightning`'s `swaps` namespace. Both swap directions are served: the reverse provider (Lightning to on-chain) and the submarine provider (on-chain to Lightning, issue 743), each opt-in.

**Contents:** [Overview](#overview) · [Architecture](#architecture) · [Import paths](#import-paths) · [Quick start](#quick-start) · [Usage guide](#usage-guide) · [Events](#events-reference) · [Errors](#typed-payment-errors) · [Module reference](#module-reference) · [Testing](#testing) · [BOLT coverage](#bolt-specification-coverage)

## Overview

- **BOLT 1** Base protocol (init, error, ping/pong, peer storage)
- **BOLT 2** Channel management (open, close, HTLCs, dual funding, quiescence, splicing, zero-conf)
- **BOLT 3** Transaction scripts (funding, commitment, HTLC, revocation, anchors, taproot/MuSig2)
- **BOLT 4** Onion routing (Sphinx packets, route blinding, onion messages)
- **BOLT 5** On-chain handling (force close, sweep, output resolution, anchor fee bumping)
- **BOLT 7** Gossip (channel/node announcements, pathfinding, gossip sync, Rapid Gossip Sync)
- **BOLT 8** Encrypted transport (Noise_XK handshake, ChaCha20-Poly1305 framing)
- **BOLT 9** Feature flags (bitmap manipulation, init negotiation)
- **BOLT 10** DNS-based peer discovery (SRV records, seed nodes)
- **BOLT 11** Invoice encoding/decoding (bech32, amount, signatures, features, hold invoices)
- **BOLT 12** Offers (reusable payment requests, TLV encoding, Schnorr signing)
- **bLIP-51** Liquidity ads (lease rates, will_fund, CLTV-locked lessor output)

## Architecture

```
src/lightning/
├── bootstrap/       BOLT 10 DNS peer discovery, seed nodes
├── crypto/          ECDH, HKDF, ChaCha20-Poly1305, MuSig2 (BIP 327)
├── message/         Wire protocol codec, TLV, all message types
├── features/        Feature flag bit manipulation
├── transport/       BOLT 8 Noise handshake, encrypted Peer, PeerManager, WebSocket, Iroh
├── keys/            Key derivation, shachain, channel signer, wallet keys
├── script/          Funding, commitment, HTLC, revocation, anchor, taproot scripts
├── channel/         Channel state machine, commitment builder, ChannelManager,
│                    zero-conf, quiescence, dual-funding, splicing, liquidity ads
├── interactive-tx/  Collaborative TX construction (types 66-74)
├── chain/           Chain monitor, closing tx, sweep tx, output resolver
├── invoice/         BOLT 11 encode/decode, amount, signing
├── gossip/          Network graph, messages, validation, pathfinding, sync
├── onion/           Sphinx crypto, hop payloads, packet construction, route blinding
├── onion-message/   Type 513 onion messages, rate limiting
├── offer/           BOLT 12 offers, TLV encode/decode, Schnorr, merkle tree
├── async-payments/  AsyncPaymentManager, held-forward ledger, release capability
├── ffor/            FFOR Variant D offline receive: epochs, voucher book, witness and issuer
├── liquidity/       JIT channel receive (LSP and wallet roles)
├── direct-funding/  Third-party funding: request envelopes, transport lanes, receiver and payer
├── swaps/           Reverse and submarine swap providers, HTLC contract, ledger, chain resolver
├── l402/            L402 (HTTP 402) client: challenges, macaroons, paid credentials
├── recovery/        Recovery Protocol: atomic persistence, outbox, journal, capsules, guardians
├── watchtower/      Altruist watchtower client (LND wtwire, justice blobs)
├── backup/          Static channel backup (SCB) export/import
├── storage/         SQLite persistence, serialization
├── wallet/          Wallet funding provider integration
├── node/            LightningNode orchestrator
├── advisor/         Liquidity, fee, and channel suggestion advisors
├── validation/      Input validation utilities
├── index.ts         Barrel: one namespace per module above
└── sqlite.ts        beignet/lightning/sqlite: SqliteStorage, GuardianStore
```

### Data Flow

```
LightningNode
 ├── PeerManager (optional) ─── Peer ─── TCP/WebSocket/Iroh + BOLT 8 encryption
 ├── ChannelManager ─── Channel[] ─── commitment-builder (functions)
 │    ├── ChainMonitor ─── output-resolver, sweep
 │    ├── ZeroConfManager ─── trusted peer set
 │    ├── QuiescenceManager ─── STFU state machine
 │    ├── DualFundingSession ─── InteractiveTxBuilder
 │    └── SpliceSession ─── InteractiveTxBuilder
 ├── NetworkGraph ─── findRoute (Dijkstra), MissionControl
 ├── Onion (Sphinx) ─── construct / process / failures / blinding
 ├── OnionMessageManager ─── send / receive / forward (type 513)
 ├── OfferManager ─── create / request / pay (BOLT 12)
 ├── AsyncPaymentManager, AsyncReceiveService ─── hold invoices, held-forward, wake
 ├── WatchtowerClient (optional) ─── justice kits per revocation
 ├── RecoveryJournal (optional) ─── outbox, capsules, guardian replication
 ├── JitReceiveManager (optional) ─── LSP-side JIT channels
 ├── ReverseSwapProvider, SubmarineSwapProvider (optional)
 ├── FforWitnessService, FforIssuerService (optional)
 ├── Invoice ─── encode / decode (BOLT 11)
 ├── Bootstrap ─── DNS seed resolution (BOLT 10)
 └── Advisor ─── LiquidityAdvisor, FeeAdvisor, ChannelSuggestions
```

### Event System

Both `Channel` and `ChainMonitor` return action arrays (`ChannelAction[]` / `ChainAction[]`) rather than emitting events directly. `ChannelManager` processes these actions and emits higher-level events. `LightningNode` listens to `ChannelManager` events and provides the public event API.

When `PeerManager` is enabled, `ChannelManager.sendMessage()` routes through `PeerManager.sendToPeer()` with a fallback to `message:outbound` emission if the peer is not connected.

`OnionMessageManager` and `OfferManager` are both `EventEmitter` instances. `LightningNode` re-emits their events through the unified node event API.

## Import paths

`beignet/lightning` exports one **namespace per module**, not flat symbols. There is no `import { LightningNode } from 'beignet/lightning'`.

```typescript
// Namespaces (this is the shape of the barrel)
import { node, channel, gossip, invoice, onion, offer } from 'beignet/lightning';

const n = node.LightningNode.fromMnemonic(mnemonic, { network: invoice.Network.REGTEST });
const route = gossip.findRoute(graph, source, destination, amountMsat, finalCltv);
const decoded = invoice.decode(bolt11);

// Or grab the whole thing
import * as lightning from 'beignet/lightning';

// Types live in the same namespaces
import { node as ln } from 'beignet/lightning';
const config: ln.INodeConfig = { /* ... */ };
```

The SQLite stores have their own entry, because they need the native `better-sqlite3` module and nothing else in `beignet/lightning` does:

```typescript
import { SqliteStorage, GuardianStore } from 'beignet/lightning/sqlite';
```

`better-sqlite3` is an optional dependency. npm installs it by default, and each store loads it when constructed. Without it, `beignet/lightning` still loads, and constructing a store throws an error naming the missing module. `BeignetNode` and the `beignet` CLI build on `SqliteStorage`, so they need it too. `storage.SqliteStorage` and `recovery.GuardianStore` still work but are deprecated, and go in the next major release.

`storage.MemoryStorage` is a pure-JS backend that keeps everything in memory, and the starting point for a backend of your own (on a React Native SQLite binding, say). `IStorageBackend` is `IStorageCore`, which every backend implements, plus optional capability groups such as `IRecoveryStorage` and `IWatchtowerStorage`, named in `IStorageCapabilities`. `storage.hasStorageCapability(backend, 'watchtower')` says whether a backend has one. To check a backend, register the conformance suite from a mocha, Jest or Vitest test file:

```typescript
import { storage } from 'beignet/lightning';

storage.runStorageConformanceSuite(() => new MyStorage());
```

Keep the backend synchronous: persist-before-send relies on `transaction()` having committed when it returns.

Every example below assumes `node` is a `LightningNode` instance and uses these namespace aliases:

```typescript
import {
  gossip as gsp,
  invoice as inv,
  node as ln,
  features as feat
} from 'beignet/lightning';
```

### Prerequisites

- Node.js 22.23.4+, 24.22.1+ or 26.12.1+ with the `crypto` module
- `bitcoinjs-lib` with `@bitcoinerlab/secp256k1`
- `bech32` (BOLT 11 invoices)
- `better-sqlite3` (optional, for `beignet/lightning/sqlite`)

## Quick Start

> **Warning**: Do NOT use `crypto.randomBytes()` for production keys. Random keys cannot be recovered
> if lost. Always derive keys from a BIP39 mnemonic via `LightningNode.fromMnemonic()`.

```typescript
import { invoice as inv, node as ln } from 'beignet/lightning';

// Recommended: derive all keys from a BIP39 mnemonic.
// fromMnemonic() is synchronous and returns a LightningNode directly.
const node = ln.LightningNode.fromMnemonic(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  { network: inv.Network.REGTEST, enableNetworking: true }
);

node.on('payment:received', (payment) => {
  console.log('Received payment:', payment.paymentHash.toString('hex'));
});

node.on('payment:sent', (payment) => {
  console.log('Payment sent:', payment.preimage?.toString('hex'));
});
```

`network` is the `invoice.Network` enum (`Network.MAINNET` = `'bc'`, `TESTNET` = `'tb'`, `REGTEST` = `'bcrt'`, `SIGNET` = `'tbs'`), not a bare string. Its values are BOLT 11 invoice prefixes, so it is not the wallet's `Network` from `beignet`, whose values are `'bitcoin'`, `'testnet'`, `'regtest'` and `'signet'`.

> **Important**: `sendPayment()` returns synchronously with PENDING status.
> For AI agents and async workflows, use `sendPaymentAsync()`, which returns a
> Promise that resolves on settlement or rejects on failure/timeout.

For simpler usage (AI agents, quick prototyping), use the `BeignetNode` wrapper in `src/cli/beignet-node.ts`:

```typescript
import { BeignetNode } from 'beignet/cli';

const node = await BeignetNode.create({ mnemonic: '...', network: 'regtest' });
const invoice = node.createInvoice(1000, 'test payment');
// invoice => { bolt11: "lnbcrt10n1...", paymentHash: "ab12...", amountSats: 1000 }

const payment = await node.payInvoice(invoice.bolt11);
await node.destroy();
```

## Usage Guide

### Creating a LightningNode

`fromMnemonic()` covers most cases. Use the constructor when you need a config field it does not expose (for example `channelConfig`, `reestablishTimeoutBlocks`, `htlcSafetyMargin`, `signerFactory`, `resourceConfig`, or the individual basepoint secrets).

```typescript
const config: ln.INodeConfig = {
  nodePrivateKey,                      // 32-byte private key
  network: inv.Network.REGTEST,        // Network enum
  channelBasepoints,                   // IChannelBasepoints
  perCommitmentSeed,                   // 32-byte seed for per-commitment keys
  fundingPrivkey,                      // 32-byte funding key

  // Optional. IChannelConfig is NOT a partial: supply every field or omit it
  // entirely to take the defaults.
  // channelConfig: { dustLimitSatoshis, maxHtlcValueInFlightMsat, ... },

  // Networking (optional)
  enableNetworking: true,              // create PeerManager
  localFeatures: feat.FeatureFlags.empty(), // feature flags for init
  chainHashes: [chainHash],            // chain hashes for init
  autoReconnect: true,                 // auto-reconnect on disconnect
  maxReconnectDelay: 300_000           // max 5 min between retries
};

const node = new ln.LightningNode(config);
```

#### `INodeConfig` reference

Generated from `node/types.ts` by `npm run docs:tables`; edit the doc comments there, not the table. Only the four key fields are required. A row shows the first paragraph of a field's doc comment; the rest is in the source and the API reference.

<details>
<summary>All <code>INodeConfig</code> fields</summary>

<!-- options:INodeConfig:start -->
| Option | Type | Description |
|--------|------|-------------|
| `zeroReserve?` | `IZeroReserveConfig` | One-way reserve waivers for new private home channels. |
| `nodePrivateKey` | `Buffer` | The node identity key (32 bytes); its public key is the node id. |
| `network?` | `Network` | The network for invoices and chain hashes (default REGTEST). |
| `channelConfig?` | `IChannelConfig` | Parameters for new channels. Not a partial: supply every field or omit it to take the defaults. |
| `channelBasepoints` | `IChannelBasepoints` | This node's channel basepoints, the public keys channel keys derive from. |
| `perCommitmentSeed` | `Buffer` | 32-byte seed for the per-commitment secrets (shachain). |
| `fundingPrivkey` | `Buffer` | 32-byte private key for the 2-of-2 funding output. |
| `signerFactory?` | `SignerFactory` | Custom channel signer factory (ISigner) so channel signing keys can live out of process (remote/external signer). When set it replaces the internal ChannelSigner construction for every channel, keyed by the channel's key index. Library-level injection only (no transport). The raw key Buffers above remain required for non-signer paths (sweeps, chain monitors); with a factory they are simply never used to sign channel commitments. |
| `htlcBasepointSecret?` | `Buffer` | HTLC basepoint secret for signing HTLC second-level transactions |
| `revocationBasepointSecret?` | `Buffer` | Revocation basepoint secret for penalty sweeps |
| `paymentBasepointSecret?` | `Buffer` | Payment basepoint secret for to_remote claims |
| `delayedPaymentBasepointSecret?` | `Buffer` | Delayed payment basepoint secret for to_local claims |
| `fundingProvider?` | `IFundingProvider` | Funding provider for auto-funding channels (builds + broadcasts funding tx) |
| `enableNetworking?` | `boolean` | Enable PeerManager networking (default false — backward compatible) |
| `localFeatures?` | `FeatureFlags` | Features to advertise in init messages |
| `chainHashes?` | `Buffer[]` | Chain hashes for init messages |
| `autoReconnect?` | `boolean` | Enable auto-reconnection (default false) |
| `autoReleaseHeldForwards?` | `boolean` | Async receive (issue #708): when an LSP reports holds parked for this node, sign and send the release capability automatically for holds whose payment the node can vouch for (default true). Off, the host releases from the 'payment:held-notice' event via sendAsyncRelease. |
| `asyncReceiveService?` | `IAsyncReceiveServiceConfig` | Async receive service, LSP role (issue #709). Absent or `enabled: false` (the default): this node parks NO hold_htlc forward, advertises no ASYNC_RECEIVE_SERVICE bit and answers no registration; the marker is treated as an unknown odd TLV. Enabled: channel peers may register (signed grant with the ceilings and fee schedule below) and only holds under an active registration are admitted, within the limits. |
| `fforWitness?` | `IFforWitnessConfig` | FFOR D-R receipt witness (spec section 9.6): store a receiver-encrypted record of every delegated preimage this node relays, before propagating the fulfil, and serve it to the receiver on return. Disabled by default. |
| `fforIssuer?` | `IFforIssuerConfig` | FFOR BOLT 12 issuer (spec section 9.7): answer invoice_requests for offers a receiver delegated to this node, one fixed-amount slot per invoice. Needs `fforWitness` (the issuer is co-hosted with the first witness, whose mailbox holds the book). Disabled by default. |
| `fforSettle?` | `IFforSettlePolicy` | Whether this node answers ff_init as a settlement peer, and on what terms (issue #729). Absent answers on any terms (the library default); a daemon passes `enabled: false` unless its operator opted in. |
| `fforConcurrent?` | `object` | FFOR concurrent receive (docs/specs/CONCURRENT-RECEIVE.md). Enabled by default when option_ff_receive and option_quiesce are present. Explicit true requires both dependencies. Explicit false clears bits 562/563 and refuses peers requiring the feature. Epochs still select their profile explicitly. To refuse only new concurrent books, set `fforSettle.allowConcurrent: false` and retain this advertisement for existing books. The feature assignment remains experimental. |
| `fforConcurrent.enabled` | `boolean` | Advertise concurrent receive, feature bits 562/563. |
| `maxReconnectDelay?` | `number` | Max reconnect delay in ms |
| `maxInboundPeers?` | `number` | Inbound peer connections (default 125). Once this many are up, only peers holding a channel with this node are admitted. |
| `resourceConfig?` | `IResourceConfig` | Resource management config |
| `storage?` | `IStorageBackend` | Storage backend for persistence |
| `guardianHost?` | `IGuardianHostConfig` | Serve the reference guardian to other nodes over bolt8 sessions (docs/RECOVERY-GUARDIAN-WIRE.md 2.7, issue #699). Requires networking. Independent of this node's own `recovery` settings: a node can guard strangers while using no guardians itself, and keeps serving them while its own writer lease is quarantined (the guardian-only lane), which is what lets nodes that guard each other restart together. |
| `recovery?` | `object` | The Recovery Protocol journal and its guardian replication (docs/RECOVERY-PROTOCOL.md). Off unless `enabled` is true and the storage backend supports the journal. |
| `recovery.enabled?` | `boolean` | Keep the hash-chained recovery journal. |
| `recovery.durability?` | `RecoveryDurability` | How durable a safety transition must be before the wire messages it authorizes may reach the peer (5.8, Phase 6). Defaults to `async-remote`, which is the node's pre-Phase-6 conduct: fsync, continue, replicate in the background. |
| `recovery.barrier?` | `DurabilityBarrier` | The barrier itself (5.8, Phase 6). Built outside the node with its guardian set, exactly as `startupGate` is, and required whenever `durability` resolves to `quorum`. It also drives replication in every mode, so an `async-remote` node passes one too if it wants its journal replicated at all. |
| `recovery.maxRetainedFrameGap?` | `number` | Frames compaction will hold back for a guardian that has not caught up, before pruning anyway. |
| `recovery.snapshotIntervalFrames?` | `number` | Delta frames between full-state snapshots (default 256). |
| `recovery.snapshotIntervalBytes?` | `number` | Delta plaintext bytes between snapshots, whichever of the two limits trips first (default 4 MiB). |
| `recovery.startupGate?` | `GuardianStartupGate` | Startup ownership quarantine (5.6, Phase 5). A guardian-backed node MUST pass its gate HERE, at construction, never afterward: the constructor schedules auto-reconnect dials, so a gate installed later races them and can lose. With a gate present the node starts quarantined and refuses ALL peer contact, inbound and outbound, including connection establishment itself, until a guardian quorum confirms the writer lease via gate.confirm(); a proven newer epoch fences the node permanently instead. Omit only for a node genuinely running without guardians. |
| `recovery.guardians?` | `GuardianDescriptor[]` | Guardian locators embedded in every Recovery Capsule the node pushes to storage peers (5.4; wire 2.4 for the recoverable credential), so a seed restore finds the guardian set from peer storage alone instead of needing it from configuration. Pure data: the node never dials a descriptor, the barrier and gate above already hold the clients. `buildGuardianRecovery` fills this from the parsed set; a peer-storage-only node has none. |
| `recovery.unknownChannelReestablishHoldMs?` | `number` | How long an inbound channel_reestablish naming a channel this node has NO record of is held before the BOLT 1 error goes out (5.7, issue #462). Absent or 0 answers immediately, which is what every mode but peer-storage wants. |
| `chainBackend?` | `IChainBackend` | Chain backend for blockchain monitoring (Electrum, Esplora, etc.) |
| `htlcSafetyMargin?` | `number` | HTLC safety margin in blocks before force-failing expiring HTLCs (default 6) |
| `forwardingEnabled?` | `boolean` | Whether to relay third-party HTLCs (be a routing hop). Default true, which preserves the historical behaviour: any node with an announced channel forwards. Set false to decline all forwards (a wallet that does not want to route); declined forwards fail back promptly with temporary_node_failure, and our channel_updates advertise the BOLT 7 disable bit so route finders stop selecting us. Does not affect our own sends or receives. |
| `eagerGossipVerify?` | `boolean` | Whether to signature-verify foreign broadcast gossip at intake. Default false: entries are admitted with deferred provenance and verified only when a gossip query asks for them, which skips nearly the entire first-dump verification cost for wallet nodes (issue #443). Nothing unverified is ever served to gossip queries in either mode. Set true on relay-class nodes that want to serve the graph: intake and restore then verify eagerly, and signatureless RGS-primed entries are re-requested from peers so their signed copies become servable. |
| `cooperativeGraphRestore?` | `boolean` | Bring back the stored network map a time slice at a time after the constructor returns, rather than inside it (default false). A phone's JavaScript thread is otherwise held for seconds as its wallet opens. Until the restore ends, gossip that would write the graph waits for it, and route finding finishes it first (whenGraphRestored). |
| `jitReceive?` | `IJitReceiveConfig` | JIT channel receive, LSP role (issue #594): hold HTLCs addressed to intercept SCIDs this node minted for wallet peers, fund a zero-conf channel to the client (or splice its existing one bigger), then forward. Off unless `enabled` is set; the caps in IJitReceiveConfig are the only ceiling on what this node will front with its own coins. |
| `jitReceiveClient?` | `object` | JIT channel receive, WALLET role (issue #595): the most this node will let an LSP quote before `requestJitReceive` refuses the ack. Separate from `jitReceive`, which is the LSP role: a wallet that only receives runs no engine, and a node that runs the engine need not buy from anybody. Defaults are blunt refusal ceilings, not a price. |
| `jitReceiveClient.maxFlatFeeSat?` | `bigint` | Flat part ceiling (sat); default JIT_CLIENT_MAX_FLAT_FEE_SAT. |
| `jitReceiveClient.maxFeePpm?` | `number` | Proportional part ceiling (ppm); default JIT_CLIENT_MAX_FEE_PPM. |
| `directFunding?` | `IDirectFundingNodeConfig` | Third-party direct funding (issue #532 phase 4): an unrelated payer's on-chain payment becomes this node's channel funding. Absent means the whole feature, lanes included, is never constructed. |
| `swaps?` | `ISwapNodeConfig` | Swap provider foundations (issue #737): the durable swap ledger and the operator's exposure and confirmation policies. The provider engines arrive separately; with `enabled` the ledger is built and rehydrated at construction so no engine ever serves from an empty view. |
| `forwardingCltvDelta?` | `number` | CLTV delta for forwarding (default 40) |
| `forwardingFeeBaseMsat?` | `number` | Base fee in msat for forwarding (default 1000) |
| `forwardingFeePropMillionths?` | `number` | Proportional fee in millionths for forwarding (default 1) |
| `forwardingPolicyGraceMs?` | `number` | How long a forward may still satisfy the PREVIOUS policy after a fee or CLTV increase on a channel (default 600000, ten minutes; 0 disables). A receiver authors the relay terms of a blinded path from the policy it read at build time and a blinded payer cannot retry with new terms, so the window lets outstanding invoices survive a bump, the way a channel_update's grace does for cleartext forwards. |
| `mppTimeoutMs?` | `number` | MPP partial payment timeout in ms (default 60000) |
| `alias?` | `string` | Human-readable node alias (max 32 bytes UTF-8, per BOLT 7) |
| `announcedAddresses?` | `INodeAddress[]` | Addresses to advertise in our node_announcement (BOLT 7 descriptors, e.g. from parseAnnouncedAddress). Only meaningful once the node has at least one announced (public) channel. |
| `socks5Proxy?` | `object` | SOCKS5 proxy for outbound peer connections (e.g. Tor on 127.0.0.1:9050) |
| `socks5Proxy.host` | `string` | Proxy host. |
| `socks5Proxy.port` | `number` | Proxy port. |
| `socks5ProxyScope?` | `Socks5ProxyScope` | Which destinations ride socks5Proxy (default 'all'). 'all' sends every public host through it; 'onion' sends only .onion hosts through it and dials public clearnet directly (LND's tor.skip-proxy-for-clearnet-targets, "hybrid mode"). Private and loopback hosts are always dialed directly. Applies to peer dials and watchtower connections alike; it has no effect without socks5Proxy, since .onion then falls back to 127.0.0.1:9050 and everything else is direct already. |
| `webSocketImpl?` | `WebSocketConstructor` | WebSocket constructor for outbound WS peer connections. Defaults to the in-repo RFC-cased Node client under Node (CLN's ws listener rejects the built-in WebSocket's lowercased headers) and to globalThis.WebSocket in browsers. Only consulted when a peer is dialed with transport {type: 'ws'}; mirrors how electrumOptions injects net/tls. |
| `iroh?` | `IIrohConfig` | Opt-in Iroh endpoint, supplied by Node or a native mobile bridge. |
| `watchtowers?` | `string[]` | Watchtowers to ship encrypted justice data to at every revocation, as `pubkey@host:port` URIs (LND altruist wtwire protocol). Empty/undefined disables the watchtower client entirely. |
| `preferAnchors?` | `boolean` | Prefer anchor channels (option_anchors_zero_fee_htlc_tx) when opening channels |
| `largeChannels?` | `boolean` | option_wumbo (large_channels, bit 18, default false): advertise the bit and lift the BOLT 2 2^24 sat funding cap to MAX_WUMBO_FUNDING_SATOSHIS (10 BTC) for peers that also advertise it. Opens/accepts/splices with non-wumbo peers keep the 2^24 cap. |
| `preferTaproot?` | `boolean` | Propose simple taproot channels (option_taproot) when opening channels. MuSig2 funding and commitment signing (deterministic verification nonces) are fully wired into the live state machine; the complete lifecycle (open, payments both directions, reestablish, cooperative close, force close) is validated against LND on regtest. Off by default because the feature bit is still in staging upstream (180/181); not recommended for mainnet balances yet. |
| `leaseRates?` | `ILeaseRates` | Liquidity ads (bLIP-0051) SELLER policy: when set, an inbound open_channel2 carrying request_funds is answered with a signed will_fund at these rates and the requested contribution is funded from the node's on-chain wallet (fundingProvider). Leave unset to never sell leases. |
| `peerStorageEnabled?` | `boolean` | BOLT 1 peer storage (option_provide_storage, default true): store the latest peer_storage blob per channel/trusted peer and return it on reconnect, and push our own blob (set via distributePeerStorage) to capable peers. When false the feature bit is not advertised and both directions are disabled. |
| `feeEstimator?` | `IFeeEstimator` | Fee estimator for dynamic fee rates |
| `logger?` | `ILogger` | Leveled diagnostic logger (debug/info/warn/error). Defaults to a no-op logger (the node is silent today), so injecting one only adds output. Every structured action log entry is mirrored to logger.debug as "category:action" alongside the persisted action log. |
| `maxPaymentRetries?` | `number` | Maximum payment retries (default 3) |
| `maxTotalInFlightHtlcs?` | `number` | Global HTLC limit across all channels (default 1000) |
| `quiescenceTimeoutMs?` | `number` | BOLT 2 quiescence watchdog window in ms (default 60_000): "MUST disconnect after 60 seconds of quiescence if the HTLCs are pending". Injectable so tests can shrink it. |
| `nextChannelIndex?` | `number` | Starting channel key index (for per-channel HD derivation) |
| `channelKeyDeriver?` | `(channelIndex: number) => IPerChannelKeys` | Per-channel key derivation callback, producing unique keys per channel index. MUST be pure and deterministic: the same index has to answer with the same key material for the life of the wallet, since a channel's basepoints are committed to on chain while its signing secrets are re-derived on every restart and every recovery. |
| `newChannelsRefused?` | `() => string \| null` | Fence on brand-new channels (issue #906), passed through to the channel manager: while it answers a reason, every open, outbound or inbound, is refused with it and no channel key index is consumed. The daemon supplies it during active capsule auto-apply or a rebuild, and while its block height is zero. Idle or refused auto-apply permits opens at a nonzero height. Unset, opens are never fenced. |
| `rateLimitConfig?` | `object` | Per-peer rate limit config |
| `rateLimitConfig.maxHtlcsPerSecond?` | `number` | HTLCs per second per peer (default 30). |
| `rateLimitConfig.burstMultiplier?` | `number` | Bucket capacity as a multiple of maxHtlcsPerSecond (default 2). |
| `reestablishTimeoutBlocks?` | `number` | Number of blocks a channel can remain in AWAITING_REESTABLISH before force-closing (default 2016 ≈ 2 weeks) |
| `autoUpdateChannelFees?` | `boolean` | Periodically bump channel commitment feerates via update_fee from the fee estimator (default false). Off by default: an uncommitted/unsynced fee bump desyncs the commitment transactions and breaks subsequent HTLCs. |
| `sweepDestinationScript?` | `Buffer` | Output script that on-chain force-close sweeps (to_local after CSV, our to_remote claim on a remote force-close) pay into. Should be an address the caller's on-chain wallet owns and scans, so recovered funds show up in the wallet balance and are spendable. Defaults to P2WPKH(fundingPubkey) — an LN-key address the wallet does NOT track — for backward compatibility. |
| `autoRebalance?` | `IAutoRebalanceConfig` | Automatic circular rebalancing (default DISABLED). When enabled, a periodic scan runs the advisor's rebalance plan via executeRebalanceRecommendations, spending at most budgetSatsPerDay in routing fees per UTC day (tracked in memory and persisted via metadata). |
| `autoTuneFees?` | `IAutoTuneFeesConfig` | Automatic routing-fee (ppm) tuning (default DISABLED). When enabled, a periodic loop nudges each channel's proportional fee up 25% when its outbound side is depleted but still forwarding, and down 25% when it saw no forwards in the window, clamped to [floorPpm, ceilPpm]. |
<!-- options:INodeConfig:end -->

</details>

### DNS Bootstrap (BOLT 10)

```typescript
// Discover peers via DNS seeds
const peers = await node.bootstrapPeers();
// => IPeerAddress[] { pubkey, host, port }

// Discover and connect in one step
const connected = await node.connectToSeeds(3); // connect up to 3
// => string[] of connected pubkey hex strings

// Custom DNS seeds
const custom = await node.bootstrapPeers({
  seeds: [{ hostname: 'nodes.lightning.directory' }],
  maxPeers: 10,
  timeoutMs: 5000
});
```

### Peer Connections

**With networking enabled** (PeerManager + TCP):

```typescript
// Connect to a remote peer
await node.connectPeer(
  '02abc...def',    // remote node pubkey (hex)
  '127.0.0.1',      // host
  9735              // port
);

// List connected peers
const peers = node.listPeers();
// => [{ pubkey, host, port, state, remoteInit }]

// Disconnect
node.disconnectPeer('02abc...def');
```

**Without networking** (test/simulation mode):

```typescript
// Wire two nodes via event loopback
nodeA.on('message:outbound', (pubkey, type, payload) => {
  if (pubkey === nodeB.getNodeId()) {
    nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
  }
});
nodeB.on('message:outbound', (pubkey, type, payload) => {
  if (pubkey === nodeA.getNodeId()) {
    nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
  }
});

// The node cannot drop a transport it does not own. When it needs a peer
// disconnected (durability barriers, the BOLT 2 quiescence watchdog), it
// asks the host: stop relaying for that peer, then resume later as a
// reconnect (the node has already marked the channels for reestablish).
nodeA.on('peer:disconnect-requested', (pubkey) => {
  // e.g. close the websocket/queue backing this peer's relay
});
```

### Channel Lifecycle

```typescript
// 1. Open channel (sends open_channel message)
const channel = node.openChannel(peerPubkey, 1_000_000n); // 1M sats

// 2. Create funding transaction (skip when a fundingProvider is configured:
//    it builds, signs and broadcasts the funding tx for you)
const channelId = node.createFunding(channel, fundingTxid, outputIndex, signature);

// 3. Confirm funding (after tx is mined). When the open was RBF'd
//    (multiple funding attempts exist), the confirmed txid is REQUIRED:
//    pass it in display byte order so the right attempt is adopted; an
//    ambiguous call is refused.
node.handleFundingConfirmed(channelId);
node.handleFundingConfirmed(channelId, confirmedTxidHex); // after an RBF
// Emits 'channel:ready' when both sides confirm

// 4. Normal operation: send/receive HTLCs

// 5. Cooperative close
node.closeChannel(channelId, scriptPubkey);

// 5b. Force close (unilateral)
node.forceCloseChannel(channelId, destinationScript);
```

### Zero-Conf Channels

Open channels that are usable immediately, before the funding transaction confirms. Only use with trusted peers.

```typescript
// Add a trusted peer for zero-conf
node.addTrustedPeer('02abc...def');

// Open a zero-conf channel
const channel = node.openZeroConfChannel(peerPubkey, 500_000n);
// Channel reaches NORMAL state after funding_signed, no confirmation wait

// Manage trusted peers
node.listTrustedPeers();  // => string[]
node.removeTrustedPeer('02abc...def');
```

### Anchor Channels

Anchor channels (`option_anchors_zero_fee_htlc_tx`, BOLT 3) add two 330-sat anchor outputs to commitment transactions, enabling CPFP fee bumping. HTLC second-level transactions use zero fees and `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY`.

**Anchors are the default channel type** (matching LND/CLN/Eclair). When a funding provider is configured, beignet attaches wallet-funded fee bumps so anchor force-closes confirm: zero-fee second-level HTLC txs get a wallet fee input attached, and the commitment is CPFP-bumped via its local anchor output.

```typescript
// Anchors are negotiated by default, no config needed.
const node = new ln.LightningNode({ ...config });

// Escape hatch: force legacy static_remotekey (non-anchor) channels.
const legacyNode = new ln.LightningNode({ ...config, preferAnchors: false });

// Channels negotiate the anchor channel_type with peers that also support it,
// and fall back to non-anchor with peers that don't.
```

### Simple Taproot Channels

`preferTaproot: true` negotiates `option_taproot` channels: MuSig2 funding output, taproot commitments and Schnorr HTLC signatures. Experimental, and the feature bit is still in staging upstream. Not recommended for mainnet balances.

```typescript
const node = new ln.LightningNode({ ...config, preferTaproot: true });
```

### Dual-Funded Channels (v2)

Open channels where both peers contribute funding.

```typescript
const channel = node.openChannelV2(peerPubkey, {
  fundingSatoshis: 1_000_000n,       // our contribution
  fundingFeeratePerkw: 253,          // optional, defaults to channel config
  commitmentFeeratePerkw: 253,       // optional
  locktime: 0                        // optional
});
// Negotiation proceeds: open_channel2 -> accept_channel2
// -> interactive TX construction (tx_add_input, tx_add_output, tx_complete)
// -> tx_signatures -> channel_ready
```

**RBF of a v2 open.** A stuck unconfirmed v2 funding tx can be fee-bumped in
the BOLT 2 window, in both directions and against Eclair/CLN peers (issue
#360): from the initial commitment exchange until `channel_ready` crosses in
either direction or an attempt confirms. As the opener:

```typescript
// Feerate must clear the BOLT 2 floor:
// max(floor(previous * 25 / 24), previous + 25) sat/kw.
const result = node.rbfOpenChannelV2(channelId, newFeeratePerkw);
if (!result.ok) console.log(result.error); // refusal reason, nothing sent

// Optionally change OUR contribution to the funding output for the
// replacement (BOLT 2 allows a different one per attempt; issue #376).
node.rbfOpenChannelV2(channelId, newFeeratePerkw, undefined, 150_000n);
```

By default the renegotiation reuses the wallet inputs registered for the open,
repriced at the new feerate; superseded broadcastable attempts are retained
durably and chain-watched beside the current one (each replacement
double-spends all of its predecessors, so at most one can confirm), and
whichever attempt confirms is adopted. Per BOLT 2, an inbound `tx_init_rbf` is
always answered with `tx_ack_rbf` or `tx_abort`, and a refusal is
attempt-scoped: only the replacement attempt dies, both sides keep the current
attempt and the channel lives on.

Either side may also change its `funding_output_contribution` from one attempt
to the next. Capacity, both balances and both capacity-derived channel reserves
are then per-attempt: every record snapshots the amounts its commitment #0 was
built at, and each rollback, adoption and restart restores them along with the
funding outpoint. Lowering our own contribution, or raising it within what the
registered inputs already cover, is answered synchronously; a larger raise
selects the shortfall from the wallet in the background, so the call returns
optimistically and a failure arrives as a `node:error` with code
`RBF_OPEN_FAILED`. An **absent** TLV means "unchanged" rather than the spec's
"not contributing", for compatibility with beignet peers predating the field (a
peer that stops contributing entirely fails the funding-output audit
attempt-scoped). A change is refused, attempt-scoped, when the new capacity
would exceed the channel maximum or fall below the funding-output dust floor, or
when it fails any of the three initial-commitment rules below.

A v2 open, and every RBF replacement, is admitted against three separate rules on
the commitment it is about to build. The first two are BOLT 2's receiver
MUST-fails, which `open_channel2` and `accept_channel2` inherit from their v1
counterparts: the funder must be able to pay commitment #0's fee, and both
outputs must not be at or below the channel reserve. The third is beignet's own,
and covers what the reserves cannot: each commitment trims at ITS OWN holder's
`dust_limit_satoshis`, while the reserve enforced on the peer deliberately floors
at the LOWER of the two, so on an asymmetric-dust channel a balance above that
reserve can still be dust in the commitment we hold. A split is therefore also
refused when the larger of the two post-fee balances falls below the larger of
the two dust limits, which is exactly the condition for one of the commitments to
have no outputs at all. Commitment #0 carries no HTLCs and an anchor output only
exists alongside a surviving main output, so nothing else can keep it non-empty.
The comparison is strict: the builder trims a value below the dust limit and
keeps one that lands exactly on it, so a split whose larger balance equals the
larger dust limit is admitted. At that boundary the larger balance clears both
dust limits and is an output in both commitments, while the smaller one is
trimmed from at least the commitment held by whichever peer has the larger dust
limit, and may still survive in the other. A transaction with no outputs cannot
be broadcast, so a side holding one would have no unilateral exit from the
funding output at all.

A v2 channel exchanges no `channel_reserve_satoshis` at all: BOLT 2 fixes it at
1% of the total capacity or the `dust_limit_satoshis`, whichever is greater, with
no maximum, and both peers derive it. The spec does not say whose dust limit
floors it (eclair and CLN disagree), so beignet derives the two sides by safety
direction: the reserve it keeps takes the greater of the two dust limits, so its
reserve output is never dust in either commitment, and the reserve it enforces on
the peer takes the lesser and skips beignet's own 546-sat policy floor, so it can
never exceed what a conforming peer computes for itself and reject a legal HTLC.

Enforcing the lesser value is inert against the peer's own gate but not against
our own trim threshold, so the admission rule above has a counterpart on the two
peer-driven updates that can move a balance under it. An inbound
`update_add_htlc` or `update_fee` that would leave
the commitment WE hold with no outputs at all is refused, asked of a candidate
commitment built by the real builder rather than of a second copy of its
arithmetic, and skipped entirely whenever the reserve we enforce already sits at
or above our own dust limit (which is every symmetric-dust channel, so ordinary
traffic never pays for the check). `getSpendableOutboundMsat` is floored at the
same dust limit so our own sends cannot reach the state either, and
`prepareForceClose` refuses to return a plan whose commitment has no outputs
instead of handing back a transaction the network will reject. While a fully
signed splice awaits its lock, the same candidate is also re-anchored on the
pending splice funding (`_splicedState`) and refused if THAT commitment would be
empty. The spliced half is evaluated even on symmetric-dust channels: the
enforced reserve bounds only the live balance, not the spliced remainder a peer
splice-out leaves behind, since reserves are not re-derived until the lock.

Two repairs run when a channel is restored from disk, one per reserve, each
moving only in its own safe direction. The reserve we ENFORCE is lowered to what
the row's capacity prices, since over-enforcing refuses an HTLC the peer believes
is legal and force closes; the reserve we KEEP is raised to what a v2 capacity
derives, since under-keeping means the peer refuses our next HTLC instead, and it
costs only spendable balance. A v2 open still in flight from before either
reserve was derived has both derived when its record is restored, and is refused
outright, rather than resumed, when its commitment #0 has no outputs and our
witnesses can still keep the funding transaction off chain.

### Refusals the peer can see

A `ChannelActionType.ERROR` is a LOCAL event. It drops a temporary channel and
tells the embedder; it never becomes bytes. Only a `SEND_MESSAGE` carrying
BOLT 1's `error` reaches the peer, so a refusal built out of the former deletes
our half of a negotiation while the peer stays parked on a message it will never
get an answer to, or keeps an update in its book that our commitment will never
hold. The channel still dies in that second case, but a round later on a
signature mismatch rather than on the refusal that actually happened.

A refusal is therefore put on the wire when both hold: it is unconditional and
permanent, so the peer's view provably diverges the moment we return; and no
legal in-flight crossing can produce it, so the predicate turns only on facts
the peer already held when it sent. Handshake refusals use the lighter shape
(wire error, then the local `ERROR`, in that order so the temporary channel is
still tracked when the cancellation reaches the transport), and update-path
refusals use `_failChannelWithWireError`, which marks the channel `ERRORED` and
persists first. Both suppress the wire half under BOLT 1's reserved all-zero
`channel_id`, which would read as "fail every channel you have with me".

The second clause is what keeps the carve-outs local, each argued at its guard:
the id-mismatch guards, since the id in the message is one we do not own; the
half of the quiescence guard where only WE have sent `stfu`, since the peer is
bound only from its own; and the lifecycle guards.

Those lifecycle guards are the subtle ones, and refusing was the wrong answer in
one case. An `update_add_htlc` that crossed our own `shutdown` is conformant
(BOLT 2 forbids one only after the peer has RECEIVED our shutdown) and is now
ACCEPTED rather than refused: dropping it did not spare the channel, it deferred
the death by one round and mislabelled it, because the peer's covering
`commitment_signed` was then verified against a commitment missing the HTLC and
failed. `handleCommitmentSigned` already accepts `SHUTTING_DOWN` for exactly
this reason.

The remaining lifecycle refusals stay local even where the peer has provably
bound itself, which is a decision and not an oversight. Nothing cascades from
them: outside `NORMAL` and `SHUTTING_DOWN` the covering `commitment_signed` is
refused by its own state gate, so the update stalls rather than force-closing.
And condemning there would force close conformant peers, because
`handleReestablish` replays every queued `update_add_htlc` and `update_fee`
after a reconnect while `remoteShutdownScript` is persisted, and because this
implementation parks taproot channels in quiescence for longer than the splicing
spec requires. The `SENT_STFU` window is closed (issue 411): a crossing add is
accepted, its disposition is parked at the node until quiescence ends, and the
manager's quiescence watchdog enforces BOLT 2's 60-second disconnect when a
session stalls with HTLCs pending.

The same replay machinery derives the crash-replay carve-outs (issue 409): a
peer restored from a legally lagging snapshot replays its whole pending update
queue on reestablish, so a fulfill or fail can land on an HTLC entry the
completed round already deleted ("HTLC not found" stays bare), and our own
lagging restore can resurrect a COMMITTED entry while the peer's ledger is
legitimately HTLC-free (the pending-HTLC `closing_signed` arm stays bare and
self-heals as the replayed round drains). The taproot `closing_signed`
nonce-exchange arm also stays bare: its predicate mixes our own unpersisted
restart state with reestablish ordering, never provable peer divergence.

Closing-negotiation refusals are otherwise wire-visible by the same two
clauses read against the negotiation itself rather than the update logs: an
invalid closing signature (checked on EVERY fee branch, and against both BOLT
3 closing variants, including the one where the signer eliminated its own
output), a malformed TLV, a non-echoed taproot fee, or a fee violating the
dust limit we advertised at open or the shared ledger balance turns only on
bytes and facts the peer held when it sent, and the single-round taproot
session can never recover in-session, so a bare refusal is an unbounded stall
nobody is told about. The taproot responder FEE BAND is the argued exception
and stays local: it is derived from our private feerate estimate, a fact the
peer never held, so a conformant initiator with a fresher fee view can land
there on a perfectly payable fee. `handleShutdown` now runs its lifecycle
gate FIRST so its wire-visible content checks (missing MuSig2 nonce, invalid
scriptPubkey) can only fire on a live channel, and a close-family payload
that fails to DECODE (a wrong-length TLV the handler checks can never see)
is failed on the wire by the manager, scoped to the channel id at the
payload's fixed offset.

Deliberate refusals (all spec-legal): replacements of an open restored from a
restart (the wallet signing closures die with the process; confirmation
adoption still works), contribution changes on a leased open (bLIP-51: the
`will_fund` signature and the lease fee were made over the original amounts),
and non-opener initiation (see the `dual-funding.ts` module header for the full
semantics).

### Liquidity Ads (bLIP-51)

Set `leaseRates` to advertise as a lessor: peers can then request funds in an
open_channel2 and beignet replies with `will_fund`, contributes the leased
capacity, and CLTV-locks its own `to_local` output for the lease term.

```typescript
const lessor = new ln.LightningNode({
  ...config,
  leaseRates: {
    fundingWeightWitness: 666,   // per-input funding weight, for the mining-fee share
    leaseFeeBasis: 100,          // proportional lease fee, in 1/10_000 of the lease
    leaseFeeBaseSat: 500,        // flat lease fee, satoshis
    channelFeeMaxBaseMsat: 1000, // max routing base fee we may charge over the term
    channelFeeMaxProportionalThousandths: 10
  }
});
```

### Splicing

Add or remove funds from an existing channel without closing it. Requires quiescence (STFU protocol).

```typescript
// Splice-in: add 100,000 sats to the channel
const inResult = node.spliceIn(channelId, 100_000n, 253);
// => { ok: boolean; error?: string; code?: SpliceRefusalCode }

// Splice-out: withdraw 50,000 sats from the channel
const outResult = node.spliceOut(channelId, 50_000n, 253);
// => { ok: boolean; error?: string; code?: SpliceRefusalCode }

// A refusal carries both the sentence and the code that classifies it
// (CHANNEL_NOT_FOUND, SPLICING_NOT_NEGOTIATED, INVALID_PARAMS,
// INSUFFICIENT_BALANCE, FUNDING_PROVIDER_REQUIRED, SPLICE_BUSY,
// SPLICE_REFUSED). SPLICE_BUSY is the one to retry unchanged: the channel
// would splice but is held off by a state that ends on its own (an
// unacknowledged abort, a peer-owned quiescence session, settling HTLCs,
// a peer reconnecting).
// `ok: true` means the splice started, not that it completed: the outcome
// arrives on splice:complete, splice:aborted or node:error.

// Flow: STFU exchange -> splice/splice_ack -> interactive TX
// -> tx_signatures -> splice_locked (both sides)
```

### Third-party funding inputs (library only)

An input someone else owns can fund a v2 open or a splice-in. It is contributed
and negotiated like any of ours, but its `signWitness` is never called, our
`tx_signatures` is withheld, and the finished witness arrives out of band.

```typescript
// Register the inputs ahead of the negotiation, bypassing wallet selection.
node.openChannelV2(peerPubkey, {
  fundingSatoshis,
  contribution: { inputs, changeScript }   // issue #572
});
node.spliceInWithInputs(channelId, amountSats, inputs, changeScript, 253);

// What the owner signs against: a defensive copy of the negotiated tx, the
// full prevout set BIP 341 commits to, and the outpoints still owed.
node.getPendingV2FundingTx(channelId);  // v2 open,   issue #612
node.getPendingSpliceTx(channelId);     // splice-in, issue #592

// Where the witness goes back. The last one released the withheld
// tx_signatures; `sendsWithheld` says it did not actually reach the peer.
node.provideV2ExternalWitness(channelId, prevTxid, prevOutputIndex, witness);
node.provideSpliceExternalWitness(channelId, prevTxid, prevOutputIndex, witness);

// For a host driving the state machine directly (resolves a v2 open still
// resident under its temporary id).
node.getRawChannel(channelId);
```

None of this has a daemon or CLI surface, deliberately. `POST /channel/open-v2`
and `POST /channel/splice-in` take no `fundingUtxos` and no `contribution`, and
no route accepts a witness. The only in-tree consumer is the direct-funding
engine, which runs in process; over HTTP the same calls would let anything
holding an API token choose the inputs of this node's funding transactions and
co-sign them, which is a larger trust decision than an API token carries today.

### Invoice Management

```typescript
// Create an invoice, returning { bolt11, paymentHash, paymentSecret }
const result = node.createInvoice({
  amountMsat: 50_000_000n,     // 50,000 sats
  description: 'Coffee',
  expiry: 3600,                // optional, default 3600s
  minFinalCltvExpiry: 40       // optional, default 40
});
// result.bolt11 => "lnbcrt500u1..."
// result.paymentHash => Buffer (32 bytes)
// result.paymentSecret => Buffer (32 bytes)

// Or use descriptionHash for long/structured metadata (> 639 bytes)
import crypto from 'crypto';
const metadata = JSON.stringify({ orderId: '12345', items: ['...'] });
const descHash = crypto.createHash('sha256').update(metadata).digest();
const result2 = node.createInvoice({
  amountMsat: 50_000_000n,
  descriptionHash: descHash
});

// Decode any BOLT 11 invoice
const decoded = inv.decode(result.bolt11);
// => { paymentHash, amountMsat, description, network, ... }
```

### Hold Invoices & Async Receive

A hold invoice parks matching HTLCs instead of settling them, which underpins escrow-style flows and async receive for an offline recipient.

```typescript
// Park incoming HTLCs instead of settling. Omit paymentHash to let the node
// generate the preimage; supply one when the preimage is held elsewhere.
const held = node.createInvoice({
  amountMsat: 50_000_000n,
  description: 'Escrow',
  hold: true
});

node.on('htlc:held', (info) => console.log('parked', info));

node.settleHeldHtlc(held.paymentHash);      // reveal the preimage, settle
node.cancelHoldInvoice(held.paymentHash);   // fail the HTLCs back
node.listHoldInvoices();                    // hold invoices + their state

// Async receive: mark the LSP hop of a blinded path with hold_htlc so the
// always-online LSP parks the HTLC until this node comes back and releases it.
node.createInvoice({
  amountMsat: 50_000_000n,
  description: 'Async',
  useBlindedPaths: true,
  asyncHold: true
});
```

#### Held forwards on the LSP (issue #708)

An LSP that sees `hold_htlc` on its blinded hop parks the inbound HTLC in a
durable **held-forward ledger** (`async-payments/held-forward-ledger.ts`)
rather than a memory map:

- **Identity.** Every held HTLC gets a random 32-byte `hold_id` and keeps its
  canonical `(incoming_channel_id, incoming_htlc_id)`. The payment hash is an
  index that groups parts; it is never the key, so MPP parts, retries and
  duplicate adds each get their own row.
- **Lifecycle.** `HELD -> RELEASING -> RELEASED` and `HELD -> FAILING ->
  FAILED` (plus `RELEASING -> FAILING` for a release whose add could never be
  placed). Every arrow is a compare-and-swap on the durable row, so duplicate
  messages, replayed channel updates and crash re-drives are idempotent. The
  row is written before anything acts on the hold, and a restart rehydrates
  the ledger at construction, before any transport exists, so no release is
  ever judged against an empty ledger.
- **Authorization.** Release is never by payment hash (every invoice discloses
  it). The receiver signs a **release capability** with its node key over a
  tagged digest (`async-payments/release-capability.ts`) binding: chain hash,
  receiver node id, LSP node id, registration id (the value of the `hold_htlc`
  marker, derived per (receiver, LSP) pair until issue #709's service
  registration replaces it), the exact amount, an expiry, a random nonce, and
  the complete sorted set of `hold_id`s. The LSP checks the onion message's
  sender is the receiver the capability names AND the receiver the hold
  recorded (the peer on the outgoing channel), then verifies the signature.
- **MPP policy.** *Atomic payment-set release* is the default: only the
  receiver knows `total_msat` (it is inside the blinded final payload), so it
  signs one capability over the complete set once the parts cover the invoice
  amount, and the LSP moves the whole set `HELD -> RELEASING` in one
  transaction or not at all. *Independent part release* is the same call with
  a set of one, which a receiver uses for amount-less invoices. Set by
  `autoReleaseHeldForwards` (default true); with it off, the host releases
  from the `'payment:held-notice'` event via `sendAsyncRelease`.
- **CLTV cutoff.** Fixed on the row when parked:
  `min(forwardCltv - DEFAULT_MIN_FINAL_CLTV_EXPIRY, incomingCltvExpiry - max(18, htlcSafetyMargin))`.
  Release is accepted strictly below it; at it the per-block scan moves the
  hold to `FAILING` and fails it upstream off-chain. Both are CAS transitions
  from `HELD` on the same row, so a release racing the cutoff has exactly one
  durable winner.
- **Restart.** The restore-time redispatch re-enters the hold path and finds
  the same row (same `hold_id`), re-arming the driver and driving a
  `RELEASING`/`FAILING` row to its terminal state; a `RELEASING` row whose
  forward linkage already exists is reconciled to `RELEASED`, so
  `channel_reestablish` never places a second add.

Wire (onion-message TLVs, experimental odd range): the LSP sends
`HELD_HTLC_NOTICE` (1105) listing hold ids, amounts and cutoffs to the receiver
when a hold is parked and whenever the receiver's channel reestablishes; the
receiver answers with a `RELEASE_HELD_HTLC` (1101) capability, or asks with
`HELD_HTLC_QUERY` (1107). `ASYNC_WAKE` (1103) is unchanged.

The store (`storage/durable-ledger.ts`: `IDurableLedgerStore`,
`MemoryLedgerStore`, `MetadataLedgerStore`), the CAS helper (`DurableLedger`)
and the rehydrate-before-serve rule are record-type agnostic: the FFOR
receipt-witness ledger (coreyphillips/ffor#24) is a different record with its
own state machine that instantiates the same infrastructure under its own
prefix, not a variant of the held-forward entry.

#### The async receive service (issue #709)

Parking is an opt-in **service** (`async-payments/service.ts`), not something
the `hold_htlc` marker can command:

- **Disabled by default.** With no `asyncReceiveService` config (or
  `enabled: false`) a node advertises no feature bit, answers no registration,
  and treats the marker as the unknown odd TLV it is to everyone else: the
  forward proceeds or fails exactly as it would without it. A row the node
  already owes from before the service was turned off is still driven to its
  terminal state on redispatch.
- **Capability negotiation.** A serving node sets
  `Feature.ASYNC_RECEIVE_SERVICE` (bit 260; the odd bit 261 is advertised) in
  its `init` and `node_announcement` features, only while the service is
  enabled. A receiver asks for a grant only from a peer that positively
  advertises the bit (read from the peer's `init` through the peer manager,
  else from its verified `node_announcement`); `requestAsyncReceiveGrant`
  refuses locally otherwise, and `createInvoice({ asyncHold: true })` /
  `createOffer({ asyncHold: true })` throw rather than hand a payer a path
  through a peer that would forward the HTLC to an offline receiver.
- **Registration exchange** (onion-message TLVs, experimental odd range):
  `ASYNC_REGISTRATION_REQUEST` (1109) from the receiver names the chain, both
  node ids, the LSP -> receiver SCID it will put in its paths, the hold window
  it wants, a timestamp and a random nonce, and is SIGNED by the receiver's
  node key (tag `beignet/async-payments/registration-request/v1`): an onion
  message reaches the LSP from whichever peer forwarded it last, so the
  transport peer proves nothing and is never consulted; a request older than
  ten minutes is refused as stale. The LSP answers with
  `ASYNC_REGISTRATION_REPLY` (1111): a signed grant, sent to the signer, or a
  refusal echoing the nonce, sent back the way the request came. One ACTIVE
  registration per (receiver, channel): a renewal supersedes the previous one,
  and holds already admitted under it still resolve under it. Registrations
  are durable ledger rows under their own prefix (`async_registration`), so a
  restart keeps them, bounded per receiver (the oldest revoked rows are
  folded into the newest and forgotten). The receiver keeps EVERY grant it
  holds per LSP (newest first, bounded, persisted under the
  `async_receive_grants` metadata key and re-verified on load): a release
  names the registration the LSP's notice reports for the hold, which an
  expired or renewed grant does not change.
- **The grant** (`async-payments/receiver-grant.ts`) is signed by the LSP's
  node key over a tagged digest (`beignet/async-payments/receiver-grant/v1`)
  and binds: service version and the feature bit negotiated under, receiver
  identity, LSP identity, the permitted outgoing SCID, the LSP-minted
  `registration_id` (the value the receiver stamps into the `hold_htlc`
  marker, the slot issue #708 reserved), max value per part and per payment,
  max concurrent parts and aggregate held value, max hold window and minimum
  remaining CLTV, the fee schedule and collection method, prepaid credit,
  issue and expiry times, the request nonce (the replay domain: the LSP
  refuses a nonce it has seen from that receiver), and a reserved
  receipt-witness profile id (coreyphillips/ffor#24; zeros for now).
- **Admission.** Before a hold row is written the service judges, in the same
  synchronous step as the write (no await between them, so two admissions
  cannot both pass a check only one of them fits): the marker names an
  ACTIVE, unexpired registration whose receiver is the outgoing channel's peer
  and whose SCID is the channel the path forwards onto; the part, the payment
  (sum of parts under one hash), the receiver's concurrent count, value and
  bytes, and the global count, value and bytes; the CLTV window (the cutoff
  is clamped to `admission height + maxHoldBlocks`, and a window shorter
  than `minRemainingCltv` is refused); then the price. A refusal reserves
  nothing and goes upstream as `invalid_onion_blinding` like every failure on
  a blinded path, so the payer learns neither the service nor the reason.
- **Pricing.** Two fees, each with one collection point, deterministic for
  release, failure, disconnect and expiry:
  - the **admission fee** per part (`admissionFeeMsat`) is NON-REFUNDABLE:
    it is debited from the receiver's prepaid credit when the row is written
    (every row carries it, so spend is derived from the ledger and survives a
    restart with it), and no outcome returns it. Credit is accounted per
    RECEIVER over every registration it ever held: the initial credit lands
    once, on its first registration, a renewal carries the balance, and
    re-registering refills nothing. When the credit cannot cover another
    part, admission refuses. This is what prices an abandoned hold:
    a receiver that lets holds expire pays for each, and once its credit is
    gone it can reserve nothing until the operator, paid by whatever means it
    sells credit (an invoice, an L402, a plan), calls `creditAsyncReceiver`;
  - the **holding fee** (`holdingFeeMsatPerBlock * maxHoldBlocks`) is paid by
    the PAYER: the receiver's blinded path adds it to the LSP hop's
    `payment_relay` base fee, admission checks the incoming amount covers it
    on top of the forwarding policy fee, and the LSP keeps it at release as
    the difference between the incoming and outgoing HTLC, exactly like any
    forwarding fee. A hold that fails (expiry, receiver fail, unplaceable
    release) refunds the payer the whole HTLC, holding fee included: the LSP
    delivered nothing. The window is priced whole rather than per block
    actually held, because the capacity is reserved for the whole window at
    admission and a payer cannot price a fee that depends on when the
    receiver comes back.
- **Metrics.** `getAsyncReceiveServiceMetrics()` (also on
  `getNodeInfo().asyncReceiveService`): occupied slots, held value, held
  bytes, oldest hold, admission refusals (total and by reason), releases,
  expiries, other failures, registration refusals, active registrations.

```typescript
// LSP: run the service.
const lsp = new LightningNode({
  ...config,
  asyncReceiveService: {
    enabled: true,
    maxPartsPerReceiver: 10,
    maxHoldBlocks: 144,
    admissionFeeMsat: 1_000n,          // per part, from prepaid credit
    holdingFeeMsatPerBlock: 10n,       // paid by the payer for the window
    initialCreditMsat: 100_000n        // what a fresh registration can spend
  }
});
lsp.listAsyncReceiveRegistrations();
lsp.creditAsyncReceiver(registrationIdHex, 50_000n);
lsp.revokeAsyncReceiveRegistration(registrationIdHex);

// Receiver: register once per LSP, then issue async invoices.
const grant = await wallet.requestAsyncReceiveGrant(lspNodeIdHex);
wallet.createInvoice({ amountMsat, description, useBlindedPaths: true, asyncHold: true });
```

### BOLT 12 Offers

Create reusable payment requests and request/pay invoices via onion messages.

```typescript
// Create an offer
const { offer, encoded } = node.createOffer({
  amount: 50_000_000n,         // optional: omit for "any amount"
  description: 'Coffee',
  issuer: 'My Shop',           // optional
  absoluteExpiry: 1700000000n  // optional
});
// encoded => "lno1..." (bech32 with lno prefix)

// Request an invoice for an offer (sent via onion message)
const invoice = await node.requestInvoice(offer, {
  amount: 50_000_000n,         // required if offer has no amount
  quantity: 2n,                // optional
  payerNote: 'Table 5'         // optional
});

// Pay the BOLT 12 invoice
const payment = node.payBolt12Invoice(invoice);
// => IPaymentInfo { status, paymentHash, preimage, ... }
```

### Onion Messages

Send and receive arbitrary data via type 513 onion messages.

```typescript
// Send an onion message
const messageData = new Map<number, Buffer>();
messageData.set(42, Buffer.from('hello'));
node.sendOnionMessage(destinationPubkey, messageData);

// Listen for incoming onion messages
node.on('onion:received', (payload) => {
  console.log('Received onion message with TLVs:', payload.tlvRecords);
});

// Register custom TLV handlers on the manager
const manager = node.getOnionMessageManager();
manager.registerTlvHandler(42, (fromPeer, tlvType, data, replyPath) => {
  console.log('Got TLV 42 from', fromPeer, ':', data);
});
```

### Sending Payments

```typescript
// Auto-route: decode invoice, find route, send
const payment = node.sendPayment(invoiceStr);
// => IPaymentInfo { status, paymentHash, preimage, ... }

// Same, but await settlement instead of getting a PENDING result back
const settled = await node.sendPaymentAsync(invoiceStr);

// Manual route: specify exact path
const routed = node.sendPaymentToRoute(route, paymentHash, finalCltvExpiry);
```

### Waiting for Payments

```typescript
// Wait for a specific incoming payment (useful for AI agents)
const result = node.createInvoice({ amountMsat: 50_000_000n, description: 'Coffee' });
const payment = await node.waitForPayment(result.paymentHash, 30_000);
// Resolves immediately if already settled, or waits up to 30s
// Rejects with a timeout error if not received in time
```

### Balance

```typescript
// Aggregate Lightning balance across all active channels
const balance = node.getBalance();
// => { localBalanceMsat: bigint, remoteBalanceMsat: bigint, unsettledBalanceMsat: bigint }
```

### Channel Health Assessment

```typescript
// Liquidity health for a specific channel
const health = node.getChannelHealth(channelId);
// => IChannelHealth {
//   channelId: string, state: string,
//   localBalancePct: number, remoteBalancePct: number,
//   htlcCount: number, maxHtlcs: number, capacitySats: number,
//   warnings: ['LOW_OUTBOUND_LIQUIDITY', 'HTLC_SLOTS_NEARLY_FULL', ...]
// }

// Warnings are generated automatically:
// - LOW_OUTBOUND_LIQUIDITY: local balance < 10% of capacity
// - LOW_INBOUND_LIQUIDITY: remote balance < 10% of capacity
// - HTLC_SLOTS_NEARLY_FULL: active HTLCs > 80% of max
// - AWAITING_REESTABLISH: channel pending reconnection
```

### Structured Logging

Critical operations emit structured log events for observability:

```typescript
node.on('log', (entry) => {
  // entry.category: 'payment' | 'channel' | 'htlc' | 'fee' | 'peer' | 'chain'
  // entry.action: e.g. 'sent', 'received', 'failed', 'ready', 'closed'
  // entry.timestamp: unix ms
  // entry.data: operation-specific fields (paymentHash, channelId, amountMsat, ...)
  console.log(`[${entry.category}:${entry.action}]`, entry.data);
});
```

Every entry is also mirrored to the injected `ILogger` at debug level as `logger.debug('category:action', data)`. `INodeConfig.logger` defaults to `noopLogger`, so the node prints nothing unless you supply one.

### Receiving Payments

Incoming payments are auto-fulfilled when the preimage is known (from `createInvoice`), unless the invoice was created with `hold: true`:

```typescript
node.on('payment:received', (payment) => {
  console.log('Received', payment.amountMsat, 'msat');
  console.log('Hash:', payment.paymentHash.toString('hex'));
});
```

### Gossip & Routing

```typescript
// Feed gossip messages to the graph
node.handlePeerMessage(pubkey, MessageType.CHANNEL_ANNOUNCEMENT, payload);
node.handlePeerMessage(pubkey, MessageType.CHANNEL_UPDATE, payload);
node.handlePeerMessage(pubkey, MessageType.NODE_ANNOUNCEMENT, payload);

// Query the graph
const graph = node.getGraph();
graph.getChannelCount();
graph.getNodeCount();
graph.getChannel(scid);        // scid: 8-byte Buffer
graph.getNode(nodeId);         // nodeId: 33-byte Buffer

// Find a route
const route = gsp.findRoute(graph, source, destination, amountMsat, finalCltv);
// => { hops: [...], totalAmountMsat, totalCltvDelta, totalFeeMsat }

// For an invoice, let the node route it: estimateRouteFee applies the
// invoice's routing hints (private channels not in the gossip graph), this
// node's own channels and mission control.
node.estimateRouteFee(bolt11); // => { feeSats, feeMsat, hops, cltvDelta } | null

// From this node to a pubkey, without hints:
node.queryRoute(destination, amountMsat);
```

Entries inserted directly through `graph.addChannelAnnouncement` /
`applyChannelUpdate` / `applyNodeAnnouncement` are unverified by default: they
work for local routing but are never served in `reply_channel_range` or
`query_short_channel_ids` responses (BOLT 7 forbids relaying unvalidated
announcements; strict peers such as eclair 0.14+ disconnect on invalid gossip
signatures). Pass `{ verified: true }` only for signature-checked messages that
re-encode byte-identically to the signed wire payload, or
`{ verified: 'deferred' }` for signed-but-unchecked ones. Rapid Gossip Sync
entries are always unverified because RGS strips signatures.

A full mainnet RGS snapshot (about 28k channels and twice as many updates)
holds the event loop for hundreds of milliseconds when applied in one pass
(`applyRapidGossipSnapshot`, `node.loadRapidGossipSnapshot`), and for seconds
on a phone. `applyRapidGossipSnapshotAsync(graph, data, { sliceMs, cancelled,
onSlice })` applies the same snapshot in time slices, yielding to the event
loop between them, and leaves exactly the same graph; it rejects with
`RapidGossipCancelledError` once `cancelled()` returns true.
`node.loadRapidGossipSnapshotAsync` (what `BeignetNode.syncRapidGossip` uses)
runs one import at a time in slices of `LightningNode.RAPID_GOSSIP_SLICE_MS`,
holds the broadcast gossip intake and any stale-gossip prune until it ends,
and stops when the node is destroyed.

The gossip rows a node has stored come back as it is built, in one pass
inside the constructor (`restoreFromStorage`). On a phone that pass holds the
JavaScript thread for seconds as the wallet opens, so
`cooperativeGraphRestore: true` (`BeignetNode`'s `deferGraphRestore`) brings
them back after the constructor instead, a page of rows at a time in slices
of `LightningNode.GRAPH_RESTORE_SLICE_MS`, with the event loop served between
slices, and leaves the same graph and the same rows on disk. Until it ends,
nothing else writes the graph, so a row from disk never replaces live data:
the broadcast gossip intake holds, a stale-gossip prune is deferred to its
end, an RGS import waits its turn, and our own channel updates, peers' gossip
queries and our own gossip sync wait for it. Anything that decides an
outcome from the graph (route finding for payments, probes and estimates, a
public channel's route hint, an FFOR settlement's announcement check)
finishes it first, synchronously, and logs `peer:graph_restore_forced`.
`node.whenGraphRestored()` settles once the map is back (false if a storage
failure or the node's destruction cut it short), `isGraphRestoring()` says
whether it is still running, and `BeignetNode.getGraphInfo()` adds
`restoring: true` meanwhile. A storage failure mid-restore is reported as
`node:error` `GRAPH_RESTORE_FAILED` and deletes nothing.

`node.getGraphRestoreStats()` (and `BeignetNode.getGraphRestoreStats()`,
which adds `constructMs`, the time building the whole node took) reports how
the restore went: inline or not, the rows read, the stale channel rows and
orphan node rows it left out (and deleted, when the storage can), the graph
it left, its time from start to end, the part spent restoring and in how many
slices, and the milliseconds spent reading and parsing the rows, restoring
them, deleting, pruning and reannouncing. A cooperative restore has none to
report until it ends; it then emits `graph:restored` with them. The same
figures are logged once as the structured log `peer:graph_restored`.
`scripts/bench-graph-restore.ts` times both on a synthetic store the size of
a phone's.

Gossip provenance has three states: verified (`*Verified: true`, servable),
unverified (`*Verified: false`, failed verification or signatureless, never
served and never re-checked) and deferred (`*VerifyDeferred: true` with the
boolean unset: carries signatures, not yet checked). The booleans never go
truthy for unchecked data, so existing `if (announcementVerified)` consumers
stay safe. By default the node runs lazy verification: foreign broadcast
gossip is admitted deferred without any signature work, `reply_channel_range`
advertises those SCIDs, and the first `query_short_channel_ids` that asks for
an entry resolves it, serving only what verifies. Resolution draws on a
verification budget shared by all queries in a rolling window
(`NetworkGraph.SERVE_VERIFY_BUDGET_MS` per `SERVE_VERIFY_WINDOW_MS`); each
channel is served atomically (announcement plus updates plus endpoint node
announcements) or omitted whole, and an omission forced by the budget is
reported through the `reply_short_channel_ids_end` `full_information` bit.
This skips nearly the entire first-dump verification cost for wallet nodes
while preserving the never-serve-unverified rule. Trust-consuming reads stay
verified everywhere: updates naming our own channels and node announcements
that feed peer address capture are verified at intake, and every dial-address
consumer goes through `NetworkGraph.getVerifiedNodeAnnouncement`, which
resolves a deferred announcement before handing out addresses. FFOR public-fee
eligibility uses `NetworkGraph.getVerifiedChannelAnnouncement`, which resolves
deferred signatures and requires the signed SCID and chain to match the lookup.
Settlement separately binds both node identities and funding keys to the selected
local public channel. Set
`eagerGossipVerify: true` on relay-class nodes to verify everything at intake
as before; eager mode also re-requests signatureless RGS-primed entries from
peers so their signed copies become servable. Stored rows that predate the
provenance flags are resolved at restore: eager mode verifies the canonical
re-encoding (failing safe to unverified), lazy mode marks them deferred and
lets the point of consumption decide.

Local public-channel gossip is rebuilt from stored channel signatures on restart,
including when a graph row already exists. Periodic refresh updates the local graph
and stored row as well as the broadcast cache, so gossip pruning does not remove the
public-fee evidence during a long FFOR epoch while the receiver is offline. Closed
or otherwise unusable channels are not revived by this refresh.

### HTLC Forwarding

Multi-hop payments are forwarded automatically. Register SCIDs to enable forwarding:

```typescript
// Map a short channel ID to a channel
node.registerChannelScid(channelId, scid);

// Listen for forwarding events
node.on('htlc:forwarded', (info) => {
  console.log('Forwarded HTLC:', info);
});
```

Set `forwardingEnabled: false` to decline all third-party forwards: they fail back promptly with `temporary_node_failure` and our `channel_update`s advertise the BOLT 7 disable bit. This does not affect our own sends and receives.

### Chain Monitoring

```typescript
import { Transaction } from 'bitcoinjs-lib';

// Handle the funding output being spent (force-close detection).
// spendingTx is a bitcoinjs-lib Transaction, not a raw Buffer.
node.handleFundingSpent(channelId, Transaction.fromHex(rawHex), blockHeight, destinationScript);

// Advance block height (triggers timelock checks)
node.handleNewBlock(blockHeight);
```

### Watchtowers

Ship an encrypted justice kit to remote altruist towers at every revocation, so a breach is punished even while this node is offline. Towers speak LND's `wtwire` protocol; sessions are `reward = 0`. Legacy and anchor channels only (taproot is not backed up yet), client side only.

```typescript
const node = ln.LightningNode.fromMnemonic(mnemonic, {
  watchtowers: ['03abc...@tower.example.com:9911']
});

node.addWatchtower('03def...@tower2.example.com:9911');
node.removeWatchtower('03def...@tower2.example.com:9911');
node.getWatchtowers();  // per-tower health, session state, backlog depth
```

### Static Channel Backup (SCB)

An SCB is an on-chain recovery path, not a state backup: on restore, peers are asked to force-close and the funds are swept to the wallet.

```typescript
const scb = node.buildStaticChannelBackupData();
// persist scb somewhere durable (it is encrypted at rest by the daemon)

const result = await node.recoverFromStaticChannelBackup(scb.channels);
```

## Events Reference

`LightningNode` is a typed emitter: `on`, `once`, `off` and `emit` accept only the events below, with these listener signatures, so a listener on a misspelled or undeclared event does not compile. The table is generated from `LightningNodeEvents` in `node/events.ts` by `npm run docs:tables`; edit the map, not the table. `ChannelManager` declares its own positional events in `channel/events.ts` (`ChannelManagerEvents`).

<!-- events:LightningNodeEvents:start -->
| Event | Arguments | Description |
|-------|-----------|-------------|
| `payment:received` | `(payment: IPaymentInfo)` | Incoming payment settled. |
| `payment:sent` | `(payment: IPaymentInfo)` | Outgoing payment completed. |
| `payment:failed` | `(payment: IPaymentInfo)` | Outgoing payment failed. |
| `payment:htlc-resolved` | `(event: IPaymentHtlcResolvedEvent)` | One offered HTLC of an outgoing payment reached a terminal state (fulfilled, irrevocably failed, or resolved on chain). |
| `payment:preimage` | `(event: IPaymentPreimageEvent)` | An outgoing payment's preimage became known, from update_fulfill_htlc or an on-chain claim, whatever the record's status was. |
| `preimage:learned` | `(paymentHash: Buffer, preimage: Buffer)` | Preimage recorded (forwarding and settlement chokepoint). |
| `invoice:settled` | `(data: { paymentHash: Buffer; bolt11: string; amountMsat: bigint })` | Invoice this node issued was settled. |
| `htlc:held` | `(data: { paymentHash: Buffer; amountMsat: bigint })` | HTLC parked by a hold invoice (one part; read `getHeldInvoiceSnapshot` for the committed set). |
| `hold:accepted` | `(event: IHoldInvoiceStateEvent)` | A part joined a hold invoice's parked set, with the set's running total. A re-park on reestablish does not fire. Acceptance can be a partial MPP payment: compare `heldAmountMsat` with the full expected amount before committing funds. |
| `hold:settled` | `(event: IHoldInvoiceStateEvent)` | A hold invoice's preimage was revealed and every parked part fulfilled. |
| `hold:cancelled` | `(event: IHoldCancelledEvent)` | A hold invoice was cancelled by the CLTV sweeper (`expiry-scan`) or the API; every parked part was failed back. |
| `payment:async-wake` | `(paymentHash: Buffer \| undefined)` | Receiver side: a wake message says a sender is waiting. Reconnect to the LSP so it can release the held HTLC. |
| `payment:held-notice` | `(data: { lspNodeId: Buffer; notice: IHeldForwardNotice })` | Receiver side: the LSP reported forwards it holds for this node. With `autoReleaseHeldForwards` off, release them with `sendAsyncRelease`. |
| `async-receive:granted` | `(grant: IReceiverGrant)` | Receiver side: an LSP granted this node an async receive registration. |
| `htlc:held-forward` | `(data: { holdId: Buffer; paymentHash: Buffer; amountMsat: bigint; cutoffHeight: number })` | LSP side: a forward to an offline receiver was parked until the receiver releases it or `cutoffHeight` passes. |
| `htlc:held-forward-released` | `(record: IHeldForwardRecord)` | LSP side: a parked forward was released to the receiver. |
| `htlc:held-forward-failed` | `(record: IHeldForwardRecord)` | LSP side: a parked forward was failed back upstream. |
| `channel:opening` | `(data: { channelId: Buffer; fundingTxid: Buffer })` | Funding flow started. |
| `channel:ready` | `(data: { channelId: Buffer })` | Channel reached NORMAL state. |
| `channel:txsigs-needed` | `(data: { channelId: Buffer; fundingTxid: Buffer; fundingOutputIndex: number; inputIndices: number[]; externalInputIndices?: number[] })` | A caller-driven v2 open owes its tx_signatures and only the embedder holds the witnesses: answer with `sendTxSignatures`. `externalInputIndices` names the inputs a third party owes, answered with `provideV2ExternalWitness`. |
| `channel:splice-txsigs-needed` | `(data: { channelId: Buffer; spliceTxid: Buffer; newFundingOutputIndex: number; externalInputIndices: number[] })` | A splice is withholding its tx_signatures on external inputs whose witnesses a third party owes: collect them and answer with `provideSpliceExternalWitness`. Re-armed per connection cycle. |
| `channel:pending-close` | `(data: { channelId: Buffer; initiator: 'local' \| 'remote' })` | A cooperative close started. |
| `channel:force-closing` | `(data: { channelId: Buffer; initiator: 'local' \| 'remote' })` | A force close started: this node broadcast its commitment (`local`) or the peer's appeared on chain (`remote`). |
| `channel:closed` | `(data: { channelId: Buffer })` | Channel closed. |
| `channel:resolved` | `(data: { channelId: Buffer })` | All on-chain outputs of the close resolved. |
| `channel:aborted` | `(temporaryChannelId: Buffer, reason: string)` | A negotiated but unfunded open was torn down. |
| `channel:voided` | `(data: { channelId: Buffer })` | Unfunded or abandoned channel discarded. |
| `announcement:ready` | `(channelId: Buffer)` | Channel eligible for announcement. |
| `splice:complete` | `(data: { channelId: Buffer; fundingTxid: Buffer \| null \| undefined })` | splice_locked exchanged both ways: the channel runs on the new funding. |
| `splice:aborted` | `(data: { channelId: Buffer; reason: string })` | A splice negotiation was unwound by tx_abort before its point of no return. |
| `splice:conflicted` | `(data: { channelId: Buffer; spliceTxid: string; conflictTxid: string; inputIndex: number; height: number })` | An input of an in-flight splice that this node does not vouch for (a depth-locked splice carrying a stranger's coin, issue #760) was spent by another transaction, confirmed six deep while the splice is not on chain: the splice can never confirm. The node records it durably, raises `node:error` code `SPLICE_INPUT_CONFLICT`, and asks the peer to verify and revert; the request is re-sent every block and on reconnect until agreed. |
| `splice:reverted` | `(data: { channelId: Buffer; spliceTxid: string; conflictTxid: string })` | A conflicted splice was unwound by agreement: both sides verified the conflict on their own chain view and returned to the pre-splice funding, which both still hold valid commitments for. The channel is NORMAL on the old outpoint, its watch re-armed; a `spliceInAndWait` on that splice rejects, and a direct-funding request behind it is failed (`direct-funding:offer:failed`, "the payer spent the offered coin elsewhere"). |
| `htlc:forward` | `(inChannelId: Buffer, outChannelId: Buffer, amountMsat: bigint, paymentHash: Buffer)` | An HTLC was relayed to the next hop. |
| `htlc:forwarded` | `(data: { inChannelId: Buffer; outChannelId: Buffer; amountInMsat: bigint; amountOutMsat: bigint; feeMsat: bigint })` | A forwarded HTLC settled: the fee was earned. |
| `htlc:forward-failed` | `(data: { inChannelId: Buffer; outChannelId: Buffer })` | A forwarded HTLC failed downstream. |
| `htlc:fulfilled` | `(data: { channelId: Buffer; htlcId: bigint })` | The peer fulfilled an HTLC this node offered: a part of its own payment or the outgoing leg of a forward. |
| `htlc:failed` | `(data: { channelId: Buffer; htlcId: bigint })` | The peer failed an HTLC this node offered: a part of its own payment or the outgoing leg of a forward. |
| `broadcast:tx` | `(tx: Buffer)` | Transaction to broadcast on chain. |
| `sweep:uneconomic` | `(channelId: Buffer, action: ISweepUneconomicChainAction)` | An on-chain claim was declined because it cannot pay its own fee (`reason: 'skipped'`), or a competing spend path opened while it stayed unclaimed (`reason: 'contested'`). Retries continue in both cases, until the outpoint is spent. |
| `block:processed` | `(height: number)` | The per-block work for this height has run. |
| `message:outbound` | `(peerPubkey: string, type: number, payload: Buffer)` | Message to send to a peer (event-transport mode). |
| `peer:connect` | `(pubkey: string)` | Peer connected (networking mode). |
| `peer:disconnect` | `(pubkey: string)` | Peer disconnected (networking mode). |
| `peer:disconnect-requested` | `(pubkey: string)` | The node needs this peer's connection severed but holds no socket for it (event-transport mode, or an unconnected peer): the host must close its transport. The protocol side (channels marked for reestablish) is already applied; reconnect and reestablish as usual. |
| `peer:error` | `(pubkey: string, error: Error)` | Peer error (networking mode). |
| `custom-message` | `(message: { peerPubkey: string; version: number; subtype: number; payload: Buffer })` | A beignet custom message (type 44069) arrived from a peer. |
| `peer_storage:retrieved` | `(peerPubkey: string, blob: Buffer)` | A peer returned the blob it stores for this node (BOLT 1 peer storage), unpadded. |
| `onion:received` | `(payload: IOnionMessagePayload)` | Onion message received (type 513). |
| `offer:created` | `(offer: IOffer)` | BOLT 12 offer created. |
| `bolt12:invoice:received` | `(invoice: IBolt12Invoice)` | BOLT 12 invoice received. |
| `bolt12:invoice:issued` | `(invoice: IBolt12Invoice)` | BOLT 12 invoice issued to a payer. |
| `recovery:durable` | `(through: bigint)` | The recovery journal is durable through this frame sequence. |
| `recovery:fenced` | `(supersededBy: GuardianState \| null \| undefined)` | A newer writer epoch owns this recovery namespace: this device must not send another channel message. Carries the superseding writer's guardian state when the barrier saw one, null or undefined otherwise (as after the node rotated away from its guardian set). |
| `recovery:backfill-lost` | `(detail: string)` | The journal was compacted past frames a guardian had not yet received, so that guardian cannot be backfilled. |
| `recovery:reestablish-held` | `(peerPubkey: string, channelIdHex: string, expiresAt: number)` | A peer's channel_reestablish for a channel this node has no record of was parked instead of failed, because the node may still be an incomplete restore target (issue #462). Apply a Recovery Capsule before `expiresAt` or the peer force-closes. |
| `graph:restored` | `(stats: IGraphRestoreStats)` | A deferred restore of the stored network map (`deferGraphRestore`) ended; the same figures `getGraphRestoreStats()` returns. |
| `ffor:state` | `(data: { channelId: Buffer; state: FforState; record: IFforEpochRecord })` | An FFOR epoch's committed state changed. |
| `ffor:enforce` | `(data: { channelId: Buffer; record: IFforEpochRecord })` | A peer contradicted an ACTIVE FFOR epoch: enforce it on chain (`fforEnforce`). |
| `ffor:settled` | `(data: { channelId: Buffer; k: number; paymentHash: Buffer; upstreamChannelId: Buffer; upstreamHtlcId: bigint })` | Settlement peer side: a delegated slot settled upstream. |
| `ffor:delegated-failed` | `(data: { channelId: Buffer; k: number; paymentHash: Buffer; upstreamChannelId: Buffer; upstreamHtlcId: bigint; reason: string })` | Settlement peer side: a delegated slot's payment was failed back upstream. |
| `ffor:slot-resolved` | `(data: { channelId: string; epochId: string; k: number; paymentHash: string; amountMsat: string; outcome: 'fulfilled' \| 'cancelled' })` | A concurrent-profile slot reached its terminal outcome. JSON-safe: hex and decimal strings. |
| `ffor:witness-audit` | `(data: { channelId: Buffer; witnessNodeId: Buffer; k: number; reason: string \| undefined })` | A witness record fetched for a slot failed verification. |
| `direct-funding:offer:accepted` | `(data: { offerId: string; paired: boolean; resumed?: boolean })` | A payer's offer was accepted. `paired` says whether it came from a peer in the trusted set, which decides zero-conf and the splice path; `resumed` marks one picked up again after a restart. |
| `direct-funding:offer:declined` | `(data: { offerId: string; reason: string })` | A payer's offer was declined with the reason. |
| `direct-funding:offer:failed` | `(data: { offerId: string; reason: string })` | An accepted offer failed with the reason. |
| `direct-funding:offer:completed` | `(data: { offerId: string })` | An offer completed with the funding out. |
| `swap:created` | `(event: ISwapEvent)` | A swap row was created: for a reverse swap with its hold invoice minted, for a submarine swap once its terms verified. |
| `swap:held` | `(event: ISwapEvent)` | Reverse swap: the complete committed payment set is held by the hold invoice; a partial MPP set never funds. |
| `swap:funding` | `(event: ISwapEvent)` | Reverse swap: the funding transaction was built, verified and recorded, and is being broadcast (`fundingTxid`, `fundingVout`). |
| `swap:funded` | `(event: ISwapEvent)` | The swap's funding confirmed to the configured depth (`fundingHeight` on a reverse swap). |
| `swap:claimed` | `(event: ISwapEvent)` | Reverse swap: a claim spend with a verified preimage was seen at any depth (`claimTxid`); the preimage is recorded before the hold settles. |
| `swap:settled` | `(event: ISwapEvent)` | Reverse swap: the hold was released with the claimed preimage. |
| `swap:refund-broadcast` | `(event: ISwapEvent)` | Reverse swap: no claim by the refund height, so a refund to the node's sweep destination was broadcast. |
| `swap:refunded` | `(event: ISwapEvent)` | Reverse swap: the refund confirmed, and only then the hold is cancelled. |
| `swap:hold-cancelled` | `(event: ISwapEvent)` | Reverse swap: the hold invoice was cancelled. |
| `swap:exposed` | `(event: ISwapEvent)` | Funds are at risk (`reason`, `previousState`): on a reverse swap the hold was cancelled while coins were or may be on chain; on a submarine swap a payment is out while the contract is not claimable. |
| `swap:failed` | `(event: ISwapEvent)` | The swap failed (`reason`). |
| `swap:funding-seen` | `(event: ISwapEvent)` | Submarine swap: an output paying the contract, of at least the amount, was seen at any depth. |
| `swap:funding-lost` | `(event: ISwapEvent)` | Submarine swap: the unconfirmed funding was replaced or vanished and none is left. |
| `swap:paying` | `(event: ISwapEvent)` | Submarine swap: this node started paying the client's invoice under the swap's expiry ceiling. |
| `swap:payment-unresolved` | `(event: ISwapEvent)` | Submarine swap: HTLCs are still out past `unresolvedAfterBlocks` (informational). |
| `swap:preimage` | `(event: ISwapEvent)` | Submarine swap: the payment's preimage is known, from a fulfil or a claim seen on chain downstream. |
| `swap:claim-broadcast` | `(event: ISwapEvent)` | Submarine swap: the claim to the sweep destination was built, persisted and broadcast. |
| `swap:claim-confirmed` | `(event: ISwapEvent)` | Submarine swap: the claim confirmed to the resolution depth. |
| `swap:payment-failed` | `(event: ISwapEvent)` | Submarine swap: every HTLC ended without a preimage; a preimage learned later still promotes the row. |
| `swap:cancelled` | `(event: ISwapEvent)` | Submarine swap: cancelled before anything was paid (invoice expired, ceiling no longer fits, client spent the funding, or the operator cancelled). |
| `log` | `(entry: IStructuredLog)` | Structured action log entry. |
| `node:error` | `(error: ILightningError<NodeErrorCode>)` | Operational error (non-fatal). LightningNode never emits the bare `'error'` event. |
| `node:ready` | `()` | Node fully operational (peers reconnected, channels restored). |
| `jit:intent` | `(intent: IJitIntent)` | A wallet's request was accepted, keyed by the intercept scid this LSP minted for it. |
| `jit:intent-superseded` | `(data: { scidHex: string; walletPubkeyHex: string })` | An idle intent was replaced by a newer one from the same wallet. |
| `jit:intercepted` | `(data: { scidHex?: string; channelIdHex?: string; amountMsat: bigint })` | A payment part was held for an intent, or on the splice path for an existing channel. |
| `jit:funding` | `(data: { scidHex?: string; channelIdHex?: string; fundingSats: bigint })` | The zero-conf open or the splice that funds the held parts started. |
| `jit:forwarded` | `(data: { scidHex?: string; channelIdHex?: string; parts: number })` | The held parts were delivered over the new liquidity. |
| `jit:failed` | `(data: { scidHex?: string; channelIdHex?: string; parts?: number; reason: string })` | The held parts were failed back upstream with the reason. |
| `jit:restored-failed` | `(data: { remaining: number })` | Holds restored from storage were failed back; `remaining` are still owed a failure and retried every block. |
| `ffor:witness-provisioned` | `(data: { mailboxId: Buffer; slots: number; retentionUntil: number; peer: string })` | Witness role: a receiver provisioned a mailbox on this node. |
| `ffor:witness-refused` | `(data: { peer: string; reason: string })` | Witness role: a provision was refused with the reason. |
| `ffor:witness-recorded` | `(data: { mailboxId: Buffer; k: number; outKey: string; unbarriered: boolean })` | Witness role: a delegated preimage's record was stored; `unbarriered` when the fulfil had already gone out at the deadline. |
| `ffor:witness-released` | `(data: { outKey: string; mailboxId: Buffer; k: number; reason: 'recorded' \| 'deadline' })` | Witness role: a held fulfil was propagated, once recorded or at its CLTV deadline. |
| `ffor:witness-closed` | `(data: { mailboxId: Buffer; held: number })` | Witness role: the receiver closed its mailbox; `held` records remain. |
| `ffor:witness-expired` | `(data: { mailboxId: Buffer })` | Witness role: a mailbox passed its retention and expired. |
| `ffor:issuer-provisioned` | `(data: { mailboxId: Buffer; offerId: Buffer; slots: number })` | Issuer role: a receiver delegated an offer and provisioned its slots. |
| `ffor:issuer-issued` | `(data: { mailboxId: Buffer; k: number; payerId: Buffer })` | Issuer role: an invoice was issued against slot `k` to a payer. |
| `ffor:issuer-retired` | `(data: { mailboxId: Buffer; reason: string })` | Issuer role: a delegated offer stopped issuing, with the reason. |
<!-- events:LightningNodeEvents:end -->

### Beignet custom messages (type 44069)

Beignet-to-beignet extensions ride one odd BOLT 1 message type, `44069`, as `[u16 version][u16 subtype][payload]`; other implementations ignore it (`message/custom.ts`, `BeignetCustomSubtype`). Reserved subtypes: 1 to 5 JIT receive, 16 to 22 direct funding, 32 to 33 recovery guardian sessions, 48 to 55 the swap provider (`swaps/README.md`), and 64 to 65 splice conflict recovery (issue #760): `SPLICE_CONFLICT` (64) `[32 channel_id][32 splice_txid][32 conflict_txid][u16 input_index]` asks the peer to verify on its own chain that the named splice input was spent elsewhere at depth and to revert to the pre-splice funding; `SPLICE_CONFLICT_ACK` (65) `[32 channel_id][32 splice_txid][u8 agreed][u16 reason_len][reason]` reports the outcome. Txids are in `tx.getHash()` byte order. A receiver never reverts on the peer's word: it fetches the spender, checks it takes an input other than the shared funding input, reads the depth from the outpoint's own history, and refuses (`agreed=0`, with a reason) on any shortfall; the requester re-asks on every block and on reconnect (`message/splice-conflict.ts`).

Channel-scoped events carry an **object**, not a bare id: `node.on('channel:ready', ({ channelId }) => ...)`, where `channelId` is a 32-byte Buffer. `announcement:ready`, `channel:aborted` and `sweep:uneconomic` are the exceptions and pass the Buffer as their first argument. `BeignetNode` normalizes all of these to hex strings.

`LightningNode` reports operational problems through `node:error` and never emits the bare `'error'` event, so `node.on('error', ...)` does not compile. The error's `code` is a `NodeErrorCode`, a closed union of every code the node raises, so a `switch` over it can be exhaustive. Splice conflict recovery (issue #760) adds the code `SPLICE_INPUT_CONFLICT`, raised once per conflicted splice alongside `splice:conflicted`. `ChannelManager` does emit `'error'` as `(channelId: Buffer | null, error: string, code?: ChannelErrorCode)`, so code that drives a `ChannelManager` directly (most unit tests) should attach a listener, even a noop, to avoid unhandled-error throws.

A channel refusal carries a `ChannelErrorCode` (`WRONG_STATE`, `BUSY`, `INSUFFICIENT_BALANCE`, `LIMIT_EXCEEDED`, `OPEN_NOT_FUNDED` and so on) on its ERROR action, on the `ChannelResult` a `ChannelManager` method returns, and on a `CHANNEL_ERROR` `node:error` as `channelErrorCode`. The arms that serve a local request (an add, a fee update, a close, a splice, a quiescence, an open, an RBF) set one; a refusal of something the peer sent may not yet, so treat an absent code as unclassified. Other coded errors follow the same shape, a `CodedError` with an enum `code`: `PeerError` (`PeerErrorCode`) from `PeerManager.sendToPeer`, and `JitReceiveError` (`JitReceiveErrorCode`) from the wallet side of a JIT receive.

## Typed Payment Errors

`sendPayment()` and `sendPaymentToRoute()` throw `LightningPaymentError` with a typed `code` property:

| Code | Thrown When |
|------|------------|
| `NO_ROUTE` | No route found to destination |
| `DUPLICATE_PAYMENT` | Payment hash already paid (known preimage or COMPLETED record, in memory or on disk), or still has an HTLC out; a failed HTLC counts as out until its removal is irrevocable (the peer's `revoke_and_ack` for the commitment without it), which is also when the automatic retry of a temporary failure is dispatched; after that a failed attempt can be sent again |
| `NO_CHANNEL_TO_HOP` | No channel to first hop peer |
| `FEE_EXCEEDS_MAX` | Route fee exceeds `maxFeeMsat` |
| `MISSING_AMOUNT` | Amount-less invoice with no `amountMsat` override |
| `INVALID_INVOICE` | Cannot determine payee from invoice |
| `INVOICE_EXPIRED` | Invoice has expired |
| `INVALID_KEYSEND` | Keysend options failed validation |

```typescript
try {
  node.sendPayment(invoiceStr);
} catch (err) {
  if (err instanceof ln.LightningPaymentError) {
    console.log(err.code); // e.g. ln.LightningErrorCode.NO_ROUTE
  }
}
```

## Node Readiness

After creating a node with `fromMnemonic()` or restoring from storage, use `waitForReady()` to block until peers are reconnected and channels are restored:

```typescript
const node = ln.LightningNode.fromMnemonic(mnemonic, { storage, enableNetworking: true });
await node.waitForReady(30_000); // resolves when peers reconnected, or after 30s timeout
```

The `node:ready` event fires once when the node is fully operational. If no peers need reconnection, it fires immediately via `process.nextTick()`.

## Stuck-Channel Timeout: `reestablishTimeoutBlocks`

Channels stuck in `AWAITING_REESTABLISH` (peer disappeared permanently) are auto-force-closed after `reestablishTimeoutBlocks` blocks (default 2016, roughly 2 weeks). This is an `INodeConfig` field, so it goes through the constructor: `fromMnemonic()` does not expose it.

```typescript
const node = new ln.LightningNode({
  ...config,
  reestablishTimeoutBlocks: 1008 // ~1 week instead of the default 2 weeks
});
```

## Module Reference

One row per namespace `beignet/lightning` exports (a test checks this table against `index.ts`). Per-module file counts are deliberately omitted: they went stale faster than anything else in this document. Use `ls src/lightning/<module>` instead.

| Module | Key Exports | BOLT |
|--------|-------------|------|
| `bootstrap` | `bootstrapPeers`, `resolveDnsSeed`, `DEFAULT_DNS_SEEDS` | 10 |
| `crypto` | `chacha20poly1305`, `ecdh`, `hkdf`, MuSig2 (BIP 327), `setCryptoProvider` | 8, 3 |
| `message` | Message encode/decode for all types, `codec`, `tlv`, `stfu`, interactive-tx, dual-funding, splice | 1, 2 |
| `features` | `FeatureFlags` | 9 |
| `transport` | `Peer`, `PeerManager`, `CipherState`, Noise_XK handshake functions, WebSocket and Iroh transports, wire capture | 8 |
| `keys` | `derivation`, `shachain`, `signer`, `wallet-keys` | 3 |
| `script` | `funding`, `commitment`, `htlc`, `revocation`, `anchor`, taproot commitment/HTLC | 3 |
| `channel` | `Channel`, `ChannelManager`, commitment builder functions, `ZeroConfManager`, `QuiescenceManager`, `DualFundingSession`, `SpliceSession`, liquidity ads | 2, bLIP-51 |
| `interactive-tx` | `InteractiveTxBuilder`, serial ID validation | 2 |
| `chain` | `ChainMonitor`, `ChainWatcher`, output resolver functions, `closing`, `sweep`, `ElectrumBackend` | 5 |
| `invoice` | `encode`, `decode`, `amount`, `signing`, `words`, `Network` | 11 |
| `gossip` | `NetworkGraph`, `findRoute`, `GossipSyncManager`, `messages`, `validation` | 7 |
| `onion` | `constructOnionPacket`, `processOnionPacket`, `failures`, `constructBlindedPath`, `processBlindedHop` | 4 |
| `onion-message` | `OnionMessageManager`, `constructSimpleOnionMessage`, `processOnionMessage` | 4 |
| `offer` | `OfferManager`, `encodeOffer`, `decodeOffer`, TLV, Schnorr, merkle | 12 |
| `async-payments` | `AsyncPaymentManager`, `HeldForwardLedger`, release capability (held forward, notice, release, wake) | 4, 11 |
| `ffor` | `FforWitnessService`, `FforIssuerService`, epoch messages, voucher book checks, transcript hashes | -- |
| `liquidity` | `JitReceiveManager`, JIT quote/ack/authorization messages, intercept SCIDs | -- |
| `direct-funding` | Request envelopes, sealed frames, `DirectFundingRequestStore`, `DirectFundingReceiver`, `DirectFundingSender`, transport lanes | -- |
| `swaps` | P2WSH HTLC contract, claim/refund transactions, swap ledger, chain resolver, `ReverseSwapProvider`, `SubmarineSwapProvider` | -- |
| `l402` | `l402Fetch`, `parseL402Challenge`, macaroon reading, credentials | -- |
| `recovery` | `RecoveryJournal`, Recovery Capsule, `ReferenceGuardian`, `GuardianReplicator`, guardian wire and transports, startup gate (`GuardianStore` is in `beignet/lightning/sqlite`) | 1 |
| `watchtower` | `WatchtowerClient`, `wtwire`, justice blob, tower connection | -- |
| `backup` | Static channel backup (SCB) encode/decode | -- |
| `node` | `LightningNode`, `INodeConfig`, rate limiter | -- |
| `storage` | `IStorageBackend` and its capability groups, `MemoryStorage`, `runStorageConformanceSuite`, `serialization` (`SqliteStorage` is in `beignet/lightning/sqlite`) | -- |
| `wallet` | `WalletFundingProvider`, `IFundingProvider` | -- |
| `advisor` | `LiquidityAdvisor`, `FeeAdvisor`, `ChannelSuggestions`, rebalance/fee executors | -- |
| `validation` | Input validation utilities | -- |

Each module is a namespace on `beignet/lightning`, camel-casing hyphenated names: `import { asyncPayments, ffor, watchtower } from 'beignet/lightning'`.

## Testing

```bash
# Lightning unit tests, interop excluded (no Docker needed)
npm run test:lightning

# Official BOLT test vectors (a subset of test:lightning)
npm run test:conformance

# Interop tests against LND/CLN/Eclair (requires Docker)
npm run test:interop

# Lightning + CLI + interop
npm run test:all

# A single module's tests
npx mocha --exit -r ts-node/register 'tests/lightning/node.test.ts'
npx mocha --exit -r ts-node/register 'tests/lightning/channel-manager.test.ts'
npx mocha --exit -r ts-node/register 'tests/lightning/offer.test.ts'
npx mocha --exit -r ts-node/register 'tests/lightning/dual-funding.test.ts'
```

| Suite | Notes |
|-------|-------|
| `test:lightning` | No infrastructure required |
| `test:conformance` | Official BOLT vectors, a subset of `test:lightning` |
| `test:chaos` | Recovery kill matrices, split out of `test:lightning` |
| `test:interop` | Live LND/CLN/Eclair on regtest, Docker required |

Test counts are kept in one place, the root README's [Tests](../../README.md#tests) section.

Interop tests and the `recovery-phase7-*` kill matrices are excluded from `npm run test:lightning`. Use `npm run test:interop` (Docker required) and `npm run test:chaos` to run them.

### Test Patterns

- **Two-party simulation**: nodes are wired via `message:outbound` event loopback, no TCP required
- **Synchronous loopback**: the entire HTLC fulfill chain completes synchronously during `addHtlc()`, so store state BEFORE calling it
- **Graph population**: tests inject gossip data directly into `NetworkGraph` rather than using signed messages; such entries are unverified and never served to gossip queries, so responder-side tests pass `{ verified: true }`
- **Crypto verification**: signed gossip messages use real cryptographic signatures for validation tests
- **Conformance vectors**: `tests/lightning/conformance/vectors` holds the official BOLT vectors, expanded into cases at runtime
- **Docker interop**: LND, CLN and Eclair interop tests auto-skip when the containers are unavailable

## BOLT Specification Coverage

| BOLT | Name | Coverage |
|------|------|----------|
| 1 | Base Protocol | init, error, warning, ping/pong, peer storage |
| 2 | Channel Management | Full state machine, 20+ message types, dual funding, quiescence, splicing, zero-conf |
| 3 | Transactions | Funding, commitment, HTLC, revocation, anchor scripts; taproot channels via MuSig2 (experimental) |
| 4 | Onion Routing | Sphinx, hop payloads, failure handling, route blinding, onion messages |
| 5 | On-chain Handling | Force close, sweep, output resolution, chain watcher, wallet-funded anchor fee bumping |
| 7 | Gossip Protocol | Announcements, graph, Dijkstra pathfinding, gossip sync, Rapid Gossip Sync |
| 8 | Transport | Noise_XK, ChaCha20-Poly1305 framing, key rotation |
| 9 | Feature Flags | Bit manipulation, init negotiation |
| 10 | DNS Bootstrap | SRV resolution, seed nodes, peer discovery |
| 11 | Invoices | Encode, decode, signing, amount parsing, hold invoices |
| 12 | Offers | TLV encode/decode, Schnorr signing, merkle tree, bech32, lno/lnr/lni prefixes, async payment offers |
| bLIP-51 | Liquidity Ads | lease_rates, request_funds, will_fund, lease fee accounting, CLTV-locked lessor output |

Validated against the official BOLT vectors (`npm run test:conformance`) and against live LND, Core Lightning and Eclair (`npm run test:interop`). Not implemented: trampoline routing, LSPS0/1/2, watchtower server mode. See the root README's [status and limitations](../../README.md#status--limitations) for caveats that apply per feature.

### Iroh transport injection

The experimental Iroh adapter carries BOLT 8 inside one QUIC bidirectional
stream, using ALPN `beignet/bolt8/1`. Import the Node backend explicitly:

```ts
import { node, transport } from 'beignet/lightning';
import { createNodeIrohEndpoint } from 'beignet/lightning/iroh-node';

const lightning = node.LightningNode.fromMnemonic(mnemonic, {
  enableNetworking: true,
  iroh: { factory: createNodeIrohEndpoint }
});
await lightning.listenIroh();
const peer = transport.parsePeerUri(primaryUri);
await lightning.connectPeer(peer.pubkey, peer.host, peer.port, peer.transport);
```

`fromMnemonic` derives the endpoint secret key using the same documented seed
label as the daemon. Direct `new LightningNode(config)` callers provide
`config.iroh.secretKey` themselves, derived from the wallet seed with
`deriveIrohSecretKey`, and must not reuse a Lightning private key.

Portable and mobile builds inject an `IrohEndpointFactory` implementing
`IIrohEndpoint`. It owns endpoint binding, dialing, incoming streams and shutdown.
Adapt native streams with `IrohTransport` and its `IIrohStream` contract. Writes
must resolve only after the complete supplied buffer is accepted, reads return
an empty buffer at EOF, and `closed()` resolves or rejects when the connection
dies. `close()` must unblock pending reads and writes. The adapter orders writes,
tracks queued bytes, buffers data between Noise readers, and closes both stream
directions at EOF. The peer layer keeps its usual BOLT ping/pong liveness checks.
The Node binding currently does not expose QUIC idle or keepalive tuning.

The portable entry point does not load or import the native binding. A mobile
host should create a fresh endpoint after suspension when necessary and dispose
of the previous one, while reusing the derived identity. Iroh is opt-in per
peer. It reveals IP addresses to peers and relays and does not provide Tor's
anonymity. See the CLI README for relay/discovery settings, API diagnostics and
remaining device and relay validation.
