# Beignet Lightning Module

A pure-TypeScript Lightning Network implementation covering BOLTs 1-5, 7-8, and 10-12. Built for `bitcoinjs-lib` and Node.js.

## Overview

This module implements the core Lightning Network protocols:

- **BOLT 1** -- Base protocol (init, error, ping/pong)
- **BOLT 2** -- Channel management (open, close, HTLCs, dual-funding, quiescence, splicing, zero-conf)
- **BOLT 3** -- Transaction scripts (funding, commitment, HTLC, revocation, anchor outputs)
- **BOLT 4** -- Onion routing (Sphinx packets, route blinding, onion messages)
- **BOLT 5** -- On-chain transaction handling (force close, sweep, output resolution)
- **BOLT 7** -- Gossip protocol (channel/node announcements, pathfinding)
- **BOLT 8** -- Encrypted transport (Noise_XK handshake, ChaCha20-Poly1305 framing)
- **BOLT 10** -- DNS-based peer discovery (SRV records, seed nodes)
- **BOLT 11** -- Invoice encoding/decoding (bech32, amount, signatures, features)
- **BOLT 12** -- Offers (reusable payment requests, TLV encoding, Schnorr signing)

## Architecture

```
src/lightning/
├── bootstrap/       BOLT 10 DNS peer discovery, seed nodes
├── crypto/          ECDH, HKDF, ChaCha20-Poly1305
├── message/         Wire protocol codec, TLV, all message types
├── features/        Feature flag bit manipulation
├── transport/       BOLT 8 Noise handshake, encrypted Peer, PeerManager
├── keys/            Key derivation, shachain, channel signer, wallet keys
├── script/          Funding, commitment, HTLC, revocation, anchor scripts
├── channel/         Channel state machine, commitment builder, ChannelManager,
│                    zero-conf, quiescence, dual-funding, splicing
├── interactive-tx/  Collaborative TX construction (types 66-74)
├── chain/           Chain monitor, closing tx, sweep tx, output resolver
├── invoice/         BOLT 11 encode/decode, amount, signing
├── gossip/          Network graph, messages, validation, pathfinding, sync
├── onion/           Sphinx crypto, hop payloads, packet construction, route blinding
├── onion-message/   Type 513 onion messages, rate limiting
├── offer/           BOLT 12 offers, TLV encode/decode, Schnorr, merkle tree
├── storage/         SQLite persistence, serialization
├── wallet/          Wallet funding provider integration
├── node/            LightningNode orchestrator
├── advisor/         Liquidity, fee, and channel suggestion advisors
├── validation/      Input validation utilities
└── index.ts         Barrel exports for all modules
```

### Data Flow

```
LightningNode
 ├── PeerManager (optional) ─── Peer ─── TCP + BOLT 8 encryption
 ├── ChannelManager ─── Channel[] ─── CommitmentBuilder
 │    ├── ChainMonitor ─── OutputResolver
 │    ├── ZeroConfManager ─── trusted peer set
 │    ├── QuiescenceManager ─── STFU state machine
 │    ├── DualFundingSession ─── InteractiveTxBuilder
 │    └── SpliceSession ─── InteractiveTxBuilder
 ├── NetworkGraph ─── Pathfinding (Dijkstra)
 ├── Onion (Sphinx) ─── construct / process / failures / blinding
 ├── OnionMessageManager ─── send / receive / forward (type 513)
 ├── OfferManager ─── create / request / pay (BOLT 12)
 ├── Invoice ─── encode / decode (BOLT 11)
 ├── Bootstrap ─── DNS seed resolution (BOLT 10)
 └── Advisor ─── LiquidityAdvisor, FeeAdvisor, ChannelSuggestions
```

### Event System

Both `Channel` and `ChainMonitor` return action arrays (`ChannelAction[]` / `ChainAction[]`) rather than emitting events directly. `ChannelManager` processes these actions and emits higher-level events. `LightningNode` listens to `ChannelManager` events and provides the public event API.

When `PeerManager` is enabled, `ChannelManager.sendMessage()` routes through `PeerManager.sendToPeer()` with a fallback to `message:outbound` emission if the peer is not connected.

`OnionMessageManager` and `OfferManager` are both `EventEmitter` instances. `LightningNode` re-emits their events through the unified node event API.

## Installation

The lightning module is part of the beignet package:

```typescript
import * as lightning from 'beignet/lightning';

// Or import specific sub-modules
import { LightningNode } from 'beignet/lightning';
import { ChannelManager } from 'beignet/lightning';
import { NetworkGraph } from 'beignet/lightning';
import { OfferManager } from 'beignet/lightning';
```

### Prerequisites

- Node.js with `crypto` module
- `bitcoinjs-lib` with `@bitcoinerlab/secp256k1`
- `bech32` (for BOLT 11 invoices)

## Quick Start

> **Warning**: Do NOT use `crypto.randomBytes()` for production keys. Random keys cannot be recovered
> if lost. Always derive keys from a BIP39 mnemonic via `LightningNode.fromMnemonic()`.

```typescript
import { LightningNode } from 'beignet/lightning';

// Recommended: derive all keys from a BIP39 mnemonic
// fromMnemonic() is synchronous — returns a LightningNode directly
const node = LightningNode.fromMnemonic(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  { network: 'bcrt', enableNetworking: true },
);

// Listen for events
node.on('payment:received', (payment) => {
  console.log('Received payment:', payment.paymentHash.toString('hex'));
});

node.on('payment:sent', (payment) => {
  console.log('Payment sent:', payment.preimage?.toString('hex'));
});
```

> **Important**: `sendPayment()` returns synchronously with PENDING status.
> For AI agents and async workflows, use `sendPaymentAsync()` which returns a
> Promise that resolves on settlement or rejects on failure/timeout.

For simpler usage (AI agents, quick prototyping), see the `BeignetNode` wrapper in `src/cli/beignet-node.ts`:

```typescript
import { BeignetNode } from 'beignet/cli';

const node = await BeignetNode.create({ mnemonic: '...', network: 'regtest' });
const invoice = node.createInvoice(1000, 'test payment');
// invoice => { bolt11: "lnbcrt10n1...", paymentHash: "ab12...", amountSats: 1000 }

const payment = await node.payInvoice(invoice.bolt11);
node.destroy();
```

## Usage Guide

### Creating a LightningNode

```typescript
import { INodeConfig } from 'beignet/lightning';

const config: INodeConfig = {
  nodePrivateKey,                      // 32-byte private key
  network: 'bcrt',                     // 'bc' | 'tb' | 'bcrt'
  channelConfig: { /* optional */ },   // IChannelConfig overrides
  channelBasepoints,                   // IChannelBasepoints
  perCommitmentSeed,                   // 32-byte seed for per-commitment keys
  fundingPrivkey,                      // 32-byte funding key

  // Networking (optional)
  enableNetworking: true,              // create PeerManager
  localFeatures: FeatureFlags.empty(), // feature flags for init
  chainHashes: [chainHash],            // chain hashes for init
  autoReconnect: true,                 // auto-reconnect on disconnect
  maxReconnectDelay: 300_000,          // max 5 min between retries
};

const node = new LightningNode(config);
```

### DNS Bootstrap (BOLT 10)

```typescript
// Discover peers via DNS seeds
const peers = await node.bootstrapPeers();
// => IPeerAddress[] { pubkey, host, port }

// Discover and connect in one step
const connected = await node.connectToSeeds(3); // connect up to 3
// => string[] of connected pubkey hex strings

// Custom DNS seeds
const peers = await node.bootstrapPeers({
  seeds: [{ hostname: 'nodes.lightning.directory' }],
  maxPeers: 10,
  timeoutMs: 5000,
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
```

### Channel Lifecycle

```typescript
// 1. Open channel (sends open_channel message)
const channel = node.openChannel(peerPubkey, 1_000_000n); // 1M sats

// 2. Create funding transaction
const channelId = node.createFunding(channel, fundingTxid, outputIndex, signature);

// 3. Confirm funding (after tx is mined)
node.handleFundingConfirmed(channelId);
// Emits 'channel:ready' when both sides confirm

// 4. Normal operation -- send/receive HTLCs

// 5. Cooperative close
node.closeChannel(channelId, scriptPubkey);

// 5b. Force close (unilateral)
node.forceCloseChannel(channelId, destinationScript);
```

### Zero-Conf Channels

Open channels that are usable immediately before the funding transaction confirms. Only use with trusted peers.

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
// Anchors are negotiated by default — no config needed.
const node = new LightningNode({ ...config });

// Escape hatch: force legacy static_remotekey (non-anchor) channels.
const legacyNode = new LightningNode({
  ...config,
  preferAnchors: false,
});

// Channels negotiate anchor channel_type with peers that also support it,
// and fall back to non-anchor with peers that don't.
```

### Dual-Funded Channels (v2)

Open channels where both peers contribute funding.

```typescript
// Open a dual-funded channel
const channel = node.openChannelV2(peerPubkey, {
  fundingSatoshis: 1_000_000n,       // our contribution
  fundingFeeratePerkw: 253,          // optional, defaults to channel config
  commitmentFeeratePerkw: 253,       // optional
  locktime: 0,                       // optional
});
// Negotiation proceeds: open_channel2 -> accept_channel2
// -> interactive TX construction (tx_add_input, tx_add_output, tx_complete)
// -> tx_signatures -> channel_ready
```

### Splicing

Add or remove funds from an existing channel without closing it. Requires quiescence (STFU protocol).

```typescript
// Splice-in: add 100,000 sats to the channel
const result = node.spliceIn(channelId, 100_000n, 253);
// => { ok: boolean; error?: string }

// Splice-out: withdraw 50,000 sats from the channel
const result = node.spliceOut(channelId, 50_000n, 253);
// => { ok: boolean; error?: string }

// Flow: STFU exchange -> splice/splice_ack -> interactive TX
// -> tx_signatures -> splice_locked (both sides)
```

### Invoice Management

```typescript
// Create an invoice — returns { bolt11, paymentHash, paymentSecret }
const result = node.createInvoice({
  amountMsat: 50_000_000n,    // 50,000 sats
  description: 'Coffee',
  expiry: 3600,                // optional, default 3600s
  minFinalCltvExpiry: 40,      // optional, default 40
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
  descriptionHash: descHash,
});

// Decode any BOLT 11 invoice
import { decode } from 'beignet/lightning';
const invoice = decode(result.bolt11);
// => { paymentHash, amountMsat, description, network, ... }
```

### BOLT 12 Offers

Create reusable payment requests and request/pay invoices via onion messages.

```typescript
// Create an offer
const { offer, encoded } = node.createOffer({
  amount: 50_000_000n,         // optional: omit for "any amount"
  description: 'Coffee',
  issuer: 'My Shop',           // optional
  absoluteExpiry: 1700000000n, // optional
});
// encoded => "lno1..." (bech32m with lno prefix)

// Request an invoice for an offer (sent via onion message)
const invoice = await node.requestInvoice(offer, {
  amount: 50_000_000n,         // required if offer has no amount
  quantity: 2n,                // optional
  payerNote: 'Table 5',        // optional
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

// Manual route: specify exact path
const payment = node.sendPaymentToRoute(route, paymentHash, finalCltvExpiry);
```

### Waiting for Payments

```typescript
// Wait for a specific incoming payment (useful for AI agents)
const result = node.createInvoice({ amountMsat: 50_000_000n, description: 'Coffee' });
const payment = await node.waitForPayment(result.paymentHash, 30_000);
// Resolves immediately if already settled, or waits up to 30s
// Rejects with timeout error if not received in time
```

### Balance

```typescript
// Get aggregate Lightning balance across all active channels
const balance = node.getBalance();
// => { localBalanceMsat: bigint, remoteBalanceMsat: bigint, unsettledBalanceMsat: bigint }
```

### Channel Health Assessment

```typescript
// Get liquidity health for a specific channel
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
node.on('log', (entry: IStructuredLog) => {
  // entry.category: 'payment' | 'channel' | 'htlc' | 'fee' | 'peer' | 'chain'
  // entry.action: e.g. 'sent', 'received', 'failed', 'ready', 'closed'
  // entry.timestamp: unix ms
  // entry.data: operation-specific fields (paymentHash, channelId, amountMsat, etc.)
  console.log(`[${entry.category}:${entry.action}]`, entry.data);
});

// Emitted on: payment sent/received/failed, channel ready/closed
```

### Receiving Payments

Incoming payments are auto-fulfilled when the preimage is known (from `createInvoice`):

```typescript
node.on('payment:received', (payment: IPaymentInfo) => {
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
graph.getChannel(scid);
graph.getNode(pubkey);

// Find a route
import { findRoute } from 'beignet/lightning';
const route = findRoute(graph, source, destination, amountMsat, finalCltv);
// => { hops: [...], totalAmountMsat, totalCltvDelta, totalFeeMsat }

// With routing hints (for invoices with private channels):
import { IRoutingHintHop } from 'beignet/lightning';
const route = findRoute(graph, source, destination, amountMsat, finalCltv,
  undefined, undefined, undefined, undefined, invoice.routingHints);
// Routing hints inject synthetic edges for private channels not in the gossip graph
```

### HTLC Forwarding

Multi-hop payments are forwarded automatically. Register SCIDs to enable forwarding:

```typescript
// Map a short channel ID to a channel
node.registerChannelScid(channelId, scid);

// Listen for forwarding events
node.on('htlc:forward', (fromChannelId, toChannelId, amountMsat, paymentHash) => {
  console.log('Forwarded HTLC:', amountMsat, 'msat');
});
```

### Chain Monitoring

```typescript
// Handle funding output being spent (force close detection)
node.handleFundingSpent(channelId, spendingTx, blockHeight, destinationScript);

// Advance block height (triggers timelock checks)
node.handleNewBlock(blockHeight);
```

## Events Reference

| Event | Arguments | Description |
|-------|-----------|-------------|
| `payment:received` | `(payment: IPaymentInfo)` | Incoming HTLC fulfilled |
| `payment:sent` | `(payment: IPaymentInfo)` | Outgoing payment completed |
| `payment:failed` | `(payment: IPaymentInfo)` | Outgoing payment failed |
| `channel:ready` | `(channelId: Buffer)` | Channel reached NORMAL state |
| `channel:closed` | `(channelId: Buffer)` | Channel closed |
| `message:outbound` | `(peerPubkey: string, type: number, payload: Buffer)` | Message to send to peer |
| `htlc:forward` | `(fromChannelId: Buffer, toChannelId: Buffer, amountMsat: bigint, paymentHash: Buffer)` | HTLC forwarded |
| `peer:connect` | `(pubkey: string)` | Peer connected (networking mode) |
| `peer:disconnect` | `(pubkey: string)` | Peer disconnected (networking mode) |
| `peer:error` | `(pubkey: string, error: Error)` | Peer error (networking mode) |
| `broadcast:tx` | `(tx: Buffer)` | Transaction to broadcast on-chain |
| `onion:received` | `(payload: IOnionMessagePayload)` | Onion message received (type 513) |
| `offer:created` | `(offer: IOffer)` | BOLT 12 offer created |
| `bolt12:invoice:received` | `(invoice: IBolt12Invoice)` | BOLT 12 invoice received |
| `node:error` | `(error: ILightningError)` | Operational error (non-fatal) |
| `node:ready` | `()` | Node fully operational (peers reconnected, channels restored) |

## Typed Payment Errors

`sendPayment()` and `sendPaymentToRoute()` throw `LightningPaymentError` with a typed `code` property:

| Code | Thrown When |
|------|------------|
| `NO_ROUTE` | No route found to destination |
| `DUPLICATE_PAYMENT` | Payment hash already in-flight |
| `NO_CHANNEL_TO_HOP` | No channel to first hop peer |
| `FEE_EXCEEDS_MAX` | Route fee exceeds `maxFeeMsat` |
| `MISSING_AMOUNT` | Amount-less invoice with no `amountMsat` override |
| `INVALID_INVOICE` | Cannot determine payee from invoice |
| `INVOICE_EXPIRED` | Invoice has expired |

```typescript
import { LightningPaymentError, LightningErrorCode } from 'beignet/lightning';

try {
  node.sendPayment(invoice);
} catch (err) {
  if (err instanceof LightningPaymentError) {
    console.log(err.code); // e.g. LightningErrorCode.NO_ROUTE
  }
}
```

## Node Readiness

After creating a node with `fromMnemonic()` or restoring from storage, use `waitForReady()` to block until peers are reconnected and channels are restored:

```typescript
const node = LightningNode.fromMnemonic(mnemonic, { storage, enableNetworking: true });
await node.waitForReady(30_000); // resolves when peers reconnected, or after 30s timeout
```

The `node:ready` event fires once when the node is fully operational. If no peers need reconnection, it fires immediately via `process.nextTick()`.

## INodeConfig: `reestablishTimeoutBlocks`

Channels stuck in `AWAITING_REESTABLISH` (peer disappeared permanently) are auto-force-closed after `reestablishTimeoutBlocks` blocks (default: 2016, ~2 weeks). Configure via `INodeConfig`:

```typescript
const node = LightningNode.fromMnemonic(mnemonic, {
  reestablishTimeoutBlocks: 1008, // ~1 week instead of default 2 weeks
});
```

## Module Reference

| Module | Files | Key Exports | BOLT |
|--------|-------|-------------|------|
| `bootstrap` | 4 | `bootstrapPeers`, `resolveDnsSeed`, `DEFAULT_DNS_SEEDS` | 10 |
| `crypto` | 4 | `chacha20poly1305`, `ecdh`, `hkdf` | 8 |
| `message` | 17 | Message encode/decode for all types, `codec`, `tlv`, `stfu`, interactive-tx, dual-funding, splice | 1, 2 |
| `features` | 2 | `FeatureFlags` | 9 |
| `transport` | 5 | `Peer`, `PeerManager`, `CipherState`, `NoiseState` | 8 |
| `keys` | 5 | `derivation`, `shachain`, `signer`, `wallet-keys` | 3 |
| `script` | 6 | `funding`, `commitment`, `htlc`, `revocation`, `anchor` | 3 |
| `channel` | 12 | `Channel`, `ChannelManager`, `CommitmentBuilder`, `ZeroConfManager`, `QuiescenceManager`, `DualFundingSession`, `SpliceSession` | 2 |
| `interactive-tx` | 4 | `InteractiveTxBuilder`, serial ID validation | 2 |
| `chain` | 8 | `ChainMonitor`, `OutputResolver`, `ChainWatcher`, `closing`, `sweep` | 5 |
| `invoice` | 7 | `encode`, `decode`, `amount`, `signing`, `words` | 11 |
| `gossip` | 9 | `NetworkGraph`, `findRoute`, `GossipSyncManager`, `messages`, `validation` | 7 |
| `onion` | 9 | `constructOnionPacket`, `processOnionPacket`, `failures`, `constructBlindedPath`, `processBlindedHop` | 4 |
| `onion-message` | 6 | `OnionMessageManager`, `constructSimpleOnionMessage`, `processOnionMessage` | 4 |
| `offer` | 8 | `OfferManager`, `encodeOffer`, `decodeOffer`, TLV, Schnorr, merkle | 12 |
| `node` | 3 | `LightningNode` | -- |
| `storage` | 4 | `SqliteStorage`, `IStorageBackend`, `serialization` | -- |
| `wallet` | 2 | `WalletFundingProvider`, `IFundingProvider` | -- |
| `advisor` | 3 | `LiquidityAdvisor`, `FeeAdvisor`, `ChannelSuggestions` | -- |
| `validation` | 1 | Input validation utilities | -- |

**Total: 120 implementation files across 20 modules.**

## Testing

```bash
# Run lightning unit tests (excludes interop — no Docker needed)
npm run test:lightning

# Run interop tests against LND/CLN/Eclair (requires Docker)
npm run test:interop

# Run everything (unit + interop)
npm run test:all

# Run specific module tests
npx mocha --exit -r ts-node/register 'tests/lightning/node.test.ts'
npx mocha --exit -r ts-node/register 'tests/lightning/channel.test.ts'
npx mocha --exit -r ts-node/register 'tests/lightning/offer.test.ts'
npx mocha --exit -r ts-node/register 'tests/lightning/dual-funding.test.ts'
```

### Test Patterns

- **Two-party simulation**: Nodes are wired via `message:outbound` event loopback -- no TCP required
- **Synchronous loopback**: The entire HTLC fulfill chain completes synchronously during `addHtlc()`
- **Graph population**: Tests inject gossip data directly into `NetworkGraph` rather than using signed messages
- **Crypto verification**: Signed gossip messages use real cryptographic signatures for validation tests
- **Docker interop**: LND, CLN, and Eclair interop tests auto-skip when Docker containers are unavailable

### Test Coverage

| Phase | Module | Tests |
|-------|--------|-------|
| 0 | Crypto & Messages | 115 |
| 1 | Transport (BOLT 8) | 73 |
| 2 | Keys & Scripts (BOLT 3) | -- |
| 3 | Channel State Machine (BOLT 2) | 161 |
| 4 | Chain Monitor (BOLT 5) | 67 |
| 5 | Invoices (BOLT 11) | 98 |
| 6 | Gossip & Routing (BOLT 7) | 104 |
| 7 | Onion & Payments (BOLT 4) | 83 |
| 8-9 | Node API + PeerManager | 68 |
| 10 | Interop (LND + CLN + Eclair) | 87 |
| 11 | Production Hardening | -- |
| -- | Bootstrap (BOLT 10) | 41 |
| -- | Zero-Conf Channels | 54 |
| -- | Quiescence (STFU) | 46 |
| -- | Interactive TX | 107 |
| -- | Dual-Funding (v2) | 95 |
| -- | Splicing | 115 |
| -- | Route Blinding | 45 |
| -- | Onion Messages | 69 |
| -- | Offers (BOLT 12) | 102 |
| -- | Production Hardening 7 | 45 |
| -- | Production Hardening 8 | 18 |
| -- | Production Hardening 9-10 | 62 |
| -- | Electrum Timeouts | 12 |
| -- | Storage Resilience | 8 |
| -- | Memory Cleanup | 7 |
| **Total** | | **2580+** |

Counts are individual test cases (`it(...)` blocks) across ~136 test files, not file counts.

Interop tests are excluded from `npm run test:lightning`. Use `npm run test:interop` to run them with Docker.

## BOLT Specification Coverage

| BOLT | Name | Status |
|------|------|--------|
| 1 | Base Protocol | Complete (init, error, ping/pong) |
| 2 | Channel Management | Complete (full state machine, 20+ message types, dual-funding, quiescence, splicing, zero-conf) |
| 3 | Transactions | Complete (funding, commitment, HTLC, revocation, anchor scripts) |
| 4 | Onion Routing | Complete (Sphinx, hop payloads, failure handling, route blinding, onion messages) |
| 5 | On-chain Handling | Complete (force close, sweep, output resolution, chain watcher) |
| 7 | Gossip Protocol | Complete (announcements, graph, Dijkstra pathfinding, gossip sync) |
| 8 | Transport | Complete (Noise_XK, ChaCha20-Poly1305 framing) |
| 9 | Feature Flags | Complete (bit manipulation, init negotiation) |
| 10 | DNS Bootstrap | Complete (SRV resolution, seed nodes, peer discovery) |
| 11 | Invoices | Complete (encode, decode, signing, amount parsing) |
| 12 | Offers | Complete (TLV encode/decode, Schnorr signing, merkle tree, bech32m, lno/lnr/lni prefixes) |
