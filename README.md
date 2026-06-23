# Beignet

A self-custodial Bitcoin wallet library for JavaScript/TypeScript, with a full Lightning Network implementation.

## Overview

Beignet provides two layers of Bitcoin wallet functionality:

- **On-chain wallet** — HD key management, address generation, UTXO tracking, transaction building, and Electrum server connectivity.
- **Lightning Network** — A complete BOLT-compliant Lightning implementation in TypeScript, supporting channel management, onion-routed payments, BOLT 11 invoices, gossip-based routing, and real TCP transport. Tested against LND, CLN, and Eclair on regtest.

## Table of Contents

1. [Getting Started](#getting-started)
2. [On-Chain Wallet](#on-chain-wallet)
3. [Lightning Network](#lightning-network)
   - [Lightning Quick Start (BeignetNode)](#lightning-quick-start-beignetnode)
   - [Decision-Support APIs](#decision-support-apis)
   - [HTTP Daemon](#http-daemon)
   - [Advanced API (LightningNode)](#advanced-api-lightningnode)
   - [Architecture](#architecture)
   - [BOLT Coverage](#bolt-coverage)
   - [Module Reference](#module-reference)
4. [Running Tests](#running-tests)
5. [Interop Testing](#interop-testing)
6. [React Native](#react-native)
7. [Documentation](#documentation)
8. [Support](#support)

## Getting Started

```bash
# Using npm
npm install beignet

# Using Yarn
yarn add beignet
```

> Requires **Node.js 18+**

### Build from source

```bash
git clone git@github.com:coreyphillips/beignet.git && cd beignet
npm install && npm run build
```

### Run the examples

Both examples launch an interactive REPL with a live wallet/node instance:

```bash
# On-chain wallet REPL
npm run example

# Lightning node REPL (recommended — uses BeignetNode)
npm run example:lightning

# Low-level Lightning node REPL (uses LightningNode directly)
npm run example:lightning -- --low-level

# Lightning node with a specific mnemonic and alias
npm run example:lightning -- abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about --alias mynode

# Two-node payment flow demo (shows complete lifecycle)
npm run example:lightning -- --payment-flow
```

## On-Chain Wallet

```javascript
import { Wallet, generateMnemonic } from 'beignet';

const mnemonic = generateMnemonic();

const createRes = await Wallet.create({ mnemonic });
if (createRes.isErr()) return;
const wallet = createRes.value;

// Get receiving address
const address = await wallet.getAddress();

// Get wallet balance
const balance = wallet.getBalance();

// Send sats
const sendRes = await wallet.send({
  address: 'bc1q...',
  amount: 50000,
  satPerByte: 2,
});

// Refresh wallet state from Electrum
await wallet.refreshWallet();
```

### Advanced On-Chain Usage

```typescript
import { Wallet, generateMnemonic } from 'beignet';
import net from 'net';
import tls from 'tls';

const wallet = await Wallet.create({
  mnemonic: generateMnemonic(),
  passphrase: 'optional-passphrase',
  electrumOptions: {
    servers: { host: '127.0.0.1', ssl: 50002, tcp: 50001, protocol: 'ssl' },
    net,
    tls,
  },
  network: 'mainnet',
  addressType: 'p2wpkh',
  coinSelectPreference: 'consolidate',
});

// Send to multiple outputs
await wallet.value.sendMany({
  txs: [
    { address: 'addr1', amount: 1000 },
    { address: 'addr2', amount: 2000 },
  ],
});

// Sweep a private key
await wallet.value.sweepPrivateKey({
  privateKey: 'L...',
  toAddress: 'bc1q...',
  satsPerByte: 5,
});

// List UTXOs
const utxos = wallet.value.listUtxos();

// Get transaction history
const history = await wallet.value.getAddressHistory('bc1q...');
```

## Lightning Network

### Lightning Quick Start (BeignetNode)

`BeignetNode` (from `beignet/cli`) is the recommended API — it wraps the protocol layer with a simpler, JSON-friendly interface: satoshi-denominated amounts, string channel IDs, and structured error codes.

For detailed deployment guidance, see [AI Agent Deployment Guide](docs/AI_AGENT_GUIDE.md).

```typescript
import { BeignetNode, isRetryableError } from 'beignet/cli';

// Create a node (auto-creates wallet, storage, funding provider)
const node = await BeignetNode.create({
  mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  network: 'regtest',
  electrumHost: '127.0.0.1',
  electrumPort: 60001,
});

// Get node info and health
console.log(node.getInfo());    // { nodeId, network, alias, ... }
console.log(node.getHealth());  // { status: 'ready', peers, channels, ... }
console.log(node.isReady());    // true when node has active channels

// Create an invoice
const inv = node.createInvoice(1000, 'coffee');
console.log(inv.bolt11);

// Pay an invoice with automatic retry logic
try {
  const payment = await node.payInvoice('lnbcrt10n1...');
  console.log(payment.status); // 'COMPLETED'
} catch (err) {
  if (isRetryableError(err)) {
    // Transient failure — safe to retry (no route, timeout, etc.)
  } else {
    // Permanent failure — do not retry (invalid invoice, expired, etc.)
  }
}

// List channels, payments, invoices
console.log(node.listChannels());
console.log(node.listPayments());
console.log(node.listInvoices());

// Clean shutdown
await node.destroy();
```

### Decision-Support APIs

Beignet includes built-in advisors that differentiate it from other Lightning libraries:

```typescript
// Channel balance analysis with actionable recommendations
const liquidity = node.getLiquiditySnapshot();
console.log('Outbound:', liquidity.outboundLiquidityPct + '%');
for (const rec of liquidity.recommendations) {
  console.log(`[${rec.priority}] ${rec.type}: ${rec.reason}`);
}

// Graph-based peer suggestions for channel opens
const suggestions = node.getChannelSuggestions(3);

// On-chain fee trend analysis (OPEN_NOW / WAIT / NEUTRAL)
const fees = node.getFeeSnapshot();

// Payment success probability + estimated fee before sending
const estimate = node.estimatePayment(bolt11);

// 11-check mainnet readiness report with weighted score
const readiness = node.getMainnetReadiness();
console.log('Score:', readiness.score + '/100', 'Ready:', readiness.ready);
```

### HTTP Daemon

BeignetNode can also run as an HTTP/SSE daemon for language-agnostic integrations:

```bash
# Start the daemon (generates OpenAPI spec at /openapi.json)
npx beignet --mnemonic "abandon ..." --network regtest --electrum-host 127.0.0.1 --electrum-port 60001

# Create an invoice
curl -X POST http://localhost:2112/invoice/create -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' -d '{"amountSats": 1000, "description": "coffee"}'

# Pay an invoice
curl -X POST http://localhost:2112/invoice/pay -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' -d '{"bolt11": "lnbcrt10n1..."}'

# Stream events (payments, channel state changes)
curl -N http://localhost:2112/events -H 'Authorization: Bearer <token>'

# Simple readiness check (auth-exempt, for load balancers)
curl http://localhost:2112/ready
```

#### Response Format

All responses use: `{ "ok": true, "result": {...} }` or `{ "ok": false, "error": { "code": "...", "message": "..." } }`.
Full spec: `GET /openapi.json` (no auth required).

### Advanced API (LightningNode)

Most users should use `BeignetNode` above. Use `LightningNode` only if you need direct access to the protocol layer (bigint amounts, Buffer IDs, raw BOLT messages).

```typescript
import { Wallet, generateMnemonic } from 'beignet';
import { LightningNode, WalletFundingProvider, Network } from 'beignet/lightning';
import net from 'net';
import tls from 'tls';

const mnemonic = generateMnemonic();

// 1. Create an on-chain wallet (same mnemonic funds both layers)
const wallet = (await Wallet.create({
  mnemonic,
  electrumOptions: { net, tls },
})).value;

// 2. Create a Lightning node with auto-funding from the wallet
const fundingProvider = new WalletFundingProvider(wallet);
const node = LightningNode.fromMnemonic(mnemonic, {
  network: Network.REGTEST,
  enableNetworking: true,
  fundingProvider,
});

// 3. Connect to a peer and open a channel — fully automatic
await node.connectPeer('03...pubkey', '127.0.0.1', 9735);
node.openChannel('03...pubkey', 100_000n);

// 4. Create a BOLT 11 invoice
const invoice = node.createInvoice({
  amountMsat: 50_000n,
  description: 'Payment for coffee',
});

// 5. Pay a BOLT 11 invoice
node.sendPayment(invoiceString);

// 6. Listen for events
node.on('channel:ready', (channelId) => {
  console.log('Channel ready:', channelId.toString('hex'));
});
node.on('payment:received', (payment) => {
  console.log('Received:', payment.amountMsat, 'msat');
});
node.on('node:error', (err) => {
  console.error(`[${err.code}]`, err.message);
});
```

**Without a wallet** — you can skip `fundingProvider` and handle funding manually:

```typescript
const node = LightningNode.fromMnemonic(mnemonic, {
  network: Network.REGTEST,
  enableNetworking: true,
});

const channel = node.openChannel('03...pubkey', 100_000n);
// Build your own funding tx, then:
const channelId = node.createFunding(channel, fundingTxid, outputIndex, signature);
```

### Architecture

Beignet's Lightning implementation follows a layered, transport-agnostic design:

```
LightningNode              ← High-level API (EventEmitter)
  ├── ChannelManager       ← Multiplexes messages to Channel instances
  │     └── Channel        ← BOLT 2 state machine (returns ChannelAction[])
  ├── PeerManager          ← TCP connections + Noise_XK encrypted transport
  │     └── Peer           ← Per-connection BOLT 8 handshake + message framing
  ├── NetworkGraph         ← BOLT 7 gossip topology + Dijkstra pathfinding
  ├── InvoiceManager       ← BOLT 11 encode/decode/sign
  ├── ChainMonitor         ← BOLT 5 force-close detection + sweep
  └── FundingProvider?     ← Auto-builds + broadcasts funding txs (via Wallet)
```

**Key design principle:** The `Channel` class is fully transport-agnostic. Every method returns `ChannelAction[]` arrays (send message, broadcast tx, watch output, etc.) that the `ChannelManager` maps to real transport or chain operations. This makes the state machine fully testable without network I/O.

### BOLT Coverage

| BOLT | Specification | Status |
|------|--------------|--------|
| 1 | Base Protocol | Peer messaging, init, error, ping/pong, feature negotiation |
| 2 | Channel Management | Full state machine: open, fund, normal operation, shutdown, close, reestablish |
| 3 | Transactions | Commitment txs, HTLC scripts, funding scripts, anchor outputs, fee calculation |
| 4 | Onion Routing | Sphinx encryption, TLV hop payloads, payment_secret, failure codes |
| 5 | On-Chain | Force-close detection, HTLC sweep, output resolution, chain monitoring, wallet-funded anchor fee bumping (commitment CPFP + zero-fee HTLC fee-attach) |
| 7 | Gossip | Channel/node announcements, network graph, Dijkstra routing, gossip sync |
| 8 | Transport | Noise_XK handshake, encrypted transport, key rotation |
| 9 | Features | DATA_LOSS_PROTECT, STATIC_REMOTE_KEY, PAYMENT_SECRET, TLV_ONION, CHANNEL_TYPE, GOSSIP_QUERIES, ANCHORS_ZERO_FEE_HTLC_TX (default) |
| 11 | Invoices | Encode, decode, sign, verify, amount formatting |

### Module Reference

The Lightning implementation is organized into 14 modules under `src/lightning/`:

| Module | Description |
|--------|-------------|
| `crypto/` | ChaCha20-Poly1305 AEAD, ECDH, HKDF key derivation |
| `message/` | Wire protocol encode/decode for all channel, gossip, and control messages |
| `features/` | Feature flag bitmap management (BOLT 9) |
| `transport/` | Noise_XK handshake, encrypted transport cipher, TCP peer connections, PeerManager |
| `keys/` | HD key derivation, per-commitment secrets (shachain), transaction signing, wallet key derivation |
| `script/` | Funding (2-of-2 multisig), commitment tx outputs, HTLC scripts, revocation, anchor outputs |
| `channel/` | Channel state machine, ChannelManager, commitment builder, channel actions, validation |
| `chain/` | ChainMonitor, ChainWatcher, output resolver, closing tx, sweep tx, Electrum backend |
| `invoice/` | BOLT 11 invoice encoding/decoding, bech32 word conversion, signature verification |
| `gossip/` | NetworkGraph, Dijkstra pathfinding, gossip sync state machine, SCID encoding |
| `onion/` | Sphinx crypto, onion packet construction/processing, hop payloads, failure handling |
| `node/` | LightningNode orchestrator — the main entry point for the Lightning API |
| `wallet/` | WalletFundingProvider — adapts the on-chain Wallet for auto-funded channel opens |
| `bootstrap/` | DNS seed resolution for discovering initial Lightning peers |

| `advisor/` | Liquidity, fee, and channel suggestion advisors for AI agents |
| `storage/` | SQLite persistence backend, channel state serialization/deserialization |
| `validation/` | Input validation utilities shared across modules |

The `BeignetNode` wrapper (`src/cli/beignet-node.ts`) provides a simplified, JSON-friendly API on top of `LightningNode` for AI agents and programmatic use.

### LightningNode API

`LightningNode` is an `EventEmitter` that provides the high-level API:

**Peer Management:**
- `connectPeer(pubkey, host, port)` — Establish encrypted connection
- `disconnectPeer(pubkey)` — Disconnect from peer
- `listPeers()` — List connected peers
- `getNodeId()` — Get this node's public key

**Channel Operations:**
- `openChannel(peerPubkey, fundingSatoshis, pushMsat?)` — Open a channel (auto-funds when `fundingProvider` is set)
- `createFunding(channel, txid, outputIndex, signature)` — Manual funding (when no `fundingProvider`)
- `handleFundingConfirmed(channelId)` — Notify funding tx confirmed
- `closeChannel(channelId, scriptPubkey)` — Cooperative close
- `forceCloseChannel(channelId, destinationScript)` — Force close (unilateral)
- `listChannels()` — List all channels
- `getChannel(channelId)` — Get channel details

**Payments:**
- `createInvoice(options)` — Generate a BOLT 11 invoice
- `sendPayment(invoiceString)` — Send a payment
- `sendPaymentToRoute(route, paymentHash, ...)` — Send via explicit route

**Chain Events:**
- `handleNewBlock(height)` — Process new block
- `handleOutputSpent(txid, index, spendingTx, height)` — Track spent outputs

**Events:**
- `payment:received` — Incoming payment fulfilled
- `payment:sent` — Outgoing payment succeeded
- `payment:failed` — Outgoing payment failed
- `channel:ready` — Channel entered NORMAL state
- `channel:closed` — Channel closed
- `peer:connect` / `peer:disconnect` — Peer connection changes
- `node:error` — Structured error (code, message, channelId, timestamp)

## Running Tests

```bash
# Run lightning unit tests (2740+ tests, no infrastructure needed)
npm run test:lightning

# Run CLI unit tests (720 CLI tests, no infrastructure needed)
npm run test:cli

# Run daemon/Electrum integration tests (requires Electrum server)
npm run test:integration

# Run interop tests against LND/CLN/Eclair (requires Docker)
npm run test:interop

# Run everything (requires Docker + Electrum)
npm run test:all
```

### Test Coverage

The Lightning implementation has **2740+ lightning unit tests + 129 interop tests + 720 CLI tests** across many phases:

| Phase | Tests | Coverage |
|-------|-------|---------|
| Crypto & Messages | 115 | ChaCha20-Poly1305, HKDF, ECDH, codec, TLV, init, error, feature flags |
| Transport (BOLT 8) | — | Noise_XK handshake, cipher, ping/pong, peer connections, PeerManager |
| Keys & Scripts (BOLT 3) | — | Key derivation, shachain, signer, funding, commitment, HTLC, revocation |
| Channel State Machine (BOLT 2) | 161 | Message encode/decode, channel types, validation, Channel, commitment builder, ChannelManager |
| Chain Monitor (BOLT 5) | 67 | Closing tx, sweep tx, output resolver, chain monitor, force close |
| Invoices (BOLT 11) | 98 | Types, words, amount, signing, decode, encode |
| Gossip & Routing (BOLT 7) | 104 | SCID, messages, validation, network graph, pathfinding |
| Onion & Payments (BOLT 4) | 83 | Sphinx crypto, hop payloads, onion construction/processing, failure handling |
| Node API | 50 | LightningNode orchestrator, invoice management, payment send/receive, HTLC forwarding |
| PeerManager Integration | 18 | PeerManager wiring, peer management, event forwarding |
| Production Hardening | — | Error visibility, input validation, resource management, BOLT 1 error propagation |
| **Interop (LND/CLN/Eclair)** | **129** | **Multi-implementation interop: TCP handshake, channel lifecycle, bidirectional payments, anchor channels, anchor force-close with wallet-funded CPFP + HTLC-timeout fee-attach, crash recovery against LND v0.20.0, CLN, and Eclair** |

## Interop Testing

The interop test suite validates beignet against real Lightning implementations on Bitcoin regtest.

### Prerequisites

- Docker and Docker Compose
- Node.js 18+

### Setup

```bash
# Start bitcoind + LND + CLN + Eclair containers
docker compose -f docker/docker-compose.yml up -d

# Wait for nodes to sync (~30 seconds)

# Run interop tests
npm run test:interop
```

### What's Tested

#### LND (43 tests)

| Tier | Tests | Validates |
|------|-------|-----------|
| **1: TCP & Init** | 5 | BOLT 8 Noise_XK handshake, BOLT 1 init exchange, feature negotiation, disconnect/reconnect, ping/pong survival |
| **2: Channel Open** | 3 | LND opens channel to beignet, balance verification, error-free lifecycle |
| **3: LND pays beignet** | 3 | Receive payment from LND, payment_secret validation, multiple sequential payments |
| **4: Beignet pays LND** | 3 | Pay LND invoice, outbound payment_secret, graceful failure handling |
| **5-9: Advanced** | 11 | Channel close, reestablish, gossip sync, MPP payments, SCID aliases |
| **10: Inbound connections** | 4 | LND connects to beignet listener, channel open from inbound peer |
| **11-13: Anchor & Recovery** | 14 | Anchor channels, beignet-funded opens, crash recovery |

#### CLN (42 tests)

| Tier | Tests | Validates |
|------|-------|-----------|
| **1: TCP & Init** | 5 | BOLT 8 handshake, init exchange, feature negotiation |
| **2-9: Channel & Payments** | 23 | Channel lifecycle, bidirectional payments, close, reestablish, gossip, MPP, SCID aliases |
| **10: Inbound** | 4 | Inbound connections from CLN |
| **12-14: Anchor & Recovery** | 10 | Anchor channels, beignet-funded opens, crash recovery |

#### Eclair (42 tests)

| Tier | Tests | Validates |
|------|-------|-----------|
| **1: TCP & Init** | 5 | BOLT 8 handshake, init exchange, feature negotiation |
| **2-9: Channel & Payments** | 23 | Channel lifecycle, bidirectional payments, close, reestablish, gossip, MPP |
| **10: Inbound** | 4 | Inbound connections from Eclair |
| **12-14: Anchor & Recovery** | 10 | Anchor channels, beignet-funded opens, crash recovery |

Interop tests are excluded from `npm run test:lightning` (which runs only unit tests). Use `npm run test:interop` to run them, or `npm run test:all` to run everything.

### Docker Compose Services

The `docker/docker-compose.yml` includes:
- **bitcoind** — Bitcoin Core regtest node (RPC port 43782, ZMQ on 28334/28335)
- **LND** — Lightning Network Daemon v0.20.0-beta (P2P port 9735, REST port 8081)
- **CLN** — Core Lightning (CLNRest API on port 3010)
- **Eclair** — ACINQ Eclair (HTTP API on port 8082)

## Known Limitations

Beignet is under active development. The following features are **not yet supported**:

| Feature | Status | Impact |
|---------|--------|--------|
| **Watchtowers** | Not implemented | If your node goes offline, a counterparty could theoretically broadcast a revoked state. Mitigate with frequent backups and auto-reconnect. |
| **LSP / LSPS protocols** | Not implemented | No automated inbound liquidity acquisition. You must manually open channels or coordinate with peers. |
| **Trampoline routing** | Not implemented | All route computation is local. Cannot delegate pathfinding to a trampoline node. |
| **BOLT 12 offers (full)** | Partial | Offer decoding and basic support exist, but end-to-end offer payment flow is incomplete. Use BOLT 11 invoices for production. |
| **Async payments** | Not implemented | Cannot receive payments while offline. Requires an always-on node. |
| **Mainnet battle-testing** | Limited | Interop-tested against LND/CLN/Eclair on regtest. Exercise caution with large mainnet balances. |
| **Mobile background** | Limited | Works on React Native but lacks mobile-specific optimizations (background sync, push notifications). |
| **Dual funding (interactive-tx)** | Partial | Protocol messages implemented but not production-tested with real peers. |

**Recommended safeguards for production use:**
- Set `maxPaymentSats` and `dailySpendLimitSats` to cap exposure
- Use `validatePayment()` before every send to catch problems early
- Enable `backupPath` for automated database backups
- Use `electrumServers` (plural) for connection redundancy
- Monitor `node:error` events and `/health` endpoint
- Start with small channel sizes and increase gradually

## React Native

You can use `react-native-tcp-socket` as a drop-in replacement for `net` & `tls`:

```json
{
  "react-native": {
    "net": "react-native-tcp-socket",
    "tls": "react-native-tcp-socket"
  }
}
```

## Documentation

- [HTML](docs/html/classes/Wallet.html)
- [Markdown](docs/markdown/classes/Wallet.md)

## Support

If you are experiencing any problems, please open an issue or reach out to us on [Telegram](https://t.me/bitkitchat).

## License

MIT
