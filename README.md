# Beignet

A self-custodial Bitcoin wallet library for JavaScript/TypeScript, with a full Lightning Network implementation.

## Overview

Beignet provides two layers of Bitcoin wallet functionality:

- **On-chain wallet** — HD key management, address generation, UTXO tracking, transaction building, and Electrum server connectivity.
- **Lightning Network** — A complete BOLT-compliant Lightning implementation in TypeScript, supporting channel management, onion-routed payments, BOLT 11 invoices, gossip-based routing, and real TCP transport. Tested against LND, CLN, and Eclair on regtest.

## Table of Contents

1. [Getting Started](#getting-started)
2. [On-Chain Wallet](#on-chain-wallet)
   - [Leveled Logging](#leveled-logging)
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

### Watch-Only Wallets

A watch-only wallet is constructed from an account-level extended public key
(xpub/ypub/zpub for mainnet, tpub/upub/vpub for testnet/regtest) instead of a
mnemonic. The key is assumed to sit at the account level
(m/purpose'/coin'/account', e.g. m/84'/0'/0' for p2wpkh), so receive and
change addresses derive publicly as xpub/0/i and xpub/1/i. SLIP-132 version
bytes are normalized automatically: a zpub/vpub implies p2wpkh and a
ypub/upub implies p2sh-p2wpkh; a plain xpub/tpub uses the `addressType`
option (default p2wpkh). Because one account xpub yields exactly one address
type, a watch-only wallet monitors only that type.

Everything read-only works: address generation, gap-limit scanning, Electrum
refresh, balances, transaction history, UTXOs, fee estimates and address
subscriptions. Anything that requires private keys
(send/sendMax/sendMany/sweepPrivateKey/getPrivateKey and the internal signing
paths) fails with the typed `WatchOnlySigningError`
(`code: 'WATCH_ONLY_CANNOT_SIGN'`, message `watch-only wallet cannot sign`).

Watch-only is a library feature only for now: the HTTP daemon always runs
with a mnemonic.

```typescript
import { Wallet } from 'beignet';

const res = await Wallet.createWatchOnly({
  xpub: 'zpub6r...',
  network: 'bitcoin',
  electrumOptions: { net, tls },
});
if (res.isErr()) return;
const watchOnly = res.value;

const address = await watchOnly.getAddress(); // works
const balance = watchOnly.getBalance(); // works
const sendRes = await watchOnly.send({ address: 'bc1q...', amount: 1000 });
// sendRes.isErr() === true; sendRes.error.message === 'watch-only wallet cannot sign'
```

### External Signer (Hardware Wallet) PSBT Flow

`buildPsbt` runs the normal transaction setup (coin selection, change, fee)
but stops before signing and returns a base64 PSBT populated with everything
a hardware signer needs: `witnessUtxo` (or `nonWitnessUtxo` for legacy
p2pkh), `redeemScript` for p2sh-p2wpkh, `tapInternalKey` plus
`tapBip32Derivation` for p2tr, and `bip32Derivation` (fingerprint + path +
pubkey) on every wallet input. It works on both full and watch-only wallets.
Note for watch-only wallets: the true master fingerprint is unknowable from
an account xpub, so the xpub's parent fingerprint is used; signers should
locate keys by derivation path.

```typescript
// 1. Build (works on a watch-only wallet)
const build = await wallet.buildPsbt({
  address: 'bc1q...',
  amount: 50000,
  satsPerByte: 4,
});
if (build.isErr()) return;
const { psbtBase64, fee, vsizeEstimate } = build.value;

// 2. Sign externally (hardware wallet / HWI / another machine)
const signedBase64 = await myHardwareWallet.signPsbt(psbtBase64);

// 3. Import: validates a signature on EVERY input, finalizes, does NOT broadcast
const imported = wallet.importSignedPsbt(signedBase64);
if (imported.isErr()) return; // missing/invalid signatures are rejected loudly
const { txHex, txid } = imported.value;

// 4. Broadcast when ready
await wallet.broadcastTransaction(txHex);

// Multi-party signing: merge partially signed copies of the same PSBT
const combined = wallet.combinePsbts([copyA, copyB]);
```

The HTTP daemon exposes the same flow on its (mnemonic-backed) wallet via
`POST /psbt/build`, `POST /psbt/import-signed` and `POST /psbt/combine`, and
the CLI via `beignet psbt build|import-signed|combine`.

### Multisig P2WSH Wallets (sortedmulti)

`Wallet.createMultisig` creates a descriptor-based sorted-multisig wallet:
`wsh(sortedmulti(threshold, key1, key2, ...))`, the interoperable standard
used by Bitcoin Core, Sparrow and Specter. Derivation follows BIP 48 with
script type 2 (`m/48'/coin'/account'/2'`, receive `/0/*`, change `/1/*`) and
public keys are ordered per BIP 67 at every index, so any wallet built from
the same account xpubs produces identical addresses regardless of the order
the cosigners were listed in.

Cosigners are supplied as account-level extended public keys (`xpub`/`tpub`,
or the SLIP-132 multisig encodings `Zpub`/`Vpub`, normalized automatically).
When a mnemonic is provided, this wallet IS one of the cosigners: its BIP 48
account xpub is derived and included automatically (pass `ourXpub` to assert
it explicitly; a mismatch is rejected). Omit the mnemonic for a watch-only
multisig coordinator: the full read-only surface (scanning, balances,
history, subscriptions) works, signing does not.

Spending is PSBT-only. Direct spends (`send`/`sendMany`/`sendMax`) fail with
the typed `MultisigSpendError` (`code: 'MULTISIG_REQUIRES_PSBT'`). `buildPsbt`
attaches the `witnessScript` and one `bip32Derivation` entry per cosigner to
every input; `signPsbtWithOurKey` adds this cosigner's partial signature
without finalizing; `importSignedPsbt` counts the VALID partial signatures on
each input against the witnessScript threshold and refuses to finalize below
it (the error names how many signatures it has and needs).
`exportDescriptors()` emits the checksummed `wsh(sortedmulti(...))` receive
and change descriptors for import into Bitcoin Core/Sparrow/Specter; our key
carries its full key origin, cosigners known only as xpubs carry a
fingerprint-only origin. Multisig is a library-only feature for now: the
HTTP daemon wallet stays single-sig.

Full 2-of-3 walkthrough:

```typescript
import { Wallet } from 'beignet';

// Each cosigner shares their BIP 48 account xpub (m/48'/0'/0'/2' on mainnet).
// Grab ours from exportDescriptors() or derive it with any BIP 48 tool.

// 1. Cosigner A creates their multisig wallet (A holds mnemonicA).
const walletA = (
  await Wallet.createMultisig({
    threshold: 2,
    mnemonic: mnemonicA, // we are one cosigner; our xpub is added automatically
    cosigners: [xpubB, xpubC],
    network: 'bitcoin',
    electrumOptions: { net, tls },
  })
).value;

// Cosigner B does the same in their own instance/machine.
const walletB = (
  await Wallet.createMultisig({
    threshold: 2,
    mnemonic: mnemonicB,
    cosigners: [xpubA, xpubC],
    network: 'bitcoin',
    electrumOptions: { net, tls },
  })
).value;

// An optional watch-only coordinator holds no keys at all.
const coordinator = (
  await Wallet.createMultisig({
    threshold: 2,
    cosigners: [xpubA, xpubB, xpubC],
    network: 'bitcoin',
    electrumOptions: { net, tls },
  })
).value;

// 2. Fund the multisig: every instance derives the same addresses.
const deposit = await walletA.getAddress(); // == walletB/coordinator address

// 3. Build the unsigned PSBT (works on any instance, coordinator included).
const built = await walletA.buildPsbt({
  address: 'bc1q...',
  amount: 50000,
  satsPerByte: 4,
});
const unsigned = built.value.psbtBase64;

// 4. Each cosigner signs their own copy (below threshold nothing finalizes).
const signedA = walletA.signPsbtWithOurKey(unsigned).value;
const signedB = walletB.signPsbtWithOurKey(unsigned).value;

// 5. Combine the partials, finalize at threshold, broadcast.
const combined = coordinator.combinePsbts([signedA, signedB]).value;
const finalized = coordinator.importSignedPsbt(combined).value; // 2-of-3 met
await coordinator.broadcastTransaction(finalized.txHex);

// Importing with only one signature fails loudly:
// 'Input 0 is below the multisig threshold: have 1 signature(s), need 2.'

// Interop: import the wallet into Bitcoin Core/Sparrow/Specter.
const descriptors = walletA.exportDescriptors().value;
// wsh(sortedmulti(2,[fp/48h/0h/0h/2h]xpub.../0/*,[fp]xpub.../0/*,...))#checksum
```

### Networks, Fee Estimates & Electrum Failover

- **Networks:** `mainnet`, `testnet`, `regtest`, and `signet` are supported end to end (on-chain wallet, Electrum, CLI/daemon via `--network signet`, and the Lightning node config, which uses the signet chain hash and `tbs` invoice prefix). Signet shares testnet's address formats and derivation paths (coin type 1); only the chain differs.
- **Fee estimation source:** `Wallet.create({ feeEstimationSource })` accepts `'electrum' | 'http' | 'auto'` (default `'auto'`). `'electrum'` queries only the connected Electrum server via `blockchain.estimatefee`, so fee lookups never leak to mempool.space/blocktank over clearnet; `'auto'` prefers Electrum and falls back to HTTP only when Electrum is unavailable or returns unusable values. All remote-sourced rates are clamped to at most 5000 sat/vB. The daemon exposes the same option as `feeEstimationSource` / `--fee-source` / `BEIGNET_FEE_SOURCE`.
- **Electrum failover:** when multiple `electrumOptions.servers` are provided, the wallet rotates through them in order on connect/reconnect failure (then through hardcoded fallback peers for the network), with a per-server cooldown so dead servers are not hammered. `wallet.electrum.currentServer` and `wallet.electrum.rotationCount` expose the current server and rotation history.
- **BIP21:** `encodeBip21({ address, amountSats?, label?, message? })` builds a `bitcoin:` payment URI; the daemon's `POST /address/new` accepts `{ bip21: true, amountSats?, label?, message? }` and the CLI supports `address --bip21 [--amount <sats>] [--label L] [--message M]`.

### Storage & Encryption

The wallet persists its state through the host-injected `TStorage` interface (`storage: { getData, setData }` on `Wallet.create`). Values are handed to the host as-is, so by default they are stored in plaintext. The persisted data is addresses, address indexes, UTXOs, transactions, balance and fee estimates. No private keys and no mnemonic are ever written, so exposure is a privacy concern (full wallet history), not fund loss.

To encrypt at rest, wrap any `TStorage` with `createEncryptedStorage` before passing it in. Values are encrypted with AES-256-GCM under a key derived from the seed via HKDF, and pre-existing plaintext values are passed through unchanged and migrate lazily as they are rewritten:

```typescript
import { createEncryptedStorage, Wallet } from 'beignet';
import * as bip39 from 'bip39';

const seed = bip39.mnemonicToSeedSync(mnemonic);
const wallet = await Wallet.create({
  mnemonic,
  storage: createEncryptedStorage({ getData, setData }, seed),
  // ...
});
```

### Leveled Logging

Diagnostic output (debug/info/warn/error) flows through a small injectable logger, kept separate from the Lightning node's persisted structured action log (`getActionLog`). The `ILogger` interface is four methods, `debug`/`info`/`warn`/`error`(`message: string, meta?: unknown`), with level filtering `debug < info < warn < error` plus `'silent'`:

```typescript
import { Wallet, createConsoleLogger, noopLogger } from 'beignet';

const wallet = await Wallet.create({
  mnemonic,
  logger: createConsoleLogger('warn'), // only warn + error reach the console
  // logger: noopLogger,               // fully silent
  // logger: myLogger,                 // any ILogger: route into your own stack
  // ...
});
```

- **`Wallet.create({ logger })`** defaults to `createConsoleLogger('info')`, which preserves the wallet's historical console output. `disableMessages` is independent and keeps its existing meaning: it only gates `onMessage` callbacks.
- **`LightningNode`** accepts `logger` in `INodeConfig` / `fromMnemonic` options and defaults to `noopLogger` (the node prints nothing, as before). Every structured action-log entry is additionally mirrored to `logger.debug('category:action', data)`.
- **`BeignetNode.create({ logger, logLevel })`**: log entries that pass `logLevel` are forwarded to the injected logger (in addition to the `'log'` event), and the logger is injected into the underlying `Wallet` and `LightningNode`. Without `logger`, behavior is unchanged (events only).
- **Daemon:** `beignet start --log-level <debug|info|warn|error|silent>` (or `BEIGNET_LOG_LEVEL`, or `logLevel` in `~/.beignet/config.json`) prints leveled diagnostics to stderr. Unset keeps the daemon silent (the default); stdout stays reserved for command output.

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

### Advisor Execution (circular rebalancing + fee auto-tuning)

The advisor can also *act*, not just recommend. Both features are **off by
default** and only run when explicitly enabled in the node options.

```typescript
// One-shot circular rebalance: self-payment out over fromChannelId and back
// in over toChannelId. Aborts WITHOUT paying if the route fee > maxFeeSats.
const result = await node.rebalanceChannel(
  fromChannelId, toChannelId, 50_000, /* maxFeeSats: */ 50
);

// Inspect what the executor would do (read-only)
const recs = node.getAdvisorRecommendations(); // analyze() + rebalancePlan[]

// Run the advisor's rebalance plan under a per-day fee budget
const summary = await node.executeRebalances(/* budgetSatsPerDay: */ 500);
```

Automatic modes (opt-in via `BeignetNodeOptions` / `INodeConfig`):

```typescript
const node = await BeignetNode.create({
  mnemonic,
  // Periodically executes the rebalance plan. Routing fees spent on
  // rebalances are capped at budgetSatsPerDay per UTC day; the running spend
  // is persisted, so restarts never overspend the same day. The budget
  // resets at midnight UTC.
  autoRebalance: { enabled: true, budgetSatsPerDay: 500, minImbalancePct: 20 },
  // Every intervalMs (default 6h) nudges each channel's proportional fee:
  // +25% when outbound is depleted (<20% local) but still forwarding,
  // -25% when the channel saw no forwards in the window, clamped to
  // [floorPpm, ceilPpm]. One adjustment per channel per interval.
  autoTuneFees: { enabled: true, floorPpm: 1, ceilPpm: 5_000 }
});
```

Daemon/CLI surfaces: `POST /rebalance`, `GET /advisor/recommendations`,
`POST /advisor/execute-rebalances`; `beignet rebalance <from> <to> <sats>
--max-fee <sats>`, `beignet advisor recommendations`, `beignet advisor
execute-rebalances [--budget <sats>]`.

### Watchtowers

Penalty enforcement normally requires this node's own chain monitor to be online:
if a counterparty broadcasts a revoked commitment while you are offline, nobody
sweeps the breach. The **watchtower client** closes that gap. At every revocation
it builds an encrypted *justice kit* (the revoked commitment's breach hint plus a
pre-signed to_local penalty) and ships it to one or more remote towers over the
standard BOLT 8 Noise transport. When a tower later sees the breach transaction on
chain, it decrypts the kit and broadcasts the penalty on your behalf — reclaiming
the channel even though you never came back online.

- **Altruist only.** Sessions use `reward = 0`; towers take no cut. There is no
  server mode (beignet is a tower *client*, not a tower).
- **LND-tower compatible.** Implements LND's `wtwire` protocol (Init/CreateSession/
  StateUpdate/DeleteSession, message types 600-607) and the version-0 justice blob
  (XChaCha20-Poly1305, breach hint = `SHA256(txid)[:16]`, key = `SHA256(txid‖txid)`),
  so it interoperates with existing public LND altruist towers.
- **Legacy + anchor channels.** The to_local revocation penalty (the fund-critical
  breach punishment) is packed for both; taproot channels are not yet backed up.
- **Durable.** Per-tower session state and the un-acked update backlog are persisted
  (encrypted at rest) and drained with exponential backoff on reconnect. An un-acked
  update is never dropped silently.

Configure towers as `pubkey@host:port` URIs (off when empty):

```ts
const node = await BeignetNode.create({
  mnemonic,
  watchtowers: ['03abc...@tower.example.com:9911']
});
```

Daemon/CLI surfaces: `GET /watchtowers`, `POST /watchtower/add`,
`DELETE /watchtower/remove`; `beignet watchtower list`, `beignet watchtower add
<pubkey@host:port>`, `beignet watchtower remove <uri>`; daemon flag `--watchtower`
(repeatable) or `BEIGNET_WATCHTOWERS` (comma-separated).

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
| 2 | Channel Management | Full state machine: open, fund, normal operation, shutdown, close, reestablish; v2 dual-funded opens (interactive-tx), splicing, quiescence |
| 3 | Transactions | Commitment txs, HTLC scripts, funding scripts, anchor outputs, fee calculation; simple taproot channels (MuSig2 funding, Schnorr HTLC sigs) |
| 4 | Onion Routing | Sphinx encryption, TLV hop payloads, payment_secret, failure codes, route blinding, onion messages |
| 5 | On-Chain | Force-close detection, HTLC sweep, output resolution, chain monitoring, wallet-funded anchor fee bumping (commitment CPFP + zero-fee HTLC fee-attach) |
| 7 | Gossip | Channel/node announcements, network graph, Dijkstra routing, gossip sync |
| 8 | Transport | Noise_XK handshake, encrypted transport, key rotation |
| 9 | Features | DATA_LOSS_PROTECT, STATIC_REMOTE_KEY, PAYMENT_SECRET, TLV_ONION, BASIC_MPP, CHANNEL_TYPE, GOSSIP_QUERIES, ANCHORS_ZERO_FEE_HTLC_TX (default), ROUTE_BLINDING, ONION_MESSAGES, QUIESCE, SCID_ALIAS, ZERO_CONF, KEYSEND, OPTION_TAPROOT, OPTION_WILL_FUND |
| 11 | Invoices | Encode, decode, sign, verify, amount formatting, hold invoices |
| 12 | Offers | Offer encode/decode, invoice_request/invoice exchange over onion messages, receive-side settlement, async payment offers |
| bLIP-51 | Liquidity Ads | lease_rates/request_funds/will_fund negotiation, lease fee accounting, CLTV-locked lessor to_local, advisor lease quoting |

### Module Reference

The Lightning implementation is organized into 21 modules under `src/lightning/`:

| Module | Description |
|--------|-------------|
| `crypto/` | ChaCha20-Poly1305 AEAD, ECDH, HKDF key derivation, MuSig2 (BIP327) for taproot channels |
| `message/` | Wire protocol encode/decode for all channel, gossip, and control messages |
| `features/` | Feature flag bitmap management (BOLT 9) |
| `transport/` | Noise_XK handshake, encrypted transport cipher, TCP peer connections, PeerManager |
| `keys/` | HD key derivation, per-commitment secrets (shachain), transaction signing, wallet key derivation |
| `script/` | Funding (2-of-2 multisig), commitment tx outputs, HTLC scripts, revocation, anchor outputs, taproot commitment/HTLC scripts |
| `channel/` | Channel state machine, ChannelManager, commitment builder, channel actions, validation, liquidity ads |
| `chain/` | ChainMonitor, ChainWatcher, output resolver, closing tx, sweep tx, Electrum backend |
| `invoice/` | BOLT 11 invoice encoding/decoding, bech32 word conversion, signature verification |
| `gossip/` | NetworkGraph, Dijkstra pathfinding, gossip sync state machine, SCID encoding |
| `onion/` | Sphinx crypto, onion packet construction/processing, hop payloads, failure handling, blinded paths |
| `onion-message/` | BOLT 4 onion message construction/processing (carries BOLT 12 and async-payment messages) |
| `offer/` | BOLT 12 offers: encode/decode, OfferManager invoice_request/invoice flows |
| `async-payments/` | Hold invoices and AsyncPaymentManager (LSP held-forward, release_held_htlc, wake) |
| `interactive-tx/` | Interactive transaction construction for v2 dual-funded opens and splicing |
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

Beignet is under active development. The following features are missing or carry caveats:

| Feature | Status | Impact |
|---------|--------|--------|
| **Watchtowers** | Client implemented (altruist) | Ships encrypted justice data to remote LND altruist towers at every revocation so a breach is punished while you are offline (see [Watchtowers](#watchtowers)). Legacy + anchor channels only; taproot channels are not yet backed up, and server mode is out of scope. |
| **LSP / LSPS protocols** | Not implemented | No automated inbound liquidity acquisition via LSPS0/1/2. Liquidity ads (bLIP-51) are supported for negotiated leases; otherwise open channels manually. |
| **Trampoline routing** | Not implemented | All route computation is local. Cannot delegate pathfinding to a trampoline node. |
| **BOLT 12 offers** | Newer | Offer creation/decoding, invoice_request/invoice over onion messages, and receive-side settlement are implemented, but the surface is newer and less battle-tested than BOLT 11. Prefer BOLT 11 invoices for production. |
| **Async payments** | Implemented (LSP-dependent) | Hold invoices plus AsyncPaymentManager let an offline receiver be paid, but the receiver's LSP must run the held-forward/wake flow. |
| **Simple taproot channels** | Experimental | Opens, payments both directions, force-close, and reestablish validated against LND v0.20 on regtest; the feature bit is still in staging upstream. Not recommended for mainnet balances yet. |
| **Splicing / dual funding** | Partial | Splice-out and splice-in validated live against CLN on mainnet; v2 dual-funded opens implemented. CLN-initiated splices, repeat splices, and multi-UTXO splice-ins are untested. |
| **Mainnet battle-testing** | Limited | Interop-tested against LND/CLN/Eclair on regtest. Exercise caution with large mainnet balances. |
| **Mobile background** | Limited | Works on React Native but lacks mobile-specific optimizations (background sync, push notifications). |

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
