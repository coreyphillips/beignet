# Beignet CLI & BeignetNode API

A simplified interface for the beignet Bitcoin + Lightning library. Two ways to use it:

1. **`BeignetNode` class** -- import into TypeScript/JS scripts
2. **`beignet` CLI** -- run shell commands that talk to an HTTP daemon

Both return plain JSON with hex string IDs and satoshi amounts (no Buffer, no bigint).

---

## Quick Start

### CLI

```bash
# Initialize (generates mnemonic, writes ~/.beignet/config.json)
npx ts-node src/cli/cli.ts init --network regtest

# Start the daemon (stays in foreground, listens on 127.0.0.1:2112)
npx ts-node src/cli/cli.ts start

# In another terminal:
npx ts-node src/cli/cli.ts info
npx ts-node src/cli/cli.ts balance
npx ts-node src/cli/cli.ts address
npx ts-node src/cli/cli.ts invoice create 1000 "coffee"
npx ts-node src/cli/cli.ts stop
```

After `npm run build`, you can also use the compiled version:

```bash
node dist/cli/cli.js start --network regtest
# or if installed globally via npm link:
beignet start --network regtest
```

### Programmatic (TypeScript)

```typescript
import { BeignetNode } from 'beignet/cli';

const node = await BeignetNode.create({
  network: 'regtest',
  electrumHost: '127.0.0.1',
  electrumPort: 60001,
});

console.log(node.getInfo());
// { nodeId: "02ab...", network: "regtest", onchainBalanceSats: 0, ... }

const addr = await node.getNewAddress();
// "bcrt1q..."

const invoice = node.createInvoice(1000, "test payment");
// { bolt11: "lnbcrt10n1...", paymentHash: "ab12...", amountSats: 1000 }

await node.destroy();
```

---

## BeignetNode API

### Factory

```typescript
const node = await BeignetNode.create({
  mnemonic?: string,        // BIP39 mnemonic; generates new if omitted
  network?: string,         // 'mainnet' | 'testnet' | 'regtest' (default: 'mainnet')
  alias?: string,           // node alias
  dataDir?: string,         // SQLite + data dir (default: ~/.beignet/data)
  electrumHost?: string,    // Electrum server host
  electrumPort?: number,    // Electrum server port
  electrumTls?: boolean,    // use TLS for Electrum
  listenPort?: number,      // listen for inbound Lightning connections
  preferAnchors?: boolean,  // anchor channels (default: true); set false for legacy static_remotekey
  autoBootstrap?: boolean,  // auto-connect to DNS seed peers on start
  autoReconnect?: boolean,  // auto-reconnect to peers on disconnect (default: true)
  electrumServers?: Array<{ host: string; port: number; tls?: boolean }>,  // failover servers
  backupPath?: string,      // enable automated backups to this path
  backupIntervalMs?: number, // backup interval (default: 6 hours, requires backupPath)
  storageEncryption?: boolean, // encrypt SQLite storage at rest with a seed-derived key (default: true)
  dailySpendLimitSats?: number, // daily spending limit in satoshis (resets at midnight UTC)
  connectTimeoutMs?: number,  // timeout for connectPeer() in ms (default: 15000)
  onError?: (error) => void, // error callback for node:error events
  logLevel?: LogLevel,       // 'debug' | 'info' | 'warn' | 'error' | 'silent' (default: 'info')
});
```

Internally wires together: `Wallet` + `LightningNode` + `SqliteStorage` + `WalletFundingProvider` + `ElectrumBackend`.

### Methods

All methods return plain objects. IDs are hex strings. Amounts are numbers in satoshis.

#### Info

| Method | Returns | Description |
|--------|---------|-------------|
| `getInfo()` | `NodeInfo` | Node ID, network, balances, peer/channel counts |
| `getMnemonic()` | `string` | The BIP39 mnemonic |
| `getBalance()` | `BalanceInfo` | `{ onchain, lightning, total, unsettledSats }` in sats |
| `signMessage(message)` | `{ signature, pubkey }` | Sign with the node key (LND-compatible: `Lightning Signed Message:` prefix, double-SHA256, compact recoverable ECDSA, zbase32). Verifiable with `lncli verifymessage` |
| `verifyMessage(message, signature)` | `{ valid, pubkey, knownNode }` | Recover the signer pubkey from an LND-style signature; `knownNode` says whether it is in our graph. Compare `pubkey` to the expected signer |

#### On-chain

| Method | Returns | Description |
|--------|---------|-------------|
| `getNewAddress()` | `Promise<string>` | Next unused bech32 receive address |
| `sendOnchain(address, amountSats, satsPerVbyte?)` | `Promise<TxInfo>` | Build, sign, broadcast tx. Returns `{ txid, hex }`. Optional fee rate. |
| `sendMaxOnchain(address, satsPerVbyte?)` | `Promise<TxInfo>` | Sweep the entire spendable balance to one address (amount = balance minus fee) |
| `bumpFeeOnchain(txid, satsPerVbyte)` | `Promise<BoostResult>` | RBF-replace an unconfirmed wallet tx at a higher fee rate (BIP 125); NOT_BOOSTABLE when RBF is unavailable |
| `boostOnchain(txid, satsPerVbyte?)` | `Promise<BoostResult>` | Fee-bump a tx: RBF when possible, else CPFP to a fresh wallet address |
| `listBoostableTransactions()` | `BoostableTransactions` | Unconfirmed wallet txs eligible for RBF and/or CPFP |
| `consolidateUtxos(satsPerVbyte?)` | `Promise<ConsolidateResult>` | Merge all UTXOs into one output at a fresh wallet address (send-max-to-self) |
| `buildPsbt(outputs, satsPerVbyte?)` | `Promise<PsbtBuildInfo>` | Build an UNSIGNED PSBT for an external signer (hardware wallet); nothing is signed or broadcast |
| `importSignedPsbt(psbtBase64)` | `PsbtImportInfo` | Validate + finalize an externally signed PSBT; returns `{ txid, txHex }` WITHOUT broadcasting |
| `combinePsbts(psbts)` | `{ psbtBase64 }` | Combine partially signed copies of the same PSBT (multi-party signing) |
| `refreshWallet()` | `Promise<void>` | Sync UTXOs from Electrum (incremental: wallet state persists in the node's SQLite DB across restarts) |

#### Peers

| Method | Returns | Description |
|--------|---------|-------------|
| `connectPeer(pubkey, host, port)` | `Promise<PeerInfo>` | Connect to Lightning peer. Times out after `connectTimeoutMs` (default 15s). |
| `disconnectPeer(pubkey)` | `void` | Disconnect peer |
| `listPeers()` | `PeerInfo[]` | List connected peers |

#### DNS Bootstrap (BOLT 10)

| Method | Returns | Description |
|--------|---------|-------------|
| `bootstrapPeers()` | `Promise<BootstrapPeerInfo[]>` | Discover peers via DNS seeds |
| `connectToSeeds(maxPeers?)` | `Promise<string[]>` | Connect to discovered seed peers |

#### Trusted Peers (Zero-Conf)

| Method | Returns | Description |
|--------|---------|-------------|
| `addTrustedPeer(pubkey)` | `TrustedPeerInfo` | Trust a peer for zero-conf channels |
| `removeTrustedPeer(pubkey)` | `TrustedPeerInfo` | Remove peer from trusted set |
| `listTrustedPeers()` | `TrustedPeerInfo[]` | List all trusted peers |

#### Channels

| Method | Returns | Description |
|--------|---------|-------------|
| `openChannel(pubkey, amountSats, pushSats?)` | `ChannelInfo` | Open channel, auto-funded from wallet |
| `openChannelAndWait(pubkey, amountSats, opts?)` | `Promise<ChannelInfo>` | Open channel + wait for NORMAL state. `opts: { pushSats?, timeoutMs? }` |
| `openZeroConfChannel(pubkey, sats, pushSats?)` | `ChannelInfo` | Open zero-conf channel (peer must be trusted) |
| `openChannelV2(pubkey, params)` | `ChannelInfo` | Open dual-funded v2 channel |
| `closeChannel(channelId)` | `{ ok, error? }` | Cooperative close |
| `forceCloseChannel(channelId)` | `{ ok, error? }` | Force close |
| `spliceIn(channelId, amountSats, feerate)` | `SpliceResult` | Add funds to existing channel |
| `spliceOut(channelId, amountSats, feerate)` | `SpliceResult` | Withdraw funds from channel |
| `listChannels()` | `ChannelInfo[]` | List all channels |
| `getChannel(channelId)` | `ChannelInfo \| null` | Get specific channel |
| `updateChannelFee(channelId, feeratePerKw)` | `{ ok: true }` | Update channel COMMITMENT feerate via update_fee (min 253). Not the routing fee policy |
| `connectAndOpenChannel(pubkey, host, port, amountSats, opts?)` | `Promise<ChannelInfo>` | Connect to peer + open channel in one call. `opts: { pushSats? }` |
| `ensureMinimumChannels(count, satsPerChannel, opts?)` | `Promise<ChannelInfo[]>` | Auto-open channels to meet minimum count. Connects to peers via gossip graph addresses before opening. `opts: { timeoutMs? }` |

#### Invoices

| Method | Returns | Description |
|--------|---------|-------------|
| `createInvoice(amountSats?, description?, expirySecs?, descriptionHash?)` | `InvoiceInfo` | Create BOLT 11 invoice. Use `descriptionHash` (hex Buffer) for hashed descriptions > 639 bytes — omit `description` when using hash. Returns `paymentSecret` for correlating incoming payments. |
| `decodeInvoice(bolt11)` | `DecodedInvoice` | Decode any BOLT 11 invoice |
| `listInvoices()` | `InvoiceInfo[]` | List all created invoices |
| `createHoldInvoice({ paymentHash, amountMsat?, amountSats?, description?, expiry? })` | `InvoiceInfo` | Hold invoice for a caller-supplied `sha256(preimage)`: the preimage stays with the caller and the incoming HTLC parks instead of settling |
| `settleHoldInvoice(preimage)` | `{ paymentHash }` | Validate `sha256(preimage)` and fulfill every parked HTLC (all MPP parts) |
| `cancelHoldInvoice(paymentHash)` | `{ paymentHash, htlcsFailed }` | Fail parked HTLCs back (`incorrect_or_unknown_payment_details`) and close the invoice |
| `listHoldInvoices()` | `HoldInvoiceInfo[]` | Hold invoices with state `OPEN\|ACCEPTED\|SETTLED\|CANCELLED` and parked totals |

##### Hold invoices

A hold (HODL) invoice decouples HTLC acceptance from settlement. The caller
generates a preimage, keeps it, and hands `sha256(preimage)` to
`createHoldInvoice`. When the payer pays, the HTLC is validated and **parked**:
the payer sees the payment as in-flight (PENDING) while the recipient decides.
`settleHoldInvoice(preimage)` completes it (the payer receives the preimage);
`cancelHoldInvoice(paymentHash)` fails it back as if the invoice were unknown.
Parked HTLCs are restart-safe (they re-park from storage) and are
**auto-cancelled** by the CLTV sweeper 18 blocks before the HTLC expiry, so a
forgotten hold can never force an on-chain timeout. Typical uses: escrow-style
flows, just-in-time inventory checks, atomic swaps.

#### Payments

| Method | Returns | Description |
|--------|---------|-------------|
| `payInvoice(bolt11, timeoutMs?, maxFeeSats?, amountSats?, metadata?)` | `Promise<PaymentInfo>` | Pay invoice. **Blocks until settled or timeout** (default 60s). `maxFeeSats` caps routing fees. `amountSats` is required for amount-less invoices. `metadata` attaches key-value labels. |
| `payInvoiceSafe(bolt11, timeoutMs?, maxFeeSats?, amountSats?)` | `Promise<PaymentInfo>` | Like `payInvoice` but **never throws** — catches all errors and resolves with `status: 'FAILED'` instead. The `failureDescription` field contains `[ERROR_CODE] message` for machine parsing. |
| `sendPaymentAsync(bolt11, maxFeeSats?, amountSats?, metadata?)` | `{ paymentHash, status: 'PENDING' }` | Fire-and-forget pay. Returns immediately. Poll `getPayment()` for settlement. |
| `payInvoiceWithRetry(bolt11, opts?)` | `Promise<RetryPaymentResult>` | Pay with exponential backoff retry. `opts: { maxRetries? (3), backoffMs? (2000), maxFeeSats?, amountSats?, metadata? }`. Emits `payment:retry` events. |
| `cancelPayment(paymentHash)` | `{ ok: true }` | Cancel a pending outbound payment (marks as FAILED) |
| `listPayments(filter?)` | `PaymentInfo[]` | List payments sorted by createdAt desc. Filter by `status`, `direction`, `since`, `limit`, `offset`, `metadataKey`, `metadataValue`. |
| `getPayment(paymentHash)` | `PaymentInfo \| null` | Get specific payment |
| `setPaymentMetadata(paymentHash, metadata)` | `void` | Attach key-value metadata to an existing payment |
| `sendKeysend(pubkey, amountSats, timeoutMs?, maxFeeSats?, metadata?)` | `Promise<PaymentInfo>` | Spontaneous payment (no invoice). **Blocks until settled or timeout** (default 60s). |
| `sendKeysendSafe(pubkey, amountSats, timeoutMs?, maxFeeSats?, metadata?)` | `Promise<PaymentInfo>` | Like `sendKeysend` but **never throws** — resolves with `status: 'FAILED'` instead. |

#### BOLT 12 Offers

| Method | Returns | Description |
|--------|---------|-------------|
| `createOffer({ description, amountSats?, issuer? })` | `OfferInfo` | Create a reusable BOLT 12 offer |
| `decodeOfferString(offerStr)` | `OfferInfo` | Decode a BOLT 12 offer string without paying |
| `listOffers()` | `OfferInfo[]` | List local offers |
| `payOffer(offerStr, amountSats?, timeoutMs?)` | `Promise<PaymentInfo>` | Pay a BOLT 12 offer (requests invoice, then pays) |

#### Channel Readiness

| Method | Returns | Description |
|--------|---------|-------------|
| `getReadyChannels()` | `ChannelInfo[]` | List channels in NORMAL state |
| `canSend(amountSats)` | `{ canSend, bestChannelId?, availableSats }` | Check if you can send this amount (accounts for channel reserves) |
| `canReceive(amountSats)` | `{ canReceive, bestChannelId?, availableSats }` | Check if you can receive this amount (accounts for channel reserves) |

#### Route Estimation & Probing

| Method | Returns | Description |
|--------|---------|-------------|
| `estimateRouteFee(bolt11, amountSats?)` | `RouteEstimate \| null` | Estimate fee without sending. Returns `{ feeSats, hops, cltvDelta }` or null |
| `probeRoute(destination, amountSats)` | `{ success, feeSats?, hops? }` | Probe route viability to a destination node |
| `estimatePayment(bolt11, amountSats?)` | `PaymentEstimate \| null` | Full payment intelligence: success probability, route quality, estimated fee and time, warnings |

#### Graph Queries

| Method | Returns | Description |
|--------|---------|-------------|
| `getGraphInfo()` | `GraphInfo` | Node/channel counts + last gossip sync time this session |
| `getGraphNode(pubkey)` | `GraphNodeInfo \| null` | Node announcement info (alias, addresses, features) + its known channel SCIDs |
| `getGraphChannel(scid)` | `GraphChannelInfo \| null` | Channel endpoints, capacity (from htlc_maximum_msat) and both directions' policies |
| `describeGraph(limit?, offset?)` | `GraphDescribeResult` | Paged channel dump (limit defaults to 500, capped at 500) |
| `queryRoute(destination, amountSats, maxFeeSats?)` | `RouteQueryResult` | Compute a route WITHOUT sending; hops feed `sendToRoute` |
| `sendToRoute(paymentHash, route, paymentSecret?)` | `PaymentInfo` | Send a payment along an explicit route from `queryRoute` |

#### Payment Proof

| Method | Returns | Description |
|--------|---------|-------------|
| `getPaymentProof(paymentHash)` | `PaymentProof \| null` | Cryptographic proof of a completed payment (preimage, invoice, route info) |
| `verifyPaymentProof(paymentHash)` | `PaymentProofVerification` | Verify proof cryptographically: `sha256(preimage) === paymentHash`. Returns `{ valid, proof?, error? }` |

#### Payment Queue

| Method | Returns | Description |
|--------|---------|-------------|
| `enqueuePayment(bolt11, priority?, opts?)` | `QueuedPayment` | Add payment to priority queue (1-10, lower = higher priority). `opts: { amountSats?, maxFeeSats?, metadata? }` |
| `listQueue()` | `QueuedPayment[]` | List all queue entries |
| `cancelQueuedPayment(id)` | `boolean` | Cancel a queued payment by ID |

#### Liquidity & Channel Intelligence

| Method | Returns | Description |
|--------|---------|-------------|
| `getLiquiditySnapshot()` | `LiquiditySnapshot` | Liquidity analysis with actionable recommendations (OPEN_CHANNEL, CLOSE_CHANNEL, REBALANCE) |
| `getChannelSuggestions(count?)` | `ChannelSuggestion[]` | Graph-based channel open suggestions scored by connectivity, capacity, freshness, relevance |
| `getFeeSnapshot()` | `FeeSnapshot \| null` | On-chain fee trend analysis with open/wait recommendation |
| `getAdvisorRecommendations()` | `AdvisorRecommendations` | Liquidity analysis plus the concrete circular-rebalance plan (read-only) |
| `rebalanceChannel(fromId, toId, amountSats, maxFeeSats)` | `Promise<RebalanceResult>` | Circular rebalance (self-payment out fromId, back in toId). Aborts without paying if the route fee exceeds `maxFeeSats` |
| `executeRebalances(budgetSatsPerDay?)` | `Promise<RebalanceExecutionSummary>` | Run the advisor's rebalance plan under a per-UTC-day fee budget (persisted; restarts never overspend the day) |

Automatic execution is **off by default**: pass `autoRebalance: { enabled: true, budgetSatsPerDay, minImbalancePct }` and/or `autoTuneFees: { enabled: true, intervalMs, floorPpm, ceilPpm }` in `BeignetNodeOptions` to turn on the periodic rebalance scan and routing-fee (ppm) auto-tuning.

#### Statistics

| Method | Returns | Description |
|--------|---------|-------------|
| `getStats(windowMs?)` | `NodeStats` | Payment stats with optional time window. Includes `avgPaymentTimeSec` and `avgFeePct` when data available |

#### Database Backup

| Method | Returns | Description |
|--------|---------|-------------|
| `backup(destPath)` | `Promise<void>` | Create online backup of SQLite database |

Storage encryption: the SQLite database is encrypted at rest by default with a
key derived (HKDF-SHA256) from the wallet's BIP39 seed. Sensitive payloads
(channel state, preimages, payment secrets, invoices, payments, chain-monitor
state) are AES-256-GCM encrypted, so backups made with `backup()` are encrypted
too; restoring one requires the same mnemonic. Pre-encryption databases are
migrated in place on first open. Set `storageEncryption: false` to opt out
(plaintext storage).

#### Static Channel Backup (SCB)

| Method | Returns | Description |
|--------|---------|-------------|
| `exportStaticChannelBackup()` | `{ encoded, channelCount, path }` | Build, encrypt, and write the static channel backup |

A static channel backup is a small, portable, versioned blob holding the
minimum needed to recover funds for every open channel without the full
database: per channel it records the channel id, peer node id and last-known
addresses, funding outpoint (txid internal byte order + output index),
capacity, per-channel key index, channel type, role, and taproot/anchor flags.
The blob is JSON encrypted with AES-256-GCM under a key derived
(HKDF-SHA256, info `beignet-scb-v1`) from the wallet's BIP39 seed, encoded as
`beignet-scb-v1:` + base64 - it is useless without the mnemonic.

The file is written atomically to `<dataDir>/channels.scb` and refreshed
automatically whenever the channel set changes (channel open/splice calls,
`channel:ready`, `channel:closed`, and channel resolution). Store a copy
off-machine (e.g. via `beignet backup scb <destPath>` or `GET /backup/scb`).

#### Automatic Peer Backup (BOLT 1 peer storage)

| Method / Command | Returns | Description |
|--------|---------|-------------|
| `getPeerRetrievedBackup()` | `{ encoded, createdAt, fromPeer } \| null` | Newest valid SCB a peer returned this session (daemon: `GET /backup/peer-retrieved`; CLI: `beignet backup peer-retrieved`) |

With `peerStorageEnabled` (default true) the node advertises
`option_provide_storage` and uses it in both directions:

- **Our backup, held by peers.** Every SCB refresh is pushed as an opaque
  `peer_storage` blob to each connected peer that advertises the feature, and
  each such peer returns its held copy via `peer_storage_retrieval` on every
  reconnect. Recovery-from-nothing: reinstall with the mnemonic, connect to
  your old peers, read `GET /backup/peer-retrieved`, and feed its `encoded`
  blob to `POST /restore/scb`. Nothing is restored automatically - recovery
  stays explicit, and SCB recovery never broadcasts a stale commitment, so a
  peer returning an old blob is harmless.
- **Trust model.** Peers only ever see the seed-encrypted `beignet-scb-v1`
  ciphertext; without the mnemonic it is useless to them. Blobs returned by
  peers are untrusted input: anything that does not decrypt as our own SCB is
  ignored, and among valid ones only the newest (`createdAt`) is kept.
- **Storing for peers.** In return the node holds ONE blob (max 65531 bytes,
  newest wins) per peer it has a non-closed channel with or trusts
  (zero-conf trusted set), accepts at most one blob per peer per 60 seconds,
  and sends it back on every reconnect. Blobs from strangers are dropped.
  Stored blobs live in the `peer_storage_blobs` table, encrypted at rest like
  the rest of the database.

#### Restore

| Method / Command | Returns | Description |
|--------|---------|-------------|
| `restoreFromScb(encoded)` | `Promise<{ recovering, skipped, channelCount }>` | Recover channels from an SCB blob (daemon: `POST /restore/scb` with `{ encoded }` or `{ path }`; CLI: `beignet restore scb <file>`) |
| `beignet restore db <backupFile>` | JSON result | Copy a database backup into place (OFFLINE, local CLI operation - no daemon call) |

Two very different restore modes:

- **SCB restore = on-chain recovery only.** The backup holds no commitment
  state, so the channels themselves cannot be resumed. Each entry is
  reconstructed as a broadcast-banned channel (`ERRORED`, data-loss flagged -
  the node will never publish its own stale commitment), the funding outpoint
  is watched, and the peer is contacted so the normal reestablish exchange
  proves our state stale. The honest peer then force-closes with ITS
  commitment and the node sweeps only our `to_remote` balance to the wallet.
  Funds arrive on-chain after the peer's force-close confirms; in-flight
  HTLCs and anything beyond `to_remote` are not recoverable this way. The
  blob decrypts only with the wallet mnemonic, and a backup taken on another
  network is refused.

- **DB restore = full state.** `beignet restore db <backupFile>` copies a
  backup made with `backup()` over `<dataDir>/<network>.db`. The node must be
  STOPPED: the command refuses while a daemon holds the wallet's
  single-instance lock (and holds that lock itself during the copy). The file
  must be a real SQLite database (16-byte header check), any existing
  database is preserved at `<db>.pre-restore-<timestamp>` first, and stale
  `-wal`/`-shm` sidecars are moved aside so they cannot corrupt the restored
  file. The database is encrypted under the wallet seed, so the node must be
  started with the same mnemonic that made the backup. WARNING: restoring a
  stale database and going online can be unsafe (peers may prove the state
  stale); prefer the most recent backup, and rely on SCB recovery when in
  doubt.

#### Health & Monitoring

| Method | Returns | Description |
|--------|---------|-------------|
| `getHealth()` | `HealthInfo` | Node health: status, uptime, block height, electrum, peers, channels, graph |
| `getChannelHealth(channelId)` | `ChannelHealth \| null` | Channel liquidity health: balance %, HTLC slot usage, warnings |
| `getMainnetReadiness()` | `ReadinessReport` | Weighted readiness checklist (storage, chain backend, channels, fees, etc.) |
| `getMetrics()` | `string` | Prometheus text exposition format metrics (channels, payments, balances, peers, uptime, etc.) |
| `triggerBackup()` | `Promise<void>` | Trigger an on-demand backup (requires `backupPath` configured) |
| `getActionLog(options?)` | `ActionLogEntry[]` | Query persistent action log. `options: { category?, since?, limit? }` |
| `getNodeUri(externalHost?)` | `string \| null` | Node connection URI (`pubkey@host:port`). Returns null if not listening. |
| `getNode()` | `LightningNode` | Access the underlying LightningNode for event wiring |

#### Waiting

| Method | Returns | Description |
|--------|---------|-------------|
| `waitForReady(timeoutMs?)` | `Promise<void>` | Wait for node to be fully operational (peers reconnected, channels restored). Default 30s timeout. |
| `waitForChannelReady(channelId, timeoutMs?)` | `Promise<void>` | Wait for channel to reach NORMAL state (default 60s timeout) |
| `waitForPayment(paymentHash, timeoutMs?)` | `Promise<PaymentInfo>` | Wait for payment to settle (default 60s timeout) |

#### Spending Limits

| Method | Returns | Description |
|--------|---------|-------------|
| `getDailySpendInfo()` | `DailySpendInfo` | Current spending limit status: `{ limitSats, spentSats, remainingSats, resetsAt }` |

#### Drain Mode

| Method | Returns | Description |
|--------|---------|-------------|
| `setDraining(enabled)` | `void` | Enable/disable drain mode. When enabled, `payInvoice()` and `sendKeysend()` throw `SERVICE_DRAINING`. |
| `isDraining()` | `boolean` | Whether the node is currently draining |
| `hasPendingPayments()` | `boolean` | Whether there are in-flight payments |

#### Lifecycle

| Method | Returns | Description |
|--------|---------|-------------|
| `gracefulShutdown(timeoutMs?)` | `Promise<void>` | Graceful shutdown: drains in-flight HTLCs, persists state, then stops (default 30s timeout) |
| `destroy()` | `Promise<void>` | Immediate shutdown (stops wallet, storage, node) |

### Events

`BeignetNode` extends `EventEmitter`. All event data is JSON-safe (hex strings, numbers — no Buffer or bigint).

```typescript
node.on('payment:received', (info: PaymentInfo) => { ... });
node.on('payment:sent', (info: PaymentInfo) => { ... });
node.on('payment:failed', (info: PaymentInfo) => { ... });
node.on('invoice:settled', ({ paymentHash, bolt11, amountSats }) => { ... }); // an invoice WE issued was paid (keysend fires only payment:received)
node.on('channel:opening', ({ channelId, fundingTxid }) => { ... }); // funding negotiated + broadcast/watched
node.on('channel:ready', ({ channelId }) => { ... });
node.on('channel:pending-close', ({ channelId, initiator }) => { ... }); // coop close initiated ('local' | 'remote')
node.on('channel:force-closing', ({ channelId, initiator }) => { ... }); // our force-close broadcast or peer unilateral detected
node.on('channel:closed', ({ channelId }) => { ... });
node.on('htlc:forwarded', ({ inChannelId, outChannelId, amountInMsat, amountOutMsat, feeMsat }) => { ... }); // a forward settled (msat values as strings)
node.on('htlc:fulfilled', ({ channelId, htlcId }) => { ... }); // an HTLC we offered was fulfilled
node.on('htlc:failed', ({ channelId, htlcId }) => { ... });
node.on('peer:connect', ({ pubkey }) => { ... });
node.on('peer:disconnect', ({ pubkey }) => { ... });
node.on('node:error', ({ code, message, timestamp }) => { ... });
node.on('node:ready', () => { ... });           // node fully operational
node.on('payment:retry', ({ paymentHash, attempt, maxRetries, nextRetryMs, error }) => { ... });
node.on('backup:completed', ({ path, timestamp }) => { ... });
node.on('backup:failed', ({ path, error, timestamp }) => { ... });
node.on('electrum:failover', ({ from, to, timestamp }) => { ... }); // auto-reconnects to next server
node.on('log', (entry: LogEntry) => { ... });  // structured logs
```

The `log` event fires based on the `logLevel` option. Set `logLevel: 'debug'` for verbose output, `'silent'` to suppress.

### Return Types

```typescript
interface NodeInfo {
  nodeId: string;           // 33-byte compressed pubkey, hex
  alias?: string;
  network: string;          // 'mainnet' | 'testnet' | 'regtest'
  blockHeight: number;
  onchainBalanceSats: number;
  lightningBalanceSats: number;
  channelCount: number;
  peerCount: number;
  listening: boolean;
}

interface BalanceInfo {
  onchain: number;          // sats
  lightning: number;        // sats
  total: number;            // sats
  unsettledSats?: number;   // sats locked in in-flight HTLCs
}

interface PeerInfo {
  pubkey: string;
  host: string;
  port: number;
  state: string;
}

interface ChannelInfo {
  channelId: string;        // 32-byte hex
  peerPubkey: string;       // 33-byte compressed pubkey hex
  state: string;            // e.g. 'NORMAL', 'AWAITING_FUNDING_CONFIRMED'
  localBalanceSats: number;
  remoteBalanceSats: number;
  capacitySats: number;
  isAnchor: boolean;        // true if anchor channel (option_anchors_zero_fee_htlc_tx)
  fundingTxid?: string;     // funding transaction ID hex
  shortChannelId?: string;  // e.g. "800000x1x0"
  feeratePerKw?: number;    // current commitment feerate
  htlcCount?: number;       // number of active HTLCs
}

interface InvoiceInfo {
  bolt11: string;           // full BOLT 11 invoice string
  paymentHash: string;      // 32-byte hex
  paymentSecret?: string;   // 32-byte hex — correlate incoming payments without re-decoding
  amountSats?: number;
  description?: string;     // invoice description
  expiry?: number;          // expiry in seconds
  createdAt?: number;       // unix seconds
  status?: 'PENDING' | 'PAID' | 'EXPIRED';  // derived from payment state + expiry
}

interface DecodedInvoice {
  network: string;          // 'bc', 'tb', 'bcrt'
  amountSats?: number;
  timestamp: number;
  paymentHash: string;      // hex
  paymentSecret?: string;   // hex
  description?: string;
  payeeNodeKey?: string;    // hex
  expiry?: number;          // seconds
  minFinalCltvExpiry?: number;
  routingHints?: Array<Array<{
    pubkey: string;
    shortChannelId: string;
    feeBaseMsat: number;
    feeProportionalMillionths: number;
    cltvExpiryDelta: number;
  }>>;
}

interface PaymentInfo {
  paymentHash: string;      // hex
  preimage?: string;        // hex, present when settled
  amountSats: number;
  feeSats?: number;         // routing fee paid (from route)
  status: 'PENDING' | 'COMPLETED' | 'FAILED';
  direction: 'OUTGOING' | 'INCOMING';
  failureCode?: number;     // BOLT 4 failure code
  failureDescription?: string;  // human-readable
  createdAt: number;        // unix ms
  completedAt?: number;     // unix ms
  metadata?: Record<string, string>;  // agent-defined key-value labels
}

interface RetryPaymentResult extends PaymentInfo {
  attempts: number;         // total attempts made (1 = first try succeeded)
}

interface RetryPaymentOptions {
  maxRetries?: number;      // default 3
  backoffMs?: number;       // base delay in ms, default 2000 (2s, 4s, 8s, ...)
  maxFeeSats?: number;      // routing fee cap
  amountSats?: number;      // for amount-less invoices
  metadata?: Record<string, string>;
}

interface PaymentFilter {
  status?: 'PENDING' | 'COMPLETED' | 'FAILED';
  direction?: 'OUTGOING' | 'INCOMING';
  since?: number;           // unix ms — only payments after this time
  limit?: number;           // max results
  offset?: number;          // skip first N results
  metadataKey?: string;     // filter by metadata key existence (or key=value with metadataValue)
  metadataValue?: string;   // filter by metadata key=value match (requires metadataKey)
}

interface RouteEstimate {
  feeSats: number;
  hops: number;
  cltvDelta: number;
}

interface NodeStats {
  totalPaymentsSent: number;
  totalPaymentsReceived: number;
  totalPaymentsFailed: number;
  totalSatsSent: number;
  totalSatsReceived: number;
  totalFeesPaid: number;
  successRate: number;      // 0.0 to 1.0
  uptimeMs: number;
  windowMs?: number;        // present when time window specified
  avgPaymentTimeSec?: number; // avg completed payment time
  avgFeePct?: number;       // avg fee as % of payment amount
}

interface TxInfo {
  txid: string;
  hex: string;
}

interface OfferInfo {
  offerId: string;          // 32-byte hex
  description: string;
  encoded?: string;         // bech32m "lno1..." string (present on creation)
  amountSats?: number;      // amount in satoshis (converted from msat)
  issuer?: string;
  issuerId?: string;        // 33-byte hex
  quantityMax?: number;
  absoluteExpiry?: number;  // unix seconds
}

interface TrustedPeerInfo {
  pubkey: string;           // 33-byte hex
  trusted: boolean;
}

interface SpliceResult {
  ok: boolean;
  error?: string;
}

interface BootstrapPeerInfo {
  pubkey: string;           // 33-byte hex
  host: string;
  port: number;
}

interface Bolt12InvoiceInfo {
  paymentHash: string;      // hex
  amountSats: number;
  description: string;
  nodeId: string;           // hex
  createdAt: number;        // unix seconds
  relativeExpiry?: number;  // seconds
}

interface ChannelHealth {
  channelId: string;        // 32-byte hex
  state: string;            // e.g. 'NORMAL', 'AWAITING_REESTABLISH'
  localBalancePct: number;  // 0-100, local balance as % of capacity
  remoteBalancePct: number; // 0-100, remote balance as % of capacity
  htlcCount: number;        // number of active HTLCs
  maxHtlcs: number;         // max allowed HTLCs
  capacitySats: number;     // total channel capacity
  warnings: string[];       // 'LOW_OUTBOUND_LIQUIDITY', 'LOW_INBOUND_LIQUIDITY',
                            // 'HTLC_SLOTS_NEARLY_FULL', 'AWAITING_REESTABLISH'
}

interface DailySpendInfo {
  limitSats: number | null; // null if no limit configured
  spentSats: number;        // sats spent today
  remainingSats: number;    // sats remaining (Infinity if no limit)
  resetsAt: number;         // unix ms — next midnight UTC
}

interface HealthInfo {
  status: 'ready' | 'syncing' | 'degraded';
  uptime: number;           // ms since start
  blockHeight: number;
  electrumConnected: boolean;
  peerCount: number;
  channelCount: number;
  readyChannelCount: number;  // channels in NORMAL state
  graphNodes: number;
  graphChannels: number;
}

interface EventMessage {
  type: string;             // e.g. 'payment:received', 'channel:ready'
  data: Record<string, unknown>;
}

interface PaymentProof {
  paymentHash: string;      // hex
  preimage: string;         // hex
  amountSats: number;
  completedAt: number;      // unix ms
  invoice?: string;         // original BOLT 11 invoice string
  hopCount?: number;
  feeSats?: number;
}

interface PaymentProofVerification {
  valid: boolean;           // true if sha256(preimage) === paymentHash
  proof?: PaymentProof;     // the proof data (if found)
  error?: string;           // error message if verification failed
}

interface PaymentEstimate {
  successProbabilityPct: number; // 0-100
  estimatedTimeMs: number;
  routeQuality: 'HIGH' | 'MEDIUM' | 'LOW';
  warning?: string;
  alternativeAvailable: boolean; // MPP route exists
  estimatedFeeSats: number;
  hopCount: number;
}

interface LiquiditySnapshot {
  totalLocalBalanceSats: number;
  totalRemoteBalanceSats: number;
  totalCapacitySats: number;
  channelCount: number;
  activeChannelCount: number;
  outboundLiquidityPct: number;  // 0-100
  inboundLiquidityPct: number;   // 0-100
  recommendations: LiquidityRecommendation[];
}

interface LiquidityRecommendation {
  type: 'OPEN_CHANNEL' | 'CLOSE_CHANNEL' | 'REBALANCE_NEEDED';
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  reason: string;
  channelId?: string;       // present for channel-specific recommendations
}

interface ChannelSuggestion {
  nodeId: string;           // 33-byte hex
  alias?: string;
  score: number;            // 0-100
  channelCount: number;
  totalCapacitySats: number;
  reason: string;           // e.g. 'well-connected, high capacity'
}

interface FeeSnapshot {
  currentSatPerVbyte: number;
  trend: 'RISING' | 'FALLING' | 'STABLE';
  percentile: number;       // 0-100
  recommendation: 'OPEN_NOW' | 'WAIT' | 'NEUTRAL';
  estimatedOpenChannelCostSats: number;
  sampleCount: number;
  minSatPerVbyte: number;
  maxSatPerVbyte: number;
  avgSatPerVbyte: number;
}

interface QueuedPayment {
  id: string;
  bolt11: string;
  priority: number;         // 1 (highest) to 10 (lowest)
  status: 'queued' | 'dispatching' | 'completed' | 'failed' | 'cancelled';
  amountSats?: number;
  maxFeeSats?: number;
  metadata?: Record<string, string>;
  error?: string;
  createdAt: number;
  completedAt?: number;
}

interface WebhookRegistration {
  id: string;
  url: string;
  events: string[];         // e.g. ['payment:received', '*']
  secret?: string;          // masked as '***' in list responses
  createdAt: number;
}

interface ActionLogEntry {
  category: string;         // 'payment' | 'channel' | 'htlc' | 'fee' | 'peer' | 'chain'
  action: string;
  timestamp: number;        // unix ms
  data: Record<string, unknown>;
}

interface ReadinessReport {
  score: number;            // 0-100 weighted pass rate
  ready: boolean;           // true if no CRITICAL failures
  checks: ReadinessCheck[];
}

interface ReadinessCheck {
  name: string;             // e.g. 'STORAGE_CONFIGURED', 'CHAIN_BACKEND_CONNECTED'
  status: 'PASS' | 'WARN' | 'FAIL';
  severity: 'CRITICAL' | 'WARNING' | 'INFO';
  message: string;
}

// BeignetNode extends EventEmitter and emits these typed events:
interface BeignetNodeEvents {
  'payment:received': (info: PaymentInfo) => void;
  'payment:sent': (info: PaymentInfo) => void;
  'payment:failed': (info: PaymentInfo) => void;
  'invoice:settled': (data: { paymentHash: string; bolt11: string; amountSats: number }) => void;
  'channel:opening': (data: { channelId: string; fundingTxid: string }) => void;
  'channel:ready': (data: { channelId: string }) => void;
  'channel:pending-close': (data: { channelId: string; initiator: 'local' | 'remote' }) => void;
  'channel:force-closing': (data: { channelId: string; initiator: 'local' | 'remote' }) => void;
  'channel:closed': (data: { channelId: string }) => void;
  'htlc:forwarded': (data: { inChannelId: string; outChannelId: string; amountInMsat: string; amountOutMsat: string; feeMsat: string }) => void;
  'htlc:fulfilled': (data: { channelId: string; htlcId: string }) => void;
  'htlc:failed': (data: { channelId: string; htlcId: string }) => void;
  'peer:connect': (data: { pubkey: string }) => void;
  'peer:disconnect': (data: { pubkey: string }) => void;
  'node:error': (data: { code: string; message: string; timestamp: number }) => void;
  'node:ready': () => void;
  'payment:retry': (data: { paymentHash: string; attempt: number; maxRetries: number; nextRetryMs: number; error: string }) => void;
  'backup:completed': (data: { path: string; timestamp: number }) => void;
  'backup:failed': (data: { path: string; error: string; timestamp: number }) => void;
  'electrum:failover': (data: { from: { host: string; port: number }; to: { host: string; port: number }; timestamp: number }) => void;
  'log': (entry: LogEntry) => void;
}

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

interface LogEntry {
  level: LogLevel;
  message: string;
  data?: Record<string, unknown>;
  timestamp: number;
}
```

### Channel States

Channels progress through these states:

| State | Can Send Payments? | Description |
|-------|-------------------|-------------|
| `AWAITING_FUNDING_CONFIRMED` | No | Funding tx broadcast, waiting for on-chain confirmations |
| `AWAITING_CHANNEL_READY` | No | Funding confirmed, exchanging `channel_ready` messages |
| `NORMAL` | **Yes** | Fully operational — HTLCs can be sent and received |
| `AWAITING_REESTABLISH` | No | Reconnected after disconnect, re-syncing state |
| `SHUTTING_DOWN` | No | Cooperative close initiated, no new HTLCs |
| `NEGOTIATING_CLOSING` | No | Exchanging closing fee proposals |
| `CLOSED` | No | Channel closed (cooperative or forced) |

Only channels in `NORMAL` state can send/receive payments.

### Error Handling

All errors throw `BeignetError` with a `code`, `message`, and optional `failureCode` (BOLT 4):

```typescript
import { BeignetError, isRetryableError, isPermanentFailure } from 'beignet/cli';

try {
  await node.payInvoice(bolt11);
} catch (err) {
  if (err instanceof BeignetError) {
    console.log(err.code);        // 'PAYMENT_FAILED', 'PAYMENT_TIMEOUT', etc.
    console.log(err.message);     // 'Payment failed: unknown_next_peer'
    console.log(err.failureCode); // BOLT 4 failure code (e.g. 0x400f)

    if (isRetryableError(err)) {
      // Transient failure — safe to retry (no route, timeout, temp failure)
    }
    if (isPermanentFailure(err)) {
      // Permanent failure — give up (expired, invalid, PERM flag set)
    }
  }
}
```

Error codes (`BeignetErrorCode` enum):

| Code | Category | Description |
|------|----------|-------------|
| `WALLET_CREATE_FAILED` | Wallet | On-chain wallet initialization failed |
| `ADDRESS_FAILED` | Wallet | Could not derive new address |
| `SEND_FAILED` | Wallet | On-chain send failed |
| `REFRESH_FAILED` | Wallet | Wallet sync failed |
| `NOT_BOOSTABLE` | Wallet | Transaction cannot be fee-bumped (unknown, confirmed, or not RBF/CPFP-able) |
| `NOTHING_TO_CONSOLIDATE` | Wallet | Consolidation needs at least two spendable UTXOs |
| `PAYMENT_FAILED` | Payments | Lightning payment failed |
| `PAYMENT_TIMEOUT` | Payments | Payment did not settle within timeout |
| `INVOICE_EXPIRED` | Payments | Invoice has expired |
| `NO_ROUTE` | Payments | No route found to destination |
| `CHANNEL_NOT_FOUND` | Channels | Channel ID does not exist |
| `CLOSE_FAILED` | Channels | Cooperative close failed |
| `FORCE_CLOSE_FAILED` | Channels | Force close failed |
| `ZERO_CONF_FAILED` | Channels | Zero-conf channel open failed |
| `NODE_DESTROYED` | Node | Operation on destroyed node |
| `INVALID_PARAMS` | Node | Missing or invalid request parameters |
| `NOT_FOUND` | Node | Resource not found |
| `BODY_TOO_LARGE` | Node | Request body exceeds 1MB |
| `MNEMONIC_REQUIRES_AUTH` | Node | apiToken required for mnemonic access |
| `UNAUTHORIZED` | Node | Invalid or missing auth token |
| `INSUFFICIENT_BALANCE` | Payments | Not enough balance to send |
| `PEER_NOT_CONNECTED` | Peers | Peer is not connected |
| `DUPLICATE_PAYMENT` | Payments | Payment with this hash already pending |
| `CHANNEL_NOT_READY` | Channels | Channel is not in NORMAL state |
| `OPEN_FAILED` | Channels | Channel open failed |
| `SPENDING_LIMIT_EXCEEDED` | Payments | Daily spending limit exceeded (permanent) |
| `SERVICE_DRAINING` | Node | Node is draining — no new payments accepted (permanent) |
| `IDEMPOTENCY_CONFLICT` | HTTP | Same idempotency key used with different request body |
| `RATE_LIMITED` | HTTP | Too many requests (token bucket rate limiter) |

#### Typed Payment Errors (Lightning Layer)

When `payInvoice()` fails, the underlying `LightningNode` throws a `LightningPaymentError` with a typed `code` property. The CLI layer catches these and maps them to `BeignetErrorCode`, but you can also import and check them directly:

```typescript
import { LightningPaymentError, LightningErrorCode } from 'beignet/cli';

try {
  await node.payInvoice(bolt11);
} catch (err) {
  if (err instanceof LightningPaymentError) {
    switch (err.code) {
      case LightningErrorCode.NO_ROUTE:         // No path to destination
      case LightningErrorCode.DUPLICATE_PAYMENT: // Payment hash already in-flight
      case LightningErrorCode.NO_CHANNEL_TO_HOP: // No channel to first hop peer
      case LightningErrorCode.FEE_EXCEEDS_MAX:   // Route fee exceeds maxFeeMsat
      case LightningErrorCode.MISSING_AMOUNT:     // Amount-less invoice with no amount
      case LightningErrorCode.INVALID_INVOICE:    // Cannot determine payee
      case LightningErrorCode.INVOICE_EXPIRED:    // Invoice has expired
    }
  }
}
```

`LightningPaymentError` extends `Error`, so existing `catch` blocks continue to work. The `code` property enables programmatic error handling without string matching.

---

## CLI Commands

The CLI is a thin HTTP client. `init` and `start` are handled locally; all other commands send requests to the daemon on `127.0.0.1:2112`.

All output is JSON. Add `--pretty` for indented output.

### Setup

```bash
beignet init [--network regtest] [--alias mynode]
beignet start [--port 2112] [--host 0.0.0.0] [--daemon] [--anchors] [--api-token mysecret] \
  [--backup-path /path/to/backup.db] [--backup-interval 21600000] \
  [--daily-spend-limit 100000] [--tls-cert /path/cert.pem] [--tls-key /path/key.pem] \
  [--htlc-events]
beignet stop
```

Seed generation is CLI-only: `beignet init` creates the mnemonic (or you supply
one via `BEIGNET_MNEMONIC`/config); the daemon never generates or replaces a
seed. `GET /mnemonic` only reveals the configured seed, and only when
`apiToken` is set.

### Info

```bash
beignet info
# {"ok":true,"result":{"nodeId":"02ab...","network":"regtest","blockHeight":100,...}}

beignet balance
# {"ok":true,"result":{"onchain":50000,"lightning":10000,"total":60000}}

beignet address
# {"ok":true,"result":{"address":"bcrt1q..."}}

beignet mnemonic
# {"ok":true,"result":{"mnemonic":"abandon abandon ..."}}

beignet health
# {"ok":true,"result":{"status":"ready","uptime":3600000,...}}

beignet readiness
# {"ok":true,"result":{"score":85,"ready":true,"checks":[...]}}

beignet metrics
# beignet_channels_total{state="NORMAL"} 2
# beignet_balance_sats{type="lightning"} 50000
# ... (Prometheus text format, not JSON)

beignet stats
# {"ok":true,"result":{"totalPaymentsSent":10,...}}

beignet stats 3600000
# {"ok":true,"result":{"totalPaymentsSent":3,"windowMs":3600000,...}}

beignet ready
# {"ok":true,"result":{"ready":true}}

beignet liquidity
# {"ok":true,"result":{"totalLocalBalanceSats":500000,...,"recommendations":[...]}}

beignet fees
# {"ok":true,"result":{"currentSatPerVbyte":12,"trend":"FALLING","recommendation":"OPEN_NOW",...}}

beignet spend-limit
# {"ok":true,"result":{"limitSats":100000,"spentSats":2500,"remainingSats":97500,"resetsAt":...}}

beignet logs --category payment --limit 20
# {"ok":true,"result":[{"category":"payment","action":"sent","timestamp":...,"data":{...}}]}

beignet can-send 50000
beignet can-receive 50000
# {"ok":true,"result":{"canSend":true,...}}

beignet node uri --host mynode.example.com
# {"ok":true,"result":{"uri":"02ab...@mynode.example.com:9735"}}

beignet node wait-ready --timeout 30000
# Blocks until the node is operational
```

### On-chain

```bash
beignet send <address> <sats>
# {"ok":true,"result":{"txid":"ab12...","hex":"0200..."}}

beignet send-max <address> [satsPerVbyte]
# Sweep the whole balance: {"ok":true,"result":{"txid":"cd34...","hex":"0200..."}}

beignet tx bump-fee <txid> <satsPerVbyte>
# RBF replacement: {"ok":true,"result":{"txid":"ef56...","boostType":"rbf","feeSats":420,"originalTxid":"ab12..."}}

beignet tx boost <txid> [satsPerVbyte]
# Auto RBF-else-CPFP: {"ok":true,"result":{"txid":"0178...","boostType":"cpfp",...}}

beignet tx boostable
# {"ok":true,"result":{"rbf":[...],"cpfp":[...]}}

beignet consolidate [satsPerVbyte]
# {"ok":true,"result":{"txid":"23ab...","utxosConsolidated":7,"address":"bc1q...","feeSats":310}}

beignet psbt build <address> <sats> [satsPerVbyte]
# Unsigned PSBT for a hardware wallet: {"ok":true,"result":{"psbtBase64":"cHNi...","feeSats":418,...}}

beignet psbt import-signed <psbtBase64|file>
# Validate + finalize (no broadcast): {"ok":true,"result":{"txid":"ab12...","txHex":"0200..."}}

beignet psbt combine <psbt|file> <psbt|file>
# {"ok":true,"result":{"psbtBase64":"cHNi..."}}
beignet wallet refresh
# {"ok":true,"result":{"refreshed":true}}
```

On-chain sends signal BIP 125 replace-by-fee, so an underpaying transaction
can later be bumped with `tx bump-fee` (or `tx boost`, which falls back to
CPFP when RBF is unavailable).

The on-chain wallet's state (addresses, UTXOs, transactions) persists in the
node's SQLite database (encrypted at rest when `storageEncryption` is on, the
default), so restarts sync incrementally from Electrum instead of rebuilding
the wallet from scratch.

### Peers

```bash
beignet peer connect <pubkey> <host> <port>
beignet peer disconnect <pubkey>
beignet peer list
```

### DNS Bootstrap (BOLT 10)

```bash
beignet bootstrap discover
# {"ok":true,"result":[{"pubkey":"02ab...","host":"1.2.3.4","port":9735},...]}

beignet bootstrap connect 5
# {"ok":true,"result":{"connected":["02ab...","03cd..."]}}
```

### Trusted Peers (Zero-Conf)

```bash
beignet trusted-peer add <pubkey>
# {"ok":true,"result":{"pubkey":"02ab...","trusted":true}}

beignet trusted-peer remove <pubkey>
# {"ok":true,"result":{"pubkey":"02ab...","trusted":false}}

beignet trusted-peer list
# {"ok":true,"result":[{"pubkey":"02ab...","trusted":true}]}
```

### Channels

```bash
beignet channel open <pubkey> <sats> [pushSats]
beignet channel open-zeroconf <pubkey> <sats> [pushSats]
beignet channel open-v2 <pubkey> <sats> [fundingFeeratePerkw]
beignet channel open-and-wait <pubkey> <sats> [pushSats] [--timeout 60000]
beignet channel connect-and-open <pubkey> <host> <port> <sats> [pushSats]
beignet channel close <channelId>
beignet channel forceclose <channelId>
beignet channel splice-in <channelId> <sats> <feeratePerkw>
beignet channel splice-out <channelId> <sats> <feeratePerkw>
beignet channel ensure-minimum 3 500000
# Auto-open channels to at least 3 using graph suggestions, 500k sats each
beignet channel update-policy <channelId|all> [--base-fee-msat N] [--ppm N] [--cltv-delta N] [--htlc-min-msat N] [--htlc-max-msat N]
beignet channel update-commitment-feerate <channelId> <feeratePerKw>
# COMMITMENT feerate (BOLT 2 update_fee, opener only) - not the routing policy
beignet channel policy <channelId>
beignet channel list
beignet channel ready
# Only channels in NORMAL state
beignet channel get <channelId>
# channel get/list include the effective routing policy fields
beignet channel health <channelId>
beignet channel suggestions [count]
beignet channel wait-ready <channelId> [--timeout 60000]
```

### Routing Fee Policy

Per-channel control of the ROUTING policy advertised in `channel_update` (not
the commitment feerate, which is `/channel/update-commitment-feerate`): base
fee, proportional fee (ppm), CLTV delta, and HTLC min/max. Unset fields fall
back to the node-wide defaults; overrides persist across restarts. Announced
channels re-broadcast the updated `channel_update` immediately; unannounced
channels send it directly to the peer.

```bash
beignet channel update-policy ab12... --base-fee-msat 500 --ppm 100
# {"ok":true,"result":{"updated":1,"policies":[{"channelId":"ab12...","feeBaseMsat":500,"feeProportionalMillionths":100,"cltvExpiryDelta":40,"htlcMinimumMsat":"1000","htlcMaximumMsat":"500000000","source":"override"}]}}

beignet channel update-policy all --cltv-delta 80
# Applies to every channel; other fields keep their current values
```

### Forwarding History

Ledger of settled forwards (HTLCs this node relayed where both legs
fulfilled), with the fee earned per forward. Records persist in the node
database (capped at 100k rows, oldest pruned first). Msat values are decimal
strings. Failed forwards are not recorded.

```bash
beignet forwards --since 1751000000000 --limit 50
# {"ok":true,"result":[{"id":7,"settledAt":1751234567890,"inChannelId":"ab12...","outChannelId":"cd34...","amountInMsat":"5005000","amountOutMsat":"5000000","feeMsat":"5000"}]}

beignet forwards summary --since 1751000000000
# {"ok":true,"result":{"count":42,"volumeOutMsat":"210000000","feesEarnedMsat":"210000"}}
### Graph Queries

lncli-style read access to the gossip network graph, plus manual routing:
compute a route without paying, then (optionally) pay along exactly that route.
SCIDs are formatted `<block>x<txIndex>x<output>` (16-char hex also accepted).

```bash
beignet graph info
# {"ok":true,"result":{"nodeCount":18432,"channelCount":51200,"lastSyncAt":1767952800000}}

beignet graph node 02abc...
# {"ok":true,"result":{"pubkey":"02abc...","alias":"ACINQ","color":"ff9900","addresses":[...],"featuresHex":"8000...","lastUpdate":1767950000,"channelCount":3,"channels":["700000x1x0",...]}}

beignet graph channel 700000x1x0
# {"ok":true,"result":{"shortChannelId":"700000x1x0","node1Pubkey":"02ab..","node2Pubkey":"03cd..","capacitySats":1000000,"node1Policy":{"feeBaseMsat":1000,"feeProportionalMillionths":1,"cltvExpiryDelta":40,"htlcMinimumMsat":"1000","htlcMaximumMsat":"1000000000","disabled":false,"lastUpdate":1767950000},"node2Policy":{...}}}

beignet graph describe --limit 100 --offset 200
# Paged dump: {"ok":true,"result":{"totalChannels":51200,"limit":100,"offset":200,"channels":[...]}}

beignet route query 02abc... 50000 --max-fee 100
# Computes a route WITHOUT paying:
# {"ok":true,"result":{"destination":"02abc...","amountSats":50000,"hops":[{"pubkey":"03cd..","shortChannelId":"700000x1x0","amountToForwardMsat":"50001000","outgoingCltvValue":80,"feeMsat":"1000","cltvExpiryDelta":40},...],"totalAmountMsat":"50001000","totalFeeMsat":"1000","totalCltvDelta":80,"finalCltvExpiry":40}}

beignet route query 02abc... 50000 --pretty > route.json
beignet payment send-to-route <paymentHash> route.json --payment-secret <hex>
# Pays along exactly that route (accepts a file path or inline JSON;
# both the full result object and a bare {"hops":[...]} work)

beignet route estimate <bolt11> [sats]
# {"ok":true,"result":{"feeSats":2,"hops":3,"cltvDelta":120}}

beignet route probe 02abc... 50000
# Probes route viability without paying
```

### Invoices & Payments

```bash
beignet invoice create [sats] [description]
# {"ok":true,"result":{"bolt11":"lnbcrt10n1...","paymentHash":"ab12...","amountSats":1000}}

beignet invoice decode <bolt11>
# {"ok":true,"result":{"network":"bcrt","amountSats":1000,"paymentHash":"ab12...",...}}

beignet invoice validate <bolt11> [sats]
# Pre-flight checks (decode, capacity, route): {"ok":true,"result":{"status":"OK","checks":[...]}}

beignet invoice get <paymentHash>
# Details of an invoice this node created

beignet invoice pay <bolt11>
# Blocks until payment settles or fails (60s timeout)
# {"ok":true,"result":{"paymentHash":"ab12...","preimage":"cd34...","status":"COMPLETED",...}}

beignet invoice pay-safe <bolt11> [--max-fee 100] [--amount 1000] [--timeout 60000]
# Never errors: resolves with status FAILED instead

beignet invoice pay-async <bolt11> [--max-fee 100] [--amount 1000]
# Fire-and-forget: returns {paymentHash,status} immediately; poll 'payment get'

beignet invoice pay-retry <bolt11> [--max-retries 5] [--backoff-ms 1000] [--max-fee 100]
# Retries with exponential backoff on transient failures
# {"ok":true,"result":{"paymentHash":"ab12...","status":"COMPLETED","attempts":2,...}}

beignet keysend <pubkey> <sats> [--max-fee 100] [--timeout 60000]
beignet keysend safe <pubkey> <sats>
# Spontaneous payment, no invoice ('safe' resolves FAILED instead of erroring)

beignet invoice list
# {"ok":true,"result":[{"bolt11":"lnbcrt10n1...","paymentHash":"ab12...","amountSats":1000,...}]}

# Hold invoices: you keep the preimage; the payer's HTLC parks until you settle
beignet invoice create-hold <sha256(preimage)> 1000 "escrow" --expiry 3600
# {"ok":true,"result":{"bolt11":"lnbcrt10n1...","paymentHash":"ab12...","amountSats":1000}}

beignet invoice held
# {"ok":true,"result":[{"paymentHash":"ab12...","state":"ACCEPTED","heldAmountMsat":"1000000","htlcCount":1,...}]}

beignet invoice settle-hold <preimage>       # fulfills the parked HTLC(s)
beignet invoice cancel-hold <paymentHash>    # fails them back to the payer

beignet payment list
beignet payment get <paymentHash>
beignet payment cancel <paymentHash>
beignet payment wait <paymentHash> [--timeout 60000]
beignet payment proof <paymentHash>
beignet payment verify-proof <paymentHash>
beignet payment estimate <bolt11> [sats]
beignet payment metadata <paymentHash> '{"orderId":"1234"}'

# Payment queue: ordered dispatch with priorities
beignet queue add <bolt11> [--priority 5] [--amount 1000] [--max-fee 100]
beignet queue list
beignet queue cancel <id>
```

### Messages & Gossip

```bash
beignet message sign "proof of node ownership"
# {"ok":true,"result":{"signature":"d7y...104 zbase32 chars...","pubkey":"02ab..."}}

beignet message verify "proof of node ownership" <signature>
# {"ok":true,"result":{"valid":true,"pubkey":"02ab...","knownNode":true}}

beignet gossip sync            # sync graph from all connected peers
beignet gossip sync-rapid      # Rapid Gossip Sync snapshot (mainnet)
beignet channel diagnostics <channelId>
beignet address validate bc1q...
beignet recover-fallback-funds --fee-rate 5
beignet backup trigger
```

### BOLT 12 Offers

```bash
beignet offer create "Coffee" 1000
# {"ok":true,"result":{"offerId":"ab12...","description":"Coffee","amountSats":1000,"encoded":"lno1..."}}

beignet offer list
# {"ok":true,"result":[{"offerId":"ab12...","description":"Coffee",...}]}

beignet offer decode lno1...
# {"ok":true,"result":{"offerId":"ab12...","description":"Coffee","amountSats":1000,...}}

beignet offer pay lno1... 1000
# Requests invoice from offer issuer, then pays it
# {"ok":true,"result":{"paymentHash":"ab12...","status":"COMPLETED",...}}
```

### Webhooks (CLI)

```bash
beignet webhooks register https://myagent.com/callback payment:received,channel:ready --secret mysecret
beignet webhooks register https://myagent.com/callback '*'
# '*' subscribes to every event, including any added in future versions
beignet webhooks list
beignet webhooks unregister <id>
```

Every daemon endpoint has a CLI command except two that only make sense over
HTTP: `GET /events` (SSE stream for long-lived consumers; use `webhooks` from
the CLI instead) and `GET /openapi.json` (machine-readable API discovery). The
deprecated `POST /channel/update-fee` alias is covered by
`channel update-commitment-feerate`.

### JSON Envelope

Every response follows this format:

```json
// Success
{"ok": true, "result": { ... }}

// Failure
{"ok": false, "error": {"code": "PAYMENT_FAILED", "message": "No route found"}}
```

---

## Configuration

### Config File

`~/.beignet/config.json`:

```json
{
  "mnemonic": "abandon abandon ...",
  "network": "regtest",
  "alias": "mynode",
  "dataDir": "/custom/path",
  "electrumHost": "127.0.0.1",
  "electrumPort": 60001,
  "electrumTls": false,
  "listenPort": 9735,
  "daemonHost": "127.0.0.1",
  "daemonPort": 2112,
  "preferAnchors": true,
  "apiToken": "mysecrettoken",
  "autoBootstrap": false,
  "backupPath": "/var/backups/beignet/node.db",
  "backupIntervalMs": 21600000,
  "electrumServers": [
    { "host": "electrum1.bluewallet.io", "port": 443, "tls": true },
    { "host": "electrum2.bluewallet.io", "port": 443, "tls": true }
  ],
  "dailySpendLimitSats": 100000,
  "connectTimeoutMs": 15000,
  "tlsCert": "/etc/ssl/beignet/cert.pem",
  "tlsKey": "/etc/ssl/beignet/key.pem",
  "htlcEvents": false
}
```

### Environment Variables

Environment variables override the config file but are overridden by CLI flags.

| Variable | Description |
|----------|-------------|
| `BEIGNET_MNEMONIC` | BIP39 mnemonic |
| `BEIGNET_NETWORK` | `mainnet`, `testnet`, or `regtest` |
| `BEIGNET_ALIAS` | Node alias |
| `BEIGNET_DATA_DIR` | Data directory path |
| `BEIGNET_ELECTRUM_HOST` | Electrum server hostname |
| `BEIGNET_ELECTRUM_PORT` | Electrum server port |
| `BEIGNET_ELECTRUM_TLS` | `true` or `false` |
| `BEIGNET_LISTEN_PORT` | Lightning listen port |
| `BEIGNET_DAEMON_HOST` | HTTP daemon bind address (default: `127.0.0.1`) |
| `BEIGNET_DAEMON_PORT` | HTTP daemon port |
| `BEIGNET_PREFER_ANCHORS` | `true` to prefer anchor channels |
| `BEIGNET_API_TOKEN` | API authentication token (required for mnemonic access) |
| `BEIGNET_AUTO_BOOTSTRAP` | `true` to auto-connect to DNS seed peers on start |
| `BEIGNET_BACKUP_PATH` | Automated backup destination path |
| `BEIGNET_BACKUP_INTERVAL_MS` | Backup interval in milliseconds (default: 21600000 = 6h) |
| `BEIGNET_DAILY_SPEND_LIMIT_SATS` | Daily spending limit in satoshis (resets at midnight UTC) |
| `BEIGNET_CONNECT_TIMEOUT_MS` | Timeout for `connectPeer()` in milliseconds (default: 15000) |
| `BEIGNET_TLS_CERT` | Path to TLS certificate for HTTPS daemon |
| `BEIGNET_TLS_KEY` | Path to TLS private key for HTTPS daemon |
| `BEIGNET_HTLC_EVENTS` | `true` to relay per-HTLC events over SSE + webhooks |

### Priority Order

CLI flags > environment variables > config file > defaults.

### Default Electrum Servers

| Network | Host | Port | TLS |
|---------|------|------|-----|
| mainnet | `fulcrum.bitkit.blocktank.to` | 8900 | yes |
| testnet | `electrum.blockstream.info` | 60002 | yes |
| regtest | `34.65.252.32` | 18483 | no |

> The regtest default is a hosted Synonym regtest Electrum server. For local
> development against your own regtest node, override it with
> `BEIGNET_ELECTRUM_HOST`/`BEIGNET_ELECTRUM_PORT` or the `electrumHost`/
> `electrumPort` options.

---

## HTTP API

The daemon exposes these endpoints on `127.0.0.1:2112` (configurable via `daemonHost`/`daemonPort`). All POST endpoints accept JSON bodies. HTTPS is supported when started with `--tls-cert` and `--tls-key`. Payment endpoints support `X-Idempotency-Key` headers (24h cache).

### Authentication

When `apiToken` is configured (via `--api-token`, `BEIGNET_API_TOKEN`, or config file), all endpoints require a `Authorization: Bearer <token>` header. Exceptions:

- `GET /health` -- always accessible (for monitoring tools)
- `GET /openapi.json` -- always accessible (for API discovery)

If no `apiToken` is configured, all endpoints are open (backward-compatible). `GET /mnemonic` is only accessible when `apiToken` is set.

### Endpoints

| Method | Path | Parameters | Description |
|--------|------|------------|-------------|
| GET | `/info` | -- | Node info |
| GET | `/mnemonic` | -- | Show mnemonic (requires apiToken) |
| GET | `/balance` | -- | Balances |
| GET | `/health` | -- | Health status (auth-exempt) |
| GET | `/openapi.json` | -- | OpenAPI 3.0 spec (auth-exempt) |
| GET | `/stats` | `?window=<ms>` | Node statistics (optional time window in ms) |
| GET | `/peers` | -- | List peers |
| GET | `/channels` | -- | List channels |
| GET | `/channels/ready` | -- | List channels in NORMAL state |
| GET | `/can-send` | `?amountSats=<n>` | Check send capacity |
| GET | `/can-receive` | `?amountSats=<n>` | Check receive capacity |
| GET | `/payments` | `?status=&direction=&since=&limit=&offset=` | List payments (filterable) |
| GET | `/forwards` | `?since=&until=&limit=&offset=&channelId=` | Settled forwards with fees earned (msat values as strings) |
| GET | `/forwards/summary` | `?since=` | Forwarding totals: `{ count, volumeOutMsat, feesEarnedMsat }` |
| GET | `/invoices` | -- | List created invoices |
| GET | `/channel` | `?channelId=<hex>` | Get channel (query param or body) |
| GET | `/channel/health` | `?channelId=<hex>` | Channel health assessment with liquidity warnings |
| GET | `/payment` | `?paymentHash=<hex>` | Get payment (query param or body) |
| GET | `/trusted-peers` | -- | List trusted peers |
| GET | `/offers` | -- | List BOLT 12 offers |
| GET | `/events` | -- | SSE event stream (auth-gated) |
| POST | `/address/new` | -- | New address |
| POST | `/wallet/refresh` | -- | Sync wallet |
| POST | `/send` | `{ address, amountSats, satsPerVbyte? }` | Send on-chain (optional fee rate) |
| POST | `/send-max` | `{ address, satsPerVbyte? }` | Sweep the whole on-chain balance to one address |
| POST | `/tx/bump-fee` | `{ txid, satsPerVbyte }` | RBF an unconfirmed tx at a higher fee (NOT_BOOSTABLE if RBF unavailable) |
| POST | `/tx/boost` | `{ txid, satsPerVbyte? }` | Fee-bump a tx: RBF when possible, else CPFP |
| GET | `/transactions/boostable` | -- | Unconfirmed txs eligible for RBF/CPFP, by method |
| POST | `/consolidate` | `{ satsPerVbyte? }` | Merge all UTXOs into one output at a fresh wallet address |
| POST | `/psbt/build` | `{ outputs, satsPerVbyte? }` | Build an UNSIGNED PSBT for an external signer |
| POST | `/psbt/import-signed` | `{ psbtBase64 }` | Validate + finalize a signed PSBT (no broadcast) |
| POST | `/psbt/combine` | `{ psbts }` | Combine partially signed PSBT copies |
| POST | `/peer/connect` | `{ pubkey, host, port }` | Connect peer |
| POST | `/peer/disconnect` | `{ pubkey }` | Disconnect peer |
| POST | `/peers/bootstrap` | -- | Discover peers via DNS |
| POST | `/peers/connect-seeds` | `{ maxPeers? }` | Connect to seed peers |
| POST | `/trusted-peer/add` | `{ pubkey }` | Trust peer for zero-conf |
| POST | `/trusted-peer/remove` | `{ pubkey }` | Remove trusted peer |
| POST | `/channel/open` | `{ pubkey, amountSats, pushSats? }` | Open channel |
| POST | `/channel/open-zeroconf` | `{ pubkey, amountSats, pushSats? }` | Open zero-conf channel |
| POST | `/channel/open-v2` | `{ pubkey, amountSats, fundingFeeratePerkw?, ... }` | Open dual-funded v2 channel |
| POST | `/channels/ensure-minimum` | `{ count, satsPerChannel, timeoutMs? }` | Auto-open channels to meet minimum count |
| POST | `/channel/connect-and-open` | `{ pubkey, host, port, amountSats, pushSats? }` | Connect + open in one call |
| POST | `/channel/open-and-wait` | `{ pubkey, amountSats, pushSats?, timeoutMs? }` | Open channel + wait for NORMAL state |
| POST | `/channel/close` | `{ channelId }` | Coop close |
| POST | `/channel/forceclose` | `{ channelId }` | Force close |
| POST | `/channel/splice-in` | `{ channelId, amountSats, feeratePerkw }` | Splice-in funds |
| POST | `/channel/splice-out` | `{ channelId, amountSats, feeratePerkw }` | Splice-out funds |
| POST | `/invoice/create` | `{ amountSats?, description? }` | Create invoice (omit amountSats for amount-less) |
| POST | `/invoice/create-hold` | `{ paymentHash, amountMsat?, amountSats?, description?, expiry? }` | Create hold invoice for a caller-supplied payment hash (HTLCs park until settle/cancel) |
| POST | `/invoice/settle-hold` | `{ preimage }` | Settle a parked hold invoice (fulfills all MPP parts) |
| POST | `/invoice/cancel-hold` | `{ paymentHash }` | Cancel a hold invoice; fails parked HTLCs back |
| GET | `/invoices/held` | -- | List hold invoices with state + parked totals |
| POST | `/invoice/decode` | `{ bolt11 }` | Decode invoice |
| POST | `/invoice/pay` | `{ bolt11, timeoutMs?, maxFeeSats?, amountSats?, metadata? }` | Pay invoice (`amountSats` for amount-less invoices, `metadata` for labels) |
| POST | `/invoice/pay-safe` | `{ bolt11, timeoutMs?, maxFeeSats?, amountSats? }` | Pay invoice; resolves with `status: 'FAILED'` on failure instead of error. |
| POST | `/invoice/pay-retry` | `{ bolt11, maxRetries?, backoffMs?, maxFeeSats?, amountSats?, metadata? }` | Pay with exponential backoff retry. Returns `RetryPaymentResult` with `attempts`. |
| POST | `/invoice/pay-async` | `{ bolt11, maxFeeSats?, amountSats?, metadata? }` | Fire-and-forget pay; returns `{ paymentHash, status }` immediately. Poll `GET /payment` for settlement. |
| POST | `/payment/cancel` | `{ paymentHash }` | Cancel a pending outbound payment (marks as FAILED) |
| POST | `/payment/metadata` | `{ paymentHash, metadata }` | Attach key-value metadata to an existing payment |
| POST | `/route/estimate` | `{ bolt11, amountSats? }` | Estimate route fee without sending |
| POST | `/route/probe` | `{ destination, amountSats }` | Probe route viability to a destination |
| GET | `/graph/info` | -- | Network graph summary: node/channel counts, last sync time |
| GET | `/graph/node` | `?pubkey=<hex>` | Node announcement info + its known channel SCIDs (404 if unknown) |
| GET | `/graph/channel` | `?scid=<BxTxO or hex>` | Channel endpoints, capacity and both directions' policies (404 if unknown) |
| GET | `/graph/describe` | `?limit=&offset=` | Paged channel dump (limit defaults to 500, capped at 500) |
| POST | `/route/query` | `{ destination, amountSats, maxFeeSats? }` | Compute a route WITHOUT sending; hops feed `/payment/send-to-route` |
| POST | `/payment/send-to-route` | `{ paymentHash, route: { hops }, paymentSecret? }` | Send a payment along an explicit route from `/route/query` |
| POST | `/backup` | `{ destPath }` | Create online database backup |
| GET | `/backup/scb` | - | Export encrypted static channel backup `{ encoded, channelCount, path }` |
| POST | `/backup/trigger` | -- | Run the configured scheduled backup now (no-op when `backupPath` unset) |
| POST | `/message/sign` | `{ message }` | Sign message with the node key (LND-compatible zbase32 signature) |
| POST | `/message/verify` | `{ message, signature }` | Recover signer pubkey; `knownNode` = present in our graph |
| POST | `/gossip/sync` | `{ pubkey? }` | Gossip sync from one peer or all connected peers |
| POST | `/gossip/sync-rapid` | -- | Rapid Gossip Sync snapshot (mainnet only) |
| GET | `/channel/diagnostics` | `?channelId=<hex>` | Routing-readiness diagnostics (SCID/announcement/peer issues) |
| POST | `/address/validate` | `{ address }` | Validate a Bitcoin address for the active network |
| POST | `/recover-fallback-funds` | `{ feeRatePerVbyte? }` | Sweep funding-key fallback UTXOs into the wallet |
| POST | `/channel/update-commitment-feerate` | `{ channelId, feeratePerKw }` | Update channel COMMITMENT feerate via update_fee (min 253). Not the routing fee policy |
| POST | `/channel/update-fee` | `{ channelId, feeratePerKw }` | Deprecated alias for `/channel/update-commitment-feerate` |
| POST | `/channel/update-policy` | `{ channelId?, all?, feeBaseMsat?, feeProportionalMillionths?, cltvExpiryDelta?, htlcMinimumMsat?, htlcMaximumMsat? }` | Set ROUTING fee policy per channel (or `all: true`); regenerates + re-broadcasts channel_update |
| GET | `/channel/policy` | `?channelId=<hex>` | Effective routing policy (override or node defaults) with `source` field |
| POST | `/node/wait-ready` | `{ timeoutMs? }` | Wait for node to be fully operational (default 30s) |
| POST | `/channel/wait-ready` | `{ channelId, timeoutMs? }` | Wait for channel to reach NORMAL (default 60s) |
| POST | `/payment/wait` | `{ paymentHash, timeoutMs? }` | Wait for payment to settle (default 60s) |
| POST | `/offer/create` | `{ description, amountSats?, issuer? }` | Create BOLT 12 offer |
| POST | `/offer/decode` | `{ offer }` | Decode a BOLT 12 offer string |
| POST | `/offer/pay` | `{ offer, amountSats?, timeoutMs? }` | Pay BOLT 12 offer |
| GET | `/payment/proof` | `?paymentHash=<hex>` | Cryptographic payment proof (preimage, invoice, route) |
| GET | `/payment/verify-proof` | `?paymentHash=<hex>` | Verify proof: `sha256(preimage) === paymentHash` |
| GET | `/node/uri` | `?host=<addr>` | Node connection URI (`pubkey@host:port`). Optional external host override. |
| POST | `/payment/estimate` | `{ bolt11, amountSats? }` | Payment intelligence: success probability, route quality, fees |
| GET | `/liquidity` | -- | Liquidity analysis with recommendations |
| GET | `/channel/suggestions` | `?count=<n>` | Graph-based channel open suggestions |
| GET | `/fees` | -- | On-chain fee trend analysis |
| GET | `/logs` | `?category=&since=&limit=` | Query persistent action log |
| GET | `/readiness` | -- | Mainnet readiness checklist (11 checks) |
| GET | `/metrics` | -- | Prometheus text exposition format metrics (auth-exempt) |
| POST | `/webhooks/register` | `{ url, events, secret? }` | Register webhook callback |
| DELETE | `/webhooks/unregister` | `{ id }` | Remove webhook |
| GET | `/webhooks` | -- | List registered webhooks |
| POST | `/queue/add` | `{ bolt11, priority?, amountSats?, maxFeeSats?, metadata? }` | Enqueue payment |
| GET | `/queue` | -- | List payment queue |
| POST | `/queue/cancel` | `{ id }` | Cancel queued payment |
| POST | `/keysend` | `{ pubkey, amountSats, timeoutMs?, maxFeeSats?, metadata? }` | Spontaneous payment (no invoice). Blocks until settled. |
| POST | `/keysend/safe` | `{ pubkey, amountSats, timeoutMs?, maxFeeSats?, metadata? }` | Keysend that never errors — resolves with `status: 'FAILED'` instead. |
| GET | `/spend-limit` | -- | Daily spending limit status: `{ limitSats, spentSats, remainingSats, resetsAt }` |
| POST | `/stop` | `{ drain?, drainTimeoutMs? }` | Stop daemon. `drain: true` waits for in-flight payments before shutting down. |

### Server-Sent Events (SSE)

`GET /events` opens a persistent connection that streams events as they occur:

```
event: payment:received
data: {"paymentHash":"ab12...","amountSats":1000,"status":"COMPLETED"}

event: channel:ready
data: {"channelId":"cd34..."}
```

Events relayed to SSE clients and webhooks: `payment:received`, `payment:sent`, `payment:failed`, `invoice:settled`, `channel:opening`, `channel:ready`, `channel:pending-close`, `channel:force-closing`, `channel:closed`, `peer:connect`, `peer:disconnect`, `node:ready`.

- `invoice:settled` fires when an invoice this node issued is paid. `payment:received` also covers spontaneous (keysend) receives, which have no invoice.
- `channel:force-closing` fires both when this node broadcasts its own commitment (`initiator: "local"`) and when a peer's unilateral close is detected on-chain (`initiator: "remote"`).

Per-HTLC events (`htlc:forwarded`, `htlc:fulfilled`, `htlc:failed`) are relayed only when the daemon is started with `--htlc-events` (config `htlcEvents: true`, env `BEIGNET_HTLC_EVENTS=true`); routing nodes generate one event per HTLC, so they are off by default.

A keepalive comment (`: keepalive`) is sent every 30 seconds to prevent proxy timeouts.

### Webhooks

For agent frameworks that prefer callbacks over persistent connections, register webhook URLs:

```bash
# Register a webhook
curl -X POST http://localhost:2112/webhooks/register \
  -H "Content-Type: application/json" \
  -d '{"url": "https://myagent.com/callback", "events": ["payment:received"], "secret": "mysecret"}'
# {"ok":true,"result":{"id":"abc123...","url":"https://...","events":["payment:received"],...}}

# List webhooks
curl http://localhost:2112/webhooks
# {"ok":true,"result":[...]}

# Unregister
curl -X DELETE http://localhost:2112/webhooks/unregister \
  -H "Content-Type: application/json" \
  -d '{"id": "abc123..."}'
```

Webhook deliveries are POST requests with JSON body `{ event, data, timestamp }`. When a `secret` is configured, an `X-Webhook-Signature: sha256=<hmac>` header is included for payload verification. Webhooks are persisted to SQLite and survive daemon restarts. Note: HMAC secrets are stored as hashes — re-register with a secret after restart if HMAC verification is needed.

Registering with `"events": ["*"]` matches every relayed event, including the invoice, channel-lifecycle, and (when `--htlc-events` is enabled) HTLC events, plus any event types added in future versions. The event list matches the SSE list above.

### API Versioning

All endpoints support an optional `/v1/` prefix for forward compatibility. The daemon strips the prefix automatically:

```
GET /v1/info       →  handled as  GET /info
POST /v1/invoice/pay  →  handled as  POST /invoice/pay
```

All responses include `X-API-Version: 1` header. Non-prefixed routes continue to work unchanged.

### CORS

Enable CORS with `cors: true` (allows all origins) or `cors: 'https://myapp.com'` (specific origin) in DaemonOptions:

```typescript
startDaemon({ cors: true });    // Access-Control-Allow-Origin: *
startDaemon({ cors: 'https://myapp.com' });  // specific origin
```

Handles `OPTIONS` preflight requests automatically.

---

## File Layout

```
src/cli/
  types.ts          -- JSON-serializable response types
  errors.ts         -- BeignetError + BeignetErrorCode + BOLT failure descriptions
  beignet-node.ts   -- Core wrapper class (most important file)
  config.ts         -- Config file + PID file management
  daemon.ts         -- HTTP daemon (http.createServer)
  openapi.ts        -- OpenAPI 3.0 spec generator (served at GET /openapi.json)
  webhooks.ts       -- WebhookManager (register, dispatch, HMAC signing)
  payment-queue.ts  -- PaymentQueue (priority, concurrency, capacity-aware)
  http-rate-limiter.ts -- Token-bucket HTTP rate limiter
  cli.ts            -- CLI entry point (#!/usr/bin/env node)
  index.ts          -- Barrel exports
  README.md         -- This file

src/lightning/advisor/
  liquidity-advisor.ts   -- Channel liquidity analysis and recommendations
  fee-advisor.ts         -- On-chain fee trend tracking (144-sample circular buffer)
  channel-suggestions.ts -- Graph-based channel open suggestions
  index.ts               -- Barrel exports

docs/
  AI_AGENT_GUIDE.md -- Comprehensive deployment guide for AI agents

tests/cli/
  beignet-node.test.ts   -- Unit tests
  webhooks.test.ts       -- Webhook tests
  payment-queue.test.ts  -- Payment queue tests
  payment-retry.test.ts  -- Payment retry with backoff tests
  readiness.test.ts      -- Readiness checklist tests
  metrics.test.ts        -- Prometheus metrics tests
  electrum-failover.test.ts -- Electrum failover tests
  auto-backup.test.ts    -- Automated backup tests
  ensure-channels.test.ts -- Auto-open minimum channels tests
  deployment-guide.test.ts -- Guide existence tests
  competitive-improvements.test.ts -- Spending limits, idempotency, TLS, drain mode tests
```

---

## Tests

```bash
# Run CLI unit tests (no infrastructure needed)
npm run test:cli

# Run daemon/Electrum integration tests (requires Electrum server)
npm run test:integration

# Run lightning unit tests
npm run test:lightning

# Run everything
npm run test:all
```
