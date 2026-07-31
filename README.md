# Beignet

A self-custodial Bitcoin wallet library for JavaScript/TypeScript with a **full Lightning Network implementation**. Beignet implements the Lightning protocol and channel state machine in TypeScript rather than wrapping LND, CLN or LDK: it speaks BOLT 8 over a real TCP socket and runs its own BOLT 2 state machine.

Two layers, one mnemonic:

- **On-chain wallet:** HD keys, address generation, UTXO tracking, transaction building, PSBT/hardware signing, multisig, watch-only, Electrum connectivity.
- **Lightning:** channel lifecycle, onion-routed payments, BOLT 11 invoices, BOLT 12 offers, gossip and pathfinding, anchors, splicing, taproot channels, watchtower client. Interop-tested against LND, Core Lightning and Eclair on regtest.

Requires **Node.js 18+**. MIT licensed.

**Jump to:** [Install](#install) · [Examples](#try-the-examples) · [On-chain wallet](#on-chain-wallet) · [Lightning](#lightning) · [Daemon & CLI](#http-daemon--cli) · [Protocol layer](#protocol-layer-advanced) · [Tests](#tests) · [Status & limitations](#status--limitations)

## Install

```bash
npm install beignet     # or: yarn add beignet
```

Smallest thing that works. `net` and `tls` are injected so the same code runs on Node and React Native:

```typescript
import net from 'net';
import tls from 'tls';
import { Wallet, generateMnemonic } from 'beignet';

const result = await Wallet.create({
  mnemonic: generateMnemonic(),
  electrumOptions: { net, tls }
});
if (result.isErr()) throw result.error;
const wallet = result.value;

console.log(await wallet.getAddress());
console.log(wallet.getBalance());
```

From here: [the on-chain wallet](#on-chain-wallet) for sending, PSBTs, multisig and watch-only, or [Lightning](#lightning) for channels and payments.

## Try the examples

The fastest way to understand the whole system is to run the two REPL examples against a live wallet and a live node. Both are checked-in TypeScript you can read and edit.

```bash
git clone git@github.com:coreyphillips/beignet.git && cd beignet
npm install
```

### 1. On-chain wallet REPL

```bash
npm run example
```

Creates a mainnet wallet (a fresh mnemonic unless you pass one), syncs it against a public Electrum server, prints the balance and a receive address, then drops you at a `>` prompt with the wallet bound to `wallet`. Type `help()` for the command list.

```js
> wallet.getBalance()
> await wallet.getAddress()
> await wallet.refreshWallet()
> await wallet.send({ address: 'bc1q...', amount: 10000, satsPerByte: 2 })
```

State persists as JSON under `example/walletData/`. Pass a mnemonic as the first argument to reuse a wallet: `npm run example -- "abandon abandon ... about"`.

### 2. Lightning node REPL

```bash
npm run example:lightning
```

Boots a real Lightning node (`BeignetNode`) with an auto-created wallet, storage and funding provider, waits for it to become operational, prints info/balance/health, and drops you at a `beignet>` prompt with the node bound to `node`. Type `help()` for the command list. Top-level `await` works.

```js
beignet> await node.getNewAddress()          // fund this on-chain, then:
beignet> await node.connectAndOpenChannel(pubkey, host, port, 200000)
beignet> node.createInvoice(1000, 'coffee').bolt11
beignet> await node.payInvoice('lnbc...')
beignet> node.getLiquiditySnapshot()
```

The flags you will actually reach for (everything after `--`):

| Flag | Effect |
|------|--------|
| `mainnet` \| `testnet` \| `regtest` | Network, as a bare positional arg (default `mainnet`) |
| `<12 or 24 words>` | Reuse a mnemonic, as bare positional args (default generates one) |
| `--electrum-host <h>` `--electrum-port <p>` | Point at your own Electrum server |
| `--alias <name>` | Node alias in `node_announcement` |

```bash
# named regtest node against a local Electrum server
npm run example:lightning -- regtest --electrum-host 127.0.0.1 --electrum-port 60001 --alias mynode
```

Tor, full-graph gossip, the low-level `LightningNode` variant and the non-interactive payment-API walkthrough have flags too: see [the flag reference](example/REPL_TESTING.md#repl-flags).

Node state lives in a SQLite DB under `~/.beignet/data/<hash-of-mnemonic>/` (the `--low-level` example uses `example/lightningData/node.db`).

Both examples run straight off the TypeScript sources through `ts-node`, so no build step is needed. Use `npm run build` when you want the compiled `dist/`.

**→ [example/REPL_TESTING.md](example/REPL_TESTING.md) is a copy-pasteable walkthrough** of the whole lifecycle in the REPL: funding, peers, channels, invoices, payments, keysend, offers, splicing, closing, backup.

## Which entry point?

| Import | Contains | Use when |
|--------|----------|----------|
| `beignet` | `Wallet`, `generateMnemonic`, types | You want the on-chain wallet |
| `beignet/cli` | `BeignetNode`, `startDaemon`, error helpers | **You want Lightning.** Sats-denominated, string IDs, structured errors |
| `beignet/lightning` | Namespaced protocol modules (`node`, `channel`, `onion`, ...) | You need the raw BOLT layer: bigint msat, Buffer IDs, wire messages |

## On-chain wallet

```typescript
import net from 'net';
import tls from 'tls';
import { Wallet, generateMnemonic } from 'beignet';

const res = await Wallet.create({
  mnemonic: generateMnemonic(),
  electrumOptions: { net, tls } // required: inject the socket implementations
});
if (res.isErr()) throw res.error;
const wallet = res.value;

const address = await wallet.getAddress();
const balance = wallet.getBalance();

await wallet.send({ address: 'bc1q...', amount: 50_000, satsPerByte: 2 });
await wallet.sendMany({ txs: [{ address: 'bc1q...', amount: 1000 }] });
await wallet.refreshWallet();

const utxos = wallet.listUtxos();
const history = await wallet.getAddressHistory('bc1q...');
```

Every fallible call returns a `Result<T>`: check `isErr()` before reading `.value`. Amounts are always satoshis.

Options worth knowing on `Wallet.create`: `network` (`EAvailableNetworks.mainnet` | `testnet` | `regtest` | `signet`), `addressType` (`p2wpkh` default, `p2sh-p2wpkh`, `p2pkh`, `p2tr`), `passphrase`, `account`, `storage`, `logger`, `coinSelectPreference`, `feeEstimationSource`, `gapLimitOptions`.

<details>
<summary><b>Custom Electrum servers, failover, fee sources, BIP21</b></summary>

```typescript
import { EAvailableNetworks, EProtocol, Wallet } from 'beignet';

const res = await Wallet.create({
  mnemonic,
  network: EAvailableNetworks.mainnet,
  feeEstimationSource: 'electrum', // 'electrum' | 'http' | 'auto' (default)
  electrumOptions: {
    net,
    tls,
    servers: [
      { host: 'bitcoin.lu.ke', ssl: 50002, tcp: 50001, protocol: EProtocol.ssl },
      { host: 'mempool.space', ssl: 60602, tcp: 60601, protocol: EProtocol.ssl }
    ]
  }
});
```

- **Failover:** with multiple servers the wallet rotates through them in order on connect/reconnect failure, then through hardcoded fallback peers for the network, with a per-server cooldown so dead servers are not hammered. Inspect `wallet.electrum.currentServer` and `wallet.electrum.rotationCount`.
- **Fee source:** `'electrum'` queries only the connected server via `blockchain.estimatefee`, so fee lookups never leak to mempool.space/blocktank over clearnet. `'auto'` prefers Electrum and falls back to HTTP. All remote rates are clamped to 5000 sat/vB.
- **Networks:** mainnet, testnet, regtest and signet work end to end (wallet, Electrum, CLI/daemon `--network signet`, Lightning chain hash and `tbs` invoice prefix). Signet shares testnet address formats and coin type 1.
- **BIP21:** `encodeBip21({ address, amountSats?, label?, message? })` builds a `bitcoin:` URI.

</details>

<details>
<summary><b>Watch-only wallets (account xpub)</b></summary>

Built from an account-level extended public key instead of a mnemonic. The key is assumed to sit at `m/purpose'/coin'/account'` (e.g. `m/84'/0'/0'`), so addresses derive as `xpub/0/i` and `xpub/1/i`. SLIP-132 version bytes are normalized: `zpub`/`vpub` implies p2wpkh, `ypub`/`upub` implies p2sh-p2wpkh, a plain `xpub`/`tpub` uses `addressType` (default p2wpkh). One account xpub yields exactly one address type, so a watch-only wallet monitors only that type.

```typescript
const res = await Wallet.createWatchOnly({
  xpub: 'zpub6r...',
  network: EAvailableNetworks.mainnet,
  electrumOptions: { net, tls }
});
if (res.isErr()) return;
const watchOnly = res.value;

await watchOnly.getAddress(); // works
watchOnly.getBalance();       // works

const send = await watchOnly.send({ address: 'bc1q...', amount: 1000 });
// send.isErr() === true, message: 'watch-only wallet cannot sign'
```

The full read-only surface works: address generation, gap-limit scanning, Electrum refresh, balances, history, UTXOs, fee estimates, address subscriptions. Anything needing private keys (`send`/`sendMax`/`sendMany`/`sweepPrivateKey`/`getPrivateKey`) fails with the typed `WatchOnlySigningError` (`code: 'WATCH_ONLY_CANNOT_SIGN'`). Library-only for now: the HTTP daemon always runs with a mnemonic.

</details>

<details>
<summary><b>Hardware wallets and external signers (PSBT)</b></summary>

`buildPsbt` runs the normal setup (coin selection, change, fee) but stops before signing, returning a base64 PSBT populated with what a hardware signer needs: `witnessUtxo` (or `nonWitnessUtxo` for legacy p2pkh), `redeemScript` for p2sh-p2wpkh, `tapInternalKey` plus `tapBip32Derivation` for p2tr, and `bip32Derivation` on every wallet input. Works on full and watch-only wallets.

```typescript
// 1. Build (never touches private keys)
const build = await wallet.buildPsbt({ address: 'bc1q...', amount: 50_000, satsPerByte: 4 });
if (build.isErr()) return;
const { psbtBase64, fee, vsizeEstimate } = build.value;

// 2. Sign externally (hardware wallet, HWI, another machine)
const signedBase64 = await myHardwareWallet.signPsbt(psbtBase64);

// 3. Import: validates a signature on EVERY input, finalizes, does NOT broadcast
const imported = wallet.importSignedPsbt(signedBase64);
if (imported.isErr()) return; // missing/invalid signatures are rejected loudly
const { txHex, txid } = imported.value;

// 4. Broadcast when ready
await wallet.broadcastTransaction(txHex);

// Multi-party: merge partially signed copies of the same PSBT
const combined = wallet.combinePsbts([copyA, copyB]);
```

For watch-only wallets the true master fingerprint is unknowable from an account xpub, so the xpub's parent fingerprint is used: signers should locate keys by derivation path.

Also on the daemon (`POST /psbt/build`, `/psbt/import-signed`, `/psbt/combine`) and the CLI (`beignet psbt build|import-signed|combine`).

</details>

<details>
<summary><b>Multisig (P2WSH sortedmulti)</b></summary>

`Wallet.createMultisig` creates a descriptor-based sorted-multisig wallet, `wsh(sortedmulti(threshold, key1, key2, ...))`: the interoperable standard used by Bitcoin Core, Sparrow and Specter. Derivation follows BIP 48 script type 2 (`m/48'/coin'/account'/2'`, receive `/0/*`, change `/1/*`) and keys are BIP 67 ordered at every index, so any wallet built from the same account xpubs produces identical addresses regardless of cosigner order.

Cosigners are account-level extended public keys (`xpub`/`tpub`, or SLIP-132 `Zpub`/`Vpub`, normalized automatically). With a mnemonic, this wallet IS one of the cosigners: its BIP 48 account xpub is derived and included automatically (pass `ourXpub` to assert it; a mismatch is rejected). Omit the mnemonic for a watch-only coordinator.

Spending is PSBT-only. `send`/`sendMany`/`sendMax` fail with `MultisigSpendError` (`code: 'MULTISIG_REQUIRES_PSBT'`).

```typescript
// 1. Each cosigner builds the same quorum from the others' BIP 48 account xpubs.
const a = await Wallet.createMultisig({
  threshold: 2,
  mnemonic: mnemonicA,       // we are one cosigner; our xpub is added automatically
  cosigners: [xpubB, xpubC],
  network: EAvailableNetworks.mainnet,
  electrumOptions: { net, tls }
});
const b = await Wallet.createMultisig({ threshold: 2, mnemonic: mnemonicB, cosigners: [xpubA, xpubC], /* ... */ });

// An optional watch-only coordinator holds no keys at all.
const c = await Wallet.createMultisig({ threshold: 2, cosigners: [xpubA, xpubB, xpubC], /* ... */ });

if (a.isErr() || b.isErr() || c.isErr()) return;
const [walletA, walletB, coordinator] = [a.value, b.value, c.value];

// 2. Fund it: every instance derives the same addresses.
const deposit = await walletA.getAddress();

// 3. Build the unsigned PSBT (any instance, coordinator included).
const built = await walletA.buildPsbt({ address: 'bc1q...', amount: 50_000, satsPerByte: 4 });
if (built.isErr()) return;
const unsigned = built.value.psbtBase64;

// 4. Each cosigner signs their own copy (nothing finalizes below threshold).
const signedA = walletA.signPsbtWithOurKey(unsigned);
const signedB = walletB.signPsbtWithOurKey(unsigned);
if (signedA.isErr() || signedB.isErr()) return;

// 5. Combine, finalize at threshold, broadcast.
const combined = coordinator.combinePsbts([signedA.value, signedB.value]);
if (combined.isErr()) return;
const finalized = coordinator.importSignedPsbt(combined.value); // 2-of-3 met
if (finalized.isErr()) return;
await coordinator.broadcastTransaction(finalized.value.txHex);

// Below threshold it fails loudly:
// 'Input 0 is below the multisig threshold: have 1 signature(s), need 2.'

// Interop: import into Bitcoin Core / Sparrow / Specter.
coordinator.exportDescriptors();
// wsh(sortedmulti(2,[fp/48h/0h/0h/2h]xpub.../0/*,[fp]xpub.../0/*,...))#checksum
```

`buildPsbt` attaches the `witnessScript` and one `bip32Derivation` per cosigner to every input. `importSignedPsbt` counts VALID partial signatures per input against the witnessScript threshold and refuses to finalize below it. Library-only for now: the daemon wallet stays single-sig.

</details>

<details>
<summary><b>Encrypted storage and leveled logging</b></summary>

The wallet persists through the host-injected `TStorage` interface (`storage: { getData, setData }`), and values are handed over as-is, so by default they are stored in plaintext. Persisted data is addresses, indexes, UTXOs, transactions, balance and fee estimates: no private keys and no mnemonic are ever written, so exposure is a privacy concern (full wallet history), not fund loss.

Wrap any `TStorage` with `createEncryptedStorage` to encrypt at rest with AES-256-GCM under an HKDF-derived key from the seed. Pre-existing plaintext values pass through unchanged and migrate lazily as they are rewritten.

```typescript
import * as bip39 from 'bip39';
import { createConsoleLogger, createEncryptedStorage, Wallet } from 'beignet';

const seed = bip39.mnemonicToSeedSync(mnemonic);
const wallet = await Wallet.create({
  mnemonic,
  storage: createEncryptedStorage({ getData, setData }, seed),
  logger: createConsoleLogger('warn'), // only warn + error reach the console
  electrumOptions: { net, tls }
});
```

Diagnostics flow through a small injectable `ILogger` (`debug`/`info`/`warn`/`error`, each `(message, meta?)`), with filtering `debug < info < warn < error` plus `'silent'`. This is separate from the Lightning node's persisted structured action log (`getActionLog`).

- `Wallet.create({ logger })` defaults to `createConsoleLogger('info')`, preserving historical console output. `disableMessages` is independent: it only gates `onMessage` callbacks.
- `LightningNode` defaults to `noopLogger` (silent). Every action-log entry is also mirrored to `logger.debug('category:action', data)`.
- `BeignetNode.create({ logger, logLevel })` forwards passing entries to the logger (in addition to the `'log'` event) and injects it into the underlying `Wallet` and `LightningNode`.
- Daemon: `beignet start --log-level <debug|info|warn|error|silent>` (or `BEIGNET_LOG_LEVEL`, or `logLevel` in `~/.beignet/config.json`) prints to stderr. Unset keeps the daemon silent; stdout stays reserved for command output.

</details>

## Lightning

> **Beignet is under active development.** Evaluate it on regtest, signet, or with small
> amounts you can afford to lose. Read [Status & limitations](#status--limitations) before
> putting meaningful mainnet funds behind it: this is a self-custodial Lightning
> implementation, and channel funds are only as safe as the node watching them.

`BeignetNode` from `beignet/cli` is the recommended API: it wraps the protocol layer with satoshi amounts, string channel IDs and structured error codes.

```typescript
import { BeignetNode, isRetryableError } from 'beignet/cli';

// Creates the wallet, storage and funding provider for you
const node = await BeignetNode.create({
  mnemonic: 'abandon abandon ... about',
  network: 'regtest',
  electrumHost: '127.0.0.1',
  electrumPort: 60001
});

node.getInfo();    // { nodeId, network, alias, ... }
node.getHealth();  // { status: 'ready', peers, channels, ... }
node.isReady();    // true once the node has active channels

const inv = node.createInvoice(1000, 'coffee');
console.log(inv.bolt11);

try {
  const payment = await node.payInvoice('lnbcrt10n1...');
  console.log(payment.status); // 'COMPLETED'
} catch (err) {
  if (isRetryableError(err)) {
    // transient: no route, timeout. Safe to retry
  } else {
    // permanent: invalid invoice, expired. Do not retry
  }
}

node.listChannels();
node.listPayments();
node.listInvoices();

await node.destroy();
```

Events: `node:ready`, `channel:ready`, `channel:closed`, `peer:connect`, `peer:disconnect`, `peer:error`, `payment:sent`, `payment:received`, `node:error`, `log`.

Useful variants: `payInvoiceSafe` (never throws), `payInvoiceWithRetry({ maxRetries, backoffMs, maxFeeSats })`, `sendPaymentAsync` (returns the hash immediately), `connectAndOpenChannel`, `openChannelAndWait`, `sendKeysend`, `createOffer`/`payOffer`, `spliceIn`/`spliceOut`, `backup`, `gracefulShutdown`.

**→ [docs/AI_AGENT_GUIDE.md](docs/AI_AGENT_GUIDE.md)** covers deployment in depth: channel strategy, liquidity management, monitoring and Prometheus metrics, pre-flight validation, safety rails, retry/backoff patterns, idempotency keys, spend limits, drain mode, backup and recovery, mainnet checklist.

### Decision-support APIs

Built-in advisors, not usually found in a Lightning library:

```typescript
// Channel balance analysis with actionable recommendations
const liquidity = node.getLiquiditySnapshot();
console.log('Outbound:', liquidity.outboundLiquidityPct + '%');
for (const rec of liquidity.recommendations) {
  console.log(`[${rec.priority}] ${rec.type}: ${rec.reason}`);
}

node.getChannelSuggestions(3);  // graph-based peer suggestions for opens
node.getFeeSnapshot();          // on-chain fee trend: OPEN_NOW / WAIT / NEUTRAL
node.estimatePayment(bolt11);   // success probability + estimated fee, pre-send
node.getMainnetReadiness();     // 11-check weighted readiness report
```

<details>
<summary><b>Advisor execution: circular rebalancing and fee auto-tuning</b></summary>

The advisor can act, not just recommend. Both features are **off by default**.

```typescript
// One-shot circular rebalance: self-payment out over `from` and back in over `to`.
// Aborts WITHOUT paying if the route fee exceeds maxFeeSats.
await node.rebalanceChannel(fromChannelId, toChannelId, 50_000, /* maxFeeSats */ 50);

node.getAdvisorRecommendations();        // read-only: analyze() + rebalancePlan[]
await node.executeRebalances(/* budgetSatsPerDay */ 500);
```

Automatic modes, opt-in via `BeignetNodeOptions` / `INodeConfig`:

```typescript
const node = await BeignetNode.create({
  mnemonic,
  // Periodically executes the rebalance plan. Routing fees spent on rebalances
  // are capped per UTC day and the running spend is persisted, so restarts
  // never overspend the same day. Resets at midnight UTC.
  autoRebalance: { enabled: true, budgetSatsPerDay: 500, minImbalancePct: 20 },
  // Every intervalMs (default 6h) nudges each channel's proportional fee:
  // +25% when outbound is depleted (<20% local) but still forwarding, -25% when
  // the channel saw no forwards in the window, clamped to [floorPpm, ceilPpm].
  // One adjustment per channel per interval.
  autoTuneFees: { enabled: true, floorPpm: 1, ceilPpm: 5_000 }
});
```

Daemon: `POST /rebalance`, `GET /advisor/recommendations`, `POST /advisor/execute-rebalances`.
CLI: `beignet rebalance <from> <to> <sats> --max-fee <sats>`, `beignet advisor recommendations`, `beignet advisor execute-rebalances [--budget <sats>]`.

</details>

<details>
<summary><b>Watchtowers (altruist client)</b></summary>

Penalty enforcement normally needs this node's chain monitor to be online: if a counterparty broadcasts a revoked commitment while you are offline, nobody sweeps the breach. The watchtower client closes that gap. At every revocation it builds an encrypted justice kit (the revoked commitment's breach hint plus a pre-signed to_local penalty) and ships it to remote towers over BOLT 8. When a tower later sees the breach on chain it decrypts the kit and broadcasts the penalty for you.

```typescript
const node = await BeignetNode.create({
  mnemonic,
  watchtowers: ['03abc...@tower.example.com:9911'] // off when empty
});
```

- **Altruist only.** Sessions use `reward = 0`. There is no server mode: beignet is a tower client, not a tower.
- **LND-tower compatible.** Implements LND's `wtwire` protocol (Init/CreateSession/StateUpdate/DeleteSession, message types 600-607) and the version-0 justice blob (XChaCha20-Poly1305, breach hint `SHA256(txid)[:16]`, key `SHA256(txid‖txid)`), so it works with existing public LND altruist towers.
- **Legacy + anchor channels.** The to_local revocation penalty (the fund-critical punishment) is packed for both. Taproot channels are not yet backed up.
- **Durable.** Per-tower session state and the un-acked backlog are persisted (encrypted at rest) and drained with exponential backoff on reconnect. An un-acked update is never dropped silently.

Daemon: `GET /watchtowers`, `POST /watchtower/add`, `DELETE /watchtower/remove`.
CLI: `beignet watchtower list|add <pubkey@host:port>|remove <uri>`, daemon flag `--watchtower` (repeatable) or `BEIGNET_WATCHTOWERS`.

</details>

## HTTP daemon & CLI

The same node runs as an HTTP/SSE daemon for language-agnostic integrations, driven by a JSON CLI.

```bash
# 1. Generate a mnemonic + ~/.beignet/config.json
npx beignet init --network regtest

# 2. Start the daemon (add --daemon to background it)
BEIGNET_ELECTRUM_HOST=127.0.0.1 BEIGNET_ELECTRUM_PORT=60001 BEIGNET_ELECTRUM_TLS=false \
  npx beignet start --network regtest --api-token mytoken

# 3. Drive it with the CLI (thin HTTP client, JSON out)
npx beignet info --pretty
npx beignet address
npx beignet channel connect-and-open <pubkey> <host> <port> 200000
npx beignet invoice create 1000 "coffee"
npx beignet invoice pay <bolt11>
```

Electrum and most other settings come from `~/.beignet/config.json` or the environment (`BEIGNET_MNEMONIC`, `BEIGNET_ELECTRUM_HOST`, `BEIGNET_ELECTRUM_PORT`, `BEIGNET_NETWORK`, ...). Run `npx beignet help` for the full command and flag list.

Or over HTTP directly:

```bash
curl -X POST http://localhost:2112/invoice/create -H 'Authorization: Bearer mytoken' \
  -H 'Content-Type: application/json' -d '{"amountSats": 1000, "description": "coffee"}'

curl -X POST http://localhost:2112/invoice/pay -H 'Authorization: Bearer mytoken' \
  -H 'Content-Type: application/json' -d '{"bolt11": "lnbcrt10n1..."}'

curl -N http://localhost:2112/events -H 'Authorization: Bearer mytoken'  # SSE stream
curl http://localhost:2112/ready                                        # load-balancer probe
```

- Responses are `{ "ok": true, "result": {...} }` or `{ "ok": false, "error": { "code": "...", "message": "..." } }`.
- Full spec at `GET /openapi.json`.
- `GET /health`, `/ready`, `/openapi.json` and `/metrics` are auth-exempt; everything else requires the bearer token **when one is configured**. Auth is off unless you set `apiToken` or `apiKeys` (named keys with `readonly`/`invoice`/`admin` scopes), so configure a token before exposing the daemon anywhere. It binds `127.0.0.1` by default.
- Embed it instead of shelling out: `import { startDaemon } from 'beignet/cli'`.

## Protocol layer (advanced)

Use this only if you need the BOLT layer directly: bigint msat, Buffer IDs, raw wire messages. `beignet/lightning` exports **namespaces**, not flat symbols.

```typescript
import net from 'net';
import tls from 'tls';
import { Wallet, generateMnemonic } from 'beignet';
import { invoice, node as ln, wallet as lnWallet } from 'beignet/lightning';

const mnemonic = generateMnemonic();

// 1. On-chain wallet (the same mnemonic funds both layers)
const res = await Wallet.create({ mnemonic, electrumOptions: { net, tls } });
if (res.isErr()) throw res.error;

// 2. Lightning node with auto-funding from the wallet
const node = ln.LightningNode.fromMnemonic(mnemonic, {
  network: invoice.Network.REGTEST,
  enableNetworking: true,
  fundingProvider: new lnWallet.WalletFundingProvider(res.value)
});

// 3. Connect and open: fully automatic with a funding provider
await node.connectPeer('03...pubkey', '127.0.0.1', 9735);
node.openChannel('03...pubkey', 100_000n);

// 4. Invoice and payment
node.createInvoice({ amountMsat: 50_000n, description: 'coffee' });
node.sendPayment(invoiceString);

// 5. Events. Channel-scoped events carry an object, not a bare id
node.on('channel:ready', ({ channelId }) => console.log(channelId.toString('hex')));
node.on('payment:received', (p) => console.log(p.amountMsat, 'msat'));
node.on('node:error', (err) => console.error(`[${err.code}]`, err.message));
```

Without a `fundingProvider`, build the funding transaction yourself and call `node.createFunding(channel, fundingTxid, outputIndex, signature)` after `openChannel`.

```
LightningNode              High-level API (EventEmitter)
  ├── ChannelManager       Multiplexes messages to Channel instances
  │     └── Channel        BOLT 2 state machine (returns ChannelAction[])
  ├── PeerManager          TCP connections + Noise_XK encrypted transport
  │     └── Peer           Per-connection BOLT 8 handshake + message framing
  ├── NetworkGraph         BOLT 7 gossip topology + Dijkstra pathfinding
  ├── InvoiceManager       BOLT 11 encode/decode/sign
  ├── ChainMonitor         BOLT 5 force-close detection + sweep
  └── FundingProvider?     Auto-builds + broadcasts funding txs (via Wallet)
```

**Key design principle:** `Channel` is fully transport-agnostic. Every method returns a `ChannelAction[]` (send message, broadcast tx, watch output, ...) that `ChannelManager` maps to real transport or chain operations, which makes the state machine testable without network I/O.

**→ [src/lightning/README.md](src/lightning/README.md)** documents the protocol layer in detail: data flow, events reference, typed payment errors, channel lifecycle, zero-conf, anchors, dual funding, splicing, offers, onion messages, forwarding, chain monitoring.

<details>
<summary><b>BOLT coverage</b></summary>

| BOLT | Specification | Implemented |
|------|--------------|-------------|
| 1 | Base Protocol | Peer messaging, init, error, ping/pong, feature negotiation, peer storage |
| 2 | Channel Management | Full state machine: open, fund, normal operation, shutdown, close, reestablish; v2 dual-funded opens (interactive-tx), splicing, quiescence |
| 3 | Transactions | Commitment txs, HTLC scripts, funding scripts, anchor outputs, fee calculation; simple taproot channels (MuSig2 funding, Schnorr HTLC sigs) |
| 4 | Onion Routing | Sphinx encryption, TLV hop payloads, payment_secret, failure codes, route blinding, onion messages |
| 5 | On-Chain | Force-close detection, HTLC sweep, output resolution, chain monitoring, wallet-funded anchor fee bumping (commitment CPFP + zero-fee HTLC fee-attach) |
| 7 | Gossip | Channel/node announcements, network graph, Dijkstra routing, gossip sync, Rapid Gossip Sync |
| 8 | Transport | Noise_XK handshake, encrypted transport, key rotation |
| 9 | Features | DATA_LOSS_PROTECT, STATIC_REMOTE_KEY, PAYMENT_SECRET, TLV_ONION, BASIC_MPP, CHANNEL_TYPE, GOSSIP_QUERIES, ANCHORS_ZERO_FEE_HTLC_TX (default), ROUTE_BLINDING, ONION_MESSAGES, QUIESCE, SCID_ALIAS, ZERO_CONF, KEYSEND, OPTION_TAPROOT, OPTION_WILL_FUND |
| 10 | DNS Bootstrap | Seed resolution for discovering initial peers |
| 11 | Invoices | Encode, decode, sign, verify, amount formatting, hold invoices |
| 12 | Offers | Offer encode/decode, invoice_request/invoice over onion messages, receive-side settlement, async payment offers |
| bLIP-51 | Liquidity Ads | lease_rates/request_funds/will_fund negotiation, lease fee accounting, CLTV-locked lessor to_local, advisor lease quoting |

</details>

<details>
<summary><b>Module reference (23 modules under <code>src/lightning/</code>)</b></summary>

| Module | Description |
|--------|-------------|
| `crypto/` | ChaCha20-Poly1305 AEAD, ECDH, HKDF, MuSig2 (BIP 327) for taproot channels |
| `message/` | Wire encode/decode for all channel, gossip and control messages |
| `features/` | Feature flag bitmap management (BOLT 9) |
| `transport/` | Noise_XK handshake, transport cipher, TCP/WebSocket peer connections, PeerManager |
| `keys/` | HD derivation, per-commitment secrets (shachain), signing, wallet keys |
| `script/` | Funding 2-of-2 multisig, commitment outputs, HTLC scripts, revocation, anchors, taproot scripts |
| `channel/` | Channel state machine, ChannelManager, commitment builder, actions, validation, liquidity ads |
| `chain/` | ChainMonitor, ChainWatcher, output resolver, closing tx, sweep tx, Electrum backend |
| `invoice/` | BOLT 11 encoding/decoding, bech32 words, signature verification |
| `gossip/` | NetworkGraph, Dijkstra pathfinding, gossip sync state machine, SCID encoding |
| `onion/` | Sphinx crypto, packet construction/processing, hop payloads, failures, blinded paths |
| `onion-message/` | Onion message construction/processing (carries BOLT 12 and async-payment messages) |
| `offer/` | BOLT 12 offers: encode/decode, OfferManager invoice_request/invoice flows |
| `async-payments/` | Hold invoices and AsyncPaymentManager (LSP held-forward, release_held_htlc, wake) |
| `interactive-tx/` | Interactive transaction construction for v2 dual-funded opens and splicing |
| `watchtower/` | Altruist watchtower client: wtwire protocol, justice blobs, tower sessions |
| `backup/` | Static channel backup (SCB) export/import |
| `recovery/` | Safety transition layer: atomic persistence, the durable outbound-message outbox, the opt-in hash-chained recovery journal, and the peer_storage Recovery Capsule |
| `l402/` | L402 (Lightning HTTP 402) client: challenge parsing, macaroon reading, paid credentials |
| `node/` | LightningNode orchestrator, the main protocol-layer entry point |
| `wallet/` | WalletFundingProvider, adapts the on-chain Wallet for auto-funded opens |
| `bootstrap/` | DNS seed resolution for discovering initial peers |
| `advisor/` | Liquidity, fee and channel-suggestion advisors |
| `storage/` | SQLite persistence backend, channel state serialization |
| `validation/` | Input validation shared across modules |

`beignet/lightning` re-exports each of these as a namespace (`crypto`, `message`, `node`, ...). `async-payments` and `watchtower` are reachable via their source paths.

</details>

## Tests

```bash
npm run test:lightning     # 4000+ Lightning unit tests, no infrastructure needed
npm run test:cli           # 900+ CLI + daemon unit tests, no infrastructure needed
npm run test:conformance   # 250+ official BOLT vector cases (subset of test:lightning)
npm run test:integration   # daemon/Electrum integration (needs an Electrum server)
npm run test:interop       # 190+ cases vs LND/CLN/Eclair (needs Docker)
npm run test:all           # Lightning + CLI + interop (needs Docker + Electrum)
```

Counts are floors, not snapshots. Run the suites for exact numbers.

The on-chain wallet suites live in `tests/*.test.ts` and connect to **live public
Electrum servers**, so they need network access and can fail on a server outage
rather than on your change. Each script runs `yarn build` first, so yarn has to be
installed:

```bash
npm run test:wallet        # also test:transaction, test:electrum, test:storage,
                           # test:derivation, test:receive, test:boost
npm test                   # everything: build, on-chain, Lightning, CLI, interop
```

The on-chain files without a dedicated script (multisig, PSBT, watch-only,
descriptors, signet and others) run through mocha directly:

```bash
npx mocha --exit -r ts-node/register 'tests/multisig.test.ts'
```

`test:conformance` runs the official BOLT test vectors (BOLT 1 bigsize/TLV, BOLT 3 commitments and anchors and per-commitment secrets, BOLT 4 onion/route-blinding/onion-errors, BOLT 7 extended queries, BOLT 8 transport, BOLT 11 invoices, BOLT 12 offers/signatures) under `tests/lightning/conformance/`.

<details>
<summary><b>Interop testing against real implementations</b></summary>

The interop suite drives beignet against real nodes on Bitcoin regtest.

```bash
docker compose -f docker/docker-compose.yml up -d   # wait ~30s for nodes to sync
npm run test:interop
```

Services in `docker/docker-compose.yml`:

| Service | Image | Ports |
|---------|-------|-------|
| bitcoind | Bitcoin Core 29.1 (regtest) | RPC 43782, ZMQ 28334/28335/28336 |
| lnd | `lightninglabs/lnd:v0.20.0-beta` | P2P 9735, REST 8081 |
| cln | `elementsproject/lightningd:v26.06.1` | CLNRest 3010 |
| eclair | `polarlightning/eclair:0.13.1` | HTTP API 8082 |
| electrs | `getumbrel/electrs:v0.10.10` | Electrum 60001 |

Covered per implementation: BOLT 8 handshake and BOLT 1 init/feature negotiation, disconnect/reconnect and ping/pong survival, channel open in both directions, bidirectional payments and payment_secret validation, MPP, SCID aliases, cooperative close, reestablish, gossip sync, inbound connections, anchor channels, anchor force-close with wallet-funded CPFP and HTLC-timeout fee-attach, and crash recovery. Beyond the shared matrix: taproot channel lifecycle vs LND (open, pay both directions, reestablish, coop and force close, penalty, SCB recovery), splice matrix and lease/liquidity-ads flows vs CLN, `simple_close` vs Eclair, blinded-path payments, and the watchtower client vs an LND tower.

Interop tests are excluded from `npm run test:lightning`.

</details>

## Status & limitations

Beignet is under active development. Known gaps and caveats:

| Feature | Status | Detail |
|---------|--------|--------|
| Mainnet battle-testing | Limited | Interop-tested on regtest, with some flows validated live on mainnet. Exercise caution with large balances. |
| Watchtowers | Client only (altruist) | Punishes breaches while you are offline via remote LND altruist towers. Legacy + anchor channels only: taproot channels are not backed up. No server mode. |
| LSP / LSPS protocols | Not implemented | No automated inbound liquidity via LSPS0/1/2. Liquidity ads (bLIP-51) cover negotiated leases; otherwise open channels manually. |
| Trampoline routing | Not implemented | All route computation is local. |
| BOLT 12 offers | Newer | Offers, invoice_request/invoice over onion messages and receive-side settlement work, but the surface is less battle-tested than BOLT 11. Prefer BOLT 11 in production. |
| Async payments | LSP-dependent | Hold invoices plus AsyncPaymentManager let an offline receiver be paid, but the receiver's LSP must run the held-forward/wake flow. |
| Simple taproot channels | Experimental | Full lifecycle validated against LND v0.20 on regtest, but the feature bit is still in staging upstream. Not recommended for mainnet balances. |
| Splicing / dual funding | Partial | Splice-out and splice-in validated live against CLN; v2 dual-funded opens implemented both as initiator and acceptor. CLN-initiated splices, repeat splices and multi-UTXO splice-ins are untested. |
| Mobile background | Limited | Works on React Native but has no background sync or push-notification support. |

Recommended safeguards in production:

- Cap exposure with `maxPaymentSats` and `dailySpendLimitSats`.
- Call `validatePayment()` before every send.
- Set `backupPath` for automated database backups, and keep an SCB (`beignet backup scb`).
- Pass multiple `electrumServers` for connection redundancy.
- Configure watchtowers so breaches are punished while you are offline.
- Monitor `node:error` events and the `/health` endpoint.
- Start with small channels and increase gradually.

## React Native

`react-native-tcp-socket` is a drop-in replacement for `net` and `tls`:

```json
{
  "react-native": {
    "net": "react-native-tcp-socket",
    "tls": "react-native-tcp-socket"
  }
}
```

## Documentation

| Document | Contents |
|----------|----------|
| [example/REPL_TESTING.md](example/REPL_TESTING.md) | Copy-pasteable REPL walkthrough of the full node lifecycle |
| [docs/AI_AGENT_GUIDE.md](docs/AI_AGENT_GUIDE.md) | Deployment, monitoring, safety rails, HTTP daemon patterns |
| [src/lightning/README.md](src/lightning/README.md) | Protocol-layer reference and usage guide |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Feature roadmap and progress |
| [docs/RECOVERY-PROTOCOL.md](docs/RECOVERY-PROTOCOL.md) | Proposed replicated state-continuity design |
| [API reference](docs/markdown/classes/Wallet.md) | Generated typedoc ([HTML](docs/html/classes/Wallet.html)) |

## Support

Open an issue, or reach out on [Telegram](https://t.me/bitkitchat).

## License

MIT
