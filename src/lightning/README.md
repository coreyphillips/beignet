# Beignet Lightning Module

A pure-TypeScript Lightning Network implementation covering BOLTs 1-5 and 7-12, plus bLIP-51 liquidity ads. Built on `bitcoinjs-lib` for Node.js.

This is the protocol layer. For the higher-level, satoshi-denominated API (`BeignetNode`), the HTTP daemon, and the project's current limitations, see the [root README](../../README.md).

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
├── transport/       BOLT 8 Noise handshake, encrypted Peer, PeerManager, WebSocket
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
├── watchtower/      Altruist watchtower client (LND wtwire, justice blobs)
├── backup/          Static channel backup (SCB) export/import
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
 ├── PeerManager (optional) ─── Peer ─── TCP/WebSocket + BOLT 8 encryption
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
 ├── AsyncPaymentManager ─── hold invoices, held-forward, wake
 ├── WatchtowerClient (optional) ─── justice kits per revocation
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

- Node.js 18+ with the `crypto` module
- `bitcoinjs-lib` with `@bitcoinerlab/secp256k1`
- `bech32` (BOLT 11 invoices), `better-sqlite3` (storage backend)

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

`network` is the `Network` enum (`Network.MAINNET` = `'bc'`, `TESTNET` = `'tb'`, `REGTEST` = `'bcrt'`, `SIGNET` = `'tbs'`), not a bare string.

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
  it wants and a random nonce; the LSP answers with
  `ASYNC_REGISTRATION_REPLY` (1111): a signed grant, or a refusal echoing the
  nonce. One ACTIVE registration per (receiver, channel): a renewal supersedes
  the previous one. Registrations are durable ledger rows under their own
  prefix (`async_registration`), so a restart keeps them; the receiver
  persists its grants under the `async_receive_grants` metadata key and
  re-verifies them on load.
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
    restart with it), and no outcome returns it. When the credit cannot cover
    another part, admission refuses. This is what prices an abandoned hold:
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

// With routing hints (for invoices with private channels):
const hinted = gsp.findRoute(graph, source, destination, amountMsat, finalCltv,
  undefined, undefined, undefined, undefined, decoded.routingHints);
// Routing hints inject synthetic edges for private channels not in the gossip graph
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
resolves a deferred announcement before handing out addresses. Set
`eagerGossipVerify: true` on relay-class nodes to verify everything at intake
as before; eager mode also re-requests signatureless RGS-primed entries from
peers so their signed copies become servable. Stored rows that predate the
provenance flags are resolved at restore: eager mode verifies the canonical
re-encoding (failing safe to unverified), lazy mode marks them deferred and
lets the point of consumption decide.

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

| Event | Arguments | Description |
|-------|-----------|-------------|
| `payment:received` | `(payment: IPaymentInfo)` | Incoming HTLC fulfilled |
| `payment:sent` | `(payment: IPaymentInfo)` | Outgoing payment completed |
| `payment:failed` | `(payment: IPaymentInfo)` | Outgoing payment failed |
| `preimage:learned` | `(paymentHash: Buffer, preimage: Buffer)` | Preimage recorded (forwarding/settlement chokepoint) |
| `invoice:settled` | `({ paymentHash, bolt11, amountMsat })` | Invoice we issued was settled |
| `channel:opening` | `({ channelId, fundingTxid })` | Funding flow started |
| `channel:ready` | `({ channelId })` | Channel reached NORMAL state |
| `channel:closed` | `({ channelId })` | Channel closed |
| `channel:resolved` | `({ channelId })` | All on-chain outputs resolved |
| `channel:aborted` | `(temporaryChannelId: Buffer, reason: string)` | Open aborted before funding |
| `channel:voided` | `({ channelId })` | Unfunded/abandoned channel discarded |
| `splice:complete` | `({ channelId, fundingTxid })` | splice_locked exchanged both ways |
| `announcement:ready` | `(channelId: Buffer)` | Channel eligible for announcement |
| `message:outbound` | `(peerPubkey: string, type: number, payload: Buffer)` | Message to send to peer |
| `htlc:forwarded` | `({ inChannelId, outChannelId, amountInMsat, amountOutMsat, feeMsat })` | HTLC relayed to the next hop |
| `htlc:fulfilled` | `({ channelId, htlcId })` | Forwarded HTLC fulfilled |
| `htlc:failed` | `({ channelId, htlcId })` | Forwarded HTLC failed |
| `htlc:held` | `({ paymentHash, amountMsat })` | HTLC parked by a hold invoice |
| `sweep:uneconomic` | `(channelId: Buffer, action: ISweepUneconomicChainAction)` | An on-chain claim was declined because it cannot pay its own fee (`reason: 'skipped'`), or a competing spend path opened while it stayed unclaimed (`reason: 'contested'`). Retries continue in both cases, until the outpoint is spent |
| `peer:connect` | `(pubkey: string)` | Peer connected (networking mode) |
| `peer:disconnect` | `(pubkey: string)` | Peer disconnected (networking mode) |
| `peer:disconnect-requested` | `(pubkey: string)` | The node needs this peer's connection severed but holds no socket for it (event-transport mode, or an unconnected peer): the HOST must close its transport. The protocol side (channels marked for reestablish) is already applied; reconnect and reestablish as usual |
| `peer:error` | `(pubkey: string, error: Error)` | Peer error (networking mode) |
| `broadcast:tx` | `(tx: Buffer)` | Transaction to broadcast on-chain |
| `onion:received` | `(payload: IOnionMessagePayload)` | Onion message received (type 513) |
| `offer:created` | `(offer: IOffer)` | BOLT 12 offer created |
| `bolt12:invoice:received` | `(invoice: IBolt12Invoice)` | BOLT 12 invoice received |
| `bolt12:invoice:issued` | `(invoice: IBolt12Invoice)` | BOLT 12 invoice issued to a payer |
| `log` | `(entry: IStructuredLog)` | Structured action log entry |
| `node:error` | `(error: ILightningError)` | Operational error (non-fatal) |
| `node:ready` | `()` | Node fully operational (peers reconnected, channels restored) |

Channel-scoped events carry an **object**, not a bare id: `node.on('channel:ready', ({ channelId }) => ...)`, where `channelId` is a 32-byte Buffer. `announcement:ready` is the exception and passes the Buffer directly. `BeignetNode` normalizes all of these to hex strings.

`LightningNode` reports operational problems through `node:error` and never emits the bare `'error'` event. `ChannelManager` does emit `'error'` as `(channelId: Buffer | null, error: string)`, so code that drives a `ChannelManager` directly (most unit tests) should attach a listener, even a noop, to avoid unhandled-error throws.

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

23 modules. Per-module file counts are deliberately omitted here: they went stale
faster than anything else in this document. Use `ls src/lightning/<module>` instead.

| Module | Key Exports | BOLT |
|--------|-------------|------|
| `bootstrap` | `bootstrapPeers`, `resolveDnsSeed`, `DEFAULT_DNS_SEEDS` | 10 |
| `crypto` | `chacha20poly1305`, `ecdh`, `hkdf`, MuSig2 (BIP 327) | 8, 3 |
| `message` | Message encode/decode for all types, `codec`, `tlv`, `stfu`, interactive-tx, dual-funding, splice | 1, 2 |
| `features` | `FeatureFlags` | 9 |
| `transport` | `Peer`, `PeerManager`, `CipherState`, `NoiseState`, WebSocket transport, wire capture | 8 |
| `keys` | `derivation`, `shachain`, `signer`, `wallet-keys` | 3 |
| `script` | `funding`, `commitment`, `htlc`, `revocation`, `anchor`, taproot commitment/HTLC | 3 |
| `channel` | `Channel`, `ChannelManager`, `CommitmentBuilder`, `ZeroConfManager`, `QuiescenceManager`, `DualFundingSession`, `SpliceSession`, liquidity ads | 2, bLIP-51 |
| `interactive-tx` | `InteractiveTxBuilder`, serial ID validation | 2 |
| `chain` | `ChainMonitor`, `OutputResolver`, `ChainWatcher`, `closing`, `sweep` | 5 |
| `invoice` | `encode`, `decode`, `amount`, `signing`, `words`, `Network` | 11 |
| `gossip` | `NetworkGraph`, `findRoute`, `GossipSyncManager`, `messages`, `validation` | 7 |
| `onion` | `constructOnionPacket`, `processOnionPacket`, `failures`, `constructBlindedPath`, `processBlindedHop` | 4 |
| `onion-message` | `OnionMessageManager`, `constructSimpleOnionMessage`, `processOnionMessage` | 4 |
| `offer` | `OfferManager`, `encodeOffer`, `decodeOffer`, TLV, Schnorr, merkle | 12 |
| `async-payments` | `AsyncPaymentManager`, `HeldForwardLedger`, release capability (held forward, notice, release, wake) | 4, 11 |
| `watchtower` | `WatchtowerClient`, `wtwire`, justice blob, tower connection | -- |
| `backup` | Static channel backup (SCB) encode/decode | -- |
| `node` | `LightningNode`, `INodeConfig`, rate limiter | -- |
| `storage` | `SqliteStorage`, `IStorageBackend`, `serialization` | -- |
| `wallet` | `WalletFundingProvider`, `IFundingProvider` | -- |
| `advisor` | `LiquidityAdvisor`, `FeeAdvisor`, `ChannelSuggestions`, rebalance/fee executors | -- |
| `validation` | Input validation utilities | -- |

`async-payments` and `watchtower` are not yet re-exported as namespaces from `beignet/lightning`; import them from their source paths. Everything else is on the barrel.

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

| Suite | Cases | Notes |
|-------|-------|-------|
| `test:lightning` | 4000+ | No infrastructure required |
| `test:conformance` | 250+ | Official BOLT vectors, included in the count above |
| `test:chaos` | 30 | Recovery kill matrices, split out of `test:lightning` |
| `test:interop` | 190+ | Live LND/CLN/Eclair on regtest, Docker required |

Counts are floors, not snapshots. Run the suites for exact numbers.

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
