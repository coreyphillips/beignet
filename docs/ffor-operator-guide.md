# FFOR Operator Guide

How to run and use FFOR (Fast-Forward Offline Receive) with a beignet node: hosting a
tower, receiving payments while offline, and the operational rules that keep it safe.

This guide is about operating the implementation. For the protocol itself, see the
[FFOR spec](https://github.com/coreyphillips/ffor).

## What FFOR gives you

FFOR lets a recipient `R` receive Lightning payments that fully settle for the payer
**while `R` is offline**, without giving custody to anyone. A payment arrives at `R`'s
channel peer (the settlement peer `S`), `S` settles it upstream immediately (the payer
sees an ordinary completed payment), and `R` is credited inside the `S`-`R` channel via
a signed voucher it can claim on return.

There are two trust variants:

- **Variant A** (self-contained): `S` holds the preimage. `S` can settle upstream and
  then withhold `R`'s credit; this is possible, bounded by the epoch budget, and always
  leaves a cryptographic fraud proof. Use it only between parties you already trust: your
  own second node, or a bonded/reputable peer.
- **Variant B** (recommended, tower-mediated): a tower `T` chosen by `R` gates the
  preimage. `S` cannot obtain the preimage to settle upstream until `T` holds a verified
  voucher crediting `R`. Theft then requires `S` and `T` to collude, and `R` picked both.
  This is the variant the operator tooling targets.

The tower holds **no funds**. In the default alert-only mode it holds **no keys**. It is
the same class of trust as an ordinary Lightning watchtower, now also covering receipt.

## Roles

A single FFOR flow involves up to four parties:

- **Payer `P`** — an ordinary Lightning node. Needs no FFOR support.
- **Settlement peer `S`** — `R`'s channel peer / last hop. Must support FFOR. Settles the
  payment on `R`'s behalf and credits `R`.
- **Recipient `R`** — goes offline, receives via vouchers.
- **Tower `T`** (Variant B) — an always-online agent chosen by `R` that gates preimage
  release and, optionally, watches the chain for breaches.

Only `R` and its chosen `S` (and, for Variant B, `T`) need to run FFOR. The payer and all
routing nodes stay completely stock.

## Running a tower

A beignet node can double as a tower. The tower logic is decoupled from the channel
machinery, so hosting one alongside normal node operation is a supported configuration.

```
npm run example:lightning -- --tower \
  --tower-store ~/.beignet/tower.db \
  --tower-addr your.host:9735 \
  --alias my-tower
```

- `--tower` enables an embedded durable tower and auto-advertises default Variant-B
  service terms in the node's `node_announcement` (so recipients can discover it, below).
- `--tower-store <path>` sets the tower database file. Defaults to `tower.db` in the
  node's data directory, a separate file from `node.db`.
- `--tower-addr <host:port>` sets the dial address advertised for the tower, so a
  discovered tower is reachable at `nodeId@host:port`.

Give recipients your `nodeId@host:port`, or let them find you through gossip.

Programmatic equivalent (the CLI is a thin wrapper over this):

```ts
node.enableTower(new SqliteTowerStore('/path/tower.db'), {
  terms: { variants: 0b10 /* B */, maxBudgetMsat: 100_000_000n, maxEpochBlocks: 4032,
           towerFeeBaseMsat: 1000, towerFeePpm: 0 },
  address: { host: 'your.host', port: 9735 },
});
node.towerStatus(); // { enabled, epochs:[{epochId,lastReleased,maxPayments}], alerts, usingTower }
```

### The durability requirement (do not skip)

A tower that releases a preimage **must** have already durably stored the voucher package
behind it. A tower that forgets a released package on restart is exactly the fund-loss the
protocol forbids. Therefore:

- `--tower` refuses to start on a non-durable (in-memory) store. It requires a file-backed
  `SqliteTowerStore`, which commits with `synchronous = FULL` so each write is
  fsync-durable before the preimage is released.
- `--tower-demo` explicitly permits an in-memory tower for demos and prints a loud
  `WARNING: NON-DURABLE` banner. Never run a real tower with it.

On restart the tower rehydrates every provisioned epoch from its store and resumes serving
with no involvement from the (offline) recipient: it keeps serving released preimages,
rejects a differing package for an already-released sequence, and can verify and release
the next one.

## Receiving offline via a tower

As a recipient, point your node at a tower, start an offline-receive epoch (which
provisions the tower up front, while you are online), hand out the invoices, and go
offline. On return, recover.

```
npm run example:lightning -- --use-tower <towerNodeIdHex@host:port> --alias my-wallet
```

Then, in the REPL:

```ts
// 1. Start the epoch. This provisions the tower NOW, over BOLT-8, while online.
const { epochId, invoices } = await node.startOfflineReceiveEpoch({
  peerPubkey: '<settlement peer pubkey>',   // or channelId
  budgetMsat: 100_000_000n,                 // total credit you can receive this epoch
  maxPayments: 8,                           // K single-use invoices
  minPaymentMsat: 1_000_000n,
  settlementDeadline: D,                    // absolute height; no settlements after
  voucherExpiry: T_exp,                     // absolute height; vouchers revert to S after
});

// 2. Hand out `invoices` (single-use, amountless). Then disconnect / go offline.

// 3. On return:
await node.recoverFromTower(channelId);     // fetch + ingest the settled vouchers
node.towerStatus();                          // shows progress
```

If you do not want to hand-configure a URI, discover a tower from gossip instead:

```ts
const towers = node.findTowers({ variant: 0b10 /* B */, minBudgetMsat: 100_000_000n });
node.useDiscoveredTower(towers[0].nodeId.toString('hex')); // resolves address from the graph
// ...then startOfflineReceiveEpoch as above.
```

### Provisioning is up front, not on crash

`startOfflineReceiveEpoch` provisions the tower immediately, while you are online, before
you go offline. There is no "flush to the tower when the node crashes" step and none is
needed: the tower is given the static verification data ahead of time and handles each
payment on its own while you sleep. If your node crashes mid-epoch, that is a non-event
for the tower, because it was never depending on live input from you.

## Running a settlement peer

If your node has channels to recipients who use FFOR, it can act as their settlement peer
with no manual tower setup. When a recipient starts a Variant-B epoch and names its tower
in the opening handshake, your node automatically connects to that tower and uses it to
release preimages during settlement. You only need to keep the channel funded (that
balance is the recipient's inbound receive budget) and stay online for the epoch.

## The rules that keep it safe

These are not optional niceties; each one closes a specific fund-safety or liveness hole.

1. **A tower must not be the settlement peer for the same recipient.** If one node is both
   `S` and `T`, it can settle upstream and withhold the credit alone, which voids
   Variant B's entire guarantee. The node enforces this: it refuses to provision a tower
   epoch whose settlement peer is itself. When you offer tower service, you are serving
   recipients whose channel peer is somebody else.

2. **A node cannot be its own tower.** When you go offline, your co-hosted tower goes down
   with you. Your tower must be a separate, always-on box. The common shapes are: an
   always-on home node acting as tower for your own mobile wallet (whose channel is to an
   external LSP), or a public tower serving strangers.

3. **A tower must stay online for the epochs it serves.** If your tower is down when a
   payment arrives, the settlement peer cannot get the preimage and the payment fails
   upstream. This is a liveness impact on the recipient, not a fund loss, but it is a
   service-level commitment. Treat a public tower like any always-on service: supervise
   it, monitor it, keep the store on durable disk.

4. **The store is sensitive.** It holds preimages and, if you opted into scoped-key
   breach response, a scoped revocation key and sweep script. It holds no funds, but treat
   the database with the same care as the node's own key material. (At-rest encryption of
   the tower store is a planned follow-up, not yet implemented.)

5. **Privacy.** A tower sees the payment hashes, amounts, and offline schedule of the
   recipients it serves. Recipients should choose a tower they are comfortable revealing
   that to, ideally their own.

## Breach response

A node-embedded tower watches each provisioned epoch's funding outpoint on its own chain
feed. If the settlement peer broadcasts a revoked state:

- **Alert-only (default):** the tower emits a `ffor:tower:breach` event so the operator or
  recipient can react. No keys are held.
- **Scoped-key (option a):** if the recipient provisioned a scoped revocation key and a
  sweep script, the tower builds and broadcasts the justice transaction itself, sweeping
  the cheater's balance to the recipient's mandated address. This is the standard
  watchtower trust trade: a malicious tower could redirect only penalty funds, and only if
  the settlement peer also cheated (a double failure).

These watches re-arm automatically on tower restart.

## Quick reference

CLI flags:

| Flag | Role | Meaning |
|---|---|---|
| `--tower` | tower | Host a durable embedded tower; auto-advertise service |
| `--tower-store <path>` | tower | Tower database file (default `<datadir>/tower.db`) |
| `--tower-addr <host:port>` | tower | Advertised dial address |
| `--tower-demo` | tower | Allow a non-durable in-memory tower (demos only, loud warning) |
| `--use-tower <nodeId@host:port>` | recipient | Default tower for this node's epochs |

Node API:

| Method | Role | Purpose |
|---|---|---|
| `enableTower(store, opts?)` | tower | Embed a tower, optionally advertise terms + address |
| `towerStatus()` | tower | Provisioned epochs, released counts, breach/escape alerts |
| `findTowers(filter?)` | recipient | Discover advertised towers from the gossip graph |
| `useTower(uri)` / `useDiscoveredTower(nodeId)` | recipient | Select a tower by URI or from the graph |
| `startOfflineReceiveEpoch(opts)` | recipient | Provision the tower + start a Variant-B epoch; returns invoices |
| `recoverFromTower(channelId)` | recipient | On return, fetch and ingest the settled vouchers |

Wire numbers (provisional, pending bLIP assignment): `node_announcement` TLV 55007
(settlement terms), 55043 (tower service advertisement); tower transport messages
55031-55041; feature bits 560/561.
