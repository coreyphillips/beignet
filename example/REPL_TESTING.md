# Beignet Lightning REPL — Testing Walkthrough

Copy-paste sequences for exercising a live `BeignetNode` from the REPL.

Start the node:

```bash
npm run example:lightning -- "<YOUR MNEMONIC>" mainnet --alias "Beignet Lightning"
```

Inside the REPL the node is bound to `node`. Type `help()` for the full command list.
`await` works at the REPL top level, so async calls can be pasted directly.

> Tip: every command below assumes the `beignet>` prompt. Anything returning a
> Promise is shown with `await`.

---

## 0. Sanity check the node

```js
node.getInfo()                 // nodeId, network, alias, peer/channel counts
node.getHealth()               // ok | degraded + reasons
node.getBalance()              // on-chain + lightning balances
node.isReady()
await node.waitForReady(15000) // resolves once peers/channels are restored
```

---

## 1. Fund the on-chain wallet

```js
await node.getNewAddress()     // send BTC here, then wait for confirmations
await node.refreshWallet()     // resync after sending funds
node.getBalance()              // confirm onchain balance shows up
```

To move funds back out, send a specific amount or sweep the whole balance:

```js
await node.sendOnchain('<address>', 50000)   // 50k sats, normal fee rate
await node.sendMaxOnchain('<address>')       // sweep everything, minus the fee
await node.sendMaxOnchain('<address>', 5)    // sweep at 5 sats/vB
```

---

## 2. Connect to a peer

```js
// Synonym/Blocktank node (example — swap in your own target):
await node.connectPeer(
  '028a8910b0048630d4eb17af25668cdd7ea6f2d8ae20956e7a06e2ae46ebcb69fc',
  '34.65.86.104',
  9400,
);
node.listPeers();
```

Or discover peers automatically:

```js
await node.bootstrapPeers();   // DNS-seed discovery
await node.connectToSeeds(3);  // connect to a few seed peers
```

---

## 3. Open a channel (auto-funded from the wallet)

```js
const peer = '028a8910b0048630d4eb17af25668cdd7ea6f2d8ae20956e7a06e2ae46ebcb69fc';

// Fire-and-forget open:
node.openChannel(peer, 200000, 0);   // 200k sat channel, 0 pushed

// Or open and block until it's NORMAL:
const ch = await node.openChannelAndWait(peer, 200000, { timeoutMs: 120000 });

// Or do connect + open in one step:
await node.connectAndOpenChannel(peer, '34.65.86.104', 9400, 200000);

node.listChannels();
node.getReadyChannels();             // channels usable for routing
```

Watch progress:

```js
node.getChannel(ch.channelId);
node.getChannelHealth(ch.channelId);
node.getChannelDiagnostics(ch.channelId);   // why isn't it routing / announced?
```

---

## 4. Receive a payment (create an invoice)

```js
const inv = node.createInvoice(1000, 'Beignets First Invoice');
inv.bolt11;                      // give this to the payer
inv.paymentHash;

node.canReceive(1000);           // do you have inbound liquidity?
node.listInvoices();
node.getInvoice(inv.paymentHash);
```

When paid, the `payment:received` event fires (printed automatically).

---

## 5. Send a payment (pay an invoice)

```js
const bolt11 = '<invoice from another node>';

node.decodeInvoice(bolt11);      // inspect amount/description/routingHints
node.validatePayment(bolt11);    // pre-flight: amount/expiry sanity
node.canSend(1000);              // outbound capacity check
node.estimateRouteFee(bolt11);   // expected fee
node.estimatePayment(bolt11);    // success probability

// Pay (throws on failure):
const p = await node.payInvoice(bolt11);
p.status;                        // SUCCEEDED / FAILED

// Or the variants:
await node.payInvoiceSafe(bolt11);                                  // never throws
await node.payInvoiceWithRetry(bolt11, { maxRetries: 3, backoffMs: 2000, maxFeeSats: 10 });
node.sendPaymentAsync(bolt11);                                      // returns paymentHash immediately
```

Inspect afterward:

```js
node.listPayments();
node.getPayment(p.paymentHash);
node.getPaymentProof(p.paymentHash);     // preimage proof bundle
node.verifyPaymentProof(p.paymentHash);
```

---

## 6. Keysend (spontaneous, no invoice)

```js
const dest = '02e9a5bc151bed9314f10d02772413cc3e96168cb4320f992bfa483865133dc28d';
await node.sendKeysend(dest, 500);
await node.sendKeysendSafe(dest, 500);   // never throws
```

---

## 7. BOLT 12 offers

```js
const offer = node.createOffer({ description: 'Tips jar', amountSats: 1000, issuer: 'beignet' });
offer.encoded;                   // share this lno1... string

node.decodeOfferString(offer.encoded);
node.listOffers();

// Paying an offer (fetches an invoice via the offer flow):
await node.payOffer('<lno1...>', 1000);
```

---

## 8. Splicing (resize a live channel)

```js
const id = node.listChannels()[0].channelId;
node.spliceIn(id, 50000, 253);   // add 50k sats (feeratePerKw = 253)
node.spliceOut(id, 50000, 253);  // remove 50k sats
```

---

## 9. Liquidity, fees & ops

```js
node.getLiquiditySnapshot();
node.getFeeSnapshot();
node.getChannelSuggestions(5);   // who to open channels with
node.getStats();                 // payment success rate, volumes
node.getMetrics();               // Prometheus text format
node.getMainnetReadiness();      // weighted go-live checklist
node.getDailySpendInfo();
node.setDraining(true);          // stop accepting new HTLCs before maintenance
```

---

## 10. Close a channel

```js
const id = node.listChannels()[0].channelId;

await node.closeChannel(id);         // cooperative
await node.forceCloseChannel(id);    // unilateral (only if peer is unresponsive)
```

---

## 11. Backup & shutdown

```js
await node.backup('example/lightningData/backup.db');
node.getMnemonic();                  // recovery phrase

await node.gracefulShutdown();       // flush channels/payments, then stop
// or just type:
.exit
```

---

## Full end-to-end smoke test (single paste)

Run against two nodes (e.g. regtest). On node B create an invoice; on node A:

```js
const peerId   = '<node B pubkey>';
const peerHost = '127.0.0.1';
const peerPort = 9735;
const amount   = 1000;

// 1. connect + open + wait
const ch = await node.connectAndOpenChannel(peerId, peerHost, peerPort, 200000);
await node.waitForChannelReady(ch.channelId, 120000);
console.log('channel ready:', node.getChannel(ch.channelId).state);

// 2. pay an invoice created on node B
const bolt11 = '<paste invoice from node B>';
console.log('can send:', node.canSend(amount).canSend);
const p = await node.payInvoice(bolt11);
console.log('payment:', p.status, node.getPaymentProof(p.paymentHash)?.preimage);

// 3. close
await node.closeChannel(ch.channelId);
console.log('closing:', node.getChannel(ch.channelId)?.state);
```
