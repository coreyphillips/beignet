# Direct-funding payer SDK

A TypeScript SDK for paying Beignet `bgnq` requests from a wallet that can sign Bitcoin transactions. The wallet retains its spending keys. The SDK handles request verification, negotiation, transaction checks, signing requests, durable payment records and receipts.

This is an initial Node.js implementation of the existing revision 2 direct-funding protocol and version 3 request envelope. It includes a generic PSBT signer, a Bitcoin Core wallet adapter, and an outbound BOLT 8 peer client that needs no Lightning channels. It is not a way to add support to an unmodified send-only wallet.

## Build and install

From the repository root, with its dependencies installed:

```sh
npm run build:direct-funding
npm pack ./packages/direct-funding
```

The result is `beignet-direct-funding-0.1.0.tgz`. Install that tarball in another project:

```sh
npm install /absolute/path/to/beignet-direct-funding-0.1.0.tgz
```

The standalone package does not depend on `beignet` or load its wallet, channel manager, receiver engine or daemon. Its protocol sources are compiled from the shared implementation so fixes do not diverge. Rebuilding from source requires this repository. The packed runtime and declarations work independently. The package has not been published to npm.

The same SDK is available from `beignet/direct-funding` and `beignet/direct-funding/node` when building this checkout. The Node.js version requirement matches the parent project's package manifest. Browser, React Native, Rust and WASM builds are not qualified in this release.

## Bitcoin Core integration

Use Bitcoin Core 24 or newer with a descriptor wallet holding native SegWit or Taproot coins. Core 26 has been exercised on regtest. Supply a wallet-scoped RPC function from your application; this keeps credentials, endpoint selection, transport security and request timeouts under your application's control. Preserve RPC error codes, including `-5` for a missing transaction. Do not return only error strings.

```ts
import {
  BitcoinCoreWalletAdapter,
  DirectFundingClient,
  Network,
  createPeerTransportRegistry
} from '@beignet/direct-funding';
import {
  FileDirectFundingStorage,
  NodePeerMessaging
} from '@beignet/direct-funding/node';

// rpc(method, params) is your existing wallet-scoped JSON-RPC function.
const network = Network.REGTEST;
const storage = new FileDirectFundingStorage('/path/to/this-wallet/direct-funding');
const wallet = await BitcoinCoreWalletAdapter.create({ rpc, network, storage });
const peers = new NodePeerMessaging({ network });
const registry = createPeerTransportRegistry(peers);
const client = new DirectFundingClient({ wallet, registry, storage, network });

// Inspect without connecting or signing, then obtain approval in your UI.
const request = client.inspect(scannedRequest);
const amountSat = request.envelope.amountSat ?? request.uriAmountSat;
const maxTotalFeeSat = 1_000n;
await obtainPaymentApproval({ request, amountSat, maxTotalFeeSat });

const result = await client.pay(scannedRequest, { maxTotalFeeSat });
// If no amount is present, also supply an explicitly approved amountSat.
console.log(result.status, result.fundingTxid);

// On startup and periodically while payments are pending:
await client.reconcile();
console.log(client.payments());

// At application shutdown, after payment/reconciliation calls have settled:
await wallet.waitForIdle();
registry.destroy();
peers.close();
storage.close();
```

The repository's `example/direct-funding.ts` shows approval and cleanup in a host application. Mainnet use must use `Network.MAINNET` throughout. The SDK checks wallet/client network agreement, Core's actual chain, and the request's signed chain hash.

Core signing happens through `walletprocesspsbt`, with finalization disabled. The adapter neither unlocks encrypted wallets nor broadcasts transactions. The receiver broadcasts the completed funding transaction. The protocol requires access to previous transactions, including other contributors' inputs. Core may need `txindex=1`, an appropriate block-aware lookup, or a different wallet adapter for those lookups.

## Adapting another wallet

Implement `IDirectFundingWallet`, including its explicit `network`. The underlying operations are defined by `IDfSenderWallet`: list/find coins, fetch raw previous transactions, produce a change script, identify wallet-owned outpoints, reserve/release coins, and report chain height and transaction status. If the wallet API is asynchronous, `refresh(fundingTxids)` should atomically populate the synchronous view. The SDK calls it before new payments and reconciliation.

Use `createPsbtCoinSigner(coin, options)` to implement `signerFor`. Its callbacks are:

```ts
const signer = createPsbtCoinSigner(coin, {
  getTransaction: txid => walletBackend.fetchRawTransaction(txid),
  signPsbt: (base64, { inputIndex, purpose }) =>
    walletBackend.signPsbt(base64, { inputIndex, purpose, broadcast: false })
});
```

The backend must sign only the selected input and return a PSBT without broadcasting it. An optional `decoratePsbt(psbt, context)` callback can add derivation paths or hardware-wallet metadata. The signer checks transaction and previous-output immutability, restricts sighash modes, and verifies the resulting signature against the original transaction before returning a witness. Partial signatures and finalized input witnesses are supported.

Ownership is proved with a non-broadcastable transaction containing an artificial second input. This is the protocol's custom proof, not BIP 322. A hardware wallet may refuse that shape. Generic PSBT support does not establish device compatibility. The lower-level `IDfCoinSigner` also supports the protocol's signed-message and raw-digest alternatives.

## Transport

`NodePeerMessaging` provides authenticated outbound TCP/Noise connections, init, ping/pong and direct-funding custom messages. Its default random identity is a transport identity, never a spending key. Supply a dedicated stable identity if the receiver pairs or recognizes the payer across restarts. The connection count and connection deadlines are bounded, and `close()` stops connections and reconnect timers.

`createPeerTransportRegistry(peers)` registers direct-peer and LSP relay lanes. You can instead supply another `IDfPeerMessaging` implementation or register a custom lane in `DfTransportRegistry`.

The initial standalone package does not include an onion-message engine. The existing registry can use a request's introduction node as an LSP relay when that node supports the relay protocol and is connected to the receiver. This does not make every onion-only request reachable. A `.onion` hostname needs a SOCKS/Tor-capable `createSocket` callback; ordinary Node TCP does not resolve it. Receiver and liquidity-peer protocol support are still required.

## Payment lifecycle and storage

Use exactly one SDK client and one reservation manager per wallet/storage scope. Storage must not be shared between networks or different wallets. `saveWalletData` must finish durably before returning and throw on failure. Promise-returning writes are rejected. `FileDirectFundingStorage` uses private files, atomic replacement and fsync, and refuses a second writer.

Payment state and the funding witness are persisted before the witness is emitted. The SDK refuses corrupt payment journals rather than silently starting with no history. Keep the storage directory through upgrades and restarts. Back up payment state and wallet reservation state together. This file store is plaintext; choose an encrypted host store or encrypted disk when required.

After a process crash, the file store intentionally leaves `.writer-lock` in place. Verify the previous process is stopped before removing that stale lock directory. Never remove a live writer's lock. Then reopen the same storage, call `reconcile()`, and retry the same request if needed. A request id already associated with another receiver or receipt is rejected.

| Status | Meaning |
| --- | --- |
| `CREATED`, `OFFERED` | No funding witness has been committed yet. |
| `SIGNED_PENDING` | A spendable signature may be out. The payment is unresolved. |
| `MEMPOOL_SEEN` | The wallet sees the funding transaction in its chain view. |
| `CONFIRMED` | The funding transaction has confirmed. |
| `ABORTED` | The attempt ended before releasing its funding witness. |
| `FAILED` | A conflicting spend confirmed. |

A missing receipt, absent mempool transaction or network timeout after signing is not permission to pay again. `pay()` returns the stored outcome for a signed retry. Use `{ recoverReceipt: true }` to request receipt replay when needed. Never automatically send to the URI's fallback address after an exception. Inspect the payment journal and resolve the existing attempt first. This SDK never initiates a fallback payment.

Core reservations use persistent `lockunspent`. They prevent Core's automatic coin selection from spending an offered coin. Core permits manual selection to bypass locks, so your application must not manually spend or unlock reserved coins. Other reservation managers must not race this adapter. If a lock RPC outcome is ambiguous, `wallet.unresolvedReservations()` exposes the quarantined outpoint for operator reconciliation; the adapter does not claim or unlock a lock it cannot prove it owns.

## Current limits

- One payer input, large enough for the amount plus the entire configured fee ceiling.
- P2WPKH and P2TR key-path spending only. No legacy input, nested SegWit, arbitrary multisig or Taproot script-path wallet adapter.
- Confirmations and receipt delivery are distinct. Zero-confirmation use depends on receiver policy and pairing.
- The Bitcoin Core adapter currently refreshes wallet history conservatively. Large-wallet incremental history caching is future work.
- Real hardware devices and additional wallet backends need independent conformance testing.

## Validation

From the repository root:

```sh
npm run test:direct-funding
npm run tsc:check
npm run tsc:check:tests
npm run build:direct-funding
```

The package test builds and packs the SDK, imports it from an isolated directory with only its declared dependencies, and typechecks a standalone consumer. Signing tests cover both input kinds, hostile PSBT mutations, invalid signatures, sighash changes and ownership probes. Client tests cover duplicate payment calls, storage failures, network checks, receipt timeouts, restart replay and confirmation tracking.

To exercise real Bitcoin Core signing and settlement with the locally available `btcpayserver/bitcoin:26.0` Docker image:

```sh
npm run test:direct-funding:regtest
```

This opt-in script creates its own offline, disposable container with no host mounts or published ports. It funds both coin types, verifies ownership proofs, exchanges messages over real TCP/BOLT 8 using the SDK's peer client, signs and broadcasts funding transactions, mines confirmations, and checks restart replay without another spend. It removes its container and temporary data afterwards. Receiver channel negotiation is scripted: this qualification does not establish a real Lightning channel or qualify a hardware device.
