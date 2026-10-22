# API conventions

The rules for new public API, and the old names they replaced. Existing internals keep their names. A public name changes only behind a deprecated wrapper, which stays for at least one minor release and goes in the next major.

`tests/api-snapshot/` records every exported name and signature, one file per entry point, and CI fails when the build no longer matches it. It also records the declarations those signatures use that no entry point exports, such as a base class, marked `unexported`. A type in a signature is written as its entry point exports it, such as `offer.IFallbackAddress`. A type only another entry point exports is written with that entry point in front, as in `beignet#Wallet`. A type from a dependency is written with its package in front, as in `bitcoinjs-lib#Transaction`. A change that means to alter the public API regenerates it with `npm run api:snapshot`, and the diff is reviewed with the change: outside a major release it should only add lines. `tests/api-snapshot/deprecated.txt` lists every declaration tagged `@deprecated`, which is what the next major removes.

## Rules for new code

**Type prefixes.** Interfaces take `I` (`IOutpoint`). Type aliases and enums take no prefix. Most of the code already follows this; older types that do not (the `E` and `T` prefixes of the on-chain types, the unprefixed `BeignetNode` types) keep their names.

**Verbs say where the answer comes from.**

| Prefix | Meaning |
|--------|---------|
| `get*`, `list*` | Reads memory or storage, never the network. `list*` returns a collection. |
| `fetch*` | Asks the network and returns its answer. |
| `refresh*` | Asks the network and stores what it learns, for `get*` and `list*` to read. |

**Parameters.** A function that takes more than three parameters takes an options object instead. A required argument or two followed by an optional options object is fine: `openChannel(pubkey, amountSats, opts)`.

**Outpoints.** An outpoint is `{ txid, vout }` (`IOutpoint`), with the txid in display order. Stored UTXO records keep Electrum's `tx_hash` and `tx_pos`.

**Bytes.** A parameter that takes bytes is typed `Uint8Array`, which a `Buffer` already is. Returns stay `Buffer` until the major release that moves to bitcoinjs-lib 7, because changing a return type breaks callers and widening a parameter does not.

**Crypto.** Under `src/lightning`, hashing, HMAC, HKDF, the AEADs and randomness go through `crypto/provider.ts`, not Node's `crypto`, so a host without Node's `crypto` can supply its own with `setCryptoProvider`. `tests/lightning/crypto-provider.test.ts` lists the few files allowed to load Node's `crypto`, and why. The CLI runs only on Node and uses it directly.

**One result per method.** No flag switches a method between two return types. `send` broadcasts and returns the txid; `createSignedTransaction` returns the signed transaction without broadcasting it.

## Deprecated names

Each old name still works and forwards to its replacement.

### `Wallet`

| Deprecated | Use |
|------------|-----|
| `getUtxos(opts)` | `refreshUtxos(opts)` |
| `getGapLimit(opts)` | `getAddressGap(opts)`, which returns the current gap, not the gap limit |
| `getNextAvailableAddress(type?)` | `fetchNextAvailableAddress(type?)` |
| `getAddressBalance(address)` | `fetchAddressBalance(address)` |
| `getAddressesBalance(addresses)` | `fetchAddressesBalance(addresses)` |
| `getScriptHashBalance(scriptHash)` | `fetchScriptHashBalance(scriptHash)` |
| `getAddressHistory(address)` | `fetchAddressHistory(address)` |
| `getTransactionDetails(txid)` | `fetchTransactionDetails(txid)` |
| `getFeeEstimates(network?)` | `fetchFeeEstimates(network?)` |
| `getFeeEstimatesFromElectrum()` | `fetchFeeEstimatesFromElectrum()` |
| `getFeeEstimatesFromHttp(network?)` | `fetchFeeEstimatesFromHttp(network?)` |
| `getFallbackFeeEstimates(network?)` | `fetchFallbackFeeEstimates(network?)` |
| `getPrivateKeyInfo(wif)` | `fetchPrivateKeyInfo(wif)` |
| `getInputData({ inputs: [{ tx_hash, vout }] })` | `fetchInputData({ inputs: [{ txid, vout }] })` |
| `getRbfData({ txHash: { tx_hash } })` | `fetchRbfData({ txid })` |
| `isUtxoFrozen(txid, index)` | `isUtxoFrozen({ txid, vout })` |
| `{ txid, index }` passed to `freezeUtxo`, `freezeUtxoIfUnfrozen`, `unfreezeUtxo` or `unfreezeUtxoIfTagged` | `{ txid, vout }` |
| `send` or `sendMany` with `broadcast: false` | `createSignedTransaction({ address, amount })` or `createSignedTransaction({ txs })` |
| `sendMax` with `broadcast: false` | `createSignedTransaction({ address, max: true })` |

### `BeignetNode`

| Deprecated | Use |
|------------|-----|
| `payInvoice(bolt11, timeoutMs, maxFeeSats, amountSats, metadata, cltvLimit, maxFeeMsat)` | `payInvoice(bolt11, { timeoutMs, maxFeeSats, amountSats, metadata, cltvLimit, maxFeeMsat })` |
| `payInvoiceSafe(bolt11, timeoutMs, ...)` | `payInvoiceSafe(bolt11, { timeoutMs, ... })` |
| `openChannel(pubkey, amountSats, pushSats, satsPerVbyte, max, trusted)` | `openChannel(pubkey, amountSats, { pushSats, satsPerVbyte, max, trusted })` |
