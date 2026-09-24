# sweepPrivateKey and addExternalInputs write the swept private key into wallet storage through the staged transaction blob

Labels: bug

Found during a security audit of the on-chain wallet. Reproduced with a script that runs `sweepPrivateKey` against an in-memory `TStorage`:

```
saved key=transaction bytes=952 contains "__D"=true contains raw private key bytes=true
private key hex f5bd857703431488799ce8672f52fd1bcde821c1dbbfed17958d4583c58137f5
```

`README.md:287` promises that "no private keys and no mnemonic are ever written, so exposure is a privacy concern (full wallet history), not fund loss".

## What the code does

`sweepPrivateKey` (`src/wallet/index.ts:6096-6108`) attaches the ECPair to every swept coin and hands the list to the transaction builder:

```ts
utxos = utxos.map((utxo) => ({ ...utxo, keyPair }));
await this.transaction.setupTransaction({ satsPerByte, utxos, outputs: [...] });
```

`setupTransaction` and every `updateSendTransaction` persist the whole staged transaction with `saveWalletData('transaction', this._data)` (`src/transaction/index.ts:181`, `:201`, `:212`, `:1253`). The storage adapters `JSON.stringify` the value (`src/cli/wallet-storage.ts:47`, `src/utils/wallet-storage-encryption.ts:69`), which serialises the key pair's private `__D` buffer. `addExternalInputs` (`transaction/index.ts:1120-1160`) attaches `keyPair` the same way. The wallet already strips `keyPair` for frozen entries (`wallet/index.ts:2904-2906`) but not here, and the sweep never resets the staged transaction afterwards, so the key stays in storage until another send overwrites the blob.

## Failure scenario

A library host following the README (plain `storage`, described as privacy-only) sweeps a paper wallet with `broadcast: false`, or the broadcast fails. The private key of the swept coin sits in the host's database and backups indefinitely; anyone who reads that storage spends the coin. Under the daemon the blob is encrypted with a seed-derived key, which reduces but does not remove the exposure (the README's promise is about the unencrypted default).

## Suggested fix

Strip `keyPair` (and any signer object) before every `saveWalletData('transaction', ...)`; keep external signers in a non-persisted map keyed by outpoint; reset the staged transaction after a sweep. Add a test that asserts the persisted transaction blob never contains a private key.
