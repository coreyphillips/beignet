# A persisted multi-recipient staged send is replayed into every later send after a restart: POST /send for 50k sats pays the previous sendMany's recipients again (double payment, outside the daily limit)

Labels: bug

Found during a security audit of the on-chain wallet. Reproduced with a script that drives `Transaction` over a wallet whose stored `transaction` blob holds a previous three-output send:

```
outputs the PSBT will carry: [ 'bcrt1qy8lq7z=50000', 'bcrt1qw508d6=200000', 'bcrt1qc7slrf=300000' ]
total paid to recipients: 550000 (user asked for 50000)
```

## What the code does

There are two copies of the staged send:

1. The live `Transaction._data`, which starts empty on every boot and is what `resetSendTransaction` (`src/transaction/index.ts:210-214`) resets: `this._data = getDefaultSendTransaction(); await this._wallet.saveWalletData('transaction', this._data)`.
2. The wallet's `_data.transaction`, loaded from storage in `setWalletData` (`src/wallet/index.ts:1146`, `this._data = walletDataResponse.value`). `saveWalletData` (`:3235`) hands the value to the storage adapter and never assigns `this._data[key]`, and no other code assigns `_data.transaction` (grep), so this snapshot is frozen at boot.

`setupTransaction` seeds a new send's outputs from the frozen snapshot (`src/transaction/index.ts:145`):

```ts
outputs = outputs || currentWallet.transaction?.outputs || [];
```

removing only our own change addresses. `updateSendTransaction` (`:1237-1245`) overwrites only the indexes it is given (`outputs[output.index] = output`). `sendMany` (`wallet/index.ts:4805-4870`) and `buildPsbt` (`:4998`, reset only at the start) leave the recipients in storage after a successful build or broadcast, and `BeignetNode.sendOnchain` (`src/cli/beignet-node.ts:6090-6133`) resets only on a refused spend limit, not after success.

## Failure scenario

Session 1: `sendMany([A:100k, B:200k, C:300k])` or `POST /psbt/build` with three outputs. Storage now holds `transaction.outputs = [A, B, C]`.

Restart (the daemon with SQLite storage, or any library host that passes `storage`).

Session 2: `POST /send {address: D, amountSats: 50000}`. `send()` resets the live copy, `setupTransaction` seeds `[A, B, C]` from the frozen snapshot, `updateSendTransaction` overwrites index 0 with D, `validateTransaction` passes, and a transaction paying D 50k, B 200k and C 300k is signed and broadcast. Because the snapshot never changes, EVERY later send in that session pays B and C again until the balance is gone. `_builtOnchainTotalSats` (`beignet-node.ts:9691`) counts only amount plus fee, so the extra 500k also bypasses `dailySpendLimitSats`. `POST /tx/bump-fee` inherits it through `setupRbf` (`transaction/index.ts:1643-1660` also merges by index); `sendMax` and `consolidate` fail with "Outputs are spending more than Inputs" instead of overpaying.

## Suggested fix

- Never seed outputs from `wallet.data.transaction`: start from `[]` unless outputs are passed explicitly.
- Reset the staged transaction at the start of `sendMany`, `buildPsbt` and `setupRbf`, and after every successful broadcast.
- Either keep `_data.transaction` in sync in `saveWalletData` or drop the snapshot entirely.
- Add a regression test: build a multi-output send, reload the wallet from the same storage, send a single-output transaction, and assert the output set.
