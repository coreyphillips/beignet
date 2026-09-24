# setupTransaction silently selects every wallet coin when inputTxHashes matches nothing, and CPFP boost inherits it: a boost can turn into a full-wallet self-send at a high fee rate

Labels: bug

Found during a security audit of the on-chain wallet. Reproduced with a script: a CPFP set up for parent `aaaaaaaa` whose outputs are not spendable selected the wallet's other coins instead:

```
requested inputs from tx aaaaaaaa -> selected inputs: [ '11111111:0=1000000', '22222222:0=2000000' ]
input total 3000000 fee at 20 sat/vB 3560
```

## What the code does

`setupTransaction` (`src/transaction/index.ts:93-115`) filters the wallet's UTXOs by `inputTxHashes`; when the filter is empty it falls back first to the inputs of the persisted snapshot and then to `removeBlackListedUtxos(currentWallet.utxos)`, i.e. every non-frozen coin. `setupCpfp` (`:1544`) passes `inputTxHashes: [txid]`. `canBoost` (`src/wallet/index.ts:6238-6280`) only requires a matched output of at least 768 sats, and `_boostCpfp` (`src/cli/beignet-node.ts:6649-6680`) builds and broadcasts. Sibling of the closed #229 (a different path to the same consolidation).

## Failure scenario

Unconfirmed parent P whose only output to us is frozen by the user, already spent by our own second pending transaction, or not yet scanned. `POST /tx/boost P`: `canBoost` says CPFP, `setupCpfp` finds no matching UTXO, falls back to ALL coins, and sends the whole wallet to its own address at `max(1, ceil((fast * (vsizeP + 141) - feeP) / 141))` sat/vB. With 20 coins and `fast = 50` that is about 1.4 kvB at roughly 99 sat/vB, around 139,000 sats, for a transaction that in the frozen case does not even descend from P: no boost, a forced consolidation, and a privacy loss.

## Suggested fix

When `inputTxHashes` is given and nothing matches, return an error instead of falling back; `setupCpfp` should refuse when the parent has no spendable output of ours; consider making the generic fallback opt-in.
