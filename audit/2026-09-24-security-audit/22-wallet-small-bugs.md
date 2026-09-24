# On-chain wallet small bugs: sendMax prices its output as the wallet's own address type, and getRbfData's "already confirmed" guard reads the request echo instead of the transaction

Labels: bug

Found during a security audit of the on-chain wallet. Two low-severity correctness items.

## 1. sendMax prices the single output as the wallet's own address type

`getMaxSendAmount` runs with `outputs = []` (`src/transaction/index.ts:325-331`, `:1376-1400`), so `increaseAddressCount` uses `this._wallet.addressType`. A p2wpkh wallet sweeping to a p2tr or p2wsh address prices a 31 vB output but builds a 43 vB one: a 1-in-1-out sweep is priced at 110 vB and built at 122 vB, about 10% below the requested fee rate. Slower confirmation, no loss.

Fix: include the recipient in the outputs used for pricing before computing the maximum.

## 2. getRbfData's confirmation guard never fires

`src/wallet/index.ts:5549` checks `tx.value.data[0].data.height > 0`, but `data` is the request object `{ tx_hash }` the wallet itself passed (rn-electrum-client tags each result with `argz[id].data`), so `height` is always undefined. The only gate is `canBoost`'s locally stored height; a parent that confirmed since the last refresh gets a pointless self-send at about 1.5x the fast rate (CPFP) or a replacement the node rejects (RBF).

Fix: look up the boosted transaction's own confirmation freshly in `setupRbf` / `setupCpfp`.
