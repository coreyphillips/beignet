# The server-reported UTXO value is used for fee and change while the signature commits to the real amount, so a lying or MITM Electrum server makes the wallet overpay fees by up to ~5000 sat/vB times the transaction size

Labels: bug

Found during a security audit of transaction building. Reproduced with a script: a 1,000,000-sat P2WPKH coin reported by the server as 500,000; a 200,000-sat send at 10 sat/vB signs, validates against the real amount, and pays 501,410 sats in fees instead of 1,410:

```
valid against REAL amount (network view): true
valid against REPORTED amount: false
outputs sum 498590 real fee paid 501410 sats; intended fee 1410 ; vsize 141 effective sat/vB 3556
```

## What the code does

- Change is computed as balance minus outputs minus fee from `input.value` (`src/transaction/index.ts:698-715`), where the value came from the server's `listunspent` (`src/electrum/index.ts:1329`) or, for RBF, from the server's JSON `vout` values (`src/wallet/index.ts:5563`).
- `addInput` (`transaction/index.ts:1027-1068`) sets `witnessUtxo.value = input.value` AND spreads `...(await this.nonWitnessUtxoField(input.tx_hash))` for p2wpkh, p2sh-p2wpkh and p2wsh inputs (for hardware-signer compatibility). bitcoinjs-lib 6.1.4 prefers `nonWitnessUtxo` when both are present (`node_modules/bitcoinjs-lib/src/psbt.js:1205-1222`), so the BIP143 amount commitment is computed over the REAL prevout value and the signature is valid on the network. p2pkh inputs use `nonWitnessUtxo` only. Nothing compares `input.value` with `prevTx.outs[tx_pos].value` even though the previous transaction is already in hand.
- The only remaining bound is bitcoinjs's default `maximumFeeRate` of 5000 sat/vB at `extractTransaction`.
- The Electrum transport accepts any TLS certificate (`node_modules/rn-electrum-client/lib/TlsSocketWrapper.js:72` and `lib/init_socket.js:21`, `rejectUnauthorized: false`, with no pinning option in beignet), so an on-path attacker can play the lying server against the default `fulcrum.bitkit.blocktank.to` endpoint.

P2TR inputs are safe: BIP341 signs the reported amount, so a mismatch makes the transaction invalid rather than expensive.

## Failure scenario

Default p2wpkh wallet. The server (or a MITM) under-reports a coin's value. Every send from that coin overpays its fee by the difference, up to the point where the effective rate reaches 5000 sat/vB; a 50-input consolidation at ~3.5 kvB can lose about 17M sats in one transaction. The transaction relays and confirms, so there is no recovery. An attacker who mines (or sells the opportunity to a miner) profits directly; otherwise the user simply loses the difference to whichever miner includes it.

## Suggested fix

- In `addInput` / `nonWitnessUtxoField`, parse the fetched previous transaction and refuse the input unless `outs[tx_pos].value === input.value` and the script matches; cross-check the same way in `getUtxos` when previous transactions are fetched, and in `getRbfData`.
- Call `psbt.setMaximumFeeRate` with a wallet ceiling (the requested rate times a small margin, capped by `MAX_FEE_RATE_SAT_PER_VBYTE`) before `extractTransaction`, so no path can sign a fee far above what the user asked for.
- Separately, give operators a way to verify the Electrum server: honour CA verification for hosts with real certificates and/or pin the server certificate on first use, instead of the client library's unconditional `rejectUnauthorized: false`.
