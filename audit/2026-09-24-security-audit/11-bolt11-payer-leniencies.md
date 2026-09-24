# BOLT 11 payer leniencies: mixed-case invoices decode, an invoice for another network is paid, and lnbc0m produces a zero-amount HTLC

Labels: bug

Found during a security audit of the BOLT 11 decode and pay paths. Reproduced with a script against `decodeInvoice` and `hrpAmountToMsat`:

```
mixed-case string: ACCEPTED
lnbc0m: decoded amountMsat=0
lnbc0:  decoded amountMsat=0
```

## 1. Mixed-case bech32 strings are accepted

`decode` lowercases the string before calling `bech32.decode` (`src/lightning/invoice/decode.ts:44-46`), which defeats the library's mixed-case rejection. BIP 173: decoders MUST reject strings that mix upper and lower case (the checksum is only defined on a single case; a mixed-case string is by construction a corrupted or hand-edited one).

Fix: pass the original string to `bech32.decode`, or reject when the string differs from both its lower- and upper-cased forms.

## 2. An invoice for a different network is paid

Neither `LightningNode.sendPayment` (`src/lightning/node/lightning-node.ts:15486-15530`) nor `BeignetNode.payInvoice`/`payOffer` compares the decoded `invoice.network` (or an offer's `offer_chains`) with the node's own chain; `grep` finds no such comparison. A mainnet node handed an `lntb`/`lnbcrt`/`lntbs` invoice routes real sats to whichever mainnet node holds the invoice's node id. Test setups commonly reuse node keys across networks, so the payment can succeed and go to a node that was never meant to receive mainnet funds. LND, CLN and LDK refuse to pay an invoice for another chain.

Fix: refuse in `sendPayment` (and in the daemon's decode/validate routes, so the caller learns it before paying) when `invoice.network !== this.network`, and refuse offers whose `offer_chains` does not contain ours.

## 3. A zero-amount HRP becomes a zero-amount HTLC

`hrpAmountToMsat` accepts `0m` and `0` (`src/lightning/invoice/amount.ts:79, 97-100` only reject leading zeros on multi-digit strings), so `lnbc0m...` decodes with `amountMsat = 0n`. `sendPayment` treats `0n` as a fixed amount, `paymentSpendSats` returns 0 so spend admission is skipped, and `Channel.addHtlc` (`src/lightning/channel/channel.ts:3165`) only refuses `amount < remote htlc_minimum_msat`. When the first-hop peer advertises `htlc_minimum_msat = 0` (Core Lightning's default) a 0-msat `update_add_htlc` goes out. BOLT 2: a receiver of `amount_msat == 0` SHOULD send a warning and close the connection or fail the channel. The same happens with `amountSats: 0` on an amountless invoice.

Fix: reject `amountMsat <= 0n` in the decoder (BOLT 11 amounts are positive), in `sendPayment`, and as a belt-and-braces check in `addHtlc`.
