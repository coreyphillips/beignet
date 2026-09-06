# Direct-funding ownership proofs

A receiver validates the offer's fields and proves control of its named input before starting channel negotiation. Proofs authorize this offer only. The sender separately verifies the complete funding transaction before returning a spendable witness.

The sender selects a signed-message proof when available, then a transaction probe, then the original digest proof. Receivers reject malformed proofs that are present; they do not fall back to a different proof form. Support demonstrated here is specific to the tested signing RPC and coin type. Hardware-wallet or other PSBT signer support requires its own verification.

## Offer binding

`offerId` is the first 16 bytes of SHA256 over UTF-8 text:

```
<lowercase display txid hex>:<decimal vout>:<decimal amountSat>
```

The receiver checks this derivation before checking ownership. Thus the probe's offer ID also binds the requested amount. It also checks the actual previous output's value and script against the offer. Calling the ownership helper alone does not replace these field and chain checks.

## Original digest and signed-message forms

The message is the following UTF-8 string, with lowercase hex and unpadded decimal integers:

```
lfbw-direct-funding-offer:<offerId hex>:<txid hex>:<vout>:<amountSat>
```

The original proof signs SHA256 of this message. P2WPKH uses ECDSA with its compressed public key; P2TR uses the script's output key and Schnorr.

Odd TLV 21 carries the signed-message alternative: a 33-byte compressed public key followed by a 65-byte compact recoverable ECDSA signature. It signs the standard Bitcoin signed-message digest, SHA256d of the CompactSize-prefixed `Bitcoin Signed Message:\n` prefix and CompactSize-prefixed message. For P2WPKH the key must hash to the previous output. For P2TR this form proves the BIP86 internal key and checks its tweak against the output key. It does not support arbitrary taproot script trees.

## Transaction-probe form

Odd TLV 23 carries 97 bytes: a 33-byte public-key field and a 64-byte signature. P2WPKH uses its compressed public key and compact ECDSA signature, verified with SIGHASH_ALL. P2TR uses a zero-filled public-key field and a Schnorr signature, verified with SIGHASH_DEFAULT against the previous output's output key. Verification takes that key from the script, not this padding field.

The receiver reconstructs this exact transaction:

| Field                   | Value                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------- |
| Version / locktime      | 2 / 0                                                                                 |
| Input 0                 | Offered txid and vout, empty scriptSig, offered sequence                              |
| Input 1 hash bytes      | SHA256(UTF-8 `lfbw-direct-funding-poison` concatenated with the raw 16-byte offer ID) |
| Input 1 vout / sequence | 0 / offered sequence                                                                  |
| Single output           | 0 sat, script `6a10` followed by the raw offer ID                                     |

The first input's txid is converted from display order to transaction byte order. The poison hash bytes are inserted directly, without another reversal. This is plain SHA256 of a domain prefix and offer ID, not the BIP340 tagged-hash construction. Its artificial previous output has value 0 and script `6a0b` followed by UTF-8 `lfbw-poison`. These previous-output fields participate in the P2TR sighash.

The signature uses input index 0. Both permitted sighash modes commit to every input, so removing or replacing the poison input invalidates it. No transaction preimage is known for the poison outpoint, making the transaction unspendable under the hash-preimage assumption. The receiver accepts neither ANYONECANPAY nor alternate sighash modes for a probe. This custom proof is inspired by transaction-based ownership proofs; it is not a BIP322 wire format.

For either alternative proof, the legacy 64-byte digest signature field is zeroed. An older receiver ignoring the odd TLV rejects that invalid legacy signature before negotiation. No signature from the probe is reused as a funding witness.

## External fixtures

`tests/lightning/fixtures/cln-ownership-probes.json` contains unsigned and signed PSBTs returned by Core Lightning v26.06.1 on regtest for real P2WPKH and P2TR wallet coins. The capture selected one confirmed unreserved coin per kind, constructed the probe, called `reserveinputs` for that coin only, called `signpsbt` with `signonly: [0]`, and released the same reservation block count in a finally block. Neither probe was broadcast.

The fixture tests reconstruct the exact transaction, round-trip the wire proof, verify the external signatures, and reject changed offer/input fields and removal of the poison input. These fixtures establish signer compatibility and proof verification. Channel broadcast and settlement require separate integration tests.
