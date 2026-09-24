# External-signer PSBT flow: change outputs carry no derivation metadata, and importSignedPsbt never verifies that the inputs and outputs it finalizes are the ones the wallet built

Labels: bug

Found during a security audit of the PSBT flow.

## What the code does

- `createUnsignedPsbt` adds outputs with address and value only (`src/transaction/index.ts:781-812`); `addSignerMetadata` (`:882-960`) annotates inputs but not outputs, so a hardware signer cannot recognise the change output as its own and shows it as an ordinary second recipient.
- `importSignedPsbt` (`src/wallet/index.ts:5084-5125`) validates partial signatures, `continue`s past already-finalized inputs (`:5096-5097`) with no check, and never compares the PSBT's inputs and outputs (scripts, values) against the staged build in `this.transaction.data` before finalizing and returning the transaction.

## Failure scenario

The point of an external signer is a compromised host or transport. Between build and sign, the change output (usually the bulk of the coins) is rewritten to the attacker's address. Without output derivation metadata the device shows it as a normal second recipient, the user approves the amounts they expected to see, `importSignedPsbt` finalizes, and the change is gone. A PSBT with pre-finalized inputs is accepted without any signature validation at all.

## Suggested fix

Add `bip32Derivation` / `tapBip32Derivation` to change outputs in `createUnsignedPsbt`; in `importSignedPsbt` compare every input and output against the staged build (or a caller-supplied expected set) and refuse on any mismatch; reject or re-verify already-finalized inputs.
