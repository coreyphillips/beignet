# The cooperative closing transaction trims outputs with hard-coded 294/546 thresholds instead of the negotiated dust_limit_satoshis, which burns a non-dust output or fails the channel against a conformant peer

Labels: bug

Found during a security audit of cooperative close. Reproduced with a script against `buildClosingTx` with the default negotiated dust limit of 354:

```
P2TR  local=500: our 500 sat output DROPPED; tx pays fee 1500 sat
P2WPKH local=300: our 300 sat output kept; tx pays fee 1000 sat
```

## What the code does

`getDustLimit` (`src/lightning/chain/closing.ts:433-451`) returns 294 for P2WPKH and 546 for everything else (P2WSH, P2TR included), and `buildClosingTx` (`:80-97`) and `closingTxRelayProfile` (`:181-206`) use that table, independent of the `dust_limit_satoshis` each side advertised (default 354, `src/lightning/channel/types.ts:433`). BOLT 2: each signer "MUST remove any output below its own dust_limit_satoshis"; BOLT 3's per-script table is 294 (P2WPKH), 330 (P2WSH), 354 (other). The peer's `closing_signed` signature is verified against the transaction Beignet builds (`channel.ts:7431-7460`), and a mismatch fails the channel on the wire. `initClosingFeeRange` reserves only `localConfig.dustLimitSatoshis` (`channel.ts:7846-7849`), so the opener-side reserve does not stop the builder from dropping an output of 355-545 sats.

## Failure scenario

Our balance is 500 sats to a P2TR shutdown script. We drop the output and sign a transaction paying it to fees. An LND or CLN peer building with dust 354 includes it; its signature fails to verify against our transaction (`Coop-close: peer closing signature failed to verify`), the channel goes ERRORED and force-closes: chain fees for both sides and no cooperative close. Against another Beignet node both drop it and the 500 sats (up to 545) go to the miner. Conversely a 300-sat P2WPKH output is kept by us and dropped by the peer, with the same signature mismatch.

## Suggested fix

Trim with the negotiated `dust_limit_satoshis` of the output's owner (at minimum use the BOLT 3 per-script table: 330 for P2WSH, 354 for P2TR and others); make `initClosingFeeRange`'s reserve use the same threshold as the builder. The companion low-severity item: `closing_signed`'s `fee_range` TLV is parsed and discarded (`src/lightning/message/channel-close.ts:174-192`) and never emitted, so as non-funder we can counter outside the funder's range (`channel.ts:7490-7540`), which a strict funder treats as a protocol error and never converges with.
