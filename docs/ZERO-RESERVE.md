# Zero-reserve home channels

This implements the `option_zero_reserve` form in [BOLTs proposal 1140](https://github.com/lightning/bolts/pull/1140): feature bits 64/65 and the empty v2 `disable_channel_reserve` TLV, type 4. The proposal is not yet a final standard. Wallets advertise support and accept waivers by default after qualification. Set `advertise: false` to opt out. Primaries grant waivers only with their operator setting.

## One-way policy

A wallet accepts a waiver and never grants one. A primary retains its own reserve and grants a wallet waiver only when its operator enables the setting. Eligible channels are outbound JIT opens for registered clients, and inbound unannounced opens from peers that advertise support. Announced routing channels retain both reserves. Unknown peer features never authorize a waiver.

Library configuration:

```ts
// Embedded wallet
zeroReserve: { advertise: true, role: 'wallet' }

// Primary
zeroReserve: {
  advertise: true,
  role: 'primary',
  waiveClientReserve: true
}
```

The daemon uses `BEIGNET_WAIVE_CLIENT_RESERVE=true`, or `waiveClientReserve: true` in its configuration file. It always uses the primary role. Unset or false preserves normal reserves on new channels. Turning the setting off does not change channels already opened with a waiver.

A wallet with no reserve can publish an old commitment without putting a retained balance at risk. The primary must remain able to detect a revoked commitment and claim the penalty within the channel's delay. Enabling the setting accepts that operator risk.

## Stored channel terms

`localReserveWaived` means the peer waived our reserve. `remoteReserveWaived` means we waived theirs. Both directions are fixed at open, stored independently, and survive restarts, splice adoption, and v2 funding replacement. Rows without these fields have neither waiver. A zero numeric reserve on an old row is never sufficient evidence of negotiation.

`GET /channels` includes those booleans, `localReserveSats`, `remoteReserveSats`, `isOpener`, and `maxSendableSats`. Raw balances and payment history retain their existing meaning.

## What remains after a max

A waived non-opener can spend its entire Lightning balance when the resulting commitments retain outputs. Pay-all fixes a debit and routing-fee cap in msat, including any allowed fee-rounding gap. A splice-out can leave a fraction of a sat because its outputs use whole sats.

An opener must still pay the commitment fee and anchor outputs. Lightning's outbound ceiling also retains the existing fee-spike buffer. Splice quotes and sends retain the current commitment cost, returned as `commitmentCostSats`, in addition to any reserve. These costs follow the channel type and current feerate.

Both commitment transactions must remain valid. An HTLC that would leave a commitment with no outputs is refused before sending; receiving such an add fails the channel. A splice with a non-funding output is refused if either resulting commitment has no outputs. Dust limits still apply to transaction outputs.

## Compatibility and migration

Peers that do not advertise bits 64/65 keep ordinary reserves. The proposal uses neither the Phoenix-specific feature bit nor a private substitute. Real waiver qualification requires a supporting Beignet primary and wallet; CLN, LND, and eclair checks establish that ordinary channels remain compatible.

Regtest qualification covers JIT pay-all to zero, both opener roles through v1 and v2 opens, P2WPKH/P2TR/P2WSH splice destinations, and SQLite restart/reestablishment. The primary keeps its reserve in every path. Ordinary CLN 26.06.1, LND 0.20 and Eclair 0.14.1 channels, payments, closes and crash recovery were checked with optional feature advertisement. Interoperability fixture corrections supply real chain heights and deterministic local offer paths.

Existing channels keep their original terms. Cooperative close and reopening provide the migration path. Enabling this setting does not rewrite an existing channel's reserve.
