# As the channel funder, an inbound update_add_htlc is never checked against our own commitment fee: a peer can stack HTLCs until our to_local is trimmed to zero

Labels: bug

Found during a security audit of the channel state machine. Reproduced against `Channel` (non-anchor channel we opened at 2500 sat/kw, our balance 30,000 sat):

```
after 80 peer adds: our balance 30000 sat, commitment outs=81 (htlcs=80), fee actually paid=30000 sat
```

Every add returned `[]` (no error); after enough adds our output is gone and the commitment fee equals our whole balance.

## What the code does

The receive-side affordability block in `handleUpdateAddHtlc` (`src/lightning/channel/channel.ts:3407-3452`) prices the commitment fee only when the PEER is the funder:

```ts
let remoteRequiredMsat = remoteReserveMsat;
if (this._state.role === ChannelRole.ACCEPTOR) {
    remoteRequiredMsat += funderCommitmentCostSats(...) * 1000n;
}
if (this._state.remoteBalanceMsat - msg.amountMsat < remoteRequiredMsat) { fail }
```

When we are the OPENER the only test is that the peer stays above its reserve. Nothing checks that OUR balance still covers `reserve + fee(n+1)` after the new HTLC. `_localCommitmentEmptyRefusal` (`:14731`) only arms when our reserve is below our dust limit or a splice is pending. The builder then saturates (`src/lightning/channel/commitment-builder.ts:700-703`, `:880-883`): `localAmount -= fee; if (localAmount < 0n) localAmount = 0n;` and omits our output. The fee-spike buffer in `getSpendableOutboundMsat` (`:13139`) protects only our own sends. Eclair (`CannotAffordFees` in `receiveAdd`), LND (the initiator reserve check in `validateCommitmentSanity`) and CLN all refuse this on receive.

## Failure scenario

A 1,000,000-sat channel we opened; our balance is 30,000 sat (reserve 10,000 plus buffer). The peer sends 65 `update_add_htlc` of 5,000 sat each from its own balance (all untrimmed). After 65 adds the local commitment holds 66 outputs, our output is gone, and the commitment fee is exactly our 30,000 sat; we sign the peer's commitment with our to_remote at 0 the same way. The peer broadcasts (or stalls until we force close); its HTLCs time out back to itself; our 30,000 sat go to miners. The loss is bounded by `(724 + 172 * 483) * feerate / 1000` (about 210k sat at 2500 sat/kw, about 840k sat at 10k sat/kw) and costs the attacker nothing.

## Suggested fix

In the OPENER branch require `localBalanceMsat >= remoteConfig.channelReserveSatoshis * 1000n + funderCommitmentCostSats(max(localFeerate, remoteFeerate), untrimmed + 1, channelType) * 1000n` and fail with `_failChannelWithWireError` like the ACCEPTOR arm (BOLT 2: the receiver MUST fail the channel if the sender cannot afford the fee); consider the same guard in `handleCommitmentSigned`.
