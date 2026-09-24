# The forwarder never applies expiry_too_soon: an HTLC whose outgoing cltv_expiry has already passed is relayed, and a beignet downstream answers by failing the channel, so one HTLC force-closes a channel between two beignet nodes

Labels: bug

Found during a security audit of the forwarding pipeline.

## What the code does

`handleForwardHtlc` checks the outgoing CLTV only relative to the incoming one (`src/lightning/node/lightning-node.ts:21155-21163` for cleartext, `:21123-21135` for blinded):

```ts
if (incomingCltvExpiry < forwardCltv + outPolicy.cltvExpiryDelta) {
    failIncoming(INCORRECT_CLTV_EXPIRY, { cltvExpiry: forwardCltv });
    return;
}
```

Nothing compares `forwardCltv` with the current block height. `Channel.addHtlc` (`src/lightning/channel/channel.ts:3155`) only refuses `cltv_expiry >= 500_000_000`, and `ChannelManager.addHtlc` adds no check either. BOLT 4 "Processing Node" requirements: the forwarder MUST fail the HTLC with `expiry_too_soon` if the outgoing CLTV is too close to the current height (LND rejects when it is within 3 blocks). The JIT engine has its own `expiryTooSoon` path (`src/lightning/liquidity/jit-receive.ts:1312`); the ordinary forward does not.

On the receiving side, `handleUpdateAddHtlc` treats an already-expired add as a wire error that fails the whole channel (`channel.ts:3477-3483`):

```ts
if (msg.cltvExpiry <= this._currentBlockHeight) {
    return this._failChannelWithWireError('HTLC CLTV already expired');
}
```

which puts the channel in ERRORED, sends `error`, and `handleChannelErrored` (`lightning-node.ts:25414-25560`) force-closes it. BOLT 2 lists no rule that requires failing the channel for an expired add; failing the HTLC is enough.

## Failure scenario

Attacker A (any node that can route to beignet router B) sends B an HTLC with `cltv_expiry = h + 41` and an onion whose payload for B says `outgoing_cltv_value = h - 1000` and `short_channel_id` = B's channel to C. B's relative check passes (`h+41 >= h-1000+40`), the fee check passes, and B offers C an `update_add_htlc` with expiry `h-1000`. If C is a beignet node it fails the channel and force-closes; B's channel to C goes on chain (fees, liquidity gone, every HTLC on it resolved on chain). A paid one failed HTLC. A can repeat this for every beignet peer of B by choosing the SCID. Against LND, CLN or Eclair the HTLC is merely failed, so the damage is limited to beignet-to-beignet channels, but the missing `expiry_too_soon` check is a BOLT 4 violation on every channel. The same race can occur without an attacker when the downstream is a block ahead and the route's tail CLTV is tight.

## Suggested fix

- In `handleForwardHtlc`, fail with `EXPIRY_TOO_SOON` when `forwardCltv <= currentBlockHeight + safetyMargin` (a few blocks), and add the same guard to `Channel.addHtlc` so no code path can offer an expired HTLC.
- Downgrade the receive-side reaction from a channel failure to an HTLC failure (`update_fail_htlc` with `expiry_too_soon`), reserving the channel failure for values that are not block heights at all.
