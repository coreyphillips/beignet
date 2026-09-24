# BOLT 4 failure handling gaps: a downstream update_fail_malformed_htlc is relayed upstream as an undecryptable 4-byte blob, an unparseable onion is failed with update_fail_htlc under a zero key, and four smaller onion edge cases

Labels: bug

Found during a security audit of onion processing. The first two items cost routing reputation on every affected payment (origins that cannot decrypt a failure penalise every hop on the route, including our channel); the rest are correctness and griefing edges.

## 1. Downstream `update_fail_malformed_htlc` on a forwarded HTLC is relayed as a synthetic blob

When downstream C answers our forwarded HTLC with `update_fail_malformed_htlc`, the channel layer builds a 4-byte synthetic reason `[failure_code][0000]` (`src/lightning/channel/channel.ts:4170-4185`). `handleHtlcFailed` (`src/lightning/node/lightning-node.ts:22654-22705`) treats it like any peer failure (`failPreWrapped` is false), and `failForwardUpstream` (`:22442-22446`) XORs it with our ammag stream and sends it upstream. Only our OWN payments special-case the 4-byte form (`:22825`). BOLT 2: the forwarder "MUST return an error in the `update_fail_htlc` sent to the link which originally sent the HTLC, using the `failure_code` given and setting the data to `sha256_of_onion`".

Fix: detect `reason.length === 4 && (code & 0x8000)` and send `createFailureMessage(inSharedSecret, code, sha256(onion we forwarded))`.

## 2. Unparseable non-blinded onion answered with `update_fail_htlc` under an all-zero key

`lightning-node.ts:16760-16772` does `createFailureMessage(Buffer.alloc(32), INVALID_ONION_HMAC)`; the comment concedes the sender cannot decrypt it. BOLT 4 requires `update_fail_malformed_htlc` with `sha256_of_onion` and the `BADONION` code for HMAC, version and key failures (the blinded branch just above does this correctly).

Fix: use `channelManager.failMalformedHtlc(channelId, htlcId, sha256(onionBuf), INVALID_ONION_HMAC | VERSION | KEY)` per error class.

## 3. Invalid `blinding_point` throws out of `handleIncomingHtlc` and drops sibling forwards

`deriveBlindedPrivkey(htlcEntry.blindingPoint, ...)` (`lightning-node.ts:16731-16734`) runs BEFORE the try/catch and throws "Expected Point" on a 33-byte non-point (`channel-update.ts:153-163` does not validate the point). The throw escapes the `htlc:forwarded` listener and aborts the revoke_and_ack action batch; every later `HTLC_FORWARDED` action in that batch is skipped and, being edge-triggered, is not re-emitted until a restart. A channel peer can stall N legitimate relayed HTLCs behind one bad blinding TLV until the CLTV backstop fails them.

Fix: derive inside the try (fail with `invalid_onion_blinding` via `failMalformedHtlc`), validate the point in the decoder, and wrap each per-HTLC emit so one listener throw cannot skip siblings.

## 4. `decryptFailureMessage` throws on an authenticated failure with `failure_len < 2`

`src/lightning/onion/failures.ts:143-145` reads `readUInt16BE(0)` with no bounds check. Our direct peer can fail our HTLC with a valid-HMAC reason whose `failure_len` is 0: `settleOwnPaymentFailure` (`lightning-node.ts:22832`) aborts before any bookkeeping, the payment stays PENDING with its mapping (re-sends refused as "in flight") until the stuck-payment sweep, and the exception unwinds `handleRevokeAndAck` past `autoSignAndSendCommitment`.

Fix: bounds-check and attribute a malformed-but-authenticated failure to that hop with an unknown code.

## 5. Hop payload defaults instead of `invalid_onion_payload`

`src/lightning/onion/hop-payload.ts:160-161` defaults `amt_to_forward` and `outgoing_cltv_value` to 0 when types 2/4 are absent; `payment_data` shorter than 32 bytes is silently ignored and `short_channel_id`/`blinding_point` lengths are unchecked (`:208-214`). The blinded relay path (`lightning-node.ts:21100-21135`) ignores `payment_constraints.htlc_minimum_msat` and does not reject cleartext forwarding fields in a blinded intermediate payload (BOLT 4 MUSTs). A forward lacking `amt_to_forward` becomes a 0-msat add refused as `temporary_channel_failure` instead of `PERM|22`.

Fix: track presence of the required types and fail with `invalid_onion_payload` (type/offset); enforce `htlc_minimum_msat`; reject cleartext fields in blinded intermediate payloads.

## 6. `node_announcement` with an unknown address type is dropped entirely

`decodeNodeAddress` (`src/lightning/gossip/messages.ts:568`) throws on an unknown descriptor type and the caller discards the whole announcement. BOLT 7: "MUST ignore the first address descriptor that does not match" but keep the rest. Nodes that add a future address type vanish from our node table, and `captureChannelPeerAddresses` loses the reconnect fallback for such a peer.

Fix: stop parsing at the first unknown type, keep the parsed addresses, mark the message non-servable.
