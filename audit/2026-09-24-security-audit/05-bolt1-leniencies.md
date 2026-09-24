# BOLT 1 leniencies on the wire: unknown even TLV types are accepted by init and most BOLT 2 parsers, init networks is never checked, and peer error text is logged verbatim

Labels: bug

Found during a security audit of the wire codec. Three related spec-conformance gaps in how peer-supplied bytes are admitted and surfaced. None is exploitable for funds on its own; they are the kind of leniency a conforming node must not have.

## 1. Unknown even TLV types are accepted instead of failing the message

`decodeTlvStream` only enforces the "unknown even type is an error" rule when the caller passes a `knownTypes` set (`src/lightning/message/tlv.ts:118`):

```ts
if (knownTypes && recordType % 2n === 0n && !knownTypes.has(recordType)) {
    throw new Error(`Unknown required TLV type: ${recordType}`);
}
```

Only three parsers pass one (`interactive-tx.ts:544`, `channel-close.ts:117` and `:307`). Thirteen call sites omit it, including `init.ts:113`, `channel-open.ts:248/388` (open_channel, accept_channel), `channel-funding.ts:146/208/279`, `channel-commitment.ts:150/217` (commitment_signed, revoke_and_ack), `channel-reestablish.ts:163`, `dual-funding.ts:328/476` and `interactive-tx.ts:444`. BOLT 1 requires a node to fail the connection (for init) or the channel/message for an unknown even type, because an even type signals a semantic the sender requires the receiver to understand. Accepting it means we can silently proceed with a channel whose peer believes a mandatory extension is in force.

Fix: define the known even-type set per message (most already have constants for their TLV types) and pass it to `decodeTlvStream`.

## 2. init `networks` is parsed but never compared to our chain

`decodeInitMessage` extracts the `networks` TLV (type 1) but nothing compares it to the node's acceptable chain hashes. BOLT 1: if the peer's `networks` contains no chain in common, the node SHOULD close the connection. A wrong-chain peer is caught later by `chain_hash` on `open_channel` and gossip, so this is a leniency rather than a loss, but it keeps useless connections alive and lets a peer on another chain reach the gossip and onion-message surfaces.

Fix: after `init`, disconnect when `networks` is present and disjoint from ours.

## 3. Peer-supplied error/warning text reaches the terminal unsanitized

`handleErrorMsg` and `handleWarningMsg` (`src/lightning/channel/channel-manager.ts:8450`, `:8558`) do `msg.data.toString('utf8')` and emit `Remote error: ${errorText}`; `lightning-node.ts:4945` logs it with `logger.error`, and the daemon's default logger writes to stderr. BOLT 1: a node "SHOULD only print out data verbatim if the string is composed solely of printable ASCII characters". Any peer that completes a handshake can send a `warning` (no channel needed) carrying newlines and ANSI escape sequences, which spoofs log lines or rewrites the operator's terminal.

Fix: replace bytes outside 0x20-0x7e before logging or surfacing peer error text (and truncate to a sane length).
