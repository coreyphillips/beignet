# accept_channel.minimum_depth is adopted unbounded, so an acceptor can lock the funder's channel indefinitely; the v2 opener ignores accept_channel2.minimum_depth entirely

Labels: bug

Found during a security audit of channel opening.

## 1. v1: any u32 minimum_depth is accepted

`validateAcceptChannelParams` (`src/lightning/channel/validation.ts:290-372`) bounds `to_self_delay`, dust, reserve and HTLC counts but not `minimum_depth` (`grep minimumDepth src/lightning/channel/validation.ts` is empty). `handleAcceptChannel` stores it (`src/lightning/channel/channel.ts:1906`), it flows into `WATCH_FUNDING` (`:2153`) and the watcher waits for `confirmations >= watched.minimumDepth` (`chain-watcher.ts:2040`). `scanStuckChannels` only emits `STUCK_CHANNEL` (`lightning-node.ts:28582-28596`).

Failure: the acceptor replies with `minimum_depth = 4294967295` (or 100,000). We broadcast the funding and lock the whole amount in the 2-of-2; the channel never becomes usable; the only exit is an operator force close from `AWAITING_FUNDING_CONFIRMED` (`channel.ts:6414`), paying the commitment fee and waiting `to_self_delay`. BOLT 2 says the receiver MAY reject an unreasonably large `minimum_depth`; LDK enforces `max_minimum_depth` (144).

Fix: add `accept.minimumDepth > MAX_MINIMUM_DEPTH` (for example 144) to `validateAcceptChannelParams` as a wire-visible refusal.

## 2. v2: the opener treats every accepter's minimum_depth as one confirmation

`createOpenerState` sets `minimumDepth: 0` (`src/lightning/channel/channel-state.ts:1122`); `handleAcceptChannel2` (`channel.ts:15605-15700`) reads `msg.minimumDepth` only for the zero-conf equality check (`:15650`) and never stores it; the v2 `WATCH_FUNDING` at `:17977` and `:18271` carries the stored 0, and the watcher fires at the first block sighting. BOLT 2: the sender of `channel_ready` MUST wait for the accepter's `minimum_depth`.

Failure: we buy inbound liquidity (the peer contributes inputs). The peer asks for depth 6, then sends `channel_ready` at once; we send ours at one confirmation, the channel goes NORMAL, and the peer pays our invoices or routes through us. A one-block reorg lets the peer double-spend its own input: the funding never confirms and the value we already paid out downstream is gone. Against an honest peer it is a plain protocol deviation.

Fix: store the (bounded) `msg.minimumDepth` in `handleAcceptChannel2`, and when the peer contributed inputs wait for `max(ourDefaultDepth, msg.minimumDepth)`.
