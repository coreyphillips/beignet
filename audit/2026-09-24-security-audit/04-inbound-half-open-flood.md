# Inbound peer admission: half-open handshakes never count toward maxInboundPeers, and there is no per-IP or socket-level cap, so a flood of stalled handshakes exhausts descriptors and memory

Labels: bug

Found during a security audit of the BOLT 8 transport.

## Summary

`PeerManager.handleInboundConnection` admits an inbound socket unless `this.inboundPeerCount >= this.maxInboundPeers`. That counter is incremented only after the Noise handshake and `init` exchange complete (`peer-manager.ts:1548`) and decremented on close (`:767`, `:1630`). A connection that never finishes its handshake is therefore never counted, yet it holds a socket, a `Peer` object and its read buffers for the whole `handshakeTimeout` (30 s by default, `peer.ts:182`). There is no per-source-address limit anywhere in the transport, `net.createServer` (`peer-manager.ts:1246`) sets no `maxConnections`, and the WebSocket listener feeds the same path (`:1306`). `maxInboundPeers` itself defaults to 125 and is not plumbed through `LightningNode` or the daemon config, so an operator cannot lower it.

## Failure scenario

1. **Half-open flood.** An attacker opens thousands of TCP or WebSocket connections and sends 49 of the 50 act-one bytes (or nothing) on each. None count toward the cap. Each lives ~30 s, so a sustained rate of a few hundred connections per second keeps tens of thousands of sockets, `Peer` instances and buffers alive, exhausting file descriptors and heap. A node driven unresponsive or OOM while it holds channels misses HTLC and commitment deadlines.
2. **Slot squatting.** Without a per-IP cap, one host can complete 125 cheap handshakes with 125 freshly generated keypairs and occupy every inbound slot, locking out the node's real channel peers (their reconnects are refused at `:1423`). Channels with those peers stay inactive until the squatter leaves.

## Where

- `src/lightning/transport/peer-manager.ts:1400-1445` (`handleInboundConnection`), `:1423` (the only gate), `:1548` (increment after handshake), `:767` and `:1630` (decrement).
- `src/lightning/transport/peer-manager.ts:1246` (`net.createServer`, no `maxConnections`), `:1306` (WebSocket inbound joins the same path).
- `src/lightning/transport/peer.ts:182` (`handshakeTimeout` default 30 s).
- `src/lightning/node/lightning-node.ts:2137-2146`: the `PeerManager` is constructed without `maxInboundPeers`; `grep maxInboundPeers src/cli` finds nothing.

## Suggested fix

- Count pending inbound handshakes (or keep a separate half-open cap, e.g. 50) and refuse new sockets above it; shorten the inbound handshake timeout (a conforming peer completes act one within a round trip).
- Add a per-source-address limit keyed on `socket.remoteAddress` (both established and pending), with an allow-list for known peers.
- Set `server.maxConnections` as a hard backstop on both listeners.
- Plumb `maxInboundPeers` through `INodeConfig` and the daemon config so operators can tune it.
