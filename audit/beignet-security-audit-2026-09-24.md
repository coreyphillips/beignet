# Beignet security audit, 2026-09-24

Consolidated report. Each section below is a ready-to-file GitHub issue; the individual files are in `audit/2026-09-24-security-audit/` on branch `claude/quirky-curie-lajw81` (local commit 416d1f3).

Audit of master at commit 1086c09 (v0.22.0). Each file in this directory is a ready-to-file GitHub issue (title on the first line, body below). Every finding was verified against the code by the lead reviewer; where a reproduction script is quoted it was re-run by the lead. Findings already tracked in the issue tracker were excluded.

| # | Severity | Area | Title |
|---|----------|------|-------|
| 06 | Critical | Payments | Payee-controlled blinded-path fee paid uncapped and invisibly to every limit |
| 17 | Critical | On-chain wallet | Persisted staged send replayed into every later send after a restart (double payment) |
| 01 | High | Daemon | One unauthenticated request with an unparsable Host header crashes the daemon |
| 02 | High | CLI | beignet init writes the mnemonic and apiToken with default (world-readable) permissions |
| 03 | High | Daemon | Default no-token loopback daemon is CSRF-able from any web page |
| 07 | High | BOLT 12 | Payer accepts an invoice for any amount, any signer, or expired |
| 08 | High | BOLT 12 | Issuer mints an invoice for whatever invreq_amount the payer sends |
| 09 | High | Payments | Routing fees outside maxPaymentSats and the daily ledger; no default fee cap |
| 13 | High | Forwarding | Forwarder never applies expiry_too_soon; beignet downstream fails the channel |
| 18 | High | On-chain wallet | Server-reported UTXO value trusted while the signature commits to the real amount |
| 19 | High | On-chain wallet | sweepPrivateKey writes the swept private key into wallet storage |
| 23 | High | Swaps | Reverse provider hands a never-relayed funding to the client after the hold is cancelled |
| 25 | High | Recovery | Fenced device admits the operator's force close of a revoked commitment |
| 26 | High | Recovery | Snapshot frames exceed the guardian ciphertext cap; replication wedges, quorum node freezes |
| 29 | High | Chain | Uneconomic to_local aborts every HTLC claim on our own force close |
| 32 | High | Payments | Zero-amount invoice via the MPP fallback underpays and poisons all persistence |
| 35 | High | Spending rails | sendToRoute bypasses maxPaymentSats, dailySpendLimitSats and the ledger |
| 36 | High | Daemon | POST /offer/pay ignores X-Idempotency-Key; retries pay twice |
| 39 | High | FFOR | Any channel peer can lock the settlement peer's balance indefinitely |
| 44 | High | Channel | Funder never checks its own commitment fee on inbound adds; balance trimmed to zero |
| 04 | Medium | Transport | Half-open handshakes never count toward maxInboundPeers; no per-IP cap |
| 10 | Medium | L402 | /l402/fetch follows redirects into private targets (blind SSRF) |
| 14 | Medium | Gossip | Unsolicited reply_channel_range accumulated without bound |
| 15 | Medium | Gossip | Pathfinding routes over unverified channel_updates (lazy mode default) |
| 16 | Medium | Forwarding | Malformed-HTLC relay and five BOLT 4 failure-handling gaps |
| 20 | Medium | On-chain wallet | setupTransaction falls back to every coin; CPFP boost inherits it |
| 21 | Medium | On-chain wallet | PSBT external-signer flow: change unlabelled, import never verifies outputs |
| 27 | Medium | Recovery | Guardian storage never shrinks; shared quota is a hard stop |
| 30 | Medium | Watchtower | Backups skip commitment #0 and revocations across a restart |
| 31 | Medium | Coop close | Closing tx trims with hard-coded dust thresholds, not the negotiated limit |
| 33 | Medium | Payments | MPP part on a reconnecting channel never fulfilled; needless force close |
| 40 | Medium | FFOR | Witness provisioning lets one peer exhaust mailbox capacity forever |
| 45 | Medium | Channel | revoke_and_ack next point not curve-validated; permanent channel wedge |
| 46 | Medium | Channel | accept_channel minimum_depth unbounded; v2 opener ignores it |
| 05 | Low | Wire | BOLT 1 leniencies: unknown even TLVs accepted, init networks unchecked, error text unsanitized |
| 11 | Low | BOLT 11 | Mixed case accepted, other-network invoices paid, zero-amount HTLC |
| 12 | Low | BOLT 12 | invoice_request / invoice decoders skip reader MUSTs |
| 22 | Low | On-chain wallet | sendMax pricing and getRbfData dead guard |
| 24 | Low | Swaps | Provider hardening: CLTV mismatch, concurrency cap, stranded rows, client CLTV bound |
| 28 | Low | Recovery | Restore racing a live writer with one guardian down deadlocks both |
| 34 | Low | Payments | Retry context left after a throwing dispatch; re-send inherits old parameters |
| 37 | Low | Spending rails | Rebalance fees and drain mode; maxPaymentSats Lightning-only |
| 38 | Low | Daemon | Invoice expiry validation; splice feerate unbounded |
| 41 | Low | Direct funding | Ownership proof not request-bound; replayable to burn attempt budgets |
| 42 | Low | Daemon | Hardening bundle: rate-limiter prune, SSE backpressure, openapi, webhooks, five small items |
| 43 | Low | Hygiene | qs advisories under bip21, Electrum TLS never verified, CI permissions and pinning |
| 47 | Low | Channel | State-machine leniencies: trimmed-HTLC affordability, reestablish gaps, uncommitted settles, upfront script |

## Considered and not filed

- Force-closing on a peer's `error` message: deliberate, matches LND, CLN and Eclair; only the counterparty can trigger it.
- Electrum SPV trust (no header or merkle verification): documented design; filed only where the wallet can cross-check data it already holds (18).
- Outgoing payment preimages visible to `readonly` API keys: consistent with `GET /payment/proof` being readonly by design.
- `wire-capture` writing decrypted messages to disk: opt-in and documented.
- Open issue 796 (swap fee floor) and the open guardian-rotation issues (862, 937, 938) already cover their topics.

## Verified sound (high level)

BOLT 8 Noise handshake and cipher rotation, wire codec bounds, BOLT 3 scripts and key derivation (Appendix C/E/F vectors pass), shachain handling, commitment construction and fee trimming, commitment_signed / revoke_and_ack ordering and persist-before-send, interactive-tx validation, Sphinx processing, failure-onion attribution, forwarding fee arithmetic, payment_secret and MPP set handling, keysend, hold invoices, SQLite parameterization and WAL/FULL durability, serialization round trips, swap scripts and refund construction, recovery frame AEAD and writer lease, guardian verb authentication, watchtower blob format and justice construction, coin selection and fee tables, multisig and taproot signing, BIP 21 parsing, daemon auth and scope keying, idempotency for BOLT 11 routes.

---

<!-- 01-host-header-crash.md -->
## Issue: One unauthenticated request with an unparsable Host header crashes the daemon: new URL() throws inside the void-wrapped request handler before auth or rate limiting run

Labels: bug

Found during a security audit of the HTTP daemon.

## Summary

The first statement of the daemon's async `requestHandler` builds a WHATWG `URL` from the client-supplied `Host` header. When that header is not a valid URL host, `new URL()` throws `TypeError [ERR_INVALID_URL]`. The throw happens before the OPTIONS short-circuit, before the rate limiter and before authentication, and outside the `try/catch` that only wraps `parseBody` and the route handler. The server callback discards the handler's promise with `void`, so the rejection is unhandled, and Node's default `--unhandled-rejections=throw` terminates the process.

One TCP connection from anyone who can reach the port takes the whole node down. A node that is down cannot claim incoming HTLCs whose preimage it knows, cannot time out offered HTLCs, and cannot react to a breach, so on a routing node this is a money-loss vector, not only availability.

## Where

- `src/cli/daemon.ts:3047-3054` (`requestHandler` prologue):
  ```ts
  const parsedUrl = new URL(
      req.url || '/',
      `http://${req.headers.host || 'localhost'}`
  );
  ```
- `src/cli/daemon.ts:3366-3372`: both `http.createServer` and `https.createServer` callbacks do `void requestHandler(req, res);`
- The `try/catch` at `src/cli/daemon.ts:3278-3357` covers only body parsing and the handler call, not the prologue.
- There is no `process.on('unhandledRejection')` or `uncaughtException` handler anywhere under `src/` (only SIGINT/SIGTERM in `cli.ts:535-536`).

## Reproduction

Against any running daemon (no token needed; `/health` is auth-exempt but the crash happens before auth anyway):

```
printf 'GET /health HTTP/1.1\r\nHost: a b\r\nConnection: close\r\n\r\n' | nc 127.0.0.1 2112
```

Other triggers: `Host: [::1`, `Host: a:b:c`, or a request target such as `//[`. Node's HTTP parser passes these header values through unchanged.

A faithful copy of the prologue plus the `void` wrapper, run on Node 22, exits with:

```
TypeError: Invalid URL
    at new URL (node:internal/url:818:25)
    at requestHandler ...
  code: 'ERR_INVALID_URL', input: '/health', base: 'http://a b'
process exit code 1
```

## Impact

- `daemonHost: 0.0.0.0` (the documented production shape behind a reverse proxy or with a token): any host on the network segment can kill the node at will, token or not.
- Default loopback bind: any local process can.
- Because the crash is a plain unhandled rejection, a supervisor restart is the only recovery, and each restart re-runs startup, reestablish and the initial sync.

## Suggested fix

1. Parse the request target against a fixed base (`new URL(req.url || '/', 'http://localhost')`) and never use the client's `Host` header as a URL base, or wrap the parse in `try/catch` and answer 400.
2. Wrap the entire handler body so no route can reject out of the server callback: `requestHandler(req, res).catch(...)` that logs and answers 500 if the response is still writable.
3. As a last line of defence, register an `unhandledRejection` handler in `cli.ts` that logs rather than exits, or at least makes the exit deliberate and logged, so a future regression of this shape is visible instead of silent.

---

<!-- 02-config-permissions.md -->
## Issue: beignet init writes the mnemonic and apiToken to ~/.beignet/config.json with default file permissions, so every local account on the host can read the seed

Labels: bug

Found during a security audit of the CLI and configuration handling.

## Summary

`saveConfig` creates `~/.beignet` and writes `config.json` with no `mode` and no `chmod`. Under the default umask of 022 the directory is 0755 and the file is 0644. `handleInit` puts the freshly generated mnemonic into that file, and `resolveConfig` reads `apiToken` from the same file when the operator configures it there (which `src/cli/README.md` documents as the normal way).

On any multi-user host whose home directories are traversable (the default on Debian, and on Ubuntu before 21.04, and on most container images that run as root with a shared filesystem), every other local account can read the seed. The seed derives the on-chain keys, the Lightning node key, every channel key, and the storage encryption key, so reading it is a total loss of every balance the node holds. The token additionally gives full admin API access to the running daemon.

## Where

- `src/cli/config.ts:52-55`:
  ```ts
  export function saveConfig(config: BeignetConfig): void {
      fs.mkdirSync(beignetDir(), { recursive: true });
      fs.writeFileSync(configPath(), JSON.stringify(config, null, 2) + '\n');
  }
  ```
- `src/cli/cli.ts:370-396` (`handleInit`): `newConfig = { ...config, mnemonic, network }` then `saveConfig(newConfig)`.
- `src/cli/config.ts:695-696` (`writePidFile`): same pattern, harmless content.
- `src/cli/beignet-node.ts:1986`: the data directory holding the SQLite database is also created without a mode. Values in the database are AES-GCM encrypted under a seed-derived key, but the lookup columns (payment hashes, channel ids, peer pubkeys, gossip, the action log) are plaintext per `sqlite-storage.ts:179-182`, so the database file is a privacy leak on the same hosts even though it does not leak funds.
- `grep -rn "mode: 0o\|chmod" src/cli` finds nothing.

## Reproduction

With `HOME` pointed at a scratch directory and umask 022, run `beignet init` and stat the results: `~/.beignet` is `drwxr-xr-x`, `config.json` is `-rw-r--r--` and contains `"mnemonic": "..."` (and `"apiToken"` once configured). This was verified with a small script that calls `saveConfig` directly and reads the modes back with `fs.statSync`.

## Suggested fix

- `fs.mkdirSync(dir, { recursive: true, mode: 0o700 })` for `~/.beignet` and for the data directory.
- Write secrets with `{ mode: 0o600 }`. Note that `writeFileSync` on an existing file keeps the file's old mode, so write to a temporary file, `chmod 0o600`, then `rename` over the target (the same shape `beignet-node.ts:711` already uses for its atomic writes).
- On load, if `config.json` is group- or world-readable, either `chmod` it or print a warning naming the file, so existing installs get fixed or at least told.
- Consider the same 0600 treatment for the SQLite database, its WAL and backups, since they are a full history of the node's activity.

---

<!-- 03-csrf-default-daemon.md -->
## Issue: The default no-token loopback daemon can be driven by any web page (CSRF): parseBody ignores Content-Type, nothing validates Origin or Host, and beignet init mints no token

Labels: bug

Found during a security audit of the HTTP daemon.

## Summary

`beignet init && beignet start` leaves the daemon on `127.0.0.1:2112` with authentication disabled: `init` generates a mnemonic but no `apiToken`, and the auth middleware is skipped entirely when no token or key is configured (`daemon.ts:3163`, `if (authenticator.enabled && !authExempt)`). The README documents this as the default ("Auth is off unless you set apiToken or apiKeys ... It binds 127.0.0.1 by default").

The daemon already refuses two dangerous configurations at startup: binding a non-loopback host without auth, and wildcard CORS without auth (`daemon.ts:690-716`). The comment explains the CORS rule as "wildcard CORS without authentication lets any page the operator visits drive those same routes". That protection is incomplete, because CORS only controls whether a page can *read* a cross-origin response. A page can still *send* a state-changing request without any CORS grant:

1. **Simple-request CSRF.** A cross-origin `POST` whose `Content-Type` is `text/plain` (the default for a string body with `mode: 'no-cors'`, or a `<form enctype="text/plain">`) is a CORS-safelisted request: the browser sends it with no preflight. `parseBody` (`daemon.ts:139-185`) never looks at `Content-Type` and JSON-parses whatever bytes arrive, so the body is accepted. The route runs, the side effect happens, and only the response is withheld from the page.
2. **DNS rebinding.** Nothing validates the `Host` header (it is only used as a URL base, see the companion crash issue) and nothing validates `Origin`. A page on `attacker.example` whose DNS answer flips to `127.0.0.1` makes same-origin requests to the daemon and can also **read** the responses: `GET /balance`, `GET /payments` (which carries preimages of outgoing payments), `GET /invoices`, `GET /channels`, and every POST route.

`GET /mnemonic` is the one route that anticipated this: it answers `MNEMONIC_REQUIRES_AUTH` when auth is off (`daemon.ts:1147-1155`). Everything else, including `POST /send`, `POST /send-max`, `POST /invoice/pay`, `POST /keysend`, `POST /channel/forceclose`, `POST /webhooks/register` and `POST /stop`, is reachable.

## Failure scenario

Operator runs the default daemon on their workstation and opens a malicious page while it is running. The page executes:

```js
fetch('http://127.0.0.1:2112/send', {
  method: 'POST', mode: 'no-cors',
  body: '{"address":"bc1q...attacker","amountSats":500000}'
});
```

The request arrives with `Host: 127.0.0.1:2112`, no `Authorization`, and `Content-Type: text/plain;charset=UTF-8`. Auth is disabled, `parseBody` parses the JSON, `POST /send` builds and broadcasts the transaction. The same works for paying an attacker's invoice, force-closing every channel (on-chain fees, funds locked for `to_self_delay`), registering a webhook that leaks every payment's preimage, or stopping the node.

Browser note: recent Chrome versions gate requests from public sites to loopback behind a Local Network Access permission prompt, which reduces but does not remove the exposure (the prompt is granted per site, and non-Chromium browsers have shipped their own protections at different times). The DNS rebinding vector does not depend on that gate at all.

## Where

- `src/cli/daemon.ts:139-185` `parseBody`: no `Content-Type` check.
- `src/cli/daemon.ts:3047-3054`: `Host` used only as a URL base, never validated against the bound address.
- `src/cli/daemon.ts:3065-3079`: CORS headers and OPTIONS handling; `Origin` is never compared to anything on non-preflight requests.
- `src/cli/daemon.ts:3163`: auth is skipped when `!authenticator.enabled`.
- `src/cli/cli.ts:370-396` `handleInit`: no token generated.
- `README.md:477`: documents no-auth as the default.

## Suggested fix (defence in depth, any one of the first three closes the simple-request vector)

1. Require `Content-Type: application/json` on every request with a body and answer 415 otherwise. A JSON content type forces a CORS preflight, and the preflight fails unless `cors` is explicitly configured.
2. On state-changing requests, reject an `Origin` header that is not the configured CORS origin (or reject any `Origin` when `cors` is off): browsers always send `Origin` on cross-origin POSTs.
3. Validate `Host` against the bound address (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`) or a configured allow-list, which closes DNS rebinding.
4. Have `beignet init` mint a random `apiToken` and print it once, so running without authentication becomes an explicit `insecure: true` choice rather than the default, and update the README accordingly.

---

<!-- 04-inbound-half-open-flood.md -->
## Issue: Inbound peer admission: half-open handshakes never count toward maxInboundPeers, and there is no per-IP or socket-level cap, so a flood of stalled handshakes exhausts descriptors and memory

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

---

<!-- 05-bolt1-leniencies.md -->
## Issue: BOLT 1 leniencies on the wire: unknown even TLV types are accepted by init and most BOLT 2 parsers, init networks is never checked, and peer error text is logged verbatim

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

---

<!-- 06-blinded-path-fee-uncapped.md -->
## Issue: A payee-controlled blinded-path fee is paid uncapped and invisibly to maxFeeSats, maxPaymentSats and the daily spend ledger: a 1000-sat offer can drain the payer's outbound liquidity

Labels: bug

Found during a security audit of the payment paths. Reproduced with a script against `findRouteToBlindedPath` and the payer admission code (a direct alice->bob channel, a 1000-sat offer whose `invoice_blindedpay` carries `fee_base_msat = fee_proportional_millionths = 4294967295`):

```
invoice amount (msat):       1000000
HTLC sent by payer (msat):   8590934590 = 8590934 sat
route.totalAmountMsat:       8590934590
route.totalFeeMsat (capped): 0
true fee paid (msat):        8589934590
```

## What the code does

1. `findRouteToBlindedPath` (`src/lightning/gossip/pathfinding.ts:1040-1043`) computes the aggregated blinded fee from the invoice's payinfo, which the payee wrote:
   ```ts
   const blindedFeeMsat =
       BigInt(payInfo.feeBaseMsat) +
       (amountMsat * BigInt(payInfo.feeProportionalMillionths)) / 1_000_000n;
   const amountAtIntro = amountMsat + blindedFeeMsat;
   ```
   and routes `amountAtIntro` to the introduction node. In the self-introduction branch (`:1077`) the returned `totalFeeMsat` includes `blindedFeeMsat`. In the normal grafted branch (`:1112`) it returns `totalFeeMsat: routeToIntro.totalFeeMsat`, i.e. only the public-hop fees, while `totalAmountMsat` and `hops[0].amountToForwardMsat` do include the blinded fee.
2. The BOLT 11 blinded-path branch of `sendPayment` (`src/lightning/node/lightning-node.ts:15614-15616`) caps on `effectiveFeeMsat = selfIntroForCap?.wireRoute.totalFeeMsat ?? blindedRoute.totalFeeMsat`, so an explicit `maxFeeSats` never sees the blinded fee.
3. `payBolt12Invoice` (`lightning-node.ts:27059`) has no fee-cap parameter at all, `BeignetNode.payOffer` does not accept one, and `POST /offer/pay` (`src/cli/daemon.ts:2739-2746`) takes only `{ offer, amountSats, timeoutMs }`.
4. Spend admission for offers opens the daily-budget claim on `paymentSpendSats(bolt12Invoice.amount, amountSats)` (`src/cli/beignet-node.ts:11534`), and `_chargeAsyncSpendClaim` records `charged.sats` (`:9396`), never the amount the HTLC actually carries. `maxPaymentSats` is checked against the same invoice amount.

The introduction node is chosen by the payee (the offer issuer), and a payee can be its own introduction node or collude with it, so the blinded fee is money the payee decides to take from the payer.

## Failure scenario

An agent configured with `maxPaymentSats: 100_000`, `dailySpendLimitSats: 500_000`, and even `maxFeeSats: 10`, calls `POST /offer/pay` for a 1000-sat offer (or pays a beignet-format BOLT 11 invoice carrying blinded paths in tag 25) from a malicious issuer. Every check passes on the 1000-sat figure, the node sends an HTLC of about 8.59 million sats to the introduction node, which claims it, and the daily ledger records 1000 sats spent. The loss is bounded only by outbound liquidity and the first hop's `htlc_maximum_msat`.

## Suggested fix

- Return `totalFeeMsat: routeToIntro.totalFeeMsat + blindedFeeMsat` in the grafted branch so every consumer of the route sees the real fee.
- Thread a `maxFeeMsat` through `payBolt12Invoice`, `BeignetNode.payOffer` and `POST /offer/pay`, with a default cap (see the companion issue on default fee caps) rather than none.
- Admit and charge spend on `route.totalAmountMsat` (amount plus fee), or at least on amount plus the fee cap, instead of the invoice amount alone.
- Add a regression test with an adversarial `invoice_blindedpay`.

---

<!-- 07-bolt12-payer-accepts-any-invoice.md -->
## Issue: The BOLT 12 payer accepts an invoice for any amount, signed by any key, and already expired, when it arrives over our reply path: the issuer can charge whatever it likes

Labels: bug

Found during a security audit of the BOLT 12 offer flow. Reproduced against `OfferManager` with a 1000-sat offer:

```
1000x overcharge signed by issuer: ACCEPTED (requested=1000000 msat, invoice amount=1000000000 msat)
invoice signed by a NON-issuer key:  ACCEPTED (nodeId==issuer? false)
invoice created 10 days ago:         ACCEPTED
```

## What the code does

`handleIncomingInvoice` (`src/lightning/offer/offer-manager.ts:1209-1290`) validates an invoice that arrives over one of our blinded reply paths with `settle()`, which runs only:

- `verifyInvoiceSignature` under the invoice's own `invoice_node_id` (so any key that signs its own invoice passes),
- `invoice_paths` non-empty and one `invoice_blindedpay` per path,
- `mirrorReason`: the invreq-range fields (types 0-159) byte-match what we sent.

It never compares `invoice_amount` (type 170) with the `invreq_amount` we sent (type 82) or with `offer_amount * quantity`; never checks `invoice_node_id` against the offer's issuer id or the blinded path's terminal key (`invoiceSignerMatchesOffer` at `:1064` is only consulted on the legacy no-path_id branch at `:1315`); and never checks `invoice_created_at + invoice_relative_expiry` against the current time. `BeignetNode.payOffer` (`src/cli/beignet-node.ts:11534-11598`) then admits and pays `bolt12Invoice.amount`.

BOLT 12, reader of an invoice: "if `invreq_amount` is present: MUST reject the invoice if `invoice_amount` is not equal to `invreq_amount`"; "MUST reject the invoice if `invoice_node_id` is not equal to `offer_issuer_id`" (or the final blinded node id when the offer uses paths); "MUST reject the invoice if the current time is after `invoice_created_at` plus `invoice_relative_expiry`". `requestInvoice` (`:636-648`) always sends `invreq_amount` when the offer has an amount, so the equality rule applies to every priced offer we pay.

## Failure scenario

An agent calls `POST /offer/pay` for a 1000-sat offer. The issuer answers with an invoice for 1,000,000 sats. The only thing between the payer and the loss is `maxPaymentSats` if the operator configured one, and the companion blinded-fee issue shows that even that check can be bypassed. A third party who can inject onion messages onto our reply path (the introduction node of our reply path, for instance) can also substitute its own invoice with its own payment hash, since the signer is not bound to the offer.

## Suggested fix

In `settle()` (or in `payOffer` before dispatch): reject when `invoice.amount !== sentInvreqAmount` (falling back to `offer.amount * quantity`, and requiring an explicit caller amount for amountless offers), reject when `!invoiceSignerMatchesOffer(invoice, offer)`, and reject when `now > createdAt + relativeExpiry`. Emit `invoice:error` with the reason as the legacy branch does.

---

<!-- 08-bolt12-issuer-mints-any-amount.md -->
## Issue: The BOLT 12 issuer mints an invoice for whatever invreq_amount the payer sends (1 msat on a 100k-sat offer) and ignores quantity and offer_quantity_max

Labels: bug

Found during a security audit of the BOLT 12 offer flow. Reproduced against `OfferManager.handleInvoiceRequest` with a 100k-sat offer, `quantity_max = 10`:

```
invreq_amount = 1 msat:                         ISSUED invoice amount=1 msat
no invreq_amount, quantity 5 (expect 500k sat): ISSUED invoice amount=100000000 msat (unit price)
invreq_amount 1 msat, quantity 1000 (> max 10): ISSUED invoice amount=1 msat
```

## What the code does

After the signature, offer_id, path_id and expiry checks, `handleInvoiceRequest` picks the amount with (`src/lightning/offer/offer-manager.ts:860`):

```ts
const amount = request.amount ?? matchedOffer.amount;
```

There is no lower bound against `offer_amount`, no multiplication by `invreq_quantity`, and no `offer_quantity_max` or `invreq_chain` checks (`quantity` appears in the file only on the payer side, `:636-648`). The issued invoice is registered through `invoice:issued` (`src/lightning/node/lightning-node.ts:27253-27300`) with `amountMsat: invoice.amount`, so the receive path later settles a 1-msat HTLC as full payment of the offer and emits the normal `payment:received`.

BOLT 12, writer of an invoice (the issuer): "MUST fail the request if `invreq_amount` is present and less than `offer_amount` times `invreq_quantity` (or 1)"; "if `offer_quantity_max` is present: MUST fail the request if there is no `invreq_quantity` field, or if `invreq_quantity` is greater than `offer_quantity_max`; otherwise MUST fail the request if there is an `invreq_quantity` field".

## Failure scenario

A merchant publishes a fixed-price offer for 100k sats. A payer sends an `invoice_request` with `invreq_amount = 1` msat. The merchant's node issues an invoice for 1 msat, receives 1 msat, and emits `payment:received` for that offer; any automation keyed on the offer id ships the goods. Quantity-priced offers likewise get paid the unit price for any quantity.

## Suggested fix

Refuse `request.amount < offer.amount * (request.quantity ?? 1n)`; when the request omits an amount, use `offer.amount * quantity`; enforce the `offer_quantity_max` rules and the chain rule; answer with an `invoice_error` on refusal, as the "Amount required" branch already does.

---

<!-- 09-fees-outside-spend-limits.md -->
## Issue: Routing fees are outside maxPaymentSats and the daily spend ledger, and the pay routes apply no fee cap by default, so a route hint can spend millions of sats past the configured limits

Labels: bug

Found during a security audit of the spending-limit enforcement. This is a distinct root cause from the blinded-path issue (there the route's reported fee is wrong; here the fee is reported correctly but nothing bounds it by default and nothing charges it).

## What the code does

- `payInvoice` opens the daily-budget claim and checks `maxPaymentSats` on `paymentSpendSats(decoded.amountMsat, amountSats)` (`src/cli/beignet-node.ts:10117`), the invoice amount. The same holds for `sendPaymentAsync` (`:10436`, `:10463`) and `payOffer` (`:11534`). `_chargeAsyncSpendClaim` records `charged.sats` (`:9396`), never the settled `feeMsat`.
- `resolveMaxFeeMsat` (`:1255-1275`) returns `undefined` when the caller sends neither `maxFeeSats` nor `maxFeeMsat`, and every fee check in `LightningNode.sendPayment` is of the form `if (maxFeeMsat !== undefined && fee > maxFeeMsat)`. `POST /invoice/pay`, `/invoice/pay-safe` and `/invoice/pay-async` (`src/cli/daemon.ts:1992-2046`) make `maxFeeSats` optional. There is no default fee cap constant anywhere (`grep -rn "DEFAULT_MAX_FEE\|maxFeePercent" src` is empty). `POST /channel/rebalance` (`:1254`) deliberately requires a cap ("fee-spending endpoints never guess a cap"); the pay routes do not follow that rule.
- A BOLT 11 `r` route hint's `fee_base_msat` and `fee_proportional_millionths` are u32 fields decoded straight off the invoice (`src/lightning/invoice/decode.ts:275-276`) and become a synthetic edge the router must use to reach a hint-only destination; `findRoute` correctly includes that fee in `totalFeeMsat` (`pathfinding.ts:666`), so an explicit cap works, but nothing applies one by default.

`docs/AI_AGENT_GUIDE.md:230` promises `maxPaymentSats: 100_000, // Reject any single payment over 100k sats`, and the README lists the two limits as the recommended production safeguards. Fees are not covered by either.

## Failure scenario

Node configured with `maxPaymentSats: 10_000` and `dailySpendLimitSats: 50_000`. An agent pays a 1000-sat invoice (no `maxFeeSats`, as in every README example) whose route hint names the attacker's private channel with `fee_base_msat = 4294967295`. The hint is the only path to the destination, so the router builds a route with a 4,294,967-sat fee, the HTLC leaves, the attacker's hop keeps the fee, and both limits saw 1000 sats. Repeatable until liquidity runs out; the ledger never learns.

## Suggested fix

- Apply a default fee cap on every pay path when the caller does not supply one (other implementations default to a percentage of the amount with a small absolute floor, for example 1% with a 50-sat floor, or refuse fees above 5%), and document it.
- Include the fee in spend admission and in the ledger: open the claim on amount plus the fee cap, and charge the settled amount plus `feeMsat`, so `maxPaymentSats` and `dailySpendLimitSats` mean what the docs say.
- Consider bounding route-hint fees independently (for example refuse a hint whose fee exceeds the cap before routing), so a hostile invoice fails fast with a clear error.

---

<!-- 10-l402-redirect-ssrf.md -->
## Issue: POST /l402/fetch follows redirects into private targets before the private-network guard re-runs (blind SSRF from the node's machine)

Labels: bug

Found during a security audit of the L402 client.

## What the code does

`BeignetNode.l402Fetch` (`src/cli/beignet-node.ts:10805-10838`) runs `_assertL402TargetAllowed(url)` on the caller's URL, then calls `l402Fetch`, which uses the global `fetch` with its default redirect policy (`src/lightning/l402/client.ts:206-233`; `withTimeout(withAuthorization(init, credential), options)` sets no `redirect`). Node's fetch follows up to 20 redirects, and 307/308 preserve the method and body. Only after the whole chain has been followed does the code check `result.response.url`, and that check only refuses to relay the body: the comment at `:10830` acknowledges "a redirect can land on a host the caller never named".

`isPrivateNetworkUrl` (`client.ts:596-609`) documents that name-based checks cannot stop DNS rebinding; that is a separate, known limitation. This issue is about redirects, which the code can control.

## Failure scenario

An admin-scoped caller (or the CSRF/no-token scenario in the companion daemon issue) sends `POST /l402/fetch {"url":"https://attacker.example/x","method":"POST","body":"..."}`. The attacker's server answers `307 Location: http://169.254.169.254/latest/api/token` or `http://127.0.0.1:2112/...` or an internal admin service. The node's fetch performs the caller's POST against the internal target with the caller's body. The caller receives `PRIVATE_NETWORK_REFUSED`, but the side effect has already happened. Node's undici strips `Authorization` on cross-origin redirects, so the L402 credential itself does not leak; the SSRF is blind.

## Suggested fix

Pass `redirect: 'manual'` and, on a 3xx, run `_assertL402TargetAllowed` on the `Location` target before following it (with a hop limit), or refuse redirects entirely for this endpoint. Apply the same check to the challenge-following code path.

---

<!-- 11-bolt11-payer-leniencies.md -->
## Issue: BOLT 11 payer leniencies: mixed-case invoices decode, an invoice for another network is paid, and lnbc0m produces a zero-amount HTLC

Labels: bug

Found during a security audit of the BOLT 11 decode and pay paths. Reproduced with a script against `decodeInvoice` and `hrpAmountToMsat`:

```
mixed-case string: ACCEPTED
lnbc0m: decoded amountMsat=0
lnbc0:  decoded amountMsat=0
```

## 1. Mixed-case bech32 strings are accepted

`decode` lowercases the string before calling `bech32.decode` (`src/lightning/invoice/decode.ts:44-46`), which defeats the library's mixed-case rejection. BIP 173: decoders MUST reject strings that mix upper and lower case (the checksum is only defined on a single case; a mixed-case string is by construction a corrupted or hand-edited one).

Fix: pass the original string to `bech32.decode`, or reject when the string differs from both its lower- and upper-cased forms.

## 2. An invoice for a different network is paid

Neither `LightningNode.sendPayment` (`src/lightning/node/lightning-node.ts:15486-15530`) nor `BeignetNode.payInvoice`/`payOffer` compares the decoded `invoice.network` (or an offer's `offer_chains`) with the node's own chain; `grep` finds no such comparison. A mainnet node handed an `lntb`/`lnbcrt`/`lntbs` invoice routes real sats to whichever mainnet node holds the invoice's node id. Test setups commonly reuse node keys across networks, so the payment can succeed and go to a node that was never meant to receive mainnet funds. LND, CLN and LDK refuse to pay an invoice for another chain.

Fix: refuse in `sendPayment` (and in the daemon's decode/validate routes, so the caller learns it before paying) when `invoice.network !== this.network`, and refuse offers whose `offer_chains` does not contain ours.

## 3. A zero-amount HRP becomes a zero-amount HTLC

`hrpAmountToMsat` accepts `0m` and `0` (`src/lightning/invoice/amount.ts:79, 97-100` only reject leading zeros on multi-digit strings), so `lnbc0m...` decodes with `amountMsat = 0n`. `sendPayment` treats `0n` as a fixed amount, `paymentSpendSats` returns 0 so spend admission is skipped, and `Channel.addHtlc` (`src/lightning/channel/channel.ts:3165`) only refuses `amount < remote htlc_minimum_msat`. When the first-hop peer advertises `htlc_minimum_msat = 0` (Core Lightning's default) a 0-msat `update_add_htlc` goes out. BOLT 2: a receiver of `amount_msat == 0` SHOULD send a warning and close the connection or fail the channel. The same happens with `amountSats: 0` on an amountless invoice.

Fix: reject `amountMsat <= 0n` in the decoder (BOLT 11 amounts are positive), in `sendPayment`, and as a belt-and-braces check in `addHtlc`.

---

<!-- 12-bolt12-reader-musts.md -->
## Issue: BOLT 12 invoice_request and invoice decoders skip the reader MUSTs the offer decoder already applies: no known-type set, no range check, unknown required features accepted, invoice_node_id not validated as a point

Labels: bug

Found during a security audit of the BOLT 12 codec. Spec conformance, no direct fund loss on its own; it is the same class of gap as the companion BOLT 1 TLV issue.

## What the code does

`decodeOfferTlv` passes `OFFER_KNOWN_TYPES` to `decodeTlvStream` and checks the offer type ranges. `decodeInvoiceRequestTlv` (`src/lightning/offer/tlv.ts:390-440`) and `decodeInvoiceTlv` (`:540-610`) call `decodeTlvStream(data)` with no known-type set, so an unknown even (required) type is accepted; neither checks that types fall in the invoice_request range (0-159 plus the experimental range) or the invoice range (0-239 plus experimental); neither rejects unknown even bits in `invreq_features` / `invoice_features`; and `invoice_node_id` is not checked to be a valid point before signature verification (a bad length throws inside `toXOnlyPubkey`, which `handleMessage`'s try/catch contains, so it is not a crash, only an unclear refusal).

BOLT 12 readers: "MUST fail the request/invoice if any non-signature TLV field is outside the allowed ranges", "MUST fail if any unknown even TLV field is present", "MUST fail if `invreq_features`/`invoice_features` contains unknown even bits".

## Failure scenario

We issue an invoice against, or pay an invoice carrying, a required feature or field we do not understand, where a conforming node would refuse and send `invoice_error`. The counterparty may then rely on semantics we silently ignore.

## Suggested fix

Mirror the offer decoder: define the known even-type sets for invoice_request and invoice, check the ranges, run `hasUnsupportedRequiredFeatures` on both feature fields, and `isValidPublicKey(nodeId)` before verifying the signature.

---

<!-- 13-forwarder-no-expiry-too-soon.md -->
## Issue: The forwarder never applies expiry_too_soon: an HTLC whose outgoing cltv_expiry has already passed is relayed, and a beignet downstream answers by failing the channel, so one HTLC force-closes a channel between two beignet nodes

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

---

<!-- 14-gossip-reply-channel-range-unbounded.md -->
## Issue: Unsolicited reply_channel_range messages are accumulated without bound or state check: a connected peer grows the daemon's heap by ~12x its wire bytes until the process dies

Labels: bug

Found during a security audit of gossip sync. Reproduced with a script: 300 `reply_channel_range` messages (19.7 MB on the wire) added 247 MB to the heap while the sync manager's state stayed IDLE.

## What the code does

`GossipSyncManager.handleReplyChannelRange` (`src/lightning/gossip/gossip-sync.ts:117-127`):

```ts
const scids = decodeShortChannelIds(msg.encodedShortIds);
this._accumulatedScids.push(...scids);
if (!msg.syncComplete) {
    return [];
}
```

It never checks that the manager is in `AWAITING_RANGE_REPLY`, that the reply's `chain_hash` and range match a query we sent, or that the accumulated list has a ceiling. Each 65 KB message decodes into up to 8191 separate 8-byte Buffers. The node routes every `reply_channel_range` to the peer's sync manager whenever one exists (`src/lightning/node/lightning-node.ts:14769-14778`), and `getOrCreateSyncManager` creates one for ANY peer that sends a `query_channel_range` (`:14791-14797`, `:14912-14919`). There is no inbound message rate limit at the transport layer.

## Failure scenario

A peer completes the handshake (no channel needed), sends one `query_channel_range` to obtain a sync manager, then streams `reply_channel_range` with `sync_complete = 0`. A few hundred megabytes of traffic OOM-kills the daemon. A dead node cannot claim inbound HTLCs before their timeouts or react to a breach.

## Suggested fix

Drop `reply_channel_range` unless `_state === AWAITING_RANGE_REPLY` and the reply echoes our query's chain hash and range; cap `_accumulatedScids` (for example 200k entries, deduplicated) and abort the sync when exceeded; discard sync managers for peers that never initiated or received a sync.

---

<!-- 15-unverified-gossip-drives-pathfinding.md -->
## Issue: Pathfinding routes over channel_updates and announcements whose signatures were never verified (lazy gossip mode, the default): any connected peer can rewrite the policy of any channel in our graph

Labels: bug

Found during a security audit of gossip handling. This is a consequence of the verify-on-serve design from #443 and the admission hardening of #446 that those issues do not appear to have weighed: deferred verification is fine for what we SERVE, but the router CONSUMES the deferred rows as if they were real.

## What the code does

- `eagerGossipVerify` defaults to `false` (`src/lightning/node/lightning-node.ts:1574`).
- `handleChannelUpdate` (`:15104-15150`) skips `verifyChannelUpdate` unless eager mode is on or the update names one of our own channels, and stores the row with `verified: 'deferred'`. `handleChannelAnnouncement` (`:14941-14980`) admits an announcement with no signature check and no funding-output check.
- `NetworkGraph.applyChannelUpdate` (`src/lightning/gossip/network-graph.ts:371-431`) lets a newer timestamp replace a slot even when the existing slot was verified; timestamps up to one hour in the future are accepted.
- `findRoute` reads `update1`/`update2` with no `*Verified` filter (`src/lightning/gossip/pathfinding.ts:494`, `:841`). Rows are persisted through `saveGossipChannel`, so forged rows survive restarts.

## Failure scenario

Peer P (any node we accept gossip from) sends unsigned `channel_update`s with `timestamp = now + 3599` for every channel adjacent to our usual destinations except its own, either with the disable bit set or with `fee_base_msat = 2^32 - 1`. Dijkstra now prefers P (fee extraction, privacy loss), or pays honest hops the forged inflated fee (they keep the excess; bounded only by the payer's fee cap, which has its own gaps in the companion issues), or finds no route at all. Real, signed updates with lower timestamps are refused as "not strictly newer" for up to an hour, and P re-forges hourly. Fake `channel_announcement`s with random signatures fill the graph to `MAX_CHANNELS = 100_000` and are persisted.

## Suggested fix

Verify a `channel_update`'s signature before it can displace a slot that pathfinding reads (one ECDSA per update for channels we already hold is cheap with the node:crypto fast path), or exclude `deferred` rows from routing until they are verified; rate-limit unverified admissions per peer; add a UTXO and amount check (or at least signature verification) before an announcement is persisted.

---

<!-- 16-malformed-htlc-relay-and-failure-leniencies.md -->
## Issue: BOLT 4 failure handling gaps: a downstream update_fail_malformed_htlc is relayed upstream as an undecryptable 4-byte blob, an unparseable onion is failed with update_fail_htlc under a zero key, and four smaller onion edge cases

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

---

<!-- 17-staged-send-replayed-after-restart.md -->
## Issue: A persisted multi-recipient staged send is replayed into every later send after a restart: POST /send for 50k sats pays the previous sendMany's recipients again (double payment, outside the daily limit)

Labels: bug

Found during a security audit of the on-chain wallet. Reproduced with a script that drives `Transaction` over a wallet whose stored `transaction` blob holds a previous three-output send:

```
outputs the PSBT will carry: [ 'bcrt1qy8lq7z=50000', 'bcrt1qw508d6=200000', 'bcrt1qc7slrf=300000' ]
total paid to recipients: 550000 (user asked for 50000)
```

## What the code does

There are two copies of the staged send:

1. The live `Transaction._data`, which starts empty on every boot and is what `resetSendTransaction` (`src/transaction/index.ts:210-214`) resets: `this._data = getDefaultSendTransaction(); await this._wallet.saveWalletData('transaction', this._data)`.
2. The wallet's `_data.transaction`, loaded from storage in `setWalletData` (`src/wallet/index.ts:1146`, `this._data = walletDataResponse.value`). `saveWalletData` (`:3235`) hands the value to the storage adapter and never assigns `this._data[key]`, and no other code assigns `_data.transaction` (grep), so this snapshot is frozen at boot.

`setupTransaction` seeds a new send's outputs from the frozen snapshot (`src/transaction/index.ts:145`):

```ts
outputs = outputs || currentWallet.transaction?.outputs || [];
```

removing only our own change addresses. `updateSendTransaction` (`:1237-1245`) overwrites only the indexes it is given (`outputs[output.index] = output`). `sendMany` (`wallet/index.ts:4805-4870`) and `buildPsbt` (`:4998`, reset only at the start) leave the recipients in storage after a successful build or broadcast, and `BeignetNode.sendOnchain` (`src/cli/beignet-node.ts:6090-6133`) resets only on a refused spend limit, not after success.

## Failure scenario

Session 1: `sendMany([A:100k, B:200k, C:300k])` or `POST /psbt/build` with three outputs. Storage now holds `transaction.outputs = [A, B, C]`.

Restart (the daemon with SQLite storage, or any library host that passes `storage`).

Session 2: `POST /send {address: D, amountSats: 50000}`. `send()` resets the live copy, `setupTransaction` seeds `[A, B, C]` from the frozen snapshot, `updateSendTransaction` overwrites index 0 with D, `validateTransaction` passes, and a transaction paying D 50k, B 200k and C 300k is signed and broadcast. Because the snapshot never changes, EVERY later send in that session pays B and C again until the balance is gone. `_builtOnchainTotalSats` (`beignet-node.ts:9691`) counts only amount plus fee, so the extra 500k also bypasses `dailySpendLimitSats`. `POST /tx/bump-fee` inherits it through `setupRbf` (`transaction/index.ts:1643-1660` also merges by index); `sendMax` and `consolidate` fail with "Outputs are spending more than Inputs" instead of overpaying.

## Suggested fix

- Never seed outputs from `wallet.data.transaction`: start from `[]` unless outputs are passed explicitly.
- Reset the staged transaction at the start of `sendMany`, `buildPsbt` and `setupRbf`, and after every successful broadcast.
- Either keep `_data.transaction` in sync in `saveWalletData` or drop the snapshot entirely.
- Add a regression test: build a multi-output send, reload the wallet from the same storage, send a single-output transaction, and assert the output set.

---

<!-- 18-utxo-value-trusted-fee-overpay.md -->
## Issue: The server-reported UTXO value is used for fee and change while the signature commits to the real amount, so a lying or MITM Electrum server makes the wallet overpay fees by up to ~5000 sat/vB times the transaction size

Labels: bug

Found during a security audit of transaction building. Reproduced with a script: a 1,000,000-sat P2WPKH coin reported by the server as 500,000; a 200,000-sat send at 10 sat/vB signs, validates against the real amount, and pays 501,410 sats in fees instead of 1,410:

```
valid against REAL amount (network view): true
valid against REPORTED amount: false
outputs sum 498590 real fee paid 501410 sats; intended fee 1410 ; vsize 141 effective sat/vB 3556
```

## What the code does

- Change is computed as balance minus outputs minus fee from `input.value` (`src/transaction/index.ts:698-715`), where the value came from the server's `listunspent` (`src/electrum/index.ts:1329`) or, for RBF, from the server's JSON `vout` values (`src/wallet/index.ts:5563`).
- `addInput` (`transaction/index.ts:1027-1068`) sets `witnessUtxo.value = input.value` AND spreads `...(await this.nonWitnessUtxoField(input.tx_hash))` for p2wpkh, p2sh-p2wpkh and p2wsh inputs (for hardware-signer compatibility). bitcoinjs-lib 6.1.4 prefers `nonWitnessUtxo` when both are present (`node_modules/bitcoinjs-lib/src/psbt.js:1205-1222`), so the BIP143 amount commitment is computed over the REAL prevout value and the signature is valid on the network. p2pkh inputs use `nonWitnessUtxo` only. Nothing compares `input.value` with `prevTx.outs[tx_pos].value` even though the previous transaction is already in hand.
- The only remaining bound is bitcoinjs's default `maximumFeeRate` of 5000 sat/vB at `extractTransaction`.
- The Electrum transport accepts any TLS certificate (`node_modules/rn-electrum-client/lib/TlsSocketWrapper.js:72` and `lib/init_socket.js:21`, `rejectUnauthorized: false`, with no pinning option in beignet), so an on-path attacker can play the lying server against the default `fulcrum.bitkit.blocktank.to` endpoint.

P2TR inputs are safe: BIP341 signs the reported amount, so a mismatch makes the transaction invalid rather than expensive.

## Failure scenario

Default p2wpkh wallet. The server (or a MITM) under-reports a coin's value. Every send from that coin overpays its fee by the difference, up to the point where the effective rate reaches 5000 sat/vB; a 50-input consolidation at ~3.5 kvB can lose about 17M sats in one transaction. The transaction relays and confirms, so there is no recovery. An attacker who mines (or sells the opportunity to a miner) profits directly; otherwise the user simply loses the difference to whichever miner includes it.

## Suggested fix

- In `addInput` / `nonWitnessUtxoField`, parse the fetched previous transaction and refuse the input unless `outs[tx_pos].value === input.value` and the script matches; cross-check the same way in `getUtxos` when previous transactions are fetched, and in `getRbfData`.
- Call `psbt.setMaximumFeeRate` with a wallet ceiling (the requested rate times a small margin, capped by `MAX_FEE_RATE_SAT_PER_VBYTE`) before `extractTransaction`, so no path can sign a fee far above what the user asked for.
- Separately, give operators a way to verify the Electrum server: honour CA verification for hosts with real certificates and/or pin the server certificate on first use, instead of the client library's unconditional `rejectUnauthorized: false`.

---

<!-- 19-sweep-private-key-written-to-storage.md -->
## Issue: sweepPrivateKey and addExternalInputs write the swept private key into wallet storage through the staged transaction blob

Labels: bug

Found during a security audit of the on-chain wallet. Reproduced with a script that runs `sweepPrivateKey` against an in-memory `TStorage`:

```
saved key=transaction bytes=952 contains "__D"=true contains raw private key bytes=true
private key hex f5bd857703431488799ce8672f52fd1bcde821c1dbbfed17958d4583c58137f5
```

`README.md:287` promises that "no private keys and no mnemonic are ever written, so exposure is a privacy concern (full wallet history), not fund loss".

## What the code does

`sweepPrivateKey` (`src/wallet/index.ts:6096-6108`) attaches the ECPair to every swept coin and hands the list to the transaction builder:

```ts
utxos = utxos.map((utxo) => ({ ...utxo, keyPair }));
await this.transaction.setupTransaction({ satsPerByte, utxos, outputs: [...] });
```

`setupTransaction` and every `updateSendTransaction` persist the whole staged transaction with `saveWalletData('transaction', this._data)` (`src/transaction/index.ts:181`, `:201`, `:212`, `:1253`). The storage adapters `JSON.stringify` the value (`src/cli/wallet-storage.ts:47`, `src/utils/wallet-storage-encryption.ts:69`), which serialises the key pair's private `__D` buffer. `addExternalInputs` (`transaction/index.ts:1120-1160`) attaches `keyPair` the same way. The wallet already strips `keyPair` for frozen entries (`wallet/index.ts:2904-2906`) but not here, and the sweep never resets the staged transaction afterwards, so the key stays in storage until another send overwrites the blob.

## Failure scenario

A library host following the README (plain `storage`, described as privacy-only) sweeps a paper wallet with `broadcast: false`, or the broadcast fails. The private key of the swept coin sits in the host's database and backups indefinitely; anyone who reads that storage spends the coin. Under the daemon the blob is encrypted with a seed-derived key, which reduces but does not remove the exposure (the README's promise is about the unencrypted default).

## Suggested fix

Strip `keyPair` (and any signer object) before every `saveWalletData('transaction', ...)`; keep external signers in a non-persisted map keyed by outpoint; reset the staged transaction after a sweep. Add a test that asserts the persisted transaction blob never contains a private key.

---

<!-- 20-setup-transaction-fallback-spends-all-coins.md -->
## Issue: setupTransaction silently selects every wallet coin when inputTxHashes matches nothing, and CPFP boost inherits it: a boost can turn into a full-wallet self-send at a high fee rate

Labels: bug

Found during a security audit of the on-chain wallet. Reproduced with a script: a CPFP set up for parent `aaaaaaaa` whose outputs are not spendable selected the wallet's other coins instead:

```
requested inputs from tx aaaaaaaa -> selected inputs: [ '11111111:0=1000000', '22222222:0=2000000' ]
input total 3000000 fee at 20 sat/vB 3560
```

## What the code does

`setupTransaction` (`src/transaction/index.ts:93-115`) filters the wallet's UTXOs by `inputTxHashes`; when the filter is empty it falls back first to the inputs of the persisted snapshot and then to `removeBlackListedUtxos(currentWallet.utxos)`, i.e. every non-frozen coin. `setupCpfp` (`:1544`) passes `inputTxHashes: [txid]`. `canBoost` (`src/wallet/index.ts:6238-6280`) only requires a matched output of at least 768 sats, and `_boostCpfp` (`src/cli/beignet-node.ts:6649-6680`) builds and broadcasts. Sibling of the closed #229 (a different path to the same consolidation).

## Failure scenario

Unconfirmed parent P whose only output to us is frozen by the user, already spent by our own second pending transaction, or not yet scanned. `POST /tx/boost P`: `canBoost` says CPFP, `setupCpfp` finds no matching UTXO, falls back to ALL coins, and sends the whole wallet to its own address at `max(1, ceil((fast * (vsizeP + 141) - feeP) / 141))` sat/vB. With 20 coins and `fast = 50` that is about 1.4 kvB at roughly 99 sat/vB, around 139,000 sats, for a transaction that in the frozen case does not even descend from P: no boost, a forced consolidation, and a privacy loss.

## Suggested fix

When `inputTxHashes` is given and nothing matches, return an error instead of falling back; `setupCpfp` should refuse when the parent has no spendable output of ours; consider making the generic fallback opt-in.

---

<!-- 21-psbt-external-signer-checks.md -->
## Issue: External-signer PSBT flow: change outputs carry no derivation metadata, and importSignedPsbt never verifies that the inputs and outputs it finalizes are the ones the wallet built

Labels: bug

Found during a security audit of the PSBT flow.

## What the code does

- `createUnsignedPsbt` adds outputs with address and value only (`src/transaction/index.ts:781-812`); `addSignerMetadata` (`:882-960`) annotates inputs but not outputs, so a hardware signer cannot recognise the change output as its own and shows it as an ordinary second recipient.
- `importSignedPsbt` (`src/wallet/index.ts:5084-5125`) validates partial signatures, `continue`s past already-finalized inputs (`:5096-5097`) with no check, and never compares the PSBT's inputs and outputs (scripts, values) against the staged build in `this.transaction.data` before finalizing and returning the transaction.

## Failure scenario

The point of an external signer is a compromised host or transport. Between build and sign, the change output (usually the bulk of the coins) is rewritten to the attacker's address. Without output derivation metadata the device shows it as a normal second recipient, the user approves the amounts they expected to see, `importSignedPsbt` finalizes, and the change is gone. A PSBT with pre-finalized inputs is accepted without any signature validation at all.

## Suggested fix

Add `bip32Derivation` / `tapBip32Derivation` to change outputs in `createUnsignedPsbt`; in `importSignedPsbt` compare every input and output against the staged build (or a caller-supplied expected set) and refuse on any mismatch; reject or re-verify already-finalized inputs.

---

<!-- 22-wallet-small-bugs.md -->
## Issue: On-chain wallet small bugs: sendMax prices its output as the wallet's own address type, and getRbfData's "already confirmed" guard reads the request echo instead of the transaction

Labels: bug

Found during a security audit of the on-chain wallet. Two low-severity correctness items.

## 1. sendMax prices the single output as the wallet's own address type

`getMaxSendAmount` runs with `outputs = []` (`src/transaction/index.ts:325-331`, `:1376-1400`), so `increaseAddressCount` uses `this._wallet.addressType`. A p2wpkh wallet sweeping to a p2tr or p2wsh address prices a 31 vB output but builds a 43 vB one: a 1-in-1-out sweep is priced at 110 vB and built at 122 vB, about 10% below the requested fee rate. Slower confirmation, no loss.

Fix: include the recipient in the outputs used for pricing before computing the maximum.

## 2. getRbfData's confirmation guard never fires

`src/wallet/index.ts:5549` checks `tx.value.data[0].data.height > 0`, but `data` is the request object `{ tx_hash }` the wallet itself passed (rn-electrum-client tags each result with `argz[id].data`), so `height` is always undefined. The only gate is `canBoost`'s locally stored height; a parent that confirmed since the last refresh gets a pointless self-send at about 1.5x the fast rate (CPFP) or a replacement the node rejects (RBF).

Fix: look up the boosted transaction's own confirmation freshly in `setupRbf` / `setupCpfp`.

---

<!-- 23-reverse-swap-funding-handed-out-after-hold-cancel.md -->
## Issue: Reverse swap provider: a funding transaction that never relayed is still handed to the client by SWAP_STATUS after the hold invoice was cancelled, and retried broadcasts never re-judge the margins, so the client can claim the on-chain funds with nothing paid

Labels: bug

Found during a security audit of the swap engines. Both paths below were reproduced on the real `ReverseSwapEngine` with the project's test harness (`swaps.test.ts` shape): final state `EXPOSED`, preimage recorded, hold settled 0, funding bytes served by status.

## What the code does

- `processFunding` sets `fundingBroadcastAttemptedAt` and calls `broadcast()`. If the broadcast throws and the funding is not seen on chain, the row stays `FUNDING` and every later pass skips the "judge the hold again, live" block because the marker is already set (`src/lightning/swaps/reverse-engine.ts:1313-1348`, `if (!current.fundingBroadcastAttemptedAt) { ... admissionProblem ... }`), then rebroadcasts the same bytes (never fee-bumped).
- `handleStatus` returns the signed funding bytes whenever `fundingBroadcastAttemptedAt !== undefined` (`:834-839`), with no check of the row's state or whether the hold still exists:
  ```ts
  const fundingTx = record.fundingTxHex && record.fundingBroadcastAttemptedAt !== undefined && ... ? Buffer.from(record.fundingTxHex, 'hex') : undefined;
  ```
- When the held-invoice sweeper (or `POST /invoice/cancel-hold`, which has no swap awareness, `src/cli/daemon.ts:1980-1985`) cancels the hold, `onHoldCancelled` moves the `FUNDING` row to `EXPOSED` and keeps the bytes (`:915-937`, "one that threw may still have propagated: treat the bytes as out"). `EXPOSED` rows are watched but never rebroadcast, and their inputs stay pledged (`:1408-1414`, `:1507-1518`), which is exactly what keeps the signed transaction valid indefinitely.

## Failure scenarios

1. Create, client pays the hold invoice, funding is built, every broadcast is refused (mempool minimum fee above the funding's rate, chained-unconfirmed rejection, or a misbehaving backend). The sweeper cancels the hold at `cancelHeight` and the client's Lightning payment is failed back. The row is `EXPOSED`. The client sends `SWAP_STATUS_REQUEST`, receives the signed funding bytes, broadcasts them itself when fees drop, and claims with the preimage it owns. The provider is out `onchainSat`; the bytes stay valid while the inputs are pledged, and status keeps answering forever because the row is non-terminal.
2. Broadcasts fail until well past the refund height and then succeed in the same block the sweeper cancels the hold (the engine's block pass runs before the held sweeper, `src/lightning/node/lightning-node.ts:25318-25340`). The row goes `FUNDING_BROADCAST` -> `EXPOSED` with the coins in the mempool; an honest client's ordinary claim logic takes them. A fresh `validateReverseSwapAdmission` at that height would have refused (`refundHeight <= currentHeight + fundingSafetyBlocks`), but the retry never runs it.

The precondition is a funding that fails to relay for roughly the whole hold window (150+ blocks with defaults). The funding is never rebuilt at a higher fee and the daemon does not expose the 200 sat/vB clamp, so a prolonged fee spike or a backend outage is enough, and once it happens the loss is deterministic.

## Suggested fix

- In `handleStatus`, hand out `fundingTx` only while the hold is still open (never for `EXPOSED` rows or once `holdCancelledAt` is set), or once the chain shows the funding.
- On every retry whose funding is not seen on chain, re-run the live admission judgement; on refusal stop broadcasting and keep watching.
- On `FUNDING -> EXPOSED` with no funding seen, prefer a conflicting spend of the inputs back to the wallet over keeping them pledged.

---

<!-- 24-swap-provider-hardening.md -->
## Issue: Swap provider hardening: hold-invoice CLTV ignores the client's preferred refund delta, unpaid creates count toward the concurrency cap, stranded rows never resolve, and the client helper does not bound the hold invoice's final CLTV

Labels: bug

Found during a security audit of the swap engines. Four low-severity items, none with direct fund loss, all reproduced or traced.

## 1. `preferredRefundDelta` above ~152 is quoted, paid, then refused

The contract's `refundHeight` honours the client's preferred delta (clamped to [72, 288], `src/lightning/swaps/reverse-engine.ts:698`), but the hold invoice's `min_final_cltv_expiry` is computed from the fixed default (`:743-747`, `refundDeltaBlocks + resolutionSafetyBlocks + holdCancelSafetyBlocks + 8`). Admission needs `earliestExpiry - 18 > refundHeight + 24` (`:1096-1110`, `policy.ts:159-167`). With defaults, preferred deltas 144-152 are admitted; 160, 200 and 288 are `REFUSED: Reverse incoming HTLCs must outlive refund resolution and hold cancellation margins` after the client already paid the hold, and the swap is cancelled. A documented protocol feature never works.

Fix: derive the invoice's `minFinalCltvExpiry` from the actual `refundHeight - height`.

## 2. Any peer can exhaust `maxConcurrentSwaps` with unpaid creates

Every non-terminal row, quoted-but-unpaid ones included, counts toward `maxConcurrentSwaps` (default 8; `exposure.ts:123-129`, `ledger.ts:448-450`). The per-peer limit (4 CREATED) is per node id, which is free. Reverse CREATED rows clear after the 1800 s invoice expiry; a submarine CREATED row lives until the client's own invoice expires (`invoiceProblem` bounds expiry only from below). Two throwaway node ids with four one-year-expiry submarine creates each refuse every real user with `EXPOSURE_EXCEEDED` for about a day, repeatable at zero cost.

Fix: exclude CREATED rows from the concurrency cap (or cap them separately with a short TTL) and refuse invoices whose expiry exceeds a provider maximum.

## 3. Rows with nothing on chain can never resolve and leak exposure forever

An `EXPOSED` reverse row whose funding never relayed has a `fundingTxid`, so `processWatched` observes an absent funding and does nothing; a `FUNDED` row whose funding was reorged out and evicted is rebroadcast once and never again (`reverse-engine.ts:1403-1404`, `:1507-1518`, `:1572-1580`). Neither reaches a terminal state; both count in `isSwapExposure` and `unresolved()`. `ledger.forget()` (`ledger.ts:556-561`) exists but is unused, and `/swaps/cancel` only covers CREATED/HELD. Eight such rows and the provider refuses every swap until the database is edited by hand.

Fix: give such rows a terminal path after the refund height plus margin (inputs released or double-spent), and expose a guarded operator forget/resolve route.

## 4. `verifyReverseSwapTerms` does not bound the hold invoice's final CLTV

`src/lightning/swaps/client.ts:190-213` checks network, hash, amount and expiry only. A malicious provider sets `c = 2016`; a wallet using this helper as its only check pays the hold, the provider never funds, and the client's outgoing HTLC is locked for two weeks.

Fix: refuse `minFinalCltvExpiry` above `maxRefundDelta + margin`.

---

<!-- 25-fenced-device-force-close-unlabelled.md -->
## Issue: A fenced (superseded) device admits the operator's force close with no acknowledgement, and the commitment it publishes is normally already revoked by the successor device

Labels: bug

Found during a security audit of the Recovery Protocol.

## What the code does

The recovery fence (startup gate `fenced`, or `_barrierFenced`) denies peer traffic and AUTOMATIC closes only. `_forceCloseWithReason` (`src/lightning/node/lightning-node.ts:11754`) explicitly exempts the operator:

```ts
if (reason !== 'user' && this.skipAutoCloseRecoveryGated(channelId, reason)) { ... }
```

The daemon's `requireForceCloseAcknowledgement` (`src/cli/beignet-node.ts:7978`) checks only the three recency-hold flags (`restoreRecencyUnproven`, `reestablishRecencyUnproven`, `reestablishSecretMissing`), which are set by the restore and reestablish paths (`channel.ts:9017`, `:10116`) and never by fencing; `hardFreezeTransports` only disconnects. `Channel.prepareForceClose` checks only `mustNotBroadcastCommitment`, also untouched by a fence. `durability-barrier.ts:273` records the intent: "Closing is deliberately left working, in both forms: it is the only exit an operator has." So on a fenced node, `POST /channel/forceclose {channelId}` with no `acceptStaleStateRisk` builds and broadcasts the stored local commitment; the only fenced-side message is the log line "this device must not send another channel message" (`beignet-node.ts:3386`). `docs/RECOVERY-PROTOCOL.md` section 5.6 describes the fenced node's exit as the labelled escape hatch; here it is unlabelled.

## Failure scenario

Quorum mode. Phone A is lost. Phone B restores through `RestoreDriver`, the wire-safety proof holds, channels RESUME (no `stateUncertain`), and B transacts for days: every commitment update revokes the commitment A still stores. A is found and booted: the startup gate (or the barrier recheck) fences it and it shows frozen channels. The operator runs `channel forceclose <id>` on A, the documented "only exit a fenced node has". A broadcasts a commitment B already revoked; the peer's justice path takes the entire channel balance. The same path is open on a QUARANTINED node (guardians unreachable), where supersession is merely unproven.

## Suggested fix

In `forceCloseChannel` / `_forceCloseWithReason`, when the gate is `fenced` or `_barrierFenced` (and arguably `quarantined`), refuse without `acceptStaleStateRisk: true`, with wording that names the takeover. Better: on fence latch, stamp every open channel with a hold flag so the existing acknowledgement machinery, `/recovery/status` and the cooperative-close refusal all fire, and prefer the peer-initiated close (channel_reestablish with data-loss protection) over broadcasting our own commitment.

---

<!-- 26-snapshot-frames-exceed-guardian-cap.md -->
## Issue: Recovery snapshot frames are unbounded and never checked against the guardian's ciphertext cap: once a snapshot exceeds it, replication wedges permanently, and in quorum mode every safety-critical batch is refused forever

Labels: bug

Found during a security audit of the Recovery Protocol. Sizes measured with a script that builds snapshots from populated storage:

```
probe snapshot bytes (1 channel): 5860
snapshot with 10000 forwarding events: 3055628 bytes
snapshot with 20000 forwarding events: 6105628 bytes
snapshot with 100000 forwarding events: 30505628 bytes
snapshot with 10k payments: 2515609 bytes
```

## What the code does

- `captureSnapshot` (`src/lightning/recovery/journal.ts:1657`) embeds the whole forwarding-events ledger (retained up to `forwardingEventsMaxRows = 100_000`, `sqlite-storage.ts:172`), every payment, invoice, chain monitor and outbox row. A snapshot is written every 256 frames or 4 MiB of deltas AND on every process restart (re-base). `writeFrame` (`:1320`) has no size bound and the writer never consults `info().maxCiphertextBytes` (only the capsule composer bounds its own size).
- The guardian refuses `ciphertext.length > maxCiphertextBytes` with `ERR_TOO_LARGE` (`guardian.ts:1208`); the host default is 4 MiB (`guardian-host.ts:75`) and the protocol hard cap is 16 MiB (`guardian.ts:343`).
- A guardian accepts only `logHead.sequence + 1`, so once it refuses snapshot S it refuses every later record with `ERR_SEQUENCE_GAP`. In `streamToGuardian` (`guardian-replication.ts:1030-1108`) an `ERR_TOO_LARGE` answer carries no receipt and no `current`, so the pass ends with no progress and no distinct error (the replication code never mentions `ERR_TOO_LARGE` at all).

## Failure scenario

A wallet that has routed about 15k forwards (or sent about 10k payments) writes its next snapshot; every guardian answers `ERR_TOO_LARGE`; the watermark never advances again.

- Quorum mode: every safety-critical batch parks and is refused after 30 s (`transition:frozen`); the node disconnects and reconnects in a loop and can never again send `revoke_and_ack`, `update_fulfill_htlc` or `commitment_signed` on ANY channel. Incoming HTLCs can only be claimed by force-closing at the deadline. Above 16 MiB no configuration can fix it.
- Async-remote mode: replication silently stops (only an `under-replicated` event). A later device-loss restore lands at the last replicated head, so every later channel update is unrecoverable and all channels end in a data-loss close.

## Suggested fix

Bound snapshot content: drop the forwarding ledger and settled payments from snapshots, or page them into separate frames; check the encoded size against the advertised `maxCiphertextBytes` before writing and degrade loudly the way `composeRecoveryCapsule` does; in the replicator, surface `ERR_TOO_LARGE` as a distinct `node:error`.

---

<!-- 27-guardian-storage-never-shrinks.md -->
## Issue: Guardian storage never shrinks and the per-set byte quota is a shared hard stop that ordinary use reaches, after which every write in the set is refused

Labels: bug

Found during a security audit of the Recovery Protocol. Companion of the snapshot-size issue; the two share the failure mode (replication stops, quorum mode freezes the node).

## What the code does

The writer compacts deltas below each snapshot locally, but guardians keep every record ever accepted (there is no prune path in `guardian.ts`, only rollback and open-time archiving; they cannot tell a snapshot from a delta), and `SYNC_EPOCH` truncations are counted in the orphan archive against the same quota ("Quotas refuse, never delete"). The quota is per SET and shared by all namespaces in it (`guardian-host.ts:76`, `:193`, `:506`: 256 MiB), judged in `quotaGate` / `chargeOrRollBack` (`guardian.ts:1529-1567`). An `ERR_QUOTA_EXCEEDED` answer carries no receipt and no progress in `streamToGuardian` (`guardian-replication.ts:1030-1108`).

Measured probe frames are about 6 KB per delta plus a full snapshot per restart and per 256 frames; the default is exhausted after roughly 40k transitions (about 10k payments) shared across the three namespaces of a mutually-guarding trio, sooner as snapshots grow (a 3 MB snapshot times 85 restarts fills it).

## Failure scenario

The set crosses the quota; every `PUT_STATE` answers `ERR_QUOTA_EXCEEDED`. Quorum mode: the same node-wide freeze as the snapshot issue (all channels end force-closed at HTLC deadlines). Async-remote: replication stops. The only exits are the guardian operators raising `BEIGNET_GUARDIAN_MAX_BYTES` or a set rotation, whose own defects are tracked in #862, #937 and #938.

## Suggested fix

Let the writer declare snapshot positions (a flag on `PUT_STATE`) so a guardian can archive and free records below a receipted snapshot once the writer's retain floor has passed it; make the quota per namespace; raise a `guardian:quota-refused` event and a node-side alarm well before exhaustion.

---

<!-- 28-restore-race-deadlock.md -->
## Issue: A restore racing a still-live writer with one guardian down deadlocks both devices until the third guardian returns

Labels: bug

Found during a security audit of the Recovery Protocol. Liveness only (the operator force close remains the exit, with the caveats of the fenced-device issue); traced through every branch, not executed.

## What the code does

- `acquireEpoch` (`src/lightning/recovery/restore-driver.ts:852-1020`) keeps a pending attempt verbatim while `acceptedSomewhere`; `repairLaggards` (`:727-784`) uses `SYNC_RECORD`.
- The guardian refuses `SYNC_RECORD` with `ERR_EPOCH_SUPERSEDED` when the record epoch differs from the lease epoch (`guardian.ts:1260-1275`).
- `resolveSupersession` (`guardian-replication.ts:1302-1355`) fences the live writer on ONE signed higher-epoch state.

## Failure scenario

A (epoch 42) commits frame N+1 while B restores; G3 is down. G1 accepts N+1 before B's `ACQUIRE(expected=N)` arrives (the CAS fails there); G2 accepts B's `ACQUIRE` first (lease 43, head N) and then refuses A's N+1 as fenced. A: `confirmOwnership` sees G2's signed epoch-43 state and is permanently fenced. B: `selectHead` adopts G1's (42, N+1); `repairLaggards` cannot bring G2 to N+1 (a `SYNC_RECORD` of an epoch-42 record is refused by a lease-43 guardian); the pending attempt is never abandoned (`certificates.length > 0`); G1 keeps failing the CAS until `cas-exhausted`. Neither device can write; both sit until G3 returns.

## Suggested fix

On retry, when the pending attempt's guard is stale and the same writer key already holds the epoch at some guardian, re-issue `ACQUIRE` with the same key against the new head and let `SYNC_EPOCH` accept a matching-key bundle whose superseded heads differ only by the minority tail; or abandon and re-target when the accepting guardians are provably a minority.

---

<!-- 29-uneconomic-to-local-aborts-htlc-claims.md -->
## Issue: An uneconomic to_local output on OUR force-closed commitment throws out of the output resolver, so no HTLC-success or HTLC-timeout is ever built: an inbound HTLC whose preimage we hold is lost to the peer's timeout

Labels: bug

Found during a security audit of the chain layer. Reproduced with a script against `resolveOurCommitmentOutputs`:

```
our commitment outputs: [ 774, 100000, 849000 ]
tracked: [ 'TO_LOCAL=774', 'RECEIVED_HTLC=100000', 'TO_REMOTE=849000' ]
feeRate 2 sat/vB -> resolved [ 'TO_LOCAL:spend', 'RECEIVED_HTLC:spend', 'TO_REMOTE:none' ]
feeRate 10 sat/vB -> THREW: Fee exceeds available value for to_local sweep (no HTLC-success built for the 100000 sat inbound HTLC)
second-level (1000 sat output, 10 sat/vB) THREW: Fee exceeds available value for second-level sweep
```

## What the code does

The legacy `TO_LOCAL` branch of `resolveOurCommitmentOutputs` (`src/lightning/chain/output-resolver.ts:1717-1745`) computes `feeSatoshis = ceil(feeRatePerVbyte * 113)` and calls `buildToLocalSweepTx` directly, which throws `Fee exceeds available value for to_local sweep` when `amount - feeSatoshis <= 0` (`src/lightning/chain/sweep.ts:89-92`). Every sibling path (taproot to_local, their-commitment to_remote and HTLC claims, revoked to_remote, penalty batches) was retrofitted with a `sweepOutputValue()` guard and `declinedAsUneconomic` (`output-resolver.ts:1960`, `:2131`, `:2339`, `:2390`, ...); this branch was not, and neither was the legacy branch of `resolveSecondLevelHtlcOutput` (`:2032`).

The resolver builds every output before `_handleOurCommitment` (`src/lightning/chain/chain-monitor.ts:2185-2216`) schedules any, so the throw escapes before any HTLC-success or HTLC-timeout exists. `channel-manager.ts:3084` has no try/catch, and the watcher only logs (`chain-watcher.ts:2357`, `checkFundingSpent(...).catch(emitError)`). `_state` is already RESOLVING and `_commitmentBroadcast` is set, so later re-reports of the same funding spend go to `_reconcileRecordedSpend` (no re-resolution), and none of the retry paths (`_retryUnsweptRevokedSweeps`, `_retryUnsweptPeerCommitmentClaims`, `updateFeeRate`, `_rebuildHeldSweeps`) cover `OUR_COMMITMENT`. The manager's `monitor:updated` emit at `:3151` is skipped too, so nothing is persisted.

## Failure scenario

We are the opener with a 1000-sat local balance (a 774-sat to_local after the commitment fee, above the 354-sat dust limit) and a 100,000-sat inbound HTLC whose preimage we hold. The node force-closes, which is exactly what `scanExpiringHtlcs` does 18 blocks before expiry. At the watcher's default sweep feerate of 10 sat/vB (`chain-watcher.ts:2362`; the threshold is to_local below `ceil(rate * 113)`: 2260 sat at 20 sat/vB, 5650 sat at 50 sat/vB) the resolver throws, the error is logged, the 100k-sat HTLC-success is never built or broadcast, and at `cltv_expiry` the peer's HTLC-timeout takes the 100k sats. Offered HTLCs on the same commitment never get their HTLC-timeout either, so their value is stranded and the upstream fail is never issued, which cascades into an upstream force close. The second-level sibling drops that `handleOutputSpent` call's other actions (`WATCH_OUTPUT`, `PREIMAGE_LEARNED` for the same tx), so the CSV output is never tracked.

## Suggested fix

Guard the legacy `TO_LOCAL` branch and the legacy branch of `resolveSecondLevelHtlcOutput` with `sweepOutputValue()` and push `{ trackedOutput, declinedAsUneconomic: true }` like the sibling paths; wrap per-output resolution in `_handleOurCommitment` / `handleOutputSpent` so one output cannot abort the rest; add an `OUR_COMMITMENT` retry in `handleNewBlock` / `updateFeeRate` so a declined output is retried when fees fall.

---

<!-- 30-watchtower-backup-gaps.md -->
## Issue: Watchtower backups skip revoked commitment #0 and every revocation that straddles a restart, leaving states the tower cannot punish

Labels: bug

Found during a security audit of the watchtower client.

## What the code does

The justice blob for a revoked remote commitment is built from a transaction cached at `signCommitment` time (`src/lightning/channel/channel.ts:4237-4266`, `_cacheRemoteCommitmentForWatchtower`, only called from `signCommitment` at `:4369`), keyed by the per-commitment point in an in-memory `Map` of at most 8 entries (`:1030-1031`). The cache is a private field that is never serialized (no reference in `storage/serialization.ts` or `channel-state.ts`). On `revoke_and_ack`, `takeRevokedCommitmentTx` (`:4271-4278`) returns null on a miss and the manager silently skips the backup (`src/lightning/channel/channel-manager.ts:4336-4343`, `if (revokedTx && revChannelId) emit('watchtower:backup')`). There is no catch-up on restart. The initial commitment (signed in the funding_created / funding_signed flow and the v2 equivalents) is never cached; `tests/lightning/watchtower.test.ts:578-581` documents that gap ("never signed via signCommitment, so never cached").

## Failure scenario

1. A peer opens an inbound channel to us; its commitment #0 pays it the full funding amount. After we receive payments, #0 is the most profitable state for it to breach with, and the tower never received a blob for it. If we are offline when it is broadcast, the breach succeeds.
2. We send `commitment_signed`, the daemon restarts (cache gone; reestablish retransmits from `lastSentCommitmentSigned` without re-running `signCommitment`), the peer's `revoke_and_ack` arrives, `takeRevokedCommitmentTx` returns null, and that revoked state is unprotected forever.

The tower's only purpose is to punish breaches while we are offline; both gaps leave revoked states it cannot punish.

## Suggested fix

Cache the initial remote commitment when it is signed; persist the pending-remote-commitment cache with channel state (or rebuild the revoked transaction from `revokedHtlcSnapshots` and the recorded balances at revoke time); on restart, back up any revoked state whose blob was never acknowledged by the tower.

---

<!-- 31-coop-close-dust-limit-mismatch.md -->
## Issue: The cooperative closing transaction trims outputs with hard-coded 294/546 thresholds instead of the negotiated dust_limit_satoshis, which burns a non-dust output or fails the channel against a conformant peer

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

---

<!-- 32-zero-amount-mpp-poisons-persistence.md -->
## Issue: Paying a zero-amount invoice through the MPP fallback underpays the payee and then poisons every later channel-state persist in the process

Labels: bug

Found during a security audit of the payment pipeline. Reproduced for the serializer and the wire encoding:

```
serializePaymentInfo throws: Cannot read properties of undefined (reading 'toString')
part amt_to_forward: 40000000 total_msat on wire: 40000000
```

## What the code does

`sendPayment` resolves a zero-amount invoice's amount from the caller (`paymentAmountMsat = amountMsat`), but when the single-path route is unavailable (no route, or `firstHopChannel.getSpendableOutboundMsat() < route.totalAmountMsat`, a routine case for a two-channel wallet) it falls back to `sendPaymentMpp(invoiceStr, invoice, multiRoute, ...)` (`src/lightning/node/lightning-node.ts:15708`), which does (`:16473`):

```ts
const totalMsat = invoice.amountMsat!;
```

`undefined` for a zero-amount invoice. That value becomes `payment.amountMsat`, `mppState.totalMsat` and every part's `payload.totalMsat`. The onion encoder then falls back to `encodeTruncatedUint(payload.totalMsat ?? payload.amountToForwardMsat)` (`src/lightning/onion/hop-payload.ts:86`), so each part carries `total_msat == amt_to_forward`. `serializePaymentInfo` does `bigintToStr(p.amountMsat)` (`src/lightning/storage/serialization.ts:1474`) and throws on `undefined`.

## Failure scenario

1. A user pays a zero-amount, MPP-capable invoice (LND and CLN default) for 100k sats with two 60k-sat channels; the single route fails the spendable check; the payment is split into two 50k parts.
2. `commitMutations('persist mpp payment')` fails (the serializer throws inside the transaction; `RecoveryManager.commit` catches and returns `committed: false`), and the dispatch continues unpersisted.
3. The recipient sees part 1 as a standalone 50k payment for an any-amount invoice (LND behaves the same) and settles it; part 2 is refused as "payment already completed". The payee is underpaid by 50k while the payer's record flips to COMPLETED in `handleHtlcFulfilled`, so the payer's app reports a successful full payment.
4. `handleHtlcFulfilled` stages `{ type: 'payment_state', payment }` (the unserializable record) onto the channel transition (`:21912`). `persistChannelState` takes the stage, the commit throws, and on failure the code re-queues the staged mutations (`:3641`, `this.stagedMutations.unshift(...staged)`); `flushStagedMutations` (`:3765-3781`) re-stages on failure too. The poisoned mutation therefore rides EVERY later `persistChannelState` for EVERY channel and makes every commit throw. No channel state, including revocation secrets received from peers, is persisted for the rest of the process. On restart all channels come back stale: an honest peer triggers data-loss handling, and a malicious peer can broadcast a revoked commitment whose secret was never written, which we cannot punish.
5. The daemon's `payment:sent` listener does `Number(p.amountMsat / 1000n)` (`src/cli/beignet-node.ts:11078`) and throws on the mixed types; `peer.ts` treats a throwing message listener as a peer error and disconnects the peer.

## Suggested fix

Pass the resolved `paymentAmountMsat` (or `multiRoute.totalAmountMsat`) into `sendPaymentMpp` instead of `invoice.amountMsat!`, and validate that `amountMsat` is a bigint before building the record. Separately, make a mutation that fails to serialize non-poisoning: on a serializer error, drop or quarantine that mutation and report it, rather than re-staging it forever.

---

<!-- 33-mpp-part-never-settled-after-reconnect.md -->
## Issue: An MPP part on a channel that disconnected between parts is never fulfilled after reconnect, ending in a needless force close

Labels: bug

Found during a security audit of the receive pipeline. Traced through callers and callees; not executed (no existing test covers a disconnect between parts).

## What the code does

When a set completes, `handleMppPart` (`src/lightning/node/lightning-node.ts:20776-20783`) does:

```ts
for (const p of pending.receivedParts) {
    p.status = PaymentStatus.COMPLETED;
    this.channelManager.fulfillHtlc(p.channelId, p.htlcId, preimage);
}
this.pendingMppPayments.delete(hashHex);
```

ignoring each `ChannelResult`, then marks the payment COMPLETED with `settledHtlcs` listing every part. `Channel.fulfillHtlc` returns an ERROR action (manager result `ok: false`) when the channel is `AWAITING_REESTABLISH` (`src/lightning/channel/channel.ts:3628-3640`, `:13514-13520`). The only re-drive of a committed, unsettled received HTLC is `redispatchUnresolvedReceivedHtlcs`, wired to `channel:restore-ready` (`:4072-4076`), which fires once per channel restored from persistence and never for a channel that stayed live. The `channel:reestablished` handler (`:4102-4120`) re-drives forwards, held forwards and hold-invoice resolutions, but not plain received HTLCs of a completed payment.

## Failure scenario

A payer sends part 1 over peer A and part 2 over peer B within the 60 s MPP window. Peer A disconnects after part 1 is irrevocably committed (channel A goes `AWAITING_REESTABLISH`). Part 2 completes the set: part 2 is fulfilled, part 1's fulfill is refused and silently dropped, the payment is recorded COMPLETED (invoice settled, `payment:received` emitted, goods delivered). Peer A reconnects minutes later: nothing fulfills HTLC 1; it stays COMMITTED with the preimage known until the inbound claim backstop in `scanExpiringHtlcs` (`:25851`) force-closes channel A `claimBuffer` blocks before expiry to claim it on chain. An avoidable unilateral close (fees, a lost channel) on every such reconnect race, and the payer's node counts the HTLC as in flight for days.

## Suggested fix

Check the result of each `fulfillHtlc` and keep refused parts (as `advanceHeldResolution` does for hold invoices); on `channel:reestablished`, fulfill any COMMITTED received HTLC whose hash has a COMPLETED incoming payment listing it in `settledHtlcs` (the same predicate the restart redispatch already trusts).

---

<!-- 34-retry-context-left-after-throw.md -->
## Issue: A BOLT 11 dispatch that throws after registering its retry context leaves the context behind, so a re-send within 60 s inherits the previous amount, fee cap, CLTV ceiling and exclusions

Labels: bug

Found during a security audit of the payment pipeline. Narrow window, but the inherited amount is a real overpayment.

## What the code does

`sendPayment` registers `paymentRetryContexts[hash]` only `if (!has(hash))` (`src/lightning/node/lightning-node.ts:15735-15746`, `:15624`) and then calls `sendPaymentToRoute`, which can throw after registration: `NO_CHANNEL_TO_HOP` (`:15913`, a route found over the announced graph copy of our own channel while its peer is offline; `getLocalChannelEdges` excludes an `AWAITING_REESTABLISH` channel and the router keeps graph first hops, `pathfinding.ts:317-329`; the daemon maps it to `PEER_NOT_CONNECTED`) or the CLTV-ceiling error (`:15923`). No payment record exists and nothing deletes the context until the 60 s cleanup tick (`:10380-10388`, timer at `:1569`). A second `sendPayment` for the same hash passes `assertHashUnpaid` and keeps the OLD context; a retry re-enters with `retryCtx.invoiceStr, retryCtx.excludedChannels, retryCtx.maxFeeMsat, retryCtx.amountMsat, retryCtx.maxCltvExpiryHeight` (`:22978`), and the ceiling is inherited at `:15503-15507`. `dispatchBolt12Route` (`:27200-27229`) already deletes its context in a `catch`; the BOLT 11 path does not.

## Failure scenario

Zero-amount invoice. Call 1: `sendPayment(inv, amount = 100k sats, maxFee = 1000)` while the LSP peer is briefly offline throws `PEER_NOT_CONNECTED`. Call 2 within 60 s: `sendPayment(inv, amount = 1k sats, maxFee = 10)`. The first attempt uses the new values, but a temporary failure re-enters `sendPayment` with the stale context: 100k sats within a 1000-sat fee cap, 100x the requested amount. A stale `maxCltvExpiryHeight` also applies to the first attempt of call 2 and can make the invoice unpayable until the prune.

## Suggested fix

Mirror `dispatchBolt12Route`: wrap the dispatch in try/catch and delete a context this call created on throw; when a caller supplies new parameters and nothing is in flight, overwrite the existing context.

---

<!-- 35-send-to-route-bypasses-limits.md -->
## Issue: sendToRoute (POST /payment/send-to-route) bypasses maxPaymentSats, dailySpendLimitSats and the daily ledger

Labels: bug

Found during a security audit of the spending rails. Same class as the closed #526 and #529; this is the remaining path. Reproduced with `BeignetNode.create` on regtest: `payInvoice` for the same amount is refused with `SPENDING_LIMIT_EXCEEDED`, `sendToRoute` passes admission and reaches the engine (`NO_CHANNEL_TO_HOP`), and `getDailySpendInfo()` reports 0 spent and 0 pending both after the call and after the engine's `payment:sent` for that hash.

## What the code does

Every other Lightning pay path (`payInvoice`, `payInvoiceSafe`, `sendPaymentAsync`, `sendKeysend`, `payOffer`, `l402Fetch` through `payInvoice`, the queue through `payInvoiceSafe`) runs `_checkMaxPayment`, `_checkSpendLimit` and opens an `AsyncSpendClaim` before dispatch. `sendToRoute` (`src/cli/beignet-node.ts:12398-12450`) runs only `this._checkDraining()` and then calls `this.node.sendPaymentToRoute({ hops }, hash, finalHop.outgoingCltvValue, secret, finalHop.amountToForwardMsat)` with the caller-supplied route; any hops and amounts are accepted by `jsonToRouteHops`, and the route need not come from `/route/query`. The engine comments that the duplicate-hash guard is "the only check on the explicit-route entry" (`src/lightning/node/lightning-node.ts:15774-15805`). On settlement the `create()` handler calls `_chargeAsyncSpendClaim(pi.paymentHash)`, which returns immediately when the hash holds no claim (`:9367-9397`), so the settled amount never reaches `_dailySpentSats` and `GET /spend-limit` under-reports.

## Failure scenario

Node configured with `maxPaymentSats: 500` and `dailySpendLimitSats: 1000`. `POST /payment/send-to-route {paymentHash, route: {hops: [..., {amountToForwardMsat: "5000000", ...}]}}` for a 5000-sat invoice is admitted, dispatched and, when it settles, leaves the ledger at 0. The same invoice through `POST /invoice/pay` is refused. An agent or operator key limited by the safety rails can drain all outbound liquidity by routing itself, any number of times per day.

## Suggested fix

In `sendToRoute`, compute the spend from the first hop's amount (which includes the fees) or at least `finalHop.amountToForwardMsat`, run `_checkMaxPayment`, `_checkSpendLimit` and `_openAsyncSpendClaim` before the engine call, close the claim when the engine throws and release it when the returned record is FAILED (mirror `sendPaymentAsync`). Document in `validatePayment` whichever paths it does not cover.

---

<!-- 36-offer-pay-not-idempotent.md -->
## Issue: POST /offer/pay ignores X-Idempotency-Key, and a retried BOLT 12 payment cannot be de-duplicated by payment hash, so a client retry pays the offer twice

Labels: bug

Found during a security audit of the payment routes.

## What the code does

BOLT 11 routes are protected twice: the idempotency key (`IDEMPOTENT_ROUTES`, `src/cli/daemon.ts:87-108`; same key plus same body returns the cached response, concurrent same-key requests share the in-flight promise since #768) and the engine's duplicate-hash refusal (#975). `POST /l402/fetch` was added to the set with the comment "a retried fetch gets a fresh challenge with a fresh invoice, so an un-keyed retry pays twice". `POST /offer/pay` (`:2739-2746`) has exactly that shape and is not in the set: `payOffer` (`src/cli/beignet-node.ts:11497-11525`) awaits `this.node.requestInvoice(offer, ...)`, which sends a new `invoice_request` per call (`src/lightning/node/lightning-node.ts:27025-27051`; `offer-manager.ts:616`, `:725-739` key pending requests by a fresh request id, no per-offer cache), the payee mints a new invoice with a new payment hash, `assertHashUnpaid` (`:27067`) sees an unknown hash, and the payment goes out again. The header is silently dropped for routes outside the set (`daemon.ts:3281-3330`).

## Failure scenario

An agent following `docs/AI_AGENT_GUIDE.md` ("Use X-Idempotency-Key header on payment requests to prevent duplicates") calls `POST /offer/pay {offer, amountSats: 100000}` with `X-Idempotency-Key: order-1`. The HTTP client times out (`payOffer` blocks up to 60 s by default; the round trip to the payee plus routing often exceeds a 30 s client timeout) or the connection drops after the HTLC left. The agent retries with the same key and body; the second request obtains a second invoice and pays 100,000 sats again. Neither drain mode nor the daily limit stops it unless the limit happens to be exhausted.

The same gap exists, less acutely, for `POST /channel/splice-out` with an external `address` (a real external spend; a retry after the first splice locks moves the funds twice) and `POST /channel/open*` (a retry opens a second channel).

## Suggested fix

Add `POST /offer/pay` (and `POST /channel/splice-out`, `POST /channel/open`, `/open-v2`, `/open-zeroconf`, `/connect-and-open`) to `IDEMPOTENT_ROUTES`; answer 400 when a key is supplied on a route that does not honour it, so a caller cannot believe it is protected.

---

<!-- 37-safety-rail-coverage-gaps.md -->
## Issue: Safety-rail coverage gaps: rebalances spend fees outside the daily budget and ignore drain mode, and maxPaymentSats is enforced on Lightning payments only

Labels: bug

Found during a security audit of the spending rails. Two low-severity gaps between what the docs promise and what the rails cover.

## 1. Circular rebalances

`rebalanceChannel` (`src/cli/beignet-node.ts:12085-12135`) and `executeRebalances` (`:12136-12168`) go straight to the engine with no `_checkDraining`, `_checkSpendLimit` or `_recordSpend`. The principal returns, but the fee (bounded only by the caller's `maxFeeSats` or the advisor budget) is a real spend that never reaches `_dailySpentSats`, and a rebalance is a real outgoing payment a draining node still dispatches. With `dailySpendLimitSats` exhausted, `POST /rebalance {amountSats: 1000000, maxFeeSats: 50000}` still spends up to 50,000 sats of fees per call; `GET /spend-limit` shows nothing; during `/stop` drain a rebalance creates a PENDING payment the drain then waits on. The README's exclusion list (`src/cli/README.md:677-695`) does not mention rebalances.

Fix: `_checkDraining()` in both; charge the settled fee via `_recordSpend` (or reserve `maxFeeSats` and record the actual fee); document it either way.

## 2. `maxPaymentSats` is Lightning-only

`_checkMaxPayment` (`:9186-9194`) is called only from the Lightning pay paths (`:10152`, `:10466`, `:10527`, `:11543`). `sendOnchain` (`:6090-6134`), `sendMaxOnchain` (`:6478`), `spliceOut` (`:11339-11417`) and `sendDirectFunding` (`:8805-8910`) pass it for any amount. `docs/AI_AGENT_GUIDE.md:230` says "Reject any single payment over 100k sats"; `src/cli/README.md` does not document `maxPaymentSats` at all and the daemon has no flag for it (`config.ts` / `cli.ts` plumb only `dailySpendLimitSats`). An SDK user with `maxPaymentSats: 100_000` and no daily limit (the guide's first example) can `sendOnchain(addr, 5_000_000)` or `spliceOut(ch, 5_000_000, rate, addr)`.

Fix: call `_checkMaxPayment` on the external on-chain paths too, or state in both READMEs that the per-payment cap is Lightning-only and plumb it through the daemon config.

---

<!-- 38-invoice-expiry-and-splice-feerate-validation.md -->
## Issue: Input validation gaps: invoice expiry accepts negative, fractional and NaN values, an over-long description is a scrubbed 500, and splice feerates accept any u32

Labels: bug

Found during a security audit of the HTTP surface. Two low-severity validation gaps, both reproduced or traced.

## 1. Invoice `expiry` / `expirySecs` is not validated

`POST /invoice/create` (`src/cli/daemon.ts:1720-1745`) and `/invoice/create-hold` (`:1936-1970`) pass `expirySecs` / `expiry` and `description` raw to `createInvoice` / `createHoldInvoice` (`src/cli/beignet-node.ts:8252-8285`, `:8945-8990`); the encoder's `encodeVarInt` loops `while (v > 0)` (`src/lightning/invoice/encode.ts:104-107`, `:179-190`). Repro: `expiry -1` decodes as 0, `1.5` as 1, `NaN` as 0, `1e15` is encoded as is; a 700-byte description throws a plain `Error('Tagged field data length ... exceeds ...')` which the daemon scrubs to `INTERNAL_ERROR`. `minFinalCltvExpiry` and amounts are validated (`requireFinalCltvExpiry`, `requireNonNegativeSafeInteger`); this is the one unguarded field. A hold invoice minted with `expiry: -1` is dead on arrival for the payer while the node reports it PENDING until its own `createdAt + expiry` check.

Fix: `requirePositiveSafeInteger(expiry)` with a sane ceiling in `createInvoice`, `createHoldInvoice` and `createJitInvoice`; refuse descriptions over 639 bytes with `INVALID_PARAMS`.

## 2. Splice feerates accept any u32

`requireU32(feeratePerkw)` for splice quote/in/out (`src/cli/beignet-node.ts:11304-11351`) and `validateU32(..., { min: 1 })` in the engine (`src/lightning/node/lightning-node.ts:12266`) have no upper bound, unlike `update_fee`, which refuses above 100,000 sat/kw (`channel.ts:5223`). An operator who mistakes sat/vB for sat/kw posts `POST /channel/splice-out {amountSats: 1000, feeratePerkw: 2500000, address}` on a 10M-sat channel: about 700 weight at 2500 sat/w, roughly 1.75M sats paid to miners from the channel balance with no refusal. `openChannel` is protected by the wallet's "fee exceeds half of inputs" guard; splices are built by the channel, not the wallet.

Fix: cap `feeratePerkw` (the update_fee bound of 100,000 is a reasonable ceiling) or refuse a fee above some fraction of the amount or balance.

---

<!-- 39-ffor-settlement-peer-balance-lock.md -->
## Issue: FFOR settlement peer: with the documented config any channel peer can lock the settlement peer's whole spendable balance in vouchers for an arbitrary number of blocks, and there is no exit from ACTIVE

Labels: bug

Found during a security audit of the FFOR protocol. The settlement role is opt-in (`fforSettle.enabled`), but the documented way to enable it (`docs/AUTOMATIC-OFFLINE-RECEIVE.md:13`, `"fforSettle": { "enabled": true }` or `BEIGNET_FFOR_SETTLE=true`) sets no bound.

## What the code does

- `handleFforInit` refuses on `maxBudgetMsat` / `maxEpochBlocks` only when the policy defines them (`src/lightning/channel/channel.ts:21755-21790`: `if (policy.maxBudgetMsat !== undefined && ...)`, `if (policy.maxEpochBlocks !== undefined && ...)`). The daemon forwards those bounds only when the operator set them (`src/cli/beignet-node.ts:2524-2538`, `src/cli/config.ts:584-597`).
- `checkVoucherBook` (`src/lightning/ffor/amounts.ts:189-273`) bounds `voucherExpiry` from below only (`voucherExpiry < settlementDeadline + 1008`) and the budget only by `sLocalBalanceMsat < sum + reserve`. A script confirmed it returns `null` (accepted) for `voucherExpiry = 0xfffffffe`.
- Once ACTIVE, `_fforAbortLocal` returns "cannot abort in state ACTIVE" (`channel.ts:22624-22637`), `_fforUpdateRefusal` refuses every add, fee update, shutdown, splice and stfu on the channel ("no ${kind} until it drains", `:21283-21286`), and only the receiver's `ff_close` or the on-chain HTLC timeout at `voucherExpiry` frees the vouchers. The vouchers are S's offered HTLCs whose preimages S generated, so R cannot claim them either. `MAX_HTLC_CLTV_EXPIRY_DELTA` (`:14605`) applies to received adds only, not to the HTLCs S offers here (`addHtlc`, `:3036`).

## Failure scenario

R, any peer with a channel in which S has balance, sends `ff_init` with `budgetMsat` = S's spendable balance, `settlementDeadline = tip + 1` and `voucherExpiry = 0xfffffffe` (about 76 years), completes the voucher round and `ff_activate` (a minute online), then disconnects. S's balance is now in K HTLCs S cannot fail; the channel carries no other traffic; a force close yields S nothing until block 2^32-2. Cost to R: zero (vouchers are S-funded and no fee is paid to reserve them). Even with a bound such as 2016 blocks the lock is a design property of the protocol, but the unbounded default turns an opt-in LSP role into an indefinite freeze by any client.

## Suggested fix

Apply defaults when the policy is enabled (`maxEpochBlocks <= MAX_HTLC_CLTV_EXPIRY_DELTA`, a `maxBudgetMsat` default such as a fraction of local balance); in `checkVoucherBook` / `handleFforInit` refuse `voucherExpiry - tip > MAX_HTLC_CLTV_EXPIRY_DELTA` unconditionally; consider letting S drain vouchers itself once `settlementDeadline` has passed.

---

<!-- 40-ffor-witness-capacity-exhaustion.md -->
## Issue: FFOR receipt witness: unauthenticated provisioning with an unbounded retention_until lets one peer permanently exhaust the witness's mailbox capacity

Labels: bug

Found during a security audit of the FFOR witness service. Reproduced against the real service with `MemoryLedgerStore`: 64 provisions from one peer with `tExp = 2^32-1-144`, `retentionUntil = 2^32-1` are all accepted; an honest receiver's provision answers `cannot reserve`; after `onBlock(2^32-1)` occupancy is unchanged.

## What the code does

`handleProvision` (`src/lightning/ffor/witness-service.ts:389-479`) accepts any peer's manifest after self-consistency checks; the only retention check is `manifest.retentionUntil < tExp + FF_WITNESS_RETENTION_MARGIN_BLOCKS` (refuse). Neither `tExp` nor `retentionUntil` is bounded against the current height. Capacity is `occupancy.mailboxes >= maxMailboxes (64) || reservedBytes + K*1024 > maxBytes (8 MiB)`, released only by `expire()` when `m.retentionUntil < height` (`witness-ledger.ts:260-283`, `witness-service.ts:629-645`). Rows are durable, so a restart changes nothing, and the daemon exposes provision, close and status routes but no operator drop (`src/cli/daemon.ts:2796-2834`).

## Failure scenario

One peer fills all 64 mailboxes (or, with K = 483 books, 17 mailboxes exhaust the byte cap) with retention far in the future. Every receiver relying on this witness, and the co-hosted issuer (which needs a mailbox), is denied for good.

## Suggested fix

Refuse `tExp` and `retentionUntil` beyond `tip + MAX_HTLC_CLTV_EXPIRY_DELTA` plus margin and require `tExp > tip`; add a per-peer mailbox quota; add an operator route to drop or expire a mailbox.

---

<!-- 41-direct-funding-ownership-proof-replay.md -->
## Issue: Direct funding: the ownership proof binds only (txid, vout, amount), so a proof harvested from one offer can be replayed against another receiver's request and burn its lifetime attempt budget

Labels: bug

Found during a security audit of direct funding. Reproduced: the same 64-byte digest signature and the same 65-byte message proof both verify (`ownershipProblem` returns `null`) on an offer carrying a different `receiptHash`, an attacker `changeScript` and `maxTotalFeeSat: 0`, after a codec round trip.

## What the code does

The signed statement is `lfbw-direct-funding-offer:<offerId>:<txid>:<vout>:<amountSat>` (`src/lightning/direct-funding/messages.ts:774-812`, `ownershipMessage` / `ownershipDigest`; the probe form adds only `sequence`). `receiptHash`, `changeScript`, `maxTotalFeeSat` and, for the digest and message forms, `sequence` are not covered. `docs/DIRECT-FUNDING-OWNERSHIP-PROOFS.md` says "Proofs authorize this offer only", but the offer id is derived from the coin and amount, not bound to the request. The receiver verifies the proof (`receiver/verify.ts:143-176`), then admits (`receiver/engine.ts:1076-1090`) and charges an attempt (`:1284`, `requests.ts:453-467`, "The COUNT stays charged"; `DF_MAX_REQUEST_ATTEMPTS = 3`).

## Failure scenario

Payer P offers coin C to receiver R1 (R1 declines or the exchange fails; C stays unspent). R1 now holds a valid proof for C. It takes any public envelope of receiver R2 and sends an offer for C with R2's receipt hash: admission passes (the chain says unspent, the proof is valid), R2 reserves C, charges an attempt, opens a dual-funded channel with its LSP, waits 120 s for the final transaction and 120 s for a witness that never comes, then aborts. Three replays make R2's request permanently unpayable ("too many funding attempts for this request"); while a replay is live, P's genuine offer for the same request is declined ("request already has an active funding attempt"); replays across requests pin R2's inflight slots and spam its LSP with aborted opens. No funds move.

## Suggested fix

Include the request binding (receipt hash or request id) in `ownershipMessage` and in the probe transaction's `OP_RETURN`, and have the receiver verify the proof against its record's receipt hash.

---

<!-- 42-daemon-hardening-lows.md -->
## Issue: Daemon hardening: rate-limiter buckets never evicted after two requests, SSE streams have no cap or backpressure, /openapi.json is rebuilt per unauthenticated request, webhooks accept any target and carry preimages, and five smaller items

Labels: bug

Found during a security audit of the HTTP daemon. Low-severity items grouped by component; each was verified (repros noted).

## 1. Rate limiter: buckets with two or more spent tokens are never pruned

`prune` (`src/cli/http-rate-limiter.ts:127-142`) deletes a bucket only when `now - lastRefill > 2*windowMs && tokens >= maxRequests - 1`, but tokens are refilled only inside `isAllowed` (`:104-112`), so an idle bucket keeps the count it had at its last request. A key that made exactly one request is pruned; one that made two is kept forever. Repro: 50,000 keys times 2 requests, clock advanced one hour, `prune()` removes 1 bucket. An attacker with a large address pool (an IPv6 /64) sends two requests per address to a network-exposed daemon with `rateLimit` on; each address costs 150-200 bytes forever; about 10M addresses is 2 GB of heap. The existing test (`tests/cli/http-rate-limiter.test.ts:58-70`) only covers a single-request bucket.

Fix: compute the refilled count in `prune` (or drop any bucket idle longer than two windows regardless of tokens); cap the map size.

## 2. SSE: no client cap, no backpressure

`GET /events` (`src/cli/daemon.ts:3106-3155`) accepts any number of connections per key, and the broadcast loop (`:3406-3415`) ignores `write()`'s return value and `writableLength`. A holder of the least-privileged `readonly` key opens N streams and stops reading; Node buffers every frame per stalled client until OOM, one fd per stream.

Fix: cap SSE clients per key and in total; destroy a client whose `write()` returns false or whose `writableLength` exceeds a threshold.

## 3. `/openapi.json` rebuilt and serialized per request, exempt from auth and the limiter

`AUTH_EXEMPT_ROUTES` (`:189-193`) skips the rate limiter too (`:3087-3090`), and `'GET /openapi.json': () => getOpenApiSpec()` (`:1214`) rebuilds the spec object and stringifies it on every hit: measured 155,678 bytes and about 1.9 ms per request, three orders of magnitude more than `/health`. About 500 unauthenticated requests per second (77 MB/s egress, one keep-alive client) pins a core.

Fix: build the spec string and its `Content-Length` once at boot; keep the limiter for exempt routes.

## 4. Webhooks: no target restriction, preimages in payloads, unsigned after restart

`register` (`src/cli/webhooks.ts:77-115`) accepts any string; `deliver` (`:251-262`) uses `https` for `https:` and plain `http` for everything else (so `file://` or an empty host becomes a POST to `localhost:80`). No loopback / link-local / RFC 1918 guard, unlike `POST /l402/fetch`. `payment:sent` / `payment:received` payloads include `preimage` (`src/cli/beignet-node.ts:11083`), so proofs of payment travel to whatever URL was registered, in cleartext over `http:`. The HMAC secret is lost across restarts (documented in code), so every post-restart delivery is unsigned and a receiver that verifies signatures rejects it.

Fix: restrict to `http:` / `https:`, apply the same private-network refusal as l402 unless explicitly allowed, omit `preimage` from webhook payloads (it stays available via `GET /payment`), persist the HMAC secret.

## 5. Smaller items

- `parseBody` (`daemon.ts:146-156`) calls `req.destroy()` before rejecting, so the 413 written afterwards never reaches the client (connection reset instead).
- `apiToken` has no minimum length (`auth.ts` accepts `'a'`; the README example is `mytoken`) and the limiter is off by default, so a weak token on an exposed daemon is brute-forceable without throttling. `--api-token` / `--api-key` values are on argv (`cli.ts:98`, `:435`), visible in `ps`.
- `beignet init` prints the mnemonic to stdout when the config already exists (`cli.ts:375-383`), so a scripted re-run leaks the seed into logs.
- `restore db` (`restore.ts`) validates only the 16-byte SQLite header; storage accepts plaintext rows (`sqlite-storage.ts:129-135`, re-encrypted on open), so the seed-encrypted backup provides confidentiality but no integrity against a tampered file.
- `POST /backup` accepts any absolute `destPath` (only `..` is filtered) and `db.backup()` overwrites it, so an admin can destroy `config.json` (with the seed) by mistake; consider restricting to the data directory.

---

<!-- 43-dependency-and-ci-hygiene.md -->
## Issue: Dependency and CI hygiene: qs advisories under bip21 pass the audit gate, the Electrum client library disables TLS verification, workflows run with default token permissions and mutable action tags

Labels: bug

Found during a security audit. Low-severity hygiene items; the TLS point is also referenced from the UTXO-value issue where it becomes a money-loss amplifier.

## 1. `qs` 6.15.3 under `bip21` carries two moderate advisories that the CI gate ignores

`npm audit` reports GHSA-x5fp-wj9c-mxmx (array-limit bypass) and GHSA-4mjr-xmp4-gh2g (DoS via attacker-controlled isBuffer) for `qs@6.15.3`, reached through `bip21@2.0.3` (`qs: ^6.3.0`). `qs` is used to parse BIP 21 URI query strings, i.e. attacker-supplied input from QR codes and pasted links. `fixAvailable: true` (qs >= 6.16.0 is within bip21's range), but `.github/workflows/audit.yml` runs `npm audit --audit-level=high`, so moderate advisories pass silently.

Fix: `npm update qs` (or add `qs` to `overrides`), and consider `--audit-level=moderate` for a wallet.

## 2. `rn-electrum-client` hardcodes `rejectUnauthorized: false`

`node_modules/rn-electrum-client/lib/TlsSocketWrapper.js:72` and `lib/init_socket.js:21` connect with certificate verification disabled and beignet offers no pinning or CA option, so every "TLS" Electrum session, including the default `fulcrum.bitkit.blocktank.to:8900`, accepts any on-path certificate. Electrum servers commonly use self-signed certificates, which is why clients usually pin on first use; beignet does neither. The README makes no verification promise, but users reading "tls" will assume one.

Fix: expose a verification mode (CA verification for hosts with real certificates, trust-on-first-use pinning otherwise) and document the current behaviour until then.

## 3. GitHub Actions hygiene

No workflow declares a `permissions:` block, so jobs run with the repository's default `GITHUB_TOKEN` scopes; actions are pinned to mutable major tags (`actions/checkout@v7`, `actions/setup-node@v7`, `jwalton/gh-docker-logs@v2`) rather than commit SHAs; `tests.yml` runs `sudo apt install wait-for-it` unpinned. A compromised action tag or apt mirror gets whatever the default token allows.

Fix: add `permissions: contents: read` at the workflow level, pin actions by SHA (Dependabot can keep them current), and pin or vendor `wait-for-it`.

---

<!-- 44-funder-never-checks-own-fee-on-inbound-add.md -->
## Issue: As the channel funder, an inbound update_add_htlc is never checked against our own commitment fee: a peer can stack HTLCs until our to_local is trimmed to zero

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

---

<!-- 45-raa-next-point-not-validated.md -->
## Issue: revoke_and_ack.next_per_commitment_point is stored and persisted without curve validation, so every later signing attempt throws and the channel is wedged for good

Labels: bug

Found during a security audit of the channel state machine. Reproduced against `Channel`:

```
decoder accepted invalid point: true
handleRevokeAndAck actions: [ 'PERSIST_STATE' ]
stored remoteNextPerCommitmentPoint === invalid point: true
buildRemoteCommitment THROWS: Expected Point
```

## What the code does

`decodeRevokeAndAckMessage` takes the 33 bytes as-is (`src/lightning/message/channel-commitment.ts:212`). `handleRevokeAndAck` verifies the revealed secret against the current point but stores `next_per_commitment_point` unchecked (`src/lightning/channel/channel.ts:5002`, `this._state.remoteNextPerCommitmentPoint = msg.nextPerCommitmentPoint;`) and persists it (`:5148`). Only `channel_ready`'s point is validated (`:2848`). The next `autoSignAndSendCommitment` (`channel-manager.ts:1863`) reaches `deriveRevocationPubkey` (`src/lightning/keys/derivation.ts:95`, `pointMultiply(perCommitmentPoint, tweakB)`) through `buildRemoteCommitment` and throws `Expected Point`.

## Failure scenario

A peer answers one of our `commitment_signed` with a valid secret and an off-curve next point. From then on every signing attempt throws: inside `handleMessage` the throw is swallowed by the generic catch (`channel-manager.ts:3762`, a local `error` emit, no wire error, channel stays NORMAL); from the manager's `addHtlc` / `fulfillHtlc` / `failHtlc` / `updateFee` wrappers it propagates into node callers that do not catch (`lightning-node.ts:17202`, `:20781`). Because the point is persisted the wedge survives restart and reconnect (only another `revoke_and_ack` replaces it, which needs a `commitment_signed` we can no longer produce). Any inbound HTLC we fulfil has its preimage on the wire (`update_fulfill_htlc` is sent before the sign attempt) while the removal can never be committed, so every settlement ends in a force close. The peer can wedge every channel it has with us at zero cost.

## Suggested fix

`if (!isValidPublicKey(msg.nextPerCommitmentPoint)) return this._failChannelWithWireError(...)` before the store, and refuse a point equal to the current one. Apply the same check to `channel_reestablish.my_current_per_commitment_point` before it is stored as `dlpRemotePerCommitmentPoint` (`channel.ts:10160`).

---

<!-- 46-accept-channel-minimum-depth-unbounded.md -->
## Issue: accept_channel.minimum_depth is adopted unbounded, so an acceptor can lock the funder's channel indefinitely; the v2 opener ignores accept_channel2.minimum_depth entirely

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

---

<!-- 47-channel-state-machine-leniencies.md -->
## Issue: Channel state-machine leniencies: acceptor affordability counts trimmed HTLCs, reestablish gaps larger than one are tolerated, settles for uncommitted HTLCs are accepted, and upfront_shutdown_script is advertised but never enforced

Labels: bug

Found during a security audit of the channel state machine. Low-severity spec-conformance items; none loses our funds, but each lets a desynced or misbehaving session continue where a conforming node would fail cleanly, or (the first) fails an honest peer.

## 1. Acceptor-side affordability counts trimmed HTLCs

`handleUpdateAddHtlc` (`src/lightning/channel/channel.ts:3431-3438`) and `handleUpdateFee` (`:5419-5432`) price the funder's required fee with `funderCommitmentCostSats(..., this._countActiveHtlcs() + 1, ...)`, and `_countActiveHtlcs` (`:14796`) counts every PENDING or COMMITTED entry, trimmed ones included. BOLT 3 charges 172 WU only for untrimmed outputs, and LND, Eclair and CLN compute their send-side affordability that way. A funder holding k dust HTLCs that offers an HTLC or an `update_fee` it can afford by the spec formula but not by ours (a `172 * k * feerate / 1000` sat difference) is wire-failed by both arms, i.e. we force-close an honest peer at the boundary.

Fix: count the HTLCs that survive `filterUntrimmedHtlcs` at the relevant dust limit and feerate.

## 2. Reestablish tolerates counters more than one behind

`channel.ts:10490-10520` retransmits the latest `commitment_signed` whenever `msg.nextCommitmentNumber <= remoteCommitmentNumber`, even when the peer is two or more behind, where BOLT 2 says the node SHOULD send an error and fail the channel. The revocation side handles only `nextRevocationNumber + 1n === localCommitmentNumber` (`:10389`); a peer two or more revocations behind is not failed and the exchange continues until a later signature mismatch.

Fix: fail the channel on a gap larger than one in either counter.

## 3. Settles accepted for HTLCs never committed

`handleUpdateFulfillHtlc` / `handleUpdateFailHtlc` (`:3725`, `:4030`) accept a settle for an OFFERED entry still PENDING (never in any commitment), where BOLT 2 says MUST fail the channel. A premature fulfil carries a valid preimage, so no loss, but the state is off-spec.

Fix: require `state === COMMITTED` (or `addRemoteCommitted !== false`) before accepting a peer settle.

## 4. `option_upfront_shutdown_script` advertised but not enforced

`implementedFeatures()` claims the feature (`src/lightning/features/flags.ts:352`), but `handleShutdown` (`channel.ts:7076`) never compares the script with the `upfront_shutdown_script` the peer sent in `open_channel` / `accept_channel`. A peer that REQUIRES the feature is not disconnected, and the guarantee it believes it has is silently not enforced.

Fix: store the peer's upfront script and enforce equality in `handleShutdown`, or stop advertising the bit.
