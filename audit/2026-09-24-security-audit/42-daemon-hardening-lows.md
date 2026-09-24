# Daemon hardening: rate-limiter buckets never evicted after two requests, SSE streams have no cap or backpressure, /openapi.json is rebuilt per unauthenticated request, webhooks accept any target and carry preimages, and five smaller items

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
