# The default no-token loopback daemon can be driven by any web page (CSRF): parseBody ignores Content-Type, nothing validates Origin or Host, and beignet init mints no token

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
