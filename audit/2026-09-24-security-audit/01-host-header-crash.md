# One unauthenticated request with an unparsable Host header crashes the daemon: new URL() throws inside the void-wrapped request handler before auth or rate limiting run

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
