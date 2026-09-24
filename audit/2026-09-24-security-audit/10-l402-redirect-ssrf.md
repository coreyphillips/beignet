# POST /l402/fetch follows redirects into private targets before the private-network guard re-runs (blind SSRF from the node's machine)

Labels: bug

Found during a security audit of the L402 client.

## What the code does

`BeignetNode.l402Fetch` (`src/cli/beignet-node.ts:10805-10838`) runs `_assertL402TargetAllowed(url)` on the caller's URL, then calls `l402Fetch`, which uses the global `fetch` with its default redirect policy (`src/lightning/l402/client.ts:206-233`; `withTimeout(withAuthorization(init, credential), options)` sets no `redirect`). Node's fetch follows up to 20 redirects, and 307/308 preserve the method and body. Only after the whole chain has been followed does the code check `result.response.url`, and that check only refuses to relay the body: the comment at `:10830` acknowledges "a redirect can land on a host the caller never named".

`isPrivateNetworkUrl` (`client.ts:596-609`) documents that name-based checks cannot stop DNS rebinding; that is a separate, known limitation. This issue is about redirects, which the code can control.

## Failure scenario

An admin-scoped caller (or the CSRF/no-token scenario in the companion daemon issue) sends `POST /l402/fetch {"url":"https://attacker.example/x","method":"POST","body":"..."}`. The attacker's server answers `307 Location: http://169.254.169.254/latest/api/token` or `http://127.0.0.1:2112/...` or an internal admin service. The node's fetch performs the caller's POST against the internal target with the caller's body. The caller receives `PRIVATE_NETWORK_REFUSED`, but the side effect has already happened. Node's undici strips `Authorization` on cross-origin redirects, so the L402 credential itself does not leak; the SSRF is blind.

## Suggested fix

Pass `redirect: 'manual'` and, on a 3xx, run `_assertL402TargetAllowed` on the `Location` target before following it (with a hop limit), or refuse redirects entirely for this endpoint. Apply the same check to the challenge-following code path.
