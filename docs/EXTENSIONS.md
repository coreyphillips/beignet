# Host extensions

A host extension is code the operator names at start that runs inside the daemon, beside the wallet it serves. It gets the on-chain wallet, its own rows in the node's database, a logger and an event emitter. The daemon serves its routes under `/x/<id>` and relays its events on `GET /events`.

The contract exists for features that need the wallet's keys and coins in the same process, and that do not belong in the engine: a second protocol built on the wallet's UTXOs, for instance. It is not a plugin market. An extension is trusted exactly as much as the engine is, because it runs with the same keys.

Contract version: `beignet-extension-api/1` (`EXTENSION_API`, with `EXTENSION_API_VERSION = 1`). The number moves only on a breaking change.

## Naming an extension

Only the process that starts the daemon can name one:

```bash
beignet start --extension /opt/app/assets-host.js          # repeatable
BEIGNET_EXTENSIONS=/opt/app/a.js,/opt/app/b.js beignet start
```

`config.json` cannot, and no route can. `POST /config` and every other API call reach `config.json`, so a setting there would let an API caller load code into the process that holds the seed.

The path must be absolute. On POSIX the file (after symlinks are resolved) and its directory must belong to the user running the daemon or to root, and be writable by no one else. The daemon refuses to start on a path that fails these checks, on an `--extension` with no path after it, on a module that does not load, and on a description it cannot serve. It says which, as `START_FAILED`, and nothing is left running.

A library host passes the same objects to `BeignetNode.create({ extensions })` or `startDaemon({ extensions })`.

## The module

The file is a CommonJS module that exports `beignetExtension`: the extension, or a function returning it (or a promise for it).

```js
const { ExtensionError } = require('beignet/node');

exports.beignetExtension = ({ network, env, engineVersion, api }) => ({
	id: 'notes',
	version: '1.0.0',
	api: 1,
	events: ['saved'],
	routes: [
		{ method: 'GET', path: '/list', scopes: ['readonly'], summary: 'List notes' },
		{ method: 'POST', path: '/save', idempotent: true, summary: 'Save a note' }
	],
	attach({ wallet, storage, logger, emit, generation }) {
		return {
			handlers: {
				'GET /list': () => ({ notes: storage.list('note/') }),
				'POST /save': ({ body }) => {
					if (typeof body.text !== 'string') {
						throw new ExtensionError('TEXT_REQUIRED', 'text is required', 400);
					}
					storage.set(`note/${Date.now()}`, body.text);
					emit('saved', { length: body.text.length });
					return { saved: true };
				}
			},
			start() {},
			stop(reason) {},
			status: () => ({ notes: storage.list('note/').length })
		};
	}
});
```

| Field | Rule |
|-------|------|
| `id` | 2 to 32 characters: lowercase letters, digits and hyphens, starting with a letter. It is the route prefix (`/x/<id>`), the event prefix (`<id>:`) and the storage namespace (`x/<id>/`). It may not be the prefix of the node's own events (`channel`, `payment` and so on) |
| `version` | The extension's own version, reported by `GET /extensions` |
| `api` | The contract version it was built for. Anything but `1` refuses the start |
| `routes` | Static. `method` is `GET`, `POST` or `DELETE`; `path` is lowercase segments such as `/send/prepare`, with no parameters (those go in the query or the body) |
| `events` | The names it may emit: lowercase letters, digits and hyphens |
| `attach(context)` | Returns the attachment, or a promise for it |

The factory's argument carries `network`, the daemon's `env`, the engine's package version as `engineVersion`, and `api`. An extension that needs a particular engine release checks `engineVersion` itself and throws.

## Lifecycle

1. **Start refused or not.** Descriptions are checked before the instance lock and the database are taken.
2. **`attach(context)`** runs once the on-chain wallet exists and before the Lightning node is created, so nothing has spent from the wallet yet. It has 30 seconds. `context.generation` is 1.
3. **`start()`** runs in the background once the node is built. The daemon does not wait for it, so a slow extension never delays the node, and the extensions are started together, so one never delays another. It has no time limit: an extension stays `attached` until its `start()` returns, and is `ready` after. Routes are served from `attach` on: an extension that is not ready yet says so in its own answers.
4. **`stop('shutdown')`** runs when the daemon stops, before the node and the wallet do. On a graceful stop the storage still takes writes while it runs. The hooks of all extensions run together under one limit: 5 seconds, or half the time the shutdown was given when that is less. That wait is part of the shutdown's time, not added to it, so an extension that hangs shortens the node's wait for payments in flight and never delays the wallet's stop or the database's close. A node destroyed without a graceful stop (`BeignetNode.destroy()`, the fallback when the graceful one fails) fences the storage first and does not wait for the hook.

An in-process rebuild replaces the node and the database under a running daemon (a capsule restore, [RECOVERY-PROTOCOL.md](RECOVERY-PROTOCOL.md)). Then:

1. The extension's rows are copied into the database being installed, with the rest of the daemon's own state. From that copy on, `set` and `delete` through the running generation's storage throw: a write the installed database would not have is refused, not acknowledged and lost. Should the install give up before it replaces the database, they work again.
2. The storage view and the emitter of the running generation are fenced, synchronously, in the same turn as that copy. From that point every storage call through the old context throws `The database connection is not open`, and `emit` does nothing. Nothing the old generation does can reach the installed database.
3. `stop('rebuild')` runs, bounded. It must not expect to write.
4. `attach` runs again on the new wallet and database, with `generation` one higher, once the previous `stop` has returned or timed out. Then `start`.

Keep nothing from one generation for the next. Everything an extension needs after a rebuild is in its rows.

A daemon holding for a guardian restore has no node, so no extension is attached until the restore completes.

## What a failure does

| What breaks | What happens |
|-------------|--------------|
| The path, the module, or the description | The daemon does not start |
| `attach()` throws or does not answer in 30 seconds | The extension is `failed`. The node is built without it and the wallet runs. An attachment that arrives after the 30 seconds is stopped with `stop('shutdown')` |
| `attach()` returns handlers that do not match the routes | The extension is `failed`, and the `stop('shutdown')` of what it returned runs, so whatever `attach()` opened can be closed |
| `start()` throws | It is `failed` and its routes close at once; then its `stop('shutdown')` runs |
| `start()` never returns | It stays `attached`. The other extensions start, and the node runs |
| `stop()` throws or hangs | Logged; the node moves on after 5 seconds |
| `status()` throws, or returns something that is not JSON | Logged; `GET /extensions` reports the extension without `status` |
| A handler throws an `ExtensionError` | The caller gets that refusal (below) |
| A handler throws anything else, a `BeignetError` included | Logged with its stack; the caller gets a generic `500 INTERNAL_ERROR`. The engine's codes are not an extension's to answer with |

A failed or stopped extension's routes answer `503 EXTENSION_UNAVAILABLE` with the reason, not `404`: the route exists, and a restart may bring it back. `GET /extensions` reports each extension's `state` (`pending`, `attached`, `ready`, `failed`, `stopped`), the `error` of a failed one, and whatever its `status()` returns.

## Routes

A route is served at `/x/<id><path>` (and under `/v1`), through the same request path as the daemon's own:

- **Authentication and scopes.** `scopes` lists the non-admin scopes that may call the route: `readonly`, `invoice`, or both. Omitted means admin only. A path under `/x/` that no extension declared is admin only and answers `404`.
- **Rate limiting, CORS, the browser guards** apply unchanged.
- **Holds.** While the daemon holds for a restore or a restart, extension routes answer `503 NODE_RESTORE_PENDING` or `NODE_RESTART_REQUIRED` like every other route.
- **Body.** JSON, at most 1 MiB, or the route's `maxBodyBytes` (up to 32 MiB).
- **Answer.** Whatever the handler returns is wrapped as `{ "ok": true, "result": ... }`; a handler that returns nothing answers `null`.
- **Idempotency.** A `POST` declared `idempotent` honours `X-Idempotency-Key` the way the daemon's own routes do: a repeat with the same key and body gets the first answer, a concurrent repeat waits for it, and the same key with another body answers `409 IDEMPOTENCY_CONFLICT`. That cache is in memory. The handler also receives the key as `idempotencyKey`, and an extension that moves funds must record it in its own rows, so that a retry after a restart is recognised too. Any other `POST` that carries the header answers `400` and runs nothing.
- **OpenAPI.** The daemon's `GET /openapi.json` lists the routes with their `summary`, `requestSchema`, `responseSchema` and accepted scopes. `getOpenApiSpec()` describes the engine alone.

### Refusals

```js
throw new ExtensionError('INSUFFICIENT_BALANCE', 'Not enough to send', 409, {
	needed: '1200',
	held: '500'
});
```

answers with that status and

```json
{
	"ok": false,
	"error": {
		"code": "EXTENSION_ERROR",
		"message": "Not enough to send",
		"extension": {
			"id": "notes",
			"code": "INSUFFICIENT_BALANCE",
			"details": { "needed": "1200", "held": "500" }
		}
	}
}
```

`error.code` is always `EXTENSION_ERROR`, so the engine's own codes stay a closed set, and `error.extension.code` is the extension's (capitals, digits and underscores). The status is one of 400, 403, 404, 409, 410, 413, 422, 429, 500, 502, 503 and 504; anything else becomes 400.

The daemon reads the refusal by shape, not by class: any `Error` with a string `extensionCode`, and optionally `status` and `details`, is one. An extension that cannot import `ExtensionError` from the engine it runs in can throw its own.

## Storage

`context.storage` is the extension's rows in the node's SQLite database:

```ts
interface IExtensionStorage {
	get(key: string): string | null;
	set(key: string, value: string): void;
	delete(key: string): void;
	list(prefix: string): Array<{ key: string; value: string }>; // '' lists all
	transaction<T>(fn: () => T): T;
}
```

- Rows live in the `metadata` table under `x/<id>/`. Keys are given without that prefix, and one extension cannot read another's.
- Values are strings, encrypted at rest with the rest of the table when storage encryption is on (the default).
- Every call is synchronous and durable when it returns (the database runs with `synchronous = FULL`).
- `transaction(fn)` is atomic: a throw undoes every write `fn` made. `fn` must be synchronous. A promise it returns is not waited for, and writes made after an `await` are outside the transaction. Transactions do not nest: a call made while one is open throws before its `fn` runs, because an inner one could not be undone on its own.
- The rows are part of the database: `beignet backup` copies them, and an in-process restore carries them into the installed database (the carry is mandatory, so a restore that cannot copy them does not install).
- They are not in a static channel backup, and the recovery phrase does not recreate them. An extension whose rows are the only record of funds must offer its own export, and say so to its users.

The view needs a backend with `loadMetadataByPrefix` and `deleteMetadata`. SQLite and the in-memory backend have both; on an injected backend without them, `attach` sees storage calls throw.

## Events

`context.emit('saved', data)` reaches subscribers of `GET /events` as `event: notes:saved`, and webhooks registered for `notes:saved` or `*`. `data` must be JSON-safe. A name the extension did not declare is dropped with a warning in the log, and so is anything emitted after `stop`.

## The wallet

`context.wallet` is the engine's `Wallet`, the same instance the node uses. Two rules follow from sharing it:

- **Coins.** Anything the extension must keep out of ordinary coin selection (an output that carries something other than bitcoin) has to be frozen with the wallet's own freeze, which is persisted with the wallet's data. Do it in `attach`, before the node can spend.
- **Fees and broadcasts** go through the wallet's API. The daemon's spending limits (`maxPaymentSats`, `dailySpendLimitSats`) apply to the daemon's own routes, not to what an extension spends through the wallet directly. An extension that spends states its own limits.

The Lightning node is not part of version 1 of the contract.

## Feature detection

- `GET /extensions` (scope `readonly`; CLI `beignet extensions`) answers `{ api, extensions }`. An engine without the contract answers `404`.
- A supervisor that decides whether to name an extension before it starts the daemon can look for the literal `beignet-extension-api/1` in the installed `dist/cli/extension.js`.
