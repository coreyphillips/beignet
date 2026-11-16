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
3. **`bind(node)`**, for an attachment that has one, runs as soon as the Lightning node is constructed: before it restores its stored channels, so before any hook of `auxiliaryChannels` can be called, and before any `start()` ([Asset channels](#asset-channels)).
4. **`start()`** runs in the background once the node is built. The daemon does not wait for it, so a slow extension never delays the node, and the extensions are started together, so one never delays another. It has no time limit: an extension stays `attached` until its `start()` returns, and is `ready` after. Routes are served from `attach` on: an extension that is not ready yet says so in its own answers.
5. **`stop('shutdown')`** runs when the daemon stops, before the node and the wallet do. On a graceful stop the storage still takes writes while it runs. The hooks of all extensions run together under one limit: 5 seconds, or half the time the shutdown was given when that is less. That wait is part of the shutdown's time, not added to it, so an extension that hangs shortens the node's wait for payments in flight and never delays the wallet's stop or the database's close. A node destroyed without a graceful stop (`BeignetNode.destroy()`, the fallback when the graceful one fails) fences the storage first and does not wait for the hook.

An in-process rebuild replaces the node and the database under a running daemon (a capsule restore, [RECOVERY-PROTOCOL.md](RECOVERY-PROTOCOL.md)). Then:

1. The extension's rows are copied into the database being installed, with the rest of the daemon's own state. From that copy on, `set` and `delete` through the running generation's storage throw: a write the installed database would not have is refused, not acknowledged and lost. Should the install give up before it replaces the database, they work again.
2. The storage view and the emitter of the running generation are fenced, synchronously, in the same turn as that copy. From that point every storage call through the old context throws `The database connection is not open`, and `emit` does nothing. Nothing the old generation does can reach the installed database.
3. `stop('rebuild')` runs, bounded. It must not expect to write.
4. `attach` runs again on the new wallet and database, with `generation` one higher, once the previous `stop` has returned or timed out. Then `bind` with the new node, then `start`.

Keep nothing from one generation for the next. Everything an extension needs after a rebuild is in its rows.

A daemon holding for a guardian restore has no node, so no extension is attached until the restore completes.

## What a failure does

| What breaks | What happens |
|-------------|--------------|
| The path, the module, or the description | The daemon does not start |
| `attach()` throws or does not answer in 30 seconds | The extension is `failed`. The node is built without it and the wallet runs. An attachment that arrives after the 30 seconds is stopped with `stop('shutdown')` |
| `attach()` returns handlers that do not match the routes | The extension is `failed`, and the `stop('shutdown')` of what it returned runs, so whatever `attach()` opened can be closed |
| The attachment's `auxiliaryChannels`, `fixedOutputFees` or `bind` is malformed, or the wallet refuses the fee policy | The extension is `failed` and its `stop('shutdown')` runs. The node is built without its provider, which refuses the start when asset channels are stored (`ASSET_PROVIDER_REQUIRED`) |
| Two extensions both supply `auxiliaryChannels` | The start is refused: `ASSET_PROVIDER_CONFLICT` |
| `bind()` throws | The extension is `failed` and its `stop('shutdown')` runs. If the node is being built with its provider, nothing is restored and the start is refused: `ASSET_PROVIDER_FAILED` |
| `start()` throws | It is `failed` and its routes close at once; then its `stop('shutdown')` runs. An extension whose provider the node holds is the exception: it is not stopped and its storage stays open, and its `stop` runs when the node stops or is rebuilt |
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

The Lightning node is not in the context. An attachment that needs it asks for it with `bind(node)`.

## Asset channels

Three optional members of the attachment reach the Lightning node. They were added to version 1 without a new contract number, because an engine that predates them reads an attachment by the members it knows and ignores the rest: the extension attaches there as before, its `bind` is never called, and the node runs no asset channels. An extension tells the two apart by whether `bind` ran before its `start()`.

```ts
interface IExtensionAttachment {
	// ...handlers, start, stop, status
	auxiliaryChannels?: IAuxiliaryChannelConfig;
	fixedOutputFees?: {
		maxFeeSatoshis: bigint;
		maxTotalFeeSatoshis: bigint;
		maxPreparationFeeSatoshis: bigint;
		feeCoinCount?: number; // 1 to 16, 4 when left out
		preparationFeeRatePerVbyte?: number; // 1 to 10000, 1 when left out
	};
	bind?(node: LightningNode): void;
}
```

- **`auxiliaryChannels`** is handed to the node as its `auxiliaryChannels`, untouched: the provider that extends the channel state machine and the hooks that tie funding, payments and forwards to the extension's protocol. One extension may supply it. The node holds it for the life of the build, whatever becomes of the extension afterwards: an attachment with no handlers and no `start`, one whose `start()` has not returned, and one whose `start()` threw all leave their provider with the node. So the provider has to answer from the moment the node is bound. When the `start()` of such an extension throws, it is reported `failed` and its routes close, but it is not stopped and its storage is not fenced: the node still calls its provider for the channels that exist, which it may have to defend on chain. Refusing new activity from then on is the extension's own to do. Its `stop` runs when the node stops or is rebuilt.

Asset channels and the recovery mode. A wallet whose recovery mode is a guardian mode (`async-remote` or `quorum`) neither opens nor accepts an asset channel: `openAuxiliaryChannel` throws `AuxiliaryGuardianModeError` (`AUXILIARY_GUARDIAN_MODE`), and an incoming asset opening is refused. A wallet that already holds asset channels does not start in a guardian mode at all: the daemon refuses the boot with `ASSET_GUARDIAN_START_REFUSED` before a guardian is asked anything, before the node is built and before anything is replicated (the engine's own refusal, for a host that builds the node itself, is `AuxiliaryGuardianStartError`, `AUXILIARY_GUARDIAN_START_REFUSED`), and the database is left as it was, so the wallet starts again in `peer-storage` or `off`, where the channels can be closed. The recovery journal carries the node's rows for a channel and nothing of what the extension keeps beside them, and a guardian restore puts those rows on another device. So no guardian journal ever holds an asset channel, a guardian restore is never handed a provider, and a journal from the guardians that does hold one is refused whole as one this build never replicates (`AuxiliaryGuardianRestoreError`, `AUXILIARY_GUARDIAN_RESTORE_REFUSED`; `ASSET_RESTORE_REFUSED` from the daemon). That refusal comes after the takeover, because the driver downloads the journal only once the old writer is fenced, which is why the refusals at the start and at the opening come first. For the same reason a restore from peer storage that holds asset channels is refused, with nothing of it installed, unless the `auxiliaryChannels` the extension supplied has a `canRestore(channels)` that returns `true` for them: `ASSET_RESTORE_REFUSED`, or `ASSET_PROVIDER_REQUIRED` when no attached extension supplies asset channels. Each channel is given with its id, its peer, where it comes from (`journal` or `static-backup`) and, from the journal, its asset funding data. An entry of a static channel backup that is an asset channel is skipped on the same terms. `canRestore` is synchronous, and only a plain `true` is a yes.

Asset payments and the spending limits. An asset payment leaves through the node the extension was given (`sendPaymentToRoute` with `assetPayment`), not through a route of the daemon, so the daemon sets the node's payment gate (`setAuxiliaryPaymentGate`) on every node that runs asset channels. Each asset payment is admitted there exactly as `POST /payment/send-to-route` admits a route: drain mode, the per-payment limit, the daily limit, and a claim on the daily budget under the payment hash, all on what the route asks its first hop to carry, in sats, and never less than the bitcoin the HTLC carries. A settled payment is charged to the same daily ledger as any Lightning payment. A refusal is thrown from the send as `AuxiliaryPaymentError` with code `ASSET_PAYMENT_REFUSED`, the limit's own code in `reason` (`SPENDING_LIMIT_EXCEEDED` or `SERVICE_DRAINING`) and its sentence in `message`; nothing was recorded, sent or claimed. The gate is the daemon's: an extension that sets another, or removes it, takes its payments out of the wallet's limits.

Asset channels and an older release. An asset channel's row is stored inside an envelope (`{ "assetChannelRow": 1, "channel": { ... } }`) that a release from before asset channels cannot decode; a channel without asset state is stored as the bytes it always was. The published 0.42.0, started over a database that holds an asset channel, skips that row as corrupt, reports it (the storage's `onCorruptRow` callback and `corruptRowCount()`, which the daemon logs as `Skipped corrupted storage row during load`), starts, runs its ordinary channels, and leaves the row and everything else stored for the channel as it was, so a return to a build that knows asset channels has the channel whole. With the recovery journal on it also records `recovery_capsule_rebase_failed` and writes no new frame, because it will not snapshot a database it cannot fully read. While the older release runs, the asset channel is neither run nor watched: nothing answers its peer, enforces an HTLC deadline or punishes a revoked commitment, so a downgrade over an open asset channel is for getting back, not for staying. `tests/lightning/auxiliary-downgrade.test.ts` drives the published 0.42.0 over a database this build wrote; it needs `BEIGNET_RELEASED_0_42_0` to name an installed copy and is skipped without it.
- **`fixedOutputFees`** bounds what the wallet may spend on the fees of an asset channel's transactions whose outputs are fixed, which cannot pay a fee from change. With it the wallet splits a coin into `feeCoinCount` equal fee coins, keeps them frozen, and spends one whole per transaction. `maxFeeSatoshis` is the most one transaction may burn and the size of a fee coin, `maxPreparationFeeSatoshis` the most one split may pay in its own fee, and `maxTotalFeeSatoshis` the most all of them together may ever commit. That last one is a lifetime budget kept in a journal in the node's database: it is charged the cap of each fee action still open, what a retired one burned, and the fee of each split. The three bounds govern new actions and new splits only. A policy lowered below what the journal holds still builds and completes everything recorded, and refuses only new actions (`FEE_BUDGET_EXHAUSTED`, with the figures). It is read only beside `auxiliaryChannels`, and without it the wallet prepares no fee coins and chooses coins exactly as it does on a node with no extension.
- **`bind(node)`** is called once per build with that build's `LightningNode`, as soon as it is constructed and before it restores its stored channels: no hook of `auxiliaryChannels` runs before it. It runs outside any storage transaction and before any `start()`. The node has restored and started nothing yet, so keep it and ask nothing of it there. It is synchronous: a promise it returns is not waited for. An in-process rebuild attaches again and binds the new node to the new attachment, so keep no node from one generation for the next.

A daemon whose database holds asset channels does not start without the provider that runs them. It answers `ASSET_PROVIDER_REQUIRED` and changes no stored row, so the same database starts once the extension is named again. Signing for such a channel as an ordinary one would leave the asset out of the commitment.

## Feature detection

- `GET /extensions` (scope `readonly`; CLI `beignet extensions`) answers `{ api, extensions }`. An engine without the contract answers `404`.
- A supervisor that decides whether to name an extension before it starts the daemon can look for the literal `beignet-extension-api/1` in the installed `dist/cli/extension.js`.
- The asset channel members have no marker of their own. An extension that supplies them finds out at run time: `bind` is called before `start()` on an engine that reads them, and never on one that does not.
