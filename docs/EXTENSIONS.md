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
| The attachment's `auxiliaryChannels`, `fixedOutputFees` or `bind` is malformed | The extension is `failed` and its `stop('shutdown')` runs. The node is built without its provider, which refuses the start when asset channels are stored (`ASSET_PROVIDER_REQUIRED`) |
| The wallet refuses the fee policy | The extension stays attached and the node is built with its provider, so a wallet that holds asset channels starts and runs them. It has no fee coin pool: `GET /extensions` reports `fixedOutputFees: { available: false, error: { code: "FEE_POLICY_REFUSED", remedy: "operator", message } }` for the extension, `node.getFixedOutputFeeStatus()` answers `{ available: false, error }`, the node opens and accepts no asset channel, and whatever needs a fee coin fails with that `FixedOutputFeeError`. Supply a policy the wallet takes and restart |
| The attachment supplies `auxiliaryChannels` without `fixedOutputFees` | The node is built with the provider and a wallet that keeps no fee coin pool. It does not offer fixed HTLC outputs (feature bit 451 is not in its init), so `getAuxiliaryHtlcMode(peer)` and an opening are refused with `New asset channels require fixed HTLC outputs or explicit peer compatibility` unless the provider's `allowLegacyHtlcSignatures` allows the peer, on both sides. `GET /extensions` reports `fixedOutputFees: { available: false, supplied: false }` for the extension, and `node.getFixedOutputFeeStatus()` answers `undefined`. Supply a fee policy and restart |
| Two extensions both supply `auxiliaryChannels` | The start is refused: `ASSET_PROVIDER_CONFLICT` |
| `bind()` throws | The extension is `failed` and its `stop('shutdown')` runs. If the node is being built with its provider, nothing is restored and the start is refused: `ASSET_PROVIDER_FAILED` |
| `start()` throws | It is `failed` and its routes close at once; then its `stop('shutdown')` runs. An extension whose provider the node holds is the exception: it is not stopped and its storage stays open, and its `stop` runs when the node stops or is rebuilt |
| `start()` never returns | It stays `attached`. The other extensions start, and the node runs |
| `stop()` throws or hangs | Logged; the node moves on after 5 seconds |
| `status()` throws, or returns something that is not JSON | Logged; `GET /extensions` reports the extension without `status` |
| A handler throws an `ExtensionError` | The caller gets that refusal (below) |
| A handler throws anything else, a `BeignetError` included | Logged with its stack; the caller gets a generic `500 INTERNAL_ERROR`. The engine's codes are not an extension's to answer with |

A failed or stopped extension's routes answer `503 EXTENSION_UNAVAILABLE` with the reason, not `404`: the route exists, and a restart may bring it back. `GET /extensions` reports each extension's `state` (`pending`, `attached`, `ready`, `failed`, `stopped`), the `error` of a failed one, whatever its `status()` returns, and `fixedOutputFees` only when the wallet refused the fee policy it supplied.

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
		preparationFeeRatePerVbyte?: number; // the least a split pays: 1 to 10000, 1 when left out
		walletCallTimeoutMs?: number; // 1 to 600000 ms, 30000 when left out
	};
	bind?(node: LightningNode): void;
}
```

- **`auxiliaryChannels`** is handed to the node as its `auxiliaryChannels`, untouched: the provider that extends the channel state machine and the hooks that tie funding, payments and forwards to the extension's protocol. One extension may supply it. The node holds it for the life of the build, whatever becomes of the extension afterwards: an attachment with no handlers and no `start`, one whose `start()` has not returned, and one whose `start()` threw all leave their provider with the node. So the provider has to answer from the moment the node is bound. When the `start()` of such an extension throws, it is reported `failed` and its routes close, but it is not stopped and its storage is not fenced: the node still calls its provider for the channels that exist, which it may have to defend on chain. Refusing new activity from then on is the extension's own to do. Its `stop` runs when the node stops or is rebuilt. At a graceful shutdown the extension that supplies the provider is the last to stop: its routes close with the others, but its `stop()` runs, and its storage is fenced, only after the node has drained its in-flight HTLCs, because the node calls the provider for every commitment until then.

Asset channels and the recovery mode. A wallet whose recovery mode is a guardian mode (`async-remote` or `quorum`) neither opens nor accepts an asset channel: `openAuxiliaryChannel` throws `AuxiliaryGuardianModeError` (`AUXILIARY_GUARDIAN_MODE`), and an incoming asset opening is refused. A wallet that already holds asset channels does not start in a guardian mode at all: the daemon refuses the boot with `ASSET_GUARDIAN_START_REFUSED` before a guardian is asked anything, before the node is built and before anything is replicated (the engine's own refusal, for a host that builds the node itself, is `AuxiliaryGuardianStartError`, `AUXILIARY_GUARDIAN_START_REFUSED`), and the database is left as it was, so the wallet starts again in `peer-storage` or `off`, where the channels can be closed. The recovery journal carries the node's rows for a channel and nothing of what the extension keeps beside them, and a guardian restore puts those rows on another device. So no guardian journal ever holds an asset channel, a guardian restore is never handed a provider, and a journal from the guardians that does hold one is refused whole as one this build never replicates (`AuxiliaryGuardianRestoreError`, `AUXILIARY_GUARDIAN_RESTORE_REFUSED`; `ASSET_RESTORE_REFUSED` from the daemon). That refusal comes after the takeover, because the driver downloads the journal only once the old writer is fenced, which is why the refusals at the start and at the opening come first. For the same reason a restore from peer storage that holds asset channels is refused, with nothing of it installed, unless the `auxiliaryChannels` the extension supplied has a `canRestore(channels)` that returns `true` for them: `ASSET_RESTORE_REFUSED`, or `ASSET_PROVIDER_REQUIRED` when no attached extension supplies asset channels. Each channel is given with its id, its peer, where it comes from (`journal` or `static-backup`) and, from the journal, its asset funding data. An entry of a static channel backup that is an asset channel is skipped on the same terms. `canRestore` is synchronous, and only a plain `true` is a yes. It is asked before the install opens, outside any storage transaction and with nothing of the restore written yet, for exactly the channels the restore then installs.

A restore may leave its asset channels out. The refusal of a capsule restore lists them: `error.details.assetChannels` is an array of `{ channelId, peerPubkey, capacitySats }`, one for each asset channel the capsule holds, on both `ASSET_RESTORE_REFUSED` and `ASSET_PROVIDER_REQUIRED`. Run again as `POST /recovery/restore-capsule` with `{ "confirm": true, "omitAssetChannels": true }` (CLI `beignet recovery restore-capsule --omit-asset-channels`; `restoreFromCapsules({ omitAssetChannels: true })`), the restore installs everything else and answers with the same list under `omittedAssetChannels`, present only when a channel was left out. Only the boolean `true` asks for it, and anything that is not a boolean is `INVALID_PARAMS`. Every asset channel the capsule holds is then left out, whether or not an extension could have restored it, and no `canRestore` is asked. No row of such a channel is written: not its state, its chain monitor, its stored messages or its HTLC rows. Its key index is kept, so its keys are never derived for another channel, and payments and invoices stay as the wallet's history. At Tier 1, where the capsule's backup is all there is, the backup's asset entries are left out of the recovery and listed the same way, and at Tier 2 a channel left out is not sent through the peer's recovery either. A channel left out is not watched and not closed by this wallet: whatever it held stays where the peer and the capsule have it, and the peer will in time close it on its own. A payment that was in flight on a channel left out is unresolved. Every payment record that is PENDING at the restore, sent or received, and has an HTLC in the stored state of such a channel is marked: `unresolved: { code: 'CHANNEL_OMITTED_AT_RESTORE', channelIds }` on the record (`IPaymentInfo.unresolved`), on its row of `GET /payments` and, for an invoice that is not paid, on its row of `GET /invoices`; the restore lists the marked by payment hash in `unresolvedPayments`. The record stays PENDING, because nothing else is true: the peer still has the channel and may settle or fail the HTLC, and a capsule can be older than the wallet's last word on it, so neither a payment sent nor a payment received can be said to have failed. No clock fails a marked record, `POST /payment/cancel` refuses it with `PAYMENT_UNRESOLVED` (409), no `payment:failed`, `payment:sent`, `payment:received` or `invoice:settled` is sent for it, no bitcoin total counts it as paid, and its hash is not sent for again. A wait on it (`awaitPaymentResolution`) ends at once with `PaymentUnresolvedError`. Nothing of the channel is acted on: no HTLC of it is held, and a settle of a held invoice on it moves nothing. A marked payment leaves the mark only when an HTLC on a channel the wallet does hold settles it. There is no call that settles or fails a marked payment by hand, and none is meant: the wallet cannot know how the HTLC ended while the peer still holds the channel, so an operator's word would put a guess on the record as a fact. The journal installed is the capsule's own and still names the channels, and the wallet does not hand that journal on: the node takes a snapshot of its tables before the first capsule of each run, so the first capsule a restored wallet gives its peers holds no row of a channel left out and carries the marks, and a restore from that capsule is not refused and brings no channel back. Only a host that composes a capsule itself from the restored database before any node ran on it gets one that still names the channels; a restore from that one is refused as the first was and leaves them out again when asked. A wallet set to apply a capsule without asking (`recoveryAutoApply`) runs the same restore with nothing asked of it, so it is refused by the same code, installs nothing and never leaves a channel out by itself. Nobody called, so the refusal is kept where a client reads it: `GET /recovery/status` answers `autoApply.phase: "refused"`, `autoApply.lastReason` beginning with the code, and `autoApply.refusal: { code, assetChannels }` with the list the route would answer, and the `recovery:restore-progress` event of type `capsule:auto-refused`, over SSE and webhooks, carries the same `refusal`. `capsules.candidates` and `capsules.best` of the same answer say the capsule still waits, the apply is not run a second time, and the confirmed call with `omitAssetChannels` restores it; `refusal` is gone from the status once a restore is installed. A refusal that is not about asset channels has no `refusal`. At Tier 1 nothing is refused: an asset entry of the backup is skipped with its reason and the rest is recovered, by the route and by the automatic apply alike, and the entries skipped are listed as a refusal lists them, under `skippedAssetChannels` in the route's answer and under `autoApply.skippedAssetChannels` after an automatic apply. There is no other way in: the CLI command calls the route, and a daemon that starts over a restore whose file swap did not complete finishes that install as it was decided, refused or asked for, and decides nothing again. The engine's own option, for a host that calls `restoreFromRecoveryCapsule` or `restoreBestRecoveryCapsule` itself, is `omitAuxiliaryChannels: true`, with the list in the result's `omittedAuxiliaryChannels` and, on a refusal, read by `refusedAuxiliaryChannels(err)`.

Asset payments and the spending limits. An asset payment leaves through the node the extension was given (`sendPaymentToRoute` with `assetPayment`), not through a route of the daemon, so the daemon sets the node's payment gate (`setAuxiliaryPaymentGate`) on every node that runs asset channels. Each asset payment is admitted there exactly as `POST /payment/send-to-route` admits a route: drain mode, the per-payment limit, the daily limit, and a claim on the daily budget under the payment hash, all on what the route asks its first hop to carry, in sats, and never less than the bitcoin the HTLC carries. A settled payment is charged to the same daily ledger as any Lightning payment. A refusal is thrown from the send as `AuxiliaryPaymentError` with code `ASSET_PAYMENT_REFUSED`, the limit's own code in `reason` (`SPENDING_LIMIT_EXCEEDED` or `SERVICE_DRAINING`) and its sentence in `message`; nothing was recorded, sent or claimed. The gate is the daemon's: an extension that sets another, or removes it, takes its payments out of the wallet's limits.

Asset channels, proofs and rebalances. The proof of a payment that asset HTLCs carried (`getPaymentProof`, `GET /payment/proof`) has `auxiliary: true` and `auxiliaryValueSats`, since its `amountSats` and `feeSats` are the bitcoin that carried the asset; the proof of any other payment is what it was. A rebalance never has an asset channel as either of its two channels: the engine refuses it with `AuxiliaryPaymentError` `ASSET_PAYMENT_UNSUPPORTED` naming the channel, and the daemon with `INVALID_PARAMS` before its fee cap is charged. A hold invoice that an asset HTLC pays says so while the HTLC is held and after: the node's `hold:accepted`, `hold:settled` and `hold:cancelled` events and the rows of `listHoldInvoices()` and `listHeldHtlcs()` carry `auxiliary: true` when a part of the set holds units, and so do the daemon's `hold:*` events, over SSE and webhooks, and its `GET /invoices/held` rows. `heldAmountMsat` is unchanged: it is what the node holds for the HTLC, which for an asset HTLC is what the provider valued it at. The row of a cancelled hold, which holds nothing, has no mark, and neither has anything of an ordinary hold. A swap is not funded against a held asset HTLC: the snapshot of the held set that the swap provider reads says a set with an HTLC that holds units is not complete, whatever the provider valued it at, so the swap pays nothing out on the chain and the set is failed back with its invoice like any set that fell short; `getHeldInvoiceSnapshot` itself answers what it did.

Asset channels and the balance. `getBalance()` and `GET /balance` say the bitcoin on this wallet's side of its asset channels apart from every bitcoin figure: `assetChannelClosingSats` for those that are closing (shutting down, negotiating a close, or force closed with the wallet's balance output not yet spent in a block), and `assetChannelSats` for every other one that is not over, whatever its state: still opening; open; waiting for its peer; failed and not yet closed. Every asset channel that is not over is in exactly one of the two. A channel is counted once its funding transaction is out: one this wallet funds from the moment the node has broadcast the transaction and the network took it, one the peer funds from the moment the node has seen it confirmed (`node.isFundingBroadcastOrConfirmed(channelId)` is the engine's answer). Until then it is in neither, because the coins a funding transaction spends are still in `onchain` while the transaction only exists, so an opening given up between `funding_created` and the broadcast is never counted. A funding the host signs and publishes itself (`prevoutScripts`) is counted from its confirmation. After a restart a channel whose funding is still unconfirmed is counted again once the node has handed the retained transaction to the network again, which it does when it starts and on every block. Neither figure is in `lightning` or `total`, and each is present only while the wallet has such a channel, so the answer of a wallet without one has the keys it always had. A closing asset channel is in no figure for bitcoin on its way back to the wallet (`pendingCloseBalanceSats`): its bitcoin stays under the asset outputs the provider closes or sweeps to, and is the host's to show from there.

Asset channels and mainnet readiness. The channel checks of `getMainnetReadiness()` are about sending and receiving bitcoin, so they read ordinary channels only. A wallet whose only channels are asset channels is told so by the four checks whose sentence for a wallet with no channel would not be true of it: `ANCHOR_CHANNELS_PREFERRED` answers `No ordinary Lightning channel yet (anchor will be used by default); asset channels are not counted here`, `SUFFICIENT_CHANNELS` answers `No ordinary Lightning channel yet; asset channels are not counted here`, `HAS_ACTIVE_CHANNEL` answers `No active ordinary Lightning channel: open one to send and receive bitcoin over Lightning; asset channels are not counted here` and `CHANNEL_BALANCE_HEALTH` answers `No active ordinary Lightning channel to assess; asset channels are not counted here`, each with the status it has for a wallet with no channel, so the score is that wallet's too. A wallet without an asset channel is answered what it always was, and so is a wallet that holds an ordinary channel, ready or not, whatever asset channels are beside it.

Asset channels and an older release. An asset channel's row is stored inside an envelope (`{ "assetChannelRow": 1, "channel": { ... } }`) that a release from before asset channels cannot decode; a channel without asset state is stored as the bytes it always was. The published 0.42.0, started over a database that holds an asset channel, skips that row as corrupt, reports it (the storage's `onCorruptRow` callback and `corruptRowCount()`, which the daemon logs as `Skipped corrupted storage row during load`), starts, runs its ordinary channels, and leaves the row and everything else stored for the channel as it was, so a return to a build that knows asset channels has the channel whole. With the recovery journal on it also records `recovery_capsule_rebase_failed` and writes no new frame, because it will not snapshot a database it cannot fully read. While the older release runs, the asset channel is neither run nor watched: nothing answers its peer, enforces an HTLC deadline or punishes a revoked commitment, so a downgrade over an open asset channel is for getting back, not for staying. `tests/lightning/auxiliary-downgrade.test.ts` drives the published 0.42.0 over a database this build wrote; it needs `BEIGNET_RELEASED_0_42_0` to name an installed copy and is skipped without it.
- **`fixedOutputFees`** bounds what the wallet may spend on the fees of an asset channel's transactions whose outputs are fixed, which cannot pay a fee from change. With it the wallet keeps a pool of fee coins. When a transaction needs a fee that no coin of the pool covers, the wallet splits one confirmed ordinary coin into at most `feeCoinCount` equal fee coins, each the size of the fee that was asked for, pays the change back to itself, and the transaction then spends fee coins whole. Only fee coins the pool's own splits made are spent this way: an ordinary coin is never burned whole, however small. From the moment a split is signed its fee coins are left alone by every ordinary coin selection, and once the wallet lists them they are frozen, until a fee action takes one. `maxFeeSatoshis` is the most one fee action may burn across all its replacements, not the size of a fee coin. `maxPreparationFeeSatoshis` is the most one split may pay in its own fee: a split that cannot fit it makes fewer coins, and when not even one coin fits it is refused (`FEE_PREPARATION_FEE_EXCEEDS_CAP`) with nothing recorded. `maxTotalFeeSatoshis` is the most all of them together may ever commit. That last one is a lifetime budget kept in a journal in the node's database: it is charged what each fee action still open can still spend, what a retired one was charged, and the fee of each split. An open action can still spend its cap until it has fee coins; from then on it can spend the fee coins it holds, with any it let go of that an earlier form of its spend may still burn, and never more than its cap. So a spend that is out holds the fee it carries, not its cap, and a raise that takes more fee coins needs room in the budget for the difference: when there is none the raise is refused (`FEE_BUDGET_EXHAUSTED`) and the spend stays out at the fee it has. The budget stays a hard total: what is held and what was spent never pass `maxTotalFeeSatoshis`. A retired action is charged the fee coins that the transaction named at its retirement spent, and the coins that transaction did not spend go back to the pool. One retired with no transaction named is charged its whole cap, because a wallet that still lists a coin does not show it unspent. The three bounds govern new actions and new splits only. A policy lowered below what the journal holds still builds and completes everything recorded, and refuses only new actions (`FEE_BUDGET_EXHAUSTED`, with the figures). Every refusal of the pool is a `FixedOutputFeeError` with a stable `code` and a `remedy`: `wait` (`FEE_PREPARATION_PENDING`, `FEE_PREPARATION_NOT_PUBLISHED`, `FEE_WALLET_TIMEOUT`, `FEE_WALLET_UNAVAILABLE`, `FEE_RESERVATION_REFUSED`), `operator` (`FEE_BUDGET_EXHAUSTED`, `FEE_FUNDS_UNAVAILABLE`, `FEE_ACTION_CAP_EXHAUSTED`, `FEE_PREPARATION_FEE_EXCEEDS_CAP`, `FEE_PREPARATION_SIGNING_FAILED`, and `FEE_POLICY_REFUSED` when the wallet refused the policy itself and there is no pool) or `none` (`FEE_ACTION_RETIRED`, `FEE_INPUT_UNAVAILABLE`). One split that cannot go on holds back no fee action that the coins already in the pool can serve. `walletCallTimeoutMs` (1 through 600000, default 30000) bounds how long the pool waits for any one wallet call, so a call that never answers fails that one selection with `FEE_WALLET_TIMEOUT` and not every later one. The fee journal is not carried by a recovery capsule or a guardian journal: a restore starts the budget afresh, and the freezes the pool left in the wallet are released when the wallet is next built. An extension reads the pool through the node it was bound to: `node.getFixedOutputFeeStatus(forFeeSatoshis?)` answers the budget (`totalSatoshis`, `reservedSatoshis`, `spentSatoshis`, `remainingSatoshis`), the fee coins no action holds (`feeCoins.ready` confirmed, `feeCoins.unconfirmed`), the open `actions` with their ids and caps, the `splits` on their way with their state, the `lastRefusal` a fee selection ended with (`code`, `remedy`, and `at` in milliseconds), and `preparation`: whether a split for a fee coin of `forFeeSatoshis` (the policy's `maxFeeSatoshis` when left out) could be made now, that is, whether the wallet lists a confirmed ordinary coin of at least `neededSatoshis` and the budget has room, so a host can warn a user whose wallet could not pay to claim an HTLC. Asking makes no split and changes nothing, and the answer is `undefined` on a node without a fee policy. That answer has `available: true`. When the wallet refused the policy the answer is `{ available: false, error }`, the error being the `FEE_POLICY_REFUSED` refusal. It is read only beside `auxiliaryChannels`, and without it the wallet prepares no fee coins and chooses coins exactly as it does on a node with no extension.
- **The rate of a split, and a deadline.** A split pays the rate of the transaction it is made for (the node's rate for that spend, rounded up to a whole sat/vB), never less than `preparationFeeRatePerVbyte` and never more in all than `maxPreparationFeeSatoshis`: when the rate asked does not fit that cap, the split pays the highest rate that does. Its input says it may be replaced. While a spend waits on a split that has not confirmed, the pool replaces the split by one that pays more: in the next block when the spend is asked at a higher rate than the split pays, otherwise 6 blocks after the split went out, or 2 blocks when the spend has a deadline within 18 blocks (the distance at which the node closes a channel to claim an HTLC). A replacement pays the rate of the spend or half as much again as the split it replaces, whichever is more, within the same cap, and at least 1 sat/vB of its own size more in all. It has the same fee coins at the same positions, every fee coin the pool or an action held follows it, and the budget is charged the difference. A split one of whose fee coins was spent is not replaced. A fee coin that the wallet no longer lists leaves the action it was pledged to and another takes its place, unless it is an input of a transaction the action is replacing that the wallet's server knows; a spend that was refused for a coin spent elsewhere is therefore funded from another coin at the next raise, and the action's record keeps the coin it let go of, which is charged at retirement only if the transaction that settled the output spent it. A retirement the wallet refuses is tried again on the next block and after a start. A fee action opened for an output of a commitment that was seen and did not confirm is retired once the commitment that confirmed in its place is settled for good: it is charged nothing and its coins go back to the pool. When a block takes a split that was replaced, its fee coins are held under its id again and the budget is charged what that split paid. A claim by preimage has a deadline, the expiry of its HTLC: the wait in `getChannelMonitorState` (`auxiliaryFeeWait.deadlineHeight`) and `getFixedOutputFeeStatus().lastRefusal.deadlineHeight` carry it. When the deadline is within 6 blocks and no confirmed fee coin is ready, the claim takes a coin of the pool's own split before the split has confirmed, in the same call that sent the split, so both can be in one block. A coin that is not of the pool's own split is never taken unconfirmed. From the block of the deadline on, a wait whose remedy was `wait` reads `none`, its message names the deadline, and the node emits one `error` that says the peer can now take the output back; the spend still goes out as soon as a fee input is there. The numbers are `FIXED_OUTPUT_FEE_TIMING`.
- **The child of a commitment.** A node that closes an asset channel by force bumps its commitment with a child that a coin of the wallet pays for, not a fee coin, and that coin is held for as long as the child can confirm. When the funding output is spent in a block, the coins the node's children took are free again in the handling of that block. When the transaction in that block is not the commitment the node was bumping, that commitment and its children are no longer offered to the network either. The node keeps the list of those coins while it runs: a node that stopped between building a child and that block leaves the coin to the wallet's own expiry of such holds.
- **`bind(node)`** is called once per build with that build's `LightningNode`, as soon as it is constructed and before it restores its stored channels: no hook of `auxiliaryChannels` runs before it. It runs outside any storage transaction and before any `start()`. The node has restored and started nothing yet, so keep it and ask nothing of it there. It is synchronous: a promise it returns is not waited for. An in-process rebuild attaches again and binds the new node to the new attachment, so keep no node from one generation for the next.

A daemon whose database holds asset channels does not start without the provider that runs them. It answers `ASSET_PROVIDER_REQUIRED` and changes no stored row, so the same database starts once the extension is named again. Signing for such a channel as an ordinary one would leave the asset out of the commitment.

## Feature detection

- `GET /extensions` (scope `readonly`; CLI `beignet extensions`) answers `{ api, extensions }`. An engine without the contract answers `404`.
- A supervisor that decides whether to name an extension before it starts the daemon can look for the literal `beignet-extension-api/1` in the installed `dist/cli/extension.js`.
- The asset channel members have no marker of their own. An extension that supplies them finds out at run time: `bind` is called before `start()` on an engine that reads them, and never on one that does not.

## The cooperative close of an asset channel

An asset channel is a channel a host's asset provider keeps state for. Its cooperative close is the engine's taproot close in one round: the opener proposes a fee, and the other node signs the same transaction or refuses.

**The fee a node accepts.** The node that answers a proposal accepts a fee inside a band it builds from its own live closing feerate (the fee estimate it would propose with itself, never below the channel's commitment feerate) and the weight of the closing transaction with the provider's outputs:

| Bound | Value |
| --- | --- |
| Lowest fee | the relay floor for the transaction's weight (253 sat/kw) |
| Highest fee, paid by the peer | ten times the node's own estimate |
| Highest fee, paid by this node | twice the node's own estimate, and never more than its balance less the dust limit of its own output |

A fee outside the band is refused locally: nothing is signed, the peer is not sent an error, the channel stays in `NEGOTIATING_CLOSING`, and a reconnect starts a new round with a new proposal. A fee that would take this node's output below its dust limit, or that the opener's balance cannot pay, fails the channel as on any other taproot channel. An ordinary channel keeps the engine's own band, built from the commitment feerates.

**A close the node did not sign.** Every spend of the funding output that is not a commitment transaction ends the channel as a cooperative close, also a transaction this node never signed and so holds no asset payload for (`closeTransactions` has no entry for its txid). The channel still ends as `CLOSED`, and the node says which transaction that was: `auxiliaryState.unrecordedCloseTxid` holds its txid in the channel's row, and the `channel:closed` event carries `unrecordedCloseTxid` beside `channelId`. The event fires once, at the close; after a restart the row still holds the txid and the event is not repeated. For a close the node signed, the field is absent from both. The chain monitor's record of the spend says the same: `getChannelMonitorState(channelId).commitmentBroadcast` is a `COOPERATIVE_CLOSE` record with `unrecordedClose: true`, on the running node and after a restart, and the record of a close the node signed has no such key.

## Asset channels in a program that embeds the engine

A program that embeds the engine can give its Lightning node an auxiliary channel provider (`INodeConfig.auxiliaryChannels`, an `IAuxiliaryChannelConfig`), and the node then holds asset channels: channels that carry asset units beside bitcoin. That is set where the node is made, not through the extension contract above, whose version 1 does not include the Lightning node. The options a host sets beside the provider are fields of the same object. This section lists the ones that bound what a channel holds, and what a host should watch.

### How many HTLCs an asset channel carries at once

`auxiliaryChannels.maxHtlcs` is the most HTLCs the node holds open at once on an asset channel, each way. It is a whole number from 1 to 83 and is 8 when the host does not set it; a node given any other value refuses to start.

- **What the node accepts.** On every asset channel it opens or accepts, the node announces this number as its `max_accepted_htlcs`. A peer that adds one HTLC more has broken the protocol and the channel fails, as on any channel.
- **What the node offers.** The node never has more than this many asset HTLCs of its own open on one asset channel, whatever the peer announced it would accept. The next asset payment is refused before anything is recorded or sent, with an `AuxiliaryPaymentError` whose code is `ASSET_HTLC_LIMIT_REACHED`; send it again once one of the open HTLCs has ended.
- **Channels that exist already.** What a channel announced when it was opened cannot be taken back, so a channel opened under another number still accepts what it announced then. The bound on what the node offers is read from the present setting and applies to every asset channel at once.

The reason for a small number: when a channel goes to the chain, every HTLC that is open is an output the node has to spend before a deadline, and each of those spends takes its fee from a wallet input of its own that the fee pool has to prepare, a few per preparation and a block each. A node with asset channels is an endpoint that makes and receives single payments, so a handful at once is all it needs. Raise the number only as far as the fee pool can pay for in the time the HTLCs leave.

Ordinary channels are not touched by this setting.

### The store of revoked views grows for as long as the channel lives

For every commitment of the peer that the peer has revoked, the node keeps the asset side of that commitment (its view) in a store of its own, so that it can punish that commitment should it ever be published. Nothing in this store is ever trimmed while the channel lives: any revoked commitment may still reach the chain, and each has to stay punishable. The store therefore grows by one row with every commitment the peer revokes, which is every payment over the channel, in either direction, and it is dropped only with the channel.

A host reads how large it has grown from `getAuxiliaryChannelInfo(channelId).revokedViews`, which answers `{ rows, bytes }`: the number of views kept for the channel and the bytes their values take in the database. The field is present when the node's storage keeps this store, which the SQLite backend does. The table is counted once, the first time a channel is asked about; after that every write of a view keeps the answer current, so reading it is cheap however large the store is. A host that plans its disk, or that wants to tell its user when a long-lived channel is worth closing and opening again, goes by this number.

## Forwards with an asset leg

This part of the contract is declared and not active yet. Its types are exported and documented so that a host, and the steps of issue #2098 that make the node run it, can be written against them, but no build calls its hooks yet: a node refuses every forward with an asset leg before anything is offered, exactly as it does without them, whatever its host supplies. `AUXILIARY_CHANNELS_API.declared` names the part as `prepareForward`. The build that runs it lists the name in `surfaces` instead, and a host relies on it only from that build on.

A forward has an asset leg when either of its HTLCs belongs to an asset channel. The incoming leg is an asset leg when its HTLC carries units or came in on an asset channel. The outgoing leg is an asset leg when it leaves over an asset channel, which offers no HTLC without units. A leg that is not an asset leg is a bitcoin leg. That makes three directions: bitcoin in and asset out (a wallet behind the node is paid), asset in and bitcoin out (a wallet behind the node pays), and asset in and asset out (two wallets behind the node that hold the same asset).

Two optional members of `IAuxiliaryChannelConfig` carry it, with the types of `src/lightning/channel/auxiliary-forward.ts`:

```ts
prepareForward?(request: IAuxiliaryForwardRequest): IAuxiliaryForwardTerms | undefined;
onForwardLegResolved?(resolution: IAuxiliaryForwardLegResolution): void;
```

A host takes part by supplying `prepareForward`. A node whose host does not supply it asks nothing and refuses every forward with an asset leg, as it does today, in every build. `valueIncomingHtlc` stays the hook of an HTLC that ends at the node: a forward is never put to it.

### Which HTLCs the host is asked about

An HTLC the node received and is not the final hop of, once it is irrevocably committed and has passed the checks the node makes of every forward before it looks for the next hop (the limits on HTLCs in flight and on a peer's rate, the onion, the expiry against the tip, forwarding being on), when either:

- one of its legs is an asset leg: it carries units or came in on an asset channel, or the short channel id the onion names is one of an asset channel of the node, by its real id or an alias; or
- the short channel id the onion names is not one the node knows: no channel of the node has it, and the node's JIT receive did not mint it. The hint of an asset invoice names a short channel id made from a quote's id, and only the host that gave the quote can recognise it, so the host is asked about every such id, also for an HTLC that carries no units.

A forward inside a blinded path is not asked about: one with an asset leg is refused, and one whose short channel id the node has no channel for fails as it does today. Neither is a forward with an asset leg that the onion asks the node to hold for an offline receiver, which is refused. The node's own payments are not forwards, and nothing here changes them.

`IAuxiliaryForwardRequest` gives the payment hash; the incoming HTLC (`incoming`: its channel, peer and id, the bitcoin it carries on the wire, its expiry, its units and custom records when it has them, and whether its channel is an asset channel); what the onion asks (`shortChannelId`, `amountToForwardMsat`, `outgoingCltvExpiry`); and `outgoing`, the node's channel that the short channel id names, absent when the node has none. The host reads anything more about either channel through the node: `getChannel` for any channel, and `getAuxiliaryChannelInfo` for an asset channel.

### What the host may answer

- **Its terms** (`IAuxiliaryForwardTerms`), with exactly the fields the forward's legs call for and no other:
  - `outgoingChannel`, when the request has no `outgoing`: the asset channel the short channel id stands for, and its peer.
  - `incomingValueMsat`, when the incoming leg is an asset leg: what the incoming HTLC is worth, in millisatoshis, above zero and within a u64.
  - `outgoingHtlc`, when the outgoing leg is an asset leg: the custom records of the outgoing HTLC (at least one, each of a type at or above 65536) and its carrier, the bitcoin it carries on the wire (`wireAmountMsat`). The host makes the records hold units worth `amountToForwardMsat` at its own rate. The engine cannot value them; the next hop judges them, as the wallet behind the node judges an HTLC against its quote.
- **`undefined`**, "not mine": only for a forward with no asset leg, whose short channel id the host does not know. The node goes on exactly as without a provider and fails the HTLC back with `unknown_next_peer`. For a forward with an asset leg it refuses.
- **A throw**: the incoming HTLC is failed back with `temporary_channel_failure`, and nothing is offered.

Anything else refuses as a throw does: a field the forward does not call for, a missing one, a value out of range, records that are not custom records, a channel that is not an asset channel of this node with the peer named, and a promise. The hook is synchronous. A host that answered with terms is told how the forward ended in every case, also when the node refused the terms as malformed or a check below refused the forward, so that it can let go of what it reserved. A host that threw or answered `undefined` took nothing on and is told nothing, save after a stop (below).

### Asked once

The host is asked once for each incoming HTLC, synchronously, outside any storage transaction, and before anything is offered. The node keeps the answer with the forward, written before the outgoing HTLC is offered or with it, and when the forward is gone through again (a reestablish, a restart) it reads the answer back and does not ask again, as the value of a held HTLC is asked once. Before it asks, the node writes that it is asking about the HTLC. A node that stopped after that write and before the answer was written goes through the HTLC again when it comes back. It asks again, with the same request, when the forward still passes the checks made before the ask. Otherwise (the tip may have passed the outgoing expiry meanwhile) it fails the HTLC back and tells the host the outgoing leg was never offered, whatever the host answered before the stop. So a host keys what it reserves for a forward, a quote for instance, by the incoming HTLC (`incoming.channelId` and `incoming.htlcId`), and answers a second ask about an HTLC as it answered the first.

A quote prices one payment. Each HTLC is a forward of its own, and whether a quote that priced one HTLC may serve another is the host's to decide.

### What the engine checks whatever the host answers

The answer lifts none of the node's checks of a forward. The node offers the outgoing HTLC only when all of these hold, and otherwise fails the incoming HTLC back. A check that needs no answer is made before the host is asked, so a forward it refuses is never put to the host; one refused after the host answered with terms is told to the host as an outgoing leg never offered.

- **Both channels.** The incoming HTLC is irrevocably committed before the outgoing one is offered: the node neither asks nor offers before then. The outgoing channel takes a new HTLC, as for any forward: it is open and not quiescing, its state can be proven current and its funding is accounted for.
- **The expiry deltas.** The outgoing expiry is more than 3 blocks above the tip, the incoming expiry is no earlier than the outgoing one plus the CLTV delta of the outgoing channel's policy, and the incoming expiry is no further ahead than the node accepts of any HTLC.
- **The HTLC limits.** The peer's `max_accepted_htlcs`, `max_htlc_value_in_flight_msat` and `htlc_minimum_msat` on the outgoing channel; for an outgoing asset leg, the node's own bound on the asset HTLCs it offers at once (`maxHtlcs`) and on outcomes its host has not taken; and the node's bound on HTLCs in flight across its channels.
- **The reserve.** The node's bitcoin on the outgoing channel covers what the HTLC carries on the wire, above the reserve its peer requires and the commitment fee the node pays as the funder.
- **The carrier of an outgoing asset HTLC.** It is above zero and at least the larger of the channel's two dust limits, so that the HTLC has an output of its own on both commitments; the provider admits its records (`validateHtlc`) and reads units from them (`getHtlcAmount`); and the node holds those units on the channel.
- **The fee.** What the incoming leg is worth covers the amount to forward and the node's fee on it, from the outgoing channel's policy, as for any forward. A bitcoin leg is worth what it carries. An incoming asset leg is worth the host's `incomingValueMsat`. The outgoing leg is worth `amountToForwardMsat`, whatever it carries on the wire.

No check that compares what a leg is worth in millisatoshis applies to the wire amount of an asset leg as it stands: that amount is a carrier, the few hundred satoshis that keep the HTLC's output on the commitments, and not what the leg is worth. The carrier is held only to the rules of its channel's own bitcoin above (the dust limits, the reserve, the peer's minimum and its bound on value in flight), as any HTLC is. Where an ordinary forward answers with a failure that quotes the amount of the incoming HTLC (`fee_insufficient`), a forward whose incoming leg is an asset leg answers `temporary_channel_failure`, so that a carrier is never quoted as what an HTLC is worth.

The fee and the CLTV delta are those of the outgoing channel's policy (`setChannelPolicy`, or the node's defaults), as for any forward. A host whose quotes advertise their own terms in a route hint, a zero fee and a CLTV delta of 40 for instance, sets them as the policy of the asset channels its quotes lead over. A quote cannot lower the delta below that policy.

### When each leg ends

A forward with an asset leg ends as any forward does, whichever of its legs holds units:

- A preimage the outgoing leg gives up, in `update_fulfill_htlc` or in a spend on the chain, claims the incoming leg: by `update_fulfill_htlc` while the incoming channel can carry it, and on the chain otherwise. For an incoming asset leg the node writes its decision to settle with the incoming channel's row as soon as it learns the preimage, so that a claim on the chain is made for that HTLC: a decision that waits on another channel.
- An outgoing leg that failed fails the incoming leg back: failed in its channel, timed out on the chain once that spend is irrevocable, or never offered.
- An incoming HTLC whose expiry comes near while its outgoing leg is unresolved takes its channel to the chain, as for any forward, so that a preimage learned late still claims it.

The host is told of each leg as it ends, through `onForwardLegResolved` (`IAuxiliaryForwardLegResolution`): the forward, by its incoming HTLC; which leg; its channel and its HTLC's id; how it ended (`fulfilled`, `failed`, or `never-offered` for an outgoing leg whose HTLC never entered its channel); whether it ended on the chain; and, for an asset leg, the units and the custom records its HTLC carried. A leg ends when its HTLC has left its channel for good, its removal irrevocably committed, or when the chain has resolved it. As with `onHtlcResolved`, an incoming leg told `fulfilled` is told again, as `failed` with `preimageRevealed: true`, when the payer took the output back on the chain after the node had claimed it. The call is synchronous and made outside any storage transaction, and it is durable: what it reports is kept with the node's rows and offered again, after a restart too, until a call returns without throwing. The two legs end in no promised order. `onHtlcResolved` is still called for every asset HTLC, the leg of a forward or not.
