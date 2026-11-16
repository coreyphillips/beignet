/**
 * Host extensions: code the operator names at start that runs inside the
 * daemon, beside the wallet it serves (docs/EXTENSIONS.md).
 *
 * An extension is a static description (id, routes, events) plus attach(),
 * which the node calls once per build with the wallet, a storage view fenced
 * to the extension's own keys, a logger and an event emitter. The daemon
 * serves the routes under /x/<id>, behind the same authentication, scopes,
 * rate limit, idempotency and error mapping as its own, and relays the
 * events on GET /events as `<id>:<name>`.
 *
 * Two rules shape everything here:
 *
 * - A configuration the daemon cannot honour is refused before anything
 *   starts: a malformed description, two extensions with one id, an
 *   extension built for another version of this contract.
 * - An extension that breaks while running never takes the wallet with it.
 *   A throw from attach(), start(), stop() or status() is logged and
 *   reported by GET /extensions, and the node carries on without it.
 */

import type { ILogger } from '../logger';
import type { Wallet } from '../wallet';
import type { IAuxiliaryChannelConfig } from '../lightning/channel/auxiliary-funding';
import type { LightningNode } from '../lightning/node/lightning-node';
import type { IFixedOutputFeePolicy } from '../lightning/wallet/fixed-output-fees';
import type {
	IMetadataScanStorage,
	IStorageBackend
} from '../lightning/storage/types';
import {
	isStorageTransactionActive,
	withStorageTransaction
} from '../lightning/storage/transaction';
import { BeignetError } from './errors';

/**
 * The contract version, as the marker a supervisor can look for in the
 * built daemon before it names an extension. The number moves only on a
 * breaking change to the interfaces below.
 */
export const EXTENSION_API = 'beignet-extension-api/1';
/** The value an extension states in `api`. */
export const EXTENSION_API_VERSION = 1;

/** Every extension row in the metadata table starts with this. */
export const EXTENSION_STORAGE_PREFIX = 'x/';
/** The largest request body a route may ask for (the default is 1 MiB). */
export const EXTENSION_MAX_BODY_BYTES = 32 * 1024 * 1024;
/** How long a stop() hook may take before the node moves on without it. */
export const EXTENSION_STOP_TIMEOUT_MS = 5_000;
/** How long attach() may take before the node is built without the extension. */
export const EXTENSION_ATTACH_TIMEOUT_MS = 30_000;

// require, not import: importing a file outside src/ widens tsc's rootDir and
// moves the build output. The path is the same depth from src/cli and dist/cli.
const { version: PACKAGE_VERSION } = require('../../package.json') as {
	version: string;
};
/** The engine's package version, as extensions see it in their context. */
export const ENGINE_VERSION: string = PACKAGE_VERSION;

const ID_RE = /^[a-z][a-z0-9-]{1,31}$/;
const ROUTE_PATH_RE = /^(\/[a-z0-9]+(-[a-z0-9]+)*)+$/;
const EVENT_NAME_RE = /^[a-z][a-z0-9-]{0,47}$/;
const ERROR_CODE_RE = /^[A-Z][A-Z0-9_]{1,63}$/;
const METHODS: readonly string[] = ['GET', 'POST', 'DELETE'];
const SCOPES: readonly string[] = ['readonly', 'invoice'];
const ERROR_STATUSES: readonly number[] = [
	400, 403, 404, 409, 410, 413, 422, 429, 500, 502, 503, 504
];

export type ExtensionNetwork = 'mainnet' | 'testnet' | 'regtest' | 'signet';
export type ExtensionMethod = 'GET' | 'POST' | 'DELETE';
/** The non-admin scopes a route can accept; admin always qualifies. */
export type ExtensionScope = 'readonly' | 'invoice';
export type ExtensionStopReason = 'shutdown' | 'rebuild';
export type ExtensionState =
	| 'pending'
	| 'attached'
	| 'ready'
	| 'failed'
	| 'stopped';

/** One route, served by the daemon at /x/<id><path>. */
export interface IExtensionRoute {
	method: ExtensionMethod;
	/** Lowercase segments under the extension's prefix, such as '/send/prepare'. */
	path: string;
	/** Non-admin scopes that may call the route. Omitted means admin only. */
	scopes?: readonly ExtensionScope[];
	/**
	 * A POST that honours X-Idempotency-Key. The daemon replays its cached
	 * answer for a repeated key while it runs, and hands the key to the
	 * handler so the extension can make the replay survive a restart.
	 */
	idempotent?: boolean;
	/** Body limit in bytes, up to EXTENSION_MAX_BODY_BYTES. Default 1 MiB. */
	maxBodyBytes?: number;
	/** One line for the OpenAPI document. */
	summary: string;
	/** JSON Schema of the request body, for the OpenAPI document. */
	requestSchema?: Record<string, unknown>;
	/** JSON Schema of the result, for the OpenAPI document. */
	responseSchema?: Record<string, unknown>;
}

export interface IExtensionRequest {
	/** The parsed JSON body; {} when the request had none. */
	body: Record<string, unknown>;
	query: URLSearchParams;
	/** X-Idempotency-Key, on a route that declared `idempotent`. */
	idempotencyKey?: string;
}

/** Returns the result; the daemon wraps it as { ok: true, result }. */
export type ExtensionHandler = (
	request: IExtensionRequest
) => unknown | Promise<unknown>;

/**
 * The extension's own rows in the node's database: metadata keys under
 * x/<id>/, encrypted at rest with the rest of the table, copied by a
 * database backup and carried across an in-process restore. Keys are given
 * without the prefix. Every call is synchronous.
 */
export interface IExtensionStorage {
	get(key: string): string | null;
	set(key: string, value: string): void;
	delete(key: string): void;
	/** Rows whose key starts with `prefix`, in key order; '' lists them all. */
	list(prefix: string): Array<{ key: string; value: string }>;
	/**
	 * Run `fn` atomically: a throw undoes every write it made. `fn` must be
	 * synchronous; a promise it returns is not waited for. Transactions do
	 * not nest: a call made while one is open throws before `fn` runs.
	 */
	transaction<T>(fn: () => T): T;
}

export interface IExtensionContext {
	/** 1 for the node built at boot, one more for each in-process rebuild. */
	generation: number;
	network: ExtensionNetwork;
	/** The node's data directory; undefined on injected storage without one. */
	dataDir: string | undefined;
	/** The engine's package version. */
	engineVersion: string;
	wallet: Wallet;
	storage: IExtensionStorage;
	logger: ILogger;
	/**
	 * Publish one of the declared events. Subscribers of GET /events and
	 * webhooks receive it as `<id>:<event>`. An undeclared name is dropped
	 * with a warning, as is anything emitted after stop().
	 */
	emit(event: string, data: unknown): void;
}

/**
 * What the node may spend on the fees of an asset channel's transactions
 * whose outputs are fixed: WalletFundingProvider's fee policy without the
 * two members the daemon supplies itself, the journal's storage (the node's
 * own database) and the wallet's identity.
 */
export type ExtensionFixedOutputFees = Omit<
	IFixedOutputFeePolicy,
	'storage' | 'walletId'
>;

export interface IExtensionAttachment {
	/** One handler per declared route, keyed '<METHOD> <path>'. */
	handlers?: Record<string, ExtensionHandler>;
	/**
	 * Asset channel support for the node this build creates (issue #2093):
	 * handed to the node as its `auxiliaryChannels`, as it is. At most one
	 * attached extension may supply it. The node keeps it for the life of
	 * the build, whatever becomes of the extension afterwards, so it has to
	 * work whether or not start() has run. An engine that predates this
	 * member ignores it.
	 */
	auxiliaryChannels?: IAuxiliaryChannelConfig;
	/**
	 * What the node may spend on the fees of the fixed-output transactions
	 * of asset channels. Read only beside `auxiliaryChannels`; without it
	 * the wallet prepares no fee coins.
	 */
	fixedOutputFees?: ExtensionFixedOutputFees;
	/**
	 * Called with the node of this build as soon as it is constructed:
	 * before it restores its stored channels, so before any hook of
	 * `auxiliaryChannels` can be called, outside any storage transaction and
	 * before any start(). The node has restored and started nothing yet, so
	 * keep it and ask nothing of it here. Synchronous; a promise it returns
	 * is not waited for.
	 */
	bind?(node: LightningNode): void;
	/** Runs once the node is built and serving. */
	start?(): void | Promise<void>;
	/**
	 * Runs before the node goes away. On a graceful 'shutdown' the storage
	 * still takes writes while this runs; a node destroyed without one has
	 * fenced the view already. On 'rebuild' the database is being replaced:
	 * the view is fenced, and attach() follows on the new one. Either way a
	 * storage call that throws here is to be expected, not a fault.
	 */
	stop?(reason: ExtensionStopReason): void | Promise<void>;
	/** A JSON-safe summary for GET /extensions. */
	status?(): unknown;
}

export interface IBeignetExtension {
	/** Route prefix, event prefix and storage namespace. */
	id: string;
	/** The extension's own version, reported by GET /extensions. */
	version: string;
	/** The contract version it was built for: EXTENSION_API_VERSION. */
	api: number;
	routes?: readonly IExtensionRoute[];
	/** Event names it may emit, without the `<id>:` prefix. */
	events?: readonly string[];
	/**
	 * Called once per node build, after the on-chain wallet exists and before
	 * the Lightning node is created, and again after every in-process
	 * rebuild. A throw marks the extension failed; the node runs without it.
	 */
	attach(
		context: IExtensionContext
	): IExtensionAttachment | Promise<IExtensionAttachment>;
}

/** What one attached extension supplies for the node's asset channels. */
export interface IExtensionAuxiliarySupply {
	/** The extension that supplies it. */
	id: string;
	auxiliaryChannels: IAuxiliaryChannelConfig;
	fixedOutputFees?: ExtensionFixedOutputFees;
}

/** What GET /extensions reports for one extension. */
export interface IExtensionInfo {
	id: string;
	version: string;
	state: ExtensionState;
	/** The node build the extension is attached to; 0 before the first. */
	generation: number;
	/** Why it failed, when state is 'failed'. */
	error?: string;
	routes: Array<{
		method: ExtensionMethod;
		path: string;
		scopes: string[];
		idempotent: boolean;
	}>;
	events: string[];
	/** The attachment's status(), when it has one and is running. */
	status?: unknown;
	/**
	 * Present only when the wallet refused the fee policy the extension
	 * supplied with its asset channel provider. The node holds the provider
	 * and has no fee coin pool: it opens and accepts no asset channel, and
	 * whatever needs a fee coin fails with this error.
	 */
	fixedOutputFees?: IExtensionFeePoolUnavailable;
}

/** The fee coin pool of an extension's node is unavailable, and why. */
export interface IExtensionFeePoolUnavailable {
	available: false;
	/** The code and remedy of the engine's FixedOutputFeeError. */
	error: { code: string; remedy: string; message: string };
}

/**
 * A refusal the caller should see. The daemon answers with the status given
 * and the code EXTENSION_ERROR, carrying `{ id, code, details }` under
 * `error.extension`. Anything else a handler throws is a fault: logged, and
 * answered as a generic 500.
 *
 * An extension that cannot import this class throws any Error with a string
 * `extensionCode` (and optionally `status` and `details`) to the same effect.
 */
export class ExtensionError extends Error {
	readonly extensionCode: string;
	readonly status: number;
	readonly details?: unknown;

	constructor(
		extensionCode: string,
		message: string,
		status = 400,
		details?: unknown
	) {
		super(message);
		this.name = 'ExtensionError';
		this.extensionCode = extensionCode;
		this.status = status;
		if (details !== undefined) this.details = details;
	}
}

/** The fields of a thrown value the daemon reads as an extension refusal. */
export interface IExtensionRefusal {
	code: string;
	message: string;
	status: number;
	details?: unknown;
}

/**
 * Read a thrown value as an extension refusal, by shape and not by class,
 * so an extension bundled with its own copy of this module still answers
 * with its own code. A code or status outside the contract is not one.
 */
export function extensionRefusal(err: unknown): IExtensionRefusal | null {
	if (!(err instanceof Error)) return null;
	const candidate = err as Error & {
		extensionCode?: unknown;
		status?: unknown;
		details?: unknown;
	};
	if (
		typeof candidate.extensionCode !== 'string' ||
		!ERROR_CODE_RE.test(candidate.extensionCode)
	) {
		return null;
	}
	const status =
		typeof candidate.status === 'number' &&
		ERROR_STATUSES.includes(candidate.status)
			? candidate.status
			: 400;
	const refusal: IExtensionRefusal = {
		code: candidate.extensionCode,
		message: candidate.message,
		status
	};
	if (candidate.details !== undefined) refusal.details = candidate.details;
	return refusal;
}

/** The route key of an extension route as the daemon sees it. */
export function extensionRouteKey(id: string, route: IExtensionRoute): string {
	return `${route.method} /${EXTENSION_STORAGE_PREFIX}${id}${route.path}`;
}

function refuse(message: string): never {
	throw new BeignetError('INVALID_PARAMS', message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** isRecord without the narrowing, for values that already have a type. */
function isObject(value: unknown): boolean {
	return isRecord(value);
}

/**
 * Check a set of extensions before anything is built on them. Throws
 * INVALID_PARAMS naming the first problem; a description that passes can be
 * served without another look.
 */
export function validateExtensions(
	extensions: readonly IBeignetExtension[]
): void {
	if (!Array.isArray(extensions)) refuse('extensions must be an array');
	const ids = new Set<string>();
	for (const extension of extensions) {
		if (!isObject(extension)) refuse('An extension must be an object');
		const { id } = extension;
		if (typeof id !== 'string' || !ID_RE.test(id)) {
			refuse(
				`Extension id ${JSON.stringify(id)} is not valid: 2 to 32 ` +
					'characters, lowercase letters, digits and hyphens, starting with a letter'
			);
		}
		const name = `Extension "${id}"`;
		if (ids.has(id)) refuse(`${name} is listed twice`);
		ids.add(id);
		if (typeof extension.version !== 'string' || extension.version === '') {
			refuse(`${name} must state its version`);
		}
		if (extension.api !== EXTENSION_API_VERSION) {
			refuse(
				`${name} was built for extension API ${String(extension.api)}; ` +
					`this engine provides ${EXTENSION_API_VERSION}`
			);
		}
		if (typeof extension.attach !== 'function') {
			refuse(`${name} has no attach function`);
		}
		if (extension.routes !== undefined && !Array.isArray(extension.routes)) {
			refuse(`${name} routes must be an array`);
		}
		const keys = new Set<string>();
		for (const route of extension.routes ?? []) {
			if (!isObject(route)) refuse(`${name} has a route that is not an object`);
			if (!METHODS.includes(route.method)) {
				refuse(
					`${name} route method ${JSON.stringify(
						route.method
					)} is not GET, POST or DELETE`
				);
			}
			if (typeof route.path !== 'string' || !ROUTE_PATH_RE.test(route.path)) {
				refuse(
					`${name} route path ${JSON.stringify(route.path)} is not valid: ` +
						'lowercase segments such as /send/prepare'
				);
			}
			const key = `${route.method} ${route.path}`;
			if (keys.has(key)) refuse(`${name} declares ${key} twice`);
			keys.add(key);
			if (typeof route.summary !== 'string' || route.summary === '') {
				refuse(`${name} route ${key} needs a summary`);
			}
			if (route.scopes !== undefined) {
				if (
					!Array.isArray(route.scopes) ||
					(route.scopes as readonly string[]).some(
						(scope) => !SCOPES.includes(scope)
					)
				) {
					refuse(
						`${name} route ${key} scopes may list only readonly and invoice`
					);
				}
			}
			if (route.idempotent !== undefined) {
				if (typeof route.idempotent !== 'boolean') {
					refuse(`${name} route ${key} idempotent must be a boolean`);
				}
				if (route.idempotent && route.method !== 'POST') {
					refuse(
						`${name} route ${key} is not a POST, so it cannot be idempotent`
					);
				}
			}
			if (route.maxBodyBytes !== undefined) {
				if (
					!Number.isInteger(route.maxBodyBytes) ||
					route.maxBodyBytes < 1 ||
					route.maxBodyBytes > EXTENSION_MAX_BODY_BYTES
				) {
					refuse(
						`${name} route ${key} maxBodyBytes must be an integer from 1 to ${EXTENSION_MAX_BODY_BYTES}`
					);
				}
			}
			for (const field of ['requestSchema', 'responseSchema'] as const) {
				if (route[field] !== undefined && !isObject(route[field])) {
					refuse(`${name} route ${key} ${field} must be an object`);
				}
			}
		}
		if (extension.events !== undefined && !Array.isArray(extension.events)) {
			refuse(`${name} events must be an array`);
		}
		const events = new Set<string>();
		for (const event of extension.events ?? []) {
			if (typeof event !== 'string' || !EVENT_NAME_RE.test(event)) {
				refuse(
					`${name} event ${JSON.stringify(event)} is not valid: lowercase ` +
						'letters, digits and hyphens, starting with a letter'
				);
			}
			if (events.has(event)) refuse(`${name} declares event ${event} twice`);
			events.add(event);
		}
	}
}

/** better-sqlite3's error, word for word, as the node's own view throws it. */
const CLOSED_CONNECTION = 'The database connection is not open';

/** A storage backend that can list and delete metadata rows. */
type ScanStorage = IStorageBackend & IMetadataScanStorage;

function requireScanStorage(storage: IStorageBackend): ScanStorage {
	if (
		typeof storage.loadMetadataByPrefix !== 'function' ||
		typeof storage.deleteMetadata !== 'function'
	) {
		throw new Error(
			'Extension storage needs a backend with loadMetadataByPrefix and deleteMetadata'
		);
	}
	return storage as ScanStorage;
}

function checkKey(key: unknown, allowEmpty: boolean): asserts key is string {
	if (typeof key !== 'string' || (!allowEmpty && key === '')) {
		throw new TypeError('An extension storage key must be a non-empty string');
	}
	if (key.length > 512) {
		throw new TypeError('An extension storage key is at most 512 characters');
	}
	// The range scan compares code units, and a NUL would end a C string.
	if (key.includes('\u0000') || key.includes('\uffff')) {
		throw new TypeError('An extension storage key has a reserved character');
	}
}

/** What a write throws between a restore's copy of the rows and its fence. */
const WRITES_HELD =
	'The database is being replaced: extension writes are refused until the node is rebuilt';

/** What transaction() throws when another transaction is already open. */
const NESTED_TRANSACTION =
	'An extension storage transaction cannot be opened inside another transaction';

/**
 * The view one extension gets of the node's metadata rows: only keys under
 * x/<id>/, read through `current` on every call (an in-process restore
 * replaces the database), and closed for good by `fence`. `holdWrites`
 * refuses set() and delete() while it is on, and leaves reads alone.
 */
export function extensionStorageView(
	id: string,
	current: () => IStorageBackend
): {
	storage: IExtensionStorage;
	fence: () => void;
	holdWrites: (held: boolean) => void;
} {
	const namespace = `${EXTENSION_STORAGE_PREFIX}${id}/`;
	let fenced = false;
	let writesHeld = false;
	const backend = (): ScanStorage => {
		if (fenced) throw new TypeError(CLOSED_CONNECTION);
		return requireScanStorage(current());
	};
	const writable = (): ScanStorage => {
		const target = backend();
		if (writesHeld) throw new Error(WRITES_HELD);
		return target;
	};
	const storage: IExtensionStorage = {
		get(key) {
			checkKey(key, false);
			return backend().loadMetadata(namespace + key);
		},
		set(key, value) {
			checkKey(key, false);
			if (typeof value !== 'string') {
				throw new TypeError('An extension storage value must be a string');
			}
			writable().saveMetadata(namespace + key, value);
		},
		delete(key) {
			checkKey(key, false);
			writable().deleteMetadata(namespace + key);
		},
		list(prefix) {
			checkKey(prefix, true);
			return backend()
				.loadMetadataByPrefix(namespace + prefix)
				.map((row) => ({
					key: row.key.slice(namespace.length),
					value: row.value
				}));
		},
		transaction(fn) {
			const target = backend();
			// A call made inside another transaction would join it, with no
			// rollback of its own: a throw the outer callback catches would
			// leave the inner writes to be committed. Refused before `fn`
			// runs, so "a throw undoes every write" has no exception.
			if (isStorageTransactionActive(target)) {
				throw new Error(NESTED_TRANSACTION);
			}
			return withStorageTransaction(target, fn);
		}
	};
	return {
		storage,
		fence: (): void => {
			fenced = true;
		},
		holdWrites: (held): void => {
			writesHeld = held;
		}
	};
}

/**
 * Copy every extension row from one database to another, for a restore
 * that replaces the database under a running node. All or nothing.
 */
export function carryExtensionRows(
	from: IStorageBackend,
	to: IStorageBackend
): number {
	const rows = requireScanStorage(from).loadMetadataByPrefix(
		EXTENSION_STORAGE_PREFIX
	);
	if (rows.length === 0) return 0;
	withStorageTransaction(to, () => {
		for (const row of rows) to.saveMetadata(row.key, row.value);
	});
	return rows.length;
}

/** What the node hands the host for each build. */
export interface IExtensionBuild {
	network: ExtensionNetwork;
	dataDir: string | undefined;
	wallet: Wallet;
	/** The node's storage, read on every call. */
	storage: () => IStorageBackend;
}

export interface IExtensionHostOptions {
	engineVersion: string;
	log: (
		level: 'debug' | 'info' | 'warn' | 'error',
		message: string,
		data?: Record<string, unknown>
	) => void;
	/** Overrides EXTENSION_STOP_TIMEOUT_MS. */
	stopTimeoutMs?: number;
	/** Overrides EXTENSION_ATTACH_TIMEOUT_MS. */
	attachTimeoutMs?: number;
}

export type ExtensionEventListener = (event: string, data: unknown) => void;

interface IExtensionSlot {
	extension: IBeignetExtension;
	state: ExtensionState;
	error?: string;
	attachment?: IExtensionAttachment;
	/**
	 * What the attachment asked of the node, read once when it was taken:
	 * unset for an attachment that names none of the three members.
	 */
	nodeMembers?: IExtensionNodeMembers;
	/** Why the wallet refused the fee policy of the current generation. */
	feePolicyRefusal?: IExtensionFeePoolUnavailable['error'];
	/**
	 * An attachment whose start() threw while the node holds its asset
	 * channel provider: failed, and kept unstopped with its storage open
	 * until the node itself stops or is rebuilt.
	 */
	retained?: IExtensionAttachment;
	handlers: Map<string, ExtensionHandler>;
	/** The attach() pass that last took the slot (ExtensionHost.pass). */
	pass: number;
	/** Closes the storage view and the emitter of the current generation. */
	fence?: () => void;
	/** Holds or releases the writes of the current generation's view. */
	holdWrites?: (held: boolean) => void;
}

/** The members of an attachment that reach the node it is attached to. */
interface IExtensionNodeMembers {
	auxiliaryChannels?: IAuxiliaryChannelConfig;
	fixedOutputFees?: ExtensionFixedOutputFees;
	bind?: (node: LightningNode) => void;
}

function errorMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

/** Wait for `work`, which never rejects, for at most `ms`. */
function within(work: Promise<void>, ms: number): Promise<void> {
	return new Promise((resolve) => {
		const timer = setTimeout(resolve, ms);
		timer.unref?.();
		void work.then(() => {
			clearTimeout(timer);
			resolve();
		});
	});
}

/**
 * Owns the extensions of one node across its builds: attaches each to a new
 * build, starts and stops them, fences a generation that is over, and
 * answers for them to the daemon. Nothing here throws into the node.
 */
export class ExtensionHost {
	private readonly slots: IExtensionSlot[];
	private readonly listeners = new Set<ExtensionEventListener>();
	private readonly opts: IExtensionHostOptions;
	private generation = 0;
	/**
	 * The stop hooks still running: of the generation before this one, and
	 * of any attachment the node gave up on. The next attach() waits for
	 * them, and so does shutdown().
	 */
	private settling: Promise<void> = Promise.resolve();
	private shutDown = false;
	/**
	 * The slot shutdown() left running for the node's drain, and whether it
	 * is there by a retained attachment (a failed start that supplied the
	 * provider). finishShutdown() stops and fences it.
	 */
	private deferred?: { slot: IExtensionSlot; retained: boolean };
	/** The extension that supplies the node's asset channels (keepUntilDrained). */
	private keptUntilDrained?: string;
	/**
	 * Moves on every attach() and on every teardown. An attach() that finds
	 * it moved was overtaken: its build is gone, and it attaches nothing more.
	 */
	private pass = 0;
	/** Settles when the latest pass of start() hooks has finished. */
	started: Promise<void> = Promise.resolve();

	constructor(
		extensions: readonly IBeignetExtension[],
		opts: IExtensionHostOptions
	) {
		validateExtensions(extensions);
		this.opts = opts;
		this.slots = extensions.map((extension) => ({
			extension,
			state: 'pending' as ExtensionState,
			handlers: new Map<string, ExtensionHandler>(),
			pass: 0
		}));
	}

	get extensions(): readonly IBeignetExtension[] {
		return this.slots.map((slot) => slot.extension);
	}

	/** Receive every event an extension emits, named `<id>:<event>`. */
	onEvent(listener: ExtensionEventListener): () => void {
		this.listeners.add(listener);
		return () => {
			this.listeners.delete(listener);
		};
	}

	/**
	 * Attach every extension to a node build. Waits for the stop hooks of
	 * the build before it, so two generations of one extension never run
	 * side by side.
	 */
	async attach(build: IExtensionBuild): Promise<void> {
		if (this.shutDown) return;
		const pass = ++this.pass;
		await this.settling;
		// A shutdown or a teardown came during that wait: this build is gone.
		if (pass !== this.pass) return;
		// Anything still attached belongs to a build that is gone.
		this.fenceAll();
		for (const stop of this.stopRetained('rebuild')) void this.settle(stop);
		const generation = ++this.generation;
		for (const slot of this.slots) {
			// Torn down while an earlier extension was attaching: the rest are
			// not attached to a build that is gone, where nothing would ever
			// fence their storage or run their stop hooks.
			if (pass !== this.pass) return;
			const { extension } = slot;
			slot.pass = pass;
			slot.state = 'pending';
			slot.error = undefined;
			slot.attachment = undefined;
			slot.nodeMembers = undefined;
			slot.feePolicyRefusal = undefined;
			slot.handlers = new Map();
			const view = extensionStorageView(extension.id, build.storage);
			let open = true;
			const fence = (): void => {
				open = false;
				view.fence();
			};
			slot.fence = fence;
			slot.holdWrites = view.holdWrites;
			const declared = new Set(extension.events ?? []);
			const context: IExtensionContext = {
				generation,
				network: build.network,
				dataDir: build.dataDir,
				engineVersion: this.opts.engineVersion,
				wallet: build.wallet,
				storage: view.storage,
				logger: this.loggerFor(extension.id),
				emit: (event, data): void => {
					if (!open) return;
					if (!declared.has(event)) {
						this.opts.log('warn', 'Extension emitted an undeclared event', {
							extension: extension.id,
							event: String(event)
						});
						return;
					}
					this.publish(`${extension.id}:${event}`, data);
				}
			};
			let attachment: IExtensionAttachment | undefined;
			try {
				attachment = await this.boundedAttach(extension, context);
				if (!open || pass !== this.pass) {
					// Torn down while attach() was still running, or a shutdown
					// began and is still waiting for the hooks it found: either
					// way nothing would stop this attachment later, so it is
					// stopped now. Its view is fenced already, or will be when
					// that shutdown finishes. The slot is left alone if a later
					// build has taken it since.
					this.discard(extension.id, attachment);
					if (slot.pass === pass) slot.state = 'stopped';
					continue;
				}
				const handlers = this.bindHandlers(extension, attachment);
				slot.nodeMembers = this.readNodeMembers(attachment);
				slot.handlers = handlers;
				slot.attachment = attachment;
				slot.state = 'attached';
			} catch (err) {
				fence();
				// An attachment the node refuses (its handlers do not match its
				// routes) has run attach() all the same, and may hold timers,
				// sockets or locks: its stop hook is the only way to hand them
				// back, and fail() below forgets the attachment.
				if (attachment !== undefined) this.discard(extension.id, attachment);
				if (slot.pass === pass) {
					this.fail(slot, 'attach', err);
				} else {
					this.opts.log('warn', 'Extension attach failed after its build', {
						extension: extension.id,
						error: errorMessage(err)
					});
				}
			}
		}
	}

	/**
	 * What the attached extensions supply for the asset channels of the node
	 * about to be built, or undefined when none supplies any. Two that both
	 * supply a provider are refused: a node runs one, and choosing between
	 * them here would leave the channels of the other unenforced.
	 */
	auxiliarySupply(): IExtensionAuxiliarySupply | undefined {
		const suppliers = this.slots.filter(
			(slot) =>
				slot.state === 'attached' &&
				slot.nodeMembers?.auxiliaryChannels !== undefined
		);
		if (suppliers.length > 1) {
			const ids = suppliers
				.map((slot) => `"${slot.extension.id}"`)
				.join(' and ');
			throw new BeignetError(
				'ASSET_PROVIDER_CONFLICT',
				`Extensions ${ids} both supply asset channels. A node runs one ` +
					'asset channel provider, so it was not started: load one of them.'
			);
		}
		const supplier = suppliers[0];
		const members = supplier?.nodeMembers;
		if (!supplier || members?.auxiliaryChannels === undefined) return undefined;
		return {
			id: supplier.extension.id,
			auxiliaryChannels: members.auxiliaryChannels,
			...(members.fixedOutputFees !== undefined
				? { fixedOutputFees: members.fixedOutputFees }
				: {})
		};
	}

	/**
	 * The wallet refused the fee policy extension `id` supplied. Called
	 * before the node is built. The extension is kept, and its provider with
	 * it, so a wallet that holds asset channels starts: GET /extensions says
	 * that its fee coin pool is unavailable, and why, until the next build.
	 */
	feePolicyRefused(
		id: string,
		error: IExtensionFeePoolUnavailable['error']
	): void {
		const slot = this.slots.find((s) => s.extension.id === id);
		if (slot && slot.state === 'attached') {
			slot.feePolicyRefusal = {
				code: error.code,
				remedy: error.remedy,
				message: error.message
			};
		}
	}

	/**
	 * Whether an attached extension asked for the node of this build. The
	 * node is given the binding callback only then, so a build with no such
	 * extension is configured exactly as one with no extension.
	 */
	binds(): boolean {
		return this.slots.some(
			(slot) =>
				slot.state === 'attached' && slot.nodeMembers?.bind !== undefined
		);
	}

	/**
	 * Give the node of this build to every attached extension that asked for
	 * it. Called by the node itself as soon as it is constructed and before
	 * it restores from storage (INodeConfig.beforeRestore), so no stored
	 * channel calls a hook of an unbound provider. Outside any storage
	 * transaction, and before start().
	 *
	 * An extension whose bind() throws is failed and stopped, and the node
	 * runs without it, with one exception: `provider`, the extension whose
	 * asset channel provider the node is being built with. A provider that
	 * was never given its node cannot run a channel, so the throw is passed
	 * on as ASSET_PROVIDER_FAILED and ends the construction before anything
	 * is restored.
	 */
	bindNode(node: LightningNode, provider?: string): void {
		for (const slot of this.slots) {
			if (slot.state !== 'attached') continue;
			const bind = slot.nodeMembers?.bind;
			if (!bind) continue;
			const { id } = slot.extension;
			try {
				const pending: unknown = bind.call(slot.attachment, node);
				if (isRecord(pending) && typeof pending.then === 'function') {
					// Not waited for. A rejection is logged, so it is not an
					// unhandled one.
					(pending as unknown as Promise<unknown>).then(undefined, (err) =>
						this.opts.log('warn', 'Extension bind rejected', {
							extension: id,
							error: errorMessage(err)
						})
					);
				}
			} catch (err) {
				this.drop(slot, 'bind', err);
				if (id === provider) {
					throw new BeignetError(
						'ASSET_PROVIDER_FAILED',
						`Extension "${id}" supplies this node's asset channels and ` +
							`refused the node it was built for: ${errorMessage(err)}. ` +
							'The node was not started.'
					);
				}
			}
		}
	}

	/**
	 * Run the start() hooks without holding the caller: the node finishes
	 * its boot whatever an extension does in start(). Routes are served
	 * from attach() on, so an extension that is not ready yet says so in
	 * its own answers.
	 */
	startInBackground(): void {
		this.started = this.start();
	}

	/**
	 * Run start() on every attached extension. Never rejects.
	 *
	 * Every hook is called before this returns its promise, and none waits
	 * for another: an extension that never finishes starting holds no other
	 * back, and a pass that is still waiting when the node is rebuilt has
	 * no hook left to call on the attachments of the next generation.
	 */
	async start(): Promise<void> {
		await Promise.all(
			this.slots
				.filter((slot) => slot.state === 'attached')
				.map((slot) => this.startOne(slot, slot.attachment))
		);
	}

	private async startOne(
		slot: IExtensionSlot,
		attachment: IExtensionAttachment | undefined
	): Promise<void> {
		try {
			await attachment?.start?.();
			// A teardown during start() has already settled the state, and a
			// rebuild may have attached the next generation since.
			if (slot.attachment === attachment && slot.state === 'attached') {
				slot.state = 'ready';
			}
		} catch (err) {
			if (slot.attachment !== attachment || slot.state !== 'attached') return;
			if (slot.nodeMembers?.auxiliaryChannels !== undefined) {
				// The node was built with this extension's asset channel
				// provider and goes on calling it for the channels that exist,
				// which it may have to defend on chain. So only the routes
				// close: the attachment is kept, unstopped and with its storage
				// open, and is stopped when the node stops or is rebuilt. New
				// activity is the extension's own to refuse.
				slot.handlers = new Map();
				this.fail(slot, 'start', err);
				slot.retained = attachment;
				return;
			}
			// Settled before the stop hook is waited for. The slot can change
			// hands during that wait: a teardown finds nothing running here
			// and does not stop the attachment a second time, and a rebuild
			// that attaches the next generation finds its slot untouched
			// afterwards. Only this generation's own fence is closed.
			const fence = slot.fence;
			slot.handlers = new Map();
			this.fail(slot, 'start', err);
			await this.settle(
				this.runStop(slot.extension.id, attachment, 'shutdown')
			);
			fence?.();
			if (slot.fence === fence) slot.fence = undefined;
		}
	}

	/**
	 * Refuse every extension's writes until the returned function is called,
	 * or for good once the generation is fenced. A restore calls it when it
	 * has copied the extensions' rows into the database it installs: a write
	 * that reached the old database after that copy would be acknowledged
	 * and then gone. Reads go on working.
	 */
	holdWrites(): () => void {
		const held: Array<(held: boolean) => void> = [];
		for (const slot of this.slots) {
			if (slot.holdWrites) held.push(slot.holdWrites);
		}
		for (const hold of held) hold(true);
		return (): void => {
			for (const hold of held) hold(false);
		};
	}

	/**
	 * The node is closing its database to replace it. Synchronous on
	 * purpose: no write of this generation may land after the rows were
	 * carried across. The stop hooks run on, bounded, and the next attach()
	 * waits for them.
	 */
	fenceForRebuild(): void {
		this.pass++;
		const running = this.slots.filter((slot) => this.isRunning(slot));
		this.fenceAll();
		for (const slot of running) {
			void this.settle(
				this.runStop(slot.extension.id, slot.attachment, 'rebuild')
			);
			slot.state = 'stopped';
			slot.handlers = new Map();
		}
		for (const stop of this.stopRetained('rebuild')) void this.settle(stop);
	}

	/**
	 * The node is shutting down. The stop hooks run first, bounded, while
	 * the wallet and the storage still work; then everything is fenced.
	 *
	 * The whole wait is one bound, the stop timeout or `limitMs` when that
	 * is shorter: the hooks of this generation run together, alongside
	 * whatever an earlier one left running, and none adds its wait to
	 * another's. The node passes a share of its own shutdown budget.
	 *
	 * The extension named to keepUntilDrained() is the exception. Its
	 * routes close with the others, but it is neither stopped nor fenced
	 * here: the node calls its provider for every commitment while it
	 * drains its in-flight HTLCs, so the extension and its storage stay as
	 * they are until finishShutdown(), after the drain.
	 */
	async shutdown(limitMs?: number): Promise<void> {
		const provider = this.keptUntilDrained;
		if (this.shutDown) return;
		this.shutDown = true;
		this.pass++;
		const limit = Math.max(
			0,
			Math.min(this.stopTimeoutMs(), limitMs ?? Infinity)
		);
		const running = this.slots.filter((slot) => this.isRunning(slot));
		// Routes close first, so a hook does not race a new request.
		for (const slot of running) slot.handlers = new Map();
		const kept =
			provider === undefined
				? undefined
				: this.slots.find(
						(slot) =>
							slot.extension.id === provider &&
							(this.isRunning(slot) || slot.retained !== undefined)
				  );
		if (kept) {
			this.deferred = { slot: kept, retained: kept.retained !== undefined };
		}
		await Promise.all([
			within(this.settling, limit),
			...running
				.filter((slot) => slot !== kept)
				.map((slot) =>
					this.runStop(slot.extension.id, slot.attachment, 'shutdown', limit)
				),
			...this.stopRetained('shutdown', limit, kept)
		]);
		this.fenceAll(kept);
		for (const slot of running) {
			if (slot !== kept) slot.state = 'stopped';
		}
		this.listeners.clear();
	}

	/**
	 * Name the extension that supplies the asset channels of the node being
	 * built, or undefined when none does. A graceful shutdown leaves that
	 * one running, with its storage open, until finishShutdown().
	 */
	keepUntilDrained(id: string | undefined): void {
		this.keptUntilDrained = id;
	}

	/**
	 * The node has drained: stop and fence the provider's extension that
	 * shutdown() left running. The wallet and the storage still work. The
	 * wait is bounded like every stop hook's. Nothing to do when shutdown()
	 * kept no extension.
	 */
	async finishShutdown(limitMs?: number): Promise<void> {
		const deferred = this.deferred;
		if (!deferred) return;
		this.deferred = undefined;
		const { slot } = deferred;
		const limit = Math.max(
			0,
			Math.min(this.stopTimeoutMs(), limitMs ?? Infinity)
		);
		const attachment = deferred.retained ? slot.retained : slot.attachment;
		slot.retained = undefined;
		try {
			await this.runStop(slot.extension.id, attachment, 'shutdown', limit);
		} finally {
			slot.fence?.();
			slot.fence = undefined;
			slot.holdWrites = undefined;
			if (!deferred.retained) slot.state = 'stopped';
		}
	}

	/**
	 * The node is being destroyed without a graceful stop. Synchronous, so
	 * destroy() reaches the wallet as soon as it did without extensions:
	 * everything is fenced at once, and the stop hooks run on unwaited.
	 */
	abort(): void {
		// A graceful shutdown that was cut short may still hold the
		// provider's extension open: it is fenced here with the rest.
		const deferred = this.deferred;
		this.deferred = undefined;
		if (deferred) {
			const { slot } = deferred;
			const attachment = deferred.retained ? slot.retained : slot.attachment;
			slot.retained = undefined;
			slot.fence?.();
			slot.fence = undefined;
			slot.holdWrites = undefined;
			void this.runStop(slot.extension.id, attachment, 'shutdown');
			if (!deferred.retained) slot.state = 'stopped';
		}
		if (this.shutDown) return;
		this.shutDown = true;
		this.pass++;
		const running = this.slots.filter((slot) => this.isRunning(slot));
		this.fenceAll();
		for (const slot of running) {
			void this.runStop(slot.extension.id, slot.attachment, 'shutdown');
			slot.state = 'stopped';
			slot.handlers = new Map();
		}
		for (const stop of this.stopRetained('shutdown')) void stop;
		this.listeners.clear();
	}

	/**
	 * The handler serving one route. A route whose extension is not running
	 * answers EXTENSION_UNAVAILABLE instead of a 404, because the route
	 * exists and a retry after a restart may find it.
	 */
	handler(id: string, key: string): ExtensionHandler {
		const slot = this.slots.find((s) => s.extension.id === id);
		const handler = slot?.handlers.get(key);
		if (handler) return handler;
		const why =
			slot?.state === 'failed'
				? `failed: ${slot.error ?? 'unknown error'}`
				: `is ${slot?.state ?? 'not loaded'}`;
		throw new BeignetError('EXTENSION_UNAVAILABLE', `Extension "${id}" ${why}`);
	}

	/** One entry per extension, for GET /extensions. */
	describe(): IExtensionInfo[] {
		return this.slots.map((slot) => {
			const { extension } = slot;
			const info: IExtensionInfo = {
				id: extension.id,
				version: extension.version,
				state: slot.state,
				generation: slot.state === 'pending' ? 0 : this.generation,
				routes: (extension.routes ?? []).map((route) => ({
					method: route.method,
					path: `/${EXTENSION_STORAGE_PREFIX}${extension.id}${route.path}`,
					scopes: [...(route.scopes ?? []), 'admin'],
					idempotent: route.idempotent === true
				})),
				events: (extension.events ?? []).map(
					(event) => `${extension.id}:${event}`
				)
			};
			if (slot.error !== undefined) info.error = slot.error;
			if (slot.feePolicyRefusal !== undefined) {
				info.fixedOutputFees = {
					available: false,
					error: { ...slot.feePolicyRefusal }
				};
			}
			if (this.isRunning(slot) && slot.attachment?.status) {
				try {
					// Through JSON here, where a value that does not serialize (a
					// BigInt, a cycle) costs this one field. Left for the answer
					// to serialize, it would fail GET /extensions for every
					// extension.
					const text = JSON.stringify(slot.attachment.status());
					if (text !== undefined) info.status = JSON.parse(text) as unknown;
				} catch (err) {
					this.opts.log('warn', 'Extension status failed', {
						extension: extension.id,
						error: errorMessage(err)
					});
				}
			}
			return info;
		});
	}

	/**
	 * Run the stop hook of every attachment that was kept for its provider
	 * after a failed start(), now that the node it served is going away.
	 */
	private stopRetained(
		reason: ExtensionStopReason,
		limitMs?: number,
		except?: IExtensionSlot
	): Promise<void>[] {
		const stops: Promise<void>[] = [];
		for (const slot of this.slots) {
			if (slot.retained === undefined || slot === except) continue;
			stops.push(
				this.runStop(slot.extension.id, slot.retained, reason, limitMs)
			);
			slot.retained = undefined;
		}
		return stops;
	}

	private isRunning(slot: IExtensionSlot): boolean {
		return slot.state === 'attached' || slot.state === 'ready';
	}

	private fenceAll(except?: IExtensionSlot): void {
		for (const slot of this.slots) {
			if (slot === except) continue;
			slot.fence?.();
			slot.fence = undefined;
			slot.holdWrites = undefined;
		}
	}

	private stopTimeoutMs(): number {
		return this.opts.stopTimeoutMs ?? EXTENSION_STOP_TIMEOUT_MS;
	}

	/** Have the next attach() and shutdown() wait for a stop hook. */
	private settle(hook: Promise<void>): Promise<void> {
		this.settling = Promise.all([this.settling, hook]).then(
			() => undefined,
			() => undefined
		);
		return hook;
	}

	private fail(slot: IExtensionSlot, phase: string, err: unknown): void {
		slot.state = 'failed';
		slot.error = `${phase}: ${errorMessage(err)}`;
		slot.attachment = undefined;
		this.opts.log(
			'error',
			`Extension ${phase} failed; the node runs without it`,
			{
				extension: slot.extension.id,
				error: errorMessage(err)
			}
		);
	}

	/**
	 * Give up on an attached extension the node cannot use: failed, its
	 * routes closed at once, its stop hook run and waited for by the next
	 * attach(), and only then its storage fenced, as for a start() that
	 * throws.
	 */
	private drop(slot: IExtensionSlot, phase: string, err: unknown): void {
		const attachment = slot.attachment;
		const fence = slot.fence;
		slot.handlers = new Map();
		slot.nodeMembers = undefined;
		this.fail(slot, phase, err);
		void this.settle(
			this.runStop(slot.extension.id, attachment, 'shutdown')
		).then(() => {
			fence?.();
			if (slot.fence === fence) slot.fence = undefined;
		});
	}

	/**
	 * attach(), bounded: the node is built without an extension that does
	 * not answer. One that answers after the bound is stopped again.
	 */
	private async boundedAttach(
		extension: IBeignetExtension,
		context: IExtensionContext
	): Promise<IExtensionAttachment> {
		const limit = this.opts.attachTimeoutMs ?? EXTENSION_ATTACH_TIMEOUT_MS;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const bound = new Promise<'timeout'>((resolve) => {
			timer = setTimeout(() => resolve('timeout'), limit);
			timer.unref?.();
		});
		const attaching = (async (): Promise<IExtensionAttachment> =>
			extension.attach(context))();
		try {
			const outcome = await Promise.race([attaching, bound]);
			if (outcome !== 'timeout') return outcome;
		} finally {
			if (timer) clearTimeout(timer);
		}
		attaching.then(
			(late) => this.discard(extension.id, late),
			() => undefined
		);
		throw new Error(`attach() did not finish within ${limit} ms`);
	}

	/**
	 * Stop an attachment the node will not use: one that arrived after its
	 * generation was over, or one attach() refused. Not waited for here; the
	 * next attach() is.
	 */
	private discard(id: string, attachment: unknown): void {
		void this.settle(this.runStop(id, attachment, 'shutdown'));
	}

	/**
	 * One stop hook, bounded and contained: never rejects. Takes whatever
	 * attach() returned, which need not be an attachment at all.
	 */
	private async runStop(
		id: string,
		attachment: unknown,
		reason: ExtensionStopReason,
		limitMs: number = this.stopTimeoutMs()
	): Promise<void> {
		if (!isRecord(attachment)) return;
		const stop = attachment.stop;
		if (typeof stop !== 'function') return;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const bound = new Promise<'timeout'>((resolve) => {
			timer = setTimeout(() => resolve('timeout'), limitMs);
			timer.unref?.();
		});
		try {
			const outcome = await Promise.race([
				(async (): Promise<'done'> => {
					await (stop as (reason: ExtensionStopReason) => unknown).call(
						attachment,
						reason
					);
					return 'done';
				})(),
				bound
			]);
			if (outcome === 'timeout') {
				this.opts.log('warn', 'Extension stop timed out', {
					extension: id,
					reason
				});
			}
		} catch (err) {
			this.opts.log('warn', 'Extension stop failed', {
				extension: id,
				reason,
				error: errorMessage(err)
			});
		} finally {
			if (timer) clearTimeout(timer);
		}
	}

	private bindHandlers(
		extension: IBeignetExtension,
		attachment: IExtensionAttachment
	): Map<string, ExtensionHandler> {
		if (!isObject(attachment)) {
			throw new Error('attach() must return an object');
		}
		const given = attachment.handlers ?? {};
		if (!isObject(given)) throw new Error('handlers must be an object');
		const declared = (extension.routes ?? []).map(
			(route) => `${route.method} ${route.path}`
		);
		const missing = declared.filter((key) => typeof given[key] !== 'function');
		if (missing.length > 0) {
			throw new Error(`no handler for ${missing.join(', ')}`);
		}
		const extra = Object.keys(given).filter((key) => !declared.includes(key));
		if (extra.length > 0) {
			throw new Error(`handler for an undeclared route: ${extra.join(', ')}`);
		}
		return new Map(
			declared.map((key) => [key, given[key] as ExtensionHandler])
		);
	}

	/**
	 * The members of an attachment that reach the node, each read once. An
	 * attachment that names none of them reads as undefined, and nothing
	 * about it is different from before these members existed.
	 */
	private readNodeMembers(
		attachment: IExtensionAttachment
	): IExtensionNodeMembers | undefined {
		const { auxiliaryChannels, fixedOutputFees, bind } = attachment;
		if (
			auxiliaryChannels === undefined &&
			fixedOutputFees === undefined &&
			bind === undefined
		) {
			return undefined;
		}
		if (auxiliaryChannels !== undefined) {
			if (
				!isRecord(auxiliaryChannels) ||
				!isRecord(auxiliaryChannels.provider) ||
				typeof auxiliaryChannels.resolveIncoming !== 'function'
			) {
				throw new Error(
					'auxiliaryChannels must carry a provider and resolveIncoming'
				);
			}
		}
		if (fixedOutputFees !== undefined) {
			if (auxiliaryChannels === undefined) {
				throw new Error(
					'fixedOutputFees is read only beside auxiliaryChannels'
				);
			}
			if (!isRecord(fixedOutputFees)) {
				throw new Error('fixedOutputFees must be an object');
			}
		}
		if (bind !== undefined && typeof bind !== 'function') {
			throw new Error('bind must be a function');
		}
		return {
			...(auxiliaryChannels !== undefined ? { auxiliaryChannels } : {}),
			...(fixedOutputFees !== undefined ? { fixedOutputFees } : {}),
			...(bind !== undefined ? { bind } : {})
		};
	}

	private loggerFor(id: string): ILogger {
		const write =
			(level: 'debug' | 'info' | 'warn' | 'error') =>
			(message: string, meta?: unknown): void => {
				this.opts.log(
					level,
					`[${id}] ${message}`,
					meta === undefined ? undefined : isRecord(meta) ? meta : { meta }
				);
			};
		return {
			debug: write('debug'),
			info: write('info'),
			warn: write('warn'),
			error: write('error')
		};
	}

	private publish(event: string, data: unknown): void {
		for (const listener of this.listeners) {
			try {
				listener(event, data);
			} catch (err) {
				this.opts.log('warn', 'Extension event listener failed', {
					event,
					error: errorMessage(err)
				});
			}
		}
	}
}

/**
 * Add the extensions' routes to an OpenAPI document. Returns the document
 * untouched when there are none, so a daemon without extensions serves
 * exactly what getOpenApiSpec() returns.
 */
export function withExtensionOperations(
	spec: Record<string, unknown>,
	extensions: readonly IBeignetExtension[]
): Record<string, unknown> {
	if (extensions.length === 0) return spec;
	const paths: Record<string, Record<string, unknown>> = {
		...(spec.paths as Record<string, Record<string, unknown>>)
	};
	for (const extension of extensions) {
		for (const route of extension.routes ?? []) {
			const routePath = `/${EXTENSION_STORAGE_PREFIX}${extension.id}${route.path}`;
			const operation: Record<string, unknown> = {
				summary: route.summary,
				tags: [`Extension: ${extension.id}`],
				'x-extension': { id: extension.id, version: extension.version },
				'x-accepted-scopes': [...(route.scopes ?? []), 'admin'],
				responses: {
					'200': {
						description: 'Success',
						content: {
							'application/json': {
								schema: {
									type: 'object',
									required: ['ok', 'result'],
									properties: {
										ok: { type: 'boolean', enum: [true] },
										result: route.responseSchema ?? {}
									}
								}
							}
						}
					}
				}
			};
			if (route.requestSchema) {
				operation.requestBody = {
					content: { 'application/json': { schema: route.requestSchema } }
				};
			}
			if (route.idempotent) operation['x-idempotent'] = true;
			paths[routePath] = {
				...paths[routePath],
				[route.method.toLowerCase()]: operation
			};
		}
	}
	return { ...spec, paths };
}
