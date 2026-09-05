/**
 * Guardian recovery assembly (docs/RECOVERY-PROTOCOL.md section 8).
 *
 * One call that turns an operator-level configuration (a durability mode and
 * a guardian set as pubkey-bearing URIs) into the objects the node consumes,
 * making the boot decision the spec requires along the way. Embedders (the
 * CLI daemon, wallet ports) share this instead of re-deriving the wiring,
 * because three ordering rules here are safety-critical and easy to get
 * subtly wrong:
 *
 * - The startup gate must be handed to the node AT CONSTRUCTION; a gate
 *   installed later races the constructor's auto-reconnect dials
 *   (node/types.ts, `recovery.startupGate`).
 * - The barrier's `lease` closure must answer with the held lease BEFORE
 *   `gate.confirm()` runs, because the gate invokes its open listeners
 *   synchronously inside confirm (durability-barrier.ts, `lease`).
 * - With a gate present the NODE kicks replication when ownership settles
 *   (`wireRecoveryBarrier`), so nothing here may spin its own pump.
 *
 * The boot decision itself is `GuardianReplicator.ensureNamespace()`'s:
 * a persisted lease short-circuits without touching the network (a normal
 * restart never depends on guardian reachability), a genuinely fresh
 * namespace registers, and every other answer is a refusal to invent state
 * locally, surfaced here as `restore-required` or `unavailable`.
 */

import * as ecc from '@bitcoinerlab/secp256k1';
import { IStorageBackend } from '../storage/types';
import { INodeConfig } from '../node/types';
import { getPublicKey } from '../crypto/ecdh';
import {
	CRASH_V1_PROFILE,
	GuardianState,
	computeGuardianSetId,
	deriveRecoveryRoot
} from './guardian-wire';
import { IGuardianRotateSetRequest } from './guardian';
import {
	GUARDIAN_BOLT8_SCHEME,
	GuardianClient,
	GuardianHttpTransport,
	IBoundGuardianClient,
	IGuardianSetContext,
	isOnionV3Hostname,
	parseBolt8GuardianUrl
} from './guardian-client';
import {
	GuardianAuth,
	GuardianDescriptor,
	GuardianTransportType,
	assertGuardianAuth
} from './capsule';
import {
	GuardianReplicator,
	IGuardianReplicationEvent
} from './guardian-replication';
import {
	DurabilityBarrier,
	IDurabilityBarrierEvent
} from './durability-barrier';
import {
	GuardianStartupGate,
	IConfirmationOutcome,
	IStartupGateEvent
} from './startup-gate';
import {
	IRestoreEvent,
	RestoreDriver,
	rotationEntries
} from './restore-driver';

/** One configured guardian: its committed identity and where to reach it. */
export interface IParsedGuardian {
	/** 32-byte x-only guardian identity key. */
	guardianId: Buffer;
	/** Base URL, e.g. https://host, http://<v3>.onion, http://127.0.0.1:8080. */
	url: string;
	/**
	 * Transport credential (wire 2.4 and 9). The `pubkey@url` URI format
	 * carries none, so embedders set it programmatically; it rides into the
	 * guardian client AND into the capsule's GuardianDescriptor, because a
	 * credential that does not survive a seed restore leaves the records
	 * behind it unreachable exactly when they matter. A bearer or macaroon
	 * credential over plaintext http to a non-loopback, non-onion host is
	 * refused unless `allowUnencryptedAuth` is set on the assembly; a
	 * `tor-v3-client-auth` credential lives at the Tor layer and needs the
	 * assembly's `transportFor` hook, without which it is refused rather
	 * than silently ignored.
	 */
	auth?: GuardianAuth;
}

/**
 * A guardian as structured configuration: what `parseGuardianUri` yields
 * from `<pubkey>@<url>` plus the optional credential the URI form cannot
 * carry. This is the shape a daemon hands back from a retrieved capsule and
 * the shape its config file accepts, so a credential recovered from peer
 * storage can re-enter the guardian modes.
 */
export interface IGuardianConfigEntry {
	guardianId: string;
	url: string;
	auth?: GuardianAuth;
}

/**
 * Parse one guardian from either form, a `<pubkey>@<url>` string or an
 * IGuardianConfigEntry object, with the same refusals for both.
 */
export function parseGuardianEntry(
	entry: string | IGuardianConfigEntry
): IParsedGuardian {
	if (typeof entry === 'string') return parseGuardianUri(entry);
	if (
		typeof entry !== 'object' ||
		entry === null ||
		typeof entry.guardianId !== 'string' ||
		typeof entry.url !== 'string'
	) {
		throw new Error(
			'guardian entry must be a <64-hex-x-only-pubkey>@<url> string or an ' +
				'object with guardianId and url'
		);
	}
	const parsed = parseGuardianParts(entry.guardianId, entry.url);
	if (entry.auth !== undefined) {
		parsed.auth = assertGuardianAuth(
			entry.auth,
			`guardian ${entry.guardianId}`
		);
	}
	return parsed;
}

/**
 * The capsule descriptor for one configured guardian (spec 5.4). The
 * transport type follows from the URL, which parseGuardianUri already
 * restricted to http(s) or bolt8: a bolt8 URL is `bolt8`, https is `https`,
 * an http v3 onion host is `onion-http`, any other http host is
 * `local-http`. That last class is wider than what endpoint selection will
 * dial: a non-loopback local-http descriptor reaches a client only through
 * `allowLocalHttpHost` (guardian-client.ts selectGuardianEndpoint), never by
 * default.
 */
export function guardianDescriptorFor(
	parsed: IParsedGuardian
): GuardianDescriptor {
	const url = new URL(parsed.url);
	const type: GuardianTransportType =
		url.protocol === GUARDIAN_BOLT8_SCHEME
			? 'bolt8'
			: url.protocol === 'https:'
			? 'https'
			: isOnionV3Hostname(url.hostname)
			? 'onion-http'
			: 'local-http';
	const descriptor: GuardianDescriptor = {
		guardianId: parsed.guardianId.toString('hex'),
		transports: [{ type, url: parsed.url }]
	};
	if (parsed.auth) descriptor.auth = parsed.auth;
	return descriptor;
}

/**
 * Parse one guardian URI of the form `<64-hex-x-only-pubkey>@<url>`,
 * mirroring the watchtower `pubkey@host:port` convention but with a full
 * URL because guardian transports are addressed by URL: `http(s)://` for
 * the HTTP transports, or `bolt8://<node id>@host:port` for a guardian
 * hosted by a beignet node (wire 2.7). The split is at the FIRST `@`, so a
 * bolt8 URL's own `@` stays inside the URL. Throws with a precise message
 * on anything malformed: silently dropping a guardian would change the
 * quorum arithmetic, which is exactly what a configuration surface must
 * never do quietly.
 */
export function parseGuardianUri(entry: string): IParsedGuardian {
	const trimmed = entry.trim();
	const at = trimmed.indexOf('@');
	if (at < 0) {
		throw new Error(
			`guardian entry "${trimmed}" is missing the pubkey@url separator; ` +
				'expected <64-hex-x-only-pubkey>@<http(s) url>'
		);
	}
	const idHex = trimmed.slice(0, at);
	const url = trimmed.slice(at + 1);
	if (!/^[0-9a-fA-F]{64}$/.test(idHex)) {
		throw new Error(
			`guardian entry "${trimmed}" does not start with a 64-hex-character ` +
				'x-only pubkey'
		);
	}
	return parseGuardianParts(idHex, url);
}

function parseGuardianParts(idHex: string, url: string): IParsedGuardian {
	if (!/^[0-9a-fA-F]{64}$/.test(idHex)) {
		throw new Error(`guardian pubkey "${idHex}" is not a 64-hex x-only key`);
	}
	const guardianId = Buffer.from(idHex, 'hex');
	if (!ecc.isXOnlyPoint(guardianId)) {
		throw new Error(
			`guardian pubkey ${idHex} is not a valid x-only secp256k1 point`
		);
	}
	if (url.toLowerCase().startsWith(GUARDIAN_BOLT8_SCHEME)) {
		// The userinfo position carries the node id here, by design; the
		// credential rule below is for the HTTP transports.
		return { guardianId, url: parseBolt8GuardianUrl(url).url };
	}
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error(`guardian URL "${url}" is not a valid URL`);
	}
	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
		throw new Error(
			`guardian URL "${url}" must use http, https or bolt8, not ${parsed.protocol}`
		);
	}
	// A credential belongs in `auth`, which the capsule encrypts and the
	// daemon redacts; userinfo in the URL would ride into every status
	// report and log line that names the endpoint.
	if (parsed.username !== '' || parsed.password !== '') {
		throw new Error(
			`guardian URL for ${idHex} must not carry credentials in the URL; ` +
				'use the auth field'
		);
	}
	return { guardianId, url };
}

export interface IGuardianAssemblyConfig {
	/** The database this node runs on (empty on a device awaiting restore). */
	storage: IStorageBackend;
	/** The node identity secret; derives the recovery root and journal keys. */
	nodeSecret: Buffer;
	/** Guardian-backed modes only; peer-storage-only nodes skip the assembly. */
	durability: 'async-remote' | 'quorum';
	/** Exactly the committed set, in any order (crash-v1: three guardians). */
	guardians: IParsedGuardian[];
	clock?: () => bigint;
	/** Barrier events, including `barrier:unreachable` for operator surfaces. */
	onBarrierEvent?: (event: IDurabilityBarrierEvent) => void;
	onGateEvent?: (event: IStartupGateEvent) => void;
	onReplicationEvent?: (event: IGuardianReplicationEvent) => void;
	barrierTimeoutMs?: number;
	allowUnencryptedSecrets?: boolean;
	/**
	 * Permit a bearer or macaroon credential over plain http to a
	 * non-loopback, non-onion host (GuardianClient's flag of the same name).
	 * Only for an isolated container network; unrelated to
	 * `allowUnencryptedSecrets`, which is about the storage backend.
	 */
	allowUnencryptedAuth?: boolean;
	/**
	 * Transport factory per guardian, for embedders that own a Tor layer: a
	 * `tor-v3-client-auth` credential is consumed HERE (the HTTP client only
	 * applies bearer and macaroon headers), so a guardian carrying one is
	 * refused when this hook is absent or returns nothing for it.
	 */
	transportFor?: (
		guardian: IParsedGuardian
	) => GuardianHttpTransport | undefined;
	/**
	 * This set was reached by following a rotation (the journal names it, or
	 * the boot loop just followed one). The incoming set of a rotation must
	 * already hold the namespace, so a quorum answering unknown-namespace is
	 * refused as `unavailable` / `rotation-target-empty` instead of
	 * registering a fresh genesis over a live history (issue #722).
	 */
	following?: boolean;
}

/**
 * What booting against the guardian set concluded.
 *
 * `run`: this device holds (or just registered) the writer lease. Pass
 * `recovery` into the node's constructor config, then call `confirm()`
 * AFTER construction: the gate quarantines all peer traffic until a quorum
 * confirms the lease, and the node releases its held dials the moment it
 * does. `confirm()` resolving `quarantined` (guardians unreachable) is
 * retryable; `fenced` is terminal for this lease.
 *
 * `restore-required`: the namespace exists on the guardians but this
 * device holds no lease, so it must take the namespace over through the
 * restore flow, never register a second genesis. Run
 * `buildRestoreDriver().restore()` against the (empty) storage, then
 * construct the node on the restored database via a fresh assembly call,
 * which will find the persisted lease and answer `run`. The restore can
 * itself refuse with `RestoreRotatedError` (reason `rotated`) when the set
 * retired the namespace after this decision was made: it carries the same
 * `rotation`, `generation` and `entries` as the `rotated` decision below,
 * and the caller follows it the same way.
 *
 * `unavailable`: no quorum answered, or the guardians disagree about
 * whether the namespace exists. Nothing can be decided; surface the detail
 * and retry when the set is reachable. `rotation-target-empty` is the
 * third shape (issue #722): the set was reached by following a rotation
 * and a quorum holds nothing under the namespace, so registering would
 * start an empty history over the live one; nothing was registered, and
 * the operator has to find out why the incoming set never received it.
 */
export type GuardianBootDecision =
	| {
			kind: 'run';
			recovery: NonNullable<INodeConfig['recovery']>;
			confirm: () => Promise<IConfirmationOutcome>;
			/**
			 * Periodic ownership re-check for an idle confirmed writer (issue
			 * #455): fences on a proven newer epoch, never downgrades
			 * otherwise. Run it on a cadence after confirm() succeeds.
			 */
			recheck: () => Promise<IConfirmationOutcome>;
			replicator: GuardianReplicator;
			barrier: DurabilityBarrier;
			gate: GuardianStartupGate;
	  }
	| {
			kind: 'restore-required';
			states: GuardianState[];
			buildRestoreDriver: (
				onEvent?: (event: IRestoreEvent) => void
			) => RestoreDriver;
	  }
	| {
			kind: 'unavailable';
			outcome: 'no-quorum' | 'inconsistent' | 'rotation-target-empty';
			detail: string;
	  }
	/**
	 * `rotated`: the configured set retired this namespace in favour of the
	 * set the rotation names (wire 5.11). Rebuild the assembly with
	 * `entries` (member id plus the transport the rotation carried) and
	 * decide again; the incoming set holds the live chain.
	 */
	| {
			kind: 'rotated';
			rotation: IGuardianRotateSetRequest;
			generation: bigint;
			entries: IGuardianConfigEntry[];
	  };

/**
 * Compose the guardian recovery stack and make the boot decision.
 *
 * Throws on configuration errors (a guardian set the crash-v1 profile
 * refuses, duplicate members) and on corrupt persisted registration or
 * lease state, all of which need an operator, not a retry.
 */
/**
 * Bind a guardian set: its committed id and member keys, and one client per
 * member bound to the identity it must prove. Shared by the boot assembly
 * and by a rotation, which binds the incoming set the same way (issue
 * #701).
 */
export function bindGuardianSet(
	guardians: IParsedGuardian[],
	options: Pick<
		IGuardianAssemblyConfig,
		'transportFor' | 'allowUnencryptedAuth'
	>
): {
	setId: Buffer;
	context: IGuardianSetContext;
	bound: IBoundGuardianClient[];
} {
	const guardianIds = guardians.map((g) => g.guardianId);
	const setId = computeGuardianSetId({
		...CRASH_V1_PROFILE,
		guardianIds
	});
	const context: IGuardianSetContext = {
		guardianSetId: setId,
		members: guardianIds
	};
	const bound: IBoundGuardianClient[] = guardians.map((g) => {
		const transport = options.transportFor?.(g);
		if (g.auth?.type === 'tor-v3-client-auth' && !transport) {
			throw new Error(
				`guardian ${g.guardianId.toString('hex')} carries a ` +
					'tor-v3-client-auth credential, which only an injected Tor ' +
					'transport can apply; provide transportFor or drop the credential'
			);
		}
		return {
			expectedGuardianId: g.guardianId,
			client: new GuardianClient({
				url: g.url,
				guardianSetId: setId,
				auth: g.auth,
				transport,
				allowUnencryptedAuth: options.allowUnencryptedAuth
			})
		};
	});
	return { setId, context, bound };
}

export async function buildGuardianRecovery(
	config: IGuardianAssemblyConfig
): Promise<GuardianBootDecision> {
	const { context, bound } = bindGuardianSet(config.guardians, config);
	const root = deriveRecoveryRoot(config.nodeSecret);
	const replicator = new GuardianReplicator({
		storage: config.storage,
		guardians: bound,
		context,
		required: CRASH_V1_PROFILE.required,
		recoveryRoot: root,
		clock: config.clock,
		onEvent: config.onReplicationEvent,
		allowUnencryptedSecrets: config.allowUnencryptedSecrets
	});

	const decision = await replicator.ensureNamespace({
		allowGenesis: !config.following
	});
	switch (decision.outcome) {
		case 'already-held':
		case 'registered': {
			const lease = decision.lease;
			// The lease is already persisted and held in this closure, so the
			// barrier's lease() answers correctly from the first pump, which
			// the gate's synchronous open listeners depend on.
			const barrier = new DurabilityBarrier({
				durability: config.durability,
				replicator,
				lease: () => lease,
				timeoutMs: config.barrierTimeoutMs,
				onEvent: config.onBarrierEvent
			});
			const gate = new GuardianStartupGate({
				storage: config.storage,
				replicator,
				required: CRASH_V1_PROFILE.required,
				clock: config.clock,
				onEvent: config.onGateEvent
			});
			return {
				kind: 'run',
				recovery: {
					enabled: true,
					durability: config.durability,
					barrier,
					startupGate: gate,
					// The locators every capsule this node pushes will carry
					// (spec 5.4): a seed restore reads them back from peer
					// storage instead of needing the set from configuration.
					guardians: config.guardians.map(guardianDescriptorFor)
				},
				confirm: (): Promise<IConfirmationOutcome> => gate.confirm(lease),
				recheck: (): Promise<IConfirmationOutcome> => gate.recheck(lease),
				replicator,
				barrier,
				gate
			};
		}
		case 'rotated': {
			const rotation = decision.rotation;
			return {
				kind: 'rotated',
				rotation,
				generation: rotation.generation,
				entries: rotationEntries(rotation)
			};
		}
		case 'exists-remotely':
			return {
				kind: 'restore-required',
				states: decision.states,
				buildRestoreDriver: (onEvent): RestoreDriver =>
					new RestoreDriver({
						target: config.storage,
						guardians: bound,
						context,
						required: CRASH_V1_PROFILE.required,
						recoveryRoot: root,
						nodeSecret: config.nodeSecret,
						nodeId: getPublicKey(config.nodeSecret),
						clock: config.clock,
						onEvent,
						allowUnencryptedSecrets: config.allowUnencryptedSecrets
					})
			};
		case 'no-quorum':
			return {
				kind: 'unavailable',
				outcome: 'no-quorum',
				detail:
					`only ${decision.responded} of ${config.guardians.length} ` +
					`guardians answered; deciding ownership needs ` +
					`${CRASH_V1_PROFILE.required}`
			};
		case 'inconsistent':
			return {
				kind: 'unavailable',
				outcome: 'inconsistent',
				detail: decision.detail
			};
		case 'not-held':
			return {
				kind: 'unavailable',
				outcome: 'rotation-target-empty',
				detail: decision.detail
			};
	}
}
