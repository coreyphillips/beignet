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
import {
	GuardianClient,
	IBoundGuardianClient,
	IGuardianSetContext
} from './guardian-client';
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
import { IRestoreEvent, RestoreDriver } from './restore-driver';

/** One configured guardian: its committed identity and where to reach it. */
export interface IParsedGuardian {
	/** 32-byte x-only guardian identity key. */
	guardianId: Buffer;
	/** Base URL, e.g. https://host, http://<v3>.onion, http://127.0.0.1:8080. */
	url: string;
}

/**
 * Parse one guardian URI of the form `<64-hex-x-only-pubkey>@<url>`,
 * mirroring the watchtower `pubkey@host:port` convention but with a full
 * URL because guardian transports are HTTP. Throws with a precise message
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
	const guardianId = Buffer.from(idHex, 'hex');
	if (!ecc.isXOnlyPoint(guardianId)) {
		throw new Error(
			`guardian pubkey ${idHex} is not a valid x-only secp256k1 point`
		);
	}
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new Error(`guardian URL "${url}" is not a valid URL`);
	}
	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
		throw new Error(
			`guardian URL "${url}" must use http or https, not ${parsed.protocol}`
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
 * which will find the persisted lease and answer `run`.
 *
 * `unavailable`: no quorum answered, or the guardians disagree about
 * whether the namespace exists. Nothing can be decided; surface the detail
 * and retry when the set is reachable.
 */
export type GuardianBootDecision =
	| {
			kind: 'run';
			recovery: NonNullable<INodeConfig['recovery']>;
			confirm: () => Promise<IConfirmationOutcome>;
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
			outcome: 'no-quorum' | 'inconsistent';
			detail: string;
	  };

/**
 * Compose the guardian recovery stack and make the boot decision.
 *
 * Throws on configuration errors (a guardian set the crash-v1 profile
 * refuses, duplicate members) and on corrupt persisted registration or
 * lease state, all of which need an operator, not a retry.
 */
export async function buildGuardianRecovery(
	config: IGuardianAssemblyConfig
): Promise<GuardianBootDecision> {
	const guardianIds = config.guardians.map((g) => g.guardianId);
	const setId = computeGuardianSetId({
		...CRASH_V1_PROFILE,
		guardianIds
	});
	const context: IGuardianSetContext = {
		guardianSetId: setId,
		members: guardianIds
	};
	const bound: IBoundGuardianClient[] = config.guardians.map((g) => ({
		expectedGuardianId: g.guardianId,
		client: new GuardianClient({ url: g.url, guardianSetId: setId })
	}));
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

	const decision = await replicator.ensureNamespace();
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
					startupGate: gate
				},
				confirm: (): Promise<IConfirmationOutcome> => gate.confirm(lease),
				replicator,
				barrier,
				gate
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
	}
}
