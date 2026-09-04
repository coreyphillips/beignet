/**
 * The guardian host: a beignet node serving the reference guardian to
 * strangers over bolt8 sessions (docs/RECOVERY-GUARDIAN-WIRE.md 2.7, issue
 * #699).
 *
 * A configured HTTP guardian serves one set it was told about. A host serves
 * whatever sets register with it, which is why REGISTER_NODE carries the
 * member list (wire 5.1): the host recomputes the set id from the list,
 * requires it to name this guardian, and only then opens a ReferenceGuardian
 * for that set. One ReferenceGuardian per set over its own SQLite file keeps
 * every set isolated and leaves the safety core untouched; the host is
 * routing, quotas and bookkeeping around it.
 *
 * Quotas refuse, never delete: pruning a namespace wedges a stranger's node
 * permanently (spec 5.8, the compaction retain floor), so an exhausted quota
 * answers ERR_QUOTA_EXCEEDED and the operator raises it or the writer moves
 * on. Both caps are checked against the set's file size, so they bound disk
 * rather than an abstract record count.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
	GuardianStatus,
	IGuardianInfoResponse,
	ReferenceGuardian
} from './guardian';
import {
	GUARDIAN_PROTOCOL_VERSION,
	CRASH_V1_PROFILE,
	computeGuardianSetId,
	xOnlyFromSecret
} from './guardian-wire';
import {
	decodeAcquireEpochRequest,
	decodeGetHeadRequest,
	decodeGetStateRequest,
	decodePutStateRequest,
	decodeRegisterNodeRequest,
	decodeSyncEpochRequest,
	decodeSyncRecordRequest
} from './guardian-proto';
import { GuardianVerbName, encodeGuardianVerbRefusal } from './guardian-http';
import {
	GuardianBolt8FrameError,
	GuardianBolt8Responder,
	IGuardianResolver,
	bolt8BearerAuthenticator
} from './guardian-bolt8';

export const GUARDIAN_HOST_DEFAULT_MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024;
export const GUARDIAN_HOST_DEFAULT_MAX_BYTES_PER_SET = 256 * 1024 * 1024;
export const GUARDIAN_HOST_DEFAULT_MAX_SETS = 16;
const MAX_RECORDS_PER_GET = 256;
const INDEX_FILE = 'sets.json';

export interface IGuardianHostConfig {
	/** Directory for the per-set stores and the host index. Created if absent. */
	path: string;
	/** The guardian signing secret, `deriveGuardianRoot(nodeSecret).guardianSecret`. */
	guardianSecret: Buffer;
	/** Bearer token every request must carry; absent runs open (wire 2.7). */
	token?: string;
	/** Advertised per-record ciphertext limit. Default 4 MiB. */
	maxCiphertextBytes?: number;
	/** Disk a single set may occupy before writes are refused. Default 256 MiB. */
	maxBytesPerSet?: number;
	/** Sets this host will register. Default 16. */
	maxSets?: number;
	maxInFlightPerSession?: number;
	onEvent?: (event: IGuardianHostEvent) => void;
	clock?: () => number;
}

export interface IGuardianHostEvent {
	type:
		| 'guardian:set-registered'
		| 'guardian:quota-refused'
		| 'guardian:session-violation';
	detail: string;
	setId?: string;
	peer?: string;
}

export interface IGuardianHostSetStatus {
	setId: string;
	members: string[];
	namespaces: number;
	bytes: number;
	registeredAt: number;
}

export interface IGuardianHostStatus {
	guardianId: string;
	authRequired: boolean;
	sessions: number;
	sets: IGuardianHostSetStatus[];
	limits: {
		maxCiphertextBytes: number;
		maxBytesPerSet: number;
		maxSets: number;
	};
}

interface IIndexEntry {
	members: string[];
	registeredAt: number;
}

interface IIndexFile {
	version: 1;
	sets: Record<string, IIndexEntry>;
}

interface IServedSet {
	setId: Buffer;
	members: Buffer[];
	guardian: ReferenceGuardian;
	file: string;
	registeredAt: number;
}

export class GuardianHost implements IGuardianResolver {
	readonly guardianId: Buffer;
	private readonly config: IGuardianHostConfig;
	private readonly sets = new Map<string, IServedSet>();
	private readonly sessions = new Map<string, GuardianBolt8Responder>();
	private readonly authenticate?: (auth: Buffer | undefined) => boolean;
	private readonly maxCiphertextBytes: number;
	private readonly maxBytesPerSet: number;
	private readonly maxSets: number;
	private readonly clock: () => number;
	private handled = 0;
	private closed = false;

	constructor(config: IGuardianHostConfig) {
		this.config = config;
		this.guardianId = xOnlyFromSecret(config.guardianSecret);
		this.authenticate =
			config.token !== undefined
				? bolt8BearerAuthenticator(config.token)
				: undefined;
		this.maxCiphertextBytes =
			config.maxCiphertextBytes ?? GUARDIAN_HOST_DEFAULT_MAX_CIPHERTEXT_BYTES;
		this.maxBytesPerSet =
			config.maxBytesPerSet ?? GUARDIAN_HOST_DEFAULT_MAX_BYTES_PER_SET;
		this.maxSets = config.maxSets ?? GUARDIAN_HOST_DEFAULT_MAX_SETS;
		this.clock = config.clock ?? ((): number => Date.now());
		fs.mkdirSync(config.path, { recursive: true });
		this.loadIndex();
	}

	// ─────────────── sessions (one responder per peer) ───────────────

	/**
	 * Feed one GUARDIAN_REQUEST payload from `peer`; returns the response
	 * frames to send back. Throws GuardianBolt8FrameError when the peer
	 * violated framing, which the caller answers by dropping the session.
	 */
	handle(peer: string, payload: Buffer): Buffer[] {
		if (this.closed) return [];
		let responder = this.sessions.get(peer);
		if (!responder) {
			responder = new GuardianBolt8Responder({
				guardian: this,
				authenticate: this.authenticate,
				maxInFlight: this.config.maxInFlightPerSession,
				clock: this.clock
			});
			this.sessions.set(peer, responder);
		}
		if (++this.handled % 64 === 0) {
			for (const session of this.sessions.values()) session.evictStale();
		}
		try {
			return responder.handle(payload);
		} catch (error) {
			if (error instanceof GuardianBolt8FrameError) {
				this.sessions.delete(peer);
				this.emit({
					type: 'guardian:session-violation',
					detail: error.message,
					peer
				});
			}
			throw error;
		}
	}

	sessionClosed(peer: string): void {
		this.sessions.delete(peer);
	}

	// ─────────────── the resolver (what the responder asks) ───────────────

	info(): IGuardianInfoResponse {
		return {
			guardianId: Buffer.from(this.guardianId),
			minProtocolVersion: GUARDIAN_PROTOCOL_VERSION,
			maxProtocolVersion: GUARDIAN_PROTOCOL_VERSION,
			guardianSetIds: [...this.sets.values()].map((set) =>
				Buffer.from(set.setId)
			),
			maxCiphertextBytes: this.maxCiphertextBytes,
			maxRecordsPerGet: MAX_RECORDS_PER_GET,
			rateLimitPerMinute: 0
		};
	}

	forRequest(verb: GuardianVerbName, body: Buffer): ReferenceGuardian | Buffer {
		const refuse = (status: GuardianStatus, detail: string): Buffer =>
			encodeGuardianVerbRefusal(verb, status, detail);
		let setId: Buffer;
		let members: Buffer[] | null = null;
		try {
			switch (verb) {
				case 'register_node': {
					const request = decodeRegisterNodeRequest(body);
					setId = request.guardianSetId;
					members = request.guardianMembers;
					break;
				}
				case 'put_state':
					setId = decodePutStateRequest(body).record.guardianSetId;
					break;
				case 'get_head':
					setId = decodeGetHeadRequest(body).guardianSetId;
					break;
				case 'get_state':
					setId = decodeGetStateRequest(body).guardianSetId;
					break;
				case 'acquire_epoch':
					setId = decodeAcquireEpochRequest(body).guardianSetId;
					break;
				case 'sync_record':
					setId = decodeSyncRecordRequest(body).record.guardianSetId;
					break;
				case 'sync_epoch': {
					const certificates = decodeSyncEpochRequest(body).certificates;
					if (certificates.length === 0) {
						return refuse(
							GuardianStatus.ERR_MALFORMED,
							'SYNC_EPOCH carries no certificates'
						);
					}
					setId = certificates[0].guardianSetId;
					break;
				}
			}
		} catch {
			return refuse(GuardianStatus.ERR_MALFORMED, 'undecodable request body');
		}
		if (setId.length !== 32) {
			return refuse(
				GuardianStatus.ERR_MALFORMED,
				'guardian_set_id must be 32 bytes'
			);
		}
		const key = setId.toString('hex');
		let served = this.sets.get(key);

		if (verb === 'register_node') {
			const problem = this.memberListProblem(members, setId);
			if (problem) return refuse(problem.status, problem.detail);
			if (!served) {
				if (this.sets.size >= this.maxSets) {
					this.emit({
						type: 'guardian:quota-refused',
						detail: `refusing a new set: ${this.sets.size} of ${this.maxSets} served`,
						setId: key
					});
					return refuse(
						GuardianStatus.ERR_QUOTA_EXCEEDED,
						`this host serves ${this.maxSets} sets and is full`
					);
				}
				served = this.openSet(setId, members as Buffer[], this.clock());
				this.saveIndex();
				this.emit({
					type: 'guardian:set-registered',
					detail: `now serving set ${key}`,
					setId: key
				});
			}
		}
		if (!served) {
			return refuse(
				GuardianStatus.ERR_UNKNOWN_SET,
				'guardian_set_id is not served by this host; register it first'
			);
		}
		if (
			(verb === 'put_state' ||
				verb === 'sync_record' ||
				verb === 'register_node') &&
			this.bytesOf(served) > this.maxBytesPerSet
		) {
			this.emit({
				type: 'guardian:quota-refused',
				detail: `set ${key} exceeds ${this.maxBytesPerSet} bytes; refusing writes`,
				setId: key
			});
			return refuse(
				GuardianStatus.ERR_QUOTA_EXCEEDED,
				`this host's storage quota for the set is exhausted`
			);
		}
		return served.guardian;
	}

	// ─────────────── status and lifecycle ───────────────

	status(): IGuardianHostStatus {
		return {
			guardianId: this.guardianId.toString('hex'),
			authRequired: this.authenticate !== undefined,
			sessions: this.sessions.size,
			sets: [...this.sets.values()].map((set) => ({
				setId: set.setId.toString('hex'),
				members: set.members.map((m) => m.toString('hex')),
				namespaces: set.guardian.listNamespaceIds().length,
				bytes: this.bytesOf(set),
				registeredAt: set.registeredAt
			})),
			limits: {
				maxCiphertextBytes: this.maxCiphertextBytes,
				maxBytesPerSet: this.maxBytesPerSet,
				maxSets: this.maxSets
			}
		};
	}

	/** The sets served, for tests and status. */
	servedSetIds(): Buffer[] {
		return [...this.sets.values()].map((set) => Buffer.from(set.setId));
	}

	close(): void {
		if (this.closed) return;
		this.closed = true;
		for (const set of this.sets.values()) set.guardian.close();
		this.sets.clear();
		this.sessions.clear();
	}

	// ─────────────── internals ───────────────

	private memberListProblem(
		members: Buffer[] | null,
		setId: Buffer
	): { status: GuardianStatus; detail: string } | null {
		if (!members || members.length !== CRASH_V1_PROFILE.total) {
			return {
				status: GuardianStatus.ERR_MALFORMED,
				detail: `guardian_members must list exactly ${CRASH_V1_PROFILE.total} keys`
			};
		}
		let computed: Buffer;
		try {
			computed = computeGuardianSetId({
				...CRASH_V1_PROFILE,
				guardianIds: members
			});
		} catch (error) {
			return {
				status: GuardianStatus.ERR_MALFORMED,
				detail: `guardian_members invalid: ${
					error instanceof Error ? error.message : String(error)
				}`
			};
		}
		if (!computed.equals(setId)) {
			return {
				status: GuardianStatus.ERR_MALFORMED,
				detail: 'guardian_members do not hash to guardian_set_id'
			};
		}
		if (!members.some((m) => m.equals(this.guardianId))) {
			return {
				status: GuardianStatus.ERR_UNKNOWN_SET,
				detail: 'this guardian is not a member of guardian_members'
			};
		}
		return null;
	}

	private openSet(
		setId: Buffer,
		members: Buffer[],
		registeredAt: number
	): IServedSet {
		const key = setId.toString('hex');
		const file = path.join(this.config.path, `${key}.sqlite`);
		const guardian = new ReferenceGuardian({
			path: file,
			guardianSecret: this.config.guardianSecret,
			members,
			maxCiphertextBytes: this.maxCiphertextBytes,
			maxRecordsPerGet: MAX_RECORDS_PER_GET,
			clock: (): bigint => BigInt(this.clock())
		});
		const served: IServedSet = {
			setId: Buffer.from(setId),
			members: members.map((m) => Buffer.from(m)),
			guardian,
			file,
			registeredAt
		};
		this.sets.set(key, served);
		return served;
	}

	private bytesOf(set: IServedSet): number {
		let total = 0;
		for (const suffix of ['', '-wal']) {
			try {
				total += fs.statSync(set.file + suffix).size;
			} catch {
				// A store not yet written, or no WAL: nothing to count.
			}
		}
		return total;
	}

	private indexPath(): string {
		return path.join(this.config.path, INDEX_FILE);
	}

	private loadIndex(): void {
		let raw: string;
		try {
			raw = fs.readFileSync(this.indexPath(), 'utf8');
		} catch {
			return;
		}
		const parsed = JSON.parse(raw) as IIndexFile;
		if (parsed.version !== 1 || typeof parsed.sets !== 'object') {
			throw new Error(`guardian host index ${this.indexPath()} is malformed`);
		}
		for (const [key, entry] of Object.entries(parsed.sets)) {
			const members = entry.members.map((hex) => Buffer.from(hex, 'hex'));
			const setId = Buffer.from(key, 'hex');
			const problem = this.memberListProblem(members, setId);
			if (problem) {
				throw new Error(
					`guardian host index names set ${key} this guardian cannot serve: ${problem.detail}`
				);
			}
			this.openSet(setId, members, entry.registeredAt);
		}
	}

	private saveIndex(): void {
		const index: IIndexFile = { version: 1, sets: {} };
		for (const [key, set] of this.sets) {
			index.sets[key] = {
				members: set.members.map((m) => m.toString('hex')),
				registeredAt: set.registeredAt
			};
		}
		const target = this.indexPath();
		const tmp = `${target}.${process.pid}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(index, null, '\t'));
		fs.renameSync(tmp, target);
	}

	private emit(event: IGuardianHostEvent): void {
		try {
			this.config.onEvent?.(event);
		} catch {
			// An observer's failure is never the host's.
		}
	}
}
