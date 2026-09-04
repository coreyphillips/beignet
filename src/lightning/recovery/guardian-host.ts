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
 * Admission comes before allocation (issue #710). A registration for a set
 * this host has never served is checked in full, root signature included,
 * before a store exists for it, and the first registration is one unit
 * from the host's side: the store is opened, the guardian registers, and
 * only an accepted registration is served, indexed and announced. A refused
 * one leaves no file, no index entry and no served set behind.
 *
 * Quotas refuse, never delete: pruning a namespace wedges a stranger's node
 * permanently (spec 5.8, the compaction retain floor), so an exhausted quota
 * answers ERR_QUOTA_EXCEEDED and the operator raises it or the writer moves
 * on. The byte quota bounds the encoded content a set stores (every column
 * of every row, GuardianStore.contentBytes) and is enforced on the write
 * that would cross it: a write is admitted only while
 * `bytes + delta <= maxBytesPerSet`, where delta is what the store grows by
 * if the guardian accepts and zero for a replay the guardian answers from
 * what it already holds. The host is synchronous, so the check, the
 * guardian's transaction and the charge are one unit against every other
 * request; the counter is re-derived from the store at open, so a restart
 * recovers it exactly. Disk is that content plus SQLite's overhead and is
 * reported alongside it.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
	GuardianStatus,
	IGuardianInfoResponse,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	ReferenceGuardian,
	registrationAdmissionProblem
} from './guardian';
import {
	GUARDIAN_PROTOCOL_VERSION,
	CRASH_V1_PROFILE,
	computeGuardianSetId,
	isGenesisLogHead,
	xOnlyFromSecret
} from './guardian-wire';
import {
	decodeAcquireEpochRequest,
	decodeGetHeadRequest,
	decodeGetStateRequest,
	decodePutStateRequest,
	decodeRegisterNodeRequest,
	decodeRotateSetRequest,
	decodeSyncEpochRequest,
	decodeSyncRecordRequest
} from './guardian-proto';
import {
	GuardianVerbName,
	IGuardianVerbOutcome,
	encodeGuardianVerbRefusal,
	runGuardianVerb
} from './guardian-http';
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

/**
 * What a record row stores besides its ciphertext: recovery_id, sequence,
 * epoch, previous_hash, frame_hash, ciphertext_hash, writer_signature
 * (guardian-store.ts). An accepted append grows the store by exactly this
 * plus the ciphertext; the namespace row it updates keeps its size.
 */
export const GUARDIAN_HOST_RECORD_OVERHEAD_BYTES =
	32 + 8 + 8 + 32 + 32 + 32 + 64;
/**
 * What a fresh registration stores: the namespace row (two 192-byte
 * states, three signatures, two issue times, the ids, the generation, the
 * stale flag) and the first epoch row (recovery_id, epoch, writer key).
 */
export const GUARDIAN_HOST_REGISTRATION_BYTES =
	32 + 32 + 192 + 1 + 192 + 64 + 8 + 64 + 8 + 64 + 8 + (32 + 8 + 32);

export interface IGuardianHostConfig {
	/** Directory for the per-set stores and the host index. Created if absent. */
	path: string;
	/** The guardian signing secret, `deriveGuardianRoot(nodeSecret).guardianSecret`. */
	guardianSecret: Buffer;
	/** Bearer token every request must carry; absent runs open (wire 2.7). */
	token?: string;
	/** Advertised per-record ciphertext limit. Default 4 MiB. */
	maxCiphertextBytes?: number;
	/** Content a single set may store before writes are refused. Default 256 MiB. */
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
	/** Encoded content stored: the quota measure. */
	bytes: number;
	/** The store's files on disk, SQLite overhead included. */
	diskBytes: number;
	registeredAt: number;
}

export interface IGuardianHostStatus {
	guardianId: string;
	authRequired: boolean;
	sessions: number;
	/** Partial requests and discarded ids retained across every session. */
	inFlight: number;
	sets: IGuardianHostSetStatus[];
	/** Encoded content stored across every set. */
	totalBytes: number;
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
	/** Encoded content stored, re-derived at open and charged per write. */
	bytes: number;
}

/** How a verb that may grow the store is admitted and accounted. */
interface IWritePlan {
	recoveryId: Buffer;
	/** Bytes the store grows by if the guardian accepts; 0 for a replay. */
	delta: number;
	/** True when delta is exact and charged as is; false measures the namespace. */
	exact: boolean;
	/** Whether the byte quota refuses the write when it would cross the limit. */
	gated: boolean;
}

const STORE_SUFFIXES = ['', '-wal', '-shm'];

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
		if (++this.handled % 64 === 0) this.evictStale();
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

	/** The peer's session is gone: everything retained for it goes with it. */
	sessionClosed(peer: string): void {
		this.sessions.delete(peer);
	}

	/** Drop partial requests and discard entries that went stale; returns how many. */
	evictStale(): number {
		let dropped = 0;
		for (const session of this.sessions.values()) {
			dropped += session.evictStale();
		}
		return dropped;
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
			rateLimitPerMinute: 0,
			acceptsRegistrations: this.sets.size < this.maxSets
		};
	}

	forRequest(verb: GuardianVerbName, body: Buffer): ReferenceGuardian | Buffer {
		const refuse = (status: GuardianStatus, detail: string): Buffer =>
			encodeGuardianVerbRefusal(verb, status, detail);
		let setId: Buffer;
		let registration: IGuardianRegisterNodeRequest | null = null;
		let record: IGuardianRecord | null = null;
		let recoveryId: Buffer | null = null;
		try {
			switch (verb) {
				case 'register_node':
					registration = decodeRegisterNodeRequest(body);
					setId = registration.guardianSetId;
					recoveryId = registration.initialState.recoveryId;
					break;
				case 'put_state':
					record = decodePutStateRequest(body).record;
					setId = record.guardianSetId;
					recoveryId = record.recoveryId;
					break;
				case 'sync_record':
					record = decodeSyncRecordRequest(body).record;
					setId = record.guardianSetId;
					recoveryId = record.recoveryId;
					break;
				case 'get_head':
					setId = decodeGetHeadRequest(body).guardianSetId;
					break;
				case 'get_state':
					setId = decodeGetStateRequest(body).guardianSetId;
					break;
				case 'acquire_epoch': {
					const request = decodeAcquireEpochRequest(body);
					setId = request.guardianSetId;
					recoveryId = request.expectedState.recoveryId;
					break;
				}
				case 'rotate_set': {
					// Addressed to the OUTGOING set, which this host serves.
					const request = decodeRotateSetRequest(body);
					setId = request.guardianSetId;
					recoveryId = request.recoveryId;
					break;
				}
				case 'sync_epoch': {
					const certificates = decodeSyncEpochRequest(body).certificates;
					if (certificates.length === 0) {
						return refuse(
							GuardianStatus.ERR_MALFORMED,
							'SYNC_EPOCH carries no certificates'
						);
					}
					setId = certificates[0].guardianSetId;
					recoveryId = certificates[0].supersededState.recoveryId;
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
		const served = this.sets.get(key);

		if (!served) {
			if (verb === 'register_node') {
				return this.registerNewSet(
					setId,
					registration as IGuardianRegisterNodeRequest,
					body
				);
			}
			// A read on a set nobody registered is a truthful "no namespace
			// here" (wire 2.6): the writer's ownership check relies on
			// ERR_UNKNOWN_NODE meaning "fresh, register", and a host serves a
			// set only once that registration has run. Writes other than
			// registration name a set that does not exist here.
			if (verb === 'get_head' || verb === 'get_state') {
				return refuse(
					GuardianStatus.ERR_UNKNOWN_NODE,
					'recovery_id not registered: this host does not serve the set yet'
				);
			}
			return refuse(
				GuardianStatus.ERR_UNKNOWN_SET,
				'guardian_set_id is not served by this host; register it first'
			);
		}
		if (recoveryId === null) return served.guardian;
		if (recoveryId.length !== 32) {
			return refuse(
				GuardianStatus.ERR_MALFORMED,
				'recovery_id must be 32 bytes'
			);
		}
		return this.write(
			served,
			verb,
			body,
			this.planWrite(served, verb, body, recoveryId, record)
		);
	}

	// ─────────────── status and lifecycle ───────────────

	status(): IGuardianHostStatus {
		let inFlight = 0;
		for (const session of this.sessions.values()) {
			inFlight += session.inFlight + session.discarding;
		}
		const sets = [...this.sets.values()].map((set) => ({
			setId: set.setId.toString('hex'),
			members: set.members.map((m) => m.toString('hex')),
			namespaces: set.guardian.listNamespaceIds().length,
			bytes: set.bytes,
			diskBytes: this.diskBytesOf(set),
			registeredAt: set.registeredAt
		}));
		return {
			guardianId: this.guardianId.toString('hex'),
			authRequired: this.authenticate !== undefined,
			sessions: this.sessions.size,
			inFlight,
			sets,
			totalBytes: sets.reduce((sum, set) => sum + set.bytes, 0),
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

	// ─────────────── registration of a set never served ───────────────

	/**
	 * The first registration of a set, one unit from the host's side: the
	 * whole admission the guardian would apply runs BEFORE a store exists,
	 * the set is counted against maxSets, the store is opened and the
	 * guardian registers into it, and only an accepted registration is
	 * served, indexed and announced. A refusal closes the store again and
	 * removes it if this attempt created it. A store already on disk that
	 * the index does not name is a registration this host committed but
	 * never answered (the index is saved before the answer leaves), so it
	 * is reopened rather than replaced and the retry adopts it.
	 */
	private registerNewSet(
		setId: Buffer,
		request: IGuardianRegisterNodeRequest,
		body: Buffer
	): Buffer {
		const key = setId.toString('hex');
		const refuse = (status: GuardianStatus, detail: string): Buffer =>
			encodeGuardianVerbRefusal('register_node', status, detail);
		const problem = registrationAdmissionProblem(
			this.guardianId,
			setId,
			request
		);
		if (problem) return refuse(problem.status, problem.detail);
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
		if (GUARDIAN_HOST_REGISTRATION_BYTES > this.maxBytesPerSet) {
			return this.quotaRefusal(
				'register_node',
				key,
				0,
				GUARDIAN_HOST_REGISTRATION_BYTES
			);
		}
		const file = this.fileFor(setId);
		const created = !fs.existsSync(file);
		const served = this.openSet(setId, request.guardianMembers, this.clock());
		let outcome: IGuardianVerbOutcome;
		try {
			outcome = runGuardianVerb(served.guardian, 'register_node', body);
		} catch (error) {
			this.discardSet(served, created);
			throw error;
		}
		if (
			outcome.status !== GuardianStatus.OK &&
			outcome.status !== GuardianStatus.OK_DUPLICATE
		) {
			// Nothing was committed: the guardian's refusals and its internal
			// errors both leave the transaction rolled back.
			this.discardSet(served, created);
			return outcome.body;
		}
		served.bytes = served.guardian.contentBytes();
		this.sets.set(key, served);
		try {
			this.saveIndex();
		} catch (error) {
			// The namespace is committed but unanswered; the store stays as
			// the orphan a retry adopts, and the set is not served until then.
			this.sets.delete(key);
			served.guardian.close();
			throw error;
		}
		this.emit({
			type: 'guardian:set-registered',
			detail: `now serving set ${key}`,
			setId: key
		});
		return outcome.body;
	}

	// ─────────────── writes on a served set ───────────────

	/**
	 * What a verb that may grow the store will cost if the guardian accepts
	 * it, decided from what the guardian holds (GET_HEAD is a snapshot read):
	 * an append inside the stored range is a replay or a conflict, which the
	 * guardian answers without writing, so it costs nothing; a registration
	 * of a namespace already held, or a rotation already stored, likewise.
	 * Records are charged exactly (their row is the request); the small rows
	 * of the other verbs are measured after the write.
	 */
	private planWrite(
		served: IServedSet,
		verb: GuardianVerbName,
		body: Buffer,
		recoveryId: Buffer,
		record: IGuardianRecord | null
	): IWritePlan {
		const head = served.guardian.getHead({
			protocolVersion: GUARDIAN_PROTOCOL_VERSION,
			guardianSetId: served.setId,
			recoveryId
		});
		const held = head.status === GuardianStatus.OK ? head.state ?? null : null;
		switch (verb) {
			case 'put_state':
			case 'sync_record': {
				const rec = record as IGuardianRecord;
				const inRange =
					held !== null &&
					!isGenesisLogHead(held.logHead) &&
					rec.sequence >= held.origin.firstSequence &&
					rec.sequence <= held.logHead.sequence;
				return {
					recoveryId,
					delta: inRange
						? 0
						: GUARDIAN_HOST_RECORD_OVERHEAD_BYTES + rec.ciphertext.length,
					exact: true,
					gated: true
				};
			}
			case 'register_node':
				return {
					recoveryId,
					delta: held !== null ? 0 : GUARDIAN_HOST_REGISTRATION_BYTES,
					exact: false,
					gated: true
				};
			case 'rotate_set':
				return {
					recoveryId,
					delta: held !== null && head.rotation ? 0 : body.length,
					exact: false,
					gated: true
				};
			default:
				// ACQUIRE_EPOCH and SYNC_EPOCH add epoch rows the quota does
				// not refuse (takeover repair is not a storage decision), but
				// the counter must still see them.
				return { recoveryId, delta: 0, exact: false, gated: false };
		}
	}

	/**
	 * Admit, run and account one write. The host is synchronous, so from the
	 * quota check through the guardian's transaction to the charge nothing
	 * else touches the set: two writes that would each fit but not together
	 * are decided one after the other, and the second sees the first's charge.
	 */
	private write(
		served: IServedSet,
		verb: GuardianVerbName,
		body: Buffer,
		plan: IWritePlan
	): Buffer {
		const key = served.setId.toString('hex');
		if (plan.gated && served.bytes + plan.delta > this.maxBytesPerSet) {
			return this.quotaRefusal(verb, key, served.bytes, plan.delta);
		}
		const before = plan.exact
			? 0
			: served.guardian.contentBytes(plan.recoveryId);
		const outcome = runGuardianVerb(served.guardian, verb, body);
		if (outcome.status === GuardianStatus.OK) {
			served.bytes += plan.exact
				? plan.delta
				: served.guardian.contentBytes(plan.recoveryId) - before;
		}
		return outcome.body;
	}

	private quotaRefusal(
		verb: GuardianVerbName,
		key: string,
		used: number,
		delta: number
	): Buffer {
		this.emit({
			type: 'guardian:quota-refused',
			detail: `set ${key} holds ${used} of ${this.maxBytesPerSet} bytes; a write of ${delta} would exceed it`,
			setId: key
		});
		return encodeGuardianVerbRefusal(
			verb,
			GuardianStatus.ERR_QUOTA_EXCEEDED,
			`this host's storage quota for the set is exhausted`
		);
	}

	// ─────────────── internals ───────────────

	private fileFor(setId: Buffer): string {
		return path.join(this.config.path, `${setId.toString('hex')}.sqlite`);
	}

	/** Open the store for a set; the caller decides whether it is served. */
	private openSet(
		setId: Buffer,
		members: Buffer[],
		registeredAt: number
	): IServedSet {
		const file = this.fileFor(setId);
		const guardian = new ReferenceGuardian({
			path: file,
			guardianSecret: this.config.guardianSecret,
			members,
			maxCiphertextBytes: this.maxCiphertextBytes,
			maxRecordsPerGet: MAX_RECORDS_PER_GET,
			clock: (): bigint => BigInt(this.clock())
		});
		return {
			setId: Buffer.from(setId),
			members: members.map((m) => Buffer.from(m)),
			guardian,
			file,
			registeredAt,
			bytes: guardian.contentBytes()
		};
	}

	/** Close a store that will not be served; remove it if this attempt made it. */
	private discardSet(served: IServedSet, created: boolean): void {
		served.guardian.close();
		if (!created) return;
		for (const suffix of STORE_SUFFIXES) {
			try {
				fs.unlinkSync(served.file + suffix);
			} catch {
				// Not every suffix exists; the main file does.
			}
		}
	}

	private diskBytesOf(set: IServedSet): number {
		let total = 0;
		for (const suffix of STORE_SUFFIXES) {
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
			this.sets.set(key, this.openSet(setId, members, entry.registeredAt));
		}
	}

	private memberListProblem(
		members: Buffer[],
		setId: Buffer
	): { detail: string } | null {
		if (members.length !== CRASH_V1_PROFILE.total) {
			return {
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
				detail: `guardian_members invalid: ${
					error instanceof Error ? error.message : String(error)
				}`
			};
		}
		if (!computed.equals(setId)) {
			return { detail: 'guardian_members do not hash to guardian_set_id' };
		}
		if (!members.some((m) => m.equals(this.guardianId))) {
			return { detail: 'this guardian is not a member of guardian_members' };
		}
		return null;
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
