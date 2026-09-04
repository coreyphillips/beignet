/**
 * bolt8 guardian sessions (docs/RECOVERY-GUARDIAN-WIRE.md 2.7, issue #699).
 *
 * A guardian hosted by a beignet node is reached over a dedicated BOLT 8
 * session to the node's ordinary peer address, `bolt8://<node id>@host:port`.
 * The signed guardian objects do not change and the protobuf bodies are the
 * exact bytes the HTTP mapping sends (wire section 6); what this module adds
 * is the envelope that carries them over Lightning's transport:
 *
 * - Every verb rides the beignet custom message (message/custom.ts, one odd
 *   wire type) on two subtypes, GUARDIAN_REQUEST and GUARDIAN_RESPONSE.
 * - BOLT 8 caps a message at 65535 bytes and a snapshot record runs to
 *   megabytes, so a request or response is split into ordered chunks that
 *   share a request id. Chunks of one request arrive in order because the
 *   session is a single ordered stream; interleaving BETWEEN requests is
 *   allowed, so several verbs can be in flight on one session.
 * - The session is opened under a FRESH random static key, never the node
 *   identity: the guardian sees a stranger, which keeps recovery_id
 *   unlinkable to the Lightning node id (wire 1.1) and keeps guardian
 *   traffic structurally off the channel connection.
 * - It does not go through the node's PeerManager. The guardian stack is
 *   assembled BEFORE the node exists (assembly.ts), and the recovery
 *   outbound gate fences everything the PeerManager sends during startup
 *   quarantine, which would fence the very confirmation that lifts it.
 *
 * Frame layout, big-endian, fixed width:
 *
 *   requestId(4) || verb(1) || totalLength(4) || chunkIndex(2) || chunkCount(2)
 *   then, on chunk 0 only:
 *     request:  authLength(2) || auth          (the Authorization header
 *                                               bytes, verbatim; empty when
 *                                               the guardian runs open)
 *     response: transportStatus(2)             (the HTTP-layer status the
 *                                               http mapping would answer)
 *   then the body bytes for this chunk.
 *
 * `transportStatus` mirrors wire 2.5 exactly: 200 for every well-formed
 * protocol exchange INCLUDING protocol-level rejections (the protocol
 * result lives in the protobuf body), 401 for a refused credential, 404 for
 * an unknown verb, 413 for a body over the advertised limit, 500 when the
 * guardian itself failed. That one-to-one mapping is what lets the
 * unchanged GuardianClient drive either transport through the same
 * `GuardianHttpTransport` function shape.
 */

import { randomBytes, timingSafeEqual } from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import { Peer } from '../transport/peer';
import { IDuplexTransport } from '../transport/duplex-transport';
import {
	BEIGNET_CUSTOM_MAX_PAYLOAD,
	BEIGNET_CUSTOM_MESSAGE_TYPE,
	BeignetCustomSubtype,
	decodeCustomMessage,
	encodeCustomMessage
} from '../message/custom';
import {
	GuardianHttpTransport,
	GuardianTransportError,
	IBolt8GuardianTarget,
	parseBolt8GuardianUrl
} from './guardian-client';
import { GUARDIAN_HTTP_BASE_PATH, encodeInfoResponse } from './guardian-proto';
import {
	GUARDIAN_ENVELOPE_ALLOWANCE_BYTES,
	GuardianVerbName,
	dispatchGuardianVerb,
	isGuardianVerbName
} from './guardian-http';
import { IGuardianInfoResponse, ReferenceGuardian } from './guardian';

// ─────────────── verbs ───────────────

/** Verb codes on the wire; INFO is the unsigned discovery verb (wire 5.8). */
export enum GuardianBolt8Verb {
	INFO = 0,
	REGISTER_NODE = 1,
	PUT_STATE = 2,
	GET_HEAD = 3,
	GET_STATE = 4,
	ACQUIRE_EPOCH = 5,
	SYNC_RECORD = 6,
	SYNC_EPOCH = 7
}

const VERB_CODE_BY_NAME: Record<GuardianVerbName | 'info', GuardianBolt8Verb> =
	{
		info: GuardianBolt8Verb.INFO,
		register_node: GuardianBolt8Verb.REGISTER_NODE,
		put_state: GuardianBolt8Verb.PUT_STATE,
		get_head: GuardianBolt8Verb.GET_HEAD,
		get_state: GuardianBolt8Verb.GET_STATE,
		acquire_epoch: GuardianBolt8Verb.ACQUIRE_EPOCH,
		sync_record: GuardianBolt8Verb.SYNC_RECORD,
		sync_epoch: GuardianBolt8Verb.SYNC_EPOCH
	};

const VERB_NAME_BY_CODE = new Map<number, GuardianVerbName | 'info'>(
	(Object.keys(VERB_CODE_BY_NAME) as Array<GuardianVerbName | 'info'>).map(
		(name) => [VERB_CODE_BY_NAME[name], name]
	)
);

/** The wire code for a verb path segment (`info` or a signed verb name). */
export function guardianBolt8VerbCode(name: string): GuardianBolt8Verb | null {
	if (name === 'info' || isGuardianVerbName(name)) {
		return VERB_CODE_BY_NAME[name];
	}
	return null;
}

/** The verb path segment for a wire code, or null for an unknown code. */
export function guardianBolt8VerbName(
	code: number
): GuardianVerbName | 'info' | null {
	return VERB_NAME_BY_CODE.get(code) ?? null;
}

// ─────────────── frames ───────────────

export const GUARDIAN_BOLT8_FRAME_HEADER_BYTES = 13;
/** Longest Authorization value a request may carry (wire 2.7). */
export const GUARDIAN_BOLT8_MAX_AUTH_BYTES = 4096;
/** Body bytes a non-first chunk carries. */
export const GUARDIAN_BOLT8_CHUNK_BODY_BYTES =
	BEIGNET_CUSTOM_MAX_PAYLOAD - GUARDIAN_BOLT8_FRAME_HEADER_BYTES;

/** Transport-level statuses a response carries (wire 2.5 HTTP layer). */
export const GuardianBolt8Status = Object.freeze({
	OK: 200,
	UNAUTHORIZED: 401,
	NOT_FOUND: 404,
	TOO_LARGE: 413,
	GUARDIAN_FAILED: 500
});

export interface IGuardianBolt8FrameHeader {
	requestId: number;
	verb: number;
	totalLength: number;
	chunkIndex: number;
	chunkCount: number;
}

export interface IGuardianBolt8Request {
	requestId: number;
	verb: number;
	/** Authorization value, verbatim bytes; absent when running open. */
	auth?: Buffer;
	body: Buffer;
}

export interface IGuardianBolt8Response {
	requestId: number;
	verb: number;
	status: number;
	body: Buffer;
}

/** A decoded chunk: the header, the chunk-0 prefix fields, the body slice. */
export interface IGuardianBolt8Frame {
	header: IGuardianBolt8FrameHeader;
	auth?: Buffer;
	status?: number;
	chunk: Buffer;
}

export class GuardianBolt8FrameError extends Error {
	constructor(
		message: string,
		readonly requestId?: number,
		readonly verb?: number
	) {
		super(message);
		this.name = 'GuardianBolt8FrameError';
	}
}

function assertU32(value: number, what: string): void {
	if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
		throw new GuardianBolt8FrameError(`${what} out of range: ${value}`);
	}
}

function encodeHeader(header: IGuardianBolt8FrameHeader): Buffer {
	const out = Buffer.alloc(GUARDIAN_BOLT8_FRAME_HEADER_BYTES);
	out.writeUInt32BE(header.requestId, 0);
	out.writeUInt8(header.verb, 4);
	out.writeUInt32BE(header.totalLength, 5);
	out.writeUInt16BE(header.chunkIndex, 9);
	out.writeUInt16BE(header.chunkCount, 11);
	return out;
}

/**
 * Split one message into custom-envelope payloads (each is what
 * encodeCustomMessage wraps). Chunk 0 carries the prefix; later chunks are
 * header plus body only. A body that needs more than 65535 chunks cannot be
 * sent, which the 16 MiB ciphertext cap (wire 8) already rules out.
 */
function chunkMessage(
	requestId: number,
	verb: number,
	prefix: Buffer,
	body: Buffer
): Buffer[] {
	assertU32(requestId, 'requestId');
	if (!Number.isInteger(verb) || verb < 0 || verb > 0xff) {
		throw new GuardianBolt8FrameError(`verb out of range: ${verb}`);
	}
	assertU32(body.length, 'totalLength');
	const firstCapacity =
		BEIGNET_CUSTOM_MAX_PAYLOAD -
		GUARDIAN_BOLT8_FRAME_HEADER_BYTES -
		prefix.length;
	if (firstCapacity < 0) {
		throw new GuardianBolt8FrameError('frame prefix exceeds the message cap');
	}
	const chunkCount =
		body.length <= firstCapacity
			? 1
			: 1 +
			  Math.ceil(
					(body.length - firstCapacity) / GUARDIAN_BOLT8_CHUNK_BODY_BYTES
			  );
	if (chunkCount > 0xffff) {
		throw new GuardianBolt8FrameError(
			`body of ${body.length} bytes needs ${chunkCount} chunks, over the cap`
		);
	}
	const frames: Buffer[] = [];
	let offset = 0;
	for (let index = 0; index < chunkCount; index++) {
		const capacity =
			index === 0 ? firstCapacity : GUARDIAN_BOLT8_CHUNK_BODY_BYTES;
		const slice = body.subarray(
			offset,
			Math.min(body.length, offset + capacity)
		);
		offset += slice.length;
		frames.push(
			Buffer.concat([
				encodeHeader({
					requestId,
					verb,
					totalLength: body.length,
					chunkIndex: index,
					chunkCount
				}),
				index === 0 ? prefix : Buffer.alloc(0),
				slice
			])
		);
	}
	return frames;
}

export function encodeGuardianBolt8Request(
	request: IGuardianBolt8Request
): Buffer[] {
	const auth = request.auth ?? Buffer.alloc(0);
	if (auth.length > GUARDIAN_BOLT8_MAX_AUTH_BYTES) {
		throw new GuardianBolt8FrameError(
			`auth of ${auth.length} bytes exceeds ${GUARDIAN_BOLT8_MAX_AUTH_BYTES}`
		);
	}
	const prefix = Buffer.alloc(2 + auth.length);
	prefix.writeUInt16BE(auth.length, 0);
	auth.copy(prefix, 2);
	return chunkMessage(request.requestId, request.verb, prefix, request.body);
}

export function encodeGuardianBolt8Response(
	response: IGuardianBolt8Response
): Buffer[] {
	if (
		!Number.isInteger(response.status) ||
		response.status < 0 ||
		response.status > 0xffff
	) {
		throw new GuardianBolt8FrameError(
			`status out of range: ${response.status}`
		);
	}
	const prefix = Buffer.alloc(2);
	prefix.writeUInt16BE(response.status, 0);
	return chunkMessage(response.requestId, response.verb, prefix, response.body);
}

/** Decode one custom-envelope payload as a request or response chunk. */
export function decodeGuardianBolt8Frame(
	payload: Buffer,
	kind: 'request' | 'response'
): IGuardianBolt8Frame {
	if (payload.length < GUARDIAN_BOLT8_FRAME_HEADER_BYTES) {
		throw new GuardianBolt8FrameError('guardian frame shorter than its header');
	}
	const header: IGuardianBolt8FrameHeader = {
		requestId: payload.readUInt32BE(0),
		verb: payload.readUInt8(4),
		totalLength: payload.readUInt32BE(5),
		chunkIndex: payload.readUInt16BE(9),
		chunkCount: payload.readUInt16BE(11)
	};
	const fail = (message: string): never => {
		throw new GuardianBolt8FrameError(message, header.requestId, header.verb);
	};
	if (header.chunkCount === 0) fail('guardian frame declares zero chunks');
	if (header.chunkIndex >= header.chunkCount) {
		fail('guardian frame chunk index past its count');
	}
	let offset = GUARDIAN_BOLT8_FRAME_HEADER_BYTES;
	const frame: IGuardianBolt8Frame = { header, chunk: Buffer.alloc(0) };
	if (header.chunkIndex === 0) {
		if (payload.length < offset + 2) fail('guardian frame prefix truncated');
		if (kind === 'request') {
			const authLength = payload.readUInt16BE(offset);
			offset += 2;
			if (authLength > GUARDIAN_BOLT8_MAX_AUTH_BYTES) {
				fail('guardian frame auth over the cap');
			}
			if (payload.length < offset + authLength) {
				fail('guardian frame auth truncated');
			}
			if (authLength > 0) {
				frame.auth = Buffer.from(payload.subarray(offset, offset + authLength));
			}
			offset += authLength;
		} else {
			frame.status = payload.readUInt16BE(offset);
			offset += 2;
		}
	}
	frame.chunk = Buffer.from(payload.subarray(offset));
	return frame;
}

// ─────────────── reassembly ───────────────

export type GuardianBolt8Assembly<T> =
	| { kind: 'complete'; message: T }
	/**
	 * Chunk 0 declared a body over the cap. The remaining chunks of this
	 * request id are swallowed silently so the stream stays usable; the
	 * caller answers (or reports) 413 exactly once.
	 */
	| { kind: 'too-large'; requestId: number; verb: number; totalLength: number }
	| null;

export interface IGuardianBolt8AssemblerOptions {
	kind: 'request' | 'response';
	/** Cap on a reassembled body, fixed or looked up per request. */
	maxBodyBytes: number | ((requestId: number, verb: number) => number);
	/** Partial messages allowed at once; more is a framing violation. */
	maxInFlight?: number;
	/** A partial message older than this is dropped by evictStale(). */
	staleMs?: number;
	clock?: () => number;
}

interface IPartial {
	header: IGuardianBolt8FrameHeader;
	auth?: Buffer;
	status?: number;
	chunks: Buffer[];
	received: number;
	startedAt: number;
}

/**
 * Reassemble chunked frames into whole requests or responses, one instance
 * per session direction. Framing violations throw GuardianBolt8FrameError:
 * a peer that interleaves chunks of one request out of order, changes a
 * header mid-message, or exceeds the in-flight allowance is misbehaving,
 * and the right answer is to drop the session, not to guess.
 */
export class GuardianBolt8Assembler {
	private readonly partials = new Map<number, IPartial>();
	/** Request ids being swallowed after a too-large chunk 0: chunks left. */
	private readonly discarding = new Map<number, number>();
	private readonly kind: 'request' | 'response';
	private readonly maxBodyBytes: (requestId: number, verb: number) => number;
	private readonly maxInFlight: number;
	private readonly staleMs: number;
	private readonly clock: () => number;

	constructor(options: IGuardianBolt8AssemblerOptions) {
		this.kind = options.kind;
		this.maxBodyBytes =
			typeof options.maxBodyBytes === 'number'
				? (): number => options.maxBodyBytes as number
				: options.maxBodyBytes;
		this.maxInFlight = options.maxInFlight ?? 64;
		this.staleMs = options.staleMs ?? 120_000;
		this.clock = options.clock ?? ((): number => Date.now());
	}

	get inFlight(): number {
		return this.partials.size;
	}

	push(
		payload: Buffer
	): GuardianBolt8Assembly<IGuardianBolt8Request | IGuardianBolt8Response> {
		const frame = decodeGuardianBolt8Frame(payload, this.kind);
		const { header } = frame;
		const fail = (message: string): never => {
			throw new GuardianBolt8FrameError(message, header.requestId, header.verb);
		};

		if (header.chunkIndex === 0) {
			if (this.partials.has(header.requestId)) {
				fail('guardian frame restarts a request still in flight');
			}
			if (this.discarding.has(header.requestId)) {
				fail('guardian frame restarts a request being discarded');
			}
			const cap = this.maxBodyBytes(header.requestId, header.verb);
			if (header.totalLength > cap) {
				if (header.chunkCount > 1) {
					this.discarding.set(header.requestId, header.chunkCount - 1);
				}
				return {
					kind: 'too-large',
					requestId: header.requestId,
					verb: header.verb,
					totalLength: header.totalLength
				};
			}
			if (header.chunkCount === 1) {
				if (frame.chunk.length !== header.totalLength) {
					fail('guardian frame body length disagrees with its header');
				}
				return { kind: 'complete', message: this.finish(frame, [frame.chunk]) };
			}
			if (this.partials.size >= this.maxInFlight) {
				fail('too many guardian requests in flight');
			}
			if (frame.chunk.length >= header.totalLength) {
				fail('guardian frame chunk 0 already exceeds the declared length');
			}
			this.partials.set(header.requestId, {
				header,
				auth: frame.auth,
				status: frame.status,
				chunks: [frame.chunk],
				received: frame.chunk.length,
				startedAt: this.clock()
			});
			return null;
		}

		const remaining = this.discarding.get(header.requestId);
		if (remaining !== undefined) {
			if (remaining <= 1) this.discarding.delete(header.requestId);
			else this.discarding.set(header.requestId, remaining - 1);
			return null;
		}
		const partial = this.partials.get(header.requestId);
		if (!partial) fail('guardian frame continues an unknown request');
		const expected = partial!.chunks.length;
		if (
			header.chunkIndex !== expected ||
			header.chunkCount !== partial!.header.chunkCount ||
			header.totalLength !== partial!.header.totalLength ||
			header.verb !== partial!.header.verb
		) {
			this.partials.delete(header.requestId);
			fail('guardian frame out of order or inconsistent with its request');
		}
		const received = partial!.received + frame.chunk.length;
		if (received > partial!.header.totalLength) {
			this.partials.delete(header.requestId);
			fail('guardian frame body exceeds the declared length');
		}
		partial!.chunks.push(frame.chunk);
		partial!.received = received;
		if (header.chunkIndex === header.chunkCount - 1) {
			this.partials.delete(header.requestId);
			if (received !== partial!.header.totalLength) {
				fail('guardian frame body shorter than the declared length');
			}
			return {
				kind: 'complete',
				message: this.finish(
					{
						header: partial!.header,
						auth: partial!.auth,
						status: partial!.status,
						chunk: Buffer.alloc(0)
					},
					partial!.chunks
				)
			};
		}
		return null;
	}

	/** Drop partial messages older than staleMs; returns how many. */
	evictStale(): number {
		const cutoff = this.clock() - this.staleMs;
		let dropped = 0;
		for (const [id, partial] of this.partials) {
			if (partial.startedAt < cutoff) {
				this.partials.delete(id);
				dropped++;
			}
		}
		return dropped;
	}

	clear(): void {
		this.partials.clear();
		this.discarding.clear();
	}

	private finish(
		frame: IGuardianBolt8Frame,
		chunks: Buffer[]
	): IGuardianBolt8Request | IGuardianBolt8Response {
		const body = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks);
		if (this.kind === 'request') {
			const request: IGuardianBolt8Request = {
				requestId: frame.header.requestId,
				verb: frame.header.verb,
				body
			};
			if (frame.auth) request.auth = frame.auth;
			return request;
		}
		return {
			requestId: frame.header.requestId,
			verb: frame.header.verb,
			status: frame.status ?? 0,
			body
		};
	}
}

// ─────────────── responder (the guardian side) ───────────────

/**
 * What answers a session's verbs. A single ReferenceGuardian serves one
 * set; a GuardianHost (guardian-host.ts) serves many and picks the guardian
 * per request, or hands back an already-encoded protocol refusal (unknown
 * set, exhausted quota, undecodable body).
 */
export interface IGuardianResolver {
	info(): IGuardianInfoResponse;
	forRequest(verb: GuardianVerbName, body: Buffer): ReferenceGuardian | Buffer;
}

export function singleGuardianResolver(
	guardian: ReferenceGuardian
): IGuardianResolver {
	return {
		info: (): IGuardianInfoResponse => guardian.info(),
		forRequest: (): ReferenceGuardian => guardian
	};
}

export interface IGuardianBolt8ResponderOptions {
	guardian: ReferenceGuardian | IGuardianResolver;
	/**
	 * Transport credential check over the request's auth bytes (wire 9).
	 * Absent means running open, which BOLT 8 makes acceptable on any
	 * network for confidentiality; the credential is an allow-list.
	 */
	authenticate?: (auth: Buffer | undefined) => boolean;
	/** Defaults to the guardian's advertised ciphertext limit plus envelope. */
	maxBodyBytes?: number;
	maxInFlight?: number;
	clock?: () => number;
}

/** Constant-time check of the request auth against `Bearer <token>`. */
export function bolt8BearerAuthenticator(
	token: string
): (auth: Buffer | undefined) => boolean {
	const expected = Buffer.from(`Bearer ${token}`, 'utf8');
	return (auth): boolean =>
		auth !== undefined &&
		auth.length === expected.length &&
		timingSafeEqual(auth, expected);
}

/**
 * The guardian side of one session: feed it every GUARDIAN_REQUEST payload
 * the peer sends, and send back every frame it returns. One instance per
 * peer session. A GuardianBolt8FrameError from handle() means the peer
 * violated framing; drop the session.
 */
export class GuardianBolt8Responder {
	private readonly resolver: IGuardianResolver;
	private readonly authenticate?: (auth: Buffer | undefined) => boolean;
	private readonly assembler: GuardianBolt8Assembler;

	constructor(options: IGuardianBolt8ResponderOptions) {
		this.resolver =
			options.guardian instanceof ReferenceGuardian
				? singleGuardianResolver(options.guardian)
				: options.guardian;
		this.authenticate = options.authenticate;
		this.assembler = new GuardianBolt8Assembler({
			kind: 'request',
			maxBodyBytes:
				options.maxBodyBytes ??
				this.resolver.info().maxCiphertextBytes +
					GUARDIAN_ENVELOPE_ALLOWANCE_BYTES,
			maxInFlight: options.maxInFlight,
			clock: options.clock
		});
	}

	handle(payload: Buffer): Buffer[] {
		const result = this.assembler.push(payload);
		if (result === null) return [];
		if (result.kind === 'too-large') {
			return encodeGuardianBolt8Response({
				requestId: result.requestId,
				verb: result.verb,
				status: GuardianBolt8Status.TOO_LARGE,
				body: Buffer.alloc(0)
			});
		}
		const request = result.message as IGuardianBolt8Request;
		const answer = (status: number, body: Buffer): Buffer[] =>
			encodeGuardianBolt8Response({
				requestId: request.requestId,
				verb: request.verb,
				status,
				body
			});
		if (this.authenticate && !this.authenticate(request.auth)) {
			return answer(GuardianBolt8Status.UNAUTHORIZED, Buffer.alloc(0));
		}
		const name = guardianBolt8VerbName(request.verb);
		if (name === null) {
			return answer(GuardianBolt8Status.NOT_FOUND, Buffer.alloc(0));
		}
		try {
			if (name === 'info') {
				return answer(
					GuardianBolt8Status.OK,
					encodeInfoResponse(this.resolver.info())
				);
			}
			const resolved = this.resolver.forRequest(name, request.body);
			const body = Buffer.isBuffer(resolved)
				? resolved
				: dispatchGuardianVerb(resolved, name, request.body);
			return answer(GuardianBolt8Status.OK, body);
		} catch {
			return answer(GuardianBolt8Status.GUARDIAN_FAILED, Buffer.alloc(0));
		}
	}

	evictStale(): number {
		return this.assembler.evictStale();
	}
}

// ─────────────── session (the writer side) ───────────────

export interface IBolt8GuardianSessionOptions {
	target: IBolt8GuardianTarget;
	/** Socket factory, e.g. a SOCKS5 factory for an onion host. */
	createSocket?: (host: string, port: number) => Promise<IDuplexTransport>;
	/**
	 * The session's static key. Fresh random per session by default, and
	 * that default is the privacy property (module comment); override only
	 * in tests.
	 */
	localPrivateKey?: Buffer;
	connectTimeoutMs?: number;
	handshakeTimeoutMs?: number;
	/** Backoff after a failed dial before the next attempt is allowed. */
	reconnectMinMs?: number;
	reconnectMaxMs?: number;
	maxInFlight?: number;
	clock?: () => number;
}

export interface IBolt8GuardianRequestOptions {
	auth?: Buffer;
	timeoutMs: number;
	maxResponseBytes: number;
}

interface IPending {
	verb: number;
	maxResponseBytes: number;
	resolve: (value: { status: number; body: Buffer }) => void;
	reject: (error: Error) => void;
	timer: ReturnType<typeof setTimeout>;
}

function freshPrivateKey(): Buffer {
	for (;;) {
		const key = randomBytes(32);
		if (ecc.isPrivate(key)) return key;
	}
}

/**
 * One long-lived session to one node-hosted guardian. Connects lazily on
 * the first request and reconnects on the next request after a drop, with
 * exponential backoff between failed dials; while backing off, requests
 * fail fast so the barrier's own timeout and retry govern, not a hidden
 * wait here. Requests are correlated by request id and may overlap.
 */
export class Bolt8GuardianSession {
	readonly target: IBolt8GuardianTarget;
	private readonly options: IBolt8GuardianSessionOptions;
	private readonly clock: () => number;
	private peer: Peer | null = null;
	private connecting: Promise<Peer> | null = null;
	private readonly pending = new Map<number, IPending>();
	private nextRequestId = 1;
	private failures = 0;
	private nextAttemptAt = 0;
	private closed = false;
	private assembler: GuardianBolt8Assembler;

	constructor(options: IBolt8GuardianSessionOptions) {
		this.target = options.target;
		this.options = options;
		this.clock = options.clock ?? ((): number => Date.now());
		this.assembler = this.newAssembler();
	}

	/** Whether a handshaken connection is up right now. */
	get connected(): boolean {
		return this.peer !== null && this.peer.getState() === 'ready';
	}

	get inFlight(): number {
		return this.pending.size;
	}

	async request(
		verb: number,
		body: Buffer,
		options: IBolt8GuardianRequestOptions
	): Promise<{ status: number; body: Buffer }> {
		if (this.closed) {
			throw new GuardianTransportError('bolt8 guardian session is closed');
		}
		const deadline = this.clock() + options.timeoutMs;
		const peer = await this.ensureConnected(options.timeoutMs);
		const remaining = deadline - this.clock();
		if (remaining <= 0) {
			throw new GuardianTransportError('guardian request timed out');
		}
		const requestId = this.allocateRequestId();
		const frames = encodeGuardianBolt8Request({
			requestId,
			verb,
			auth: options.auth,
			body
		});
		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(requestId);
				reject(new GuardianTransportError('guardian request timed out'));
			}, remaining);
			this.pending.set(requestId, {
				verb,
				maxResponseBytes: options.maxResponseBytes,
				resolve,
				reject,
				timer
			});
			try {
				for (const frame of frames) {
					peer.sendMessage(
						BEIGNET_CUSTOM_MESSAGE_TYPE,
						encodeCustomMessage(BeignetCustomSubtype.GUARDIAN_REQUEST, frame)
					);
				}
			} catch (error) {
				clearTimeout(timer);
				this.pending.delete(requestId);
				reject(
					error instanceof GuardianTransportError
						? error
						: new GuardianTransportError(String(error))
				);
			}
		});
	}

	close(): void {
		this.closed = true;
		const peer = this.peer;
		this.peer = null;
		if (peer) peer.disconnect();
		this.failAll(new GuardianTransportError('bolt8 guardian session closed'));
	}

	private newAssembler(): GuardianBolt8Assembler {
		return new GuardianBolt8Assembler({
			kind: 'response',
			maxBodyBytes: (requestId): number =>
				this.pending.get(requestId)?.maxResponseBytes ?? 0,
			maxInFlight: this.options.maxInFlight,
			clock: this.clock
		});
	}

	private allocateRequestId(): number {
		for (;;) {
			const id = this.nextRequestId;
			this.nextRequestId = id >= 0xffffffff ? 1 : id + 1;
			if (!this.pending.has(id)) return id;
		}
	}

	private failAll(error: Error): void {
		for (const [, entry] of this.pending) {
			clearTimeout(entry.timer);
			entry.reject(error);
		}
		this.pending.clear();
		this.assembler.clear();
	}

	private ensureConnected(timeoutMs: number): Promise<Peer> {
		if (this.peer && this.peer.getState() === 'ready') {
			return Promise.resolve(this.peer);
		}
		if (this.connecting) return this.connecting;
		const now = this.clock();
		if (now < this.nextAttemptAt) {
			return Promise.reject(
				new GuardianTransportError(
					`bolt8 guardian session backing off for ` +
						`${this.nextAttemptAt - now}ms after ${this.failures} failed dials`
				)
			);
		}
		this.connecting = this.dial(timeoutMs).finally(() => {
			this.connecting = null;
		});
		return this.connecting;
	}

	private async dial(timeoutMs: number): Promise<Peer> {
		const peer = new Peer({
			localPrivateKey: this.options.localPrivateKey ?? freshPrivateKey(),
			remotePublicKey: this.target.nodeId,
			host: this.target.host,
			port: this.target.port,
			createSocket: this.options.createSocket,
			connectTimeout: Math.min(
				this.options.connectTimeoutMs ?? 15_000,
				timeoutMs
			),
			handshakeTimeout: Math.min(
				this.options.handshakeTimeoutMs ?? 30_000,
				timeoutMs
			)
		});
		peer.on('message', (type: number, payload: Buffer) => {
			this.onMessage(peer, type, payload);
		});
		peer.on('error', () => {
			// A close follows every transport error; pending requests are
			// failed there, once.
		});
		peer.on('close', () => {
			if (this.peer === peer) this.peer = null;
			this.failAll(
				new GuardianTransportError('bolt8 guardian session dropped')
			);
		});
		try {
			await peer.connect();
		} catch (error) {
			this.failures++;
			const min = this.options.reconnectMinMs ?? 1_000;
			const max = this.options.reconnectMaxMs ?? 60_000;
			this.nextAttemptAt =
				this.clock() +
				Math.min(max, min * 2 ** Math.min(this.failures - 1, 16));
			throw new GuardianTransportError(
				`bolt8 guardian dial to ${this.target.url} failed: ${
					error instanceof Error ? error.message : String(error)
				}`
			);
		}
		if (this.closed) {
			peer.disconnect();
			throw new GuardianTransportError('bolt8 guardian session is closed');
		}
		this.failures = 0;
		this.nextAttemptAt = 0;
		this.peer = peer;
		this.assembler = this.newAssembler();
		return peer;
	}

	private onMessage(peer: Peer, type: number, payload: Buffer): void {
		if (type !== BEIGNET_CUSTOM_MESSAGE_TYPE) return;
		let subtype: number;
		let frame: Buffer;
		try {
			const envelope = decodeCustomMessage(payload);
			subtype = envelope.subtype;
			frame = envelope.payload;
		} catch {
			return;
		}
		if (subtype !== BeignetCustomSubtype.GUARDIAN_RESPONSE) return;
		let result: GuardianBolt8Assembly<
			IGuardianBolt8Request | IGuardianBolt8Response
		>;
		try {
			result = this.assembler.push(frame);
		} catch (error) {
			// The guardian violated framing; the session is not trustworthy.
			peer.disconnect();
			this.failAll(
				new GuardianTransportError(
					`bolt8 guardian framing violation: ${
						error instanceof Error ? error.message : String(error)
					}`
				)
			);
			return;
		}
		if (result === null) return;
		if (result.kind === 'too-large') {
			const entry = this.pending.get(result.requestId);
			if (!entry) return;
			clearTimeout(entry.timer);
			this.pending.delete(result.requestId);
			entry.reject(
				new GuardianTransportError('guardian response exceeds size cap')
			);
			return;
		}
		const response = result.message as IGuardianBolt8Response;
		const entry = this.pending.get(response.requestId);
		if (!entry) return;
		clearTimeout(entry.timer);
		this.pending.delete(response.requestId);
		entry.resolve({ status: response.status, body: response.body });
	}
}

// ─────────────── transport factory (what assembly.ts injects) ───────────────

export interface IBolt8GuardianTransportOptions {
	createSocket?: (host: string, port: number) => Promise<IDuplexTransport>;
	session?: Omit<IBolt8GuardianSessionOptions, 'target' | 'createSocket'>;
}

export interface IBolt8GuardianTransport extends GuardianHttpTransport {
	/** Close every session this transport opened. */
	close(): void;
	/** Open sessions, by canonical guardian URL. */
	sessions(): Map<string, Bolt8GuardianSession>;
}

/**
 * A GuardianHttpTransport over bolt8 sessions, one persistent session per
 * guardian URL. GuardianClient composes `${base}${GUARDIAN_HTTP_BASE_PATH}/<verb>`
 * for every exchange, so the verb is read back off the path here and the
 * base is the session address; the Authorization header, when the client
 * set one, rides verbatim as the request auth bytes.
 */
export function bolt8GuardianTransport(
	options: IBolt8GuardianTransportOptions = {}
): IBolt8GuardianTransport {
	const sessions = new Map<string, Bolt8GuardianSession>();
	const transport = (async (
		url: string,
		init: {
			method: 'GET' | 'POST';
			headers: Record<string, string>;
			body?: Buffer;
			timeoutMs: number;
			maxResponseBytes: number;
		}
	): Promise<{ status: number; body: Buffer }> => {
		const at = url.indexOf(`${GUARDIAN_HTTP_BASE_PATH}/`);
		if (at < 0) {
			throw new GuardianTransportError(
				`bolt8 guardian URL "${url}" carries no verb path`
			);
		}
		const verbName = url.slice(at + GUARDIAN_HTTP_BASE_PATH.length + 1);
		const verb = guardianBolt8VerbCode(verbName);
		if (verb === null) {
			throw new GuardianTransportError(`unknown guardian verb "${verbName}"`);
		}
		if ((verbName === 'info') !== (init.method === 'GET')) {
			throw new GuardianTransportError(
				`guardian verb ${verbName} does not take ${init.method}`
			);
		}
		let target: IBolt8GuardianTarget;
		try {
			target = parseBolt8GuardianUrl(url.slice(0, at));
		} catch (error) {
			throw new GuardianTransportError(
				error instanceof Error ? error.message : String(error)
			);
		}
		let session = sessions.get(target.url);
		if (!session) {
			session = new Bolt8GuardianSession({
				...options.session,
				target,
				createSocket: options.createSocket
			});
			sessions.set(target.url, session);
		}
		const authHeader = init.headers.Authorization;
		return session.request(verb, init.body ?? Buffer.alloc(0), {
			auth:
				authHeader !== undefined ? Buffer.from(authHeader, 'utf8') : undefined,
			timeoutMs: init.timeoutMs,
			maxResponseBytes: init.maxResponseBytes
		});
	}) as IBolt8GuardianTransport;
	transport.close = (): void => {
		for (const session of sessions.values()) session.close();
		sessions.clear();
	};
	transport.sessions = (): Map<string, Bolt8GuardianSession> => sessions;
	return transport;
}
