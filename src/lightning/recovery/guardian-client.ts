/**
 * Guardian client (wire spec sections 2, 9, 10): endpoint selection over a
 * capsule GuardianDescriptor, the HTTP verb mapping with per-verb protobuf
 * envelopes, recoverable transport credentials, version gating against
 * InfoResponse, and the quorum fan-out primitives the recovery flows build
 * on.
 *
 * The transport is injectable: the default reaches http and https URLs
 * through node's own modules, while onion-http endpoints need a Tor-capable
 * transport (a SOCKS proxy or an embedded Tor) supplied by the caller. The
 * client never weakens verification based on transport: receipts and
 * certificates are checked against the guardian set, not the connection.
 */

import { request as httpRequest } from 'http';
import { request as httpsRequest } from 'https';
import {
	GUARDIAN_PROTOCOL_VERSION,
	GuardianState,
	receiptTranscriptHash,
	takeoverTranscriptHash,
	verifyTranscript
} from './guardian-wire';
import {
	IGuardianAcquireEpochRequest,
	IGuardianAcquireEpochResponse,
	IGuardianGetHeadResponse,
	IGuardianGetStateResponse,
	IGuardianInfoResponse,
	IGuardianPutStateResponse,
	IGuardianReceipt,
	IGuardianRecord,
	IGuardianRegisterNodeRequest,
	IGuardianRegisterNodeResponse,
	IGuardianSyncEpochResponse,
	IGuardianSyncRecordResponse,
	IGuardianTakeoverCertificate
} from './guardian';
import {
	GUARDIAN_CONTENT_TYPE,
	GUARDIAN_HTTP_BASE_PATH,
	decodeAcquireEpochResponse,
	decodeGetHeadResponse,
	decodeGetStateResponse,
	decodeInfoResponse,
	decodePutStateResponse,
	decodeRegisterNodeResponse,
	decodeSyncEpochResponse,
	decodeSyncRecordResponse,
	encodeAcquireEpochRequest,
	encodeGetHeadRequest,
	encodeGetStateRequest,
	encodePutStateRequest,
	encodeRegisterNodeRequest,
	encodeSyncEpochRequest,
	encodeSyncRecordRequest
} from './guardian-proto';
import { GuardianAuth, GuardianDescriptor } from './capsule';

export { GuardianAuth } from './capsule';

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

/** The HTTP layer failed (non-200); distinct from protocol-level statuses. */
export class GuardianTransportError extends Error {
	readonly httpStatus?: number;

	constructor(message: string, httpStatus?: number) {
		super(message);
		this.name = 'GuardianTransportError';
		this.httpStatus = httpStatus;
	}
}

/** Minimal binary HTTP transport, injectable for Tor and for tests. */
export type GuardianHttpTransport = (
	url: string,
	init: {
		method: 'GET' | 'POST';
		headers: Record<string, string>;
		body?: Buffer;
		timeoutMs: number;
		maxResponseBytes: number;
	}
) => Promise<{ status: number; body: Buffer }>;

/** Default transport over node http/https; refuses other schemes. */
export function nodeGuardianTransport(): GuardianHttpTransport {
	return (url, init): Promise<{ status: number; body: Buffer }> =>
		new Promise((resolve, reject) => {
			const parsed = new URL(url);
			const requestFn =
				parsed.protocol === 'https:'
					? httpsRequest
					: parsed.protocol === 'http:'
					? httpRequest
					: null;
			if (!requestFn) {
				reject(
					new GuardianTransportError(
						`unsupported URL scheme ${parsed.protocol}`
					)
				);
				return;
			}
			const request = requestFn(
				parsed,
				{ method: init.method, headers: init.headers },
				(response) => {
					const chunks: Buffer[] = [];
					let total = 0;
					response.on('data', (chunk: Buffer) => {
						total += chunk.length;
						if (total > init.maxResponseBytes) {
							request.destroy();
							reject(
								new GuardianTransportError('guardian response exceeds size cap')
							);
							return;
						}
						chunks.push(chunk);
					});
					response.on('end', () => {
						resolve({
							status: response.statusCode ?? 0,
							body: Buffer.concat(chunks)
						});
					});
					response.on('error', reject);
				}
			);
			request.setTimeout(init.timeoutMs, () => {
				request.destroy(
					new GuardianTransportError('guardian request timed out')
				);
			});
			request.on('error', (error) =>
				reject(
					error instanceof GuardianTransportError
						? error
						: new GuardianTransportError(String(error))
				)
			);
			if (init.body) request.write(init.body);
			request.end();
		});
}

// ─────────────── endpoint selection (wire 2.4) ───────────────

export interface IGuardianEndpointSelection {
	url: string;
	transportType: 'onion-http' | 'https' | 'local-http';
}

/**
 * Selection rule: Tor enabled means the first onion-http endpoint (falling
 * back to https when the guardian advertises no onion one); otherwise the
 * first https endpoint; local-http only when explicitly allowed. A
 * descriptor with no usable transport is an error surfaced to the operator,
 * never a silent skip.
 */
export function selectGuardianEndpoint(
	descriptor: GuardianDescriptor,
	options: { torEnabled: boolean; allowLocalHttp?: boolean }
): IGuardianEndpointSelection {
	const usable = (
		type: 'onion-http' | 'https' | 'local-http'
	): IGuardianEndpointSelection | null => {
		for (const transport of descriptor.transports) {
			if (transport.type !== type) continue;
			let parsed: URL;
			try {
				parsed = new URL(transport.url);
			} catch {
				continue;
			}
			if (type === 'https' && parsed.protocol !== 'https:') continue;
			if (type === 'local-http' && parsed.protocol !== 'http:') continue;
			if (type === 'onion-http' && !parsed.hostname.endsWith('.onion'))
				continue;
			return { url: transport.url, transportType: type };
		}
		return null;
	};
	const order: Array<'onion-http' | 'https' | 'local-http'> = options.torEnabled
		? ['onion-http', 'https']
		: ['https'];
	if (options.allowLocalHttp) order.push('local-http');
	for (const type of order) {
		const selected = usable(type);
		if (selected) return selected;
	}
	throw new GuardianTransportError(
		`guardian ${descriptor.guardianId} advertises no usable transport ` +
			`(torEnabled=${options.torEnabled}, allowLocalHttp=${Boolean(
				options.allowLocalHttp
			)})`
	);
}

// ─────────────── the client ───────────────

export interface IGuardianClientOptions {
	/** Base URL of the guardian, e.g. https://host or http://127.0.0.1:8080. */
	url: string;
	/** Every request of this client carries this set id. */
	guardianSetId: Buffer;
	/**
	 * Transport credential (wire 9). bearer and macaroon ride the
	 * Authorization header; tor-v3-client-auth lives at the Tor layer and is
	 * consumed by the injected transport, not by HTTP headers.
	 */
	auth?: GuardianAuth;
	transport?: GuardianHttpTransport;
	timeoutMs?: number;
	maxResponseBytes?: number;
}

export class GuardianClient {
	readonly url: string;
	private readonly guardianSetId: Buffer;
	private readonly transport: GuardianHttpTransport;
	private readonly headers: Record<string, string>;
	private readonly timeoutMs: number;
	private readonly maxResponseBytes: number;

	constructor(options: IGuardianClientOptions) {
		this.url = options.url.replace(/\/+$/, '');
		this.guardianSetId = Buffer.from(options.guardianSetId);
		this.transport = options.transport ?? nodeGuardianTransport();
		this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		this.maxResponseBytes =
			options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
		this.headers = {};
		if (options.auth?.type === 'bearer') {
			this.headers.Authorization = `Bearer ${options.auth.token}`;
		} else if (options.auth?.type === 'macaroon') {
			this.headers.Authorization = `Macaroon ${options.auth.macaroon}`;
		}
	}

	private async exchange(verb: string | null, body?: Buffer): Promise<Buffer> {
		const url =
			verb === null
				? `${this.url}${GUARDIAN_HTTP_BASE_PATH}/info`
				: `${this.url}${GUARDIAN_HTTP_BASE_PATH}/${verb}`;
		const response = await this.transport(url, {
			method: verb === null ? 'GET' : 'POST',
			headers:
				verb === null
					? { ...this.headers }
					: { ...this.headers, 'Content-Type': GUARDIAN_CONTENT_TYPE },
			body,
			timeoutMs: this.timeoutMs,
			maxResponseBytes: this.maxResponseBytes
		});
		if (response.status !== 200) {
			throw new GuardianTransportError(
				`guardian answered HTTP ${response.status}`,
				response.status
			);
		}
		return response.body;
	}

	async info(): Promise<IGuardianInfoResponse> {
		return decodeInfoResponse(await this.exchange(null));
	}

	/**
	 * Version gating (wire 10): reject a guardian whose advertised range
	 * excludes this protocol version before sending it anything signed.
	 */
	async checkVersion(): Promise<IGuardianInfoResponse> {
		const info = await this.info();
		if (
			info.minProtocolVersion > GUARDIAN_PROTOCOL_VERSION ||
			info.maxProtocolVersion < GUARDIAN_PROTOCOL_VERSION
		) {
			throw new GuardianTransportError(
				`guardian supports protocol ${info.minProtocolVersion}..` +
					`${info.maxProtocolVersion}, not ${GUARDIAN_PROTOCOL_VERSION}`
			);
		}
		return info;
	}

	async register(
		request: IGuardianRegisterNodeRequest
	): Promise<IGuardianRegisterNodeResponse> {
		return decodeRegisterNodeResponse(
			await this.exchange('register_node', encodeRegisterNodeRequest(request))
		);
	}

	async putState(record: IGuardianRecord): Promise<IGuardianPutStateResponse> {
		return decodePutStateResponse(
			await this.exchange('put_state', encodePutStateRequest({ record }))
		);
	}

	async getHead(recoveryId: Buffer): Promise<IGuardianGetHeadResponse> {
		return decodeGetHeadResponse(
			await this.exchange(
				'get_head',
				encodeGetHeadRequest({
					protocolVersion: GUARDIAN_PROTOCOL_VERSION,
					guardianSetId: this.guardianSetId,
					recoveryId
				})
			)
		);
	}

	async getState(
		recoveryId: Buffer,
		fromSequence: bigint,
		maxRecords = 0
	): Promise<IGuardianGetStateResponse> {
		return decodeGetStateResponse(
			await this.exchange(
				'get_state',
				encodeGetStateRequest({
					protocolVersion: GUARDIAN_PROTOCOL_VERSION,
					guardianSetId: this.guardianSetId,
					recoveryId,
					fromSequence,
					maxRecords
				})
			)
		);
	}

	async acquireEpoch(
		request: IGuardianAcquireEpochRequest
	): Promise<IGuardianAcquireEpochResponse> {
		return decodeAcquireEpochResponse(
			await this.exchange('acquire_epoch', encodeAcquireEpochRequest(request))
		);
	}

	async syncRecord(
		record: IGuardianRecord
	): Promise<IGuardianSyncRecordResponse> {
		return decodeSyncRecordResponse(
			await this.exchange('sync_record', encodeSyncRecordRequest({ record }))
		);
	}

	async syncEpoch(
		certificates: IGuardianTakeoverCertificate[]
	): Promise<IGuardianSyncEpochResponse> {
		return decodeSyncEpochResponse(
			await this.exchange(
				'sync_epoch',
				encodeSyncEpochRequest({ certificates })
			)
		);
	}
}

// ─────────────── client-side artifact verification ───────────────

export interface IGuardianSetContext {
	guardianSetId: Buffer;
	/** The committed member keys (32-byte x-only each). */
	members: Buffer[];
}

/** A receipt is valid evidence only under the committed set and a member key. */
export function verifyGuardianReceipt(
	receipt: IGuardianReceipt,
	context: IGuardianSetContext
): boolean {
	try {
		if (receipt.protocolVersion !== GUARDIAN_PROTOCOL_VERSION) return false;
		if (!receipt.guardianSetId.equals(context.guardianSetId)) return false;
		if (!context.members.some((m) => m.equals(receipt.guardianId)))
			return false;
		return verifyTranscript(
			receiptTranscriptHash(
				receipt.guardianSetId,
				receipt.guardianId,
				receipt.state,
				receipt.issuedAt
			),
			receipt.signature,
			receipt.guardianId
		);
	} catch {
		return false;
	}
}

export function verifyGuardianCertificate(
	cert: IGuardianTakeoverCertificate,
	context: IGuardianSetContext
): boolean {
	try {
		if (cert.protocolVersion !== GUARDIAN_PROTOCOL_VERSION) return false;
		if (!cert.guardianSetId.equals(context.guardianSetId)) return false;
		if (!context.members.some((m) => m.equals(cert.guardianId))) return false;
		return verifyTranscript(
			takeoverTranscriptHash(
				cert.guardianSetId,
				cert.guardianId,
				cert.supersededState,
				cert.newEpoch,
				cert.newWriterPublicKey,
				cert.issuedAt
			),
			cert.signature,
			cert.guardianId
		);
	} catch {
		return false;
	}
}

// ─────────────── quorum fan-out primitives ───────────────

export interface IGuardianFanOutResult<T> {
	client: GuardianClient;
	result?: T;
	error?: Error;
}

/**
 * Run one operation against every guardian concurrently and settle all of
 * them: partial failure is the normal case a 2-of-3 deployment exists for,
 * so errors are collected, never thrown.
 */
export async function guardianFanOut<T>(
	clients: GuardianClient[],
	operation: (client: GuardianClient) => Promise<T>
): Promise<Array<IGuardianFanOutResult<T>>> {
	return Promise.all(
		clients.map(async (client) => {
			try {
				return { client, result: await operation(client) };
			} catch (error) {
				return {
					client,
					error: error instanceof Error ? error : new Error(String(error))
				};
			}
		})
	);
}

/**
 * Count DISTINCT verified receipt signers over an exact state: the barrier
 * discipline (spec 5.3) counts a record durable once `required` distinct
 * guardians have receipted a state at or past it.
 */
export function countReceiptQuorum(
	results: Array<IGuardianFanOutResult<{ receipt?: IGuardianReceipt }>>,
	context: IGuardianSetContext,
	covers: (receiptState: GuardianState) => boolean
): number {
	const signers = new Set<string>();
	for (const entry of results) {
		const receipt = entry.result?.receipt;
		if (!receipt) continue;
		if (!verifyGuardianReceipt(receipt, context)) continue;
		if (!covers(receipt.state)) continue;
		signers.add(receipt.guardianId.toString('hex'));
	}
	return signers.size;
}
