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

/** A Tor v3 onion service hostname: 56 base32 characters plus .onion. */
const ONION_V3_HOSTNAME = /^[a-z2-7]{56}\.onion$/;

/** Strictly loopback; container hostnames need explicit approval. */
export function isLoopbackHostname(hostname: string): boolean {
	return hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]';
}

export interface IGuardianEndpointOptions {
	torEnabled: boolean;
	/** Permits local-http to LOOPBACK hosts only. */
	allowLocalHttp?: boolean;
	/**
	 * Approves specific NON-loopback local-http hostnames, for deployments
	 * where an orchestrator genuinely guarantees network isolation (the
	 * Umbrel container case). Providing this also enables loopback. A plain
	 * boolean cannot express this safely: bearer and macaroon credentials
	 * ride the Authorization header, so a stale or hostile descriptor
	 * naming a clearnet http URL would otherwise receive them in plaintext.
	 */
	allowLocalHttpHost?: (hostname: string) => boolean;
}

/**
 * Selection rule: Tor enabled means the first onion-http endpoint (falling
 * back to https when the guardian advertises no onion one); otherwise the
 * first https endpoint; local-http only when explicitly configured, and
 * then only to loopback or individually approved isolated-network hosts
 * (wire 2.3: a general LAN or clearnet address never qualifies). A
 * descriptor with no usable transport is an error surfaced to the operator,
 * never a silent skip.
 */
export function selectGuardianEndpoint(
	descriptor: GuardianDescriptor,
	options: IGuardianEndpointOptions
): IGuardianEndpointSelection {
	const localEnabled =
		options.allowLocalHttp === true || options.allowLocalHttpHost !== undefined;
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
			if (type === 'local-http') {
				if (parsed.protocol !== 'http:') continue;
				const approved =
					isLoopbackHostname(parsed.hostname) ||
					options.allowLocalHttpHost?.(parsed.hostname) === true;
				if (!approved) continue;
			}
			if (
				type === 'onion-http' &&
				(parsed.protocol !== 'http:' ||
					!ONION_V3_HOSTNAME.test(parsed.hostname))
			) {
				continue;
			}
			return { url: transport.url, transportType: type };
		}
		return null;
	};
	const order: Array<'onion-http' | 'https' | 'local-http'> = options.torEnabled
		? ['onion-http', 'https']
		: ['https'];
	if (localEnabled) order.push('local-http');
	for (const type of order) {
		const selected = usable(type);
		if (selected) return selected;
	}
	throw new GuardianTransportError(
		`guardian ${descriptor.guardianId} advertises no usable transport ` +
			`(torEnabled=${options.torEnabled}, localHttp=${localEnabled})`
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
	/**
	 * Permit a bearer or macaroon credential over plain http to a
	 * NON-loopback, non-onion host. Off by default: that is a plaintext
	 * credential on the wire, defensible only where an orchestrator
	 * guarantees network isolation (the local-http container case).
	 */
	allowUnencryptedAuth?: boolean;
}

export class GuardianClient {
	readonly url: string;
	private readonly guardianSetId: Buffer;
	private readonly transport: GuardianHttpTransport;
	private readonly headers: Record<string, string>;
	private readonly timeoutMs: number;
	private readonly maxResponseBytes: number;
	private versionGate: Promise<IGuardianInfoResponse> | null = null;

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
		if (this.headers.Authorization && !options.allowUnencryptedAuth) {
			const parsed = new URL(this.url);
			if (
				parsed.protocol === 'http:' &&
				!isLoopbackHostname(parsed.hostname) &&
				!parsed.hostname.endsWith('.onion')
			) {
				throw new GuardianTransportError(
					'refusing to send a bearer or macaroon credential over plaintext ' +
						'HTTP to a non-local host; set allowUnencryptedAuth only for an ' +
						'isolated container network'
				);
			}
		}
	}

	/**
	 * The advertised-range gate (wire 10), enforced rather than advisory:
	 * every verb awaits one cached INFO exchange before sending anything, so
	 * a guardian outside the supported protocol range is rejected without
	 * ever receiving signed material. A failed probe clears the cache so a
	 * transient outage does not wedge the client.
	 */
	private ensureCompatible(): Promise<IGuardianInfoResponse> {
		if (!this.versionGate) {
			this.versionGate = (async (): Promise<IGuardianInfoResponse> => {
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
			})().catch((error) => {
				this.versionGate = null;
				throw error;
			});
		}
		return this.versionGate;
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

	/** The public face of the gate; shares its cache with every verb. */
	async checkVersion(): Promise<IGuardianInfoResponse> {
		return this.ensureCompatible();
	}

	async register(
		request: IGuardianRegisterNodeRequest
	): Promise<IGuardianRegisterNodeResponse> {
		await this.ensureCompatible();
		return decodeRegisterNodeResponse(
			await this.exchange('register_node', encodeRegisterNodeRequest(request))
		);
	}

	async putState(record: IGuardianRecord): Promise<IGuardianPutStateResponse> {
		await this.ensureCompatible();
		return decodePutStateResponse(
			await this.exchange('put_state', encodePutStateRequest({ record }))
		);
	}

	async getHead(recoveryId: Buffer): Promise<IGuardianGetHeadResponse> {
		await this.ensureCompatible();
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
		await this.ensureCompatible();
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
		await this.ensureCompatible();
		return decodeAcquireEpochResponse(
			await this.exchange('acquire_epoch', encodeAcquireEpochRequest(request))
		);
	}

	async syncRecord(
		record: IGuardianRecord
	): Promise<IGuardianSyncRecordResponse> {
		await this.ensureCompatible();
		return decodeSyncRecordResponse(
			await this.exchange('sync_record', encodeSyncRecordRequest({ record }))
		);
	}

	async syncEpoch(
		certificates: IGuardianTakeoverCertificate[]
	): Promise<IGuardianSyncEpochResponse> {
		await this.ensureCompatible();
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
