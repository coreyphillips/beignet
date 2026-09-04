/**
 * HTTP transport for the reference guardian (wire spec 2.5): every verb is
 * POST {base}/<verb-lowercase> with a protobuf body, discovery is GET
 * {base}/info, and HTTP status is 200 for every well-formed protocol
 * exchange INCLUDING protocol-level rejections; the protocol result lives in
 * the body's status field. Non-200 means the HTTP layer itself failed: 404
 * wrong path, 401 missing or invalid transport credential, 413 body over the
 * advertised limit, 5xx guardian down.
 *
 * The same listener serves all three transport profiles: bind it to
 * 127.0.0.1 and publish through a Tor HiddenServicePort for onion-http, put
 * it behind a TLS terminator for https, or use it directly for local-http
 * (loopback, a Unix socket, or an isolated container network). Transport
 * authentication (wire 9) is a hook: it is anti-DoS and privacy hardening
 * and never participates in record acceptance.
 */

import { IncomingMessage, Server, ServerResponse, createServer } from 'http';
import { timingSafeEqual } from 'crypto';
import { GuardianStatus, ReferenceGuardian } from './guardian';
import {
	GUARDIAN_CONTENT_TYPE,
	GUARDIAN_HTTP_BASE_PATH,
	decodeAcquireEpochRequest,
	decodeGetHeadRequest,
	decodeGetStateRequest,
	decodePutStateRequest,
	decodeRegisterNodeRequest,
	decodeSyncEpochRequest,
	decodeSyncRecordRequest,
	encodeAcquireEpochResponse,
	encodeGetHeadResponse,
	encodeGetStateResponse,
	encodeInfoResponse,
	encodePutStateResponse,
	encodeRegisterNodeResponse,
	encodeSyncEpochResponse,
	encodeSyncRecordResponse
} from './guardian-proto';

/** Request body allowance: the ciphertext cap plus a 4 KiB envelope (wire 8). */
export const GUARDIAN_ENVELOPE_ALLOWANCE_BYTES = 4096;

/** The signed verbs, by their wire-spec lowercase names (wire 2.5). */
export type GuardianVerbName =
	| 'register_node'
	| 'put_state'
	| 'get_head'
	| 'get_state'
	| 'acquire_epoch'
	| 'sync_record'
	| 'sync_epoch';

export const GUARDIAN_VERB_NAMES: readonly GuardianVerbName[] = Object.freeze([
	'register_node',
	'put_state',
	'get_head',
	'get_state',
	'acquire_epoch',
	'sync_record',
	'sync_epoch'
]);

export function isGuardianVerbName(verb: string): verb is GuardianVerbName {
	return (GUARDIAN_VERB_NAMES as readonly string[]).includes(verb);
}

// Each verb pairs its decoder, its core handler, and its encoder; a body
// that fails to decode is a protocol-level ERR_MALFORMED inside a successful
// exchange, exactly like any other protocol rejection (wire 2.5, section 7).
const VERB_HANDLERS: Record<
	GuardianVerbName,
	(guardian: ReferenceGuardian, body: Buffer) => Buffer
> = {
	register_node: (guardian, body) =>
		encodeRegisterNodeResponse(
			guardian.register(decodeRegisterNodeRequest(body))
		),
	put_state: (guardian, body) =>
		encodePutStateResponse(guardian.putState(decodePutStateRequest(body))),
	get_head: (guardian, body) =>
		encodeGetHeadResponse(guardian.getHead(decodeGetHeadRequest(body))),
	get_state: (guardian, body) =>
		encodeGetStateResponse(guardian.getState(decodeGetStateRequest(body))),
	acquire_epoch: (guardian, body) =>
		encodeAcquireEpochResponse(
			guardian.acquireEpoch(decodeAcquireEpochRequest(body))
		),
	sync_record: (guardian, body) =>
		encodeSyncRecordResponse(
			guardian.syncRecord(decodeSyncRecordRequest(body))
		),
	sync_epoch: (guardian, body) =>
		encodeSyncEpochResponse(guardian.syncEpoch(decodeSyncEpochRequest(body)))
};

const MALFORMED_FOR: Record<GuardianVerbName, (detail: string) => Buffer> = {
	register_node: (detail) =>
		encodeRegisterNodeResponse({
			status: GuardianStatus.ERR_MALFORMED,
			detail
		}),
	put_state: (detail) =>
		encodePutStateResponse({ status: GuardianStatus.ERR_MALFORMED, detail }),
	get_head: (detail) =>
		encodeGetHeadResponse({ status: GuardianStatus.ERR_MALFORMED, detail }),
	get_state: (detail) =>
		encodeGetStateResponse({ status: GuardianStatus.ERR_MALFORMED, detail }),
	acquire_epoch: (detail) =>
		encodeAcquireEpochResponse({
			status: GuardianStatus.ERR_MALFORMED,
			detail
		}),
	sync_record: (detail) =>
		encodeSyncRecordResponse({ status: GuardianStatus.ERR_MALFORMED, detail }),
	sync_epoch: (detail) =>
		encodeSyncEpochResponse({ status: GuardianStatus.ERR_MALFORMED, detail })
};

/**
 * Run one signed verb against the guardian and encode its protocol answer.
 * Transport-neutral on purpose: the HTTP listener below and the bolt8
 * session responder (guardian-bolt8.ts) both call this, so the two
 * transports cannot drift in what a verb means. The core never throws for
 * protocol conditions; an exception here means the BODY failed to decode
 * as protobuf, which is answered as ERR_MALFORMED in the verb's own
 * response shape.
 */
export function dispatchGuardianVerb(
	guardian: ReferenceGuardian,
	verb: GuardianVerbName,
	body: Buffer
): Buffer {
	try {
		return VERB_HANDLERS[verb](guardian, body);
	} catch {
		return MALFORMED_FOR[verb]('undecodable request body');
	}
}

/** The discovery answer (wire 5.8), encoded. */
export function encodeGuardianInfo(guardian: ReferenceGuardian): Buffer {
	return encodeInfoResponse(guardian.info());
}

export interface IGuardianHttpOptions {
	guardian: ReferenceGuardian;
	/**
	 * Transport credential check; MANDATORY for every non-local deployment
	 * (wire 9). Returning false answers 401 before any body is read. Absent
	 * means running open, reserved for local development and local-http.
	 */
	authenticate?: (request: IncomingMessage) => boolean;
	/** Defaults to the guardian's advertised ciphertext limit plus envelope. */
	maxBodyBytes?: number;
}

/** Constant-time bearer-token authenticator for the Authorization header. */
export function bearerAuthenticator(
	token: string
): (request: IncomingMessage) => boolean {
	const expected = Buffer.from(`Bearer ${token}`, 'utf8');
	return (request): boolean => {
		const header = request.headers.authorization;
		if (typeof header !== 'string') return false;
		const presented = Buffer.from(header, 'utf8');
		if (presented.length !== expected.length) return false;
		return timingSafeEqual(presented, expected);
	};
}

function readBodyCapped(
	request: IncomingMessage,
	maxBytes: number
): Promise<Buffer | null> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		let total = 0;
		let settled = false;
		request.on('data', (chunk: Buffer) => {
			if (settled) return;
			total += chunk.length;
			if (total > maxBytes) {
				settled = true;
				resolve(null);
				return;
			}
			chunks.push(chunk);
		});
		request.on('end', () => {
			if (settled) return;
			settled = true;
			resolve(Buffer.concat(chunks));
		});
		request.on('error', (error) => {
			if (settled) return;
			settled = true;
			reject(error);
		});
	});
}

function respond(
	response: ServerResponse,
	httpStatus: number,
	body?: Buffer
): void {
	if (body) {
		response.writeHead(httpStatus, {
			'Content-Type': GUARDIAN_CONTENT_TYPE,
			'Content-Length': body.length
		});
		response.end(body);
	} else {
		response.writeHead(httpStatus);
		response.end();
	}
}

/**
 * Build the request listener. Exposed separately from the server wrapper so
 * a deployment can mount it on an existing HTTP server or a Unix socket.
 */
export function createGuardianRequestListener(
	options: IGuardianHttpOptions
): (request: IncomingMessage, response: ServerResponse) => void {
	const guardian = options.guardian;
	const maxBodyBytes =
		options.maxBodyBytes ??
		guardian.info().maxCiphertextBytes + GUARDIAN_ENVELOPE_ALLOWANCE_BYTES;

	return (request, response): void => {
		void (async (): Promise<void> => {
			if (options.authenticate && !options.authenticate(request)) {
				respond(response, 401);
				// Drain whatever body arrives so the connection can settle
				// without buffering it; never destroy before the 401 flushes.
				request.resume();
				return;
			}
			const url = request.url ?? '';
			const path = url.split('?')[0];
			if (request.method === 'GET') {
				if (path === `${GUARDIAN_HTTP_BASE_PATH}/info`) {
					respond(response, 200, encodeGuardianInfo(guardian));
				} else {
					respond(response, 404);
				}
				return;
			}
			if (request.method !== 'POST') {
				respond(response, 404);
				return;
			}
			if (!path.startsWith(`${GUARDIAN_HTTP_BASE_PATH}/`)) {
				respond(response, 404);
				return;
			}
			const verb = path.slice(GUARDIAN_HTTP_BASE_PATH.length + 1);
			if (!isGuardianVerbName(verb)) {
				respond(response, 404);
				return;
			}
			const body = await readBodyCapped(request, maxBodyBytes);
			if (body === null) {
				// Stop the oversized upload, but only after the 413 has flushed;
				// destroying first races the client out of ever seeing it.
				response.once('finish', () => request.destroy());
				respond(response, 413);
				return;
			}
			respond(response, 200, dispatchGuardianVerb(guardian, verb, body));
		})().catch(() => {
			try {
				respond(response, 500);
			} catch {
				response.destroy();
			}
		});
	};
}

/** A minimal standalone server around the listener; binds loopback by default. */
export class GuardianHttpServer {
	readonly server: Server;

	constructor(options: IGuardianHttpOptions) {
		this.server = createServer(createGuardianRequestListener(options));
	}

	/** Resolves with the actual bound port (pass 0 for an ephemeral one). */
	listen(port: number, host = '127.0.0.1'): Promise<number> {
		return new Promise((resolve, reject) => {
			this.server.once('error', reject);
			this.server.listen(port, host, () => {
				const address = this.server.address();
				if (address === null || typeof address === 'string') {
					reject(new Error('guardian server bound no TCP address'));
					return;
				}
				resolve(address.port);
			});
		});
	}

	close(): Promise<void> {
		return new Promise((resolve, reject) => {
			this.server.close((error) => (error ? reject(error) : resolve()));
		});
	}
}
