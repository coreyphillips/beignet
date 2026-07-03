/**
 * FFOR M7.1: tower transport over BOLT-8 peer messages (spec Appendix C).
 *
 * The demo TCP/JSON + in-process loopback transport is replaced by real
 * request/response messages carried over the node's existing BOLT-8 Noise
 * connection. The tower is a known named party the client connects to
 * DIRECTLY (nodeId@host:port) — not via onion messages; onion indirection is a
 * later privacy upgrade.
 *
 * Six custom, odd (ignorable) message types in the 55031+ range, clear of the
 * 55001-55023 FFOR epoch set:
 *
 *   FF_TOWER_PROVISION      55031  R -> T
 *   FF_TOWER_ACK            55033  T -> R   (provision result)
 *   FF_TOWER_RELEASE        55035  S -> T   (raw ff_settlement payload)
 *   FF_TOWER_RELEASE_RESP   55037  T -> S   (preimage or error)
 *   FF_TOWER_FETCH          55039  R -> T   (authenticated fetch)
 *   FF_TOWER_FETCH_RESP     55041  T -> R   (packages + preimages)
 *
 * LN messages are fire-and-forget, so every REQUEST carries a 16-byte
 * request_id and the client keys a pending-promise map by it to correlate the
 * async RESPONSE (with a timeout).
 *
 * AUTH is two-layered. The Noise-authenticated sender pubkey is the
 * ACCESS-CONTROL layer: provision must come from the epoch's R, release from
 * its S, fetch from its R. The per-message node-key signatures the tower
 * already verifies (the fetch digest) remain the §12.2 non-repudiation
 * EVIDENCE layer. The two are independent.
 */

import crypto from 'crypto';
import { MessageType } from '../message/types';
import { PeerManager } from '../transport/peer-manager';
import {
	FforTower,
	IFforTowerClient,
	IFforTowerReleaseResult,
	IFforTowerFetchRequest,
	IFforTowerFetchResponse
} from './tower';
import {
	serializeTowerProvisioning,
	deserializeTowerProvisioning
} from './tower-serialization';
import { decodeFforSettlementMessage } from './messages';

export const FF_TOWER_PROVISION_TYPE = MessageType.FF_TOWER_PROVISION;
export const FF_TOWER_ACK_TYPE = MessageType.FF_TOWER_ACK;
export const FF_TOWER_RELEASE_TYPE = MessageType.FF_TOWER_RELEASE;
export const FF_TOWER_RELEASE_RESP_TYPE = MessageType.FF_TOWER_RELEASE_RESP;
export const FF_TOWER_FETCH_TYPE = MessageType.FF_TOWER_FETCH;
export const FF_TOWER_FETCH_RESP_TYPE = MessageType.FF_TOWER_FETCH_RESP;

/** The 3 response types a client must listen for. */
export const FF_TOWER_RESPONSE_TYPES = [
	FF_TOWER_ACK_TYPE,
	FF_TOWER_RELEASE_RESP_TYPE,
	FF_TOWER_FETCH_RESP_TYPE
];
/** The 3 request types a tower server must listen for. */
export const FF_TOWER_REQUEST_TYPES = [
	FF_TOWER_PROVISION_TYPE,
	FF_TOWER_RELEASE_TYPE,
	FF_TOWER_FETCH_TYPE
];

const REQUEST_ID_LEN = 16;

// ─────────────── low-level helpers ───────────────

function newRequestId(): Buffer {
	return crypto.randomBytes(REQUEST_ID_LEN);
}

function readU16Len(payload: Buffer, o: number): { s: string; next: number } {
	const len = payload.readUInt16BE(o);
	o += 2;
	const s = payload.subarray(o, o + len).toString('utf8');
	return { s, next: o + len };
}

function u16LenField(s: string): Buffer {
	const b = Buffer.from(s, 'utf8');
	const len = Buffer.alloc(2);
	len.writeUInt16BE(b.length, 0);
	return Buffer.concat([len, b]);
}

// ─────────────── FF_TOWER_PROVISION (R -> T) ───────────────

/** [16 request_id][rest: provisioning JSON (UTF-8)]. */
export function encodeTowerProvision(
	requestId: Buffer,
	provisioningJson: string
): Buffer {
	return Buffer.concat([requestId, Buffer.from(provisioningJson, 'utf8')]);
}
export function decodeTowerProvision(payload: Buffer): {
	requestId: Buffer;
	provisioningJson: string;
} {
	if (payload.length < REQUEST_ID_LEN) {
		throw new Error('ff_tower_provision too short');
	}
	return {
		requestId: payload.subarray(0, REQUEST_ID_LEN),
		provisioningJson: payload.subarray(REQUEST_ID_LEN).toString('utf8')
	};
}

// ─────────────── FF_TOWER_ACK (T -> R) ───────────────

/** [16 request_id][1 ok][2 err_len][err_len error]. */
export function encodeTowerAck(
	requestId: Buffer,
	ok: boolean,
	error = ''
): Buffer {
	return Buffer.concat([
		requestId,
		Buffer.from([ok ? 1 : 0]),
		u16LenField(error)
	]);
}
export function decodeTowerAck(payload: Buffer): {
	requestId: Buffer;
	ok: boolean;
	error: string;
} {
	if (payload.length < REQUEST_ID_LEN + 3) {
		throw new Error('ff_tower_ack too short');
	}
	const requestId = payload.subarray(0, REQUEST_ID_LEN);
	const ok = payload[REQUEST_ID_LEN] === 1;
	const { s } = readU16Len(payload, REQUEST_ID_LEN + 1);
	return { requestId, ok, error: s };
}

// ─────────────── FF_TOWER_RELEASE (S -> T) ───────────────

/** [16 request_id][rest: raw ff_settlement payload]. */
export function encodeTowerRelease(
	requestId: Buffer,
	settlementPayload: Buffer
): Buffer {
	return Buffer.concat([requestId, settlementPayload]);
}
export function decodeTowerRelease(payload: Buffer): {
	requestId: Buffer;
	settlementPayload: Buffer;
} {
	if (payload.length < REQUEST_ID_LEN) {
		throw new Error('ff_tower_release too short');
	}
	return {
		requestId: payload.subarray(0, REQUEST_ID_LEN),
		settlementPayload: payload.subarray(REQUEST_ID_LEN)
	};
}

// ─────────────── FF_TOWER_RELEASE_RESP (T -> S) ───────────────

/** [16 request_id][1 ok] then ok? [2 seq][32 preimage] : [2 err_len][error]. */
export function encodeTowerReleaseResp(
	requestId: Buffer,
	result: IFforTowerReleaseResult
): Buffer {
	if (result.ok) {
		const seq = Buffer.alloc(2);
		seq.writeUInt16BE(result.seq, 0);
		return Buffer.concat([requestId, Buffer.from([1]), seq, result.preimage]);
	}
	return Buffer.concat([
		requestId,
		Buffer.from([0]),
		u16LenField(result.error)
	]);
}
export function decodeTowerReleaseResp(payload: Buffer): {
	requestId: Buffer;
	result: IFforTowerReleaseResult;
} {
	if (payload.length < REQUEST_ID_LEN + 1) {
		throw new Error('ff_tower_release_resp too short');
	}
	const requestId = payload.subarray(0, REQUEST_ID_LEN);
	const ok = payload[REQUEST_ID_LEN] === 1;
	if (ok) {
		const seq = payload.readUInt16BE(REQUEST_ID_LEN + 1);
		const preimage = payload.subarray(REQUEST_ID_LEN + 3, REQUEST_ID_LEN + 35);
		return { requestId, result: { ok: true, seq, preimage } };
	}
	const { s } = readU16Len(payload, REQUEST_ID_LEN + 1);
	return { requestId, result: { ok: false, error: s } };
}

// ─────────────── FF_TOWER_FETCH (R -> T) ───────────────

/** [16 request_id][32 epoch_id][32 nonce][64 signature]. */
export function encodeTowerFetch(
	requestId: Buffer,
	req: IFforTowerFetchRequest
): Buffer {
	return Buffer.concat([requestId, req.epochId, req.nonce, req.signature]);
}
export function decodeTowerFetch(payload: Buffer): {
	requestId: Buffer;
	req: IFforTowerFetchRequest;
} {
	if (payload.length < REQUEST_ID_LEN + 128) {
		throw new Error('ff_tower_fetch too short');
	}
	let o = 0;
	const requestId = payload.subarray(o, (o += REQUEST_ID_LEN));
	const epochId = payload.subarray(o, (o += 32));
	const nonce = payload.subarray(o, (o += 32));
	const signature = payload.subarray(o, (o += 64));
	return { requestId, req: { epochId, nonce, signature } };
}

// ─────────────── FF_TOWER_FETCH_RESP (T -> R) ───────────────

/**
 * [16 request_id][1 ok] then ok?
 *   [4 lastReleased][2 numPackages]{[4 len][package]}*[2 numPreimages]{[32]}*
 * : [2 err_len][error].
 */
export function encodeTowerFetchResp(
	requestId: Buffer,
	resp: IFforTowerFetchResponse
): Buffer {
	if (!resp.ok) {
		return Buffer.concat([
			requestId,
			Buffer.from([0]),
			u16LenField(resp.error ?? 'fetch failed')
		]);
	}
	const parts: Buffer[] = [requestId, Buffer.from([1])];
	const head = Buffer.alloc(6);
	head.writeUInt32BE(resp.lastReleased, 0);
	head.writeUInt16BE(resp.packages.length, 4);
	parts.push(head);
	for (const pkg of resp.packages) {
		const len = Buffer.alloc(4);
		len.writeUInt32BE(pkg.length, 0);
		parts.push(len, pkg);
	}
	const pc = Buffer.alloc(2);
	pc.writeUInt16BE(resp.preimages.length, 0);
	parts.push(pc);
	for (const pre of resp.preimages) {
		parts.push(pre);
	}
	return Buffer.concat(parts);
}
export function decodeTowerFetchResp(payload: Buffer): {
	requestId: Buffer;
	resp: IFforTowerFetchResponse;
} {
	if (payload.length < REQUEST_ID_LEN + 1) {
		throw new Error('ff_tower_fetch_resp too short');
	}
	const requestId = payload.subarray(0, REQUEST_ID_LEN);
	const ok = payload[REQUEST_ID_LEN] === 1;
	if (!ok) {
		const { s } = readU16Len(payload, REQUEST_ID_LEN + 1);
		return {
			requestId,
			resp: {
				ok: false,
				error: s,
				lastReleased: 0,
				packages: [],
				preimages: []
			}
		};
	}
	let o = REQUEST_ID_LEN + 1;
	const lastReleased = payload.readUInt32BE(o);
	o += 4;
	const numPackages = payload.readUInt16BE(o);
	o += 2;
	const packages: Buffer[] = [];
	for (let i = 0; i < numPackages; i++) {
		const len = payload.readUInt32BE(o);
		o += 4;
		packages.push(Buffer.from(payload.subarray(o, o + len)));
		o += len;
	}
	const numPreimages = payload.readUInt16BE(o);
	o += 2;
	const preimages: Buffer[] = [];
	for (let i = 0; i < numPreimages; i++) {
		preimages.push(Buffer.from(payload.subarray(o, o + 32)));
		o += 32;
	}
	return {
		requestId,
		resp: { ok: true, lastReleased, packages, preimages }
	};
}

// ─────────────── Server: dispatch a request to an embedded tower ───────────────

/**
 * Given an embedded tower, the Noise-authenticated sender pubkey (hex), and an
 * incoming FF_TOWER_* REQUEST, produce the response to send back. Applies the
 * access-control layer (provision from R, release from S, fetch from R) before
 * touching the tower. Returns null for a non-request type (nothing to answer).
 */
export function handleTowerServerMessage(
	tower: FforTower,
	senderPubkeyHex: string,
	type: number,
	payload: Buffer
): { type: number; payload: Buffer } | null {
	switch (type) {
		case FF_TOWER_PROVISION_TYPE: {
			const { requestId, provisioningJson } = decodeTowerProvision(payload);
			try {
				const prov = deserializeTowerProvisioning(JSON.parse(provisioningJson));
				// Access control: provision MUST come from the epoch's R.
				if (prov.rNodeId.toString('hex') !== senderPubkeyHex) {
					return {
						type: FF_TOWER_ACK_TYPE,
						payload: encodeTowerAck(
							requestId,
							false,
							'provision rejected: sender is not the epoch recipient (R)'
						)
					};
				}
				tower.provision(prov);
				return {
					type: FF_TOWER_ACK_TYPE,
					payload: encodeTowerAck(requestId, true)
				};
			} catch (e) {
				return {
					type: FF_TOWER_ACK_TYPE,
					payload: encodeTowerAck(
						requestId,
						false,
						`provision failed: ${(e as Error).message}`
					)
				};
			}
		}
		case FF_TOWER_RELEASE_TYPE: {
			const { requestId, settlementPayload } = decodeTowerRelease(payload);
			let epochId: Buffer;
			try {
				epochId = decodeFforSettlementMessage(settlementPayload).epochId;
			} catch (e) {
				return {
					type: FF_TOWER_RELEASE_RESP_TYPE,
					payload: encodeTowerReleaseResp(requestId, {
						ok: false,
						error: `undecodable package: ${(e as Error).message}`
					})
				};
			}
			// Access control: release MUST come from the epoch's S.
			const auth = tower.getEpochAuth(epochId);
			if (!auth) {
				return {
					type: FF_TOWER_RELEASE_RESP_TYPE,
					payload: encodeTowerReleaseResp(requestId, {
						ok: false,
						error: 'unknown epoch'
					})
				};
			}
			if (auth.sNodeId.toString('hex') !== senderPubkeyHex) {
				return {
					type: FF_TOWER_RELEASE_RESP_TYPE,
					payload: encodeTowerReleaseResp(requestId, {
						ok: false,
						error:
							'release rejected: sender is not the epoch settlement peer (S)'
					})
				};
			}
			const result = tower.handleReleaseRequest(settlementPayload);
			return {
				type: FF_TOWER_RELEASE_RESP_TYPE,
				payload: encodeTowerReleaseResp(requestId, result)
			};
		}
		case FF_TOWER_FETCH_TYPE: {
			const { requestId, req } = decodeTowerFetch(payload);
			// Access control: fetch MUST come from the epoch's R (in ADDITION to
			// the signed fetch digest the tower verifies inside handleFetch).
			const auth = tower.getEpochAuth(req.epochId);
			if (!auth) {
				return {
					type: FF_TOWER_FETCH_RESP_TYPE,
					payload: encodeTowerFetchResp(requestId, {
						ok: false,
						error: 'unknown epoch',
						lastReleased: 0,
						packages: [],
						preimages: []
					})
				};
			}
			if (auth.rNodeId.toString('hex') !== senderPubkeyHex) {
				return {
					type: FF_TOWER_FETCH_RESP_TYPE,
					payload: encodeTowerFetchResp(requestId, {
						ok: false,
						error: 'fetch rejected: sender is not the epoch recipient (R)',
						lastReleased: 0,
						packages: [],
						preimages: []
					})
				};
			}
			const resp = tower.handleFetch(req);
			return {
				type: FF_TOWER_FETCH_RESP_TYPE,
				payload: encodeTowerFetchResp(requestId, resp)
			};
		}
		default:
			return null;
	}
}

/**
 * Register a PeerManager to serve an embedded tower: dispatch the 3 request
 * types to handleTowerServerMessage and send the response back to the
 * authenticated sender. Convenience for a standalone tower node; the same
 * dispatch is also wired into ChannelManager for full nodes hosting a tower.
 */
export function attachTowerServer(
	peerManager: PeerManager,
	tower: FforTower
): void {
	for (const reqType of FF_TOWER_REQUEST_TYPES) {
		peerManager.onMessage(reqType, (pubkey, type, payload) => {
			const resp = handleTowerServerMessage(tower, pubkey, type, payload);
			if (resp) {
				peerManager.sendToPeer(pubkey, resp.type, resp.payload);
			}
		});
	}
}

// ─────────────── Client: PeerTowerClient ───────────────

interface IPending {
	resolve: (payload: Buffer) => void;
	reject: (err: Error) => void;
	timer: ReturnType<typeof setTimeout>;
}

export interface IPeerTowerClientOptions {
	/** Tower node id (33-byte pubkey), or a nodeId@host:port URI. */
	towerNodeId?: Buffer | string;
	towerUri?: string;
	/** Tower address, when not carried in the URI. */
	address?: { host: string; port: number };
	/** Resolve a node id (hex) to an address, when neither URI nor address set. */
	resolver?: (nodeIdHex: string) => { host: string; port: number } | undefined;
	/** Per-request response timeout in ms (default 30_000). */
	timeoutMs?: number;
}

/**
 * IFforTowerClient over a real BOLT-8 PeerManager connection: the drop-in
 * replacement for LoopbackTowerClient. Ensures a Noise connection to the tower,
 * sends the request, and awaits the correlated response (pending-promise map
 * keyed by request_id, with a timeout).
 */
export class PeerTowerClient implements IFforTowerClient {
	private peerManager: PeerManager;
	private towerNodeIdHex: string;
	private address?: { host: string; port: number };
	private resolver?: (
		nodeIdHex: string
	) => { host: string; port: number } | undefined;
	private timeoutMs: number;
	private pending = new Map<string, IPending>();

	constructor(peerManager: PeerManager, opts: IPeerTowerClientOptions) {
		this.peerManager = peerManager;
		this.timeoutMs = opts.timeoutMs ?? 30_000;
		this.resolver = opts.resolver;

		let nodeIdHex: string | undefined;
		let address = opts.address;
		if (opts.towerUri) {
			const at = opts.towerUri.indexOf('@');
			nodeIdHex = at >= 0 ? opts.towerUri.slice(0, at) : opts.towerUri;
			if (at >= 0) {
				const hostPort = opts.towerUri.slice(at + 1);
				const colon = hostPort.lastIndexOf(':');
				if (colon >= 0) {
					address = {
						host: hostPort.slice(0, colon),
						port: parseInt(hostPort.slice(colon + 1), 10)
					};
				}
			}
		}
		if (opts.towerNodeId) {
			nodeIdHex = Buffer.isBuffer(opts.towerNodeId)
				? opts.towerNodeId.toString('hex')
				: opts.towerNodeId;
		}
		if (!nodeIdHex) {
			throw new Error(
				'PeerTowerClient: no tower node id (towerNodeId/towerUri)'
			);
		}
		this.towerNodeIdHex = nodeIdHex;
		this.address = address;

		// Correlate every response by its request_id.
		for (const respType of FF_TOWER_RESPONSE_TYPES) {
			this.peerManager.onMessage(respType, (pubkey, _type, payload) => {
				if (pubkey !== this.towerNodeIdHex) return; // only from our tower
				const requestId = payload.subarray(0, REQUEST_ID_LEN).toString('hex');
				const p = this.pending.get(requestId);
				if (!p) return;
				this.pending.delete(requestId);
				clearTimeout(p.timer);
				p.resolve(payload);
			});
		}
	}

	private async ensureConnected(): Promise<void> {
		const peer = this.peerManager.getPeer(this.towerNodeIdHex);
		if (peer && peer.getState() === 'ready') return;
		const addr =
			this.address ??
			this.peerManager.getPeerAddress(this.towerNodeIdHex) ??
			this.resolver?.(this.towerNodeIdHex);
		if (!addr) {
			throw new Error(
				`PeerTowerClient: no address for tower ${this.towerNodeIdHex}`
			);
		}
		await this.peerManager.connectPeer(
			this.towerNodeIdHex,
			addr.host,
			addr.port
		);
	}

	/** Send a request and await its correlated response payload. */
	private async request(
		reqType: number,
		requestId: Buffer,
		payload: Buffer
	): Promise<Buffer> {
		await this.ensureConnected();
		const idHex = requestId.toString('hex');
		const responsePromise = new Promise<Buffer>((resolve, reject) => {
			const timer = setTimeout(() => {
				this.pending.delete(idHex);
				reject(new Error(`tower request ${reqType} timed out`));
			}, this.timeoutMs);
			this.pending.set(idHex, { resolve, reject, timer });
		});
		this.peerManager.sendToPeer(this.towerNodeIdHex, reqType, payload);
		return responsePromise;
	}

	async provision(p: import('./tower').IFforTowerProvisioning): Promise<void> {
		const requestId = newRequestId();
		const json = JSON.stringify(serializeTowerProvisioning(p));
		const respPayload = await this.request(
			FF_TOWER_PROVISION_TYPE,
			requestId,
			encodeTowerProvision(requestId, json)
		);
		const { ok, error } = decodeTowerAck(respPayload);
		if (!ok) {
			throw new Error(`tower provision rejected: ${error}`);
		}
	}

	async requestRelease(pkg: Buffer): Promise<IFforTowerReleaseResult> {
		const requestId = newRequestId();
		const respPayload = await this.request(
			FF_TOWER_RELEASE_TYPE,
			requestId,
			encodeTowerRelease(requestId, pkg)
		);
		return decodeTowerReleaseResp(respPayload).result;
	}

	async fetch(req: IFforTowerFetchRequest): Promise<IFforTowerFetchResponse> {
		const requestId = newRequestId();
		const respPayload = await this.request(
			FF_TOWER_FETCH_TYPE,
			requestId,
			encodeTowerFetch(requestId, req)
		);
		return decodeTowerFetchResp(respPayload).resp;
	}

	/** Cancel all in-flight requests (e.g. on shutdown). */
	destroy(): void {
		for (const p of this.pending.values()) {
			clearTimeout(p.timer);
			p.reject(new Error('PeerTowerClient destroyed'));
		}
		this.pending.clear();
	}
}
