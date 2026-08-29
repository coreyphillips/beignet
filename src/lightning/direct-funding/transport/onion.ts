/**
 * Lane 2: direct funding over BOLT onion messages and blinded paths.
 *
 * The receiver publishes a blinded path in its envelope; the payer routes every
 * sealed frame down it and attaches its OWN blinded reply path to each frame,
 * so the receiver answers without ever learning the payer's node id. The
 * introduction node forwards fixed-size onions it cannot read. This lane is
 * anonymous by construction, and 4C must treat it that way: nothing here sets
 * `authenticatedPeer`.
 *
 * Four delivery rules, all rev 2 MUSTs:
 *
 *  - The final hop's `path_id` is a per-request SECRET that appears nowhere in
 *    the envelope, and is not the request id. 4A persists it as
 *    `onionPathSecretHex`. Any payer-visible value would let a request holder
 *    mint routes that pass the issued-path check.
 *  - A frame with no `path_id` is dropped outright. `processOnionMessage`
 *    surfaces one only from DECRYPTED `encrypted_recipient_data`, never from
 *    plaintext hop data, so its presence is what proves the route was ours.
 *  - The `path_id` must resolve to an outstanding request AND the sealed frame
 *    must name that same request. Two independent checks: the first proves we
 *    issued the route, the second proves the content was sealed to it.
 *  - Delivery is unreliable by specification. Nothing here retries; the
 *    idempotence rules in 4C are what make it dependable, and a retry that
 *    changed content would be worse than a lost frame.
 *
 * The onion manager holds no path_id registry and applies no policy (a TLV type
 * with no handler is simply skipped), so this lane owns its own, keyed on the
 * persisted path secrets from 4A for the receiving side and on locally minted
 * ids for the paying side. One map, one rule, both directions.
 *
 * Deployment note for 4D: `OnionMessageManager` rate limits inbound messages
 * per SENDING peer at 10 per 60 s by default, and every frame on this lane
 * arrives from the same introduction node. A busy LSP intro node can therefore
 * exhaust the budget for everything else that node speaks. The fork answered
 * that by raising the global limit to 120 in the manager's constructor, which
 * is a policy change for every onion consumer made to suit one feature. The
 * limit is left alone here; `setRateLimitConfig` exists, and the number belongs
 * in config with a stated reason.
 */

import crypto from 'crypto';
import { OnionMessageManager } from '../../onion-message/manager';
import { IBlindedPath, constructBlindedPath } from '../../onion/blinded-path';
import { BEIGNET_CUSTOM_MESSAGE_TYPE } from '../../message/custom';
import { decodeSealedFrame } from '../frames';
import {
	DF_PATH_SECRET_BYTES,
	DfTransportDescriptor,
	DfTransportType,
	DirectFundingError,
	DirectFundingErrorCode,
	IDfOnionTransport,
	malformed
} from '../types';
import { deliverIsolated } from './lane-table';
import {
	DF_FRAME_SUBTYPES,
	DF_LOG_FRAME_DROPPED,
	DF_MAX_FRAME_BYTES,
	DfDropReason,
	DfFrameHandler,
	DfTransportLog,
	IDfInboundFrame,
	IDfLaneFactory,
	IDfLaneSender,
	IDfOpenContext,
	IDfPeerMessaging,
	IDfTransport
} from './types';

/**
 * Odd TLV type carrying a direct-funding frame in an onion message. The same
 * number as the custom message type on purpose: one protocol, one identifier,
 * whichever wire it takes. Odd, so a node with no handler skips it.
 */
export const DF_ONION_TLV = BEIGNET_CUSTOM_MESSAGE_TYPE;

const TRANSPORT = 'onion';

/**
 * Onion body: `u16 subtype || sealed frame`. The onion TLV carries no subtype
 * of its own, and the frame's associated data binds the subtype, so this
 * prefix cannot be rewritten without breaking authentication.
 */
export function encodeDfOnionBody(subtype: number, frame: Buffer): Buffer {
	if (!Number.isInteger(subtype) || subtype < 0 || subtype > 0xffff) {
		throw malformed(`direct-funding subtype out of range: ${subtype}`);
	}
	const header = Buffer.alloc(2);
	header.writeUInt16BE(subtype, 0);
	return Buffer.concat([header, frame]);
}

/** Parse an onion body, or null when the bytes are not one. Never throws. */
export function decodeDfOnionBody(
	data: Buffer
): { subtype: number; frame: Buffer } | null {
	if (data.length < 2 || data.length > DF_MAX_FRAME_BYTES + 2) return null;
	return {
		subtype: data.readUInt16BE(0),
		frame: Buffer.from(data.subarray(2))
	};
}

/**
 * Mint a two-hop blinded path [via, self] whose final hop carries `pathId`.
 * Only `via` appears in the clear; this node appears as a blinded id nobody can
 * link back to its real key.
 */
export function mintDfBlindedPath(
	viaNodeId: Buffer,
	selfNodeId: Buffer,
	pathId: Buffer
): IBlindedPath {
	return constructBlindedPath(
		crypto.randomBytes(32),
		[viaNodeId, selfNodeId],
		[{ nextNodeId: selfNodeId }, { pathId }]
	);
}

/** The blinded path a receiver's onion descriptor describes. */
export function blindedPathFromDescriptor(
	t: IDfOnionTransport
): IBlindedPath | null {
	if (t.hops.length === 0) return null;
	return {
		introductionNodeId: t.introNodeId,
		blindingPoint: t.pathKey,
		blindedHops: t.hops
	};
}

export interface IDfOnionLaneDeps {
	manager: OnionMessageManager;
	peers: IDfPeerMessaging;
	/** This node's own id, for the reply path's final hop. */
	nodeId(): Buffer;
	/**
	 * Resolve a path secret to the hex request id it was minted for, or null.
	 * 4D wires this to `DirectFundingRequestStore.byOnionPathSecret`, which
	 * already excludes expired requests.
	 */
	resolvePathSecret(pathSecretHex: string): string | null;
}

/** A payer lane's claim on a path id it minted for one request. */
interface IDfPathClaim {
	requestIdHex: string;
	/**
	 * The lane itself. An answer to a payer-role frame goes back out the way the
	 * lane went, reply path and all: a bare sender built from the send path alone
	 * would attach none, and the receiver would have nothing to answer on.
	 */
	reply: IDfLaneSender;
	deliver: DfFrameHandler;
}

export class DfOnionLaneFactory implements IDfLaneFactory {
	readonly type = DfTransportType.ONION_MESSAGE;

	private readonly claims = new Map<string, IDfPathClaim>();
	private readonly sinks = new Set<DfFrameHandler>();
	private handlerRegistered = false;

	constructor(
		private readonly deps: IDfOnionLaneDeps,
		private readonly log: DfTransportLog = (): void => undefined
	) {}

	async open(
		descriptor: DfTransportDescriptor,
		ctx: IDfOpenContext
	): Promise<IDfTransport | null> {
		if (descriptor.type !== DfTransportType.ONION_MESSAGE) return null;
		const onion = descriptor as IDfOnionTransport;
		const sendPath = blindedPathFromDescriptor(onion);
		if (!sendPath) return null;
		const introHex = onion.introNodeId.toString('hex');
		if (!this.deps.peers.isPeerConnected(introHex)) {
			try {
				await this.deps.peers.connectPeer(introHex, onion.host, onion.port);
			} catch {
				if (!this.deps.peers.isPeerConnected(introHex)) return null;
			}
		}
		// Minted per lane, never derived from anything the receiver holds: this
		// is the id the RECEIVER's answers come back on, and it is ours alone.
		const localPathId = crypto.randomBytes(DF_PATH_SECRET_BYTES);
		let replyPath: IBlindedPath;
		try {
			replyPath = mintDfBlindedPath(
				onion.introNodeId,
				this.deps.nodeId(),
				localPathId
			);
		} catch {
			return null;
		}
		this.ensureHandlerRegistered();
		return new DfOnionLane(this, {
			manager: this.deps.manager,
			peers: this.deps.peers,
			pathIdHex: localPathId.toString('hex'),
			requestIdHex: ctx.requestId.toString('hex'),
			sendPath,
			replyPath,
			log: this.log
		});
	}

	attachInbound(sink: DfFrameHandler): () => void {
		this.ensureHandlerRegistered();
		this.sinks.add(sink);
		return () => {
			this.sinks.delete(sink);
		};
	}

	/**
	 * Removes EVERY handler for the direct-funding TLV type, which is safe only
	 * because this protocol owns the number.
	 */
	destroy(): void {
		if (this.handlerRegistered) {
			this.deps.manager.unregisterTlvHandler(DF_ONION_TLV);
			this.handlerRegistered = false;
		}
		this.claims.clear();
		this.sinks.clear();
	}

	/** Live path claims. Tests assert this returns to zero. */
	get openLaneCount(): number {
		return this.claims.size;
	}

	// ─────────────── Internals, used by the lane ───────────────

	claimPath(pathIdHex: string, claim: IDfPathClaim): () => void {
		this.claims.set(pathIdHex, claim);
		return () => {
			// Released here rather than when the last subscriber leaves, so a
			// decline path that opens a lane and returns cannot leak an entry
			// (defect D21).
			if (this.claims.get(pathIdHex) === claim) this.claims.delete(pathIdHex);
		};
	}

	private ensureHandlerRegistered(): void {
		if (this.handlerRegistered) return;
		this.handlerRegistered = true;
		this.deps.manager.registerTlvHandler(
			DF_ONION_TLV,
			(_fromPeer, _tlvType, data, replyPath, pathId) => {
				try {
					this.handle(data, replyPath, pathId);
				} catch (err) {
					this.drop(DfDropReason.HANDLER_FAILED, { error: errorText(err) });
				}
			}
		);
	}

	private handle(
		data: Buffer,
		replyPath?: IBlindedPath,
		pathId?: Buffer
	): void {
		if (!pathId) {
			// No decrypted recipient data means no proof the route was ours. This
			// is the check the whole lane rests on.
			this.drop(DfDropReason.NO_PATH_ID, {});
			return;
		}
		const pathIdHex = pathId.toString('hex');
		const claim = this.claims.get(pathIdHex);
		// A claimed id is a lane WE opened as payer; otherwise the id has to be
		// one of our own outstanding requests' path secrets.
		const boundRequestIdHex =
			claim?.requestIdHex ?? this.deps.resolvePathSecret(pathIdHex);
		if (!boundRequestIdHex) {
			this.drop(DfDropReason.UNKNOWN_PATH_ID, {});
			return;
		}
		const body = decodeDfOnionBody(data);
		if (!body) {
			this.drop(DfDropReason.MALFORMED_BODY, { bytes: data.length });
			return;
		}
		if (!DF_FRAME_SUBTYPES.has(body.subtype)) {
			this.drop(DfDropReason.UNHANDLED_SUBTYPE, { subtype: body.subtype });
			return;
		}
		const wire = decodeSealedFrame(body.frame);
		if (!wire) {
			this.drop(DfDropReason.NOT_A_SEALED_FRAME, {});
			return;
		}
		if (
			wire.requestId !== undefined &&
			wire.requestId.toString('hex') !== boundRequestIdHex
		) {
			// The route was ours and the content was not: a holder of one request
			// trying to speak on another's path.
			this.drop(DfDropReason.REQUEST_ID_MISMATCH, { subtype: body.subtype });
			return;
		}
		// A payer answers on its own lane; a receiver has only what the frame
		// carried, so a frame with no reply path is unanswerable.
		let reply: IDfLaneSender;
		if (claim) {
			reply = claim.reply;
		} else if (replyPath) {
			reply = new DfOnionSender(
				this.deps.manager,
				this.deps.peers,
				replyPath,
				undefined,
				this.log
			);
		} else {
			this.drop(DfDropReason.NO_REPLY_PATH, { subtype: body.subtype });
			return;
		}
		const frame: IDfInboundFrame = {
			type: DfTransportType.ONION_MESSAGE,
			laneKey: pathIdHex,
			subtype: body.subtype,
			payload: body.frame,
			reply,
			boundRequestId: Buffer.from(boundRequestIdHex, 'hex')
		};
		const handlers = claim ? [claim.deliver] : [...this.sinks];
		if (handlers.length === 0) {
			this.drop(DfDropReason.NO_LISTENER, { subtype: body.subtype });
			return;
		}
		deliverIsolated(handlers, frame, (err) =>
			this.drop(DfDropReason.HANDLER_FAILED, { error: errorText(err) })
		);
	}

	private drop(reason: DfDropReason, data: Record<string, unknown>): void {
		logDrop(this.log, reason, data);
	}
}

/** Send half: a blinded path to send down, and optionally one to answer on. */
class DfOnionSender implements IDfLaneSender {
	readonly type = DfTransportType.ONION_MESSAGE;

	constructor(
		protected readonly manager: OnionMessageManager,
		protected readonly peers: IDfPeerMessaging,
		protected readonly sendPath: IBlindedPath,
		protected readonly replyPath: IBlindedPath | undefined,
		protected readonly log: DfTransportLog
	) {}

	send(subtype: number, payload: Buffer): void {
		if (payload.length > DF_MAX_FRAME_BYTES) {
			throw malformed(
				`direct-funding frame is ${payload.length} bytes, max ${DF_MAX_FRAME_BYTES}`
			);
		}
		// The node's onion send hook swallows a `sendToPeer` failure, so nothing
		// downstream can tell a delivered frame from one that never left. Refuse
		// here instead: a lane that counted an undelivered frame as exchanged
		// would also deny the registry the fall-through it is owed.
		const introHex = this.sendPath.introductionNodeId.toString('hex');
		if (!this.peers.isPeerConnected(introHex)) {
			throw new DirectFundingError(
				DirectFundingErrorCode.UNREACHABLE,
				'not connected to the blinded path introduction node'
			);
		}
		// The BOLT 4 form is chosen from the payload alone (1300 or 32768 bytes
		// of routing info), the HMAC covers the whole routing info, and there are
		// exactly two on-wire sizes, so the length leaks at most one bit. A frame
		// past the large form is refused there, by name.
		this.manager.sendReply(
			this.sendPath,
			new Map([[DF_ONION_TLV, encodeDfOnionBody(subtype, payload)]]),
			this.replyPath ? { replyPath: this.replyPath } : undefined
		);
		this.onSent();
	}

	trySend(subtype: number, payload: Buffer): boolean {
		try {
			this.send(subtype, payload);
			return true;
		} catch (err) {
			logDrop(this.log, DfDropReason.SEND_FAILED, {
				subtype,
				error: errorText(err)
			});
			return false;
		}
	}

	protected onSent(): void {
		return;
	}
}

class DfOnionLane extends DfOnionSender implements IDfTransport {
	private readonly handlers = new Set<DfFrameHandler>();
	private readonly release: () => void;
	private exchanged = 0;
	private closed = false;

	constructor(
		factory: DfOnionLaneFactory,
		opts: {
			manager: OnionMessageManager;
			peers: IDfPeerMessaging;
			pathIdHex: string;
			requestIdHex: string;
			sendPath: IBlindedPath;
			replyPath: IBlindedPath;
			log: DfTransportLog;
		}
	) {
		super(opts.manager, opts.peers, opts.sendPath, opts.replyPath, opts.log);
		this.release = factory.claimPath(opts.pathIdHex, {
			requestIdHex: opts.requestIdHex,
			reply: this,
			deliver: (frame) => {
				this.exchanged++;
				deliverIsolated([...this.handlers], frame, (err) =>
					logDrop(this.log, DfDropReason.HANDLER_FAILED, {
						error: errorText(err)
					})
				);
			}
		});
	}

	onMessage(cb: DfFrameHandler): () => void {
		this.handlers.add(cb);
		return () => {
			this.handlers.delete(cb);
		};
	}

	framesExchanged(): number {
		return this.exchanged;
	}

	close(): void {
		if (this.closed) return;
		this.closed = true;
		this.release();
		this.handlers.clear();
	}

	protected onSent(): void {
		this.exchanged++;
	}
}

function logDrop(
	log: DfTransportLog,
	reason: DfDropReason,
	data: Record<string, unknown>
): void {
	try {
		log(DF_LOG_FRAME_DROPPED, { transport: TRANSPORT, reason, ...data });
	} catch {
		// A throwing log observer must not take the lane down.
	}
}

function errorText(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
