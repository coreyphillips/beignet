/**
 * Lane 3: direct funding blind-relayed through a shared peer, usually the
 * receiver's LSP.
 *
 * The originator sends `{to, subtype, payload}` under subtype 22. The relay
 * forwards `{from, subtype, payload}` to the target, stamping `from` itself
 * from the authenticated connection the frame arrived on and ignoring anything
 * the sender supplied. The two wrapper shapes are deliberately different and
 * carry exactly one of the two fields (4A `encodeDfRelayFrame` refuses both and
 * neither), because "a frame already carrying `from` is never re-forwarded" is
 * what makes loops impossible.
 *
 * The relay reads no payload: frames stay sealed to the per-request key, so it
 * moves bytes it cannot interpret. Its identity stamp authenticates the RELAY,
 * not the payer, which is why an inbound frame surfaces it as
 * `relayAssertedFrom` and never as `authenticatedPeer`: 4C must not treat a
 * relayed origin as pairing.
 *
 * Defect D29 is the reason the server half looks the way it does. The fork's
 * forwarder had no rate limit, no per-peer budget, no size cap and no refusal
 * for a self-addressed frame, so any connected peer could use an opt-in relay
 * as an unmetered message bus to any other connected peer. Here every frame a
 * peer hands the relay costs it a token whatever happens to the frame, an
 * oversized one is refused before it is even parsed, and a frame addressed to
 * the relay itself or back at its own sender is refused outright.
 *
 * Logging: a successful forward writes NOTHING. A drop names its reason and at
 * most the SENDING peer, never the target, so the relay's unavoidable metadata
 * view (who talked to whom) is not additionally written to disk.
 */

import { PeerRateLimiter } from '../../node/rate-limiter';
import { BeignetCustomSubtype } from '../../message/custom';
import { decodeSealedFrame } from '../frames';
import {
	IDfRelayFrame,
	decodeDfRelayFrame,
	encodeDfRelayFrame
} from '../messages';
import {
	DF_MAX_MESSAGE_BYTES,
	DfTransportDescriptor,
	DfTransportType,
	IDfRelayTransport,
	malformed
} from '../types';
import { DfLaneTable, deliverIsolated } from './lane-table';
import {
	DF_FRAME_SUBTYPES,
	DF_LOG_FRAME_DROPPED,
	DfDropReason,
	DfFrameHandler,
	DfTransportLog,
	IDfCustomMessage,
	IDfInboundFrame,
	IDfLaneFactory,
	IDfLaneSender,
	IDfOpenContext,
	IDfPeerMessaging,
	IDfRelayServerConfig,
	IDfTransport
} from './types';

const TRANSPORT = 'relay';

/** TLV records, lengths and the 33-byte address around a relayed frame. */
export const DF_RELAY_WRAPPER_OVERHEAD = 64;

/**
 * Tighter than `DF_MAX_FRAME_BYTES`, which the other two lanes use, because the
 * wrapper's own payload field is bounded at `DF_MAX_MESSAGE_BYTES` by the 4A
 * codec. Refusing here means an oversized frame is named at the lane rather
 * than surfacing as a forward that threw.
 */
export const DF_RELAY_MAX_FRAME_BYTES = DF_MAX_MESSAGE_BYTES;

export const DF_RELAY_DEFAULTS = {
	/** Sustained frames one peer may hand the relay. */
	maxFramesPerSecond: 4,
	/** Bucket depth, so one exchange's worth of frames goes through at once. */
	burstMultiplier: 4,
	maxFrameBytes: DF_RELAY_MAX_FRAME_BYTES
};

// ─────────────── Client half ───────────────

export class DfRelayLaneFactory implements IDfLaneFactory {
	readonly type = DfTransportType.LSP_RELAY;

	private readonly table = new DfLaneTable();
	private unsubscribe: (() => void) | null = null;

	constructor(
		private readonly peers: IDfPeerMessaging,
		private readonly log: DfTransportLog = (): void => undefined
	) {}

	async open(
		descriptor: DfTransportDescriptor,
		ctx: IDfOpenContext
	): Promise<IDfTransport | null> {
		if (descriptor.type !== DfTransportType.LSP_RELAY) return null;
		const relay = descriptor as IDfRelayTransport;
		const relayHex = relay.relayNodeId.toString('hex');
		const targetHex = ctx.receiverNodeId.toString('hex');
		// A relay that is also the counterparty is not a relay; it would stamp a
		// frame it sent to itself.
		if (relayHex === targetHex) return null;
		if (!this.peers.isPeerConnected(relayHex)) {
			try {
				await this.peers.connectPeer(relayHex, relay.host, relay.port);
			} catch {
				if (!this.peers.isPeerConnected(relayHex)) return null;
			}
		}
		this.ensureSubscribed();
		return new DfRelayLane(
			this.peers,
			this.table,
			relayHex,
			ctx.receiverNodeId,
			ctx.requestId.toString('hex'),
			this.log
		);
	}

	attachInbound(sink: DfFrameHandler): () => void {
		this.ensureSubscribed();
		return this.table.attach(sink);
	}

	destroy(): void {
		this.unsubscribe?.();
		this.unsubscribe = null;
		this.table.clear();
	}

	/** Live payer claims. Tests assert this returns to zero. */
	get openLaneCount(): number {
		return this.table.claimCount;
	}

	// ─────────────── Internals ───────────────

	private ensureSubscribed(): void {
		if (this.unsubscribe) return;
		this.unsubscribe = this.peers.onCustomMessage((msg) => {
			try {
				this.handle(msg);
			} catch (err) {
				this.drop(DfDropReason.HANDLER_FAILED, { error: errorText(err) });
			}
		});
	}

	private handle(msg: IDfCustomMessage): void {
		if (msg.subtype !== BeignetCustomSubtype.DIRECT_FUNDING_RELAY) return;
		let wrapper: IDfRelayFrame;
		try {
			wrapper = decodeDfRelayFrame(msg.payload);
		} catch (err) {
			this.drop(DfDropReason.MALFORMED_RELAY_FRAME, {
				pubkey: msg.peerPubkey,
				error: errorText(err)
			});
			return;
		}
		if (!wrapper.from) {
			// Addressed with `to`: this is an ORIGINATOR frame, which only the
			// relay server half answers. A client seeing one is being asked to
			// relay, and it does not relay.
			this.drop(DfDropReason.RELAY_ALREADY_FORWARDED, {
				pubkey: msg.peerPubkey
			});
			return;
		}
		if (!DF_FRAME_SUBTYPES.has(wrapper.subtype)) {
			this.drop(DfDropReason.UNHANDLED_SUBTYPE, {
				pubkey: msg.peerPubkey,
				subtype: wrapper.subtype
			});
			return;
		}
		const originHex = wrapper.from.toString('hex');
		const laneKey = laneKeyFor(msg.peerPubkey, originHex);
		const wire = decodeSealedFrame(wrapper.payload);
		if (!wire) {
			this.drop(DfDropReason.NOT_A_SEALED_FRAME, { pubkey: msg.peerPubkey });
			return;
		}
		const handlers = this.table.route(laneKey, wire.requestId?.toString('hex'));
		if (handlers.length === 0) {
			this.drop(DfDropReason.NO_LISTENER, {
				pubkey: msg.peerPubkey,
				subtype: wrapper.subtype
			});
			return;
		}
		const frame: IDfInboundFrame = {
			type: DfTransportType.LSP_RELAY,
			laneKey,
			subtype: wrapper.subtype,
			payload: wrapper.payload,
			reply: new DfRelaySender(
				this.peers,
				msg.peerPubkey,
				wrapper.from,
				this.log
			),
			relayAssertedFrom: originHex
		};
		deliverIsolated(handlers, frame, (err) =>
			this.drop(DfDropReason.HANDLER_FAILED, { error: errorText(err) })
		);
	}

	private drop(reason: DfDropReason, data: Record<string, unknown>): void {
		logDrop(this.log, reason, data);
	}
}

/** Send half: wrap in `{to, subtype, payload}` and hand it to the relay. */
class DfRelaySender implements IDfLaneSender {
	readonly type = DfTransportType.LSP_RELAY;

	constructor(
		protected readonly peers: IDfPeerMessaging,
		protected readonly relayHex: string,
		protected readonly to: Buffer,
		protected readonly log: DfTransportLog
	) {}

	send(subtype: number, payload: Buffer): void {
		if (payload.length > DF_RELAY_MAX_FRAME_BYTES) {
			throw malformed(
				`relayed direct-funding frame is ${payload.length} bytes, ` +
					`max ${DF_RELAY_MAX_FRAME_BYTES}`
			);
		}
		this.peers.sendCustomMessage(
			this.relayHex,
			BeignetCustomSubtype.DIRECT_FUNDING_RELAY,
			encodeDfRelayFrame({ to: this.to, subtype, payload })
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

class DfRelayLane extends DfRelaySender implements IDfTransport {
	private readonly handlers = new Set<DfFrameHandler>();
	private readonly release: () => void;
	private exchanged = 0;
	private closed = false;

	constructor(
		peers: IDfPeerMessaging,
		table: DfLaneTable,
		relayHex: string,
		to: Buffer,
		requestIdHex: string,
		log: DfTransportLog
	) {
		super(peers, relayHex, to, log);
		this.release = table.claim(
			laneKeyFor(relayHex, to.toString('hex')),
			requestIdHex,
			(frame) => {
				this.exchanged++;
				deliverIsolated([...this.handlers], frame, (err) =>
					logDrop(this.log, DfDropReason.HANDLER_FAILED, {
						error: errorText(err)
					})
				);
			}
		);
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

// ─────────────── Server half ───────────────

/**
 * Make this node a blind relay. Operator opt-in (`BEIGNET_DF_RELAY`, wired in
 * 4D): a node that has not asked for this never constructs one.
 */
export class DfRelayForwarder {
	private readonly budget: PeerRateLimiter;
	private readonly maxFrameBytes: number;
	private unsubscribe: (() => void) | null = null;

	constructor(
		private readonly peers: IDfPeerMessaging,
		config: IDfRelayServerConfig = {},
		private readonly log: DfTransportLog = (): void => undefined
	) {
		// A per-peer token bucket, which is what a frame budget is. The config
		// field is named for the HTLC limiter's original caller; the mechanism is
		// rate and burst either way.
		this.budget = new PeerRateLimiter({
			maxHtlcsPerSecond:
				config.maxFramesPerSecond ?? DF_RELAY_DEFAULTS.maxFramesPerSecond,
			burstMultiplier:
				config.burstMultiplier ?? DF_RELAY_DEFAULTS.burstMultiplier
		});
		this.maxFrameBytes =
			config.maxFrameBytes ?? DF_RELAY_DEFAULTS.maxFrameBytes;
	}

	start(): void {
		if (this.unsubscribe) return;
		this.unsubscribe = this.peers.onCustomMessage((msg) => {
			try {
				this.handle(msg);
			} catch (err) {
				this.drop(DfDropReason.HANDLER_FAILED, {
					pubkey: msg.peerPubkey,
					error: errorText(err)
				});
			}
		});
	}

	stop(): void {
		this.unsubscribe?.();
		this.unsubscribe = null;
		this.budget.clear();
	}

	/** Forget a disconnected peer's bucket. */
	forgetPeer(peerPubkeyHex: string): void {
		this.budget.removePeer(peerPubkeyHex);
	}

	private handle(msg: IDfCustomMessage): void {
		if (msg.subtype !== BeignetCustomSubtype.DIRECT_FUNDING_RELAY) return;
		// The budget is spent BEFORE anything else this frame could cost us, so
		// a peer cannot buy unmetered parsing with frames it knows will be
		// dropped.
		if (!this.budget.tryConsume(msg.peerPubkey)) {
			this.drop(DfDropReason.RELAY_OVER_BUDGET, { pubkey: msg.peerPubkey });
			return;
		}
		if (msg.payload.length > this.maxFrameBytes + DF_RELAY_WRAPPER_OVERHEAD) {
			this.drop(DfDropReason.FRAME_TOO_LARGE, {
				pubkey: msg.peerPubkey,
				bytes: msg.payload.length
			});
			return;
		}
		let wrapper: IDfRelayFrame;
		try {
			wrapper = decodeDfRelayFrame(msg.payload);
		} catch (err) {
			this.drop(DfDropReason.MALFORMED_RELAY_FRAME, {
				pubkey: msg.peerPubkey,
				error: errorText(err)
			});
			return;
		}
		if (wrapper.from || !wrapper.to) {
			// Only originator frames carry `to`. A frame already stamped with an
			// origin has been relayed once, and relaying it again is the only way
			// a loop could form.
			this.drop(DfDropReason.RELAY_ALREADY_FORWARDED, {
				pubkey: msg.peerPubkey
			});
			return;
		}
		if (wrapper.payload.length > this.maxFrameBytes) {
			this.drop(DfDropReason.FRAME_TOO_LARGE, {
				pubkey: msg.peerPubkey,
				bytes: wrapper.payload.length
			});
			return;
		}
		const targetHex = wrapper.to.toString('hex');
		if (targetHex === this.peers.nodeIdHex() || targetHex === msg.peerPubkey) {
			// Addressed to the relay itself, or back at its own sender. Neither is
			// a relay request; both are a peer using us as an echo.
			this.drop(DfDropReason.RELAY_SELF_ADDRESSED, { pubkey: msg.peerPubkey });
			return;
		}
		if (!this.peers.isPeerConnected(targetHex)) {
			// A store-nothing relay can do nothing else. The target is not named
			// in the log.
			this.drop(DfDropReason.RELAY_TARGET_NOT_CONNECTED, {
				pubkey: msg.peerPubkey
			});
			return;
		}
		try {
			this.peers.sendCustomMessage(
				targetHex,
				BeignetCustomSubtype.DIRECT_FUNDING_RELAY,
				encodeDfRelayFrame({
					// Stamped from the authenticated connection this arrived on.
					// Whatever the sender put in the wrapper is not consulted: the
					// codec refuses a wrapper carrying both fields, and this one is
					// built fresh regardless.
					from: Buffer.from(msg.peerPubkey, 'hex'),
					subtype: wrapper.subtype,
					payload: wrapper.payload
				})
			);
		} catch (err) {
			this.drop(DfDropReason.RELAY_FORWARD_FAILED, {
				pubkey: msg.peerPubkey,
				error: errorText(err)
			});
		}
		// A successful forward logs nothing at all.
	}

	private drop(reason: DfDropReason, data: Record<string, unknown>): void {
		logDrop(this.log, reason, data);
	}
}

// ─────────────── Shared ───────────────

/** One counterparty reachable through one relay. */
export function laneKeyFor(relayHex: string, counterpartyHex: string): string {
	return `${relayHex}:${counterpartyHex}`;
}

function logDrop(
	log: DfTransportLog,
	reason: DfDropReason,
	data: Record<string, unknown>
): void {
	try {
		log(DF_LOG_FRAME_DROPPED, { transport: TRANSPORT, reason, ...data });
	} catch {
		// A throwing log observer must not take the lane or the relay down.
	}
}

function errorText(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
