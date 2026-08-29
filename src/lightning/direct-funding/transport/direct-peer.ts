/**
 * Lane 1: direct funding over an authenticated peer connection.
 *
 * Frames ride the beignet custom message type (44069, #546) under their own
 * subtype, out through `LightningNode.sendCustomMessage` and in on the
 * `custom-message` event.
 *
 * This lane inherits the recovery gates and must not route around them. The
 * outbound gate is consulted inside `PeerManager.sendToPeer` and refuses by
 * throwing, the connection gate inside `connectPeer`, and the inbound gate
 * drops before `handlePeerMessage` emits anything. Nothing here reaches the
 * wire by another road, which is why the deps interface exposes only those
 * three calls.
 *
 * It is also the ONLY lane that authenticates the payer, because the frame
 * arrives on a Noise connection whose peer id we know. That fact is surfaced
 * as `authenticatedPeer` and nowhere else; the other two lanes are anonymous by
 * construction and say so by leaving it unset.
 */

import { BeignetCustomSubtype } from '../../message/custom';
import { decodeSealedFrame } from '../frames';
import {
	DfTransportDescriptor,
	DfTransportType,
	IDfDirectPeerTransport,
	malformed
} from '../types';
import { DfLaneTable, deliverIsolated } from './lane-table';
import {
	DF_FRAME_SUBTYPES,
	DF_LOG_FRAME_DROPPED,
	DF_MAX_FRAME_BYTES,
	DfDropReason,
	DfFrameHandler,
	DfTransportLog,
	IDfCustomMessage,
	IDfInboundFrame,
	IDfLaneFactory,
	IDfOpenContext,
	IDfPeerMessaging,
	IDfTransport
} from './types';

const TRANSPORT = 'direct_peer';

export class DfDirectPeerLaneFactory implements IDfLaneFactory {
	readonly type = DfTransportType.DIRECT_PEER;

	private readonly table = new DfLaneTable();
	private unsubscribe: (() => void) | null = null;

	constructor(
		private readonly peers: IDfPeerMessaging,
		private readonly log: DfTransportLog = (): void => undefined
	) {}

	/**
	 * Dial the receiver at the address it published and hand back a lane. A
	 * connection failure returns null so the registry can try the next
	 * descriptor; nothing has reached the wire at that point.
	 */
	async open(
		descriptor: DfTransportDescriptor,
		ctx: IDfOpenContext
	): Promise<IDfTransport | null> {
		if (descriptor.type !== DfTransportType.DIRECT_PEER) return null;
		const { host, port } = descriptor as IDfDirectPeerTransport;
		const peerHex = ctx.receiverNodeId.toString('hex');
		if (!this.peers.isPeerConnected(peerHex)) {
			try {
				await this.peers.connectPeer(peerHex, host, port);
			} catch {
				// A concurrent dial may have landed while ours failed.
				if (!this.peers.isPeerConnected(peerHex)) return null;
			}
		}
		this.ensureSubscribed();
		return new DfDirectPeerLane(
			this.peers,
			this.table,
			peerHex,
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
			// Self-contained, like the JIT authorization handler: the node emits
			// 'custom-message' inside ONE try/catch, so a throw here would skip
			// every listener registered after ours.
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

	private handle(msg: IDfCustomMessage): void {
		if (!DF_FRAME_SUBTYPES.has(msg.subtype)) {
			// Everything else on this wire type belongs to another consumer (JIT
			// receive, the relay wrapper) and is not ours to report. The reserved
			// abort subtype IS addressed to this protocol, so a peer sending one
			// shows up in the log rather than vanishing.
			if (msg.subtype === BeignetCustomSubtype.DIRECT_FUNDING_ABORT) {
				this.drop(DfDropReason.UNHANDLED_SUBTYPE, {
					pubkey: msg.peerPubkey,
					subtype: msg.subtype
				});
			}
			return;
		}
		if (msg.payload.length > DF_MAX_FRAME_BYTES) {
			this.drop(DfDropReason.FRAME_TOO_LARGE, {
				pubkey: msg.peerPubkey,
				bytes: msg.payload.length
			});
			return;
		}
		const wire = decodeSealedFrame(msg.payload);
		if (!wire) {
			this.drop(DfDropReason.NOT_A_SEALED_FRAME, { pubkey: msg.peerPubkey });
			return;
		}
		const handlers = this.table.route(
			msg.peerPubkey,
			wire.requestId?.toString('hex')
		);
		if (handlers.length === 0) {
			this.drop(DfDropReason.NO_LISTENER, {
				pubkey: msg.peerPubkey,
				subtype: msg.subtype
			});
			return;
		}
		const frame: IDfInboundFrame = {
			type: DfTransportType.DIRECT_PEER,
			laneKey: msg.peerPubkey,
			subtype: msg.subtype,
			payload: msg.payload,
			reply: new DfDirectPeerSender(this.peers, msg.peerPubkey, this.log),
			authenticatedPeer: msg.peerPubkey
		};
		deliverIsolated(handlers, frame, (err) =>
			this.drop(DfDropReason.HANDLER_FAILED, {
				pubkey: msg.peerPubkey,
				error: errorText(err)
			})
		);
	}

	private drop(reason: DfDropReason, data: Record<string, unknown>): void {
		logDrop(this.log, reason, data);
	}
}

/** Send half: what a payer lane and an inbound frame's `reply` share. */
class DfDirectPeerSender {
	readonly type = DfTransportType.DIRECT_PEER;

	constructor(
		protected readonly peers: IDfPeerMessaging,
		protected readonly peerHex: string,
		protected readonly log: DfTransportLog
	) {}

	send(subtype: number, payload: Buffer): void {
		if (payload.length > DF_MAX_FRAME_BYTES) {
			throw malformed(
				`direct-funding frame is ${payload.length} bytes, max ${DF_MAX_FRAME_BYTES}`
			);
		}
		this.peers.sendCustomMessage(this.peerHex, subtype, payload);
		this.onSent();
	}

	trySend(subtype: number, payload: Buffer): boolean {
		try {
			this.send(subtype, payload);
			return true;
		} catch (err) {
			logDrop(this.log, DfDropReason.SEND_FAILED, {
				pubkey: this.peerHex,
				subtype,
				error: errorText(err)
			});
			return false;
		}
	}

	/** Overridden by the duplex lane, which counts what it carried. */
	protected onSent(): void {
		return;
	}
}

class DfDirectPeerLane extends DfDirectPeerSender implements IDfTransport {
	private readonly handlers = new Set<DfFrameHandler>();
	private readonly release: () => void;
	private exchanged = 0;
	private closed = false;

	constructor(
		peers: IDfPeerMessaging,
		table: DfLaneTable,
		peerHex: string,
		requestIdHex: string,
		log: DfTransportLog
	) {
		super(peers, peerHex, log);
		this.release = table.claim(peerHex, requestIdHex, (frame) => {
			this.exchanged++;
			deliverIsolated([...this.handlers], frame, (err) =>
				logDrop(this.log, DfDropReason.HANDLER_FAILED, {
					pubkey: this.peerHex,
					error: errorText(err)
				})
			);
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
		// A throwing log observer must not cost the peer its connection.
	}
}

function errorText(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}
