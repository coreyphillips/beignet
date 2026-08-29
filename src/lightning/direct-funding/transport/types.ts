/**
 * Direct-funding transports: the lane contract and the registry seam (issue
 * #611, LFBW port #532 workstream 4B).
 *
 * A lane moves an opaque sealed frame (4A `frames.ts`) between a payer and a
 * receiver. Three of them ship here: a direct peer connection, BOLT onion
 * messages over blinded paths, and a blind relay through the receiver's LSP.
 * A fourth type is reserved for the deferred rendezvous transport (#533).
 *
 * The fork had the lane abstraction and no selection: which lane to use was an
 * if-else chain in one HTTP route, and the swarm lane was a top-level import,
 * so `require('hyperswarm')` ran at boot even with the swarm disabled. A plugin
 * that must be imported before it can be optional is not optional. Hence
 * `DfTransportRegistry`: a lane is registered with a config gate and a LOADER,
 * and a lane that is disabled or never selected is never loaded at all.
 *
 * The lane layer reads no plaintext. It carries `(subtype, sealed bytes)` and
 * knows nothing about offers, transactions or channels; 4C and 4D own those.
 */

import { BeignetCustomSubtype } from '../../message/custom';
import { DF_FRAME_NONCE_BYTES, DF_FRAME_TAG_BYTES } from '../frames';
import {
	DF_MAX_MESSAGE_BYTES,
	DF_NODE_ID_BYTES,
	DF_REQUEST_ID_BYTES,
	DfTransportDescriptor,
	DfTransportType
} from '../types';

// ─────────────── Sizes ───────────────

/**
 * Everything `encodeSealedFrame` adds to a message body at its widest: the
 * form byte, an opening frame's request id and ephemeral key, the nonce and
 * the Poly1305 tag.
 */
export const DF_SEALED_FRAME_OVERHEAD =
	1 +
	DF_REQUEST_ID_BYTES +
	DF_NODE_ID_BYTES +
	DF_FRAME_NONCE_BYTES +
	DF_FRAME_TAG_BYTES;

/**
 * Largest sealed frame any lane will carry: the widest message the 4A codec
 * will decode, plus that overhead. A frame past this is refused by name at the
 * lane rather than deep in a transport cipher, and the relay refuses to forward
 * one at all (defect D29: the fork's relay had no size cap).
 */
export const DF_MAX_FRAME_BYTES =
	DF_MAX_MESSAGE_BYTES + DF_SEALED_FRAME_OVERHEAD;

// ─────────────── Subtypes a lane will carry ───────────────

/**
 * The protocol frames a lane delivers. Subtype 20 (`funding_abort`) is
 * reserved and deliberately unimplemented, and 22 is the relay WRAPPER rather
 * than a frame, so neither is here: a lane that handed either to a session
 * handler would be inventing protocol.
 */
export const DF_FRAME_SUBTYPES: ReadonlySet<number> = new Set<number>([
	BeignetCustomSubtype.DIRECT_FUNDING_OFFER,
	BeignetCustomSubtype.DIRECT_FUNDING_OFFER_ACK,
	BeignetCustomSubtype.DIRECT_FUNDING_SIGN_REQUEST,
	BeignetCustomSubtype.DIRECT_FUNDING_WITNESS,
	BeignetCustomSubtype.DIRECT_FUNDING_RECEIPT
]);

// ─────────────── Drops ───────────────

/**
 * Why a frame went nowhere. Rev 2 requires silence on the wire for every one
 * of these, which in the fork meant silence everywhere: seven distinct drop
 * sites with no metric and no log between them (defect D28). Silence stays on
 * the wire; each drop names its reason in the structured log, the way the
 * node's own custom-message decode failures already do.
 */
export enum DfDropReason {
	/** An onion frame whose recipient data did not decrypt to a path_id. */
	NO_PATH_ID = 'no_path_id',
	/** A path_id matching neither a live lane nor an outstanding request. */
	UNKNOWN_PATH_ID = 'unknown_path_id',
	/** The path_id and the sealed frame name different requests. */
	REQUEST_ID_MISMATCH = 'request_id_mismatch',
	/** Nothing to answer on: no reply path and no fixed send path. */
	NO_REPLY_PATH = 'no_reply_path',
	/** The lane's own envelope around the sealed frame did not parse. */
	MALFORMED_BODY = 'malformed_body',
	/** The payload is not a sealed frame at all. */
	NOT_A_SEALED_FRAME = 'not_a_sealed_frame',
	/** A direct-funding subtype this lane does not carry (20 and 22). */
	UNHANDLED_SUBTYPE = 'unhandled_subtype',
	FRAME_TOO_LARGE = 'frame_too_large',
	/** Nothing claimed the frame: no payer lane, no receiver sink attached. */
	NO_LISTENER = 'no_listener',
	/** A send refused: not connected, gated, or over the frame cap. */
	SEND_FAILED = 'send_failed',
	/** A relay wrapper that already carries `from`: never re-forwarded. */
	RELAY_ALREADY_FORWARDED = 'relay_already_forwarded',
	/** An originator wrapper arrived at a node that does not relay. */
	RELAY_NOT_A_SERVER = 'relay_not_a_server',
	/** A relay wrapper addressed to the relay itself or back at its sender. */
	RELAY_SELF_ADDRESSED = 'relay_self_addressed',
	RELAY_TARGET_NOT_CONNECTED = 'relay_target_not_connected',
	RELAY_OVER_BUDGET = 'relay_over_budget',
	/** The forward itself threw: not connected any more, or gated. */
	RELAY_FORWARD_FAILED = 'relay_forward_failed',
	MALFORMED_RELAY_FRAME = 'malformed_relay_frame',
	/** A subscriber threw. It never takes the lane or the peer down. */
	HANDLER_FAILED = 'handler_failed'
}

/** Why the registry moved past a descriptor without running an exchange. */
export enum DfLaneSkipReason {
	/** No lane claims this descriptor type. Skipped, never an error. */
	UNKNOWN_TYPE = 'unknown_transport_type',
	DISABLED = 'lane_disabled',
	/** The loader threw: an optional dependency is not installed. */
	MODULE_UNAVAILABLE = 'lane_module_unavailable',
	/** Connection establishment failed. The ONLY fall-through rev 2 allows. */
	NOT_ESTABLISHED = 'lane_not_established',
	/** The exchange failed before either side had put a frame on the lane. */
	NO_FRAME_EXCHANGED = 'no_frame_exchanged'
}

/** Structured-log sink. 4D maps this onto the node's `emitStructuredLog`. */
export type DfTransportLog = (
	action: string,
	data: Record<string, unknown>
) => void;

export const DF_LOG_FRAME_DROPPED = 'df_frame_dropped';
export const DF_LOG_LANE_SKIPPED = 'df_lane_skipped';

// ─────────────── Frames in and out ───────────────

/** Somewhere to put one sealed frame. */
export interface IDfLaneSender {
	readonly type: number;
	/**
	 * Emit one frame. Throws when the lane cannot carry it, which for a payer's
	 * FIRST frame is what tells the registry the lane never got established.
	 */
	send(subtype: number, payload: Buffer): void;
	/**
	 * Emit one frame, reporting failure instead of throwing. Every send driven
	 * by a timer goes through this: the fork's offer resend fired from a bare
	 * `setTimeout` straight into a send that throws `Not connected to peer`,
	 * which is an uncaughtException with no caller to catch it (defect D2).
	 */
	trySend(subtype: number, payload: Buffer): boolean;
}

/** One sealed frame as a lane delivers it. */
export interface IDfInboundFrame {
	readonly type: number;
	/**
	 * Stable for the duration of one counterparty relationship on this lane:
	 * the peer pubkey, the blinded path_id, or `relay:origin`. A consumer keys
	 * its sessions on it, because a continuation frame carries no request id.
	 */
	readonly laneKey: string;
	subtype: number;
	/** The sealed frame, exactly as it arrived. */
	payload: Buffer;
	/** Answer the counterparty on the lane the frame arrived on. */
	reply: IDfLaneSender;
	/**
	 * The peer whose authenticated Noise connection carried this frame. The
	 * direct-peer lane is the ONLY one that sets it, because it is the only one
	 * where the transport itself proves who the payer is. 4C's zero-conf
	 * decision reads this and nothing else.
	 */
	authenticatedPeer?: string;
	/**
	 * The origin a relay stamped on a forwarded frame. Deliberately NOT
	 * `authenticatedPeer`: it authenticates the RELAY, not the payer, so it can
	 * never stand in for pairing (rev 2, delegated zero-conf).
	 */
	relayAssertedFrom?: string;
	/**
	 * The request this lane is bound to, when the lane knows: the onion lane
	 * resolves it from the path_id. A consumer must refuse a frame that opens
	 * under a different request.
	 */
	boundRequestId?: Buffer;
}

export type DfFrameHandler = (frame: IDfInboundFrame) => void;

/** A duplex lane a payer opened toward a receiver. */
export interface IDfTransport extends IDfLaneSender {
	/** Subscribe to inbound frames; the return value unsubscribes. */
	onMessage(cb: DfFrameHandler): () => void;
	/**
	 * Frames put on the wire in either direction. Zero means the lane never
	 * carried anything, which is the only state rev 2 lets the registry fall
	 * through from.
	 */
	framesExchanged(): number;
	/** Release every listener, timer and registry entry this lane holds. */
	close(): void;
}

// ─────────────── The node surface a lane needs ───────────────

/** The `custom-message` event payload (issue #546). */
export interface IDfCustomMessage {
	peerPubkey: string;
	subtype: number;
	payload: Buffer;
}

/**
 * The narrow slice of the node the peer-carried lanes need, declared here
 * rather than imported whole so a lane can be driven by a stub in tests (the
 * shape 3A established with IJitManagerDeps).
 *
 * Every method here routes through `PeerManager`, so the recovery gates apply
 * without a lane doing anything: the outbound gate refuses inside `sendToPeer`,
 * the connection gate inside `connectPeer`, and the inbound gate drops before
 * `handlePeerMessage` ever emits `custom-message`. No lane may reach the wire
 * by another road.
 */
export interface IDfPeerMessaging {
	/** Our own node id, hex. */
	nodeIdHex(): string;
	sendCustomMessage(
		peerPubkeyHex: string,
		subtype: number,
		payload: Buffer
	): void;
	/** Subscribe to inbound custom messages; the return value unsubscribes. */
	onCustomMessage(cb: (msg: IDfCustomMessage) => void): () => void;
	isPeerConnected(peerPubkeyHex: string): boolean;
	connectPeer(peerPubkeyHex: string, host: string, port: number): Promise<void>;
}

// ─────────────── The registry seam ───────────────

/** What a payer knows about the exchange it is opening a lane for. */
export interface IDfOpenContext {
	/** The request being paid. Binds an onion path claim to it. */
	requestId: Buffer;
	/** The receiver named by the envelope. */
	receiverNodeId: Buffer;
}

/**
 * One lane implementation. `open` is the payer half and `attachInbound` the
 * receiver half; a lane may implement either or both.
 */
export interface IDfLaneFactory {
	readonly type: number;
	/**
	 * Open a lane toward this descriptor, or return null when the connection
	 * could not be established. Null (and a throw, which the registry treats
	 * the same way, since neither has put a frame on the wire) is the only
	 * thing that lets the registry try a later descriptor.
	 */
	open(
		descriptor: DfTransportDescriptor,
		ctx: IDfOpenContext
	): Promise<IDfTransport | null>;
	/**
	 * Route inbound frames nobody opened a lane for into `sink`. Returns the
	 * detach. Called once by the registry, whatever the lane count.
	 */
	attachInbound(sink: DfFrameHandler): () => void;
	/** Drop every listener and handler registration. */
	destroy?(): void;
}

/**
 * How a lane joins the registry. The loader is the seam #533 needs: a lane
 * behind an optional npm dependency stays unimported until a descriptor for it
 * is actually selected, and a loader that throws takes only its own type out of
 * service.
 */
export interface IDfLaneRegistration {
	type: DfTransportType | number;
	/** Config gate. A disabled lane is never loaded, let alone imported. */
	enabled: boolean;
	load: () => IDfLaneFactory | Promise<IDfLaneFactory>;
}

/** Frame budget and size cap for a node acting as a blind relay (D29). */
export interface IDfRelayServerConfig {
	/** Frames one peer may hand the relay per second, sustained. */
	maxFramesPerSecond?: number;
	/** Burst multiplier over that rate; the bucket holds rate * this. */
	burstMultiplier?: number;
	/** Largest sealed frame the relay will forward. */
	maxFrameBytes?: number;
}

/** Which lanes this node runs, and how. 4D reads these from config. */
export interface IDfTransportConfig {
	directPeer?: boolean;
	onion?: boolean;
	relay?: boolean;
	/** Relaying for OTHERS is separate operator opt-in (BEIGNET_DF_RELAY). */
	relayServer?: boolean;
	relayServerConfig?: IDfRelayServerConfig;
}
