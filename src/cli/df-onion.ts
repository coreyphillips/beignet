import * as crypto from 'crypto';
import type { BeignetNode } from './beignet-node';
import type { DfTransport } from './direct-funding';
import type { ISerializedBlindedPath } from './df-envelope';
import { BeignetCustomSubtype } from '../lightning/message/custom';
import {
	IBlindedPath,
	constructBlindedPath
} from '../lightning/onion/blinded-path';

/**
 * Direct-funding frames over BOLT onion messages with blinded paths.
 *
 * The receiver mints a blinded path [LSP, receiver] whose path_id is the
 * request id and signs it into the payment request. A sender routes every
 * sealed frame through that path as an onion message, and includes its OWN
 * blinded reply path [LSP, sender] on each frame, so:
 *
 * - the sender never learns a network address for the receiver, only the
 *   introduction node's;
 * - the receiver never learns the sender's node id or address at all
 *   (frames arrive from the introduction node, authenticated end to end by
 *   the request-key sealing, not by transport identity);
 * - the introduction node forwards fixed-size onions it cannot read and
 *   learns neither endpoint's role in the exchange beyond what forwarding
 *   itself reveals.
 *
 * Frames ride ONE odd TLV in the onion message payload, mirroring the
 * custom-message wire type. Delivery is trusted only when the manager
 * surfaces a path_id, which BOLT 4 authenticates as decrypted recipient
 * data: it proves the frame arrived over a path this node itself issued.
 */

/** Odd TLV type carrying a direct-funding frame in an onion message. */
export const DF_ONION_TLV = 44069;

interface IOnionLane {
	cbs: Array<(subtype: number, payload: Buffer) => void>;
	/** Latest reply path advertised by the counterparty. */
	peerReplyPath?: IBlindedPath;
}

export interface IOnionDfDispatcher {
	lanes: Map<string, IOnionLane>;
	/** Receiver hook: a first frame (offer) on a path id no lane claims. */
	offerSink?: (
		pathIdHex: string,
		sealedOffer: object,
		replyPath?: IBlindedPath
	) => void;
}

const dispatchers = new WeakMap<object, IOnionDfDispatcher>();

/**
 * One TLV handler per node routes all direct-funding onion frames: frames
 * whose path_id matches an open lane are delivered there; an offer on a
 * fresh path id goes to the receiver's offer sink. Frames without a
 * path_id are ignored outright: no verifiable path, no processing.
 */
export function onionDfDispatcher(node: BeignetNode): IOnionDfDispatcher {
	const ln = node.lightningNode;
	const existing = dispatchers.get(ln);
	if (existing) return existing;
	const dispatcher: IOnionDfDispatcher = { lanes: new Map() };
	ln.getOnionMessageManager().registerTlvHandler(
		DF_ONION_TLV,
		(_fromPeer, _tlvType, data, replyPath, pathId) => {
			if (!pathId) return;
			const id = pathId.toString('hex');
			let frame: { t?: number; f?: object };
			try {
				frame = JSON.parse(data.toString('utf8'));
			} catch {
				return;
			}
			if (typeof frame?.t !== 'number' || frame.f === undefined) return;
			const lane = dispatcher.lanes.get(id);
			if (lane) {
				if (replyPath) lane.peerReplyPath = replyPath;
				const payload = Buffer.from(JSON.stringify(frame.f), 'utf8');
				for (const cb of [...lane.cbs]) cb(frame.t, payload);
				return;
			}
			if (frame.t === BeignetCustomSubtype.DIRECT_FUNDING_OFFER) {
				dispatcher.offerSink?.(id, frame.f, replyPath);
			}
		}
	);
	dispatchers.set(ln, dispatcher);
	return dispatcher;
}

/**
 * A duplex direct-funding lane over onion messages. The sender's lane sends
 * on the fixed path from the payment request and advertises its own reply
 * path on every frame; the receiver's lane sends on whatever reply path the
 * counterparty last advertised.
 */
export function createOnionLane(
	node: BeignetNode,
	dispatcher: IOnionDfDispatcher,
	localPathIdHex: string,
	opts: {
		sendPath?: IBlindedPath;
		initialPeerReplyPath?: IBlindedPath;
		includeReplyPath?: IBlindedPath;
	}
): DfTransport {
	const lane: IOnionLane = dispatcher.lanes.get(localPathIdHex) ?? {
		cbs: [],
		peerReplyPath: opts.initialPeerReplyPath
	};
	dispatcher.lanes.set(localPathIdHex, lane);
	return {
		send: (subtype, payload) => {
			const path = opts.sendPath ?? lane.peerReplyPath;
			if (!path) {
				throw new Error('no onion path to reach the counterparty');
			}
			node.lightningNode.getOnionMessageManager().sendReply(
				path,
				new Map([
					[
						DF_ONION_TLV,
						Buffer.from(JSON.stringify({ t: subtype, f: payload }), 'utf8')
					]
				]),
				opts.includeReplyPath ? { replyPath: opts.includeReplyPath } : undefined
			);
		},
		onMessage: (cb) => {
			lane.cbs.push(cb);
			return () => {
				const i = lane.cbs.indexOf(cb);
				if (i >= 0) lane.cbs.splice(i, 1);
				if (lane.cbs.length === 0) dispatcher.lanes.delete(localPathIdHex);
			};
		}
	};
}

/**
 * Mint a two-hop blinded path [via, self] whose final hop carries pathId.
 * The path names only the via node in the clear; the self hop appears as a
 * blinded id nobody can link to the real node key.
 */
export function mintDfBlindedPath(
	viaNodeIdHex: string,
	selfNodeIdHex: string,
	pathIdHex: string
): IBlindedPath {
	const self = Buffer.from(selfNodeIdHex, 'hex');
	return constructBlindedPath(
		crypto.randomBytes(32),
		[Buffer.from(viaNodeIdHex, 'hex'), self],
		[{ nextNodeId: self }, { pathId: Buffer.from(pathIdHex, 'hex') }]
	);
}

export function serializeBlindedPath(p: IBlindedPath): ISerializedBlindedPath {
	return {
		intro: p.introductionNodeId.toString('hex'),
		blinding: p.blindingPoint.toString('hex'),
		hops: p.blindedHops.map((h) => ({
			id: h.blindedNodeId.toString('hex'),
			data: h.encryptedData.toString('hex')
		}))
	};
}

export function deserializeBlindedPath(
	sp: ISerializedBlindedPath
): IBlindedPath {
	if (
		!/^[0-9a-f]{66}$/.test(sp?.intro ?? '') ||
		!/^[0-9a-f]{66}$/.test(sp?.blinding ?? '') ||
		!Array.isArray(sp.hops) ||
		sp.hops.length === 0
	) {
		throw new Error('malformed blinded path');
	}
	return {
		introductionNodeId: Buffer.from(sp.intro, 'hex'),
		blindingPoint: Buffer.from(sp.blinding, 'hex'),
		blindedHops: sp.hops.map((h) => ({
			blindedNodeId: Buffer.from(h.id, 'hex'),
			encryptedData: Buffer.from(h.data, 'hex')
		}))
	};
}
