/**
 * Inbound routing for the two peer-carried lanes.
 *
 * A node runs both roles at once: it pays requests and it serves its own. The
 * frames are indistinguishable at the transport, so something has to decide
 * whether an arriving frame belongs to a payer session or is a fresh offer.
 *
 * The discriminator is the frame itself. An opening frame names its request in
 * the clear (4A `decodeSealedFrame`), so it routes to the payer lane bound to
 * that request, or, when no lane is, to the receiver sink. A continuation frame
 * names nothing, so it goes to every payer lane holding the counterparty key AND
 * to the sink; the seal sorts out whose it was, and whoever cannot open it drops
 * it.
 *
 * The lifecycle rule is the fix for defect D21. The fork's onion dispatcher
 * inserted a lane entry unconditionally and deleted it only when the last
 * callback unsubscribed, so every decline path that created a lane and returned
 * without subscribing left a permanent empty entry, keyed by peer, growable by
 * any peer that sent a declinable offer. Here a claim exists only between
 * `claim()` and the returned release, and the registry releases in a `finally`.
 */

import { IDfInboundFrame, DfFrameHandler } from './types';

interface IDfLaneClaim {
	/** Hex request id this lane is paying. */
	requestIdHex: string;
	deliver: DfFrameHandler;
}

export class DfLaneTable {
	private readonly claims = new Map<string, IDfLaneClaim[]>();
	private readonly sinks = new Set<DfFrameHandler>();

	/** Bind a payer lane to (counterparty key, request). Returns the release. */
	claim(
		laneKey: string,
		requestIdHex: string,
		deliver: DfFrameHandler
	): () => void {
		const claim: IDfLaneClaim = { requestIdHex, deliver };
		const existing = this.claims.get(laneKey);
		if (existing) existing.push(claim);
		else this.claims.set(laneKey, [claim]);
		return () => {
			const list = this.claims.get(laneKey);
			if (!list) return;
			const i = list.indexOf(claim);
			if (i >= 0) list.splice(i, 1);
			// Reaped here, not on the next arrival: an empty list is the entry
			// the fork leaked.
			if (list.length === 0) this.claims.delete(laneKey);
		};
	}

	/** Register a receiver sink. Returns the detach. */
	attach(sink: DfFrameHandler): () => void {
		this.sinks.add(sink);
		return () => {
			this.sinks.delete(sink);
		};
	}

	/**
	 * Everything that should see this frame. Empty means nothing wanted it,
	 * which the caller reports as a drop rather than passing over in silence.
	 */
	route(laneKey: string, declaredRequestIdHex?: string): DfFrameHandler[] {
		const claims = this.claims.get(laneKey) ?? [];
		if (declaredRequestIdHex !== undefined) {
			const owner = claims.filter(
				(c) => c.requestIdHex === declaredRequestIdHex
			);
			// An opening frame for a request we are not paying is somebody
			// offering to pay US, whatever else is open with this counterparty.
			if (owner.length > 0) return owner.map((c) => c.deliver);
			return [...this.sinks];
		}
		// Both roles can be live with one counterparty, and a continuation names
		// nothing that would separate them, so every holder of the key gets a
		// look. Whoever cannot open the seal drops it.
		return [...claims.map((c) => c.deliver), ...this.sinks];
	}

	clear(): void {
		this.claims.clear();
		this.sinks.clear();
	}

	/** Live payer claims, for tests that assert nothing leaked. */
	get claimCount(): number {
		let total = 0;
		for (const list of this.claims.values()) total += list.length;
		return total;
	}

	/** Distinct counterparty keys holding a claim. */
	get keyCount(): number {
		return this.claims.size;
	}
}

/**
 * Hand a frame to each subscriber in isolation. A throwing application
 * observer never takes down the lane or the peer connection: the node's own
 * custom-message dispatch makes the same promise and would otherwise lose the
 * connection to a bug in a listener registered after ours.
 */
export function deliverIsolated(
	handlers: DfFrameHandler[],
	frame: IDfInboundFrame,
	onHandlerError: (err: unknown) => void
): void {
	for (const handler of handlers) {
		try {
			handler(frame);
		} catch (err) {
			onHandlerError(err);
		}
	}
}
