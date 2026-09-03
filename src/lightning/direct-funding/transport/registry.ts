/**
 * The transport registry: lane selection, and the seam #533 registers into.
 *
 * This file imports NO lane. Lanes arrive through `register`, each with a
 * config gate and a loader that is called at most once and only when a
 * descriptor of its type is actually selected. That is what makes an optional
 * lane optional: a build without the dependency loads, serves every other lane,
 * and skips the missing one by name.
 *
 * Two rules from rev 2 live here rather than in the caller, because a caller
 * that gets either wrong loses money rather than a connection:
 *
 *  - Only connection-establishment failures fall through to a later
 *    descriptor. Once any frame has been put on a lane, that lane owns the
 *    exchange: re-running it elsewhere would offer the same coin twice.
 *  - A descriptor type nobody claims is SKIPPED, by its length prefix, not
 *    treated as an error. Type 4 is exactly that until #533 lands.
 */

import {
	DfTransportDescriptor,
	DfTransportType,
	DirectFundingError,
	DirectFundingErrorCode,
	IDfOnionTransport,
	IDfRelayTransport
} from '../types';
import {
	DF_LOG_LANE_SKIPPED,
	DfFrameHandler,
	DfLaneSkipReason,
	DfTransportLog,
	IDfLaneFactory,
	IDfLaneRegistration,
	IDfOpenContext,
	IDfTransport
} from './types';

/** A registration plus whatever its loader has produced so far. */
interface IResolvedRegistration extends IDfLaneRegistration {
	factory?: IDfLaneFactory;
	/**
	 * The load in flight. Recorded before the first await, so two first uses
	 * that overlap share one factory: a second one would install a second set of
	 * listeners, and `destroy` could only ever reach the last one stored.
	 */
	loading?: Promise<IDfLaneFactory>;
	/** Set once the loader has thrown; it is never called a second time. */
	unavailable?: boolean;
}

/**
 * What the registry may ask about the node it runs in. Both are optional so
 * the registry stays constructible bare (tests, the swarm plugin seam).
 */
export interface IDfRegistryPeerView {
	/** Is the payer already connected to this node id (hex)? */
	isPeerConnected?(peerPubkeyHex: string): boolean;
	/** This node's own id, to recognise a relay descriptor naming itself. */
	nodeId?(): Buffer;
}

export class DfTransportRegistry {
	private readonly lanes = new Map<number, IResolvedRegistration>();

	constructor(
		private readonly log: DfTransportLog = (): void => undefined,
		private readonly peerView: IDfRegistryPeerView = {}
	) {}

	/** Register a lane. A second registration of a type replaces the first. */
	register(registration: IDfLaneRegistration): void {
		this.lanes.set(registration.type, { ...registration });
	}

	/** Whether a lane of this type is registered and switched on. */
	isEnabled(type: number): boolean {
		return this.lanes.get(type)?.enabled === true;
	}

	/** Registered and enabled types, in registration order. */
	enabledTypes(): number[] {
		return [...this.lanes.values()].filter((r) => r.enabled).map((r) => r.type);
	}

	/**
	 * Attach every enabled lane's receiving side to one sink and return a
	 * single detach. A lane whose loader throws is logged and skipped; the
	 * others still serve, which is the whole point of the loader.
	 */
	async attachInbound(sink: DfFrameHandler): Promise<() => void> {
		const detachers: Array<() => void> = [];
		for (const registration of this.lanes.values()) {
			if (!registration.enabled) continue;
			const factory = await this.resolve(registration);
			if (!factory) continue;
			detachers.push(factory.attachInbound(sink));
		}
		return () => {
			for (const detach of detachers) detach();
		};
	}

	/** Drop every loaded lane's registrations. */
	destroy(): void {
		for (const registration of this.lanes.values()) {
			registration.factory?.destroy?.();
		}
	}

	/**
	 * Walk the receiver's descriptors in ITS stated order, open the first lane
	 * that establishes, and run the exchange on it. The lane is closed when the
	 * exchange settles, so nothing survives this call.
	 *
	 * A later descriptor is tried only when nothing was exchanged: either the
	 * lane never opened, or it opened and `exchange` failed before either side
	 * had put a frame on it. Any failure after the first frame belongs to that
	 * lane and propagates.
	 */
	async run<T>(
		transports: readonly DfTransportDescriptor[],
		ctx: IDfOpenContext,
		exchange: (lane: IDfTransport) => Promise<T>
	): Promise<T> {
		let attempted = 0;
		const self = this.peerView.nodeId?.();
		for (const descriptor of this.withExistingConnection(
			withSynthesizedRelay(transports),
			ctx
		)) {
			// A relay descriptor naming the payer's own node is the ordinary case
			// for a home node paying its own lightning-first wallets (it IS their
			// relay). Dialing it meant two minutes of the node resetting its own
			// connection before EXCHANGE_TIMEOUT; there is nothing to relay through.
			if (
				descriptor.type === DfTransportType.LSP_RELAY &&
				self &&
				(descriptor as IDfRelayTransport).relayNodeId.equals(self)
			) {
				this.skip(descriptor.type, DfLaneSkipReason.SELF_RELAY);
				continue;
			}
			const registration = this.lanes.get(descriptor.type);
			if (!registration) {
				this.skip(descriptor.type, DfLaneSkipReason.UNKNOWN_TYPE);
				continue;
			}
			if (!registration.enabled) {
				this.skip(descriptor.type, DfLaneSkipReason.DISABLED);
				continue;
			}
			const factory = await this.resolve(registration);
			if (!factory) continue;

			let lane: IDfTransport | null = null;
			try {
				lane = await factory.open(descriptor, ctx);
			} catch (err) {
				// A throw out of open() and a null return mean the same thing:
				// nothing reached the wire, so trying the next descriptor cannot
				// duplicate an exchange.
				this.skip(descriptor.type, DfLaneSkipReason.NOT_ESTABLISHED, {
					error: errorText(err)
				});
				continue;
			}
			if (!lane) {
				this.skip(descriptor.type, DfLaneSkipReason.NOT_ESTABLISHED);
				continue;
			}
			attempted++;
			try {
				return await exchange(lane);
			} catch (err) {
				if (lane.framesExchanged() > 0) throw err;
				this.skip(descriptor.type, DfLaneSkipReason.NO_FRAME_EXCHANGED, {
					error: errorText(err)
				});
			} finally {
				lane.close();
			}
		}
		throw new DirectFundingError(
			DirectFundingErrorCode.UNREACHABLE,
			attempted === 0
				? 'no usable transport in the payment request'
				: 'every transport in the payment request failed to carry a frame'
		);
	}

	// ─────────────── Internals ───────────────

	/** Load a lane at most once, and at most once more after a failure never. */
	private async resolve(
		registration: IResolvedRegistration
	): Promise<IDfLaneFactory | null> {
		if (registration.factory) return registration.factory;
		if (registration.unavailable) return null;
		if (!registration.loading) {
			// Through a promise rather than a bare call, so a loader that throws
			// synchronously fails the same way an async one does.
			registration.loading = (async () => registration.load())();
		}
		try {
			registration.factory = await registration.loading;
		} catch (err) {
			registration.unavailable = true;
			this.skip(registration.type, DfLaneSkipReason.MODULE_UNAVAILABLE, {
				error: errorText(err)
			});
			return null;
		}
		return registration.factory;
	}

	/**
	 * A connection the payer already holds to the receiver is the best lane
	 * there is, whatever the receiver published: it needs no dial, no relay
	 * and no onion path. When one exists and the receiver listed no direct
	 * descriptor (a wallet with no address to advertise), a direct descriptor
	 * is tried FIRST. The direct lane's open() never dials a connected peer,
	 * so the placeholder address is never used; should the connection drop in
	 * between, the dial fails and the receiver's own descriptors follow.
	 */
	private withExistingConnection(
		ordered: DfTransportDescriptor[],
		ctx: IDfOpenContext
	): DfTransportDescriptor[] {
		if (ordered.some((t) => t.type === DfTransportType.DIRECT_PEER)) {
			return ordered;
		}
		const direct = this.lanes.get(DfTransportType.DIRECT_PEER);
		if (!direct?.enabled) return ordered;
		const connected = this.peerView.isPeerConnected?.(
			ctx.receiverNodeId.toString('hex')
		);
		if (!connected) return ordered;
		return [
			{ type: DfTransportType.DIRECT_PEER, host: '', port: 0 },
			...ordered
		];
	}

	private skip(
		type: number,
		reason: DfLaneSkipReason,
		extra: Record<string, unknown> = {}
	): void {
		try {
			this.log(DF_LOG_LANE_SKIPPED, { transportType: type, reason, ...extra });
		} catch {
			// A throwing log observer must not abandon a payment.
		}
	}
}

function errorText(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

/**
 * The receiver's descriptors, plus a relay descriptor synthesized from the
 * onion introduction node when it published an onion transport and no relay.
 *
 * A single LSP that is both the blinded path's introduction node and the blind
 * relay only has to appear once in the envelope, which is what keeps a request
 * inside a scannable QR. The synthesized descriptor goes LAST: the receiver did
 * not state it, so it cannot claim a position in the receiver's preference
 * order.
 */
export function withSynthesizedRelay(
	transports: readonly DfTransportDescriptor[]
): DfTransportDescriptor[] {
	const ordered = [...transports];
	if (ordered.some((t) => t.type === DfTransportType.LSP_RELAY)) return ordered;
	const onion = ordered.find(
		(t) => t.type === DfTransportType.ONION_MESSAGE
	) as IDfOnionTransport | undefined;
	if (!onion) return ordered;
	const synthesized: IDfRelayTransport = {
		type: DfTransportType.LSP_RELAY,
		relayNodeId: onion.introNodeId,
		host: onion.host,
		port: onion.port
	};
	ordered.push(synthesized);
	return ordered;
}
