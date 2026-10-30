import { DfTransportRegistry } from '../lightning/direct-funding/transport/registry';
import { DfDirectPeerLaneFactory } from '../lightning/direct-funding/transport/direct-peer';
import { DfRelayLaneFactory } from '../lightning/direct-funding/transport/relay';
import { DfTransportType } from '../lightning/direct-funding/types';
import type {
	DfTransportDescriptor,
	IDfRelayTransport
} from '../lightning/direct-funding/types';
import type {
	DfTransportLog,
	IDfLaneFactory,
	IDfOpenContext,
	IDfPeerMessaging,
	IDfTransport
} from '../lightning/direct-funding/transport/types';

/** A peer layer that keeps a connection only while something holds it. */
export interface IDfPeerHolds {
	/** Hold this peer's connection; the returned function ends the hold. */
	holdPeer(peerNodeId: string): () => void;
}

function holdsPeers(
	peers: IDfPeerMessaging
): peers is IDfPeerMessaging & IDfPeerHolds {
	return typeof (peers as Partial<IDfPeerHolds>).holdPeer === 'function';
}

/** Hold the peer a lane dials from before its dial until the lane closes. */
function holding(
	factory: IDfLaneFactory,
	peers: IDfPeerHolds,
	peerFor: (descriptor: DfTransportDescriptor, ctx: IDfOpenContext) => string
): IDfLaneFactory {
	return {
		type: factory.type,
		async open(descriptor, ctx): Promise<IDfTransport | null> {
			if (descriptor.type !== factory.type)
				return factory.open(descriptor, ctx);
			const release = peers.holdPeer(peerFor(descriptor, ctx));
			let lane: IDfTransport | null;
			try {
				lane = await factory.open(descriptor, ctx);
			} catch (err) {
				release();
				throw err;
			}
			if (!lane) {
				release();
				return null;
			}
			const close = lane.close.bind(lane);
			lane.close = (): void => {
				close();
				release();
			};
			return lane;
		},
		attachInbound: (sink) => factory.attachInbound(sink),
		destroy: () => factory.destroy?.()
	};
}

/**
 * Direct peer and LSP relay lanes. The caller owns the peer connection lifecycle.
 * With a peer layer that has holdPeer, such as NodePeerMessaging, each lane
 * holds its peer until the lane closes, so connections end with the payments
 * that used them.
 */
export function createPeerTransportRegistry(
	peers: IDfPeerMessaging,
	log?: DfTransportLog
): DfTransportRegistry {
	const registry = new DfTransportRegistry(log, {
		nodeId: () => Buffer.from(peers.nodeIdHex(), 'hex'),
		isPeerConnected: (id) => peers.isPeerConnected(id),
		connectPeer: (id, host, port, timeout) =>
			peers.connectPeer(id, host, port, timeout, { reconnect: false })
	});
	registry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: true,
		load: () => {
			const factory = new DfDirectPeerLaneFactory(peers, log);
			return holdsPeers(peers)
				? holding(factory, peers, (_, ctx) =>
						ctx.receiverNodeId.toString('hex')
				  )
				: factory;
		}
	});
	registry.register({
		type: DfTransportType.LSP_RELAY,
		enabled: true,
		load: () => {
			const factory = new DfRelayLaneFactory(peers, log);
			return holdsPeers(peers)
				? holding(factory, peers, (descriptor) =>
						(descriptor as IDfRelayTransport).relayNodeId.toString('hex')
				  )
				: factory;
		}
	});
	return registry;
}
