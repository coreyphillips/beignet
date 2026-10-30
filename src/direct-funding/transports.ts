import { DfTransportRegistry } from '../lightning/direct-funding/transport/registry';
import { DfDirectPeerLaneFactory } from '../lightning/direct-funding/transport/direct-peer';
import { DfRelayLaneFactory } from '../lightning/direct-funding/transport/relay';
import { DfTransportType } from '../lightning/direct-funding/types';
import type {
	DfTransportLog,
	IDfPeerMessaging
} from '../lightning/direct-funding/transport/types';

/** Direct peer and LSP relay lanes. The caller owns the peer connection lifecycle. */
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
		load: () => new DfDirectPeerLaneFactory(peers, log)
	});
	registry.register({
		type: DfTransportType.LSP_RELAY,
		enabled: true,
		load: () => new DfRelayLaneFactory(peers, log)
	});
	return registry;
}
