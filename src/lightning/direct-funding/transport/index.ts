/**
 * Direct-funding transports (issue #611, LFBW port #532 workstream 4B): the
 * lane registry and the three lanes that ship with it.
 *
 * `createDirectFundingTransports` is the composition root 4D calls. Note what
 * it does NOT do: it never hands the registry a constructed factory, only a
 * loader. A lane behind an optional dependency (the rendezvous transport
 * deferred to #533, reserved as descriptor type 4) registers the same way and
 * stays unimported until a descriptor selects it, so a build without that
 * dependency loads and serves every other lane. That is the whole seam #533
 * needs, and it needs nothing else from core.
 */

import { OnionMessageManager } from '../../onion-message/manager';
import { DfTransportType } from '../types';
import { DfDirectPeerLaneFactory } from './direct-peer';
import { DfOnionLaneFactory } from './onion';
import { DfRelayForwarder, DfRelayLaneFactory } from './relay';
import { DfTransportRegistry } from './registry';
import { DfTransportLog, IDfPeerMessaging, IDfTransportConfig } from './types';

export { DfTransportRegistry, withSynthesizedRelay } from './registry';
export { DfDirectPeerLaneFactory } from './direct-peer';
export {
	DF_ONION_TLV,
	DfOnionLaneFactory,
	blindedPathFromDescriptor,
	decodeDfOnionBody,
	encodeDfOnionBody,
	mintDfBlindedPath
} from './onion';
export type { IDfOnionLaneDeps } from './onion';
export {
	DF_RELAY_DEFAULTS,
	DF_RELAY_MAX_FRAME_BYTES,
	DF_RELAY_WRAPPER_OVERHEAD,
	DfRelayForwarder,
	DfRelayLaneFactory,
	laneKeyFor
} from './relay';
export { DfLaneTable, deliverIsolated } from './lane-table';
export {
	DF_FRAME_SUBTYPES,
	DF_LOG_FRAME_DROPPED,
	DF_LOG_LANE_SKIPPED,
	DF_MAX_FRAME_BYTES,
	DF_SEALED_FRAME_OVERHEAD,
	DfDropReason,
	DfLaneSkipReason
} from './types';
export type {
	DfFrameHandler,
	DfTransportLog,
	IDfCustomMessage,
	IDfInboundFrame,
	IDfLaneFactory,
	IDfLaneRegistration,
	IDfLaneSender,
	IDfOpenContext,
	IDfPeerMessaging,
	IDfRelayServerConfig,
	IDfTransport,
	IDfTransportConfig
} from './types';

export interface IDfTransportDeps {
	peers: IDfPeerMessaging;
	/** This node's own id. */
	nodeId(): Buffer;
	/** Present only when the node runs onion messaging. */
	onionManager?: OnionMessageManager;
	/**
	 * Resolve a blinded path secret to the request it was minted for.
	 * `DirectFundingRequestStore.byOnionPathSecret` in production.
	 */
	resolvePathSecret?(pathSecretHex: string): string | null;
}

export interface IDfTransportStack {
	registry: DfTransportRegistry;
	/** Constructed only when the operator opted into relaying for others. */
	forwarder: DfRelayForwarder | null;
}

/**
 * Build the registry and register the built-in lanes. Every lane is gated by
 * config and produced by a loader; a disabled lane is never constructed.
 */
export function createDirectFundingTransports(
	deps: IDfTransportDeps,
	config: IDfTransportConfig = {},
	log: DfTransportLog = (): void => undefined
): IDfTransportStack {
	const registry = new DfTransportRegistry(log);

	registry.register({
		type: DfTransportType.DIRECT_PEER,
		enabled: config.directPeer !== false,
		load: () => new DfDirectPeerLaneFactory(deps.peers, log)
	});

	const onionManager = deps.onionManager;
	registry.register({
		type: DfTransportType.ONION_MESSAGE,
		// Without an onion manager there is no lane to build, so the type is
		// registered disabled rather than left out: a descriptor for it then
		// reports "lane_disabled" instead of "unknown transport type", which is
		// the truthful reason.
		enabled: config.onion !== false && onionManager !== undefined,
		load: () =>
			new DfOnionLaneFactory(
				{
					manager: onionManager as OnionMessageManager,
					peers: deps.peers,
					nodeId: deps.nodeId,
					resolvePathSecret: (hex) => deps.resolvePathSecret?.(hex) ?? null
				},
				log
			)
	});

	registry.register({
		type: DfTransportType.LSP_RELAY,
		enabled: config.relay !== false,
		load: () => new DfRelayLaneFactory(deps.peers, log)
	});

	const forwarder = config.relayServer
		? new DfRelayForwarder(deps.peers, config.relayServerConfig ?? {}, log)
		: null;

	return { registry, forwarder };
}
