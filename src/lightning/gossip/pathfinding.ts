/**
 * BOLT 7: Pathfinding — Dijkstra-based route computation.
 *
 * Searches backwards from destination to source (standard Lightning approach)
 * since fees accumulate at each hop. Minimizes total cost to the sender.
 */

import {
	IGraphChannel,
	IRoute,
	IRouteHop,
	CHANNEL_FLAG_DISABLED,
	MESSAGE_FLAG_HTLC_MAX,
	DEFAULT_PRUNE_MAX_AGE
} from './types';
import { NetworkGraph } from './network-graph';
import { MissionControl } from './mission-control';
import { IRoutingHintHop } from '../invoice/types';

/** Default max hops per BOLT 4. */
const DEFAULT_MAX_HOPS = 20;

/**
 * Per-hop reliability penalty (msat) added to the routing cost for every hop.
 *
 * Pure fee-minimization happily selects very long paths through zero-fee
 * channels (e.g. a 12-hop route costing 50 msat), but each extra hop is an
 * independent point of failure — an offline/illiquid intermediary leaves the
 * HTLC stuck in-flight with no fulfil or fail until it times out. This penalty
 * biases pathfinding toward shorter, more reliable routes: a longer path is
 * only chosen when it is cheaper by more than HOP_PENALTY_MSAT per extra hop.
 * It affects route *selection* only, not the fee actually paid or the maxFee cap.
 */
export const HOP_PENALTY_MSAT = 1000n;

/**
 * Calculate the routing fee for forwarding a given amount.
 * fee = base_msat + (amount_msat * proportional_millionths / 1_000_000)
 */
export function calculateFee(
	amountMsat: bigint,
	feeBaseMsat: number,
	feeProportionalMillionths: number
): bigint {
	return (
		BigInt(feeBaseMsat) +
		(amountMsat * BigInt(feeProportionalMillionths)) / 1_000_000n
	);
}

// ── Priority Queue (min-heap) ───────────────────────────────────────

interface IHeapEntry {
	cost: bigint;
	nodeId: string;
	amountMsat: bigint;
	cltvValue: number;
	hops: number;
}

class MinHeap {
	private _data: IHeapEntry[] = [];

	get size(): number {
		return this._data.length;
	}

	push(entry: IHeapEntry): void {
		this._data.push(entry);
		this._siftUp(this._data.length - 1);
	}

	pop(): IHeapEntry | undefined {
		if (this._data.length === 0) return undefined;
		const top = this._data[0];
		const last = this._data.pop()!;
		if (this._data.length > 0) {
			this._data[0] = last;
			this._siftDown(0);
		}
		return top;
	}

	private _siftUp(i: number): void {
		while (i > 0) {
			const parent = (i - 1) >> 1;
			if (this._data[i].cost < this._data[parent].cost) {
				[this._data[i], this._data[parent]] = [
					this._data[parent],
					this._data[i]
				];
				i = parent;
			} else {
				break;
			}
		}
	}

	private _siftDown(i: number): void {
		const n = this._data.length;
		// eslint-disable-next-line no-constant-condition -- sift loops until it returns
		while (true) {
			let smallest = i;
			const left = 2 * i + 1;
			const right = 2 * i + 2;
			if (left < n && this._data[left].cost < this._data[smallest].cost) {
				smallest = left;
			}
			if (right < n && this._data[right].cost < this._data[smallest].cost) {
				smallest = right;
			}
			if (smallest !== i) {
				[this._data[i], this._data[smallest]] = [
					this._data[smallest],
					this._data[i]
				];
				i = smallest;
			} else {
				break;
			}
		}
	}
}

// ── Routing Hint Helpers ─────────────────────────────────────────────

/**
 * Build a map of synthetic IGraphChannel edges from invoice routing hints.
 * Only creates edges for node/channel pairs NOT already in the gossip graph.
 *
 * Key insight for backward Dijkstra: edges are keyed by the DESTINATION node
 * of each hop (the next node in forward direction), so that when the algorithm
 * visits that node it can find the incoming edge from the upstream hop.
 */
function buildSyntheticEdges(
	hints: IRoutingHintHop[][],
	graph: NetworkGraph,
	destination: Buffer
): Map<string, IGraphChannel[]> {
	const syntheticEdges = new Map<string, IGraphChannel[]>();
	const destHex = destination.toString('hex');

	for (const hintRoute of hints) {
		for (let i = 0; i < hintRoute.length; i++) {
			const hop = hintRoute[i];

			// Skip if this channel is already in the graph
			if (graph.getChannel(hop.shortChannelId)) continue;

			// The destination of this hop (next node in forward direction)
			const nextNodeHex =
				i < hintRoute.length - 1
					? hintRoute[i + 1].pubkey.toString('hex')
					: destHex;

			// Create a synthetic graph channel.
			// nodeId1 = the hop's forwarding pubkey (upstream in backward Dijkstra)
			// The edge is stored under nextNodeHex so it is found when Dijkstra
			// visits the destination-side of this hop working backwards.
			const synthetic: IGraphChannel = {
				shortChannelId: hop.shortChannelId,
				nodeId1: hop.pubkey,
				nodeId2: hop.pubkey, // placeholder — resolved via hintDestMap
				features: Buffer.alloc(0),
				announcement: {} as IGraphChannel['announcement'],
				update1: {
					signature: Buffer.alloc(64),
					chainHash: Buffer.alloc(32),
					shortChannelId: hop.shortChannelId,
					timestamp: Math.floor(Date.now() / 1000),
					messageFlags: MESSAGE_FLAG_HTLC_MAX,
					channelFlags: 0,
					cltvExpiryDelta: hop.cltvExpiryDelta,
					htlcMinimumMsat: 0n,
					feeBaseMsat: hop.feeBaseMsat,
					feeProportionalMillionths: hop.feeProportionalMillionths,
					htlcMaximumMsat: 0xffffffffffffffffn
				},
				update2: {
					signature: Buffer.alloc(64),
					chainHash: Buffer.alloc(32),
					shortChannelId: hop.shortChannelId,
					timestamp: Math.floor(Date.now() / 1000),
					messageFlags: MESSAGE_FLAG_HTLC_MAX,
					channelFlags: 0,
					cltvExpiryDelta: hop.cltvExpiryDelta,
					htlcMinimumMsat: 0n,
					feeBaseMsat: hop.feeBaseMsat,
					feeProportionalMillionths: hop.feeProportionalMillionths,
					htlcMaximumMsat: 0xffffffffffffffffn
				}
			};

			// Index by the destination (next node key) for backward Dijkstra
			const existing = syntheticEdges.get(nextNodeHex) ?? [];
			existing.push(synthetic);
			syntheticEdges.set(nextNodeHex, existing);
		}
	}

	return syntheticEdges;
}

/**
 * Build a map from SCID to the hop pubkey (upstream node in backward Dijkstra).
 * Used to identify synthetic hint edges and resolve the upstream node.
 */
function buildHintDestinationMap(
	hints: IRoutingHintHop[][],
	destination: Buffer
): Map<string, string> {
	const destMap = new Map<string, string>();
	const destHex = destination.toString('hex');

	for (const hintRoute of hints) {
		for (let i = 0; i < hintRoute.length; i++) {
			const hop = hintRoute[i];
			// The node this hop leads to: next hop in the hint, or the final destination
			const nextNodeHex =
				i < hintRoute.length - 1
					? hintRoute[i + 1].pubkey.toString('hex')
					: destHex;
			// Map SCID → nextNode so we know where this hint edge leads
			destMap.set(hop.shortChannelId.toString('hex'), nextNodeHex);
		}
	}

	return destMap;
}

// ── Local Channel Helpers ────────────────────────────────────────────

/**
 * A usable channel owned by the source node. These let pathfinding route over
 * our own channels — most importantly a direct payment to a channel peer —
 * even when the channel is not in the public gossip graph (e.g. private or not
 * yet announced). This matches LND/CLN/LDK, which always route over local
 * channels regardless of announcement.
 */
export interface ILocalChannelEdge {
	/** Short channel ID (real SCID or alias). */
	shortChannelId: Buffer;
	/** The channel peer's node id (the far end of the channel). */
	peer: Buffer;
	/** Spendable outbound capacity in millisatoshis. */
	outboundMsat: bigint;
	/** Minimum HTLC the channel accepts (default 0). */
	htlcMinimumMsat?: bigint;
	/** CLTV delta to apply on our outgoing hop (default 0 — we originate). */
	cltvExpiryDelta?: number;
}

/**
 * Build a synthetic graph edge for a local channel: source → peer. The edge is
 * keyed by the peer (its destination side) for the backward Dijkstra, and its
 * upstream node is the source — resolved via nodeId1 in the destMap branch.
 */
function makeLocalChannelEdge(
	source: Buffer,
	lc: ILocalChannelEdge
): IGraphChannel {
	const update = {
		signature: Buffer.alloc(64),
		chainHash: Buffer.alloc(32),
		shortChannelId: lc.shortChannelId,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: MESSAGE_FLAG_HTLC_MAX,
		channelFlags: 0,
		cltvExpiryDelta: lc.cltvExpiryDelta ?? 0,
		htlcMinimumMsat: lc.htlcMinimumMsat ?? 0n,
		feeBaseMsat: 0, // we never charge ourselves on our own outgoing channel
		feeProportionalMillionths: 0,
		htlcMaximumMsat: lc.outboundMsat
	};
	return {
		shortChannelId: lc.shortChannelId,
		nodeId1: source, // upstream (us) — used when this edge matches the destMap branch
		nodeId2: lc.peer,
		features: Buffer.alloc(0),
		announcement: {} as IGraphChannel['announcement'],
		update1: update,
		update2: update
	};
}

/**
 * Combine routing-hint synthetic edges and local-channel edges into a single
 * overlay (edges keyed by destination-side node, plus a SCID→destination map)
 * that the backward Dijkstra merges with the gossip graph.
 */
function buildEdgeOverlay(
	graph: NetworkGraph,
	source: Buffer,
	destination: Buffer,
	routingHints?: IRoutingHintHop[][],
	localChannels?: ILocalChannelEdge[]
): {
	syntheticEdges: Map<string, IGraphChannel[]>;
	hintDestMap: Map<string, string>;
} {
	const syntheticEdges = new Map<string, IGraphChannel[]>();
	const hintDestMap = new Map<string, string>();

	if (routingHints) {
		for (const [k, v] of buildSyntheticEdges(
			routingHints,
			graph,
			destination
		)) {
			syntheticEdges.set(k, [...(syntheticEdges.get(k) ?? []), ...v]);
		}
		for (const [k, v] of buildHintDestinationMap(routingHints, destination)) {
			hintDestMap.set(k, v);
		}
	}

	if (localChannels) {
		for (const lc of localChannels) {
			// If the channel is already announced, the gossip graph handles it.
			if (graph.getChannel(lc.shortChannelId)) continue;
			const peerHex = lc.peer.toString('hex');
			const edge = makeLocalChannelEdge(source, lc);
			syntheticEdges.set(peerHex, [
				...(syntheticEdges.get(peerHex) ?? []),
				edge
			]);
			hintDestMap.set(lc.shortChannelId.toString('hex'), peerHex);
		}
	}

	return { syntheticEdges, hintDestMap };
}

// ── Route Finding ───────────────────────────────────────────────────

interface IPredecessor {
	channel: IGraphChannel;
	nextNodeId: string;
	amountMsat: bigint;
	cltvValue: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	cltvExpiryDelta: number;
}

/**
 * Find a route from source to destination through the network graph.
 *
 * Uses Dijkstra's algorithm working backwards from destination.
 * Returns null if no path found.
 *
 * @param graph - The network graph
 * @param source - 33-byte source node public key
 * @param destination - 33-byte destination node public key
 * @param amountMsat - Amount to deliver to destination (in millisatoshis)
 * @param finalCltvExpiry - CLTV expiry for the final hop
 * @param maxHops - Maximum number of hops (default 20)
 */
/** Default maximum CLTV lockup budget in blocks (~2 weeks). */
const DEFAULT_MAX_CLTV_EXPIRY = 2016;

export function findRoute(
	graph: NetworkGraph,
	source: Buffer,
	destination: Buffer,
	amountMsat: bigint,
	finalCltvExpiry: number,
	maxHops: number = DEFAULT_MAX_HOPS,
	excludedChannels?: Set<string>,
	missionControl?: MissionControl,
	maxCltvExpiry: number = DEFAULT_MAX_CLTV_EXPIRY,
	routingHints?: IRoutingHintHop[][],
	currentTimestamp?: number,
	localChannels?: ILocalChannelEdge[]
): IRoute | null {
	const sourceHex = source.toString('hex');
	const destHex = destination.toString('hex');

	if (sourceHex === destHex) {
		return null;
	}

	// Overlay edges: routing-hint private channels + our own local channels
	// (so a direct payment to a channel peer routes even when unannounced).
	const { syntheticEdges, hintDestMap } = buildEdgeOverlay(
		graph,
		source,
		destination,
		routingHints,
		localChannels
	);

	// Best known cost to reach each node (working backwards from dest)
	const bestCost = new Map<string, bigint>();
	// Predecessor map: for each node, the channel/info used to reach it
	const predecessors = new Map<string, IPredecessor>();

	const heap = new MinHeap();

	// Seed with destination
	heap.push({
		cost: amountMsat,
		nodeId: destHex,
		amountMsat,
		cltvValue: finalCltvExpiry,
		hops: 0
	});
	bestCost.set(destHex, amountMsat);

	while (heap.size > 0) {
		const current = heap.pop()!;

		// If we already found a better path to this node, skip
		const known = bestCost.get(current.nodeId);
		if (known !== undefined && current.cost > known) {
			continue;
		}

		// Reached source — we're done
		if (current.nodeId === sourceHex) {
			break;
		}

		if (current.hops >= maxHops) {
			continue;
		}

		// Explore all adjacent channels — merge gossip graph + synthetic hint edges
		const nodeIdBuf = Buffer.from(current.nodeId, 'hex');
		const graphChannels = graph.getNodeChannels(nodeIdBuf);
		const hintChannels = syntheticEdges?.get(current.nodeId) ?? [];
		const channels =
			hintChannels.length > 0
				? [...graphChannels, ...hintChannels]
				: graphChannels;

		for (const channel of channels) {
			// Skip excluded channels (used for payment retry)
			if (
				excludedChannels &&
				excludedChannels.has(channel.shortChannelId.toString('hex'))
			) {
				continue;
			}

			// For synthetic hint channels, resolve the upstream node from the hint map
			const scidHex = channel.shortChannelId.toString('hex');
			const hintDest = hintDestMap?.get(scidHex);
			let upstreamNodeHex: string;
			let update: typeof channel.update1;

			if (hintDest !== undefined) {
				// Synthetic hint channel: the hop pubkey is the upstream node
				upstreamNodeHex = channel.nodeId1.toString('hex');
				update = channel.update1;
				// Only use this edge if it leads to the current node
				if (hintDest !== current.nodeId) continue;
			} else {
				const node1Hex = channel.nodeId1.toString('hex');
				const node2Hex = channel.nodeId2.toString('hex');

				// The upstream node is the one that is NOT current
				const isCurrentNode2 = current.nodeId === node2Hex;
				upstreamNodeHex = isCurrentNode2 ? node1Hex : node2Hex;

				// The upstream node uses the update for its direction.
				update = isCurrentNode2 ? channel.update1 : channel.update2;
			}

			if (!update) continue;

			// Skip disabled channels
			if ((update.channelFlags & CHANNEL_FLAG_DISABLED) !== 0) continue;

			// Skip stale channel_updates (>2 weeks old per BOLT 7) — but not synthetic hints
			if (currentTimestamp !== undefined && hintDest === undefined) {
				const staleCutoff = currentTimestamp - DEFAULT_PRUNE_MAX_AGE;
				if (update.timestamp < staleCutoff) continue;
			}

			// Check amount bounds
			if (current.amountMsat < update.htlcMinimumMsat) continue;
			if (
				(update.messageFlags & MESSAGE_FLAG_HTLC_MAX) !== 0 &&
				update.htlcMaximumMsat !== undefined &&
				current.amountMsat > update.htlcMaximumMsat
			) {
				continue;
			}

			// Calculate fee and new amount that upstream must forward
			const fee = calculateFee(
				current.amountMsat,
				update.feeBaseMsat,
				update.feeProportionalMillionths
			);
			const newAmount = current.amountMsat + fee;
			const newCltv = current.cltvValue + update.cltvExpiryDelta;

			// CLTV budget check: prune routes exceeding max lockup (Fix 3.4)
			if (newCltv > maxCltvExpiry) continue;

			const penalty = missionControl
				? missionControl.getPenalty(channel.shortChannelId.toString('hex'))
				: 0n;
			// Accumulate a per-hop penalty so shorter, more reliable routes win.
			const newCost =
				newAmount + penalty + BigInt(current.hops + 1) * HOP_PENALTY_MSAT;

			const existingBest = bestCost.get(upstreamNodeHex);
			if (existingBest !== undefined && newCost >= existingBest) {
				continue;
			}

			bestCost.set(upstreamNodeHex, newCost);
			predecessors.set(upstreamNodeHex, {
				channel,
				nextNodeId: current.nodeId,
				amountMsat: current.amountMsat,
				cltvValue: current.cltvValue,
				feeBaseMsat: update.feeBaseMsat,
				feeProportionalMillionths: update.feeProportionalMillionths,
				cltvExpiryDelta: update.cltvExpiryDelta
			});

			heap.push({
				cost: newCost,
				nodeId: upstreamNodeHex,
				amountMsat: newAmount,
				cltvValue: newCltv,
				hops: current.hops + 1
			});
		}
	}

	// Reconstruct path from source to destination
	if (!predecessors.has(sourceHex)) {
		return null;
	}

	const hops: IRouteHop[] = [];
	let currentNode = sourceHex;

	while (currentNode !== destHex) {
		const pred = predecessors.get(currentNode);
		if (!pred) break;

		const hopNodeHex = pred.nextNodeId;
		// Look ahead: the hop's own forwarding fee comes from its own predecessor entry
		const hopPred = predecessors.get(hopNodeHex);

		hops.push({
			pubkey: Buffer.from(hopNodeHex, 'hex'),
			shortChannelId: Buffer.from(pred.channel.shortChannelId),
			amountToForwardMsat: pred.amountMsat,
			outgoingCltvValue: pred.cltvValue,
			cltvExpiryDelta: pred.cltvExpiryDelta,
			feeBaseMsat: hopPred ? hopPred.feeBaseMsat : 0,
			feeProportionalMillionths: hopPred ? hopPred.feeProportionalMillionths : 0
		});

		currentNode = hopNodeHex;
	}

	if (hops.length === 0) {
		return null;
	}

	// Final CLTV budget check on the reconstructed route (Fix 3.4)
	if (hops.length > 0 && hops[0].outgoingCltvValue > maxCltvExpiry) {
		return null;
	}

	// totalAmountMsat = what the sender sends = what the first hop receives
	// (not bestCost[source] which incorrectly includes the source's own channel fee)
	const totalAmountMsat = hops[0].amountToForwardMsat;
	const totalFeeMsat = totalAmountMsat - amountMsat;

	let totalCltvDelta = 0;
	for (const hop of hops) {
		totalCltvDelta += hop.cltvExpiryDelta;
	}

	return {
		hops,
		totalAmountMsat,
		totalCltvDelta,
		totalFeeMsat
	};
}

// ── Multi-Path Route Finding ────────────────────────────────────────

export interface IMultiPathRoute {
	parts: IRoute[];
	totalAmountMsat: bigint;
	totalFeeMsat: bigint;
}

/**
 * Find multiple paths from source to destination that together deliver the
 * required amount. Iteratively finds single paths, deducting used capacity
 * from each channel to avoid reusing the same liquidity.
 *
 * Returns null if the total deliverable amount across all paths is insufficient.
 */
export function findMultiPathRoute(
	graph: NetworkGraph,
	source: Buffer,
	destination: Buffer,
	amountMsat: bigint,
	finalCltvExpiry: number,
	maxParts = 4,
	maxHops: number = DEFAULT_MAX_HOPS,
	missionControl?: MissionControl,
	routingHints?: IRoutingHintHop[][],
	currentTimestamp?: number,
	localChannels?: ILocalChannelEdge[]
): IMultiPathRoute | null {
	// Track used capacity per SCID to avoid reusing same liquidity
	const usedCapacity = new Map<string, bigint>();
	const parts: IRoute[] = [];
	let remaining = amountMsat;

	for (let i = 0; i < maxParts && remaining > 0n; i++) {
		// Try to route the full remaining amount first
		let route = findRouteWithCapacityLimits(
			graph,
			source,
			destination,
			remaining,
			finalCltvExpiry,
			maxHops,
			usedCapacity,
			missionControl,
			routingHints,
			currentTimestamp,
			localChannels
		);

		// If that fails, try halving the amount until we find a path or give up
		if (!route) {
			let tryAmount = remaining / 2n;
			for (let attempt = 0; attempt < 8 && tryAmount > 0n; attempt++) {
				route = findRouteWithCapacityLimits(
					graph,
					source,
					destination,
					tryAmount,
					finalCltvExpiry,
					maxHops,
					usedCapacity,
					missionControl,
					routingHints,
					currentTimestamp,
					localChannels
				);
				if (route) break;
				tryAmount = tryAmount / 2n;
			}
		}

		if (!route) {
			break;
		}

		// The amount delivered by this path
		const deliveredMsat = route.hops[route.hops.length - 1].amountToForwardMsat;

		// Mark the used capacity on each channel in this route
		for (const hop of route.hops) {
			const scidHex = hop.shortChannelId.toString('hex');
			const current = usedCapacity.get(scidHex) ?? 0n;
			usedCapacity.set(scidHex, current + hop.amountToForwardMsat);
		}

		parts.push(route);
		remaining -= deliveredMsat;
	}

	if (remaining > 0n) {
		return null; // Could not deliver full amount
	}

	let totalAmountMsat = 0n;
	let totalFeeMsat = 0n;
	for (const part of parts) {
		totalAmountMsat += part.totalAmountMsat;
		totalFeeMsat += part.totalFeeMsat;
	}

	return { parts, totalAmountMsat, totalFeeMsat };
}

/**
 * Find a route respecting already-used capacity on channels.
 */
function findRouteWithCapacityLimits(
	graph: NetworkGraph,
	source: Buffer,
	destination: Buffer,
	amountMsat: bigint,
	finalCltvExpiry: number,
	maxHops: number,
	usedCapacity: Map<string, bigint>,
	missionControl?: MissionControl,
	routingHints?: IRoutingHintHop[][],
	currentTimestamp?: number,
	localChannels?: ILocalChannelEdge[]
): IRoute | null {
	const sourceHex = source.toString('hex');
	const destHex = destination.toString('hex');

	if (sourceHex === destHex) return null;

	// Overlay edges: routing-hint private channels + our own local channels.
	const { syntheticEdges, hintDestMap } = buildEdgeOverlay(
		graph,
		source,
		destination,
		routingHints,
		localChannels
	);

	const bestCost = new Map<string, bigint>();
	const predecessors = new Map<string, IPredecessor>();
	const heap = new MinHeap();

	heap.push({
		cost: amountMsat,
		nodeId: destHex,
		amountMsat,
		cltvValue: finalCltvExpiry,
		hops: 0
	});
	bestCost.set(destHex, amountMsat);

	while (heap.size > 0) {
		const current = heap.pop()!;

		const known = bestCost.get(current.nodeId);
		if (known !== undefined && current.cost > known) continue;

		if (current.nodeId === sourceHex) break;
		if (current.hops >= maxHops) continue;

		const nodeIdBuf = Buffer.from(current.nodeId, 'hex');
		const graphChannels = graph.getNodeChannels(nodeIdBuf);
		const hintChannels = syntheticEdges?.get(current.nodeId) ?? [];
		const channels =
			hintChannels.length > 0
				? [...graphChannels, ...hintChannels]
				: graphChannels;

		for (const channel of channels) {
			const scidHex = channel.shortChannelId.toString('hex');
			const hintDest = hintDestMap?.get(scidHex);
			let upstreamNodeHex: string;
			let update: typeof channel.update1;

			if (hintDest !== undefined) {
				upstreamNodeHex = channel.nodeId1.toString('hex');
				update = channel.update1;
				if (hintDest !== current.nodeId) continue;
			} else {
				const node1Hex = channel.nodeId1.toString('hex');
				const node2Hex = channel.nodeId2.toString('hex');
				const isCurrentNode2 = current.nodeId === node2Hex;
				upstreamNodeHex = isCurrentNode2 ? node1Hex : node2Hex;
				update = isCurrentNode2 ? channel.update1 : channel.update2;
			}

			if (!update) continue;
			if ((update.channelFlags & CHANNEL_FLAG_DISABLED) !== 0) continue;

			// Skip stale channel_updates (>2 weeks old per BOLT 7) — but not synthetic hints
			if (currentTimestamp !== undefined && hintDest === undefined) {
				const staleCutoff = currentTimestamp - DEFAULT_PRUNE_MAX_AGE;
				if (update.timestamp < staleCutoff) continue;
			}

			// Check remaining capacity after used amounts
			const used = usedCapacity.get(scidHex) ?? 0n;
			const maxCapacity =
				(update.messageFlags & MESSAGE_FLAG_HTLC_MAX) !== 0 &&
				update.htlcMaximumMsat !== undefined
					? update.htlcMaximumMsat
					: 0xffffffffffffffffn;
			const availableCapacity = maxCapacity > used ? maxCapacity - used : 0n;

			if (current.amountMsat < update.htlcMinimumMsat) continue;
			if (current.amountMsat > availableCapacity) continue;

			const fee = calculateFee(
				current.amountMsat,
				update.feeBaseMsat,
				update.feeProportionalMillionths
			);
			const newAmount = current.amountMsat + fee;
			const newCltv = current.cltvValue + update.cltvExpiryDelta;
			const penalty = missionControl ? missionControl.getPenalty(scidHex) : 0n;
			// Accumulate a per-hop penalty so shorter, more reliable routes win.
			const newCost =
				newAmount + penalty + BigInt(current.hops + 1) * HOP_PENALTY_MSAT;

			const existingBest = bestCost.get(upstreamNodeHex);
			if (existingBest !== undefined && newCost >= existingBest) continue;

			bestCost.set(upstreamNodeHex, newCost);
			predecessors.set(upstreamNodeHex, {
				channel,
				nextNodeId: current.nodeId,
				amountMsat: current.amountMsat,
				cltvValue: current.cltvValue,
				feeBaseMsat: update.feeBaseMsat,
				feeProportionalMillionths: update.feeProportionalMillionths,
				cltvExpiryDelta: update.cltvExpiryDelta
			});

			heap.push({
				cost: newCost,
				nodeId: upstreamNodeHex,
				amountMsat: newAmount,
				cltvValue: newCltv,
				hops: current.hops + 1
			});
		}
	}

	if (!predecessors.has(sourceHex)) return null;

	const hops: IRouteHop[] = [];
	let currentNode = sourceHex;

	while (currentNode !== destHex) {
		const pred = predecessors.get(currentNode);
		if (!pred) break;

		const hopNodeHex = pred.nextNodeId;
		const hopPred = predecessors.get(hopNodeHex);

		hops.push({
			pubkey: Buffer.from(hopNodeHex, 'hex'),
			shortChannelId: Buffer.from(pred.channel.shortChannelId),
			amountToForwardMsat: pred.amountMsat,
			outgoingCltvValue: pred.cltvValue,
			cltvExpiryDelta: pred.cltvExpiryDelta,
			feeBaseMsat: hopPred ? hopPred.feeBaseMsat : 0,
			feeProportionalMillionths: hopPred ? hopPred.feeProportionalMillionths : 0
		});

		currentNode = hopNodeHex;
	}

	if (hops.length === 0) return null;

	const totalAmountMsat = hops[0].amountToForwardMsat;
	const deliveredMsat = hops[hops.length - 1].amountToForwardMsat;
	const totalFeeMsat = totalAmountMsat - deliveredMsat;

	let totalCltvDelta = 0;
	for (const hop of hops) {
		totalCltvDelta += hop.cltvExpiryDelta;
	}

	return { hops, totalAmountMsat, totalCltvDelta, totalFeeMsat };
}

// ── Blinded Path Route Finding ──────────────────────────────────────

import {
	IBlindedPath,
	IBlindedPayInfo
} from '../onion/blinded-path';

/**
 * Find a route from `source` through a blinded path to the recipient.
 *
 * Convention (matches constructBlindedPath): blindedHops[0] corresponds to the
 * introduction node itself, blindedHops[1..] to the subsequent blinded hops,
 * and the last entry is the recipient. So we route normally to the introduction
 * node, attach its encrypted_recipient_data + the path's blinding_point to that
 * hop, then append the remaining blinded hops carrying only their encrypted
 * data (each derives its own blinding point downstream).
 *
 * The blinded section's aggregate fee/CLTV (payInfo) is paid at the
 * introduction node: we route `amountMsat + blindedFee` to it with
 * `finalCltvExpiry + payInfo.cltvExpiryDelta` of headroom, and the recipient
 * still receives exactly `amountMsat`.
 *
 * @param graph - The network graph
 * @param source - 33-byte source node public key
 * @param blindedPath - The blinded path to route through
 * @param payInfo - Aggregate pay parameters advertised for the blinded path
 * @param amountMsat - Amount to deliver to the recipient (in millisatoshis)
 * @param finalCltvExpiry - CLTV expiry delta for the final hop
 * @param maxHops - Maximum number of hops (default 20)
 * @returns Combined route or null if no path to introduction node
 */
export function findRouteToBlindedPath(
	graph: NetworkGraph,
	source: Buffer,
	blindedPath: IBlindedPath,
	payInfo: IBlindedPayInfo,
	amountMsat: bigint,
	finalCltvExpiry: number,
	maxHops: number = DEFAULT_MAX_HOPS,
	excludedChannels?: Set<string>,
	missionControl?: MissionControl,
	localChannels?: ILocalChannelEdge[]
): IRoute | null {
	const hops = blindedPath.blindedHops;
	if (hops.length === 0) return null;

	// Aggregate fee charged across the blinded section, paid at the intro node.
	const blindedFeeMsat =
		BigInt(payInfo.feeBaseMsat) +
		(amountMsat * BigInt(payInfo.feeProportionalMillionths)) / 1_000_000n;
	const amountAtIntro = amountMsat + blindedFeeMsat;
	const cltvAtIntro = finalCltvExpiry + payInfo.cltvExpiryDelta;

	const introNodeId = blindedPath.introductionNodeId;
	const sourceHex = source.toString('hex');
	const introHex = introNodeId.toString('hex');

	// Build the blinded tail: the introduction-node hop carries the path's
	// blinding point + its own encrypted data; later blinded hops carry only
	// their encrypted data. The recipient (last hop) gets exactly amountMsat.
	const tail: IRouteHop[] = hops.map((hop, i) => ({
		pubkey: hop.blindedNodeId,
		shortChannelId: Buffer.alloc(8), // blinded hops route via encrypted data
		amountToForwardMsat: i === 0 ? amountAtIntro : amountMsat,
		outgoingCltvValue: i === 0 ? cltvAtIntro : finalCltvExpiry,
		cltvExpiryDelta: 0,
		feeBaseMsat: 0,
		feeProportionalMillionths: 0,
		encryptedRecipientData: hop.encryptedData,
		...(i === 0 ? { blindingPoint: blindedPath.blindingPoint } : {})
	}));

	// If source IS the introduction node, the route is just the blinded tail,
	// but the intro hop's real pubkey is known (it's us routing onward).
	if (sourceHex === introHex) {
		tail[0].pubkey = introNodeId;
		return {
			hops: tail,
			totalAmountMsat: amountAtIntro,
			totalCltvDelta: cltvAtIntro,
			totalFeeMsat: blindedFeeMsat
		};
	}

	// Otherwise route to the introduction node carrying amountAtIntro, then graft
	// the blinded tail on. The intro node is reached as a normal hop; we overlay
	// its blinded fields onto that final routed hop and append hops[1..].
	const routeToIntro = findRoute(
		graph,
		source,
		introNodeId,
		amountAtIntro,
		cltvAtIntro,
		maxHops - (hops.length - 1),
		excludedChannels,
		missionControl,
		DEFAULT_MAX_CLTV_EXPIRY,
		undefined,
		undefined,
		// Use our local channel edges so a direct channel to the introduction node
		// is usable even when it isn't in the public gossip graph (interop, private).
		localChannels
	);
	if (!routeToIntro) return null;

	const introHop = routeToIntro.hops[routeToIntro.hops.length - 1];
	introHop.encryptedRecipientData = hops[0].encryptedData;
	introHop.blindingPoint = blindedPath.blindingPoint;

	const combinedHops = [...routeToIntro.hops, ...tail.slice(1)];

	return {
		hops: combinedHops,
		totalAmountMsat: routeToIntro.totalAmountMsat,
		totalCltvDelta: routeToIntro.totalCltvDelta,
		totalFeeMsat: routeToIntro.totalFeeMsat
	};
}
