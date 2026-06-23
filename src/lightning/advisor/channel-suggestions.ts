/**
 * ChannelSuggestions: Analyzes the gossip graph to recommend nodes for opening channels.
 * Pure analysis -- reads from NetworkGraph, no side effects.
 *
 * Scoring (0-100):
 *   - Connectivity (40pts): normalized channel count
 *   - Capacity (20pts): normalized total capacity
 *   - Freshness (20pts): recency of last channel update
 *   - Relevance (20pts): whether node is a payment destination or neighbor of one
 */

import { NetworkGraph } from '../gossip/network-graph';

export interface IChannelSuggestion {
	nodeId: string;
	alias?: string;
	score: number; // 0-100
	channelCount: number;
	totalCapacitySats: number;
	reason: string;
}

export interface IChannelSuggestionsOptions {
	/** Node IDs to exclude (already peers) */
	excludeNodeIds?: Set<string>;
	/** Node IDs we've sent payments to (for relevance scoring) */
	paymentDestinations?: Set<string>;
	/** Maximum number of suggestions (default 5) */
	maxResults?: number;
}

export class ChannelSuggestions {
	/**
	 * Analyze the network graph and return channel open suggestions.
	 * Scoring: connectivity (40), capacity (20), freshness (20), relevance (20).
	 */
	suggest(
		graph: NetworkGraph,
		ownNodeId: string,
		options?: IChannelSuggestionsOptions
	): IChannelSuggestion[] {
		const excludeSet = options?.excludeNodeIds ?? new Set<string>();
		const destinations = options?.paymentDestinations ?? new Set<string>();
		const maxResults = options?.maxResults ?? 5;

		const allNodes = graph.getAllNodes();

		if (allNodes.length === 0) return [];

		// Pre-compute per-node stats and global maxima for normalization
		let maxChannelCount = 0;
		let maxCapacity = 0n;
		let latestTimestamp = 0;

		const nodeStats = new Map<
			string,
			{ channelCount: number; totalCapacity: bigint; latestUpdate: number }
		>();

		for (const node of allNodes) {
			const nodeIdHex = node.nodeId.toString('hex');
			const nodeChannels = graph.getNodeChannels(node.nodeId);
			let totalCap = 0n;
			let latest = 0;

			for (const ch of nodeChannels) {
				const update = ch.update1 || ch.update2;
				if (update) {
					totalCap += update.htlcMaximumMsat ?? 0n;
					if (update.timestamp > latest) latest = update.timestamp;
				}
			}

			if (nodeChannels.length > maxChannelCount)
				maxChannelCount = nodeChannels.length;
			if (totalCap > maxCapacity) maxCapacity = totalCap;
			if (latest > latestTimestamp) latestTimestamp = latest;

			nodeStats.set(nodeIdHex, {
				channelCount: nodeChannels.length,
				totalCapacity: totalCap,
				latestUpdate: latest
			});
		}

		// Score each node
		const scored: IChannelSuggestion[] = [];

		for (const node of allNodes) {
			const nodeIdHex = node.nodeId.toString('hex');

			// Skip self and excluded nodes
			if (nodeIdHex === ownNodeId) continue;
			if (excludeSet.has(nodeIdHex)) continue;

			const stats = nodeStats.get(nodeIdHex);
			if (!stats || stats.channelCount === 0) continue;

			// Connectivity score (0-40): normalized by max channel count
			const connectivityScore =
				maxChannelCount > 0 ? (stats.channelCount / maxChannelCount) * 40 : 0;

			// Capacity score (0-20): normalized by max capacity
			const capacityScore =
				maxCapacity > 0n
					? (Number(stats.totalCapacity) / Number(maxCapacity)) * 20
					: 0;

			// Freshness score (0-20): how recently the node was updated
			const age =
				latestTimestamp > 0 ? latestTimestamp - stats.latestUpdate : 0;
			const maxAge = 7 * 24 * 3600; // 1 week
			const freshnessScore = Math.max(0, 1 - age / maxAge) * 20;

			// Relevance score (0-20): is this node a payment destination or neighbor of one?
			let relevanceScore = 0;
			if (destinations.has(nodeIdHex)) {
				relevanceScore = 20;
			} else {
				// Check if this node is a neighbor of any payment destination
				const nodeChannels = graph.getNodeChannels(node.nodeId);
				for (const ch of nodeChannels) {
					const peerId =
						ch.nodeId1.toString('hex') === nodeIdHex
							? ch.nodeId2.toString('hex')
							: ch.nodeId1.toString('hex');
					if (destinations.has(peerId)) {
						relevanceScore = Math.max(relevanceScore, 10);
					}
				}
			}

			const score = Math.round(
				connectivityScore + capacityScore + freshnessScore + relevanceScore
			);

			// Build reason
			const reasons: string[] = [];
			if (connectivityScore > 30) reasons.push('well-connected');
			else if (connectivityScore > 15) reasons.push('moderately connected');
			if (capacityScore > 15) reasons.push('high capacity');
			if (freshnessScore > 15) reasons.push('recently active');
			if (relevanceScore > 0) reasons.push('relevant to your payments');

			scored.push({
				nodeId: nodeIdHex,
				alias: node.announcement
					? node.announcement.alias.toString('utf8').replace(/\0+$/, '') ||
					  undefined
					: undefined,
				score,
				channelCount: stats.channelCount,
				totalCapacitySats: Number(stats.totalCapacity / 1000n),
				reason: reasons.length > 0 ? reasons.join(', ') : 'available node'
			});
		}

		// Sort by score descending
		scored.sort((a, b) => b.score - a.score);

		return scored.slice(0, maxResults);
	}
}
