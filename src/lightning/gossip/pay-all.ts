import { NetworkGraph } from './network-graph';
import {
	buildEdgeOverlay,
	calculateFee,
	ILocalChannelEdge,
	policyFor,
	TPolicyOverrides
} from './pathfinding';
import {
	CHANNEL_FLAG_DISABLED,
	DEFAULT_PRUNE_MAX_AGE,
	IChannelUpdateMessage,
	IRoute,
	MESSAGE_FLAG_HTLC_MAX
} from './types';
import { IRoutingHintHop } from '../invoice/types';

interface Edge {
	from: string;
	to: string;
	scid: Buffer;
	policy: IChannelUpdateMessage;
}

interface Candidate {
	node: string;
	edges: Edge[];
	minimum: bigint;
	maximum: bigint;
	cltv: number;
}

export interface IPayAllRouteResult {
	route: IRoute | null;
	/** An exact drain was refused; this amount must not silently become a fee. */
	remainderMsat: bigint;
	searchExhausted: boolean;
}

/** Incoming amount needed at the first node of a fixed suffix. */
function price(edges: Edge[], recipient: bigint): bigint {
	let amount = recipient;
	for (let i = edges.length - 1; i >= 0; i--) {
		const p = edges[i].policy;
		amount += calculateFee(amount, p.feeBaseMsat, p.feeProportionalMillionths);
	}
	return amount;
}

/** Invert a monotonic fixed-path amount, never a route-existence predicate. */
function upperBound(
	low: bigint,
	high: bigint,
	limit: bigint,
	amount: (recipient: bigint) => bigint
): bigint {
	if (amount(low) > limit) return low - 1n;
	while (low < high) {
		const mid = (low + high + 1n) / 2n;
		if (amount(mid) <= limit) low = mid;
		else high = mid - 1n;
	}
	return low;
}

function toRoute(edges: Edge[], recipient: bigint, finalCltv: number): IRoute {
	let amount = recipient;
	let cltv = finalCltv;
	const hops: IRoute['hops'] = [];
	for (let i = edges.length - 1; i >= 0; i--) {
		const edge = edges[i];
		const nextPolicy = edges[i + 1]?.policy;
		hops.unshift({
			pubkey: Buffer.from(edge.to, 'hex'),
			shortChannelId: edge.scid,
			amountToForwardMsat: amount,
			outgoingCltvValue: cltv,
			feeBaseMsat: nextPolicy?.feeBaseMsat ?? 0,
			feeProportionalMillionths: nextPolicy?.feeProportionalMillionths ?? 0,
			cltvExpiryDelta: edge.policy.cltvExpiryDelta
		});
		if (i > 0) {
			amount += calculateFee(
				amount,
				edge.policy.feeBaseMsat,
				edge.policy.feeProportionalMillionths
			);
			cltv += edge.policy.cltvExpiryDelta;
		}
	}
	return {
		hops,
		totalAmountMsat: amount,
		totalFeeMsat: amount - recipient,
		totalCltvDelta: cltv - finalCltv
	};
}

/**
 * Search simple paths using exact feasible recipient intervals. Lower HTLC
 * bounds can make route existence non-monotonic, so each suffix keeps both
 * bounds. The local edge must carry the entire frozen debit. A bounded search
 * refuses if unexplored paths could improve the recipient amount.
 */
export function findPayAllRoute(options: {
	graph: NetworkGraph;
	source: Buffer;
	destination: Buffer;
	debitMsat: bigint;
	maxFeeMsat: bigint;
	finalCltvExpiry: number;
	localChannels: ILocalChannelEdge[];
	routingHints?: IRoutingHintHop[][];
	excludedChannels?: Set<string>;
	policyOverrides?: TPolicyOverrides;
	maxCltvExpiry?: number;
	currentTimestamp?: number;
	maxCandidates?: number;
	/** Full local admission with exact debit and relative CLTV. */
	canSend?: (route: IRoute) => boolean;
}): IPayAllRouteResult {
	const {
		graph,
		source,
		destination,
		debitMsat,
		maxFeeMsat,
		finalCltvExpiry,
		localChannels,
		routingHints,
		excludedChannels,
		policyOverrides
	} = options;
	const result: IPayAllRouteResult = {
		route: null,
		remainderMsat: 0n,
		searchExhausted: false
	};
	if (debitMsat <= 0n || maxFeeMsat < 0n || source.equals(destination))
		return result;
	const sourceHex = source.toString('hex');
	const destHex = destination.toString('hex');
	const locals = localChannels.filter(
		(c) => c.outboundMsat >= debitMsat && (c.htlcMinimumMsat ?? 0n) <= debitMsat
	);
	if (locals.length === 0) return result;
	const { syntheticEdges, hintDestMap, shadowedScids, localFirstHopScids } =
		buildEdgeOverlay(graph, source, destination, routingHints, locals);
	const maxCltv = options.maxCltvExpiry ?? 2016;
	const now = options.currentTimestamp ?? Math.floor(Date.now() / 1000);
	const frontier: Candidate[] = [
		{
			node: destHex,
			edges: [],
			minimum: 1n,
			maximum: debitMsat,
			cltv: finalCltvExpiry
		}
	];
	let bestRecipient = 0n;
	let refusedRecipient = 0n;
	let explored = 0;
	let queued = 1;
	while (frontier.length > 0) {
		// Highest upper bound first. Ties prefer fewer hops.
		frontier.sort((a, b) =>
			a.maximum === b.maximum
				? b.edges.length - a.edges.length
				: a.maximum < b.maximum
				? -1
				: 1
		);
		const candidate = frontier.pop()!;
		if (candidate.maximum <= bestRecipient) break;
		if (++explored > (options.maxCandidates ?? 10_000)) {
			return {
				route: null,
				remainderMsat: result.remainderMsat,
				searchExhausted: true
			};
		}
		if (candidate.edges.length >= 20 || candidate.cltv > maxCltv) continue;
		const channels = [
			...graph
				.getNodeChannels(Buffer.from(candidate.node, 'hex'))
				.filter((c) => !shadowedScids.has(c.shortChannelId.toString('hex'))),
			...(syntheticEdges.get(candidate.node) ?? [])
		];
		for (const channel of channels) {
			const scid = channel.shortChannelId.toString('hex');
			if (excludedChannels?.has(scid)) continue;
			const hintDest = hintDestMap.get(scid);
			if (hintDest !== undefined && hintDest !== candidate.node) continue;
			const node1 = channel.nodeId1.toString('hex');
			const node2 = channel.nodeId2.toString('hex');
			const from =
				hintDest !== undefined || candidate.node === node2 ? node1 : node2;
			if (from === destHex || candidate.edges.some((e) => e.from === from))
				continue;
			const isSource = from === sourceHex;
			if (isSource && !localFirstHopScids?.has(scid)) continue;
			const update = policyFor(
				hintDest !== undefined || candidate.node === node2
					? channel.update1
					: channel.update2,
				// The owner, not a remote failure, prices its local edge.
				isSource ? undefined : policyOverrides,
				scid,
				from,
				candidate.node
			);
			if (!update || (update.channelFlags & CHANNEL_FLAG_DISABLED) !== 0)
				continue;
			if (
				hintDest === undefined &&
				update.timestamp < now - DEFAULT_PRUNE_MAX_AGE
			)
				continue;
			const edge: Edge = {
				from,
				to: candidate.node,
				scid: channel.shortChannelId,
				policy: update
			};
			const edges = [edge, ...candidate.edges];
			const incoming = (x: bigint): bigint => price(candidate.edges, x);
			let minimum = candidate.minimum;
			let maximum = candidate.maximum;
			if (!isSource) {
				minimum =
					upperBound(minimum, maximum, update.htlcMinimumMsat - 1n, incoming) +
					1n;
				if (minimum > maximum) continue;
				if (
					(update.messageFlags & MESSAGE_FLAG_HTLC_MAX) !== 0 &&
					update.htlcMaximumMsat !== undefined
				) {
					maximum = upperBound(
						minimum,
						maximum,
						update.htlcMaximumMsat,
						incoming
					);
				}
			}
			if (minimum > maximum) continue;
			const required = isSource
				? incoming
				: (x: bigint): bigint => price(edges, x);
			maximum = upperBound(minimum, maximum, debitMsat, required);
			if (maximum < minimum || maximum <= bestRecipient) continue;
			const cltv = candidate.cltv + (isSource ? 0 : update.cltvExpiryDelta);
			if (cltv > maxCltv) continue;
			if (!isSource) {
				if (++queued > (options.maxCandidates ?? 10_000)) {
					return {
						route: null,
						remainderMsat: result.remainderMsat,
						searchExhausted: true
					};
				}
				frontier.push({ node: from, edges, minimum, maximum, cltv });
				continue;
			}
			const route = toRoute(edges, maximum, finalCltvExpiry);
			const gap = debitMsat - route.totalAmountMsat;
			if (
				debitMsat - maximum > maxFeeMsat ||
				(gap > 0n && (edges.length < 2 || required(maximum + 1n) <= debitMsat))
			) {
				if (maximum > refusedRecipient) {
					refusedRecipient = maximum;
					result.remainderMsat = gap;
				}
				continue;
			}
			route.hops[0].amountToForwardMsat = debitMsat;
			route.totalAmountMsat = debitMsat;
			route.totalFeeMsat = debitMsat - maximum;
			if (options.canSend && !options.canSend(route)) continue;
			bestRecipient = maximum;
			result.route = route;
			result.remainderMsat = 0n;
		}
	}
	return result;
}
