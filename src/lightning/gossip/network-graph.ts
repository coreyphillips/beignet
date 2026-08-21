/**
 * BOLT 7: Network graph — in-memory store of channel and node information.
 */

import { BITCOIN_CHAIN_HASH } from '../channel/types';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	INodeAnnouncementMessage,
	IGraphChannel,
	IGraphNode,
	CHANNEL_FLAG_DIRECTION,
	DEFAULT_PRUNE_MAX_AGE,
	decodeShortChannelId
} from './types';
import {
	verifyChannelAnnouncementMessage,
	verifyChannelUpdateMessage,
	verifyNodeAnnouncementMessage
} from './validation';

export class NetworkGraph {
	private _channels: Map<string, IGraphChannel> = new Map();
	private _nodes: Map<string, IGraphNode> = new Map();
	// BOLT 7: announcements are chain-scoped. The graph accepts only its own
	// chain — previously hardcoded to mainnet, which silently discarded every
	// announcement on regtest/testnet/signet (S-7.M1).
	private readonly _chainHash: Buffer;

	constructor(chainHash: Buffer = BITCOIN_CHAIN_HASH) {
		this._chainHash = chainHash;
	}

	getChannelCount(): number {
		return this._channels.size;
	}

	getNodeCount(): number {
		return this._nodes.size;
	}

	/**
	 * Add a channel to the graph from a channel_announcement.
	 * Validates that nodeId1 < nodeId2 lexicographically and chain_hash matches.
	 * Pass { verified: true } only for signature-verified (or self-signed)
	 * announcements; unverified entries are excluded from gossip query
	 * responses (BOLT 7: MUST NOT relay unvalidated announcements, #340).
	 */
	addChannelAnnouncement(
		msg: IChannelAnnouncementMessage,
		opts: { verified?: boolean } = {}
	): boolean {
		// Validate chain hash against OUR chain (not hardcoded mainnet).
		if (!msg.chainHash.equals(this._chainHash)) {
			return false;
		}

		// Validate nodeId1 < nodeId2 (lexicographic ordering per BOLT 7)
		if (Buffer.compare(msg.nodeId1, msg.nodeId2) >= 0) {
			return false;
		}

		const scidHex = msg.shortChannelId.toString('hex');

		const existing = this._channels.get(scidHex);
		if (existing) {
			// Upgrade path: a signed announcement for an SCID we only hold
			// unverified (e.g. Rapid Gossip Sync primed it) replaces the entry
			// in place, so the channel becomes servable. Endpoints must match;
			// existing updates and their provenance flags are preserved.
			if (
				opts.verified === true &&
				existing.announcementVerified !== true &&
				existing.nodeId1.equals(msg.nodeId1) &&
				existing.nodeId2.equals(msg.nodeId2)
			) {
				existing.announcement = msg;
				existing.features = Buffer.from(msg.features);
				existing.announcementVerified = true;
				return true;
			}
			// Reject duplicate
			return false;
		}

		// Create the channel entry
		const channel: IGraphChannel = {
			shortChannelId: Buffer.from(msg.shortChannelId),
			nodeId1: Buffer.from(msg.nodeId1),
			nodeId2: Buffer.from(msg.nodeId2),
			features: Buffer.from(msg.features),
			announcement: msg,
			announcementVerified: opts.verified === true
		};
		this._channels.set(scidHex, channel);

		// Ensure node entries exist and link channel
		const node1Hex = msg.nodeId1.toString('hex');
		const node2Hex = msg.nodeId2.toString('hex');

		if (!this._nodes.has(node1Hex)) {
			this._nodes.set(node1Hex, {
				nodeId: Buffer.from(msg.nodeId1),
				channels: new Set()
			});
		}
		this._nodes.get(node1Hex)!.channels.add(scidHex);

		if (!this._nodes.has(node2Hex)) {
			this._nodes.set(node2Hex, {
				nodeId: Buffer.from(msg.nodeId2),
				channels: new Set()
			});
		}
		this._nodes.get(node2Hex)!.channels.add(scidHex);

		return true;
	}

	/**
	 * Apply a channel_update to an existing channel.
	 * Direction bit determines whether to set update1 (dir=0) or update2 (dir=1).
	 * Rejects if channel unknown or timestamp is not strictly newer.
	 * Pass { verified: true } only for signature-verified (or self-signed)
	 * updates; unverified updates are excluded from gossip query responses.
	 */
	applyChannelUpdate(
		msg: IChannelUpdateMessage,
		opts: { verified?: boolean } = {}
	): boolean {
		const scidHex = msg.shortChannelId.toString('hex');
		const channel = this._channels.get(scidHex);
		if (!channel) {
			return false;
		}

		const direction = msg.channelFlags & CHANNEL_FLAG_DIRECTION;
		const existing = direction === 0 ? channel.update1 : channel.update2;
		const existingVerified =
			direction === 0 ? channel.update1Verified : channel.update2Verified;

		// Reject if not strictly newer, unless a verified update is taking over
		// an unverified slot: RGS stamps synthetic updates with the snapshot's
		// global latest-seen timestamp, which would otherwise block the real
		// signed update forever.
		if (existing && msg.timestamp <= existing.timestamp) {
			if (!(opts.verified === true && existingVerified !== true)) {
				return false;
			}
		}

		if (direction === 0) {
			channel.update1 = msg;
			channel.update1Verified = opts.verified === true;
		} else {
			channel.update2 = msg;
			channel.update2Verified = opts.verified === true;
		}

		return true;
	}

	/**
	 * Apply a node_announcement to an existing node.
	 * Rejects if node has no channels or timestamp is not strictly newer.
	 * Pass { verified: true } only for signature-verified (or self-signed)
	 * announcements; unverified ones are excluded from gossip query responses.
	 */
	applyNodeAnnouncement(
		msg: INodeAnnouncementMessage,
		opts: { verified?: boolean } = {}
	): boolean {
		const nodeHex = msg.nodeId.toString('hex');
		const node = this._nodes.get(nodeHex);

		// Node must have at least one channel
		if (!node || node.channels.size === 0) {
			return false;
		}

		// Reject if not strictly newer, unless a verified announcement is taking
		// over an unverified slot (see applyChannelUpdate).
		if (node.announcement && msg.timestamp <= node.announcement.timestamp) {
			if (!(opts.verified === true && node.announcementVerified !== true)) {
				return false;
			}
		}

		node.announcement = msg;
		node.announcementVerified = opts.verified === true;
		return true;
	}

	// ── Pre-verification gates ─────────────────────────────────────────────
	// Signature verification runs in pure JS and a full-graph gossip dump from
	// one peer carries hundreds of thousands of signatures, so the intake path
	// asks these BEFORE verifying: each mirrors its apply method's acceptance
	// rule under the most permissive provenance (verified), so a false here
	// means the message cannot change the graph no matter what verification
	// finds, and its signatures need never be checked. Keep each gate next to
	// the rule it mirrors; they must not drift (beignet issue #437: a peer
	// re-serving a known graph pinned the event loop for the whole dump).

	/**
	 * Whether a channel_announcement could change the graph at all. False for
	 * a wrong chain, disordered node ids, or an SCID already held with a
	 * verified announcement (announcements are immutable per SCID; only the
	 * unverified-to-verified upgrade in addChannelAnnouncement remains, and it
	 * requires matching endpoints).
	 */
	wouldAcceptChannelAnnouncement(msg: IChannelAnnouncementMessage): boolean {
		if (!msg.chainHash.equals(this._chainHash)) return false;
		if (Buffer.compare(msg.nodeId1, msg.nodeId2) >= 0) return false;
		const existing = this._channels.get(msg.shortChannelId.toString('hex'));
		if (!existing) return true;
		return (
			existing.announcementVerified !== true &&
			existing.nodeId1.equals(msg.nodeId1) &&
			existing.nodeId2.equals(msg.nodeId2)
		);
	}

	/**
	 * Whether a channel_update could change the graph at all. False when the
	 * channel is unknown, or when the held update for that direction is
	 * verified and not older (the verified-over-unverified takeover is then
	 * out of reach, so a stale re-send can be refused by its timestamp alone,
	 * never needing its signature).
	 */
	wouldAcceptChannelUpdate(msg: IChannelUpdateMessage): boolean {
		const channel = this._channels.get(msg.shortChannelId.toString('hex'));
		if (!channel) return false;
		const direction = msg.channelFlags & CHANNEL_FLAG_DIRECTION;
		const existing = direction === 0 ? channel.update1 : channel.update2;
		const existingVerified =
			direction === 0 ? channel.update1Verified : channel.update2Verified;
		if (existing && msg.timestamp <= existing.timestamp) {
			return existingVerified !== true;
		}
		return true;
	}

	/**
	 * Whether a node_announcement could change the graph at all. False for a
	 * channel-less node, or when the held announcement is verified and not
	 * older (same shape as wouldAcceptChannelUpdate).
	 */
	wouldAcceptNodeAnnouncement(msg: INodeAnnouncementMessage): boolean {
		const node = this._nodes.get(msg.nodeId.toString('hex'));
		if (!node || node.channels.size === 0) return false;
		if (node.announcement && msg.timestamp <= node.announcement.timestamp) {
			return node.announcementVerified !== true;
		}
		return true;
	}

	getChannel(shortChannelId: Buffer): IGraphChannel | undefined {
		return this._channels.get(shortChannelId.toString('hex'));
	}

	getNode(nodeId: Buffer): IGraphNode | undefined {
		return this._nodes.get(nodeId.toString('hex'));
	}

	/**
	 * Get all channels that a node is part of.
	 */
	getNodeChannels(nodeId: Buffer): IGraphChannel[] {
		const node = this._nodes.get(nodeId.toString('hex'));
		if (!node) return [];
		const result: IGraphChannel[] = [];
		for (const scidHex of node.channels) {
			const ch = this._channels.get(scidHex);
			if (ch) result.push(ch);
		}
		return result;
	}

	/**
	 * Remove a channel and clean up orphaned nodes.
	 */
	removeChannel(shortChannelId: Buffer): boolean {
		const scidHex = shortChannelId.toString('hex');
		const channel = this._channels.get(scidHex);
		if (!channel) return false;

		this._channels.delete(scidHex);

		// Remove from endpoint nodes' channel sets
		const node1Hex = channel.nodeId1.toString('hex');
		const node2Hex = channel.nodeId2.toString('hex');

		const node1 = this._nodes.get(node1Hex);
		if (node1) {
			node1.channels.delete(scidHex);
			if (node1.channels.size === 0) {
				this._nodes.delete(node1Hex);
			}
		}

		const node2 = this._nodes.get(node2Hex);
		if (node2) {
			node2.channels.delete(scidHex);
			if (node2.channels.size === 0) {
				this._nodes.delete(node2Hex);
			}
		}

		return true;
	}

	/**
	 * Prune channels whose latest update is older than maxAge seconds.
	 * Channels with no updates at all are also pruned.
	 * Returns the number of pruned channels.
	 */
	pruneStaleChannels(
		currentTimestamp: number,
		maxAge: number = DEFAULT_PRUNE_MAX_AGE
	): number {
		const cutoff = currentTimestamp - maxAge;
		const toPrune: Buffer[] = [];

		for (const channel of this._channels.values()) {
			const ts1 = channel.update1?.timestamp ?? 0;
			const ts2 = channel.update2?.timestamp ?? 0;
			const latest = Math.max(ts1, ts2);
			if (latest < cutoff) {
				toPrune.push(channel.shortChannelId);
			}
		}

		for (const scid of toPrune) {
			this.removeChannel(scid);
		}

		return toPrune.length;
	}

	getAllChannelIds(): Buffer[] {
		const result: Buffer[] = [];
		for (const channel of this._channels.values()) {
			result.push(Buffer.from(channel.shortChannelId));
		}
		return result;
	}

	getAllNodeIds(): Buffer[] {
		const result: Buffer[] = [];
		for (const node of this._nodes.values()) {
			result.push(Buffer.from(node.nodeId));
		}
		return result;
	}

	/**
	 * Restore a channel directly into the graph (bypasses graph validation).
	 * Rows persisted before provenance tracking carry no verified flags;
	 * they are resolved here by verifying the canonical re-encoding, since
	 * absence cannot be trusted (pre-#340 rows could hold zero-signature RGS
	 * messages persisted alongside a verified update). Fails safe to
	 * unverified; rows with explicit flags skip the signature checks. This is
	 * the common boundary for every storage backend, custom ones included.
	 */
	restoreChannel(channel: IGraphChannel): void {
		if (channel.announcementVerified === undefined) {
			channel.announcementVerified = verifyChannelAnnouncementMessage(
				channel.announcement
			);
		}
		if (channel.update1 && channel.update1Verified === undefined) {
			channel.update1Verified = verifyChannelUpdateMessage(
				channel.update1,
				channel.nodeId1,
				channel.nodeId2
			);
		}
		if (channel.update2 && channel.update2Verified === undefined) {
			channel.update2Verified = verifyChannelUpdateMessage(
				channel.update2,
				channel.nodeId1,
				channel.nodeId2
			);
		}

		const scidHex = channel.shortChannelId.toString('hex');
		this._channels.set(scidHex, channel);

		// Ensure node entries exist and link channel
		const node1Hex = channel.nodeId1.toString('hex');
		const node2Hex = channel.nodeId2.toString('hex');

		if (!this._nodes.has(node1Hex)) {
			this._nodes.set(node1Hex, {
				nodeId: Buffer.from(channel.nodeId1),
				channels: new Set()
			});
		}
		this._nodes.get(node1Hex)!.channels.add(scidHex);

		if (!this._nodes.has(node2Hex)) {
			this._nodes.set(node2Hex, {
				nodeId: Buffer.from(channel.nodeId2),
				channels: new Set()
			});
		}
		this._nodes.get(node2Hex)!.channels.add(scidHex);
	}

	/**
	 * Restore a node directly into the graph (bypasses graph validation).
	 * Legacy rows without a provenance flag are resolved by verifying the
	 * canonical re-encoding (see restoreChannel).
	 */
	restoreNode(node: IGraphNode): void {
		if (node.announcement && node.announcementVerified === undefined) {
			node.announcementVerified = verifyNodeAnnouncementMessage(
				node.announcement
			);
		}
		const nodeHex = node.nodeId.toString('hex');
		const existing = this._nodes.get(nodeHex);
		if (existing) {
			existing.announcement = node.announcement;
			existing.announcementVerified = node.announcementVerified;
		} else {
			this._nodes.set(nodeHex, node);
		}
	}

	/**
	 * Get all channels for iteration.
	 */
	getAllChannels(): IGraphChannel[] {
		return [...this._channels.values()];
	}

	/**
	 * Get all nodes for iteration.
	 */
	getAllNodes(): IGraphNode[] {
		return [...this._nodes.values()];
	}

	// ── Gossip Sync Methods (BOLT 7 §4) ────────────────────────────

	/**
	 * Get all channel SCIDs whose block height falls within [firstBlock, firstBlock + numberOfBlocks).
	 * Returns sorted 8-byte SCID buffers.
	 */
	getChannelsByBlockRange(
		firstBlock: number,
		numberOfBlocks: number
	): Buffer[] {
		const endBlock = firstBlock + numberOfBlocks;
		const result: Buffer[] = [];
		for (const channel of this._channels.values()) {
			// BOLT 7: never advertise announcements we have not validated (#340).
			// Strict peers (eclair 0.14+) disconnect on invalid gossip signatures.
			if (channel.announcementVerified !== true) continue;
			const scid = decodeShortChannelId(channel.shortChannelId);
			if (scid.block >= firstBlock && scid.block < endBlock) {
				result.push(Buffer.from(channel.shortChannelId));
			}
		}
		// Sort by SCID value (lexicographic on 8 bytes = numeric order)
		result.sort((a, b) => Buffer.compare(a, b));
		return result;
	}

	/**
	 * Given a list of remote SCIDs, return those we don't have in our graph.
	 */
	getMissingSCIDs(remoteScids: Buffer[]): Buffer[] {
		return remoteScids.filter(
			(scid) => !this._channels.has(scid.toString('hex'))
		);
	}

	/**
	 * Get all gossip messages (announcement + updates + node announcements) for a set of SCIDs.
	 * Used to respond to query_short_channel_ids.
	 */
	getGossipMessagesForChannels(scids: Buffer[]): {
		announcements: IChannelAnnouncementMessage[];
		updates: IChannelUpdateMessage[];
		nodeAnnouncements: INodeAnnouncementMessage[];
	} {
		const announcements: IChannelAnnouncementMessage[] = [];
		const updates: IChannelUpdateMessage[] = [];
		const seenNodes = new Set<string>();
		const nodeAnnouncements: INodeAnnouncementMessage[] = [];

		for (const scid of scids) {
			const channel = this._channels.get(scid.toString('hex'));
			if (!channel) continue;
			// BOLT 7: never relay announcements we have not validated (#340).
			// Skipping the whole channel also covers a verified update sitting
			// on an unverified announcement: an update MUST NOT be sent without
			// a servable channel_announcement.
			if (channel.announcementVerified !== true) continue;

			announcements.push(channel.announcement);
			if (channel.update1 && channel.update1Verified === true) {
				updates.push(channel.update1);
			}
			if (channel.update2 && channel.update2Verified === true) {
				updates.push(channel.update2);
			}

			// Collect node announcements for endpoint nodes (deduplicated)
			for (const nodeId of [channel.nodeId1, channel.nodeId2]) {
				const nodeHex = nodeId.toString('hex');
				if (seenNodes.has(nodeHex)) continue;
				seenNodes.add(nodeHex);
				const node = this._nodes.get(nodeHex);
				if (node?.announcement && node.announcementVerified === true) {
					nodeAnnouncements.push(node.announcement);
				}
			}
		}

		return { announcements, updates, nodeAnnouncements };
	}
}
