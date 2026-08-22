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
	TGossipVerified,
	CHANNEL_FLAG_DIRECTION,
	DEFAULT_PRUNE_MAX_AGE,
	gossipTimestampTooFarFuture,
	decodeShortChannelId
} from './types';
import {
	verifyChannelAnnouncementMessage,
	verifyChannelUpdateMessage,
	verifyNodeAnnouncementMessage
} from './validation';

const ZERO_SIG = Buffer.alloc(64);

/**
 * A stored message with an all-zero signature can never be verified or served
 * (Rapid Gossip Sync strips signatures). Such slots also carry synthetic
 * timestamps, which is why some freshness rules treat them specially.
 */
function isSignatureless(sig: Buffer): boolean {
	return sig.equals(ZERO_SIG);
}

/**
 * Normalize a caller's provenance claim: anything other than the two positive
 * states is explicit false, and a 'deferred' claim on a signatureless message
 * is also false, since it can never verify. Without that downgrade an
 * identical zero-signature replay would stay takeover-eligible against its
 * own zero-signature slot forever, each acceptance re-triggering persistence.
 */
function normalizeVerified(
	verified: TGossipVerified | undefined,
	signature: Buffer
): TGossipVerified {
	if (verified === true) return true;
	if (verified === 'deferred')
		return isSignatureless(signature) ? false : 'deferred';
	return false;
}

/**
 * The stored form of a provenance claim: a settled boolean, or an undefined
 * boolean plus the deferred marker. The *Verified fields stay strictly
 * boolean so downstream truthiness checks never see a truthy unverified
 * value (issue #443 review).
 */
function provenancePair(verified: TGossipVerified): {
	verified: boolean | undefined;
	deferred: true | undefined;
} {
	if (verified === true) return { verified: true, deferred: undefined };
	if (verified === 'deferred') return { verified: undefined, deferred: true };
	return { verified: false, deferred: undefined };
}

/**
 * Storage rows come from arbitrary backends: only exact booleans are trusted
 * in a *Verified field, and a settled boolean always clears the deferred
 * marker. Anything else resolves at the restore boundary like a legacy row.
 */
function sanitizeSlot(
	verified: boolean | undefined,
	deferred: boolean | undefined
): { verified: boolean | undefined; deferred: true | undefined } {
	const v = typeof verified === 'boolean' ? verified : undefined;
	return {
		verified: v,
		deferred: v === undefined && deferred === true ? true : undefined
	};
}

export class NetworkGraph {
	/**
	 * Wall-clock budget for resolving deferred provenance inside
	 * getGossipMessagesForChannels, shared by every query in the current
	 * window. The serve path is synchronous on the message path, so lazy
	 * verification must be bounded or repeated query_short_channel_ids
	 * bursts would starve the event loop the way unsliced intake once did
	 * (issue #437); a shared rolling window, rather than a per-query timer,
	 * keeps the bound from multiplying with the query rate. Channels left
	 * unresolved are omitted whole from the reply, reported through the end
	 * marker's full_information bit, and stay resolvable in a later window.
	 * Static and mutable so tests can pin them (the
	 * INITIAL_GOSSIP_PRIME_TIMEOUT_MS pattern).
	 */
	static SERVE_VERIFY_BUDGET_MS = 50;
	static SERVE_VERIFY_WINDOW_MS = 1000;

	/**
	 * Hard ceiling on graph channels. Lazy intake (issue #443) admits gossip
	 * for the price of a decode, so without a ceiling a hostile peer can
	 * inflate graph memory and the gossip tables without ever paying for a
	 * signature (issue #446). The public graph is well under this; the bound
	 * only bites on garbage. At the ceiling, verified admissions evict an
	 * unverified entry (garbage never starves out real data) while
	 * unverified ones are refused. Static and mutable so tests can pin it
	 * (the SERVE_VERIFY_BUDGET_MS pattern).
	 */
	static MAX_CHANNELS = 100_000;

	private _channels: Map<string, IGraphChannel> = new Map();
	/**
	 * scidHex of every held channel whose announcement is not settled
	 * verified: the eviction candidates, indexed so admission at the ceiling
	 * stays O(1). Invariant: member iff present in _channels with
	 * announcementVerified !== true; every site that settles a channel's
	 * announcement provenance or changes _channels membership maintains it.
	 */
	private _unverifiedChannels: Set<string> = new Set();
	/** Start of the current serve-verification budget window (epoch ms). */
	private _serveVerifyWindowStart = 0;
	/** Verification time spent in the current window across all queries. */
	private _serveVerifySpentMs = 0;
	private _nodes: Map<string, IGraphNode> = new Map();
	// BOLT 7: announcements are chain-scoped. The graph accepts only its own
	// chain — previously hardcoded to mainnet, which silently discarded every
	// announcement on regtest/testnet/signet (S-7.M1).
	private readonly _chainHash: Buffer;
	// Eager mode (relay-class nodes): foreign gossip is verified at intake and
	// restore, and RGS-primed signatureless entries are re-requested from
	// peers. Lazy mode (default, wallets): verification is deferred until a
	// gossip query asks for the entry (issue #443).
	private readonly _eagerVerify: boolean;
	// Fired with the scidHex of every channel dropped by ceiling eviction
	// (including restore-time trims), so the owner can delete the persisted
	// row; the graph itself never touches storage.
	private readonly _onChannelEvicted?: (scidHex: string) => void;
	// Fired with the nodeIdHex of every node garbage-collected because its
	// last graph channel went away (prune or ceiling eviction), so the owner
	// can delete the persisted gossip_nodes row; the graph itself never
	// touches storage (issue #447).
	private readonly _onNodeEvicted?: (nodeIdHex: string) => void;
	// Non-null while a ceiling replacement is in flight: removeChannel
	// deposits GC'd node hexes here instead of reporting them, and the
	// admission flushes only the ones still absent once the incoming
	// channel is in place. Reporting mid-replacement would delete the
	// persisted row of an endpoint the victim shares with the admitted
	// channel.
	private _deferredNodeEvictions: string[] | null = null;

	constructor(
		chainHash: Buffer = BITCOIN_CHAIN_HASH,
		opts: {
			eagerVerify?: boolean;
			onChannelEvicted?: (scidHex: string) => void;
			onNodeEvicted?: (nodeIdHex: string) => void;
		} = {}
	) {
		this._chainHash = chainHash;
		this._eagerVerify = opts.eagerVerify === true;
		this._onChannelEvicted = opts.onChannelEvicted;
		this._onNodeEvicted = opts.onNodeEvicted;
	}

	/**
	 * Keep the eviction index in step with a channel's settled announcement
	 * provenance. Call after any site settles announcementVerified.
	 */
	private _syncUnverifiedIndex(scidHex: string, channel: IGraphChannel): void {
		if (channel.announcementVerified === true) {
			this._unverifiedChannels.delete(scidHex);
		} else {
			this._unverifiedChannels.add(scidHex);
		}
	}

	/**
	 * Evict one unverified channel to admit a verified one at the ceiling.
	 * Insertion order makes the victim the oldest unverified entry. Returns
	 * false when nothing is evictable (every held channel is verified).
	 * Note the preference, not the ceiling, is best-effort: announcement
	 * verification proves signatures over keys the message itself carries,
	 * not UTXO existence, so an attacker who baits serve-time resolution of
	 * their fabricated announcements makes them unevictable. The ceiling
	 * still holds absolutely.
	 */
	/**
	 * Report deferred node evictions once an admission has completed. Only
	 * nodes still absent are reported: an endpoint the ceiling victim
	 * shared with the admitted channel was re-created by the insert and
	 * its persisted row must survive.
	 */
	private _flushDeferredNodeEvictions(): void {
		const deferred = this._deferredNodeEvictions;
		this._deferredNodeEvictions = null;
		if (!deferred) return;
		for (const nodeIdHex of deferred) {
			if (!this._nodes.has(nodeIdHex)) {
				this._onNodeEvicted?.(nodeIdHex);
			}
		}
	}

	private _evictOneUnverified(): boolean {
		const victim = this._unverifiedChannels.values().next();
		if (victim.done) return false;
		const channel = this._channels.get(victim.value);
		if (channel) {
			this.removeChannel(channel.shortChannelId);
		} else {
			// Defensive: repair a desynced index entry.
			this._unverifiedChannels.delete(victim.value);
		}
		this._onChannelEvicted?.(victim.value);
		return true;
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
	 * announcements, { verified: 'deferred' } for signed-but-unchecked ones;
	 * anything else is stored unverified and excluded from gossip query
	 * responses (BOLT 7: MUST NOT relay unvalidated announcements, #340).
	 */
	addChannelAnnouncement(
		msg: IChannelAnnouncementMessage,
		opts: { verified?: TGossipVerified } = {}
	): boolean {
		// Validate chain hash against OUR chain (not hardcoded mainnet).
		if (!msg.chainHash.equals(this._chainHash)) {
			return false;
		}

		// Validate nodeId1 < nodeId2 (lexicographic ordering per BOLT 7)
		if (Buffer.compare(msg.nodeId1, msg.nodeId2) >= 0) {
			return false;
		}

		const verified = normalizeVerified(opts.verified, msg.nodeSignature1);
		const scidHex = msg.shortChannelId.toString('hex');

		const existing = this._channels.get(scidHex);
		if (existing) {
			// Upgrade path: a signed announcement for an SCID we only hold
			// unverified (e.g. Rapid Gossip Sync primed it) replaces the entry
			// in place, so the channel becomes servable. Endpoints must match;
			// existing updates and their provenance flags are preserved. A
			// deferred candidate (always real-signature, normalizeVerified
			// downgrades the rest) may only displace a SIGNATURELESS slot:
			// over a signed slot it could change nothing servability-wise,
			// and a peer re-serving a known dump against an all-deferred
			// graph would otherwise "accept" every duplicate and re-trigger a
			// storage write per entry (the issue #437 failure class,
			// relocated to disk).
			const upgrade =
				verified === true ||
				(verified === 'deferred' &&
					isSignatureless(existing.announcement.nodeSignature1));
			if (
				upgrade &&
				existing.announcementVerified !== true &&
				existing.nodeId1.equals(msg.nodeId1) &&
				existing.nodeId2.equals(msg.nodeId2)
			) {
				const pair = provenancePair(verified);
				existing.announcement = msg;
				existing.features = Buffer.from(msg.features);
				existing.announcementVerified = pair.verified;
				existing.announcementVerifyDeferred = pair.deferred;
				this._syncUnverifiedIndex(scidHex, existing);
				return true;
			}
			// Reject duplicate
			return false;
		}

		// Ceiling (issue #446): only new entries are growth (the upgrade path
		// above settles in place), and only a verified admission may make room
		// by evicting an unverified entry; unverified ones are refused, so
		// garbage displaces nothing. Node-eviction reports wait until the
		// incoming channel is inserted (the victim may share an endpoint).
		if (this._channels.size >= NetworkGraph.MAX_CHANNELS) {
			if (verified !== true) return false;
			this._deferredNodeEvictions = [];
			if (!this._evictOneUnverified()) {
				this._deferredNodeEvictions = null;
				return false;
			}
		}

		// Create the channel entry
		const pair = provenancePair(verified);
		const channel: IGraphChannel = {
			shortChannelId: Buffer.from(msg.shortChannelId),
			nodeId1: Buffer.from(msg.nodeId1),
			nodeId2: Buffer.from(msg.nodeId2),
			features: Buffer.from(msg.features),
			announcement: msg,
			announcementVerified: pair.verified,
			announcementVerifyDeferred: pair.deferred
		};
		this._channels.set(scidHex, channel);
		this._syncUnverifiedIndex(scidHex, channel);

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

		this._flushDeferredNodeEvictions();
		return true;
	}

	/**
	 * Apply a channel_update to an existing channel.
	 * Direction bit determines whether to set update1 (dir=0) or update2 (dir=1).
	 * Rejects if channel unknown or timestamp is not strictly newer.
	 * Pass { verified: true } only for signature-verified (or self-signed)
	 * updates, { verified: 'deferred' } for signed-but-unchecked ones;
	 * anything else is stored unverified and excluded from query responses.
	 */
	applyChannelUpdate(
		msg: IChannelUpdateMessage,
		opts: { verified?: TGossipVerified } = {}
	): boolean {
		// BOLT 7: ignore timestamps unreasonably far in the future, whatever
		// the provenance; admitted, one would camp its slot against the
		// strictly-newer rule below and never go stale (issue #446).
		if (gossipTimestampTooFarFuture(msg.timestamp)) {
			return false;
		}
		const scidHex = msg.shortChannelId.toString('hex');
		const channel = this._channels.get(scidHex);
		if (!channel) {
			return false;
		}

		const direction = msg.channelFlags & CHANNEL_FLAG_DIRECTION;
		const existing = direction === 0 ? channel.update1 : channel.update2;
		const existingVerified =
			direction === 0 ? channel.update1Verified : channel.update2Verified;
		const verified = normalizeVerified(opts.verified, msg.signature);

		// Reject if not strictly newer, unless a verified update is taking over
		// an unverified slot: RGS stamps synthetic updates with the snapshot's
		// global latest-seen timestamp, which would otherwise block the real
		// signed update forever. A deferred candidate (always real-signature,
		// normalizeVerified downgrades the rest) gets the same bypass but
		// ONLY over a signatureless slot (whose timestamp is synthetic by
		// construction); over signed slots normal freshness applies, so a
		// re-served known update refuses here without a storage write.
		if (existing && msg.timestamp <= existing.timestamp) {
			const takeover =
				existingVerified !== true &&
				(verified === true ||
					(verified === 'deferred' && isSignatureless(existing.signature)));
			if (!takeover) {
				return false;
			}
		}

		const pair = provenancePair(verified);
		if (direction === 0) {
			channel.update1 = msg;
			channel.update1Verified = pair.verified;
			channel.update1VerifyDeferred = pair.deferred;
		} else {
			channel.update2 = msg;
			channel.update2Verified = pair.verified;
			channel.update2VerifyDeferred = pair.deferred;
		}

		return true;
	}

	/**
	 * Apply a node_announcement to an existing node.
	 * Rejects if node has no channels or timestamp is not strictly newer.
	 * Pass { verified: true } only for signature-verified (or self-signed)
	 * announcements, { verified: 'deferred' } for signed-but-unchecked ones;
	 * anything else is stored unverified and excluded from query responses.
	 */
	applyNodeAnnouncement(
		msg: INodeAnnouncementMessage,
		opts: { verified?: TGossipVerified } = {}
	): boolean {
		// BOLT 7: ignore far-future timestamps (see applyChannelUpdate).
		if (gossipTimestampTooFarFuture(msg.timestamp)) {
			return false;
		}
		const nodeHex = msg.nodeId.toString('hex');
		const node = this._nodes.get(nodeHex);

		// Node must have at least one channel
		if (!node || node.channels.size === 0) {
			return false;
		}

		const verified = normalizeVerified(opts.verified, msg.signature);

		// Reject if not strictly newer, unless a verified announcement is taking
		// over an unverified slot (see applyChannelUpdate). No deferred bypass
		// here: RGS carries no node_announcements, so signatureless node slots
		// with synthetic timestamps never exist.
		if (node.announcement && msg.timestamp <= node.announcement.timestamp) {
			if (!(verified === true && node.announcementVerified !== true)) {
				return false;
			}
		}

		const pair = provenancePair(verified);
		node.announcement = msg;
		node.announcementVerified = pair.verified;
		node.announcementVerifyDeferred = pair.deferred;
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
	// Deferred candidates (issue #443) accept a strict subset of what verified
	// candidates accept (every deferred takeover additionally requires a
	// signatureless slot), so mirroring the verified rules keeps these gates
	// valid upper bounds for both provenances.

	/**
	 * Whether a channel_announcement could change the graph at all. False for
	 * a wrong chain, disordered node ids, an SCID already held with a
	 * verified announcement (announcements are immutable per SCID; only the
	 * unverified-to-verified upgrade in addChannelAnnouncement remains, and it
	 * requires matching endpoints), or a full graph with nothing evictable.
	 */
	wouldAcceptChannelAnnouncement(msg: IChannelAnnouncementMessage): boolean {
		if (!msg.chainHash.equals(this._chainHash)) return false;
		if (Buffer.compare(msg.nodeId1, msg.nodeId2) >= 0) return false;
		const existing = this._channels.get(msg.shortChannelId.toString('hex'));
		if (!existing) {
			// Ceiling mirror: at the ceiling a new entry is only admissible
			// (under the most permissive provenance, verified) while an
			// unverified entry remains evictable.
			return (
				this._channels.size < NetworkGraph.MAX_CHANNELS ||
				this._unverifiedChannels.size > 0
			);
		}
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
		if (gossipTimestampTooFarFuture(msg.timestamp)) return false;
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
		if (gossipTimestampTooFarFuture(msg.timestamp)) return false;
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
	 * The node's announcement resolved to signature-verified provenance, or
	 * undefined. This is the trust boundary for every consumer that acts on
	 * announcement contents beyond routing (reconnect fallbacks, pubkey-only
	 * dials, channel-open suggestions): a deferred announcement is verified
	 * here on first read, so an unproven address claim is never dialed. Cost
	 * is one bounded verification per unresolved node, caller-driven, and the
	 * settled flag makes it one-time.
	 */
	getVerifiedNodeAnnouncement(
		nodeId: Buffer
	): INodeAnnouncementMessage | undefined {
		const node = this._nodes.get(nodeId.toString('hex'));
		if (!node?.announcement) return undefined;
		if (node.announcementVerifyDeferred === true) {
			node.announcementVerified = verifyNodeAnnouncementMessage(
				node.announcement
			);
			node.announcementVerifyDeferred = undefined;
		}
		return node.announcementVerified === true ? node.announcement : undefined;
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
		this._unverifiedChannels.delete(scidHex);

		// Remove from endpoint nodes' channel sets
		const node1Hex = channel.nodeId1.toString('hex');
		const node2Hex = channel.nodeId2.toString('hex');

		const evictedNodes: string[] = [];

		const node1 = this._nodes.get(node1Hex);
		if (node1) {
			node1.channels.delete(scidHex);
			if (node1.channels.size === 0) {
				this._nodes.delete(node1Hex);
				evictedNodes.push(node1Hex);
			}
		}

		const node2 = this._nodes.get(node2Hex);
		if (node2) {
			node2.channels.delete(scidHex);
			if (node2.channels.size === 0) {
				this._nodes.delete(node2Hex);
				evictedNodes.push(node2Hex);
			}
		}

		// Report only after both endpoints are cleaned: a throwing callback
		// must not leave node2 pointing at a channel that no longer exists.
		// Inside a ceiling replacement the reports are deferred until the
		// incoming channel is in place.
		for (const nodeIdHex of evictedNodes) {
			if (this._deferredNodeEvictions) {
				this._deferredNodeEvictions.push(nodeIdHex);
			} else {
				this._onNodeEvicted?.(nodeIdHex);
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
	 * absence cannot be trusted (pre-#340 rows could hold zero-signature RGS
	 * messages persisted alongside a verified update), so unresolved flags
	 * (absent, non-boolean, or marked deferred) are resolved here. Eager mode
	 * verifies the canonical re-encoding at once, so an eager node never
	 * holds deferred entries post-boot, a lazy-to-eager migration included.
	 * Lazy mode (default) marks them deferred instead, moving the signature
	 * work to the point of consumption (issue #443); either way nothing
	 * unresolved is ever served. Rows with explicit boolean flags skip the
	 * signature checks. This is the common boundary for every storage
	 * backend, custom ones included.
	 */
	restoreChannel(channel: IGraphChannel): void {
		// A row persisted before the far-future bound existed can carry a
		// timestamp the intake gates now refuse; restored raw it would re-camp
		// its slot (verified flags block every takeover) and, keying pruning
		// off the same timestamp, never go stale. Drop the poisoned slot: the
		// freed slot takes the next real update, a row left with no updates is
		// pruned right after restore, and per the issue #443 precedent the
		// repair is not written back (the row self-heals on the next accepted
		// update).
		if (
			channel.update1 &&
			gossipTimestampTooFarFuture(channel.update1.timestamp)
		) {
			channel.update1 = undefined;
			channel.update1Verified = undefined;
			channel.update1VerifyDeferred = undefined;
		}
		if (
			channel.update2 &&
			gossipTimestampTooFarFuture(channel.update2.timestamp)
		) {
			channel.update2 = undefined;
			channel.update2Verified = undefined;
			channel.update2VerifyDeferred = undefined;
		}

		const ann = sanitizeSlot(
			channel.announcementVerified,
			channel.announcementVerifyDeferred
		);
		const upd1 = sanitizeSlot(
			channel.update1Verified,
			channel.update1VerifyDeferred
		);
		const upd2 = sanitizeSlot(
			channel.update2Verified,
			channel.update2VerifyDeferred
		);
		if (this._eagerVerify) {
			channel.announcementVerified =
				ann.verified ?? verifyChannelAnnouncementMessage(channel.announcement);
			channel.announcementVerifyDeferred = undefined;
			channel.update1Verified = channel.update1
				? upd1.verified ??
				  verifyChannelUpdateMessage(
						channel.update1,
						channel.nodeId1,
						channel.nodeId2
				  )
				: undefined;
			channel.update1VerifyDeferred = undefined;
			channel.update2Verified = channel.update2
				? upd2.verified ??
				  verifyChannelUpdateMessage(
						channel.update2,
						channel.nodeId1,
						channel.nodeId2
				  )
				: undefined;
			channel.update2VerifyDeferred = undefined;
		} else {
			channel.announcementVerified = ann.verified;
			channel.announcementVerifyDeferred =
				ann.verified === undefined ? true : undefined;
			channel.update1Verified = channel.update1 ? upd1.verified : undefined;
			channel.update1VerifyDeferred =
				channel.update1 && upd1.verified === undefined ? true : undefined;
			channel.update2Verified = channel.update2 ? upd2.verified : undefined;
			channel.update2VerifyDeferred =
				channel.update2 && upd2.verified === undefined ? true : undefined;
		}

		const scidHex = channel.shortChannelId.toString('hex');

		// Ceiling (issue #446): the restore path admits rows with no gates, so
		// a poisoned store would otherwise re-inflate the graph on every boot.
		// Same preference as live admission: a verified row may evict an
		// unverified in-graph entry; an unverified row is dropped, and
		// reported so its storage row is deleted. A verified row that cannot
		// be admitted (everything held is verified, reachable only if the
		// ceiling was lowered between runs) is skipped WITHOUT the report:
		// provably-signed data is left on disk for a future run rather than
		// trimmed.
		const isNew = !this._channels.has(scidHex);
		if (isNew && this._channels.size >= NetworkGraph.MAX_CHANNELS) {
			if (channel.announcementVerified === true) {
				this._deferredNodeEvictions = [];
				if (!this._evictOneUnverified()) {
					this._deferredNodeEvictions = null;
					return;
				}
			} else {
				this._onChannelEvicted?.(scidHex);
				return;
			}
		}

		this._channels.set(scidHex, channel);
		this._syncUnverifiedIndex(scidHex, channel);

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

		this._flushDeferredNodeEvictions();
	}

	/**
	 * Restore a node directly into the graph (bypasses graph validation).
	 * Unresolved provenance is settled per the policy in restoreChannel:
	 * eager verifies at once, lazy marks it deferred.
	 */
	restoreNode(node: IGraphNode): void {
		// Same repair as restoreChannel: a pre-bound far-future announcement
		// would camp the node's slot forever, so it is dropped and the next
		// real announcement takes the slot.
		if (
			node.announcement &&
			gossipTimestampTooFarFuture(node.announcement.timestamp)
		) {
			node.announcement = undefined;
		}
		const slot = sanitizeSlot(
			node.announcementVerified,
			node.announcementVerifyDeferred
		);
		if (node.announcement) {
			if (this._eagerVerify) {
				node.announcementVerified =
					slot.verified ?? verifyNodeAnnouncementMessage(node.announcement);
				node.announcementVerifyDeferred = undefined;
			} else {
				node.announcementVerified = slot.verified;
				node.announcementVerifyDeferred =
					slot.verified === undefined ? true : undefined;
			}
		} else {
			node.announcementVerified = undefined;
			node.announcementVerifyDeferred = undefined;
		}
		const nodeHex = node.nodeId.toString('hex');
		const existing = this._nodes.get(nodeHex);
		if (existing) {
			existing.announcement = node.announcement;
			existing.announcementVerified = node.announcementVerified;
			existing.announcementVerifyDeferred = node.announcementVerifyDeferred;
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
			// Deferred entries ARE advertised (issue #443): a reply_channel_range
			// carries only SCIDs, not gossip data, and verifying during this
			// full-graph scan would be unbounded. The follow-up
			// query_short_channel_ids is where resolution happens; an entry that
			// then fails simply gets omitted from that reply.
			if (
				channel.announcementVerified !== true &&
				channel.announcementVerifyDeferred !== true
			) {
				continue;
			}
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
	 * In eager mode (relay-class nodes) an SCID also counts as missing when a
	 * held message is signatureless (RGS-primed): the signed copy is worth
	 * re-fetching because it upgrades the entry to servable. Entries whose
	 * signatures are real but failed verification are NOT re-requested; the
	 * peer would re-serve the same bytes and the fetch would loop forever.
	 */
	getMissingSCIDs(remoteScids: Buffer[]): Buffer[] {
		return remoteScids.filter((scid) => {
			const channel = this._channels.get(scid.toString('hex'));
			if (!channel) return true;
			if (!this._eagerVerify) return false;
			return (
				isSignatureless(channel.announcement.nodeSignature1) ||
				(channel.update1 !== undefined &&
					isSignatureless(channel.update1.signature)) ||
				(channel.update2 !== undefined &&
					isSignatureless(channel.update2.signature))
			);
		});
	}

	/**
	 * Get all gossip messages (announcement + updates + node announcements) for a set of SCIDs.
	 * Used to respond to query_short_channel_ids. `complete` is false when a
	 * channel was omitted only because the shared verification budget ran
	 * out; the caller reports it through the end marker's full_information
	 * bit so the requester knows the reply omitted known data.
	 */
	getGossipMessagesForChannels(scids: Buffer[]): {
		announcements: IChannelAnnouncementMessage[];
		updates: IChannelUpdateMessage[];
		nodeAnnouncements: INodeAnnouncementMessage[];
		complete: boolean;
	} {
		const announcements: IChannelAnnouncementMessage[] = [];
		const updates: IChannelUpdateMessage[] = [];
		const seenNodes = new Set<string>();
		const nodeAnnouncements: INodeAnnouncementMessage[] = [];

		// Deferred provenance (issue #443) is resolved here, on demand: this is
		// the only place verification of foreign gossip pays for itself (the
		// right to serve the entry). The loop runs synchronously on the message
		// path, so resolution draws on a budget SHARED by every query in the
		// current window; a per-query timer would multiply with the query rate
		// and rebuild the very starvation this design avoids. Resolved flags
		// are sticky booleans, so no entry is ever verified twice in one
		// process lifetime.
		const now = Date.now();
		if (
			now - this._serveVerifyWindowStart >=
			NetworkGraph.SERVE_VERIFY_WINDOW_MS
		) {
			this._serveVerifyWindowStart = now;
			this._serveVerifySpentMs = 0;
		}
		let complete = true;

		for (const scid of scids) {
			const scidHex = scid.toString('hex');
			const channel = this._channels.get(scidHex);
			if (!channel) continue;

			// A channel is served atomically or not at all: partial output
			// (an announcement without its updates) would make the requester
			// record the SCID as synced and never ask for the omitted pieces
			// again.
			const nodesNeedingResolution = [channel.nodeId1, channel.nodeId2]
				.map((id) => id.toString('hex'))
				.filter((hex) => {
					if (seenNodes.has(hex)) return false;
					const n = this._nodes.get(hex);
					return (
						n?.announcement !== undefined &&
						n.announcementVerifyDeferred === true
					);
				});
			const needsResolution =
				channel.announcementVerifyDeferred === true ||
				(channel.update1 !== undefined &&
					channel.update1VerifyDeferred === true) ||
				(channel.update2 !== undefined &&
					channel.update2VerifyDeferred === true) ||
				nodesNeedingResolution.length > 0;

			if (needsResolution) {
				if (this._serveVerifySpentMs >= NetworkGraph.SERVE_VERIFY_BUDGET_MS) {
					// Budget exhausted: omit the whole channel from this reply.
					// It stays deferred, resolvable in a later window, and the
					// end marker reports the omission.
					complete = false;
					continue;
				}
				// Once started, a channel's slots settle as a group; the budget
				// overrun is bounded by one channel (at most 8 signature
				// checks: 4 announcement, 2 updates, 2 node announcements).
				const t0 = Date.now();
				if (channel.announcementVerifyDeferred === true) {
					channel.announcementVerified = verifyChannelAnnouncementMessage(
						channel.announcement
					);
					channel.announcementVerifyDeferred = undefined;
					this._syncUnverifiedIndex(scidHex, channel);
				}
				// The updates and node announcements of a non-servable channel
				// are never verified: its endpoint keys are unauthenticated.
				if (channel.announcementVerified === true) {
					if (
						channel.update1 !== undefined &&
						channel.update1VerifyDeferred === true
					) {
						channel.update1Verified = verifyChannelUpdateMessage(
							channel.update1,
							channel.nodeId1,
							channel.nodeId2
						);
						channel.update1VerifyDeferred = undefined;
					}
					if (
						channel.update2 !== undefined &&
						channel.update2VerifyDeferred === true
					) {
						channel.update2Verified = verifyChannelUpdateMessage(
							channel.update2,
							channel.nodeId1,
							channel.nodeId2
						);
						channel.update2VerifyDeferred = undefined;
					}
					for (const hex of nodesNeedingResolution) {
						const n = this._nodes.get(hex)!;
						n.announcementVerified = verifyNodeAnnouncementMessage(
							n.announcement!
						);
						n.announcementVerifyDeferred = undefined;
					}
				}
				this._serveVerifySpentMs += Date.now() - t0;
			}

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

		return { announcements, updates, nodeAnnouncements, complete };
	}
}
