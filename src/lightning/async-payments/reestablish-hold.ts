/**
 * Reestablish hold (issue #1726): a forward whose outgoing channel is
 * awaiting reestablish, to a wallet this node provides liquidity for, is
 * parked for a short window instead of failed at once. A phone wallet goes
 * quiet whenever its owner switches apps, and that is when the owner pays it
 * from the other app.
 *
 * The window runs from the peer's disconnect, not from the HTLC's arrival,
 * so a peer gone longer than the window gets no hold at all. The caps bound
 * what a payer (or a wallet paying itself) can pin on the payer-facing
 * channels: parts per peer, value per channel (no more than the channel
 * could carry when the peer left), and parts overall. Past any cap the part
 * is refused, never queued.
 *
 * The holds live in the held-forward ledger beside async holds, written
 * RELEASING: the channel's reestablish places them, and the CLTV cutoff,
 * the window or a restart's reconcile fails them.
 */

import {
	IHeldForwardRecord,
	isUnresolvedHeldForward
} from './held-forward-ledger';

export interface IReestablishHoldConfig {
	enabled: boolean;
	/** Window measured from the peer's disconnect (ms). */
	holdMs?: number;
	/** Parts held for one peer at once. */
	maxPartsPerPeer?: number;
	/** Parts held across every peer. */
	maxHolds?: number;
}

export interface IReestablishHoldLimits {
	holdMs: number;
	maxPartsPerPeer: number;
	maxHolds: number;
}

/** Covers a switch to another app, the payment, the switch back and the redial. */
export const DEFAULT_REESTABLISH_HOLD_MS = 180_000;
/** The JIT engine's hold budget, so the LSP role has one hold ceiling. */
export const MAX_REESTABLISH_HOLD_MS = 300_000;
export const DEFAULT_REESTABLISH_HOLD_PARTS_PER_PEER = 10;
export const DEFAULT_REESTABLISH_HOLD_MAX_HOLDS = 200;

/** Null when the hold is off. */
export function resolveReestablishHold(
	cfg: IReestablishHoldConfig | undefined
): IReestablishHoldLimits | null {
	if (!cfg?.enabled) return null;
	const holdMs = Math.min(
		Math.max(0, cfg.holdMs ?? DEFAULT_REESTABLISH_HOLD_MS),
		MAX_REESTABLISH_HOLD_MS
	);
	if (holdMs === 0) return null;
	return {
		holdMs,
		maxPartsPerPeer:
			cfg.maxPartsPerPeer ?? DEFAULT_REESTABLISH_HOLD_PARTS_PER_PEER,
		maxHolds: cfg.maxHolds ?? DEFAULT_REESTABLISH_HOLD_MAX_HOLDS
	};
}

export function isReestablishHold(record: IHeldForwardRecord): boolean {
	return record.kind === 'reestablish';
}

export type ReestablishHoldRefusal =
	| 'disconnect_unknown'
	| 'peer_gone_too_long'
	| 'past_cutoff'
	| 'peer_count'
	| 'channel_value'
	| 'global_count';

export interface IReestablishHoldCandidate {
	peerHex: string;
	outChannelIdHex: string;
	forwardAmountMsat: bigint;
	cutoffHeight: number;
	/** What the channel can still send the peer; it cannot change while the peer is away. */
	channelSendableMsat: bigint;
	/** When the peer's channels went to reestablish; undefined if not seen in this process. */
	disconnectedAt: number | undefined;
	now: number;
	height: number;
}

/**
 * Judge one part against the window and the caps. Pure over `records`: the
 * caller writes the row in the same synchronous step as this verdict.
 */
export function judgeReestablishHold(
	c: IReestablishHoldCandidate,
	records: IHeldForwardRecord[],
	limits: IReestablishHoldLimits
):
	| { ok: true; holdUntil: number }
	| { ok: false; reason: ReestablishHoldRefusal } {
	if (c.disconnectedAt === undefined) {
		return { ok: false, reason: 'disconnect_unknown' };
	}
	const holdUntil = c.disconnectedAt + limits.holdMs;
	if (c.now >= holdUntil) return { ok: false, reason: 'peer_gone_too_long' };
	if (c.height > 0 && c.height >= c.cutoffHeight) {
		return { ok: false, reason: 'past_cutoff' };
	}
	let total = 0;
	let peerParts = 0;
	let channelMsat = 0n;
	for (const r of records) {
		if (!isReestablishHold(r) || !isUnresolvedHeldForward(r.state)) continue;
		total++;
		if (r.receiverNodeIdHex === c.peerHex) peerParts++;
		if (r.outChannelIdHex === c.outChannelIdHex) {
			channelMsat += BigInt(r.forwardAmountMsat);
		}
	}
	if (peerParts + 1 > limits.maxPartsPerPeer) {
		return { ok: false, reason: 'peer_count' };
	}
	if (channelMsat + c.forwardAmountMsat > c.channelSendableMsat) {
		return { ok: false, reason: 'channel_value' };
	}
	if (total + 1 > limits.maxHolds) return { ok: false, reason: 'global_count' };
	return { ok: true, holdUntil };
}
