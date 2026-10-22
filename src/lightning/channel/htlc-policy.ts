/**
 * HTLC policy: the channel reserves, dust classification and exposure, the
 * funder-fee views of each commitment, and the refusals built from them.
 * Each function reads the state it is given and changes nothing.
 */

import type { IChannelState } from './channel-state';
import type { IHtlcEntry } from './types';
import {
	ChannelRole,
	HtlcDirection,
	HtlcState,
	isAnchorChannel
} from './types';
import type { IBuiltCommitment } from './commitment-builder';
import {
	buildLocalCommitment,
	buildRemoteCommitment,
	filterUntrimmedHtlcs,
	funderCommitmentCostSats,
	getCommitmentFeeRate,
	getLocalCommitmentFeeRate,
	getRemoteCommitmentFeeRate,
	HTLC_SUCCESS_WEIGHT
} from './commitment-builder';
import { bigIntMax, bigIntMin, getPerCommitmentPoint } from './channel-helpers';

/**
 * Compute channel reserve: 1% of funding (matching LND/CLN/Eclair),
 * floored at the greater of dust limit and 546 sats (LND's minimum),
 * capped at funding / 5 (20%). The cap is local policy for the reserve we
 * PROPOSE on a v1 open, not a spec rule: BOLT 2 states no maximum. It must
 * not be applied to a v2 channel, whose reserve is not negotiated at all
 * (see v2ReserveWeKeep).
 */
const MIN_CHANNEL_RESERVE_SATOSHIS = 546n; // LND enforces P2PKH dust limit as minimum reserve

export function computeChannelReserve(
	fundingSatoshis: bigint,
	dustLimitSatoshis: bigint
): bigint {
	const onePercent = fundingSatoshis / 100n;
	const maxReserve = fundingSatoshis / 5n;
	const minReserve =
		dustLimitSatoshis > MIN_CHANNEL_RESERVE_SATOSHIS
			? dustLimitSatoshis
			: MIN_CHANNEL_RESERVE_SATOSHIS;
	let reserve = onePercent;
	if (reserve < minReserve) reserve = minReserve;
	if (reserve > maxReserve) reserve = maxReserve;
	return reserve;
}

/**
 * The channel reserve of a v2 (dual-funded) channel, which BOLT 2 leaves out of
 * open_channel2/accept_channel2 entirely: "the channel reserve is fixed at 1% of
 * the total channel balance ... rounded down to the nearest whole satoshi or the
 * `dust_limit_satoshis`, whichever is greater." Both peers DERIVE it, so there is
 * nothing to negotiate and, crucially, no maximum: the v1 helper's 20% cap can
 * pull the result BELOW the dust limit on a small channel, which is exactly the
 * case the spec's dust floor exists to prevent (a reserve under dust admits a
 * commitment whose outputs all trim away, leaving no spendable exit).
 *
 * The spec does not say WHOSE dust_limit_satoshis floors it, and the two
 * reference implementations disagree: eclair (Commitments.scala localChannelReserve
 * / remoteChannelReserve) floors each side at the OTHER peer's dust limit, while
 * CLN (openingd/dualopend.c set_reserve) gives both sides one value floored at the
 * OPENER's. So the two sides are derived directionally instead of mirroring either,
 * which is safe against both peers at any dust pairing (and identical to both
 * whenever the two dust limits agree, which is every real pairing):
 *
 *   - the reserve WE keep takes the maximum, so it is never below either peer's
 *     dust limit and never below what a conforming peer requires of us. Being
 *     generous here only costs us spendable balance; the reserve is not on the
 *     wire and the commitment builder never reads it, so it cannot change
 *     commitment bytes. This is also the only variant that keeps our reserve
 *     output non-dust in BOTH commitments (BOLT 2's rationale for the v1 dust
 *     couplings is that each reserve sits above both dust limits).
 *   - the reserve we ENFORCE on the peer takes the minimum dust limit and skips
 *     beignet's stricter 546-sat policy floor, so it can never exceed what eclair
 *     (max(1%, our dust)) or CLN (max(1%, opener dust)) computes for itself in
 *     either role. A local policy applied here would reject an honest peer's
 *     spec-legal HTLC.
 *
 * Under-enforcing is inert as far as the peer's own gate is concerned, but NOT
 * as far as our own commitment is concerned: once the two dust limits differ,
 * this value sits below the limit OUR commitment trims at, so a peer balance
 * that clears it can still be dust to us. localCommitmentEmptyRefusal
 * is what keeps that from emptying the commitment we hold (issue #386).
 */
export function v2ReserveWeKeep(
	fundingSatoshis: bigint,
	ourDustLimitSatoshis: bigint,
	peerDustLimitSatoshis: bigint
): bigint {
	return bigIntMax(
		bigIntMax(fundingSatoshis / 100n, MIN_CHANNEL_RESERVE_SATOSHIS),
		bigIntMax(ourDustLimitSatoshis, peerDustLimitSatoshis)
	);
}

export function v2ReserveWeEnforce(
	fundingSatoshis: bigint,
	ourDustLimitSatoshis: bigint,
	peerDustLimitSatoshis: bigint
): bigint {
	return bigIntMax(
		fundingSatoshis / 100n,
		bigIntMin(ourDustLimitSatoshis, peerDustLimitSatoshis)
	);
}

/**
 * The reserve we may enforce on the peer at a given capacity, re-derived from a
 * row alone.
 *
 * The two callers (splice adoption and the load-time repair) both revisit the
 * enforced reserve of a channel that is already open, where the value we
 * advertised is either gone (a row written before issue #381 recorded it) or no
 * longer priced at the current capacity (a splice). Neither may land ABOVE what
 * the peer keeps for itself: over-enforcement refuses an HTLC the peer believes
 * is legal, the refusal is a bare ERROR action the peer never sees, and its next
 * commitment_signed then covers an HTLC we do not hold. Erring low is inert,
 * since the peer's own gate binds and no commitment builder reads this value.
 *
 * Which of the two rules the peer is applying is decided by the row, not by a
 * guess:
 *
 * - DERIVED, for a v2 row or any row that has ever been spliced. A v2 reserve
 *   was never negotiated, so both sides derive it. And eclair switches a channel
 *   to the derived rule for `DualFunding || fundingTxIndex > 0`
 *   (Commitments.scala localChannelReserve), i.e. once it has been spliced, v1
 *   included, keeping max(1% of capacity, a dust limit).
 *   v2ReserveWeEnforce is at or below that in either role and at either peer's
 *   dust pairing, which is exactly why it omits beignet's 546-sat policy floor:
 *   that floor sits above what a spliced peer keeps on a small capacity.
 *   spliceFundingTxid is the marker because it is persisted, starts null and is
 *   only ever assigned; fundingTxIndex is NOT a splice counter (adoption resets
 *   it to 0).
 * - NEGOTIATED, for an unspliced v1 row: the peer keeps the constant we
 *   advertised at open, which is computeChannelReserve at this capacity.
 *
 * The unspliced v1 branch deliberately omits the acceptor's peer-dust floor,
 * which is why it reproduces the OPENER's advertisement exactly and an
 * ACCEPTOR's only from below. That floor arrived in PR #115 and our own dust
 * floor in #381, while computeChannelReserve itself has not changed since the
 * first commit, so a row written before either advertised the unfloored value
 * and nothing on disk tells the two apart. Re-deriving today's floors would put
 * those rows above what their peer keeps, which is the failure this exists to
 * prevent; omitting them can only under-enforce. The unfloored result is still a
 * sound lower bound in both roles, since an acceptor's advertisement is a max
 * over it and an opener's open is refused outright when it lands under our own
 * dust limit (validateOpenChannelParams).
 *
 * A backup-recovered row hardcodes fundingVersion 1 even for a v2 channel, so it
 * takes the negotiated branch; that errs low, and such a row is ERRORED with
 * dataLossDetected and never admits an HTLC anyway.
 */
export function reserveWeEnforceAt(
	state: IChannelState,
	capacitySatoshis: bigint
): bigint {
	if (state.remoteReserveWaived) return 0n;
	const ourDust = state.localConfig.dustLimitSatoshis;
	if (state.fundingVersion === 2 || state.spliceFundingTxid) {
		return v2ReserveWeEnforce(
			capacitySatoshis,
			ourDust,
			state.remoteConfig.dustLimitSatoshis
		);
	}
	return computeChannelReserve(capacitySatoshis, ourDust);
}

/**
 * The splice in flight, as the policy below needs it: whether it is past
 * tx_signatures, the state re-anchored on its funding, and our balance and
 * reserve there. Channel answers these, since the spliced view comes from its
 * splice session rather than the state. They are methods, not values, so each
 * is computed only on the paths that ask.
 */
export interface IPendingSpliceView {
	isSplicePendingLock(): boolean;
	splicedState(base?: IChannelState): IChannelState | null;
	getPendingSpliceLocalBalanceMsat(): bigint | null;
	pendingSpliceKeptReserveSats(): bigint | null;
}

/**
 * BOLT 2 quiescence gate: stfu may only be sent (or honored) when no
 * UPDATES are pending, i.e. nothing is between "sent" and "irrevocably
 * committed by both sides". A fully-committed live HTLC is NOT a pending
 * update — rejecting stfu for one (the old behavior) made CLN/eclair
 * initiated quiescence (and thus splicing) on any busy channel stall until
 * the peer's quiescence timeout disconnected us (S-2.M8).
 */
export function hasPendingHtlcs(state: Readonly<IChannelState>): boolean {
	if (state.needsCommitment === true) {
		return true;
	}
	for (const entry of state.htlcs.values()) {
		// An add not yet committed by both sides.
		if (entry.state === HtlcState.PENDING) {
			return true;
		}
		// A removal in flight: fulfilled/failed entries are deleted once the
		// removal is fully committed, so their presence means it is not.
		if (
			entry.state === HtlcState.FULFILLED ||
			entry.state === HtlcState.FAILED
		) {
			return true;
		}
		// Two-phase flags mid-flight (false = the covering commitment round
		// has not completed; absent/true = settled).
		if (
			entry.addRemoteCommitted === false ||
			entry.addLocallyRevoked === false ||
			entry.removalRemoteCommitted === false ||
			entry.removalLocallyRevoked === false ||
			entry.commitCoverPending === true
		) {
			return true;
		}
	}
	return false;
}

/**
 * Whether an HTLC of this amount would be trimmed (dust) on at least one of
 * the two commitments at the given feerate. Mirrors the commitment builder's
 * trim rule (dust_limit + second-level tx fee): for non-anchor channels the
 * threshold is feerate-dependent, and every HTLC is a received-HTLC (success
 * weight, the larger of the two) on one side's commitment, so success weight
 * is the binding threshold regardless of direction. Anchor channels use
 * zero-fee second-level txs, making the threshold the static dust limit.
 */
function isDustHtlcAtRate(
	state: Readonly<IChannelState>,
	amountMsat: bigint,
	feeratePerKw: number
): boolean {
	const dustLimitSats =
		state.localConfig.dustLimitSatoshis > state.remoteConfig.dustLimitSatoshis
			? state.localConfig.dustLimitSatoshis
			: state.remoteConfig.dustLimitSatoshis;
	let secondLevelFeeSats = 0n;
	if (!isAnchorChannel(state.channelType)) {
		secondLevelFeeSats = BigInt(
			Math.floor((HTLC_SUCCESS_WEIGHT * feeratePerKw) / 1000)
		);
	}
	return amountMsat < (dustLimitSats + secondLevelFeeSats) * 1000n;
}

/** Whether an HTLC of this amount would be trimmed (dust) on the commitment. */
export function isDustHtlc(
	state: Readonly<IChannelState>,
	amountMsat: bigint
): boolean {
	return isDustHtlcAtRate(state, amountMsat, getCommitmentFeeRate(state));
}

/** Total in-flight dust-HTLC value (both directions) at a feerate, in msat. */
export function dustExposureAtRateMsat(
	state: Readonly<IChannelState>,
	feeratePerKw: number
): bigint {
	let total = 0n;
	for (const entry of state.htlcs.values()) {
		if (
			(entry.state === HtlcState.PENDING ||
				entry.state === HtlcState.COMMITTED) &&
			isDustHtlcAtRate(state, entry.amountMsat, feeratePerKw)
		) {
			total += entry.amountMsat;
		}
	}
	return total;
}

/** Total in-flight dust-HTLC value (both directions), in msat. */
export function dustExposureMsat(state: Readonly<IChannelState>): bigint {
	return dustExposureAtRateMsat(state, getCommitmentFeeRate(state));
}

export function initialWaivedCommitmentRefusal(
	state: Readonly<IChannelState>
): string | null {
	if (!state.localReserveWaived && !state.remoteReserveWaived) return null;
	const s = state;
	const opener = s.role === ChannelRole.OPENER;
	const cost =
		funderCommitmentCostSats(
			opener ? s.localConfig.feeratePerKw : s.remoteConfig.feeratePerKw,
			0,
			s.channelType
		) * 1000n;
	const ours = s.localBalanceMsat - (opener ? cost : 0n);
	const theirs = s.remoteBalanceMsat - (opener ? 0n : cost);
	const dust =
		bigIntMax(
			s.localConfig.dustLimitSatoshis,
			s.remoteConfig.dustLimitSatoshis
		) * 1000n;
	return ours < 0n || theirs < 0n || bigIntMax(ours, theirs) < dust
		? 'Initial commitment would have no outputs or insufficient commitment funding'
		: null;
}

export function waivedCommitmentRefusal(view: IChannelState): string | null {
	if (!view.localReserveWaived && !view.remoteReserveWaived) return null;
	if (view.localBalanceMsat < 0n || view.remoteBalanceMsat < 0n) {
		return 'Splice would leave a negative channel balance';
	}
	try {
		const n = view.localCommitmentNumber + 1n;
		const local = buildLocalCommitment(
			view,
			getPerCommitmentPoint(view.localPerCommitmentSeed, n),
			n
		);
		const remote = buildRemoteCommitment(
			view,
			view.remoteNextPerCommitmentPoint ??
				view.remoteCurrentPerCommitmentPoint!,
			view.remoteCommitmentNumber + 1n
		);
		for (const [built, side] of [
			[local, 'local'],
			[remote, 'remote']
		] as const) {
			const refusal = waivedCommitmentFundingRefusal(view, built, side);
			if (refusal) return refusal;
		}
		return local.result.tx.outs.length && remote.result.tx.outs.length
			? null
			: 'Operation would leave a commitment with no outputs';
	} catch {
		return 'Cannot build both commitments for the proposed operation';
	}
}

function waivedCommitmentFundingRefusal(
	view: IChannelState,
	built: IBuiltCommitment,
	side: 'local' | 'remote'
): string | null {
	const rate =
		side === 'local'
			? getLocalCommitmentFeeRate(view)
			: getRemoteCommitmentFeeRate(view);
	const cost = funderCommitmentCostSats(
		rate,
		built.htlcOutputs.length,
		view.channelType
	);
	if (built.funderBalanceMsat < cost * 1000n) {
		return 'Operation would leave the opener unable to pay its commitment cost';
	}
	const outputSats = built.result.tx.outs.reduce(
		(sum, output) => sum + BigInt(output.value),
		0n
	);
	return outputSats > view.fundingSatoshis
		? 'Commitment outputs exceed the funding amount'
		: null;
}

/**
 * Would the commitment WE hold be built with NO outputs once a peer-driven
 * update is applied? A refusal reason, or null (issue #386).
 *
 * The reserve we enforce on the peer floors at the LOWER of the two dust
 * limits (v2ReserveWeEnforce, and computeChannelReserve's capacity/5 cap can
 * land under our own dust limit too), so on an asymmetric-dust channel a
 * peer balance that clears its reserve can still be dust in OUR commitment.
 * Pair that with our own balance already under our dust limit, which a v2
 * open legitimately starts at whenever we contribute little or nothing, and
 * an ordinary update_add_htlc or update_fee produces a commitment with every
 * output trimmed. Nothing downstream catches it: the peer builds the same
 * bytes, so its signature verifies, and prepareForceClose would hand back a
 * transaction with no outputs, which cannot be broadcast. We would hold no
 * unilateral exit at all while the peer keeps one. This is the same rule
 * _v2InitialCommitmentRefusal applies at open, moved to where balances
 * actually change.
 *
 * The cheap gate first: when the reserve we enforce is at or above our own
 * dust limit, the peer's balance can never fall below it, so their to_remote
 * output in our commitment always survives and there is nothing to check.
 * Both handlers admit only when the peer keeps reserve + the commitment fee,
 * the builder's remote balance is never lower than the live one (it only
 * takes credits), and with no untrimmed HTLC the builder's fee is at or
 * below the estimate the handlers use. Every default-configured node sits on
 * that side of the gate, so the hot path is untouched.
 *
 * Past the gate it asks the REAL builder rather than repeating its
 * arithmetic. buildLocalCommitment also applies the deferred balance credits
 * of an in-flight settlement round, the second-level fee in the HTLC trim
 * threshold, the funder's anchor cost and the saturate-at-zero rule; a guard
 * that re-derived any of those would understate to_local mid-round and
 * refuse a commitment the builder builds with outputs, which is a force
 * close of a healthy channel.
 *
 * While a fully signed splice awaits its lock, the same question is asked
 * of the SPLICED view: _splicedState(candidate) re-anchors the candidate
 * on the new funding, deriving the peer's balance as the remainder of the
 * new capacity after in-flight HTLC value, so the add's amount counts once
 * rather than twice. The spliced half runs regardless of the cheap gate:
 * the reserve we enforce bounds only the peer's LIVE balance, and a peer
 * splice-out leaves a spliced remainder below it because reserves are not
 * re-derived until the lock (issue #382). It is skipped when the in-memory
 * session is not rebuilt (no spliced view exists to check);
 * _handleCommitmentSignedBatch independently fails closed there before any
 * revocation. getSpendableOutboundMsat still covers our own sends across
 * both views (issue #405).
 */
export function localCommitmentEmptyRefusal(
	state: Readonly<IChannelState>,
	splice: IPendingSpliceView,
	overrides: {
		localBalanceMsat?: bigint;
		remoteBalanceMsat?: bigint;
		pendingFeeratePerKw?: number;
		addedHtlc?: { key: string; entry: IHtlcEntry };
	}
): string | null {
	const ourDust = state.localConfig.dustLimitSatoshis;
	const waived = state.localReserveWaived || state.remoteReserveWaived;
	const liveHalf = waived || state.localConfig.channelReserveSatoshis < ourDust;
	const spliceHalf = splice.isSplicePendingLock();
	if (!liveHalf && !spliceHalf) return null;
	const candidate: IChannelState = { ...state };
	if (overrides.localBalanceMsat !== undefined)
		candidate.localBalanceMsat = overrides.localBalanceMsat;
	if (overrides.remoteBalanceMsat !== undefined) {
		candidate.remoteBalanceMsat = overrides.remoteBalanceMsat;
	}
	if (overrides.pendingFeeratePerKw !== undefined) {
		candidate.pendingFeeratePerKw = overrides.pendingFeeratePerKw;
	}
	if (overrides.addedHtlc) {
		candidate.htlcs = new Map(state.htlcs);
		candidate.htlcs.set(overrides.addedHtlc.key, overrides.addedHtlc.entry);
	}
	const next = state.localCommitmentNumber + 1n;
	const point = getPerCommitmentPoint(state.localPerCommitmentSeed, next);
	const emptyRefusal = (view: IChannelState, what: string): string | null => {
		let outputCount: number;
		try {
			const local = buildLocalCommitment(view, point, next);
			outputCount = local.result.tx.outs.length;
			if (waived) {
				const remote = buildRemoteCommitment(
					view,
					view.remoteNextPerCommitmentPoint ??
						view.remoteCurrentPerCommitmentPoint!,
					view.remoteCommitmentNumber + 1n
				);
				for (const [built, side] of [
					[local, 'local'],
					[remote, 'remote']
				] as const) {
					const refusal = waivedCommitmentFundingRefusal(view, built, side);
					if (refusal) return refusal;
				}
				if (remote.result.tx.outs.length === 0)
					return `Update would trim every output of the remote ${what}`;
			}
		} catch {
			// A commitment we cannot build is strictly worse than one we can,
			// so this refuses rather than admitting on the builder's behalf.
			// It needs remoteBasepoints and fundingTxid, which any channel
			// taking peer updates already has.
			return `Cannot build the ${what} this update would leave us holding`;
		}
		if (outputCount > 0) return null;
		return `Update would trim every output of the ${what} we hold at the ${ourDust}-sat dust limit`;
	};
	const checkRates = (view: IChannelState, what: string): string | null => {
		const transient = emptyRefusal(view, what);
		if (transient) return transient;
		if (waived && overrides.pendingFeeratePerKw !== undefined) {
			const rate = overrides.pendingFeeratePerKw;
			return emptyRefusal(
				{
					...view,
					localConfig: { ...view.localConfig, feeratePerKw: rate },
					remoteConfig: { ...view.remoteConfig, feeratePerKw: rate },
					pendingFeeratePerKw: undefined
				},
				`${what} after the fee update commits`
			);
		}
		return null;
	};
	if (liveHalf) {
		const refusal = checkRates(candidate, 'commitment');
		if (refusal) return refusal;
	}
	if (spliceHalf) {
		const spliced = splice.splicedState(candidate);
		if (spliced) {
			// An update the NEW capacity cannot fund derives a negative
			// balance: the remainder invariant (local + remote + htlcs =
			// capacity) then puts more value in outputs than the spliced
			// funding holds, and the builder happily emits e.g. an
			// untrimmed HTLC output larger than the funding — a
			// consensus-invalid commitment an output-count check alone
			// accepts. With both derived balances non-negative the same
			// invariant bounds every output combination by the capacity,
			// so this is the complete underfunding check.
			if (spliced.localBalanceMsat < 0n || spliced.remoteBalanceMsat < 0n) {
				return `Update would overdraw the ${spliced.fundingSatoshis}-sat pending-splice capacity`;
			}
			return checkRates(spliced, 'pending-splice commitment');
		} else if (waived) {
			return 'Cannot verify the pending-splice commitments until restoration completes';
		}
	}
	return null;
}

/**
 * The three readings of "what the funder holds and pays" behind the
 * funder-fee guards (issue #1020). Each returns the balance to set
 * against the reserve, the untrimmed HTLC count the builder fees, the
 * rate that count was classified at and funderCommitmentCostSats of it
 * (the BOLT 3 fee at the channel type's base weight plus, on anchor
 * channels, the two 330-sat anchor outputs the builder deducts on top),
 * in msat. Counting goes through the builder's own filterUntrimmedHtlcs
 * (the whole-satoshi amount against dust limit plus second-level fee,
 * timeout weight for an offered output and success weight for a received
 * one, no second-level fee on anchor channels), never countActiveHtlcs,
 * which counts trimmed entries the builder does not fee (#1047).
 */
function countUntrimmedRows(
	state: Readonly<IChannelState>,
	rows: { amount: bigint; direction: HtlcDirection }[],
	dustLimitSats: bigint,
	feeratePerKw: number
): number {
	return filterUntrimmedHtlcs(
		rows,
		dustLimitSats,
		feeratePerKw,
		isAnchorChannel(state.channelType)
	).length;
}

export function funderCostMsat(
	state: Readonly<IChannelState>,
	feeratePerKw: number,
	untrimmed: number
): bigint {
	return (
		funderCommitmentCostSats(feeratePerKw, untrimmed, state.channelType) * 1000n
	);
}

/**
 * What a peer that funds pays on the commitment WE hold, which is what
 * LND, eclair and CLN price a funder's update_add_htlc or update_fee
 * against on receipt: every PENDING or COMMITTED entry plus the
 * candidates, trimmed at our dust limit under our commitment's direction
 * rule. BOLT 3 charges weight only for untrimmed outputs, so counting a
 * trimmed one failed an honest funder holding dust HTLCs (#1047).
 */
export function remoteFunderLocalCostMsat(
	state: Readonly<IChannelState>,
	feeratePerKw: number,
	candidates: { amountMsat: bigint; direction: HtlcDirection }[]
): bigint {
	const rows: { amount: bigint; direction: HtlcDirection }[] = [];
	for (const entry of state.htlcs.values()) {
		if (
			entry.state === HtlcState.PENDING ||
			entry.state === HtlcState.COMMITTED
		) {
			rows.push({
				amount: entry.amountMsat / 1000n,
				direction: entry.direction
			});
		}
	}
	for (const c of candidates) {
		rows.push({ amount: c.amountMsat / 1000n, direction: c.direction });
	}
	const untrimmed = countUntrimmedRows(
		state,
		rows,
		state.localConfig.dustLimitSatoshis,
		feeratePerKw
	);
	return funderCostMsat(state, feeratePerKw, untrimmed);
}

/**
 * The view of OUR commitment a conforming peer holds when it decides
 * whether it may offer us an add, for the case where WE fund: eclair's
 * canSendAdd reduces remoteCommit.spec with remoteChanges.acked and
 * localChanges.proposed and prices commitTxTotalCost at OUR dust limit
 * and the spec's feerate; LND's validateCommitmentSanity at its acked
 * index and CLN's view at the recipient's feerate compute the same.
 *  - balance: localBalanceMsat, plus every offered add of ours the peer
 *    has not revoked for (addRemoteCommitted === false: addHtlc debits
 *    at send, the peer debits only at its revoke_and_ack), plus every
 *    offered HTLC of ours the peer has failed (its own proposal, in its
 *    view from the moment it sends it; handleRevokeAndAck lands the
 *    refund a round later). NO credit for a received HTLC we fulfilled:
 *    the peer applies our removal only once it has revoked for it, and
 *    handleRevokeAndAck credits and deletes the entry on that very
 *    revoke_and_ack, so while the entry is here the credit is unapplied
 *    and the output still stands (#1020 review: crediting it admitted
 *    98 adds and built a held commitment with no to_local).
 *  - outputs: every PENDING or COMMITTED entry in either direction except
 *    those same un-revoked adds of ours, plus every received HTLC whose
 *    removal the peer has not committed (removalRemoteCommitted ===
 *    false: the commitment we hold still carries it), plus the
 *    candidates, trimmed at OUR dust limit under our commitment's
 *    direction rule.
 *  - rate: getLocalCommitmentFeeRate, the rate the peer has revoked for.
 *    Our own staged update_fee applies to the commitment we hold only
 *    once the peer's revoke_and_ack promotes it; pricing a crossing add
 *    at the staged rate refused a legal add right after our own raise.
 * Every conforming sender stops at reserve plus this cost, so a refusal
 * past this line can never hit an honest peer.
 */
export function funderSenderView(
	state: Readonly<IChannelState>,
	candidates: { amountMsat: bigint; direction: HtlcDirection }[]
): {
	balanceMsat: bigint;
	untrimmed: number;
	feeratePerKw: number;
	costMsat: bigint;
} {
	let balanceMsat = state.localBalanceMsat;
	const rows: { amount: bigint; direction: HtlcDirection }[] = [];
	for (const entry of state.htlcs.values()) {
		const inFlight =
			entry.state === HtlcState.PENDING || entry.state === HtlcState.COMMITTED;
		if (entry.direction === HtlcDirection.OFFERED) {
			if (inFlight && entry.addRemoteCommitted === false) {
				balanceMsat += entry.amountMsat;
				continue;
			}
			if (entry.state === HtlcState.FAILED) {
				balanceMsat += entry.amountMsat;
				continue;
			}
			if (!inFlight) continue;
		} else if (!inFlight && entry.removalRemoteCommitted !== false) {
			continue;
		}
		rows.push({
			amount: entry.amountMsat / 1000n,
			direction: entry.direction
		});
	}
	for (const c of candidates) {
		rows.push({ amount: c.amountMsat / 1000n, direction: c.direction });
	}
	const feeratePerKw = getLocalCommitmentFeeRate(state);
	const untrimmed = countUntrimmedRows(
		state,
		rows,
		state.localConfig.dustLimitSatoshis,
		feeratePerKw
	);
	return {
		balanceMsat,
		untrimmed,
		feeratePerKw,
		costMsat: funderCostMsat(state, feeratePerKw, untrimmed)
	};
}

/**
 * The dearest reading of what we pay as funder, for the floor under which
 * an add fails the channel: every PENDING or COMMITTED entry in either
 * direction (our own un-revoked adds included, they enter the commitment
 * on the peer's next revoke_and_ack), every removal not yet out of a
 * commitment we sign (received with removalRemoteCommitted === false,
 * offered with removalLocallyRevoked === false), and the candidates,
 * trimmed at the LOWER of the two dust limits (the commitment trimming
 * lower carries every output the other does, and the fee comes off our
 * output on both: to_local on ours, to_remote on the peer's), priced at
 * the local and the remote commitment rate each with the count THAT rate
 * produces, keeping the dearer: mid fee round the two differ, and on
 * non-anchor channels the trim threshold moves with the rate, so neither
 * the higher rate nor the larger count alone is guaranteed to price the
 * dearer commitment. Set against the LIVE balance plus creditMsat: the
 * refund of every offered HTLC of ours the peer failed and we have revoked
 * for the removal of (removalLocallyRevoked !== false), which BOTH
 * builders already apply (buildLocalCommitment refunds it outright,
 * buildRemoteCommitment once we have revoked). One still awaiting our
 * revoke_and_ack stays an output and is not credited, since the remote
 * build does not refund it yet. No other deferred credit: a fulfilled
 * received HTLC's value stays out until the peer commits the removal.
 */
export function funderConservativeView(
	state: Readonly<IChannelState>,
	candidates: { amountMsat: bigint; direction: HtlcDirection }[]
): {
	untrimmed: number;
	feeratePerKw: number;
	costMsat: bigint;
	creditMsat: bigint;
} {
	const rows: { amount: bigint; direction: HtlcDirection }[] = [];
	let creditMsat = 0n;
	for (const entry of state.htlcs.values()) {
		const present =
			entry.state === HtlcState.PENDING ||
			entry.state === HtlcState.COMMITTED ||
			(entry.direction === HtlcDirection.RECEIVED
				? entry.removalRemoteCommitted === false
				: entry.removalLocallyRevoked === false);
		if (!present) {
			if (
				entry.direction === HtlcDirection.OFFERED &&
				entry.state === HtlcState.FAILED
			) {
				creditMsat += entry.amountMsat;
			}
			continue;
		}
		rows.push({
			amount: entry.amountMsat / 1000n,
			direction: entry.direction
		});
	}
	for (const c of candidates) {
		rows.push({ amount: c.amountMsat / 1000n, direction: c.direction });
	}
	const dustLimitSats = bigIntMin(
		state.localConfig.dustLimitSatoshis,
		state.remoteConfig.dustLimitSatoshis
	);
	const priceAt = (
		feeratePerKw: number
	): {
		untrimmed: number;
		feeratePerKw: number;
		costMsat: bigint;
		creditMsat: bigint;
	} => {
		const untrimmed = countUntrimmedRows(
			state,
			rows,
			dustLimitSats,
			feeratePerKw
		);
		return {
			untrimmed,
			feeratePerKw,
			costMsat: funderCostMsat(state, feeratePerKw, untrimmed),
			creditMsat
		};
	};
	const local = priceAt(getLocalCommitmentFeeRate(state));
	const remoteRate = getRemoteCommitmentFeeRate(state);
	if (remoteRate === local.feeratePerKw) return local;
	const remote = priceAt(remoteRate);
	return remote.costMsat > local.costMsat ? remote : local;
}

/**
 * eclair's climb-out regime (Commitments.canSendAdd on a spliced channel):
 * once the funding has moved, and while fewer than 5 HTLCs are in the
 * map, eclair offers an add while the funder's balance merely exceeds the
 * fee, reserve or not, so that a funder a splice-out left under its
 * reserve can climb back out. The receive-side arm admits those adds
 * outright and the sign-time backstop tolerates a remainder under the
 * dust limit in this regime, refusing only a fee that exceeds our whole
 * balance (eclair's own canReceiveAdd bound). The exposure is bounded by
 * four fee slots. The map size is the population eclair counts, settled
 * entries awaiting their round included.
 */
export function inSplicedClimbOut(view: IChannelState): boolean {
	return view.hasBeenSpliced === true && view.htlcs.size < 5;
}

/**
 * The sign-time backstop of the funder-fee guards (issue #1020): the
 * receive-side arm bounds each add on the LIVE state, and two
 * protocol-legal changes of state can carry a set of admitted adds past
 * that bound afterwards. The peer's revoke_and_ack promoting a fee raise
 * of ours re-prices every add it admitted at the old rate, and its
 * revoke_and_ack for an add of our own brings that add, credited back
 * until then, into the count. LND holds the line at signing time
 * (SignNextCommitment re-runs validateCommitmentSanity on the remote
 * chain and fails the channel with its balance intact); so does this.
 *
 * Asked of the commitment about to be signed (the peer's, our output is
 * its to_remote) or accepted (ours, our output is its to_local), built
 * by the real builder at the rate that applies to it, so the answer is
 * exact once the promoted rate is known. A refusal here is a wire
 * failure: the commitments we then hold and would broadcast are the
 * earlier ones, with our output in them. Only a funder's output can be
 * trimmed by the fee, and only when its balance clears the dust limit is
 * the absence the fee's doing: below it the output is absent whatever the
 * fee, and that is the reserve's business, not this guard's. In eclair's
 * climb-out regime the remainder under the dust limit is tolerated and
 * only a fee exceeding our whole balance refuses (its canReceiveAdd
 * bound), or every add that branch admits would fail here.
 */
export function funderOutputTrimmedRefusal(
	view: IChannelState,
	side: 'local' | 'remote',
	perCommitmentPoint: Buffer,
	commitmentNumber: bigint
): string | null {
	if (view.role !== ChannelRole.OPENER) return null;
	if (!view.remoteBasepoints || !view.fundingTxid) return null;
	const dustSats =
		side === 'local'
			? view.localConfig.dustLimitSatoshis
			: view.remoteConfig.dustLimitSatoshis;
	const balanceSats = view.localBalanceMsat / 1000n;
	if (!view.localReserveWaived && balanceSats < dustSats) return null;
	let built: IBuiltCommitment;
	try {
		built =
			side === 'local'
				? buildLocalCommitment(view, perCommitmentPoint, commitmentNumber)
				: buildRemoteCommitment(view, perCommitmentPoint, commitmentNumber);
	} catch {
		// Unbuildable here is unbuildable at the signing or verifying step
		// that follows, which answers with its own reason.
		return null;
	}
	const ours =
		side === 'local'
			? built.result.outputMap.toLocal
			: built.result.outputMap.toRemote;
	if (ours !== undefined) return null;
	if (view.localReserveWaived || inSplicedClimbOut(view)) {
		const feeratePerKw =
			side === 'local'
				? getLocalCommitmentFeeRate(view)
				: getRemoteCommitmentFeeRate(view);
		const feeSats = funderCommitmentCostSats(
			feeratePerKw,
			built.htlcOutputs.length,
			view.channelType
		);
		const funderSats = view.localReserveWaived
			? built.funderBalanceMsat / 1000n
			: balanceSats;
		if (feeSats <= funderSats && built.result.tx.outs.length > 0) return null;
	}
	return 'Commitment would trim our output to fees';
}

/**
 * funderSenderView from the other chair, for the case where the PEER
 * funds and we are about to offer it adds: the view the funder holds of
 * ITS commitment, read from our book, so that what we offer is what its
 * own guard admits.
 *  - balance: remoteBalanceMsat, plus every add of the funder's we have
 *    not revoked for (addLocallyRevoked === false: handleUpdateAddHtlc
 *    debited it at receipt, the funder's own view debits it only on our
 *    revoke_and_ack), plus every HTLC of the funder's we failed (our
 *    proposal, credited by every sender), plus every offered HTLC of
 *    ours the funder fulfilled once we have revoked for the removal
 *    (removalLocallyRevoked === true: that revoke_and_ack is what lets
 *    the funder credit and delete it; before it the funder's view still
 *    carries the output and no credit).
 *  - outputs: every PENDING or COMMITTED entry except those same
 *    un-revoked adds of the funder's, plus every offered HTLC of ours
 *    whose removal we have not revoked for (removalLocallyRevoked ===
 *    false), plus the candidates, trimmed at the FUNDER's dust limit
 *    under ITS commitment's direction rule: what we offer is a received
 *    output there (success weight), what we receive an offered one
 *    (timeout weight).
 *  - rate: getRemoteCommitmentFeeRate, the rate the funder has acked; its
 *    staged raise counts only once signable, i.e. once we revoked for the
 *    commitment_signed that carried it, which is when its own view
 *    promotes the rate.
 * extraSlots reserves that many further untrimmed HTLCs beyond the
 * candidates, charged only when a candidate is itself untrimmed there: a
 * trimmed add costs the funder no fee weight, and LND and eclair senders
 * offer one at zero slots.
 */
function remoteFunderSenderView(
	state: Readonly<IChannelState>,
	candidates: { amountMsat: bigint; direction: HtlcDirection }[],
	extraSlots: number
): {
	balanceMsat: bigint;
	untrimmed: number;
	feeratePerKw: number;
	costMsat: bigint;
} {
	let balanceMsat = state.remoteBalanceMsat;
	const rows: { amount: bigint; direction: HtlcDirection }[] = [];
	const onFunder = (direction: HtlcDirection): HtlcDirection =>
		direction === HtlcDirection.OFFERED
			? HtlcDirection.RECEIVED
			: HtlcDirection.OFFERED;
	for (const entry of state.htlcs.values()) {
		const inFlight =
			entry.state === HtlcState.PENDING || entry.state === HtlcState.COMMITTED;
		if (entry.direction === HtlcDirection.RECEIVED) {
			if (inFlight && entry.addLocallyRevoked === false) {
				balanceMsat += entry.amountMsat;
				continue;
			}
			if (entry.state === HtlcState.FAILED) {
				balanceMsat += entry.amountMsat;
				continue;
			}
			if (!inFlight) continue;
		} else if (!inFlight) {
			if (entry.removalLocallyRevoked !== false) {
				if (entry.state === HtlcState.FULFILLED) {
					balanceMsat += entry.amountMsat;
				}
				continue;
			}
		}
		rows.push({
			amount: entry.amountMsat / 1000n,
			direction: onFunder(entry.direction)
		});
	}
	const candidateRows = candidates.map((c) => ({
		amount: c.amountMsat / 1000n,
		direction: onFunder(c.direction)
	}));
	const feeratePerKw = getRemoteCommitmentFeeRate(state);
	const dustLimitSats = state.remoteConfig.dustLimitSatoshis;
	const untrimmedCandidates = countUntrimmedRows(
		state,
		candidateRows,
		dustLimitSats,
		feeratePerKw
	);
	const untrimmed =
		countUntrimmedRows(state, rows, dustLimitSats, feeratePerKw) +
		untrimmedCandidates +
		(untrimmedCandidates > 0 ? extraSlots : 0);
	return {
		balanceMsat,
		untrimmed,
		feeratePerKw,
		costMsat: funderCostMsat(state, feeratePerKw, untrimmed)
	};
}

/**
 * A reading of our balance above the reserve the peer requires of us,
 * bound by the pending-splice view while a splice awaits its lock,
 * exactly as updateFee's send side binds: an add admitted now rides both
 * commitments, and the spliced one has its own balance (a splice-out
 * leaves less) and its own reserve (priced at the pending capacity). The
 * spliced balance derives from the LIVE figure, so the reading's
 * adjustments are carried onto it.
 */
export function funderHeadroomMsat(
	state: Readonly<IChannelState>,
	splice: IPendingSpliceView,
	balanceMsat: bigint
): bigint {
	const adjustMsat = balanceMsat - state.localBalanceMsat;
	let headroomMsat =
		balanceMsat - state.remoteConfig.channelReserveSatoshis * 1000n;
	const pendingMsat = splice.getPendingSpliceLocalBalanceMsat();
	const pendingReserveSats = splice.pendingSpliceKeptReserveSats();
	if (pendingMsat !== null && pendingReserveSats !== null) {
		const pendingHeadroomMsat =
			pendingMsat + adjustMsat - pendingReserveSats * 1000n;
		if (pendingHeadroomMsat < headroomMsat) {
			headroomMsat = pendingHeadroomMsat;
		}
	}
	return headroomMsat;
}

/** The lesser of our live balance and its pending-splice reading. */
export function funderLiveBalanceFloorMsat(
	state: Readonly<IChannelState>,
	splice: IPendingSpliceView
): bigint {
	const pendingMsat = splice.getPendingSpliceLocalBalanceMsat();
	return pendingMsat !== null && pendingMsat < state.localBalanceMsat
		? pendingMsat
		: state.localBalanceMsat;
}

/**
 * A reading of the funder's balance above the reserve we enforce, bound
 * by the pending-splice view. With the session rebuilt, _splicedState
 * derives the funder's spliced balance; after a restart it is derived
 * from the invariant the spliced state itself uses (new capacity = ours
 * + theirs + every entry's value) off the persisted record, so the
 * mirror never skips the view the funder's own guard binds on. That
 * fallback (getPendingSpliceLocalBalanceMsat) leaves the initiator's
 * splice-out fee in our own pending balance, so the funder's remainder
 * reads lower than it is: stricter only.
 */
export function remoteFunderHeadroomMsat(
	state: Readonly<IChannelState>,
	splice: IPendingSpliceView,
	balanceMsat: bigint
): bigint {
	const reserveSats = state.localConfig.channelReserveSatoshis;
	const adjustMsat = balanceMsat - state.remoteBalanceMsat;
	let headroomMsat = balanceMsat - reserveSats * 1000n;
	const inFlight = state.spliceInFlight;
	if (!inFlight) return headroomMsat;
	const spliced = splice.splicedState();
	let pendingMsat: bigint | null = null;
	let pendingCapacity = inFlight.newFundingSatoshis;
	if (spliced) {
		pendingMsat = spliced.remoteBalanceMsat;
		pendingCapacity = spliced.fundingSatoshis;
	} else {
		const pendingLocalMsat = splice.getPendingSpliceLocalBalanceMsat();
		if (pendingLocalMsat !== null) {
			let htlcMsat = 0n;
			for (const e of state.htlcs.values()) htlcMsat += e.amountMsat;
			pendingMsat = pendingCapacity * 1000n - pendingLocalMsat - htlcMsat;
		}
	}
	if (pendingMsat !== null) {
		// The reserve the funder keeps on the pending capacity, floored at
		// the stored value: the mirror of _pendingSpliceKeptReserveSats.
		const pendingReserveSats = state.remoteReserveWaived
			? 0n
			: bigIntMax(
					reserveSats,
					v2ReserveWeKeep(
						pendingCapacity,
						state.remoteConfig.dustLimitSatoshis,
						state.localConfig.dustLimitSatoshis
					)
			  );
		const pendingHeadroomMsat =
			pendingMsat + adjustMsat - pendingReserveSats * 1000n;
		if (pendingHeadroomMsat < headroomMsat) {
			headroomMsat = pendingHeadroomMsat;
		}
	}
	return headroomMsat;
}

/**
 * The send-side mirror of the funder-side arm in handleUpdateAddHtlc,
 * for the case where the PEER funds: null when the funder's own view of
 * its commitment (remoteFunderSenderView) still keeps its reserve plus
 * the funder's cost with these offered adds in, else the local error to
 * answer with. One extra untrimmed slot is kept beyond the adds so a
 * sats-scale difference between the two books can only make this side
 * refuse first: a refusal here costs a retry, the funder's costs the
 * channel (issue #1020). Nothing to ask when we fund:
 * getSpendableOutboundMsat already retains our own fee with a buffer.
 */
export function remoteFunderFeeRefusal(
	state: Readonly<IChannelState>,
	splice: IPendingSpliceView,
	amounts: bigint[]
): string | null {
	if (state.role !== ChannelRole.ACCEPTOR) return null;
	const view = remoteFunderSenderView(
		state,
		amounts.map((amountMsat) => ({
			amountMsat,
			direction: HtlcDirection.OFFERED
		})),
		1
	);
	if (
		remoteFunderHeadroomMsat(state, splice, view.balanceMsat) >= view.costMsat
	) {
		return null;
	}
	return 'Remote funder cannot afford commitment fee for HTLC';
}

/**
 * The outbound ceiling folded with the mirror, so the router and MPP
 * planning never select an add remoteFunderFeeRefusal then refuses:
 * unchanged while the funder can take one more untrimmed HTLC with the
 * slot to spare (the cost of its untrimmed set plus two), capped at the
 * largest amount that trims on the funder's commitment while it can
 * still carry the set it has (a trimmed add costs it no fee weight and no
 * slot), zero below that. Not the funder's headroom itself: our sends do
 * not draw on the funder's balance, so subtracting its cost from our
 * ceiling would under-report a healthy channel by the funder's whole
 * slack.
 */
export function remoteFunderCeilingMsat(
	state: Readonly<IChannelState>,
	splice: IPendingSpliceView,
	spendableMsat: bigint
): bigint {
	if (state.role !== ChannelRole.ACCEPTOR) return spendableMsat;
	// The funder's untrimmed set as it stands; an untrimmed add of ours
	// needs the funder to carry it plus the spare slot (two more), a
	// trimmed one needs nothing beyond the set itself.
	const current = remoteFunderSenderView(state, [], 0);
	const headroomMsat = remoteFunderHeadroomMsat(
		state,
		splice,
		current.balanceMsat
	);
	if (
		headroomMsat >=
		funderCostMsat(state, current.feeratePerKw, current.untrimmed + 2)
	) {
		return spendableMsat;
	}
	if (headroomMsat < current.costMsat) return 0n;
	// An add of ours is a received output on the funder's commitment:
	// trimmed below its dust limit plus the HTLC-success fee at the rate
	// the funder has acked (no second-level fee on anchor channels).
	let secondLevelFeeSats = 0n;
	if (!isAnchorChannel(state.channelType)) {
		secondLevelFeeSats = BigInt(
			Math.floor((HTLC_SUCCESS_WEIGHT * current.feeratePerKw) / 1000)
		);
	}
	const trimmedCapMsat =
		(state.remoteConfig.dustLimitSatoshis + secondLevelFeeSats) * 1000n - 1n;
	return trimmedCapMsat < spendableMsat ? trimmedCapMsat : spendableMsat;
}

export function countActiveHtlcs(state: Readonly<IChannelState>): number {
	let count = 0;
	for (const entry of state.htlcs.values()) {
		if (
			entry.state === HtlcState.PENDING ||
			entry.state === HtlcState.COMMITTED
		) {
			count++;
		}
	}
	return count;
}

export function countPendingHtlcs(
	state: Readonly<IChannelState>,
	direction: HtlcDirection
): number {
	let count = 0;
	for (const entry of state.htlcs.values()) {
		if (
			entry.direction === direction &&
			(entry.state === HtlcState.PENDING || entry.state === HtlcState.COMMITTED)
		) {
			count++;
		}
	}
	return count;
}

export function totalInFlightMsat(
	state: Readonly<IChannelState>,
	direction: HtlcDirection
): bigint {
	let total = 0n;
	for (const entry of state.htlcs.values()) {
		if (
			entry.direction === direction &&
			(entry.state === HtlcState.PENDING || entry.state === HtlcState.COMMITTED)
		) {
			total += entry.amountMsat;
		}
	}
	return total;
}
