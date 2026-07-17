/**
 * BOLT 3: Commitment transaction building integration.
 *
 * Bridges Phase 2 script builders into the channel state machine,
 * coordinating key derivation, transaction construction, and signing
 * per commitment.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { derivePublicKey, deriveRevocationPubkey } from '../keys/derivation';
import { verify } from '../crypto/ecdh';
import { ISigner } from '../keys/signer';
import {
	buildCommitmentTx,
	calculateObscuredCommitmentNumber,
	ICommitmentTxParams,
	ICommitmentTxResult,
	IHtlcOutput
} from '../script/commitment';
import { createFundingScript } from '../script/funding';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript,
	buildHtlcSuccessTx,
	buildHtlcTimeoutTx
} from '../script/htlc';
import { ANCHOR_TOTAL_COST } from '../script/anchor';
import { IChannelState } from './channel-state';
import {
	ChannelRole,
	HtlcDirection,
	HtlcState,
	isAnchorChannel,
	isTaprootChannel
} from './types';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootAnchorOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput
} from '../script/commitment-taproot';
import { createTaprootFundingScript } from '../script/funding-taproot';
import {
	buildTaprootHtlcSuccessTx,
	buildTaprootHtlcTimeoutTx,
	taprootHtlcLeafSighash,
	verifyTaprootHtlcLeaf
} from '../script/htlc-taproot';
import {
	taprootCommitmentSighash,
	startCommitmentSigningSession,
	verifyPartialCommitmentSig,
	aggregateCommitmentSig
} from './commitment-musig';

/**
 * option_taproot: build the P2TR scriptPubKey for an HTLC output (or undefined
 * for non-taproot channels). `kind` is the script class actually used for this
 * commitment side (already direction-resolved by the caller, matching the
 * witness-v0 offered/received choice).
 */
function taprootHtlcScript(
	isTaproot: boolean,
	kind: 'offered' | 'received',
	keys: ICommitmentKeys,
	paymentHash: Buffer,
	cltvExpiry: number
): Buffer | undefined {
	if (!isTaproot) return undefined;
	if (kind === 'offered') {
		return buildTaprootOfferedHtlcOutput(
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			paymentHash
		).output;
	}
	return buildTaprootReceivedHtlcOutput(
		keys.revocationPubkey,
		keys.localHtlcPubkey,
		keys.remoteHtlcPubkey,
		paymentHash,
		cltvExpiry
	).output;
}

/**
 * option_taproot: replace the to_local / to_remote / anchor scriptPubKeys with
 * P2TR overrides when the channel is taproot. Uses the keys already resolved on
 * `params` (correct for whichever commitment side is being built), so non-taproot
 * channels are completely untouched. NOTE: lease-expiry CLTV on a taproot
 * to_local is not yet modelled (lease+taproot is an unsupported combination).
 */
function applyTaprootCommitOverrides(
	params: ICommitmentTxParams,
	channelType: Buffer | null
): void {
	if (!isTaprootChannel(channelType)) return;
	params.taprootToLocalScript = buildTaprootToLocalOutput(
		params.revocationPubkey,
		params.localDelayedPubkey,
		params.toSelfDelay
	).output;
	params.taprootToRemoteScript = buildTaprootToRemoteOutput(
		params.remotePaymentPubkey
	).output;
	// Taproot anchors are keyed to the COMMITMENT keys, NOT the funding/multisig
	// keys used by legacy anchor channels: local anchor → ToLocalKey (the to_local
	// delayed pubkey), remote anchor → ToRemoteKey (the to_remote payment pubkey).
	// (LND CommitScriptAnchors taproot keySelector; verified live vs lnd v0.20.)
	params.taprootAnchorLocalScript = buildTaprootAnchorOutput(
		params.localDelayedPubkey
	).output;
	params.taprootAnchorRemoteScript = buildTaprootAnchorOutput(
		params.remotePaymentPubkey
	).output;
}

/** BOLT 3: HTLC-success transaction weight (without anchors) */
export const HTLC_SUCCESS_WEIGHT = 703;
/** BOLT 3: HTLC-timeout transaction weight (without anchors) */
export const HTLC_TIMEOUT_WEIGHT = 663;

/** BOLT 3: HTLC-success transaction weight (with anchors) */
export const HTLC_SUCCESS_WEIGHT_ANCHORS = 706;
/** BOLT 3: HTLC-timeout transaction weight (with anchors) */
export const HTLC_TIMEOUT_WEIGHT_ANCHORS = 666;

/** BOLT 3: Base commitment tx weight (both to_local and to_remote outputs) */
const COMMITMENT_TX_BASE_WEIGHT = 724;
/** BOLT 3: Base commitment tx weight with anchor outputs */
const COMMITMENT_TX_BASE_WEIGHT_ANCHORS = 1124;
/**
 * Base commitment tx weight for simple taproot channels (LND TaprootCommitWeight).
 * Lower than the witness-v0 anchor weight (1124) because the funding input is a
 * single 64-byte MuSig2 key-path Schnorr sig instead of a P2WSH 2-of-2 witness.
 * Verified live vs lnd v0.20: floor(968 * feerate / 1000) matches LND's funder fee.
 */
const COMMITMENT_TX_BASE_WEIGHT_TAPROOT = 968;
/** BOLT 3: Weight added per non-trimmed HTLC output */
const COMMITMENT_TX_HTLC_WEIGHT = 172;

/**
 * Calculate the commitment transaction fee per BOLT 3.
 * fee = floor((base_weight + 172 * num_untrimmed_htlcs) * feerate_per_kw / 1000)
 *
 * @param feeratePerKw - Fee rate in sat/kW (from opener's config)
 * @param numUntrimmedHtlcs - Number of non-dust HTLC outputs
 * @param isAnchor - Whether this is an anchor channel (uses higher base weight)
 */
export function calculateCommitmentFee(
	feeratePerKw: number,
	numUntrimmedHtlcs: number,
	isAnchor?: boolean,
	isTaproot?: boolean
): bigint {
	const baseWeight = isTaproot
		? COMMITMENT_TX_BASE_WEIGHT_TAPROOT
		: isAnchor
		? COMMITMENT_TX_BASE_WEIGHT_ANCHORS
		: COMMITMENT_TX_BASE_WEIGHT;
	const weight = baseWeight + COMMITMENT_TX_HTLC_WEIGHT * numUntrimmedHtlcs;
	return BigInt(Math.floor((weight * feeratePerKw) / 1000));
}

/**
 * BOLT 3 HTLC trimming: an HTLC is trimmed (no on-chain output) when its amount
 * is below the holder's dust_limit PLUS the fee its second-level (timeout for
 * offered, success for received) transaction would cost at the commitment
 * feerate. Anchor (zero-fee-HTLC) channels have a 0 second-level fee, so the
 * threshold is just the dust limit. Returns the HTLCs that survive trimming —
 * used for BOTH the commitment outputs and the num_untrimmed_htlcs fee count so
 * the two never diverge (a divergence builds a commitment the peer rejects).
 */
function filterUntrimmedHtlcs<
	T extends { amount: bigint; direction: HtlcDirection }
>(
	htlcOutputs: T[],
	dustLimitSat: bigint,
	feeratePerKw: number,
	isAnchor: boolean
): T[] {
	return htlcOutputs.filter((h) => {
		let htlcFeeSat = 0n;
		if (!isAnchor) {
			const weight =
				h.direction === HtlcDirection.OFFERED
					? HTLC_TIMEOUT_WEIGHT
					: HTLC_SUCCESS_WEIGHT;
			htlcFeeSat = BigInt(Math.floor((weight * feeratePerKw) / 1000));
		}
		return h.amount >= dustLimitSat + htlcFeeSat;
	});
}

/** The last COMMITTED channel feerate (fee rounds fully finalized). */
function committedFeeRate(state: IChannelState): number {
	return state.role === ChannelRole.OPENER
		? state.localConfig.feeratePerKw
		: state.remoteConfig.feeratePerKw;
}

/**
 * Get the fee rate for the commitment tx.
 * The opener sets the fee rate.
 *
 * Generic/advisory rate (dust-exposure guards, fee suggestions): the staged
 * update_fee rate when one is in flight, else the committed rate. Commitment
 * CONSTRUCTION must not use this — the staged rate applies to our local and
 * the peer's commitment at DIFFERENT points of the fee round (BOLT 2
 * two-phase updates); use getLocalCommitmentFeeRate /
 * getRemoteCommitmentFeeRate instead.
 */
export function getCommitmentFeeRate(
	state: IChannelState,
	signedLocal = false
): number {
	// Rebuilding the CURRENT SIGNED local commitment (force-close, on-chain
	// claims of pre-signed second-level HTLC txs): use the exact rate the
	// stored remote signature was verified against. Mid-fee-round the in-flight
	// rate below can differ from it, and any difference changes the sighash and
	// invalidates the signature.
	if (signedLocal && state.lastSignedCommitFeeratePerKw !== undefined) {
		return state.lastSignedCommitFeeratePerKw;
	}
	if (state.pendingFeeratePerKw !== undefined) {
		return state.pendingFeeratePerKw;
	}
	return committedFeeRate(state);
}

/**
 * Fee rate for OUR local commitment — verifying the peer's commitment_signed
 * or rebuilding what they signed.
 *
 * Acceptor: a staged remote update_fee applies IMMEDIATELY — the opener bakes
 * its own fee into every signature it produces from the moment it sends
 * update_fee, and the update_fee always precedes its covering
 * commitment_signed on the wire.
 *
 * Opener: our own staged update_fee does NOT apply — the acceptor may only
 * sign at the new rate after it has revoked a commitment covering the fee,
 * and its revoke_and_ack promotes our staged rate to the committed config
 * BEFORE any new-rate signature of the acceptor can arrive. Until then the
 * peer's signatures (including ones that crossed our update_fee in flight)
 * are over the OLD rate.
 */
export function getLocalCommitmentFeeRate(
	state: IChannelState,
	signedLocal = false
): number {
	if (signedLocal && state.lastSignedCommitFeeratePerKw !== undefined) {
		return state.lastSignedCommitFeeratePerKw;
	}
	if (
		state.pendingFeeratePerKw !== undefined &&
		state.role === ChannelRole.ACCEPTOR
	) {
		return state.pendingFeeratePerKw;
	}
	return committedFeeRate(state);
}

/**
 * Fee rate for the commitment WE SIGN for the peer (commitment_signed we
 * send).
 *
 * Opener: our own staged update_fee applies immediately — we announced it
 * before this signature on the wire.
 *
 * Acceptor: a staged remote update_fee applies ONLY once it is signable
 * (pendingFeerateSignable): we have received the opener's commitment_signed
 * covering the fee and revoked. Before that the opener still builds its own
 * commitment at the old rate (its fee is not revocation-acked), so a new-rate
 * signature would be rejected ("Bad commit_sig" at CLN) — the exact live
 * failure this gates against.
 */
export function getRemoteCommitmentFeeRate(state: IChannelState): number {
	if (state.pendingFeeratePerKw !== undefined) {
		if (
			state.role === ChannelRole.OPENER ||
			state.pendingFeerateSignable === true
		) {
			return state.pendingFeeratePerKw;
		}
	}
	return committedFeeRate(state);
}

/**
 * Derived keys for a specific commitment transaction.
 */
export interface ICommitmentKeys {
	revocationPubkey: Buffer;
	localDelayedPubkey: Buffer;
	remotePaymentPubkey: Buffer;
	localHtlcPubkey: Buffer;
	remoteHtlcPubkey: Buffer;
}

/**
 * Derive the set of keys needed for a commitment transaction.
 *
 * @param localBasepoints - Local party's basepoints
 * @param remoteBasepoints - Remote party's basepoints
 * @param perCommitmentPoint - The per-commitment point for this commitment
 * @param isLocal - true if building the local commitment (we hold it)
 */
export function deriveCommitmentKeys(
	localBasepoints: {
		revocationBasepoint: Buffer;
		paymentBasepoint: Buffer;
		delayedPaymentBasepoint: Buffer;
		htlcBasepoint: Buffer;
	},
	remoteBasepoints: {
		revocationBasepoint: Buffer;
		paymentBasepoint: Buffer;
		delayedPaymentBasepoint: Buffer;
		htlcBasepoint: Buffer;
	},
	perCommitmentPoint: Buffer,
	isLocal: boolean
): ICommitmentKeys {
	if (isLocal) {
		// Local commitment: to_local uses our delayed key, to_remote uses their payment key
		// Revocation comes from remote's revocation basepoint + our per-commitment point
		return {
			revocationPubkey: deriveRevocationPubkey(
				remoteBasepoints.revocationBasepoint,
				perCommitmentPoint
			),
			localDelayedPubkey: derivePublicKey(
				localBasepoints.delayedPaymentBasepoint,
				perCommitmentPoint
			),
			remotePaymentPubkey: remoteBasepoints.paymentBasepoint,
			localHtlcPubkey: derivePublicKey(
				localBasepoints.htlcBasepoint,
				perCommitmentPoint
			),
			remoteHtlcPubkey: derivePublicKey(
				remoteBasepoints.htlcBasepoint,
				perCommitmentPoint
			)
		};
	} else {
		// Remote commitment: to_local uses their delayed key, to_remote uses our payment key
		// Revocation comes from our revocation basepoint + their per-commitment point
		return {
			revocationPubkey: deriveRevocationPubkey(
				localBasepoints.revocationBasepoint,
				perCommitmentPoint
			),
			localDelayedPubkey: derivePublicKey(
				remoteBasepoints.delayedPaymentBasepoint,
				perCommitmentPoint
			),
			remotePaymentPubkey: localBasepoints.paymentBasepoint,
			localHtlcPubkey: derivePublicKey(
				remoteBasepoints.htlcBasepoint,
				perCommitmentPoint
			),
			remoteHtlcPubkey: derivePublicKey(
				localBasepoints.htlcBasepoint,
				perCommitmentPoint
			)
		};
	}
}

/**
 * Result of building a commitment transaction.
 */
export interface IBuiltCommitment {
	result: ICommitmentTxResult;
	fundingWitnessScript: Buffer;
	fundingAmount: number;
	/**
	 * The trimmed HTLC output set actually enumerated into the commitment tx,
	 * in the SAME basis as result.outputMap.htlcOriginalIndices (those indices
	 * point INTO this array). Second-level HTLC signing/verification MUST read
	 * metadata from here, not from a freshly rebuilt UNFILTERED list: filtering
	 * compacts positions, so an unfiltered list is a different basis and a
	 * trimmed HTLC ordered before a surviving one would shift every subsequent
	 * index and bind the counterparty signature to the wrong output.
	 */
	htlcOutputs: (IHtlcOutput & { direction: HtlcDirection })[];
}

/**
 * Build the local commitment transaction (the one we hold).
 *
 * From our perspective:
 * - to_local = our balance (with CSV delay + revocation)
 * - to_remote = their balance (P2WPKH)
 * - offered HTLCs = HTLCs we offered (we can timeout)
 * - received HTLCs = HTLCs we received (we can claim with preimage)
 */
export function buildLocalCommitment(
	state: IChannelState,
	perCommitmentPoint: Buffer,
	commitmentNumber?: bigint,
	signedLocal = false
): IBuiltCommitment {
	if (!state.remoteBasepoints || !state.fundingTxid) {
		throw new Error('Channel state not ready for commitment building');
	}

	const keys = deriveCommitmentKeys(
		state.localBasepoints,
		state.remoteBasepoints,
		perCommitmentPoint,
		true
	);

	// Determine opener/acceptor payment basepoints for obscured commitment number
	const isOpener = state.role === ChannelRole.OPENER;
	const openPaymentBasepoint = isOpener
		? state.localBasepoints.paymentBasepoint
		: state.remoteBasepoints.paymentBasepoint;
	const acceptPaymentBasepoint = isOpener
		? state.remoteBasepoints.paymentBasepoint
		: state.localBasepoints.paymentBasepoint;

	// Use provided commitment number (for verification of next commitment)
	// or fall back to current state commitment number
	const commitNum = commitmentNumber ?? state.localCommitmentNumber;
	const obscuredCommitmentNumber = calculateObscuredCommitmentNumber(
		openPaymentBasepoint,
		acceptPaymentBasepoint,
		commitNum
	);

	// Detect anchor channel
	const useAnchors = isAnchorChannel(state.channelType);

	// Calculate commitment fee (BOLT 3): opener pays the fee
	const feeratePerKw = getLocalCommitmentFeeRate(state, signedLocal);

	// Build HTLC outputs, then trim per BOLT 3 (dust_limit + second-level fee).
	// The SAME trimmed set feeds both the commitment outputs and the
	// num_untrimmed_htlcs fee count so they can never diverge.
	const htlcOutputs = filterUntrimmedHtlcs(
		buildHtlcOutputsForLocal(state, keys),
		state.localConfig.dustLimitSatoshis,
		feeratePerKw,
		useAnchors
	);
	const numUntrimmedHtlcs = htlcOutputs.length;
	const fee = calculateCommitmentFee(
		feeratePerKw,
		numUntrimmedHtlcs,
		useAnchors,
		isTaprootChannel(state.channelType)
	);

	// BOLT 3: every commitment output value is the whole-satoshi FLOOR of its
	// msat amount; an untrimmed HTLC's sub-satoshi remainder is simply lost to
	// fee. Crediting it back to the offerer's to_local (a prior beignet rule)
	// diverges from LND (and the spec) by 1 sat whenever an HTLC carries
	// fractional msat: verified live against LND 0.20, whose commitment floors
	// the offerer's post-deduction balance with no remainder redistribution.

	// Deduct fee from opener's balance
	// Local commitment: localAmount = our balance, remoteAmount = their balance.
	// Adjust balances for FULFILLED/FAILED HTLCs (excluded from outputs above,
	// but balance updates were deferred until revoke_and_ack). This MUST happen
	// in millisatoshis BEFORE flooring to whole satoshis: once the removal is
	// finalized the refund/credit is applied to the msat balance and the SUM is
	// floored, so flooring the parts separately here diverges by 1 sat whenever
	// a fractional-msat amount rejoins a balance carrying the matching
	// sub-satoshi residue (e.g. a failed HTLC refunding its offerer). That 1-sat
	// skew made the two sides of a removal round sign different commitments.
	let localMsat = state.localBalanceMsat;
	let remoteMsat = state.remoteBalanceMsat;
	for (const entry of state.htlcs.values()) {
		if (entry.state === HtlcState.FULFILLED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received and fulfilled: credit our balance — unless the peer
				// has not committed our removal yet (the HTLC output is still in
				// this commitment; see buildHtlcOutputsForLocal).
				if (entry.removalRemoteCommitted !== false) {
					localMsat += entry.amountMsat;
				}
			} else {
				// We offered and remote fulfilled: credit their balance
				remoteMsat += entry.amountMsat;
			}
		} else if (entry.state === HtlcState.FAILED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received but failed: refund their balance — unless our
				// removal is not committed by the peer yet (output still present).
				if (entry.removalRemoteCommitted !== false) {
					remoteMsat += entry.amountMsat;
				}
			} else {
				// We offered but failed: refund our balance
				localMsat += entry.amountMsat;
			}
		} else if (
			entry.direction === HtlcDirection.OFFERED &&
			entry.addRemoteCommitted === false
		) {
			// An add of ours the peer has not committed yet: the provisional
			// balance deduction from addHtlc is not in the peer's signatures —
			// return it for this build (the output is excluded above).
			localMsat += entry.amountMsat;
		}
	}
	let localAmount = localMsat / 1000n;
	let remoteAmount = remoteMsat / 1000n;

	if (state.role === ChannelRole.OPENER) {
		localAmount -= fee;
		// Anchor channels: deduct 660 sats (2×330) for anchor outputs from opener
		if (useAnchors) localAmount -= ANCHOR_TOTAL_COST;
	} else {
		remoteAmount -= fee;
		if (useAnchors) remoteAmount -= ANCHOR_TOTAL_COST;
	}

	// BOLT 3: when the opener cannot fully cover the commitment fee, its main
	// output is removed (not negative). Saturate at zero so a fee spike can
	// never produce a negative-amount output downstream.
	if (localAmount < 0n) localAmount = 0n;
	if (remoteAmount < 0n) remoteAmount = 0n;

	const funding = createFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints.fundingPubkey
	);

	const params: ICommitmentTxParams = {
		fundingTxid: state.fundingTxid.toString('hex'),
		fundingOutputIndex: state.fundingOutputIndex,
		fundingAmount: state.fundingSatoshis,
		obscuredCommitmentNumber,
		localAmount,
		revocationPubkey: keys.revocationPubkey,
		localDelayedPubkey: keys.localDelayedPubkey,
		toSelfDelay: state.remoteConfig.toSelfDelay,
		// Liquidity ads: if WE are the lessor, our own to_local is CLTV-locked until
		// the lease expires (we can't reclaim the leased funds early).
		leaseExpiry: state.isLessor ? state.leaseExpiry : undefined,
		remoteAmount,
		remotePaymentPubkey: keys.remotePaymentPubkey,
		// Liquidity ads: OUR commitment's to_remote pays the PEER, so it is
		// lease-locked when the peer is the lessor (we are the lessee) — the
		// MIRROR of the to_local gate above. Exactly one of to_local/to_remote
		// per commitment carries the lock, always on the lessor's balance.
		// (See the matching gate in buildRemoteCommitment.)
		toRemoteLeaseExpiry: !state.isLessor ? state.leaseExpiry : undefined,
		htlcOutputs,
		// Our local commitment is trimmed with OUR negotiated dust_limit_satoshis
		// (we are the holder who would broadcast it).
		dustLimitSatoshis: state.localConfig.dustLimitSatoshis,
		useAnchors,
		localFundingPubkey: useAnchors
			? state.localBasepoints.fundingPubkey
			: undefined,
		remoteFundingPubkey: useAnchors
			? state.remoteBasepoints.fundingPubkey
			: undefined
	};

	applyTaprootCommitOverrides(params, state.channelType);
	const result = buildCommitmentTx(params);

	return {
		result,
		fundingWitnessScript: funding.witnessScript,
		fundingAmount: Number(state.fundingSatoshis),
		htlcOutputs
	};
}

/**
 * Build the remote commitment transaction (the one they hold).
 *
 * From their perspective (mirror of local):
 * - to_local = their balance (with CSV delay + revocation)
 * - to_remote = our balance (P2WPKH)
 * - Offered/received HTLCs are swapped relative to local
 */
export function buildRemoteCommitment(
	state: IChannelState,
	remotePerCommitmentPoint: Buffer,
	commitmentNumber?: bigint
): IBuiltCommitment {
	if (!state.remoteBasepoints || !state.fundingTxid) {
		throw new Error('Channel state not ready for commitment building');
	}

	const keys = deriveCommitmentKeys(
		state.localBasepoints,
		state.remoteBasepoints,
		remotePerCommitmentPoint,
		false
	);

	// Determine opener/acceptor payment basepoints
	const isOpener = state.role === ChannelRole.OPENER;
	const openPaymentBasepoint = isOpener
		? state.localBasepoints.paymentBasepoint
		: state.remoteBasepoints.paymentBasepoint;
	const acceptPaymentBasepoint = isOpener
		? state.remoteBasepoints.paymentBasepoint
		: state.localBasepoints.paymentBasepoint;

	const commitNum = commitmentNumber ?? state.remoteCommitmentNumber;
	const obscuredCommitmentNumber = calculateObscuredCommitmentNumber(
		openPaymentBasepoint,
		acceptPaymentBasepoint,
		commitNum
	);

	// Detect anchor channel
	const useAnchors = isAnchorChannel(state.channelType);

	// Calculate commitment fee (BOLT 3): opener pays the fee
	const feeratePerKw = getRemoteCommitmentFeeRate(state);

	// Build HTLC outputs (swapped perspective), then trim per BOLT 3 against the
	// REMOTE holder's dust limit + second-level fee — same trimmed set for outputs
	// and the fee count (see buildLocalCommitment).
	const htlcOutputs = filterUntrimmedHtlcs(
		buildHtlcOutputsForRemote(state, keys),
		state.remoteConfig.dustLimitSatoshis,
		feeratePerKw,
		useAnchors
	);
	const numUntrimmedHtlcs = htlcOutputs.length;
	const fee = calculateCommitmentFee(
		feeratePerKw,
		numUntrimmedHtlcs,
		useAnchors,
		isTaprootChannel(state.channelType)
	);

	// BOLT 3: outputs are pure whole-satoshi floors; sub-satoshi HTLC
	// remainders are lost to fee (see buildLocalCommitment).

	// Deduct fee from opener's balance
	// Remote commitment: localAmount = their balance (to_local), remoteAmount = our balance (to_remote)
	// Adjust balances for FULFILLED/FAILED HTLCs in MILLISATOSHIS before the
	// whole-satoshi floor — see buildLocalCommitment for why flooring the parts
	// separately desyncs the two sides of a removal round by 1 sat.
	let localMsat = state.remoteBalanceMsat;
	let remoteMsat = state.localBalanceMsat;
	for (const entry of state.htlcs.values()) {
		if (entry.state === HtlcState.FULFILLED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received and fulfilled: credit our balance
				remoteMsat += entry.amountMsat;
			} else {
				// We offered and remote fulfilled: credit their balance — unless
				// we have not revoked for the peer's removal yet (the HTLC output
				// is still in this commitment; see buildHtlcOutputsForRemote).
				if (entry.removalLocallyRevoked !== false) {
					localMsat += entry.amountMsat;
				}
			}
		} else if (entry.state === HtlcState.FAILED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received but failed: refund their balance
				localMsat += entry.amountMsat;
			} else {
				// We offered but failed: refund our balance — unless we have not
				// revoked for the peer's removal yet (output still present).
				if (entry.removalLocallyRevoked !== false) {
					remoteMsat += entry.amountMsat;
				}
			}
		} else if (
			entry.direction === HtlcDirection.RECEIVED &&
			entry.addLocallyRevoked === false
		) {
			// An add of the PEER's we have not revoked for: the peer's
			// provisional balance deduction is not in its own view of this
			// commitment yet — return it for this build (output excluded above).
			localMsat += entry.amountMsat;
		}
	}
	let localAmount = localMsat / 1000n;
	let remoteAmount = remoteMsat / 1000n;

	if (state.role === ChannelRole.OPENER) {
		// We are opener; our balance is to_remote on their commitment
		remoteAmount -= fee;
		if (useAnchors) remoteAmount -= ANCHOR_TOTAL_COST;
	} else {
		// They are opener; their balance is to_local on their commitment
		localAmount -= fee;
		if (useAnchors) localAmount -= ANCHOR_TOTAL_COST;
	}

	// BOLT 3: when the opener cannot fully cover the commitment fee, its main
	// output is removed (not negative). Saturate at zero so a fee spike can
	// never produce a negative-amount output downstream.
	if (localAmount < 0n) localAmount = 0n;
	if (remoteAmount < 0n) remoteAmount = 0n;

	const funding = createFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints.fundingPubkey
	);

	// For remote commitment: "local" from tx perspective = remote party, "remote" = us
	// localFundingPubkey/remoteFundingPubkey are from the tx holder's perspective
	const params: ICommitmentTxParams = {
		fundingTxid: state.fundingTxid.toString('hex'),
		fundingOutputIndex: state.fundingOutputIndex,
		fundingAmount: state.fundingSatoshis,
		obscuredCommitmentNumber,
		localAmount,
		revocationPubkey: keys.revocationPubkey,
		localDelayedPubkey: keys.localDelayedPubkey,
		toSelfDelay: state.localConfig.toSelfDelay,
		// Liquidity ads: this to_local is the REMOTE party's delayed output. If the
		// remote is the lessor (i.e. WE are the lessee), lock it until lease expiry
		// so the signature we give them is over the encumbered script. When we are
		// the lessor the remote is the lessee, so no lock.
		leaseExpiry: state.isLessor ? undefined : state.leaseExpiry,
		remoteAmount,
		remotePaymentPubkey: keys.remotePaymentPubkey,
		// Liquidity ads: THEIR commitment's to_remote pays US, so it is
		// lease-locked when WE are the lessor — the MIRROR of the to_local gate
		// above (and the counterpart of buildLocalCommitment's to_remote gate).
		// This is the output S-L.H4 was about: without it a seller escapes the
		// lease by provoking the buyer into force-closing.
		toRemoteLeaseExpiry: state.isLessor ? state.leaseExpiry : undefined,
		htlcOutputs,
		// The remote commitment is trimmed with THEIR negotiated
		// dust_limit_satoshis (they are the holder who would broadcast it).
		dustLimitSatoshis: state.remoteConfig.dustLimitSatoshis,
		useAnchors,
		localFundingPubkey: useAnchors
			? state.remoteBasepoints.fundingPubkey
			: undefined,
		remoteFundingPubkey: useAnchors
			? state.localBasepoints.fundingPubkey
			: undefined
	};

	applyTaprootCommitOverrides(params, state.channelType);
	const result = buildCommitmentTx(params);

	return {
		result,
		fundingWitnessScript: funding.witnessScript,
		fundingAmount: Number(state.fundingSatoshis),
		htlcOutputs
	};
}

/**
 * Sign the remote party's commitment transaction.
 * Returns the signature they need to broadcast their commitment,
 * plus signatures for each HTLC second-level transaction.
 *
 * HTLC signatures are ordered by commitment output index.
 * For each non-dust HTLC on the remote's commitment:
 * - Our OFFERED (their received) → HTLC-success tx signature (locktime=0)
 * - Our RECEIVED (their offered) → HTLC-timeout tx signature (locktime=cltvExpiry)
 */
export function signRemoteCommitment(
	state: IChannelState,
	signer: ISigner,
	remotePerCommitmentPoint: Buffer,
	commitmentNumber?: bigint
): { signature: Buffer; htlcSignatures: Buffer[] } {
	const built = buildRemoteCommitment(
		state,
		remotePerCommitmentPoint,
		commitmentNumber
	);

	const signature = signer.signCommitmentTx(
		built.result.tx,
		built.fundingWitnessScript,
		built.fundingAmount
	);

	const htlcSignatures: Buffer[] = [];

	// If the signer has no HTLC keys or no HTLC outputs, return empty sigs
	if (!signer.hasHtlcKeys || built.result.outputMap.htlcs.length === 0) {
		return { signature, htlcSignatures };
	}

	// Get commitment keys for the remote commitment
	const keys = deriveCommitmentKeys(
		state.localBasepoints,
		state.remoteBasepoints!,
		remotePerCommitmentPoint,
		false
	);

	// HTLC metadata comes from the SAME trimmed set the commitment tx
	// enumerated (built.htlcOutputs) — htlcOriginalIndices index INTO it. A
	// freshly rebuilt UNFILTERED list is a different basis (filtering compacts
	// positions), so a trimmed HTLC ordered before a surviving one would shift
	// the index and bind this signature to the wrong output.
	const htlcOutputsMeta = built.htlcOutputs;

	// Fee rate for HTLC transaction fee calculation — MUST be the same rate the
	// commitment body above was built at (buildRemoteCommitment), or the HTLC
	// second-level signatures diverge from the peer's mid-fee-round.
	const feeratePerKw = getRemoteCommitmentFeeRate(state);

	const useAnchors = isAnchorChannel(state.channelType);
	const htlcSuccessWeight = useAnchors
		? HTLC_SUCCESS_WEIGHT_ANCHORS
		: HTLC_SUCCESS_WEIGHT;
	const htlcTimeoutWeight = useAnchors
		? HTLC_TIMEOUT_WEIGHT_ANCHORS
		: HTLC_TIMEOUT_WEIGHT;

	const commitTxid = built.result.tx.getId();
	const { htlcs, htlcOriginalIndices } = built.result.outputMap;

	// Sign each HTLC second-level transaction in commitment output order
	for (let k = 0; k < htlcs.length; k++) {
		const outputIndex = htlcs[k];
		const origIdx = htlcOriginalIndices[k];
		const meta = htlcOutputsMeta[origIdx];

		// Liquidity ads: this is the REMOTE's commitment, so its second-level HTLC
		// output is CLTV-locked iff the remote is the lessor (i.e. we are not).
		const htlcLeaseExpiry = state.isLessor ? undefined : state.leaseExpiry;
		let htlcTx;
		if (meta.direction === HtlcDirection.OFFERED) {
			// Our offered = their received → HTLC-success tx (locktime=0)
			const fee = BigInt(Math.floor((htlcSuccessWeight * feeratePerKw) / 1000));
			htlcTx = buildHtlcSuccessTx(
				commitTxid,
				outputIndex,
				meta.amount,
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				state.localConfig.toSelfDelay,
				fee,
				useAnchors,
				htlcLeaseExpiry
			);
		} else {
			// Our received = their offered → HTLC-timeout tx (locktime=cltvExpiry)
			const fee = BigInt(Math.floor((htlcTimeoutWeight * feeratePerKw) / 1000));
			htlcTx = buildHtlcTimeoutTx(
				commitTxid,
				outputIndex,
				meta.amount,
				meta.cltvExpiry,
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				state.localConfig.toSelfDelay,
				fee,
				useAnchors,
				htlcLeaseExpiry
			);
		}

		// The signer derives our per-commitment HTLC privkey internally from
		// the remote per-commitment point and our advertised HTLC basepoint.
		const sig = signer.signHtlcTxForCommitment(
			htlcTx,
			meta.script,
			Number(meta.amount),
			remotePerCommitmentPoint,
			state.localBasepoints.htlcBasepoint,
			useAnchors
		);
		htlcSignatures.push(sig);
	}

	return { signature, htlcSignatures };
}

/**
 * Verify the remote's signature on our local commitment transaction.
 */
export function verifyRemoteCommitmentSig(
	state: IChannelState,
	signer: ISigner,
	perCommitmentPoint: Buffer,
	remoteSig: Buffer,
	commitmentNumber?: bigint
): boolean {
	if (!state.remoteBasepoints) {
		throw new Error('No remote basepoints');
	}

	// Build the local commitment for the given number. Mirrors buildLocalCommitment/
	// signRemoteCommitment: the caller supplies the number explicitly (the
	// commitment_signed flow passes localCommitmentNumber + 1), and it defaults to
	// the current localCommitmentNumber for the symmetric initial-commitment case.
	const built = buildLocalCommitment(
		state,
		perCommitmentPoint,
		commitmentNumber
	);

	const valid = signer.verifyCommitmentSig(
		built.result.tx,
		remoteSig,
		state.remoteBasepoints.fundingPubkey,
		built.fundingWitnessScript,
		built.fundingAmount
	);

	return valid;
}

// ── option_taproot commitment signing (MuSig2) ──────────────────────────────
// For a taproot channel the commitment is signed with a MuSig2 partial signature
// over the funding key-spend sighash instead of an ECDSA signature. Nonces are
// passed EXPLICITLY (not pulled from state) so the channel state machine retains
// full control of the single-use nonce lifecycle — reuse is catastrophic.

/** The taproot funding output scriptPubKey for this channel. */
function taprootFundingSpk(state: IChannelState): Buffer {
	return createTaprootFundingScript(
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey
	).p2trOutput;
}

/**
 * Produce OUR MuSig2 partial signature over the REMOTE commitment (sent to the
 * peer in commitment_signed). `ourPublicNonce` MUST be the single-use object from
 * generateNonce; `theirPublicNonce` is the peer's nonce for this commitment.
 */
export function signRemoteCommitmentPartial(
	state: IChannelState,
	signer: ISigner,
	ourPublicNonce: Uint8Array,
	theirPublicNonce: Buffer,
	remotePerCommitmentPoint: Buffer,
	commitmentNumber?: bigint
): Buffer {
	const built = buildRemoteCommitment(
		state,
		remotePerCommitmentPoint,
		commitmentNumber
	);
	const sighash = taprootCommitmentSighash(
		built.result.tx,
		taprootFundingSpk(state),
		Number(state.fundingSatoshis)
	);
	const session = startCommitmentSigningSession(
		sighash,
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey,
		ourPublicNonce,
		theirPublicNonce
	);
	return signer.signCommitmentPartial(session, ourPublicNonce);
}

/**
 * Verify the peer's MuSig2 partial signature over OUR local commitment (received
 * in commitment_signed).
 */
export function verifyRemoteCommitmentPartial(
	state: IChannelState,
	theirPartialSig: Buffer,
	ourPublicNonce: Uint8Array,
	theirPublicNonce: Buffer,
	localPerCommitmentPoint: Buffer,
	commitmentNumber?: bigint
): boolean {
	const built = buildLocalCommitment(
		state,
		localPerCommitmentPoint,
		commitmentNumber
	);
	const sighash = taprootCommitmentSighash(
		built.result.tx,
		taprootFundingSpk(state),
		Number(state.fundingSatoshis)
	);
	const session = startCommitmentSigningSession(
		sighash,
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey,
		ourPublicNonce,
		theirPublicNonce
	);
	return verifyPartialCommitmentSig(
		session,
		theirPartialSig,
		state.remoteBasepoints!.fundingPubkey,
		theirPublicNonce
	);
}

/**
 * Aggregate our own partial + the peer's partial over OUR local commitment into
 * the final 64-byte key-spend signature (used as the funding witness when we
 * broadcast our commitment, e.g. on force-close).
 */
export function aggregateLocalCommitmentSig(
	state: IChannelState,
	signer: ISigner,
	ourPublicNonce: Uint8Array,
	theirPublicNonce: Buffer,
	theirPartialSig: Buffer,
	localPerCommitmentPoint: Buffer,
	commitmentNumber?: bigint
): Buffer {
	// Force-close aggregation: rebuild at the feerate the stored partial covers
	// (signedLocal), not the in-flight rate — see getCommitmentFeeRate.
	const built = buildLocalCommitment(
		state,
		localPerCommitmentPoint,
		commitmentNumber,
		true
	);
	const sighash = taprootCommitmentSighash(
		built.result.tx,
		taprootFundingSpk(state),
		Number(state.fundingSatoshis)
	);
	const session = startCommitmentSigningSession(
		sighash,
		state.localBasepoints.fundingPubkey,
		state.remoteBasepoints!.fundingPubkey,
		ourPublicNonce,
		theirPublicNonce
	);
	const ourPartial = signer.signCommitmentPartial(session, ourPublicNonce);
	return aggregateCommitmentSig(session, ourPartial, theirPartialSig);
}

// ── option_taproot HTLC second-level signatures (BIP340 Schnorr) ─────────────
// Unlike the funding output (MuSig2 key-spend), each HTLC second-level tx spends
// a P2TR 2-of-2 tapscript leaf, so each party signs INDEPENDENTLY with its HTLC
// key over the BIP342 tapscript sighash. These ride in commitment_signed's
// htlc_signatures exactly like the legacy ECDSA ones. Kept SEPARATE from the
// ECDSA signRemoteCommitment / verifyRemoteHtlcSignatures loops (rather than
// branching them) to leave those proven, interop-tested paths untouched.

/** Reconstruct the P2TR HTLC output + the 2-of-2 leaf its second-level tx spends. */
function taprootHtlcOutputAndLeaf(
	kind: 'offered' | 'received',
	keys: ICommitmentKeys,
	paymentHash: Buffer,
	cltvExpiry: number
): { output: Buffer; leafScript: Buffer; leafVersion: number } {
	if (kind === 'received') {
		const o = buildTaprootReceivedHtlcOutput(
			keys.revocationPubkey,
			keys.localHtlcPubkey,
			keys.remoteHtlcPubkey,
			paymentHash,
			cltvExpiry
		);
		// HTLC-success spends the preimage/2-of-2 success leaf.
		return {
			output: o.output,
			leafScript: o.success.script,
			leafVersion: o.success.leafVersion
		};
	}
	const o = buildTaprootOfferedHtlcOutput(
		keys.revocationPubkey,
		keys.localHtlcPubkey,
		keys.remoteHtlcPubkey,
		paymentHash
	);
	// HTLC-timeout spends the 2-of-2 timeout leaf.
	return {
		output: o.output,
		leafScript: o.timeout.script,
		leafVersion: o.timeout.leafVersion
	};
}

/**
 * option_taproot: produce our BIP340 Schnorr signatures over the second-level
 * HTLC transactions for the REMOTE commitment, ordered by HTLC output index (the
 * taproot analogue of signRemoteCommitment's htlcSignatures). Returns [] when the
 * channel is not taproot, the signer has no HTLC basepoint secret, or there are
 * no HTLC outputs.
 */
export function signRemoteHtlcSignaturesTaproot(
	state: IChannelState,
	signer: ISigner,
	remotePerCommitmentPoint: Buffer,
	commitmentNumber?: bigint
): Buffer[] {
	if (!isTaprootChannel(state.channelType) || !signer.hasHtlcKeys) {
		return [];
	}
	const built = buildRemoteCommitment(
		state,
		remotePerCommitmentPoint,
		commitmentNumber
	);
	const { htlcs, htlcOriginalIndices } = built.result.outputMap;
	if (htlcs.length === 0) return [];

	const keys = deriveCommitmentKeys(
		state.localBasepoints,
		state.remoteBasepoints!,
		remotePerCommitmentPoint,
		false
	);
	// Same trimmed basis as htlcOriginalIndices (see signRemoteCommitment).
	const htlcOutputsMeta = built.htlcOutputs;
	const commitTxid = built.result.tx.getId();

	const sigs: Buffer[] = [];
	for (let k = 0; k < htlcs.length; k++) {
		const outputIndex = htlcs[k];
		const meta = htlcOutputsMeta[htlcOriginalIndices[k]];
		// REMOTE commitment kind mapping (mirrors buildHtlcOutputsForRemote):
		// our OFFERED → their received output; our RECEIVED → their offered output.
		const kind =
			meta.direction === HtlcDirection.OFFERED ? 'received' : 'offered';
		const { output, leafScript, leafVersion } = taprootHtlcOutputAndLeaf(
			kind,
			keys,
			meta.paymentHash,
			meta.cltvExpiry
		);
		const htlcTx =
			kind === 'received'
				? buildTaprootHtlcSuccessTx(
						commitTxid,
						outputIndex,
						meta.amount,
						keys.revocationPubkey,
						keys.localDelayedPubkey,
						state.localConfig.toSelfDelay
				  )
				: buildTaprootHtlcTimeoutTx(
						commitTxid,
						outputIndex,
						meta.amount,
						meta.cltvExpiry,
						keys.revocationPubkey,
						keys.localDelayedPubkey,
						state.localConfig.toSelfDelay
				  );
		const sighash = taprootHtlcLeafSighash(
			htlcTx,
			output,
			Number(meta.amount),
			leafScript,
			leafVersion
		);
		// The signer derives our per-commitment HTLC privkey internally (same
		// derivation as the ECDSA path in signRemoteCommitment).
		sigs.push(
			signer.signTaprootHtlcForCommitment(
				sighash,
				remotePerCommitmentPoint,
				state.localBasepoints.htlcBasepoint
			)
		);
	}
	return sigs;
}

/**
 * option_taproot: verify the remote's Schnorr signatures over the second-level
 * HTLC transactions for OUR local commitment (taproot analogue of
 * verifyRemoteHtlcSignatures).
 */
export function verifyRemoteHtlcSignaturesTaproot(
	state: IChannelState,
	perCommitmentPoint: Buffer,
	htlcSignatures: Buffer[],
	commitmentNumber?: bigint
): boolean {
	if (!state.remoteBasepoints) return false;
	// Default: the post-round number (the normal commitment_signed flow).
	// Mid-splice callers verify the CURRENT number's commitment re-anchored on
	// the new funding and pass it explicitly.
	const nextCommitNum = commitmentNumber ?? state.localCommitmentNumber + 1n;
	const built = buildLocalCommitment(state, perCommitmentPoint, nextCommitNum);
	const { htlcs, htlcOriginalIndices } = built.result.outputMap;

	if (htlcSignatures.length !== htlcs.length) return false;
	if (htlcs.length === 0) return true;

	const keys = deriveCommitmentKeys(
		state.localBasepoints,
		state.remoteBasepoints,
		perCommitmentPoint,
		true
	);
	// Same trimmed basis as htlcOriginalIndices (see signRemoteCommitment).
	const htlcOutputsMeta = built.htlcOutputs;
	const commitTxid = built.result.tx.getId();

	for (let k = 0; k < htlcs.length; k++) {
		const outputIndex = htlcs[k];
		const meta = htlcOutputsMeta[htlcOriginalIndices[k]];
		// LOCAL commitment kind mapping (mirrors buildHtlcOutputsForLocal):
		// our OFFERED → offered output; our RECEIVED → received output.
		const kind =
			meta.direction === HtlcDirection.OFFERED ? 'offered' : 'received';
		const { output, leafScript, leafVersion } = taprootHtlcOutputAndLeaf(
			kind,
			keys,
			meta.paymentHash,
			meta.cltvExpiry
		);
		const htlcTx =
			kind === 'received'
				? buildTaprootHtlcSuccessTx(
						commitTxid,
						outputIndex,
						meta.amount,
						keys.revocationPubkey,
						keys.localDelayedPubkey,
						state.remoteConfig.toSelfDelay
				  )
				: buildTaprootHtlcTimeoutTx(
						commitTxid,
						outputIndex,
						meta.amount,
						meta.cltvExpiry,
						keys.revocationPubkey,
						keys.localDelayedPubkey,
						state.remoteConfig.toSelfDelay
				  );
		const sighash = taprootHtlcLeafSighash(
			htlcTx,
			output,
			Number(meta.amount),
			leafScript,
			leafVersion
		);
		if (
			!verifyTaprootHtlcLeaf(sighash, keys.remoteHtlcPubkey, htlcSignatures[k])
		) {
			return false;
		}
	}
	return true;
}

/**
 * Verify the remote's HTLC signatures on our local commitment.
 *
 * The remote signs second-level HTLC transactions for our local commitment:
 * - For our OFFERED HTLCs: remote signs HTLC-timeout tx (we broadcast to reclaim)
 * - For our RECEIVED HTLCs: remote signs HTLC-success tx (we broadcast to claim with preimage)
 *
 * Signatures are ordered by HTLC output index on the commitment tx per BOLT 3.
 *
 * @returns true if all signatures are valid
 */
export function verifyRemoteHtlcSignatures(
	state: IChannelState,
	signer: ISigner,
	perCommitmentPoint: Buffer,
	htlcSignatures: Buffer[],
	commitmentNumber?: bigint
): boolean {
	if (!state.remoteBasepoints) return false;

	// Default: the post-round number (same as verifyRemoteCommitmentSig in the
	// normal commitment_signed flow). Mid-splice callers verify the CURRENT
	// number's commitment re-anchored on the new funding and pass it explicitly.
	const nextCommitNum = commitmentNumber ?? state.localCommitmentNumber + 1n;
	const built = buildLocalCommitment(state, perCommitmentPoint, nextCommitNum);
	const { htlcs, htlcOriginalIndices } = built.result.outputMap;

	// Signature count must match HTLC output count
	if (htlcSignatures.length !== htlcs.length) return false;
	if (htlcs.length === 0) return true;

	// Derive keys for local commitment
	const keys = deriveCommitmentKeys(
		state.localBasepoints,
		state.remoteBasepoints,
		perCommitmentPoint,
		true
	);

	// HTLC metadata in the SAME trimmed basis as htlcOriginalIndices (see
	// signRemoteCommitment) — never an unfiltered rebuild.
	const htlcOutputsMeta = built.htlcOutputs;

	// Remote's HTLC pubkey on our local commitment
	const remoteHtlcPubkey = keys.remoteHtlcPubkey;

	// Same rate as the LOCAL commitment these HTLC txs spend from
	// (buildLocalCommitment above).
	const feeratePerKw = getLocalCommitmentFeeRate(state);
	const useAnchors = isAnchorChannel(state.channelType);
	const htlcSuccessWeight = useAnchors
		? HTLC_SUCCESS_WEIGHT_ANCHORS
		: HTLC_SUCCESS_WEIGHT;
	const htlcTimeoutWeight = useAnchors
		? HTLC_TIMEOUT_WEIGHT_ANCHORS
		: HTLC_TIMEOUT_WEIGHT;
	const sighashType = useAnchors
		? bitcoin.Transaction.SIGHASH_SINGLE |
		  bitcoin.Transaction.SIGHASH_ANYONECANPAY
		: bitcoin.Transaction.SIGHASH_ALL;

	const commitTxid = built.result.tx.getId();

	for (let k = 0; k < htlcs.length; k++) {
		const outputIndex = htlcs[k];
		const origIdx = htlcOriginalIndices[k];
		const meta = htlcOutputsMeta[origIdx];

		// Liquidity ads: this is OUR commitment, so its second-level HTLC output is
		// CLTV-locked iff we are the lessor. Both parties build this script
		// identically (peer via signRemoteCommitment), so the sigs still match.
		const htlcLeaseExpiry = state.isLessor ? state.leaseExpiry : undefined;
		let htlcTx;
		if (meta.direction === HtlcDirection.OFFERED) {
			// Our offered → HTLC-timeout tx (we reclaim after timeout)
			const fee = BigInt(Math.floor((htlcTimeoutWeight * feeratePerKw) / 1000));
			htlcTx = buildHtlcTimeoutTx(
				commitTxid,
				outputIndex,
				meta.amount,
				meta.cltvExpiry,
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				state.remoteConfig.toSelfDelay,
				fee,
				useAnchors,
				htlcLeaseExpiry
			);
		} else {
			// Our received → HTLC-success tx (we claim with preimage)
			const fee = BigInt(Math.floor((htlcSuccessWeight * feeratePerKw) / 1000));
			htlcTx = buildHtlcSuccessTx(
				commitTxid,
				outputIndex,
				meta.amount,
				keys.revocationPubkey,
				keys.localDelayedPubkey,
				state.remoteConfig.toSelfDelay,
				fee,
				useAnchors,
				htlcLeaseExpiry
			);
		}

		const sigHash = htlcTx.hashForWitnessV0(
			0,
			meta.script,
			Number(meta.amount),
			sighashType
		);

		// strict (low-S): these signatures go into the second-level HTLC txs we
		// broadcast on force-close, so reject non-canonical (high-S) sigs that would
		// make those txs non-standard/non-relayable (BIP146).
		if (!verify(sigHash, remoteHtlcPubkey, htlcSignatures[k], true)) {
			return false;
		}
	}

	return true;
}

/**
 * Build HTLC outputs for the local commitment transaction.
 * - Offered HTLCs use buildOfferedHtlcScript (we offered, they can claim)
 * - Received HTLCs use buildReceivedHtlcScript (we received, we can claim)
 */
function buildHtlcOutputsForLocal(
	state: IChannelState,
	keys: ICommitmentKeys
): (IHtlcOutput & { direction: HtlcDirection; amountMsat: bigint })[] {
	const outputs: (IHtlcOutput & {
		direction: HtlcDirection;
		amountMsat: bigint;
	})[] = [];
	const useAnchors = isAnchorChannel(state.channelType);

	for (const entry of state.htlcs.values()) {
		// Only include PENDING and COMMITTED HTLCs in commitment outputs.
		// FULFILLED/FAILED HTLCs are excluded because we already sent
		// update_fulfill/fail_htlc + commitment_signed for them — the remote
		// expects the next commitment without these HTLCs.
		//
		// Two-phase exceptions (this is OUR commitment — the peer's signatures
		// define its contents, and the peer only incorporates OUR updates after
		// revoking a commitment that covers them):
		// - an add WE offered that the peer has not committed yet
		//   (addRemoteCommitted === false) is NOT in the peer's signatures —
		//   exclude it;
		// - a removal WE sent for a RECEIVED HTLC that the peer has not
		//   committed yet (removalRemoteCommitted === false) is not in the
		//   peer's signatures either — the HTLC output is still present.
		if (
			entry.state === HtlcState.FULFILLED ||
			entry.state === HtlcState.FAILED
		) {
			const stillPresent =
				entry.direction === HtlcDirection.RECEIVED &&
				entry.removalRemoteCommitted === false;
			if (!stillPresent) {
				continue;
			}
		} else if (
			entry.state !== HtlcState.PENDING &&
			entry.state !== HtlcState.COMMITTED
		) {
			continue;
		} else if (
			entry.direction === HtlcDirection.OFFERED &&
			entry.addRemoteCommitted === false
		) {
			continue;
		}

		const isTaproot = isTaprootChannel(state.channelType);
		if (entry.direction === HtlcDirection.OFFERED) {
			const script = buildOfferedHtlcScript(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				entry.paymentHash,
				useAnchors
			);
			outputs.push({
				script,
				amount: entry.amountMsat / 1000n,
				amountMsat: entry.amountMsat,
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				direction: HtlcDirection.OFFERED,
				taprootScript: taprootHtlcScript(
					isTaproot,
					'offered',
					keys,
					entry.paymentHash,
					entry.cltvExpiry
				)
			});
		} else {
			const script = buildReceivedHtlcScript(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				entry.paymentHash,
				entry.cltvExpiry,
				useAnchors
			);
			outputs.push({
				script,
				amount: entry.amountMsat / 1000n,
				amountMsat: entry.amountMsat,
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				direction: HtlcDirection.RECEIVED,
				taprootScript: taprootHtlcScript(
					isTaproot,
					'received',
					keys,
					entry.paymentHash,
					entry.cltvExpiry
				)
			});
		}
	}

	return outputs;
}

/**
 * HTLC output with metadata for signing second-level transactions.
 */
export interface IHtlcOutputWithMeta extends IHtlcOutput {
	htlcId: bigint;
	direction: HtlcDirection;
	amountMsat: bigint;
}

/**
 * Build HTLC outputs for the remote commitment transaction.
 * Directions are swapped: our offered = their received, vice versa.
 * Returns metadata (htlcId, direction) for HTLC transaction signing.
 */
function buildHtlcOutputsForRemote(
	state: IChannelState,
	keys: ICommitmentKeys
): IHtlcOutputWithMeta[] {
	const outputs: IHtlcOutputWithMeta[] = [];
	const useAnchors = isAnchorChannel(state.channelType);

	for (const entry of state.htlcs.values()) {
		// For the REMOTE commitment, exclude FULFILLED/FAILED HTLCs because
		// we already sent update_fulfill/fail_htlc for them.
		// Only include PENDING and COMMITTED HTLCs.
		//
		// Two-phase exceptions (this is the PEER's commitment — WE sign it, and
		// we may only incorporate the PEER's updates after we have revoked for
		// its covering commitment_signed; until then the peer builds its own
		// local commitment WITHOUT them):
		// - an add the PEER offered that we have not revoked for
		//   (addLocallyRevoked === false) must be excluded;
		// - a removal the PEER sent for an HTLC we offered
		//   (removalLocallyRevoked === false) is not in the peer's own view
		//   yet — the HTLC output is still present.
		if (
			entry.state === HtlcState.FULFILLED ||
			entry.state === HtlcState.FAILED
		) {
			const stillPresent =
				entry.direction === HtlcDirection.OFFERED &&
				entry.removalLocallyRevoked === false;
			if (!stillPresent) {
				continue;
			}
		} else if (
			entry.state !== HtlcState.PENDING &&
			entry.state !== HtlcState.COMMITTED
		) {
			continue;
		} else if (
			entry.direction === HtlcDirection.RECEIVED &&
			entry.addLocallyRevoked === false
		) {
			continue;
		}

		const isTaproot = isTaprootChannel(state.channelType);
		if (entry.direction === HtlcDirection.OFFERED) {
			// Our offered = their received
			const script = buildReceivedHtlcScript(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				entry.paymentHash,
				entry.cltvExpiry,
				useAnchors
			);
			outputs.push({
				script,
				amount: entry.amountMsat / 1000n,
				amountMsat: entry.amountMsat,
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				htlcId: entry.id,
				direction: entry.direction,
				taprootScript: taprootHtlcScript(
					isTaproot,
					'received',
					keys,
					entry.paymentHash,
					entry.cltvExpiry
				)
			});
		} else {
			// Our received = their offered
			const script = buildOfferedHtlcScript(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				entry.paymentHash,
				useAnchors
			);
			outputs.push({
				script,
				amount: entry.amountMsat / 1000n,
				amountMsat: entry.amountMsat,
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				htlcId: entry.id,
				direction: entry.direction,
				taprootScript: taprootHtlcScript(
					isTaproot,
					'offered',
					keys,
					entry.paymentHash,
					entry.cltvExpiry
				)
			});
		}
	}

	return outputs;
}
