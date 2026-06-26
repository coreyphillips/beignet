/**
 * BOLT 3: Commitment transaction building integration.
 *
 * Bridges Phase 2 script builders into the channel state machine,
 * coordinating key derivation, transaction construction, and signing
 * per commitment.
 */

import * as bitcoin from 'bitcoinjs-lib';
import {
	derivePublicKey,
	deriveRevocationPubkey,
	derivePrivateKey
} from '../keys/derivation';
import { verify } from '../crypto/ecdh';
import { ChannelSigner } from '../keys/signer';
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
	isAnchorChannel
} from './types';

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
	isAnchor?: boolean
): bigint {
	const baseWeight = isAnchor
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
function filterUntrimmedHtlcs<T extends { amount: bigint; direction: HtlcDirection }>(
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

/**
 * Get the fee rate for the commitment tx.
 * The opener sets the fee rate.
 */
export function getCommitmentFeeRate(state: IChannelState): number {
	// A staged (proposed) fee update applies to the in-flight commitment for both
	// parties — they both saw the update_fee before this round. It becomes the
	// committed config once the round finalizes (or is rolled back on reestablish).
	if (state.pendingFeeratePerKw !== undefined) {
		return state.pendingFeeratePerKw;
	}
	return state.role === ChannelRole.OPENER
		? state.localConfig.feeratePerKw
		: state.remoteConfig.feeratePerKw;
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
	commitmentNumber?: bigint
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
	const feeratePerKw = getCommitmentFeeRate(state);

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
		useAnchors
	);

	// Deduct fee from opener's balance
	// Local commitment: localAmount = our balance, remoteAmount = their balance
	let localAmount = state.localBalanceMsat / 1000n;
	let remoteAmount = state.remoteBalanceMsat / 1000n;

	// Adjust balances for FULFILLED/FAILED HTLCs (excluded from outputs above,
	// but balance updates were deferred until revoke_and_ack)
	for (const entry of state.htlcs.values()) {
		if (entry.state === HtlcState.FULFILLED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received and fulfilled: credit our balance
				localAmount += entry.amountMsat / 1000n;
			} else {
				// We offered and remote fulfilled: credit their balance
				remoteAmount += entry.amountMsat / 1000n;
			}
		} else if (entry.state === HtlcState.FAILED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received but failed: refund their balance
				remoteAmount += entry.amountMsat / 1000n;
			} else {
				// We offered but failed: refund our balance
				localAmount += entry.amountMsat / 1000n;
			}
		}
	}

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
		remoteAmount,
		remotePaymentPubkey: keys.remotePaymentPubkey,
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

	const result = buildCommitmentTx(params);

	return {
		result,
		fundingWitnessScript: funding.witnessScript,
		fundingAmount: Number(state.fundingSatoshis)
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
	const feeratePerKw = getCommitmentFeeRate(state);

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
		useAnchors
	);

	// Deduct fee from opener's balance
	// Remote commitment: localAmount = their balance (to_local), remoteAmount = our balance (to_remote)
	let localAmount = state.remoteBalanceMsat / 1000n;
	let remoteAmount = state.localBalanceMsat / 1000n;

	// Adjust balances for FULFILLED/FAILED HTLCs (excluded from outputs above,
	// but balance updates were deferred until revoke_and_ack)
	for (const entry of state.htlcs.values()) {
		if (entry.state === HtlcState.FULFILLED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received and fulfilled: credit our balance
				remoteAmount += entry.amountMsat / 1000n;
			} else {
				// We offered and remote fulfilled: credit their balance
				localAmount += entry.amountMsat / 1000n;
			}
		} else if (entry.state === HtlcState.FAILED) {
			if (entry.direction === HtlcDirection.RECEIVED) {
				// We received but failed: refund their balance
				localAmount += entry.amountMsat / 1000n;
			} else {
				// We offered but failed: refund our balance
				remoteAmount += entry.amountMsat / 1000n;
			}
		}
	}

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
		remoteAmount,
		remotePaymentPubkey: keys.remotePaymentPubkey,
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

	const result = buildCommitmentTx(params);

	return {
		result,
		fundingWitnessScript: funding.witnessScript,
		fundingAmount: Number(state.fundingSatoshis)
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
	signer: ChannelSigner,
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

	// If no htlcBasepointSecret or no HTLC outputs, return empty sigs
	if (
		!signer.htlcBasepointSecret ||
		built.result.outputMap.htlcs.length === 0
	) {
		return { signature, htlcSignatures };
	}

	// Derive our HTLC private key for the remote's commitment
	const localHtlcPrivkey = derivePrivateKey(
		signer.htlcBasepointSecret,
		remotePerCommitmentPoint,
		state.localBasepoints.htlcBasepoint
	);

	// Get commitment keys for the remote commitment
	const keys = deriveCommitmentKeys(
		state.localBasepoints,
		state.remoteBasepoints!,
		remotePerCommitmentPoint,
		false
	);

	// Build HTLC outputs with metadata to know direction/cltvExpiry
	const htlcOutputsMeta = buildHtlcOutputsForRemote(state, keys);

	// Fee rate for HTLC transaction fee calculation
	const feeratePerKw =
		state.role === ChannelRole.OPENER
			? state.localConfig.feeratePerKw
			: state.remoteConfig.feeratePerKw;

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
				useAnchors
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
				useAnchors
			);
		}

		const sig = signer.signHtlcTx(
			htlcTx,
			meta.script,
			Number(meta.amount),
			localHtlcPrivkey,
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
	signer: ChannelSigner,
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
	signer: ChannelSigner,
	perCommitmentPoint: Buffer,
	htlcSignatures: Buffer[]
): boolean {
	if (!state.remoteBasepoints) return false;

	// Use next commitment number (same as verifyRemoteCommitmentSig)
	const nextCommitNum = state.localCommitmentNumber + 1n;
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

	// Build HTLC output metadata for the local commitment
	const htlcOutputsMeta = buildHtlcOutputsForLocal(state, keys);

	// Remote's HTLC pubkey on our local commitment
	const remoteHtlcPubkey = keys.remoteHtlcPubkey;

	const feeratePerKw = getCommitmentFeeRate(state);
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
				useAnchors
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
				useAnchors
			);
		}

		const sigHash = htlcTx.hashForWitnessV0(
			0,
			meta.script,
			Number(meta.amount),
			sighashType
		);

		if (!verify(sigHash, remoteHtlcPubkey, htlcSignatures[k])) {
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
): (IHtlcOutput & { direction: HtlcDirection })[] {
	const outputs: (IHtlcOutput & { direction: HtlcDirection })[] = [];
	const useAnchors = isAnchorChannel(state.channelType);

	for (const entry of state.htlcs.values()) {
		// Only include PENDING and COMMITTED HTLCs in commitment outputs.
		// FULFILLED/FAILED HTLCs are excluded because we already sent
		// update_fulfill/fail_htlc + commitment_signed for them — the remote
		// expects the next commitment without these HTLCs.
		if (
			entry.state !== HtlcState.PENDING &&
			entry.state !== HtlcState.COMMITTED
		) {
			continue;
		}

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
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				direction: HtlcDirection.OFFERED
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
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				direction: HtlcDirection.RECEIVED
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
		if (
			entry.state !== HtlcState.PENDING &&
			entry.state !== HtlcState.COMMITTED
		) {
			continue;
		}

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
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				htlcId: entry.id,
				direction: entry.direction
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
				cltvExpiry: entry.cltvExpiry,
				paymentHash: entry.paymentHash,
				htlcId: entry.id,
				direction: entry.direction
			});
		}
	}

	return outputs;
}
