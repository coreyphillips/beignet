/**
 * BOLT 5: Output resolver.
 *
 * Given a commitment transaction on-chain + channel state, classifies
 * each output and builds appropriate spend transactions.
 */

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import {
	CommitmentType,
	OutputType,
	ITrackedOutput,
	OutputStatus
} from './types';
import {
	buildToLocalSweepTx,
	buildToLocalDelayedWitness,
	buildSecondLevelSweepTx,
	buildToRemoteClaimTx,
	buildToRemoteWitness,
	buildToRemoteAnchorWitness,
	buildRemoteHtlcPreimageClaimTx,
	buildRemoteHtlcPreimageWitness,
	buildRemoteHtlcTimeoutClaimTx,
	buildRemoteHtlcTimeoutWitness,
	buildHtlcSuccessWitness,
	buildHtlcTimeoutWitness,
	signSweepInput,
	signP2wpkhInput,
	estimateSweepVbytes,
	encodeWitnessSignature
} from './sweep';
import { buildToLocalScript } from '../script/commitment';
import {
	buildToRemoteAnchorOutput,
	leaseCsvFromToRemoteScript
} from '../script/anchor';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript,
	buildHtlcSuccessTx,
	buildHtlcTimeoutTx
} from '../script/htlc';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput,
	tweakTaprootKeyPathPrivkey,
	TAPLEAF_VERSION
} from '../script/commitment-taproot';
import {
	buildTaprootHtlcSuccessTx,
	buildTaprootHtlcTimeoutTx,
	taprootHtlcLeafSighash,
	tapleafHash,
	signTaprootHtlcLeaf,
	TAPROOT_HTLC_SIGHASH_TYPE
} from '../script/htlc-taproot';
import {
	buildPenaltyTx,
	signPenaltyInput,
	buildToLocalPenaltyWitness,
	buildHtlcPenaltyWitness
} from '../script/revocation';
import {
	derivePublicKey,
	deriveRevocationPubkey,
	deriveRevocationPrivkey,
	derivePrivateKey,
	perCommitmentPointFromSecret
} from '../keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { IChannelState } from '../channel/channel-state';
import { leaseCsvBlocks } from '../channel/liquidity-ads';
import {
	ChannelRole,
	HtlcDirection,
	HtlcState,
	isAnchorChannel,
	isTaprootChannel
} from '../channel/types';
import {
	getCommitmentFeeRate,
	HTLC_SUCCESS_WEIGHT,
	HTLC_TIMEOUT_WEIGHT
} from '../channel/commitment-builder';

const SIGHASH_ALL = bitcoin.Transaction.SIGHASH_ALL;
const SIGHASH_ANCHOR =
	bitcoin.Transaction.SIGHASH_SINGLE | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

/**
 * The exact fee a pre-signed second-level HTLC transaction commits to. The
 * remote party signed this amount in commitment_signed, so the on-chain claim
 * MUST reproduce it byte-for-byte or the signature is invalid. Anchor channels
 * use zero-fee second-level txs (bumped later via CPFP / extra inputs).
 */
function secondLevelHtlcFee(state: IChannelState, isSuccess: boolean): bigint {
	if (isAnchorChannel(state.channelType)) return 0n;
	// Rebuild at the rate the signature covers (signedLocal), never the
	// in-flight rate a half-finished fee round may have staged.
	const feeratePerKw = getCommitmentFeeRate(state, true);
	const weight = isSuccess ? HTLC_SUCCESS_WEIGHT : HTLC_TIMEOUT_WEIGHT;
	return BigInt(Math.floor((weight * feeratePerKw) / 1000));
}

bitcoin.initEccLib(ecc);

/**
 * Classified commitment transaction info.
 */
export interface IClassifiedCommitment {
	type: CommitmentType;
	commitmentNumber: bigint;
}

/**
 * A resolved output with its spend transaction and witness.
 */
export interface IResolvedOutput {
	trackedOutput: ITrackedOutput;
	spendTx?: bitcoin.Transaction;
	witness?: Buffer[];
	/** CSV delay before this output can be spent */
	csvDelay?: number;
	/** CLTV expiry before this output can be spent */
	cltvExpiry?: number;
}

// ─────────────── Commitment Number Extraction ───────────────

/**
 * Extract the commitment number from a commitment transaction.
 * Reverses the obscured commitment number encoded in locktime + sequence.
 *
 * BOLT 3: obscured = ((upper 24 bits from sequence) << 24) | (lower 24 bits from locktime)
 */
export function extractCommitmentNumber(
	tx: bitcoin.Transaction,
	openPaymentBasepoint: Buffer,
	acceptPaymentBasepoint: Buffer
): bigint {
	const locktime = tx.locktime;
	const sequence = tx.ins[0].sequence;

	// Extract obscured number: lower 24 bits of locktime + upper 24 bits from (sequence & 0xFFFFFF)
	const lower24 = BigInt(locktime & 0xffffff);
	const upper24 = BigInt(sequence & 0xffffff);
	const obscured = (upper24 << 24n) | lower24;

	// Compute the mask to un-obscure
	const hash = crypto
		.createHash('sha256')
		.update(openPaymentBasepoint)
		.update(acceptPaymentBasepoint)
		.digest();

	let mask = 0n;
	for (let i = 26; i < 32; i++) {
		mask = (mask << 8n) | BigInt(hash[i]);
	}

	return obscured ^ mask;
}

// ─────────────── Commitment Classification ───────────────

/**
 * Classify a commitment transaction by comparing it against expected values.
 */
export function classifyCommitmentTx(
	tx: bitcoin.Transaction,
	state: IChannelState
): IClassifiedCommitment {
	// Cooperative close needs no key material to identify (BOLT 3 commitments
	// stamp the obscured commitment number into locktime/sequence with the
	// 0x20/0x80 type bits, so a commitment's sequence is never 0xffffffff).
	// Checked before the key-material guard so a recovery state without remote
	// basepoints still recognizes a mutual close.
	if (tx.locktime === 0 && tx.ins[0].sequence === 0xffffffff) {
		return { type: CommitmentType.COOPERATIVE_CLOSE, commitmentNumber: 0n };
	}

	if (!state.remoteBasepoints || !state.fundingTxid) {
		// Static-channel-backup recovery: the reconstructed state has no remote
		// basepoints, so the obscured commitment number cannot be extracted. With
		// dataLossDetected set we can never have broadcast a commitment ourselves
		// (Channel.forceClose refuses and scanStuckChannels skips), so any
		// non-cooperative spend of the funding output is necessarily the peer's
		// commitment: treat it as THEIR_FUTURE_COMMITMENT and resolve only our
		// to_remote, which derives from our STATIC payment basepoint and needs no
		// peer key material.
		if (state.dataLossDetected) {
			return {
				type: CommitmentType.THEIR_FUTURE_COMMITMENT,
				commitmentNumber: 0n
			};
		}
		return { type: CommitmentType.UNKNOWN, commitmentNumber: 0n };
	}

	const isOpener = state.role === ChannelRole.OPENER;
	const openPaymentBasepoint = isOpener
		? state.localBasepoints.paymentBasepoint
		: state.remoteBasepoints.paymentBasepoint;
	const acceptPaymentBasepoint = isOpener
		? state.remoteBasepoints.paymentBasepoint
		: state.localBasepoints.paymentBasepoint;

	const commitmentNumber = extractCommitmentNumber(
		tx,
		openPaymentBasepoint,
		acceptPaymentBasepoint
	);

	const matchesLocal = commitmentNumber === state.localCommitmentNumber;
	const matchesRemote = commitmentNumber === state.remoteCommitmentNumber;

	if (matchesLocal && matchesRemote) {
		// Both commitment numbers are equal — differentiate by comparing
		// the to_local output script against expected local vs remote commitment.
		// On our commitment, to_local uses our delayed key with their revocation.
		// On their commitment, to_local uses their delayed key with our revocation.
		const type = disambiguateCommitmentTx(tx, state, commitmentNumber);
		return { type, commitmentNumber };
	}

	if (matchesLocal) {
		// The index also equals OUR local commitment number, but that is not proof
		// of ownership: during an in-flight round localCommitmentNumber lags
		// remoteCommitmentNumber by one, so a peer's REVOKED commitment can share
		// this exact index. If we hold the revocation secret for it, decide ownership
		// by matching the actual to_local script — never by index equality alone.
		// (Fund-safety: otherwise a revoked breach at this index is misread as ours
		// and never penalized, letting the peer sweep a stale, self-favorable state.)
		const revokedSecret =
			commitmentNumber < state.remoteCommitmentNumber
				? state.shaChainStore.getSecret(MAX_INDEX - commitmentNumber)
				: undefined;
		if (revokedSecret) {
			const byScript = disambiguateCommitmentTx(tx, state, commitmentNumber);
			if (byScript !== CommitmentType.OUR_COMMITMENT) {
				// Our to_local is absent from this tx → it is the peer's revoked
				// commitment sharing our index; route it to the penalty path.
				return {
					type: CommitmentType.THEIR_REVOKED_COMMITMENT,
					commitmentNumber
				};
			}
		}
		return { type: CommitmentType.OUR_COMMITMENT, commitmentNumber };
	}

	if (matchesRemote) {
		return { type: CommitmentType.THEIR_CURRENT_COMMITMENT, commitmentNumber };
	}

	// Check if this is a revoked commitment (older than current remote)
	if (commitmentNumber < state.remoteCommitmentNumber) {
		// Verify we have the revocation secret
		const secretIndex = MAX_INDEX - commitmentNumber;
		const secret = state.shaChainStore.getSecret(secretIndex);
		if (secret) {
			return {
				type: CommitmentType.THEIR_REVOKED_COMMITMENT,
				commitmentNumber
			};
		}
	}

	// A commitment index beyond our recorded remote state means the peer
	// legitimately advanced past us (data loss on our side); we can only
	// claim our to_remote output from it.
	if (commitmentNumber > state.remoteCommitmentNumber) {
		return { type: CommitmentType.THEIR_FUTURE_COMMITMENT, commitmentNumber };
	}

	return { type: CommitmentType.UNKNOWN, commitmentNumber };
}

/**
 * When local and remote commitment numbers are equal, differentiate by
 * comparing the to_local output scripts.
 */
function disambiguateCommitmentTx(
	tx: bitcoin.Transaction,
	state: IChannelState,
	commitmentNumber: bigint
): CommitmentType {
	if (!state.remoteBasepoints) return CommitmentType.UNKNOWN;

	// Build expected to_local script for OUR commitment
	const localPerCommitmentSecret = generateFromSeed(
		state.localPerCommitmentSeed,
		MAX_INDEX - commitmentNumber
	);
	const localPerCommitmentPoint = perCommitmentPointFromSecret(
		localPerCommitmentSecret
	);

	const ourRevocationPubkey = deriveRevocationPubkey(
		state.remoteBasepoints.revocationBasepoint,
		localPerCommitmentPoint
	);
	const ourDelayedPubkey = derivePublicKey(
		state.localBasepoints.delayedPaymentBasepoint,
		localPerCommitmentPoint
	);
	// Our to_local scriptPubKey: P2TR for taproot, P2WSH otherwise.
	const ourToLocalSpk = isTaprootChannel(state.channelType)
		? buildTaprootToLocalOutput(
				ourRevocationPubkey,
				ourDelayedPubkey,
				state.remoteConfig.toSelfDelay
		  ).output
		: bitcoin.payments.p2wsh({
				redeem: {
					// Liquidity ads: when WE are the lessor our to_local carries the
					// lease CLTV lock (mirrors buildLocalCommitment), so the rebuilt
					// script must include it for the byte-equality match to succeed.
					output: buildToLocalScript(
						ourRevocationPubkey,
						ourDelayedPubkey,
						state.remoteConfig.toSelfDelay,
						state.isLessor
							? leaseCsvBlocks(state.leaseExpiry, state.leaseCommitBlockheight)
							: undefined
					)
				}
		  }).output;

	// Check if any tx output matches our to_local script
	for (const out of tx.outs) {
		if (ourToLocalSpk && Buffer.from(out.script).equals(ourToLocalSpk)) {
			return CommitmentType.OUR_COMMITMENT;
		}
	}

	// Not ours — positively test THEIR to_local (their delayed key + our revocation)
	// for this index rather than guessing. Their per-commitment point is the current
	// point for the current commitment, or is derived from the stored revocation
	// secret for a revoked one. A THEIR_CURRENT_COMMITMENT result here means only
	// "this is a remote commitment by script"; the caller decides current vs revoked
	// from the index (whether we hold its revocation secret).
	let theirPerCommitmentPoint: Buffer | undefined;
	if (
		commitmentNumber === state.remoteCommitmentNumber &&
		state.remoteCurrentPerCommitmentPoint
	) {
		theirPerCommitmentPoint = state.remoteCurrentPerCommitmentPoint;
	} else {
		const secret = state.shaChainStore.getSecret(MAX_INDEX - commitmentNumber);
		if (secret) theirPerCommitmentPoint = perCommitmentPointFromSecret(secret);
	}
	if (theirPerCommitmentPoint) {
		const theirRevocationPubkey = deriveRevocationPubkey(
			state.localBasepoints.revocationBasepoint,
			theirPerCommitmentPoint
		);
		const theirDelayedPubkey = derivePublicKey(
			state.remoteBasepoints.delayedPaymentBasepoint,
			theirPerCommitmentPoint
		);
		const theirToLocalSpk = isTaprootChannel(state.channelType)
			? buildTaprootToLocalOutput(
					theirRevocationPubkey,
					theirDelayedPubkey,
					state.localConfig.toSelfDelay
			  ).output
			: bitcoin.payments.p2wsh({
					redeem: {
						// Their to_local carries the lease CLTV lock when THEY are the
						// lessor (mirrors buildRemoteCommitment).
						output: buildToLocalScript(
							theirRevocationPubkey,
							theirDelayedPubkey,
							state.localConfig.toSelfDelay,
							state.isLessor
								? undefined
								: leaseCsvBlocks(
										state.leaseExpiry,
										state.leaseCommitBlockheight
								  )
						)
					}
			  }).output;
		for (const out of tx.outs) {
			if (theirToLocalSpk && Buffer.from(out.script).equals(theirToLocalSpk)) {
				return CommitmentType.THEIR_CURRENT_COMMITMENT;
			}
		}
	}

	// Both to_local scripts are absent (e.g. trimmed on both sides) — cannot decide
	// ownership from scripts; the caller falls back to the commitment index.
	return CommitmentType.UNKNOWN;
}

// ─────────────── Output Classification ───────────────

/**
 * Classify each output of a commitment transaction.
 * Returns tracked outputs for each classified output.
 */
export function classifyOutputs(
	tx: bitcoin.Transaction,
	state: IChannelState,
	commitmentType: CommitmentType,
	commitmentNumber: bigint
): ITrackedOutput[] {
	// THEIR_FUTURE_COMMITMENT (data-loss / SCB recovery) matches only our
	// to_remote output, which derives from our STATIC payment basepoint - the
	// one classification that works without the peer's basepoints.
	if (
		!state.remoteBasepoints &&
		commitmentType !== CommitmentType.THEIR_FUTURE_COMMITMENT
	) {
		return [];
	}

	const txid = tx.getId();
	const outputs: ITrackedOutput[] = [];

	if (commitmentType === CommitmentType.OUR_COMMITMENT) {
		return classifyOurCommitmentOutputs(tx, state, txid, commitmentNumber);
	} else if (
		commitmentType === CommitmentType.THEIR_CURRENT_COMMITMENT ||
		commitmentType === CommitmentType.THEIR_REVOKED_COMMITMENT
	) {
		return classifyTheirCommitmentOutputs(tx, state, txid, commitmentNumber);
	} else if (commitmentType === CommitmentType.THEIR_FUTURE_COMMITMENT) {
		return classifyTheirFutureCommitmentOutputs(tx, state, txid);
	}

	// For cooperative close, track outputs but they're already resolved
	for (let i = 0; i < tx.outs.length; i++) {
		outputs.push({
			txid,
			outputIndex: i,
			amount: BigInt(tx.outs[i].value),
			outputType: OutputType.TO_LOCAL, // best guess for cooperative
			status: OutputStatus.CONFIRMED,
			confirmationHeight: 0
		});
	}

	return outputs;
}

function classifyOurCommitmentOutputs(
	tx: bitcoin.Transaction,
	state: IChannelState,
	txid: string,
	commitmentNumber: bigint
): ITrackedOutput[] {
	if (!state.remoteBasepoints) return [];

	if (isTaprootChannel(state.channelType)) {
		return classifyTaprootCommitmentOutputs(
			tx,
			state,
			txid,
			commitmentNumber,
			true
		);
	}

	const outputs: ITrackedOutput[] = [];

	// Derive keys for our commitment
	const perCommitmentSecret = generateFromSeed(
		state.localPerCommitmentSeed,
		MAX_INDEX - commitmentNumber
	);
	const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);

	const revocationPubkey = deriveRevocationPubkey(
		state.remoteBasepoints.revocationBasepoint,
		perCommitmentPoint
	);
	const localDelayedPubkey = derivePublicKey(
		state.localBasepoints.delayedPaymentBasepoint,
		perCommitmentPoint
	);
	const remotePaymentPubkey = state.remoteBasepoints.paymentBasepoint;

	const toSelfDelay = state.remoteConfig.toSelfDelay;
	// Liquidity ads: when WE are the lessor our to_local carries the lease CLTV
	// lock (mirrors buildLocalCommitment); without it the byte-equality match
	// below never fires and the output would go untracked and unswept.
	const toLocalScript = buildToLocalScript(
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay,
		state.isLessor
			? leaseCsvBlocks(state.leaseExpiry, state.leaseCommitBlockheight)
			: undefined
	);
	const toLocalP2wsh = bitcoin.payments.p2wsh({
		redeem: { output: toLocalScript }
	});
	const remoteP2wpkh = bitcoin.payments.p2wpkh({ pubkey: remotePaymentPubkey });

	// Derive HTLC keys
	const localHtlcPubkey = derivePublicKey(
		state.localBasepoints.htlcBasepoint,
		perCommitmentPoint
	);
	const remoteHtlcPubkey = derivePublicKey(
		state.remoteBasepoints.htlcBasepoint,
		perCommitmentPoint
	);

	let htlcSigCounter = 0;
	for (let i = 0; i < tx.outs.length; i++) {
		const outScript = tx.outs[i].script;

		if (toLocalP2wsh.output && outScript.equals(toLocalP2wsh.output)) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType: OutputType.TO_LOCAL,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				witnessScript: toLocalScript
			});
			continue;
		}

		if (remoteP2wpkh.output && outScript.equals(remoteP2wpkh.output)) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType: OutputType.TO_REMOTE,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0
			});
			continue;
		}

		// Try to match HTLC outputs
		const htlcMatch = matchHtlcOutput(
			outScript,
			state,
			revocationPubkey,
			localHtlcPubkey,
			remoteHtlcPubkey,
			true
		);
		if (htlcMatch) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType:
					htlcMatch.direction === HtlcDirection.OFFERED
						? OutputType.OFFERED_HTLC
						: OutputType.RECEIVED_HTLC,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				paymentHash: htlcMatch.paymentHash,
				cltvExpiry: htlcMatch.cltvExpiry,
				witnessScript: htlcMatch.witnessScript,
				htlcSigIndex: htlcSigCounter++
			});
		}
	}

	return outputs;
}

function classifyTheirCommitmentOutputs(
	tx: bitcoin.Transaction,
	state: IChannelState,
	txid: string,
	commitmentNumber: bigint
): ITrackedOutput[] {
	if (!state.remoteBasepoints) return [];

	if (isTaprootChannel(state.channelType)) {
		return classifyTaprootCommitmentOutputs(
			tx,
			state,
			txid,
			commitmentNumber,
			false
		);
	}

	const outputs: ITrackedOutput[] = [];

	// For their commitment, we need their per-commitment point
	let perCommitmentPoint: Buffer;
	if (commitmentNumber === state.remoteCommitmentNumber) {
		// Current commitment — use the current per-commitment point
		if (state.remoteCurrentPerCommitmentPoint) {
			perCommitmentPoint = state.remoteCurrentPerCommitmentPoint;
		} else {
			return outputs;
		}
	} else {
		// Revoked commitment — derive from stored secret
		const secretIndex = MAX_INDEX - commitmentNumber;
		const secret = state.shaChainStore.getSecret(secretIndex);
		if (!secret) return outputs;
		perCommitmentPoint = perCommitmentPointFromSecret(secret);
	}

	// On their commitment, from their perspective:
	// - their to_local uses their delayed key + our revocation
	// - their to_remote is our payment key (P2WPKH)
	const revocationPubkey = deriveRevocationPubkey(
		state.localBasepoints.revocationBasepoint,
		perCommitmentPoint
	);
	const theirDelayedPubkey = derivePublicKey(
		state.remoteBasepoints.delayedPaymentBasepoint,
		perCommitmentPoint
	);
	const ourPaymentPubkey = state.localBasepoints.paymentBasepoint;

	const toSelfDelay = state.localConfig.toSelfDelay;
	// Their to_local carries the lease CLTV lock when THEY are the lessor
	// (mirrors buildRemoteCommitment); the penalty path also depends on this
	// match to store the correct witnessScript for a revoked leased commitment.
	const toLocalScript = buildToLocalScript(
		revocationPubkey,
		theirDelayedPubkey,
		toSelfDelay,
		state.isLessor
			? undefined
			: leaseCsvBlocks(state.leaseExpiry, state.leaseCommitBlockheight)
	);
	const toLocalP2wsh = bitcoin.payments.p2wsh({
		redeem: { output: toLocalScript }
	});
	const ourP2wpkh = bitcoin.payments.p2wpkh({ pubkey: ourPaymentPubkey });
	// Anchor channels carry our to_remote as a P2WSH with a 1-block CSV rather
	// than a plain P2WPKH. Match both so we can claim our balance either way.
	const ourToRemoteAnchor = isAnchorChannel(state.channelType)
		? buildToRemoteAnchorOutput(ourPaymentPubkey)
		: null;
	// Liquidity ads: when WE are the lessor, our balance on THEIR commitment is
	// the lease-locked to_remote variant (CLTV until lease expiry). Match it
	// first; the plain variant stays matched for pre-lease/legacy outputs.
	const ourToRemoteAnchorLease =
		ourToRemoteAnchor && state.isLessor && state.leaseExpiry
			? buildToRemoteAnchorOutput(
					ourPaymentPubkey,
					leaseCsvBlocks(state.leaseExpiry, state.leaseCommitBlockheight)
			  )
			: null;

	// HTLC keys from their perspective
	const theirHtlcPubkey = derivePublicKey(
		state.remoteBasepoints.htlcBasepoint,
		perCommitmentPoint
	);
	const ourHtlcPubkey = derivePublicKey(
		state.localBasepoints.htlcBasepoint,
		perCommitmentPoint
	);

	for (let i = 0; i < tx.outs.length; i++) {
		const outScript = tx.outs[i].script;

		if (toLocalP2wsh.output && outScript.equals(toLocalP2wsh.output)) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType: OutputType.TO_LOCAL,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				witnessScript: toLocalScript
			});
			continue;
		}

		if (
			ourToRemoteAnchorLease &&
			outScript.equals(ourToRemoteAnchorLease.script)
		) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType: OutputType.TO_REMOTE,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				// The lease-locked witnessScript: the resolver reads the CLTV out
				// of it to set the sweep's nLockTime.
				witnessScript: ourToRemoteAnchorLease.witnessScript
			});
			continue;
		}

		if (ourToRemoteAnchor && outScript.equals(ourToRemoteAnchor.script)) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType: OutputType.TO_REMOTE,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				// Presence of a witnessScript signals the anchor (CSV-1) variant
				// to the resolver, which must spend via the P2WSH script path.
				witnessScript: ourToRemoteAnchor.witnessScript
			});
			continue;
		}

		if (ourP2wpkh.output && outScript.equals(ourP2wpkh.output)) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType: OutputType.TO_REMOTE,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0
			});
			continue;
		}

		// Match HTLC outputs from their perspective
		// On their commitment: their offered = our received, their received = our offered
		const htlcMatch = matchHtlcOutput(
			outScript,
			state,
			revocationPubkey,
			theirHtlcPubkey,
			ourHtlcPubkey,
			false
		);
		if (htlcMatch) {
			outputs.push({
				txid,
				outputIndex: i,
				amount: BigInt(tx.outs[i].value),
				outputType:
					htlcMatch.direction === HtlcDirection.OFFERED
						? OutputType.OFFERED_HTLC
						: OutputType.RECEIVED_HTLC,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				paymentHash: htlcMatch.paymentHash,
				cltvExpiry: htlcMatch.cltvExpiry,
				witnessScript: htlcMatch.witnessScript
			});
		}
	}

	return outputs;
}

/**
 * to_remote-only scan for a commitment the peer advanced past our recorded
 * state (data loss on our side). We never learned its per-commitment point,
 * so to_local/HTLC scripts cannot be derived - and we could not claim them
 * anyway. Our to_remote pays our STATIC payment basepoint on every channel
 * type we run (static_remotekey P2WPKH, anchors CSV-1 P2WSH, taproot leaf)
 * and needs no per-commitment point.
 */
function classifyTheirFutureCommitmentOutputs(
	tx: bitcoin.Transaction,
	state: IChannelState,
	txid: string
): ITrackedOutput[] {
	// Intentionally NO remoteBasepoints guard: every to_remote variant below
	// derives from our STATIC payment basepoint only, so this must also work
	// for SCB-recovery states where the peer's basepoints are unknown.
	const outputs: ITrackedOutput[] = [];
	const ourPaymentPubkey = state.localBasepoints.paymentBasepoint;

	const taprootToRemote = isTaprootChannel(state.channelType)
		? buildTaprootToRemoteOutput(ourPaymentPubkey).output
		: null;
	const anchorToRemote =
		!taprootToRemote && isAnchorChannel(state.channelType)
			? buildToRemoteAnchorOutput(ourPaymentPubkey)
			: null;
	// Liquidity ads: a lessor's to_remote is the lease-locked variant. The
	// lease fields ride along in the SCB, so this also works after recovery.
	const anchorToRemoteLease =
		anchorToRemote && state.isLessor && state.leaseExpiry
			? buildToRemoteAnchorOutput(
					ourPaymentPubkey,
					leaseCsvBlocks(state.leaseExpiry, state.leaseCommitBlockheight)
			  )
			: null;
	const plainToRemote =
		!taprootToRemote && !anchorToRemote
			? bitcoin.payments.p2wpkh({ pubkey: ourPaymentPubkey }).output
			: null;

	for (let i = 0; i < tx.outs.length; i++) {
		const outScript = tx.outs[i].script;
		const isLeased =
			!!anchorToRemoteLease && outScript.equals(anchorToRemoteLease.script);
		const isOurs =
			isLeased ||
			(taprootToRemote
				? outScript.equals(taprootToRemote)
				: anchorToRemote
				? outScript.equals(anchorToRemote.script)
				: !!plainToRemote && outScript.equals(plainToRemote));
		if (!isOurs) continue;
		outputs.push({
			txid,
			outputIndex: i,
			amount: BigInt(tx.outs[i].value),
			outputType: OutputType.TO_REMOTE,
			status: OutputStatus.CONFIRMED,
			confirmationHeight: 0,
			// witnessScript signals the anchor (CSV-1) variant to the resolver;
			// the lease variant additionally carries the CLTV the sweep must honor.
			witnessScript: isLeased
				? anchorToRemoteLease!.witnessScript
				: anchorToRemote?.witnessScript
		});
	}

	return outputs;
}

interface IHtlcMatch {
	direction: HtlcDirection;
	paymentHash: Buffer;
	cltvExpiry: number;
	witnessScript: Buffer;
}

function matchHtlcOutput(
	outScript: Buffer,
	state: IChannelState,
	revocationPubkey: Buffer,
	localHtlcPubkey: Buffer,
	remoteHtlcPubkey: Buffer,
	isLocal: boolean
): IHtlcMatch | null {
	// Anchor channels add a 1-block CSV to every HTLC output script, so the
	// scripts (and thus the P2WSH we match against) differ. Build the variant
	// that matches the on-chain commitment.
	const useAnchors = isAnchorChannel(state.channelType);

	for (const entry of state.htlcs.values()) {
		if (
			entry.state !== HtlcState.PENDING &&
			entry.state !== HtlcState.COMMITTED
		) {
			continue;
		}

		let script: Buffer;
		let direction: HtlcDirection;

		if (isLocal) {
			// Our commitment: offered uses buildOfferedHtlcScript, received uses buildReceivedHtlcScript
			if (entry.direction === HtlcDirection.OFFERED) {
				script = buildOfferedHtlcScript(
					revocationPubkey,
					localHtlcPubkey,
					remoteHtlcPubkey,
					entry.paymentHash,
					useAnchors
				);
				direction = HtlcDirection.OFFERED;
			} else {
				script = buildReceivedHtlcScript(
					revocationPubkey,
					localHtlcPubkey,
					remoteHtlcPubkey,
					entry.paymentHash,
					entry.cltvExpiry,
					useAnchors
				);
				direction = HtlcDirection.RECEIVED;
			}
		} else {
			// Their commitment: swap direction
			if (entry.direction === HtlcDirection.OFFERED) {
				// Our offered = their received
				script = buildReceivedHtlcScript(
					revocationPubkey,
					localHtlcPubkey,
					remoteHtlcPubkey,
					entry.paymentHash,
					entry.cltvExpiry,
					useAnchors
				);
				direction = HtlcDirection.OFFERED;
			} else {
				// Our received = their offered
				script = buildOfferedHtlcScript(
					revocationPubkey,
					localHtlcPubkey,
					remoteHtlcPubkey,
					entry.paymentHash,
					useAnchors
				);
				direction = HtlcDirection.RECEIVED;
			}
		}

		const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: script } });
		if (p2wsh.output && outScript.equals(p2wsh.output)) {
			return {
				direction,
				paymentHash: entry.paymentHash,
				cltvExpiry: entry.cltvExpiry,
				witnessScript: script
			};
		}
	}

	return null;
}

// ── option_taproot output classification ─────────────────────────────────────
// Mirrors classifyOur/TheirCommitmentOutputs but matches the P2TR commitment
// scriptPubKeys. Kept separate so the proven witness-v0 path is untouched. The
// per-output leaf data is NOT stored — resolution re-derives it deterministically
// from (state, commitmentNumber), exactly like the witness-v0 path re-derives
// keys; only outputType + HTLC metadata + htlcSigIndex are recorded.

interface ITaprootCommitKeys {
	revocationPubkey: Buffer;
	delayedPubkey: Buffer;
	paymentPubkey: Buffer;
	localHtlcPubkey: Buffer;
	remoteHtlcPubkey: Buffer;
	toSelfDelay: number;
}

function deriveTaprootCommitKeys(
	state: IChannelState,
	perCommitmentPoint: Buffer,
	isOurs: boolean
): ITaprootCommitKeys {
	const remote = state.remoteBasepoints!;
	if (isOurs) {
		return {
			revocationPubkey: deriveRevocationPubkey(
				remote.revocationBasepoint,
				perCommitmentPoint
			),
			delayedPubkey: derivePublicKey(
				state.localBasepoints.delayedPaymentBasepoint,
				perCommitmentPoint
			),
			paymentPubkey: remote.paymentBasepoint,
			localHtlcPubkey: derivePublicKey(
				state.localBasepoints.htlcBasepoint,
				perCommitmentPoint
			),
			remoteHtlcPubkey: derivePublicKey(
				remote.htlcBasepoint,
				perCommitmentPoint
			),
			toSelfDelay: state.remoteConfig.toSelfDelay
		};
	}
	return {
		revocationPubkey: deriveRevocationPubkey(
			state.localBasepoints.revocationBasepoint,
			perCommitmentPoint
		),
		delayedPubkey: derivePublicKey(
			remote.delayedPaymentBasepoint,
			perCommitmentPoint
		),
		paymentPubkey: state.localBasepoints.paymentBasepoint,
		// On their commitment "local" = them, "remote" = us.
		localHtlcPubkey: derivePublicKey(remote.htlcBasepoint, perCommitmentPoint),
		remoteHtlcPubkey: derivePublicKey(
			state.localBasepoints.htlcBasepoint,
			perCommitmentPoint
		),
		toSelfDelay: state.localConfig.toSelfDelay
	};
}

function matchTaprootHtlcOutput(
	outScript: Buffer,
	state: IChannelState,
	keys: ITaprootCommitKeys,
	isOurs: boolean
): IHtlcMatch | null {
	for (const entry of state.htlcs.values()) {
		if (
			entry.state !== HtlcState.PENDING &&
			entry.state !== HtlcState.COMMITTED
		) {
			continue;
		}

		// Pick the taproot HTLC output the same way matchHtlcOutput picks the
		// witness-v0 script: on our commitment offered→offered/received→received;
		// on their commitment the direction swaps.
		const asOffered = isOurs
			? entry.direction === HtlcDirection.OFFERED
			: entry.direction === HtlcDirection.RECEIVED;

		const built = asOffered
			? buildTaprootOfferedHtlcOutput(
					keys.revocationPubkey,
					keys.localHtlcPubkey,
					keys.remoteHtlcPubkey,
					entry.paymentHash
			  )
			: buildTaprootReceivedHtlcOutput(
					keys.revocationPubkey,
					keys.localHtlcPubkey,
					keys.remoteHtlcPubkey,
					entry.paymentHash,
					entry.cltvExpiry
			  );

		if (outScript.equals(built.output)) {
			return {
				// outputType reflects OUR perspective on the HTLC.
				direction: entry.direction,
				paymentHash: entry.paymentHash,
				cltvExpiry: entry.cltvExpiry,
				witnessScript: built.output
			};
		}
	}
	return null;
}

function classifyTaprootCommitmentOutputs(
	tx: bitcoin.Transaction,
	state: IChannelState,
	txid: string,
	commitmentNumber: bigint,
	isOurs: boolean
): ITrackedOutput[] {
	const outputs: ITrackedOutput[] = [];

	let perCommitmentPoint: Buffer;
	if (isOurs) {
		const secret = generateFromSeed(
			state.localPerCommitmentSeed,
			MAX_INDEX - commitmentNumber
		);
		perCommitmentPoint = perCommitmentPointFromSecret(secret);
	} else if (commitmentNumber === state.remoteCommitmentNumber) {
		if (!state.remoteCurrentPerCommitmentPoint) return outputs;
		perCommitmentPoint = state.remoteCurrentPerCommitmentPoint;
	} else {
		const secret = state.shaChainStore.getSecret(MAX_INDEX - commitmentNumber);
		if (!secret) return outputs;
		perCommitmentPoint = perCommitmentPointFromSecret(secret);
	}

	const keys = deriveTaprootCommitKeys(state, perCommitmentPoint, isOurs);
	const toLocalSpk = buildTaprootToLocalOutput(
		keys.revocationPubkey,
		keys.delayedPubkey,
		keys.toSelfDelay
	).output;
	const toRemoteSpk = buildTaprootToRemoteOutput(keys.paymentPubkey).output;

	let htlcSigCounter = 0;
	for (let i = 0; i < tx.outs.length; i++) {
		const outScript = tx.outs[i].script;
		const base = {
			txid,
			outputIndex: i,
			amount: BigInt(tx.outs[i].value),
			status: OutputStatus.CONFIRMED,
			confirmationHeight: 0
		};

		if (outScript.equals(toLocalSpk)) {
			outputs.push({ ...base, outputType: OutputType.TO_LOCAL });
			continue;
		}
		if (outScript.equals(toRemoteSpk)) {
			outputs.push({ ...base, outputType: OutputType.TO_REMOTE });
			continue;
		}
		const htlc = matchTaprootHtlcOutput(outScript, state, keys, isOurs);
		if (htlc) {
			outputs.push({
				...base,
				outputType:
					htlc.direction === HtlcDirection.OFFERED
						? OutputType.OFFERED_HTLC
						: OutputType.RECEIVED_HTLC,
				paymentHash: htlc.paymentHash,
				cltvExpiry: htlc.cltvExpiry,
				htlcSigIndex: htlcSigCounter++
			});
		}
		// Anchor outputs (and anything else) are left untracked — they are CPFP
		// helpers, not value to sweep here.
	}

	return outputs;
}

// ─────────────── Output Resolution ───────────────

/**
 * Resolve outputs from our own commitment transaction.
 * - to_local: sweep after CSV delay
 * - offered HTLC: HTLC-timeout after CLTV
 * - received HTLC: HTLC-success with preimage
 */
export function resolveOurCommitmentOutputs(
	state: IChannelState,
	trackedOutputs: ITrackedOutput[],
	commitmentNumber: bigint,
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	knownPreimages: Map<string, Buffer>,
	delayedPaymentBasepointSecret?: Buffer,
	htlcBasepointSecret?: Buffer,
	remoteHtlcSignatures?: Buffer[]
): IResolvedOutput[] {
	if (!state.remoteBasepoints) return [];

	if (isTaprootChannel(state.channelType)) {
		return resolveOurTaprootCommitmentOutputs(
			state,
			trackedOutputs,
			commitmentNumber,
			destinationScript,
			feeRatePerVbyte,
			knownPreimages,
			delayedPaymentBasepointSecret,
			htlcBasepointSecret,
			remoteHtlcSignatures
		);
	}

	const perCommitmentSecret = generateFromSeed(
		state.localPerCommitmentSeed,
		MAX_INDEX - commitmentNumber
	);
	const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);

	const revocationPubkey = deriveRevocationPubkey(
		state.remoteBasepoints.revocationBasepoint,
		perCommitmentPoint
	);
	const localDelayedPubkey = derivePublicKey(
		state.localBasepoints.delayedPaymentBasepoint,
		perCommitmentPoint
	);
	const toSelfDelay = state.remoteConfig.toSelfDelay;
	const useAnchors = isAnchorChannel(state.channelType);
	const htlcSighash = useAnchors ? SIGHASH_ANCHOR : SIGHASH_ALL;

	const resolved: IResolvedOutput[] = [];

	for (const output of trackedOutputs) {
		const feeSatoshis = BigInt(
			Math.ceil(feeRatePerVbyte * estimateSweepVbytes(output.outputType))
		);

		if (output.outputType === OutputType.TO_LOCAL && output.witnessScript) {
			// Liquidity ads (CLN pure-CSV): a lessor's to_local CSV is
			// max(to_self_delay, lease_csv), so the sweep's input nSequence must
			// satisfy that larger value, not just to_self_delay.
			const leaseCsv = state.isLessor
				? leaseCsvBlocks(state.leaseExpiry, state.leaseCommitBlockheight)
				: undefined;
			const toLocalCsv =
				leaseCsv !== undefined && leaseCsv > toSelfDelay
					? leaseCsv
					: toSelfDelay;
			const sweepTx = buildToLocalSweepTx({
				commitmentTxid: output.txid,
				outputIndex: output.outputIndex,
				amount: output.amount,
				witnessScript: output.witnessScript,
				toSelfDelay: toLocalCsv,
				destinationScript,
				feeSatoshis
			});

			// Derive the delayed payment private key for signing
			const basepointSecret =
				delayedPaymentBasepointSecret || state.localPerCommitmentSeed;
			const delayedPrivkey = derivePrivateKey(
				basepointSecret,
				perCommitmentPoint,
				state.localBasepoints.delayedPaymentBasepoint
			);

			const sig = signSweepInput(
				sweepTx,
				0,
				output.witnessScript,
				Number(output.amount),
				delayedPrivkey
			);
			const witness = buildToLocalDelayedWitness(sig, output.witnessScript);

			resolved.push({
				trackedOutput: output,
				spendTx: sweepTx,
				witness,
				csvDelay: toLocalCsv
			});
		} else if (output.outputType === OutputType.TO_REMOTE) {
			// to_remote on our commitment belongs to remote — we don't spend it
			resolved.push({ trackedOutput: output });
		} else if (
			output.outputType === OutputType.OFFERED_HTLC &&
			output.witnessScript
		) {
			// We offered this HTLC — claim via HTLC-timeout after CLTV expiry.
			// The second-level tx is pre-signed by the remote, so it must reproduce
			// exactly what they signed: the committed fee (or zero for anchors) and,
			// for anchors, the zero-fee variant (seq=1) + ANYONECANPAY sighash.
			const htlcTimeoutTx = buildHtlcTimeoutTx(
				output.txid,
				output.outputIndex,
				output.amount,
				output.cltvExpiry || 0,
				revocationPubkey,
				localDelayedPubkey,
				toSelfDelay,
				secondLevelHtlcFee(state, false),
				useAnchors
			);

			// Sign HTLC-timeout if we have the htlc basepoint secret and remote sig
			let witness: Buffer[] | undefined;
			if (
				htlcBasepointSecret &&
				remoteHtlcSignatures &&
				output.htlcSigIndex !== undefined &&
				output.htlcSigIndex < remoteHtlcSignatures.length
			) {
				const localHtlcPrivkey = derivePrivateKey(
					htlcBasepointSecret,
					perCommitmentPoint,
					state.localBasepoints.htlcBasepoint
				);
				const localSig = signSweepInput(
					htlcTimeoutTx,
					0,
					output.witnessScript,
					Number(output.amount),
					localHtlcPrivkey,
					htlcSighash
				);
				const remoteSig = encodeWitnessSignature(
					remoteHtlcSignatures[output.htlcSigIndex],
					htlcSighash
				);
				witness = buildHtlcTimeoutWitness(
					remoteSig,
					localSig,
					output.witnessScript
				);
			}

			resolved.push({
				trackedOutput: output,
				spendTx: htlcTimeoutTx,
				witness,
				cltvExpiry: output.cltvExpiry,
				csvDelay: toSelfDelay
			});
		} else if (
			output.outputType === OutputType.RECEIVED_HTLC &&
			output.witnessScript
		) {
			// We received this HTLC — claim via HTLC-success with preimage
			const hashHex = output.paymentHash?.toString('hex');
			const preimage = hashHex ? knownPreimages.get(hashHex) : undefined;

			if (preimage) {
				const htlcSuccessTx = buildHtlcSuccessTx(
					output.txid,
					output.outputIndex,
					output.amount,
					revocationPubkey,
					localDelayedPubkey,
					toSelfDelay,
					secondLevelHtlcFee(state, true),
					useAnchors
				);

				// Sign HTLC-success if we have the htlc basepoint secret and remote sig
				let witness: Buffer[] | undefined;
				if (
					htlcBasepointSecret &&
					remoteHtlcSignatures &&
					output.htlcSigIndex !== undefined &&
					output.htlcSigIndex < remoteHtlcSignatures.length
				) {
					const localHtlcPrivkey = derivePrivateKey(
						htlcBasepointSecret,
						perCommitmentPoint,
						state.localBasepoints.htlcBasepoint
					);
					const localSig = signSweepInput(
						htlcSuccessTx,
						0,
						output.witnessScript,
						Number(output.amount),
						localHtlcPrivkey,
						htlcSighash
					);
					const remoteSig = encodeWitnessSignature(
						remoteHtlcSignatures[output.htlcSigIndex],
						htlcSighash
					);
					witness = buildHtlcSuccessWitness(
						remoteSig,
						localSig,
						preimage,
						output.witnessScript
					);
				}

				resolved.push({
					trackedOutput: output,
					spendTx: htlcSuccessTx,
					witness,
					csvDelay: toSelfDelay
				});
			} else {
				// No preimage yet — track but can't resolve
				resolved.push({ trackedOutput: output });
			}
		}
	}

	return resolved;
}

/**
 * M2: sweep the CSV-delayed output of one of OUR second-level HTLC txs
 * (HTLC-timeout / HTLC-success on our own commitment). That tx creates a fresh
 * `to_local`-format output (revocation-OR-delayed+CSV) that is NOT one of the
 * commitment outputs and was therefore never tracked or swept — the value sat
 * unspent (recoverable, since it pays our own delayed key). This reconstructs the
 * output's script from our commitment keys, then builds+signs the CSV sweep to
 * our destination. Handles BOTH witness-v0 (to_local script) and option_taproot
 * (TaprootSecondLevelScriptTree delay leaf). Returns null if `htlcTx.outs[0]` is
 * not our expected second-level output.
 */
export function resolveSecondLevelHtlcOutput(
	state: IChannelState,
	htlcTx: bitcoin.Transaction,
	confirmationHeight: number,
	commitmentNumber: bigint,
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	delayedPaymentBasepointSecret: Buffer | undefined,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): IResolvedOutput | null {
	if (!state.remoteBasepoints) return null;
	const out = htlcTx.outs[0];
	if (!out) return null;

	// option_taproot: the second-level output is a TaprootSecondLevelScriptTree
	// (revocation key INTERNAL + a single delay leaf). Sweep the delay leaf
	// (script-path) with our delayed key after the CSV.
	//
	// NB: unlike the witness-v0 branch below, this deliberately does NOT add a
	// lessor lease CLTV lock. Script-enforced lease and simple taproot are
	// mutually-exclusive commitment types (LND's taproot builders take no
	// lease_expiry; there is no taproot lease script), so beignet rejects a leased
	// taproot channel at negotiation (channel.ts handleOpenChannel2 /
	// handleAcceptChannel2). A taproot channel is therefore never a lessor and its
	// second-level output is never lease-locked, so this lock-free reconstruction
	// matches the on-chain output. Adding a lock would change the script, fail the
	// `sl.output.equals(out.script)` match, and strand the funds.
	if (isTaprootChannel(state.channelType)) {
		const point = perCommitmentPointFromSecret(
			generateFromSeed(
				state.localPerCommitmentSeed,
				MAX_INDEX - commitmentNumber
			)
		);
		const keys = deriveTaprootCommitKeys(state, point, true);
		const toSelfDelay = keys.toSelfDelay;
		const sl = buildTaprootSecondLevelOutput(
			keys.revocationPubkey,
			keys.delayedPubkey,
			toSelfDelay,
			network
		);
		if (!sl.output.equals(out.script)) return null;
		const amount = BigInt(out.value);
		const feeSatoshis = BigInt(
			Math.ceil(feeRatePerVbyte * estimateSweepVbytes(OutputType.TO_LOCAL))
		);
		const htlcTxid = htlcTx.getId();
		const sweepTx = new bitcoin.Transaction();
		sweepTx.version = 2;
		sweepTx.addInput(Buffer.from(htlcTxid, 'hex').reverse(), 0, toSelfDelay);
		sweepTx.addOutput(destinationScript, Number(amount - feeSatoshis));
		const delayedBasepointSecret =
			delayedPaymentBasepointSecret || state.localPerCommitmentSeed;
		const delayedPrivkey = derivePrivateKey(
			delayedBasepointSecret,
			point,
			state.localBasepoints.delayedPaymentBasepoint
		);
		const sighash = sweepTx.hashForWitnessV1(
			0,
			[sl.output],
			[Number(amount)],
			bitcoin.Transaction.SIGHASH_DEFAULT,
			tapleafHash(sl.delay.script, sl.delay.leafVersion)
		);
		const sig = signTaprootHtlcLeaf(sighash, delayedPrivkey);
		return {
			trackedOutput: {
				txid: htlcTxid,
				outputIndex: 0,
				amount,
				outputType: OutputType.TO_LOCAL,
				status: OutputStatus.CONFIRMED,
				confirmationHeight,
				witnessScript: sl.output,
				// Tag so a later rebuild reconstructs the second-level tree (revocation
				// internal + single delay leaf), not the commitment to_local tree.
				isSecondLevelHtlc: true
			},
			spendTx: sweepTx,
			witness: [sig, sl.delay.script, sl.delay.controlBlock],
			csvDelay: toSelfDelay
		};
	}

	const perCommitmentSecret = generateFromSeed(
		state.localPerCommitmentSeed,
		MAX_INDEX - commitmentNumber
	);
	const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);
	const revocationPubkey = deriveRevocationPubkey(
		state.remoteBasepoints.revocationBasepoint,
		perCommitmentPoint
	);
	const delayedPubkey = derivePublicKey(
		state.localBasepoints.delayedPaymentBasepoint,
		perCommitmentPoint
	);
	const toSelfDelay = state.remoteConfig.toSelfDelay;
	// The second-level output uses the SAME to_local-format script the
	// HTLC-timeout/success tx produced (buildHtlcTimeoutTx / buildHtlcSuccessTx):
	// revocation-OR-(delayed + CSV). BOLT 3 / CLN: never lease-locked.
	const witnessScript = buildToLocalScript(
		revocationPubkey,
		delayedPubkey,
		toSelfDelay
	);
	const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: witnessScript } });
	if (!p2wsh.output || !p2wsh.output.equals(out.script)) return null;

	const amount = BigInt(out.value);
	const feeSatoshis = BigInt(
		Math.ceil(feeRatePerVbyte * estimateSweepVbytes(OutputType.TO_LOCAL))
	);
	const htlcTxid = htlcTx.getId();
	const sweepTx = buildSecondLevelSweepTx({
		htlcTxid,
		outputIndex: 0,
		amount,
		witnessScript,
		toSelfDelay,
		destinationScript,
		feeSatoshis
	});

	const basepointSecret =
		delayedPaymentBasepointSecret || state.localPerCommitmentSeed;
	const delayedPrivkey = derivePrivateKey(
		basepointSecret,
		perCommitmentPoint,
		state.localBasepoints.delayedPaymentBasepoint
	);
	const sig = signSweepInput(
		sweepTx,
		0,
		witnessScript,
		Number(amount),
		delayedPrivkey
	);
	const witness = buildToLocalDelayedWitness(sig, witnessScript);

	return {
		trackedOutput: {
			txid: htlcTxid,
			outputIndex: 0,
			amount,
			outputType: OutputType.TO_LOCAL,
			status: OutputStatus.CONFIRMED,
			confirmationHeight,
			witnessScript
		},
		spendTx: sweepTx,
		witness,
		csvDelay: toSelfDelay
	};
}

/**
 * option_taproot: resolve outputs from OUR own commitment.
 * - to_local: CSV-delayed self-spend via the delay tapleaf (we sign, deduct fee).
 * - offered HTLC: zero-fee HTLC-timeout via the 2-of-2 timeout leaf (our sig +
 *   the remote's pre-signed sig); fee attached downstream by the wallet.
 * - received HTLC: zero-fee HTLC-success via the 2-of-2 success leaf (+ preimage).
 */
function resolveOurTaprootCommitmentOutputs(
	state: IChannelState,
	trackedOutputs: ITrackedOutput[],
	commitmentNumber: bigint,
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	knownPreimages: Map<string, Buffer>,
	delayedPaymentBasepointSecret?: Buffer,
	htlcBasepointSecret?: Buffer,
	remoteHtlcSignatures?: Buffer[]
): IResolvedOutput[] {
	if (!state.remoteBasepoints) return [];

	const perCommitmentSecret = generateFromSeed(
		state.localPerCommitmentSeed,
		MAX_INDEX - commitmentNumber
	);
	const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);
	const keys = deriveTaprootCommitKeys(state, perCommitmentPoint, true);
	const toSelfDelay = keys.toSelfDelay;
	const sighashByte = Buffer.from([TAPROOT_HTLC_SIGHASH_TYPE]);

	const hasHtlcSig = (o: ITrackedOutput): boolean =>
		!!htlcBasepointSecret &&
		!!remoteHtlcSignatures &&
		o.htlcSigIndex !== undefined &&
		o.htlcSigIndex < remoteHtlcSignatures.length;

	const resolved: IResolvedOutput[] = [];
	for (const output of trackedOutputs) {
		if (output.outputType === OutputType.TO_LOCAL) {
			// A second-level-derived output uses the TaprootSecondLevelScriptTree
			// (revocation-key internal + single delay leaf), NOT the commitment
			// to_local tree (NUMS internal + delay/revoke leaves). Reconstruct the
			// matching one or the prevout scriptPubKey + control block are wrong and
			// the sweep is invalid (stranding the second-level funds on rebuild).
			const toLocal = output.isSecondLevelHtlc
				? buildTaprootSecondLevelOutput(
						keys.revocationPubkey,
						keys.delayedPubkey,
						toSelfDelay
				  )
				: buildTaprootToLocalOutput(
						keys.revocationPubkey,
						keys.delayedPubkey,
						toSelfDelay
				  );
			const feeSatoshis = BigInt(
				Math.ceil(feeRatePerVbyte * estimateSweepVbytes(output.outputType))
			);
			const sweepTx = new bitcoin.Transaction();
			sweepTx.version = 2;
			sweepTx.addInput(
				Buffer.from(output.txid, 'hex').reverse(),
				output.outputIndex,
				toSelfDelay // CSV: the to_local delay leaf requires this relative timelock
			);
			sweepTx.addOutput(destinationScript, Number(output.amount - feeSatoshis));
			const delayedBasepointSecret =
				delayedPaymentBasepointSecret || state.localPerCommitmentSeed;
			const delayedPrivkey = derivePrivateKey(
				delayedBasepointSecret,
				perCommitmentPoint,
				state.localBasepoints.delayedPaymentBasepoint
			);
			const sighash = sweepTx.hashForWitnessV1(
				0,
				[toLocal.output],
				[Number(output.amount)],
				bitcoin.Transaction.SIGHASH_DEFAULT,
				tapleafHash(toLocal.delay.script, toLocal.delay.leafVersion)
			);
			const sig = signTaprootHtlcLeaf(sighash, delayedPrivkey);
			resolved.push({
				trackedOutput: output,
				spendTx: sweepTx,
				witness: [sig, toLocal.delay.script, toLocal.delay.controlBlock],
				csvDelay: toSelfDelay
			});
		} else if (output.outputType === OutputType.TO_REMOTE) {
			// On our commitment to_remote belongs to the peer — nothing to do.
			resolved.push({ trackedOutput: output });
		} else if (output.outputType === OutputType.OFFERED_HTLC) {
			const htlcOut = buildTaprootOfferedHtlcOutput(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				output.paymentHash!
			);
			const htlcTx = buildTaprootHtlcTimeoutTx(
				output.txid,
				output.outputIndex,
				output.amount,
				output.cltvExpiry || 0,
				keys.revocationPubkey,
				keys.delayedPubkey,
				toSelfDelay
			);
			let witness: Buffer[] | undefined;
			if (hasHtlcSig(output)) {
				const localHtlcPrivkey = derivePrivateKey(
					htlcBasepointSecret!,
					perCommitmentPoint,
					state.localBasepoints.htlcBasepoint
				);
				const sighash = taprootHtlcLeafSighash(
					htlcTx,
					htlcOut.output,
					Number(output.amount),
					htlcOut.timeout.script,
					htlcOut.timeout.leafVersion
				);
				const localSig = signTaprootHtlcLeaf(sighash, localHtlcPrivkey);
				const remoteSig = remoteHtlcSignatures![output.htlcSigIndex!];
				// Offered-timeout leaf is <local> CHECKSIGVERIFY <remote> CHECKSIG →
				// local consumed first (top of stack): witness bottom→top = remote, local.
				witness = [
					Buffer.concat([remoteSig, sighashByte]),
					Buffer.concat([localSig, sighashByte]),
					htlcOut.timeout.script,
					htlcOut.timeout.controlBlock
				];
			}
			resolved.push({
				trackedOutput: output,
				spendTx: htlcTx,
				witness,
				cltvExpiry: output.cltvExpiry,
				csvDelay: toSelfDelay
			});
		} else if (output.outputType === OutputType.RECEIVED_HTLC) {
			const hashHex = output.paymentHash?.toString('hex');
			const preimage = hashHex ? knownPreimages.get(hashHex) : undefined;
			if (!preimage) {
				resolved.push({ trackedOutput: output });
				continue;
			}
			const htlcOut = buildTaprootReceivedHtlcOutput(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				output.paymentHash!,
				output.cltvExpiry || 0
			);
			const htlcTx = buildTaprootHtlcSuccessTx(
				output.txid,
				output.outputIndex,
				output.amount,
				keys.revocationPubkey,
				keys.delayedPubkey,
				toSelfDelay
			);
			let witness: Buffer[] | undefined;
			if (hasHtlcSig(output)) {
				const localHtlcPrivkey = derivePrivateKey(
					htlcBasepointSecret!,
					perCommitmentPoint,
					state.localBasepoints.htlcBasepoint
				);
				const sighash = taprootHtlcLeafSighash(
					htlcTx,
					htlcOut.output,
					Number(output.amount),
					htlcOut.success.script,
					htlcOut.success.leafVersion
				);
				const localSig = signTaprootHtlcLeaf(sighash, localHtlcPrivkey);
				const remoteSig = remoteHtlcSignatures![output.htlcSigIndex!];
				// Received-success leaf is ...<local> CHECKSIGVERIFY <remote> CHECKSIG →
				// consume preimage (top), then local, then remote: bottom→top =
				// remote, local, preimage.
				witness = [
					Buffer.concat([remoteSig, sighashByte]),
					Buffer.concat([localSig, sighashByte]),
					preimage,
					htlcOut.success.script,
					htlcOut.success.controlBlock
				];
			}
			resolved.push({
				trackedOutput: output,
				spendTx: htlcTx,
				witness,
				csvDelay: toSelfDelay
			});
		}
	}
	return resolved;
}

/**
 * option_taproot: resolve outputs from their CURRENT (non-revoked) commitment.
 * - to_remote (our funds): claim the 1-block-CSV to_remote tapleaf with our key.
 * - our offered HTLC (their received output): reclaim via the CLTV-timeout leaf
 *   (single sig, once expired) — we hold no preimage.
 * - our received HTLC (their offered output): claim via the preimage success leaf
 *   (single sig + preimage). All are direct single-sig tapleaf spends (no
 *   second-level tx — on the peer's commitment we are the claiming party).
 */
function resolveTheirCurrentTaprootCommitmentOutputs(
	state: IChannelState,
	trackedOutputs: ITrackedOutput[],
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	knownPreimages: Map<string, Buffer>,
	paymentPrivkey: Buffer,
	htlcBasepointSecret?: Buffer,
	remotePerCommitmentPoint?: Buffer
): IResolvedOutput[] {
	// Our to_remote on their commitment is a NUMS-internal-key P2TR whose single
	// 1-CSV leaf pays our STATIC payment basepoint - it needs NO peer key
	// material and NO per-commitment point, exactly like the static_remotekey /
	// anchor variants. The full taproot key set (which requires the peer's
	// basepoints and a per-commitment point) is only needed for the HTLC leaves,
	// so derive it opportunistically: an SCB-recovery state (remoteBasepoints
	// null, no point ever learned - THEIR_FUTURE_COMMITMENT) must still resolve
	// the to_remote sweep instead of returning nothing.
	const point =
		remotePerCommitmentPoint || state.remoteCurrentPerCommitmentPoint;
	const keys =
		state.remoteBasepoints && point
			? deriveTaprootCommitKeys(state, point, false)
			: null;
	const htlcPrivkey =
		htlcBasepointSecret && point
			? derivePrivateKey(
					htlcBasepointSecret,
					point,
					state.localBasepoints.htlcBasepoint
			  )
			: undefined;
	const resolved: IResolvedOutput[] = [];

	const spendLeaf = (
		output: ITrackedOutput,
		spk: Buffer,
		leafScript: Buffer,
		controlBlock: Buffer,
		leafVersion: number,
		privkey: Buffer,
		extraWitness: Buffer[],
		nLockTime: number,
		nSequence: number
	): bitcoin.Transaction => {
		const feeSatoshis = BigInt(
			Math.ceil(feeRatePerVbyte * estimateSweepVbytes(output.outputType))
		);
		const tx = new bitcoin.Transaction();
		tx.version = 2;
		tx.locktime = nLockTime;
		tx.addInput(
			Buffer.from(output.txid, 'hex').reverse(),
			output.outputIndex,
			nSequence
		);
		tx.addOutput(destinationScript, Number(output.amount - feeSatoshis));
		const sighash = tx.hashForWitnessV1(
			0,
			[spk],
			[Number(output.amount)],
			bitcoin.Transaction.SIGHASH_DEFAULT,
			tapleafHash(leafScript, leafVersion)
		);
		const sig = signTaprootHtlcLeaf(sighash, privkey);
		tx.ins[0].witness = [sig, ...extraWitness, leafScript, controlBlock];
		return tx;
	};

	for (const output of trackedOutputs) {
		if (output.outputType === OutputType.TO_REMOTE) {
			// Static key: identical to keys.paymentPubkey when keys are derivable,
			// but also available on an SCB-recovery state (paymentPrivkey is its
			// secret in both cases - the monitor supplies the per-channel
			// paymentBasepointSecret located by the SCB's channelKeyIndex).
			const tr = buildTaprootToRemoteOutput(
				state.localBasepoints.paymentBasepoint
			);
			const tx = spendLeaf(
				output,
				tr.output,
				tr.spend.script,
				tr.spend.controlBlock,
				tr.spend.leafVersion,
				paymentPrivkey,
				[],
				0,
				1 // 1-block CSV
			);
			resolved.push({
				trackedOutput: output,
				spendTx: tx,
				witness: tx.ins[0].witness,
				csvDelay: 1
			});
		} else if (output.outputType === OutputType.TO_LOCAL) {
			// Their to_local — not ours unless revoked (handled elsewhere).
			resolved.push({ trackedOutput: output });
		} else if (
			output.outputType === OutputType.OFFERED_HTLC &&
			htlcPrivkey &&
			keys
		) {
			// Our offered = their received output → reclaim via the CLTV-timeout leaf.
			const h = buildTaprootReceivedHtlcOutput(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				output.paymentHash!,
				output.cltvExpiry || 0
			);
			const tx = spendLeaf(
				output,
				h.output,
				h.timeout.script,
				h.timeout.controlBlock,
				h.timeout.leafVersion,
				htlcPrivkey,
				[],
				output.cltvExpiry || 0,
				1 // received-timeout leaf now has OP_1 CSV (+ CLTV via nLockTime)
			);
			resolved.push({
				trackedOutput: output,
				spendTx: tx,
				witness: tx.ins[0].witness,
				cltvExpiry: output.cltvExpiry
			});
		} else if (
			output.outputType === OutputType.RECEIVED_HTLC &&
			htlcPrivkey &&
			keys
		) {
			// Our received = their offered output → claim via the preimage success leaf.
			const hashHex = output.paymentHash?.toString('hex');
			const preimage = hashHex ? knownPreimages.get(hashHex) : undefined;
			if (!preimage) {
				resolved.push({ trackedOutput: output });
				continue;
			}
			const h = buildTaprootOfferedHtlcOutput(
				keys.revocationPubkey,
				keys.localHtlcPubkey,
				keys.remoteHtlcPubkey,
				output.paymentHash!
			);
			const tx = spendLeaf(
				output,
				h.output,
				h.success.script,
				h.success.controlBlock,
				h.success.leafVersion,
				htlcPrivkey,
				[preimage],
				0,
				1 // offered-success leaf now has OP_1 CSV
			);
			resolved.push({
				trackedOutput: output,
				spendTx: tx,
				witness: tx.ins[0].witness
			});
		}
	}
	return resolved;
}

/**
 * Resolve outputs from their current (non-revoked) commitment transaction.
 * - to_remote (our funds): claim immediately with P2WPKH
 * - HTLC outputs: claim with preimage or wait for CLTV timeout
 */
export function resolveTheirCurrentCommitmentOutputs(
	state: IChannelState,
	trackedOutputs: ITrackedOutput[],
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	knownPreimages: Map<string, Buffer>,
	paymentPrivkey: Buffer,
	htlcBasepointSecret?: Buffer,
	remotePerCommitmentPoint?: Buffer
): IResolvedOutput[] {
	if (!state.remoteBasepoints) {
		// SCB recovery (THEIR_FUTURE_COMMITMENT on a reconstructed state): only
		// our to_remote is resolvable - it pays our STATIC payment basepoint and
		// needs no peer key material. Every other output type requires the
		// peer's basepoints, so drop them rather than refusing the sweep.
		trackedOutputs = trackedOutputs.filter(
			(o) => o.outputType === OutputType.TO_REMOTE
		);
		if (trackedOutputs.length === 0) return [];
	}

	if (isTaprootChannel(state.channelType)) {
		return resolveTheirCurrentTaprootCommitmentOutputs(
			state,
			trackedOutputs,
			destinationScript,
			feeRatePerVbyte,
			knownPreimages,
			paymentPrivkey,
			htlcBasepointSecret,
			remotePerCommitmentPoint
		);
	}

	const resolved: IResolvedOutput[] = [];

	for (const output of trackedOutputs) {
		// A lease-locked to_remote (liquidity ads, we are the lessor) carries a
		// CSV number > 1 in the witness script (CLN model); the claim's input
		// nSequence must satisfy it.
		const toRemoteLeaseCsv =
			output.outputType === OutputType.TO_REMOTE && output.witnessScript
				? leaseCsvFromToRemoteScript(output.witnessScript)
				: undefined;
		const feeSatoshis = BigInt(
			Math.ceil(
				feeRatePerVbyte *
					estimateSweepVbytes(output.outputType, toRemoteLeaseCsv !== undefined)
			)
		);

		if (output.outputType === OutputType.TO_REMOTE) {
			// This is our balance on their commitment — claim it with our payment key.
			const paymentPubkey = state.localBasepoints.paymentBasepoint;

			if (output.witnessScript) {
				// Anchor channel: to_remote is a P2WSH with a 1-block CSV. Spend via
				// the script path with nSequence=1 instead of the legacy P2WPKH path.
				const claimTx = buildToLocalSweepTx({
					commitmentTxid: output.txid,
					outputIndex: output.outputIndex,
					amount: output.amount,
					witnessScript: output.witnessScript,
					toSelfDelay: toRemoteLeaseCsv ?? 1,
					destinationScript,
					feeSatoshis
				});

				const sig = signSweepInput(
					claimTx,
					0,
					output.witnessScript,
					Number(output.amount),
					paymentPrivkey
				);
				const witness = buildToRemoteAnchorWitness(sig, output.witnessScript);

				resolved.push({
					trackedOutput: output,
					spendTx: claimTx,
					witness,
					csvDelay: toRemoteLeaseCsv ?? 1
				});
			} else {
				// Non-anchor (static_remotekey): P2WPKH, claimable immediately.
				const claimTx = buildToRemoteClaimTx({
					commitmentTxid: output.txid,
					outputIndex: output.outputIndex,
					amount: output.amount,
					destinationScript,
					feeSatoshis
				});

				const sig = signP2wpkhInput(
					claimTx,
					0,
					paymentPubkey,
					Number(output.amount),
					paymentPrivkey
				);
				const witness = buildToRemoteWitness(sig, paymentPubkey);

				resolved.push({
					trackedOutput: output,
					spendTx: claimTx,
					witness
				});
			}
		} else if (output.outputType === OutputType.TO_LOCAL) {
			// Their to_local — we cannot spend (unless revoked, handled separately)
			resolved.push({ trackedOutput: output });
		} else if (
			output.outputType === OutputType.OFFERED_HTLC &&
			output.paymentHash
		) {
			// Output types are labelled from OUR perspective (see classifyOutputs /
			// matchHtlcOutput). An OFFERED_HTLC is one WE offered (outbound) — on
			// their commitment it uses the received-HTLC script and we reclaim it via
			// the CLTV-timeout path once the HTLC has expired (the downstream never
			// settled, so we hold no preimage). Build the single-sig timeout claim
			// using our HTLC key; the monitor schedules it at cltv maturity. Without
			// this the output was tracked but never swept — the funds (neither party
			// can claim before timeout) were stranded after a remote force-close.
			if (
				output.witnessScript &&
				htlcBasepointSecret &&
				remotePerCommitmentPoint
			) {
				const claimTx = buildRemoteHtlcTimeoutClaimTx({
					commitmentTxid: output.txid,
					outputIndex: output.outputIndex,
					amount: output.amount,
					witnessScript: output.witnessScript,
					destinationScript,
					feeSatoshis,
					cltvExpiry: output.cltvExpiry ?? 0,
					inputSequence: isAnchorChannel(state.channelType) ? 1 : 0xfffffffd
				});

				// Our HTLC private key is the timeout-path signer (the script's
				// remote_htlcpubkey on their commitment is our HTLC key).
				const localHtlcPrivkey = derivePrivateKey(
					htlcBasepointSecret,
					remotePerCommitmentPoint,
					state.localBasepoints.htlcBasepoint
				);
				const sig = signSweepInput(
					claimTx,
					0,
					output.witnessScript,
					Number(output.amount),
					localHtlcPrivkey
				);
				const witness = buildRemoteHtlcTimeoutWitness(
					sig,
					output.witnessScript
				);

				resolved.push({
					trackedOutput: output,
					spendTx: claimTx,
					witness,
					cltvExpiry: output.cltvExpiry
				});
			} else {
				resolved.push({
					trackedOutput: output,
					cltvExpiry: output.cltvExpiry
				});
			}
		} else if (
			output.outputType === OutputType.RECEIVED_HTLC &&
			output.paymentHash
		) {
			// A RECEIVED_HTLC is one WE received (inbound). On their commitment this
			// is their offered-HTLC script, which we sweep immediately with the
			// payment preimage using our HTLC key.
			const hashHex = output.paymentHash.toString('hex');
			const preimage = knownPreimages.get(hashHex);

			if (
				preimage &&
				output.witnessScript &&
				htlcBasepointSecret &&
				remotePerCommitmentPoint
			) {
				// Build and sign the preimage claim transaction. Anchor channels add
				// a 1-block CSV to the HTLC output's claim path, so the input must use
				// sequence 1 (the default 0xffffffff disable bit would fail OP_CSV).
				const claimTx = buildRemoteHtlcPreimageClaimTx({
					commitmentTxid: output.txid,
					outputIndex: output.outputIndex,
					amount: output.amount,
					witnessScript: output.witnessScript,
					destinationScript,
					feeSatoshis,
					inputSequence: isAnchorChannel(state.channelType) ? 1 : 0xffffffff
				});

				// Derive local HTLC private key for signing
				const localHtlcPrivkey = derivePrivateKey(
					htlcBasepointSecret,
					remotePerCommitmentPoint,
					state.localBasepoints.htlcBasepoint
				);

				const sig = signSweepInput(
					claimTx,
					0,
					output.witnessScript,
					Number(output.amount),
					localHtlcPrivkey
				);
				const witness = buildRemoteHtlcPreimageWitness(
					sig,
					preimage,
					output.witnessScript
				);

				resolved.push({
					trackedOutput: output,
					spendTx: claimTx,
					witness
				});
			} else if (preimage) {
				// Have preimage but missing key material — track but can't claim yet
				resolved.push({ trackedOutput: output });
			} else {
				resolved.push({ trackedOutput: output });
			}
		}
	}

	return resolved;
}

/**
 * Resolve outputs from a revoked commitment transaction.
 * All outputs can be claimed using the revocation key.
 */
export function resolveRevokedCommitmentOutputs(
	state: IChannelState,
	trackedOutputs: ITrackedOutput[],
	commitmentNumber: bigint,
	revokedTx: bitcoin.Transaction,
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	revocationBasepointSecret: Buffer,
	paymentPrivkey: Buffer,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): IResolvedOutput[] {
	if (!state.remoteBasepoints) return [];

	if (isTaprootChannel(state.channelType)) {
		return resolveRevokedTaprootCommitmentOutputs(
			state,
			trackedOutputs,
			commitmentNumber,
			revokedTx,
			destinationScript,
			feeRatePerVbyte,
			revocationBasepointSecret,
			paymentPrivkey,
			network
		);
	}

	// Get the per-commitment secret for the revoked commitment
	const secretIndex = MAX_INDEX - commitmentNumber;
	const perCommitmentSecret = state.shaChainStore.getSecret(secretIndex);
	if (!perCommitmentSecret) return [];

	const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);

	// Derive the revocation private key
	const revocationPrivkey = deriveRevocationPrivkey(
		revocationBasepointSecret,
		perCommitmentSecret,
		state.localBasepoints.revocationBasepoint,
		perCommitmentPoint
	);

	const resolved: IResolvedOutput[] = [];

	// Collect claimable output indices and witness scripts
	const claimableIndices: number[] = [];
	const witnessScripts = new Map<number, Buffer>();

	for (const output of trackedOutputs) {
		if (output.outputType === OutputType.TO_LOCAL && output.witnessScript) {
			claimableIndices.push(output.outputIndex);
			witnessScripts.set(output.outputIndex, output.witnessScript);
		} else if (
			(output.outputType === OutputType.OFFERED_HTLC ||
				output.outputType === OutputType.RECEIVED_HTLC) &&
			output.witnessScript
		) {
			claimableIndices.push(output.outputIndex);
			witnessScripts.set(output.outputIndex, output.witnessScript);
		} else if (output.outputType === OutputType.TO_REMOTE) {
			// to_remote is OUR balance on their revoked commitment. It is not part
			// of the penalty (we own it outright), but it must still be swept to our
			// wallet — the previous code only tracked it and never built a claim, so
			// the funds sat unspent at a channel-specific key (and for anchor
			// channels the CSV-1 P2WSH needs an explicit script-path spend). Claim
			// it exactly like the non-revoked remote-commitment path.
			// A lessor's to_remote is lease-locked (CLTV in the witness script);
			// the claim must set nLockTime to it even on a revoked commitment.
			const toRemoteLeaseCsv = output.witnessScript
				? leaseCsvFromToRemoteScript(output.witnessScript)
				: undefined;
			const feeSatoshis = BigInt(
				Math.ceil(
					feeRatePerVbyte *
						estimateSweepVbytes(
							OutputType.TO_REMOTE,
							toRemoteLeaseCsv !== undefined
						)
				)
			);
			if (output.witnessScript) {
				// Anchor channel: P2WSH with a 1-block CSV — spend via script path.
				const claimTx = buildToLocalSweepTx({
					commitmentTxid: output.txid,
					outputIndex: output.outputIndex,
					amount: output.amount,
					witnessScript: output.witnessScript,
					toSelfDelay: toRemoteLeaseCsv ?? 1,
					destinationScript,
					feeSatoshis
				});
				const sig = signSweepInput(
					claimTx,
					0,
					output.witnessScript,
					Number(output.amount),
					paymentPrivkey
				);
				const witness = buildToRemoteAnchorWitness(sig, output.witnessScript);
				resolved.push({
					trackedOutput: output,
					spendTx: claimTx,
					witness,
					csvDelay: 1
				});
			} else {
				// Non-anchor (static_remotekey): plain P2WPKH, claimable immediately.
				const paymentPubkey = state.localBasepoints.paymentBasepoint;
				const claimTx = buildToRemoteClaimTx({
					commitmentTxid: output.txid,
					outputIndex: output.outputIndex,
					amount: output.amount,
					destinationScript,
					feeSatoshis
				});
				const sig = signP2wpkhInput(
					claimTx,
					0,
					paymentPubkey,
					Number(output.amount),
					paymentPrivkey
				);
				const witness = buildToRemoteWitness(sig, paymentPubkey);
				resolved.push({
					trackedOutput: output,
					spendTx: claimTx,
					witness
				});
			}
		}
	}

	// H2: include HTLC outputs that were in this (revoked) commitment but have
	// since settled and left state.htlcs — classifyOutputs only matches live
	// HTLCs, so without the snapshot those outputs go unpenalized and the cheater
	// reclaims them after their CLTV/CSV. Reconstruct each snapshot HTLC's script
	// (using this commitment's keys) and add any matching, not-yet-claimed output.
	const snapshot = state.revokedHtlcSnapshots?.get(commitmentNumber.toString());
	if (snapshot && snapshot.length > 0) {
		const useAnchors = isAnchorChannel(state.channelType);
		const htlcRevocationPubkey = deriveRevocationPubkey(
			state.localBasepoints.revocationBasepoint,
			perCommitmentPoint
		);
		const theirHtlcPubkey = derivePublicKey(
			state.remoteBasepoints.htlcBasepoint,
			perCommitmentPoint
		);
		const ourHtlcPubkey = derivePublicKey(
			state.localBasepoints.htlcBasepoint,
			perCommitmentPoint
		);
		for (const entry of snapshot) {
			// On their commitment: our offered HTLC uses the received-HTLC script,
			// our received HTLC uses the offered-HTLC script (perspective swap).
			const script =
				entry.direction === HtlcDirection.OFFERED
					? buildReceivedHtlcScript(
							htlcRevocationPubkey,
							theirHtlcPubkey,
							ourHtlcPubkey,
							entry.paymentHash,
							entry.cltvExpiry,
							useAnchors
					  )
					: buildOfferedHtlcScript(
							htlcRevocationPubkey,
							theirHtlcPubkey,
							ourHtlcPubkey,
							entry.paymentHash,
							useAnchors
					  );
			const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: script } });
			if (!p2wsh.output) continue;
			for (let i = 0; i < revokedTx.outs.length; i++) {
				if (
					!claimableIndices.includes(i) &&
					revokedTx.outs[i].script.equals(p2wsh.output)
				) {
					claimableIndices.push(i);
					witnessScripts.set(i, script);
					break;
				}
			}
		}
	}

	if (claimableIndices.length === 0) {
		return resolved;
	}

	// Build the address from destination script
	const destAddress = bitcoin.address.fromOutputScript(
		destinationScript,
		network
	);

	// Build penalty transaction
	const penaltyTx = buildPenaltyTx({
		revokedTx,
		revocationPrivkey,
		destinationAddress: destAddress,
		feeRatePerVbyte,
		outputIndices: claimableIndices,
		witnessScripts,
		network
	});

	// Sign each input and build witnesses
	const revocationPubkey = deriveRevocationPubkey(
		state.localBasepoints.revocationBasepoint,
		perCommitmentPoint
	);

	for (let i = 0; i < claimableIndices.length; i++) {
		const outputIdx = claimableIndices[i];
		const ws = witnessScripts.get(outputIdx)!;
		const value = revokedTx.outs[outputIdx].value;
		// May be undefined for an HTLC output reconstructed from the snapshot
		// (it was not in the live classification because the HTLC had settled).
		const output = trackedOutputs.find((o) => o.outputIndex === outputIdx);

		const sig = signPenaltyInput(penaltyTx, i, ws, value, revocationPrivkey);

		let witness: Buffer[];
		if (output?.outputType === OutputType.TO_LOCAL) {
			witness = buildToLocalPenaltyWitness(sig, ws);
		} else {
			// Both tracked HTLC outputs and snapshot-reconstructed ones use the
			// HTLC revocation (penalty) witness.
			witness = buildHtlcPenaltyWitness(sig, revocationPubkey, ws);
		}

		penaltyTx.setWitness(i, witness);

		resolved.push({
			trackedOutput: output ?? {
				txid: revokedTx.getId(),
				outputIndex: outputIdx,
				amount: BigInt(value),
				outputType: OutputType.OFFERED_HTLC,
				status: OutputStatus.CONFIRMED,
				confirmationHeight: 0,
				witnessScript: ws
			},
			spendTx: penaltyTx,
			witness
		});
	}

	return resolved;
}

/**
 * option_taproot: sweep a peer's REVOKED commitment (justice). Builds one penalty
 * transaction spending every penalty output with the revocation key:
 * - their to_local: script-path spend of the revoke tapleaf.
 * - HTLC outputs: key-path spend (the HTLC output's internal key IS the revocation
 *   key), via the BIP341-tweaked revocation private key.
 * Our own to_remote balance is claimed in a separate tx (1-block-CSV leaf). All
 * spend paths were regtest-validated in the P4 taproot spend tests.
 */
function resolveRevokedTaprootCommitmentOutputs(
	state: IChannelState,
	trackedOutputs: ITrackedOutput[],
	commitmentNumber: bigint,
	revokedTx: bitcoin.Transaction,
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	revocationBasepointSecret: Buffer,
	paymentPrivkey: Buffer,
	network: bitcoin.Network
): IResolvedOutput[] {
	if (!state.remoteBasepoints) return [];
	const perCommitmentSecret = state.shaChainStore.getSecret(
		MAX_INDEX - commitmentNumber
	);
	if (!perCommitmentSecret) return [];
	const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);
	const revocationPrivkey = deriveRevocationPrivkey(
		revocationBasepointSecret,
		perCommitmentSecret,
		state.localBasepoints.revocationBasepoint,
		perCommitmentPoint
	);
	const keys = deriveTaprootCommitKeys(state, perCommitmentPoint, false);
	const resolved: IResolvedOutput[] = [];

	interface IPenaltyIn {
		output: ITrackedOutput;
		spk: Buffer;
		value: number;
		leafScript?: Buffer;
		controlBlock?: Buffer;
		merkleRoot?: Buffer; // present ⇒ key-path spend
	}
	const penaltyIns: IPenaltyIn[] = [];

	for (const o of trackedOutputs) {
		if (o.outputType === OutputType.TO_LOCAL) {
			const tl = buildTaprootToLocalOutput(
				keys.revocationPubkey,
				keys.delayedPubkey,
				keys.toSelfDelay,
				network
			);
			penaltyIns.push({
				output: o,
				spk: tl.output,
				value: Number(o.amount),
				leafScript: tl.revoke.script,
				controlBlock: tl.revoke.controlBlock
			});
		} else if (
			o.outputType === OutputType.OFFERED_HTLC ||
			o.outputType === OutputType.RECEIVED_HTLC
		) {
			// On their commitment our RECEIVED = their offered output, our OFFERED =
			// their received output (the classification swap).
			const asOffered = o.outputType === OutputType.RECEIVED_HTLC;
			const h = asOffered
				? buildTaprootOfferedHtlcOutput(
						keys.revocationPubkey,
						keys.localHtlcPubkey,
						keys.remoteHtlcPubkey,
						o.paymentHash!,
						network
				  )
				: buildTaprootReceivedHtlcOutput(
						keys.revocationPubkey,
						keys.localHtlcPubkey,
						keys.remoteHtlcPubkey,
						o.paymentHash!,
						o.cltvExpiry || 0,
						network
				  );
			penaltyIns.push({
				output: o,
				spk: h.output,
				value: Number(o.amount),
				merkleRoot: h.merkleRoot
			});
		} else if (o.outputType === OutputType.TO_REMOTE) {
			// Our balance — claim the 1-block-CSV to_remote leaf with our payment key.
			const tr = buildTaprootToRemoteOutput(keys.paymentPubkey, network);
			const feeSatoshis = BigInt(
				Math.ceil(feeRatePerVbyte * estimateSweepVbytes(OutputType.TO_REMOTE))
			);
			const claimTx = new bitcoin.Transaction();
			claimTx.version = 2;
			claimTx.addInput(
				Buffer.from(o.txid, 'hex').reverse(),
				o.outputIndex,
				1 // 1-block CSV
			);
			claimTx.addOutput(destinationScript, Number(o.amount - feeSatoshis));
			const sighash = claimTx.hashForWitnessV1(
				0,
				[tr.output],
				[Number(o.amount)],
				bitcoin.Transaction.SIGHASH_DEFAULT,
				tapleafHash(tr.spend.script, tr.spend.leafVersion)
			);
			const sig = signTaprootHtlcLeaf(sighash, paymentPrivkey);
			claimTx.ins[0].witness = [sig, tr.spend.script, tr.spend.controlBlock];
			resolved.push({
				trackedOutput: o,
				spendTx: claimTx,
				witness: claimTx.ins[0].witness,
				csvDelay: 1
			});
		}
	}

	// H1: include taproot HTLC outputs that were in this (revoked) commitment but
	// have since settled and left state.htlcs — classifyTaprootCommitmentOutputs
	// matches only live HTLCs, so without the snapshot those outputs go unpenalized
	// and the cheater reclaims them after their CLTV/CSV (mirrors the witness-v0
	// snapshot fallback in resolveRevokedCommitmentOutputs). Each is a
	// revocation-key-path (merkleRoot) breach spend.
	const snapshot = state.revokedHtlcSnapshots?.get(commitmentNumber.toString());
	if (snapshot && snapshot.length > 0) {
		const handled = new Set<number>(trackedOutputs.map((o) => o.outputIndex));
		for (const entry of snapshot) {
			// outputType/direction reflect OUR perspective; on THEIR commitment our
			// received HTLC is their offered output and vice-versa (the same swap the
			// tracked-output loop above and matchTaprootHtlcOutput use).
			const asOffered = entry.direction === HtlcDirection.RECEIVED;
			const h = asOffered
				? buildTaprootOfferedHtlcOutput(
						keys.revocationPubkey,
						keys.localHtlcPubkey,
						keys.remoteHtlcPubkey,
						entry.paymentHash,
						network
				  )
				: buildTaprootReceivedHtlcOutput(
						keys.revocationPubkey,
						keys.localHtlcPubkey,
						keys.remoteHtlcPubkey,
						entry.paymentHash,
						entry.cltvExpiry || 0,
						network
				  );
			for (let i = 0; i < revokedTx.outs.length; i++) {
				if (handled.has(i)) continue;
				if (!revokedTx.outs[i].script.equals(h.output)) continue;
				handled.add(i);
				penaltyIns.push({
					output: {
						txid: revokedTx.getId(),
						outputIndex: i,
						amount: BigInt(revokedTx.outs[i].value),
						outputType:
							entry.direction === HtlcDirection.OFFERED
								? OutputType.OFFERED_HTLC
								: OutputType.RECEIVED_HTLC,
						status: OutputStatus.CONFIRMED,
						confirmationHeight: 0,
						paymentHash: entry.paymentHash,
						cltvExpiry: entry.cltvExpiry
					},
					spk: h.output,
					value: revokedTx.outs[i].value,
					merkleRoot: h.merkleRoot
				});
				break;
			}
		}
	}

	if (penaltyIns.length > 0) {
		const penaltyTx = new bitcoin.Transaction();
		penaltyTx.version = 2;
		let totalIn = 0;
		for (const pin of penaltyIns) {
			penaltyTx.addInput(
				Buffer.from(pin.output.txid, 'hex').reverse(),
				pin.output.outputIndex
			);
			totalIn += pin.value;
		}
		// Rough taproot penalty vbytes: ~43 base + per-input (~58 key-path / ~70
		// script-path) + ~43 output. Overestimate slightly so we clear min-relay.
		const estVbytes = 50 + penaltyIns.length * 75 + 43;
		const fee = Math.ceil(feeRatePerVbyte * estVbytes);
		penaltyTx.addOutput(destinationScript, totalIn - fee);

		const prevScripts = penaltyIns.map((p) => p.spk);
		const values = penaltyIns.map((p) => p.value);

		for (let i = 0; i < penaltyIns.length; i++) {
			const pin = penaltyIns[i];
			let witness: Buffer[];
			if (pin.merkleRoot) {
				// HTLC key-path breach: tweak the revocation key by the output's tree.
				const sighash = penaltyTx.hashForWitnessV1(
					i,
					prevScripts,
					values,
					bitcoin.Transaction.SIGHASH_DEFAULT
				);
				const tweaked = tweakTaprootKeyPathPrivkey(
					revocationPrivkey,
					pin.merkleRoot
				);
				witness = [signTaprootHtlcLeaf(sighash, tweaked)];
			} else {
				// to_local revoke tapleaf (script-path).
				const sighash = penaltyTx.hashForWitnessV1(
					i,
					prevScripts,
					values,
					bitcoin.Transaction.SIGHASH_DEFAULT,
					tapleafHash(pin.leafScript!, TAPLEAF_VERSION)
				);
				witness = [
					signTaprootHtlcLeaf(sighash, revocationPrivkey),
					pin.leafScript!,
					pin.controlBlock!
				];
			}
			penaltyTx.setWitness(i, witness);
			resolved.push({
				trackedOutput: pin.output,
				spendTx: penaltyTx,
				witness
			});
		}
	}

	return resolved;
}

/**
 * Justice on the peer's SECOND-LEVEL HTLC tx after a REVOKED commitment: when
 * the cheater confirms their pre-signed HTLC-success/HTLC-timeout before our
 * HTLC penalty, that tx creates a fresh to_local-format output whose revocation
 * branch WE control (we hold the revoked per-commitment secret) with NO
 * timelock. BOLT 5: a node SHOULD spend the HTLC-timeout/HTLC-success output
 * using the revocation private key — without this claim the HTLC value is lost
 * once the cheater's to_self_delay matures. Sides mirror
 * resolveSecondLevelHtlcOutput to THEIR commitment: their delayed key, our
 * revocation basepoint, the to_self_delay we demanded of them. Matches EVERY
 * output of spendingTx (implementations may batch several HTLC claims into one
 * tx); returns one immediate revocation-path claim per match, witness set.
 */
export function resolveRevokedSecondLevelOutput(
	state: IChannelState,
	spendingTx: bitcoin.Transaction,
	confirmationHeight: number,
	commitmentNumber: bigint,
	destinationScript: Buffer,
	feeRatePerVbyte: number,
	revocationBasepointSecret: Buffer,
	network: bitcoin.Network = bitcoin.networks.bitcoin
): IResolvedOutput[] {
	if (!state.remoteBasepoints) return [];
	const perCommitmentSecret = state.shaChainStore.getSecret(
		MAX_INDEX - commitmentNumber
	);
	if (!perCommitmentSecret) return [];
	const perCommitmentPoint = perCommitmentPointFromSecret(perCommitmentSecret);
	const revocationPrivkey = deriveRevocationPrivkey(
		revocationBasepointSecret,
		perCommitmentSecret,
		state.localBasepoints.revocationBasepoint,
		perCommitmentPoint
	);
	const feeSatoshis = BigInt(
		Math.ceil(feeRatePerVbyte * estimateSweepVbytes(OutputType.TO_LOCAL))
	);
	const spendingTxid = spendingTx.getId();
	const resolved: IResolvedOutput[] = [];

	// option_taproot: the second-level output is a TaprootSecondLevelScriptTree
	// with the revocation key as INTERNAL key — breach-spend via key path with
	// the tweaked revocation privkey, exactly like the revoked-commitment HTLC
	// penalty. Keys mirror resolveRevokedTaprootCommitmentOutputs (isOurs=false:
	// their delayed key, our revocation basepoint, our demanded to_self_delay).
	// No lease variant: leased taproot channels are rejected at negotiation.
	if (isTaprootChannel(state.channelType)) {
		const keys = deriveTaprootCommitKeys(state, perCommitmentPoint, false);
		const sl = buildTaprootSecondLevelOutput(
			keys.revocationPubkey,
			keys.delayedPubkey,
			keys.toSelfDelay,
			network
		);
		const merkleRoot = tapleafHash(sl.delay.script, sl.delay.leafVersion);
		for (let i = 0; i < spendingTx.outs.length; i++) {
			const out = spendingTx.outs[i];
			if (!sl.output.equals(out.script)) continue;
			const amount = BigInt(out.value);
			if (amount <= feeSatoshis) continue;
			const claimTx = new bitcoin.Transaction();
			claimTx.version = 2;
			claimTx.addInput(Buffer.from(spendingTxid, 'hex').reverse(), i);
			claimTx.addOutput(destinationScript, Number(amount - feeSatoshis));
			const sighash = claimTx.hashForWitnessV1(
				0,
				[sl.output],
				[Number(amount)],
				bitcoin.Transaction.SIGHASH_DEFAULT
			);
			const tweaked = tweakTaprootKeyPathPrivkey(revocationPrivkey, merkleRoot);
			const witness = [signTaprootHtlcLeaf(sighash, tweaked)];
			claimTx.setWitness(0, witness);
			resolved.push({
				trackedOutput: {
					txid: spendingTxid,
					outputIndex: i,
					amount,
					outputType: OutputType.TO_LOCAL,
					status: OutputStatus.CONFIRMED,
					confirmationHeight,
					witnessScript: sl.output
				},
				spendTx: claimTx,
				witness
			});
		}
		return resolved;
	}

	const revocationPubkey = deriveRevocationPubkey(
		state.localBasepoints.revocationBasepoint,
		perCommitmentPoint
	);
	const delayedPubkey = derivePublicKey(
		state.remoteBasepoints.delayedPaymentBasepoint,
		perCommitmentPoint
	);
	const toSelfDelay = state.localConfig.toSelfDelay;
	// BOLT 3 / CLN: second-level HTLC outputs are never lease-locked, so the
	// peer's revoked second-level output is the plain to_local-format script.
	const candidateScripts: Buffer[] = [
		buildToLocalScript(revocationPubkey, delayedPubkey, toSelfDelay)
	];

	for (let i = 0; i < spendingTx.outs.length; i++) {
		const out = spendingTx.outs[i];
		let witnessScript: Buffer | undefined;
		for (const script of candidateScripts) {
			const p2wsh = bitcoin.payments.p2wsh({ redeem: { output: script } });
			if (p2wsh.output && p2wsh.output.equals(out.script)) {
				witnessScript = script;
				break;
			}
		}
		if (!witnessScript) continue;
		const amount = BigInt(out.value);
		if (amount <= feeSatoshis) continue;
		// Revocation branch: no CSV/CLTV — spend immediately (default sequence,
		// locktime 0, matching buildPenaltyTx's convention).
		const claimTx = new bitcoin.Transaction();
		claimTx.version = 2;
		claimTx.addInput(Buffer.from(spendingTxid, 'hex').reverse(), i);
		claimTx.addOutput(destinationScript, Number(amount - feeSatoshis));
		const sig = signPenaltyInput(
			claimTx,
			0,
			witnessScript,
			Number(amount),
			revocationPrivkey
		);
		const witness = buildToLocalPenaltyWitness(sig, witnessScript);
		claimTx.setWitness(0, witness);
		resolved.push({
			trackedOutput: {
				txid: spendingTxid,
				outputIndex: i,
				amount,
				outputType: OutputType.TO_LOCAL,
				status: OutputStatus.CONFIRMED,
				confirmationHeight,
				witnessScript
			},
			spendTx: claimTx,
			witness
		});
	}

	return resolved;
}

// ─────────────── Preimage Extraction ───────────────

/**
 * Extract a preimage from an HTLC spend witness on-chain.
 * In an HTLC-success spend, the witness contains the preimage as the
 * 4th element: [0, remoteSig, localSig, preimage, witnessScript]
 *
 * @returns The 32-byte preimage, or null if not found
 */
export function extractPreimageFromWitness(witness: Buffer[]): Buffer | null {
	if (!witness || witness.length < 5) {
		return null;
	}

	// HTLC-success witness format: [0, remoteSig, localSig, preimage, witnessScript]
	// The preimage should be exactly 32 bytes
	const candidate = witness[3];
	if (candidate && candidate.length === 32) {
		return candidate;
	}

	return null;
}
