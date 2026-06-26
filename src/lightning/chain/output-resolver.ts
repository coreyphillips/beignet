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
import { buildToRemoteAnchorOutput } from '../script/anchor';
import {
	buildOfferedHtlcScript,
	buildReceivedHtlcScript,
	buildHtlcSuccessTx,
	buildHtlcTimeoutTx
} from '../script/htlc';
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
import {
	ChannelRole,
	HtlcDirection,
	HtlcState,
	isAnchorChannel
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
	const feeratePerKw = getCommitmentFeeRate(state);
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
	if (!state.remoteBasepoints || !state.fundingTxid) {
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

	// Check if this is a cooperative close (version 2, locktime 0, no witness programs in outputs)
	if (tx.locktime === 0 && tx.ins[0].sequence === 0xffffffff) {
		return { type: CommitmentType.COOPERATIVE_CLOSE, commitmentNumber: 0n };
	}

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
	const ourToLocalScript = buildToLocalScript(
		ourRevocationPubkey,
		ourDelayedPubkey,
		state.remoteConfig.toSelfDelay
	);
	const ourToLocalP2wsh = bitcoin.payments.p2wsh({
		redeem: { output: ourToLocalScript }
	});

	// Check if any tx output matches our to_local script
	for (const out of tx.outs) {
		if (
			ourToLocalP2wsh.output &&
			Buffer.from(out.script).equals(ourToLocalP2wsh.output)
		) {
			return CommitmentType.OUR_COMMITMENT;
		}
	}

	// If not ours, check if it could be theirs
	if (state.remoteCurrentPerCommitmentPoint) {
		return CommitmentType.THEIR_CURRENT_COMMITMENT;
	}

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
	if (!state.remoteBasepoints) {
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
	const toLocalScript = buildToLocalScript(
		revocationPubkey,
		localDelayedPubkey,
		toSelfDelay
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
	const toLocalScript = buildToLocalScript(
		revocationPubkey,
		theirDelayedPubkey,
		toSelfDelay
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
			const sweepTx = buildToLocalSweepTx({
				commitmentTxid: output.txid,
				outputIndex: output.outputIndex,
				amount: output.amount,
				witnessScript: output.witnessScript,
				toSelfDelay,
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
				csvDelay: toSelfDelay
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
	if (!state.remoteBasepoints) return [];

	const resolved: IResolvedOutput[] = [];

	for (const output of trackedOutputs) {
		const feeSatoshis = BigInt(
			Math.ceil(feeRatePerVbyte * estimateSweepVbytes(output.outputType))
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
					toSelfDelay: 1,
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
			if (output.witnessScript && htlcBasepointSecret && remotePerCommitmentPoint) {
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
			const feeSatoshis = BigInt(
				Math.ceil(
					feeRatePerVbyte * estimateSweepVbytes(OutputType.TO_REMOTE)
				)
			);
			if (output.witnessScript) {
				// Anchor channel: P2WSH with a 1-block CSV — spend via script path.
				const claimTx = buildToLocalSweepTx({
					commitmentTxid: output.txid,
					outputIndex: output.outputIndex,
					amount: output.amount,
					witnessScript: output.witnessScript,
					toSelfDelay: 1,
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
			trackedOutput:
				output ?? {
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
