import type * as bitcoin from 'bitcoinjs-lib';
import { hmacSha256, sha256 } from '../crypto/provider';
import { generateNonce } from '../crypto/musig';
import type { ISigner } from '../keys/signer';
import {
	startCommitmentSigningSession,
	verifyPartialCommitmentSig,
	aggregateCommitmentSig
} from './commitment-musig';
import {
	taprootKeySpendSighash,
	createTaprootFundingScript
} from '../script/funding-taproot';
import { ecc } from '../../utils/ecc';

/** Public evidence retained before any signature from this attempt leaves. */
export interface ITaprootFundingRound {
	domain: Buffer;
	localVerificationNonce: Buffer;
	remoteVerificationNonce?: Buffer;
	localSharedNonce?: Buffer;
	localNextVerificationNonce?: Buffer;
	remoteNextVerificationNonce?: Buffer;
	remoteSharedNonce?: Buffer;
	ourCommitmentPartial?: Buffer;
	ourCommitmentDigest?: Buffer;
	ourCommitmentMessage?: Buffer;
	remoteCommitmentPartial?: Buffer;
	remoteSigningNonce?: Buffer;
	ourSharedPartial?: Buffer;
	sharedDigest?: Buffer;
}

/** Funding identity distinguishes same-height commitments on different outputs. */
export function fundingNonceDomain(transaction: bitcoin.Transaction): Buffer {
	return sha256(
		Buffer.concat([
			Buffer.from('native-taproot-funding-v1'),
			transaction.getHash()
		])
	);
}

/** Regenerated only for one fixed transaction and peer nonce binding. */
export function deriveFundingNonce(
	seed: Buffer,
	publicKey: Buffer,
	domain: Buffer,
	purpose: 'commitment' | 'shared',
	height = 0n
): Uint8Array {
	if (
		seed.length !== 32 ||
		domain.length !== 32 ||
		height < 0n ||
		height > 0xffffffffffffffffn
	)
		throw new Error('Invalid funding nonce domain');
	const index = Buffer.alloc(8);
	index.writeBigUInt64BE(height);
	return generateNonce({
		publicKey,
		sessionId: hmacSha256(
			seed,
			Buffer.concat([
				Buffer.from(`native-taproot-${purpose}-nonce-v1`),
				domain,
				index
			])
		)
	});
}

/** A peer cannot change a nonce once any partial for that transcript exists. */
export function bindFundingPeerNonces(
	round: ITaprootFundingRound,
	verification: Buffer,
	shared?: Buffer,
	next?: Buffer
): void {
	if (
		verification.length !== 66 ||
		(shared && shared.length !== 66) ||
		(next && next.length !== 66)
	)
		throw new Error('Invalid funding public nonce');
	const signed = !!(
		round.ourCommitmentPartial ||
		round.remoteCommitmentPartial ||
		round.ourSharedPartial
	);
	if (
		signed &&
		(!round.remoteVerificationNonce?.equals(verification) ||
			!!round.remoteSharedNonce !== !!shared ||
			(shared && !round.remoteSharedNonce?.equals(shared)) ||
			!!round.remoteNextVerificationNonce !== !!next ||
			(next && !round.remoteNextVerificationNonce?.equals(next)))
	)
		throw new Error('Funding peer changed a committed nonce');
	round.remoteVerificationNonce = Buffer.from(verification);
	round.remoteSharedNonce = shared ? Buffer.from(shared) : undefined;
	if (next) round.remoteNextVerificationNonce = Buffer.from(next);
	else delete round.remoteNextVerificationNonce;
}

export interface ITaprootSharedInput {
	transaction: bitcoin.Transaction;
	inputIndex: number;
	prevoutScripts: Buffer[];
	prevoutValues: number[];
	localFundingPubkey: Buffer;
	remoteFundingPubkey: Buffer;
	fundingMerkleRoot?: Buffer;
}
function sharedSession(
	round: ITaprootFundingRound,
	input: ITaprootSharedInput
) {
	if (
		!round.domain.equals(fundingNonceDomain(input.transaction)) ||
		!round.localSharedNonce ||
		!round.remoteSharedNonce
	)
		throw new Error('Incomplete funding signature transcript');
	const script = createTaprootFundingScript(
		input.localFundingPubkey,
		input.remoteFundingPubkey,
		undefined,
		input.fundingMerkleRoot
	);
	if (!input.prevoutScripts[input.inputIndex]?.equals(script.p2trOutput))
		throw new Error('Shared input funding script differs');
	const digest = taprootKeySpendSighash(
		input.transaction,
		input.inputIndex,
		input.prevoutScripts,
		input.prevoutValues
	);
	if (round.sharedDigest && !round.sharedDigest.equals(digest))
		throw new Error('Shared input signing transcript changed');
	const session = startCommitmentSigningSession(
		digest,
		input.localFundingPubkey,
		input.remoteFundingPubkey,
		round.localSharedNonce,
		round.remoteSharedNonce,
		input.fundingMerkleRoot
	);
	return { session, digest, script };
}

/** The returned partial is cached before callers place it behind persistence. */
export function signFundingSharedInput(
	round: ITaprootFundingRound,
	input: ITaprootSharedInput,
	seed: Buffer,
	signer: ISigner
): Buffer {
	const { session, digest } = sharedSession(round, input);
	if (!round.ourSharedPartial) {
		const nonce = deriveFundingNonce(
			seed,
			input.localFundingPubkey,
			round.domain,
			'shared'
		);
		if (!Buffer.from(nonce).equals(round.localSharedNonce!))
			throw new Error('Stored funding nonce differs');
		round.sharedDigest = Buffer.from(digest);
		round.ourSharedPartial = Buffer.from(
			signer.signCommitmentPartial(session, nonce)
		);
	}
	return Buffer.concat([round.ourSharedPartial, round.localSharedNonce!]);
}
export function verifyFundingSharedInput(
	round: ITaprootFundingRound,
	input: ITaprootSharedInput,
	partialWithNonce: Buffer
): boolean {
	try {
		if (
			partialWithNonce.length !== 98 ||
			!round.remoteSharedNonce?.equals(partialWithNonce.subarray(32))
		)
			return false;
		return verifyPartialCommitmentSig(
			sharedSession(round, input).session,
			partialWithNonce.subarray(0, 32),
			input.remoteFundingPubkey,
			round.remoteSharedNonce
		);
	} catch {
		return false;
	}
}
export function finalizeFundingSharedInput(
	round: ITaprootFundingRound,
	input: ITaprootSharedInput,
	partialWithNonce: Buffer
): Buffer {
	if (
		!round.ourSharedPartial ||
		!verifyFundingSharedInput(round, input, partialWithNonce)
	)
		throw new Error('Invalid shared funding partial');
	const { session, digest, script } = sharedSession(round, input);
	const signature = aggregateCommitmentSig(
		session,
		round.ourSharedPartial,
		partialWithNonce.subarray(0, 32)
	);
	if (!ecc.verifySchnorr(digest, script.outputKey, signature))
		throw new Error('Invalid aggregate funding signature');
	return signature;
}
