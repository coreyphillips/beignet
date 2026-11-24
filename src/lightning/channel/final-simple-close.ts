import { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import {
	buildSimpleClosingTx,
	isDustOutput,
	minRelayFeeForWeight,
	SimpleCloseVariant,
	type ISimpleClosingTxParams
} from '../chain/closing';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import {
	decodeClosingCompleteMessage,
	decodeClosingSigMessage,
	encodeClosingCompleteMessage,
	encodeClosingSigMessage,
	type IClosingCompleteMessage
} from '../message/channel-close';
import { createTaprootFundingScript } from '../script/funding-taproot';
import {
	aggregateCommitmentSig,
	partialSignCommitment,
	startCommitmentSigningSession,
	taprootCommitmentSighash,
	verifyPartialCommitmentSig
} from './commitment-musig';
import { isValidShutdownScript } from './validation';

export interface IFinalSimpleCloseParams {
	channelId: Buffer;
	fundingTx: Buffer;
	fundingOutputIndex: number;
	localFundingPrivkey: Buffer;
	remoteFundingPubkey: Buffer;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
	localScriptPubkey: Buffer;
	remoteScriptPubkey: Buffer;
	localIsCloser: boolean;
	blockHeight: number;
	feeSatoshis: bigint;
	locktime: number;
}

const finalFormat = { finalTaproot: true };
const { CLOSER_OUTPUT_ONLY, CLOSEE_OUTPUT_ONLY, CLOSER_AND_CLOSEE } =
	SimpleCloseVariant;
const field = {
	[SimpleCloseVariant.CLOSER_OUTPUT_ONLY]: 'closerOutputOnlyPartialSig',
	[SimpleCloseVariant.CLOSEE_OUTPUT_ONLY]: 'closeeOutputOnlyPartialSig',
	[SimpleCloseVariant.CLOSER_AND_CLOSEE]: 'closerAndCloseePartialSig'
} as const;
const variants = [
	CLOSER_OUTPUT_ONLY,
	CLOSEE_OUTPUT_ONLY,
	CLOSER_AND_CLOSEE
] as const;

interface ICloseTerms {
	localKey: Buffer;
	peerKey: Buffer;
	prevout: Transaction['outs'][number];
	funding: ReturnType<typeof createTaprootFundingScript>;
	message: IClosingCompleteMessage;
	closerLarger: boolean;
	closerDust: boolean;
	closeeDust: boolean;
	transaction: Omit<ISimpleClosingTxParams, 'variant'>;
}

function terms(
	p: IFinalSimpleCloseParams,
	localIsCloser: boolean
): ICloseTerms {
	if (p.localIsCloser !== localIsCloser || p.channelId.length !== 32)
		throw new Error('Invalid final close role or channel id');
	if (
		!Number.isSafeInteger(p.blockHeight) ||
		p.blockHeight < 0 ||
		!Number.isSafeInteger(p.locktime) ||
		p.locktime < 0 ||
		p.locktime >= 500_000_000 ||
		(p.locktime > 0 && (p.blockHeight === 0 || p.locktime > p.blockHeight + 6))
	)
		throw new Error('Invalid final close locktime');
	if (
		!isValidShutdownScript(p.localScriptPubkey, true, false) ||
		!isValidShutdownScript(p.remoteScriptPubkey, true, true)
	)
		throw new Error('Invalid final close payout script');
	const parent = Transaction.fromBuffer(p.fundingTx);
	const prevout = parent.outs[p.fundingOutputIndex];
	const localKey = getPublicKey(p.localFundingPrivkey);
	const funding = createTaprootFundingScript(localKey, p.remoteFundingPubkey);
	if (
		!prevout ||
		localKey.equals(p.remoteFundingPubkey) ||
		!prevout.script.equals(funding.p2trOutput) ||
		prevout.value <= 0
	)
		throw new Error(
			'Final close funding outpoint does not match the channel keys'
		);
	if (
		p.localBalanceMsat < 0n ||
		p.remoteBalanceMsat < 0n ||
		p.localBalanceMsat + p.remoteBalanceMsat !== 1000n * BigInt(prevout.value)
	)
		throw new Error(
			'Final close balances do not account for the funding value'
		);
	const closerMsat = localIsCloser ? p.localBalanceMsat : p.remoteBalanceMsat;
	const closeeMsat = localIsCloser ? p.remoteBalanceMsat : p.localBalanceMsat;
	const closerAmount = closerMsat / 1000n,
		closeeAmount = closeeMsat / 1000n;
	if (p.feeSatoshis < 0n || p.feeSatoshis > closerAmount)
		throw new Error('Final close fee exceeds the closer balance');
	const message = {
		channelId: p.channelId,
		feeSatoshis: p.feeSatoshis,
		locktime: p.locktime,
		closerScriptPubkey: localIsCloser
			? p.localScriptPubkey
			: p.remoteScriptPubkey,
		closeeScriptPubkey: localIsCloser
			? p.remoteScriptPubkey
			: p.localScriptPubkey
	};
	return {
		localKey,
		peerKey: p.remoteFundingPubkey,
		prevout,
		funding,
		message,
		closerLarger: closerMsat >= closeeMsat,
		closerDust: isDustOutput(
			message.closerScriptPubkey,
			closerAmount - p.feeSatoshis
		),
		closeeDust: isDustOutput(message.closeeScriptPubkey, closeeAmount),
		transaction: {
			...message,
			fundingTxid: parent.getHash().toString('hex'),
			fundingOutputIndex: p.fundingOutputIndex,
			closerAmount,
			closeeAmount
		}
	};
}

function matchTerms(t: ICloseTerms, msg: IClosingCompleteMessage): void {
	const m = t.message;
	if (
		!m.channelId.equals(msg.channelId) ||
		m.feeSatoshis !== msg.feeSatoshis ||
		m.locktime !== msg.locktime ||
		!m.closerScriptPubkey.equals(msg.closerScriptPubkey) ||
		!m.closeeScriptPubkey.equals(msg.closeeScriptPubkey)
	)
		throw new Error(
			'Final close message differs from agreed channel, fee, locktime or payout scripts'
		);
}

function candidate(
	t: ICloseTerms,
	variant: SimpleCloseVariant
): { tx: Transaction; digest: Buffer } {
	const { tx } = buildSimpleClosingTx({ ...t.transaction, variant });
	if (tx.outs.some((o) => isDustOutput(o.script, BigInt(o.value))))
		throw new Error('Final close variant has dust outputs');
	const paid =
		BigInt(t.prevout.value) -
		tx.outs.reduce((sum, o) => sum + BigInt(o.value), 0n);
	tx.setWitness(0, [Buffer.alloc(64)]);
	if (paid < minRelayFeeForWeight(tx.weight()))
		throw new Error('Final close fee is below relay minimum');
	tx.setWitness(0, []);
	return {
		tx,
		digest: taprootCommitmentSighash(tx, t.prevout.script, t.prevout.value)
	};
}

function distinctNonces(nonces: Uint8Array[]): void {
	const seen = new Set<string>();
	for (const n of nonces) {
		const nonce = Buffer.from(n);
		if (
			nonce.length !== 66 ||
			!isValidPublicKey(nonce.subarray(0, 33)) ||
			!isValidPublicKey(nonce.subarray(33)) ||
			seen.has(nonce.toString('hex'))
		)
			throw new Error('Invalid or repeated final close public nonce');
		seen.add(nonce.toString('hex'));
	}
}
function proposalNonces(msg: IClosingCompleteMessage): Buffer[] {
	return variants.flatMap((v) =>
		msg[field[v]] ? [msg[field[v]]!.subarray(32)] : []
	);
}

function proposalVariants(t: ICloseTerms): SimpleCloseVariant[] {
	if (t.closerLarger) {
		if (t.closerDust)
			throw new Error('Final close fee leaves the required closer output dust');
		return t.closeeDust
			? [CLOSER_OUTPUT_ONLY]
			: [CLOSER_OUTPUT_ONLY, CLOSER_AND_CLOSEE];
	}
	if (t.closeeDust)
		throw new Error('Final close has no economical closee output');
	return t.closerDust ? [CLOSEE_OUTPUT_ONLY] : [CLOSER_AND_CLOSEE];
}

/** Create a payload for type 40. Each offered variant consumes its own reserved nonce. */
export function proposeFinalSimpleClose(
	p: IFinalSimpleCloseParams,
	peerCloseeNonce: Buffer,
	createFreshNonceForVariant: (
		variant: SimpleCloseVariant,
		sighash: Buffer
	) => Uint8Array
): { proposal: Buffer } {
	const t = terms(p, true);
	const message: IClosingCompleteMessage = { ...t.message };
	const offered = proposalVariants(t).map((variant) => ({
		variant,
		...candidate(t, variant)
	}));
	const prepared = offered.map(({ variant, digest }) => ({
		variant,
		digest,
		nonce: createFreshNonceForVariant(variant, digest)
	}));
	distinctNonces([peerCloseeNonce, ...prepared.map((x) => x.nonce)]);
	for (const { variant, digest, nonce } of prepared) {
		const session = startCommitmentSigningSession(
			digest,
			t.localKey,
			t.peerKey,
			nonce,
			peerCloseeNonce
		);
		message[field[variant]] = Buffer.concat([
			partialSignCommitment(session, p.localFundingPrivkey, nonce),
			Buffer.from(nonce)
		]);
	}
	return { proposal: encodeClosingCompleteMessage(message, finalFormat) };
}

function signedTransaction(
	t: ICloseTerms,
	tx: Transaction,
	digest: Buffer,
	session: ReturnType<typeof startCommitmentSigningSession>,
	closerSig: Buffer,
	closeeSig: Buffer
): Buffer {
	const sig = aggregateCommitmentSig(session, closerSig, closeeSig);
	if (!ecc.verifySchnorr(digest, t.funding.outputKey, sig))
		throw new Error('Invalid final close aggregate signature');
	tx.setWitness(0, [sig]);
	return tx.toBuffer();
}

/** Verify the selected closer signature before consuming our single-use closee nonce. */
export function acceptFinalSimpleClose(
	p: IFinalSimpleCloseParams,
	proposal: Buffer,
	ourCloseeNonce: Uint8Array,
	nextCloseeNonce: Buffer
): { reply: Buffer; transaction: Buffer } {
	const t = terms(p, false);
	const msg = decodeClosingCompleteMessage(proposal, finalFormat);
	matchTerms(t, msg);
	distinctNonces([ourCloseeNonce, nextCloseeNonce, ...proposalNonces(msg)]);
	const variant = t.closeeDust
		? CLOSER_OUTPUT_ONLY
		: msg.closerAndCloseePartialSig
		? CLOSER_AND_CLOSEE
		: CLOSEE_OUTPUT_ONLY;
	const offered = msg[field[variant]];
	if (!offered)
		throw new Error('Final close has no valid signature for the closee payout');
	const { tx, digest } = candidate(t, variant);
	const closerNonce = offered.subarray(32),
		closerSig = offered.subarray(0, 32);
	const session = startCommitmentSigningSession(
		digest,
		t.localKey,
		t.peerKey,
		ourCloseeNonce,
		closerNonce
	);
	if (!verifyPartialCommitmentSig(session, closerSig, t.peerKey, closerNonce))
		throw new Error('Invalid final close closer signature');
	const closeeSig = partialSignCommitment(
		session,
		p.localFundingPrivkey,
		ourCloseeNonce
	);
	const transaction = signedTransaction(
		t,
		tx,
		digest,
		session,
		closerSig,
		closeeSig
	);
	const reply = encodeClosingSigMessage(
		{ ...t.message, [field[variant]]: closeeSig, nextCloseeNonce },
		finalFormat
	);
	return { reply, transaction };
}

/** Watch every exact funding spend we offered, including a peer broadcast before its reply. */
export function finalSimpleCloseProposalTxids(
	p: IFinalSimpleCloseParams,
	proposal: Buffer
): string[] {
	const t = terms(p, true);
	const msg = decodeClosingCompleteMessage(proposal, finalFormat);
	matchTerms(t, msg);
	distinctNonces(proposalNonces(msg));
	const expected = proposalVariants(t);
	const offered = variants.filter((v) => msg[field[v]] !== undefined);
	if (
		offered.length !== expected.length ||
		offered.some((v) => !expected.includes(v))
	)
		throw new Error('Unexpected final close proposal variants');
	return offered.map((v) => candidate(t, v).tx.getId());
}

/** Finalize a saved proposal without consuming a second closer nonce. */
export function completeFinalSimpleClose(
	p: IFinalSimpleCloseParams,
	proposal: Buffer,
	reply: Buffer,
	peerCloseeNonce: Buffer
): Buffer {
	const t = terms(p, true);
	const msg = decodeClosingCompleteMessage(proposal, finalFormat),
		response = decodeClosingSigMessage(reply, finalFormat);
	matchTerms(t, msg);
	matchTerms(t, response);
	distinctNonces([
		peerCloseeNonce,
		response.nextCloseeNonce!,
		...proposalNonces(msg)
	]);
	const variant = variants.find((v) => response[field[v]] !== undefined)!;
	const offered = msg[field[variant]],
		closeeSig = response[field[variant]]!;
	if (!offered)
		throw new Error('Final close reply selected an unoffered variant');
	const { tx, digest } = candidate(t, variant);
	const closerNonce = offered.subarray(32),
		closerSig = offered.subarray(0, 32);
	const session = startCommitmentSigningSession(
		digest,
		t.localKey,
		t.peerKey,
		closerNonce,
		peerCloseeNonce
	);
	if (
		!verifyPartialCommitmentSig(session, closerSig, t.localKey, closerNonce) ||
		!verifyPartialCommitmentSig(session, closeeSig, t.peerKey, peerCloseeNonce)
	)
		throw new Error('Invalid final close partial signature');
	return signedTransaction(t, tx, digest, session, closerSig, closeeSig);
}
