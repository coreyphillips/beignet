import { Transaction } from 'bitcoinjs-lib';
import { sha256 } from '../crypto/provider';
import { validateFundingWitness } from '../interactive-tx/funding-witness';
import {
	checkFeeSufficiency,
	MAX_STANDARD_TX_WEIGHT
} from '../interactive-tx/validation';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import {
	decodeTxSignaturesMessage,
	encodeTxSignaturesMessage
} from '../message/interactive-tx';
import type { FinalOpeningAuthority } from './final-opening-authority';
import type { IFinalOpeningCandidate } from './final-opening-candidate';
import type { IFinalOpeningNonces } from './final-opening-nonces';
import type { IFinalOpeningSigning } from './final-opening-signing';

type Prevouts = { scripts: Buffer[]; values: bigint[] };
export type FinalFundingWitnessSigner = (
	unsigned: Transaction,
	indices: readonly number[],
	prevouts: Prevouts
) => Buffer[][];

export function finalFundingInputs(candidate: IFinalOpeningCandidate): {
	tx: Transaction;
	prevouts: Prevouts;
	local: number[];
	peer: number[];
} {
	const tx = Transaction.fromHex(candidate.fundingTxHex);
	const prevouts: Prevouts = { scripts: [], values: [] };
	const local: number[] = [],
		peer: number[] = [];
	for (const [i, input] of candidate.inputs.entries()) {
		const prev = Transaction.fromHex(input.prevTxHex).outs[tx.ins[i].index];
		prevouts.scripts.push(prev.script);
		prevouts.values.push(BigInt(prev.value));
		(input.isLocal ? local : peer).push(i);
	}
	return { tx, prevouts, local, peer };
}

function requireCommitments(
	signing?: IFinalOpeningSigning
): asserts signing is IFinalOpeningSigning & {
	exit: string;
	outgoing: string;
	peer: string;
} {
	if (!signing?.exit || !signing.outgoing || !signing.peer)
		throw new Error(
			'Funding witnesses require both opening commitments and the signed local exit'
		);
}

function readWire(hex: string): Buffer {
	if (
		typeof hex !== 'string' ||
		hex.length > 2 * MAX_LIGHTNING_PAYLOAD ||
		!/^(?:[a-f0-9]{2})+$/.test(hex)
	)
		throw new Error('Invalid saved funding witness payload');
	return Buffer.from(hex, 'hex');
}

function assembled(
	candidate: IFinalOpeningCandidate,
	signing: IFinalOpeningSigning
): Buffer | null {
	const { tx, prevouts, local, peer } = finalFundingInputs(candidate);
	const id = Buffer.from(candidate.channelId, 'hex');
	const txid = tx.getHash();
	for (const [hex, indices] of [
		[signing.fundingLocal, local],
		[signing.fundingPeer, peer]
	] as const) {
		if (hex === undefined) continue;
		const raw = readWire(hex);
		const message = decodeTxSignaturesMessage(raw, { taproot: true });
		if (
			!message.channelId.equals(id) ||
			!message.txid.equals(txid) ||
			message.sharedInputSignature ||
			message.sharedInputPartialSignatureWithNonce ||
			message.witnesses.length !== indices.length ||
			!encodeTxSignaturesMessage(message).equals(raw)
		)
			throw new Error('Funding tx_signatures do not match the opening');
		for (const [position, index] of indices.entries()) {
			const stack = message.witnesses[position];
			const error = validateFundingWitness(tx, index, stack, prevouts);
			if (error) throw new Error(error);
			tx.setWitness(index, stack);
		}
	}
	if (signing.fundingLocal === undefined || signing.fundingPeer === undefined)
		return null;
	const weight = tx.weight();
	const fee =
		prevouts.values.reduce((a, b) => a + b, 0n) -
		tx.outs.reduce((a, b) => a + BigInt(b.value), 0n);
	if (weight > MAX_STANDARD_TX_WEIGHT)
		throw new Error('Signed funding transaction exceeds standard weight');
	const feeError = checkFeeSufficiency(
		fee,
		weight,
		candidate.fundingFeeratePerKw
	);
	if (feeError) throw new Error(feeError);
	return tx.toBuffer();
}

/** Every persisted witness and the resulting funding transaction are reverified on recovery. */
export function verifyOpeningFunding(
	candidate: IFinalOpeningCandidate,
	signing: IFinalOpeningSigning
): void {
	if (
		signing.fundingLocal === undefined &&
		signing.fundingPeer === undefined &&
		signing.fundingTransaction === undefined
	)
		return;
	requireCommitments(signing);
	if (
		assembled(candidate, signing)?.toString('hex') !==
		signing.fundingTransaction
	)
		throw new Error(
			'Stored funding transaction differs from the verified witness exchange'
		);
}

export function recordOpeningFunding(
	candidate: IFinalOpeningCandidate,
	state: IFinalOpeningNonces,
	nonceKey: Buffer,
	authority: FinalOpeningAuthority | null,
	operation:
		| { sign: FinalFundingWitnessSigner }
		| { peer: Buffer }
		| { witnesses: Buffer[][] }
): Buffer {
	const signing = state.signing;
	requireCommitments(signing);
	if ('sign' in operation && state.session?.assetEvidence)
		throw new Error('Asset opening requires prepared asset wallet witnesses');
	const field = 'peer' in operation ? 'fundingPeer' : 'fundingLocal';
	if (
		'peer' in operation &&
		(!Buffer.isBuffer(operation.peer) ||
			operation.peer.length > MAX_LIGHTNING_PAYLOAD)
	)
		throw new Error('Invalid peer funding witness payload');
	const saved = signing[field];
	const supplied =
		'witnesses' in operation
			? walletWitnessPayload(candidate, operation.witnesses)
			: undefined;
	if (saved !== undefined) {
		const original = readWire(saved);
		if ('peer' in operation && !original.equals(operation.peer))
			throw new Error('Peer changed its saved funding witnesses');
		if (supplied && !original.equals(supplied))
			throw new Error('Changed asset funding witnesses');
		return original;
	}
	if (!authority)
		throw new Error('New funding witnesses require the original wallet device');
	const slot = 'funding-witness/' + field + '/' + candidate.channelId;
	const transcript = fundingTranscript(
		nonceKey,
		state,
		'peer' in operation ? operation.peer : undefined
	);
	let wire: Buffer;
	if (!('peer' in operation)) {
		const { tx, local, prevouts } = finalFundingInputs(candidate);
		reserveOpeningInputs(
			candidate.channelId,
			signing.exit,
			tx,
			local,
			authority,
			transcript
		);
		const cached = authority.claim(slot, transcript);
		if (cached) {
			if (supplied && !cached.equals(supplied))
				throw new Error('Changed asset funding witnesses');
			wire = cached;
		} else if (supplied) wire = supplied;
		else if ('sign' in operation) {
			// The wallet receives its own working copy. Verify its result against the stored unsigned transaction.
			wire = walletWitnessPayload(
				candidate,
				local.length ? operation.sign(tx, local, prevouts) : []
			);
		} else throw new Error('Missing asset funding witnesses');
	} else wire = Buffer.from(operation.peer);
	signing[field] = wire.toString('hex');
	const complete = assembled(candidate, signing);
	if (complete) signing.fundingTransaction = complete.toString('hex');
	if ('peer' in operation) authority.claim(slot, transcript);
	return authority.finish(slot, transcript, wire);
}

function walletWitnessPayload(
	candidate: IFinalOpeningCandidate,
	witnesses: Buffer[][]
): Buffer {
	const { tx, local } = finalFundingInputs(candidate);
	if (
		!Array.isArray(witnesses) ||
		witnesses.length !== local.length ||
		witnesses.some(
			(w) =>
				!Array.isArray(w) ||
				w.length < 1 ||
				w.length > 2 ||
				w.some((e) => !Buffer.isBuffer(e) || e.length > 73)
		)
	)
		throw new Error('Invalid wallet funding witness stacks');
	return encodeTxSignaturesMessage({
		channelId: Buffer.from(candidate.channelId, 'hex'),
		txid: tx.getHash(),
		witnesses
	});
}

function fundingTranscript(
	nonceKey: Buffer,
	state: IFinalOpeningNonces,
	peer?: Buffer
): string {
	const signing = state.signing;
	requireCommitments(signing);
	const evidence = state.session?.assetEvidence;
	return sha256(
		Buffer.from(
			JSON.stringify([
				nonceKey.toString('hex'),
				signing.outgoing,
				signing.peer,
				signing.exit,
				...(evidence
					? [sha256(Buffer.from(JSON.stringify(evidence))).toString('hex')]
					: []),
				peer ? peer.toString('hex') : null
			])
		)
	).toString('hex');
}

function reserveOpeningInputs(
	id: string,
	exit: string,
	tx: Transaction,
	local: number[],
	authority: FinalOpeningAuthority,
	transcript: string
): void {
	authority.requireEnforceableExit(id, exit);
	authority.bindFundingInputs(
		local.map((i) => {
			const input = tx.ins[i];
			return (
				Buffer.from(input.hash).reverse().toString('hex') + ':' + input.index
			);
		}),
		transcript
	);
}

/** Reserve the asset exit and pledge each input before the host gets a signing request. */
export function prepareAssetWitnessRelease(
	candidate: IFinalOpeningCandidate,
	state: IFinalOpeningNonces,
	nonceKey: Buffer,
	authority: FinalOpeningAuthority
) {
	if (!state.session?.assetEvidence)
		throw new Error('Missing asset opening proof material');
	requireCommitments(state.signing);
	const inputs = finalFundingInputs(candidate);
	const transcript = fundingTranscript(nonceKey, state);
	reserveOpeningInputs(
		candidate.channelId,
		state.signing.exit,
		inputs.tx,
		inputs.local,
		authority,
		transcript
	);
	authority.claim(
		'funding-witness/fundingLocal/' + candidate.channelId,
		transcript
	);
	return inputs;
}
