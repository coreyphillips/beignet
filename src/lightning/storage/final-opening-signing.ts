import type { BIP32Interface } from 'bip32';
import { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import {
	buildFinalOpeningCommitment,
	type IFinalOpeningTerms
} from '../channel/final-opening-commitment';
import {
	aggregateCommitmentSig,
	partialSignCommitment,
	startCommitmentSigningSession,
	verifyPartialCommitmentSig
} from '../channel/commitment-musig';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { generateNonce, type SessionKey } from '../crypto/musig';
import { hmacSha256, sha256 } from '../crypto/provider';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../message/channel-commitment';
import { decodeTxCompleteMessage } from '../message/interactive-tx';
import type { FinalOpeningAuthority } from './final-opening-authority';
import type { IFinalOpeningCandidate } from './final-opening-candidate';
import {
	openingVerificationNonce,
	type IFinalOpeningNonces
} from './final-opening-nonces';

export interface IFinalOpeningSigning {
	terms: IFinalOpeningTerms;
	channelKeyIndex: number;
	outgoing?: string;
	peer?: string;
	exit?: string;
}

const WIRE_BYTES = 98 + 34 + 100;

function assertIndex(index: number): void {
	if (!Number.isSafeInteger(index) || index < 0 || index > 0x7fffffff)
		throw new Error('Invalid opening channel key index');
}

function canonicalTerms(terms: IFinalOpeningTerms): string {
	const fields = [
		...Object.keys(terms),
		...Object.keys(terms.localBasepoints),
		...Object.keys(terms.remoteBasepoints)
	].sort();
	return JSON.stringify(terms, fields);
}

function fundingSecret(
	root: BIP32Interface,
	identity: string,
	index: number,
	terms: IFinalOpeningTerms
): Buffer {
	assertIndex(index);
	const [, nodeId, network] = JSON.parse(identity);
	const coinType = network === 'mainnet' ? 0 : 1;
	if (
		deriveLightningKeys(root, coinType).nodePublicKey.toString('hex') !== nodeId
	)
		throw new Error('Opening signer does not match the enrolled wallet');
	const keys = deriveChannelKeys(root, coinType, index);
	const points = keys.channelBasepoints;
	points.firstPerCommitmentPoint = getPublicKey(
		generateFromSeed(keys.perCommitmentSeed, MAX_INDEX)
	);
	for (const name of Object.keys(points) as (keyof typeof points)[]) {
		if (points[name].toString('hex') !== terms.localBasepoints[name])
			throw new Error(
				'Opening keys do not match the negotiated local basepoints'
			);
	}
	return keys.fundingPrivkey;
}

function noncePair(payload?: string): { current: Buffer; next: Buffer } {
	if (!payload)
		throw new Error('Both opening tx_complete payloads are required');
	const pair = decodeTxCompleteMessage(Buffer.from(payload, 'hex'), {
		taproot: true
	}).commitNonces;
	if (!pair) throw new Error('Missing opening verification nonces');
	return pair;
}

interface CommitmentView {
	tx: Transaction;
	script: Buffer;
	fundingTxid: Buffer;
	channelId: Buffer;
	digest: Buffer;
	holderNonce: Buffer;
	holderKey: Buffer;
	signerKey: Buffer;
	promises: Buffer[];
}

function commitmentView(
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	nonces: IFinalOpeningNonces,
	owner: 'local' | 'remote'
): CommitmentView {
	const tx = buildFinalOpeningCommitment(candidate, terms, owner);
	const funding = Transaction.fromHex(candidate.fundingTxHex);
	const { script, value } = funding.outs[candidate.fundingOutputIndex];
	const local = noncePair(nonces.local?.payload);
	const remote = noncePair(nonces.peer);
	const promises = [local.current, local.next, remote.current, remote.next];
	if (new Set(promises.map((n) => n.toString('hex'))).size !== promises.length)
		throw new Error('Overlapping opening verification nonce promises');
	return {
		tx,
		script,
		fundingTxid: funding.getHash(),
		channelId: Buffer.from(candidate.channelId, 'hex'),
		digest: tx.hashForWitnessV1(
			0,
			[script],
			[value],
			Transaction.SIGHASH_DEFAULT
		),
		holderNonce: owner === 'local' ? local.current : remote.current,
		holderKey: Buffer.from(
			owner === 'local'
				? candidate.localFundingPubkey
				: candidate.remoteFundingPubkey,
			'hex'
		),
		signerKey: Buffer.from(
			owner === 'local'
				? candidate.remoteFundingPubkey
				: candidate.localFundingPubkey,
			'hex'
		),
		promises
	};
}

function parseShare(
	view: CommitmentView,
	payload: Buffer
): { session: SessionKey; share: Buffer } {
	if (!Buffer.isBuffer(payload) || payload.length !== WIRE_BYTES)
		throw new Error('Invalid opening commitment_signed length');
	const wire = decodeCommitmentSignedMessage(payload);
	const data = wire.partialSignatureWithNonce;
	if (
		!data ||
		!wire.channelId.equals(view.channelId) ||
		!wire.fundingTxid?.equals(view.fundingTxid) ||
		!wire.signature.equals(Buffer.alloc(64)) ||
		wire.htlcSignatures.length ||
		!encodeCommitmentSignedMessage(wire).equals(payload)
	)
		throw new Error('Invalid opening commitment_signed');
	const share = data.subarray(0, 32);
	const nonce = data.subarray(32);
	if (
		!isValidPublicKey(nonce.subarray(0, 33)) ||
		!isValidPublicKey(nonce.subarray(33)) ||
		view.promises.some((promised) => nonce.equals(promised))
	)
		throw new Error('Invalid opening signing nonce');
	const session = startCommitmentSigningSession(
		view.digest,
		view.holderKey,
		view.signerKey,
		view.holderNonce,
		nonce
	);
	if (!verifyPartialCommitmentSig(session, share, view.signerKey, nonce))
		throw new Error('Incorrect opening commitment partial signature');
	return { session, share };
}

function verifyExit(view: CommitmentView, raw: Buffer): void {
	const witness = Transaction.fromBuffer(raw).ins[0]?.witness;
	if (
		!witness ||
		witness.length !== 1 ||
		witness[0].length !== 64 ||
		!ecc.verifySchnorr(view.digest, view.script.subarray(2), witness[0])
	)
		throw new Error('Invalid opening commitment funding signature');
	const expected = view.tx.clone();
	expected.setWitness(0, witness);
	if (!expected.toBuffer().equals(raw))
		throw new Error(
			'Signed opening exit differs from the negotiated local commitment'
		);
}

function storedBytes(hex: string, maxBytes: number): Buffer {
	if (
		typeof hex !== 'string' ||
		hex.length > maxBytes * 2 ||
		!/^(?:[0-9a-f]{2})+$/.test(hex)
	)
		throw new Error('Invalid stored opening signature encoding');
	return Buffer.from(hex, 'hex');
}

export function verifyOpeningSigning(
	candidate: IFinalOpeningCandidate,
	state: IFinalOpeningNonces,
	storedIndex: number | null
): void {
	const signing = state.signing;
	if (signing === undefined) return;
	if (
		!signing ||
		Object.keys(signing).some(
			(k) =>
				!['terms', 'channelKeyIndex', 'outgoing', 'peer', 'exit'].includes(k)
		) ||
		signing.channelKeyIndex !== storedIndex ||
		(!signing.outgoing && !signing.exit) ||
		(signing.peer === undefined) !== (signing.exit === undefined)
	)
		throw new Error('Incomplete opening signing record');
	assertIndex(signing.channelKeyIndex);
	if (signing.outgoing !== undefined) {
		if (!candidate.inputs.some((i) => i.isLocal) && signing.exit === undefined)
			throw new Error('Missing local exit for a zero-input signer');
		parseShare(
			commitmentView(candidate, signing.terms, state, 'remote'),
			storedBytes(signing.outgoing, WIRE_BYTES)
		);
	}
	if (signing.peer !== undefined && signing.exit !== undefined) {
		const local = commitmentView(candidate, signing.terms, state, 'local');
		parseShare(local, storedBytes(signing.peer, WIRE_BYTES));
		// A one-input key spend adds two marker bytes, two length bytes and a 64-byte signature.
		verifyExit(local, storedBytes(signing.exit, local.tx.byteLength() + 68));
	}
}

/** Both recipient commitments must be viable before the wallet signs either one. */
export function signOpening(
	candidate: IFinalOpeningCandidate,
	state: IFinalOpeningNonces,
	nonceKey: Buffer,
	terms: IFinalOpeningTerms,
	root: BIP32Interface,
	index: number,
	identity: string,
	authority: FinalOpeningAuthority | null,
	peerPayload?: Buffer
): Buffer {
	const receiving = peerPayload !== undefined;
	if (
		receiving &&
		(!Buffer.isBuffer(peerPayload) || peerPayload.length !== WIRE_BYTES)
	)
		throw new Error('Invalid opening commitment_signed length');
	const local = commitmentView(candidate, terms, state, 'local');
	const remote = commitmentView(candidate, terms, state, 'remote');
	const key = fundingSecret(root, identity, index, terms);
	const normalized = canonicalTerms(terms);
	const signing = state.signing ?? {
		terms: JSON.parse(normalized) as IFinalOpeningTerms,
		channelKeyIndex: index
	};
	if (
		signing.channelKeyIndex !== index ||
		canonicalTerms(signing.terms) !== normalized
	)
		throw new Error('Opening commitment terms or key index changed');
	if (
		receiving &&
		signing.peer !== undefined &&
		signing.peer !== peerPayload.toString('hex')
	)
		throw new Error('Peer changed the opening commitment_signed');
	const previous = receiving ? signing.exit : signing.outgoing;
	if (previous !== undefined) return Buffer.from(previous, 'hex');
	if (!receiving && !candidate.inputs.some((i) => i.isLocal) && !signing.exit)
		throw new Error('A zero-input signer requires its signed local exit first');
	if (!authority)
		throw new Error(
			'New opening signatures require the original wallet device'
		);
	const contract = sha256(
		Buffer.from(
			JSON.stringify([
				nonceKey.toString('hex'),
				index,
				normalized,
				state.local!.payload,
				state.peer
			])
		)
	).toString('hex');
	const view = receiving ? local : remote;
	const proof = receiving ? parseShare(view, peerPayload) : undefined;
	const transcript = sha256(
		Buffer.concat([
			Buffer.from(contract, 'hex'),
			Buffer.from(receiving ? 'local' : 'remote'),
			view.digest,
			peerPayload ?? Buffer.alloc(0)
		])
	).toString('hex');
	const context = authority.nonceContext(nonceKey);
	const handle = receiving
		? openingVerificationNonce(
				0,
				Buffer.from(state.local!.salt, 'hex'),
				context,
				key
		  )
		: generateNonce({
				publicKey: view.signerKey,
				secretKey: key,
				sessionId: hmacSha256(context, Buffer.from(transcript, 'hex')),
				msg: view.digest,
				extraInput: Buffer.from('beignet-final-opening-signing-v1')
		  });
	const nonce = Buffer.from(handle);
	if (
		receiving
			? !nonce.equals(view.holderNonce)
			: view.promises.some((p) => nonce.equals(p))
	)
		throw new Error('Opening nonce does not match its signing purpose');

	// These reservations commit independently of the wallet. A rolled-back
	// wallet can repeat the same challenge, including its exact peer share.
	authority.claim('commitment/terms/' + candidate.channelId, contract);
	authority.claim('commitment/key/' + index, candidate.channelId);
	const slot = 'commitment/nonce/' + nonce.toString('hex');
	let raw = authority.claim(slot, transcript);
	if (receiving && proof) {
		if (!raw) {
			const ourShare = partialSignCommitment(proof.session, key, handle);
			const signature = aggregateCommitmentSig(
				proof.session,
				ourShare,
				proof.share
			);
			view.tx.setWitness(0, [signature]);
			raw = view.tx.toBuffer();
		}
		verifyExit(view, raw);
		signing.peer = peerPayload.toString('hex');
		signing.exit = raw.toString('hex');
	} else {
		if (!raw) {
			const session = startCommitmentSigningSession(
				view.digest,
				view.holderKey,
				view.signerKey,
				view.holderNonce,
				nonce
			);
			const share = partialSignCommitment(session, key, handle);
			raw = encodeCommitmentSignedMessage({
				channelId: view.channelId,
				signature: Buffer.alloc(64),
				htlcSignatures: [],
				fundingTxid: view.fundingTxid,
				partialSignatureWithNonce: Buffer.concat([share, nonce])
			});
		}
		parseShare(view, raw);
		signing.outgoing = raw.toString('hex');
	}
	authority.finish(slot, transcript, raw);
	state.signing = signing;
	return raw;
}
