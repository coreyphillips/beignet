import { Transaction } from 'bitcoinjs-lib';
import { isAssetOpeningType } from '../features/asset-opening';
import { createTaprootFundingScript } from '../script/funding-taproot';
import { decodeTlvStream } from '../message/tlv';
import type { IFinalFundingReference } from '../channel/final-splice-candidate';
import type { IFinalCommitmentView } from '../channel/final-opening-commitment';
import {
	aggregateCommitmentSig,
	partialSignCommitment,
	startCommitmentSigningSession,
	verifyPartialCommitmentSig
} from '../channel/commitment-musig';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { generateNonce } from '../crypto/musig';
import { hmacSha256, sha256 } from '../crypto/provider';
import { derivePrivateKey } from '../keys/derivation';
import type { IChannelKeys } from '../keys/wallet-keys';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../message/channel-commitment';
import {
	signTaprootHtlcLeaf,
	verifyTaprootHtlcLeaf
} from '../script/htlc-taproot';
import { ecc } from '../../utils/ecc';
import type { FinalOpeningAuthority } from './final-opening-authority';
import type { IFinalOpeningCandidate } from './final-opening-candidate';
import { readyVerificationNonce } from './final-opening-ready';

export class FinalUpdateProtocolError extends Error {}

export interface IFinalUpdateNonce {
	pub: string;
	/** Only local reservations have derivation coordinates. */
	source?: 'ready' | 'reconnect' | 'revocation' | 'splice' | 'update-reconnect';
	generation?: number;
}

export function updateVerificationNonce(
	context: Buffer,
	key: Buffer,
	height: number,
	reservation: IFinalUpdateNonce
): Uint8Array {
	if (reservation.source === 'ready' || reservation.source === 'reconnect') {
		if (
			reservation.generation === undefined ||
			!Number.isSafeInteger(reservation.generation) ||
			reservation.generation < 0
		)
			throw new Error('Invalid device readiness generation');
		return readyVerificationNonce(context, key, reservation.generation);
	}
	const reconnect = reservation.source === 'update-reconnect';
	if (
		reconnect &&
		(!Number.isSafeInteger(reservation.generation) ||
			reservation.generation! < 1)
	)
		throw new Error('Invalid commitment reconnect generation');
	if (
		!reconnect &&
		reservation.source !== 'revocation' &&
		reservation.source !== 'splice'
	)
		throw new Error('Missing local commitment verification reservation');
	return generateNonce({
		publicKey: getPublicKey(key),
		secretKey: key,
		sessionId: hmacSha256(
			context,
			Buffer.from(
				reconnect
					? 'final-update-reconnect/' + reservation.generation
					: 'final-update-revoke/' + height
			)
		),
		extraInput: Buffer.from('beignet-final-update-verification-v1')
	});
}

export function spliceCommitmentNonceContext(
	id: string,
	fundingTxid: Buffer,
	outputIndex: number
): Buffer {
	if (
		!/^[a-f0-9]{64}$/.test(id) ||
		!Buffer.isBuffer(fundingTxid) ||
		fundingTxid.length !== 32 ||
		!Number.isSafeInteger(outputIndex) ||
		outputIndex < 0 ||
		outputIndex > 0xffffffff
	)
		throw new Error('Invalid splice commitment nonce context');
	const index = Buffer.alloc(4);
	index.writeUInt32BE(outputIndex);
	return sha256(
		Buffer.concat([
			Buffer.from('beignet-final-splice-commitment-v1'),
			Buffer.from(id, 'hex'),
			fundingTxid,
			index
		])
	);
}

export function checkUpdateNonce(nonce: Buffer): void {
	if (
		!Buffer.isBuffer(nonce) ||
		nonce.length !== 66 ||
		!isValidPublicKey(nonce.subarray(0, 33)) ||
		!isValidPublicKey(nonce.subarray(33))
	)
		throw new FinalUpdateProtocolError('Invalid final commitment nonce');
}

/** Sign the peer transaction or aggregate its share into our verified enforceable exit.
 * The participant that advertised the verification nonce never signs a different
 * message with that nonce. Retransmission to a new peer nonce uses a new signing handle.
 */
export function signFinalUpdate(
	candidate: IFinalOpeningCandidate,
	view: IFinalCommitmentView,
	point: Buffer,
	height: number,
	reservation: IFinalUpdateNonce,
	keys: IChannelKeys,
	authority: FinalOpeningAuthority,
	nonceKey: Buffer,
	updates: string[],
	peerPayload?: Buffer,
	spliceFunding?: {
		reference: IFinalFundingReference;
		privateKey: Buffer;
		asset?: { fundingRoot: Buffer; transcriptDigest: Buffer };
	}
): Buffer {
	const receiving = peerPayload !== undefined;
	const tx = view.tx;
	const ref = spliceFunding?.reference ?? candidate;
	const localFundingKey = spliceFunding?.privateKey ?? keys.fundingPrivkey;
	const funding = Transaction.fromHex(ref.fundingTxHex);
	const prevout = funding.outs[ref.fundingOutputIndex];
	const asset = spliceFunding?.asset;
	if (isAssetOpeningType(candidate.channelType) !== (asset !== undefined))
		throw new Error(
			'Asset commitment signing requires its funding root and transcript'
		);
	if (
		asset &&
		(!Buffer.isBuffer(asset.fundingRoot) ||
			asset.fundingRoot.length !== 32 ||
			!Buffer.isBuffer(asset.transcriptDigest) ||
			asset.transcriptDigest.length !== 32 ||
			!nonceKey.equals(
				spliceCommitmentNonceContext(
					candidate.channelId,
					funding.getHash(),
					ref.fundingOutputIndex
				)
			) ||
			!prevout ||
			!prevout.script.equals(
				createTaprootFundingScript(
					Buffer.from(ref.localFundingPubkey, 'hex'),
					Buffer.from(ref.remoteFundingPubkey, 'hex'),
					undefined,
					asset.fundingRoot
				).p2trOutput
			))
	)
		throw new Error(
			'Asset commitment funding script, nonce context or transcript mismatch'
		);
	if (
		getPublicKey(localFundingKey).toString('hex') !== ref.localFundingPubkey ||
		tx.ins.length !== 1 ||
		!tx.ins[0].hash.equals(funding.getHash()) ||
		tx.ins[0].index !== ref.fundingOutputIndex
	)
		throw new Error(
			'Commitment signing key or funding outpoint disagrees with view'
		);
	const digest = tx.hashForWitnessV1(
		0,
		[prevout.script],
		[prevout.value],
		Transaction.SIGHASH_DEFAULT
	);
	const holderKey = Buffer.from(
		receiving ? ref.localFundingPubkey : ref.remoteFundingPubkey,
		'hex'
	);
	const signerKey = Buffer.from(
		receiving ? ref.remoteFundingPubkey : ref.localFundingPubkey,
		'hex'
	);
	const promised = Buffer.from(reservation.pub, 'hex');
	checkUpdateNonce(promised);
	const contract = sha256(
		Buffer.from(
			JSON.stringify([
				candidate.channelId,
				receiving ? 'local' : 'peer',
				height,
				funding.getId(),
				point.toString('hex'),
				digest.toString('hex'),
				updates,
				view.htlcs.map((h) => h.digest.toString('hex')),
				...(asset
					? [
							'asset-splice-v1',
							asset.fundingRoot.toString('hex'),
							asset.transcriptDigest.toString('hex')
					  ]
					: [])
			])
		)
	);
	const challenge = sha256(
		Buffer.concat([contract, promised, peerPayload ?? Buffer.alloc(0)])
	);
	const context = authority.nonceContext(nonceKey);
	const handle = receiving
		? updateVerificationNonce(context, localFundingKey, height, reservation)
		: generateNonce({
				publicKey: signerKey,
				secretKey: localFundingKey,
				sessionId: hmacSha256(context, challenge),
				msg: digest,
				extraInput: Buffer.from('beignet-final-update-signing-v1')
		  });
	let signerNonce: Buffer;
	let wire: ReturnType<typeof decodeCommitmentSignedMessage> | undefined;
	if (receiving) {
		if (!Buffer.from(handle).equals(promised))
			throw new Error('Device nonce differs from persisted promise');
		try {
			wire = decodeCommitmentSignedMessage(peerPayload);
			const fields = decodeTlvStream(
				peerPayload,
				98 + wire.htlcSignatures.length * 64,
				new Set([1n, 2n])
			).records;
			if (fields.some((f) => f.type === 1n && f.value.length !== 32))
				throw new Error('Invalid funding_txid');
		} catch {
			throw new FinalUpdateProtocolError('Malformed final commitment_signed');
		}
		const partial = wire.partialSignatureWithNonce;
		if (
			!partial ||
			!wire.signature.equals(Buffer.alloc(64)) ||
			wire.channelId.toString('hex') !== candidate.channelId ||
			(asset && !wire.fundingTxid) ||
			(wire.fundingTxid !== undefined &&
				!wire.fundingTxid.equals(funding.getHash())) ||
			wire.htlcSignatures.length !== view.htlcs.length
		)
			throw new FinalUpdateProtocolError(
				'Incorrect final commitment_signed fields'
			);
		signerNonce = partial.subarray(32);
		if (
			view.htlcs.some(
				(h, i) =>
					!verifyTaprootHtlcLeaf(
						h.digest,
						view.keys.remoteHtlcPubkey,
						wire!.htlcSignatures[i]
					)
			)
		)
			throw new FinalUpdateProtocolError(
				'Invalid final commitment HTLC signature'
			);
	} else signerNonce = Buffer.from(handle);
	checkUpdateNonce(signerNonce);
	if (signerNonce.equals(promised))
		throw new FinalUpdateProtocolError(
			'Commitment signer reused the verification nonce'
		);
	const session = startCommitmentSigningSession(
		digest,
		holderKey,
		signerKey,
		promised,
		signerNonce,
		asset?.fundingRoot
	);
	const partial = wire?.partialSignatureWithNonce?.subarray(0, 32);
	if (
		partial &&
		!verifyPartialCommitmentSig(session, partial, signerKey, signerNonce)
	)
		throw new FinalUpdateProtocolError(
			'Invalid final peer commitment partial signature'
		);
	authority.claim(
		'update-contract/' +
			candidate.channelId +
			'/' +
			funding.getId() +
			'/' +
			ref.fundingOutputIndex +
			'/' +
			(receiving ? 'local' : 'peer') +
			'/' +
			height,
		contract.toString('hex')
	);
	const slot = 'commitment/nonce/' + Buffer.from(handle).toString('hex');
	const cached = authority.claim(slot, challenge.toString('hex'));
	if (cached) return cached;
	const share = partialSignCommitment(session, localFundingKey, handle);
	let raw: Buffer;
	if (partial) {
		const aggregate = aggregateCommitmentSig(session, share, partial);
		if (!ecc.verifySchnorr(digest, prevout.script.subarray(2), aggregate))
			throw new Error('Invalid complete local update commitment');
		tx.setWitness(0, [aggregate]);
		raw = tx.toBuffer();
	} else {
		const htlcKey = derivePrivateKey(
			keys.htlcBasepointSecret,
			point,
			keys.channelBasepoints.htlcBasepoint
		);
		raw = encodeCommitmentSignedMessage({
			channelId: Buffer.from(candidate.channelId, 'hex'),
			signature: Buffer.alloc(64),
			htlcSignatures: view.htlcs.map((h) =>
				signTaprootHtlcLeaf(h.digest, htlcKey)
			),
			fundingTxid: funding.getHash(),
			partialSignatureWithNonce: Buffer.concat([share, signerNonce])
		});
	}
	return authority.finish(slot, challenge.toString('hex'), raw);
}
