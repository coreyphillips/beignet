import type { Transaction } from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import {
	createTaprootFundingScript,
	taprootKeySpendSighash
} from '../script/funding-taproot';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { generateNonce } from '../crypto/musig';
import { sha256 } from '../crypto/provider';
import { validateFundingWitness } from '../interactive-tx/funding-witness';
import {
	decodeTxSignaturesMessage,
	encodeTxSignaturesMessage
} from '../message/interactive-tx';
import { validateFinalSpliceExits } from './final-splice-exits';
import {
	loadAssetSpliceExitProofs,
	recordAssetSpliceFundingPhase,
	type IAssetSpliceReleaseContext
} from '../storage/asset-splice-exit-proofs';
import type { FinalOpeningAuthority } from '../storage/final-opening-authority';
import type { FinalFundingWitnessSigner } from '../storage/final-opening-funding';
import {
	aggregateCommitmentSig,
	partialSignCommitment,
	startCommitmentSigningSession,
	verifyPartialCommitmentSig
} from './commitment-musig';
import type {
	IFinalSpliceCandidate,
	IFinalSpliceTerms
} from './final-splice-candidate';
import { finalSpliceFeeError } from './final-splice-candidate';
import { MAX_STANDARD_TX_WEIGHT } from '../interactive-tx/validation';

function nonceHandle(
	c: IFinalSpliceCandidate,
	key: Buffer,
	authority: FinalOpeningAuthority
): Uint8Array {
	const pub = getPublicKey(key);
	return generateNonce({
		publicKey: pub,
		secretKey: key,
		msg: c.digest,
		sessionId: authority.nonceContext(
			sha256(
				Buffer.concat([
					Buffer.from('final-splice/shared-input/v1'),
					pub,
					c.digest
				])
			)
		),
		extraInput: Buffer.from('beignet-splice-shared-input')
	});
}

export function finalSpliceSharedNonce(
	c: IFinalSpliceCandidate,
	key: Buffer,
	authority: FinalOpeningAuthority
): Buffer {
	return Buffer.from(nonceHandle(c, key, authority));
}

export function verifyFinalSpliceContribution(
	c: IFinalSpliceCandidate,
	terms: IFinalSpliceTerms,
	id: Buffer,
	wire: Buffer,
	own: boolean,
	localNonce: Buffer,
	peerNonce: Buffer
): { witnesses: Buffer[][]; share: Buffer } {
	const msg = decodeTxSignaturesMessage(wire, { taproot: true });
	const data = msg.sharedInputPartialSignatureWithNonce;
	const nonce = own ? localNonce : peerNonce;
	const indices = own ? c.localInputs : c.peerInputs;
	if (
		!data ||
		data.length !== 98 ||
		!data.subarray(32).equals(nonce) ||
		msg.sharedInputSignature ||
		!msg.channelId.equals(id) ||
		!msg.txid.equals(c.tx.getHash()) ||
		msg.witnesses.length !== indices.length ||
		!encodeTxSignaturesMessage(msg).equals(wire)
	)
		throw new Error('Invalid final splice funding witnesses');
	const session = startCommitmentSigningSession(
		c.digest,
		terms.oldLocalKey,
		terms.oldPeerKey,
		localNonce,
		peerNonce,
		terms.assetFundingRoots?.parent
	);
	const share = data.subarray(0, 32);
	if (
		!verifyPartialCommitmentSig(
			session,
			share,
			own ? terms.oldLocalKey : terms.oldPeerKey,
			nonce
		)
	)
		throw new Error('Invalid shared input partial signature');
	const prevouts = { scripts: c.scripts, values: c.values.map(BigInt) };
	for (const [pos, index] of indices.entries()) {
		const stack = msg.witnesses[pos];
		if (
			!stack.length ||
			stack.length > 2 ||
			stack.some((item) => item.length > 73)
		)
			throw new Error('Invalid splice wallet witness');
		const error = validateFundingWitness(c.tx, index, stack, prevouts);
		if (error) throw new Error(error);
	}
	return { witnesses: msg.witnesses, share };
}

/** Reserve the local verification nonce before producing either a wallet witness or the shared partial. */
export function signFinalSpliceFunding(
	c: IFinalSpliceCandidate,
	terms: IFinalSpliceTerms,
	id: Buffer,
	key: Buffer,
	localNonce: Buffer,
	peerNonce: Buffer,
	authority: FinalOpeningAuthority,
	exits: Parameters<typeof validateFinalSpliceExits>[0],
	signWallet: FinalFundingWitnessSigner,
	proofContext?: IAssetSpliceReleaseContext
): Buffer {
	const handle = nonceHandle(c, key, authority);
	if (
		!getPublicKey(key).equals(terms.oldLocalKey) ||
		!Buffer.from(handle).equals(localNonce) ||
		peerNonce.length !== 66 ||
		!isValidPublicKey(peerNonce.subarray(0, 33)) ||
		!isValidPublicKey(peerNonce.subarray(33)) ||
		localNonce.equals(peerNonce)
	)
		throw new Error('Unverified shared funding nonce or key');
	// Verify the supplied terms again at the one-use signer boundary.
	const parent = terms.parent.outs[terms.parentIndex];
	const shared = c.tx.ins[c.sharedIndex];
	const roots = terms.assetFundingRoots;
	if (
		!parent ||
		!shared ||
		!shared.hash.equals(terms.parent.getHash()) ||
		shared.index !== terms.parentIndex ||
		c.values[c.sharedIndex] !== parent.value ||
		!c.scripts[c.sharedIndex]?.equals(parent.script) ||
		(roots !== undefined &&
			(!Buffer.isBuffer(roots?.parent) ||
				roots.parent.length !== 32 ||
				!Buffer.isBuffer(roots.candidate) ||
				roots.candidate.length !== 32)) ||
		!createTaprootFundingScript(
			terms.oldLocalKey,
			terms.oldPeerKey,
			undefined,
			roots?.parent
		).p2trOutput.equals(parent.script) ||
		!createTaprootFundingScript(
			terms.newLocalKey,
			terms.newPeerKey,
			undefined,
			roots?.candidate
		).p2trOutput.equals(c.tx.outs[c.fundingIndex].script) ||
		!taprootKeySpendSighash(c.tx, c.sharedIndex, c.scripts, c.values).equals(
			c.digest
		)
	)
		throw new Error(
			'Splice keys, roots or digest disagree with the funding transaction'
		);
	validateFinalSpliceExits(exits, c, terms);
	if (Boolean(proofContext) !== Boolean(roots))
		throw new Error('Asset funding requires retained proof-backed exits');
	let receipt: ReturnType<typeof loadAssetSpliceExitProofs> | undefined;
	let evidenceHash: Buffer | undefined;
	if (proofContext && roots) {
		const { store, finalDigest, stateNumber, parentRemote, candidateRemote } =
			proofContext;
		store.assertAssetSpliceAuthority(authority);
		if (authority.exitRequest(id.toString('hex')))
			throw new Error('Cannot release asset funding after a unilateral close');
		receipt = loadAssetSpliceExitProofs(
			store,
			id.toString('hex'),
			finalDigest.toString('hex')
		);
		if (String(stateNumber) !== receipt.stateNumber)
			throw new Error('Asset proof state differs from commitment state');
		for (const [name, funding, index, remote] of [
			['parent', terms.parent, terms.parentIndex, parentRemote],
			['candidate', c.tx, c.fundingIndex, candidateRemote]
		] as const) {
			const saved = receipt[name];
			if (
				saved.fundingTxid !== funding.getId() ||
				saved.outputIndex !== index ||
				saved.fundingRoot !== roots[name].toString('hex') ||
				saved.localCommitment !== exits[name].signed.toHex() ||
				saved.remoteCommitment !== remote.toHex()
			)
				throw new Error(
					'Asset funding disagrees with retained commitment or proof generation'
				);
		}
		evidenceHash = recordAssetSpliceFundingPhase(store, receipt);
	}
	const txid = c.tx.getId();
	const retained = sha256(exits.candidate.signed.toBuffer()).toString('hex');
	authority.claim(
		'splice/enforceable-exit/' + id.toString('hex') + '/' + txid,
		retained
	);
	const slot = 'splice/shared-nonce/' + localNonce.toString('hex');
	const transcript = sha256(
		Buffer.concat([
			id,
			c.digest,
			localNonce,
			peerNonce,
			Buffer.from(retained, 'hex'),
			...(roots
				? [
						terms.oldLocalKey,
						terms.oldPeerKey,
						roots.parent,
						roots.candidate,
						evidenceHash!
				  ]
				: [])
		])
	).toString('hex');
	let signed = authority.claim(slot, transcript);
	if (!signed) {
		const family = sha256(
			Buffer.concat([
				Buffer.from('final-splice-wallet/'),
				id,
				terms.parent.getHash(),
				c.tx.ins[c.sharedIndex].hash,
				Buffer.from(String(terms.parentIndex))
			])
		).toString('hex');
		authority.bindFundingInputs(
			c.localInputs.map(
				(i) =>
					Buffer.from(c.tx.ins[i].hash).reverse().toString('hex') +
					':' +
					c.tx.ins[i].index
			),
			family
		);
		const witnesses = c.localInputs.length
			? signWallet(c.tx.clone(), c.localInputs, {
					scripts: c.scripts.map((v) => Buffer.from(v)),
					values: c.values.map(BigInt)
			  })
			: [];
		const session = startCommitmentSigningSession(
			c.digest,
			terms.oldLocalKey,
			terms.oldPeerKey,
			handle,
			peerNonce,
			terms.assetFundingRoots?.parent
		);
		const partial = partialSignCommitment(session, key, handle);
		signed = encodeTxSignaturesMessage({
			channelId: id,
			txid: c.tx.getHash(),
			witnesses,
			sharedInputPartialSignatureWithNonce: Buffer.concat([partial, localNonce])
		});
	}
	verifyFinalSpliceContribution(
		c,
		terms,
		id,
		signed,
		true,
		localNonce,
		peerNonce
	);
	const packet = authority.finish(slot, transcript, signed);
	if (proofContext && receipt) {
		if (authority.exitRequest(id.toString('hex')))
			throw new Error('Channel closed while authorizing asset funding');
		recordAssetSpliceFundingPhase(proofContext.store, receipt, packet);
	}
	return packet;
}

export function assembleFinalSplice(
	c: IFinalSpliceCandidate,
	terms: IFinalSpliceTerms,
	id: Buffer,
	localNonce: Buffer,
	peerNonce: Buffer,
	ours: Buffer,
	theirs: Buffer
): Transaction {
	const a = verifyFinalSpliceContribution(
		c,
		terms,
		id,
		ours,
		true,
		localNonce,
		peerNonce
	);
	const b = verifyFinalSpliceContribution(
		c,
		terms,
		id,
		theirs,
		false,
		localNonce,
		peerNonce
	);
	const session = startCommitmentSigningSession(
		c.digest,
		terms.oldLocalKey,
		terms.oldPeerKey,
		localNonce,
		peerNonce,
		terms.assetFundingRoots?.parent
	);
	const aggregate = aggregateCommitmentSig(session, a.share, b.share);
	if (
		!ecc.verifySchnorr(
			c.digest,
			c.scripts[c.sharedIndex].subarray(2),
			aggregate
		)
	)
		throw new Error('Invalid shared funding signature');
	const tx = c.tx.clone();
	tx.setWitness(c.sharedIndex, [aggregate]);
	for (const [indices, witnesses] of [
		[c.localInputs, a.witnesses],
		[c.peerInputs, b.witnesses]
	] as const)
		for (const [pos, index] of indices.entries())
			tx.setWitness(index, witnesses[pos]);
	const fee =
		c.values.reduce((sum, v) => sum + BigInt(v), 0n) -
		tx.outs.reduce((sum, v) => sum + BigInt(v.value), 0n);
	if (
		tx.weight() > MAX_STANDARD_TX_WEIGHT ||
		finalSpliceFeeError(fee, tx.weight(), terms, tx.ins.length === 1)
	)
		throw new Error('Insufficient fee for signed splice');
	return tx;
}
