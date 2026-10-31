import * as bitcoin from 'bitcoinjs-lib';
import { randomBytes } from '../crypto/provider';
import { ecc } from '../../utils/ecc';
import { taggedHash } from '../crypto/hash';
import { tapleafHash } from '../script/htlc-taproot';
import { encrypt, decrypt } from '../crypto/xchacha20poly1305';
import { breachKeyFromTxid } from './blob';
import type { IChannelState } from '../channel/channel-state';
import { selectFundingEpoch } from '../channel/funding-state';
import { ShaChainStore, MAX_INDEX } from '../keys/shachain';
import { perCommitmentPointFromSecret } from '../keys/derivation';
import { ChannelRole } from '../channel/types';
import { CommitmentType } from '../chain/types';
import {
	classifyCommitmentTx,
	extractCommitmentNumber,
	classifyOutputs,
	resolveRevokedCommitmentOutputs
} from '../chain/output-resolver';

/** Native extension. This is deliberately separate from LND's fixed-size kits. */
export interface IAuxiliaryJusticePackage {
	version: 1;
	channelId: string;
	revokedTransaction: string;
	commitmentNumber: string;
	commitmentData: string;
	sweeps: {
		transaction: string;
		auxiliaryData?: string;
		csvDelay: number;
		/** Fixed asset input/output; a tower may append fee inputs, never outputs. */
		feeSponsorship?: {
			type: 'all-anyonecanpay';
			prevoutScript: string;
			prevoutValue: string;
		};
	}[];
}

export const AUXILIARY_JUSTICE_MAX_BYTES = 16 * 1024 * 1024;
const AAD = Buffer.from('beignet/asset-justice/v1');
const hex = (s: unknown, max: number): s is string =>
	typeof s === 'string' &&
	s.length > 0 &&
	s.length <= max * 2 &&
	s.length % 2 === 0 &&
	/^[0-9a-f]+$/.test(s);

const SPONSOR_HASH_TYPE =
	bitcoin.Transaction.SIGHASH_ALL | bitcoin.Transaction.SIGHASH_ANYONECANPAY;

/** Verify the exact immutable carrier and its BIP341 authorization. */
function validateSponsorTemplate(
	tx: bitcoin.Transaction,
	parent: bitcoin.Transaction,
	metadata: NonNullable<
		IAuxiliaryJusticePackage['sweeps'][number]['feeSponsorship']
	>
): void {
	const previous = parent.outs[tx.ins[0]?.index];
	if (
		metadata.type !== 'all-anyonecanpay' ||
		tx.ins.length !== 1 ||
		tx.outs.length !== 1 ||
		!previous ||
		metadata.prevoutScript !== previous.script.toString('hex') ||
		metadata.prevoutValue !== String(previous.value) ||
		previous.script.length !== 34 ||
		previous.script[0] !== bitcoin.opcodes.OP_1 ||
		previous.script[1] !== 32 ||
		tx.outs[0].script.length !== 34 ||
		tx.outs[0].script[0] !== bitcoin.opcodes.OP_1 ||
		tx.outs[0].script[1] !== 32 ||
		tx.outs[0].value < 330 ||
		tx.ins[0].script.length !== 0
	)
		throw new Error('Invalid asset justice sponsorship descriptor');
	const witness = tx.ins[0].witness;
	const signature = witness[0];
	if (
		!signature ||
		signature.length !== 65 ||
		signature[64] !== SPONSOR_HASH_TYPE
	)
		throw new Error('Asset justice sponsorship requires ALL|ANYONECANPAY');
	let publicKey: Buffer;
	let leafHash: Buffer | undefined;
	if (witness.length === 1) {
		publicKey = previous.script.subarray(2);
	} else if (witness.length === 3) {
		const [, leaf, control] = witness;
		if (
			control.length < 33 ||
			control.length > 33 + 32 * 128 ||
			(control.length - 33) % 32 !== 0 ||
			(control[0] & 0xfe) !== 0xc0
		)
			throw new Error('Invalid sponsored justice control block');
		leafHash = tapleafHash(leaf, control[0] & 0xfe);
		let root = leafHash;
		for (let offset = 33; offset < control.length; offset += 32) {
			const sibling = control.subarray(offset, offset + 32);
			root =
				Buffer.compare(root, sibling) < 0
					? taggedHash('TapBranch', root, sibling)
					: taggedHash('TapBranch', sibling, root);
		}
		const internal = control.subarray(1, 33);
		const tweaked = ecc.xOnlyPointAddTweak(
			internal,
			taggedHash('TapTweak', internal, root)
		);
		if (
			!tweaked ||
			tweaked.parity !== (control[0] & 1) ||
			!Buffer.from(tweaked.xOnlyPubkey).equals(previous.script.subarray(2))
		)
			throw new Error('Sponsored justice leaf does not match its parent');
		const chunks = bitcoin.script.decompile(leaf);
		if (
			chunks?.length === 4 &&
			Buffer.isBuffer(chunks[0]) &&
			chunks[0].length === 32 &&
			chunks[1] === bitcoin.opcodes.OP_DROP &&
			Buffer.isBuffer(chunks[2]) &&
			chunks[2].length === 32 &&
			chunks[3] === bitcoin.opcodes.OP_CHECKSIG
		) {
			publicKey = chunks[2];
		} else if (
			chunks?.length === 5 &&
			Buffer.isBuffer(chunks[0]) &&
			chunks[0].length === 32 &&
			chunks[1] === bitcoin.opcodes.OP_CHECKSIG &&
			chunks[2] === bitcoin.opcodes.OP_1 &&
			chunks[3] === bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY &&
			chunks[4] === bitcoin.opcodes.OP_DROP &&
			tx.version >= 2 &&
			(tx.ins[0].sequence & 0x80400000) === 0 &&
			(tx.ins[0].sequence & 0xffff) >= 1
		) {
			publicKey = chunks[0];
		} else throw new Error('Unsupported sponsored justice leaf');
	} else throw new Error('Invalid sponsored justice witness');
	const digest = tx.hashForWitnessV1(
		0,
		[previous.script],
		[previous.value],
		SPONSOR_HASH_TYPE,
		leafHash
	);
	if (!ecc.verifySchnorr(digest, publicKey, signature.subarray(0, 64)))
		throw new Error('Invalid sponsored justice signature');
}

/** Validate every spend against the breached parent before handing it to a tower. */
export function validateAuxiliaryJusticePackage(
	value: unknown
): IAuxiliaryJusticePackage {
	const p = value as IAuxiliaryJusticePackage;
	if (
		!p ||
		p.version !== 1 ||
		!hex(p.channelId, 32) ||
		p.channelId.length !== 64 ||
		!hex(p.revokedTransaction, 400000) ||
		!hex(p.commitmentData, AUXILIARY_JUSTICE_MAX_BYTES) ||
		typeof p.commitmentNumber !== 'string' ||
		!/^(0|[1-9][0-9]{0,14})$/.test(p.commitmentNumber) ||
		!Array.isArray(p.sweeps) ||
		p.sweeps.length === 0 ||
		p.sweeps.length > 2048
	)
		throw new Error('Invalid auxiliary justice package');
	const parent = bitcoin.Transaction.fromHex(p.revokedTransaction);
	const hash = parent.getHash();
	const seen = new Set<string>();
	for (const sweep of p.sweeps) {
		if (
			!hex(sweep.transaction, 400000) ||
			(sweep.auxiliaryData !== undefined &&
				!hex(sweep.auxiliaryData, AUXILIARY_JUSTICE_MAX_BYTES)) ||
			!Number.isSafeInteger(sweep.csvDelay) ||
			sweep.csvDelay < 0 ||
			sweep.csvDelay > 65535
		)
			throw new Error('Invalid auxiliary justice sweep');
		const tx = bitcoin.Transaction.fromHex(sweep.transaction);
		if (seen.has(tx.getId()) || !tx.ins.length || !tx.outs.length)
			throw new Error('Duplicate or empty auxiliary justice sweep');
		seen.add(tx.getId());
		const inputs = new Set<number>();
		let total = 0;
		for (const input of tx.ins) {
			if (
				!input.hash.equals(hash) ||
				!parent.outs[input.index] ||
				inputs.has(input.index) ||
				!input.witness.length
			)
				throw new Error(
					'Auxiliary justice sweep does not spend its breached parent'
				);
			inputs.add(input.index);
			total += parent.outs[input.index].value;
		}
		if (
			tx.outs.some((o) => !Number.isSafeInteger(o.value) || o.value < 0) ||
			(!sweep.feeSponsorship &&
				tx.outs.reduce((n, o) => n + o.value, 0) >= total)
		)
			throw new Error('Invalid auxiliary justice sweep value');
		if (sweep.feeSponsorship) {
			if (!sweep.auxiliaryData)
				throw new Error('Sponsored justice requires asset provenance');
			validateSponsorTemplate(tx, parent, sweep.feeSponsorship);
		}
	}
	return p;
}

/** Construct aggregate and independent remedies without exporting signing keys. */
export function buildAuxiliaryJusticePackage(options: {
	state: IChannelState;
	revokedTransaction: Buffer;
	destinationScript: Buffer;
	feeRates: readonly number[];
	revocationBasepointSecret: Buffer;
	paymentBasepointSecret: Buffer;
	network: bitcoin.Network;
	/** A cache-authenticated reveal received before the channel applies revoke_and_ack. */
	revealedSecret?: Buffer;
}): IAuxiliaryJusticePackage {
	const parent = bitcoin.Transaction.fromBuffer(options.revokedTransaction);
	if (parent.ins.length !== 1)
		throw new Error('Asset justice parent must have one funding input');
	let state = selectFundingEpoch(
		options.state,
		parent.ins[0].hash,
		parent.ins[0].index
	);
	if (options.revealedSecret) {
		if (!state.remoteBasepoints)
			throw new Error('Asset justice peer keys are missing');
		const opener = state.role === ChannelRole.OPENER;
		const number = extractCommitmentNumber(
			parent,
			(opener ? state.localBasepoints : state.remoteBasepoints)
				.paymentBasepoint,
			(opener ? state.remoteBasepoints : state.localBasepoints).paymentBasepoint
		);
		const previous = state.shaChainStore.getSecret(MAX_INDEX - number);
		const point = perCommitmentPointFromSecret(options.revealedSecret);
		const expected =
			number === BigInt(state.shaChainStore.getKnownCount())
				? state.remoteCurrentPerCommitmentPoint
				: undefined;
		if (
			previous
				? !previous.equals(options.revealedSecret)
				: !expected?.equals(point)
		)
			throw new Error(
				'Asset justice reveal does not match the signed commitment point'
			);
		const store = ShaChainStore.restore(
			state.shaChainStore.getEntries(),
			state.shaChainStore.getKnownCount()
		);
		if (
			!previous &&
			!store.addSecret(MAX_INDEX - number, options.revealedSecret)
		)
			throw new Error('Asset justice reveal conflicts with revocation history');
		state = {
			...state,
			shaChainStore: store,
			remoteCommitmentNumber:
				number >= state.remoteCommitmentNumber
					? number + 1n
					: state.remoteCommitmentNumber
		};
	}
	if (
		!state.auxiliaryState ||
		!state.channelId ||
		!options.feeRates.length ||
		options.feeRates.length > 4 ||
		options.feeRates.some(
			(rate) => !Number.isFinite(rate) || rate <= 0 || rate > 10000
		)
	)
		throw new Error('Invalid asset justice request');
	if (
		parent.ins.length !== 1 ||
		!parent.ins[0].hash.equals(state.fundingTxid!) ||
		parent.ins[0].index !== state.fundingOutputIndex
	)
		throw new Error('Asset justice parent does not spend the channel funding');
	const classified = classifyCommitmentTx(parent, state);
	if (classified.type !== CommitmentType.THEIR_REVOKED_COMMITMENT)
		throw new Error('Asset justice parent is not a revoked remote commitment');
	const view = state.auxiliaryState.remoteCommitments.get(
		classified.commitmentNumber
	);
	if (!view) throw new Error('Missing persisted asset justice commitment');
	const outputs = classifyOutputs(
		parent,
		state,
		classified.type,
		classified.commitmentNumber
	);
	const sweeps = new Map<string, IAuxiliaryJusticePackage['sweeps'][number]>();
	const covered = new Set<number>();
	for (const feeRate of options.feeRates) {
		// Independent remedies still work if a competing HTLC spend defeats the batch.
		for (const selected of [
			undefined,
			...parent.outs.map((_, index) => index)
		]) {
			const excluded =
				selected === undefined
					? undefined
					: new Set(parent.outs.map((_, i) => i).filter((i) => i !== selected));
			const resolved = resolveRevokedCommitmentOutputs(
				state,
				outputs,
				classified.commitmentNumber,
				parent,
				options.destinationScript,
				feeRate,
				options.revocationBasepointSecret,
				options.paymentBasepointSecret,
				options.network,
				undefined,
				excluded
			);
			for (const output of resolved) {
				let tx = output.spendTx;
				if (!tx) continue;
				if (output.witness && tx.ins.length === 1)
					tx.setWitness(0, output.witness);
				let data = output.auxiliaryData ?? output.trackedOutput.auxiliaryData;
				let feeSponsorship: IAuxiliaryJusticePackage['sweeps'][number]['feeSponsorship'];
				if (output.auxiliaryFunding) {
					// Sponsor templates expose one authenticated original input.
					// Independent candidates preserve every asset allocation.
					if (tx.ins.length !== 1 || tx.outs.length !== 1) continue;
					const attachment = output.auxiliaryFunding;
					const signed = attachment.sign(
						tx.toBuffer(),
						attachment.prevoutScripts,
						attachment.prevoutValues,
						SPONSOR_HASH_TYPE as 0x81
					);
					tx = bitcoin.Transaction.fromBuffer(signed.transaction);
					data = signed.auxiliaryData;
					feeSponsorship = {
						type: 'all-anyonecanpay',
						prevoutScript: attachment.prevoutScripts[0].toString('hex'),
						prevoutValue: attachment.prevoutValues[0].toString()
					};
				}
				for (const input of tx.ins) covered.add(input.index);
				sweeps.set(tx.getId(), {
					transaction: tx.toHex(),
					...(data ? { auxiliaryData: data.toString('hex') } : {}),
					csvDelay: output.csvDelay ?? 0,
					...(feeSponsorship ? { feeSponsorship } : {})
				});
			}
		}
	}
	for (const index of view.outputLeaves.keys()) {
		if (!covered.has(index))
			throw new Error(
				`Asset justice output ${index} has no economical signed remedy`
			);
	}
	return validateAuxiliaryJusticePackage({
		version: 1,
		channelId: state.channelId.toString('hex'),
		revokedTransaction: parent.toHex(),
		commitmentNumber: classified.commitmentNumber.toString(),
		commitmentData: view.customData.toString('hex'),
		sweeps: [...sweeps.values()]
	});
}

export function encryptAuxiliaryJusticePackage(
	value: IAuxiliaryJusticePackage
): Buffer {
	const p = validateAuxiliaryJusticePackage(value);
	const bytes = Buffer.from(JSON.stringify(p));
	if (bytes.length > AUXILIARY_JUSTICE_MAX_BYTES)
		throw new Error('Asset justice package is too large');
	const nonce = randomBytes(24);
	const key = breachKeyFromTxid(
		bitcoin.Transaction.fromHex(p.revokedTransaction).getHash()
	);
	return Buffer.concat([nonce, encrypt(key, nonce, bytes, AAD)]);
}

export function decryptAuxiliaryJusticePackage(
	blob: Buffer,
	parent: bitcoin.Transaction
): IAuxiliaryJusticePackage {
	if (blob.length < 40 || blob.length > AUXILIARY_JUSTICE_MAX_BYTES + 40)
		throw new Error('Invalid asset justice ciphertext');
	const bytes = decrypt(
		breachKeyFromTxid(parent.getHash()),
		blob.subarray(0, 24),
		blob.subarray(24),
		AAD
	);
	const p = validateAuxiliaryJusticePackage(JSON.parse(bytes.toString('utf8')));
	if (
		bitcoin.Transaction.fromHex(p.revokedTransaction).getId() !== parent.getId()
	)
		throw new Error('Asset justice breach identity differs');
	return p;
}
