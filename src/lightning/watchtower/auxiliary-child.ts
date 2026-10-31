import * as bitcoin from 'bitcoinjs-lib';
import { ecc } from '../../utils/ecc';
import { sha256 } from '../crypto/provider';
import { taggedHash } from '../crypto/hash';
import type { IChannelState } from '../channel/channel-state';
import type {
	IAuxiliarySweepResult,
	IAuxiliarySweepSigningRequest
} from '../channel/auxiliary';
import { HtlcDirection, isRevokedChildCustodyChannel } from '../channel/types';
import { deriveCommitmentKeys } from '../channel/commitment-builder';
import { revokedChildPrivateKey } from '../channel/child-revocation';
import {
	deriveRevocationPrivkey,
	deriveRevocationPubkey,
	perCommitmentPointFromSecret
} from '../keys/derivation';
import { MAX_INDEX } from '../keys/shachain';
import { matchRevokedHtlcSnapshotOutputs } from '../chain/output-resolver';
import {
	buildTaprootHtlcSuccessTx,
	buildTaprootHtlcTimeoutTx,
	tapleafHash
} from '../script/htlc-taproot';
import {
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootSecondLevelOutput,
	tweakTaprootKeyPathPrivkey
} from '../script/commitment-taproot';

/** Explicit Bitcoin and asset custody, restricted to one irrevocably revoked commitment. */
export interface IAuxiliaryJusticeChild {
	version: 1;
	id: string;
	sourceOutputIndex: number;
	htlcId: string;
	direction: HtlcDirection;
	paymentHash: string;
	cltvExpiry: number;
	childTemplate: string;
	htlcLeafScript: string;
	htlcControlBlock: string;
	localHtlcPubkey: string;
	remoteHtlcPubkey: string;
	perCommitmentPoint: string;
	revocationBasepoint: string;
	revocationPubkey: string;
	/** This independently derived state's authority, never a reusable channel scalar. */
	revocationPrivateKey: string;
	delayedPubkey: string;
	toSelfDelay: number;
	auxiliaryLeaf: { script: string; leafVersion: number };
	capsule: string;
}

export interface IAuxiliaryChildRemedyContext {
	transaction: bitcoin.Transaction;
	childTransaction: bitcoin.Transaction;
	capsule: Buffer;
	secondLevelRevocationKey: Buffer;
	sign(request: IAuxiliarySweepSigningRequest): Buffer;
}

const bytes = (value: string, length?: number): Buffer => {
	if (
		typeof value !== 'string' ||
		!/^(?:[0-9a-f]{2})+$/.test(value) ||
		value.length > 32 * 1024 * 1024
	)
		throw new Error('Invalid child custody bytes');
	const result = Buffer.from(value, 'hex');
	if (length !== undefined && result.length !== length)
		throw new Error('Invalid child custody field length');
	return result;
};
const publicKey = (value: string): Buffer => {
	const result = bytes(value, 33);
	if (!ecc.isPoint(result)) throw new Error('Invalid child custody public key');
	return result;
};
const childIdentity = (
	parent: bitcoin.Transaction,
	value: Omit<IAuxiliaryJusticeChild, 'id'>
): string =>
	taggedHash(
		'beignet/asset-child-custody/descriptor/v1',
		parent.getHash(),
		Buffer.from(
			JSON.stringify([
				value.version,
				value.sourceOutputIndex,
				value.htlcId,
				value.direction,
				value.paymentHash,
				value.cltvExpiry,
				value.childTemplate,
				value.htlcLeafScript,
				value.htlcControlBlock,
				value.localHtlcPubkey,
				value.remoteHtlcPubkey,
				value.perCommitmentPoint,
				value.revocationBasepoint,
				value.revocationPubkey,
				value.revocationPrivateKey,
				value.delayedPubkey,
				value.toSelfDelay,
				value.auxiliaryLeaf.script,
				value.auxiliaryLeaf.leafVersion,
				value.capsule
			])
		)
	).toString('hex');

function signWithKey(
	secret: Buffer,
	request: IAuxiliarySweepSigningRequest
): Buffer {
	if (
		request.transactionInputIndex !== 0 ||
		request.sigHash.length !== 32 ||
		!Buffer.from(ecc.pointFromScalar(secret, true)!).equals(request.publicKey)
	)
		throw new Error('Child custody requested an unrelated signing key');
	let key = Buffer.from(secret);
	if (request.singleTweak) {
		if (request.singleTweak.length !== 32)
			throw new Error('Invalid child custody key tweak');
		const tweaked = ecc.privateAdd(key, request.singleTweak);
		if (!tweaked) throw new Error('Invalid child custody zero key');
		key = Buffer.from(tweaked);
	}
	if (request.taprootMerkleRoot) {
		if (request.taprootMerkleRoot.length !== 32)
			throw new Error('Invalid child custody Taproot root');
		key = tweakTaprootKeyPathPrivkey(key, request.taprootMerkleRoot);
	}
	return Buffer.from(ecc.signSchnorr(request.sigHash, key));
}

/** Reconstruct and authenticate the exact child output and its original HTLC branch. */
export function validateAuxiliaryJusticeChild(
	parent: bitcoin.Transaction,
	value: IAuxiliaryJusticeChild
): void {
	const { id, ...body } = value;
	if (
		value.version !== 1 ||
		id !== childIdentity(parent, body) ||
		!Number.isInteger(value.sourceOutputIndex) ||
		!parent.outs[value.sourceOutputIndex] ||
		!/^\d+$/.test(value.htlcId) ||
		BigInt(value.htlcId) > 0xffffffffffffffffn ||
		![HtlcDirection.OFFERED, HtlcDirection.RECEIVED].includes(
			value.direction
		) ||
		!Number.isInteger(value.cltvExpiry) ||
		value.cltvExpiry < 0 ||
		value.cltvExpiry > 0xffffffff ||
		!Number.isInteger(value.toSelfDelay) ||
		value.toSelfDelay < 0 ||
		value.toSelfDelay > 65535
	)
		throw new Error('Invalid child custody identity');
	bytes(value.paymentHash, 32);
	bytes(value.capsule);
	const secret = bytes(value.revocationPrivateKey, 32),
		revocation = publicKey(value.revocationPubkey);
	if (
		!ecc.isPrivate(secret) ||
		!Buffer.from(ecc.pointFromScalar(secret, true)!).equals(revocation) ||
		!deriveRevocationPubkey(
			publicKey(value.revocationBasepoint),
			publicKey(value.perCommitmentPoint)
		).equals(revocation)
	)
		throw new Error(
			'Child custody scalar does not match its scoped output key'
		);
	const local = publicKey(value.localHtlcPubkey),
		remote = publicKey(value.remoteHtlcPubkey);
	const script = bytes(value.htlcLeafScript),
		control = bytes(value.htlcControlBlock);
	if (
		control.length < 33 ||
		control.length > 4129 ||
		(control.length - 33) % 32 ||
		(control[0] & 0xfe) !== 0xc0
	)
		throw new Error('Invalid child custody HTLC proof');
	let root = tapleafHash(script, 0xc0);
	for (let offset = 33; offset < control.length; offset += 32) {
		const sibling = control.subarray(offset, offset + 32);
		root =
			Buffer.compare(root, sibling) < 0
				? taggedHash('TapBranch', root, sibling)
				: taggedHash('TapBranch', sibling, root);
	}
	const internal = control.subarray(1, 33),
		tweaked = ecc.xOnlyPointAddTweak(
			internal,
			taggedHash('TapTweak', internal, root)
		);
	const source = parent.outs[value.sourceOutputIndex];
	if (
		!tweaked ||
		tweaked.parity !== (control[0] & 1) ||
		source.script.length !== 34 ||
		source.script[0] !== 0x51 ||
		source.script[1] !== 32 ||
		!Buffer.from(tweaked.xOnlyPubkey).equals(source.script.subarray(2))
	)
		throw new Error('Child custody HTLC proof does not match the commitment');
	const timeout = value.direction === HtlcDirection.RECEIVED;
	const expectedLeaf = timeout
		? buildTaprootOfferedHtlcOutput(
				Buffer.concat([Buffer.from([2]), internal]),
				local,
				remote,
				bytes(value.paymentHash)
		  ).timeout
		: buildTaprootReceivedHtlcOutput(
				Buffer.concat([Buffer.from([2]), internal]),
				local,
				remote,
				bytes(value.paymentHash),
				value.cltvExpiry
		  ).success;
	if (!expectedLeaf.script.equals(script))
		throw new Error('Child custody HTLC signing policy changed');
	const child = bitcoin.Transaction.fromHex(value.childTemplate);
	const tree = buildTaprootSecondLevelOutput(
		revocation,
		publicKey(value.delayedPubkey),
		value.toSelfDelay,
		undefined,
		{
			script: bytes(value.auxiliaryLeaf.script),
			leafVersion: value.auxiliaryLeaf.leafVersion
		}
	);
	if (
		value.auxiliaryLeaf.leafVersion !== 0xc0 ||
		child.version !== 2 ||
		child.locktime !== (timeout ? value.cltvExpiry : 0) ||
		child.ins.length !== 1 ||
		child.ins[0].index !== value.sourceOutputIndex ||
		!child.ins[0].hash.equals(parent.getHash()) ||
		child.ins[0].sequence !== 1 ||
		child.ins[0].script.length ||
		child.ins[0].witness.length ||
		child.outs.length !== 1 ||
		child.outs[0].value !== source.value ||
		!child.outs[0].script.equals(tree.output)
	)
		throw new Error(
			'Child custody template changed its authenticated allocation'
		);
}

/** Match only valid fixed-output children, including a reordered original input. */
export function matchAuxiliaryJusticeChild(
	parent: bitcoin.Transaction,
	authority: IAuxiliaryJusticeChild,
	child: bitcoin.Transaction,
	prevoutScripts: readonly Buffer[],
	prevoutValues?: readonly number[]
): boolean {
	validateAuxiliaryJusticeChild(parent, authority);
	const template = bitcoin.Transaction.fromHex(authority.childTemplate);
	if (
		prevoutScripts.length !== child.ins.length ||
		child.weight() > 4_000_000 ||
		child.version !== template.version ||
		child.locktime !== template.locktime ||
		child.outs.length !== 1 ||
		child.outs[0].value !== template.outs[0].value ||
		!child.outs[0].script.equals(template.outs[0].script)
	)
		return false;
	const indexes = child.ins.flatMap((input, index) =>
		input.hash.equals(parent.getHash()) &&
		input.index === authority.sourceOutputIndex
			? [index]
			: []
	);
	if (indexes.length !== 1) return false;
	const index = indexes[0],
		input = child.ins[index],
		source = parent.outs[authority.sourceOutputIndex];
	if (
		!prevoutScripts[index].equals(source.script) ||
		input.sequence !== 1 ||
		input.script.length
	)
		return false;
	const timeout = authority.direction === HtlcDirection.RECEIVED,
		witness = input.witness;
	if (
		witness.length !== (timeout ? 4 : 5) ||
		!witness[witness.length - 2].equals(bytes(authority.htlcLeafScript)) ||
		!witness[witness.length - 1].equals(bytes(authority.htlcControlBlock)) ||
		witness[0].length !== 65 ||
		witness[0][64] !== 0x81 ||
		(witness[1].length !== 64 &&
			(witness[1].length !== 65 ||
				![1, 2, 3, 0x81, 0x82, 0x83].includes(witness[1][64]))) ||
		(!timeout &&
			(witness[2].length !== 32 ||
				!sha256(witness[2]).equals(bytes(authority.paymentHash))))
	)
		return false;
	const ownerHashType = witness[1].length === 64 ? 0 : witness[1][64];
	if (
		prevoutValues &&
		(prevoutValues.length !== child.ins.length ||
			prevoutValues.some(
				(value) => !Number.isSafeInteger(value) || value < 0
			) ||
			prevoutValues[index] !== source.value)
	)
		return false;
	if (!(ownerHashType & 0x80) && child.ins.length > 1 && !prevoutValues)
		return false;
	const values = prevoutValues
		? [...prevoutValues]
		: child.ins.map((_entry, offset) => (offset === index ? source.value : 0));
	const digest = child.hashForWitnessV1(
		index,
		[...prevoutScripts],
		values,
		0x81,
		tapleafHash(bytes(authority.htlcLeafScript))
	);
	try {
		return (
			ecc.verifySchnorr(
				digest,
				publicKey(authority.remoteHtlcPubkey).subarray(1),
				witness[0].subarray(0, 64)
			) &&
			ecc.verifySchnorr(
				child.hashForWitnessV1(
					index,
					[...prevoutScripts],
					values,
					ownerHashType,
					tapleafHash(bytes(authority.htlcLeafScript))
				),
				publicKey(authority.localHtlcPubkey).subarray(1),
				witness[1].subarray(0, 64)
			)
		);
	} catch {
		return false;
	}
}

/** Build only after authenticating the observed child and every additional prevout. */
export function buildAuxiliaryChildRemedy(
	parent: bitcoin.Transaction,
	authority: IAuxiliaryJusticeChild,
	child: bitcoin.Transaction,
	prevoutScripts: readonly Buffer[],
	prepare: (context: IAuxiliaryChildRemedyContext) => IAuxiliarySweepResult,
	prevoutValues?: readonly number[]
): {
	transaction: string;
	auxiliaryData: string;
	csvDelay: 0;
	feeSponsorship: {
		type: 'all-anyonecanpay';
		prevoutScript: string;
		prevoutValue: string;
	};
} {
	if (
		!matchAuxiliaryJusticeChild(
			parent,
			authority,
			child,
			prevoutScripts,
			prevoutValues
		)
	)
		throw new Error('Unauthenticated revoked HTLC child');
	const secret = bytes(authority.revocationPrivateKey, 32),
		key = publicKey(authority.revocationPubkey);
	const tree = buildTaprootSecondLevelOutput(
		key,
		publicKey(authority.delayedPubkey),
		authority.toSelfDelay,
		undefined,
		{
			script: bytes(authority.auxiliaryLeaf.script),
			leafVersion: authority.auxiliaryLeaf.leafVersion
		}
	);
	const transaction = new bitcoin.Transaction();
	transaction.version = 2;
	transaction.addInput(child.getHash(), 0, 0xfffffffd);
	transaction.addOutput(
		Buffer.concat([Buffer.from([0x51, 0x20]), Buffer.alloc(32)]),
		child.outs[0].value
	);
	const prepared = prepare({
		transaction: transaction.clone(),
		childTransaction: child.clone(),
		capsule: bytes(authority.capsule),
		secondLevelRevocationKey: key,
		sign: (request) => signWithKey(secret, request)
	});
	const script = prepared.outputScripts.get(0);
	if (
		!prepared.customData.length ||
		prepared.outputScripts.size !== 1 ||
		!script ||
		script.length !== 34 ||
		script[0] !== 0x51 ||
		script[1] !== 32
	)
		throw new Error('Revoked child remedy omitted its fixed asset allocation');
	transaction.outs[0].script = Buffer.from(script);
	const digest = transaction.hashForWitnessV1(
		0,
		[child.outs[0].script],
		[child.outs[0].value],
		0x81
	);
	transaction.setWitness(0, [
		Buffer.concat([
			Buffer.from(
				ecc.signSchnorr(
					digest,
					tweakTaprootKeyPathPrivkey(secret, tree.merkleRoot)
				)
			),
			Buffer.from([0x81])
		])
	]);
	return {
		transaction: transaction.toHex(),
		auxiliaryData: prepared.customData.toString('hex'),
		csvDelay: 0,
		feeSponsorship: {
			type: 'all-anyonecanpay',
			prevoutScript: child.outs[0].script.toString('hex'),
			prevoutValue: String(child.outs[0].value)
		}
	};
}

/** Called only after the remote commitment and reveal have passed breach classification. */
export function buildAuxiliaryJusticeChildren(
	state: IChannelState,
	parent: bitcoin.Transaction,
	number: bigint,
	revocationBasepointSecret: Buffer
): IAuxiliaryJusticeChild[] {
	if (!isRevokedChildCustodyChannel(state.channelType)) return [];
	const view = state.auxiliaryState?.remoteCommitments.get(number);
	if (
		view &&
		![...(view.htlcOutputIndexes ?? [])].some(
			([identity, index]) =>
				view.secondLevelLeaves.has(identity) && view.outputLeaves.has(index)
		)
	)
		return [];
	const reveal = state.shaChainStore.getSecret(MAX_INDEX - number);
	if (
		!view ||
		!reveal ||
		!state.remoteBasepoints ||
		view.secondLevelCommitmentTxid !== parent.getId() ||
		!view.secondLevelRevocationKey ||
		!view.secondLevelRevocationBasepoint
	)
		throw new Error('Missing authenticated revoked child custody state');
	const point = perCommitmentPointFromSecret(reveal),
		keys = deriveCommitmentKeys(
			state.localBasepoints,
			state.remoteBasepoints,
			point,
			false
		);
	const original = deriveRevocationPrivkey(
		revocationBasepointSecret,
		reveal,
		state.localBasepoints.revocationBasepoint,
		point
	);
	const secret = revokedChildPrivateKey(
		state.localPerCommitmentSeed,
		parent,
		reveal
	);
	if (
		!Buffer.from(ecc.pointFromScalar(secret, true)!).equals(
			view.secondLevelRevocationKey
		)
	)
		throw new Error('Scoped child authority differs from the signed view');
	const matched = matchRevokedHtlcSnapshotOutputs(state, number, parent);
	const result: IAuxiliaryJusticeChild[] = [];
	for (const [identity, sourceOutputIndex] of view.htlcOutputIndexes ?? []) {
		const auxiliaryLeaf = view.secondLevelLeaves.get(identity),
			sourceLeaf = view.outputLeaves.get(sourceOutputIndex);
		if (!auxiliaryLeaf || !sourceLeaf) continue;
		const metadata = matched.get(sourceOutputIndex);
		if (!metadata || !state.auxiliaryProvider?.prepareRevokedChild)
			throw new Error(
				'Revoked asset child requires a custody capsule provider'
			);
		const [direction, id] = identity.split(':'),
			htlcId = BigInt(id);
		const timeout = direction === HtlcDirection.RECEIVED;
		const output = timeout
			? buildTaprootOfferedHtlcOutput(
					keys.revocationPubkey,
					keys.localHtlcPubkey,
					keys.remoteHtlcPubkey,
					metadata.paymentHash,
					undefined,
					sourceLeaf
			  )
			: buildTaprootReceivedHtlcOutput(
					keys.revocationPubkey,
					keys.localHtlcPubkey,
					keys.remoteHtlcPubkey,
					metadata.paymentHash,
					metadata.cltvExpiry,
					undefined,
					sourceLeaf
			  );
		if (!output.output.equals(parent.outs[sourceOutputIndex].script))
			throw new Error('Revoked child source script changed');
		const leaf = timeout ? output.timeout : output.success;
		const child = timeout
			? buildTaprootHtlcTimeoutTx(
					parent.getId(),
					sourceOutputIndex,
					BigInt(parent.outs[sourceOutputIndex].value),
					metadata.cltvExpiry,
					view.secondLevelRevocationKey,
					keys.localDelayedPubkey,
					state.localConfig.toSelfDelay,
					undefined,
					auxiliaryLeaf
			  )
			: buildTaprootHtlcSuccessTx(
					parent.getId(),
					sourceOutputIndex,
					BigInt(parent.outs[sourceOutputIndex].value),
					view.secondLevelRevocationKey,
					keys.localDelayedPubkey,
					state.localConfig.toSelfDelay,
					undefined,
					auxiliaryLeaf
			  );
		const capsule = state.auxiliaryProvider.prepareRevokedChild({
			state,
			commitmentNumber: number,
			commitmentTransaction: parent.clone(),
			commitmentData: Buffer.from(view.customData),
			sourceOutputIndex,
			htlcId,
			direction: direction as HtlcDirection,
			paymentHash: Buffer.from(metadata.paymentHash),
			cltvExpiry: metadata.cltvExpiry,
			childTemplate: child.clone(),
			htlcLeafScript: Buffer.from(leaf.script),
			htlcControlBlock: Buffer.from(leaf.controlBlock),
			firstLevelRevocationKey: keys.revocationPubkey,
			secondLevelRevocationKey: view.secondLevelRevocationKey,
			sign: (request) => signWithKey(original, request)
		});
		if (!capsule.length)
			throw new Error('Revoked child custody capsule is empty');
		const body: Omit<IAuxiliaryJusticeChild, 'id'> = {
			version: 1,
			sourceOutputIndex,
			htlcId: id,
			direction: direction as HtlcDirection,
			paymentHash: metadata.paymentHash.toString('hex'),
			cltvExpiry: metadata.cltvExpiry,
			childTemplate: child.toHex(),
			htlcLeafScript: leaf.script.toString('hex'),
			htlcControlBlock: leaf.controlBlock.toString('hex'),
			localHtlcPubkey: keys.localHtlcPubkey.toString('hex'),
			remoteHtlcPubkey: keys.remoteHtlcPubkey.toString('hex'),
			perCommitmentPoint: point.toString('hex'),
			revocationBasepoint: view.secondLevelRevocationBasepoint.toString('hex'),
			revocationPubkey: view.secondLevelRevocationKey.toString('hex'),
			revocationPrivateKey: secret.toString('hex'),
			delayedPubkey: keys.localDelayedPubkey.toString('hex'),
			toSelfDelay: state.localConfig.toSelfDelay,
			auxiliaryLeaf: {
				script: auxiliaryLeaf.script.toString('hex'),
				leafVersion: auxiliaryLeaf.leafVersion ?? 0xc0
			},
			capsule: capsule.toString('hex')
		};
		const descriptor = { ...body, id: childIdentity(parent, body) };
		validateAuxiliaryJusticeChild(parent, descriptor);
		result.push(descriptor);
	}
	return result;
}
