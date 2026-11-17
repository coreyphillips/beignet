/**
 * Asset channels: the auxiliary side of one commitment transaction.
 *
 * buildCommitmentTx builds and sorts the ordinary Bitcoin commitment. For a
 * channel with asset state, applyAuxiliaryCommitment then describes every
 * output to the provider, takes back one auxiliary leaf for each output
 * that carries assets, and rewrites those output scripts to commit to the
 * leaf. The order of the outputs is the order of the ordinary transaction
 * and does not change. A channel without asset state returns at the first
 * line with its transaction untouched.
 */

import { sha256 } from '../crypto/provider';
import { serializeAuxiliaryState } from '../storage/auxiliary-serialization';
import { resolveChildRevocationKey } from './child-revocation';
import type { ICommitmentTxResult } from '../script/commitment';
import {
	buildTaprootToLocalOutput,
	buildTaprootToRemoteOutput,
	buildTaprootOfferedHtlcOutput,
	buildTaprootReceivedHtlcOutput,
	buildTaprootAnchorOutput,
	TAPROOT_NUMS_KEY
} from '../script/commitment-taproot';
import type { IChannelState } from './channel-state';
import type {
	ICommitmentKeys,
	IHtlcOutputWithMeta
} from './commitment-builder';
import type { IAuxiliaryOutput, IAuxiliaryCommitmentData } from './auxiliary';
import { copyAuxiliaryCommitment, requireAuxiliaryProvider } from './auxiliary';
import {
	HtlcDirection,
	isTaprootChannel,
	isOverlayChannel,
	isRevokedChildCustodyChannel
} from './types';

/**
 * A digest of everything the provider is asked about one commitment: the
 * side, the number and point, the Bitcoin transaction before any leaf (which
 * holds every output, key and amount), the asset balances, what each HTLC
 * carries, and the channel's own asset data.
 */
function auxiliaryQuestion(
	state: IChannelState,
	side: 'local' | 'remote',
	commitmentNumber: bigint,
	perCommitmentPoint: Buffer,
	baseTransaction: ICommitmentTxResult['tx'],
	localAssetBalance: bigint,
	remoteAssetBalance: bigint,
	signedLocal: boolean,
	htlcs: IHtlcOutputWithMeta[]
): string {
	const parts: string[] = [
		side,
		commitmentNumber.toString(),
		perCommitmentPoint.toString('hex'),
		baseTransaction.toBuffer().toString('hex'),
		localAssetBalance.toString(),
		remoteAssetBalance.toString(),
		signedLocal ? 'signed' : 'unsigned',
		state.auxiliaryState?.channelData.toString('hex') ?? ''
	];
	for (const htlc of htlcs) {
		parts.push(
			[
				htlc.direction,
				htlc.htlcId.toString(),
				htlc.amountMsat.toString(),
				htlc.paymentHash.toString('hex'),
				htlc.cltvExpiry,
				htlc.auxiliaryAmount?.toString() ?? '',
				...[...(htlc.customRecords ?? new Map<bigint, Buffer>())]
					.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
					.map(([type, value]) => `${type}=${value.toString('hex')}`)
			].join(':')
		);
	}
	return sha256(Buffer.from(parts.join('|'))).toString('hex');
}

/**
 * Check what the provider answered where it comes in, before anything is
 * signed or sent on it, by the rules the stored form is read back with: the
 * answer is put through the writer, which runs the reader over its result.
 * An answer that could not be read back from the channel row is refused
 * here and never reaches it. A second-level leaf also has to belong to an
 * HTLC output of this commitment.
 */
function validateAuxiliaryAnswer(
	answer: IAuxiliaryCommitmentData,
	commitmentNumber: bigint,
	htlcOutputIndexes: Map<string, number>
): void {
	if (
		!answer ||
		typeof answer !== 'object' ||
		!Buffer.isBuffer(answer.customData) ||
		!(answer.outputLeaves instanceof Map) ||
		!(answer.secondLevelLeaves instanceof Map)
	) {
		throw new Error('Malformed asset commitment from the provider');
	}
	try {
		serializeAuxiliaryState({
			channelData: Buffer.from([0]),
			localBalance: 0n,
			remoteBalance: 0n,
			localCommitments: new Map([[commitmentNumber, answer]]),
			remoteCommitments: new Map()
		});
	} catch (err) {
		throw new Error(
			`Malformed asset commitment from the provider: ${(err as Error).message}`
		);
	}
	for (const key of answer.secondLevelLeaves.keys()) {
		if (!htlcOutputIndexes.has(key)) {
			throw new Error(
				'Asset commitment from the provider has a second-level leaf for no HTLC output of the commitment'
			);
		}
	}
}

/**
 * Commit the asset side of a commitment into `result.tx` and return it, or
 * return undefined for a channel that has none.
 *
 * Throws, and so stops the signature that asked, when the provider is
 * missing, when a party or an HTLC holds assets and the provider gave its
 * output no leaf, when a leaf names an output that cannot carry one, or
 * when an asset balance has no Bitcoin output to ride on.
 */
export function applyAuxiliaryCommitment(
	state: IChannelState,
	side: 'local' | 'remote',
	commitmentNumber: bigint,
	perCommitmentPoint: Buffer,
	keys: ICommitmentKeys,
	result: ICommitmentTxResult,
	htlcs: IHtlcOutputWithMeta[],
	localAssetBalance: bigint,
	remoteAssetBalance: bigint,
	signedLocal: boolean
): IAuxiliaryCommitmentData | undefined {
	if (
		!state.auxiliaryState &&
		!state.fundingTaprootMerkleRoot &&
		!isOverlayChannel(state.channelType)
	)
		return undefined;
	if (!isTaprootChannel(state.channelType))
		throw new Error('Asset channels require Taproot commitments');
	const provider = requireAuxiliaryProvider(state);
	const holderBalance =
		side === 'local' ? localAssetBalance : remoteAssetBalance;
	const peerBalance = side === 'local' ? remoteAssetBalance : localAssetBalance;
	if (holderBalance < 0n || peerBalance < 0n)
		throw new Error('Negative asset commitment balance');
	if (
		(holderBalance > 0n && result.outputMap.toLocal === undefined) ||
		(peerBalance > 0n && result.outputMap.toRemote === undefined)
	)
		throw new Error('Asset-bearing commitment balance has no Bitcoin output');
	const delay =
		side === 'local'
			? state.remoteConfig.toSelfDelay
			: state.localConfig.toSelfDelay;
	const outputs: IAuxiliaryOutput[] = [];
	const add = (
		outputIndex: number | undefined,
		data: Omit<IAuxiliaryOutput, 'outputIndex' | 'bitcoinValue' | 'script'>
	): void => {
		if (outputIndex === undefined) return;
		const output = result.tx.outs[outputIndex];
		outputs.push({
			...data,
			outputIndex,
			bitcoinValue: BigInt(output.value),
			script: Buffer.from(output.script)
		});
	};
	const local = buildTaprootToLocalOutput(
		keys.revocationPubkey,
		keys.localDelayedPubkey,
		delay
	);
	add(result.outputMap.toLocal, {
		role: 'to_local',
		internalKey: Buffer.concat([Buffer.from([2]), TAPROOT_NUMS_KEY]),
		leaves: [local.delay, local.revoke]
	});
	const remote = buildTaprootToRemoteOutput(keys.remotePaymentPubkey);
	add(result.outputMap.toRemote, {
		role: 'to_remote',
		internalKey: Buffer.concat([Buffer.from([2]), TAPROOT_NUMS_KEY]),
		leaves: [remote.spend]
	});
	for (let i = 0; i < result.outputMap.htlcs.length; i++) {
		const meta = htlcs[result.outputMap.htlcOriginalIndices[i]];
		const offered =
			(meta.direction === HtlcDirection.OFFERED) === (side === 'local');
		const output = offered
			? buildTaprootOfferedHtlcOutput(
					keys.revocationPubkey,
					keys.localHtlcPubkey,
					keys.remoteHtlcPubkey,
					meta.paymentHash
			  )
			: buildTaprootReceivedHtlcOutput(
					keys.revocationPubkey,
					keys.localHtlcPubkey,
					keys.remoteHtlcPubkey,
					meta.paymentHash,
					meta.cltvExpiry
			  );
		add(result.outputMap.htlcs[i], {
			role: offered ? 'offered_htlc' : 'received_htlc',
			internalKey: Buffer.from(keys.revocationPubkey),
			leaves: [output.success, output.timeout],
			htlcId: meta.htlcId,
			direction: meta.direction,
			cltvExpiry: meta.cltvExpiry
		});
	}
	const anchorLocal = buildTaprootAnchorOutput(keys.localDelayedPubkey);
	add(result.outputMap.anchorLocal, {
		role: 'anchor_local',
		internalKey: Buffer.from(keys.localDelayedPubkey),
		leaves: [anchorLocal.anyone]
	});
	const anchorRemote = buildTaprootAnchorOutput(keys.remotePaymentPubkey);
	add(result.outputMap.anchorRemote, {
		role: 'anchor_remote',
		internalKey: Buffer.from(keys.remotePaymentPubkey),
		leaves: [anchorRemote.anyone]
	});
	outputs.sort((a, b) => a.outputIndex - b.outputIndex);
	// The stored view is reused only to rebuild our own signed commitment,
	// where it is the view the peer's signature was verified against. Every
	// other build asks the provider, which must give the same answer the
	// peer's provider gives for the same commitment. A view left behind by a
	// signing round that never completed is therefore never signed over
	// again for a commitment that has since changed.
	const previous =
		side === 'local' && signedLocal
			? state.auxiliaryState!.localCommitments.get(commitmentNumber)
			: undefined;
	const htlcOutputIndexes = new Map(
		outputs
			.filter((output) => output.htlcId !== undefined)
			.map((output): [string, number] => [
				`${output.direction}:${output.htlcId}`,
				output.outputIndex
			])
	);
	if (previous?.htlcOutputIndexes) {
		const stored = previous.htlcOutputIndexes;
		if (
			stored.size !== htlcOutputIndexes.size ||
			[...htlcOutputIndexes].some(([key, index]) => stored.get(key) !== index)
		)
			throw new Error(
				'Persisted asset commitment does not match the rebuilt transaction'
			);
	}
	// The provider is asked once about a commitment. Its answer is kept, in
	// memory only, with a digest of everything it was asked, and the same
	// commitment built again gets that answer: the view a signature is made
	// or verified against is then the view that is stored, and a round that
	// asked before it sent anything does not ask again when it signs.
	const asked = previous
		? undefined
		: auxiliaryQuestion(
				state,
				side,
				commitmentNumber,
				perCommitmentPoint,
				result.tx,
				localAssetBalance,
				remoteAssetBalance,
				signedLocal,
				htlcs
		  );
	const kept = asked ? state.auxiliaryAnswers?.get(side) : undefined;
	let answer =
		previous ?? (kept && kept.asked === asked ? kept.answer : undefined);
	if (!answer) {
		answer = provider.buildCommitment({
			resolveSecondLevelRevocationKey: (transaction) =>
				resolveChildRevocationKey(state, side, perCommitmentPoint, transaction)
					?.publicKey,
			state,
			side,
			commitmentNumber,
			localAssetBalance,
			remoteAssetBalance,
			signedLocal,
			perCommitmentPoint: Buffer.from(perCommitmentPoint),
			keys,
			baseTransaction: result.tx.clone(),
			outputs,
			htlcs
		});
		validateAuxiliaryAnswer(answer, commitmentNumber, htlcOutputIndexes);
		(state.auxiliaryAnswers ??= new Map()).set(side, {
			asked: asked!,
			answer: copyAuxiliaryCommitment(answer)
		});
	}
	const prepared = copyAuxiliaryCommitment(answer);
	prepared.htlcOutputIndexes = htlcOutputIndexes;
	if (
		(holderBalance > 0n &&
			!prepared.outputLeaves.has(result.outputMap.toLocal!)) ||
		(peerBalance > 0n && !prepared.outputLeaves.has(result.outputMap.toRemote!))
	)
		throw new Error('Missing asset balance commitment leaf');
	for (const output of outputs) {
		if (output.htlcId === undefined) continue;
		const meta = htlcs.find(
			(item) =>
				item.htlcId === output.htlcId && item.direction === output.direction
		);
		if (!meta?.auxiliaryAmount) continue;
		const key = `${output.direction}:${output.htlcId}`;
		if (
			!prepared.outputLeaves.has(output.outputIndex) ||
			(!prepared.secondLevelLeaves.has(key) &&
				!isRevokedChildCustodyChannel(state.channelType))
		)
			throw new Error('Missing asset HTLC commitment leaf');
	}

	for (const [index, leaf] of prepared.outputLeaves) {
		const output = outputs.find((item) => item.outputIndex === index);
		if (
			!output ||
			output.role === 'anchor_local' ||
			output.role === 'anchor_remote'
		)
			throw new Error('Invalid asset auxiliary output index');
		let script: Buffer;
		switch (output.role) {
			case 'to_local':
				script = buildTaprootToLocalOutput(
					keys.revocationPubkey,
					keys.localDelayedPubkey,
					delay,
					undefined,
					leaf
				).output;
				break;
			case 'to_remote':
				script = buildTaprootToRemoteOutput(
					keys.remotePaymentPubkey,
					undefined,
					leaf
				).output;
				break;
			default: {
				const meta = htlcs.find(
					(item) =>
						item.htlcId === output.htlcId && item.direction === output.direction
				)!;
				script =
					output.role === 'offered_htlc'
						? buildTaprootOfferedHtlcOutput(
								keys.revocationPubkey,
								keys.localHtlcPubkey,
								keys.remoteHtlcPubkey,
								meta.paymentHash,
								undefined,
								leaf
						  ).output
						: buildTaprootReceivedHtlcOutput(
								keys.revocationPubkey,
								keys.localHtlcPubkey,
								keys.remoteHtlcPubkey,
								meta.paymentHash,
								meta.cltvExpiry,
								undefined,
								leaf
						  ).output;
			}
		}
		// The auxiliary leaf changes the output key, never the pre-aux sort order.
		result.tx.outs[index].script = script;
	}

	const child = resolveChildRevocationKey(
		state,
		side,
		perCommitmentPoint,
		result.tx
	);
	if (child) {
		if (
			prepared.secondLevelCommitmentTxid &&
			prepared.secondLevelCommitmentTxid !== result.tx.getId()
		)
			throw new Error('Persisted child custody commitment changed');
		if (
			prepared.secondLevelRevocationKey &&
			!prepared.secondLevelRevocationKey.equals(child.publicKey)
		)
			throw new Error('Persisted child custody key changed');
		prepared.secondLevelRevocationKey = child.publicKey;
		prepared.secondLevelRevocationBasepoint = child.basepoint;
		prepared.secondLevelCommitmentTxid = result.tx.getId();
	}
	if (child) {
		for (const output of outputs) {
			const meta = htlcs.find(
				(item) =>
					item.htlcId === output.htlcId && item.direction === output.direction
			);
			if (
				meta?.auxiliaryAmount &&
				!prepared.secondLevelLeaves.has(`${meta.direction}:${meta.htlcId}`)
			)
				throw new Error('Missing scoped asset HTLC commitment leaf');
		}
	}
	return prepared;
}
