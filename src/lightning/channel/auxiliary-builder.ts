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
	const previous = (
		side === 'local'
			? state.auxiliaryState!.localCommitments
			: state.auxiliaryState!.remoteCommitments
	).get(commitmentNumber);
	const prepared = copyAuxiliaryCommitment(
		previous ??
			provider.buildCommitment({
				resolveSecondLevelRevocationKey: (transaction) =>
					resolveChildRevocationKey(
						state,
						side,
						perCommitmentPoint,
						transaction
					)?.publicKey,
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
			})
	);
	prepared.htlcOutputIndexes = new Map(
		outputs
			.filter((output) => output.htlcId !== undefined)
			.map((output) => [
				`${output.direction}:${output.htlcId}`,
				output.outputIndex
			])
	);
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
