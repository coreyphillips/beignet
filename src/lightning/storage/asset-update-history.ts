import type { IAssetSpliceExitBranch } from './asset-splice-exit-proofs';
import { decodeAssetUpdateIntent } from '../channel/asset-splice-update-intent';
import type { SqliteStorage } from './sqlite-storage';

export interface IAssetUpdateSavedHtlc {
	id: string;
	offeredBy: 'local' | 'peer';
	amountMsat: string;
	paymentHash: string;
	cltvExpiry: number;
	allocations: { assetId: string; units: string }[];
}
export interface IAssetUpdateSecured {
	kind: 'asset-update-secured';
	id: string;
	height: string;
	digest: string;
	feerate: number;
	nextLocalId: string;
	nextPeerId: string;
	htlcs: IAssetUpdateSavedHtlc[];
	members: IAssetSpliceExitBranch[];
	peerCommitments: string[];
	localCommitments: string[];
}
export type AssetUpdateEvent =
	| IAssetUpdateSecured
	| {
			kind: 'asset-update-stage';
			id: string;
			height: string;
			digest: string;
			stage:
				| 'intent'
				| 'offer'
				| 'peer-offer'
				| 'local-shares'
				| 'joint-shares'
				| 'local-htlcs'
				| 'verified'
				| 'local-commits'
				| 'local-revoke'
				| 'peer-revoke';
			bytes: string;
	  };
export function assetUpdateHistory(store: SqliteStorage, id: string) {
	const all = store
		.readAssetSpliceJournal<AssetUpdateEvent>(id)
		.records.filter(
			(e) =>
				e.kind === 'asset-update-stage' || e.kind === 'asset-update-secured'
		);
	const states = new Map<bigint, IAssetUpdateSecured>(),
		stages = new Map<string, string>(),
		digests = new Map<bigint, string>();
	for (const e of all) {
		const height = BigInt(e.height);
		if (
			e.id !== id ||
			height < 1n ||
			height.toString() !== e.height ||
			!/^[0-9a-f]{64}$/.test(e.digest) ||
			(digests.has(height) && digests.get(height) !== e.digest)
		)
			throw new Error('Inconsistent original asset update journal');
		digests.set(height, e.digest);
		if (e.kind === 'asset-update-secured') {
			if (states.has(height) || !stages.has(height + '/local-commits'))
				throw new Error('Invalid secured asset update round');
			states.set(height, e);
			continue;
		}
		const key = height + '/' + e.stage;
		if (
			stages.has(key) ||
			(!states.has(height) &&
				(e.stage === 'local-revoke' || e.stage === 'peer-revoke')) ||
			!e.bytes ||
			!/^(?:[a-f0-9]{2})+$/.test(e.bytes)
		)
			throw new Error('Invalid asset update signing stage');
		stages.set(key, e.bytes);
	}
	return { states, stages, digests, latest: [...states.values()].at(-1) };
}

export function assetSpliceUpdateHead(store: SqliteStorage, id: string) {
	const opening = store.loadFinalOpening(id);
	if (!opening || !store.canSpliceDualFundedAssets)
		throw new Error('Missing original asset update wallet');
	const history = assetUpdateHistory(store, id),
		newest = history.latest;
	const last = newest ? BigInt(newest.height) : 0n;
	const acknowledged =
		newest &&
		history.stages.has(last + '/local-revoke') &&
		history.stages.has(last + '/peer-revoke');
	const current = acknowledged ? newest : history.states.get(last - 1n);
	const nextNumber = current ? BigInt(current.height) + 1n : 1n;
	const intent = history.stages.get(nextNumber + '/intent');
	return {
		nextNumber,
		nextLocalId: BigInt(current?.nextLocalId ?? 0),
		nextPeerId: BigInt(current?.nextPeerId ?? 0),
		committed: current,
		...(intent && {
			inProgress: {
				stateNumber: nextNumber,
				changes: decodeAssetUpdateIntent(
					id,
					opening.isInitiator,
					Buffer.from(intent, 'hex')
				)
			}
		})
	};
}
