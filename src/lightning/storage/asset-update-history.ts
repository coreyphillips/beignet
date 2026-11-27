import type { IAssetSpliceExitBranch } from './asset-splice-exit-proofs';
import {
	canonicalSpliceFunding,
	canonicalSpliceHolder
} from './asset-splice-recovery';
import { decodeAssetUpdateIntent } from '../channel/asset-splice-update-intent';
import type { SqliteStorage } from './sqlite-storage';
import type {
	IFinalAssetSeed,
	IFinalChannelTypeRecord
} from './final-channel-type';

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
/** The peer's side of one member, kept before this device signs the peer's commitment. */
export type IAssetUpdatePeerExit = Pick<
	IAssetSpliceExitBranch,
	| 'minimumDepth'
	| 'funding'
	| 'fundingTxid'
	| 'outputIndex'
	| 'fundingRoot'
	| 'fundingProofs'
	| 'remoteCommitment'
	| 'remoteProofs'
	| 'remoteRecovery'
>;
export interface IAssetUpdatePeerExits {
	feerate: number;
	htlcs: IAssetUpdateSavedHtlc[];
	members: IAssetUpdatePeerExit[];
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
				| 'peer-exits'
				| 'local-commits'
				| 'local-revoke'
				| 'peer-revoke';
			bytes: string;
	  };
/** The current asset record, whose seed starts the asset ledger at its state number (#2151). */
export function currentAssetRecord(
	store: SqliteStorage,
	id: string
): IFinalChannelTypeRecord | undefined {
	// A store without records (a test double or an older surface) has none.
	const records =
		typeof store.loadFinalChannelTypeRecords === 'function'
			? store.loadFinalChannelTypeRecords(id)
			: [];
	const latest = records.at(-1);
	return latest?.type === 'asset' ? latest : undefined;
}
/** The seed of an asset record as the secured state at its N. */
function seededState(
	id: string,
	r: IFinalChannelTypeRecord
): IAssetUpdateSecured {
	const seed = r.seed as IFinalAssetSeed;
	return {
		kind: 'asset-update-secured',
		id,
		height: r.stateNumber,
		digest: seed.digest,
		feerate: seed.feerate,
		nextLocalId: seed.nextLocalId,
		nextPeerId: seed.nextPeerId,
		htlcs: [],
		members: seed.members,
		peerCommitments: seed.members.map((m) => m.remoteCommitment),
		localCommitments: seed.members.map((m) => m.localCommitment)
	};
}
export function assetUpdateHistory(
	store: SqliteStorage,
	id: string
): ReturnType<typeof historyOf> {
	return historyOf(store, id, currentAssetRecord(store, id));
}

/**
 * The asset history of one era (#2151 step 2b), in the shape of
 * assetUpdateHistory: for era 0, the opening's events up to the first
 * record's N; for the era of an asset record, its seed at N and the events
 * above N up to the next record's N. The current asset era is
 * assetUpdateHistory itself. A plain era has no asset history.
 */
export function assetEraHistory(
	store: SqliteStorage,
	id: string,
	era: number
): ReturnType<typeof assetUpdateHistory> {
	const records =
		typeof store.loadFinalChannelTypeRecords === 'function'
			? store.loadFinalChannelTypeRecords(id)
			: [];
	if (!Number.isSafeInteger(era) || era < 0 || era > records.length)
		throw new Error('Unknown channel type era');
	const record = era ? records[era - 1] : undefined;
	const next = records[era];
	const asset = record
		? record.type === 'asset'
		: !!store.loadAssetOpeningEvidence(id);
	if (!asset) return emptyHistory();
	// The last era is the current one.
	if (!next) return assetUpdateHistory(store, id);
	return historyOf(store, id, record, BigInt(next.stateNumber));
}

function emptyHistory(): ReturnType<typeof assetUpdateHistory> {
	return {
		states: new Map<bigint, IAssetUpdateSecured>(),
		stages: new Map<string, string>(),
		digests: new Map<bigint, string>(),
		latest: undefined,
		seedHeight: undefined,
		seed: undefined
	};
}

function historyOf(
	store: SqliteStorage,
	id: string,
	record: IFinalChannelTypeRecord | undefined,
	upTo?: bigint
) {
	const seedHeight = record ? BigInt(record.stateNumber) : undefined;
	const all = store.readAssetSpliceJournal<AssetUpdateEvent>(id).records.filter(
		(e) =>
			(e.kind === 'asset-update-stage' || e.kind === 'asset-update-secured') &&
			// The seed shadows every height at or below its N.
			(seedHeight === undefined ||
				!/^[0-9]+$/.test(e.height) ||
				BigInt(e.height) > seedHeight) &&
			// A later record ends the era at its N (#2151 step 2b).
			(upTo === undefined ||
				!/^[0-9]+$/.test(e.height) ||
				BigInt(e.height) <= upTo)
	);
	const states = new Map<bigint, IAssetUpdateSecured>(),
		stages = new Map<string, string>(),
		digests = new Map<bigint, string>();
	if (record && seedHeight !== undefined) {
		const seed = record.seed as IFinalAssetSeed;
		states.set(seedHeight, seededState(id, record));
		digests.set(seedHeight, seed.digest);
		if (seed.localRevoke)
			stages.set(seedHeight + '/local-revoke', seed.localRevoke);
		if (seed.peerRevoke)
			stages.set(seedHeight + '/peer-revoke', seed.peerRevoke);
	}
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
	return {
		states,
		stages,
		digests,
		latest: [...states.values()].at(-1),
		seedHeight,
		seed: record?.seed as IFinalAssetSeed | undefined
	};
}

const isHex = (v: unknown, bytes?: number): v is string =>
	typeof v === 'string' &&
	v.length > 0 &&
	v.length % 2 === 0 &&
	(bytes === undefined || v.length === bytes * 2) &&
	/^[0-9a-f]+$/.test(v);

/**
 * Peer commitments this device has signed in a round it has not secured yet.
 * The peer can publish one before it returns its own signatures.
 */
export function inFlightAssetUpdates(
	history: ReturnType<typeof assetUpdateHistory>
): Map<bigint, IAssetUpdatePeerExits & { digest: string }> {
	const pending = new Map<bigint, IAssetUpdatePeerExits & { digest: string }>();
	for (const [key, raw] of history.stages) {
		const [h, stage] = key.split('/');
		const height = BigInt(h);
		if (stage !== 'peer-exits' || history.states.has(height)) continue;
		const v = JSON.parse(Buffer.from(raw, 'hex').toString()) as unknown;
		const r = v as Partial<IAssetUpdatePeerExits>;
		if (
			!r ||
			!Number.isSafeInteger(r.feerate) ||
			!Array.isArray(r.htlcs) ||
			!Array.isArray(r.members) ||
			!r.members.length
		)
			throw new Error('Invalid in-flight asset update peer exits');
		const members = r.members.map((m) => {
			if (
				!isHex(m.fundingTxid, 32) ||
				!Number.isSafeInteger(m.outputIndex) ||
				!Number.isSafeInteger(m.minimumDepth) ||
				!isHex(m.fundingRoot, 32) ||
				!isHex(m.fundingProofs) ||
				!isHex(m.remoteCommitment) ||
				!isHex(m.remoteProofs)
			)
				throw new Error('Invalid in-flight asset update peer exit');
			return {
				...m,
				funding: canonicalSpliceFunding(m.funding),
				remoteRecovery: canonicalSpliceHolder(m.remoteRecovery)
			};
		});
		pending.set(height, {
			digest: history.digests.get(height)!,
			feerate: r.feerate!,
			htlcs: r.htlcs,
			members
		});
	}
	return pending;
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
		(history.seedHeight === last ||
			(history.stages.has(last + '/local-revoke') &&
				history.stages.has(last + '/peer-revoke')));
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
