import { assetUpdateFundingMembers } from '../storage/asset-update-history';
import { Transaction } from 'bitcoinjs-lib';
import { sha256 } from '../crypto/provider';
import type {
	IAssetUpdateSavedHtlc,
	IAssetUpdateSecured
} from '../storage/asset-update-history';
import type { IAssetSpliceExitBranch } from '../storage/asset-splice-exit-proofs';
import type { IFinalUpdateLimits } from '../storage/final-channel-updates';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import type { SqliteStorage } from '../storage/sqlite-storage';
import { assertFinalTaprootHtlcExpiry } from '../script/commitment-taproot';
import { validateFinalSpliceReserves } from './final-commitment-reserve';
import type { IFinalOpeningTerms } from './final-opening-commitment';
import type { IFinalFundingReference } from './final-splice-candidate';
import type {
	AssetUpdateChange,
	IAssetUpdateHtlc
} from './asset-splice-update-provider';
import type { AssetSpliceConstructionEvent } from './asset-splice-construction';

export function saveUpdateHtlc(h: IAssetUpdateHtlc): IAssetUpdateSavedHtlc {
	return {
		...h,
		id: String(h.id),
		amountMsat: String(h.amountMsat),
		paymentHash: h.paymentHash.toString('hex'),
		allocations: h.allocations.map((a) => ({
			assetId: a.assetId,
			units: String(a.units)
		}))
	};
}
export function readUpdateHtlc(h: IAssetUpdateSavedHtlc): IAssetUpdateHtlc {
	return {
		...h,
		id: BigInt(h.id),
		amountMsat: BigInt(h.amountMsat),
		paymentHash: Buffer.from(h.paymentHash, 'hex'),
		allocations: h.allocations.map((a) => ({
			assetId: a.assetId,
			units: BigInt(a.units)
		}))
	};
}
export function fundingPoint(ref: IFinalFundingReference) {
	return (
		Transaction.fromHex(ref.fundingTxHex).getId() + ':' + ref.fundingOutputIndex
	);
}
export interface UpdateSource {
	minimumDepth: number;
	funding: IFinalFundingReference;
	root: string;
	proofs: string;
	localBalanceMsat: bigint;
	remoteBalanceMsat: bigint;
}
export function assetUpdateSources(
	store: SqliteStorage,
	id: string,
	previous: IAssetUpdateSecured | undefined
): {
	sources: UpdateSource[];
	opening: NonNullable<ReturnType<SqliteStorage['loadFinalDaemonOpening']>>;
} {
	const opening = store.loadFinalDaemonOpening(id);
	if (
		!opening?.funding ||
		!opening.session.assetEvidence ||
		!opening.session.updateLimits
	)
		throw new Error(
			'Missing funded original asset channel and negotiated limits'
		);
	const info = store.loadAssetSpliceFundingInfo(id);
	if (info.reconciliation || info.awaitingImport)
		throw new Error('Asset funding membership is under reconciliation');
	const source = (b: IAssetSpliceExitBranch): UpdateSource => ({
		minimumDepth: b.minimumDepth,
		funding: { ...b.funding },
		root: b.fundingRoot,
		proofs: b.fundingProofs,
		localBalanceMsat: BigInt(b.localRecovery.localBalanceMsat),
		remoteBalanceMsat: BigInt(b.localRecovery.remoteBalanceMsat)
	});
	const c = opening.candidate,
		e = opening.session.assetEvidence;
	const selected = info.active
		? source(info.active.candidate)
		: {
				funding: {
					fundingTxHex: c.fundingTxHex,
					fundingOutputIndex: c.fundingOutputIndex,
					localFundingPubkey: c.localFundingPubkey,
					remoteFundingPubkey: c.remoteFundingPubkey,
					localFundingKeyIndex: opening.session.channelKeyIndex
				},
				minimumDepth: c.minimumDepth,
				root: e.fundingRoot,
				proofs: e.fundingProofs,
				localBalanceMsat: BigInt(c.localContributionSats) * 1000n,
				remoteBalanceMsat: BigInt(c.remoteContributionSats) * 1000n
		  };
	const starts = store
		.readAssetSpliceJournal<AssetSpliceConstructionEvent>(id)
		.records.filter((s) => s.kind === 'construction-start');
	const sources = [
		selected,
		...info.pending.map((candidate) => {
			const begin = starts.find((b) => b.finalDigest === candidate.finalDigest);
			if (
				!begin ||
				!store.releasedAssetSplice(id, begin.attempt)?.transaction()
			)
				throw new Error('Incomplete funding exchange freezes asset updates');
			return source(candidate.candidate);
		})
	].sort((a, b) =>
		fundingPoint(a.funding).localeCompare(fundingPoint(b.funding))
	);
	if (
		sources.length > 20 ||
		new Set(
			sources.map((s) => Transaction.fromHex(s.funding.fundingTxHex).getId())
		).size !== sources.length
	)
		throw new Error('Invalid asset commitment batch membership');
	const members = previous
		? assetUpdateFundingMembers(store, id, previous)
		: [];
	for (const s of sources)
		if (previous) {
			const prior = members.find(
				(b) => fundingPoint(b.funding) === fundingPoint(s.funding)
			);
			if (!prior || prior.fundingRoot !== s.root)
				throw new Error('No cross-signed predecessor for the elected funding');
			s.localBalanceMsat = BigInt(prior.localRecovery.localBalanceMsat);
			s.remoteBalanceMsat = BigInt(prior.localRecovery.remoteBalanceMsat);
		}
	return { sources, opening };
}

export function applyAssetChanges(
	changes: readonly AssetUpdateChange[],
	previous: IAssetUpdateSecured | undefined,
	sources: UpdateSource[],
	candidate: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	limits: IFinalUpdateLimits,
	block: number
) {
	if (
		!changes.length ||
		changes.length > 967 ||
		!Number.isSafeInteger(block) ||
		block < 0
	)
		throw new Error('Invalid asset update batch');
	let feerate = previous?.feerate ?? terms.commitmentFeeratePerKw;
	const next = {
		local: BigInt(previous?.nextLocalId ?? 0),
		peer: BigInt(previous?.nextPeerId ?? 0)
	};
	const htlcs = (previous?.htlcs ?? []).map(readUpdateHtlc),
		prior = new Set(htlcs.map((h) => h.offeredBy + '/' + h.id));
	const signedChanges: unknown[] = [];
	const participant = (dir: 'local' | 'peer') =>
		(dir === 'local') === candidate.isInitiator ? 'initiator' : 'acceptor';
	for (const change of changes) {
		if (change.kind === 'fee') {
			if (
				!Number.isSafeInteger(change.feeratePerKw) ||
				change.feeratePerKw < 253 ||
				change.feeratePerKw > 100000 ||
				change.feeratePerKw > 10 * feerate
			)
				throw new Error('Invalid asset commitment fee');
			feerate = change.feeratePerKw;
			signedChanges.push(['fee', feerate]);
			continue;
		}
		const adding = change.kind === 'add',
			dir = adding ? change.htlc.offeredBy : change.offeredBy,
			id = adding ? change.htlc.id : change.id;
		if (
			(dir !== 'local' && dir !== 'peer') ||
			typeof id !== 'bigint' ||
			id < 0n ||
			id > 0xffffffffffffffffn
		)
			throw new Error('Invalid asset HTLC identity');
		const index = htlcs.findIndex((h) => h.offeredBy === dir && h.id === id),
			limit = dir === 'local' ? limits.remote : limits.local;
		let h: IAssetUpdateHtlc;
		if (adding) {
			h = change.htlc;
			if (
				id !== next[dir]++ ||
				index >= 0 ||
				typeof h.amountMsat !== 'bigint' ||
				h.amountMsat <= 0n ||
				h.amountMsat < BigInt(limit.htlcMinimumMsat) ||
				h.amountMsat > 0xffffffffffffffffn ||
				h.paymentHash.length !== 32 ||
				h.cltvExpiry <= block + 18 ||
				!Array.isArray(h.allocations) ||
				h.allocations.length > 483
			)
				throw new Error('Invalid or near-expiry asset HTLC');
			assertFinalTaprootHtlcExpiry(h.cltvExpiry);
			const ids = new Set<string>();
			for (const a of h.allocations) {
				if (
					!/^[0-9a-f]{64}$/.test(a.assetId) ||
					ids.has(a.assetId) ||
					typeof a.units !== 'bigint' ||
					a.units <= 0n ||
					a.units > 0xffffffffffffffffn
				)
					throw new Error('Invalid per-issuance HTLC allocation');
				ids.add(a.assetId);
			}
			h = readUpdateHtlc(saveUpdateHtlc(h));
			htlcs.push(h);
			signedChanges.push([
				'add',
				participant(dir),
				String(id),
				String(h.amountMsat),
				h.paymentHash.toString('hex'),
				h.cltvExpiry,
				h.allocations.map((a) => [a.assetId, String(a.units)]).sort()
			]);
		} else {
			if (index < 0 || !prior.delete(dir + '/' + id))
				throw new Error('Unknown or uncommitted asset HTLC removal');
			h = htlcs[index];
			htlcs.splice(index, 1);
			if (
				change.kind === 'fulfill'
					? !Buffer.isBuffer(change.preimage) ||
					  change.preimage.length !== 32 ||
					  !sha256(change.preimage).equals(h.paymentHash)
					: change.kind !== 'fail' ||
					  !Buffer.isBuffer(change.reason) ||
					  !change.reason.length ||
					  change.reason.length > 65533
			)
				throw new Error('Invalid asset HTLC resolution');
			signedChanges.push([
				change.kind,
				participant(dir),
				String(id),
				(change.kind === 'fulfill' ? change.preimage : change.reason).toString(
					'hex'
				)
			]);
		}
		for (const s of sources) {
			const local =
				change.kind === 'fulfill' ? dir === 'peer' : dir === 'local';
			s[local ? 'localBalanceMsat' : 'remoteBalanceMsat'] += adding
				? -h.amountMsat
				: h.amountMsat;
		}
		const offered = htlcs.filter((v) => v.offeredBy === dir);
		if (
			offered.length > limit.maxAcceptedHtlcs ||
			offered.reduce((n, v) => n + v.amountMsat, 0n) >
				BigInt(limit.maxHtlcValueInFlightMsat)
		)
			throw new Error('Asset HTLC exceeds negotiated live-view limits');
	}
	if (htlcs.some((h) => h.cltvExpiry <= block + 18))
		throw new Error('A pending asset HTLC needs a timely chain exit');
	for (const s of sources) {
		const tx = Transaction.fromHex(s.funding.fundingTxHex);
		validateFinalSpliceReserves(
			BigInt(tx.outs[s.funding.fundingOutputIndex].value),
			{ ...terms, commitmentFeeratePerKw: feerate },
			s,
			htlcs,
			candidate.isInitiator,
			[true, true]
		);
	}
	return { htlcs, next, feerate, signedChanges };
}
