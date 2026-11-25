import { MAX_ACCEPTED_HTLCS } from './types';
import { assertFinalTaprootHtlcExpiry } from '../script/commitment-taproot';

type Owner = 'initiator' | 'acceptor';

interface IIssuance {
	assetId: string;
	funding: bigint;
	initiator: bigint;
	acceptor: bigint;
}

interface IHtlc {
	offeredBy: Owner;
	id: bigint;
	paymentHash: string;
	cltvExpiry: number;
	amountMsat: bigint;
	allocations: readonly { assetId: string; units: bigint }[];
}

export interface IAssetSpliceBalanceState {
	issuances: readonly IIssuance[];
	htlcs: readonly IHtlc[];
}

export interface IAssetSpliceUnitMovement {
	assetId: string;
	owner: Owner;
	inputs: bigint;
	change: bigint;
	withdrawals: bigint;
	delta: bigint;
}

export interface IAssetSpliceBalancePlan {
	parent: IAssetSpliceBalanceState;
	candidate: IAssetSpliceBalanceState;
	spendable: readonly Omit<IIssuance, 'funding'>[];
}

function validId(id: string): boolean {
	return typeof id === 'string' && id.length === 64 && /^[0-9a-f]+$/.test(id);
}

function uint64(n: bigint): boolean {
	return typeof n === 'bigint' && n >= 0n && n <= 0xffffffffffffffffn;
}

function byIssuance(a: { assetId: string }, b: { assetId: string }): number {
	return a.assetId < b.assetId ? -1 : a.assetId > b.assetId ? 1 : 0;
}

function emptyIssuance(assetId: string): IIssuance {
	return { assetId, funding: 0n, initiator: 0n, acceptor: 0n };
}

/** Each obligation is identified by its offerer and ID, including plain HTLCs. */
function snapshotHtlcs(
	htlcs: readonly IHtlc[],
	locked: Map<string, bigint>
): IHtlc[] {
	const seen = { initiator: new Set<bigint>(), acceptor: new Set<bigint>() };
	return htlcs.map((h) => {
		if (
			(h.offeredBy !== 'initiator' && h.offeredBy !== 'acceptor') ||
			!uint64(h.id) ||
			!uint64(h.amountMsat) ||
			h.amountMsat === 0n ||
			!validId(h.paymentHash) ||
			seen[h.offeredBy].has(h.id) ||
			seen[h.offeredBy].size >= MAX_ACCEPTED_HTLCS
		)
			throw new Error('Invalid splice HTLC');
		assertFinalTaprootHtlcExpiry(h.cltvExpiry);
		seen[h.offeredBy].add(h.id);
		const ids = new Set<string>();
		const allocations = h.allocations
			.map(({ assetId, units }) => {
				const total = locked.get(assetId);
				if (
					total === undefined ||
					ids.has(assetId) ||
					!uint64(units) ||
					units === 0n
				)
					throw new Error('Invalid splice HTLC allocation');
				ids.add(assetId);
				locked.set(assetId, total + units);
				return { assetId, units };
			})
			.sort(byIssuance);
		return { ...h, allocations };
	});
}

/** Project one authorized splice in initiator order. Each funding output keeps its own inventory. */
export function planAssetSpliceBalances(
	parent: IAssetSpliceBalanceState,
	movements: readonly IAssetSpliceUnitMovement[]
): IAssetSpliceBalancePlan {
	const old = new Map<string, IIssuance>();
	const locked = new Map<string, bigint>();
	for (const row of parent.issuances) {
		const { assetId, funding, initiator, acceptor } = row;
		if (
			!validId(assetId) ||
			old.has(assetId) ||
			!uint64(funding) ||
			funding === 0n ||
			!uint64(initiator) ||
			!uint64(acceptor)
		)
			throw new Error('Invalid splice parent issuance');
		old.set(assetId, { assetId, funding, initiator, acceptor });
		locked.set(assetId, 0n);
	}
	if (!old.size) throw new Error('Missing parent asset inventory');
	const htlcs = snapshotHtlcs(parent.htlcs, locked);
	const next = new Map<string, IIssuance>();
	const available = new Map<string, Omit<IIssuance, 'funding'>>();
	for (const row of old.values()) {
		if (row.funding !== row.initiator + row.acceptor + locked.get(row.assetId)!)
			throw new Error(
				'Parent free and unresolved units differ from its funded issuance'
			);
		next.set(row.assetId, { ...row });
		available.set(row.assetId, {
			assetId: row.assetId,
			initiator: row.initiator,
			acceptor: row.acceptor
		});
	}
	const seen = new Set<string>();
	for (const m of movements) {
		const { assetId, owner, inputs, change, withdrawals, delta } = m;
		if (
			!validId(assetId) ||
			(owner !== 'initiator' && owner !== 'acceptor') ||
			!uint64(inputs) ||
			!uint64(change) ||
			!uint64(withdrawals) ||
			change > inputs ||
			withdrawals > (old.get(assetId)?.[owner] ?? 0n) ||
			delta !== inputs - change - withdrawals ||
			seen.has(assetId + owner)
		)
			throw new Error('Invalid owner or per-issuance splice movement');
		seen.add(assetId + owner);
		const row = next.get(assetId) ?? emptyIssuance(assetId);
		row[owner] += delta;
		row.funding += delta;
		next.set(assetId, row);
		const spendable = available.get(assetId) ?? {
			assetId,
			initiator: 0n,
			acceptor: 0n
		};
		spendable[owner] -= withdrawals;
		available.set(assetId, spendable);
	}
	for (const row of next.values()) {
		if (!old.has(row.assetId) && row.funding === 0n)
			throw new Error(
				'Splice movement names an issuance absent from both funding outputs'
			);
	}
	const candidateRows = [...next.values()].filter((row) => row.funding !== 0n);
	if (
		!candidateRows.length ||
		candidateRows.some((row) => !uint64(row.funding))
	)
		throw new Error('Invalid candidate asset inventory');
	return {
		parent: { issuances: [...old.values()].sort(byIssuance), htlcs },
		candidate: {
			issuances: candidateRows.sort(byIssuance),
			htlcs: htlcs.map((h) => ({
				...h,
				allocations: h.allocations.map((a) => ({ ...a }))
			}))
		},
		spendable: [...available.values()].sort(byIssuance)
	};
}
