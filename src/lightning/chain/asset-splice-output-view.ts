import { decodeRevokeAndAckMessage } from '../message/channel-commitment';
import {
	assetUpdateHistory,
	inFlightAssetUpdates,
	type IAssetUpdatePeerExit
} from '../storage/asset-update-history';
import { Transaction } from 'bitcoinjs-lib';
import type {
	IAssetOpeningPayout,
	IAssetFundingLineageEntry
} from '../channel/asset-opening-provider';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import {
	buildAssetOpeningCommitment,
	type IFinalOpeningTerms
} from '../channel/final-opening-commitment';
import { assetOpeningLeaves } from '../storage/asset-opening-evidence';
import {
	publishableAssetSpliceEvidence,
	type AssetSpliceExitEvent,
	type IAssetSpliceExitBranch
} from '../storage/asset-splice-exit-proofs';
import { spliceRecoveryView } from '../storage/asset-splice-recovery';
import type { SqliteStorage } from '../storage/sqlite-storage';
import type { IAssetOpeningEvidence } from '../storage/asset-opening-evidence';
import type {
	IAssetSpliceLeaves,
	IFinalCommitmentView
} from '../channel/final-opening-commitment';
import { assetEraHistory } from '../storage/asset-update-history';
import {
	finalBranchReaders,
	type IFinalBranchReaders,
	type IFinalChannelFunding
} from '../storage/final-branch-readers';
import {
	branchCommitmentType,
	conversionRecoveryView,
	conversionViewContext
} from '../storage/final-conversion-exits';
import { fundingOutpoint } from '../storage/final-channel-type';
import { spendsBranch } from './final-spend-branch';

type History = ReturnType<typeof assetUpdateHistory>;
type Protection = { revoked: Buffer | undefined } | undefined;
type Authority = (
	height: string,
	holder: 'local' | 'remote',
	point: string
) => Protection;

/** A matched asset commitment, with the views and proofs its claims need. */
export interface IAssetPayoutMatch {
	revoked: Buffer | undefined;
	view: IFinalCommitmentView;
	assets: IAssetSpliceLeaves;
	holder: 'local' | 'remote';
	point: Buffer;
	state: bigint;
	fundingProofs: string;
	exitProofs: string;
	splice: IAssetOpeningPayout['splice'];
	update: IAssetOpeningPayout['update'];
	/** A branch's host lineage, era history, and whether it is a pending conversion's candidate (#2151 step 2b). */
	lineage?: IAssetFundingLineageEntry[];
	history?: History;
	conversion?: boolean;
}

/**
 * Match an observed commitment to its asset state. With a branch (#2151
 * step 2b), the match is within that branch's era, its secrets come from the
 * store over every ledger, and a pending conversion's candidate is matched
 * by its branch alone.
 */
export function matchedAssetPayoutViews(
	storage: SqliteStorage,
	id: string,
	parent: Transaction,
	branch?: IFinalChannelFunding
): IAssetPayoutMatch[] {
	if (branch) return branchPayoutViews(storage, id, parent, branch);
	const opening = storage.loadFinalOpening(id),
		session = storage.loadFinalOpeningSession(id);
	// A recorded channel is matched by branch (#2151 step 2b).
	if (
		!opening ||
		!session?.assetEvidence ||
		storage.loadFinalChannelTypeRecords(id).length
	)
		return [];
	const evidence = session.assetEvidence;
	const history = storage.canSpliceDualFundedAssets
		? assetUpdateHistory(storage, id)
		: undefined;
	// A received revocation names the preceding logical height. The caller
	// checks its secret against the point of the matched commitment.
	const authority = (height: string, holder: 'local' | 'remote') => {
		const wire = history?.stages.get(
			BigInt(height) +
				1n +
				'/' +
				(holder === 'local' ? 'local-revoke' : 'peer-revoke')
		);
		if (!wire) return { revoked: undefined as Buffer | undefined };
		if (holder !== 'remote' || !storage.canRecoverAssetSplice) return;
		const msg = decodeRevokeAndAckMessage(Buffer.from(wire, 'hex'), {
			finalTaproot: true
		});
		if (msg.channelId.toString('hex') !== id)
			throw Error('Asset payout revocation names a different channel');
		return { revoked: msg.perCommitmentSecret };
	};
	return openingEraViews(
		storage,
		id,
		parent,
		opening,
		session.terms,
		evidence,
		history,
		authority
	);
}

/** The opening era's match: its secured and in-flight rounds, its retained splices, and the opening at state 0. */
function openingEraViews(
	storage: SqliteStorage,
	id: string,
	parent: Transaction,
	opening: IFinalOpeningCandidate,
	terms: IFinalOpeningTerms,
	evidence: IAssetOpeningEvidence,
	history: History | undefined,
	authority: Authority
): IAssetPayoutMatch[] {
	const session = { terms };
	for (const updated of [...(history?.states.values() ?? [])].reverse()) {
		for (const b of updated.members) {
			if (
				parent.ins.length !== 1 ||
				parent.ins[0].index !== b.outputIndex ||
				!parent.ins[0].hash.equals(Buffer.from(b.fundingTxid, 'hex').reverse())
			)
				continue;
			for (const holder of ['local', 'remote'] as const) {
				const local = holder === 'local',
					commit = Transaction.fromHex(
						local ? b.localCommitment : b.remoteCommitment
					);
				if (commit.getId() !== parent.getId()) continue;
				const protection = authority(
					updated.height,
					holder,
					local ? b.localRecovery.point : b.remoteRecovery.point
				);
				if (!protection) return [];
				return [
					{
						...protection,
						...spliceRecoveryView(
							opening,
							{ ...session.terms, commitmentFeeratePerKw: updated.feerate },
							evidence.fundingRoot,
							b,
							holder,
							updated.height
						),
						holder,
						state: BigInt(updated.height),
						fundingProofs: b.fundingProofs,
						exitProofs: local ? b.localProofs : b.remoteProofs,
						splice: undefined as IAssetOpeningPayout['splice'],
						update: {
							roundDigest: updated.digest,
							stateNumber: updated.height,
							fundingTxid: b.fundingTxid,
							fundingOutputIndex: b.outputIndex
						}
					}
				];
			}
		}
	}

	// The peer holds our signature for its commitment in a round we have not
	// secured. It is the peer's current state on that member.
	for (const [height, round] of history ? inFlightAssetUpdates(history) : []) {
		for (const b of round.members) {
			if (
				parent.ins.length !== 1 ||
				parent.ins[0].index !== b.outputIndex ||
				!parent.ins[0].hash.equals(
					Buffer.from(b.fundingTxid, 'hex').reverse()
				) ||
				Transaction.fromHex(b.remoteCommitment).getId() !== parent.getId()
			)
				continue;
			const protection = authority(
				String(height),
				'remote',
				b.remoteRecovery.point
			);
			if (!protection) return [];
			return [
				{
					...protection,
					...spliceRecoveryView(
						opening,
						{ ...session.terms, commitmentFeeratePerKw: round.feerate },
						evidence.fundingRoot,
						b,
						'remote',
						String(height)
					),
					holder: 'remote' as const,
					state: height,
					fundingProofs: b.fundingProofs,
					exitProofs: b.remoteProofs,
					splice: undefined as IAssetOpeningPayout['splice'],
					update: {
						roundDigest: round.digest,
						stateNumber: String(height),
						fundingTxid: b.fundingTxid,
						fundingOutputIndex: b.outputIndex
					}
				}
			];
		}
	}

	const retained = storage.canSpliceDualFundedAssets
		? publishableAssetSpliceEvidence(
				storage.readAssetSpliceJournal<AssetSpliceExitEvent>(id).records,
				id
		  )
		: [];
	const holders = ['local', 'remote'] as const;
	// The opening commitment spends the original outpoint at state 0. A splice
	// signed from a later state keeps no copy of it, so it is matched here by
	// its exact txid whenever no retained splice commitment matches.
	const openingMatch = () =>
		holders.flatMap((holder) => {
			const protection = authority(
				'0',
				holder,
				(holder === 'local'
					? session.terms.localBasepoints
					: session.terms.remoteBasepoints
				).firstPerCommitmentPoint
			);
			if (!protection) return [];
			const assets = assetOpeningLeaves(evidence, holder);
			const view = buildAssetOpeningCommitment(
				opening,
				session.terms,
				holder,
				assets
			);
			return view.tx.getId() === parent.getId()
				? [
						{
							...protection,
							view,
							assets,
							holder,
							point: Buffer.from(
								(holder === 'local'
									? session.terms.localBasepoints
									: session.terms.remoteBasepoints
								).firstPerCommitmentPoint,
								'hex'
							),
							state: 0n,
							fundingProofs: evidence.fundingProofs,
							exitProofs: evidence[holder].proofs,
							splice: undefined as IAssetOpeningPayout['splice'],
							update: undefined as IAssetOpeningPayout['update']
						}
				  ]
				: [];
		});
	if (!retained.length) return openingMatch();
	const matches = retained.flatMap((entry) =>
		(['parent', 'candidate'] as const).flatMap((generation) => {
			const b = entry[generation];
			if (
				parent.ins.length !== 1 ||
				parent.ins[0].index !== b.outputIndex ||
				!parent.ins[0].hash.equals(Buffer.from(b.fundingTxid, 'hex').reverse())
			)
				return [];
			return holders.flatMap((holder) => {
				const local = holder === 'local';
				const tx = Transaction.fromHex(
					local ? b.localCommitment : b.remoteCommitment
				);
				if (tx.getId() !== parent.getId()) return [];
				const protection = authority(
					entry.stateNumber,
					holder,
					local ? b.localRecovery.point : b.remoteRecovery.point
				);
				if (!protection) return [];
				const state =
					entry.priorDigest && history?.states.get(BigInt(entry.stateNumber));
				if (entry.priorDigest && (!state || state.digest !== entry.priorDigest))
					throw Error(
						'Historical asset splice is missing its signed predecessor'
					);
				const built = spliceRecoveryView(
					opening,
					state
						? { ...session.terms, commitmentFeeratePerKw: state.feerate }
						: session.terms,
					evidence.fundingRoot,
					b,
					holder,
					entry.stateNumber
				);
				return [
					{
						...built,
						...protection,
						holder,
						state: BigInt(entry.stateNumber),
						fundingProofs: b.fundingProofs,
						exitProofs: local ? b.localProofs : b.remoteProofs,
						update: undefined as IAssetOpeningPayout['update'],
						splice: {
							finalDigest: entry.finalDigest,
							stateNumber: entry.stateNumber,
							generation,
							fundingTxid: b.fundingTxid,
							fundingOutputIndex: b.outputIndex
						}
					}
				];
			});
		})
	);
	const first = matches[0];
	if (
		first &&
		matches.some(
			(m) =>
				m.holder !== first.holder ||
				m.state !== first.state ||
				m.fundingProofs !== first.fundingProofs ||
				m.exitProofs !== first.exitProofs
		)
	)
		throw new Error('Ambiguous retained proof for watched asset commitment');
	return first ? [first] : openingMatch();
}

const holders = ['local', 'remote'] as const;

/** The store's protection of a branch's commitment: a peer one revoked by any ledger's secret, our own never claimed once revoked. */
function storeAuthority(
	readers: IFinalBranchReaders,
	id: string,
	era: number,
	history: History
): Authority {
	return (height, holder, point) => {
		const h = BigInt(height);
		if (holder === 'local')
			return history.stages.has(h + 1n + '/local-revoke') ||
				readers.finalOwnCommitmentRevoked(id, era, h)
				? undefined
				: { revoked: undefined };
		return {
			revoked:
				readers.loadFinalPeerSecret(id, h, Buffer.from(point, 'hex')).secret ??
				undefined
		};
	};
}

function branchPayoutViews(
	storage: SqliteStorage,
	id: string,
	parent: Transaction,
	branch: IFinalChannelFunding
): IAssetPayoutMatch[] {
	const readers = finalBranchReaders(storage);
	const opening = storage.loadFinalOpening(id),
		session = storage.loadFinalOpeningSession(id);
	if (
		!readers ||
		!opening ||
		!session ||
		branch.type !== 'asset' ||
		!spendsBranch(parent, branch)
	)
		return [];
	const openingRoot = session.assetEvidence?.fundingRoot;
	if (branch.source === 'conversion') {
		// A pending candidate is matched by its branch alone: no journal read,
		// the commitments at the conversion's height, and no revoked state.
		const exits = readers.finalConversion(id, branch.digest ?? '');
		const b = exits?.candidate;
		if (!exits || b?.type !== 'asset') return [];
		const ctx = conversionViewContext(opening, session.terms, openingRoot);
		for (const holder of holders) {
			const local = holder === 'local';
			const tx = Transaction.fromHex(
				local ? b.localCommitment : b.remoteCommitment
			);
			if (tx.getId() !== parent.getId()) continue;
			const built = conversionRecoveryView(ctx, b, holder, exits.stateNumber);
			if (built.type !== 'asset') return [];
			return [
				{
					revoked: undefined,
					view: built.view,
					assets: built.assets,
					point: built.point,
					holder,
					state: BigInt(exits.stateNumber),
					fundingProofs: b.fundingProofs,
					exitProofs: local ? b.localProofs : b.remoteProofs,
					update: undefined,
					splice: {
						finalDigest: exits.digest,
						stateNumber: exits.stateNumber,
						generation: 'candidate',
						fundingTxid: b.fundingTxid,
						fundingOutputIndex: b.outputIndex
					},
					conversion: true,
					// Its parent is plain, so the asset lineage starts at the candidate.
					lineage: [
						{
							parentTxid: exits.parent.fundingTxid,
							parentOutputIndex: exits.parent.outputIndex,
							fundingTxid: b.fundingTxid,
							fundingOutputIndex: b.outputIndex,
							fundingTxHex: b.funding.fundingTxHex
						}
					]
				}
			];
		}
		return [];
	}
	const era = branch.era ?? 0;
	const history = assetEraHistory(storage, id, era);
	const authority = storeAuthority(readers, id, era, history);
	if (era === 0) {
		if (!session.assetEvidence) return [];
		return openingEraViews(
			storage,
			id,
			parent,
			opening,
			session.terms,
			session.assetEvidence,
			history,
			authority
		).map((m) => ({ ...m, history }));
	}
	// A seeded asset era: its seed at N and its later rounds, on the record's
	// funding, whose lineage starts at the record's edge.
	const record = readers.finalEraRecords(id)[era - 1];
	if (!record || record.type !== 'asset') return [];
	const as = branchCommitmentType(
		record.channelType,
		openingRoot ? Buffer.from(openingRoot, 'hex') : undefined
	);
	const base = fundingOutpoint(record.funding);
	const prefix: IAssetFundingLineageEntry[] = [
		{
			parentTxid: record.parent.txid,
			parentOutputIndex: record.parent.outputIndex,
			fundingTxid: base.txid,
			fundingOutputIndex: base.outputIndex,
			fundingTxHex: record.funding.fundingTxHex
		}
	];
	const matched = (
		b: IAssetUpdatePeerExit & Partial<IAssetSpliceExitBranch>,
		holder: 'local' | 'remote',
		height: string,
		feerate: number,
		digest: string
	): IAssetPayoutMatch[] => {
		const local = holder === 'local';
		const protection = authority(
			height,
			holder,
			local ? b.localRecovery!.point : b.remoteRecovery.point
		);
		if (!protection) return [];
		return [
			{
				...protection,
				...spliceRecoveryView(
					opening,
					{ ...session.terms, commitmentFeeratePerKw: feerate },
					openingRoot ?? '',
					b,
					holder,
					height,
					as
				),
				holder,
				state: BigInt(height),
				fundingProofs: b.fundingProofs,
				exitProofs: local ? b.localProofs! : b.remoteProofs,
				splice: undefined,
				update: {
					roundDigest: digest,
					stateNumber: height,
					fundingTxid: b.fundingTxid,
					fundingOutputIndex: b.outputIndex
				},
				history,
				lineage: retainedAssetFundingLineage(
					storage,
					id,
					opening,
					b.fundingTxid,
					b.outputIndex,
					{ ...base, prefix }
				)
			}
		];
	};
	for (const updated of [...history.states.values()].reverse())
		for (const b of updated.members) {
			if (b.fundingTxid !== branch.txid || b.outputIndex !== branch.outputIndex)
				continue;
			for (const holder of holders) {
				const tx = Transaction.fromHex(
					holder === 'local' ? b.localCommitment : b.remoteCommitment
				);
				if (tx.getId() === parent.getId())
					return matched(
						b,
						holder,
						updated.height,
						updated.feerate,
						updated.digest
					);
			}
		}
	for (const [height, round] of inFlightAssetUpdates(history))
		for (const b of round.members)
			if (
				b.fundingTxid === branch.txid &&
				b.outputIndex === branch.outputIndex &&
				Transaction.fromHex(b.remoteCommitment).getId() === parent.getId()
			)
				return matched(
					b,
					'remote',
					String(height),
					round.feerate,
					round.digest
				);
	return [];
}

/** Follow only released candidate funding outpoints back to the enrolled opening.
 * The peer can finish the witness after the local share was sent and before the
 * signed transaction was recorded. The authorized txid still binds that template.
 */
export function retainedAssetFundingLineage(
	storage: SqliteStorage,
	id: string,
	opening: IFinalOpeningCandidate,
	fundingTxid: string,
	fundingOutputIndex: number,
	base?: {
		txid: string;
		outputIndex: number;
		prefix: IAssetFundingLineageEntry[];
	}
): IAssetFundingLineageEntry[] {
	if (!storage.canRecoverAssetSplice || opening.channelId !== id)
		throw Error('Asset payout lineage requires the original recovery wallet');
	// The era base: the opening for era 0, a seeded asset era's record funding
	// with its own edge first (#2151 step 2b).
	const original = base
		? base.txid + ':' + base.outputIndex
		: Transaction.fromHex(opening.fundingTxHex).getId() +
		  ':' +
		  opening.fundingOutputIndex;
	let outpoint = fundingTxid + ':' + fundingOutputIndex;
	if (outpoint === original) return (base?.prefix ?? []).map((e) => ({ ...e }));
	type Stage = { kind: 'peer-splice-stage'; field: string; hex: string };
	const { records } = storage.readAssetSpliceJournal<
		AssetSpliceExitEvent | Stage
	>(id);
	const releases = new Set<string>();
	const assembled = new Map<string, string>();
	const phases = records.filter(
		(r): r is AssetSpliceExitEvent => r.kind !== 'peer-splice-stage'
	);
	for (const row of records) {
		if (row.kind === 'funding-released') releases.add(row.finalDigest);
		if (row.kind !== 'peer-splice-stage' || row.field !== 'assembled') continue;
		const txid = Transaction.fromHex(row.hex).getId();
		if (assembled.has(txid) && assembled.get(txid) !== row.hex)
			throw Error('Conflicting signed asset splice funding transactions');
		assembled.set(txid, row.hex);
	}
	const candidates = new Map<string, IAssetFundingLineageEntry>();
	for (const e of publishableAssetSpliceEvidence(phases, id)) {
		if (!releases.has(e.finalDigest)) continue;
		const { parent, candidate } = e;
		const edge = {
			parentTxid: parent.fundingTxid,
			parentOutputIndex: parent.outputIndex,
			fundingTxid: candidate.fundingTxid,
			fundingOutputIndex: candidate.outputIndex,
			fundingTxHex:
				assembled.get(candidate.fundingTxid) ?? candidate.funding.fundingTxHex
		};
		const key = edge.fundingTxid + ':' + edge.fundingOutputIndex;
		if (candidates.has(key))
			throw Error('Ambiguous released asset splice lineage');
		candidates.set(key, edge);
	}
	const path: IAssetFundingLineageEntry[] = [];
	while (outpoint !== original) {
		const edge = candidates.get(outpoint);
		if (!edge) throw Error('Missing released asset splice funding lineage');
		candidates.delete(outpoint);
		const tx = Transaction.fromHex(edge.fundingTxHex);
		if (
			tx.getId() !== edge.fundingTxid ||
			!tx.outs[edge.fundingOutputIndex] ||
			tx.ins.filter(
				(i) =>
					i.index === edge.parentOutputIndex &&
					i.hash.equals(Buffer.from(edge.parentTxid, 'hex').reverse())
			).length !== 1
		)
			throw Error('Released asset splice differs from its parent outpoint');
		path.push(edge);
		outpoint = edge.parentTxid + ':' + edge.parentOutputIndex;
	}
	return [...(base?.prefix ?? []).map((e) => ({ ...e })), ...path.reverse()];
}
