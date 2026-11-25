import { decodeRevokeAndAckMessage } from '../message/channel-commitment';
import {
	assetUpdateHistory,
	inFlightAssetUpdates
} from '../storage/asset-update-history';
import { Transaction } from 'bitcoinjs-lib';
import type {
	IAssetOpeningPayout,
	IAssetFundingLineageEntry
} from '../channel/asset-opening-provider';
import type { IFinalOpeningCandidate } from '../storage/final-opening-candidate';
import { buildAssetOpeningCommitment } from '../channel/final-opening-commitment';
import { assetOpeningLeaves } from '../storage/asset-opening-evidence';
import {
	publishableAssetSpliceEvidence,
	type AssetSpliceExitEvent
} from '../storage/asset-splice-exit-proofs';
import { spliceRecoveryView } from '../storage/asset-splice-recovery';
import type { SqliteStorage } from '../storage/sqlite-storage';

export function matchedAssetPayoutViews(
	storage: SqliteStorage,
	id: string,
	parent: Transaction
) {
	const opening = storage.loadFinalOpening(id),
		session = storage.loadFinalOpeningSession(id);
	if (!opening || !session?.assetEvidence) return [];
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
				const protection = authority(updated.height, holder);
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
			const protection = authority(String(height), 'remote');
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
			const protection = authority('0', holder);
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
				const protection = authority(entry.stateNumber, holder);
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

/** Follow only released candidate funding outpoints back to the enrolled opening.
 * The peer can finish the witness after the local share was sent and before the
 * signed transaction was recorded. The authorized txid still binds that template.
 */
export function retainedAssetFundingLineage(
	storage: SqliteStorage,
	id: string,
	opening: IFinalOpeningCandidate,
	fundingTxid: string,
	fundingOutputIndex: number
): IAssetFundingLineageEntry[] {
	if (!storage.canRecoverAssetSplice || opening.channelId !== id)
		throw Error('Asset payout lineage requires the original recovery wallet');
	const original =
		Transaction.fromHex(opening.fundingTxHex).getId() +
		':' +
		opening.fundingOutputIndex;
	let outpoint = fundingTxid + ':' + fundingOutputIndex;
	if (outpoint === original) return [];
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
	return path.reverse();
}
