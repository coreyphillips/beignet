import { assetUpdateHistory } from '../storage/asset-update-history';
import { Transaction } from 'bitcoinjs-lib';
import type { IAssetOpeningPayout } from '../channel/asset-opening-provider';
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
				if (
					history?.stages.has(
						BigInt(updated.height) +
							1n +
							'/' +
							(local ? 'local-revoke' : 'peer-revoke')
					)
				)
					return [];
				return [
					{
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

	const retained = storage.canSpliceDualFundedAssets
		? publishableAssetSpliceEvidence(
				storage.readAssetSpliceJournal<AssetSpliceExitEvent>(id).records,
				id
		  )
		: [];
	const holders = ['local', 'remote'] as const;
	const revoked = (height: string, holder: 'local' | 'remote') =>
		history?.stages.has(
			BigInt(height) +
				1n +
				'/' +
				(holder === 'local' ? 'local-revoke' : 'peer-revoke')
		);
	if (!retained.length)
		return holders.flatMap((holder) => {
			if (revoked('0', holder)) return [];
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
				if (tx.getId() !== parent.getId() || revoked(entry.stateNumber, holder))
					return [];
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
	return first ? [first] : [];
}
