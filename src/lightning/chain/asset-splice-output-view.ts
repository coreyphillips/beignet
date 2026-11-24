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
	const retained = storage.canSpliceDualFundedAssets
		? publishableAssetSpliceEvidence(
				storage.readAssetSpliceJournal<AssetSpliceExitEvent>(id).records,
				id
		  )
		: [];
	const holders = ['local', 'remote'] as const;
	if (!retained.length)
		return holders.flatMap((holder) => {
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
							splice: undefined as IAssetOpeningPayout['splice']
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
				if (tx.getId() !== parent.getId()) return [];
				const built = spliceRecoveryView(
					opening,
					session.terms,
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
