import { Transaction } from 'bitcoinjs-lib';
import {
	publishableAssetSpliceEvidence,
	type AssetSpliceExitEvent
} from './asset-splice-exit-proofs';

/** Select the latest common logical height across every possibly spendable funding output. */
export function assetSpliceFundingExits(
	records: readonly AssetSpliceExitEvent[],
	channelId: string,
	openingTxid: string,
	openingIndex: number,
	openingRoot: string,
	openingExit?: string
): string[] {
	const receipts = publishableAssetSpliceEvidence(records, channelId);
	const opening = openingTxid + ':' + openingIndex;
	const parents = new Map<string, string>([[opening, '']]);
	const views = new Map<
		string,
		{
			height: bigint;
			root: string;
			local: string;
			localTxid: string;
			remote: string;
		}
	>();
	let latest = 0n;
	for (const receipt of receipts) {
		const parent =
			receipt.parent.fundingTxid + ':' + receipt.parent.outputIndex;
		const next =
			receipt.candidate.fundingTxid + ':' + receipt.candidate.outputIndex;
		if (
			!parents.has(parent) ||
			(parents.has(next) && parents.get(next) !== parent)
		)
			throw new Error(
				'Asset splice exit is outside the enrolled funding history'
			);
		parents.set(next, parent);
		const height = BigInt(receipt.stateNumber);
		if (height > latest) latest = height;
		for (const [i, branch] of [receipt.parent, receipt.candidate].entries()) {
			const key = i === 0 ? parent : next;
			const prior = views.get(key);
			const localTxid = Transaction.fromHex(branch.localCommitment).getId();
			if (
				key === opening &&
				(branch.fundingRoot !== openingRoot ||
					(height === 0n &&
						(!openingExit ||
							localTxid !== Transaction.fromHex(openingExit).getId())))
			)
				throw new Error(
					'Asset splice parent differs from its enrolled opening'
				);
			if (
				prior &&
				(prior.root !== branch.fundingRoot ||
					(prior.height === height &&
						(prior.localTxid !== localTxid ||
							prior.remote !== branch.remoteCommitment)))
			)
				throw new Error(
					'Conflicting commitments for the same asset funding output and height'
				);
			// Fresh MuSig2 nonces can produce a different valid witness for the same transaction.
			if (!prior || height > prior.height)
				views.set(key, {
					height,
					root: branch.fundingRoot,
					local: branch.localCommitment,
					localTxid,
					remote: branch.remoteCommitment
				});
		}
	}
	const exits: string[] = [];
	for (const view of views.values()) {
		if (view.height !== latest)
			throw new Error(
				'A live asset funding output lacks the latest commitment'
			);
		exits.push(view.local);
	}
	return exits;
}
