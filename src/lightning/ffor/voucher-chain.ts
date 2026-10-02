import { IChainMonitorState } from '../chain/chain-monitor';
import {
	CommitmentType,
	IRREVOCABLE_DEPTH,
	ITrackedOutput,
	OutputStatus,
	OutputType
} from '../chain/types';
import {
	fforChainReceiptId,
	IFforVoucherArchive,
	IFforVoucherChainResolution,
	mergeFforVoucherArchive
} from './voucher-archive';

/** Preserve observed proof and archive final value with its owning monitor write. */
export function archiveFforChainEvidence(
	record: IFforVoucherArchive,
	monitor: IChainMonitorState
): IFforVoucherArchive {
	if (record.role !== 'R') return record;
	const broadcast = monitor.commitmentBroadcast;
	if (
		!broadcast ||
		![
			CommitmentType.OUR_COMMITMENT,
			CommitmentType.THEIR_CURRENT_COMMITMENT
		].includes(broadcast.commitmentType)
	)
		return record;
	const final = (output: ITrackedOutput): boolean =>
		output.status === OutputStatus.IRREVOCABLY_RESOLVED &&
		!!output.resolutionTxid &&
		!output.spendReverifyPending &&
		output.confirmationHeight > 0 &&
		monitor.currentBlockHeight - output.confirmationHeight >= IRREVOCABLE_DEPTH;
	let next = record;
	for (const output of monitor.trackedOutputs) {
		const spend = output.receivedHtlcSpend;
		if (
			output.outputType !== OutputType.RECEIVED_HTLC ||
			output.txid !== broadcast.txid ||
			output.htlcId?.toString() !== record.htlcId ||
			output.paymentHash?.toString('hex') !== record.paymentHash ||
			output.amount !== BigInt(record.amountMsat) / 1000n ||
			output.cltvExpiry !== record.voucherExpiry ||
			!spend ||
			output.resolutionTxid !== spend.txid
		)
			continue;
		const observation = {
			outputTxid: output.txid,
			outputIndex: output.outputIndex,
			spendingTxid: spend.txid,
			...(spend.preimage ? { preimage: spend.preimage } : {})
		};
		next = mergeFforVoucherArchive(next, {
			...next,
			...(spend.preimage ? { preimage: spend.preimage } : {}),
			chainObservations: [observation]
		});
		if (
			!final(output) ||
			next.chainResolutions?.some(
				(r) => fforChainReceiptId(r) === fforChainReceiptId(observation)
			)
		)
			continue;
		let secondLevel: IFforVoucherChainResolution['secondLevel'];
		if (
			spend.preimage &&
			broadcast.commitmentType === CommitmentType.OUR_COMMITMENT
		) {
			// The monitor only adopts this output after verifying our success
			// template. A CSV claim is not yet a final sweep to the receiver.
			const descendant = monitor.trackedOutputs.find(
				(o) =>
					o.txid === spend.txid && o.outputIndex === 0 && o.isSecondLevelHtlc
			);
			if (!descendant || !final(descendant)) continue;
			secondLevel = {
				outputIndex: descendant.outputIndex,
				spendingTxid: descendant.resolutionTxid!,
				confirmationHeight: descendant.confirmationHeight
			};
		}
		next = mergeFforVoucherArchive(next, {
			...next,
			chainResolutions: [
				{
					...observation,
					confirmationHeight: output.confirmationHeight,
					finalizedHeight: monitor.currentBlockHeight,
					amountMsat: (output.amount * 1000n).toString(),
					...(secondLevel ? { secondLevel } : {})
				}
			]
		});
	}
	return next;
}
