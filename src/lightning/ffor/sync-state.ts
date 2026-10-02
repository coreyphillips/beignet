import crypto from 'crypto';
import {
	decodeFforHeader,
	decodeFforSyncMessage,
	decodeFforSyncReplyMessage,
	verifyFforMessage
} from './messages';
import {
	FF_SYNC_TYPE,
	FF_SYNC_REPLY_TYPE,
	FforSlotState,
	IFforEpochRecord,
	isFforConcurrentVersion
} from './types';

/** A persisted snapshot is progress evidence, so a damaged record is never empty. */
export function validateFforSyncState(record: IFforEpochRecord): void {
	const wires = [
		record.syncRequestWire,
		record.syncSnapshotWire,
		record.syncConflictWire
	];
	if (!wires.some(Boolean) && !record.slotRedeemed) return;
	if (!isFforConcurrentVersion(record.concurrentVersion))
		throw new Error('Receipt sync state requires a concurrent epoch');
	if (
		record.slotRedeemed &&
		(record.role !== 'S' ||
			record.slotRedeemed.length !== record.params.maxPayments ||
			record.slotRedeemed.some((value) => typeof value !== 'boolean'))
	)
		throw new Error('Invalid voucher redemption state');
	const channelId = decodeFforHeader(record.initWire.subarray(2)).channelId;
	for (let i = 0; i < wires.length; i++) {
		const wire = wires[i];
		if (!wire) continue;
		const type = i === 0 ? FF_SYNC_TYPE : FF_SYNC_REPLY_TYPE;
		if (
			wire.length < 2 ||
			wire.length > 0xffff ||
			wire.readUInt16BE(0) !== type
		)
			throw new Error('Invalid persisted receipt sync wire');
		const msg =
			i === 0
				? decodeFforSyncMessage(wire.subarray(2))
				: decodeFforSyncReplyMessage(wire.subarray(2));
		if (
			!record.hAct ||
			!msg.channelId.equals(channelId) ||
			!msg.epochId.equals(record.epochId) ||
			!msg.activationHash.equals(record.hAct)
		)
			throw new Error('Persisted receipt sync identity mismatch');
		if (i === 0) {
			if (record.role !== 'R' || record.closeAckWire)
				throw new Error('Invalid outstanding receipt fetch');
			continue;
		}
		const snapshot = decodeFforSyncReplyMessage(wire.subarray(2));
		if (
			snapshot.numSlots !== record.params.maxPayments ||
			(snapshot.snapshotSeq === 0n && snapshot.preimages.length > 0)
		)
			throw new Error('Invalid persisted receipt snapshot');
		if (
			record.role === 'R' &&
			!verifyFforMessage(type, wire.subarray(2), record.remoteNodeId)
		)
			throw new Error('Invalid persisted receipt signature');
		if (i === 2 && record.role !== 'R')
			throw new Error('Invalid receipt conflict role');
		for (const proof of snapshot.preimages) {
			if (
				!crypto
					.createHash('sha256')
					.update(proof.preimage)
					.digest()
					.equals(record.paymentHashes[proof.k - 1])
			)
				throw new Error('Persisted receipt proof mismatch');
			if (
				record.role === 'R' &&
				!record.knownPreimages[proof.k - 1]?.equals(proof.preimage)
			)
				throw new Error('Persisted receipt lost its claim proof');
			if (
				record.role === 'S' &&
				record.slotStates[proof.k - 1] !== FforSlotState.SETTLED &&
				record.voucherOutcomes?.[proof.k - 1]?.outcome !== 'fulfilled'
			)
				throw new Error('Persisted receipt lost its settlement state');
		}
	}
}
