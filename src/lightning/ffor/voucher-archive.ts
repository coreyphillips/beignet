import { createHash } from 'crypto';
import { IFforEpochRecord } from './types';
import { IRREVOCABLE_DEPTH } from '../chain/types';

/** Observed spend identity. Its presence alone never establishes final value. */
export interface IFforVoucherChainObservation {
	outputTxid: string;
	outputIndex: number;
	spendingTxid: string;
	preimage?: string;
}

/** A spend that reached the chain monitor's finality threshold. */
export interface IFforVoucherChainResolution
	extends IFforVoucherChainObservation {
	confirmationHeight: number;
	finalizedHeight: number;
	/** The original output value, before any claim transaction fees. */
	amountMsat: string;
	/** A local commitment claim also needs its CSV output's final sweep. */
	secondLevel?: {
		outputIndex: number;
		spendingTxid: string;
		confirmationHeight: number;
	};
}

/** JSON-safe custody record. It survives epoch replacement and channel pruning. */
export interface IFforVoucherArchive {
	channelId: string;
	epochId: string;
	slot: number;
	role: 'R' | 'S';
	paymentHash: string;
	amountMsat: string;
	htlcId: string;
	voucherExpiry: number;
	concurrentVersion: number;
	preimage?: string;
	outcome?: {
		outcome: 'fulfilled' | 'cancelled';
		localCommitmentNumber: string;
		remoteCommitmentNumber: string;
	};
	chainObservations?: IFforVoucherChainObservation[];
	chainResolutions?: IFforVoucherChainResolution[];
	/** Written atomically with the first invoice credit. Other receipts remain visible. */
	creditedReceiptId?: string;
}

export function fforVoucherArchiveId(record: IFforVoucherArchive): string {
	return `${record.channelId}:${record.epochId}:${record.slot}`;
}

export function fforChainReceiptId(r: IFforVoucherChainObservation): string {
	return `chain:${r.outputTxid}:${r.outputIndex}:${r.spendingTxid}`;
}

/** Source identities are stable across replay and independent of payment status. */
export function fforVoucherReceiptIds(record: IFforVoucherArchive): string[] {
	return [
		...(record.outcome?.outcome === 'fulfilled'
			? [
					`commitment:${fforVoucherArchiveId(record)}:${
						record.outcome.localCommitmentNumber
					}:${record.outcome.remoteCommitmentNumber}`
			  ]
			: []),
		...(record.chainResolutions ?? [])
			.filter((r) => r.preimage)
			.map(fforChainReceiptId)
	];
}

/** Strict reads are intentional: missing custody must never become an empty ledger. */
export function validateFforVoucherArchive(
	value: unknown
): IFforVoucherArchive {
	const record = value as IFforVoucherArchive;
	const hex = (s: unknown): s is string =>
		typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
	const uint = (s: unknown): s is string =>
		typeof s === 'string' &&
		/^(0|[1-9][0-9]*)$/.test(s) &&
		BigInt(s) <= 0xffffffffffffffffn;
	if (
		!record ||
		!hex(record.channelId) ||
		!hex(record.epochId) ||
		!hex(record.paymentHash) ||
		!Number.isInteger(record.slot) ||
		record.slot < 1 ||
		record.slot > 483 ||
		(record.role !== 'R' && record.role !== 'S') ||
		!uint(record.amountMsat) ||
		BigInt(record.amountMsat) <= 0n ||
		!uint(record.htlcId) ||
		!Number.isInteger(record.voucherExpiry) ||
		record.voucherExpiry <= 0 ||
		record.voucherExpiry > 0xffffffff ||
		![0, 1, 2].includes(record.concurrentVersion)
	) {
		throw new Error('Invalid FFOR voucher archive identity');
	}
	if (
		record.preimage !== undefined &&
		(!hex(record.preimage) ||
			createHash('sha256')
				.update(Buffer.from(record.preimage, 'hex'))
				.digest('hex') !== record.paymentHash)
	) {
		throw new Error('Invalid FFOR voucher archive preimage');
	}
	if (
		record.outcome !== undefined &&
		(!record.outcome ||
			!['fulfilled', 'cancelled'].includes(record.outcome.outcome) ||
			!uint(record.outcome.localCommitmentNumber) ||
			!uint(record.outcome.remoteCommitmentNumber))
	) {
		throw new Error('Invalid FFOR voucher archive outcome');
	}
	for (const records of [record.chainObservations, record.chainResolutions]) {
		if (records === undefined) continue;
		if (!Array.isArray(records))
			throw new Error('Invalid FFOR voucher chain records');
		const sources = new Set<string>();
		for (const r of records) {
			if (
				!r ||
				!hex(r.outputTxid) ||
				!hex(r.spendingTxid) ||
				!Number.isInteger(r.outputIndex) ||
				r.outputIndex < 0 ||
				r.outputIndex > 0xffffffff ||
				(r.preimage !== undefined &&
					(!hex(r.preimage) ||
						createHash('sha256')
							.update(Buffer.from(r.preimage, 'hex'))
							.digest('hex') !== record.paymentHash))
			) {
				throw new Error('Invalid FFOR voucher chain observation');
			}
			const source = fforChainReceiptId(r);
			if (sources.has(source))
				throw new Error('Duplicate FFOR voucher chain resolution');
			sources.add(source);
		}
	}
	for (const r of record.chainResolutions ?? []) {
		if (
			!Number.isSafeInteger(r.confirmationHeight) ||
			r.confirmationHeight <= 0 ||
			!Number.isSafeInteger(r.finalizedHeight) ||
			r.finalizedHeight - r.confirmationHeight < IRREVOCABLE_DEPTH ||
			!uint(r.amountMsat) ||
			BigInt(r.amountMsat) <= 0n ||
			(r.secondLevel !== undefined &&
				(!r.secondLevel ||
					!Number.isInteger(r.secondLevel.outputIndex) ||
					r.secondLevel.outputIndex !== 0 ||
					!hex(r.secondLevel.spendingTxid) ||
					!Number.isSafeInteger(r.secondLevel.confirmationHeight) ||
					r.secondLevel.confirmationHeight <= 0 ||
					r.finalizedHeight - r.secondLevel.confirmationHeight <
						IRREVOCABLE_DEPTH))
		)
			throw new Error('Invalid FFOR voucher chain resolution');
	}
	if (
		record.creditedReceiptId !== undefined &&
		!fforVoucherReceiptIds(record).includes(record.creditedReceiptId)
	) {
		throw new Error('Invalid FFOR voucher credit source');
	}
	return record;
}

/** Merge only additional evidence. Neither identity nor a terminal outcome can change. */
export function mergeFforVoucherArchive(
	previous: IFforVoucherArchive | null,
	incoming: IFforVoucherArchive
): IFforVoucherArchive {
	validateFforVoucherArchive(incoming);
	if (!previous) return incoming;
	validateFforVoucherArchive(previous);
	const identity = (r: IFforVoucherArchive): string =>
		JSON.stringify([
			r.channelId,
			r.epochId,
			r.slot,
			r.role,
			r.paymentHash,
			r.amountMsat,
			r.htlcId,
			r.voucherExpiry,
			r.concurrentVersion
		]);
	if (identity(previous) !== identity(incoming))
		throw new Error('FFOR voucher archive identity changed');
	if (
		previous.outcome &&
		incoming.outcome &&
		(previous.outcome.outcome !== incoming.outcome.outcome ||
			previous.outcome.localCommitmentNumber !==
				incoming.outcome.localCommitmentNumber ||
			previous.outcome.remoteCommitmentNumber !==
				incoming.outcome.remoteCommitmentNumber)
	) {
		throw new Error('FFOR voucher archive outcome changed');
	}
	const chainResolutions = [...(previous.chainResolutions ?? [])];
	for (const incomingResolution of incoming.chainResolutions ?? []) {
		const prior = chainResolutions.find(
			(r) => fforChainReceiptId(r) === fforChainReceiptId(incomingResolution)
		);
		if (prior && JSON.stringify(prior) !== JSON.stringify(incomingResolution))
			throw new Error('FFOR voucher chain resolution changed');
		if (!prior) chainResolutions.push(incomingResolution);
	}
	const chainObservations = [...(previous.chainObservations ?? [])];
	for (const observation of incoming.chainObservations ?? []) {
		const prior = chainObservations.find(
			(r) => fforChainReceiptId(r) === fforChainReceiptId(observation)
		);
		if (prior && prior.preimage !== observation.preimage)
			throw new Error('FFOR voucher chain observation changed');
		if (!prior) chainObservations.push(observation);
	}
	if (
		previous.creditedReceiptId &&
		incoming.creditedReceiptId &&
		previous.creditedReceiptId !== incoming.creditedReceiptId
	)
		throw new Error('FFOR voucher credit source changed');
	return validateFforVoucherArchive({
		...incoming,
		...(previous.preimage ? { preimage: previous.preimage } : {}),
		...(previous.outcome ? { outcome: previous.outcome } : {}),
		...(chainObservations.length ? { chainObservations } : {}),
		...(chainResolutions.length ? { chainResolutions } : {}),
		...(previous.creditedReceiptId
			? { creditedReceiptId: previous.creditedReceiptId }
			: {})
	});
}

/** Capture immutable slot identity with the channel transition that adopts it. */
export function archiveFforVouchers(
	channelId: string,
	epoch: IFforEpochRecord
): IFforVoucherArchive[] {
	if (!epoch.acceptWire || epoch.sHtlcIdBase === null) return [];
	return epoch.paymentHashes.map((hash, i) => {
		const outcome = epoch.voucherOutcomes?.[i];
		const preimage = epoch.role === 'R' ? epoch.knownPreimages[i] : undefined;
		return validateFforVoucherArchive({
			channelId,
			epochId: epoch.epochId.toString('hex'),
			slot: i + 1,
			role: epoch.role,
			paymentHash: hash.toString('hex'),
			amountMsat: epoch.params.voucherAmountsMsat[i].toString(),
			htlcId: (epoch.sHtlcIdBase! + BigInt(i)).toString(),
			voucherExpiry: epoch.params.voucherExpiry,
			concurrentVersion: epoch.concurrentVersion ?? 0,
			...(preimage ? { preimage: preimage.toString('hex') } : {}),
			...(outcome
				? {
						outcome: {
							outcome: outcome.outcome,
							localCommitmentNumber: outcome.localCommitmentNumber.toString(),
							remoteCommitmentNumber: outcome.remoteCommitmentNumber.toString()
						}
				  }
				: {})
		});
	});
}
