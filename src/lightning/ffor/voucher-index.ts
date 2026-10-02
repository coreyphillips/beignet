import { fforVoucherArchiveId, IFforVoucherArchive } from './voucher-archive';

/** Permanent book identity, rebuilt from custody before accepting peer traffic. */
export class FforVoucherIndex {
	private readonly hashes = new Map<string, IFforVoucherArchive>();
	private readonly offeredIds = new Map<string, string>();

	get(paymentHash: string): IFforVoucherArchive | undefined {
		return this.hashes.get(paymentHash);
	}

	assertAvailable(record: IFforVoucherArchive): void {
		const id = fforVoucherArchiveId(record);
		const previous = this.hashes.get(record.paymentHash);
		if (previous && fforVoucherArchiveId(previous) !== id)
			throw new Error('FFOR voucher payment hash was already adopted');
		const offeredId = this.offeredIds.get(this.offeredKey(record));
		if (offeredId && offeredId !== id)
			throw new Error('FFOR voucher HTLC id was already adopted');
	}

	assertAvailableAll(records: IFforVoucherArchive[]): void {
		const hashes = new Set<string>();
		const offered = new Set<string>();
		for (const record of records) {
			this.assertAvailable(record);
			if (
				hashes.has(record.paymentHash) ||
				offered.has(this.offeredKey(record))
			)
				throw new Error('FFOR book repeats a voucher identity');
			hashes.add(record.paymentHash);
			offered.add(this.offeredKey(record));
		}
	}

	remember(record: IFforVoucherArchive): void {
		this.assertAvailable(record);
		this.hashes.set(record.paymentHash, record);
		this.offeredIds.set(this.offeredKey(record), fforVoucherArchiveId(record));
	}

	private offeredKey(record: IFforVoucherArchive): string {
		// Role fixes direction on this node. R sees received IDs and S offered IDs.
		return `${record.channelId}:${record.role}:${record.htlcId}`;
	}
}
