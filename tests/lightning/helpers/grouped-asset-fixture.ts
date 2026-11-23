import type {
	IChannelAuxiliaryProvider,
	IAuxiliaryCommitmentData
} from '../../../src/lightning/channel/auxiliary';
import { hash, referenceProvider } from './auxiliary-pair';

/** Distinct issuances and their funding allocations in the sample group. */
export const issuances = [
	{ id: hash('issuance A'), local: 210n, remote: 33n },
	{ id: hash('issuance B'), local: 320n, remote: 28n },
	{ id: hash('issuance C'), local: 370n, remote: 39n }
];

export function fundingData(count: number, phase: number): Buffer {
	return Buffer.concat(
		issuances.slice(0, count).map(({ id, local, remote }, i) => {
			const record = Buffer.alloc(6 * 1024, 16 * phase + i);
			id.copy(record);
			record.writeBigUInt64BE(local, 32);
			record.writeBigUInt64BE(remote, 40);
			return record;
		})
	);
}

/** Opaque views with distinct contents for each generation and commitment holder. */
export function sizedViewProvider(count: number): IChannelAuxiliaryProvider {
	const provider = referenceProvider();
	const build = provider.buildCommitment;
	provider.buildCommitment = (context): IAuxiliaryCommitmentData => {
		const view = build(context);
		const holderKey =
			context.side === 'local'
				? context.state.localBasepoints.fundingPubkey
				: context.state.remoteBasepoints!.fundingPubkey;
		const marker = hash(Buffer.concat([holderKey, view.customData]));
		const size = (count === 1 ? 8 : 16) * 1024;
		return { ...view, customData: Buffer.alloc(size, marker) };
	};
	return provider;
}
