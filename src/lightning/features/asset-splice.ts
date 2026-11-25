import { MAX_AUXILIARY_HTLCS_PER_PARTY } from '../channel/auxiliary';
import { encodeBigSize } from '../message/codec';
import { encodeCommitmentSignedMessage } from '../message/channel-commitment';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import {
	ASSET_OPENING_TYPE_HEX,
	assetOpeningNegotiated
} from './asset-opening';
import { Feature, type FeatureFlags } from './flags';

/** Private regtest extension. Each participant must explicitly select this profile. */
export function assetSpliceNegotiated(
	channelType: string,
	local: FeatureFlags,
	peer?: FeatureFlags
): boolean {
	return (
		channelType === ASSET_OPENING_TYPE_HEX &&
		!!peer &&
		assetOpeningNegotiated(local, peer) &&
		[local, peer].every((flags) =>
			[Feature.QUIESCE, Feature.SPLICE, Feature.OPTION_ASSET_SPLICE].every(
				(f) => flags.hasFeature(f)
			)
		)
	);
}

export interface IAssetSpliceWireRecordLimit {
	type: bigint;
	/** Complete value at the maximum negotiated HTLC counts, including any provider framing. */
	maxBytes: number;
}
const taggedBase = encodeCommitmentSignedMessage({
	channelId: Buffer.alloc(32),
	signature: Buffer.alloc(64),
	htlcSignatures: [],
	fundingTxid: Buffer.alloc(32),
	partialSignatureWithNonce: Buffer.alloc(98)
}).length;

/** Compute a single holder's worst-case wire size without allocating provider-sized buffers. */
export function assetSpliceCommitmentBytes(
	limits: readonly [number, number],
	records: readonly IAssetSpliceWireRecordLimit[]
): number {
	if (
		limits.length !== 2 ||
		!limits.every(
			(n) =>
				Number.isSafeInteger(n) && n >= 1 && n <= MAX_AUXILIARY_HTLCS_PER_PARTY
		) ||
		!Array.isArray(records) ||
		!records.length ||
		!records.some((r) => r.type === 65537n)
	)
		throw new Error('Incomplete asset splice commitment limits');
	let bytes = taggedBase + (limits[0] + limits[1]) * 64;
	const types = new Set<bigint>();
	for (const { type, maxBytes } of records) {
		if (
			typeof type !== 'bigint' ||
			type < 65536n ||
			type > 0xffffffffffffffffn ||
			types.has(type) ||
			!Number.isSafeInteger(maxBytes) ||
			maxBytes < 0 ||
			maxBytes > MAX_LIGHTNING_PAYLOAD
		)
			throw new Error('Invalid asset splice signature record limits');
		types.add(type);
		bytes +=
			encodeBigSize(type).length +
			encodeBigSize(BigInt(maxBytes)).length +
			maxBytes;
	}
	if (bytes > MAX_LIGHTNING_PAYLOAD)
		throw new Error(
			'Tagged asset commitment requires ' + bytes + ' payload bytes'
		);
	return bytes;
}
