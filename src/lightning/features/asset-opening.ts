import { Feature, FeatureFlags } from './flags';

// Version 1 defines the final Bitcoin scripts with an auxiliary leaf.
// The distinct type can coexist with staging Taproot for existing v1 peers.
const channelTypeFlags = FeatureFlags.empty();
for (const feature of [
	Feature.OPTION_DUAL_FUNDED_ASSETS,
	Feature.OPTION_TAPROOT_OVERLAY
])
	channelTypeFlags.setCompulsory(feature);
export const ASSET_OPENING_TYPE_HEX = channelTypeFlags
	.toBuffer()
	.toString('hex');

const recoveryType = FeatureFlags.fromBuffer(channelTypeFlags.toBuffer());
recoveryType.setCompulsory(Feature.OPTION_ASSET_SPLICE_RECOVERY);
export const ASSET_SPLICE_RECOVERY_TYPE_HEX = recoveryType
	.toBuffer()
	.toString('hex');

export function isAssetOpeningType(type: string | undefined): boolean {
	return (
		type === ASSET_OPENING_TYPE_HEX || type === ASSET_SPLICE_RECOVERY_TYPE_HEX
	);
}

export function assetOpeningDependencies(flags: FeatureFlags): boolean {
	return [
		Feature.CHANNEL_TYPE,
		Feature.DUAL_FUND,
		Feature.OPTION_TAPROOT_OVERLAY,
		Feature.OPTION_ASSET_FIXED_HTLC_OUTPUTS
	].every((f) => flags.hasFeature(f));
}

export function assetOpeningNegotiated(
	local: FeatureFlags,
	remote: FeatureFlags | undefined,
	channelType: string = ASSET_OPENING_TYPE_HEX
): boolean {
	return (
		isAssetOpeningType(channelType) &&
		!!remote &&
		[local, remote].every(
			(f) =>
				assetOpeningDependencies(f) &&
				f.hasFeature(Feature.OPTION_DUAL_FUNDED_ASSETS) &&
				(channelType !== ASSET_SPLICE_RECOVERY_TYPE_HEX ||
					[
						Feature.QUIESCE,
						Feature.SPLICE,
						Feature.OPTION_ASSET_SPLICE,
						Feature.OPTION_ASSET_SPLICE_RECOVERY
					].every((bit) => f.hasFeature(bit)))
		)
	);
}
