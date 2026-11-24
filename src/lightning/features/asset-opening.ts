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
	remote: FeatureFlags | undefined
): boolean {
	return (
		!!remote &&
		[local, remote].every(
			(f) =>
				assetOpeningDependencies(f) &&
				f.hasFeature(Feature.OPTION_DUAL_FUNDED_ASSETS)
		)
	);
}
