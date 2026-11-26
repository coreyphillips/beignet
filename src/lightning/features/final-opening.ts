import { isFinalTaprootTypeHex } from '../channel/commitment-profile';
import { Feature, FeatureFlags } from './flags';

export function finalOpeningDependencies(features: FeatureFlags): boolean {
	return [
		Feature.CHANNEL_TYPE,
		Feature.SHUTDOWN_ANY_SEGWIT,
		Feature.SIMPLE_CLOSE,
		Feature.DUAL_FUND
	].every((feature) => features.hasFeature(feature));
}

/**
 * What bit 463 stands for between two generation 6 peers: their inits keep
 * the asset masks, which clear simple close and bit 81, so the conversion bit
 * takes the place of both for the plain final type.
 */
function conversionDependencies(features: FeatureFlags): boolean {
	return [
		Feature.OPTION_ASSET_CONVERSION,
		Feature.CHANNEL_TYPE,
		Feature.SHUTDOWN_ANY_SEGWIT,
		Feature.DUAL_FUND
	].every((feature) => features.hasFeature(feature));
}

/**
 * Opening admission uses the two live init vectors, including the proposed
 * SCID alias. A generation 6 wallet (`conversionWallet`) negotiates the plain
 * final type only through bit 463 on both inits.
 */
export function finalOpeningNegotiated(
	local: FeatureFlags,
	remote: FeatureFlags | undefined,
	channelType: Buffer,
	conversionWallet = false
): boolean {
	if (
		!Buffer.isBuffer(channelType) ||
		!isFinalTaprootTypeHex(channelType.toString('hex')) ||
		!remote
	)
		return false;
	const alias = FeatureFlags.fromBuffer(channelType).hasFeature(
		Feature.SCID_ALIAS
	);
	return [local, remote].every(
		(features) =>
			(conversionWallet
				? conversionDependencies(features)
				: finalOpeningDependencies(features) &&
				  features.hasFeature(Feature.OPTION_SIMPLE_TAPROOT)) &&
			(!alias || features.hasFeature(Feature.SCID_ALIAS))
	);
}

export function finalOpeningChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_SIMPLE_TAPROOT);
	return flags.toBuffer();
}
