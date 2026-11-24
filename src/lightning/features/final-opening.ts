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

/** Opening admission uses the two live init vectors, including the proposed SCID alias. */
export function finalOpeningNegotiated(
	local: FeatureFlags,
	remote: FeatureFlags | undefined,
	channelType: Buffer
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
			finalOpeningDependencies(features) &&
			features.hasFeature(Feature.OPTION_SIMPLE_TAPROOT) &&
			(!alias || features.hasFeature(Feature.SCID_ALIAS))
	);
}

export function finalOpeningChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.OPTION_SIMPLE_TAPROOT);
	return flags.toBuffer();
}
