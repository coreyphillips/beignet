import { ASSET_SPLICE_RECOVERY_TYPE_HEX } from './asset-opening';
import { assetSpliceNegotiated } from './asset-splice';
import { finalOpeningNegotiated } from './final-opening';
import { Feature, type FeatureFlags } from './flags';

/**
 * Whether two live inits agree on converting a channel (#2151): both set
 * bit 462 or 463, the recovery asset splice is negotiated, and so is the
 * plain final type of the conversion. `plainType` is the parent's type for
 * a conversion to an asset, whose alias bit then needs `SCID_ALIAS` on both
 * inits, and the type without the alias bit for one to plain. Internal: not
 * exported from the features barrel.
 */
export function assetConversionNegotiated(
	local: FeatureFlags,
	remote: FeatureFlags | undefined,
	plainType: Buffer
): boolean {
	return (
		!!remote &&
		local.hasFeature(Feature.OPTION_ASSET_CONVERSION) &&
		remote.hasFeature(Feature.OPTION_ASSET_CONVERSION) &&
		assetSpliceNegotiated(ASSET_SPLICE_RECOVERY_TYPE_HEX, local, remote) &&
		finalOpeningNegotiated(local, remote, plainType, true)
	);
}
