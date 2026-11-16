/**
 * What this build offers a host of asset channels (issue #2093), said by
 * the build itself, so that a host does not have to guess it from the
 * shape of a function.
 *
 * Reached as `channel.AUXILIARY_CHANNELS_API` from `beignet/lightning`. A
 * build without it has no asset channels. `version` is 0 while the build
 * cannot open one, which it does not until it can also close and defend
 * it on chain, and 1 from the build that can. A host treats a missing
 * constant, and any version below the one it was written for, as
 * unsupported. `surfaces` names the optional parts of the contract that
 * are present, each by the member a host would otherwise have to probe.
 */
export const AUXILIARY_CHANNELS_API = Object.freeze({
	version: 0,
	surfaces: Object.freeze([
		// valueIncomingHtlc answers a value, undefined ("not mine") or throws.
		'valueIncomingHtlc:three-outcome',
		// sendPaymentToRoute takes { assetPayment } as its ninth argument.
		'sendPaymentToRoute:assetPayment',
		// getAuxiliaryPaymentHtlcs and the htlcs of getAuxiliaryChannelInfo.
		'getAuxiliaryPaymentHtlcs',
		// onHtlcResolved carries the channel id and the HTLC id.
		'onHtlcResolved:htlcId',
		'queryAuxiliaryRoute',
		// fundAuxiliaryChannel takes an unsigned transaction and the scripts it spends.
		'fundAuxiliaryChannel:unsigned',
		// The opener's point of no return, and the call that undoes an opening before it.
		'onFundingSigned',
		'abandonAuxiliaryOpen',
		// A channel row of listChannels carries auxiliary: true.
		'IChannelInfo.auxiliary'
	] as const)
});

/** A name in `AUXILIARY_CHANNELS_API.surfaces`. */
export type AuxiliaryChannelsSurface =
	(typeof AUXILIARY_CHANNELS_API.surfaces)[number];
