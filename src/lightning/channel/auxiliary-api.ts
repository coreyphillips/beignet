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
 * `declared` names the parts whose types and documentation the build
 * already carries and which it does not run: a host may supply their
 * hooks, and the node calls none of them and does what it does without
 * them. A name leaves `declared` for `surfaces` in the build that runs its
 * part, and a host relies on a part only once `surfaces` names it.
 */
export const AUXILIARY_CHANNELS_API = Object.freeze({
	version: 1,
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
		'IChannelInfo.auxiliary',
		// The node's wrapper can refuse an asset payment: ASSET_PAYMENT_REFUSED.
		'setAuxiliaryPaymentGate',
		// What the chain monitor of a channel recorded, as a copy.
		'getChannelMonitorState',
		// A payment record carried by asset HTLCs has auxiliary: true, and
		// an outgoing one what it is worth to the payee beside the bitcoin
		// its HTLCs carried.
		'IPaymentInfo.auxiliary',
		'IPaymentInfo.auxiliaryValueMsat',
		// An invoice paid by asset HTLCs has auxiliary: true, in its record
		// and in its invoice:settled event.
		'IInvoiceInfo.auxiliary',
		// How many outcomes of a channel's asset HTLCs its host has not
		// taken, beside the channel's other figures.
		'IAuxiliaryChannelInfo.undeliveredOutcomes',
		// onHtlcResolved also reports, with the outcome 'never-sent', a part
		// of an outgoing asset payment whose HTLC never entered its channel.
		'onHtlcResolved:never-sent',
		// The node answers the state of its wallet's fee coin pool, and says
		// when a fee policy was refused and there is none.
		'getFixedOutputFeeStatus',
		// A PENDING payment record that had an HTLC on an asset channel a
		// capsule restore left out carries unresolved, and stays PENDING.
		'IPaymentInfo.unresolved',
		// The hold:* events and the rows of listHoldInvoices and listHeldHtlcs
		// carry auxiliary: true for a set with an HTLC that holds units.
		'IHoldInvoiceStateEvent.auxiliary',
		// Forwards with an asset leg (issue #2098): prepareForward and
		// onForwardLegResolved, with the types of auxiliary-forward.ts and the
		// contract in docs/EXTENSIONS.md, and IAuxiliaryChannelInfo's
		// forwardsInFlight and undeliveredForwardLegEnds.
		'prepareForward',
		// The pool's status says how many fee coins a split would make now.
		'getFixedOutputFeeStatus:splitCoins',
		// Issue #2098, step 6: a node that forwards keeps fee coins for its
		// spends with a deadline and says so in getFixedOutputFeeStatus()
		// .reserve; a host may have asset HTLCs that end at the node taken
		// only while those coins would pay to claim them.
		'getFixedOutputFeeStatus:reserve',
		'requireFeeCoinsToSettle',
		// Issue #2098, step 7: each leg's end tells the quote the forward was
		// taken under: the next hop the onion named (shortChannelId) and what
		// the leg was worth (valueMsat).
		'onForwardLegResolved:quote',
		// A forward with an asset leg is in the forwarding history and its
		// htlc:forwarded event, marked auxiliary at what each leg was worth,
		// and the summary counts it apart.
		'IForwardingEvent.auxiliary',
		// Whoever wraps the node can refuse a forward with an asset leg
		// before anything of it is offered.
		'setAuxiliaryForwardGate',
		// Issue #2098, step 8: an asset invoice paid in parts, collected into
		// one set for a host that sets receiveInParts, settled together, and
		// every part claimed once the set is committed.
		'receiveInParts',
		// Issue #2098, step 9: an asset payment sent in parts, for a host that
		// sets sendInParts, each part recorded before it is sent and counted
		// toward its channel's bound, the payment's record kept across them.
		'sendInParts',
		// Issue #2098, step 10: createInvoice takes { assetInvoice }, and such
		// an invoice carries only its host's routing hints and offers
		// basic_mpp only where its parts can be collected.
		'createInvoice:assetInvoice',
		'dualFunding:v1',
		'assetSplice:v1'
	] as const),
	// Nothing is declared and not run in this build.
	declared: Object.freeze([] as const)
});

/** A name in `AUXILIARY_CHANNELS_API.surfaces`. */
export type AuxiliaryChannelsSurface =
	(typeof AUXILIARY_CHANNELS_API.surfaces)[number];

/** A name in `AUXILIARY_CHANNELS_API.declared`. */
export type AuxiliaryChannelsDeclared =
	(typeof AUXILIARY_CHANNELS_API.declared)[number];
