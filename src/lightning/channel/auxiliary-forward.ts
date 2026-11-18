/**
 * Forwards with an asset leg (issue #2098): which HTLCs a node asks its host
 * about when it is to forward one and either leg is an asset leg, what the
 * host may answer, and what the host is told when each leg ends.
 *
 * Declared and not run. This build calls neither `prepareForward` nor
 * `onForwardLegResolved`: a node refuses every forward with an asset leg
 * before anything is offered, whatever hooks its host supplies, and
 * `AUXILIARY_CHANNELS_API.declared` names the part. The contract in full,
 * with what the engine checks whatever the host answers, is in
 * docs/EXTENSIONS.md, under "Forwards with an asset leg".
 *
 * A leg is an asset leg when its HTLC belongs to an asset channel: the
 * incoming HTLC when it carries units or came in on an asset channel, and
 * the outgoing HTLC when it leaves over an asset channel, which offers no
 * HTLC without units. A leg that is not an asset leg is a bitcoin leg.
 */

import type { CustomRecords } from '../message/custom-records';

/** The HTLC a forward came in on, irrevocably committed on its channel. */
export interface IAuxiliaryForwardIncoming {
	channelId: Buffer;
	peerPubkey: string;
	htlcId: bigint;
	/** The bitcoin the HTLC carries on the wire: for an asset leg, its carrier. */
	wireAmountMsat: bigint;
	cltvExpiry: number;
	/** The asset units the HTLC carries. Absent for a plain bitcoin HTLC. */
	auxiliaryAmount?: bigint;
	/** The custom records it was added with. Empty for a plain bitcoin HTLC. */
	customRecords: CustomRecords;
	/** It came in on an asset channel. */
	auxiliaryChannel: boolean;
}

/** A channel of the node that a forward's next hop names. */
export interface IAuxiliaryForwardChannel {
	channelId: Buffer;
	peerPubkey: string;
	/** It is an asset channel. */
	auxiliaryChannel: boolean;
}

/**
 * A forward the host is asked about (`IAuxiliaryChannelConfig.prepareForward`):
 * bitcoin in and asset out, asset in and bitcoin out, asset in and asset
 * out, or a forward whose next hop is a short channel id the node has no
 * channel for, which only the host can say is one of its own (the id a
 * quote of the host's gave to the hint of an asset invoice).
 */
export interface IAuxiliaryForwardRequest {
	paymentHash: Buffer;
	incoming: IAuxiliaryForwardIncoming;
	/** The next hop the onion names. */
	shortChannelId: Buffer;
	/**
	 * What the onion asks the node to forward. The outgoing leg is worth this
	 * much, whatever it carries on the wire.
	 */
	amountToForwardMsat: bigint;
	/** The expiry the onion asks of the outgoing HTLC, a block height. */
	outgoingCltvExpiry: number;
	/**
	 * The channel of the node that `shortChannelId` names, by its real id or
	 * an alias. Absent when the node has none: the forward then goes on only
	 * over an asset channel the host names for the id.
	 */
	outgoing?: IAuxiliaryForwardChannel;
}

/**
 * What the host answers for a forward it takes on: exactly the fields the
 * forward's legs call for, and no other. None of them lifts a check of the
 * engine's own.
 */
export interface IAuxiliaryForwardTerms {
	/**
	 * The asset channel a short channel id of the host's stands for, and the
	 * peer of that channel. Given when the request has no `outgoing`, and only
	 * then. It has to be an asset channel of this node with that peer.
	 */
	outgoingChannel?: { channelId: Buffer; peerPubkey: string };
	/**
	 * What the incoming HTLC is worth, in millisatoshis, above zero and within
	 * a u64. Given when the incoming leg is an asset leg, and only then. It
	 * stands where the incoming amount stands in the node's fee check.
	 */
	incomingValueMsat?: bigint;
	/**
	 * The outgoing HTLC, given when the outgoing leg is an asset leg and only
	 * then: the custom records that carry its units (at least one, each of a
	 * type at or above 65536), made by the host to hold units worth
	 * `amountToForwardMsat` at its own rate, and the bitcoin it carries on the
	 * wire, its carrier.
	 */
	outgoingHtlc?: { customRecords: CustomRecords; wireAmountMsat: bigint };
}

/**
 * The end of one leg of a forward the host took on
 * (`IAuxiliaryChannelConfig.onForwardLegResolved`).
 */
export interface IAuxiliaryForwardLegResolution {
	paymentHash: Buffer;
	/** The forward, by the HTLC it came in on. */
	incomingChannelId: Buffer;
	incomingHtlcId: bigint;
	/** Which leg ended. */
	leg: 'incoming' | 'outgoing';
	/**
	 * The channel of the leg that ended. For an outgoing leg never offered,
	 * the channel the node found or the host named for it, and absent when
	 * there was neither.
	 */
	channelId?: Buffer;
	/** The id of its HTLC on that channel. Absent for a leg never offered. */
	htlcId?: bigint;
	/**
	 * `fulfilled` or `failed`. `never-offered` is for an outgoing leg whose
	 * HTLC never entered its channel: after the host had answered with
	 * terms, the node refused them as malformed or a check of its own
	 * refused the forward. Its incoming leg is then failed back.
	 */
	outcome: 'fulfilled' | 'failed' | 'never-offered';
	/** It ended on the chain, and not by a message in its channel. */
	onChain: boolean;
	/** The asset units its HTLC carried. Absent for a bitcoin leg. */
	auxiliaryAmount?: bigint;
	/** The custom records its HTLC carried. Empty for a bitcoin leg. */
	customRecords: CustomRecords;
	/**
	 * Only on a failed incoming leg: the node had claimed it with the
	 * preimage, in a fulfil made in the channel or in a claim it signed for
	 * the chain, and the payer took the output back all the same. Such a leg
	 * may have been told `fulfilled` before.
	 */
	preimageRevealed?: true;
}
