/**
 * Real commitment signing for direct-Channel test fixtures.
 *
 * The channel verifies every incoming commitment/funding signature
 * unconditionally (it fails closed when the signer or remote basepoints are
 * missing), so fixtures that drive handlers directly must exchange REAL
 * signatures. These helpers reproduce the ChannelManager's signing recipe
 * (autoSignAndSendCommitment) for fixtures whose basepoint privkeys derive
 * as sha256(seed || [i]) with the funding key at i=0 and the HTLC basepoint
 * at i=4 (the makeBasepoints convention shared by the state-machine tests).
 */

import crypto from 'crypto';
import { Channel } from '../../../src/lightning/channel/channel';
import { ChannelSigner } from '../../../src/lightning/keys/signer';
import { signRemoteCommitment } from '../../../src/lightning/channel/commitment-builder';

/** The i-th deterministic basepoint privkey of the makeBasepoints convention. */
export function seedKey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

/** A real ChannelSigner matching makeBasepoints(seed). */
export function signerFromSeed(seed: Buffer): ChannelSigner {
	return new ChannelSigner(seedKey(seed, 0), seedKey(seed, 4));
}

/**
 * Our real signature over the PEER's initial commitment (#0), for
 * createFundingCreated (opener side) or the handleFundingCreated reply
 * (acceptor side). Signing needs the funding outpoint in state, so it is
 * installed here; the handler that follows sets the same values again.
 */
export function realInitialCommitmentSig(
	channel: Channel,
	fundingTxid: Buffer,
	fundingOutputIndex: number
): Buffer {
	const state = channel.getFullState();
	state.fundingTxid = fundingTxid;
	state.fundingOutputIndex = fundingOutputIndex;
	return signRemoteCommitment(
		state,
		channel.getSigner()!,
		state.remoteCurrentPerCommitmentPoint!,
		0n
	).signature;
}

/**
 * Our real signature set over the peer's NEXT commitment, for signCommitment
 * in a live commitment round (the ChannelManager recipe: next remote point,
 * remoteCommitmentNumber + 1).
 */
export function realCommitmentSigs(channel: Channel): {
	signature: Buffer;
	htlcSignatures: Buffer[];
} {
	const state = channel.getFullState();
	const point =
		state.remoteNextPerCommitmentPoint || state.remoteCurrentPerCommitmentPoint;
	return signRemoteCommitment(
		state,
		channel.getSigner()!,
		point!,
		state.remoteCommitmentNumber + 1n
	);
}
