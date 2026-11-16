/**
 * What an asset channel (issue #2093) cannot do, said once and by name.
 *
 * An asset channel's funding key commits to an asset root and its
 * commitments carry asset leaves, so the code that closes, sweeps, punishes,
 * splices or re-shapes an ordinary channel builds the wrong transaction for
 * it. Every such path asks here first and refuses with an error that names
 * the channel and what was asked of it, instead of running the ordinary
 * logic. A path leaves this list in the step that teaches it about asset
 * state, and only then.
 */

import { CodedError } from '../../utils/errors';
import type { IChannelState } from './channel-state';
import { isOverlayChannel } from './types';

/** What a caller asked of an asset channel that it does not do. */
export type AuxiliaryUnsupportedOperation =
	| 'a cooperative close'
	| 'a force close'
	| 'on-chain resolution'
	| 'a splice'
	| 'quiescence'
	| 'a delegated settlement epoch';

export class AuxiliaryChannelUnsupportedError extends CodedError<'ASSET_CHANNEL_UNSUPPORTED'> {
	/** The channel id, or the temporary id of a channel that has none yet, hex. */
	readonly channelId: string;
	readonly operation: AuxiliaryUnsupportedOperation;

	constructor(channelId: string, operation: AuxiliaryUnsupportedOperation) {
		super(
			'ASSET_CHANNEL_UNSUPPORTED',
			`An asset channel does not support ${operation} (channel ${channelId})`
		);
		this.name = 'AuxiliaryChannelUnsupportedError';
		this.channelId = channelId;
		this.operation = operation;
	}
}

/** Whether a channel holds, or was opened to hold, asset state. */
export function isAuxiliaryChannelState(state: IChannelState): boolean {
	return (
		state.auxiliaryState !== undefined ||
		state.fundingTaprootMerkleRoot !== undefined ||
		isOverlayChannel(state.channelType)
	);
}

/**
 * The refusal of `operation` for an asset channel, or undefined for any
 * other channel, which is not touched.
 */
export function auxiliaryUnsupported(
	state: IChannelState,
	operation: AuxiliaryUnsupportedOperation
): AuxiliaryChannelUnsupportedError | undefined {
	if (!isAuxiliaryChannelState(state)) return undefined;
	return new AuxiliaryChannelUnsupportedError(
		(state.channelId ?? state.temporaryChannelId).toString('hex'),
		operation
	);
}
