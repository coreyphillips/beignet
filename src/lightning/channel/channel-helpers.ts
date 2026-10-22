/**
 * Small helpers Channel shares with the modules it delegates to.
 */

import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { perCommitmentPointFromSecret } from '../keys/derivation';
import type { MessageType } from '../message/types';
import type { ISendMessageAction } from './channel-actions';
import { ChannelActionType } from './channel-actions';

export function getPerCommitmentPoint(
	seed: Buffer,
	commitmentNumber: bigint
): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	const secret = generateFromSeed(seed, index);
	return perCommitmentPointFromSecret(secret);
}

export function getPerCommitmentSecret(
	seed: Buffer,
	commitmentNumber: bigint
): Buffer {
	const index = MAX_INDEX - commitmentNumber;
	return generateFromSeed(seed, index);
}

export function sendMsg(
	messageType: MessageType,
	payload: Buffer
): ISendMessageAction {
	return { type: ChannelActionType.SEND_MESSAGE, messageType, payload };
}

export function bigIntMax(a: bigint, b: bigint): bigint {
	return a > b ? a : b;
}

export function bigIntMin(a: bigint, b: bigint): bigint {
	return a < b ? a : b;
}
