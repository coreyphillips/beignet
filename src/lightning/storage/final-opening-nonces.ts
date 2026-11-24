import type { IFinalOpeningSigning } from './final-opening-signing';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { generateNonce } from '../crypto/musig';
import { hmacSha256, randomBytes } from '../crypto/provider';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import {
	decodeTxCompleteMessage,
	encodeTxCompleteMessage
} from '../message/interactive-tx';

export interface IFinalOpeningSession {
	updateLimits?: import('./final-channel-updates').IFinalUpdateLimits;
	peer: string;
	channelKeyIndex: number;
	remoteSecondPerCommitmentPoint?: string;
	terms: import('../channel/final-opening-commitment').IFinalOpeningTerms;
}

export interface IFinalReestablishNonce {
	generation: number;
	nonce: string;
}

export interface IFinalOpeningNonces {
	localReady?: string;
	peerReady?: string;
	localReconnect?: IFinalReestablishNonce;
	peerReconnect?: IFinalReestablishNonce;
	session?: IFinalOpeningSession;
	local?: { salt: string; payload: string };
	peer?: string;
	signing?: IFinalOpeningSigning;
}

function validPayload(channelId: string, payload: Buffer): void {
	if (!Buffer.isBuffer(payload) || payload.length > MAX_LIGHTNING_PAYLOAD)
		throw new Error('Invalid opening tx_complete payload');
	const message = decodeTxCompleteMessage(payload, { taproot: true });
	const pair = message.commitNonces;
	if (
		!pair ||
		message.fundingInputNonce ||
		message.channelId.toString('hex') !== channelId ||
		pair.current.equals(pair.next)
	)
		throw new Error('Invalid opening commitment nonce pair');
	for (const nonce of [pair.current, pair.next]) {
		if (
			!isValidPublicKey(nonce.subarray(0, 33)) ||
			!isValidPublicKey(nonce.subarray(33))
		)
			throw new Error('Invalid opening public nonce point');
	}
}

function readPayload(channelId: string, hex: string): Buffer {
	if (
		typeof hex !== 'string' ||
		hex.length % 2 ||
		hex.length > MAX_LIGHTNING_PAYLOAD * 2 ||
		!/^[0-9a-f]+$/.test(hex)
	)
		throw new Error('Invalid stored tx_complete');
	const payload = Buffer.from(hex, 'hex');
	validPayload(channelId, payload);
	return payload;
}

export function decodeOpeningNonces(
	channelId: string,
	text: string
): IFinalOpeningNonces {
	const value: IFinalOpeningNonces = JSON.parse(text);
	if (
		!value ||
		typeof value !== 'object' ||
		Array.isArray(value) ||
		Object.keys(value).some(
			(key) =>
				key !== 'local' &&
				key !== 'peer' &&
				key !== 'signing' &&
				key !== 'localReady' &&
				key !== 'peerReady' &&
				key !== 'localReconnect' &&
				key !== 'peerReconnect' &&
				key !== 'session'
		)
	)
		throw new Error('Invalid stored final opening nonces');
	if (value.local !== undefined) {
		if (
			!value.local ||
			typeof value.local.salt !== 'string' ||
			!/^[0-9a-f]{64}$/.test(value.local.salt) ||
			Object.keys(value.local).length !== 2
		)
			throw new Error('Invalid local opening nonce reservation');
		readPayload(channelId, value.local.payload);
	}
	if (value.peer !== undefined) readPayload(channelId, value.peer);
	return value;
}

/** The signer consumes the original BIP327 handle. Only its public bytes go on wire. */
export function openingVerificationNonce(
	height: 0 | 1,
	salt: Buffer,
	context: Buffer,
	fundingPrivateKey: Buffer
): Uint8Array {
	return generateNonce({
		publicKey: getPublicKey(fundingPrivateKey),
		secretKey: fundingPrivateKey,
		sessionId: hmacSha256(salt, Buffer.concat([context, Buffer.of(height)])),
		extraInput: Buffer.from('beignet-final-opening-verification-v1')
	});
}

/** Reserve verification nonces for commitment heights zero and one. A signing nonce has a separate lifecycle. */
export function localOpeningTxComplete(
	state: IFinalOpeningNonces,
	channelId: string,
	localFundingPubkey: string,
	fundingPrivateKey: Buffer,
	context: Buffer,
	initialSalt?: Buffer
): Buffer {
	const publicKey = getPublicKey(fundingPrivateKey);
	if (publicKey.toString('hex') !== localFundingPubkey)
		throw new Error('Opening funding key does not match');
	const salt = state.local
		? Buffer.from(state.local.salt, 'hex')
		: initialSalt ?? randomBytes(32);

	const payload = encodeTxCompleteMessage({
		channelId: Buffer.from(channelId, 'hex'),
		commitNonces: {
			current: Buffer.from(
				openingVerificationNonce(0, salt, context, fundingPrivateKey)
			),
			next: Buffer.from(
				openingVerificationNonce(1, salt, context, fundingPrivateKey)
			)
		}
	});
	validPayload(channelId, payload);
	if (state.local) {
		const promised = Buffer.from(state.local.payload, 'hex');
		if (!payload.equals(promised))
			throw new Error(
				'Opening nonce reservation does not reproduce the promised payload'
			);
		return promised;
	}
	state.local = {
		salt: salt.toString('hex'),
		payload: payload.toString('hex')
	};
	return payload;
}

export function recordPeerTxComplete(
	state: IFinalOpeningNonces,
	channelId: string,
	payload: Buffer
): void {
	validPayload(channelId, payload);
	const hex = payload.toString('hex');
	if (state.peer !== undefined && state.peer !== hex)
		throw new Error('Peer changed its remembered opening tx_complete');
	state.peer = hex;
}
