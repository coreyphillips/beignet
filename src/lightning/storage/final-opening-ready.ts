import type { BIP32Interface } from 'bip32';
import { getPublicKey, isValidPublicKey } from '../crypto/ecdh';
import { generateNonce } from '../crypto/musig';
import { hmacSha256 } from '../crypto/provider';
import { generateFromSeed, MAX_INDEX } from '../keys/shachain';
import { deriveChannelKeys, deriveLightningKeys } from '../keys/wallet-keys';
import { decodeCommitmentSignedMessage } from '../message/channel-commitment';
import {
	decodeChannelReadyMessage,
	encodeChannelReadyMessage
} from '../message/channel-funding';
import { MAX_LIGHTNING_PAYLOAD } from '../message/custom-records';
import { decodeTxCompleteMessage } from '../message/interactive-tx';
import type {
	IFinalOpeningNonces,
	IFinalReestablishNonce
} from './final-opening-nonces';

export class FinalChannelReadyProtocolError extends Error {}

function decodeReady(payload: string): Buffer {
	if (
		typeof payload !== 'string' ||
		payload.length > MAX_LIGHTNING_PAYLOAD * 2 ||
		!/^(?:[0-9a-f]{2})+$/.test(payload)
	)
		throw new Error('Invalid stored channel_ready');
	return Buffer.from(payload, 'hex');
}

export function requireReadySession(
	state: IFinalOpeningNonces,
	requireFunding: boolean
): void {
	if (
		!state.session ||
		!state.signing?.exit ||
		!state.peer ||
		!state.local ||
		(requireFunding && !state.signing.fundingTransaction)
	)
		throw new Error('Opening is incomplete for readiness');
}

export function verifyReadyNonce(
	state: IFinalOpeningNonces,
	nonce: Buffer,
	local: boolean
): void {
	if (
		!Buffer.isBuffer(nonce) ||
		nonce.length !== 66 ||
		!isValidPublicKey(nonce.subarray(0, 33)) ||
		!isValidPublicKey(nonce.subarray(33))
	)
		throw new FinalChannelReadyProtocolError('Invalid channel readiness nonce');
	// Only the peer's own unused height-one verification nonce may be re-advertised.
	const used = [];
	for (const [payload, ours] of [
		[state.local!.payload, true],
		[state.peer!, false]
	] as const) {
		const pair = decodeTxCompleteMessage(Buffer.from(payload, 'hex'), {
			taproot: true
		}).commitNonces!;
		used.push(pair.current);
		if (ours || local) used.push(pair.next);
	}
	for (const signed of [state.signing!.peer, state.signing!.outgoing]) {
		if (signed)
			used.push(
				decodeCommitmentSignedMessage(
					Buffer.from(signed, 'hex')
				).partialSignatureWithNonce!.subarray(32)
			);
	}
	const otherReady = local ? state.peerReady : state.localReady;
	if (otherReady)
		used.push(
			decodeChannelReadyMessage(decodeReady(otherReady)).nextLocalNonce!
		);
	const otherReconnect = local ? state.peerReconnect : state.localReconnect;
	if (otherReconnect) used.push(Buffer.from(otherReconnect.nonce, 'hex'));
	if (used.some((n) => !n || nonce.equals(n)))
		throw new FinalChannelReadyProtocolError(
			'Readiness nonce collides with another commitment promise'
		);
}

export function verifyReady(
	state: IFinalOpeningNonces,
	id: string,
	payload: Buffer,
	local: boolean,
	requireAlias: boolean
): void {
	requireReadySession(state, true);
	if (!Buffer.isBuffer(payload) || payload.length > MAX_LIGHTNING_PAYLOAD)
		throw new FinalChannelReadyProtocolError('Invalid channel_ready length');
	let msg: ReturnType<typeof decodeChannelReadyMessage>;
	try {
		msg = decodeChannelReadyMessage(payload);
	} catch (err) {
		throw new FinalChannelReadyProtocolError(
			'Invalid final channel_ready: ' + String(err)
		);
	}
	const session = state.session!;
	const expected = local ? undefined : session.remoteSecondPerCommitmentPoint;
	const first = (
		local ? session.terms.localBasepoints : session.terms.remoteBasepoints
	).firstPerCommitmentPoint;
	if (
		msg.channelId.toString('hex') !== id ||
		!isValidPublicKey(msg.secondPerCommitmentPoint) ||
		msg.secondPerCommitmentPoint.toString('hex') === first ||
		(expected !== undefined &&
			expected !== msg.secondPerCommitmentPoint.toString('hex')) ||
		(requireAlias && !msg.shortChannelId) ||
		(msg.shortChannelId && msg.shortChannelId.length !== 8) ||
		!msg.nextLocalNonce
	)
		throw new FinalChannelReadyProtocolError(
			'Invalid final channel_ready fields'
		);
	verifyReadyNonce(state, msg.nextLocalNonce, local);
}

/** A peer may refresh its optional alias while retaining its original height-one promise. */
export function requireSameReadyPromise(first: Buffer, next: Buffer): void {
	if (first.equals(next)) return;
	const a = decodeChannelReadyMessage(first);
	const b = decodeChannelReadyMessage(next);
	if (
		!a.secondPerCommitmentPoint.equals(b.secondPerCommitmentPoint) ||
		!a.nextLocalNonce!.equals(b.nextLocalNonce!)
	)
		throw new FinalChannelReadyProtocolError(
			'Peer changed its first channel_ready commitment promise'
		);
}

export function verifyStoredReadiness(
	state: IFinalOpeningNonces,
	id: string,
	requireAlias: boolean
): void {
	if (state.localReady !== undefined)
		verifyReady(state, id, decodeReady(state.localReady), true, true);
	if (state.peerReady !== undefined)
		verifyReady(state, id, decodeReady(state.peerReady), false, requireAlias);
	for (const [entry, local] of [
		[state.localReconnect, true],
		[state.peerReconnect, false]
	] as const) {
		if (entry === undefined) continue;
		requireReadySession(state, local);
		if (
			!entry ||
			Object.keys(entry).sort().join(',') !== 'generation,nonce' ||
			!Number.isSafeInteger(entry.generation) ||
			entry.generation < 1 ||
			typeof entry.nonce !== 'string' ||
			!/^[0-9a-f]{132}$/.test(entry.nonce)
		)
			throw new Error('Invalid stored reconnect nonce');
		verifyReadyNonce(state, Buffer.from(entry.nonce, 'hex'), local);
	}
}

export function preservesReconnectNonce(
	before?: IFinalReestablishNonce,
	after?: IFinalReestablishNonce
): boolean {
	return (
		before === undefined ||
		(after !== undefined &&
			(after.generation > before.generation ||
				(after.generation === before.generation &&
					after.nonce === before.nonce)))
	);
}

export function readyKeys(
	root: BIP32Interface,
	state: IFinalOpeningNonces,
	identity: string
): ReturnType<typeof deriveChannelKeys> {
	const session = state.session!;
	const [, nodeId, network] = JSON.parse(identity);
	if (
		network !== 'regtest' ||
		nodeId !== deriveLightningKeys(root, 1).nodePublicKey.toString('hex')
	)
		throw new Error('Readiness requires the enrolled regtest wallet');
	const keys = deriveChannelKeys(root, 1, session.channelKeyIndex);
	if (
		keys.channelBasepoints.fundingPubkey.toString('hex') !==
		session.terms.localBasepoints.fundingPubkey
	)
		throw new Error('Incorrect commitment funding locator');
	return keys;
}

/** Generation zero is the immutable channel_ready. Reconnect generations start at one.
 * The wallet copy alone cannot reproduce the secret signing handle.
 */
export function readyVerificationNonce(
	context: Buffer,
	key: Buffer,
	generation: number
): Uint8Array {
	return generateNonce({
		publicKey: getPublicKey(key),
		secretKey: key,
		sessionId: hmacSha256(
			context,
			Buffer.from('final-ready-height-one/' + generation)
		),
		extraInput: Buffer.from('beignet-final-ready-verification-v1')
	});
}

export function makeReadyPayload(
	id: string,
	keys: ReturnType<typeof deriveChannelKeys>,
	context: Buffer
): Buffer {
	const alias = Buffer.from(
		hmacSha256(context, Buffer.from('final-ready-alias')).subarray(0, 8)
	);
	// Use a synthetic block height far above today's chain.
	alias[0] = 0xff;
	return encodeChannelReadyMessage({
		channelId: Buffer.from(id, 'hex'),
		secondPerCommitmentPoint: getPublicKey(
			generateFromSeed(keys.perCommitmentSeed, MAX_INDEX - 1n)
		),
		shortChannelId: alias,
		nextLocalNonce: Buffer.from(
			readyVerificationNonce(context, keys.fundingPrivkey, 0)
		)
	});
}
