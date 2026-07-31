/**
 * Recovery frame codec (docs/RECOVERY-PROTOCOL.md 5.3, Phase 2).
 *
 * Encodes a RecoveryFrame's typed payload (mutations, outbound messages, and
 * an optional full-state snapshot) to a deterministic JSON byte string and
 * back. The codec reuses the storage layer's serializers for every
 * state-bearing shape, which is what makes reconstruction byte-identical to
 * direct writes: a channel state decoded from a frame is EXACTLY the object
 * `saveChannel` would have been handed at commit time, so the row it produces
 * is the row the live node wrote.
 *
 * The frame hash is computed over these plaintext bytes; encode once, store,
 * decode on replay. JSON key order follows object insertion order, which this
 * module keeps fixed, so hashing the encoded bytes is stable.
 */

import { createHash } from 'crypto';
import {
	serializeChannelState,
	deserializeChannelState,
	serializeChainMonitorState,
	deserializeChainMonitorState,
	serializePaymentInfo,
	deserializePaymentInfo,
	ISerializedChannelState,
	ISerializedPaymentInfo
} from '../storage/serialization';
import { IRecoveryOutboxMessage } from '../storage/types';
import {
	RecoveryFrame,
	RecoveryMutation,
	RecoveryOutboundMessage,
	RecoverySnapshot
} from './types';

/** JSON-safe encoding of one RecoveryMutation. */
interface IEncodedMutation {
	type: RecoveryMutation['type'];
	[key: string]: unknown;
}

interface IEncodedOutboundMessage {
	peerId: string;
	channelId?: string;
	messageType: number;
	wireMessage: string;
	disposition: IRecoveryOutboxMessage['disposition'];
}

interface IEncodedSnapshot {
	channels: Array<{
		channelId: string;
		state: ISerializedChannelState;
		peerPubkey: string;
	}>;
	keyIndices: Array<{ channelId: string; channelIndex: number }>;
	chainMonitors: Array<{ channelId: string; state: string }>;
	preimages: Array<{ paymentHash: string; preimage: string }>;
	payments: Array<{ paymentHash: string; payment: ISerializedPaymentInfo }>;
	paymentSecrets: Array<{ paymentHash: string; secret: string }>;
	htlcPaymentMappings: Array<{ key: string; paymentHash: string }>;
	forwardedHtlcs: Array<{
		outKey: string;
		inChannelId: string;
		inHtlcId: string;
	}>;
	htlcSharedSecrets: Array<{ key: string; secret: string }>;
	outbox: IEncodedOutboundMessage[];
}

interface IEncodedFrame {
	version: 1;
	writerEpoch: string;
	sequence: string;
	previousFrameHash: string;
	timestamp: number;
	mutations: IEncodedMutation[];
	outboundMessages: IEncodedOutboundMessage[];
	snapshot?: IEncodedSnapshot;
}

function encodeMutation(mutation: RecoveryMutation): IEncodedMutation {
	switch (mutation.type) {
		case 'channel_state':
			return {
				type: mutation.type,
				channelId: mutation.channelId,
				state: serializeChannelState(mutation.state),
				peerPubkey: mutation.peerPubkey
			};
		case 'channel_key_index':
			return {
				type: mutation.type,
				channelId: mutation.channelId,
				channelIndex: mutation.channelIndex
			};
		case 'chain_monitor':
			return {
				type: mutation.type,
				channelId: mutation.channelId,
				state: serializeChainMonitorState(mutation.state)
			};
		case 'payment_preimage':
			return {
				type: mutation.type,
				paymentHash: mutation.paymentHash,
				preimage: mutation.preimage.toString('hex')
			};
		case 'htlc_payment_mapping':
			return {
				type: mutation.type,
				htlcKey: mutation.htlcKey,
				paymentHash: mutation.paymentHash
			};
		case 'delete_htlc_payment_mapping':
			return { type: mutation.type, htlcKey: mutation.htlcKey };
		case 'htlc_shared_secret':
			return {
				type: mutation.type,
				key: mutation.key,
				secret: mutation.secret.toString('hex')
			};
		case 'delete_htlc_shared_secret':
			return { type: mutation.type, key: mutation.key };
		case 'forwarded_htlc':
			return {
				type: mutation.type,
				outKey: mutation.outKey,
				inChannelId: mutation.inChannelId.toString('hex'),
				inHtlcId: mutation.inHtlcId.toString()
			};
		case 'delete_forwarded_htlc':
			return { type: mutation.type, outKey: mutation.outKey };
		case 'payment_state':
			return {
				type: mutation.type,
				paymentHash: mutation.paymentHash,
				payment: serializePaymentInfo(mutation.payment)
			};
		case 'payment_secret':
			return {
				type: mutation.type,
				paymentHash: mutation.paymentHash,
				secret: mutation.secret.toString('hex')
			};
		case 'delete_payment_secret':
			return { type: mutation.type, paymentHash: mutation.paymentHash };
		case 'channel_closed':
			return { type: mutation.type, channelId: mutation.channelId };
		case 'outbox_supersede':
			return {
				type: mutation.type,
				channelId: mutation.channelId,
				messageTypes: mutation.messageTypes
			};
	}
}

function decodeMutation(encoded: IEncodedMutation): RecoveryMutation {
	switch (encoded.type) {
		case 'channel_state':
			return {
				type: encoded.type,
				channelId: encoded.channelId as string,
				state: deserializeChannelState(
					encoded.state as ISerializedChannelState
				),
				peerPubkey: encoded.peerPubkey as string
			};
		case 'channel_key_index':
			return {
				type: encoded.type,
				channelId: encoded.channelId as string,
				channelIndex: encoded.channelIndex as number
			};
		case 'chain_monitor':
			return {
				type: encoded.type,
				channelId: encoded.channelId as string,
				state: deserializeChainMonitorState(encoded.state as string)
			};
		case 'payment_preimage':
			return {
				type: encoded.type,
				paymentHash: encoded.paymentHash as string,
				preimage: Buffer.from(encoded.preimage as string, 'hex')
			};
		case 'htlc_payment_mapping':
			return {
				type: encoded.type,
				htlcKey: encoded.htlcKey as string,
				paymentHash: encoded.paymentHash as string
			};
		case 'delete_htlc_payment_mapping':
			return { type: encoded.type, htlcKey: encoded.htlcKey as string };
		case 'htlc_shared_secret':
			return {
				type: encoded.type,
				key: encoded.key as string,
				secret: Buffer.from(encoded.secret as string, 'hex')
			};
		case 'delete_htlc_shared_secret':
			return { type: encoded.type, key: encoded.key as string };
		case 'forwarded_htlc':
			return {
				type: encoded.type,
				outKey: encoded.outKey as string,
				inChannelId: Buffer.from(encoded.inChannelId as string, 'hex'),
				inHtlcId: BigInt(encoded.inHtlcId as string)
			};
		case 'delete_forwarded_htlc':
			return { type: encoded.type, outKey: encoded.outKey as string };
		case 'payment_state':
			return {
				type: encoded.type,
				paymentHash: encoded.paymentHash as string,
				payment: deserializePaymentInfo(
					encoded.payment as ISerializedPaymentInfo
				)
			};
		case 'payment_secret':
			return {
				type: encoded.type,
				paymentHash: encoded.paymentHash as string,
				secret: Buffer.from(encoded.secret as string, 'hex')
			};
		case 'delete_payment_secret':
			return { type: encoded.type, paymentHash: encoded.paymentHash as string };
		case 'channel_closed':
			return { type: encoded.type, channelId: encoded.channelId as string };
		case 'outbox_supersede':
			return {
				type: encoded.type,
				channelId: encoded.channelId as string,
				messageTypes: encoded.messageTypes as number[] | undefined
			};
		default:
			throw new Error(
				`Unknown recovery mutation type: ${String(encoded.type)}`
			);
	}
}

function encodeOutboundMessage(
	message: RecoveryOutboundMessage
): IEncodedOutboundMessage {
	return {
		peerId: message.peerId,
		channelId: message.channelId,
		messageType: message.messageType,
		wireMessage: message.wireMessage.toString('hex'),
		disposition: message.disposition
	};
}

function decodeOutboundMessage(
	encoded: IEncodedOutboundMessage
): RecoveryOutboundMessage {
	return {
		peerId: encoded.peerId,
		channelId: encoded.channelId,
		messageType: encoded.messageType,
		wireMessage: Buffer.from(encoded.wireMessage, 'hex'),
		disposition: encoded.disposition
	};
}

function encodeSnapshot(snapshot: RecoverySnapshot): IEncodedSnapshot {
	return {
		channels: snapshot.channels.map((c) => ({
			channelId: c.channelId,
			state: serializeChannelState(c.state),
			peerPubkey: c.peerPubkey
		})),
		keyIndices: snapshot.keyIndices,
		chainMonitors: snapshot.chainMonitors.map((m) => ({
			channelId: m.channelId,
			state: serializeChainMonitorState(m.state)
		})),
		preimages: snapshot.preimages.map((p) => ({
			paymentHash: p.paymentHash,
			preimage: p.preimage.toString('hex')
		})),
		payments: snapshot.payments.map((p) => ({
			paymentHash: p.paymentHash,
			payment: serializePaymentInfo(p.payment)
		})),
		paymentSecrets: snapshot.paymentSecrets.map((s) => ({
			paymentHash: s.paymentHash,
			secret: s.secret.toString('hex')
		})),
		htlcPaymentMappings: snapshot.htlcPaymentMappings,
		forwardedHtlcs: snapshot.forwardedHtlcs.map((f) => ({
			outKey: f.outKey,
			inChannelId: f.inChannelId.toString('hex'),
			inHtlcId: f.inHtlcId.toString()
		})),
		htlcSharedSecrets: snapshot.htlcSharedSecrets.map((s) => ({
			key: s.key,
			secret: s.secret.toString('hex')
		})),
		outbox: snapshot.outbox.map(encodeOutboundMessage)
	};
}

function decodeSnapshot(encoded: IEncodedSnapshot): RecoverySnapshot {
	return {
		channels: encoded.channels.map((c) => ({
			channelId: c.channelId,
			state: deserializeChannelState(c.state),
			peerPubkey: c.peerPubkey
		})),
		keyIndices: encoded.keyIndices,
		chainMonitors: encoded.chainMonitors.map((m) => ({
			channelId: m.channelId,
			state: deserializeChainMonitorState(m.state)
		})),
		preimages: encoded.preimages.map((p) => ({
			paymentHash: p.paymentHash,
			preimage: Buffer.from(p.preimage, 'hex')
		})),
		payments: encoded.payments.map((p) => ({
			paymentHash: p.paymentHash,
			payment: deserializePaymentInfo(p.payment)
		})),
		paymentSecrets: encoded.paymentSecrets.map((s) => ({
			paymentHash: s.paymentHash,
			secret: Buffer.from(s.secret, 'hex')
		})),
		htlcPaymentMappings: encoded.htlcPaymentMappings,
		forwardedHtlcs: encoded.forwardedHtlcs.map((f) => ({
			outKey: f.outKey,
			inChannelId: Buffer.from(f.inChannelId, 'hex'),
			inHtlcId: BigInt(f.inHtlcId)
		})),
		htlcSharedSecrets: encoded.htlcSharedSecrets.map((s) => ({
			key: s.key,
			secret: Buffer.from(s.secret, 'hex')
		})),
		outbox: encoded.outbox.map(decodeOutboundMessage)
	};
}

/** Encode a frame to the plaintext bytes the frame hash commits to. */
export function encodeFrame(frame: RecoveryFrame): Buffer {
	const encoded: IEncodedFrame = {
		version: frame.version,
		writerEpoch: frame.writerEpoch.toString(),
		sequence: frame.sequence.toString(),
		previousFrameHash: frame.previousFrameHash.toString('hex'),
		timestamp: frame.timestamp,
		mutations: frame.mutations.map(encodeMutation),
		outboundMessages: frame.outboundMessages.map(encodeOutboundMessage)
	};
	if (frame.snapshot) {
		encoded.snapshot = encodeSnapshot(frame.snapshot);
	}
	return Buffer.from(JSON.stringify(encoded), 'utf8');
}

/** Decode plaintext frame bytes. Throws on any malformed content. */
export function decodeFrame(plaintext: Buffer): RecoveryFrame {
	const encoded = JSON.parse(plaintext.toString('utf8')) as IEncodedFrame;
	if (encoded.version !== 1) {
		throw new Error(`Unsupported recovery frame version: ${encoded.version}`);
	}
	const frame: RecoveryFrame = {
		version: 1,
		writerEpoch: BigInt(encoded.writerEpoch),
		sequence: BigInt(encoded.sequence),
		previousFrameHash: Buffer.from(encoded.previousFrameHash, 'hex'),
		timestamp: encoded.timestamp,
		mutations: encoded.mutations.map(decodeMutation),
		outboundMessages: encoded.outboundMessages.map(decodeOutboundMessage)
	};
	if (encoded.snapshot) {
		frame.snapshot = decodeSnapshot(encoded.snapshot);
	}
	return frame;
}

/** SHA-256 over the plaintext frame bytes: the hash the chain links. */
export function hashFrame(plaintext: Buffer): Buffer {
	return createHash('sha256').update(plaintext).digest();
}
