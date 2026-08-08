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
import {
	IForwardingEvent,
	IInvoiceInfo,
	IRecoveryOutboxMessage
} from '../storage/types';
import {
	RecoveryDurability,
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
	/** Snapshot content schema, authenticated by the frame hash. Written
	 *  first so its bytes sit at a stable position; conditional so frames
	 *  captured before the field existed re-encode byte-identically. */
	schemaVersion?: string;
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
	invoices: Array<{ paymentHash: string; invoice: IEncodedInvoice }>;
	invoicePathIds: Array<{ paymentHash: string; pathId: string }>;
	forwardingEvents: IEncodedForwardingEvent[];
	outbox: Array<IEncodedOutboundMessage & { frameSequence: number | null }>;
}

/** IInvoiceInfo with its one bigint field made JSON-safe. */
type IEncodedInvoice = Omit<IInvoiceInfo, 'amountMsat'> & {
	amountMsat?: string;
};

type IEncodedForwardingEvent = Omit<
	Omit<IForwardingEvent, 'id'>,
	'amountInMsat' | 'amountOutMsat' | 'feeMsat'
> & {
	amountInMsat: string;
	amountOutMsat: string;
	feeMsat: string;
};

function encodeInvoice(invoice: IInvoiceInfo): IEncodedInvoice {
	const { amountMsat, ...rest } = invoice;
	return amountMsat != null
		? { ...rest, amountMsat: amountMsat.toString() }
		: { ...rest };
}

function decodeInvoice(encoded: IEncodedInvoice): IInvoiceInfo {
	const { amountMsat, ...rest } = encoded;
	return amountMsat != null
		? { ...rest, amountMsat: BigInt(amountMsat) }
		: { ...rest };
}

function encodeForwardingEvent(
	event: Omit<IForwardingEvent, 'id'>
): IEncodedForwardingEvent {
	return {
		...event,
		amountInMsat: event.amountInMsat.toString(),
		amountOutMsat: event.amountOutMsat.toString(),
		feeMsat: event.feeMsat.toString()
	};
}

function decodeForwardingEvent(
	encoded: IEncodedForwardingEvent
): Omit<IForwardingEvent, 'id'> {
	return {
		...encoded,
		amountInMsat: BigInt(encoded.amountInMsat),
		amountOutMsat: BigInt(encoded.amountOutMsat),
		feeMsat: BigInt(encoded.feeMsat)
	};
}

interface IEncodedFrame {
	version: 1;
	writerEpoch: string;
	sequence: string;
	previousFrameHash: string;
	timestamp: number;
	mutations: IEncodedMutation[];
	outboundMessages: IEncodedOutboundMessage[];
	durability?: RecoveryDurability;
	durabilityPolicy?: number;
	snapshot?: IEncodedSnapshot;
}

/** The only durability values a frame may declare (spec 5.8). */
const DURABILITY_VALUES: readonly RecoveryDurability[] = [
	'local',
	'async-remote',
	'quorum'
];

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
		case 'delete_payment':
		case 'delete_preimage':
		case 'delete_invoice':
		case 'delete_invoice_path_id':
			return { type: mutation.type, paymentHash: mutation.paymentHash };
		case 'invoice_state':
			return {
				type: mutation.type,
				paymentHash: mutation.paymentHash,
				invoice: encodeInvoice(mutation.invoice)
			};
		case 'invoice_path_id':
			return {
				type: mutation.type,
				paymentHash: mutation.paymentHash,
				pathId: mutation.pathId.toString('hex')
			};
		case 'forwarding_event':
			return {
				type: mutation.type,
				event: encodeForwardingEvent(mutation.event)
			};
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
		case 'delete_payment':
		case 'delete_preimage':
		case 'delete_invoice':
		case 'delete_invoice_path_id':
			return { type: encoded.type, paymentHash: encoded.paymentHash as string };
		case 'invoice_state':
			return {
				type: encoded.type,
				paymentHash: encoded.paymentHash as string,
				invoice: decodeInvoice(encoded.invoice as IEncodedInvoice)
			};
		case 'invoice_path_id':
			return {
				type: encoded.type,
				paymentHash: encoded.paymentHash as string,
				pathId: Buffer.from(encoded.pathId as string, 'hex')
			};
		case 'forwarding_event':
			return {
				type: encoded.type,
				event: decodeForwardingEvent(encoded.event as IEncodedForwardingEvent)
			};
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
		// Pure passthrough, no default: a decoded pre-field frame must
		// re-encode to its stored hash byte for byte.
		...(snapshot.schemaVersion !== undefined
			? { schemaVersion: snapshot.schemaVersion }
			: {}),
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
		invoices: snapshot.invoices.map((i) => ({
			paymentHash: i.paymentHash,
			invoice: encodeInvoice(i.invoice)
		})),
		invoicePathIds: snapshot.invoicePathIds.map((i) => ({
			paymentHash: i.paymentHash,
			pathId: i.pathId.toString('hex')
		})),
		forwardingEvents: snapshot.forwardingEvents.map(encodeForwardingEvent),
		outbox: snapshot.outbox.map((row) => ({
			...encodeOutboundMessage(row),
			frameSequence: row.frameSequence
		}))
	};
}

function decodeSnapshot(encoded: IEncodedSnapshot): RecoverySnapshot {
	return {
		...(encoded.schemaVersion !== undefined
			? { schemaVersion: encoded.schemaVersion }
			: {}),
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
		invoices: encoded.invoices.map((i) => ({
			paymentHash: i.paymentHash,
			invoice: decodeInvoice(i.invoice)
		})),
		invoicePathIds: encoded.invoicePathIds.map((i) => ({
			paymentHash: i.paymentHash,
			pathId: Buffer.from(i.pathId, 'hex')
		})),
		forwardingEvents: encoded.forwardingEvents.map(decodeForwardingEvent),
		outbox: encoded.outbox.map((row) => ({
			...decodeOutboundMessage(row),
			frameSequence: row.frameSequence
		}))
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
	// Key insertion order IS the byte layout the frame hash commits to, so
	// durability is written here, between outboundMessages and snapshot, on
	// every frame that declares one. A frame without a declaration encodes
	// exactly as it did before Phase 6, which is what keeps pre-existing
	// journals verifiable and their hashes stable.
	if (frame.durability) {
		encoded.durability = frame.durability;
		// The stamp sits immediately after the declaration it qualifies, and is
		// a pure passthrough with no default: re-encoding a decoded frame has
		// to reproduce its stored hash byte for byte, so the codec must never
		// invent a value the writer did not put there.
		if (frame.durabilityPolicy !== undefined) {
			encoded.durabilityPolicy = frame.durabilityPolicy;
		}
	}
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
	if (encoded.durability !== undefined) {
		// An unrecognised value is a CORRUPT frame, never a tolerated unknown.
		// The restore path reads this field to decide whether a channel may
		// resume, so silently dropping a value we cannot interpret would turn
		// a garbled frame into a downgrade nobody noticed.
		if (!DURABILITY_VALUES.includes(encoded.durability)) {
			throw new Error(
				`Unsupported recovery frame durability: ${String(encoded.durability)}`
			);
		}
		frame.durability = encoded.durability;
	}
	if (encoded.durabilityPolicy !== undefined) {
		if (
			!Number.isInteger(encoded.durabilityPolicy) ||
			encoded.durabilityPolicy < 1
		) {
			throw new Error(
				`Unsupported recovery frame durability policy: ${String(
					encoded.durabilityPolicy
				)}`
			);
		}
		frame.durabilityPolicy = encoded.durabilityPolicy;
	} else if (frame.durability === 'quorum') {
		// A quorum declaration with no stamp is CORRUPTION, not an old writer:
		// no released build has ever written a quorum frame, so nothing
		// legitimate can produce this. Structural validity throws here.
		// Whether a well formed version is one this build understands is a
		// different question, answered by a refusal in deriveWireSafetyProof,
		// so a newer writer's journal still restores down the DLP path rather
		// than failing to restore at all.
		throw new Error(
			`Recovery journal frame ${frame.sequence} declares quorum durability with no policy version`
		);
	}
	if (encoded.snapshot) {
		frame.snapshot = decodeSnapshot(encoded.snapshot);
	}
	return frame;
}

/** SHA-256 over the plaintext frame bytes: the hash the chain links. */
export function hashFrame(plaintext: Buffer): Buffer {
	return createHash('sha256').update(plaintext).digest();
}
