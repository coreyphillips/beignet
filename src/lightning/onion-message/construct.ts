/**
 * BOLT 7.5: Onion Message Construction
 *
 * Builds onion packets for message delivery (similar to payment onions
 * but without HTLC-specific fields). Uses 1300-byte payloads with
 * Sphinx onion routing.
 */

import crypto from 'crypto';
import {
	IOnionMessage,
	IOnionMessagePayload,
	ISendOnionMessageOptions
} from './types';
import { encodeOnionMessagePayload } from './codec';
import { ONION_VERSION, ROUTING_INFO_LENGTH } from '../onion/types';
import {
	computeSharedSecrets,
	deriveHopKeys,
	generateCipherStream,
	generateKey
} from '../onion/sphinx-crypto';
import { getPublicKey } from '../crypto/ecdh';
import { IBlindedPath, encodeBlindedHopData } from '../onion/blinded-path';
import { encodeOnionPacket } from '../onion/construct';

/**
 * Generate filler bytes for onion message construction.
 * Same algorithm as payment onion filler but for onion message payloads.
 */
function generateFiller(
	sharedSecrets: Buffer[],
	payloadSizes: number[]
): Buffer {
	let filler = Buffer.alloc(0);

	for (let i = 0; i < sharedSecrets.length - 1; i++) {
		const hopSize = payloadSizes[i] + 32; // payload + HMAC
		const fillerStart = ROUTING_INFO_LENGTH - filler.length;

		const keys = deriveHopKeys(sharedSecrets[i]);
		const stream = generateCipherStream(
			keys.rho,
			ROUTING_INFO_LENGTH + hopSize
		);

		// Extend filler by hopSize zeros
		const newFiller = Buffer.alloc(filler.length + hopSize);
		filler.copy(newFiller, 0);
		filler = newFiller;

		// XOR entire filler with stream[fillerStart..fillerStart+filler.length]
		for (let j = 0; j < filler.length; j++) {
			filler[j] ^= stream[fillerStart + j];
		}
	}

	return filler;
}

/**
 * Construct an onion packet for onion message delivery.
 *
 * @param sessionKey - 32-byte random session key (ephemeral private key)
 * @param hops - Array of { pubkey, payload } for each hop in the path
 * @returns Encoded onion packet as a 1366-byte buffer
 */
export function constructOnionMessagePacket(
	sessionKey: Buffer,
	hops: { pubkey: Buffer; payload: Buffer }[]
): Buffer {
	if (hops.length === 0) {
		throw new Error('At least one hop is required');
	}
	if (hops.length > 20) {
		throw new Error('Too many hops (max 20)');
	}

	const hopPubkeys = hops.map((h) => h.pubkey);
	const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
		sessionKey,
		hopPubkeys
	);

	const payloadSizes = hops.map((h) => h.payload.length);

	// Generate filler
	const filler = generateFiller(sharedSecrets, payloadSizes);

	// BOLT 4: initialize routing_info from the pseudo-random `pad`-key stream
	// keyed by the SESSION private key, NOT zeros and NOT any per-hop secret.
	// Zero-init leaves the trailing padding recognizable after each hop
	// decrypts (leaking hop count); keying from a hop's shared secret would let
	// that hop regenerate the stream and locate the padding boundary.
	let routingInfo = generateCipherStream(
		generateKey('pad', sessionKey),
		ROUTING_INFO_LENGTH
	);
	let currentHmac = Buffer.alloc(32); // Start with zero HMAC (last hop marker)

	// Build right-to-left (last hop first)
	for (let i = hops.length - 1; i >= 0; i--) {
		const keys = deriveHopKeys(sharedSecrets[i]);
		const payloadBytes = hops[i].payload;
		const shiftSize = payloadBytes.length + 32; // payload + HMAC

		// Right-shift routing info to make room
		const newRoutingInfo = Buffer.alloc(ROUTING_INFO_LENGTH);
		payloadBytes.copy(newRoutingInfo, 0);
		currentHmac.copy(newRoutingInfo, payloadBytes.length);
		routingInfo.copy(
			newRoutingInfo,
			shiftSize,
			0,
			ROUTING_INFO_LENGTH - shiftSize
		);
		routingInfo = newRoutingInfo;

		// XOR with cipher stream
		const stream = generateCipherStream(keys.rho, ROUTING_INFO_LENGTH);
		for (let j = 0; j < ROUTING_INFO_LENGTH; j++) {
			routingInfo[j] ^= stream[j];
		}

		// For the innermost hop, apply filler AFTER XOR
		if (i === hops.length - 1 && filler.length > 0) {
			filler.copy(routingInfo, ROUTING_INFO_LENGTH - filler.length);
		}

		// Compute HMAC for this hop
		currentHmac = Buffer.from(
			crypto.createHmac('sha256', keys.mu).update(routingInfo).digest()
		);
	}

	// Serialize to 1366-byte onion packet
	return encodeOnionPacket({
		version: ONION_VERSION,
		ephemeralKey: ephemeralKeys[0],
		routingInfo,
		hmac: currentHmac
	});
}

/**
 * Construct a complete onion message (type 513) for delivery to a destination.
 *
 * This builds the onion packet and wraps it with the blinding point.
 * For non-blinded paths, the blinding point is derived from the session key.
 *
 * @param sessionKey - 32-byte random session key
 * @param path - Array of node public keys forming the route
 * @param payloads - Encoded payload for each hop
 * @returns The complete IOnionMessage ready for wire encoding
 */
export function constructOnionMessage(
	sessionKey: Buffer,
	path: Buffer[],
	payloads: Buffer[]
): IOnionMessage {
	if (path.length !== payloads.length) {
		throw new Error('path and payloads must have the same length');
	}

	const hops = path.map((pubkey, i) => ({
		pubkey,
		payload: payloads[i]
	}));

	const onionRoutingPacket = constructOnionMessagePacket(sessionKey, hops);
	const blindingPoint = getPublicKey(sessionKey);

	return {
		blindingPoint,
		onionRoutingPacket
	};
}

/**
 * Convenience API to construct an onion message to a single destination.
 *
 * @param destination - 33-byte destination node public key
 * @param messageData - Application data as a Map of TLV type -> value
 * @param sessionKey - Optional 32-byte session key (random if not provided)
 * @param options - Optional: reply path, etc.
 * @returns The complete IOnionMessage
 */
export function constructSimpleOnionMessage(
	destination: Buffer,
	messageData: Map<number, Buffer>,
	sessionKey?: Buffer,
	options?: ISendOnionMessageOptions
): IOnionMessage {
	const sessKey = sessionKey || crypto.randomBytes(32);

	// Build the final hop payload
	const finalPayload: IOnionMessagePayload = {
		replyPath: options?.replyPath,
		messageTlvs: messageData
	};

	const encodedPayload = encodeOnionMessagePayload(finalPayload);

	return constructOnionMessage(sessKey, [destination], [encodedPayload]);
}

/**
 * Construct a multi-hop onion message through intermediate nodes to a destination.
 *
 * @param intermediateNodes - Array of intermediate node public keys
 * @param destination - Final destination public key
 * @param messageData - Application data for the final hop
 * @param sessionKey - Optional session key
 * @param options - Optional: reply path, etc.
 * @returns The complete IOnionMessage
 */
export function constructMultiHopOnionMessage(
	intermediateNodes: Buffer[],
	destination: Buffer,
	messageData: Map<number, Buffer>,
	sessionKey?: Buffer,
	options?: ISendOnionMessageOptions
): IOnionMessage {
	const sessKey = sessionKey || crypto.randomBytes(32);

	const path = [...intermediateNodes, destination];
	const payloads: Buffer[] = [];

	// Intermediate hops need encrypted_recipient_data with next_node_id
	for (let i = 0; i < intermediateNodes.length; i++) {
		const nextNode =
			i < intermediateNodes.length - 1 ? intermediateNodes[i + 1] : destination;
		const hopData = encodeBlindedHopData({ nextNodeId: nextNode });
		const intermediatePayload: IOnionMessagePayload = {
			encryptedRecipientData: hopData,
			messageTlvs: new Map()
		};
		payloads.push(encodeOnionMessagePayload(intermediatePayload));
	}

	// Final hop gets the message data and optional reply path
	const finalPayload: IOnionMessagePayload = {
		replyPath: options?.replyPath,
		messageTlvs: messageData
	};
	payloads.push(encodeOnionMessagePayload(finalPayload));

	return constructOnionMessage(sessKey, path, payloads);
}

/**
 * Construct a reply onion message using a blinded reply path.
 *
 * @param replyPath - The blinded path received in the original message
 * @param messageData - Application data for the reply
 * @param sessionKey - Optional session key
 * @returns The complete IOnionMessage
 */
export function constructReplyOnionMessage(
	replyPath: IBlindedPath,
	messageData: Map<number, Buffer>,
	sessionKey?: Buffer,
	options?: ISendOnionMessageOptions
): IOnionMessage {
	const sessKey = sessionKey || crypto.randomBytes(32);

	// The reply uses the blinded path's introduction node as the first hop.
	// The blinded hops contain encrypted routing data.
	const path: Buffer[] = [];
	const payloads: Buffer[] = [];

	// First hop: introduction node, payload includes encrypted data for first blinded hop
	if (replyPath.blindedHops.length === 0) {
		throw new Error('Reply path must have at least one blinded hop');
	}

	// Build hop payloads for the blinded path
	// The introduction node gets the first blinded hop's encrypted data. In a
	// 1-hop reply path the introduction node IS the recipient, so it must also
	// receive the message body; hard-coding an empty TLV map here made every
	// reply over a 1-hop path arrive empty.
	//
	// BOLT 4 route blinding: the sphinx onion is encrypted to each hop's
	// BLINDED node id — including the introduction node's (path_hops[0]) —
	// and every hop derives its blinded key from the path_key on receipt.
	// Sphinx-addressing the intro by its real id (the old behavior) produced
	// onions no spec implementation (CLN/LND) could peel.
	path.push(replyPath.blindedHops[0].blindedNodeId);
	const introIsRecipient = replyPath.blindedHops.length === 1;
	const introPayload: IOnionMessagePayload = {
		encryptedRecipientData: replyPath.blindedHops[0].encryptedData,
		// The recipient hop also carries OUR reply path when the message
		// expects an answer (e.g. invoice_request over an offer's path).
		...(introIsRecipient && options?.replyPath
			? { replyPath: options.replyPath }
			: {}),
		messageTlvs: introIsRecipient ? messageData : new Map()
	};
	payloads.push(encodeOnionMessagePayload(introPayload));

	// Additional blinded hops
	for (let i = 1; i < replyPath.blindedHops.length; i++) {
		const hop = replyPath.blindedHops[i];
		path.push(hop.blindedNodeId);

		const isLast = i === replyPath.blindedHops.length - 1;
		const hopPayload: IOnionMessagePayload = {
			encryptedRecipientData: hop.encryptedData,
			...(isLast && options?.replyPath ? { replyPath: options.replyPath } : {}),
			messageTlvs: isLast ? messageData : new Map()
		};
		payloads.push(encodeOnionMessagePayload(hopPayload));
	}

	const hops = path.map((pubkey, i) => ({
		pubkey,
		payload: payloads[i]
	}));

	const onionRoutingPacket = constructOnionMessagePacket(sessKey, hops);

	// For blinded reply paths, use the reply path's blinding point
	return {
		blindingPoint: replyPath.blindingPoint,
		onionRoutingPacket
	};
}
