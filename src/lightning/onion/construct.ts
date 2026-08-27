/**
 * BOLT 4: Onion Packet Construction
 *
 * Builds onion packets from a list of hop payloads. Payment onions are
 * always 1366 bytes; onion messages may use the BOLT 4 large form
 * (32834 bytes). Construction works right-to-left (last hop first),
 * wrapping each hop's payload into the routing info with XOR encryption
 * and HMAC.
 */

import crypto from 'crypto';
import {
	IHopPayload,
	IOnionPacket,
	LARGE_ONION_PACKET_LENGTH,
	LARGE_ROUTING_INFO_LENGTH,
	ONION_VERSION,
	ROUTING_INFO_LENGTH
} from './types';
import {
	computeSharedSecrets,
	deriveHopKeys,
	generateCipherStream,
	generateKey
} from './sphinx-crypto';
import { encodeHopPayload } from './hop-payload';

/**
 * Generate filler bytes that fill the tail of routingInfo.
 * This prevents the final recipient from determining their position
 * in the route based on the zero-padding at the end.
 *
 * For each outer hop (0 to N-2), the filler accumulates the stream
 * bytes that would be pushed beyond the 1300-byte boundary during
 * the right-shift in construction.
 */
export function generateFiller(
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
 * Construct a complete onion packet from a session key and hop payloads.
 */
export function constructOnionPacket(
	sessionKey: Buffer,
	hops: { pubkey: Buffer; payload: IHopPayload }[],
	associatedData?: Buffer
): IOnionPacket {
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

	// Pre-encode all hop payloads
	const encodedPayloads = hops.map((h) => encodeHopPayload(h.payload));
	const payloadSizes = encodedPayloads.map((p) => p.length);

	// Generate filler
	const filler = generateFiller(sharedSecrets, payloadSizes);

	// Initialize routing info with a deterministic pseudo-random pad stream,
	// NOT zeros (BOLT 4 Packet Construction). The pad key is derived from the
	// session key — generate_key("pad", session_key) — so the unused tail of
	// the onion is indistinguishable from real hop data and the final recipient
	// cannot infer the route length. Zero-init would leak that structure.
	let routingInfo = generateCipherStream(
		generateKey('pad', sessionKey),
		ROUTING_INFO_LENGTH
	);
	let currentHmac = Buffer.alloc(32); // Start with zero HMAC (last hop marker)

	// Build right-to-left (last hop first)
	for (let i = hops.length - 1; i >= 0; i--) {
		const keys = deriveHopKeys(sharedSecrets[i]);
		const payloadBytes = encodedPayloads[i];
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

		// For the innermost hop, apply filler AFTER XOR to overwrite
		// the encrypted tail with the pre-computed filler bytes
		if (i === hops.length - 1 && filler.length > 0) {
			filler.copy(routingInfo, ROUTING_INFO_LENGTH - filler.length);
		}

		// Compute HMAC for this hop (BOLT 4: HMAC(mu, routing_info || associated_data))
		const hmacCalc = crypto.createHmac('sha256', keys.mu).update(routingInfo);
		if (associatedData) {
			hmacCalc.update(associatedData);
		}
		currentHmac = Buffer.from(hmacCalc.digest());
	}

	return {
		version: ONION_VERSION,
		ephemeralKey: ephemeralKeys[0],
		routingInfo,
		hmac: currentHmac
	};
}

/**
 * Serialize an onion packet.
 * Format: version(1) + ephemeralKey(33) + routingInfo(n) + hmac(32),
 * where n is 1300 (standard form) or 32768 (large onion message form).
 * The whitelist keeps a malformed routing info (e.g. a short slice
 * produced by an adversarial relay payload) from ever serializing to a
 * third on-wire size.
 */
export function encodeOnionPacket(packet: IOnionPacket): Buffer {
	const riLen = packet.routingInfo.length;
	if (riLen !== ROUTING_INFO_LENGTH && riLen !== LARGE_ROUTING_INFO_LENGTH) {
		throw new Error(
			`Onion packet routing info must be 1300 or 32768 bytes, got ${riLen}`
		);
	}
	const buf = Buffer.alloc(66 + riLen);
	buf[0] = packet.version;
	packet.ephemeralKey.copy(buf, 1);
	packet.routingInfo.copy(buf, 34);
	packet.hmac.copy(buf, 34 + riLen);
	return buf;
}

/**
 * Deserialize a 1366-byte (standard) or 32834-byte (large onion message
 * form) buffer into an onion packet.
 */
export function decodeOnionPacket(buf: Buffer): IOnionPacket {
	if (buf.length !== 1366 && buf.length !== LARGE_ONION_PACKET_LENGTH) {
		throw new Error(
			`Onion packet must be 1366 or 32834 bytes, got ${buf.length}`
		);
	}
	const riLen = buf.length - 66;
	return {
		version: buf[0],
		ephemeralKey: Buffer.from(buf.subarray(1, 34)),
		routingInfo: Buffer.from(buf.subarray(34, 34 + riLen)),
		hmac: Buffer.from(buf.subarray(34 + riLen, 66 + riLen))
	};
}
