/**
 * BOLT 4: Onion Packet Processing
 *
 * Each intermediate node peels one layer of the onion to reveal their
 * hop payload and the next onion packet to forward.
 *
 * Key: the cipher stream is generated at 2x the routing info length (2600 bytes).
 * The routing info is extended with zeros before XOR so that the tail bytes
 * of the next routing info come from the stream (matching the filler generated
 * during construction) rather than being zero-padded.
 */

import crypto from 'crypto';
import { ecdh, pointMultiply } from '../crypto/ecdh';
import {
	IOnionPacket,
	IProcessedOnion,
	ONION_VERSION,
	ROUTING_INFO_LENGTH
} from './types';
import {
	computeBlindingFactor,
	deriveHopKeys,
	generateCipherStream
} from './sphinx-crypto';
import { decodeHopPayload } from './hop-payload';

/**
 * Process (peel) one layer of an onion packet.
 * Returns the decoded hop payload and the next onion packet to forward.
 */
export function processOnionPacket(
	packet: IOnionPacket,
	nodePrivkey: Buffer,
	associatedData?: Buffer
): IProcessedOnion {
	if (packet.version !== ONION_VERSION) {
		throw new Error(`Invalid onion version: ${packet.version}`);
	}

	// Compute shared secret
	const sharedSecret = ecdh(nodePrivkey, packet.ephemeralKey);
	const keys = deriveHopKeys(sharedSecret);

	// Verify HMAC on the encrypted routing info (BOLT 4: HMAC(mu, routing_info || associated_data))
	const hmacCalc = crypto
		.createHmac('sha256', keys.mu)
		.update(packet.routingInfo);
	if (associatedData) {
		hmacCalc.update(associatedData);
	}
	const expectedHmac = hmacCalc.digest();

	if (!packet.hmac.equals(expectedHmac)) {
		throw new Error('HMAC verification failed');
	}

	// Decrypt routing info using a 2x-length stream.
	// Extend routing info with zeros so the tail bytes come from the stream,
	// matching the filler that was applied during construction.
	const extendedLen = 2 * ROUTING_INFO_LENGTH;
	const stream = generateCipherStream(keys.rho, extendedLen);
	const extended = Buffer.alloc(extendedLen);
	packet.routingInfo.copy(extended, 0);
	// Positions [1300..2600] are zeros (from Buffer.alloc)
	for (let i = 0; i < extendedLen; i++) {
		extended[i] ^= stream[i];
	}

	// Decode hop payload from the decrypted extended routing info
	const { payload: hopPayload, bytesRead } = decodeHopPayload(extended, 0);

	// Extract next HMAC (immediately after the hop payload)
	const nextHmac = Buffer.from(extended.subarray(bytesRead, bytesRead + 32));

	// Build next routing info: take 1300 bytes starting after payload + HMAC.
	// The tail bytes come from the extended stream, not zero-padding.
	const shiftStart = bytesRead + 32;
	const nextRoutingInfo = Buffer.from(
		extended.subarray(shiftStart, shiftStart + ROUTING_INFO_LENGTH)
	);

	// Blind ephemeral key for next hop
	const blindingFactor = computeBlindingFactor(
		packet.ephemeralKey,
		sharedSecret
	);
	const nextEphemeralKey = pointMultiply(packet.ephemeralKey, blindingFactor);

	const nextPacket: IOnionPacket = {
		version: ONION_VERSION,
		ephemeralKey: nextEphemeralKey,
		routingInfo: nextRoutingInfo,
		hmac: nextHmac
	};

	return { hopPayload, nextPacket, sharedSecret };
}

/**
 * Check if an onion packet's HMAC is all zeros, indicating the final hop.
 */
export function isFinalHop(packet: IOnionPacket): boolean {
	return packet.hmac.equals(Buffer.alloc(32));
}
