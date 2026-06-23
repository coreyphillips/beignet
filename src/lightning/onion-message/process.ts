/**
 * BOLT 7.5: Onion Message Processing
 *
 * Peels one layer of an onion message packet, returning either:
 * - Forward: next hop info + forwarding onion for intermediate nodes
 * - Delivery: decrypted payload for the final destination
 */

import crypto from 'crypto';
import { ecdh, pointMultiply } from '../crypto/ecdh';
import { ONION_VERSION, ROUTING_INFO_LENGTH } from '../onion/types';
import {
	computeBlindingFactor,
	deriveHopKeys,
	generateCipherStream
} from '../onion/sphinx-crypto';
import { decodeOnionPacket, encodeOnionPacket } from '../onion/construct';
import { decodeOnionMessagePayload } from './codec';
import { OnionMessageProcessResult } from './types';
import { decodeBlindedHopData } from '../onion/blinded-path';
import {
	deriveBlindingSharedSecret,
	deriveBlindingEncryptionKey,
	decryptBlindedData,
	deriveNextBlindingKey
} from '../onion/blinding';

/**
 * Process an incoming onion message.
 *
 * Peels one layer of the Sphinx onion to reveal either:
 * - Intermediate hop: next hop ID + forwarding onion
 * - Final hop: message payload with application data
 *
 * @param onionPacketBuf - The 1366-byte onion routing packet
 * @param nodePrivkey - This node's private key (32 bytes)
 * @param blindingPoint - The blinding point from the onion_message (33 bytes), or undefined for non-blinded
 * @returns Processing result: forward or delivery
 */
export function processOnionMessage(
	onionPacketBuf: Buffer,
	nodePrivkey: Buffer,
	blindingPoint?: Buffer
): OnionMessageProcessResult {
	const packet = decodeOnionPacket(onionPacketBuf);

	if (packet.version !== ONION_VERSION) {
		throw new Error(`Invalid onion version: ${packet.version}`);
	}

	// Compute shared secret with the onion ephemeral key
	const sharedSecret = ecdh(nodePrivkey, packet.ephemeralKey);
	const keys = deriveHopKeys(sharedSecret);

	// Verify HMAC on the encrypted routing info
	const expectedHmac = crypto
		.createHmac('sha256', keys.mu)
		.update(packet.routingInfo)
		.digest();

	if (!packet.hmac.equals(expectedHmac)) {
		throw new Error('HMAC verification failed');
	}

	// Decrypt routing info using a 2x-length stream
	const extendedLen = 2 * ROUTING_INFO_LENGTH;
	const stream = generateCipherStream(keys.rho, extendedLen);
	const extended = Buffer.alloc(extendedLen);
	packet.routingInfo.copy(extended, 0);
	for (let i = 0; i < extendedLen; i++) {
		extended[i] ^= stream[i];
	}

	// Decode the hop payload from decrypted routing info
	const { payload: hopPayload, bytesRead } = decodeOnionMessagePayload(
		extended,
		0
	);

	// Extract next HMAC
	const nextHmac = Buffer.from(extended.subarray(bytesRead, bytesRead + 32));

	// Build next routing info
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

	// Check if this is the final hop (all-zero HMAC)
	const isFinal = nextHmac.equals(Buffer.alloc(32));

	if (isFinal) {
		// Final delivery — return the decoded payload
		return {
			type: 'delivery',
			payload: hopPayload
		};
	}

	// Intermediate hop — determine next node
	if (!hopPayload.encryptedRecipientData) {
		throw new Error('Cannot determine next hop: no encrypted_recipient_data');
	}

	// Resolve next hop: try blinded decryption first, fall back to raw decode
	const resolved = resolveNextHop(
		hopPayload.encryptedRecipientData,
		nodePrivkey,
		blindingPoint,
		nextEphemeralKey
	);
	const nextNodeId = resolved.nextNodeId;
	const nextBlindingKey = resolved.nextBlindingKey;

	// Build the forwarding onion message
	const nextOnionPacket = encodeOnionPacket({
		version: ONION_VERSION,
		ephemeralKey: nextEphemeralKey,
		routingInfo: nextRoutingInfo,
		hmac: nextHmac
	});

	return {
		type: 'forward',
		nextNodeId,
		nextBlindingKey,
		nextOnionMessage: {
			blindingPoint: nextBlindingKey,
			onionRoutingPacket: nextOnionPacket
		}
	};
}

/**
 * Resolve next hop from encrypted_recipient_data.
 * Attempts blinded path decryption first; falls back to raw hop data decoding.
 */
function resolveNextHop(
	encryptedRecipientData: Buffer,
	nodePrivkey: Buffer,
	blindingPoint: Buffer | undefined,
	fallbackBlindingKey: Buffer
): { nextNodeId: Buffer; nextBlindingKey: Buffer } {
	// Try blinded path decryption if blinding point is available
	if (blindingPoint) {
		try {
			const blindingSharedSecret = deriveBlindingSharedSecret(
				blindingPoint,
				nodePrivkey
			);
			const encKey = deriveBlindingEncryptionKey(blindingSharedSecret);
			const plaintext = decryptBlindedData(encKey, encryptedRecipientData);
			const blindedHopData = decodeBlindedHopData(plaintext);

			if (blindedHopData.nextNodeId) {
				return {
					nextNodeId: blindedHopData.nextNodeId,
					nextBlindingKey: deriveNextBlindingKey(
						blindingPoint,
						blindingSharedSecret
					)
				};
			}
		} catch {
			// Blinded decryption failed — try raw decode
		}
	}

	// Fallback: parse raw (unencrypted) hop data
	const data = decodeBlindedHopData(encryptedRecipientData);
	if (!data.nextNodeId) {
		throw new Error(
			'Cannot determine next hop: no next_node_id in encrypted_recipient_data'
		);
	}
	return {
		nextNodeId: data.nextNodeId,
		nextBlindingKey: blindingPoint || fallbackBlindingKey
	};
}
