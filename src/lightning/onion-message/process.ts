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
import {
	decodeBlindedHopData,
	deriveBlindedPrivkey
} from '../onion/blinded-path';
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

	// BOLT 4 route blinding: a spec onion message is sphinx-encrypted to our
	// BLINDED node id, so the packet must be peeled with the blinded private
	// key derived from the path_key (this is how CLN/LND always send). Try
	// that first, then fall back to the raw node key for beignet's own
	// single-hop direct sends (sendOnionMessage, which carries no blinding).
	const candidateKeys: Buffer[] = [];
	if (blindingPoint) {
		try {
			candidateKeys.push(deriveBlindedPrivkey(blindingPoint, nodePrivkey));
		} catch {
			// Invalid blinding point — fall through to the raw key.
		}
	}
	candidateKeys.push(nodePrivkey);

	let sharedSecret: Buffer | null = null;
	let keys: ReturnType<typeof deriveHopKeys> | null = null;
	for (const candidate of candidateKeys) {
		const ss = ecdh(candidate, packet.ephemeralKey);
		const k = deriveHopKeys(ss);
		const expectedHmac = crypto
			.createHmac('sha256', k.mu)
			.update(packet.routingInfo)
			.digest();
		if (packet.hmac.equals(expectedHmac)) {
			sharedSecret = ss;
			keys = k;
			break;
		}
	}
	if (!sharedSecret || !keys) {
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
		// Final delivery — surface the blinded-path path_id (BOLT 4) so the
		// recipient can verify the message arrived via a path it published.
		// Only trust a path_id from SUCCESSFULLY DECRYPTED recipient data:
		// unencrypted/plaintext hop data is attacker-forgeable.
		let pathId: Buffer | undefined;
		if (hopPayload.encryptedRecipientData && blindingPoint) {
			try {
				const blindingSharedSecret = deriveBlindingSharedSecret(
					blindingPoint,
					nodePrivkey
				);
				const encKey = deriveBlindingEncryptionKey(blindingSharedSecret);
				const plaintext = decryptBlindedData(
					encKey,
					hopPayload.encryptedRecipientData
				);
				pathId = decodeBlindedHopData(plaintext).pathId;
			} catch {
				// Undecryptable final-hop recipient data: no verifiable path_id.
			}
		}
		return {
			type: 'delivery',
			payload: hopPayload,
			...(pathId ? { pathId } : {})
		};
	}

	// Intermediate hop — determine next node
	if (!hopPayload.encryptedRecipientData) {
		throw new Error('Cannot determine next hop: no encrypted_recipient_data');
	}

	// Resolve next hop from the DECRYPTED recipient data only.
	const resolved = resolveNextHop(
		hopPayload.encryptedRecipientData,
		nodePrivkey,
		blindingPoint
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
 * Resolve next hop from encrypted_recipient_data (BOLT 4 route blinding).
 * Forwarding REQUIRES a blinding point and decryptable recipient data: the
 * plaintext next_node_id fallback (beignet's pre-route-blinding multi-hop
 * form) is gone — a plaintext blob is attacker-forgeable and no spec
 * implementation emits one.
 */
function resolveNextHop(
	encryptedRecipientData: Buffer,
	nodePrivkey: Buffer,
	blindingPoint: Buffer | undefined
): { nextNodeId: Buffer; nextBlindingKey: Buffer } {
	if (!blindingPoint) {
		throw new Error(
			'Cannot determine next hop: onion message carries no blinding point'
		);
	}
	const blindingSharedSecret = deriveBlindingSharedSecret(
		blindingPoint,
		nodePrivkey
	);
	const encKey = deriveBlindingEncryptionKey(blindingSharedSecret);
	const plaintext = decryptBlindedData(encKey, encryptedRecipientData);
	const blindedHopData = decodeBlindedHopData(plaintext);

	if (!blindedHopData.nextNodeId) {
		throw new Error(
			'Cannot determine next hop: no next_node_id in encrypted_recipient_data'
		);
	}
	return {
		nextNodeId: blindedHopData.nextNodeId,
		nextBlindingKey: deriveNextBlindingKey(blindingPoint, blindingSharedSecret)
	};
}
