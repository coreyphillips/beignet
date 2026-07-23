/**
 * BOLT 4: blinded onion message test vector
 * (bolt04/blinded-onion-message-onion-test.json).
 *
 * The route is Dave's blinded path (Bob->Dave) with a sender-prepended hop
 * through Alice; Alice's encrypted data carries next_path_key_override
 * (ERD type 8), the seam where the sender's path joins Dave's.
 *
 * Asserted byte-exact:
 *  - Generate: per-hop path key (E), shared secret (both directions),
 *    blinded_node_id tweak + id, blinding factor H(E||ss), the path-secret
 *    chain, rho, and encrypted_recipient_data
 *  - Packet: the 1366-byte onion message packet built from the spec session
 *    key, and the full type-513 wire message
 *  - Decrypt: every hop peels its own wire message (forward hops resolve
 *    next_node_id, Dave receives delivery with a verified path_id), and the
 *    relay chain reproduces each next wire message including the path key
 *    override at the seam
 */

import { expect } from 'chai';
import {
	deriveBlindingSharedSecret,
	deriveBlindingFactor,
	deriveBlindedNodeIdTweak,
	computeBlindedNodeId,
	deriveBlindingEncryptionKey,
	encryptBlindedData
} from '../../../src/lightning/onion/blinding';
import {
	getPublicKey,
	privateMultiply
} from '../../../src/lightning/crypto/ecdh';
import { constructOnionMessagePacket } from '../../../src/lightning/onion-message/construct';
import { processOnionMessage } from '../../../src/lightning/onion-message/process';
import {
	encodeOnionMessage,
	decodeOnionMessage,
	encodeOnionMessagePayload
} from '../../../src/lightning/onion-message/codec';
import { encodeBigSize } from '../../../src/lightning/message/codec';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IOmGenerateHop {
	alias: string;
	path_key_secret: string;
	tlvs: { next_path_key_override?: string };
	encrypted_data_tlv: string;
	ss: string;
	"HMAC256('blinded_node_id', ss)": string;
	blinded_node_id: string;
	E: string;
	'H(E || ss)': string;
	next_e: string;
	rho: string;
	encrypted_recipient_data: string;
}

interface IOmVectors {
	generate: { session_key: string; hops: IOmGenerateHop[] };
	route: {
		first_node_id: string;
		first_path_key: string;
		hops: { blinded_node_id: string; encrypted_recipient_data: string }[];
	};
	onionmessage: { unknown_tag_1: string; onion_message_packet: string };
	decrypt: {
		hops: {
			alias: string;
			privkey: string;
			onion_message: string;
			next_node_id?: string;
		}[];
	};
}

const v = loadVectors<IOmVectors>('bolt04/blinded-onion-message.json');

const ONION_MESSAGE_TYPE_PREFIX = '0201'; // message type 513

/** Build each hop's onion payload; the final hop carries the app TLV too. */
function buildPayloads(): Buffer[] {
	return v.generate.hops.map((hop, i) => {
		const erd = hexToBuffer(hop.encrypted_recipient_data);
		if (i < v.generate.hops.length - 1) {
			return encodeOnionMessagePayload({
				encryptedRecipientData: erd,
				messageTlvs: new Map()
			});
		}
		// Dave's payload carries the spec's deliberately-unknown odd TLV 1
		// ('hello') ahead of the ERD; encodeOnionMessagePayload only accepts
		// application TLVs >= 64, so the stream is assembled by hand.
		const hello = hexToBuffer(v.onionmessage.unknown_tag_1);
		const tlvs = Buffer.concat([
			encodeBigSize(1n),
			encodeBigSize(BigInt(hello.length)),
			hello,
			encodeBigSize(4n),
			encodeBigSize(BigInt(erd.length)),
			erd
		]);
		return Buffer.concat([encodeBigSize(BigInt(tlvs.length)), tlvs]);
	});
}

describe('BOLT 4: blinded onion message conformance', function () {
	describe('generate (blinded route)', function () {
		v.generate.hops.forEach((hop, i) => {
			it(`derives ${hop.alias}'s blinded hop byte-for-byte`, function () {
				const pathSecret = hexToBuffer(hop.path_key_secret);
				const nodePrivkey = hexToBuffer(v.decrypt.hops[i].privkey);
				const pathKey = hexToBuffer(hop.E);

				expect(bufferToHex(getPublicKey(pathSecret))).to.equal(hop.E);

				// Receiver-side ECDH; the creator derives the same secret from
				// (path_key_secret, node_id).
				const ss = deriveBlindingSharedSecret(pathKey, nodePrivkey);
				expect(bufferToHex(ss)).to.equal(hop.ss);
				expect(
					bufferToHex(
						deriveBlindingSharedSecret(getPublicKey(nodePrivkey), pathSecret)
					)
				).to.equal(hop.ss);

				expect(bufferToHex(deriveBlindedNodeIdTweak(ss))).to.equal(
					hop["HMAC256('blinded_node_id', ss)"]
				);
				expect(
					bufferToHex(computeBlindedNodeId(getPublicKey(nodePrivkey), ss))
				).to.equal(hop.blinded_node_id);

				const factor = deriveBlindingFactor(pathKey, ss);
				expect(bufferToHex(factor)).to.equal(hop['H(E || ss)']);
				// next_e is printed with a trailing 0x01 compression marker.
				expect(bufferToHex(privateMultiply(pathSecret, factor))).to.equal(
					hop.next_e.slice(0, 64)
				);

				const rho = deriveBlindingEncryptionKey(ss);
				expect(bufferToHex(rho)).to.equal(hop.rho);
				expect(
					bufferToHex(
						encryptBlindedData(rho, hexToBuffer(hop.encrypted_data_tlv))
					)
				).to.equal(hop.encrypted_recipient_data);
			});
		});

		it('chains path secrets within the blinded route', function () {
			// Bob->Carol->Dave share one path-key chain; Alice->Bob is the
			// seam where Alice's override hands over to Dave's route.
			for (let i = 1; i + 1 < v.generate.hops.length; i++) {
				expect(v.generate.hops[i].next_e.slice(0, 64)).to.equal(
					v.generate.hops[i + 1].path_key_secret
				);
			}
			expect(v.generate.hops[0].tlvs.next_path_key_override).to.equal(
				v.generate.hops[1].E
			);
		});
	});

	it('constructs the spec onion message packet byte-for-byte', function () {
		const packet = constructOnionMessagePacket(
			hexToBuffer(v.generate.session_key),
			v.route.hops.map((hop, i) => ({
				pubkey: hexToBuffer(hop.blinded_node_id),
				payload: buildPayloads()[i]
			}))
		);
		expect(bufferToHex(packet)).to.equal(v.onionmessage.onion_message_packet);

		// The full type-513 wire message delivered to the first hop.
		const wire =
			ONION_MESSAGE_TYPE_PREFIX +
			bufferToHex(
				encodeOnionMessage({
					blindingPoint: hexToBuffer(v.route.first_path_key),
					onionRoutingPacket: packet
				})
			);
		expect(wire).to.equal(v.decrypt.hops[0].onion_message);
	});

	describe('decrypt (per-hop, from the vector inputs)', function () {
		v.decrypt.hops.forEach((hop, i) => {
			it(`processes at ${hop.alias}`, function () {
				const wire = hexToBuffer(hop.onion_message);
				expect(bufferToHex(wire.subarray(0, 2))).to.equal(
					ONION_MESSAGE_TYPE_PREFIX
				);
				const msg = decodeOnionMessage(wire.subarray(2));
				const result = processOnionMessage(
					msg.onionRoutingPacket,
					hexToBuffer(hop.privkey),
					msg.blindingPoint
				);

				if (hop.next_node_id) {
					expect(result.type).to.equal('forward');
					if (result.type === 'forward') {
						expect(bufferToHex(result.nextNodeId)).to.equal(hop.next_node_id);
						// The forwarded packet bytes must match the next hop's
						// wire message (path key handover asserted separately).
						const nextWire = hexToBuffer(v.decrypt.hops[i + 1].onion_message);
						const nextMsg = decodeOnionMessage(nextWire.subarray(2));
						expect(
							bufferToHex(result.nextOnionMessage.onionRoutingPacket)
						).to.equal(bufferToHex(nextMsg.onionRoutingPacket));
					}
				} else {
					expect(result.type).to.equal('delivery');
					if (result.type === 'delivery') {
						expect(
							bufferToHex(result.payload.encryptedRecipientData as Buffer)
						).to.equal(
							v.route.hops[v.route.hops.length - 1].encrypted_recipient_data
						);
						expect(bufferToHex(result.pathId as Buffer)).to.equal(
							'deadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0ffeedeadbeefbadc0'
						);
					}
				}
			});
		});
	});

	it('relays the full chain including the path key override at the seam', function () {
		// End-to-end: each hop's forwarded wire message must equal the next
		// hop's input EXACTLY, including the path key. Alice's hop data
		// carries next_path_key_override (ERD type 8), so her forwarded
		// message must carry Dave's chosen path key for Bob, not the
		// standard derivation.
		for (let i = 0; i + 1 < v.decrypt.hops.length; i++) {
			const hop = v.decrypt.hops[i];
			const msg = decodeOnionMessage(
				hexToBuffer(hop.onion_message).subarray(2)
			);
			const result = processOnionMessage(
				msg.onionRoutingPacket,
				hexToBuffer(hop.privkey),
				msg.blindingPoint
			);
			expect(result.type).to.equal('forward');
			if (result.type === 'forward') {
				const forwardedWire =
					ONION_MESSAGE_TYPE_PREFIX +
					bufferToHex(encodeOnionMessage(result.nextOnionMessage));
				expect(forwardedWire, `${hop.alias} forwarded wire`).to.equal(
					v.decrypt.hops[i + 1].onion_message
				);
			}
		}
	});
});
