/**
 * BOLT 4: blinded payment onion test vector
 * (bolt04/blinded-payment-onion-test.json).
 *
 * Sender side: every spec hop payload must round-trip byte-exact through
 * decode/encode (pinning the blinded payment TLVs: encrypted_recipient_data,
 * current_path_key, and the final hop's amount/total/cltv), and the onion
 * built from the spec session key must match the spec packet byte-for-byte.
 *
 * Receiver side: the onion is peeled along the whole route. Alice and Bob
 * (the introduction node, addressed by its real node id) peel with their raw
 * privkeys; the blinded hops peel with privkeys tweaked by the running path
 * key. Carol's encrypted data carries next_path_key_override (TLV type 8,
 * the seam where two blinded routes were concatenated), so the forwarded
 * path key is resolved from the raw TLV when present.
 */

import { expect } from 'chai';
import {
	constructOnionPacket,
	encodeOnionPacket,
	decodeOnionPacket
} from '../../../src/lightning/onion/construct';
import {
	processOnionPacket,
	isFinalHop
} from '../../../src/lightning/onion/process';
import {
	encodeHopPayload,
	decodeHopPayload
} from '../../../src/lightning/onion/hop-payload';
import {
	processBlindedHop,
	deriveBlindedPrivkey
} from '../../../src/lightning/onion/blinded-path';
import {
	deriveBlindingSharedSecret,
	deriveBlindingEncryptionKey,
	decryptBlindedData
} from '../../../src/lightning/onion/blinding';
import { decodeBigSize } from '../../../src/lightning/message/codec';
import {
	decodeTlvStream,
	findTlvRecord
} from '../../../src/lightning/message/tlv';
import { IHopPayload } from '../../../src/lightning/onion/types';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IBlindedPaymentVectors {
	generate: {
		session_key: string;
		associated_data: string;
		blinded_route: {
			first_node_id: string;
			first_path_key: string;
			hops: {
				alias: string;
				blinded_node_id: string;
				encrypted_data: string;
			}[];
		};
		full_route: {
			hops: { alias: string; pubkey: string; payload: string }[];
		};
		onion: string;
	};
	decrypt: {
		hops: {
			alias: string;
			onion: string;
			node_privkey: string;
			next_path_key?: string;
		}[];
	};
}

const v = loadVectors<IBlindedPaymentVectors>(
	'bolt04/blinded-payment-onion.json'
);

const ERD_NEXT_PATH_KEY_OVERRIDE = 8n;

/**
 * Parse a spec payload (BigSize length prefix + TLV stream) into beignet's
 * IHopPayload. A blinded intermediate hop omits amt_to_forward /
 * outgoing_cltv_value entirely; the decoded struct cannot distinguish
 * "absent" from "zero", so presence is read from the raw TLV records and
 * mapped to the omitForwardAmounts encode hint.
 */
function parsePayload(hex: string): IHopPayload {
	const buf = hexToBuffer(hex);
	const { payload } = decodeHopPayload(buf, 0);
	const prefix = decodeBigSize(buf, 0);
	const { records } = decodeTlvStream(buf, prefix.bytesRead);
	if (!records.some((r) => r.type === 2n)) {
		payload.omitForwardAmounts = true;
	}
	return payload;
}

describe('BOLT 4: blinded payment onion conformance', function () {
	const sessionKey = hexToBuffer(v.generate.session_key);
	const associatedData = hexToBuffer(v.generate.associated_data);

	it('round-trips each spec hop payload through decode/encode', function () {
		for (const hop of v.generate.full_route.hops) {
			expect(bufferToHex(encodeHopPayload(parsePayload(hop.payload)))).to.equal(
				hop.payload
			);
		}
	});

	it('decodes the spec payload fields beignet models', function () {
		const alice = parsePayload(v.generate.full_route.hops[0].payload);
		expect(bufferToHex(alice.shortChannelId as Buffer)).to.equal(
			'000000000000000a' // 0x0x10
		);
		expect(alice.amountToForwardMsat).to.equal(110125n);
		expect(alice.outgoingCltvValue).to.equal(749150);

		const bob = parsePayload(v.generate.full_route.hops[1].payload);
		expect(bufferToHex(bob.blindingPoint as Buffer)).to.equal(
			v.generate.blinded_route.first_path_key
		);
		expect(bufferToHex(bob.encryptedRecipientData as Buffer)).to.equal(
			v.generate.blinded_route.hops[0].encrypted_data
		);

		const eve = parsePayload(v.generate.full_route.hops[4].payload);
		expect(eve.amountToForwardMsat).to.equal(100000n);
		expect(eve.outgoingCltvValue).to.equal(749000);
		expect(eve.totalAmountMsat).to.equal(150000n);
	});

	it('constructs the spec onion packet byte-for-byte', function () {
		const hops = v.generate.full_route.hops.map((h) => ({
			pubkey: hexToBuffer(h.pubkey),
			payload: parsePayload(h.payload)
		}));
		const packet = constructOnionPacket(sessionKey, hops, associatedData);
		expect(bufferToHex(encodeOnionPacket(packet))).to.equal(v.generate.onion);
	});

	it('peels the spec onion along the full route', function () {
		expect(v.decrypt.hops[0].onion).to.equal(v.generate.onion);

		// The path key each blinded hop receives; undefined until Bob (the
		// introduction node) reads current_path_key from his own payload.
		let pathKey: Buffer | undefined;

		for (let i = 0; i < v.decrypt.hops.length; i++) {
			const hop = v.decrypt.hops[i];
			const nodePrivkey = hexToBuffer(hop.node_privkey);
			const peelKey = pathKey
				? deriveBlindedPrivkey(pathKey, nodePrivkey)
				: nodePrivkey;

			const processed = processOnionPacket(
				decodeOnionPacket(hexToBuffer(hop.onion)),
				peelKey,
				associatedData
			);

			const lastHop = i === v.decrypt.hops.length - 1;
			expect(isFinalHop(processed.nextPacket)).to.equal(lastHop);
			if (!lastHop) {
				expect(bufferToHex(encodeOnionPacket(processed.nextPacket))).to.equal(
					v.decrypt.hops[i + 1].onion
				);
			}

			const erd = processed.hopPayload.encryptedRecipientData;
			if (!erd) {
				// Alice, the only unblinded hop.
				expect(hop.alias).to.equal('Alice');
				continue;
			}

			// Bob learns the initial path key from his own payload; later
			// hops received it (conceptually) via update_add_htlc.
			const currentPathKey =
				processed.hopPayload.blindingPoint ?? (pathKey as Buffer);
			const blinded = processBlindedHop(currentPathKey, nodePrivkey, erd);

			if (hop.alias === 'Eve') {
				// Final hop: recipient-private path_id, no forwarding.
				expect(bufferToHex(blinded.hopData.pathId as Buffer)).to.equal(
					'c9cf92f45ade68345bc20ae672e2012f4af487ed4415'
				);
			}

			// Forwarded path key: TLV type 8 override when present (the seam
			// where two blinded routes were concatenated, at Carol), else the
			// standard derivation.
			const override = findOverride(currentPathKey, nodePrivkey, erd);
			const forwarded = override ?? blinded.nextBlindingKey;
			expect(bufferToHex(forwarded)).to.equal(hop.next_path_key);
			pathKey = forwarded;
		}
	});
});

/** Extract next_path_key_override (ERD type 8) from a hop's encrypted data. */
function findOverride(
	pathKey: Buffer,
	nodePrivkey: Buffer,
	encryptedData: Buffer
): Buffer | undefined {
	const ss = deriveBlindingSharedSecret(pathKey, nodePrivkey);
	const plaintext = decryptBlindedData(
		deriveBlindingEncryptionKey(ss),
		encryptedData
	);
	const { records } = decodeTlvStream(plaintext);
	return findTlvRecord(records, ERD_NEXT_PATH_KEY_OVERRIDE);
}
