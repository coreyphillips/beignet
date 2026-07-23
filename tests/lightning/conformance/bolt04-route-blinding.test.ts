/**
 * BOLT 4: route blinding test vector (bolt04/route-blinding-test.json).
 *
 * Both sides of the construction are asserted byte-exact:
 *  - Generate — from each hop's path_privkey + node_id, reproduce the shared
 *    secret, rho, blinded node id, and encrypted_data (the vector's
 *    encoded_tlvs plaintext is fed directly so hops carrying TLVs beignet does
 *    not model, e.g. next_path_key_override / allowed_features, still pin the
 *    crypto), plus the path-key/path-privkey chain within each session.
 *  - Unblind — from each hop's node_privkey + path_key, reproduce the shared
 *    secret (ECDH symmetry), blinded privkey, decrypted plaintext, and the
 *    computed next_path_key.
 *
 * The vector's route is a concatenation of two blinded routes; Carol's
 * next_path_key_override (encrypted_data TLV type 8) marks the seam. The
 * override value is asserted at the raw TLV level here; honoring it during
 * relay is exercised by the onion-message vector.
 */

import { expect } from 'chai';
import {
	deriveBlindingSharedSecret,
	deriveBlindingFactor,
	deriveNextBlindingKey,
	computeBlindedNodeId,
	deriveBlindingEncryptionKey,
	encryptBlindedData,
	decryptBlindedData
} from '../../../src/lightning/onion/blinding';
import {
	processBlindedHop,
	deriveBlindedPrivkey,
	decodeBlindedHopData
} from '../../../src/lightning/onion/blinded-path';
import {
	getPublicKey,
	privateMultiply
} from '../../../src/lightning/crypto/ecdh';
import {
	decodeTlvStream,
	findTlvRecord
} from '../../../src/lightning/message/tlv';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IGenerateHop {
	session_key?: string;
	alias: string;
	node_id: string;
	encoded_tlvs: string;
	path_privkey: string;
	path_key: string;
	shared_secret: string;
	rho: string;
	encrypted_data: string;
	blinded_node_id: string;
}

interface IUnblindHop {
	alias: string;
	node_privkey: string;
	path_key: string;
	blinded_privkey: string;
	decrypted_data: string;
	next_path_key: string;
	next_path_key_override?: string;
}

interface IRouteBlindingVectors {
	generate: { hops: IGenerateHop[] };
	route: {
		first_node_id: string;
		first_path_key: string;
		hops: { blinded_node_id: string; encrypted_data: string }[];
	};
	unblind: { hops: IUnblindHop[] };
}

const v = loadVectors<IRouteBlindingVectors>('bolt04/route-blinding.json');

const ERD_NEXT_PATH_KEY_OVERRIDE = 8n;

describe('BOLT 4: route blinding conformance', function () {
	describe('generate (sender side)', function () {
		for (const hop of v.generate.hops) {
			it(`derives ${hop.alias}'s blinded hop byte-for-byte`, function () {
				const pathPrivkey = hexToBuffer(hop.path_privkey);
				const nodeId = hexToBuffer(hop.node_id);

				expect(bufferToHex(getPublicKey(pathPrivkey))).to.equal(hop.path_key);

				const ss = deriveBlindingSharedSecret(nodeId, pathPrivkey);
				expect(bufferToHex(ss)).to.equal(hop.shared_secret);

				const rho = deriveBlindingEncryptionKey(ss);
				expect(bufferToHex(rho)).to.equal(hop.rho);

				expect(bufferToHex(computeBlindedNodeId(nodeId, ss))).to.equal(
					hop.blinded_node_id
				);

				expect(
					bufferToHex(encryptBlindedData(rho, hexToBuffer(hop.encoded_tlvs)))
				).to.equal(hop.encrypted_data);
			});
		}

		it('chains path keys and path privkeys within each session', function () {
			for (let i = 0; i + 1 < v.generate.hops.length; i++) {
				const cur = v.generate.hops[i];
				const next = v.generate.hops[i + 1];
				if (next.session_key) {
					// A fresh session key starts a new blinded route (the
					// vector concatenates Bob->Carol with Dave->Eve).
					continue;
				}
				const pathKey = hexToBuffer(cur.path_key);
				const ss = hexToBuffer(cur.shared_secret);
				expect(bufferToHex(deriveNextBlindingKey(pathKey, ss))).to.equal(
					next.path_key
				);
				expect(
					bufferToHex(
						privateMultiply(
							hexToBuffer(cur.path_privkey),
							deriveBlindingFactor(pathKey, ss)
						)
					)
				).to.equal(next.path_privkey);
			}
		});

		it('exposes the route exactly as generated', function () {
			expect(v.route.first_node_id).to.equal(v.generate.hops[0].node_id);
			expect(v.route.first_path_key).to.equal(v.generate.hops[0].path_key);
			v.route.hops.forEach((hop, i) => {
				expect(hop.blinded_node_id).to.equal(
					v.generate.hops[i].blinded_node_id
				);
				expect(hop.encrypted_data).to.equal(v.generate.hops[i].encrypted_data);
			});
		});
	});

	describe('unblind (receiver side)', function () {
		v.unblind.hops.forEach((hop, i) => {
			it(`unblinds at ${hop.alias}`, function () {
				const nodePrivkey = hexToBuffer(hop.node_privkey);
				const pathKey = hexToBuffer(hop.path_key);

				// ECDH symmetry: the receiver derives the same shared secret
				// from (path_key, node_privkey) as the sender did from
				// (node_id, path_privkey).
				const ss = deriveBlindingSharedSecret(pathKey, nodePrivkey);
				expect(bufferToHex(ss)).to.equal(v.generate.hops[i].shared_secret);

				const blindedPrivkey = deriveBlindedPrivkey(pathKey, nodePrivkey);
				expect(bufferToHex(blindedPrivkey)).to.equal(hop.blinded_privkey);
				expect(bufferToHex(getPublicKey(blindedPrivkey))).to.equal(
					v.route.hops[i].blinded_node_id
				);

				const plaintext = decryptBlindedData(
					deriveBlindingEncryptionKey(ss),
					hexToBuffer(v.route.hops[i].encrypted_data)
				);
				expect(bufferToHex(plaintext)).to.equal(hop.decrypted_data);

				// The vector's next_path_key is the STANDARD derivation; the
				// key actually forwarded honors the override (ERD type 8) at
				// the seam between the two concatenated routes (Carol).
				expect(bufferToHex(deriveNextBlindingKey(pathKey, ss))).to.equal(
					hop.next_path_key
				);

				const processed = processBlindedHop(
					pathKey,
					nodePrivkey,
					hexToBuffer(v.route.hops[i].encrypted_data)
				);
				expect(bufferToHex(processed.nextBlindingKey)).to.equal(
					hop.next_path_key_override ?? hop.next_path_key
				);

				const { records } = decodeTlvStream(plaintext);
				const override = findTlvRecord(records, ERD_NEXT_PATH_KEY_OVERRIDE);
				if (hop.next_path_key_override) {
					expect(bufferToHex(override as Buffer)).to.equal(
						hop.next_path_key_override
					);
				} else {
					expect(override).to.equal(undefined);
				}
			});
		});

		it('decodes the spec plaintext TLVs beignet models', function () {
			// Bob (payment forwarding hop).
			const bob = decodeBlindedHopData(
				hexToBuffer(v.unblind.hops[0].decrypted_data)
			);
			expect(bufferToHex(bob.shortChannelId as Buffer)).to.equal(
				'00000000000006c1' // 0x0x1729
			);
			expect(bob.paymentRelay).to.deep.equal({
				cltvExpiryDelta: 36,
				feeProportionalMillionths: 150,
				feeBaseMsat: 10000
			});
			expect(bob.paymentConstraints?.maxCltvExpiry).to.equal(748005);
			expect(bob.paymentConstraints?.htlcMinimumMsat).to.equal(1500n);

			// Eve (final hop) carries the recipient's path_id.
			const eve = decodeBlindedHopData(
				hexToBuffer(v.unblind.hops[3].decrypted_data)
			);
			expect(bufferToHex(eve.pathId as Buffer)).to.equal('deadbeef');
		});
	});
});
