/**
 * BOLT 4: Sphinx onion packet test vector (onion-test.json).
 *
 * Two directions, both asserted byte-exact against the spec:
 *   1. Construct — parse the spec hop payloads, build the onion from the spec
 *      session key, and assert the 1366-byte packet matches the spec onion.
 *   2. Process — peel the spec onion hop-by-hop with each node's privkey, and
 *      assert the recovered payload bytes match the spec at every hop and that
 *      the final hop is reached.
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
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface IOnionVectors {
	session_key: string;
	associated_data: string;
	hops: { pubkey: string; privkey: string; payload: string }[];
	onion: string;
}

const v = loadVectors<IOnionVectors>('bolt04/onion.json');
const sessionKey = hexToBuffer(v.session_key);
const associatedData = hexToBuffer(v.associated_data);

describe('BOLT 4: Sphinx onion conformance', function () {
	const buildHops = () =>
		v.hops.map((h) => ({
			pubkey: hexToBuffer(h.pubkey),
			// Parse the spec payload bytes via beignet's own decoder, then feed
			// the structured payload back into construction.
			payload: decodeHopPayload(hexToBuffer(h.payload), 0).payload
		}));

	it('constructs the spec onion packet byte-for-byte', function () {
		const packet = constructOnionPacket(
			sessionKey,
			buildHops(),
			associatedData
		);
		expect(bufferToHex(encodeOnionPacket(packet))).to.equal(v.onion);
	});

	it('builds a self-consistent onion it can fully peel', function () {
		let packet = constructOnionPacket(sessionKey, buildHops(), associatedData);
		for (let i = 0; i < v.hops.length; i++) {
			const processed = processOnionPacket(
				packet,
				hexToBuffer(v.hops[i].privkey),
				associatedData
			);
			expect(bufferToHex(encodeHopPayload(processed.hopPayload))).to.equal(
				v.hops[i].payload
			);
			expect(isFinalHop(processed.nextPacket)).to.equal(
				i === v.hops.length - 1
			);
			packet = processed.nextPacket;
		}
	});

	it('round-trips each spec hop payload through decode/encode', function () {
		for (const h of v.hops) {
			const decoded = decodeHopPayload(hexToBuffer(h.payload), 0).payload;
			const reEncoded = encodeHopPayload(decoded);
			expect(bufferToHex(reEncoded)).to.equal(h.payload);
		}
	});

	it('peels the spec onion hop-by-hop with matching payloads', function () {
		let packet = decodeOnionPacket(hexToBuffer(v.onion));

		for (let i = 0; i < v.hops.length; i++) {
			const processed = processOnionPacket(
				packet,
				hexToBuffer(v.hops[i].privkey),
				associatedData
			);

			// The recovered payload must re-encode to the spec payload bytes.
			expect(bufferToHex(encodeHopPayload(processed.hopPayload))).to.equal(
				v.hops[i].payload
			);

			const lastHop = i === v.hops.length - 1;
			expect(isFinalHop(processed.nextPacket)).to.equal(lastHop);
			packet = processed.nextPacket;
		}
	});
});
