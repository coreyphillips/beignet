/**
 * BOLT 4 route blinding: next_path_key_override (encrypted_recipient_data
 * type 8).
 *
 * When two blinded routes are concatenated (a sender-prepended segment
 * joining a recipient-built path), the seam hop's encrypted data carries the
 * path key the NEXT hop must unblind with, replacing the standard
 * derivation. Without honoring it, the hop after the seam derives the wrong
 * blinded privkey and the relay dies at the seam.
 */

import { expect } from 'chai';
import {
	constructBlindedPath,
	encodeBlindedHopData,
	decodeBlindedHopData,
	processBlindedHop,
	deriveBlindedPrivkey
} from '../../src/lightning/onion/blinded-path';
import {
	deriveBlindingSharedSecret,
	deriveBlindingEncryptionKey,
	encryptBlindedData,
	deriveNextBlindingKey
} from '../../src/lightning/onion/blinding';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { constructOnionMessagePacket } from '../../src/lightning/onion-message/construct';
import { processOnionMessage } from '../../src/lightning/onion-message/process';
import { encodeOnionMessagePayload } from '../../src/lightning/onion-message/codec';

const alicePriv = Buffer.alloc(32, 0x41);
const bobPriv = Buffer.alloc(32, 0x42);
const carolPriv = Buffer.alloc(32, 0x43);
const bobPub = getPublicKey(bobPriv);
const carolPub = getPublicKey(carolPriv);

const senderSecret = Buffer.alloc(32, 0x61);
const recipientSecret = Buffer.alloc(32, 0x62);
const sessionKey = Buffer.alloc(32, 0x63);

describe('blinded path: next_path_key_override', function () {
	it('round-trips through encode/decode (ERD type 8)', function () {
		const override = getPublicKey(recipientSecret);
		const encoded = encodeBlindedHopData({
			nextNodeId: bobPub,
			nextPathKeyOverride: override
		});
		const decoded = decodeBlindedHopData(encoded);
		expect(decoded.nextNodeId?.equals(bobPub)).to.equal(true);
		expect(decoded.nextPathKeyOverride?.equals(override)).to.equal(true);
	});

	it('processBlindedHop forwards the override instead of the derivation', function () {
		const override = getPublicKey(recipientSecret);
		const pathKey = getPublicKey(senderSecret);
		const ss = deriveBlindingSharedSecret(pathKey, alicePriv);
		const encrypted = encryptBlindedData(
			deriveBlindingEncryptionKey(ss),
			encodeBlindedHopData({
				nextNodeId: bobPub,
				nextPathKeyOverride: override
			})
		);

		const { hopData, nextBlindingKey } = processBlindedHop(
			pathKey,
			alicePriv,
			encrypted
		);
		expect(hopData.nextPathKeyOverride?.equals(override)).to.equal(true);
		expect(nextBlindingKey.equals(override)).to.equal(true);
		expect(nextBlindingKey.equals(deriveNextBlindingKey(pathKey, ss))).to.equal(
			false
		);
	});

	it('relays an onion message across a concatenated-route seam', function () {
		// Carol builds her own blinded route Bob -> Carol.
		const recipientPath = constructBlindedPath(
			recipientSecret,
			[bobPub, carolPub],
			[{ nextNodeId: carolPub }, { pathId: Buffer.from('feedface', 'hex') }]
		);

		// The sender prepends a segment through Alice whose encrypted data
		// hands over Carol's chosen path key for Bob (the seam).
		const senderPath = constructBlindedPath(
			senderSecret,
			[getPublicKey(alicePriv)],
			[
				{
					nextNodeId: bobPub,
					nextPathKeyOverride: recipientPath.blindingPoint
				}
			]
		);

		const blindedHops = [
			...senderPath.blindedHops,
			...recipientPath.blindedHops
		];
		const packet = constructOnionMessagePacket(
			sessionKey,
			blindedHops.map((hop) => ({
				pubkey: hop.blindedNodeId,
				payload: encodeOnionMessagePayload({
					encryptedRecipientData: hop.encryptedData,
					messageTlvs: new Map()
				})
			}))
		);

		// Alice peels and must forward Carol's path key, not her derivation.
		const atAlice = processOnionMessage(
			packet,
			alicePriv,
			senderPath.blindingPoint
		);
		expect(atAlice.type).to.equal('forward');
		if (atAlice.type !== 'forward') return;
		expect(atAlice.nextNodeId.equals(bobPub)).to.equal(true);
		expect(
			atAlice.nextBlindingKey.equals(recipientPath.blindingPoint)
		).to.equal(true);

		// Bob can only unblind because the seam handed over the right key.
		expect(
			getPublicKey(
				deriveBlindedPrivkey(atAlice.nextBlindingKey, bobPriv)
			).equals(recipientPath.blindedHops[0].blindedNodeId)
		).to.equal(true);
		const atBob = processOnionMessage(
			atAlice.nextOnionMessage.onionRoutingPacket,
			bobPriv,
			atAlice.nextBlindingKey
		);
		expect(atBob.type).to.equal('forward');
		if (atBob.type !== 'forward') return;
		expect(atBob.nextNodeId.equals(carolPub)).to.equal(true);

		// Carol receives the delivery and her creator-authenticated path_id.
		const atCarol = processOnionMessage(
			atBob.nextOnionMessage.onionRoutingPacket,
			carolPriv,
			atBob.nextBlindingKey
		);
		expect(atCarol.type).to.equal('delivery');
		if (atCarol.type !== 'delivery') return;
		expect(atCarol.pathId?.toString('hex')).to.equal('feedface');
	});
});
