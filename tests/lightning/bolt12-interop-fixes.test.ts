/**
 * Regressions for the live-CLN BOLT 12 paid-offer fixes:
 *  - onion messages are sphinx-encrypted to BLINDED node ids (spec route
 *    blinding) and the receiver peels with the blinded key derived from the
 *    path_key, falling back to the raw key for legacy unblinded sends;
 *  - constructReplyOnionMessage can attach OUR reply path to the final hop;
 *  - hop payload TLV 18 (total_amount_msat) round-trips for the blinded
 *    final payment hop (CLN fails invalid_onion_payload without it).
 * Each fails against the pre-fix code (CLN silently dropped every beignet
 * onion message, and blinded final payment payloads were rejected).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	constructBlindedPath,
	deriveBlindedPrivkey
} from '../../src/lightning/onion/blinded-path';
import {
	constructReplyOnionMessage,
	constructSimpleOnionMessage
} from '../../src/lightning/onion-message/construct';
import { processOnionMessage } from '../../src/lightning/onion-message/process';
import {
	encodeHopPayload,
	decodeHopPayload
} from '../../src/lightning/onion/hop-payload';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

function keyPair(): { privkey: Buffer; pubkey: Buffer } {
	const privkey = crypto.randomBytes(32);
	return { privkey, pubkey: getPublicKey(privkey) };
}

describe('BOLT 12 live-CLN interop fixes', function () {
	describe('onion messages use spec route blinding', function () {
		it('a 1-hop blinded message peels with the BLINDED key, not the raw key', function () {
			const dest = keyPair();
			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[dest.pubkey],
				[{}]
			);
			const data = new Map<number, Buffer>([[64, Buffer.from('invreq')]]);
			const msg = constructReplyOnionMessage(path, data);

			// The sphinx layer is addressed to the blinded node id: the blinded
			// private key (path_key tweak) verifies...
			const result = processOnionMessage(
				msg.onionRoutingPacket,
				dest.privkey,
				msg.blindingPoint
			);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.messageTlvs.get(64)!.toString()).to.equal(
					'invreq'
				);
			}

			// ...and the raw key alone (no path_key) does NOT — proving the
			// packet is genuinely blinded, exactly what CLN/LND require.
			expect(() =>
				processOnionMessage(msg.onionRoutingPacket, dest.privkey)
			).to.throw(/HMAC/);
		});

		it('a 2-hop blinded path forwards at the blinded intermediate and delivers', function () {
			const hop1 = keyPair();
			const dest = keyPair();
			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[hop1.pubkey, dest.pubkey],
				[{ nextNodeId: dest.pubkey }, {}]
			);
			const data = new Map<number, Buffer>([[65, Buffer.from('hello')]]);
			const msg = constructReplyOnionMessage(path, data);

			const first = processOnionMessage(
				msg.onionRoutingPacket,
				hop1.privkey,
				msg.blindingPoint
			);
			expect(first.type).to.equal('forward');
			if (first.type !== 'forward') return;
			expect(first.nextNodeId.equals(dest.pubkey)).to.equal(true);

			const second = processOnionMessage(
				first.nextOnionMessage.onionRoutingPacket,
				dest.privkey,
				first.nextOnionMessage.blindingPoint
			);
			expect(second.type).to.equal('delivery');
			if (second.type === 'delivery') {
				expect(second.payload.messageTlvs.get(65)!.toString()).to.equal(
					'hello'
				);
			}
		});

		it('legacy unblinded sends still peel via the raw-key fallback', function () {
			const dest = keyPair();
			const data = new Map<number, Buffer>([[67, Buffer.from('legacy')]]);
			const msg = constructSimpleOnionMessage(dest.pubkey, data);
			const result = processOnionMessage(
				msg.onionRoutingPacket,
				dest.privkey,
				msg.blindingPoint
			);
			expect(result.type).to.equal('delivery');
		});

		it('deriveBlindedPrivkey matches the blinded node id in the path', function () {
			const dest = keyPair();
			const path = constructBlindedPath(
				crypto.randomBytes(32),
				[dest.pubkey],
				[{}]
			);
			const blindedPriv = deriveBlindedPrivkey(
				path.blindingPoint,
				dest.privkey
			);
			expect(
				getPublicKey(blindedPriv).equals(path.blindedHops[0].blindedNodeId)
			).to.equal(true);
		});
	});

	describe('reply path attachment on a blinded send', function () {
		it('the final hop payload carries OUR reply path when requested', function () {
			const dest = keyPair();
			const me = keyPair();
			const toDest = constructBlindedPath(
				crypto.randomBytes(32),
				[dest.pubkey],
				[{}]
			);
			const myReplyPath = constructBlindedPath(
				crypto.randomBytes(32),
				[me.pubkey],
				[{ pathId: crypto.randomBytes(32) }]
			);
			const data = new Map<number, Buffer>([[64, Buffer.from('invreq')]]);
			const msg = constructReplyOnionMessage(toDest, data, undefined, {
				replyPath: myReplyPath
			});
			const result = processOnionMessage(
				msg.onionRoutingPacket,
				dest.privkey,
				msg.blindingPoint
			);
			expect(result.type).to.equal('delivery');
			if (result.type === 'delivery') {
				expect(result.payload.replyPath, 'reply path delivered').to.exist;
				expect(
					result.payload.replyPath!.introductionNodeId.equals(me.pubkey)
				).to.equal(true);
			}
		});
	});

	describe('hop payload total_amount_msat (TLV 18)', function () {
		it('round-trips on a blinded final payment payload', function () {
			const encoded = encodeHopPayload({
				amountToForwardMsat: 25_000_000n,
				outgoingCltvValue: 700,
				encryptedRecipientData: crypto.randomBytes(64),
				blindingPoint: getPublicKey(crypto.randomBytes(32)),
				totalAmountMsat: 25_000_000n
			});
			const { payload } = decodeHopPayload(encoded, 0);
			expect(payload.totalAmountMsat).to.equal(25_000_000n);
			expect(payload.amountToForwardMsat).to.equal(25_000_000n);
		});
	});
});
