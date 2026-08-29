/**
 * Direct-funding sealed frames (issue #610, LFBW port #532 4A).
 *
 * The four properties the frame layer owes: directional keys, a fresh nonce
 * on every seal, silence for a request we did not mint, and an identity key
 * that never decrypts anything.
 */

import { expect } from 'chai';
import {
	DF_FRAME_FORM_CONTINUATION,
	DF_FRAME_FORM_OPENING,
	DF_INFO_RECEIVER_TO_SENDER,
	DF_INFO_SENDER_TO_RECEIVER,
	decodeSealedFrame,
	encodeSealedFrame,
	mintRequestEncryptionKeys,
	openFrame,
	receiverLaneKeys,
	sealFrame,
	senderLaneKeys
} from '../../src/lightning/direct-funding';
import { hkdf } from '../../src/lightning/crypto/hkdf';
import { ecdh, getPublicKey } from '../../src/lightning/crypto/ecdh';

const REQUEST_ID = Buffer.from('0f0e0d0c0b0a09080706050403020100', 'hex');
const OFFER_SUBTYPE = 16;
const RECEIPT_SUBTYPE = 21;

function lanes(): {
	sender: ReturnType<typeof senderLaneKeys>;
	receiver: ReturnType<typeof receiverLaneKeys>;
	request: ReturnType<typeof mintRequestEncryptionKeys>;
} {
	const request = mintRequestEncryptionKeys();
	const sender = senderLaneKeys(request.publicKey, REQUEST_ID);
	const receiver = receiverLaneKeys(
		request.privateKey,
		sender.ephemeralPublicKey,
		REQUEST_ID
	);
	return { sender, receiver, request };
}

describe('Direct funding: sealed frames', () => {
	it('derives the same directional keys on both sides', () => {
		const { sender, receiver } = lanes();
		expect(sender.keys.sendKey).to.deep.equal(receiver.recvKey);
		expect(sender.keys.recvKey).to.deep.equal(receiver.sendKey);
		expect(sender.keys.sendKey).to.not.deep.equal(sender.keys.recvKey);
	});

	it('derives them exactly as the draft states', () => {
		const request = mintRequestEncryptionKeys();
		const ephemeral = Buffer.alloc(32, 0x09);
		const sender = senderLaneKeys(request.publicKey, REQUEST_ID, ephemeral);
		// shared = SHA256 of the compressed shared point (BOLT 8 style), then
		// HKDF-SHA256 with the raw request id as salt and the byte-exact infos.
		const shared = ecdh(ephemeral, request.publicKey);
		expect(sender.ephemeralPublicKey).to.deep.equal(getPublicKey(ephemeral));
		expect(sender.keys.sendKey).to.deep.equal(
			hkdf(REQUEST_ID, shared, Buffer.from(DF_INFO_SENDER_TO_RECEIVER), 32)
		);
		expect(sender.keys.recvKey).to.deep.equal(
			hkdf(REQUEST_ID, shared, Buffer.from(DF_INFO_RECEIVER_TO_SENDER), 32)
		);
	});

	it('seals and opens in both directions', () => {
		const { sender, receiver } = lanes();
		const toReceiver = sealFrame(
			sender.keys.sendKey,
			REQUEST_ID,
			OFFER_SUBTYPE,
			Buffer.from('offer body')
		);
		expect(
			openFrame(receiver.recvKey, REQUEST_ID, OFFER_SUBTYPE, toReceiver)
		).to.deep.equal(Buffer.from('offer body'));

		const toSender = sealFrame(
			receiver.sendKey,
			REQUEST_ID,
			RECEIPT_SUBTYPE,
			Buffer.from('receipt body')
		);
		expect(
			openFrame(sender.keys.recvKey, REQUEST_ID, RECEIPT_SUBTYPE, toSender)
		).to.deep.equal(Buffer.from('receipt body'));
	});

	it('fails a frame reflected back at its author', () => {
		const { sender } = lanes();
		const frame = sealFrame(
			sender.keys.sendKey,
			REQUEST_ID,
			OFFER_SUBTYPE,
			Buffer.from('offer body')
		);
		// The author receives its own frame back: its recv key is the OTHER
		// direction's, so authentication fails rather than accepting it as a
		// reply from the peer.
		expect(
			openFrame(sender.keys.recvKey, REQUEST_ID, OFFER_SUBTYPE, frame)
		).to.equal(null);
	});

	it('fails a frame opened with the wrong key', () => {
		const { sender } = lanes();
		const other = lanes();
		const frame = sealFrame(
			sender.keys.sendKey,
			REQUEST_ID,
			OFFER_SUBTYPE,
			Buffer.from('offer body')
		);
		expect(
			openFrame(other.receiver.recvKey, REQUEST_ID, OFFER_SUBTYPE, frame)
		).to.equal(null);
	});

	it('binds the request id and subtype as associated data', () => {
		const { sender, receiver } = lanes();
		const frame = sealFrame(
			sender.keys.sendKey,
			REQUEST_ID,
			OFFER_SUBTYPE,
			Buffer.from('offer body')
		);
		expect(
			openFrame(receiver.recvKey, REQUEST_ID, RECEIPT_SUBTYPE, frame)
		).to.equal(null);
		expect(
			openFrame(receiver.recvKey, Buffer.alloc(16, 0xff), OFFER_SUBTYPE, frame)
		).to.equal(null);
	});

	it('fails a tampered ciphertext without throwing', () => {
		const { sender, receiver } = lanes();
		const frame = sealFrame(
			sender.keys.sendKey,
			REQUEST_ID,
			OFFER_SUBTYPE,
			Buffer.from('offer body')
		);
		frame.ciphertext[0] ^= 0xff;
		expect(
			openFrame(receiver.recvKey, REQUEST_ID, OFFER_SUBTYPE, frame)
		).to.equal(null);
	});

	it('re-seals a retransmission under a fresh nonce', () => {
		const { sender, receiver } = lanes();
		const body = Buffer.from('the same logical offer');
		const first = sealFrame(
			sender.keys.sendKey,
			REQUEST_ID,
			OFFER_SUBTYPE,
			body
		);
		const retry = sealFrame(
			sender.keys.sendKey,
			REQUEST_ID,
			OFFER_SUBTYPE,
			body
		);
		expect(first.nonce).to.not.deep.equal(retry.nonce);
		expect(first.ciphertext).to.not.deep.equal(retry.ciphertext);
		// Both still open: a retransmit is a valid frame, just never under a
		// nonce that has already carried a plaintext.
		expect(
			openFrame(receiver.recvKey, REQUEST_ID, OFFER_SUBTYPE, retry)
		).to.deep.equal(body);
	});

	it('keeps nonces unique across many seals', () => {
		const { sender } = lanes();
		const seen = new Set<string>();
		for (let i = 0; i < 200; i++) {
			seen.add(
				sealFrame(
					sender.keys.sendKey,
					REQUEST_ID,
					OFFER_SUBTYPE,
					Buffer.from([i])
				).nonce.toString('hex')
			);
		}
		expect(seen.size).to.equal(200);
	});

	describe('wire form', () => {
		it('round trips the opening form with the request id in the clear', () => {
			const { sender, receiver } = lanes();
			const frame = sealFrame(
				sender.keys.sendKey,
				REQUEST_ID,
				OFFER_SUBTYPE,
				Buffer.from('offer body')
			);
			const wire = encodeSealedFrame(frame, {
				requestId: REQUEST_ID,
				ephemeralPublicKey: sender.ephemeralPublicKey
			});
			expect(wire[0]).to.equal(DF_FRAME_FORM_OPENING);
			const decoded = decodeSealedFrame(wire);
			expect(decoded?.requestId).to.deep.equal(REQUEST_ID);
			expect(decoded?.ephemeralPublicKey).to.deep.equal(
				sender.ephemeralPublicKey
			);
			expect(
				openFrame(receiver.recvKey, REQUEST_ID, OFFER_SUBTYPE, decoded!)
			).to.deep.equal(Buffer.from('offer body'));
		});

		it('round trips a continuation frame as nonce and ciphertext only', () => {
			const { receiver, sender } = lanes();
			const frame = sealFrame(
				receiver.sendKey,
				REQUEST_ID,
				RECEIPT_SUBTYPE,
				Buffer.from('receipt body')
			);
			const wire = encodeSealedFrame(frame);
			expect(wire[0]).to.equal(DF_FRAME_FORM_CONTINUATION);
			expect(wire.length).to.equal(1 + 12 + frame.ciphertext.length);
			const decoded = decodeSealedFrame(wire);
			expect(decoded?.requestId).to.equal(undefined);
			expect(
				openFrame(sender.keys.recvKey, REQUEST_ID, RECEIPT_SUBTYPE, decoded!)
			).to.deep.equal(Buffer.from('receipt body'));
		});

		it('returns null for junk instead of throwing', () => {
			expect(decodeSealedFrame(Buffer.alloc(0))).to.equal(null);
			expect(decodeSealedFrame(Buffer.from([7, 1, 2, 3]))).to.equal(null);
			expect(decodeSealedFrame(Buffer.from([0, 1, 2]))).to.equal(null);
			expect(
				decodeSealedFrame(Buffer.concat([Buffer.from([1]), Buffer.alloc(20)]))
			).to.equal(null);
		});
	});
});
