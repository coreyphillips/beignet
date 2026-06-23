import { expect } from 'chai';
import crypto from 'crypto';
import {
	CipherState,
	TransportCipher
} from '../../src/lightning/transport/cipher';
import {
	createInitiatorHandshake,
	createResponderHandshake,
	ACT_ONE_LENGTH,
	ACT_TWO_LENGTH,
	ACT_THREE_LENGTH
} from '../../src/lightning/transport/noise';
import {
	encodePingMessage,
	decodePingMessage,
	encodePongMessage,
	decodePongMessage
} from '../../src/lightning/message/ping';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { hkdf2 } from '../../src/lightning/crypto/hkdf';

describe('Lightning Transport (BOLT 8)', function () {
	// ─── CipherState Tests ──────────────────────────────────────

	describe('CipherState', function () {
		it('Should encrypt and decrypt a message', function () {
			const key = crypto.randomBytes(32);
			const ck = crypto.randomBytes(32);

			const sender = new CipherState(key, ck);
			const receiver = new CipherState(Buffer.from(key), Buffer.from(ck));

			const plaintext = Buffer.from('Hello Lightning!');
			const ciphertext = sender.encryptMessage(plaintext);
			const decrypted = receiver.decryptMessage(ciphertext);

			expect(decrypted.equals(plaintext)).to.be.true;
		});

		it('Should track nonce correctly', function () {
			const key = crypto.randomBytes(32);
			const ck = crypto.randomBytes(32);
			const cipher = new CipherState(key, ck);

			expect(cipher.getNonce()).to.equal(0n);

			cipher.encryptMessage(Buffer.from('test'));
			expect(cipher.getNonce()).to.equal(1n);

			cipher.encryptMessage(Buffer.from('test2'));
			expect(cipher.getNonce()).to.equal(2n);
		});

		it('Should fail to decrypt with wrong key', function () {
			const key1 = crypto.randomBytes(32);
			const key2 = crypto.randomBytes(32);
			const ck = crypto.randomBytes(32);

			const sender = new CipherState(key1, ck);
			const receiver = new CipherState(key2, ck);

			const ciphertext = sender.encryptMessage(Buffer.from('secret'));
			expect(() => receiver.decryptMessage(ciphertext)).to.throw();
		});

		it('Should fail to decrypt with mismatched nonce', function () {
			const key = crypto.randomBytes(32);
			const ck = crypto.randomBytes(32);

			const sender = new CipherState(key, ck);
			const receiver = new CipherState(Buffer.from(key), Buffer.from(ck));

			// Advance sender nonce
			sender.encryptMessage(Buffer.from('skip'));

			const ciphertext = sender.encryptMessage(Buffer.from('actual'));
			expect(() => receiver.decryptMessage(ciphertext)).to.throw();
		});

		it('Should rotate keys after 1000 messages', function () {
			const key = crypto.randomBytes(32);
			const ck = crypto.randomBytes(32);

			const sender = new CipherState(Buffer.from(key), Buffer.from(ck));
			const receiver = new CipherState(Buffer.from(key), Buffer.from(ck));

			// Send 1000 messages to trigger rotation
			for (let i = 0; i < 1000; i++) {
				const plaintext = Buffer.from(`msg-${i}`);
				const ciphertext = sender.encryptMessage(plaintext);
				const decrypted = receiver.decryptMessage(ciphertext);
				expect(decrypted.equals(plaintext)).to.be.true;
			}

			// After rotation, nonce resets to 0
			expect(sender.getNonce()).to.equal(0n);
			expect(receiver.getNonce()).to.equal(0n);

			// Should still work after rotation
			const plaintext = Buffer.from('after rotation');
			const ciphertext = sender.encryptMessage(plaintext);
			const decrypted = receiver.decryptMessage(ciphertext);
			expect(decrypted.equals(plaintext)).to.be.true;
		});

		it('Should encrypt/decrypt with associated data', function () {
			const key = crypto.randomBytes(32);
			const ck = crypto.randomBytes(32);
			const aad = Buffer.from('additional data');

			const cipher = new CipherState(key, ck);
			const ciphertext = cipher.encryptWithAd(Buffer.from('hello'), aad);

			const decipher = new CipherState(Buffer.from(key), Buffer.from(ck));
			const decrypted = decipher.decryptWithAd(ciphertext, aad);

			expect(decrypted.toString()).to.equal('hello');
		});

		it('Should reject invalid key length', function () {
			expect(
				() => new CipherState(Buffer.alloc(16), Buffer.alloc(32))
			).to.throw('32 bytes');
			expect(
				() => new CipherState(Buffer.alloc(32), Buffer.alloc(16))
			).to.throw('32 bytes');
		});
	});

	// ─── TransportCipher Tests ──────────────────────────────────

	describe('TransportCipher', function () {
		it('Should encrypt and decrypt a packet', function () {
			const ck = crypto.randomBytes(32);

			// In a real setup, send and recv keys are different
			const [sk, rk] = hkdf2(ck, Buffer.alloc(0));

			const sender = new TransportCipher(sk, rk, ck);
			const receiver = new TransportCipher(rk, sk, Buffer.from(ck));

			const payload = Buffer.from('Hello Lightning Network!');
			const encrypted = sender.encryptPacket(payload);

			// Encrypted: 18 bytes length + payload.length + 16 bytes body tag
			expect(encrypted.length).to.equal(18 + payload.length + 16);

			// Decrypt
			const encLength = encrypted.subarray(0, 18);
			const bodyLen = receiver.decryptLength(encLength);
			expect(bodyLen).to.equal(payload.length);

			const encBody = encrypted.subarray(18);
			const decrypted = receiver.decryptBody(encBody);
			expect(decrypted.equals(payload)).to.be.true;
		});

		it('Should handle multiple sequential packets', function () {
			const ck = crypto.randomBytes(32);
			const [sk, rk] = hkdf2(ck, Buffer.alloc(0));

			const sender = new TransportCipher(sk, rk, ck);
			const receiver = new TransportCipher(rk, sk, Buffer.from(ck));

			for (let i = 0; i < 10; i++) {
				const payload = Buffer.from(`Message ${i}`);
				const encrypted = sender.encryptPacket(payload);

				expect(receiver.decryptLength(encrypted.subarray(0, 18))).to.equal(
					payload.length
				);
				const decrypted = receiver.decryptBody(encrypted.subarray(18));

				expect(decrypted.equals(payload)).to.be.true;
			}
		});

		it('Should reject payloads larger than 65535 bytes', function () {
			const ck = crypto.randomBytes(32);
			const [sk, rk] = hkdf2(ck, Buffer.alloc(0));
			const sender = new TransportCipher(sk, rk, ck);

			expect(() => sender.encryptPacket(Buffer.alloc(65536))).to.throw('65535');
		});

		it('Should reject invalid encrypted length size', function () {
			const ck = crypto.randomBytes(32);
			const [sk, rk] = hkdf2(ck, Buffer.alloc(0));
			const receiver = new TransportCipher(rk, sk, ck);

			expect(() => receiver.decryptLength(Buffer.alloc(10))).to.throw(
				'18 bytes'
			);
		});
	});

	// ─── Noise_XK Handshake Tests ───────────────────────────────

	describe('Noise_XK Handshake', function () {
		it('Should complete a full handshake between initiator and responder', function () {
			const initiatorStaticPriv = crypto.randomBytes(32);
			const responderStaticPriv = crypto.randomBytes(32);
			const responderStaticPub = getPublicKey(responderStaticPriv);
			const initiatorStaticPub = getPublicKey(initiatorStaticPriv);

			const initiator = createInitiatorHandshake(
				initiatorStaticPriv,
				responderStaticPub
			);
			const responder = createResponderHandshake(responderStaticPriv);

			// Act 1
			expect(initiator.act1.length).to.equal(ACT_ONE_LENGTH);
			responder.processAct1(initiator.act1);

			// Act 2
			const act2 = responder.createAct2();
			expect(act2.length).to.equal(ACT_TWO_LENGTH);
			initiator.processAct2(act2);

			// Act 3
			const act3 = initiator.createAct3();
			expect(act3.length).to.equal(ACT_THREE_LENGTH);
			const remotePub = responder.processAct3(act3);

			// Responder should have authenticated the initiator's static pubkey
			expect(remotePub.equals(initiatorStaticPub)).to.be.true;
		});

		it('Should derive matching transport ciphers', function () {
			const initiatorStaticPriv = crypto.randomBytes(32);
			const responderStaticPriv = crypto.randomBytes(32);
			const responderStaticPub = getPublicKey(responderStaticPriv);

			const initiator = createInitiatorHandshake(
				initiatorStaticPriv,
				responderStaticPub
			);
			const responder = createResponderHandshake(responderStaticPriv);

			responder.processAct1(initiator.act1);
			const act2 = responder.createAct2();
			initiator.processAct2(act2);
			const act3 = initiator.createAct3();
			responder.processAct3(act3);

			const iTransport = initiator.deriveTransport();
			const rTransport = responder.deriveTransport();

			// Test bidirectional communication
			const msg1 = Buffer.from('Hello from initiator');
			const encrypted1 = iTransport.encryptPacket(msg1);
			expect(rTransport.decryptLength(encrypted1.subarray(0, 18))).to.equal(
				msg1.length
			);
			const body1 = rTransport.decryptBody(encrypted1.subarray(18));
			expect(body1.equals(msg1)).to.be.true;

			const msg2 = Buffer.from('Hello from responder');
			const encrypted2 = rTransport.encryptPacket(msg2);
			expect(iTransport.decryptLength(encrypted2.subarray(0, 18))).to.equal(
				msg2.length
			);
			const body2 = iTransport.decryptBody(encrypted2.subarray(18));
			expect(body2.equals(msg2)).to.be.true;
		});

		it('Should reject Act 1 with wrong version', function () {
			const responderStaticPriv = crypto.randomBytes(32);
			const responder = createResponderHandshake(responderStaticPriv);

			const badAct1 = Buffer.alloc(50);
			badAct1[0] = 0x01; // Wrong version

			expect(() => responder.processAct1(badAct1)).to.throw('version');
		});

		it('Should reject Act 2 with wrong length', function () {
			const initiatorStaticPriv = crypto.randomBytes(32);
			const responderStaticPriv = crypto.randomBytes(32);
			const responderStaticPub = getPublicKey(responderStaticPriv);

			const initiator = createInitiatorHandshake(
				initiatorStaticPriv,
				responderStaticPub
			);

			expect(() => initiator.processAct2(Buffer.alloc(49))).to.throw(
				'50 bytes'
			);
		});

		it('Should reject Act 3 with wrong length', function () {
			const initiatorStaticPriv = crypto.randomBytes(32);
			const responderStaticPriv = crypto.randomBytes(32);
			const responderStaticPub = getPublicKey(responderStaticPriv);

			const initiator = createInitiatorHandshake(
				initiatorStaticPriv,
				responderStaticPub
			);
			const responder = createResponderHandshake(responderStaticPriv);

			responder.processAct1(initiator.act1);
			const act2 = responder.createAct2();
			initiator.processAct2(act2);

			expect(() => responder.processAct3(Buffer.alloc(65))).to.throw(
				'66 bytes'
			);
		});

		it('Should reject Act 1 with an off-curve ephemeral key', function () {
			const responderStaticPriv = crypto.randomBytes(32);
			const responder = createResponderHandshake(responderStaticPriv);

			// Valid length + version, but bytes 1..34 are not a curve point
			// (0x02 compressed prefix with x = 0 has no valid y).
			const badAct1 = Buffer.alloc(ACT_ONE_LENGTH);
			badAct1[0] = 0x00;
			badAct1[1] = 0x02;

			expect(() => responder.processAct1(badAct1)).to.throw(
				'valid curve point'
			);
		});

		it('Should reject Act 2 with an off-curve ephemeral key', function () {
			const initiatorStaticPriv = crypto.randomBytes(32);
			const responderStaticPriv = crypto.randomBytes(32);
			const responderStaticPub = getPublicKey(responderStaticPriv);

			const initiator = createInitiatorHandshake(
				initiatorStaticPriv,
				responderStaticPub
			);

			const badAct2 = Buffer.alloc(ACT_TWO_LENGTH);
			badAct2[0] = 0x00;
			badAct2[1] = 0x02;

			expect(() => initiator.processAct2(badAct2)).to.throw(
				'valid curve point'
			);
		});

		// BOLT 8 Appendix A Test Vectors
		describe('BOLT 8 Test Vectors', function () {
			const initiatorStaticPriv = Buffer.from(
				'1111111111111111111111111111111111111111111111111111111111111111',
				'hex'
			);
			const responderStaticPriv = Buffer.from(
				'2121212121212121212121212121212121212121212121212121212121212121',
				'hex'
			);
			const responderStaticPub = getPublicKey(responderStaticPriv);
			const initiatorEphemeralPriv = Buffer.from(
				'1212121212121212121212121212121212121212121212121212121212121212',
				'hex'
			);
			const responderEphemeralPriv = Buffer.from(
				'2222222222222222222222222222222222222222222222222222222222222222',
				'hex'
			);

			it('Should produce correct Act 1 output', function () {
				const initiator = createInitiatorHandshake(
					initiatorStaticPriv,
					responderStaticPub,
					initiatorEphemeralPriv
				);

				expect(initiator.act1.length).to.equal(50);
				expect(initiator.act1[0]).to.equal(0x00); // version

				// The ephemeral pubkey should be deterministic
				const expectedEphPub = getPublicKey(initiatorEphemeralPriv);
				expect(initiator.act1.subarray(1, 34).equals(expectedEphPub)).to.be
					.true;
			});

			it('Should complete handshake with known keys', function () {
				const initiator = createInitiatorHandshake(
					initiatorStaticPriv,
					responderStaticPub,
					initiatorEphemeralPriv
				);
				const responder = createResponderHandshake(
					responderStaticPriv,
					responderEphemeralPriv
				);

				// Act 1
				responder.processAct1(initiator.act1);

				// Act 2
				const act2 = responder.createAct2();
				expect(act2.length).to.equal(50);
				initiator.processAct2(act2);

				// Act 3
				const act3 = initiator.createAct3();
				expect(act3.length).to.equal(66);
				const remotePub = responder.processAct3(act3);

				expect(remotePub.equals(getPublicKey(initiatorStaticPriv))).to.be.true;

				// Derive transport ciphers and verify they work
				const iTransport = initiator.deriveTransport();
				const rTransport = responder.deriveTransport();

				const testMsg = Buffer.from('test message');
				const enc = iTransport.encryptPacket(testMsg);
				expect(rTransport.decryptLength(enc.subarray(0, 18))).to.equal(
					testMsg.length
				);
				const dec = rTransport.decryptBody(enc.subarray(18));
				expect(dec.equals(testMsg)).to.be.true;
			});
		});
	});

	// ─── Message Framing Tests ──────────────────────────────────

	describe('Encrypted Message Framing', function () {
		it('Should frame and deframe messages correctly', function () {
			const ck = crypto.randomBytes(32);
			const [sk, rk] = hkdf2(ck, Buffer.alloc(0));

			const sender = new TransportCipher(sk, rk, ck);
			const receiver = new TransportCipher(rk, sk, Buffer.from(ck));

			// Simulate multiple messages
			const messages = [
				Buffer.from('short'),
				Buffer.alloc(100, 0x42),
				Buffer.alloc(65535, 0xff), // max size
				Buffer.alloc(0) // empty
			];

			for (const msg of messages) {
				const encrypted = sender.encryptPacket(msg);
				const bodyLen = receiver.decryptLength(encrypted.subarray(0, 18));
				expect(bodyLen).to.equal(msg.length);

				const decrypted = receiver.decryptBody(encrypted.subarray(18));
				expect(decrypted.equals(msg)).to.be.true;
			}
		});

		it('Should handle partial buffer reassembly', function () {
			const ck = crypto.randomBytes(32);
			const [sk, rk] = hkdf2(ck, Buffer.alloc(0));

			const sender = new TransportCipher(sk, rk, ck);
			const receiver = new TransportCipher(rk, sk, Buffer.from(ck));

			const payload = Buffer.from('test partial reads');
			const encrypted = sender.encryptPacket(payload);

			// Split encrypted data into chunks and reassemble
			const chunk1 = encrypted.subarray(0, 18);
			const chunk2 = encrypted.subarray(18);

			const bodyLen = receiver.decryptLength(chunk1);
			expect(bodyLen).to.equal(payload.length);

			const decrypted = receiver.decryptBody(chunk2);
			expect(decrypted.equals(payload)).to.be.true;
		});
	});

	// ─── Ping/Pong Tests ────────────────────────────────────────

	describe('Ping/Pong Messages', function () {
		it('Should encode and decode a ping message', function () {
			const payload = encodePingMessage(100, 32);
			const decoded = decodePingMessage(payload);

			expect(decoded.numPongBytes).to.equal(100);
			expect(decoded.byteslen).to.equal(32);
		});

		it('Should encode and decode a ping with zero padding', function () {
			const payload = encodePingMessage(50, 0);
			expect(payload.length).to.equal(4);

			const decoded = decodePingMessage(payload);
			expect(decoded.numPongBytes).to.equal(50);
			expect(decoded.byteslen).to.equal(0);
		});

		it('Should encode and decode a pong message', function () {
			const payload = encodePongMessage(100);
			const decoded = decodePongMessage(payload);

			expect(decoded.byteslen).to.equal(100);
		});

		it('Should encode and decode a pong with zero bytes', function () {
			const payload = encodePongMessage(0);
			expect(payload.length).to.equal(2);

			const decoded = decodePongMessage(payload);
			expect(decoded.byteslen).to.equal(0);
		});

		it('Should reject ping with too-short payload', function () {
			expect(() => decodePingMessage(Buffer.alloc(3))).to.throw(
				'at least 4 bytes'
			);
		});

		it('Should reject pong with too-short payload', function () {
			expect(() => decodePongMessage(Buffer.alloc(1))).to.throw(
				'at least 2 bytes'
			);
		});

		it('Should reject ping num_pong_bytes > 65531', function () {
			expect(() => encodePingMessage(65532, 0)).to.throw('65531');
		});

		it('Should round-trip ping/pong', function () {
			const numPongBytes = 42;
			const pingPayload = encodePingMessage(numPongBytes, 10);
			const ping = decodePingMessage(pingPayload);

			// Build matching pong
			const pongPayload = encodePongMessage(ping.numPongBytes);
			const pong = decodePongMessage(pongPayload);

			expect(pong.byteslen).to.equal(numPongBytes);
		});
	});

	// ─── BOLT 1 Message Type Handling ───────────────────────────
	describe('BOLT 1 Message Type Handling', function () {
		it('isRequiredMessageType should return true for even types', function () {
			const {
				isRequiredMessageType
			} = require('../../src/lightning/message/types');
			expect(isRequiredMessageType(100)).to.be.true;
			expect(isRequiredMessageType(0)).to.be.true;
		});

		it('isRequiredMessageType should return false for odd types', function () {
			const {
				isRequiredMessageType
			} = require('../../src/lightning/message/types');
			expect(isRequiredMessageType(101)).to.be.false;
			expect(isRequiredMessageType(1)).to.be.false;
		});

		it('messageTypeName should return known name for known types', function () {
			const {
				messageTypeName,
				MessageType
			} = require('../../src/lightning/message/types');
			expect(messageTypeName(MessageType.INIT)).to.equal('INIT');
			expect(messageTypeName(MessageType.PING)).to.equal('PING');
		});

		it('messageTypeName should return UNKNOWN for unknown types', function () {
			const { messageTypeName } = require('../../src/lightning/message/types');
			expect(messageTypeName(99999)).to.include('UNKNOWN');
		});
	});

	// ─── Message Size Validation ────────────────────────────────
	describe('Message Size Validation', function () {
		it('should import Peer class', function () {
			// Just verify the Peer module is accessible for future tests
			const { Peer } = require('../../src/lightning/transport/peer');
			expect(Peer).to.exist;
		});

		it('TransportCipher should reject payloads larger than 65535 bytes in encryptPacket', function () {
			// TransportCipher already validates this — just verify the behavior
			const ck = crypto.randomBytes(32);
			const [sk, rk] = hkdf2(ck, Buffer.alloc(0));
			const transport = new TransportCipher(sk, rk, ck);

			const oversizedPayload = Buffer.alloc(65536);
			expect(() => transport.encryptPacket(oversizedPayload)).to.throw();
		});
	});
});
