/**
 * Phase 1: BOLT 4 Failure Messages — Tests
 *
 * Tests for encrypted failure message creation, intermediate hop wrapping,
 * sender-side decryption, processOnionPacket shared secret return, and
 * various failure code encoding/decoding round-trips.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	createFailureMessage,
	wrapFailureMessage,
	decryptFailureMessage
} from '../../src/lightning/onion/failures';
import { constructOnionPacket } from '../../src/lightning/onion/construct';
import {
	processOnionPacket,
	isFinalHop
} from '../../src/lightning/onion/process';
import { computeSharedSecrets } from '../../src/lightning/onion/sphinx-crypto';
import { getPublicKey, ecdh } from '../../src/lightning/crypto/ecdh';
import {
	INVALID_ONION_HMAC,
	UNKNOWN_NEXT_PEER,
	INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
	TEMPORARY_CHANNEL_FAILURE,
	FEE_INSUFFICIENT,
	INCORRECT_CLTV_EXPIRY,
	EXPIRY_TOO_SOON,
	MPP_TIMEOUT,
	TEMPORARY_NODE_FAILURE,
	IHopPayload
} from '../../src/lightning/onion/types';

// ── Helpers ─────────────────────────────────────────────────────────

function randomPrivkey(): Buffer {
	let key: Buffer;
	do {
		key = crypto.randomBytes(32);
	} while (key[0] === 0);
	return key;
}

/**
 * Build a 3-node test route: sender -> node0 -> node1 -> node2 (final).
 * Returns private keys, public keys, hop payloads, and a session key.
 */
function buildThreeHopRoute(): {
	sessionKey: Buffer;
	nodeKeys: Buffer[];
	nodePubkeys: Buffer[];
	hops: { pubkey: Buffer; payload: IHopPayload }[];
} {
	const sessionKey = randomPrivkey();
	const nodeKeys = [randomPrivkey(), randomPrivkey(), randomPrivkey()];
	const nodePubkeys = nodeKeys.map((k) => getPublicKey(k));

	const scid01 = Buffer.alloc(8);
	scid01.writeUInt32BE(700000, 0);
	scid01.writeUInt32BE(1, 4);

	const scid12 = Buffer.alloc(8);
	scid12.writeUInt32BE(700001, 0);
	scid12.writeUInt32BE(2, 4);

	const hops: { pubkey: Buffer; payload: IHopPayload }[] = [
		{
			pubkey: nodePubkeys[0],
			payload: {
				amountToForwardMsat: 1002000n,
				outgoingCltvValue: 580,
				shortChannelId: scid01
			}
		},
		{
			pubkey: nodePubkeys[1],
			payload: {
				amountToForwardMsat: 1001000n,
				outgoingCltvValue: 540,
				shortChannelId: scid12
			}
		},
		{
			pubkey: nodePubkeys[2],
			payload: {
				amountToForwardMsat: 1000000n,
				outgoingCltvValue: 500
			}
		}
	];

	return { sessionKey, nodeKeys, nodePubkeys, hops };
}

// ── Tests ───────────────────────────────────────────────────────────

describe('BOLT 4: HTLC Failure Messages', () => {
	describe('createFailureMessage', () => {
		it('should produce a 290-byte encrypted message for TEMPORARY_CHANNEL_FAILURE', () => {
			const sharedSecret = crypto.randomBytes(32);
			const msg = createFailureMessage(sharedSecret, TEMPORARY_CHANNEL_FAILURE);
			expect(msg.length).to.equal(290);
		});

		it('should produce a 290-byte encrypted message for UNKNOWN_NEXT_PEER', () => {
			const sharedSecret = crypto.randomBytes(32);
			const msg = createFailureMessage(sharedSecret, UNKNOWN_NEXT_PEER);
			expect(msg.length).to.equal(290);
		});

		it('should produce a 290-byte encrypted message for INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS', () => {
			const sharedSecret = crypto.randomBytes(32);
			const msg = createFailureMessage(
				sharedSecret,
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);
			expect(msg.length).to.equal(290);
		});

		it('should produce a 290-byte encrypted message for FEE_INSUFFICIENT', () => {
			const sharedSecret = crypto.randomBytes(32);
			const msg = createFailureMessage(sharedSecret, FEE_INSUFFICIENT);
			expect(msg.length).to.equal(290);
		});

		it('should produce a 290-byte encrypted message for MPP_TIMEOUT', () => {
			const sharedSecret = crypto.randomBytes(32);
			const msg = createFailureMessage(sharedSecret, MPP_TIMEOUT);
			expect(msg.length).to.equal(290);
		});

		it('should produce different ciphertext for different shared secrets', () => {
			const ss1 = crypto.randomBytes(32);
			const ss2 = crypto.randomBytes(32);
			const msg1 = createFailureMessage(ss1, TEMPORARY_CHANNEL_FAILURE);
			const msg2 = createFailureMessage(ss2, TEMPORARY_CHANNEL_FAILURE);
			expect(msg1.equals(msg2)).to.be.false;
		});

		it('should produce different ciphertext for different failure codes', () => {
			const sharedSecret = crypto.randomBytes(32);
			const msg1 = createFailureMessage(
				sharedSecret,
				TEMPORARY_CHANNEL_FAILURE
			);
			const msg2 = createFailureMessage(sharedSecret, UNKNOWN_NEXT_PEER);
			expect(msg1.equals(msg2)).to.be.false;
		});
	});

	describe('wrapFailureMessage', () => {
		it('should produce output of the same length as input', () => {
			const sharedSecret = crypto.randomBytes(32);
			const innerMsg = createFailureMessage(
				crypto.randomBytes(32),
				TEMPORARY_CHANNEL_FAILURE
			);
			const wrapped = wrapFailureMessage(sharedSecret, innerMsg);
			expect(wrapped.length).to.equal(innerMsg.length);
		});

		it('should produce different output from input (XOR encryption)', () => {
			const sharedSecret = crypto.randomBytes(32);
			const innerMsg = createFailureMessage(
				crypto.randomBytes(32),
				TEMPORARY_CHANNEL_FAILURE
			);
			const wrapped = wrapFailureMessage(sharedSecret, innerMsg);
			expect(wrapped.equals(innerMsg)).to.be.false;
		});

		it('should be reversible with the same shared secret (double-wrap = identity)', () => {
			const sharedSecret = crypto.randomBytes(32);
			const innerMsg = createFailureMessage(
				crypto.randomBytes(32),
				TEMPORARY_CHANNEL_FAILURE
			);
			const wrapped = wrapFailureMessage(sharedSecret, innerMsg);
			const unwrapped = wrapFailureMessage(sharedSecret, wrapped);
			expect(unwrapped.equals(innerMsg)).to.be.true;
		});
	});

	describe('Round-trip: createFailure -> wrap -> decrypt', () => {
		it('should recover failure code from a single-hop route', () => {
			const sessionKey = randomPrivkey();
			const nodeKey = randomPrivkey();
			const nodePub = getPublicKey(nodeKey);

			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				[nodePub]
			);

			// The node derives the shared secret using its private key and the ephemeral key
			const nodeSecret = ecdh(nodeKey, ephemeralKeys[0]);
			const msg = createFailureMessage(nodeSecret, UNKNOWN_NEXT_PEER);

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(0);
			expect(result!.failure.failureCode).to.equal(UNKNOWN_NEXT_PEER);
		});

		it('should recover failure code and origin from a 3-hop route (failure at final hop)', () => {
			const { sessionKey, nodeKeys, nodePubkeys } = buildThreeHopRoute();
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				nodePubkeys
			);

			// Final hop (index 2) fails
			const hop2Secret = ecdh(nodeKeys[2], ephemeralKeys[2]);
			let msg = createFailureMessage(
				hop2Secret,
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);

			// Wrap backwards: hop1, hop0
			const hop1Secret = ecdh(nodeKeys[1], ephemeralKeys[1]);
			msg = wrapFailureMessage(hop1Secret, msg);

			const hop0Secret = ecdh(nodeKeys[0], ephemeralKeys[0]);
			msg = wrapFailureMessage(hop0Secret, msg);

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(2);
			expect(result!.failure.failureCode).to.equal(
				INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			);
		});

		it('should recover failure code and origin from a 3-hop route (failure at intermediate hop)', () => {
			const { sessionKey, nodeKeys, nodePubkeys } = buildThreeHopRoute();
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				nodePubkeys
			);

			// Intermediate hop (index 1) fails with fee_insufficient
			const hop1Secret = ecdh(nodeKeys[1], ephemeralKeys[1]);
			let msg = createFailureMessage(hop1Secret, FEE_INSUFFICIENT);

			// Only hop0 wraps (hop1 originated, so hop2 never saw it)
			const hop0Secret = ecdh(nodeKeys[0], ephemeralKeys[0]);
			msg = wrapFailureMessage(hop0Secret, msg);

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(1);
			expect(result!.failure.failureCode).to.equal(FEE_INSUFFICIENT);
		});

		it('should recover failure code and origin from a 3-hop route (failure at first hop)', () => {
			const { sessionKey, nodeKeys, nodePubkeys } = buildThreeHopRoute();
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				nodePubkeys
			);

			// First hop (index 0) fails — no wrapping needed at all
			const hop0Secret = ecdh(nodeKeys[0], ephemeralKeys[0]);
			const msg = createFailureMessage(hop0Secret, EXPIRY_TOO_SOON);

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(0);
			expect(result!.failure.failureCode).to.equal(EXPIRY_TOO_SOON);
		});

		it('should preserve failure data through the round-trip', () => {
			const { sessionKey, nodeKeys, nodePubkeys } = buildThreeHopRoute();
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				nodePubkeys
			);

			const failData = Buffer.alloc(12);
			failData.writeBigUInt64BE(42000n, 0);
			failData.writeUInt32BE(144, 8);

			const hop1Secret = ecdh(nodeKeys[1], ephemeralKeys[1]);
			let msg = createFailureMessage(
				hop1Secret,
				INCORRECT_CLTV_EXPIRY,
				failData
			);

			const hop0Secret = ecdh(nodeKeys[0], ephemeralKeys[0]);
			msg = wrapFailureMessage(hop0Secret, msg);

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.not.be.null;
			expect(result!.failure.failureCode).to.equal(INCORRECT_CLTV_EXPIRY);
			expect(result!.failure.failureData.equals(failData)).to.be.true;
		});

		it('should return null for a tampered failure message', () => {
			const { sessionKey, nodeKeys, nodePubkeys } = buildThreeHopRoute();
			const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
				sessionKey,
				nodePubkeys
			);

			const hop0Secret = ecdh(nodeKeys[0], ephemeralKeys[0]);
			const msg = createFailureMessage(hop0Secret, TEMPORARY_CHANNEL_FAILURE);

			// Corrupt a byte
			msg[50] ^= 0xff;

			const result = decryptFailureMessage(sharedSecrets, msg);
			expect(result).to.be.null;
		});
	});

	describe('processOnionPacket returns sharedSecret', () => {
		it('should return a 32-byte sharedSecret in the result', () => {
			const { sessionKey, nodeKeys, hops } = buildThreeHopRoute();
			const packet = constructOnionPacket(sessionKey, hops);

			const result = processOnionPacket(packet, nodeKeys[0]);
			expect(result.sharedSecret).to.be.instanceOf(Buffer);
			expect(result.sharedSecret.length).to.equal(32);
		});

		it('should return the same shared secret the sender computed', () => {
			const { sessionKey, nodeKeys, nodePubkeys, hops } = buildThreeHopRoute();
			const { sharedSecrets } = computeSharedSecrets(sessionKey, nodePubkeys);
			const packet = constructOnionPacket(sessionKey, hops);

			const result = processOnionPacket(packet, nodeKeys[0]);
			expect(result.sharedSecret.equals(sharedSecrets[0])).to.be.true;
		});

		it('should return correct shared secret at each hop in a 3-hop route', () => {
			const { sessionKey, nodeKeys, nodePubkeys, hops } = buildThreeHopRoute();
			const { sharedSecrets } = computeSharedSecrets(sessionKey, nodePubkeys);
			const packet = constructOnionPacket(sessionKey, hops);

			const r0 = processOnionPacket(packet, nodeKeys[0]);
			expect(r0.sharedSecret.equals(sharedSecrets[0])).to.be.true;

			const r1 = processOnionPacket(r0.nextPacket, nodeKeys[1]);
			expect(r1.sharedSecret.equals(sharedSecrets[1])).to.be.true;

			const r2 = processOnionPacket(r1.nextPacket, nodeKeys[2]);
			expect(r2.sharedSecret.equals(sharedSecrets[2])).to.be.true;
			expect(isFinalHop(r2.nextPacket)).to.be.true;
		});

		it('should allow using the returned sharedSecret to create a failure message', () => {
			const { sessionKey, nodeKeys, nodePubkeys, hops } = buildThreeHopRoute();
			const { sharedSecrets } = computeSharedSecrets(sessionKey, nodePubkeys);
			const packet = constructOnionPacket(sessionKey, hops);

			// Process at hop 0
			const r0 = processOnionPacket(packet, nodeKeys[0]);
			// Process at hop 1
			const r1 = processOnionPacket(r0.nextPacket, nodeKeys[1]);

			// Hop 1 creates a failure using the sharedSecret from processOnionPacket
			let failMsg = createFailureMessage(
				r1.sharedSecret,
				TEMPORARY_NODE_FAILURE
			);

			// Hop 0 wraps using its sharedSecret from processOnionPacket
			failMsg = wrapFailureMessage(r0.sharedSecret, failMsg);

			// Sender decrypts
			const result = decryptFailureMessage(sharedSecrets, failMsg);
			expect(result).to.not.be.null;
			expect(result!.originIndex).to.equal(1);
			expect(result!.failure.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
		});
	});

	describe('Failure code encoding/decoding', () => {
		const codes: Array<{ name: string; code: number }> = [
			{ name: 'INVALID_ONION_HMAC', code: INVALID_ONION_HMAC },
			{ name: 'UNKNOWN_NEXT_PEER', code: UNKNOWN_NEXT_PEER },
			{
				name: 'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS',
				code: INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
			},
			{ name: 'TEMPORARY_CHANNEL_FAILURE', code: TEMPORARY_CHANNEL_FAILURE },
			{ name: 'FEE_INSUFFICIENT', code: FEE_INSUFFICIENT },
			{ name: 'INCORRECT_CLTV_EXPIRY', code: INCORRECT_CLTV_EXPIRY },
			{ name: 'EXPIRY_TOO_SOON', code: EXPIRY_TOO_SOON },
			{ name: 'MPP_TIMEOUT', code: MPP_TIMEOUT },
			{ name: 'TEMPORARY_NODE_FAILURE', code: TEMPORARY_NODE_FAILURE }
		];

		for (const { name, code } of codes) {
			it(`should round-trip ${name} (0x${code.toString(
				16
			)}) through create+decrypt`, () => {
				const sessionKey = randomPrivkey();
				const nodeKey = randomPrivkey();
				const nodePub = getPublicKey(nodeKey);

				const { sharedSecrets, ephemeralKeys } = computeSharedSecrets(
					sessionKey,
					[nodePub]
				);
				const nodeSecret = ecdh(nodeKey, ephemeralKeys[0]);

				const msg = createFailureMessage(nodeSecret, code);
				expect(msg.length).to.equal(290);

				const result = decryptFailureMessage(sharedSecrets, msg);
				expect(result).to.not.be.null;
				expect(result!.failure.failureCode).to.equal(code);
				expect(result!.originIndex).to.equal(0);
			});
		}
	});
});
