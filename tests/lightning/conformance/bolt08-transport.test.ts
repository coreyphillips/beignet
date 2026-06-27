/**
 * BOLT 8 Appendix A: Transport (Noise_XK) Test Vectors.
 *
 * Drives the handshake with the spec's fixed ephemeral keys and asserts the
 * act1/act2/act3 bytes, the final chaining key, and the derived sending/
 * receiving keys all match the spec exactly. Negative vectors assert beignet
 * rejects malformed handshake messages.
 */

import { expect } from 'chai';
import {
	createInitiatorHandshake,
	createResponderHandshake
} from '../../../src/lightning/transport/noise';
import { hkdf2 } from '../../../src/lightning/crypto/hkdf';
import { loadVectors, hexToBuffer, bufferToHex } from './helpers';

interface ITransportVectors {
	keys: {
		initiator_ls_priv: string;
		initiator_e_priv: string;
		responder_ls_priv: string;
		responder_ls_pub: string;
		responder_e_priv: string;
		initiator_ls_pub: string;
	};
	successful_handshake: {
		act1: string;
		act2: string;
		act3: string;
		final_ck: string;
		sk: string;
		rk: string;
	};
	initiator_act2_errors: { name: string; input: string }[];
	responder_act1_errors: { name: string; input: string }[];
	responder_act3_errors: { name: string; input: string }[];
}

const v = loadVectors<ITransportVectors>('bolt08/transport.json');
const k = v.keys;

describe('BOLT 8 Appendix A: transport handshake conformance', function () {
	it('produces spec act1/act2/act3 bytes and transport keys', function () {
		const initiator = createInitiatorHandshake(
			hexToBuffer(k.initiator_ls_priv),
			hexToBuffer(k.responder_ls_pub),
			hexToBuffer(k.initiator_e_priv)
		);
		const responder = createResponderHandshake(
			hexToBuffer(k.responder_ls_priv),
			hexToBuffer(k.responder_e_priv)
		);

		// Act 1: initiator -> responder
		expect(bufferToHex(initiator.act1)).to.equal(v.successful_handshake.act1);
		responder.processAct1(initiator.act1);

		// Act 2: responder -> initiator
		const act2 = responder.createAct2();
		expect(bufferToHex(act2)).to.equal(v.successful_handshake.act2);
		initiator.processAct2(act2);

		// Act 3: initiator -> responder
		const act3 = initiator.createAct3();
		expect(bufferToHex(act3)).to.equal(v.successful_handshake.act3);
		const recoveredInitiatorStatic = responder.processAct3(act3);
		expect(bufferToHex(recoveredInitiatorStatic)).to.equal(k.initiator_ls_pub);

		// Both sides must converge to the same final chaining key.
		expect(bufferToHex(initiator.state.ck)).to.equal(
			v.successful_handshake.final_ck
		);
		expect(bufferToHex(responder.state.ck)).to.equal(
			v.successful_handshake.final_ck
		);

		// Split: sk, rk = HKDF(final_ck, zero). Mirrors deriveTransportCipher.
		const [sk, rk] = hkdf2(initiator.state.ck, Buffer.alloc(0));
		expect(bufferToHex(sk)).to.equal(v.successful_handshake.sk);
		expect(bufferToHex(rk)).to.equal(v.successful_handshake.rk);

		// Functional check: the initiator's transport cipher and the responder's
		// must interoperate (initiator send -> responder recv).
		const initiatorTransport = initiator.deriveTransport();
		const responderTransport = responder.deriveTransport();
		const msg = Buffer.from('conformance check', 'utf8');
		const packet = initiatorTransport.encryptPacket(msg);
		const len = responderTransport.decryptLength(packet.subarray(0, 18));
		const body = responderTransport.decryptBody(
			packet.subarray(18, 18 + len + 16)
		);
		expect(body.equals(msg)).to.equal(true);
	});

	describe('initiator rejects malformed act2', function () {
		for (const tc of v.initiator_act2_errors) {
			it(tc.name, function () {
				const initiator = createInitiatorHandshake(
					hexToBuffer(k.initiator_ls_priv),
					hexToBuffer(k.responder_ls_pub),
					hexToBuffer(k.initiator_e_priv)
				);
				expect(() => initiator.processAct2(hexToBuffer(tc.input))).to.throw();
			});
		}
	});

	describe('responder rejects malformed act1', function () {
		for (const tc of v.responder_act1_errors) {
			it(tc.name, function () {
				const responder = createResponderHandshake(
					hexToBuffer(k.responder_ls_priv),
					hexToBuffer(k.responder_e_priv)
				);
				expect(() => responder.processAct1(hexToBuffer(tc.input))).to.throw();
			});
		}
	});

	describe('responder rejects malformed act3', function () {
		for (const tc of v.responder_act3_errors) {
			it(tc.name, function () {
				const initiator = createInitiatorHandshake(
					hexToBuffer(k.initiator_ls_priv),
					hexToBuffer(k.responder_ls_pub),
					hexToBuffer(k.initiator_e_priv)
				);
				const responder = createResponderHandshake(
					hexToBuffer(k.responder_ls_priv),
					hexToBuffer(k.responder_e_priv)
				);
				responder.processAct1(initiator.act1);
				const act2 = responder.createAct2();
				initiator.processAct2(act2);
				expect(() => responder.processAct3(hexToBuffer(tc.input))).to.throw();
			});
		}
	});
});
