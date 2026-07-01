/**
 * option_taproot MuSig2 commitment co-signing (M4.5): crypto + nonce safety.
 *
 * Validates that two parties co-sign a commitment sighash with MuSig2 partial
 * signatures that mutually verify and aggregate to a valid BIP340 key-spend
 * signature for the funding output key, and documents the single-use nonce
 * constraint (reuse is catastrophic).
 */

import { expect } from 'chai';
import * as ecc from '@bitcoinerlab/secp256k1';
import crypto from 'crypto';
import {
	deriveTaprootFundingKey,
	generateNonce
} from '../../src/lightning/crypto/musig';
import {
	startCommitmentSigningSession,
	partialSignCommitment,
	verifyPartialCommitmentSig,
	aggregateCommitmentSig
} from '../../src/lightning/channel/commitment-musig';

function keypair(): { priv: Buffer; pub: Buffer } {
	const priv = crypto.randomBytes(32);
	return { priv, pub: Buffer.from(ecc.pointFromScalar(priv, true)!) };
}

describe('option_taproot MuSig2 commitment co-signing', function () {
	it('two parties co-sign a commitment sighash → valid key-spend signature', function () {
		const local = keypair();
		const remote = keypair();
		const { outputKey } = deriveTaprootFundingKey(local.pub, remote.pub);
		const sighash = crypto.randomBytes(32); // stand-in for the commitment sighash

		const localNonce = generateNonce({
			publicKey: local.pub,
			secretKey: local.priv,
			sessionId: crypto.randomBytes(32),
			msg: sighash
		});
		const remoteNonce = generateNonce({
			publicKey: remote.pub,
			secretKey: remote.priv,
			sessionId: crypto.randomBytes(32),
			msg: sighash
		});

		// Both sides derive the SAME session (regardless of local/remote order).
		const sessionL = startCommitmentSigningSession(
			sighash,
			local.pub,
			remote.pub,
			localNonce,
			Buffer.from(remoteNonce)
		);
		const sessionR = startCommitmentSigningSession(
			sighash,
			remote.pub,
			local.pub,
			remoteNonce,
			Buffer.from(localNonce)
		);

		const localPartial = partialSignCommitment(sessionL, local.priv, localNonce);
		const remotePartial = partialSignCommitment(
			sessionR,
			remote.priv,
			remoteNonce
		);

		// Each verifies the other's partial against its own session.
		expect(
			verifyPartialCommitmentSig(
				sessionL,
				remotePartial,
				remote.pub,
				Buffer.from(remoteNonce)
			)
		).to.be.true;
		expect(
			verifyPartialCommitmentSig(
				sessionR,
				localPartial,
				local.pub,
				Buffer.from(localNonce)
			)
		).to.be.true;

		const finalSig = aggregateCommitmentSig(
			sessionL,
			localPartial,
			remotePartial
		);
		expect(finalSig).to.have.length(64);
		// Independent BIP340 verification against the funding output key.
		expect(ecc.verifySchnorr(sighash, outputKey, finalSig)).to.be.true;
		expect(ecc.verifySchnorr(crypto.randomBytes(32), outputKey, finalSig)).to.be
			.false;
	});

	it('a partial-sig verify FAILS for the wrong peer key (tamper guard)', function () {
		const local = keypair();
		const remote = keypair();
		const wrong = keypair();
		const sighash = crypto.randomBytes(32);
		const localNonce = generateNonce({
			publicKey: local.pub,
			sessionId: crypto.randomBytes(32)
		});
		const remoteNonce = generateNonce({
			publicKey: remote.pub,
			sessionId: crypto.randomBytes(32)
		});
		const session = startCommitmentSigningSession(
			sighash,
			local.pub,
			remote.pub,
			localNonce,
			Buffer.from(remoteNonce)
		);
		const remotePartial = partialSignCommitment(
			startCommitmentSigningSession(
				sighash,
				remote.pub,
				local.pub,
				remoteNonce,
				Buffer.from(localNonce)
			),
			remote.priv,
			remoteNonce
		);
		expect(
			verifyPartialCommitmentSig(
				session,
				remotePartial,
				wrong.pub,
				Buffer.from(remoteNonce)
			)
		).to.be.false;
	});

	it('a secret nonce is single-use — re-signing with it throws (reuse guard)', function () {
		const local = keypair();
		const remote = keypair();
		const sighash = crypto.randomBytes(32);
		const localNonce = generateNonce({
			publicKey: local.pub,
			sessionId: crypto.randomBytes(32)
		});
		const remoteNonce = generateNonce({
			publicKey: remote.pub,
			sessionId: crypto.randomBytes(32)
		});
		const session = startCommitmentSigningSession(
			sighash,
			local.pub,
			remote.pub,
			localNonce,
			Buffer.from(remoteNonce)
		);
		partialSignCommitment(session, local.priv, localNonce);
		// The library consumes (deletes) the secret nonce after one signature.
		expect(() =>
			partialSignCommitment(session, local.priv, localNonce)
		).to.throw();
	});
});
