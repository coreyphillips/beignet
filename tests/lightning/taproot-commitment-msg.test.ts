/**
 * option_taproot wire format (M4.5): partial_signature_with_nonce in
 * commitment_signed + next_local_nonce in revoke_and_ack round-trip.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	encodeCommitmentSignedMessage,
	decodeCommitmentSignedMessage,
	encodeRevokeAndAckMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';

describe('option_taproot commitment messages', function () {
	const channelId = crypto.randomBytes(32);

	it('commitment_signed round-trips a 98-byte partial_signature_with_nonce', function () {
		const psig = crypto.randomBytes(98); // 32-byte partial || 66-byte nonce
		const decoded = decodeCommitmentSignedMessage(
			encodeCommitmentSignedMessage({
				channelId,
				signature: Buffer.alloc(64), // zero for taproot
				htlcSignatures: [],
				partialSignatureWithNonce: psig
			})
		);
		expect(decoded.partialSignatureWithNonce!.equals(psig)).to.be.true;
	});

	it('commitment_signed carries both splice funding_txid (1) and partial sig (2)', function () {
		const psig = crypto.randomBytes(98);
		const fundingTxid = crypto.randomBytes(32);
		const decoded = decodeCommitmentSignedMessage(
			encodeCommitmentSignedMessage({
				channelId,
				signature: Buffer.alloc(64),
				htlcSignatures: [crypto.randomBytes(64)],
				fundingTxid,
				partialSignatureWithNonce: psig
			})
		);
		expect(decoded.fundingTxid!.equals(fundingTxid)).to.be.true;
		expect(decoded.partialSignatureWithNonce!.equals(psig)).to.be.true;
		expect(decoded.htlcSignatures).to.have.length(1);
	});

	it('non-taproot commitment_signed is unchanged (no partial sig)', function () {
		const decoded = decodeCommitmentSignedMessage(
			encodeCommitmentSignedMessage({
				channelId,
				signature: crypto.randomBytes(64),
				htlcSignatures: []
			})
		);
		expect(decoded.partialSignatureWithNonce).to.be.undefined;
	});

	it('rejects a wrong-length partial sig', function () {
		expect(() =>
			encodeCommitmentSignedMessage({
				channelId,
				signature: Buffer.alloc(64),
				htlcSignatures: [],
				partialSignatureWithNonce: crypto.randomBytes(97)
			})
		).to.throw('98 bytes');
	});

	it('revoke_and_ack round-trips a 66-byte next_local_nonce', function () {
		const nonce = crypto.randomBytes(66);
		const decoded = decodeRevokeAndAckMessage(
			encodeRevokeAndAckMessage({
				channelId,
				perCommitmentSecret: crypto.randomBytes(32),
				nextPerCommitmentPoint: crypto.randomBytes(33),
				nextLocalNonce: nonce
			})
		);
		expect(decoded.nextLocalNonce!.equals(nonce)).to.be.true;
	});

	it('non-taproot revoke_and_ack stays 97 bytes with no nonce', function () {
		const encoded = encodeRevokeAndAckMessage({
			channelId,
			perCommitmentSecret: crypto.randomBytes(32),
			nextPerCommitmentPoint: crypto.randomBytes(33)
		});
		expect(encoded).to.have.length(97);
		expect(decodeRevokeAndAckMessage(encoded).nextLocalNonce).to.be.undefined;
	});
});
