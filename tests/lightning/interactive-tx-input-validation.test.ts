/**
 * S-2.H3 regression: BOLT 2 interactive-tx receive-side validation of
 * tx_add_input.
 *
 * The anti-malleability rule is the fund-affecting one: a peer contributing a
 * non-native-segwit input can malleate the txid of the collaborative
 * funding/splice transaction after both sides signed commitments against it,
 * so the confirmed transaction holds the whole capacity at an outpoint with
 * no valid commitment signature (no unilateral exit). Also enforced now:
 * prevtx validity, prevtx_vout range, the 0xFFFFFFFE/0xFFFFFFFF sequence
 * rejection, and the 4096-message DoS cap.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { InteractiveTxBuilder } from '../../src/lightning/interactive-tx/builder';
import {
	MAX_INTERACTIVE_TX_MSGS,
	validatePeerInputPrevTx
} from '../../src/lightning/interactive-tx/validation';
import { IInteractiveTxInput } from '../../src/lightning/interactive-tx/types';

bitcoin.initEccLib(ecc);

/** A prev tx whose vout-0 script is the given scriptPubKey. */
function prevTxWithScript(script: Buffer, valueSats = 100_000): Buffer {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(script, valueSats);
	return tx.toBuffer();
}

const p2wpkhScript = (): Buffer =>
	bitcoin.payments.p2wpkh({ hash: crypto.randomBytes(20) }).output!;
const p2trScript = (): Buffer =>
	Buffer.concat([Buffer.from([0x51, 0x20]), crypto.randomBytes(32)]);
const p2pkhScript = (): Buffer =>
	bitcoin.payments.p2pkh({ hash: crypto.randomBytes(20) }).output!;
const p2shScript = (): Buffer =>
	bitcoin.payments.p2sh({ hash: crypto.randomBytes(20) }).output!;

function peerInput(
	overrides: Partial<IInteractiveTxInput> & { prevTx?: Buffer } = {}
): IInteractiveTxInput {
	const prevTx = overrides.prevTx ?? prevTxWithScript(p2wpkhScript());
	const prevTxid =
		prevTx.length > 0
			? Buffer.from(bitcoin.Transaction.fromBuffer(prevTx).getId(), 'hex')
			: crypto.randomBytes(32);
	return {
		serialId: 1n, // we are initiator below, so the peer uses odd ids
		prevTxid,
		prevOutputIndex: 0,
		sequence: 0xfffffffd,
		prevTx,
		prevTxVout: 0,
		...overrides
	};
}

describe('S-2.H3: interactive-tx tx_add_input receive-side validation', function () {
	describe('validatePeerInputPrevTx', function () {
		it('accepts native segwit spends (P2WPKH, P2WSH-shaped, P2TR)', function () {
			expect(validatePeerInputPrevTx(prevTxWithScript(p2wpkhScript()), 0)).to.be
				.null;
			const p2wsh = Buffer.concat([
				Buffer.from([0x00, 0x20]),
				crypto.randomBytes(32)
			]);
			expect(validatePeerInputPrevTx(prevTxWithScript(p2wsh), 0)).to.be.null;
			expect(validatePeerInputPrevTx(prevTxWithScript(p2trScript()), 0)).to.be
				.null;
		});

		it('rejects legacy and wrapped spends (txid malleable after signing)', function () {
			expect(
				validatePeerInputPrevTx(prevTxWithScript(p2pkhScript()), 0)
			).to.match(/non-native-segwit/);
			expect(
				validatePeerInputPrevTx(prevTxWithScript(p2shScript()), 0)
			).to.match(/non-native-segwit/);
		});

		it('rejects a missing, empty or unparseable prev_tx', function () {
			expect(validatePeerInputPrevTx(undefined, 0)).to.match(/missing/);
			expect(validatePeerInputPrevTx(Buffer.alloc(0), 0)).to.match(/missing/);
			expect(validatePeerInputPrevTx(crypto.randomBytes(64), 0)).to.match(
				/does not parse/
			);
		});

		it('rejects an out-of-range prev_tx_vout', function () {
			const prevTx = prevTxWithScript(p2wpkhScript());
			expect(validatePeerInputPrevTx(prevTx, 1)).to.match(/out of range/);
			expect(validatePeerInputPrevTx(prevTx, -1)).to.match(/invalid/);
		});
	});

	describe('InteractiveTxBuilder.addPeerInput', function () {
		it('rejects a peer input spending a legacy output', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addPeerInput(
				peerInput({ prevTx: prevTxWithScript(p2pkhScript()) })
			);
			expect(err).to.match(/non-native-segwit/);
		});

		it('rejects sequence 0xFFFFFFFE and 0xFFFFFFFF, accepts 0xFFFFFFFD', function () {
			const builder = new InteractiveTxBuilder(true);
			expect(
				builder.addPeerInput(peerInput({ sequence: 0xfffffffe }))
			).to.match(/sequence/);
			expect(
				builder.addPeerInput(peerInput({ sequence: 0xffffffff }))
			).to.match(/sequence/);
			expect(builder.addPeerInput(peerInput({ sequence: 0xfffffffd }))).to.be
				.null;
		});

		it('exempts the splice shared input from the prevtx checks', function () {
			const builder = new InteractiveTxBuilder(true);
			const err = builder.addPeerInput(
				peerInput({ prevTx: Buffer.alloc(0), isShared: true })
			);
			expect(err).to.be.null;
		});

		it('fails the negotiation after 4096 tx_add_input messages', function () {
			const builder = new InteractiveTxBuilder(true);
			const prevTx = prevTxWithScript(p2wpkhScript());
			// Add/remove churn: the per-side 252-input cap never trips, but every
			// received message counts toward the DoS cap.
			let err: string | null = null;
			for (let i = 0; i < MAX_INTERACTIVE_TX_MSGS; i++) {
				err = builder.addPeerInput(peerInput({ prevTx }));
				expect(err, `message ${i + 1} within the cap`).to.be.null;
				builder.removePeerInput(1n);
			}
			err = builder.addPeerInput(peerInput({ prevTx }));
			expect(err).to.match(/4096/);
		});
	});
});
