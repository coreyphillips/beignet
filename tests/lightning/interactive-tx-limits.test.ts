/**
 * Interactive-tx receive-side limits and tx_signatures ordering regression
 * tests (BOLT 2).
 *
 * Covers two audit findings:
 * - S-2.M4: tx_complete/tx_add_output receive-side limits (peer funds
 *   coverage, feerate sufficiency, 252-per-peer caps, 400k-WU cap,
 *   MAX_MONEY, negotiated dust).
 * - S-2.M5: tx_signatures ordering must tie-break on the lower node_id
 *   instead of falling back to the non-initiator.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { InteractiveTxBuilder } from '../../src/lightning/interactive-tx/builder';
import {
	validateCompletedInteractiveTx,
	MAX_INTERACTIVE_TX_INPUTS,
	MAX_INTERACTIVE_TX_OUTPUTS,
	MAX_MONEY_SATS
} from '../../src/lightning/interactive-tx/validation';
import { IInteractiveTxInput } from '../../src/lightning/interactive-tx/types';

/** A parseable prev_tx paying `sats` to a random P2WPKH at vout 0. */
function makePrevTx(sats: bigint): Buffer {
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(crypto.randomBytes(32), 0);
	tx.addOutput(
		Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
		Number(sats)
	);
	return tx.toBuffer();
}

function peerInput(serialId: bigint, sats: bigint): IInteractiveTxInput {
	const prevTx = makePrevTx(sats);
	return {
		serialId,
		prevTxid: Buffer.from(bitcoin.Transaction.fromBuffer(prevTx).getHash()),
		prevOutputIndex: 0,
		sequence: 0xfffffffd,
		prevTx,
		prevTxVout: 0
	};
}

describe('Interactive-tx receive-side limits (S-2.M4)', function () {
	it('rejects a peer output above MAX_MONEY', function () {
		const builder = new InteractiveTxBuilder(true); // we are initiator
		const err = builder.addPeerOutput({
			serialId: 1n, // peer = acceptor = odd
			amountSats: MAX_MONEY_SATS + 1n,
			scriptPubkey: Buffer.alloc(22)
		});
		expect(err).to.contain('MAX_MONEY');
	});

	it('enforces the negotiated dust limit, not a flat 546', function () {
		const builder = new InteractiveTxBuilder(true);
		builder.setDustLimit(1_000n);
		const err = builder.addPeerOutput({
			serialId: 1n,
			amountSats: 800n, // above 546, below the negotiated 1000
			scriptPubkey: Buffer.alloc(22)
		});
		expect(err).to.contain('below dust limit 1000');
	});

	it('never lowers the dust floor below 546', function () {
		const builder = new InteractiveTxBuilder(true);
		builder.setDustLimit(100n);
		const err = builder.addPeerOutput({
			serialId: 1n,
			amountSats: 400n,
			scriptPubkey: Buffer.alloc(22)
		});
		expect(err).to.contain('below dust limit');
	});

	it('caps a peer at 252 inputs', function () {
		const builder = new InteractiveTxBuilder(true);
		for (let i = 0; i < MAX_INTERACTIVE_TX_INPUTS; i++) {
			const err = builder.addPeerInput({
				serialId: BigInt(2 * i + 1),
				prevTxid: crypto.randomBytes(32),
				prevOutputIndex: i,
				sequence: 0xfffffffd
			});
			expect(err).to.equal(null);
		}
		const err = builder.addPeerInput({
			serialId: BigInt(2 * MAX_INTERACTIVE_TX_INPUTS + 1),
			prevTxid: crypto.randomBytes(32),
			prevOutputIndex: 0,
			sequence: 0xfffffffd
		});
		expect(err).to.contain('exceeded 252 inputs');
	});

	it('caps a peer at 252 outputs', function () {
		const builder = new InteractiveTxBuilder(true);
		for (let i = 0; i < MAX_INTERACTIVE_TX_OUTPUTS; i++) {
			const err = builder.addPeerOutput({
				serialId: BigInt(2 * i + 1),
				amountSats: 1_000n,
				scriptPubkey: Buffer.alloc(22)
			});
			expect(err).to.equal(null);
		}
		const err = builder.addPeerOutput({
			serialId: BigInt(2 * MAX_INTERACTIVE_TX_OUTPUTS + 1),
			amountSats: 1_000n,
			scriptPubkey: Buffer.alloc(22)
		});
		expect(err).to.contain('exceeded 252 outputs');
	});

	describe('validateCompletedInteractiveTx', function () {
		const base = {
			remoteInputSats: 100_000n,
			remoteOutputSats: 20_000n,
			remoteContributionSats: 50_000n,
			feeSats: 1_000n,
			weight: 1_000,
			feeratePerKw: 253
		};

		it('accepts a balanced negotiation', function () {
			expect(validateCompletedInteractiveTx(base)).to.equal(null);
		});

		it('rejects a peer whose inputs do not cover outputs + contribution', function () {
			expect(
				validateCompletedInteractiveTx({
					...base,
					remoteInputSats: 60_000n // < 20k outputs + 50k contribution
				})
			).to.contain('do not cover');
		});

		it('allows a negative contribution (splice-out) to fund peer outputs', function () {
			expect(
				validateCompletedInteractiveTx({
					...base,
					remoteInputSats: 0n,
					remoteOutputSats: 50_000n,
					remoteContributionSats: -50_000n
				})
			).to.equal(null);
		});

		it('rejects outputs exceeding inputs', function () {
			expect(
				validateCompletedInteractiveTx({ ...base, feeSats: -1n })
			).to.contain('exceed its inputs');
		});

		it('rejects an insufficient feerate', function () {
			expect(
				validateCompletedInteractiveTx({
					...base,
					feeSats: 100n, // < ceil(1000 * 253 / 1000) = 253
					weight: 1_000
				})
			).to.contain('below minimum');
		});

		it('rejects a transaction above 400k WU', function () {
			expect(
				validateCompletedInteractiveTx({ ...base, weight: 400_001 })
			).to.contain('exceeds 400000');
		});
	});
});

describe('tx_signatures ordering tie-break (S-2.M5)', function () {
	/**
	 * Drive the private _v2ShouldSignFirst through a minimal mocked
	 * dual-funding session: both sides contribute the SAME input value, so
	 * only the node-id tie-break decides.
	 */
	function tieBreakResult(localNodeIdLower: boolean): boolean {
		const { Channel } = require('../../src/lightning/channel/channel');
		const channel = Object.create(Channel.prototype);
		channel._state = {
			dualFundingSession: {
				isInitiator: () => true,
				getTxBuilder: () => ({
					getInputs: () => [peerInput(0n, 50_000n), peerInput(1n, 50_000n)]
				})
			}
		};
		channel._localNodeIdLower = localNodeIdLower;
		return channel._v2ShouldSignFirst();
	}

	it('the lower node_id signs first on an exact value tie', function () {
		expect(tieBreakResult(true)).to.equal(true);
		expect(tieBreakResult(false)).to.equal(false);
	});

	/**
	 * Splice ordering: hard-coding acceptor-first deadlocks when the acceptor
	 * contributed MORE input value than the initiator's shared input (both
	 * sides wait). The value rule must decide.
	 */
	function spliceSignFirst(
		weAreInitiator: boolean,
		acceptorInputSats: bigint
	): boolean {
		const { Channel } = require('../../src/lightning/channel/channel');
		const channel = Object.create(Channel.prototype);
		const sharedInput: IInteractiveTxInput = {
			serialId: 0n, // even = initiator
			prevTxid: crypto.randomBytes(32),
			prevOutputIndex: 0,
			sequence: 0xfffffffd,
			prevTx: Buffer.alloc(0) // shared funding input travels without prev_tx
		};
		channel._state = { fundingSatoshis: 1_000_000n };
		channel._spliceSession = {
			isInitiator: () => weAreInitiator,
			getTxBuilder: () => ({
				getInputs: () => [sharedInput, peerInput(1n, acceptorInputSats)]
			})
		};
		channel._localNodeIdLower = null;
		return channel._spliceShouldSignFirst();
	}

	it('the splice initiator signs first when the acceptor contributed more value', function () {
		// Acceptor splice-in of 2M vs a 1M prior capacity: initiator has less.
		expect(spliceSignFirst(true, 2_000_000n)).to.equal(true);
		expect(spliceSignFirst(false, 2_000_000n)).to.equal(false);
	});

	it('the acceptor still signs first in the common splice shape', function () {
		expect(spliceSignFirst(true, 100_000n)).to.equal(false);
		expect(spliceSignFirst(false, 100_000n)).to.equal(true);
	});
});
