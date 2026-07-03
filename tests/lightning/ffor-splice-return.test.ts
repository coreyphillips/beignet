/**
 * FFOR M6: splice-on-return (spec §11.3 "On return"). After a completed epoch
 * (vouchers fulfilled to balance) the channel is in a fully NORMAL state:
 * R splices OUT its revenue on the SAME channel, the channel locks the new
 * funding, and ordinary payments still flow afterwards. Proves the epoch
 * leaves no residue that blocks the standard quiescence/splice machinery.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	createTriple,
	goOffline,
	reconnectSR,
	pay,
	sha256,
	FUNDING_SATOSHIS
} from './ffor-m6-harness';
import { FforEpochState } from '../../src/lightning/ffor/types';
import { ChannelState } from '../../src/lightning/channel/types';

describe('FFOR M6: splice-on-return (§11.3)', function () {
	it('R splices out its FFOR revenue after the epoch; channel stays operational', function () {
		const t = createTriple({ prefix: 'splice-out' });

		// Full epoch: two settlements while R is offline, then reconcile +
		// convert vouchers to balance.
		goOffline(t);
		pay(t, t.hashes[0], 1_000_000n);
		pay(t, t.hashes[1], 50_000_000n);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(2);
		reconnectSR(t);
		expect(
			t.rChannel.getFforEpoch()!.state,
			t.rErrors.concat(t.sErrors).join('; ')
		).to.equal(FforEpochState.FF_CLOSED);
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok).to.equal(true);
		const revenueMsat = 994_000n + 49_749_000n; // v_1 + v_2
		expect(t.rChannel.getBalances().localMsat).to.equal(revenueMsat);
		const preSpliceFunding = t.rChannel.getFullState().fundingTxid!;

		// R splices out 30,000 sats of revenue to its wallet (keeping enough
		// above channel_reserve for the follow-up payment).
		const withdrawSats = 30_000n;
		const destScript = Buffer.concat([
			Buffer.from([0x00, 0x14]),
			crypto.randomBytes(20)
		]);
		t.rChannel.setSpliceOutDestination(destScript, withdrawSats);
		// BOLT/CLN splice-out rule: the on-chain fee folds into the declared
		// relative_satoshis (destination receives the full withdrawal).
		const spliceFee = 1_000n;
		const res = t.rManager.initiateSplice(
			t.srChannelId,
			-(withdrawSats + spliceFee),
			253
		);
		expect(res.ok, t.rErrors.concat(t.sErrors).join('; ')).to.equal(true);

		// The interactive-tx + commitment_signed + tx_signatures exchange ran
		// synchronously over the loopback; lock the splice on both sides.
		const lockR = t.rManager.sendSpliceLocked(t.srChannelId);
		expect(lockR.ok, t.rErrors.join('; ')).to.equal(true);
		const lockS = t.sManager.sendSpliceLocked(t.srChannelId);
		expect(lockS.ok, t.sErrors.join('; ')).to.equal(true);

		// Both back to NORMAL on a NEW funding outpoint; R's balance dropped by
		// the withdrawal + splice fee (R initiated, R pays the tx fee).
		expect(t.rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(t.sChannel.getState()).to.equal(ChannelState.NORMAL);
		const newFunding = t.rChannel.getFullState().fundingTxid!;
		expect(newFunding.equals(preSpliceFunding)).to.equal(false);
		expect(t.sChannel.getFullState().fundingTxid!.equals(newFunding)).to.equal(
			true
		);
		const postSplice = t.rChannel.getBalances().localMsat;
		expect(postSplice < revenueMsat - withdrawSats * 1000n + 1n).to.equal(true);
		// S's balance is untouched by R's splice-out.
		expect(t.sChannel.getBalances().localMsat).to.equal(
			FUNDING_SATOSHIS * 1000n - revenueMsat
		);

		// The channel is fully operational: a plain R->S payment settles.
		const preimage = crypto.randomBytes(32);
		t.rManager.addHtlc(
			t.srChannelId,
			1_000_000n,
			sha256(preimage),
			900,
			Buffer.alloc(1366)
		);
		t.sManager.fulfillHtlc(
			t.srChannelId,
			t.rChannel.getFullState().localHtlcCounter - 1n,
			preimage
		);
		expect(t.rChannel.getBalances().localMsat).to.equal(
			postSplice - 1_000_000n
		);

		// And a NEW epoch can begin on the spliced channel (§11.3: "the next
		// epoch can begin").
		const again = t.rManager.initiateFforEpoch(t.srChannelId, {
			variant: 1,
			budgetMsat: 10_000_000n,
			maxPayments: 2,
			minPaymentMsat: 600_000n,
			settlementDeadline: 1000,
			voucherExpiry: 2008,
			feeBaseMsat: 1000,
			feeProportionalMillionths: 5000,
			escapeGranularityMsat: 0n
		});
		expect(again.ok, t.rErrors.concat(t.sErrors).join('; ')).to.equal(true);
		expect(t.sChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_EPOCH);
	});

	it('S splices in replenishment after the epoch (relative positive splice)', function () {
		const t = createTriple({ prefix: 'splice-in' });
		goOffline(t);
		pay(t, t.hashes[0], 50_000_000n);
		expect(t.pFulfilled, t.sErrors.join('; ')).to.have.length(1);
		reconnectSR(t);
		expect(t.rChannel.getFforEpoch()!.state).to.equal(FforEpochState.FF_CLOSED);
		expect(t.rManager.fforFulfillVouchers(t.srChannelId).ok).to.equal(true);

		// S replenishes its sell-side inventory: splice-in 200,000 sats from
		// a (synthetic) wallet UTXO.
		const prevTx = (():
			| { prevTx: Buffer; vout: number; valueSats: bigint }
			| never => {
			const bitcoin = require('bitcoinjs-lib');
			const tx = new bitcoin.Transaction();
			tx.addInput(crypto.randomBytes(32), 0);
			tx.addOutput(
				Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)]),
				250_000
			);
			return { prevTx: tx.toBuffer(), vout: 0, valueSats: 250_000n };
		})();
		t.sChannel.setSpliceInInputs(
			[
				{
					prevTx: prevTx.prevTx,
					prevOutputIndex: prevTx.vout,
					sequence: 0xfffffffd,
					value: prevTx.valueSats,
					signWitness: (): Buffer[] => [Buffer.alloc(72), Buffer.alloc(33)]
				}
			],
			Buffer.concat([Buffer.from([0x00, 0x14]), crypto.randomBytes(20)])
		);
		const res = t.sManager.initiateSplice(t.srChannelId, 200_000n, 253);
		expect(res.ok, t.sErrors.concat(t.rErrors).join('; ')).to.equal(true);
		expect(t.sManager.sendSpliceLocked(t.srChannelId).ok).to.equal(true);
		expect(t.rManager.sendSpliceLocked(t.srChannelId).ok).to.equal(true);
		expect(t.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(t.rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(t.sChannel.getFundingSatoshis()).to.equal(
			FUNDING_SATOSHIS + 200_000n
		);
	});
});
