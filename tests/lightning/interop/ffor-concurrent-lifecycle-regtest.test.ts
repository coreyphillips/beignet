import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	FF_RECONCILE_MARGIN_BLOCKS,
	FforState
} from '../../../src/lightning/ffor/types';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { exposeAndLeave, pay, record } from '../helpers/ffor-world';
import { bitcoinRpc } from './shared-helpers';
import { bitcoindUp, regtestWorld } from './ffor-concurrent-helpers';

describe('Concurrent retirement and shared capacity on regtest', function () {
	this.timeout(600000);
	before(async () => {
		if (!(await bitcoindUp())) throw Error('Bitcoin Core regtest is required');
	});
	for (const version of [1, 2] as const)
		for (const paymentFirst of [false, true]) {
			it(`version ${version}, ${
				paymentFirst ? 'payment before close' : 'close before payment'
			} preserves pending ordinary payments`, async () => {
				const rw = await regtestWorld({
					concurrent: true,
					srPushMsat: 200000000n,
					feeInputs: 0,
					rChannel: {
						maxAcceptedHtlcs: 4,
						maxHtlcValueInFlightMsat: 203000000n
					}
				});
				const { w, chain } = rw;
				try {
					expect(
						w.r.startFforEpoch(w.srHex, {
							voucherAmountsMsat: [100000000n, 100000000n],
							minPaymentMsat: 100000000n,
							settlementDeadline: chain.height + 200,
							voucherExpiry: chain.height + 200 + FF_RECONCILE_MARGIN_BLOCKS,
							feeBaseMsat: 1000,
							feeProportionalMillionths: 5000,
							concurrent: true,
							concurrentVersion: version
						}).ok
					).to.be.true;
					const bookHashes = record(w.r, w.srHex).paymentHashes.map((hash) =>
						hash.toString('hex')
					);
					const sChannel = w.s.getChannelManager().getChannel(w.srChannelId)!;
					// The third output fits the count limit, but exceeds the value limit.
					expect(sChannel.canOfferHtlcSet([3000001n])).to.be.false;
					const incoming = [1, 2].map((index) =>
						w.r.createInvoice({
							amountMsat: 1000000n,
							description: `ordinary receive ${index}`,
							hold: true
						})
					);
					for (const invoice of incoming)
						expect(w.s.sendPayment(invoice.bolt11).status).to.equal(
							PaymentStatus.PENDING
						);
					// Another small add fits the value limit, but exceeds the count limit.
					expect(sChannel.canOfferHtlcSet([1000n])).to.be.false;
					const outgoing = w.s.createInvoice({
						amountMsat: 3000000n,
						description: 'ordinary send while retiring',
						hold: true
					});
					expect(w.r.sendPayment(outgoing.bolt11).status).to.equal(
						PaymentStatus.PENDING
					);
					const [offline] = exposeAndLeave(w, [1]);
					if (paymentFirst)
						expect(pay(w, offline).status).to.equal(PaymentStatus.COMPLETED);
					w.sr.reconnect();
					expect(w.r.closeFforEpoch(w.srHex).ok).to.be.true;
					if (!paymentFirst)
						expect(pay(w, offline).status).to.equal(PaymentStatus.FAILED);
					let unresolvedSlots = 0;
					for (const node of [w.s, w.r]) {
						expect(record(node, w.srHex).state).to.equal(
							version === 1 ? FforState.CLOSED : FforState.DRAINING
						);
						const channel = node.getChannelManager().getChannel(w.srChannelId)!;
						const unresolved = [...channel.getFullState().htlcs.values()]
							.map((htlc) => htlc.paymentHash.toString('hex'))
							.filter((hash) => bookHashes.includes(hash));
						expect(unresolved).to.have.members(
							version === 2 ? bookHashes.slice(paymentFirst ? 1 : 0) : []
						);
						expect(channel.getFullState().htlcs.size).to.equal(
							3 + unresolved.length
						);
						unresolvedSlots = unresolved.length;
						const plan = channel.prepareForceClose(channel.getSigner()!, {});
						expect(plan.ok).to.be.true;
						if (!plan.ok) throw Error(plan.error);
						const transaction = bitcoin.Transaction.fromBuffer(
							plan.commitmentTx
						);
						const [result] = (await bitcoinRpc('testmempoolaccept', [
							[transaction.toHex()]
						])) as { allowed: boolean; 'reject-reason'?: string }[];
						expect(result.allowed, result['reject-reason']).to.be.true;
					}
					for (const invoice of incoming)
						expect(w.r.settleHeldHtlc(invoice.paymentHash)).to.be.true;
					expect(w.s.settleHeldHtlc(outgoing.paymentHash)).to.be.true;
					expect(
						w.r.getChannelManager().getChannel(w.srChannelId)!.getFullState()
							.localBalanceMsat
					).to.equal(paymentFirst ? 299000000n : 199000000n);
					console.log(
						JSON.stringify({
							version,
							paymentFirst,
							fundingTxid: rw.fundingTx.getId(),
							receiverBalanceMsat: paymentFirst ? '299000000' : '199000000',
							unresolvedSlots
						})
					);
				} finally {
					w.p.destroy();
					w.s.destroy();
					w.r.destroy();
				}
			});
		}
});
