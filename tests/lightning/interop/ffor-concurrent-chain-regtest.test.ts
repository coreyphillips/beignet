import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import {
	CommitmentType,
	OutputType,
	IRREVOCABLE_DEPTH
} from '../../../src/lightning/chain/types';
import { FF_RECONCILE_MARGIN_BLOCKS } from '../../../src/lightning/ffor/types';
import { MessageType } from '../../../src/lightning/message/types';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { exposeAndLeave, pay, record, REGTEST } from '../helpers/ffor-world';
import {
	bitcoindUp,
	regtestWorld,
	forceCloseOnChain,
	resolveHtlcs,
	taps,
	spends,
	submit,
	waitFor,
	paidTo,
	confirmations,
	SWEEP_FEE_RATE
} from './ffor-concurrent-helpers';

describe('Concurrent receive current commitment chain qualification', function () {
	this.timeout(600000);
	before(async () => {
		if (!(await bitcoindUp()))
			throw new Error('Bitcoin Core regtest is required');
	});
	for (const version of [1, 2] as const)
		for (const closer of ['R', 'S'] as const)
			for (const phase of ['before', 'during', 'after'] as const) {
				it(`version ${version}, ${closer} current commitment ${phase} redemption preserves the paid voucher claim`, async () => {
					const storage = new SqliteStorage(':memory:');
					storage.open();
					const rw = await regtestWorld({
						concurrent: true,
						rStorage: storage,
						srPushMsat: 200000000n,
						feeInputs: 8
					});
					const { w, chain, rDest, sDest } = rw;
					try {
						const amount = 100000000n;
						expect(
							w.r.startFforEpoch(w.srHex, {
								voucherAmountsMsat: [amount, amount],
								minPaymentMsat: amount,
								settlementDeadline: chain.height + 200,
								voucherExpiry: chain.height + 200 + FF_RECONCILE_MARGIN_BLOCKS,
								feeBaseMsat: 1000,
								feeProportionalMillionths: 5000,
								concurrent: true,
								concurrentVersion: version
							}).ok
						).to.equal(true);
						for (const [sender, receiver] of [
							[w.s, w.r],
							[w.r, w.s]
						] as const) {
							const ordinary = receiver.createInvoice({
								amountMsat: 1000000n,
								description: 'ordinary online payment'
							});
							expect(sender.sendPayment(ordinary.bolt11).status).to.equal(
								PaymentStatus.COMPLETED
							);
						}
						const held = w.r.createInvoice({
							amountMsat: 50000000n,
							description: 'ordinary payment beside vouchers',
							hold: true
						});
						expect(w.s.sendPayment(held.bolt11).status).to.equal(
							PaymentStatus.PENDING
						);
						const [first, second] = exposeAndLeave(w, [1, 2]);
						const paid = pay(w, first);
						expect(paid.status).to.equal(PaymentStatus.COMPLETED);
						w.sr.reconnect();
						let claimPayment = paid;
						if (phase === 'after') {
							expect(w.r.fforSync(w.srHex).ok).to.equal(true);
							expect(w.r.getPayment(paid.paymentHash)?.status).to.equal(
								PaymentStatus.COMPLETED
							);
							w.sr.disconnect();
							claimPayment = pay(w, second);
							expect(claimPayment.status).to.equal(PaymentStatus.COMPLETED);
							w.sr.reconnect();
						} else if (phase === 'during') {
							// Pause a normal wire stream during redemption. R's cell covers
							// the revoke/next-signature window, while S's pauses the initial
							// fulfillment before it reaches S. Neither channel is rewound.
							let paused = false;
							w.sr.drop = (from, type): boolean => {
								if (
									closer === 'R' &&
									from === w.s.getNodeId() &&
									type === MessageType.COMMITMENT_SIGNED
								)
									paused = true;
								if (
									closer === 'S' &&
									from === w.r.getNodeId() &&
									type === MessageType.UPDATE_FULFILL_HTLC
								)
									paused = true;
								return paused;
							};
							expect(w.r.fforAddPreimage(w.srHex, paid.preimage!).ok).to.equal(
								true
							);
							expect(paused).to.equal(true);
						}
						w.sr.disconnect();
						chain.unwatch(w.s);
						const { commitment, confirmedAt } = await forceCloseOnChain(
							rw,
							closer === 'R' ? w.r : w.s,
							closer === 'R' ? rDest : sDest
						);
						const hash = claimPayment.paymentHash;
						const importProof = (): void => {
							expect(
								w.r.fforAddPreimage(w.srHex, claimPayment.preimage!).ok
							).to.equal(true);
						};
						let claims: bitcoin.Transaction[];
						if (closer === 'R') {
							claims = await resolveHtlcs(
								rw,
								w.r,
								commitment,
								confirmedAt,
								rDest,
								OutputType.RECEIVED_HTLC,
								CommitmentType.OUR_COMMITMENT,
								{
									paymentHashes: [hash.toString('hex')],
									afterObserve: importProof
								}
							);
						} else {
							const seen = taps(w.r);
							w.r
								.getChannelManager()
								.handleFundingSpent(
									w.srChannelId,
									commitment,
									confirmedAt,
									rDest,
									SWEEP_FEE_RATE,
									undefined,
									undefined,
									REGTEST
								);
							const monitor = w.r
								.getChannelManager()
								.getMonitor(w.srChannelId)!;
							expect(
								monitor.getFullState().commitmentBroadcast?.commitmentType
							).to.equal(CommitmentType.THEIR_CURRENT_COMMITMENT);
							const output = monitor
								.getTrackedOutputs()
								.find(
									(entry) =>
										entry.outputType === OutputType.RECEIVED_HTLC &&
										entry.paymentHash?.equals(hash)
								);
							expect(output, 'paid voucher remains on current commitment').to
								.exist;
							importProof();
							await chain.mine(2);
							const claim = await waitFor(
								() =>
									seen.find((tx) =>
										spends(tx, commitment, output!.outputIndex)
									),
								'current commitment voucher claim'
							);
							await submit(claim, 'current voucher claim');
							await chain.mine(1);
							expect(await confirmations(claim.getId())).to.be.at.least(1);
							claims = [claim];
						}
						for (const claim of claims)
							for (const input of claim.ins)
								w.r
									.getChannelManager()
									.handleOutputSpent(
										Buffer.from(input.hash).reverse().toString('hex'),
										input.index,
										claim,
										chain.height
									);
						await chain.mine(IRREVOCABLE_DEPTH);
						expect(w.r.getPayment(hash)?.status).to.equal(
							PaymentStatus.COMPLETED
						);
						const creditedAt = w.r.getPayment(hash)!.completedAt;
						importProof();
						await chain.mine(1);
						expect(w.r.getPayment(hash)!.completedAt).to.equal(creditedAt);
						expect(claims).to.have.length(1);
						const swept = paidTo(claims[0], rDest);
						expect(Number(swept)).to.be.greaterThan(80000);
						const receipt = storage
							.loadAllFforVouchers()
							.find((entry) => entry.paymentHash === hash.toString('hex'))!;
						expect(receipt.creditedReceiptId).to.be.a('string');
						console.log(
							JSON.stringify({
								version,
								closer,
								phase,
								fundingTxid: rw.fundingTx.getId(),
								commitmentTxid: commitment.getId(),
								claimTxid: claims[0].getId(),
								receiverSweepSats: swept.toString(),
								creditedMsat: w.r.getPayment(hash)!.amountMsat.toString()
							})
						);
					} finally {
						w.p.destroy();
						w.s.destroy();
						w.r.destroy();
						storage.close();
					}
				});
			}
	for (const version of [1, 2] as const) {
		it(`version ${version}: unpaid vouchers time out beside an ordinary HTLC and preserve the receiver balance`, async () => {
			const rw = await regtestWorld({
				concurrent: true,
				srPushMsat: 200000000n,
				feeInputs: 8
			});
			const { w, chain, rDest, sDest } = rw;
			try {
				const expiry = chain.height + 20 + FF_RECONCILE_MARGIN_BLOCKS;
				expect(
					w.r.startFforEpoch(w.srHex, {
						voucherAmountsMsat: [100000000n, 100000000n],
						minPaymentMsat: 100000000n,
						settlementDeadline: chain.height + 20,
						voucherExpiry: expiry,
						feeBaseMsat: 1000,
						feeProportionalMillionths: 5000,
						concurrent: true,
						concurrentVersion: version
					}).ok
				).to.equal(true);
				const held = w.s.createInvoice({
					amountMsat: 10000000n,
					hold: true,
					description: 'ordinary payment beside timeout vouchers'
				});
				expect(w.r.sendPayment(held.bolt11).status).to.equal(
					PaymentStatus.PENDING
				);
				exposeAndLeave(w, [1, 2]);
				const hashes = record(w.s, w.srHex).paymentHashes.map((hash) =>
					hash.toString('hex')
				);
				chain.unwatch(w.r);
				chain.unwatch(w.s);
				chain.unwatch(w.p);
				await chain.mine(expiry - chain.height + 1);
				const { commitment, confirmedAt } = await forceCloseOnChain(
					rw,
					w.s,
					sDest
				);
				chain.watch(w.s);
				const claims = await resolveHtlcs(
					rw,
					w.s,
					commitment,
					confirmedAt,
					sDest,
					OutputType.OFFERED_HTLC,
					CommitmentType.OUR_COMMITMENT,
					{ paymentHashes: hashes }
				);
				expect(claims).to.have.length(2);
				const total = claims.reduce((sum, tx) => sum + paidTo(tx, sDest), 0n);
				expect(Number(total)).to.be.greaterThan(160000);
				const seen = taps(w.r);
				w.r
					.getChannelManager()
					.handleFundingSpent(
						w.srChannelId,
						commitment,
						confirmedAt,
						rDest,
						SWEEP_FEE_RATE,
						undefined,
						undefined,
						REGTEST
					);
				chain.watch(w.r);
				await chain.mine(2);
				const output = w.r
					.getChannelManager()
					.getMonitor(w.srChannelId)!
					.getTrackedOutputs()
					.find((entry) => entry.outputType === OutputType.TO_REMOTE)!;
				const balance = await waitFor(
					() => seen.find((tx) => spends(tx, commitment, output.outputIndex)),
					'receiver ordinary balance'
				);
				await submit(balance, 'receiver balance');
				await chain.mine(1);
				expect(Number(paidTo(balance, rDest))).to.be.greaterThan(180000);
				for (const hash of hashes)
					expect(w.r.getPayment(Buffer.from(hash, 'hex'))?.status).to.not.equal(
						PaymentStatus.COMPLETED
					);
				console.log(
					JSON.stringify({
						version,
						phase: 'timeout',
						commitmentTxid: commitment.getId(),
						timeoutSweeps: claims.map((tx) => tx.getId()),
						timeoutSats: total.toString(),
						receiverBalanceSats: paidTo(balance, rDest).toString()
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
