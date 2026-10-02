import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ChannelState } from '../../../src/lightning/channel/types';
import {
	FF_RECONCILE_MARGIN_BLOCKS,
	FforState
} from '../../../src/lightning/ffor/types';
import { PaymentStatus } from '../../../src/lightning/node/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import {
	FforReceiverProcess,
	IReceiverSnapshot
} from '../helpers/ffor-process';
import { exposeAndLeave, pay, record } from '../helpers/ffor-world';
import { bitcoindUp, regtestWorld } from './ffor-concurrent-helpers';

async function untilReceiver(
	child: FforReceiverProcess,
	channelId: string,
	predicate: (snapshot: IReceiverSnapshot) => boolean
): Promise<IReceiverSnapshot> {
	const end = Date.now() + 30_000;
	for (;;) {
		const snapshot = await child.inspect(channelId);
		if (predicate(snapshot)) return snapshot;
		if (Date.now() > end)
			throw new Error(
				`receiver state did not advance: ${JSON.stringify(
					{ snapshot, errors: child.errors, wire: child.wireTypes.slice(-20) },
					(_key, value) =>
						typeof value === 'bigint' ? value.toString() : value
				)}`
			);
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
}

describe('Concurrent receive Bitcoin Core qualification', function () {
	this.timeout(180_000);
	before(async function () {
		if (!(await bitcoindUp()))
			throw new Error(
				'Bitcoin Core regtest is required for concurrent qualification'
			);
	});

	for (const version of [1, 2] as const) {
		it(`version ${version}: funded receiver resumes after SIGKILL, syncs once and keeps its second invoice payable`, async () => {
			const dir = fs.mkdtempSync(
				path.join(os.tmpdir(), 'ffor-process-regtest-')
			);
			const file = path.join(dir, 'receiver.sqlite');
			const storage = new SqliteStorage(file);
			storage.open();
			const { w, chain, fundingTx } = await regtestWorld({
				concurrent: true,
				rStorage: storage,
				srPushMsat: 200_000_000n
			});
			let child: FforReceiverProcess | undefined;
			try {
				const amount = 100_000_000n;
				const start = w.r.startFforEpoch(w.srHex, {
					voucherAmountsMsat: [amount, amount],
					minPaymentMsat: amount,
					settlementDeadline: chain.height + 60,
					voucherExpiry: chain.height + 60 + FF_RECONCILE_MARGIN_BLOCKS,
					feeBaseMsat: 1000,
					feeProportionalMillionths: 5000,
					concurrent: true,
					concurrentVersion: version
				});
				expect(start.ok, start.error).to.be.true;
				const toReceiver = w.r.createInvoice({
					amountMsat: 2_000_000n,
					description: 'ordinary receive beside reservations'
				});
				w.s.sendPayment(toReceiver.bolt11);
				expect(w.s.getPayment(toReceiver.paymentHash)?.status).to.equal(
					PaymentStatus.COMPLETED
				);
				const toSender = w.s.createInvoice({
					amountMsat: 1_000_000n,
					description: 'ordinary send beside reservations'
				});
				w.r.sendPayment(toSender.bolt11);
				expect(w.r.getPayment(toSender.paymentHash)?.status).to.equal(
					PaymentStatus.COMPLETED
				);
				const before = w.r
					.getChannelManager()
					.getChannel(w.srChannelId)!
					.getFullState().localBalanceMsat;
				const hashes = record(w.r, w.srHex).paymentHashes.map((hash) =>
					hash.toString('hex')
				);
				const [first, second] = exposeAndLeave(w, [1, 2]);
				chain.unwatch(w.r);
				w.r.destroy();
				storage.close();
				child = new FforReceiverProcess(w.s);
				await child.start(w.rConfig, file, chain.height);
				await child.reconnect();
				await untilReceiver(
					child,
					w.srHex,
					(snapshot) => snapshot.state === ChannelState.NORMAL
				);
				expect(await child.kill()).to.equal('SIGKILL');
				expect(pay(w, first).status).to.equal(PaymentStatus.COMPLETED);

				child = new FforReceiverProcess(w.s);
				await child.start(w.rConfig, file, chain.height);
				await child.reconnect();
				await untilReceiver(
					child,
					w.srHex,
					(snapshot) => snapshot.state === ChannelState.NORMAL
				);
				expect((await child.sync(w.srHex)).ok).to.be.true;
				const firstCredit = await untilReceiver(
					child,
					w.srHex,
					(snapshot) => snapshot.payments[0].status === PaymentStatus.COMPLETED
				);
				expect(firstCredit.epochState).to.equal(FforState.ACTIVE);
				expect(firstCredit.vouchers).to.deep.equal([hashes[1]]);
				expect(firstCredit.localBalanceMsat).to.equal(before + amount);
				expect(firstCredit.completions).to.equal(1);
				expect(await child.kill()).to.equal('SIGKILL');

				child = new FforReceiverProcess(w.s);
				await child.start(w.rConfig, file, chain.height);
				await child.reconnect();
				await untilReceiver(
					child,
					w.srHex,
					(snapshot) => snapshot.state === ChannelState.NORMAL
				);
				expect((await child.sync(w.srHex)).ok).to.be.true;
				const again = await untilReceiver(
					child,
					w.srHex,
					(snapshot) => !snapshot.syncPending
				);
				expect(again.payments[0].completedAt).to.equal(
					firstCredit.payments[0].completedAt
				);
				expect(again.localBalanceMsat).to.equal(firstCredit.localBalanceMsat);
				expect(again.completions).to.equal(0);
				expect(await child.kill()).to.equal('SIGKILL');
				expect(pay(w, second).status).to.equal(PaymentStatus.COMPLETED);

				child = new FforReceiverProcess(w.s);
				await child.start(w.rConfig, file, chain.height);
				await child.reconnect();
				await untilReceiver(
					child,
					w.srHex,
					(snapshot) => snapshot.state === ChannelState.NORMAL
				);
				expect((await child.sync(w.srHex)).ok).to.be.true;
				const both = await untilReceiver(
					child,
					w.srHex,
					(snapshot) => snapshot.payments[1].status === PaymentStatus.COMPLETED
				);
				expect(both.localBalanceMsat).to.equal(before + 2n * amount);
				expect(both.vouchers).to.have.length(0);
				expect(both.completions).to.equal(1);
				expect(both.epochState).to.equal(FforState.ACTIVE);
				console.log(
					JSON.stringify({
						version,
						fundingTxid: fundingTx.getId(),
						receiverBalanceMsat: both.localBalanceMsat.toString(),
						ordinaryReceiveMsat: '2000000',
						ordinarySendMsat: '1000000',
						voucherCredits: 2,
						killedProcesses: 3
					})
				);
			} finally {
				await child?.kill();
				w.p.destroy();
				w.s.destroy();
				w.r.destroy();
				storage.close();
				fs.rmSync(dir, { recursive: true, force: true });
			}
		});
	}
});
