import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { HtlcState } from '../../src/lightning/channel/types';
import { FforSlotState, FforState } from '../../src/lightning/ffor/types';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IPaymentInfo, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import { exposeAndLeave, pay, record, TIP } from './helpers/ffor-world';

describe('FFOR concurrent node redemption durability', function () {
	this.timeout(30_000);
	const nodes: LightningNode[] = [];
	const stores: SqliteStorage[] = [];
	const directories: string[] = [];
	function store(file = ':memory:'): SqliteStorage {
		const storage = new SqliteStorage(file);
		storage.open();
		stores.push(storage);
		return storage;
	}
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
		for (const storage of stores.splice(0)) storage.close();
		for (const dir of directories.splice(0))
			fs.rmSync(dir, { recursive: true });
	});

	for (const version of [1, 2] as const) {
		it(`version ${version}: withholds fulfillment until the receipt and upstream state commit together`, () => {
			const storage = store();
			const w = createConcurrentWorld({ sStorage: storage });
			nodes.push(w.p, w.s, w.r);
			activateWorld(w, true, undefined, version);
			const [invoice] = exposeAndLeave(w, [1]);
			const save = storage.saveChannel.bind(storage);
			storage.saveChannel = (id, state, peer): void => {
				if (
					id === w.srHex &&
					state.ffor?.slotStates[0] === FforSlotState.SETTLED
				)
					throw new Error('deferred receipt transaction');
				save(id, state, peer);
			};
			const payment = pay(w, invoice);
			expect(payment.status).not.to.equal(PaymentStatus.COMPLETED);
			expect(storage.loadChannel(w.srHex)!.state.ffor!.slotStates[0]).to.equal(
				FforSlotState.SETTLING
			);
			expect(
				w.ps
					.sentBy(w.s)
					.filter((m) => m.type === MessageType.UPDATE_FULFILL_HTLC)
			).to.have.length(0);
			const upstream = storage.loadChannel(
				w.psChannelId.toString('hex')
			)!.state;
			expect(
				[...upstream.htlcs.values()].filter(
					(entry) => entry.state === HtlcState.FULFILLED
				)
			).to.have.length(0);
			storage.saveChannel = save;
			w.ps.disconnect();
			w.ps.reconnect();
			expect(w.p.getPayment(payment.paymentHash)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(storage.loadChannel(w.srHex)!.state.ffor!.slotStates[0]).to.equal(
				FforSlotState.SETTLED
			);
			w.sr.reconnect();
			expect(w.r.fforSync(w.srHex).ok).to.be.true;
			expect(w.r.getPayment(payment.paymentHash)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
		});

		it(`version ${version}: durably reports a paid slot, credits once and retains the rest after disk restart`, () => {
			const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ffor-live-redeem-'));
			directories.push(dir);
			const sStorage = store();
			const rFile = path.join(dir, 'receiver.sqlite');
			const rStorage = store(rFile);
			const w = createConcurrentWorld({ sStorage, rStorage });
			nodes.push(w.p, w.s, w.r);
			activateWorld(w, true, undefined, version);
			const [first, second] = exposeAndLeave(w, [1, 2]);
			const hash = record(w.r, w.srHex).paymentHashes[0];
			const received: IPaymentInfo[] = [];
			w.r.on('payment:received', (p) => received.push(p));
			let inspected = 0;
			const inspectFulfill = (peer: string, type: number): void => {
				if (
					peer !== w.p.getNodeId() ||
					type !== MessageType.UPDATE_FULFILL_HTLC
				)
					return;
				const book = sStorage.loadChannel(w.srHex)!.state.ffor!;
				expect(book.slotStates[0]).to.equal(FforSlotState.SETTLED);
				const upstream = sStorage.loadChannel(
					w.psChannelId.toString('hex')
				)!.state;
				expect(
					[...upstream.htlcs.values()].some(
						(entry) =>
							entry.paymentHash.equals(hash) &&
							entry.state === HtlcState.FULFILLED
					)
				).to.be.true;
				inspected++;
			};
			w.s.prependListener('message:outbound', inspectFulfill);
			expect(pay(w, first).status).to.equal(PaymentStatus.COMPLETED);
			expect(inspected).to.equal(1);
			w.s.removeListener('message:outbound', inspectFulfill);
			w.sr.reconnect();
			expect(w.r.fforSync(w.srHex).ok).to.be.true;
			expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
			expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
			expect(record(w.r, w.srHex).voucherOutcomes?.slice(1)).to.deep.equal([
				null,
				null
			]);
			expect(received).to.have.length(1);
			const completedAt = w.r.getPayment(hash)!.completedAt;
			w.r.handleNewBlock(TIP + 1);
			expect(w.r.fforSync(w.srHex).ok).to.be.true;
			expect(received).to.have.length(1);
			w.sr.disconnect();
			// The second invoice remains valid while the receiver is offline again.
			expect(pay(w, second).status).to.equal(PaymentStatus.COMPLETED);
			w.r.destroy();
			nodes.splice(nodes.indexOf(w.r), 1);
			rStorage.close();
			stores.splice(stores.indexOf(rStorage), 1);
			const reopened = store(rFile);
			const restored = new LightningNode({ ...w.rConfig, storage: reopened });
			nodes.push(restored);
			const restoredEvents: IPaymentInfo[] = [];
			restored.on('payment:received', (p) => restoredEvents.push(p));
			restored.handleNewBlock(TIP + 2);
			expect(restored.getPayment(hash)?.completedAt).to.equal(completedAt);
			expect(record(restored, w.srHex).state).to.equal(FforState.ACTIVE);
			expect(restoredEvents).to.have.length(0);
			expect(
				restored.getFforVoucherReceipts(w.srHex)[0].receiptIds
			).to.have.length(1);
		});

		it(`version ${version}: retries a deferred invoice write while the book is active`, () => {
			const storage = store();
			const w = createConcurrentWorld({ rStorage: storage });
			nodes.push(w.p, w.s, w.r);
			activateWorld(w, true, undefined, version);
			const [invoice] = exposeAndLeave(w, [1]);
			expect(pay(w, invoice).status).to.equal(PaymentStatus.COMPLETED);
			const hash = record(w.r, w.srHex).paymentHashes[0];
			const save = storage.savePayment.bind(storage);
			storage.savePayment = (key, payment): void => {
				if (payment.status === PaymentStatus.COMPLETED)
					throw new Error('deferred completion write');
				save(key, payment);
			};
			w.sr.reconnect();
			expect(w.r.fforSync(w.srHex).ok).to.be.true;
			expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
			expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
			storage.savePayment = save;
			const received: IPaymentInfo[] = [];
			w.r.on('payment:received', (p) => received.push(p));
			w.r.handleNewBlock(TIP + 1);
			w.r.handleNewBlock(TIP + 2);
			expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
			expect(received).to.have.length(1);
		});
	}
});
