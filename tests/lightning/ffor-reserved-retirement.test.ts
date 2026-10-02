import { expect } from 'chai';
import { FforState } from '../../src/lightning/ffor/types';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IPaymentInfo, PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	deserializeFforEpoch,
	serializeFforEpoch
} from '../../src/lightning/storage/serialization';
import {
	activate,
	AMOUNTS,
	balances,
	createPair,
	expectHealthy,
	expectVouchersCarried,
	pay,
	record,
	restart,
	vouchers
} from './helpers/ffor-concurrent-pair';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	exposeAndLeave,
	pay as payInvoice,
	record as nodeRecord,
	TIP
} from './helpers/ffor-world';

describe('FFOR version 2 reserved retirement', function () {
	this.timeout(30_000);
	const nodes: LightningNode[] = [];
	const stores: SqliteStorage[] = [];
	afterEach((): void => {
		for (const node of nodes.splice(0)) node.destroy();
		for (const store of stores.splice(0)) store.close();
	});

	for (const funder of ['S', 'R'] as const) {
		it(`retains unknown slots beside ordinary payments with ${funder} funding`, () => {
			const pair = createPair({ funder, pushSat: 200_000n });
			activate(pair, AMOUNTS, true, 2);
			const before = balances(pair);
			expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
			expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
			expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
			expect(balances(pair)).to.deep.equal(before);
			expectVouchersCarried(pair, [1, 2, 3]);
			pay(pair, 'R', 3_000_000n);
			pay(pair, 'S', 2_000_000n);
			expect(balances(pair).r).to.equal(before.r - 1_000_000n);
			expectVouchersCarried(pair, [1, 2, 3]);
			for (const side of ['R', 'S'] as const) {
				restart(pair, side);
				pair.link.reconnect();
			}
			pay(pair, 'R', 2_000_000n);
			expectVouchersCarried(pair, [1, 2, 3]);
			expect(record(pair.rChannel).concurrentVersion).to.equal(2);
			expect(pair.rChannel.fforAdmissionHold()).to.equal(null);
			expectHealthy(pair);
		});
	}

	it('stops new invoice exposure before the close acknowledgement arrives', () => {
		const pair = createPair();
		activate(pair, AMOUNTS, true, 2);
		expect(pair.rChannel.fforExposureRefusal(1)).to.equal(null);
		pair.link.holdAt = (from, type): boolean =>
			from === 'S' && type === MessageType.FF_CLOSE_ACK;
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		expect(pair.rChannel.fforExposureRefusal(1)).to.equal(
			'invoice admission has stopped'
		);
		const stored = serializeFforEpoch(record(pair.rChannel));
		expect(deserializeFforEpoch(stored).closeSent).to.be.true;
		pair.link.holdAt = null;
		pair.link.release('S');
		expect(pair.rChannel.fforExposureRefusal(2)).to.equal(
			'invoice admission has stopped'
		);
		expect(pair.sChannel.fforSettlementRefusal(1, TIP)).to.equal(
			'epoch is DRAINING'
		);
	});

	it('fulfills a later verified claim without releasing the other reservations', () => {
		const pair = createPair({ pushSat: 200_000n });
		activate(pair, AMOUNTS, true, 2);
		const preimages = record(pair.sChannel).preimages.map((p) =>
			Buffer.from(p)
		);
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
		const before = balances(pair);
		const originalAck = Buffer.from(record(pair.rChannel).closeAckWire!);
		expect(pair.rManager.fforAddPreimage(pair.channelId, preimages[0]).ok).to.be
			.true;
		expect(balances(pair).r).to.equal(before.r + AMOUNTS[0]);
		for (const ch of [pair.rChannel, pair.sChannel]) {
			expect(record(ch).state).to.equal(FforState.DRAINING);
			expect(record(ch).voucherOutcomes?.[0]?.outcome).to.equal('fulfilled');
			expect(vouchers(ch)).to.have.length(2);
		}
		expect(record(pair.rChannel).closeAckWire?.equals(originalAck)).to.be.true;
		expectVouchersCarried(pair, [2, 3]);
		for (const preimage of preimages.slice(1)) {
			expect(pair.rManager.fforAddPreimage(pair.channelId, preimage).ok).to.be
				.true;
		}
		expect(record(pair.rChannel).state).to.equal(FforState.CLOSED);
		expect(record(pair.sChannel).state).to.equal(FforState.CLOSED);
		expect(balances(pair).r).to.equal(
			before.r + AMOUNTS.reduce((a, b) => a + b, 0n)
		);
		expectHealthy(pair);
	});

	for (const restartReceiver of [false, true]) {
		it(`credits a fulfilled slot once while unknown slots remain reserved${
			restartReceiver ? ' across restart' : ''
		}`, () => {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			stores.push(storage);
			const w = createConcurrentWorld({ rStorage: storage });
			nodes.push(w.p, w.s, w.r);
			activateWorld(w, true, undefined, 2);
			const [invoice] = exposeAndLeave(w, [1]);
			expect(payInvoice(w, invoice).status).to.equal(PaymentStatus.COMPLETED);
			const hash = nodeRecord(w.r, w.srHex).paymentHashes[0];
			const save = storage.savePayment.bind(storage);
			let fail = restartReceiver;
			storage.savePayment = (key, payment): void => {
				if (
					fail &&
					key === hash.toString('hex') &&
					payment.status === PaymentStatus.COMPLETED
				) {
					throw new Error('injected payment write failure');
				}
				save(key, payment);
			};
			const received: IPaymentInfo[] = [];
			w.r.on('payment:received', (p) => received.push(p));
			w.sr.reconnect();
			expect(w.r.closeFforEpoch(w.srHex).ok).to.be.true;
			expect(nodeRecord(w.r, w.srHex).state).to.equal(FforState.DRAINING);
			if (restartReceiver) {
				expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
				expect(received).to.have.length(0);
			}
			fail = false;
			const receiver = restartReceiver ? new LightningNode(w.rConfig) : w.r;
			if (restartReceiver) nodes.push(receiver);
			expect(receiver.getPayment(hash)?.status).to.equal(
				PaymentStatus.COMPLETED
			);
			const completedAt = receiver.getPayment(hash)?.completedAt;
			receiver.handleNewBlock(TIP + 1);
			receiver.handleNewBlock(TIP + 2);
			expect(receiver.getPayment(hash)?.completedAt).to.equal(completedAt);
			expect(nodeRecord(receiver, w.srHex).state).to.equal(FforState.DRAINING);
			expect(
				nodeRecord(receiver, w.srHex).voucherOutcomes?.slice(1)
			).to.deep.equal([null, null]);
			expect(received).to.have.length(restartReceiver ? 0 : 1);
		});
	}
});
