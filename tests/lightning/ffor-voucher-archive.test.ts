import { expect } from 'chai';
import crypto from 'crypto';
import {
	IFforVoucherArchive,
	fforVoucherArchiveId,
	fforVoucherReceiptIds
} from '../../src/lightning/ffor/voucher-archive';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	RecoveryJournal,
	RecoveryManager,
	RecoveryCriticality,
	reconstructFromFrames
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	exposeAndLeave,
	makeNodeConfig,
	pay,
	record,
	TIP
} from './helpers/ffor-world';

const preimage = Buffer.alloc(32, 9);
function voucher(slot = 1): IFforVoucherArchive {
	return {
		channelId: '11'.repeat(32),
		epochId: '22'.repeat(32),
		slot,
		role: 'R',
		paymentHash: crypto.createHash('sha256').update(preimage).digest('hex'),
		amountMsat: '1000000',
		htlcId: String(slot - 1),
		voucherExpiry: 800000,
		concurrentVersion: 2,
		preimage: preimage.toString('hex'),
		outcome: {
			outcome: 'fulfilled',
			localCommitmentNumber: '4',
			remoteCommitmentNumber: '5'
		}
	};
}

describe('FFOR durable voucher archive', function () {
	this.timeout(30_000);
	const stores: SqliteStorage[] = [];
	const nodes: LightningNode[] = [];
	function store(): SqliteStorage {
		const s = new SqliteStorage(':memory:');
		s.open();
		stores.push(s);
		return s;
	}
	afterEach((): void => {
		for (const n of nodes.splice(0)) n.destroy();
		for (const s of stores.splice(0)) s.close();
	});

	it('keeps identity, proof and outcome through repeated partial writes', () => {
		const s = store();
		const row = voucher();
		s.saveFforVoucher(row);
		const { preimage: _proof, outcome: _outcome, ...identity } = row;
		s.saveFforVoucher(identity);
		expect(s.loadFforVoucher(fforVoucherArchiveId(row))).to.deep.equal(row);
		expect(() => s.saveFforVoucher({ ...row, amountMsat: '2000000' })).to.throw(
			'identity changed'
		);
		expect(() =>
			s.saveFforVoucher({
				...row,
				outcome: { ...row.outcome!, outcome: 'cancelled' }
			})
		).to.throw('outcome changed');
		s.deleteChannel(row.channelId);
		expect(s.loadAllFforVouchers()).to.deep.equal([row]);
	});

	for (const paged of [false, true]) {
		it(`restores all voucher custody from ${
			paged ? 'paged' : 'whole'
		} journal snapshots and later deltas`, () => {
			const s = store();
			const key = Buffer.alloc(32, 3);
			const journal = new RecoveryJournal(
				s,
				key,
				getPublicKey(key),
				Buffer.alloc(32, 4),
				{
					snapshotIntervalFrames: 2,
					...(paged ? { maxFrameCiphertextBytes: (): number => 2500 } : {})
				}
			);
			const manager = new RecoveryManager(s, { journal });
			for (let i = 1; i <= 12; i++) {
				const result = manager.commit({
					criticality: RecoveryCriticality.SafetyCritical,
					mutations: [
						{
							type: 'ffor_voucher',
							record: {
								...voucher(i),
								chainObservations: [
									{
										outputTxid: '33'.repeat(32),
										outputIndex: i,
										spendingTxid: '44'.repeat(32),
										preimage: preimage.toString('hex')
									}
								],
								chainResolutions: [
									{
										outputTxid: '33'.repeat(32),
										outputIndex: i,
										spendingTxid: '44'.repeat(32),
										preimage: preimage.toString('hex'),
										confirmationHeight: 100,
										finalizedHeight: 200,
										amountMsat: '1000000'
									}
								],
								creditedReceiptId: fforVoucherReceiptIds(voucher(i))[0]
							}
						}
					],
					outboundMessages: []
				});
				expect(result.committed, result.error?.message).to.be.true;
			}
			const frames = journal.loadVerifiedFrames();
			expect(frames[0].snapshot?.schemaVersion).to.equal(
				paged ? '2+ffor-vouchers+pages' : '2+ffor-vouchers'
			);
			if (paged) expect(frames[0].snapshot?.pageFrames).to.be.greaterThan(0);
			const restored = store();
			reconstructFromFrames(restored, frames);
			expect(restored.loadAllFforVouchers()).to.deep.equal(
				s.loadAllFforVouchers()
			);
		});
	}

	it('rolls back voucher custody with the payment when a safety commit fails', () => {
		const s = store();
		const manager = new RecoveryManager(s);
		const save = s.saveFforVoucher.bind(s);
		s.saveFforVoucher = (row): void => {
			save(row);
			throw new Error('injected custody failure');
		};
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [{ type: 'ffor_voucher', record: voucher() }],
			outboundMessages: []
		});
		expect(result.committed).to.be.false;
		expect(s.loadAllFforVouchers()).to.deep.equal([]);
	});

	it('retains an additional receipt for reconciliation without a second invoice credit', () => {
		const s = store();
		const row = voucher();
		row.creditedReceiptId = fforVoucherReceiptIds(row)[0];
		row.chainResolutions = [
			{
				outputTxid: '33'.repeat(32),
				outputIndex: 0,
				spendingTxid: '44'.repeat(32),
				confirmationHeight: 100,
				finalizedHeight: 200,
				amountMsat: '1000000',
				preimage: preimage.toString('hex')
			}
		];
		s.saveFforVoucher(row);
		s.savePayment(row.paymentHash, {
			paymentHash: Buffer.from(row.paymentHash, 'hex'),
			preimage,
			amountMsat: BigInt(row.amountMsat),
			direction: PaymentDirection.INCOMING,
			status: PaymentStatus.COMPLETED,
			createdAt: 1,
			completedAt: 2,
			metadata: { fforReceiptId: row.creditedReceiptId }
		});
		const receiver = new LightningNode(makeNodeConfig(9801, s));
		nodes.push(receiver);
		let completions = 0;
		receiver.on('payment:received', () => completions++);
		receiver.handleNewBlock(TIP);
		expect(
			receiver.getPayment(Buffer.from(row.paymentHash, 'hex'))?.completedAt
		).to.equal(2);
		expect(completions).to.equal(0);
		const receipt = receiver.getFforVoucherReceipts(row.channelId)[0];
		expect(receipt.creditedReceiptId).to.equal(row.creditedReceiptId);
		expect(receipt.receiptIds).to.have.length(2);
		expect(receipt.uncreditedReceiptIds).to.have.length(1);
		expect(receipt.reconciliationRequired).to.be.true;
	});

	it('reconciles a committed receipt after the original channel row is absent', () => {
		const s = store();
		const w = createConcurrentWorld({ rStorage: s });
		nodes.push(w.p, w.s, w.r);
		activateWorld(w, true, undefined, 2);
		const [invoice] = exposeAndLeave(w, [1]);
		expect(pay(w, invoice).status).to.equal(PaymentStatus.COMPLETED);
		const hash = record(w.r, w.srHex).paymentHashes[0];
		const save = s.savePayment.bind(s);
		s.savePayment = (key, payment): void => {
			if (
				key === hash.toString('hex') &&
				payment.status === PaymentStatus.COMPLETED
			)
				throw new Error('injected payment failure');
			save(key, payment);
		};
		w.sr.reconnect();
		expect(w.r.closeFforEpoch(w.srHex).ok).to.be.true;
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		const archived = s
			.loadAllFforVouchers()
			.find((v) => v.paymentHash === hash.toString('hex'))!;
		expect(archived.outcome?.outcome).to.equal('fulfilled');
		// Restore only the durable payment and archive, without an epoch row.
		const target = store();
		target.saveFforVoucher(archived);
		target.savePayment(
			hash.toString('hex'),
			s.loadPayment(hash.toString('hex'))!
		);
		const receiver = new LightningNode({ ...w.rConfig, storage: target });
		nodes.push(receiver);
		expect(receiver.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		const completedAt = receiver.getPayment(hash)?.completedAt;
		receiver.handleNewBlock(TIP + 1);
		expect(receiver.getPayment(hash)?.completedAt).to.equal(completedAt);
		expect(target.loadAllChannels()).to.have.length(0);
	});
});
