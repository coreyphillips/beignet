import { expect } from 'chai';
import { FforVoucherIndex } from '../../src/lightning/ffor/voucher-index';
import { IFforVoucherArchive } from '../../src/lightning/ffor/voucher-archive';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import { exposeAndLeave, pay, record } from './helpers/ffor-world';
import { PaymentStatus } from '../../src/lightning/node/types';

describe('FFOR permanent voucher identities', function () {
	this.timeout(30_000);
	const nodes: LightningNode[] = [];
	const stores: SqliteStorage[] = [];
	function storage(): SqliteStorage {
		const s = new SqliteStorage(':memory:');
		s.open();
		stores.push(s);
		return s;
	}
	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
		for (const s of stores.splice(0)) s.close();
	});

	function identity(): IFforVoucherArchive {
		return {
			channelId: '11'.repeat(32),
			epochId: '22'.repeat(32),
			slot: 1,
			role: 'S',
			paymentHash: '33'.repeat(32),
			htlcId: '0',
			amountMsat: '1000000',
			voucherExpiry: 800000,
			concurrentVersion: 2
		};
	}

	it('reserves the hash and directional HTLC identity after archive reload', () => {
		const s = storage();
		const row = identity();
		s.saveFforVoucher(row);
		s.deleteChannel(row.channelId);
		const index = new FforVoucherIndex();
		for (const retained of s.loadAllFforVouchers()) index.remember(retained);
		expect(index.get(row.paymentHash)).to.deep.equal(row);
		expect(() => index.assertAvailable(row)).not.to.throw();
		expect(() =>
			index.assertAvailable({ ...row, epochId: '44'.repeat(32), htlcId: '1' })
		).to.throw('payment hash was already adopted');
		expect(() =>
			index.assertAvailable({
				...row,
				epochId: '44'.repeat(32),
				paymentHash: '55'.repeat(32)
			})
		).to.throw('HTLC id was already adopted');
		expect(index.get('66'.repeat(32))).to.equal(undefined);
	});

	it('keeps baseline delegated settlement available on a legacy storage adapter', () => {
		const s = storage();
		for (const method of [
			'saveFforVoucher',
			'loadFforVoucher',
			'loadAllFforVouchers'
		])
			Object.defineProperty(s, method, { value: undefined });
		const w = createConcurrentWorld({ sStorage: s, concurrent: false });
		nodes.push(w.p, w.s, w.r);
		activateWorld(w, false);
		const [invoice] = exposeAndLeave(w, [1]);
		expect(pay(w, invoice).status).to.equal(PaymentStatus.COMPLETED);
	});

	it('backfills retained legacy books before exposing restored channels', () => {
		const s = storage();
		const w = createConcurrentWorld({ sStorage: s });
		nodes.push(w.p, w.s, w.r);
		activateWorld(w, true, undefined, 1);
		const hash = record(w.s, w.srHex).paymentHashes[0];
		// A pre-archive database retained its book only in the channel row.
		(s as unknown as { db: { exec(sql: string): void } }).db.exec(
			'DELETE FROM ffor_vouchers'
		);
		const restored = new LightningNode(w.sConfig);
		nodes.push(restored);
		expect(s.loadAllFforVouchers()).to.have.length(3);
		expect(
			restored.getChannelManager().fforFindDelegatedSlot(hash)?.entry.k
		).to.equal(1);
		s.deleteChannel(w.srHex);
		const pruned = new LightningNode(w.sConfig);
		nodes.push(pruned);
		expect(pruned.getChannelManager().fforFindDelegatedSlot(hash)).to.equal(
			null
		);
		expect(
			s
				.loadAllFforVouchers()
				.some((entry) => entry.paymentHash === hash.toString('hex'))
		).to.be.true;
	});

	it('stops startup when retained identity backfill cannot commit', () => {
		const s = storage();
		const w = createConcurrentWorld({ sStorage: s });
		nodes.push(w.p, w.s, w.r);
		activateWorld(w, true, undefined, 2);
		(s as unknown as { db: { exec(sql: string): void } }).db.exec(
			'DELETE FROM ffor_vouchers'
		);
		const save = s.saveFforVoucher.bind(s);
		s.saveFforVoucher = (): void => {
			throw new Error('identity store unavailable');
		};
		expect(() => new LightningNode(w.sConfig)).to.throw(
			'Could not restore durable voucher identities'
		);
		expect(s.loadAllFforVouchers()).to.have.length(0);
		s.saveFforVoucher = save;
		const restored = new LightningNode(w.sConfig);
		nodes.push(restored);
		expect(s.loadAllFforVouchers()).to.have.length(3);
	});
});
