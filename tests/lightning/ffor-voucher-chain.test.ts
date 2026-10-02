import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { PaymentStatus } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IRREVOCABLE_DEPTH, OutputType } from '../../src/lightning/chain/types';
import { fforVoucherReceiptIds } from '../../src/lightning/ffor/voucher-archive';
import {
	activateWorld,
	createConcurrentWorld
} from './helpers/ffor-concurrent-world';
import {
	exposeAndLeave,
	forceCloseAndObserve,
	pay,
	record,
	TIP
} from './helpers/ffor-world';

describe('FFOR version 2 durable chain receipts', function () {
	this.timeout(30_000);
	const stores: SqliteStorage[] = [];
	const nodes: LightningNode[] = [];
	function store(): SqliteStorage {
		const s = new SqliteStorage(':memory:');
		s.open();
		stores.push(s);
		return s;
	}
	afterEach(() => {
		for (const n of nodes.splice(0)) n.destroy();
		for (const s of stores.splice(0)) s.close();
	});
	function setup(
		ownCommitment: boolean,
		amounts?: bigint[],
		version: 1 | 2 = 2
	) {
		const storage = store();
		const w = createConcurrentWorld({ rStorage: storage });
		nodes.push(w.p, w.s, w.r);
		activateWorld(w, true, amounts, version);
		const [invoice] = exposeAndLeave(w, [1]);
		const paid = pay(w, invoice);
		expect(paid.status).to.equal(PaymentStatus.COMPLETED);
		const hash = record(w.r, w.srHex).paymentHashes[0];
		expect(w.r.fforAddPreimage(w.srHex, paid.preimage!).ok).to.be.true;
		const closer = ownCommitment ? w.r : w.s;
		const key = ownCommitment
			? w.rConfig.fundingPrivkey!
			: w.sConfig.fundingPrivkey!;
		const view = forceCloseAndObserve(
			w,
			closer,
			key,
			w.r,
			w.rConfig.fundingPrivkey!
		);
		const output = view.outputs.find(
			(o) =>
				o.outputType === OutputType.RECEIVED_HTLC && o.paymentHash?.equals(hash)
		)!;
		expect(output.sweepTxHex).to.be.a('string');
		const claim = bitcoin.Transaction.fromHex(output.sweepTxHex!);
		const report = (receiver = w.r, height = TIP + 3): void => {
			receiver
				.getChannelManager()
				.handleOutputSpent(view.tx.getId(), output.outputIndex, claim, height);
		};
		const archived = () =>
			storage
				.loadAllFforVouchers()
				.find((r) => r.paymentHash === hash.toString('hex'))!;
		return { w, storage, hash, output, claim, report, archived };
	}

	it('credits a direct success once after finality, then survives loss of the live channel', () => {
		const { w, storage, hash, claim, report, archived } = setup(false);
		let completions = 0;
		w.r.on('payment:received', () => completions++);
		report();
		expect(archived().chainObservations).to.have.length(1);
		expect(archived().chainResolutions).to.equal(undefined);
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		w.r.handleNewBlock(TIP + 3 + IRREVOCABLE_DEPTH);
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(w.r.getPayment(hash)?.metadata?.claimTxid).to.equal(claim.getId());
		expect(archived().creditedReceiptId).to.equal(
			fforVoucherReceiptIds(archived())[0]
		);
		expect(completions).to.equal(1);
		w.r.handleNewBlock(TIP + 4 + IRREVOCABLE_DEPTH);
		expect(completions).to.equal(1);
		const target = store();
		target.saveFforVoucher(archived());
		target.savePayment(
			hash.toString('hex'),
			storage.loadPayment(hash.toString('hex'))!
		);
		const restored = new LightningNode({ ...w.rConfig, storage: target });
		nodes.push(restored);
		expect(restored.getPayment(hash)?.completedAt).to.equal(
			w.r.getPayment(hash)?.completedAt
		);
		expect(target.loadAllChannels()).to.have.length(0);
	});

	it('waits for our success transaction and its delayed output sweep to become final', () => {
		const { w, hash, claim, report, archived } = setup(true);
		report();
		const manager = w.r.getChannelManager();
		const descendant = manager
			.getMonitor(w.srChannelId)!
			.getTrackedOutputs()
			.find((o) => o.txid === claim.getId() && o.isSecondLevelHtlc)!;
		expect(descendant).to.exist;
		w.r.handleNewBlock(TIP + 3 + IRREVOCABLE_DEPTH);
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		expect(archived().chainResolutions).to.equal(undefined);
		const sweep = bitcoin.Transaction.fromHex(descendant.sweepTxHex!);
		const sweepHeight = TIP + 4 + IRREVOCABLE_DEPTH;
		manager.handleOutputSpent(
			claim.getId(),
			descendant.outputIndex,
			sweep,
			sweepHeight
		);
		w.r.handleNewBlock(sweepHeight + IRREVOCABLE_DEPTH);
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(archived().chainResolutions?.[0].secondLevel?.spendingTxid).to.equal(
			sweep.getId()
		);
		expect(fforVoucherReceiptIds(archived())).to.have.length(1);
	});

	it('credits the archived whole-satoshi chain value for a fractional voucher amount', () => {
		const { w, hash, report, archived } = setup(false, [1_000_999n]);
		report();
		w.r.handleNewBlock(TIP + 3 + IRREVOCABLE_DEPTH);
		expect(archived().amountMsat).to.equal('1000999');
		expect(archived().chainResolutions?.[0].amountMsat).to.equal('1000000');
		expect(w.r.getPayment(hash)?.amountMsat).to.equal(1_000_000n);
	});

	it('attributes an existing version 1 confirmed credit when that same claim becomes final', () => {
		const { w, hash, report, archived } = setup(false, undefined, 1);
		let completions = 0;
		w.r.on('payment:received', () => completions++);
		report();
		const completedAt = w.r.getPayment(hash)?.completedAt;
		expect(completions).to.equal(1);
		expect(archived().creditedReceiptId).to.equal(undefined);
		w.r.handleNewBlock(TIP + 3 + IRREVOCABLE_DEPTH);
		expect(archived().creditedReceiptId).to.equal(
			fforVoucherReceiptIds(archived())[0]
		);
		expect(w.r.getPayment(hash)?.completedAt).to.equal(completedAt);
		expect(completions).to.equal(1);
		expect(w.r.getFforVoucherReceipts(w.srHex)[0].reconciliationRequired).to.be
			.false;
	});

	it('retains observations through an ordinary spend reorg and requires fresh evidence after restart', () => {
		const { w, storage, hash, output, report, archived } = setup(false);
		report();
		w.r
			.getChannelManager()
			.handleOutputUnspent(output.txid, output.outputIndex);
		w.r.handleNewBlock(TIP + 3 + IRREVOCABLE_DEPTH);
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		expect(archived().chainObservations).to.have.length(1);
		expect(archived().chainResolutions).to.equal(undefined);
		const restored = new LightningNode({ ...w.rConfig, storage });
		nodes.push(restored);
		restored.handleNewBlock(TIP + 4 + IRREVOCABLE_DEPTH);
		expect(restored.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		const height = TIP + 5 + IRREVOCABLE_DEPTH;
		report(restored, height);
		restored.handleNewBlock(height + IRREVOCABLE_DEPTH);
		expect(restored.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
	});

	it('retries a failed final archive transaction without another spend report', () => {
		const { w, storage, hash, report, archived } = setup(false, [1_000_000n]);
		report();
		const manager = w.r.getChannelManager();
		// Resolve the ordinary to_remote balance as well, so the monitor
		// stops receiving normal block callbacks at the failure boundary.
		for (const output of manager
			.getMonitor(w.srChannelId)!
			.getTrackedOutputs()) {
			if (output.outputType === OutputType.TO_REMOTE && output.sweepTxHex) {
				manager.handleOutputSpent(
					output.txid,
					output.outputIndex,
					bitcoin.Transaction.fromHex(output.sweepTxHex),
					TIP + 3
				);
			}
		}
		const save = storage.saveFforVoucher.bind(storage);
		storage.saveFforVoucher = (r): void => {
			if (r.chainResolutions?.length)
				throw new Error('injected final custody failure');
			save(r);
		};
		w.r.handleNewBlock(TIP + 3 + IRREVOCABLE_DEPTH);
		expect(manager.getMonitor(w.srChannelId)!.isFullyResolved()).to.be.true;
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		expect(archived().chainResolutions).to.equal(undefined);
		storage.saveFforVoucher = save;
		w.r.handleNewBlock(TIP + 4 + IRREVOCABLE_DEPTH);
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(archived().chainResolutions).to.have.length(1);
	});

	it('retries a payment write from final custody after channel and monitor pruning', () => {
		const { w, storage, hash, report, archived } = setup(false);
		report();
		const save = storage.savePayment.bind(storage);
		storage.savePayment = (key, payment): void => {
			if (
				key === hash.toString('hex') &&
				payment.status === PaymentStatus.COMPLETED
			)
				throw new Error('injected receipt credit failure');
			save(key, payment);
		};
		w.r.handleNewBlock(TIP + 3 + IRREVOCABLE_DEPTH);
		expect(archived().chainResolutions).to.have.length(1);
		expect(archived().creditedReceiptId).to.equal(undefined);
		expect(w.r.getPayment(hash)?.status).to.equal(PaymentStatus.PENDING);
		const target = store();
		target.saveFforVoucher(archived());
		target.savePayment(
			hash.toString('hex'),
			storage.loadPayment(hash.toString('hex'))!
		);
		const receiver = new LightningNode({ ...w.rConfig, storage: target });
		nodes.push(receiver);
		expect(receiver.getPayment(hash)?.status).to.equal(PaymentStatus.COMPLETED);
		expect(target.loadAllChannels()).to.have.length(0);
		expect(target.loadAllChainMonitors()).to.have.length(0);
		expect(target.loadAllFforVouchers()[0].creditedReceiptId).to.be.a('string');
	});
});
