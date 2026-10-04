import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	serializePaymentInfo,
	deserializePaymentInfo
} from '../../src/lightning/storage/serialization';
import { createFailureMessage } from '../../src/lightning/onion/failures';
import { TEMPORARY_NODE_FAILURE } from '../../src/lightning/onion/types';
import {
	createNode,
	connectNodes,
	openReadyChannel
} from './helpers/loopback-nodes';

type Payee = {
	handleFinalHopHtlc: (...args: unknown[]) => void;
	receivedHtlcSharedSecrets: Map<string, Buffer>;
};

async function reconnect(a: LightningNode, b: LightningNode): Promise<void> {
	const queue: Array<() => void> = [];
	let hold = true;
	for (const [from, to] of [
		[a, b],
		[b, a]
	]) {
		from.on('message:outbound', (pk: string, type: number, payload: Buffer) => {
			if (pk !== to.getNodeId()) return;
			const deliver = (): void =>
				to.handlePeerMessage(from.getNodeId(), type, payload);
			if (hold) queue.push(deliver);
			else deliver();
		});
	}
	a.getChannelManager().handlePeerReconnected(b.getNodeId());
	b.getChannelManager().handlePeerReconnected(a.getNodeId());
	while (queue.length) queue.shift()!();
	hold = false;
	for (let i = 0; i < 4; i++)
		await new Promise<void>((resolve) => setImmediate(resolve));
}

describe('Single-part pay-all lifecycle', function () {
	this.timeout(20_000);
	let alice: LightningNode;
	let bob: LightningNode;
	let storage: SqliteStorage;
	let dir: string;
	let db: string;
	let channelId: Buffer;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-pay-all-'));
		db = path.join(dir, 'alice.db');
		storage = new SqliteStorage(db);
		storage.open();
		alice = createNode('pay-all', 1, storage, { preferAnchors: true });
		bob = createNode('pay-all', 2, undefined, { preferAnchors: true });
		alice.on('node:error', () => {});
		bob.on('node:error', () => {});
		connectNodes(alice, bob);
		channelId = openReadyChannel(alice, bob);
	});
	afterEach(() => {
		alice.destroy();
		bob.destroy();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('quotes without a record or HTLC and persists exact figures before synchronous settlement', () => {
		const invoice = bob.createInvoice({ description: 'pay all' });
		const quote = alice.quotePayAll(invoice.bolt11, 0n);
		expect(quote.routeFound).to.equal(true);
		expect(alice.getPayment(invoice.paymentHash)).to.equal(undefined);
		expect(storage.loadPayment(invoice.paymentHash.toString('hex'))).to.equal(
			null
		);
		expect(alice.hasHtlcInFlight(invoice.paymentHash)).to.equal(false);
		let beforeDispatch: IPaymentInfo | null = null;
		alice.prependListener('message:outbound', (_pk: string, type: number) => {
			if (type === 128)
				beforeDispatch = storage.loadPayment(
					invoice.paymentHash.toString('hex')
				);
		});
		alice.sendPayAll(invoice.bolt11, quote.debitMsat, quote.maxFeeMsat);
		const payment = alice.getPayment(invoice.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(payment.amountMsat).to.equal(quote.debitMsat);
		expect(payment.payAll).to.deep.equal({
			debitMsat: quote.debitMsat,
			maxFeeMsat: 0n,
			deliveredMsat: quote.debitMsat,
			feeMsat: 0n,
			remainderMsat: 0n
		});
		expect((beforeDispatch as IPaymentInfo | null)?.payAll).to.deep.equal(
			payment.payAll
		);
		expect(
			storage.loadPayment(invoice.paymentHash.toString('hex'))!.payAll
		).to.deep.equal(payment.payAll);
		expect(
			alice
				.getChannelManager()
				.getChannel(channelId)!
				.getSpendableOutboundMsat()
		).to.equal(0n);
	});

	it('refuses dispatch when the frozen budget cannot be persisted', () => {
		const invoice = bob.createInvoice({ description: 'persistence refusal' });
		const quote = alice.quotePayAll(invoice.bolt11, 0n);
		const save = storage.savePayment.bind(storage);
		let failOnce = true;
		storage.savePayment = (hash, payment) => {
			if (payment.payAll && failOnce) {
				failOnce = false;
				throw new Error('test write failure');
			}
			return save(hash, payment);
		};
		let adds = 0;
		alice.on('message:outbound', (_pk: string, type: number) => {
			if (type === 128) adds++;
		});
		expect(() =>
			alice.sendPayAll(invoice.bolt11, quote.debitMsat, 0n)
		).to.throw('Could not persist pay-all budget');
		expect(adds).to.equal(0);
		expect(alice.hasHtlcInFlight(invoice.paymentHash)).to.equal(false);
		expect(alice.getPayment(invoice.paymentHash)).to.equal(undefined);
		expect(storage.loadPayment(invoice.paymentHash.toString('hex'))).to.equal(
			null
		);
		alice.sendPayAll(invoice.bolt11, quote.debitMsat, 0n);
		expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
	});

	it('keeps funds received after review outside the frozen debit', () => {
		const seed = bob.createInvoice({
			amountMsat: 100_000_001n,
			description: 'seed inbound'
		});
		alice.sendPayment(seed.bolt11);
		const invoice = bob.createInvoice({ description: 'review before receipt' });
		const quote = alice.quotePayAll(invoice.bolt11, 0n);
		expect(quote.debitMsat % 1000n).to.equal(999n);
		const receipt = alice.createInvoice({
			amountMsat: 50_000_001n,
			description: 'arrives during review'
		});
		bob.sendPayment(receipt.bolt11);
		alice.sendPayAll(invoice.bolt11, quote.debitMsat, 0n);
		expect(alice.getPayment(invoice.paymentHash)!.payAll!.debitMsat).to.equal(
			quote.debitMsat
		);
		expect(
			alice
				.getChannelManager()
				.getChannel(channelId)!
				.getSpendableOutboundMsat()
		).to.equal(50_000_001n);
	});

	it('expires a budget that is no longer spendable before creating an attempt', () => {
		const invoice = bob.createInvoice({ description: 'review before spend' });
		const quote = alice.quotePayAll(invoice.bolt11, 0n);
		alice.sendPayment(
			bob.createInvoice({ amountMsat: 1000n, description: 'another send' })
				.bolt11
		);
		expect(() =>
			alice.sendPayAll(invoice.bolt11, quote.debitMsat, 0n)
		).to.throw('no longer spendable');
		expect(alice.getPayment(invoice.paymentHash)).to.equal(undefined);
	});

	it('uses full admission in a quote without changing channel state', () => {
		const channel = alice.getChannelManager().getChannel(channelId)!;
		const invoice = bob.createInvoice({ description: 'admission' });
		channel.getFullState().remoteConfig.maxAcceptedHtlcs = 0;
		expect(alice.quotePayAll(invoice.bolt11, 0n).routeFound).to.equal(false);
		expect(channel.getFullState().localHtlcCounter).to.equal(0n);
		expect(channel.getFullState().htlcs.size).to.equal(0);
	});

	it('refuses fixed-amount invoices and invalid budgets', () => {
		const fixed = bob.createInvoice({
			amountMsat: 1000n,
			description: 'fixed'
		});
		expect(() => alice.quotePayAll(fixed.bolt11, 0n)).to.throw('amountless');
		const open = bob.createInvoice({ description: 'open' });
		for (const [debit, fee] of [
			[0n, 0n],
			[1000n, -1n],
			[1000n, 1000n]
		]) {
			expect(() => alice.sendPayAll(open.bolt11, debit, fee)).to.throw(
				'positive u64'
			);
		}
	});

	it('retries only after removal and retains its original budget', () => {
		const payee = bob as unknown as Payee;
		const original = payee.handleFinalHopHtlc.bind(bob);
		let attempts = 0;
		payee.handleFinalHopHtlc = (...args: unknown[]): void => {
			attempts++;
			if (attempts > 1) return original(...args);
			const [id, htlc] = args as [Buffer, bigint];
			const secret = payee.receivedHtlcSharedSecrets.get(
				`${id.toString('hex')}:${htlc}`
			)!;
			bob
				.getChannelManager()
				.failHtlc(
					id,
					htlc,
					createFailureMessage(secret, TEMPORARY_NODE_FAILURE)
				);
		};
		const invoice = bob.createInvoice({ description: 'retry' });
		const quote = alice.quotePayAll(invoice.bolt11, 0n);
		alice.sendPayAll(invoice.bolt11, quote.debitMsat, 0n);
		expect(attempts).to.equal(2);
		expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(alice.getPayment(invoice.paymentHash)!.payAll!.debitMsat).to.equal(
			quote.debitMsat
		);
	});

	for (const outcome of ['fulfill', 'fail'] as const) {
		it(`does not retry a timed-out unresolved attempt across restart before a late ${outcome}`, async () => {
			const invoice = bob.createInvoice({
				description: 'held across restart',
				hold: true
			});
			const quote = alice.quotePayAll(invoice.bolt11, 0n);
			alice.sendPayAll(invoice.bolt11, quote.debitMsat, 0n);
			expect(
				alice.failPaymentUnlessInFlight(invoice.paymentHash, 'local timeout')
			).to.equal(false);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				PaymentStatus.PENDING
			);
			alice.removeAllListeners('message:outbound');
			bob.removeAllListeners('message:outbound');
			bob.getChannelManager().handlePeerDisconnected(alice.getNodeId());
			alice.destroy();
			storage = new SqliteStorage(db);
			storage.open();
			alice = createNode('pay-all', 1, storage, { preferAnchors: true });
			let adds = 0;
			alice.on('message:outbound', (_pk: string, type: number) => {
				if (type === 128) adds++;
			});
			expect(alice.getPayment(invoice.paymentHash)!.payAll!.debitMsat).to.equal(
				quote.debitMsat
			);
			expect(() =>
				alice.sendPayAll(invoice.bolt11, quote.debitMsat, 0n)
			).to.throw('already in flight');
			await reconnect(alice, bob);
			expect(adds).to.equal(0);
			if (outcome === 'fulfill') bob.settleHeldHtlc(invoice.paymentHash);
			else bob.cancelHoldInvoice(invoice.paymentHash);
			expect(alice.getPayment(invoice.paymentHash)!.status).to.equal(
				outcome === 'fulfill' ? PaymentStatus.COMPLETED : PaymentStatus.FAILED
			);
			expect(adds).to.equal(0);
		});
	}

	it('preserves a pruned failed attempt budget in storage and refuses ordinary retries', () => {
		const invoice = bob.createInvoice({ description: 'persisted failed' });
		storage.savePayment(invoice.paymentHash.toString('hex'), {
			paymentHash: invoice.paymentHash,
			amountMsat: 1000n,
			status: PaymentStatus.FAILED,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now(),
			payAll: {
				debitMsat: 1000n,
				maxFeeMsat: 0n,
				deliveredMsat: 1000n,
				feeMsat: 0n,
				remainderMsat: 0n
			}
		});
		expect(() => alice.sendPayAll(invoice.bolt11, 2000n, 0n)).to.throw(
			'persisted pay-all'
		);
		expect(() =>
			alice.sendPayment(invoice.bolt11, undefined, 0n, 1000n)
		).to.throw('persisted budget');
		expect(alice.getPayment(invoice.paymentHash)).to.equal(undefined);
	});

	it('round-trips msat above safe integer precision and accepts legacy records without pay-all', () => {
		const debitMsat = 9_007_199_254_741_123n;
		const record: IPaymentInfo = {
			paymentHash: Buffer.alloc(32, 5),
			amountMsat: debitMsat,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: 1,
			payAll: {
				debitMsat,
				maxFeeMsat: 123n,
				deliveredMsat: debitMsat - 123n,
				feeMsat: 123n,
				remainderMsat: 0n
			}
		};
		expect(
			deserializePaymentInfo(serializePaymentInfo(record)).payAll
		).to.deep.equal(record.payAll);
		delete record.payAll;
		expect(
			deserializePaymentInfo(serializePaymentInfo(record)).payAll
		).to.equal(undefined);
	});
});
