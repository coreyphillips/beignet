/**
 * Issue #1063: payments over a day old left GET /payments a minute after
 * start, GET /payment answered NOT_FOUND for them and their invoices read
 * EXPIRED or PENDING. The engine prunes a completed or failed record from
 * its in-memory map 24 hours after completion (oldest first past 10,000)
 * while its SQLite row stays, and BeignetNode read only the map. It now
 * reads the rows under the map: a wallet must never show less than it
 * already knew.
 *
 * Offline suite: the node boots against an unreachable Electrum server, so
 * nothing here needs a chain or a channel. The rows are written the way the
 * engine writes them, in a first run, and the node under test boots on the
 * same directory, so the records reach the map the way they do on a phone:
 * loaded at start, pruned on the first cleanup tick.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import sinon from 'sinon';
import { BeignetNode } from '../../src/cli/beignet-node';
import { startDaemon, IStartedDaemon } from '../../src/cli/daemon';
import { InvoiceInfo, PaymentFilter, PaymentInfo } from '../../src/cli/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

// Same rationale as tests/cli/pay-invoice-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const ROUTE_TOKEN = 'durable-reads-token';

/** Past the 24 hour TTL of the in-memory record. */
const A_DAY_AND_AN_HOUR_MS = 25 * 60 * 60 * 1000;

const bootNode = (dataDir: string): Promise<BeignetNode> =>
	BeignetNode.create({
		mnemonic: MNEMONIC,
		network: 'regtest',
		dataDir,
		logLevel: 'silent',
		rapidGossipSync: false,
		autoGossipSync: false,
		...OFFLINE_ELECTRUM
	});

const settle = (ms: number): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/** An invoice from somebody else, for a preimage the test knows. */
const invoiceFrom = (
	description: string,
	amountSats = 1_000
): { bolt11: string; paymentHash: Buffer; preimage: Buffer } => {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat: BigInt(amountSats) * 1000n,
			timestamp: Math.floor(Date.now() / 1000),
			paymentHash,
			paymentSecret: crypto.randomBytes(32),
			description,
			expiry: 3600,
			minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			privateKey: crypto
				.createHash('sha256')
				.update(Buffer.from(`payee-${description}`))
				.digest()
		}),
		paymentHash,
		preimage
	};
};

interface IRecordOptions {
	paymentHash: Buffer;
	direction: PaymentDirection;
	status: PaymentStatus;
	amountSats: number;
	completedAgoMs: number;
	preimage?: Buffer;
	label: string;
	failureReason?: string;
}

/** A durable row the way the engine writes one at settlement. */
const recordOf = (o: IRecordOptions): IPaymentInfo => {
	const amountMsat = BigInt(o.amountSats) * 1000n;
	return {
		paymentHash: o.paymentHash,
		...(o.preimage ? { preimage: o.preimage } : {}),
		amountMsat,
		// An outgoing settlement records what left the node, fees included,
		// which is where the API reads feeSats from.
		...(o.direction === PaymentDirection.OUTGOING &&
		o.status === PaymentStatus.COMPLETED
			? { sentMsat: amountMsat + 3_000n }
			: {}),
		status: o.status,
		direction: o.direction,
		createdAt: Date.now() - o.completedAgoMs - 1_000,
		completedAt: Date.now() - o.completedAgoMs,
		...(o.failureReason ? { failureReason: o.failureReason } : {}),
		metadata: { label: o.label }
	};
};

const saveRecord = (node: BeignetNode, o: IRecordOptions): string => {
	const hashHex = o.paymentHash.toString('hex');
	const storage = node.getStorage();
	storage.savePayment(hashHex, recordOf(o));
	if (o.preimage) storage.savePreimage(hashHex, o.preimage);
	return hashHex;
};

interface ISeeded {
	/** Two completed sends, 25 hours old. */
	outgoing: string[];
	/** Two completed receives, 25 hours old: the invoices' hashes. */
	incoming: string[];
	/** The receive whose invoice expiry (1 s) has passed by the time it is read. */
	expiredInvoice: string;
	/** The receive whose invoice expiry (1 h) has not. */
	openInvoice: string;
}

/**
 * A first run that leaves two completed sends and two paid invoices, all
 * completed 25 hours ago, in the database. The invoices are the node's own
 * (createInvoice persists them with their preimages), and their receive
 * records are written the way a settlement writes them.
 */
const seedHistory = async (dataDir: string): Promise<ISeeded> => {
	const first = await bootNode(dataDir);
	try {
		const outgoing: string[] = [];
		for (const label of ['sent-1', 'sent-2']) {
			const preimage = crypto.randomBytes(32);
			outgoing.push(
				saveRecord(first, {
					paymentHash: crypto.createHash('sha256').update(preimage).digest(),
					direction: PaymentDirection.OUTGOING,
					status: PaymentStatus.COMPLETED,
					amountSats: 1_000,
					completedAgoMs: A_DAY_AND_AN_HOUR_MS,
					preimage,
					label
				})
			);
		}
		const expired = first.createInvoice(1_500, 'paid, then expired', 1);
		const open = first.createInvoice(2_500, 'paid, still open', 3_600);
		const incoming: string[] = [];
		for (const inv of [expired, open]) {
			const preimage = first.getStorage().loadPreimage(inv.paymentHash);
			expect(preimage, 'createInvoice persists the preimage').to.not.equal(
				null
			);
			incoming.push(
				saveRecord(first, {
					paymentHash: Buffer.from(inv.paymentHash, 'hex'),
					direction: PaymentDirection.INCOMING,
					status: PaymentStatus.COMPLETED,
					amountSats: inv.amountSats!,
					completedAgoMs: A_DAY_AND_AN_HOUR_MS,
					preimage: preimage!,
					label: inv.description ?? 'received'
				})
			);
		}
		return {
			outgoing,
			incoming,
			expiredInvoice: expired.paymentHash,
			openInvoice: open.paymentHash
		};
	} finally {
		await first.destroy();
	}
};

/** Every filter the route exposes, over the seeded history. */
const filters = (): Array<[string, PaymentFilter]> => [
	['status', { status: 'COMPLETED' }],
	['direction', { direction: 'OUTGOING' }],
	['direction + limit', { direction: 'OUTGOING', limit: 1 }],
	['since', { since: Date.now() - 2 * A_DAY_AND_AN_HOUR_MS }],
	['since (nothing that recent)', { since: Date.now() - 1_000 }],
	['metadataKey', { metadataKey: 'label' }],
	['metadataKey + value', { metadataKey: 'label', metadataValue: 'sent-2' }],
	['offset', { offset: 1 }],
	['offset + limit', { offset: 1, limit: 2 }],
	[
		'everything at once',
		{
			status: 'COMPLETED',
			direction: 'INCOMING',
			since: 0,
			metadataKey: 'label',
			limit: 5
		}
	]
];

const byHash = (payments: PaymentInfo[]): Map<string, PaymentInfo> =>
	new Map(payments.map((p) => [p.paymentHash, p]));

/** One authenticated request to the daemon, JSON in and out. */
const request = (
	port: number,
	urlPath: string,
	method = 'GET'
): Promise<{ status: number; body: Record<string, unknown> }> =>
	new Promise((resolve, reject) => {
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: urlPath,
				method,
				headers: { Authorization: `Bearer ${ROUTE_TOKEN}` }
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					try {
						resolve({
							status: res.statusCode!,
							body: JSON.parse(Buffer.concat(chunks).toString())
						});
					} catch (err) {
						reject(err);
					}
				});
			}
		);
		req.on('error', reject);
		req.end();
	});

describe('Pruned payments stay readable from their durable rows (issue #1063)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let node: BeignetNode;
	let seeded: ISeeded;
	let allHashes: string[];
	let paymentsBefore: PaymentInfo[];
	let paymentByHashBefore: Map<string, PaymentInfo | null>;
	let invoicesBefore: InvoiceInfo[];
	let invoiceByHashBefore: Map<string, InvoiceInfo | null>;
	let filteredBefore: Map<string, PaymentInfo[]>;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-durable-reads-'));
		seeded = await seedHistory(tmpDir);
		allHashes = [...seeded.outgoing, ...seeded.incoming];
		node = await bootNode(tmpDir);
		// The 1 s invoice is past its expiry before anything reads it, so
		// PAID has to win over EXPIRED, not just over PENDING.
		await settle(1_200);

		paymentsBefore = node.listPayments();
		paymentByHashBefore = new Map(
			allHashes.map((h) => [h, node.getPayment(h)])
		);
		invoicesBefore = node.listInvoices();
		invoiceByHashBefore = new Map(
			seeded.incoming.map((h) => [h, node.getInvoice(h)])
		);
		filteredBefore = new Map(
			filters().map(([label, filter]) => [label, node.listPayments(filter)])
		);

		// What the wallet saw for the first minute after start.
		for (const h of allHashes) {
			expect(byHash(paymentsBefore).get(h)?.status, h).to.equal('COMPLETED');
			expect(paymentByHashBefore.get(h)?.status, h).to.equal('COMPLETED');
		}
		for (const h of seeded.incoming) {
			expect(invoiceByHashBefore.get(h)?.status, h).to.equal('PAID');
		}

		// The cleanup tick.
		const pruned = node.getNode().pruneCompletedPayments();
		expect(pruned).to.be.at.least(allHashes.length);
		for (const h of allHashes) {
			expect(
				node.getNode().getPayment(Buffer.from(h, 'hex')),
				`${h} is gone from the map`
			).to.equal(undefined);
		}
	});

	afterEach(() => {
		sinon.restore();
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('listPayments lists every pruned payment with the status, amount and fee it had', () => {
		const after = node.listPayments();
		expect(after).to.deep.equal(paymentsBefore);
		const listed = byHash(after);
		for (const h of seeded.outgoing) {
			expect(listed.get(h)).to.include({
				status: 'COMPLETED',
				direction: 'OUTGOING',
				// What left the node, fees included (#1185).
				amountSats: 1_003,
				feeSats: 3
			});
		}
		for (const h of seeded.incoming) {
			expect(listed.get(h)).to.include({
				status: 'COMPLETED',
				direction: 'INCOMING'
			});
		}
	});

	it('getPayment finds each pruned payment, as it did before the prune', () => {
		for (const h of allHashes) {
			const found = node.getPayment(h);
			expect(found, h).to.not.equal(null);
			expect(found).to.deep.equal(paymentByHashBefore.get(h));
		}
	});

	it('listInvoices and getInvoice still read PAID, past the expiry and within it', () => {
		const after = node.listInvoices();
		expect(after).to.deep.equal(invoicesBefore);
		const listed = new Map(after.map((i) => [i.paymentHash, i]));
		expect(listed.get(seeded.expiredInvoice)?.status).to.equal('PAID');
		expect(listed.get(seeded.openInvoice)?.status).to.equal('PAID');
		for (const h of seeded.incoming) {
			expect(node.getInvoice(h)).to.deep.equal(invoiceByHashBefore.get(h));
			expect(node.getInvoice(h)?.status).to.equal('PAID');
		}
	});

	it('status, direction, since, metadataKey, offset and limit give what they gave with nothing pruned', () => {
		for (const [label, filter] of filters()) {
			expect(node.listPayments(filter), label).to.deep.equal(
				filteredBefore.get(label)
			);
		}
		// The filters are not vacuous: some of them select rows.
		expect(node.listPayments({ direction: 'OUTGOING' })).to.have.length(2);
		expect(
			node.listPayments({ metadataKey: 'label', metadataValue: 'sent-2' })
		).to.have.length(1);
		expect(node.listPayments({ offset: 1, limit: 2 })).to.have.length(2);
	});

	it('a hash in both the map and the database appears once, with the live record', () => {
		const hashHex = seeded.outgoing[0];
		const durable = node.getStorage().loadPayment(hashHex)!;
		const live: IPaymentInfo = {
			...durable,
			metadata: { label: 'live' }
		};
		const payments = (
			node.getNode() as unknown as { payments: Map<string, IPaymentInfo> }
		).payments;
		payments.set(hashHex, live);
		try {
			const listed = node
				.listPayments()
				.filter((p) => p.paymentHash === hashHex);
			expect(listed).to.have.length(1);
			expect(listed[0].metadata).to.deep.equal({ label: 'live' });
			expect(node.getPayment(hashHex)?.metadata).to.deep.equal({
				label: 'live'
			});
		} finally {
			payments.delete(hashHex);
		}
	});

	it('a fresh pending payment is listed once, with the map winning over its row', () => {
		// A pending send: the engine writes the record and its row together.
		const fresh = invoiceFrom('in flight now');
		const hashHex = fresh.paymentHash.toString('hex');
		const record = recordOf({
			paymentHash: fresh.paymentHash,
			direction: PaymentDirection.OUTGOING,
			status: PaymentStatus.PENDING,
			amountSats: 1_000,
			completedAgoMs: 0,
			label: 'in flight'
		});
		delete record.completedAt;
		const payments = (
			node.getNode() as unknown as { payments: Map<string, IPaymentInfo> }
		).payments;
		payments.set(hashHex, record);
		node.getStorage().savePayment(hashHex, record);
		try {
			const listed = node.listPayments();
			expect(listed.filter((p) => p.paymentHash === hashHex)).to.have.length(1);
			expect(listed[0].paymentHash, 'newest first').to.equal(hashHex);
			expect(listed[0].status).to.equal('PENDING');
			expect(listed).to.have.length(paymentsBefore.length + 1);
			expect(node.listPayments({ status: 'PENDING' })).to.have.length(1);
		} finally {
			payments.delete(hashHex);
			node.getStorage().deletePayment(hashHex);
		}
	});

	it('a database read that fails fails the call rather than shrinking it', () => {
		const storage = node.getStorage();
		// A record the map still holds: an unpaid invoice of this run.
		const liveInvoice = node.createInvoice(700, 'still in the map', 3_600);

		sinon.stub(storage, 'loadAllPayments').throws(new Error('disk gone'));
		expect(() => node.listPayments()).to.throw('disk gone');
		expect(() => node.listPayments({ direction: 'INCOMING' })).to.throw(
			'disk gone'
		);
		expect(() => node.listInvoices()).to.throw('disk gone');

		sinon.stub(storage, 'loadPayment').throws(new Error('disk gone'));
		for (const h of allHashes) {
			expect(() => node.getPayment(h), h).to.throw('disk gone');
		}
		for (const h of seeded.incoming) {
			expect(() => node.getInvoice(h), h).to.throw('disk gone');
		}
		// The map answers for what it still holds, without touching the rows.
		expect(node.getPayment(liveInvoice.paymentHash)?.status).to.equal(
			'PENDING'
		);
		expect(node.getInvoice(liveInvoice.paymentHash)?.status).to.equal(
			'PENDING'
		);
	});

	it('listInvoices reads the rows once for all its invoices, never one per invoice', () => {
		const storage = node.getStorage();
		const all = sinon.spy(storage, 'loadAllPayments');
		const one = sinon.spy(storage, 'loadPayment');
		const listed = node.listInvoices();
		expect(listed.length).to.be.at.least(2);
		expect(all.callCount).to.equal(1);
		expect(one.callCount).to.equal(0);
	});
});

describe('The pay paths keep this attempt over an old FAILED row (issue #1063)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let node: BeignetNode;
	let failed: ReturnType<typeof invoiceFrom>;
	let hashHex: string;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-durable-pay-'));
		failed = invoiceFrom('failed a day ago');
		const first = await bootNode(tmpDir);
		try {
			hashHex = saveRecord(first, {
				paymentHash: failed.paymentHash,
				direction: PaymentDirection.OUTGOING,
				status: PaymentStatus.FAILED,
				amountSats: 1_000,
				completedAgoMs: A_DAY_AND_AN_HOUR_MS,
				label: 'yesterday',
				failureReason: 'no route yesterday'
			});
		} finally {
			await first.destroy();
		}
		node = await bootNode(tmpDir);
		expect(node.getNode().pruneCompletedPayments()).to.be.at.least(1);
		expect(node.getNode().getPayment(failed.paymentHash)).to.equal(undefined);
		// The read API still finds yesterday's failure.
		expect(node.getPayment(hashHex)?.failureDescription).to.equal(
			'no route yesterday'
		);
	});

	afterEach(() => {
		sinon.restore();
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('payInvoiceSafe reports the fresh refusal, not the row of an earlier attempt', async () => {
		const started = Date.now();
		// A refusal that leaves no record, as NO_ROUTE does before dispatch.
		sinon
			.stub(node.getNode(), 'sendPayment')
			.throws(new Error('no route this time'));
		const result = await node.payInvoiceSafe(failed.bolt11, 5_000);
		expect(result.paymentHash).to.equal(hashHex);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.include('no route this time');
		expect(result.failureDescription).to.not.include('yesterday');
		expect(result.createdAt).to.be.at.least(started);
	});

	it('payInvoiceWithRetry reports the fresh refusal once its retries are spent', async () => {
		const started = Date.now();
		sinon
			.stub(node.getNode(), 'sendPayment')
			.throws(new Error('no route this time'));
		const result = await node.payInvoiceWithRetry(failed.bolt11, {
			maxRetries: 0
		});
		expect(result.paymentHash).to.equal(hashHex);
		expect(result.status).to.equal('FAILED');
		expect(result.attempts).to.equal(1);
		expect(result.failureDescription).to.include('no route this time');
		expect(result.failureDescription).to.not.include('yesterday');
		expect(result.createdAt).to.be.at.least(started);
	});
});

describe('GET /payments, /payment, /invoices and /invoice after the prune (issue #1063)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let daemon: IStartedDaemon;
	let port: number;
	let seeded: ISeeded;
	let snapshot: Map<string, { status: number; body: Record<string, unknown> }>;

	const paths = (): string[] => [
		'/payments',
		'/payments?direction=OUTGOING&limit=1',
		'/payments?status=COMPLETED&offset=1&limit=2',
		'/payments?metadataKey=label&metadataValue=sent-1',
		'/invoices',
		`/invoice?paymentHash=${seeded.expiredInvoice}`,
		`/invoice?paymentHash=${seeded.openInvoice}`,
		...[...seeded.outgoing, ...seeded.incoming].map(
			(h) => `/payment?paymentHash=${h}`
		)
	];

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-durable-http-'));
		seeded = await seedHistory(tmpDir);
		daemon = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM,
			daemonPort: 0,
			apiToken: ROUTE_TOKEN
		});
		port = (daemon.server.address() as AddressInfo).port;
		await settle(1_200);

		snapshot = new Map();
		for (const p of paths()) snapshot.set(p, await request(port, p));
		const listed = snapshot.get('/payments')!.body.result as PaymentInfo[];
		expect(listed.map((p) => p.paymentHash).sort()).to.deep.equal(
			[...seeded.outgoing, ...seeded.incoming].sort()
		);
		const invoices = snapshot.get('/invoices')!.body.result as InvoiceInfo[];
		expect(invoices.map((i) => i.status)).to.deep.equal(['PAID', 'PAID']);

		expect(daemon.node.getNode().pruneCompletedPayments()).to.be.at.least(4);
	});

	afterEach(() => {
		sinon.restore();
	});

	after(async () => {
		await daemon?.stop();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('every route answers what it answered before the prune', async () => {
		for (const p of paths()) {
			const res = await request(port, p);
			expect(res.status, p).to.equal(200);
			expect(res, p).to.deep.equal(snapshot.get(p));
		}
	});

	it('a database read that fails answers 500, never a shorter list or NOT_FOUND', async () => {
		const storage = daemon.node.getStorage();
		sinon.stub(storage, 'loadAllPayments').throws(new Error('disk gone'));
		sinon.stub(storage, 'loadPayment').throws(new Error('disk gone'));
		for (const p of [
			'/payments',
			'/invoices',
			`/invoice?paymentHash=${seeded.openInvoice}`,
			`/payment?paymentHash=${seeded.outgoing[0]}`
		]) {
			const res = await request(port, p);
			expect(res.status, p).to.equal(500);
			expect(res.body.ok, p).to.equal(false);
		}
	});
});
