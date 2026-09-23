/**
 * Issue #967: the payment queue across a restart. Restored entries used to
 * dispatch only on the next unrelated enqueue, and an entry that was in
 * flight at the restart was restored 'queued' and sent again. sendPayment
 * refuses a second payment to a hash only while the first is PENDING, so a
 * payment that had COMPLETED was paid a second time. BeignetNode now settles
 * such an entry against its own record before anything sends it again.
 *
 * Offline suite: the node boots against an unreachable Electrum server, so
 * nothing here needs a chain or a channel.
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
import { QueuedPayment } from '../../src/cli/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	IOutgoingPaymentResolution,
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

const resolution = (
	paymentHash: Buffer,
	status: PaymentStatus | null,
	preimage?: Buffer
): IOutgoingPaymentResolution => ({
	paymentHash,
	status,
	htlcs: [],
	resolved: true,
	latestOutstandingExpiry: null,
	...(preimage ? { preimage } : {})
});

const settle = (ms = 20): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

const ROUTE_TOKEN = 'queue-restart-token';

/** One authenticated request to the daemon, JSON in and out. */
const postJson = (
	port: number,
	urlPath: string,
	body: Record<string, unknown> | undefined,
	method = 'POST'
): Promise<{ status: number; body: Record<string, unknown> }> =>
	new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {
			Authorization: `Bearer ${ROUTE_TOKEN}`
		};
		if (payload) {
			headers['Content-Type'] = 'application/json';
			headers['Content-Length'] = Buffer.byteLength(payload);
		}
		const req = http.request(
			{ hostname: '127.0.0.1', port, path: urlPath, method, headers },
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
		if (payload) req.write(payload);
		req.end();
	});

/** Replaces payInvoiceSafe with a recorder that completes every payment. */
const stubPayInvoiceSafe = (node: BeignetNode): string[] => {
	const calls: string[] = [];
	(
		node as unknown as {
			payInvoiceSafe: (b: string) => Promise<unknown>;
		}
	).payInvoiceSafe = async (bolt11: string): Promise<unknown> => {
		calls.push(bolt11);
		return {
			paymentHash: 'stub',
			amountSats: 1_000,
			status: 'COMPLETED',
			direction: 'OUTGOING',
			createdAt: Date.now()
		};
	};
	return calls;
};

/** The queue entry once it reaches a status the queue leaves it in. */
const queueEntryOnceFinal = async (
	node: BeignetNode,
	id: string,
	timeoutMs = 10_000
): Promise<QueuedPayment> => {
	const deadline = Date.now() + timeoutMs;
	for (;;) {
		const entry = node.listQueue().find((e) => e.id === id);
		if (entry && entry.status !== 'queued' && entry.status !== 'dispatching') {
			return entry;
		}
		if (Date.now() > deadline) {
			throw new Error(
				`queue entry ${id} never settled (last status: ${entry?.status})`
			);
		}
		await settle(25);
	}
};

/**
 * A restored channel of 1 000 000 sats with 900 000 on our side, by default
 * waiting on its peer's channel_reestablish. NORMAL, it can carry the 1 000
 * sat payments of this suite.
 */
const injectChannel = (
	node: BeignetNode,
	initial: ChannelState = ChannelState.AWAITING_REESTABLISH
): Channel => {
	const seed = crypto.randomBytes(32);
	const basepoint = (i: number): Buffer =>
		getPublicKey(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: {
			fundingPubkey: basepoint(0),
			revocationBasepoint: basepoint(1),
			paymentBasepoint: basepoint(2),
			delayedPaymentBasepoint: basepoint(3),
			htlcBasepoint: basepoint(4),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		localPerCommitmentSeed: seed
	});
	state.channelId = crypto.randomBytes(32);
	state.state = initial;
	state.fundingTxid = crypto.randomBytes(32);
	state.localBalanceMsat = 900_000_000n;
	state.remoteBalanceMsat = 100_000_000n;
	const channel = new Channel(state);
	const manager = node.getNode().getChannelManager() as unknown as {
		channels: Map<string, Channel>;
		channelPeers: Map<string, string>;
	};
	manager.channels.set(state.channelId.toString('hex'), channel);
	manager.channelPeers.set(
		state.channelId.toString('hex'),
		'02'.padEnd(66, 'ab')
	);
	return channel;
};

describe('BeignetNode.resolveInterruptedPayment (issue #967)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-resolve-'));
		node = await bootNode(tmpDir);
	});

	afterEach(() => {
		sinon.restore();
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('is completed when the preimage is known, whatever the record says, and waits with no timeout', async () => {
		const { bolt11, paymentHash, preimage } = invoiceFrom('preimage');
		const wait = sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, PaymentStatus.FAILED, preimage));

		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'completed',
			paymentHash: paymentHash.toString('hex')
		});
		expect(wait.calledOnce).to.equal(true);
		expect((wait.firstCall.args[0] as Buffer).equals(paymentHash)).to.equal(
			true
		);
		expect(wait.firstCall.args[1]).to.equal(undefined);
	});

	it('is completed when the record says COMPLETED', async () => {
		const { bolt11, paymentHash } = invoiceFrom('completed');
		sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, PaymentStatus.COMPLETED));

		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'completed',
			paymentHash: paymentHash.toString('hex')
		});
	});

	it('is unpaid when every HTLC resolved and none revealed the preimage', async () => {
		const { bolt11, paymentHash } = invoiceFrom('failed');
		sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, PaymentStatus.FAILED));

		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'unpaid'
		});
	});

	it('is unpaid when the node has no record and offered nothing for the hash', async () => {
		const { bolt11 } = invoiceFrom('never sent');
		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'unpaid'
		});
	});

	/** A durable record for the hash, as storage would return it. */
	const durableRecord = (
		paymentHash: Buffer,
		direction: PaymentDirection,
		status: PaymentStatus,
		preimage?: Buffer
	): IPaymentInfo => ({
		paymentHash,
		...(preimage ? { preimage } : {}),
		amountMsat: 1_000_000n,
		status,
		direction,
		createdAt: Date.now() - 1_000
	});

	it('is completed when the in-memory view has nothing but the durable OUTGOING record is COMPLETED or holds the preimage', async () => {
		for (const [status, withPreimage] of [
			[PaymentStatus.COMPLETED, false],
			[PaymentStatus.FAILED, true]
		] as Array<[PaymentStatus, boolean]>) {
			const { bolt11, paymentHash, preimage } = invoiceFrom(
				`durable ${status}`
			);
			sinon
				.stub(node.getNode(), 'awaitPaymentResolution')
				.resolves(resolution(paymentHash, null));
			sinon
				.stub(node.getStorage(), 'loadPayment')
				.returns(
					durableRecord(
						paymentHash,
						PaymentDirection.OUTGOING,
						status,
						withPreimage ? preimage : undefined
					)
				);
			expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
				status: 'completed',
				paymentHash: paymentHash.toString('hex')
			});
			sinon.restore();
		}
	});

	it('is unpaid when the durable record is not an OUTGOING payment that was made', async () => {
		const { bolt11, paymentHash, preimage } = invoiceFrom('durable other');
		sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, null));
		const load = sinon.stub(node.getStorage(), 'loadPayment');
		// This node's own invoice for the hash: its preimage is not a payment.
		load.returns(
			durableRecord(
				paymentHash,
				PaymentDirection.INCOMING,
				PaymentStatus.COMPLETED,
				preimage
			)
		);
		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'unpaid'
		});
		load.returns(
			durableRecord(
				paymentHash,
				PaymentDirection.OUTGOING,
				PaymentStatus.FAILED
			)
		);
		expect(await node.resolveInterruptedPayment(bolt11)).to.deep.equal({
			status: 'unpaid'
		});
	});

	it('throws when the durable record cannot be read, so the entry waits', async () => {
		const { bolt11, paymentHash } = invoiceFrom('durable unreadable');
		sinon
			.stub(node.getNode(), 'awaitPaymentResolution')
			.resolves(resolution(paymentHash, null));
		sinon
			.stub(node.getStorage(), 'loadPayment')
			.throws(new Error('The database connection is not open'));
		let refused: unknown;
		try {
			await node.resolveInterruptedPayment(bolt11);
		} catch (err: unknown) {
			refused = err;
		}
		expect((refused as Error | undefined)?.message).to.contain('not open');
	});

	it('waits while the payment is unresolved', async () => {
		const { bolt11, paymentHash, preimage } = invoiceFrom('held');
		let release!: (view: IOutgoingPaymentResolution) => void;
		sinon.stub(node.getNode(), 'awaitPaymentResolution').returns(
			new Promise<IOutgoingPaymentResolution>((resolve) => {
				release = resolve;
			})
		);

		let settled = false;
		const outcome = node.resolveInterruptedPayment(bolt11).then((o) => {
			settled = true;
			return o;
		});
		await settle(50);
		expect(settled).to.equal(false);

		release(resolution(paymentHash, PaymentStatus.COMPLETED, preimage));
		expect(await outcome).to.deep.equal({
			status: 'completed',
			paymentHash: paymentHash.toString('hex')
		});
	});

	it('is unpaid for a string that does not decode, without asking the node', async () => {
		const wait = sinon.stub(node.getNode(), 'awaitPaymentResolution');
		expect(
			await node.resolveInterruptedPayment('lnbcrt_not_an_invoice')
		).to.deep.equal({ status: 'unpaid' });
		expect(wait.called).to.equal(false);
	});

	it('throws while there is no node to ask, so the entry waits for the next start', async () => {
		const { bolt11 } = invoiceFrom('no node');
		const wait = sinon.stub(node.getNode(), 'awaitPaymentResolution');
		const flags = node as unknown as Record<string, boolean>;
		const expected: Array<[string, string]> = [
			['_restorePending', 'NODE_RESTORE_PENDING'],
			['_resuming', 'NODE_RESTORE_PENDING'],
			['_restartRequired', 'NODE_RESTART_REQUIRED'],
			['destroyed', 'NODE_DESTROYED']
		];
		for (const [flag, code] of expected) {
			flags[flag] = true;
			try {
				let refused: unknown;
				try {
					await node.resolveInterruptedPayment(bolt11);
				} catch (err: unknown) {
					refused = err;
				}
				expect((refused as { code?: string } | undefined)?.code, flag).to.equal(
					code
				);
			} finally {
				flags[flag] = false;
			}
		}
		expect(wait.called).to.equal(false);
	});
});

describe('BeignetNode.whenReadyToPay (issue #967)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;
	let flags: Record<string, boolean>;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-ready-'));
		node = await bootNode(tmpDir);
		flags = node as unknown as Record<string, boolean>;
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('runs once the node is ready', async () => {
		let runs = 0;
		node.whenReadyToPay(() => runs++);
		await settle();
		expect(runs).to.equal(1);
	});

	it('never runs while a capsule restore rebuilds the node or a restart is required', async () => {
		let runs = 0;
		for (const flag of ['_resuming', '_restartRequired']) {
			flags[flag] = true;
			try {
				node.whenReadyToPay(() => runs++);
				await settle();
			} finally {
				flags[flag] = false;
			}
		}
		expect(runs).to.equal(0);
	});

	it('waits for a pending guardian restore to finish', async () => {
		let runs = 0;
		const before = node.listenerCount('recovery:restored');
		flags._restorePending = true;
		try {
			node.whenReadyToPay(() => runs++);
			await settle();
			expect(runs).to.equal(0);
			expect(node.listenerCount('recovery:restored')).to.equal(before + 1);
		} finally {
			flags._restorePending = false;
		}
		node.emit('recovery:restored', {});
		await settle();
		expect(runs).to.equal(1);
		expect(node.listenerCount('recovery:restored')).to.equal(before);
	});

	it('a wait on a pending restore does not outlive shutdown', async () => {
		let runs = 0;
		flags._restorePending = true;
		try {
			node.whenReadyToPay(() => runs++);
		} finally {
			flags._restorePending = false;
		}
		await node.destroy();
		expect(node.listenerCount('recovery:restored')).to.equal(0);
		node.whenReadyToPay(() => runs++);
		await settle();
		expect(runs).to.equal(0);
	});
});

describe('A payment in flight at a restart is not paid again (issue #967)', function () {
	this.timeout(60_000);

	let tmpDir: string;

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-restart-'));
	});

	afterEach(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * Run 1: leave the node's record of an outgoing payment and a queue row
	 * the queue never got to update, as a stop mid-payment does.
	 */
	const seedRun = async (seed: (node: BeignetNode) => void): Promise<void> => {
		const first = await bootNode(tmpDir);
		try {
			seed(first);
		} finally {
			await first.destroy();
		}
	};

	const recordOutgoing = (
		node: BeignetNode,
		paymentHash: Buffer,
		status: PaymentStatus,
		preimage?: Buffer,
		completedAgoMs = 0
	): void => {
		const storage = node.getStorage();
		const hashHex = paymentHash.toString('hex');
		storage.savePayment(hashHex, {
			paymentHash,
			...(preimage ? { preimage } : {}),
			amountMsat: 1_000_000n,
			status,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now() - completedAgoMs - 1_000,
			completedAt: Date.now() - completedAgoMs
		});
		if (preimage) storage.savePreimage(hashHex, preimage);
	};

	it('a payment that completed before the restart is recorded completed, and never sent again, even when another payment is enqueued first', async () => {
		const paid = invoiceFrom('paid before the restart');
		await seedRun((first) => {
			recordOutgoing(
				first,
				paid.paymentHash,
				PaymentStatus.COMPLETED,
				paid.preimage
			);
			first.getStorage().saveQueueEntry({
				id: 'q-1-967',
				bolt11: paid.bolt11,
				priority: 5,
				status: 'dispatching',
				createdAt: Date.now() - 1_000
			});
		});

		const second = await bootNode(tmpDir);
		try {
			// A channel that can carry the unrelated payment: with none, it
			// waits for capacity like any entry with an amount (issue #981).
			injectChannel(second, ChannelState.NORMAL);
			const payCalls = stubPayInvoiceSafe(second);
			expect(second.listQueue().map((e) => e.id)).to.include('q-1-967');
			// Before the fix this dispatched the restored row again: the
			// engine does not refuse a hash whose record is COMPLETED.
			const other = invoiceFrom('an unrelated payment');
			const added = second.enqueuePayment(other.bolt11);

			const restored = await queueEntryOnceFinal(second, 'q-1-967');
			expect(restored.status).to.equal('completed');
			expect(payCalls).to.not.include(paid.bolt11);
			await queueEntryOnceFinal(second, added.id);
			expect(payCalls).to.deep.equal([other.bolt11]);
			const row = second
				.getStorage()
				.loadAllQueueEntries()
				.find((r) => r.id === 'q-1-967');
			expect(row?.status).to.equal('completed');
		} finally {
			await second.destroy();
		}
	});

	it('what was queued, or in flight and paid nothing, dispatches once the node is ready, with no enqueue', async () => {
		const unpaid = invoiceFrom('failed before the restart');
		const waiting = invoiceFrom('queued before the restart');
		await seedRun((first) => {
			recordOutgoing(first, unpaid.paymentHash, PaymentStatus.FAILED);
			const storage = first.getStorage();
			storage.saveQueueEntry({
				id: 'q-1-unpaid',
				bolt11: unpaid.bolt11,
				priority: 5,
				status: 'dispatching',
				createdAt: Date.now() - 1_000
			});
			storage.saveQueueEntry({
				id: 'q-2-waiting',
				bolt11: waiting.bolt11,
				priority: 5,
				status: 'queued',
				createdAt: Date.now() - 1_000
			});
		});

		const second = await bootNode(tmpDir);
		try {
			// A channel that can carry both payments: with none, they wait
			// for capacity like any entry with an amount (issue #981).
			injectChannel(second, ChannelState.NORMAL);
			const payCalls = stubPayInvoiceSafe(second);
			// Only builds the queue: nothing is enqueued in this run.
			second.listQueue();

			expect((await queueEntryOnceFinal(second, 'q-1-unpaid')).status).to.equal(
				'completed'
			);
			expect(
				(await queueEntryOnceFinal(second, 'q-2-waiting')).status
			).to.equal('completed');
			expect([...payCalls].sort()).to.deep.equal(
				[unpaid.bolt11, waiting.bolt11].sort()
			);
		} finally {
			await second.destroy();
		}
	});

	// Review round 1: the in-memory record and preimage are pruned 24 hours
	// after completion, on a 60 s tick that can run before the queue starts.
	// The resolver then saw no record and no preimage and answered 'unpaid',
	// while the record stayed COMPLETED on disk.
	it('a completed payment whose in-memory record was pruned is still recorded completed, and never sent again', async () => {
		const paid = invoiceFrom('paid 25 hours before the restart');
		await seedRun((first) => {
			recordOutgoing(
				first,
				paid.paymentHash,
				PaymentStatus.COMPLETED,
				paid.preimage,
				25 * 60 * 60 * 1000
			);
			first.getStorage().saveQueueEntry({
				id: 'q-1-pruned',
				bolt11: paid.bolt11,
				priority: 5,
				status: 'dispatching',
				createdAt: Date.now() - 25 * 60 * 60 * 1000
			});
		});

		const second = await bootNode(tmpDir);
		try {
			const hashHex = paid.paymentHash.toString('hex');
			// The cleanup tick, before the queue exists.
			const pruned = second.getNode().pruneCompletedPayments();
			expect(pruned).to.be.greaterThan(0);
			expect(
				second.getNode().getOutgoingHtlcs(paid.paymentHash).preimage
			).to.equal(undefined);
			expect(second.getStorage().loadPayment(hashHex)?.status).to.equal(
				'COMPLETED'
			);

			const payCalls = stubPayInvoiceSafe(second);
			second.listQueue();
			const restored = await queueEntryOnceFinal(second, 'q-1-pruned');
			expect(restored.status).to.equal('completed');
			expect(payCalls).to.deep.equal([]);
		} finally {
			await second.destroy();
		}
	});
});

describe('Restored queue entries wait for a channel that can carry an HTLC (issue #967)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let node: BeignetNode;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-usable-'));
		node = await bootNode(tmpDir);
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/** A restored channel, by default waiting on its peer's channel_reestablish. */
	const injectReestablishingChannel = (
		initial: ChannelState = ChannelState.AWAITING_REESTABLISH
	): Channel => injectChannel(node, initial);

	// Review round 1: node:ready fires once the peers' init handshakes are
	// done, before channel_reestablish. Started then, the queue sent a
	// payment with no amount straight into "no route" (recorded failed), and
	// held one with an amount back on canSend with nothing to look again.
	it('neither restored row is dispatched or failed before the channel is usable, and both dispatch once it is, with no enqueue', async () => {
		const channel = injectReestablishingChannel();
		const noAmount = invoiceFrom('restored, no amount');
		const withAmount = invoiceFrom('restored, with an amount');
		const storage = node.getStorage();
		storage.saveQueueEntry({
			id: 'q-1-no-amount',
			bolt11: noAmount.bolt11,
			priority: 5,
			status: 'queued',
			createdAt: Date.now() - 1_000
		});
		storage.saveQueueEntry({
			id: 'q-2-with-amount',
			bolt11: withAmount.bolt11,
			priority: 5,
			status: 'queued',
			amountSats: 1_000,
			createdAt: Date.now() - 1_000
		});
		const payCalls = stubPayInvoiceSafe(node);
		// The node is ready (its peers answered init) but the channel is not.
		await node.getNode().waitForReady(1_000);

		node.listQueue();
		await settle(200);
		expect(payCalls).to.deep.equal([]);
		expect(
			node
				.listQueue()
				.map((e) => e.status)
				.sort()
		).to.deep.equal(['queued', 'queued']);

		// The peer's channel_reestablish lands and the channel is NORMAL.
		(channel as unknown as { _state: { state: ChannelState } })._state.state =
			ChannelState.NORMAL;
		expect(channel.acceptsNewHtlcs()).to.equal(true);
		node
			.getNode()
			.getChannelManager()
			.emit('channel:reestablished', channel.getChannelId());

		expect((await queueEntryOnceFinal(node, 'q-1-no-amount')).status).to.equal(
			'completed'
		);
		expect(
			(await queueEntryOnceFinal(node, 'q-2-with-amount')).status
		).to.equal('completed');
		expect([...payCalls].sort()).to.deep.equal(
			[noAmount.bolt11, withAmount.bolt11].sort()
		);
	});

	it('an entry held back by canSend after the start dispatches when a channel becomes usable, with no enqueue', async () => {
		const payCalls = stubPayInvoiceSafe(node);
		// No channel yet: the queue starts at once.
		node.listQueue();
		await settle();
		const invoice = invoiceFrom('waits for capacity');
		const entry = node.enqueuePayment(invoice.bolt11, 5, { amountSats: 1_000 });
		await settle();
		expect(payCalls).to.deep.equal([]);
		expect(node.listQueue().find((e) => e.id === entry.id)?.status).to.equal(
			'queued'
		);

		const channel = injectReestablishingChannel();
		(channel as unknown as { _state: { state: ChannelState } })._state.state =
			ChannelState.NORMAL;
		node
			.getNode()
			.getChannelManager()
			.emit('channel:reestablished', channel.getChannelId());

		expect((await queueEntryOnceFinal(node, entry.id)).status).to.equal(
			'completed'
		);
		expect(payCalls).to.deep.equal([invoice.bolt11]);
	});

	// Issue #981: the queue read the amount from amountSats alone, so an
	// entry whose amount was only in its invoice was dispatched with no
	// capacity check and failed with "no route" where one with amountSats
	// waited. BeignetNode now hands the queue the invoice's amount.
	it('an entry whose amount is only in its invoice waits for capacity for that amount, and dispatches once the channel can carry it (issue #981)', async () => {
		const payCalls = stubPayInvoiceSafe(node);
		const channel = injectReestablishingChannel(ChannelState.NORMAL);
		const state = (
			channel as unknown as { _state: { localBalanceMsat: bigint } }
		)._state;
		// The channel can carry an HTLC, but not one of 100 000 sats.
		state.localBalanceMsat = 50_000_000n;
		node.listQueue();
		await node.getNode().waitForReady(1_000);
		await settle();

		const invoice = invoiceFrom('amount only in the invoice', 100_000);
		const entry = node.enqueuePayment(invoice.bolt11);
		await settle();
		expect(payCalls).to.deep.equal([]);
		expect(node.listQueue().find((e) => e.id === entry.id)?.status).to.equal(
			'queued'
		);

		// The channel's balance grows (an inbound payment settled, say).
		state.localBalanceMsat = 900_000_000n;
		node.emit('channel:usable', {
			channelId: channel.getChannelId().toString('hex')
		});

		expect((await queueEntryOnceFinal(node, entry.id)).status).to.equal(
			'completed'
		);
		expect(payCalls).to.deep.equal([invoice.bolt11]);
	});

	it('a wait for a usable channel does not outlive shutdown', async () => {
		injectReestablishingChannel();
		let runs = 0;
		const before = node.listenerCount('channel:usable');
		node.whenReadyToPay(() => runs++);
		await settle();
		expect(node.listenerCount('channel:usable')).to.equal(before + 1);
		await node.destroy();
		expect(node.eventNames()).to.deep.equal([]);
		expect(runs).to.equal(0);
	});

	const setState = (channel: Channel, state: ChannelState): void => {
		(channel as unknown as { _state: { state: ChannelState } })._state.state =
			state;
	};

	const seedQueued = (id: string, bolt11: string): void =>
		node.getStorage().saveQueueEntry({
			id,
			bolt11,
			priority: 5,
			status: 'queued',
			createdAt: Date.now() - 1_000
		});

	// Review round 2 (C2): the channel manager reports a reestablish only for
	// a channel that can settle HTLCs, and a splice lock only as
	// splice:complete. A channel still SPLICING at the reestablish, or a
	// taproot one parked until splice_locked, never announced itself.
	it('a channel still SPLICING at the start releases the restored row when its splice locks, with no enqueue', async () => {
		const channel = injectReestablishingChannel(ChannelState.SPLICING);
		expect(channel.acceptsNewHtlcs()).to.equal(false);
		const invoice = invoiceFrom('restored behind a splice');
		seedQueued('q-1-splice', invoice.bolt11);
		const payCalls = stubPayInvoiceSafe(node);

		node.listQueue();
		await settle(200);
		expect(payCalls).to.deep.equal([]);

		setState(channel, ChannelState.NORMAL);
		node.getNode().emit('splice:complete', {
			channelId: channel.getChannelId(),
			fundingTxid: channel.getFullState().fundingTxid
		});

		expect((await queueEntryOnceFinal(node, 'q-1-splice')).status).to.equal(
			'completed'
		);
		expect(payCalls).to.deep.equal([invoice.bolt11]);
	});

	it('a funding quarantine lifting releases the restored row, with no enqueue', async () => {
		const channel = injectReestablishingChannel(ChannelState.NORMAL);
		(
			channel as unknown as { _state: { fundingUnaccounted?: boolean } }
		)._state.fundingUnaccounted = true;
		expect(channel.acceptsNewHtlcs()).to.equal(false);
		const invoice = invoiceFrom('restored behind a quarantine');
		seedQueued('q-1-quarantine', invoice.bolt11);
		const payCalls = stubPayInvoiceSafe(node);

		node.listQueue();
		await settle(200);
		expect(payCalls).to.deep.equal([]);

		(
			node.getNode() as unknown as {
				liftFundingMissingHold: (channelId: Buffer) => void;
			}
		).liftFundingMissingHold(channel.getChannelId()!);

		expect((await queueEntryOnceFinal(node, 'q-1-quarantine')).status).to.equal(
			'completed'
		);
		expect(payCalls).to.deep.equal([invoice.bolt11]);
	});

	// Review round 2 (C3): a closed channel counted as one that might yet
	// become usable, so a node whose only channel was closing waited for
	// good, and an interrupted payment needed no channel to settle.
	it('with only a FORCE_CLOSED channel, an interrupted payment settles against the durable record at once', async () => {
		injectReestablishingChannel(ChannelState.FORCE_CLOSED);
		const paid = invoiceFrom('paid before the channel closed');
		const storage = node.getStorage();
		const hashHex = paid.paymentHash.toString('hex');
		storage.savePayment(hashHex, {
			paymentHash: paid.paymentHash,
			preimage: paid.preimage,
			amountMsat: 1_000_000n,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now() - 2_000,
			completedAt: Date.now() - 1_000
		});
		storage.saveQueueEntry({
			id: 'q-1-closed',
			bolt11: paid.bolt11,
			priority: 5,
			status: 'dispatching',
			createdAt: Date.now() - 2_000
		});
		const payCalls = stubPayInvoiceSafe(node);

		node.listQueue();
		expect((await queueEntryOnceFinal(node, 'q-1-closed')).status).to.equal(
			'completed'
		);
		expect(payCalls).to.deep.equal([]);
	});

	it('a wait for a usable channel ends once the last live channel closes', async () => {
		const channel = injectReestablishingChannel();
		const invoice = invoiceFrom('restored, channel then closes');
		seedQueued('q-1-last-close', invoice.bolt11);
		const payCalls = stubPayInvoiceSafe(node);

		const start = sinon.spy(node.getPaymentQueue(), 'start');
		await settle(200);
		expect(start.callCount).to.equal(0);
		expect(payCalls).to.deep.equal([]);

		setState(channel, ChannelState.FORCE_CLOSED);
		node.getNode().emit('channel:force-closing', {
			channelId: channel.getChannelId(),
			initiator: 'remote'
		});
		await settle(200);

		// No live channel is left, so the queue starts rather than wait for
		// one for good. The restored row, whose amount is in its invoice,
		// then waits for capacity like any entry with an amount, instead of
		// being sent into "no route" unchecked (issue #981).
		expect(start.callCount).to.equal(1);
		expect(payCalls).to.deep.equal([]);
		expect(
			node.listQueue().find((e) => e.id === 'q-1-last-close')?.status
		).to.equal('queued');
	});

	// Review round 2 (P3).
	it('announces no channel:usable while a capsule restore rebuilds the node', async () => {
		const channel = injectReestablishingChannel(ChannelState.NORMAL);
		let usable = 0;
		node.on('channel:usable', () => usable++);
		const flags = node as unknown as { _resuming: boolean };
		flags._resuming = true;
		try {
			node
				.getNode()
				.getChannelManager()
				.emit('channel:reestablished', channel.getChannelId());
			await settle();
			expect(usable).to.equal(0);
		} finally {
			flags._resuming = false;
		}
		node
			.getNode()
			.getChannelManager()
			.emit('channel:reestablished', channel.getChannelId());
		await settle();
		expect(usable).to.equal(1);
	});
});

describe('POST /queue/add refuses an amount the queue could never check (issue #967)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let daemon: IStartedDaemon;
	let port: number;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-queue-route-'));
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
	});

	after(async () => {
		await daemon?.stop();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	for (const [label, extra] of [
		['a fractional amountSats', { amountSats: 1.5 }],
		['a string amountSats', { amountSats: '1000' }],
		['a negative maxFeeSats', { maxFeeSats: -1 }]
	] as Array<[string, Record<string, unknown>]>) {
		it(`answers 400 INVALID_PARAMS for ${label}, and queues nothing`, async () => {
			const res = await postJson(port, '/queue/add', {
				bolt11: invoiceFrom(label).bolt11,
				...extra
			});
			expect(res.status).to.equal(400);
			expect((res.body as { error?: { code?: string } }).error?.code).to.equal(
				'INVALID_PARAMS'
			);
			const listed = await postJson(port, '/queue', undefined, 'GET');
			expect(listed.body.result).to.deep.equal([]);
		});
	}
});
