/**
 * Issue #978: one payment queue per process. The daemon built its own
 * PaymentQueue over the payment_queue table while BeignetNode built another
 * on the first enqueuePayment/listQueue/cancelQueuedPayment, so an embedder
 * touching a daemon's node got two queues restoring and dispatching the same
 * rows, and an entry enqueued on one side was invisible to the other. The
 * daemon now serves the node's queue.
 *
 * Offline suite: the node boots against an unreachable Electrum server; the
 * channel that releases a held payment is injected into the channel manager.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
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

const TOKEN = 'single-queue-token';

// A refused loopback connect returns instantly, where the regtest default is
// a public host (the pay-invoice-limits pattern).
const BOOT = {
	mnemonic:
		'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
	network: 'regtest' as const,
	logLevel: 'silent' as const,
	rapidGossipSync: false,
	autoGossipSync: false,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

/** An invoice from somebody else. */
const invoiceFrom = (description: string): string =>
	encodeInvoice({
		network: Network.REGTEST,
		amountMsat: 1_000_000n,
		timestamp: Math.floor(Date.now() / 1000),
		paymentHash: crypto.randomBytes(32),
		paymentSecret: crypto.randomBytes(32),
		description,
		expiry: 3600,
		minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
		privateKey: crypto
			.createHash('sha256')
			.update(Buffer.from(`payee-${description}`))
			.digest()
	});

const settle = (ms = 20): Promise<void> =>
	new Promise((resolve) => setTimeout(resolve, ms));

/** One authenticated request to the daemon, JSON in and out. */
const request = (
	port: number,
	method: string,
	urlPath: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> =>
	new Promise((resolve, reject) => {
		const payload = body ? JSON.stringify(body) : undefined;
		const headers: Record<string, string | number> = {
			Authorization: `Bearer ${TOKEN}`
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

const listedIds = async (port: number): Promise<string[]> => {
	const res = await request(port, 'GET', '/queue');
	expect(res.status).to.equal(200);
	return (res.body.result as QueuedPayment[]).map((e) => e.id);
};

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

/** A NORMAL channel with a spendable local balance, straight into the manager. */
const injectUsableChannel = (node: BeignetNode): Channel => {
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
	state.state = ChannelState.NORMAL;
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

describe('The daemon and BeignetNode run one payment queue (issue #978)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let daemon: IStartedDaemon | undefined;
	let port: number;

	const boot = async (): Promise<void> => {
		daemon = await startDaemon({
			...BOOT,
			dataDir: tmpDir,
			daemonPort: 0,
			apiToken: TOKEN
		});
		port = (daemon.server.address() as AddressInfo).port;
	};

	beforeEach(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-single-queue-'));
		daemon = undefined;
	});

	afterEach(async () => {
		await daemon?.stop();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('an entry enqueued through the node is listed by GET /queue, one added through POST /queue/add by listQueue, and a cancel on either side is seen by the other', async () => {
		await boot();
		const node = daemon!.node;
		// With no channel, canSend holds an entry with an amount back: it
		// stays queued.
		const viaNode = node.enqueuePayment(invoiceFrom('via the node'), 5, {
			amountSats: 1_000
		});
		expect(await listedIds(port)).to.deep.equal([viaNode.id]);

		const added = await request(port, 'POST', '/queue/add', {
			bolt11: invoiceFrom('via the route'),
			amountSats: 1_000
		});
		expect(added.status, JSON.stringify(added.body)).to.equal(200);
		const viaRoute = (added.body.result as QueuedPayment).id;
		expect(
			node
				.listQueue()
				.map((e) => e.id)
				.sort()
		).to.deep.equal([viaNode.id, viaRoute].sort());

		expect(node.cancelQueuedPayment(viaRoute)).to.equal(true);
		expect(await listedIds(port)).to.deep.equal([viaNode.id]);
		const cancelled = await request(port, 'POST', '/queue/cancel', {
			id: viaNode.id
		});
		expect(cancelled.status, JSON.stringify(cancelled.body)).to.equal(200);
		expect(node.listQueue()).to.deep.equal([]);
	});

	it('a restored row is dispatched exactly once when the embedder lists the queue too, and both sides see the same outcome', async () => {
		// Run 1 leaves a queued row, as a stop before the payment could go
		// out does.
		const bolt11 = invoiceFrom('restored');
		const seeded = await BeignetNode.create({ ...BOOT, dataDir: tmpDir });
		try {
			seeded.getStorage().saveQueueEntry({
				id: 'q-1-restored',
				bolt11,
				priority: 5,
				status: 'queued',
				amountSats: 1_000,
				createdAt: Date.now() - 1_000
			});
		} finally {
			await seeded.destroy();
		}

		await boot();
		const node = daemon!.node;
		const payCalls = stubPayInvoiceSafe(node);
		// The embedder's view of the queue. Before the fix this built a
		// second PaymentQueue over the same table, restoring the row again.
		expect(node.listQueue().map((e) => e.id)).to.deep.equal(['q-1-restored']);
		expect(await listedIds(port)).to.deep.equal(['q-1-restored']);
		// The node is ready to pay (no channel), so every queue has started;
		// the row is held back by canSend until a channel can carry it.
		await settle(200);
		expect(payCalls).to.deep.equal([]);

		const channel = injectUsableChannel(node);
		node
			.getNode()
			.getChannelManager()
			.emit('channel:reestablished', channel.getChannelId());

		expect((await queueEntryOnceFinal(node, 'q-1-restored')).status).to.equal(
			'completed'
		);
		// Long enough for a second queue's dispatch to show.
		await settle(300);
		expect(payCalls).to.deep.equal([bolt11]);
		const listed = await request(port, 'GET', '/queue');
		expect(
			(listed.body.result as QueuedPayment[]).map((e) => [e.id, e.status])
		).to.deep.equal([['q-1-restored', 'completed']]);
		expect(
			node
				.getStorage()
				.loadAllQueueEntries()
				.map((r) => r.status)
		).to.deep.equal(['completed']);
	});
});
