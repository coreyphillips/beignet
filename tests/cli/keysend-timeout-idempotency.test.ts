/**
 * Issue #1133: a keyed POST /keysend that timed out with its HTLC still out
 * was cached as a plain 504 envelope, which the idempotency sweep drops at the
 * 24 hour TTL. A retry after that ran sendKeysend again, and the engine picks
 * a fresh preimage per keysend, so the second payment had a new hash that no
 * duplicate check could tie to the first, and both could settle.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's sendKeysend is stubbed to leave a PENDING record for a fresh
 * hash on every call, with an HTLC out until the test resolves it.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { BeignetNode } from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

// Same rationale as tests/cli/pay-offer-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

type Engine = {
	payments: Map<string, IPaymentInfo>;
	sendKeysend: (...args: unknown[]) => unknown;
	hasHtlcInFlight: (paymentHash: Buffer) => boolean;
	emit: (event: string, info: unknown) => boolean;
};

type Reply = { status: number; body: Record<string, unknown> };

/** POST /keysend with the body, and the status and parsed envelope it got. */
const postKeysend = (
	port: number,
	body: Record<string, unknown>,
	headers: Record<string, string>
): Promise<Reply> =>
	new Promise((resolve, reject) => {
		const payload = JSON.stringify(body);
		const req = http.request(
			{
				hostname: '127.0.0.1',
				port,
				path: '/keysend',
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(payload),
					...headers
				}
			},
			(res) => {
				const chunks: Buffer[] = [];
				res.on('data', (chunk: Buffer) => chunks.push(chunk));
				res.on('end', () => {
					resolve({
						status: res.statusCode!,
						body: JSON.parse(Buffer.concat(chunks).toString())
					});
				});
			}
		);
		req.on('error', reject);
		req.write(payload);
		req.end();
	});

const errorOf = (reply: Reply): { code: string; paymentHash?: string } =>
	reply.body.error as { code: string; paymentHash?: string };

describe('keyed POST /keysend after a timeout (#1133)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;

	/** The hash of every keysend the engine was asked to send. */
	let sent: string[];
	/** Hashes with an HTLC still out. */
	let htlcsOut: Set<string>;

	const engine = (): Engine => (node as unknown as { node: Engine }).node;

	/** The daemon's idempotency cache sweep, run by hand instead of on its timer. */
	let sweepIdempotency: (() => void) | undefined;

	/** Runs the sweep as it would run 25 hours from now, past the TTL. */
	const sweepPastTtl = (): number => {
		expect(sweepIdempotency, 'the cache sweep was captured').to.be.a(
			'function'
		);
		const realNow = Date.now;
		const later = realNow() + 25 * 60 * 60 * 1000;
		Date.now = (): number => later;
		try {
			sweepIdempotency!();
		} finally {
			Date.now = realNow;
		}
		return later;
	};

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-keysend-1133-'));
		const realSetInterval = global.setInterval;
		global.setInterval = ((fn: () => void, ...rest: unknown[]) => {
			if (String(fn).includes('idempotencyCache')) sweepIdempotency = fn;
			return (realSetInterval as (...args: unknown[]) => unknown)(fn, ...rest);
		}) as unknown as typeof setInterval;
		try {
			({ server, node } = await startDaemon({
				mnemonic: MNEMONIC,
				network: 'regtest',
				dataDir: tmpDir,
				logLevel: 'silent',
				rapidGossipSync: false,
				autoGossipSync: false,
				daemonPort: 0,
				...OFFLINE_ELECTRUM
			}));
		} finally {
			global.setInterval = realSetInterval;
		}
		port = (server.address() as AddressInfo).port;
	});

	after(async () => {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	beforeEach(() => {
		sent = [];
		htlcsOut = new Set();
		const e = engine();
		e.sendKeysend = (...args: unknown[]): IPaymentInfo => {
			const { preimage } = args[0] as { preimage: Buffer };
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const hashHex = paymentHash.toString('hex');
			const record: IPaymentInfo = {
				paymentHash,
				amountMsat: 1_000_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now()
			};
			e.payments.set(hashHex, record);
			htlcsOut.add(hashHex);
			sent.push(hashHex);
			return record;
		};
		e.hasHtlcInFlight = (hash: Buffer): boolean =>
			htlcsOut.has(hash.toString('hex'));
	});

	/** The HTLC resolves: the record ends and the engine event fires. */
	const resolveHtlc = (
		hashHex: string,
		status: 'COMPLETED' | 'FAILED'
	): void => {
		const record = engine().payments.get(hashHex)!;
		record.status =
			status === 'COMPLETED' ? PaymentStatus.COMPLETED : PaymentStatus.FAILED;
		record.completedAt = Date.now();
		htlcsOut.delete(hashHex);
		engine().emit(
			status === 'COMPLETED' ? 'payment:sent' : 'payment:failed',
			record
		);
	};

	const body = { pubkey: '02' + '11'.repeat(32), amountSats: 1_000 };

	it('does not send again past the idempotency TTL while the first HTLC is out, and answers it once settled', async () => {
		const request = { ...body, timeoutMs: 50 };
		const headers = { 'X-Idempotency-Key': `keysend-ttl-${Date.now()}` };

		const timedOut = await postKeysend(port, request, headers);
		expect(timedOut.status).to.equal(504);
		expect(errorOf(timedOut).code).to.equal('PAYMENT_TIMEOUT');
		expect(sent).to.have.length(1);
		const [first] = sent;
		expect(
			errorOf(timedOut).paymentHash,
			'the timeout names the payment to look up'
		).to.equal(first);

		const sweptAt = sweepPastTtl();
		const stored = node
			.getStorage()
			.loadWalletData('daemon:payment-timeout-markers:v1');
		expect(stored).to.not.equal(null);
		const markers = JSON.parse(stored!) as Record<
			string,
			{ expiresAt: number }
		>;
		expect(
			markers[`POST /keysend:${headers['X-Idempotency-Key']}`].expiresAt
		).to.be.greaterThan(sweptAt);

		const retried = await postKeysend(port, request, headers);
		expect(retried.status).to.equal(409);
		expect(errorOf(retried).code).to.equal('DUPLICATE_PAYMENT');
		expect(errorOf(retried).paymentHash).to.equal(first);
		expect(sent, 'the retry sent a second keysend').to.have.length(1);

		resolveHtlc(first, 'COMPLETED');
		const settled = await postKeysend(port, request, headers);
		expect(settled.status).to.equal(200);
		const result = settled.body.result as {
			paymentHash: string;
			status: string;
		};
		expect(result.paymentHash).to.equal(first);
		expect(result.status).to.equal('COMPLETED');
		expect(sent).to.have.length(1);
	});

	it('sends again under the key once the timed-out keysend failed', async () => {
		const request = { ...body, timeoutMs: 50 };
		const headers = { 'X-Idempotency-Key': `keysend-fails-${Date.now()}` };

		expect((await postKeysend(port, request, headers)).status).to.equal(504);
		const [first] = sent;
		resolveHtlc(first, 'FAILED');

		// Nothing sent for the first can settle now, so the retry is a new
		// keysend under a new hash.
		const rerun = await postKeysend(port, request, headers);
		expect(rerun.status).to.equal(504);
		expect(sent).to.have.length(2);
		expect(errorOf(rerun).paymentHash).to.equal(sent[1]);
		expect(sent[1]).to.not.equal(first);
	});

	// Issue #1153: stored before the HTLC goes out, so a daemon stopped before
	// the timeout still leaves the retry after a restart its marker.
	it('stores the keysend in flight under its hash until the request answers', async () => {
		const headers = { 'X-Idempotency-Key': `keysend-in-flight-${Date.now()}` };
		const cacheKey = `POST /keysend:${headers['X-Idempotency-Key']}`;
		const storedMarkers = (): Record<string, { paymentHash: string }> =>
			JSON.parse(
				node.getStorage().loadWalletData('daemon:payment-timeout-markers:v1') ??
					'{}'
			);

		const dispatch = engine().sendKeysend;
		let storedAtDispatch: string | undefined;
		engine().sendKeysend = (...args: unknown[]): unknown => {
			storedAtDispatch = storedMarkers()[cacheKey]?.paymentHash;
			return dispatch(...args);
		};
		const reply = postKeysend(port, { ...body, timeoutMs: 60_000 }, headers);
		for (let i = 0; sent.length === 0 && i < 250; i++) {
			await new Promise((resolve) => setTimeout(resolve, 20));
		}
		expect(sent).to.have.length(1);
		expect(storedAtDispatch, 'stored before the HTLC went out').to.equal(
			sent[0]
		);

		resolveHtlc(sent[0], 'COMPLETED');
		expect((await reply).status).to.equal(200);
		expect(storedMarkers()).to.not.have.property(cacheKey);
	});

	it('refuses the keysend when its hash cannot be stored', async () => {
		const headers = { 'X-Idempotency-Key': `keysend-unstored-${Date.now()}` };
		const storage = node.getStorage();
		const save = storage.saveWalletData;
		storage.saveWalletData = (key: string, value: string): void => {
			if (key === 'daemon:payment-timeout-markers:v1') {
				throw new Error('disk full');
			}
			save.call(storage, key, value);
		};
		// The daemon reports the failed write on stderr.
		const write = process.stderr.write;
		process.stderr.write = ((): boolean => true) as typeof write;
		let reply: Reply;
		try {
			reply = await postKeysend(port, { ...body, timeoutMs: 1_000 }, headers);
		} finally {
			storage.saveWalletData = save;
			process.stderr.write = write;
		}
		expect(reply.status).to.equal(503);
		expect(errorOf(reply).code).to.equal('NOT_PERSISTED');
		expect(sent, 'the keysend went out').to.have.length(0);
	});
});
