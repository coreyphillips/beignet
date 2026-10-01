/**
 * sendToRoute admission (issue #1017): sendToRoute and the
 * POST /payment/send-to-route route apply drain mode, the per-payment and
 * daily spending limits, and the same claim on the daily budget every other
 * pay path opens, all on what the first hop carries, which is exactly what
 * leaves this node. Before this the route ran only the drain check, and its
 * settlement, finding no claim, was never charged.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's sendPaymentToRoute is stubbed, so nothing here needs a chain
 * or a channel. Structure follows tests/cli/async-payment-limits.test.ts.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { AddressInfo } from 'net';
import { AsyncSpendClaim, BeignetNode } from '../../src/cli/beignet-node';
import { startDaemon } from '../../src/cli/daemon';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';
import { RouteHop } from '../../src/cli/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

// Same rationale as tests/cli/async-payment-limits.test.ts: a refused loopback
// connect returns instantly, where the regtest default is a public host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const HOP_PUBKEY = getPublicKey(Buffer.alloc(32, 3)).toString('hex');
const DEST_PUBKEY = getPublicKey(Buffer.alloc(32, 5)).toString('hex');

/** What the engine was asked to send. */
type RouteCall = {
	paymentHash: string;
	firstHopMsat: bigint;
	totalMsat: bigint | undefined;
	route: { totalAmountMsat?: bigint; totalFeeMsat?: bigint };
};

type StubbedEngine = {
	payments: Map<string, IPaymentInfo>;
	sendPaymentToRoute: (...args: unknown[]) => unknown;
	hasHtlcInFlight: (paymentHash: Buffer) => boolean;
	emit: (event: string, info: unknown) => boolean;
};

type Internals = {
	node: StubbedEngine;
	_pendingSpendSats: number;
	_asyncSpendClaims: Map<string, AsyncSpendClaim[]>;
};

const internals = (node: BeignetNode): Internals =>
	node as unknown as Internals;

/** Sats the claims of a hash still hold against the daily budget. */
const claimedSats = (node: BeignetNode, paymentHash: string): number =>
	(internals(node)._asyncSpendClaims.get(paymentHash) ?? [])
		.filter((claim) => claim.reserved)
		.reduce((total, claim) => total + claim.sats, 0);

/** Claim records for a hash, reserved or not. */
const claimRecords = (node: BeignetNode, paymentHash: string): number =>
	(internals(node)._asyncSpendClaims.get(paymentHash) ?? []).length;

/**
 * What the engine answers about the HTLCs behind a hash (issue #977).
 * Without a channel the real predicate answers false.
 */
const holdHtlcsInFlight = (node: BeignetNode, inFlight: boolean): void => {
	internals(node).node.hasHtlcInFlight = (): boolean => inFlight;
};

/** A two-hop route: the first hop carries `firstMsat`, the final `finalMsat`. */
const routeOf = (
	firstMsat: bigint | string,
	finalMsat: bigint | string
): { hops: RouteHop[] } => ({
	hops: [
		{
			pubkey: HOP_PUBKEY,
			shortChannelId: '500x1x0',
			amountToForwardMsat: String(firstMsat),
			outgoingCltvValue: 80,
			feeMsat: '0',
			cltvExpiryDelta: 40
		},
		{
			pubkey: DEST_PUBKEY,
			shortChannelId: '600x1x0',
			amountToForwardMsat: String(finalMsat),
			outgoingCltvValue: 40,
			feeMsat: '0',
			cltvExpiryDelta: 40
		}
	]
});

/**
 * Replaces sendPaymentToRoute with a recorder that leaves the record the
 * engine would (in its payments map, so getPayment finds it) and returns it.
 * `status` is what the engine hands back synchronously; `throws` refuses the
 * send before any record exists.
 */
const stubSendToRoute = (
	node: BeignetNode,
	opts: { throws?: Error; status?: PaymentStatus } = {}
): RouteCall[] => {
	const calls: RouteCall[] = [];
	const engine = internals(node).node;
	engine.sendPaymentToRoute = (...args: unknown[]): IPaymentInfo => {
		const route = args[0] as {
			hops: Array<{ amountToForwardMsat: bigint }>;
			totalAmountMsat?: bigint;
			totalFeeMsat?: bigint;
		};
		const paymentHash = args[1] as Buffer;
		calls.push({
			paymentHash: paymentHash.toString('hex'),
			firstHopMsat: route.hops[0].amountToForwardMsat,
			totalMsat: args[4] as bigint | undefined,
			route
		});
		if (opts.throws) throw opts.throws;
		const record: IPaymentInfo = {
			paymentHash,
			amountMsat: route.hops[0].amountToForwardMsat,
			status: opts.status ?? PaymentStatus.PENDING,
			direction: PaymentDirection.OUTGOING,
			route: route as IPaymentInfo['route'],
			createdAt: Date.now()
		};
		engine.payments.set(paymentHash.toString('hex'), record);
		return record;
	};
	return calls;
};

/** The payee settles: the record completes and payment:sent fires. */
const settle = (
	node: BeignetNode,
	paymentHash: string,
	status: 'COMPLETED' | 'FAILED' = 'COMPLETED'
): void => {
	const engine = internals(node).node;
	const record = engine.payments.get(paymentHash);
	expect(record, 'the record the settlement completes').to.not.equal(undefined);
	record!.status =
		status === 'COMPLETED' ? PaymentStatus.COMPLETED : PaymentStatus.FAILED;
	record!.completedAt = Date.now();
	engine.emit(
		status === 'COMPLETED' ? 'payment:sent' : 'payment:failed',
		record
	);
};

const randomHash = (): string => crypto.randomBytes(32).toString('hex');

/** Run `fn`, returning the BeignetError it threw. Fails if it threw anything else. */
const refusalFrom = (fn: () => unknown): BeignetError => {
	try {
		fn();
	} catch (err: unknown) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	return expect.fail('expected a refusal');
};

describe('sendToRoute admission and spend accounting (#1017)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	const pending = (): number => internals(node)._pendingSpendSats;
	const spent = (): number => node.getDailySpendInfo().spentSats;

	beforeEach(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-send-to-route-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			...OFFLINE_ELECTRUM
		});
	});

	afterEach(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('refuses a route while draining, without reaching the engine', () => {
		const calls = stubSendToRoute(node);
		node.setDraining(true);
		const err = refusalFrom(() =>
			node.sendToRoute(randomHash(), routeOf(1_000_000n, 1_000_000n))
		);
		expect(err.code).to.equal('SERVICE_DRAINING');
		expect(calls).to.have.length(0);
		expect(pending()).to.equal(0);
	});

	it('refuses a route over the per-payment limit without reaching the engine', () => {
		const calls = stubSendToRoute(node);
		// 5 001 sats leave over the first hop, whatever the final hop gets.
		const err = refusalFrom(() =>
			node.sendToRoute(randomHash(), routeOf(5_001_000n, 4_000_000n))
		);
		expect(err.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(err.message).to.equal(
			'Payment amount 5001 sats exceeds per-payment limit of 5000 sats'
		);
		expect(calls).to.have.length(0);
		expect(pending()).to.equal(0);
	});

	it('reserves what the first hop carries so concurrent routes cannot overshoot the daily limit', () => {
		const calls = stubSendToRoute(node);
		node.sendToRoute(randomHash(), routeOf(4_000_000n, 3_990_000n));
		node.sendToRoute(randomHash(), routeOf(4_000_000n, 3_990_000n));
		expect(pending()).to.equal(8_000);
		expect(spent()).to.equal(0);

		const err = refusalFrom(() =>
			node.sendToRoute(randomHash(), routeOf(4_000_000n, 3_990_000n))
		);
		expect(err.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(err.message).to.contain('requested: 4000 sats');
		expect(calls).to.have.length(2);
	});

	it('reserves the first hop in sats, fees included, and reports a finite fee', () => {
		const calls = stubSendToRoute(node);
		const paymentHash = randomHash();
		const info = node.sendToRoute(paymentHash, routeOf(3_010_000n, 3_000_000n));
		expect(claimedSats(node, paymentHash)).to.equal(3_010);
		expect(pending()).to.equal(3_010);
		expect(node.getDailySpendInfo().pendingSats).to.equal(3_010);
		// The engine was handed the route with its totals, so the record
		// carries a real fee rather than NaN.
		expect(calls[0].route.totalAmountMsat?.toString()).to.equal('3010000');
		expect(calls[0].route.totalFeeMsat?.toString()).to.equal('10000');
		expect(calls[0].totalMsat?.toString()).to.equal('3000000');
		expect(info.feeSats).to.equal(10);
		expect(info.route?.totalFeeMsat).to.equal(10_000);
		expect(
			Number.isFinite(node.getPayment(paymentHash)!.route!.totalFeeMsat)
		).to.equal(true);
	});

	it('closes the claim when the engine throws', () => {
		stubSendToRoute(node, {
			throws: Object.assign(new Error('No channel to first hop'), {
				code: 'NO_CHANNEL_TO_HOP'
			})
		});
		const paymentHash = randomHash();
		const err = refusalFrom(() =>
			node.sendToRoute(paymentHash, routeOf(3_000_000n, 3_000_000n))
		);
		expect(err.code).to.equal('NO_CHANNEL_TO_HOP');
		// A payment that never started holds no capacity.
		expect(pending()).to.equal(0);
		expect(claimRecords(node, paymentHash)).to.equal(0);
	});

	it('releases the reservation when the engine reports a failure by return', () => {
		stubSendToRoute(node, { status: PaymentStatus.FAILED });
		const paymentHash = randomHash();
		const info = node.sendToRoute(paymentHash, routeOf(3_000_000n, 3_000_000n));
		expect(info.status).to.equal('FAILED');
		expect(pending()).to.equal(0);
		expect(claimedSats(node, paymentHash)).to.equal(0);
		// The record stays, for a settlement that still arrives.
		expect(claimRecords(node, paymentHash)).to.equal(1);
	});

	it('charges the first hop once when the payment settles', () => {
		stubSendToRoute(node);
		const paymentHash = randomHash();
		node.sendToRoute(paymentHash, routeOf(3_010_000n, 3_000_000n));
		expect(pending()).to.equal(3_010);

		settle(node, paymentHash);
		// Before the fix no claim existed for the hash, so the settlement was
		// charged to nobody and the day stayed at zero.
		expect(spent()).to.equal(3_010);
		expect(node.getDailySpendInfo().lightningSats).to.equal(3_010);
		expect(pending()).to.equal(0);
		expect(claimRecords(node, paymentHash)).to.equal(0);

		// A repeated terminal event must not count the payment twice.
		settle(node, paymentHash);
		expect(spent()).to.equal(3_010);
	});

	it("keeps a failed route's reservation while its HTLC is still out, and releases it once nothing is", () => {
		stubSendToRoute(node);
		const paymentHash = randomHash();
		node.sendToRoute(paymentHash, routeOf(3_000_000n, 3_000_000n));

		holdHtlcsInFlight(node, true);
		settle(node, paymentHash, 'FAILED');
		expect(pending()).to.equal(3_000);

		holdHtlcsInFlight(node, false);
		settle(node, paymentHash, 'FAILED');
		expect(pending()).to.equal(0);
		expect(spent()).to.equal(0);
	});

	it('keys the claim by the lowercase hash whatever case the caller used', () => {
		const calls = stubSendToRoute(node);
		const paymentHash = randomHash();
		node.sendToRoute(
			paymentHash.toUpperCase(),
			routeOf(3_010_000n, 3_000_000n)
		);
		// The engine reports the hash as lowercase hex, and that is where the
		// settlement looks for the claim.
		expect(calls[0].paymentHash).to.equal(paymentHash);
		expect(claimedSats(node, paymentHash)).to.equal(3_010);
		expect(claimedSats(node, paymentHash.toUpperCase())).to.equal(0);

		settle(node, paymentHash);
		expect(spent()).to.equal(3_010);
		expect(pending()).to.equal(0);
	});

	it('refuses a first hop below the final amount, and a negative amount, as INVALID_PARAMS', () => {
		const calls = stubSendToRoute(node);
		const below = refusalFrom(() =>
			node.sendToRoute(randomHash(), routeOf(2_999_000n, 3_000_000n))
		);
		expect(below.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		expect(below.message).to.contain('route.hops[0].amountToForwardMsat');

		const negative = refusalFrom(() =>
			node.sendToRoute(randomHash(), routeOf('-1', '-1'))
		);
		expect(negative.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		expect(negative.message).to.contain('must not be negative');

		expect(calls).to.have.length(0);
		expect(pending()).to.equal(0);
	});
});

describe('POST /payment/send-to-route admission (#1017)', function () {
	this.timeout(60_000);

	let tmpDir: string;
	let server: http.Server;
	let node: BeignetNode;
	let port: number;
	let calls: RouteCall[];

	const post = (
		body: Record<string, unknown>
	): Promise<{ status: number; body: Record<string, unknown> }> =>
		new Promise((resolve, reject) => {
			const payload = JSON.stringify(body);
			const req = http.request(
				{
					hostname: '127.0.0.1',
					port,
					path: '/payment/send-to-route',
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Content-Length': Buffer.byteLength(payload)
					}
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
						} catch {
							resolve({ status: res.statusCode!, body: {} });
						}
					});
				}
			);
			req.on('error', reject);
			req.write(payload);
			req.end();
		});

	const errorCode = (body: Record<string, unknown>): string =>
		(body.error as { code: string }).code;

	before(async () => {
		tmpDir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'beignet-send-to-route-api-')
		);
		({ server, node } = await startDaemon({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			daemonPort: 0,
			dailySpendLimitSats: 10_000,
			maxPaymentSats: 5_000,
			...OFFLINE_ELECTRUM
		}));
		port = (server.address() as AddressInfo).port;
		calls = stubSendToRoute(node);
	});

	after(async () => {
		server?.close();
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('answers 403 SPENDING_LIMIT_EXCEEDED over the per-payment limit', async () => {
		const res = await post({
			paymentHash: randomHash(),
			route: routeOf(5_001_000n, 4_000_000n)
		});
		expect(res.status).to.equal(403);
		expect(errorCode(res.body)).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(calls).to.have.length(0);
	});

	it('answers 400 INVALID_PARAMS for a first hop below the final amount', async () => {
		const res = await post({
			paymentHash: randomHash(),
			route: routeOf(2_999_000n, 3_000_000n)
		});
		expect(res.status).to.equal(400);
		expect(errorCode(res.body)).to.equal('INVALID_PARAMS');
		expect(calls).to.have.length(0);
	});

	it('reserves an accepted route against the daily budget', async () => {
		const accepted = await post({
			paymentHash: randomHash(),
			route: routeOf(4_000_000n, 3_990_000n)
		});
		expect(accepted.body.ok).to.equal(true);
		expect(calls).to.have.length(1);
		expect(internals(node)._pendingSpendSats).to.equal(4_000);

		const overshoot = await post({
			paymentHash: randomHash(),
			route: routeOf(4_000_000n, 3_990_000n)
		});
		expect(overshoot.body.ok).to.equal(true);
		const refused = await post({
			paymentHash: randomHash(),
			route: routeOf(4_000_000n, 3_990_000n)
		});
		expect(refused.status).to.equal(403);
		expect(errorCode(refused.body)).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(calls).to.have.length(2);
	});
});
