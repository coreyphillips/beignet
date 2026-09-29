/**
 * Outgoing payment sats round up and agree across surfaces (#1185).
 *
 * The balance, a payment's amountSats and its feeSats each truncated their
 * own msat figure, so a send paying 20,001.5 sats from a 50,000 sat balance
 * read -20,001 with a 1 sat fee while the balance fell to 29,998. An outgoing
 * amount is now what left the node, fees included, and it and the fee round
 * up; an MPP record reports the same figure as a single-path one, and the
 * proof, the stats and a rebalance's fee report what the history does.
 *
 * Rounding up makes one send agree with the balance when the balance held
 * whole sats before it. It does not make a whole history add up: sub-sat
 * remainders across several sends can differ from the balance by a sat.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's payment reads are stubbed with the record under test.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	IPaymentInfo,
	IPaymentProof,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import { IRouteHop } from '../../src/lightning/gossip/types';

// A refused loopback connect returns instantly, where the regtest default is
// a public host (see tests/cli/async-payment-limits.test.ts).
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65528,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const hop = (id: number, amountToForwardMsat: bigint): IRouteHop => ({
	pubkey: Buffer.alloc(33, id),
	shortChannelId: Buffer.alloc(8, id),
	amountToForwardMsat,
	outgoingCltvValue: 100,
	cltvExpiryDelta: 40,
	feeBaseMsat: 0,
	feeProportionalMillionths: 0
});

/** A route whose first hop receives `invoiceMsat + feeMsat`. */
const route = (
	invoiceMsat: bigint,
	feeMsat: bigint
): IPaymentInfo['route'] => ({
	hops: [hop(1, invoiceMsat + feeMsat), hop(2, invoiceMsat)],
	totalAmountMsat: invoiceMsat + feeMsat,
	totalFeeMsat: feeMsat,
	totalCltvDelta: 80
});

describe('outgoing payment sats round up and agree across surfaces (#1185)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;
	let record: IPaymentInfo | undefined;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-sats-rounding-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM
		});
		const engine = (
			node as unknown as {
				node: {
					getPayment: (hash: Buffer) => IPaymentInfo | undefined;
					getPaymentProof: (hash: Buffer) => IPaymentProof | null;
					listPayments: () => IPaymentInfo[];
					rebalanceChannel: (options: unknown) => Promise<{
						paymentHash: Buffer;
						feeMsat: bigint;
						hops: number;
					}>;
				};
			}
		).node;
		engine.getPayment = (hash: Buffer): IPaymentInfo | undefined =>
			record && hash.equals(record.paymentHash) ? record : undefined;
		// The engine builds a proof from the record: its amountMsat and route.
		engine.getPaymentProof = (hash: Buffer): IPaymentProof | null =>
			record && record.preimage && hash.equals(record.paymentHash)
				? {
						paymentHash: record.paymentHash,
						preimage: record.preimage,
						amountMsat: record.amountMsat,
						completedAt: record.completedAt ?? record.createdAt,
						route: record.route
				  }
				: null;
		engine.listPayments = (): IPaymentInfo[] => (record ? [record] : []);
		engine.rebalanceChannel = async (): Promise<{
			paymentHash: Buffer;
			feeMsat: bigint;
			hops: number;
		}> => ({
			paymentHash: crypto.randomBytes(32),
			feeMsat: 1_500n,
			hops: 2
		});
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	const report = (
		fields: Partial<IPaymentInfo> & Pick<IPaymentInfo, 'amountMsat'>
	): ReturnType<BeignetNode['getPayment']> => {
		record = {
			paymentHash: crypto.randomBytes(32),
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now(),
			completedAt: Date.now(),
			preimage: crypto.randomBytes(32),
			...fields
		};
		return node.getPayment(record.paymentHash.toString('hex'));
	};

	it('a single-path send with a fractional fee reads what the balance lost', () => {
		// The issue's shape: 20,000 sats paid with a 1,500 msat fee. The
		// record's amount is the first-hop amount, fees included.
		const info = report({
			amountMsat: 20_001_500n,
			route: route(20_000_000n, 1_500n)
		})!;
		expect(info.amountSats).to.equal(20_002);
		expect(info.feeSats).to.equal(2);
		const balanceBeforeMsat = 50_000_000n;
		const balanceAfterSats = Number((balanceBeforeMsat - 20_001_500n) / 1000n);
		expect(50_000 - info.amountSats).to.equal(balanceAfterSats);
	});

	it('an MPP send reports what left the node, as a single-path send does', () => {
		// The invoice amount in amountMsat, what the parts sent in sentMsat;
		// the route is the first part only.
		const info = report({
			amountMsat: 20_000_000n,
			sentMsat: 20_001_500n,
			route: route(10_000_000n, 700n)
		})!;
		expect(info.amountSats).to.equal(20_002);
		expect(info.feeSats).to.equal(2);
	});

	it('a whole-sat fee reads as before', () => {
		const info = report({
			amountMsat: 20_001_000n,
			route: route(20_000_000n, 1_000n)
		})!;
		expect(info.amountSats).to.equal(20_001);
		expect(info.feeSats).to.equal(1);
	});

	it('an incoming amount still rounds down, as the balance does', () => {
		const info = report({
			amountMsat: 20_000_500n,
			direction: PaymentDirection.INCOMING
		})!;
		expect(info.amountSats).to.equal(20_000);
		expect(info.feeSats).to.equal(undefined);
	});

	it('the proof and the stats report the history figures, single-path and MPP', () => {
		const shapes: Array<
			Partial<IPaymentInfo> & Pick<IPaymentInfo, 'amountMsat'>
		> = [
			{ amountMsat: 20_001_500n, route: route(20_000_000n, 1_500n) },
			{
				amountMsat: 20_000_000n,
				sentMsat: 20_001_500n,
				route: route(10_000_000n, 700n)
			}
		];
		for (const fields of shapes) {
			const info = report(fields)!;
			expect(info.amountSats).to.equal(20_002);
			expect(info.feeSats).to.equal(2);
			const proof = node.getPaymentProof(info.paymentHash)!;
			expect(proof.amountSats).to.equal(info.amountSats);
			expect(proof.feeSats).to.equal(info.feeSats);
			const stats = node.getStats();
			expect(stats.totalSatsSent).to.equal(info.amountSats);
			expect(stats.totalFeesPaid).to.equal(info.feeSats);
		}
	});

	it("a rebalance's fee rounds up as its history row does", async () => {
		const result = await node.rebalanceChannel(
			'aa'.repeat(32),
			'bb'.repeat(32),
			10_000,
			10
		);
		expect(result.feeMsat).to.equal('1500');
		expect(result.feeSats).to.equal(2);
	});

	it('several sends with sub-sat fees can read a sat more than the balance lost', () => {
		// Per-payment rounding reconciles one send from a whole-sat balance,
		// not a whole history: two 1,500 msat fees read 2 + 2, while the
		// floored balance falls by 3. Only msat figures add up exactly.
		const first = report({
			amountMsat: 1_001_500n,
			route: route(1_000_000n, 1_500n)
		})!;
		const second = report({
			amountMsat: 1_001_500n,
			route: route(1_000_000n, 1_500n)
		})!;
		const balanceBeforeMsat = 50_000_000n;
		const balanceAfterSats = Number(
			(balanceBeforeMsat - 2n * 1_001_500n) / 1000n
		);
		expect(first.amountSats + second.amountSats).to.equal(2_004);
		expect(50_000 - balanceAfterSats).to.equal(2_003);
	});
});
