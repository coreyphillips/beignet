/**
 * Payment amounts in sats add up to the balance (#1185).
 *
 * The balance, a payment's amountSats and its feeSats each truncated their
 * own msat figure, so a send paying 20,001.5 sats from a 50,000 sat balance
 * read -20,001 with a 1 sat fee while the balance fell to 29,998. An outgoing
 * amount is now what left the node, fees included, and it and the fee round
 * up; an MPP record reports the same figure as a single-path one.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's getPayment is stubbed with the record under test.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import {
	IPaymentInfo,
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

describe('payment sats add up to the balance (#1185)', function () {
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
				node: { getPayment: (hash: Buffer) => IPaymentInfo | undefined };
			}
		).node;
		engine.getPayment = (hash: Buffer): IPaymentInfo | undefined =>
			record && hash.equals(record.paymentHash) ? record : undefined;
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
});
