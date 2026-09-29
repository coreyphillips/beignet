/**
 * Per-hop route fees in the payment record (issue #1056).
 *
 * GET /payment and the library's getPayment reported route.hops[].feeMsat
 * as each hop's fee_base_msat, so a route paying 753 msat over 0-base hops
 * read 0 at every hop. The field is the fee the hop kept: what it received
 * less what it forwarded, 0 at the final hop, and the hops sum to
 * totalFeeMsat.
 *
 * Offline suite: the node boots against an unreachable Electrum server and
 * the engine's getPayment is stubbed with a record carrying a route.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode, hopFeeMsat } from '../../src/cli/beignet-node';
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
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** A route hop that receives `amountToForwardMsat` and advertises `feeBaseMsat`. */
const hop = (
	id: number,
	amountToForwardMsat: bigint,
	feeBaseMsat: number
): IRouteHop => ({
	pubkey: Buffer.alloc(33, id),
	shortChannelId: Buffer.alloc(8, id),
	amountToForwardMsat,
	outgoingCltvValue: 100,
	cltvExpiryDelta: 40,
	feeBaseMsat,
	feeProportionalMillionths: 0
});

describe('route.hops[].feeMsat is the fee each hop kept (#1056)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-hop-fee-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM
		});
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('hopFeeMsat is received less forwarded, 0 at the final hop and for a record without hop amounts', () => {
		const hops = [
			hop(1, 1_000_753n, 0),
			hop(2, 1_000_500n, 0),
			hop(3, 1_000_000n, 1000)
		];
		expect(hopFeeMsat(hops, 0)).to.equal(253);
		expect(hopFeeMsat(hops, 1)).to.equal(500);
		expect(hopFeeMsat(hops, 2)).to.equal(0);
		expect(hopFeeMsat([{}, {}], 0)).to.equal(0);
	});

	it("getPayment reports each hop's fee, not its fee_base_msat, and the hops sum to totalFeeMsat", () => {
		const paymentHash = crypto.randomBytes(32);
		// The issue's shape: a route paying 753 msat over hops whose
		// advertised base fee is 0. Hop 1 keeps 253, hop 2 keeps 500, hop 3
		// keeps nothing, and the final hop (whose base fee, 1000, is what
		// the field used to report) keeps nothing either.
		const hops = [
			hop(1, 1_000_753n, 0),
			hop(2, 1_000_500n, 0),
			hop(3, 1_000_000n, 0),
			hop(4, 1_000_000n, 1000)
		];
		const record: IPaymentInfo = {
			paymentHash,
			amountMsat: 1_000_000n,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now(),
			completedAt: Date.now(),
			route: {
				hops,
				totalAmountMsat: 1_000_753n,
				totalFeeMsat: 753n,
				totalCltvDelta: 160
			}
		};
		const engine = (
			node as unknown as {
				node: { getPayment: (hash: Buffer) => IPaymentInfo | undefined };
			}
		).node;
		engine.getPayment = (hash: Buffer): IPaymentInfo | undefined =>
			hash.equals(paymentHash) ? record : undefined;

		const info = node.getPayment(paymentHash.toString('hex'))!;
		expect(info.route, 'the route is reported').to.not.equal(undefined);
		expect(info.route!.hops.map((h) => h.feeMsat)).to.deep.equal([
			253, 500, 0, 0
		]);
		expect(info.route!.totalFeeMsat).to.equal(753);
		expect(info.route!.hops.reduce((sum, h) => sum + h.feeMsat, 0)).to.equal(
			753
		);
		expect(info.route!.hopCount).to.equal(4);
		// 753 msat rounds up to 1 sat: it left the node (#1185).
		expect(info.feeSats).to.equal(1);
	});
});
