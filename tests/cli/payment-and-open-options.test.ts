/**
 * Issue #1694: payInvoice and payInvoiceSafe took seven positional
 * parameters, four of them plain numbers, and openChannel six with two
 * booleans. Each now takes an options object; the positional form is
 * deprecated and must reach the engine with the same arguments.
 */

import { expect } from 'chai';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';
import { BeignetNode } from '../../src/cli/beignet-node';

const PUBKEY = '02' + 'ab'.repeat(32);
/** 2500 µBTC, the BOLT 11 spec's coffee invoice. */
const BOLT11 =
	'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs' +
	'pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7' +
	'enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke' +
	'0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh';
const TIP = 800_000;

/**
 * A BeignetNode over a stub engine, with the spend-accounting fields its
 * constructor would set: Object.create skips them.
 */
function nodeWithEngine(engine: Record<string, unknown>): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: {
			getPayment: (): undefined => undefined,
			getCurrentBlockHeight: (): number => TIP,
			hasHtlcInFlight: (): boolean => false,
			on: (): void => {},
			removeListener: (): void => {},
			...engine
		},
		networkName: 'regtest',
		wallet: { feeEstimates: { normal: 4 } },
		_pendingSpendSats: 0,
		_asyncSpendClaims: new Map(),
		_dailySpentSats: 0,
		_dailySpentLightningSats: 0,
		_dailySpentOnchainSats: 0,
		_dailySpendLimitSats: undefined,
		_draining: false
	}) as unknown as BeignetNode;
}

/** A node whose engine records each sendPayment and refuses it. */
function payingNode(): { node: BeignetNode; sent: unknown[][] } {
	const sent: unknown[][] = [];
	const node = nodeWithEngine({
		sendPayment: (...args: unknown[]): never => {
			sent.push(args);
			throw Object.assign(new Error('No route found'), { code: 'NO_ROUTE' });
		}
	});
	return { node, sent };
}

/** A node whose engine records each openChannel and refuses it. */
function openingNode(): { node: BeignetNode; opened: unknown[][] } {
	const opened: unknown[][] = [];
	const node = nodeWithEngine({
		openChannel: (...args: unknown[]): never => {
			opened.push(args);
			throw new Error('stop after the engine call');
		}
	});
	return { node, opened };
}

async function rejection(run: () => Promise<unknown>): Promise<BeignetError> {
	try {
		await run();
	} catch (err: unknown) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	return expect.fail('expected a rejection');
}

describe('payInvoice and openChannel options objects (issue #1694)', () => {
	const metadata = { order: '42' };

	it('payInvoice sends the same payment from the options object and the positional form', async () => {
		const options = payingNode();
		await rejection(() =>
			options.node.payInvoice(BOLT11, {
				timeoutMs: 5_000,
				maxFeeSats: 300,
				metadata,
				cltvLimit: 144
			})
		);
		const positional = payingNode();
		await rejection(() =>
			positional.node.payInvoice(BOLT11, 5_000, 300, undefined, metadata, 144)
		);
		expect(options.sent).to.have.length(1);
		expect(options.sent).to.deep.equal(positional.sent);
		const [, , maxFeeMsat, , maxCltvExpiryHeight, , sentMetadata] =
			options.sent[0];
		expect(maxFeeMsat).to.equal(300_000n);
		expect(maxCltvExpiryHeight).to.equal(TIP + 144);
		expect(sentMetadata).to.equal(metadata);
	});

	it('payInvoice reads maxFeeMsat and amountSats from the options object', async () => {
		const options = payingNode();
		await rejection(() =>
			options.node.payInvoice(BOLT11, { maxFeeMsat: '1234', amountSats: 7 })
		);
		const positional = payingNode();
		await rejection(() =>
			positional.node.payInvoice(
				BOLT11,
				undefined,
				undefined,
				7,
				undefined,
				undefined,
				'1234'
			)
		);
		expect(options.sent).to.deep.equal(positional.sent);
		expect(options.sent[0][2]).to.equal(1234n);
		expect(options.sent[0][3]).to.equal(7_000n);
	});

	it('payInvoice refuses an options object followed by positional values', async () => {
		const { node, sent } = payingNode();
		const call = node.payInvoice as (...args: unknown[]) => Promise<unknown>;
		const err = await rejection(() =>
			call.call(node, BOLT11, { timeoutMs: 5_000 }, 300)
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		expect(sent).to.have.length(0);
		expect(
			(node as unknown as { _pendingSpendSats: number })._pendingSpendSats
		).to.equal(0);
	});

	it('payInvoiceSafe takes the options object and never throws', async () => {
		const { node, sent } = payingNode();
		const result = await node.payInvoiceSafe(BOLT11, { maxFeeSats: 300 });
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.match(/^\[NO_ROUTE\]/);
		expect(sent).to.have.length(1);
		expect(sent[0][2]).to.equal(300_000n);

		const call = node.payInvoiceSafe as (
			...args: unknown[]
		) => Promise<{ status: string; failureDescription?: string }>;
		const mixed = await call.call(node, BOLT11, { maxFeeSats: 300 }, 400);
		expect(mixed.status).to.equal('FAILED');
		expect(mixed.failureDescription).to.match(/^\[INVALID_PARAMS\]/);
		expect(sent).to.have.length(1);
	});

	it('openChannel opens the same channel from the options object and the positional form', () => {
		const options = openingNode();
		expect(() =>
			options.node.openChannel(PUBKEY, 100_000, {
				pushSats: 1_000,
				satsPerVbyte: 5,
				max: true,
				trusted: true
			})
		).to.throw('stop after the engine call');
		const positional = openingNode();
		expect(() =>
			positional.node.openChannel(PUBKEY, 100_000, 1_000, 5, true, true)
		).to.throw('stop after the engine call');
		expect(options.opened).to.deep.equal([
			[PUBKEY, 100_000n, 1_000_000n, 5, true, true]
		]);
		expect(options.opened).to.deep.equal(positional.opened);
	});

	it('openChannel defaults max and trusted to false', () => {
		const { node, opened } = openingNode();
		expect(() => node.openChannel(PUBKEY, 100_000, {})).to.throw(
			'stop after the engine call'
		);
		expect(opened).to.deep.equal([
			[PUBKEY, 100_000n, undefined, undefined, false, false]
		]);
	});

	it('openChannel refuses an options object followed by positional values', () => {
		const { node, opened } = openingNode();
		const call = node.openChannel as (...args: unknown[]) => unknown;
		expect(() => call.call(node, PUBKEY, 100_000, { pushSats: 1 }, 5))
			.to.throw(BeignetError)
			.with.property('code', BeignetErrorCode.INVALID_PARAMS);
		expect(opened).to.have.length(0);
	});
});
