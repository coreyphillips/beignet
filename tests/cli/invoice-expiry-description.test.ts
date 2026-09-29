/**
 * Issue #1043: invoice expiry and description reached the BOLT 11 encoder
 * unchecked. The encoder packs whatever number it is given, so an expiry of
 * -1 or NaN went out as 0 and 1.5 as 1, and a description longer than the d
 * tag holds threw a plain Error that the daemon scrubbed to a 500.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';
import { BeignetNode } from '../../src/cli/beignet-node';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { decode } from '../../src/lightning/invoice/decode';

const ONE_YEAR_SECS = 365 * 24 * 60 * 60;
const BAD_EXPIRIES: unknown[] = [
	-1,
	0,
	1.5,
	Number.NaN,
	Number.POSITIVE_INFINITY,
	ONE_YEAR_SECS + 1,
	1e15,
	'3600'
];
/** 213 three-byte characters: 639 bytes, the most a d tag holds. */
const LONGEST_DESCRIPTION = '€'.repeat(213);
const TOO_LONG_DESCRIPTION = LONGEST_DESCRIPTION + 'x';

function makeEngine(): LightningNode {
	const key = (label: string): Buffer =>
		crypto.createHash('sha256').update(label).digest();
	const node = new LightningNode({
		nodePrivateKey: key('1043-node'),
		channelBasepoints: {
			fundingPubkey: getPublicKey(key('1043-0')),
			revocationBasepoint: getPublicKey(key('1043-1')),
			paymentBasepoint: getPublicKey(key('1043-2')),
			delayedPaymentBasepoint: getPublicKey(key('1043-3')),
			htlcBasepoint: getPublicKey(key('1043-4')),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		perCommitmentSeed: key('1043-seed'),
		fundingPrivkey: key('1043-funding'),
		network: Network.REGTEST
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

/** A BeignetNode over a real engine, counting what reaches its encoder. */
function wrap(engine: Record<string, unknown>): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: engine,
		networkName: 'regtest'
	}) as unknown as BeignetNode;
}

function refusal(fn: () => unknown, label: string): BeignetError {
	try {
		fn();
	} catch (err: unknown) {
		expect(err, label).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	expect.fail(`${label}: expected a refusal`);
}

describe('Issue #1043: invoice expiry and description bounds', () => {
	let engine: LightningNode;
	let encoded: number;
	let bn: BeignetNode;

	beforeEach(() => {
		engine = makeEngine();
		encoded = 0;
		const createInvoice = engine.createInvoice.bind(engine);
		bn = wrap({
			createInvoice: (opts: Parameters<LightningNode['createInvoice']>[0]) => {
				encoded++;
				return createInvoice(opts);
			},
			createJitInvoice: (): never => {
				expect.fail('the LSP was asked past the guard');
			}
		});
	});

	afterEach(() => engine.destroy());

	const hash = (): string => crypto.randomBytes(32).toString('hex');

	it('refuses an expiry the encoder would rewrite, on /invoice/create', () => {
		for (const bad of BAD_EXPIRIES) {
			const err = refusal(
				() => bn.createInvoice(1_000, 'x', bad as number),
				String(bad)
			);
			expect(err.code, String(bad)).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(err.message).to.match(
				/expirySecs must be a whole number of seconds between 1 and 31536000/
			);
		}
		expect(encoded, 'nothing reached the encoder').to.equal(0);
	});

	it('refuses the same on /invoice/create-hold', () => {
		for (const bad of BAD_EXPIRIES) {
			const err = refusal(
				() =>
					bn.createHoldInvoice({
						paymentHash: hash(),
						amountSats: 1_000,
						expiry: bad as number
					}),
				String(bad)
			);
			expect(err.code, String(bad)).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(err.message).to.match(/^expiry must be a whole number/);
		}
		expect(encoded).to.equal(0);
	});

	it('refuses the same on /jit/invoice before the LSP is asked', async () => {
		for (const bad of BAD_EXPIRIES) {
			try {
				await bn.createJitInvoice({
					lspPubkey: '02' + 'ab'.repeat(32),
					amountSats: 1_000,
					expirySecs: bad as number
				});
				expect.fail(`${String(bad)}: expected a refusal`);
			} catch (err: unknown) {
				expect(err, String(bad)).to.be.instanceOf(BeignetError);
				expect((err as BeignetError).code).to.equal(
					BeignetErrorCode.INVALID_PARAMS
				);
			}
		}
	});

	it('refuses a description the d tag cannot hold, as INVALID_PARAMS', async () => {
		const calls: Array<[string, () => unknown]> = [
			['create', (): unknown => bn.createInvoice(1_000, TOO_LONG_DESCRIPTION)],
			[
				'create-hold',
				(): unknown =>
					bn.createHoldInvoice({
						paymentHash: hash(),
						description: TOO_LONG_DESCRIPTION
					})
			]
		];
		for (const [label, call] of calls) {
			const err = refusal(call, label);
			expect(err.code, label).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(err.message, label).to.include('at most 639 bytes');
		}
		expect(encoded).to.equal(0);
		try {
			await bn.createJitInvoice({
				lspPubkey: '02' + 'ab'.repeat(32),
				description: TOO_LONG_DESCRIPTION
			});
			expect.fail('expected the JIT invoice to be refused');
		} catch (err: unknown) {
			expect(err).to.be.instanceOf(BeignetError);
			expect((err as BeignetError).code).to.equal(
				BeignetErrorCode.INVALID_PARAMS
			);
		}
	});

	it('encodes both limits exactly as asked', () => {
		const plain = decode(
			bn.createInvoice(1_000, LONGEST_DESCRIPTION, ONE_YEAR_SECS).bolt11
		);
		expect(plain.expiry).to.equal(ONE_YEAR_SECS);
		expect(plain.description).to.equal(LONGEST_DESCRIPTION);

		const hold = decode(
			bn.createHoldInvoice({
				paymentHash: hash(),
				description: LONGEST_DESCRIPTION,
				expiry: 1
			}).bolt11
		);
		expect(hold.expiry).to.equal(1);
		expect(hold.description).to.equal(LONGEST_DESCRIPTION);
		expect(encoded).to.equal(2);
	});

	it('leaves a long description alone when a descriptionHash replaces it', () => {
		const descriptionHash = crypto
			.createHash('sha256')
			.update(TOO_LONG_DESCRIPTION)
			.digest();
		const inv = decode(
			bn.createInvoice(1_000, TOO_LONG_DESCRIPTION, undefined, descriptionHash)
				.bolt11
		);
		expect(inv.descriptionHash?.equals(descriptionHash)).to.equal(true);
	});
});
