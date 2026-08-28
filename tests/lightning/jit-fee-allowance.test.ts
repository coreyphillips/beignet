/**
 * JIT receive opening-fee allowance at the final hop (issue #595, LFBW 3B).
 *
 * An LSP takes its opening fee out of a forward whose onion it cannot rewrite,
 * so the HTLC arrives SHORT of the onion's amt_to_forward and BOLT 4 would
 * have us fail it (final_incorrect_htlc_amount). A JIT invoice registers the
 * quote the LSP gave us, and the final hop accepts a shortfall up to the fee
 * that quote implies on the total the payment declares.
 *
 * The two things the arithmetic has to get right, and the fork got wrong:
 *
 *  - The bound is AGGREGATE across the payment's parts. Applied per part, an
 *    MPP payment could be skimmed the whole fee on every part, so a two-part
 *    payment loses twice what the wallet agreed to.
 *  - An amount-less invoice is judged against the DECLARED TOTAL, not against
 *    a hardcoded cap. The fork sized the allowance off 1,000,000,000 msat, so
 *    a 1000-sat receive authorized the ppm fee on 10,000,000 sat.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { jitOpeningFeeMsat } from '../../src/lightning/liquidity/jit-receive';
import { IInvoiceInfo } from '../../src/lightning/storage/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(label: string, storage?: SqliteStorage): LightningNode {
	const seed = crypto
		.createHash('sha256')
		.update(`allowance-${label}`)
		.digest();
	const node = new LightningNode({
		...(storage ? { storage } : {}),
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(`allowance-priv-${label}`)
			.digest(),
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		network: Network.REGTEST
	});
	node.on('error', () => undefined);
	node.on('node:error', () => undefined);
	return node;
}

const HASH_HEX = crypto.randomBytes(32).toString('hex');

/* eslint-disable @typescript-eslint/no-explicit-any */

function seedInvoice(
	node: LightningNode,
	extra: Partial<IInvoiceInfo> = {}
): void {
	(node as any).invoices.set(HASH_HEX, {
		paymentHash: HASH_HEX,
		bolt11: 'lnbcrt1allowance',
		expiry: 3600,
		createdAt: 0,
		...extra
	} as IInvoiceInfo);
}

/**
 * One arriving HTLC through the shared final-hop safety checks. Returns true
 * when the HTLC was ACCEPTED (the checks returned no failure reason). The
 * CLTV arm is skipped by leaving the incoming expiry undefined, so only the
 * amount arm is under test.
 */
function accepts(
	node: LightningNode,
	part: {
		htlcKey: string;
		amountMsat: bigint;
		amtToForwardMsat: bigint;
		declaredTotalMsat?: bigint;
	}
): boolean {
	return (
		(node as any).finalHopSafetyFailure(
			undefined,
			{
				amountToForwardMsat: part.amtToForwardMsat,
				...(part.declaredTotalMsat !== undefined
					? { totalMsat: part.declaredTotalMsat }
					: {})
			},
			undefined,
			part.amountMsat,
			HASH_HEX,
			part.htlcKey
		) === null
	);
}

describe('JIT opening fee arithmetic (issue #595)', () => {
	it('is the flat part in msat plus the proportional part of the total', () => {
		expect(
			jitOpeningFeeMsat(1_000_000n, { flatFeeSat: 10n, feePpm: 2000 })
		).to.equal(10_000n + 2_000n);
	});

	it('floors the proportional part rather than rounding it up', () => {
		// 1 ppm of 1_500_000 msat is 1.5 msat; the payer must never owe the
		// half we would round up to.
		expect(
			jitOpeningFeeMsat(1_500_000n, { flatFeeSat: 0n, feePpm: 1 })
		).to.equal(1n);
	});

	it('normalises a fractional or negative quote instead of throwing', () => {
		expect(
			jitOpeningFeeMsat(1_000_000n, { flatFeeSat: -5n, feePpm: -3 })
		).to.equal(0n);
		expect(
			jitOpeningFeeMsat(1_000_000n, { flatFeeSat: 0n, feePpm: 1500.9 })
		).to.equal(1500n);
	});
});

describe('JIT fee allowance at the final hop (issue #595)', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = makeNode('final-hop');
	});

	afterEach(() => {
		node.destroy();
	});

	it('fails a short HTLC when the invoice registered no allowance', () => {
		seedInvoice(node, { amountMsat: 1_000_000n });
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 999_999n,
				amtToForwardMsat: 1_000_000n
			}),
			'BOLT 4 unchanged for an ordinary invoice'
		).to.equal(false);
	});

	it('accepts an HTLC covering its amt_to_forward, allowance or not', () => {
		seedInvoice(node, { amountMsat: 1_000_000n });
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 1_000_000n,
				amtToForwardMsat: 1_000_000n
			})
		).to.equal(true);
	});

	it('accepts a shortfall up to the quoted fee and refuses one msat more', () => {
		seedInvoice(node, {
			amountMsat: 1_000_000n,
			jitFee: { flatFeeSat: 1, feePpm: 1000 }
		});
		// 1 sat flat + 1000 ppm of 1_000_000 msat = 1000 + 1000 = 2000 msat.
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 998_000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 1_000_000n
			}),
			'exactly the quoted fee'
		).to.equal(true);

		expect(
			accepts(node, {
				htlcKey: 'chan:2',
				amountMsat: 997_999n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 1_000_000n
			}),
			'one msat past the quote'
		).to.equal(false);
	});

	it('bounds a multi-part payment in aggregate, not per part', () => {
		seedInvoice(node, {
			amountMsat: 2_000_000n,
			jitFee: { flatFeeSat: 10, feePpm: 0 }
		});
		// The LSP takes the fee ONCE, off one part; both parts declare the
		// same 2_000_000 msat total.
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 990_000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 2_000_000n
			}),
			'first part carries the whole fee'
		).to.equal(true);

		// A per-part bound would accept this too, and the payment would be
		// skimmed 20 sat for a 10 sat fee.
		expect(
			accepts(node, {
				htlcKey: 'chan:2',
				amountMsat: 990_000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 2_000_000n
			}),
			'second part re-claiming the full fee'
		).to.equal(false);
	});

	it('lets the parts of a set share one allowance between them', () => {
		seedInvoice(node, {
			amountMsat: 2_000_000n,
			jitFee: { flatFeeSat: 10, feePpm: 0 }
		});
		for (const [key, amount] of [
			['chan:1', 996_000n],
			['chan:2', 994_000n]
		] as const) {
			expect(
				accepts(node, {
					htlcKey: key,
					amountMsat: amount,
					amtToForwardMsat: 1_000_000n,
					declaredTotalMsat: 2_000_000n
				}),
				key
			).to.equal(true);
		}
		// The set has now used 4000 + 6000 = 10_000 msat, all of it.
		expect(
			accepts(node, {
				htlcKey: 'chan:3',
				amountMsat: 999_999n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 3_000_000n
			}),
			'a third part with nothing left to spend'
		).to.equal(false);
	});

	it('sizes an amount-less invoice against the declared total', () => {
		seedInvoice(node, { jitFee: { flatFeeSat: 0, feePpm: 2000 } });
		// 2000 ppm of the 1_000_000 msat actually being paid is 2000 msat. The
		// fork computed the allowance off a hardcoded 1_000_000_000 msat cap,
		// which would have authorized 2_000_000 msat here.
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 998_000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 1_000_000n
			}),
			'the fee owed on what actually arrived'
		).to.equal(true);

		expect(
			accepts(node, {
				htlcKey: 'chan:2',
				amountMsat: 1_000_000n - 2_000_000n / 1000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 1_000_000n
			}),
			'the fee the hardcoded cap would have authorized'
		).to.equal(false);
	});

	it('falls back to the part amount when no total is declared', () => {
		seedInvoice(node, { jitFee: { flatFeeSat: 0, feePpm: 1000 } });
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 999_000n,
				amtToForwardMsat: 1_000_000n
			})
		).to.equal(true);
		expect(
			accepts(node, {
				htlcKey: 'chan:2',
				amountMsat: 998_999n,
				amtToForwardMsat: 1_000_000n
			})
		).to.equal(false);
	});

	it('lets one HTLC replace its own claim rather than adding to it', () => {
		seedInvoice(node, {
			amountMsat: 1_000_000n,
			jitFee: { flatFeeSat: 10, feePpm: 0 }
		});
		// The same incoming HTLC re-dispatched (a reestablish replays it) must
		// not spend the allowance twice and fail itself the second time.
		for (const attempt of [1, 2]) {
			expect(
				accepts(node, {
					htlcKey: 'chan:1',
					amountMsat: 990_000n,
					amtToForwardMsat: 1_000_000n,
					declaredTotalMsat: 1_000_000n
				}),
				`attempt ${attempt}`
			).to.equal(true);
		}
	});

	it('returns the allowance when a part it was conceded to resolves', () => {
		seedInvoice(node, {
			amountMsat: 1_000_000n,
			jitFee: { flatFeeSat: 10, feePpm: 0 }
		});
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 990_000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 1_000_000n
			})
		).to.equal(true);
		// Every per-HTLC terminal point on the receive path runs this, fail and
		// fulfill alike, so a part that never settles stops holding the budget.
		(node as any).cleanupHtlcSharedSecret('chan:1');
		expect(
			accepts(node, {
				htlcKey: 'chan:2',
				amountMsat: 990_000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 1_000_000n
			}),
			'a retry after the first part was failed back'
		).to.equal(true);
	});

	it('retires the whole set of claims on a terminal payment outcome', () => {
		seedInvoice(node, {
			amountMsat: 1_000_000n,
			jitFee: { flatFeeSat: 10, feePpm: 0 }
		});
		expect(
			accepts(node, {
				htlcKey: 'chan:1',
				amountMsat: 990_000n,
				amtToForwardMsat: 1_000_000n,
				declaredTotalMsat: 1_000_000n
			})
		).to.equal(true);
		expect((node as any).jitSkimTaken.size).to.equal(1);
		(node as any).clearJitSkim(HASH_HEX);
		expect((node as any).jitSkimTaken.size).to.equal(0);
	});
});

describe('createInvoice jitFeeAllowance (issue #595)', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = makeNode('create');
	});

	afterEach(() => {
		node.destroy();
	});

	it('records the quote on the invoice', () => {
		const result = node.createInvoice({
			amountMsat: 1_000_000n,
			description: 'jit',
			jitFeeAllowance: { flatFeeSat: 7, feePpm: 250 }
		});
		const record = (node as any).invoices.get(
			result.paymentHash.toString('hex')
		) as IInvoiceInfo;
		expect(record.jitFee).to.deep.equal({ flatFeeSat: 7, feePpm: 250 });
	});

	it('carries the quote through storage, so a restart still settles', () => {
		// The invoice can be out in the world for an hour before it is paid. An
		// allowance held only in memory would be gone by then, and the LSP's
		// skimmed HTLC would be failed at the final hop for a payment the
		// sender already made.
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const stored = makeNode('persist-write', storage);
		try {
			const result = stored.createInvoice({
				amountMsat: 1_000_000n,
				description: 'jit',
				jitFeeAllowance: { flatFeeSat: 7, feePpm: 250 }
			});
			const rows = storage.loadAllInvoices();
			const row = rows.find(
				(r) => r.paymentHashHex === result.paymentHash.toString('hex')
			);
			expect(row, 'the invoice reached storage').to.not.equal(undefined);
			expect(row!.invoice.jitFee).to.deep.equal({ flatFeeSat: 7, feePpm: 250 });
		} finally {
			stored.destroy();
			storage.close();
		}
	});

	it('refuses a quote that is not a whole non-negative number', () => {
		for (const quote of [
			{ flatFeeSat: -1, feePpm: 0 },
			{ flatFeeSat: 0.5, feePpm: 0 },
			{ flatFeeSat: 0, feePpm: Number.NaN }
		]) {
			expect(
				() =>
					node.createInvoice({
						amountMsat: 1_000_000n,
						description: 'jit',
						jitFeeAllowance: quote
					}),
				JSON.stringify(quote)
			).to.throw(/jitFeeAllowance/);
		}
	});

	it('leaves an ordinary invoice with no allowance at all', () => {
		const result = node.createInvoice({
			amountMsat: 1_000_000n,
			description: 'plain'
		});
		const record = (node as any).invoices.get(
			result.paymentHash.toString('hex')
		) as IInvoiceInfo;
		expect(record.jitFee).to.equal(undefined);
	});
});
