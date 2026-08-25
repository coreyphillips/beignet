/**
 * Issues #471 and #472, both follow-ups to #464.
 *
 * #471: a channel-funding request the node cannot serve for its OWN state or
 * configuration (no funding provider, not enough on-chain balance for a max
 * open, no fee sample yet) threw a plain Error, so the daemon logged it as an
 * unhandled fault and answered 500 INTERNAL_ERROR "Internal server error".
 * INVALID_PARAMS would be a lie for these, so each carries a code of its own.
 * And every domain code was missing from STATUS_BY_ERROR_CODE, so even a typed
 * failure shipped as a 500, which is the class an agent retries.
 *
 * #472: openZeroConfChannel and openChannelV2 skipped the amountSats/pushSats
 * integer guards openChannel applies, so a fractional amount threw an uncaught
 * RangeError at BigInt() and scrubbed to the same 500. The splice paths had the
 * same gap.
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import {
	BeignetError,
	BeignetErrorCode,
	isRetryableError
} from '../../src/cli/errors';
import { BeignetNode } from '../../src/cli/beignet-node';
import { statusForErrorCode, statusForFailure } from '../../src/cli/daemon';
import {
	ChannelFundingUnavailableCode,
	ChannelFundingUnavailableError,
	InvalidPeerConnectError,
	InvalidSpliceError
} from '../../src/lightning/node/types';

const PUBKEY = '02' + 'ab'.repeat(32);
const CHANNEL_ID = 'cd'.repeat(32);

/**
 * A BeignetNode whose engine is the given stub. Inheriting the prototype keeps
 * the internal helpers resolvable, the same idiom typed-open-refusals.test.ts
 * and beignet-node.test.ts use.
 */
function nodeWithEngine(engine: Record<string, unknown>): BeignetNode {
	return Object.assign(Object.create(BeignetNode.prototype), {
		node: engine,
		networkName: 'regtest',
		wallet: { feeEstimates: { normal: 4 } }
	}) as unknown as BeignetNode;
}

/** Run `fn`, returning the BeignetError it threw. Fails if it threw anything else. */
function refusalFrom(fn: () => unknown, label: string): BeignetError {
	try {
		fn();
	} catch (err: unknown) {
		expect(err, label).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	expect.fail(`${label}: expected a refusal`);
}

describe('Issue #471: state and config refusals carry a code, not a 500', () => {
	const MESSAGES: Record<ChannelFundingUnavailableCode, string> = {
		[ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED]:
			'max funding on a dual-funded (v2) open requires a funding provider with quoteDualFundingMax and selectMaxDualFundingInputs',
		[ChannelFundingUnavailableCode.INSUFFICIENT_BALANCE]:
			'insufficient funds for a max dual-funded open: 100 sats spendable cannot cover the 700 sat funding fee',
		[ChannelFundingUnavailableCode.FEE_ESTIMATE_NOT_READY]:
			'fee estimate not ready yet for a dual-funded open (the estimator has not delivered its first sample); retry shortly or pass an explicit satsPerVbyte',
		[ChannelFundingUnavailableCode.CHANNEL_NOT_FOUND]: `Channel not found: ${CHANNEL_ID}`
	};

	/** Each engine code, the code it must reach the caller as, and its status. */
	const EXPECTED: Array<
		[ChannelFundingUnavailableCode, BeignetErrorCode, number]
	> = [
		[
			ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED,
			BeignetErrorCode.FUNDING_PROVIDER_REQUIRED,
			409
		],
		[
			ChannelFundingUnavailableCode.INSUFFICIENT_BALANCE,
			BeignetErrorCode.INSUFFICIENT_BALANCE,
			409
		],
		[
			ChannelFundingUnavailableCode.FEE_ESTIMATE_NOT_READY,
			BeignetErrorCode.FEE_ESTIMATE_NOT_READY,
			503
		],
		[
			ChannelFundingUnavailableCode.CHANNEL_NOT_FOUND,
			BeignetErrorCode.CHANNEL_NOT_FOUND,
			404
		]
	];

	for (const [engineCode, cliCode, status] of EXPECTED) {
		it(`${engineCode} answers ${cliCode} (HTTP ${status}) with the engine's message`, () => {
			const bn = nodeWithEngine({
				openChannel: (): never => {
					throw new ChannelFundingUnavailableError(
						engineCode,
						MESSAGES[engineCode]
					);
				}
			});
			const err = refusalFrom(
				() => bn.openChannel(PUBKEY, 100_000, undefined, 5, true),
				engineCode
			);
			expect(err.code).to.equal(cliCode);
			// The message is the whole point: "the estimator has not delivered
			// its first sample, retry shortly" is actionable, "Internal server
			// error" is a dead end.
			expect(err.message).to.equal(MESSAGES[engineCode]);
			expect(statusForErrorCode(err.code)).to.equal(status);
		});
	}

	it('converts on the max-open quote path too, not just the open', async () => {
		const bn = nodeWithEngine({
			peerFundingInfo: () => ({ peerKnown: true, dualFund: true }),
			quoteDualFundingMaxOpen: (): never => {
				throw new ChannelFundingUnavailableError(
					ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED,
					'quoting a max dual-funded (v2) open requires a funding provider with quoteDualFundingMax'
				);
			}
		});
		try {
			await bn.quoteChannelFunding({ peerPubkey: PUBKEY });
			expect.fail('expected the quote to be refused');
		} catch (err: unknown) {
			expect(err).to.be.instanceOf(BeignetError);
			expect((err as BeignetError).code).to.equal(
				BeignetErrorCode.FUNDING_PROVIDER_REQUIRED
			);
		}
	});

	it('leaves a node fault untyped, so it still scrubs', () => {
		const bn = nodeWithEngine({
			openChannel: (): never => {
				throw new Error('database is locked');
			}
		});
		try {
			bn.openChannel(PUBKEY, 100_000);
			expect.fail('expected the open to throw');
		} catch (err: unknown) {
			expect(err).to.not.be.instanceOf(BeignetError);
			expect((err as Error).message).to.equal('database is locked');
		}
	});

	it('types a splice argument refusal as INVALID_PARAMS', () => {
		const bn = nodeWithEngine({
			spliceIn: (): never => {
				throw new InvalidSpliceError('amountSats must be positive');
			}
		});
		const err = refusalFrom(
			() => bn.spliceIn(CHANNEL_ID, 50_000, 2500),
			'splice-in'
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		expect(statusForErrorCode(err.code)).to.equal(400);
	});
});

/**
 * Every code the daemon can put on the wire, read out of the source rather than
 * from the enum: BeignetError takes an arbitrary string and production uses
 * that, so walking BeignetErrorCode alone would leave codes like FEE_EXCEEDS_MAX
 * unchecked (they were falling through to 500).
 */
function emittedErrorCodes(): string[] {
	const root = path.join(__dirname, '..', '..', 'src');
	const files: string[] = [];
	const walk = (dir: string): void => {
		for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
			const full = path.join(dir, entry.name);
			if (entry.isDirectory()) walk(full);
			else if (entry.name.endsWith('.ts')) files.push(full);
		}
	};
	walk(root);
	const patterns = [
		/new BeignetError\(\s*'([A-Z0-9_]+)'/g,
		/new BeignetError\(\s*BeignetErrorCode\.([A-Z0-9_]+)/g,
		/\bfailure\(\s*'([A-Z0-9_]+)'/g,
		// An assignment inside a catch, which becomes failure(code, msg). NOT a
		// `readonly code =` class field: those live on plain Error subclasses
		// the daemon never unwraps, so they scrub whole (issue #474).
		/(?<!readonly )\bcode\s*=\s*'([A-Z0-9_]+)'/g
	];
	const codes = new Set<string>(Object.values(BeignetErrorCode));
	for (const file of files) {
		const src = fs.readFileSync(file, 'utf8');
		for (const pattern of patterns) {
			for (const match of src.matchAll(pattern)) codes.add(match[1]);
		}
		// Values of the string-keyed translation tables (payment failure codes,
		// recovery refusal reasons) are emitted the same way.
		for (const block of src.matchAll(
			/(?:codeMap|RESTORE_ERROR_CODES)[^=]*=\s*\{([\s\S]*?)\n\t*\};/g
		)) {
			for (const match of block[1].matchAll(/:\s*'([A-Z0-9_]+)'/g))
				codes.add(match[1]);
		}
	}
	return [...codes].sort();
}

describe('Issue #471: every error code the daemon emits has a decided status', () => {
	/**
	 * Codes that keep the 500 default on purpose. WALLET_CREATE_FAILED,
	 * ADDRESS_FAILED, REFRESH_FAILED and DESCRIPTOR_EXPORT_FAILED are node
	 * faults. SEND_FAILED, CLOSE_FAILED, FORCE_CLOSE_FAILED, ZERO_CONF_FAILED
	 * and the PSBT_* trio are grab-bags whose producers span caller state and
	 * genuine faults, so no single status is honest until they are split
	 * (issue #474). INSTANCE_ALREADY_RUNNING never reaches HTTP, and
	 * INTERNAL_ERROR is the scrub itself.
	 *
	 * Adding a code here must be a decision, not an oversight: that is the
	 * whole point of reading the list out of the source.
	 */
	const STAYS_500 = new Set<string>([
		'WALLET_CREATE_FAILED',
		'ADDRESS_FAILED',
		'REFRESH_FAILED',
		'DESCRIPTOR_EXPORT_FAILED',
		'SEND_FAILED',
		'CLOSE_FAILED',
		'FORCE_CLOSE_FAILED',
		'ZERO_CONF_FAILED',
		'PSBT_BUILD_FAILED',
		'PSBT_COMBINE_FAILED',
		'PSBT_IMPORT_FAILED',
		'INSTANCE_ALREADY_RUNNING',
		'INTERNAL_ERROR',
		'CAPSULE_RESTORE_INSTALL_FAILED'
	]);

	const CODES = emittedErrorCodes();

	it('finds the codes by reading the source, not just the enum', () => {
		// A guard on the guard: if the scan stops matching, every assertion
		// below passes vacuously.
		expect(CODES.length).to.be.greaterThan(50);
		expect(CODES).to.include('FEE_EXCEEDS_MAX');
		expect(CODES).to.include(BeignetErrorCode.CONNECT_FAILED);
	});

	for (const code of CODES) {
		it(`${code} is mapped or explicitly left as a server fault`, () => {
			const status = statusForErrorCode(code);
			if (STAYS_500.has(code)) {
				expect(status).to.equal(500);
			} else {
				expect(
					status,
					`${code} falls through to 500: give it a status or add it to STAYS_500`
				).to.not.equal(500);
			}
		});
	}

	/**
	 * The invariant behind the whole change: 502/503/504 tell a caller to try
	 * again. A code isPermanentFailure calls permanent may never answer one, or
	 * the status and the library predicate give opposite instructions.
	 */
	it('never answers a retryable 5xx for a permanent failure', () => {
		for (const code of CODES) {
			const status = statusForErrorCode(code);
			if (status < 500 || status === 500) continue;
			const err = new BeignetError(code, 'test');
			expect(
				isRetryableError(err),
				`${code} answers ${status}, which says retry, but isRetryableError says permanent`
			).to.equal(true);
		}
	});

	it('drops a permanent BOLT 4 payment failure out of the retryable class', () => {
		// 0x400f = PERM|incorrect_or_unknown_payment_details. The payee will
		// refuse it every time, so PAYMENT_FAILED's own 502 would be a lie.
		const perm = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'gone',
			0x400f
		);
		expect(isRetryableError(perm)).to.equal(false);
		expect(statusForFailure(perm.code, perm.failureCode)).to.equal(409);
		// Without the flag it stays upstream trouble, which is retryable.
		const temp = new BeignetError(BeignetErrorCode.PAYMENT_FAILED, 'busy', 7);
		expect(isRetryableError(temp)).to.equal(true);
		expect(statusForFailure(temp.code, temp.failureCode)).to.equal(502);
	});

	it('keeps an unknown code a server fault', () => {
		expect(statusForErrorCode('INTERNAL_ERROR')).to.equal(500);
		expect(statusForErrorCode('SOMETHING_NEW')).to.equal(500);
	});

	it('answers a failed peer dial as upstream trouble, not a node fault', () => {
		expect(statusForErrorCode(BeignetErrorCode.CONNECT_FAILED)).to.equal(502);
		expect(statusForErrorCode(BeignetErrorCode.CONNECT_TIMEOUT)).to.equal(504);
		expect(statusForErrorCode(BeignetErrorCode.PEER_NOT_CONNECTED)).to.equal(
			409
		);
	});
});

describe('Issue #472: every open path guards its amounts before BigInt()', () => {
	const ENTRY_POINTS: Array<{
		name: string;
		engineMethod: string;
		open: (bn: BeignetNode, amountSats: unknown, pushSats?: unknown) => unknown;
		push: boolean;
	}> = [
		{
			name: 'openChannel',
			engineMethod: 'openChannel',
			open: (bn, amountSats, pushSats): unknown =>
				bn.openChannel(PUBKEY, amountSats as number, pushSats as number),
			push: true
		},
		{
			name: 'openZeroConfChannel',
			engineMethod: 'openZeroConfChannel',
			open: (bn, amountSats, pushSats): unknown =>
				bn.openZeroConfChannel(
					PUBKEY,
					amountSats as number,
					pushSats as number
				),
			push: true
		},
		{
			name: 'openChannelV2',
			engineMethod: 'openChannelV2',
			open: (bn, amountSats): unknown =>
				bn.openChannelV2(PUBKEY, { amountSats: amountSats as number }),
			push: false
		}
	];

	for (const entry of ENTRY_POINTS) {
		/** An engine that must never be reached: the guard runs first. */
		const guarded = (): BeignetNode =>
			nodeWithEngine({
				[entry.engineMethod]: (): never => {
					expect.fail(`${entry.name}: the engine was reached past the guard`);
				}
			});

		it(`${entry.name} refuses a fractional amountSats`, () => {
			const err = refusalFrom(() => entry.open(guarded(), 1.5), entry.name);
			expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(err.message).to.equal(
				'amountSats must be an integer number of satoshis'
			);
			expect(statusForErrorCode(err.code)).to.equal(400);
		});

		it(`${entry.name} refuses a string amountSats`, () => {
			// BigInt('1000') would succeed, so the amount would slip past the
			// conversion and reach the spend-limit math as a string.
			const err = refusalFrom(() => entry.open(guarded(), '1000'), entry.name);
			expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		});

		it(`${entry.name} refuses a negative amountSats`, () => {
			const err = refusalFrom(() => entry.open(guarded(), -1), entry.name);
			expect(err.message).to.equal('amountSats must be >= 0');
		});

		if (entry.push) {
			it(`${entry.name} refuses a fractional pushSats`, () => {
				const err = refusalFrom(
					() => entry.open(guarded(), 100_000, 0.5),
					entry.name
				);
				expect(err.message).to.equal(
					'pushSats must be a non-negative integer number of satoshis'
				);
			});
		}
	}
});

describe('Issue #472: the splice paths guard their arguments too', () => {
	function guardedSplice(): BeignetNode {
		const unreachable = (): never => {
			expect.fail('the engine was reached past the guard');
		};
		return nodeWithEngine({
			spliceIn: unreachable,
			spliceOut: unreachable,
			spliceQuote: unreachable
		});
	}

	it('refuses a channelId that is not 32 bytes of hex', () => {
		// Buffer.from('not-hex', 'hex') truncates silently, so an unchecked id
		// reaches the engine as a short buffer.
		const err = refusalFrom(
			() => guardedSplice().spliceIn('not-hex', 50_000, 2500),
			'channelId'
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		expect(err.message).to.include('64-character hex channel id');
	});

	it('refuses a fractional splice amount', () => {
		const err = refusalFrom(
			() => guardedSplice().spliceOut(CHANNEL_ID, 1.5, 2500),
			'splice-out amount'
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
	});

	/**
	 * funding_feerate_perkw is a u32 on the wire. writeUInt32BE turns 1.5 into
	 * 1, quietly repricing the splice, and throws on 2^32 AFTER the channel has
	 * moved to SPLICING and persisted, which wedges it until a restart. Both
	 * bounds have to be enforced before any of that runs.
	 */
	const BAD_FEERATES: Array<[string, number]> = [
		['zero', 0],
		['negative', -1],
		['fractional', 1.5],
		['above u32', 0x1_0000_0000],
		['not finite', Number.POSITIVE_INFINITY]
	];
	for (const [label, feerate] of BAD_FEERATES) {
		it(`refuses a ${label} splice feerate on all three entry points`, () => {
			const calls: Array<() => unknown> = [
				(): unknown => guardedSplice().spliceQuote(CHANNEL_ID, 'in', feerate),
				(): unknown => guardedSplice().spliceIn(CHANNEL_ID, 50_000, feerate),
				(): unknown => guardedSplice().spliceOut(CHANNEL_ID, 50_000, feerate)
			];
			for (const call of calls) {
				const err = refusalFrom(call, `${label} feerate`);
				expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
				expect(err.message).to.include('4294967295');
			}
		});
	}

	it('refuses the same out-of-range values on the v2 open wire fields', () => {
		const bn = (): BeignetNode =>
			nodeWithEngine({
				openChannelV2: (): never => {
					expect.fail('the engine was reached past the guard');
				}
			});
		const cases: Array<[string, Record<string, number>]> = [
			['fundingFeeratePerkw', { fundingFeeratePerkw: 1.5 }],
			['commitmentFeeratePerkw', { commitmentFeeratePerkw: 0x1_0000_0000 }],
			['locktime', { locktime: 2.5 }]
		];
		for (const [label, extra] of cases) {
			const err = refusalFrom(
				() => bn().openChannelV2(PUBKEY, { amountSats: 100_000, ...extra }),
				label
			);
			expect(err.code, label).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(err.message, label).to.include(label);
		}
	});

	it('refuses a destination address this network cannot decode', () => {
		const err = refusalFrom(
			() =>
				guardedSplice().spliceOut(CHANNEL_ID, 50_000, 2500, 'not-an-address'),
			'destinationAddress'
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		expect(err.message).to.include('destinationAddress');
	});
});

describe('Issue #471: the grab-bag codes stop swallowing caller refusals', () => {
	it('a malformed pubkey is INVALID_PARAMS, not a CONNECT_FAILED to retry', async () => {
		const bn = nodeWithEngine({
			// The engine method is async, so its refusals arrive as rejections.
			connectPeer: async (): Promise<never> => {
				throw new InvalidPeerConnectError('pubkey must be 33 bytes of hex');
			},
			listPeers: (): unknown[] => []
		});
		Object.assign(bn, { _connectTimeoutMs: 5_000 });
		try {
			await bn.connectPeer('nonsense');
			expect.fail('expected the dial to be refused');
		} catch (err: unknown) {
			expect(err).to.be.instanceOf(BeignetError);
			const beignetErr = err as BeignetError;
			// CONNECT_FAILED answers 502, which tells an agent to dial again.
			expect(beignetErr.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(statusForErrorCode(beignetErr.code)).to.equal(400);
		}
	});

	it('a genuine dial failure is still CONNECT_FAILED', async () => {
		const bn = nodeWithEngine({
			connectPeer: async (): Promise<never> => {
				throw new Error('ECONNREFUSED');
			},
			listPeers: (): unknown[] => []
		});
		Object.assign(bn, { _connectTimeoutMs: 5_000 });
		try {
			await bn.connectPeer(PUBKEY, '127.0.0.1', 9735);
			expect.fail('expected the dial to fail');
		} catch (err: unknown) {
			expect((err as BeignetError).code).to.equal(
				BeignetErrorCode.CONNECT_FAILED
			);
			expect(statusForErrorCode((err as BeignetError).code)).to.equal(502);
		}
	});
});

/**
 * Issue #474: the payment and invoice paths were left out of #472's sweep.
 *
 * Two separate faults, both reachable from a single mistyped field:
 *
 * 1. payInvoice and sendKeysend raised _pendingSpendSats BEFORE the BigInt()
 *    conversion that throws, and every decrement lives in the Promise below
 *    that a RangeError never reaches. The reservation was stranded, and once
 *    the leaked total passed dailySpendLimit, _checkSpendLimit refused every
 *    real payment until the daemon restarted. The same strand happened on a
 *    perfectly well-formed request whose sendPayment refused synchronously
 *    (no route, a duplicate, a peer that is gone).
 *
 * 2. The rest of the caller-facing API converted amounts with an unguarded
 *    BigInt(), so a fractional value scrubbed to a 500 INTERNAL_ERROR, the
 *    class an agent retries.
 *
 * And the caller-state half of the two close codes: an unknown channel came
 * back as CLOSE_FAILED, which has no status entry and shipped as a 500 with
 * "Channel not found" in the body.
 */
describe('Issue #474: the payment and invoice paths guard before BigInt()', () => {
	/** A signed BOLT 11 vector (BOLT 11 test vectors, 2500u) that decodes. */
	const BOLT11 =
		'lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs' +
		'pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7' +
		'enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke' +
		'0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh';
	/**
	 * nodeWithEngine plus the spend-accounting fields. They are class fields
	 * set in the constructor, so Object.create leaves them undefined and
	 * `undefined += n` would quietly make the counter NaN instead of leaking.
	 */
	function payingNode(
		engine: Record<string, unknown>,
		/** undefined is "no limit", which is what an unconfigured node has. */
		dailySpendLimitSats?: number
	): BeignetNode {
		return Object.assign(nodeWithEngine(engine), {
			_pendingSpendSats: 0,
			_dailySpentSats: 0,
			_dailySpentLightningSats: 0,
			_dailySpentOnchainSats: 0,
			_dailySpendLimitSats: dailySpendLimitSats,
			_draining: false
		}) as unknown as BeignetNode;
	}

	const pendingOf = (bn: BeignetNode): number =>
		(bn as unknown as { _pendingSpendSats: number })._pendingSpendSats;

	/** Run `fn`, returning the BeignetError it rejected with. */
	async function asyncRefusalFrom(
		fn: () => Promise<unknown>,
		label: string
	): Promise<BeignetError> {
		try {
			await fn();
		} catch (err: unknown) {
			expect(err, label).to.be.instanceOf(BeignetError);
			return err as BeignetError;
		}
		return expect.fail(`${label}: expected a refusal`);
	}

	/** Every entry point, its unreachable engine method, and how to call it. */
	const ENTRY_POINTS: Array<{
		name: string;
		engineMethod: string;
		/** Called with the bad value in each numeric position, in turn. */
		call: (bn: BeignetNode, bad: unknown) => unknown;
		field: string;
	}> = [
		{
			name: 'createInvoice(amountSats)',
			engineMethod: 'createInvoice',
			call: (bn, bad): unknown => bn.createInvoice(bad as number),
			field: 'amountSats'
		},
		{
			name: 'createHoldInvoice(amountSats)',
			engineMethod: 'createInvoice',
			call: (bn, bad): unknown =>
				bn.createHoldInvoice({
					paymentHash: 'ab'.repeat(32),
					amountSats: bad as number
				}),
			field: 'amountSats'
		},
		{
			name: 'payInvoice(maxFeeSats)',
			engineMethod: 'sendPayment',
			call: (bn, bad): unknown => bn.payInvoice(BOLT11, 60_000, bad as number),
			field: 'maxFeeSats'
		},
		{
			name: 'payInvoice(amountSats)',
			engineMethod: 'sendPayment',
			call: (bn, bad): unknown =>
				bn.payInvoice(BOLT11, 60_000, undefined, bad as number),
			field: 'amountSats'
		},
		{
			name: 'sendPaymentAsync(maxFeeSats)',
			engineMethod: 'sendPayment',
			call: (bn, bad): unknown => bn.sendPaymentAsync(BOLT11, bad as number),
			field: 'maxFeeSats'
		},
		{
			name: 'sendPaymentAsync(amountSats)',
			engineMethod: 'sendPayment',
			call: (bn, bad): unknown =>
				bn.sendPaymentAsync(BOLT11, undefined, bad as number),
			field: 'amountSats'
		},
		{
			name: 'sendKeysend(amountSats)',
			engineMethod: 'sendKeysend',
			call: (bn, bad): unknown => bn.sendKeysend(PUBKEY, bad as number),
			field: 'amountSats'
		},
		{
			name: 'sendKeysend(maxFeeSats)',
			engineMethod: 'sendKeysend',
			call: (bn, bad): unknown =>
				bn.sendKeysend(PUBKEY, 1_000, 60_000, bad as number),
			field: 'maxFeeSats'
		},
		{
			name: 'queryRoute(maxFeeSats)',
			engineMethod: 'queryRoute',
			call: (bn, bad): unknown =>
				bn.queryRoute('02' + 'cd'.repeat(32), 1_000, bad as number),
			field: 'maxFeeSats'
		},
		{
			name: 'canSend(amountSats)',
			engineMethod: 'listChannels',
			call: (bn, bad): unknown => bn.canSend(bad as number),
			field: 'amountSats'
		},
		{
			name: 'canReceive(amountSats)',
			engineMethod: 'listChannels',
			call: (bn, bad): unknown => bn.canReceive(bad as number),
			field: 'amountSats'
		},
		{
			name: 'updateChannelPolicy(htlcMinimumMsat)',
			engineMethod: 'setChannelPolicy',
			call: (bn, bad): unknown =>
				bn.updateChannelPolicy(CHANNEL_ID, {
					htlcMinimumMsat: bad as number
				}),
			field: 'htlcMinimumMsat'
		},
		{
			name: 'updateChannelPolicy(htlcMaximumMsat)',
			engineMethod: 'setChannelPolicy',
			call: (bn, bad): unknown =>
				bn.updateChannelPolicy(CHANNEL_ID, {
					htlcMaximumMsat: bad as number
				}),
			field: 'htlcMaximumMsat'
		}
	];

	for (const entry of ENTRY_POINTS) {
		/** An engine that must never be reached: the guard runs first. */
		const guarded = (): BeignetNode =>
			payingNode({
				[entry.engineMethod]: (): never => {
					expect.fail(`${entry.name}: the engine was reached past the guard`);
				},
				setPaymentMetadata: (): void => {},
				listChannels: (): unknown[] => []
			});

		for (const [label, bad] of [
			['fractional', 1.5],
			['negative', -1],
			['non-finite', Number.POSITIVE_INFINITY],
			['unsafe', Number.MAX_SAFE_INTEGER + 2]
		] as Array<[string, unknown]>) {
			it(`${entry.name} refuses a ${label} value`, async () => {
				const bn = guarded();
				const err = await asyncRefusalFrom(
					async () => entry.call(bn, bad),
					entry.name
				);
				expect(err.code, entry.name).to.equal(BeignetErrorCode.INVALID_PARAMS);
				expect(err.message, entry.name).to.contain(entry.field);
				expect(statusForErrorCode(err.code), entry.name).to.equal(400);
				// Nothing was reserved for a request that never started.
				expect(pendingOf(bn), entry.name).to.equal(0);
			});
		}
	}

	it('a repeated bad maxFeeSats does not ratchet the spend reservation', async () => {
		const bn = payingNode({
			sendPayment: (): never => expect.fail('the engine was reached'),
			setPaymentMetadata: (): void => {}
		});
		for (let i = 0; i < 3; i++) {
			const err = await asyncRefusalFrom(
				async () => bn.payInvoice(BOLT11, 60_000, 1.5),
				'payInvoice'
			);
			expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		}
		// Each refusal used to leave the invoice's own 250 000 sats reserved,
		// so three of them put 750 000 sats permanently against the limit.
		expect(pendingOf(bn)).to.equal(0);
	});

	it('payInvoice releases the reservation when the send is refused', async () => {
		const bn = payingNode({
			setPaymentMetadata: (): void => {},
			failPayment: (): void => {},
			on: (): void => {},
			removeListener: (): void => {},
			sendPayment: (): never => {
				throw Object.assign(new Error('No route found'), { code: 'NO_ROUTE' });
			}
		});
		const err = await asyncRefusalFrom(
			async () => bn.payInvoice(BOLT11, 60_000),
			'payInvoice'
		);
		expect(err.code).to.equal(BeignetErrorCode.NO_ROUTE);
		// A payment that never started holds no capacity.
		expect(pendingOf(bn)).to.equal(0);
	});

	it('sendKeysend releases the reservation when the send throws', async () => {
		const bn = payingNode({
			sendKeysend: (): never => {
				throw new Error('boom');
			}
		});
		try {
			await bn.sendKeysend(PUBKEY, 5_000);
			expect.fail('expected the keysend to fail');
		} catch (err: unknown) {
			expect((err as Error).message).to.equal('boom');
		}
		expect(pendingOf(bn)).to.equal(0);
	});

	it('a settled keysend records the spend exactly once', async () => {
		const bn = payingNode(
			{
				sendKeysend: (): unknown => ({
					paymentHash: Buffer.alloc(32, 1),
					amountMsat: 5_000_000n,
					status: 'COMPLETED',
					direction: 'OUTGOING',
					createdAt: 0
				}),
				listChannels: (): unknown[] => []
			},
			1_000_000
		);
		await bn.sendKeysend(PUBKEY, 5_000);
		expect(pendingOf(bn)).to.equal(0);
		expect(
			(bn as unknown as { _dailySpentSats: number })._dailySpentSats
		).to.equal(5_000);
	});

	it('a string amount never reaches the spend accounting', async () => {
		const bn = payingNode({
			sendPayment: (): never => expect.fail('the engine was reached'),
			setPaymentMetadata: (): void => {}
		});
		const err = await asyncRefusalFrom(
			async () =>
				bn.payInvoice(BOLT11, 60_000, undefined, '1000' as unknown as number),
			'payInvoice'
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
		// BigInt('1000') would have succeeded, so the string used to reach the
		// limit math, where + concatenates instead of adding.
		expect(typeof pendingOf(bn)).to.equal('number');
		expect(pendingOf(bn)).to.equal(0);
	});

	it('a zero fee ceiling and an amountless invoice still work', () => {
		const bn = payingNode({
			createInvoice: (opts: { amountMsat?: bigint }): unknown => ({
				bolt11: 'lnbcrt1',
				paymentHash: Buffer.alloc(32),
				paymentSecret: Buffer.alloc(32),
				amountMsat: opts.amountMsat
			})
		});
		// Zero means "amountless", the BOLT 11 shape the guard must not refuse.
		expect(bn.createInvoice(0).amountSats).to.equal(undefined);
		expect(bn.createInvoice(undefined).amountSats).to.equal(undefined);
		expect(bn.createInvoice(1_000).amountSats).to.equal(1_000);
	});

	it('accepts a decimal-string msat policy field, and refuses a word', () => {
		let seen: { htlcMinimumMsat?: bigint } | undefined;
		const bn = payingNode({
			setChannelPolicy: (
				_id: unknown,
				update: { htlcMinimumMsat?: bigint }
			) => {
				seen = update;
			},
			listChannels: (): unknown[] => [],
			getChannelPolicy: (): undefined => undefined
		});
		bn.updateChannelPolicy(CHANNEL_ID, { htlcMinimumMsat: '1000' });
		expect(seen?.htlcMinimumMsat).to.equal(1000n);
		const err = refusalFrom(
			() => bn.updateChannelPolicy(CHANNEL_ID, { htlcMinimumMsat: 'lots' }),
			'updateChannelPolicy'
		);
		expect(err.code).to.equal(BeignetErrorCode.INVALID_PARAMS);
	});

	it('closes: an unknown channel is CHANNEL_NOT_FOUND, not a 500 grab-bag', () => {
		const bn = nodeWithEngine({
			getChannel: (): undefined => undefined,
			getFundingAddress: (): string =>
				'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
			getRecoveryStatus: (): unknown => ({ channels: [] }),
			closeChannel: (): never => expect.fail('the engine was reached'),
			forceCloseChannel: (): never => expect.fail('the engine was reached')
		});
		for (const [label, call] of [
			['closeChannel', (): unknown => bn.closeChannel(CHANNEL_ID)],
			['forceCloseChannel', (): unknown => bn.forceCloseChannel(CHANNEL_ID)]
		] as Array<[string, () => unknown]>) {
			const err = refusalFrom(call, label);
			expect(err.code, label).to.equal(BeignetErrorCode.CHANNEL_NOT_FOUND);
			expect(statusForErrorCode(err.code), label).to.equal(404);
			expect(err.message, label).to.contain(CHANNEL_ID);
		}
	});

	it('closes: a malformed channel id is refused, not truncated', () => {
		const bn = nodeWithEngine({
			getChannel: (): never => expect.fail('the id guard was skipped'),
			getFundingAddress: (): never => expect.fail('the id guard was skipped'),
			getRecoveryStatus: (): unknown => ({ channels: [] })
		});
		for (const [label, call] of [
			['closeChannel', (): unknown => bn.closeChannel('cd')],
			['forceCloseChannel', (): unknown => bn.forceCloseChannel('cd')]
		] as Array<[string, () => unknown]>) {
			const err = refusalFrom(call, label);
			expect(err.code, label).to.equal(BeignetErrorCode.INVALID_PARAMS);
			expect(statusForErrorCode(err.code), label).to.equal(400);
		}
	});

	it('keeps CLOSE_FAILED for a channel that exists and would not close', () => {
		const bn = nodeWithEngine({
			getChannel: (): unknown => ({ channelId: Buffer.alloc(32) }),
			getFundingAddress: (): string =>
				'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080',
			closeChannel: (): unknown => ({
				ok: false,
				error: 'channel is quiescing'
			})
		});
		const result = bn.closeChannel(CHANNEL_ID);
		expect(result.ok).to.equal(false);
		expect(result.error).to.equal('channel is quiescing');
	});
});
