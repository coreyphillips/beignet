/**
 * Issue #1042: the spending rails cover circular rebalances and the external
 * on-chain sends.
 *
 * A rebalance's amount comes back round the loop, but its routing fee is a
 * real spend, and the rebalance is an outgoing payment a draining node would
 * have to wait on. Both entry points went straight to the engine. And
 * maxPaymentSats was enforced on Lightning payments only, so a caller with a
 * per-payment cap and no daily limit could send any amount on-chain.
 *
 * Every case drives the real BeignetNode method over Object.create of its
 * prototype with the engine or wallet stubbed, so the admission code under
 * test is the shipped code with none of the node boot.
 */

import { expect } from 'chai';
import * as bitcoin from 'bitcoinjs-lib';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import { ok } from '../../src/utils/result';

const CHANNEL_A = 'aa'.repeat(32);
const CHANNEL_B = 'bb'.repeat(32);

const REGTEST_ADDRESS = bitcoin.payments.p2wpkh({
	pubkey: Buffer.from(
		'0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
		'hex'
	),
	network: bitcoin.networks.regtest
}).address!;

interface Ledger {
	_dailySpendLimitSats?: number;
	_maxPaymentSats?: number;
	_dailySpentSats: number;
	_dailySpentLightningSats: number;
	_dailySpentOnchainSats: number;
	_pendingSpendSats: number;
	_dailySpendResetTime: number;
	_asyncSpendClaims: Map<string, unknown>;
	_draining: boolean;
	logLevel: string;
}

/** The methods under test, over the ledger BeignetNode keeps private. */
type Fake<T> = Ledger &
	T &
	Pick<
		BeignetNode,
		| 'rebalanceChannel'
		| 'executeRebalances'
		| 'sendOnchain'
		| 'sendMaxOnchain'
		| 'spliceOut'
		| 'sendDirectFunding'
	>;

/** A BeignetNode with the spend ledger set and `extra` laid over it. */
function fakeNode<T extends object>(
	limits: { daily?: number; maxPayment?: number },
	extra: T
): Fake<T> {
	const ledger: Ledger = {
		_dailySpendLimitSats: limits.daily,
		_maxPaymentSats: limits.maxPayment,
		_dailySpentSats: 0,
		_dailySpentLightningSats: 0,
		_dailySpentOnchainSats: 0,
		_pendingSpendSats: 0,
		_dailySpendResetTime: Date.now() + 24 * 60 * 60 * 1000,
		_asyncSpendClaims: new Map(),
		_draining: false,
		logLevel: 'silent'
	};
	return Object.assign(
		Object.create(BeignetNode.prototype),
		ledger,
		extra
	) as Fake<T>;
}

async function refusal(fn: () => Promise<unknown>): Promise<BeignetError> {
	try {
		await fn();
	} catch (err: unknown) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	return expect.fail('expected a refusal');
}

describe('Issue #1042: rebalances under the drain and the daily limit', () => {
	function rebalancingNode(
		limits: { daily?: number; maxPayment?: number },
		engine: {
			feeMsat?: bigint;
			fails?: boolean;
			feeSpentMsat?: bigint;
			budgetSatsPerDay?: number;
		} = {}
	): Fake<{ engineCalls: number; pendingDuringCall: number[] }> {
		const node = fakeNode(limits, {
			engineCalls: 0,
			pendingDuringCall: [] as number[],
			node: {
				rebalanceChannel: async (): Promise<unknown> => {
					node.engineCalls++;
					node.pendingDuringCall.push(node._pendingSpendSats);
					if (engine.fails) throw new Error('No circular route');
					return {
						paymentHash: Buffer.alloc(32, 1),
						amountMsat: 100_000_000n,
						feeMsat: engine.feeMsat ?? 0n,
						hops: 3
					};
				},
				rebalanceBudgetSatsPerDay: (given?: number): number =>
					given ?? engine.budgetSatsPerDay ?? 1_000,
				executeRebalanceRecommendations: async (): Promise<unknown> => {
					node.engineCalls++;
					node.pendingDuringCall.push(node._pendingSpendSats);
					return {
						attempts: [],
						succeeded: 1,
						failed: 0,
						skippedBudget: 0,
						feeSpentMsat: engine.feeSpentMsat ?? 0n,
						budgetRemainingMsat: 0n
					};
				}
			}
		});
		return node;
	}

	it('refuses a rebalance while draining, before the engine', async () => {
		const node = rebalancingNode({});
		node._draining = true;
		const err = await refusal(() =>
			node.rebalanceChannel(CHANNEL_A, CHANNEL_B, 100_000, 500)
		);
		expect(err.code).to.equal('SERVICE_DRAINING');
		expect(node.engineCalls).to.equal(0);
	});

	it('refuses a rebalance whose fee cap does not fit the day', async () => {
		const node = rebalancingNode({ daily: 10_000 });
		node._dailySpentSats = 10_000;
		const err = await refusal(() =>
			node.rebalanceChannel(CHANNEL_A, CHANNEL_B, 1_000_000, 50_000)
		);
		expect(err.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(node.engineCalls).to.equal(0);
	});

	it('holds the fee cap in flight and charges the fee paid, rounded up', async () => {
		const node = rebalancingNode({ daily: 100_000 }, { feeMsat: 1_234_500n });
		const result = await node.rebalanceChannel(
			CHANNEL_A,
			CHANNEL_B,
			100_000,
			5_000
		);
		expect(result.feeMsat).to.equal('1234500');
		expect(node.pendingDuringCall).to.deep.equal([5_000]);
		expect(node._pendingSpendSats).to.equal(0);
		expect(node._dailySpentSats).to.equal(1_235);
		expect(node._dailySpentLightningSats).to.equal(1_235);
		// The amount returns: only the fee is spent.
		expect(node._dailySpentOnchainSats).to.equal(0);
	});

	it('gives the hold back and charges nothing when the rebalance fails', async () => {
		const node = rebalancingNode({ daily: 100_000 }, { fails: true });
		let threw = false;
		try {
			await node.rebalanceChannel(CHANNEL_A, CHANNEL_B, 100_000, 5_000);
		} catch {
			threw = true;
		}
		expect(threw).to.equal(true);
		expect(node._pendingSpendSats).to.equal(0);
		expect(node._dailySpentSats).to.equal(0);
	});

	it('leaves maxPaymentSats out of a rebalance', async () => {
		const node = rebalancingNode({ maxPayment: 1_000 }, { feeMsat: 10_000n });
		const result = await node.rebalanceChannel(
			CHANNEL_A,
			CHANNEL_B,
			100_000,
			500
		);
		expect(result.feeSats).to.equal(10);
		expect(node.engineCalls).to.equal(1);
	});

	it('refuses an advisor run while draining, before the engine', async () => {
		const node = rebalancingNode({});
		node._draining = true;
		const err = await refusal(() => node.executeRebalances(1_000));
		expect(err.code).to.equal('SERVICE_DRAINING');
		expect(node.engineCalls).to.equal(0);
	});

	it('refuses an advisor run whose day budget does not fit the limit', async () => {
		// No budget given: the configured one is what the run is held at.
		const node = rebalancingNode(
			{ daily: 10_000 },
			{ budgetSatsPerDay: 2_000 }
		);
		node._dailySpentSats = 9_000;
		const err = await refusal(() => node.executeRebalances());
		expect(err.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(node.engineCalls).to.equal(0);
	});

	it('holds the day budget during a run and charges the fees it paid', async () => {
		const node = rebalancingNode(
			{ daily: 10_000 },
			{ feeSpentMsat: 2_000_001n }
		);
		const summary = await node.executeRebalances(1_500);
		expect(summary.feeSpentMsat).to.equal('2000001');
		expect(node.pendingDuringCall).to.deep.equal([1_500]);
		expect(node._pendingSpendSats).to.equal(0);
		expect(node._dailySpentSats).to.equal(2_001);
		expect(node._dailySpentLightningSats).to.equal(2_001);
	});
});

describe('Issue #1042: maxPaymentSats on the external on-chain sends', () => {
	const FEE_SATS = 150;

	function walletNode(
		limits: { daily?: number; maxPayment?: number },
		sweepInputSats = 0
	): Fake<{ built: number; broadcasts: string[] }> {
		const node = fakeNode(limits, {
			built: 0,
			broadcasts: [] as string[],
			wallet: {
				rbf: true,
				feeEstimates: { normal: 2 },
				validateAddress: (): boolean => true,
				send: async (): Promise<unknown> => {
					node.built++;
					return ok('00');
				},
				sendMax: async (): Promise<unknown> => {
					node.built++;
					return ok('00');
				},
				transaction: {
					data: { fee: FEE_SATS, inputs: [] },
					getTransactionInputValue: (): number => sweepInputSats
				},
				resetSendTransaction: async (): Promise<unknown> => ok('reset')
			},
			_broadcastRawTx: async (hex: string): Promise<unknown> => {
				node.broadcasts.push(hex);
				return { txid: 'ab'.repeat(32), hex };
			}
		});
		return node;
	}

	it('refuses a send whose amount is over the cap before building it', async () => {
		// The guide's first example: a per-payment cap and no daily limit.
		const node = walletNode({ maxPayment: 100_000 });
		const err = await refusal(() =>
			node.sendOnchain(REGTEST_ADDRESS, 5_000_000)
		);
		expect(err.code).to.equal('SPENDING_LIMIT_EXCEEDED');
		expect(err.message).to.equal(
			'Payment amount 5000000 sats exceeds per-payment limit of 100000 sats'
		);
		expect(node.built).to.equal(0);
	});

	it('refuses a send that crosses the cap only with its fee, unbroadcast', async () => {
		const node = walletNode({ maxPayment: 100_000 });
		const err = await refusal(() =>
			node.sendOnchain(REGTEST_ADDRESS, 99_900, 2)
		);
		expect(err.message).to.equal(
			'Payment amount 99900 sats plus up to 150 sats in on-chain fees exceeds per-payment limit of 100000 sats; lower satsPerVbyte or the amount'
		);
		expect(node.broadcasts).to.deep.equal([]);
	});

	it('sends within the cap', async () => {
		const node = walletNode({ maxPayment: 100_000 });
		await node.sendOnchain(REGTEST_ADDRESS, 99_850, 2);
		expect(node.broadcasts).to.deep.equal(['00']);
	});

	it('refuses a sweep over the cap, unbroadcast', async () => {
		const node = walletNode({ maxPayment: 100_000 }, 250_000);
		const err = await refusal(() => node.sendMaxOnchain(REGTEST_ADDRESS, 2));
		expect(err.message).to.equal(
			'Payment amount 250000 sats exceeds per-payment limit of 100000 sats'
		);
		expect(node.broadcasts).to.deep.equal([]);
	});

	it('refuses an address-targeted splice-out over the cap, before the engine', () => {
		let engineCalls = 0;
		const node = fakeNode(
			{ maxPayment: 100_000 },
			{
				getBitcoinNetwork: (): unknown => bitcoin.networks.regtest,
				node: {
					spliceOut: (): { ok: boolean } => {
						engineCalls++;
						return { ok: true };
					}
				}
			}
		);
		expect(() =>
			node.spliceOut(CHANNEL_A, 5_000_000, 2500, REGTEST_ADDRESS)
		).to.throw('Payment amount 5000000 sats exceeds per-payment limit');
		expect(engineCalls).to.equal(0);
		// Wallet-credited: the funds come back to us, so no cap applies.
		expect(node.spliceOut(CHANNEL_A, 5_000_000, 2500).ok).to.equal(true);
		expect(engineCalls).to.equal(1);
	});

	it('refuses a direct-funding send over the cap, before the exchange', async () => {
		let sends = 0;
		const node = fakeNode(
			{ maxPayment: 100_000 },
			{
				directFundingSender: {
					isReplay: (): boolean => false,
					quote: (): { amountSat: bigint; maxTotalFeeSat: bigint } => ({
						amountSat: 99_000n,
						maxTotalFeeSat: 2_000n
					}),
					send: async (): Promise<unknown> => {
						sends++;
						return { status: 'ACCEPTED', offerId: 'x' };
					}
				}
			}
		);
		const err = await refusal(() =>
			node.sendDirectFunding({ request: 'df-request' })
		);
		expect(err.message).to.equal(
			'Payment amount 99000 sats plus up to 2000 sats in fees exceeds per-payment limit of 100000 sats; lower maxTotalFeeSat or the amount'
		);
		expect(sends).to.equal(0);
	});
});
