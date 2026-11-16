/**
 * A node's read of its wallet's fee coin pool (issue #2093).
 *
 * getFixedOutputFeeStatus is the funding provider's own answer, handed on
 * unchanged, so an extension reaches the pool through the node it was bound
 * to. A node whose provider has no fee policy, or that has no provider,
 * answers undefined.
 */

import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IFundingProvider } from '../../src/lightning/node/types';
import { IFixedOutputFeePoolState } from '../../src/lightning/wallet/fixed-output-fees';
import { createNode } from './helpers/loopback-nodes';

describe('A node reads its fee coin pool (#2093)', function () {
	this.timeout(30_000);
	const nodes: LightningNode[] = [];

	afterEach(() => {
		for (const node of nodes.splice(0)) node.destroy();
	});

	const nodeWith = (
		seed: number,
		fundingProvider?: Partial<IFundingProvider>
	): LightningNode => {
		const node = createNode(
			'fee-status',
			seed,
			undefined,
			fundingProvider
				? { fundingProvider: fundingProvider as IFundingProvider }
				: {}
		);
		node.on('node:error', () => undefined);
		nodes.push(node);
		return node;
	};

	it('answers undefined without a funding provider, and with one that has no fee policy', () => {
		expect(nodeWith(1).getFixedOutputFeeStatus()).to.equal(undefined);
		// A provider from before the read existed.
		expect(nodeWith(2, {}).getFixedOutputFeeStatus()).to.equal(undefined);
		// One that has the read and no policy.
		expect(
			nodeWith(3, {
				getFixedOutputFeeStatus: () => undefined
			}).getFixedOutputFeeStatus()
		).to.equal(undefined);
	});

	it('hands the question, with the fee it was asked for, to the funding provider and answers what it says', () => {
		const state: IFixedOutputFeePoolState = {
			available: true,
			budget: {
				totalSatoshis: 20000n,
				reservedSatoshis: 2000n,
				spentSatoshis: 234n,
				remainingSatoshis: 17766n
			},
			feeCoins: { ready: 3, readySatoshis: 1704n, unconfirmed: 0 },
			actions: [
				{ feeActionId: 'a', capSatoshis: 2000n, inputs: 1, heldSatoshis: 568n }
			],
			splits: [],
			preparation: {
				possible: false,
				forFeeSatoshis: 2000n,
				neededSatoshis: 3000n,
				largestConfirmedSatoshis: 0n,
				reason: 'FEE_FUNDS_UNAVAILABLE'
			},
			lastRefusal: { code: 'FEE_PREPARATION_PENDING', remedy: 'wait', at: 1 }
		};
		const asked: Array<bigint | undefined> = [];
		const node = nodeWith(4, {
			getFixedOutputFeeStatus: (forFeeSatoshis?: bigint) => {
				asked.push(forFeeSatoshis);
				return state;
			}
		});
		expect(node.getFixedOutputFeeStatus()).to.equal(state);
		expect(node.getFixedOutputFeeStatus(700n)).to.equal(state);
		expect(asked).to.deep.equal([undefined, 700n]);
	});
});
