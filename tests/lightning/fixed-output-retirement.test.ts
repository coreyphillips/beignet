import { expect } from 'chai';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { IFundingProvider } from '../../src/lightning/node/types';
import type { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	fixedOutputHtlcFeeActionId,
	parseFixedOutputHtlcFeeActionId,
	OutputStatus,
	OutputType
} from '../../src/lightning/chain/types';
import { makeNodeConfig } from './helpers/ffor-world';
const tick = () => new Promise<void>((resolve) => setImmediate(resolve));
describe('fixed-output fee finality retirement', () => {
	it('uses exact canonical channel and source identities', () => {
		const channel = Buffer.alloc(32, 3),
			id = fixedOutputHtlcFeeActionId(channel, 'aa'.repeat(32), 7);
		expect(parseFixedOutputHtlcFeeActionId(id)).deep.equal({
			channelId: channel,
			txid: 'aa'.repeat(32),
			outputIndex: 7
		});
		for (const bad of [
			id + 'x',
			id + ':extra',
			id.replace(':7', ':07'),
			id.replace(':7', ':4294967296')
		])
			expect(parseFixedOutputHtlcFeeActionId(bad)).equal(undefined);
	});
	it('retires finalized and abandoned sources only after persisted finality, retrying failures', async () => {
		const channel = Buffer.alloc(32, 3),
			hex = channel.toString('hex'),
			txid = 'aa'.repeat(32);
		const active = fixedOutputHtlcFeeActionId(channel, txid, 0),
			orphan = fixedOutputHtlcFeeActionId(channel, 'bb'.repeat(32), 1),
			foreign = fixedOutputHtlcFeeActionId(
				Buffer.alloc(32, 4),
				'cc'.repeat(32),
				2
			);
		let fundingFinal = false,
			fail = true;
		const retired: string[] = [];
		const provider: IFundingProvider = {
			buildFundingTransaction: async () => {
				throw new Error('Unexpected funding');
			},
			broadcastTransaction: async () => {
				throw new Error('Unexpected publication');
			},
			getFixedOutputFeeActionIds: () => [
				active,
				orphan,
				foreign,
				active + ':suffix'
			],
			retireFixedOutputFeeAction: async (id) => {
				if (fail) {
					fail = false;
					throw new Error('Retirement write refused');
				}
				retired.push(id);
			}
		};
		const node = new LightningNode(
			makeNodeConfig(146, undefined, { fundingProvider: provider })
		);
		const internals = node as unknown as {
			recovery: unknown;
			dirtyMonitors: Set<string>;
			retireFinalFixedFeeActions(id: string, monitor: ChainMonitor): void;
		};
		const previousRecovery = internals.recovery;
		const source = {
			txid,
			outputIndex: 0,
			amount: 355n,
			outputType: OutputType.OFFERED_HTLC,
			status: OutputStatus.SPEND_CONFIRMED,
			confirmationHeight: 100,
			spendReverifyPending: false
		};
		const monitor = {
			getTrackedOutputs: () => [source],
			isFundingSpendIrrevocable: () => fundingFinal
		} as unknown as ChainMonitor;
		try {
			internals.retireFinalFixedFeeActions(hex, monitor);
			await tick();
			expect(retired).length(0);
			source.status = OutputStatus.IRREVOCABLY_RESOLVED;
			internals.recovery = {};
			internals.dirtyMonitors.add(hex);
			internals.retireFinalFixedFeeActions(hex, monitor);
			await tick();
			expect(retired).length(0);
			internals.dirtyMonitors.clear();
			source.spendReverifyPending = true;
			internals.retireFinalFixedFeeActions(hex, monitor);
			await tick();
			expect(retired).length(0);
			source.spendReverifyPending = false;
			internals.retireFinalFixedFeeActions(hex, monitor);
			await tick();
			expect(retired).length(0);
			internals.retireFinalFixedFeeActions(hex, monitor);
			await tick();
			expect(retired).deep.equal([active]);
			internals.retireFinalFixedFeeActions(hex, monitor);
			await tick();
			expect(retired).deep.equal([active]);
			fundingFinal = true;
			internals.retireFinalFixedFeeActions(hex, monitor);
			await tick();
			expect(retired).deep.equal([active, orphan]);
		} finally {
			internals.recovery = previousRecovery;
			node.destroy();
		}
	});
});
