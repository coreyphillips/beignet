/**
 * A node's read of its wallet's fee coin pool (issue #2093).
 *
 * getFixedOutputFeeStatus is the funding provider's own answer, handed on
 * unchanged, so an extension reaches the pool through the node it was bound
 * to. A node whose provider has no fee policy, or that has no provider,
 * answers undefined.
 *
 * A provider whose fee policy the wallet refused says its pool is
 * unavailable, by a typed error. A node built on it keeps its asset channel
 * provider, and neither opens nor accepts an asset channel.
 */

import { expect } from 'chai';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IFundingProvider } from '../../src/lightning/node/types';
import {
	FixedOutputFeeError,
	IFixedOutputFeePoolState
} from '../../src/lightning/wallet/fixed-output-fees';
import {
	assetHost,
	connectHosts,
	IAssetHost,
	openAssetChannel,
	withAssetOpens
} from './helpers/auxiliary-nodes';
import { ASSET_FUNDING_ROOT } from './helpers/auxiliary-pair';
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

describe('A node whose wallet refused the fee policy of its asset channels (#2093)', function () {
	this.timeout(30_000);
	withAssetOpens();

	const refusal = new FixedOutputFeeError(
		'FEE_POLICY_REFUSED',
		'operator',
		'The wallet refused the fixed-output fee policy of extension "assets": too small'
	);
	let hosts: IAssetHost[];

	beforeEach(() => {
		hosts = [];
	});

	afterEach(() => {
		for (const host of hosts) host.node.destroy();
	});

	const host = (tag: string, seedId: number, refused: boolean): IAssetHost => {
		const broadcasts: string[] = [];
		const made = assetHost(
			tag,
			seedId,
			{},
			refused
				? {
						extra: {
							fundingProvider: {
								buildFundingTransaction: async () => {
									throw new Error('an asset channel is funded by the host');
								},
								broadcastTransaction: async (txHex: string) => {
									broadcasts.push(txHex);
									return 'broadcast';
								},
								supportsFixedOutputFees: () => false,
								getFixedOutputFeeStatus: () => ({
									available: false as const,
									error: refusal
								})
							} as unknown as IFundingProvider
						}
				  }
				: {}
		);
		hosts.push(made);
		return made;
	};

	it('keeps its asset channel provider and says its fee coin pool is unavailable, with the refusal', () => {
		const alice = host('refused status', 1, true);
		expect(alice.node.getFixedOutputFeeStatus()).to.deep.equal({
			available: false,
			error: refusal
		});
		expect(alice.node)
			.to.have.property('auxiliaryChannels')
			.that.is.an('object');
	});

	it('refuses to open an asset channel, with the refusal itself, and sends nothing', () => {
		const tag = 'refused open';
		const alice = host(tag, 1, true);
		const bob = host(tag, 2, false);
		connectHosts(alice, bob);
		let thrown: unknown;
		try {
			alice.node.openAuxiliaryChannel(bob.node.getNodeId(), 2_000_000n, {
				temporaryChannelId: Buffer.alloc(32, 7),
				fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
				channelData: Buffer.from('proposed asset funding'),
				localBalance: 900n,
				remoteBalance: 100n
			});
		} catch (err) {
			thrown = err;
		}
		expect(thrown).to.equal(refusal);
		expect(alice.node.listChannels()).to.have.length(0);
		expect(bob.node.listChannels()).to.have.length(0);
	});

	it('refuses to accept an asset channel, and tells the peer no more than that', async () => {
		const tag = 'refused accept';
		const alice = host(tag, 1, false);
		const bob = host(tag, 2, true);
		connectHosts(alice, bob);
		const told: string[] = [];
		bob.node.on('message:outbound', (_peer: string, type: number, payload) => {
			if (type === MessageType.ERROR) {
				told.push((payload as Buffer).toString('latin1'));
			}
		});
		const reasons: string[] = [];
		(
			bob.node as unknown as {
				channelManager: {
					on(event: 'error', listener: (...args: unknown[]) => void): void;
				};
			}
		).channelManager.on('error', (...args: unknown[]) => {
			reasons.push(args.map((arg) => String(arg)).join(' '));
		});
		let failure: unknown;
		try {
			await openAssetChannel(alice, bob, {
				tag,
				openerUnits: 900n,
				acceptorUnits: 100n
			});
		} catch (err) {
			failure = err;
		}
		expect(failure).to.be.instanceOf(Error);
		expect((failure as Error).message).to.match(/was not accepted/);
		// The node knows why.
		expect(reasons.join('\n')).to.match(
			/open_channel refused: The wallet refused the fixed-output fee policy of extension "assets": too small/
		);
		// The peer is told the opening was refused, and nothing of this
		// node's wallet.
		expect(told).to.have.length(1);
		expect(told[0]).to.include(
			'open_channel refused: the asset channel could not be accepted'
		);
		expect(told[0]).to.not.match(/fee|wallet|policy/i);
		expect(bob.node.listChannels()).to.have.length(0);
	});

	it('opens and accepts asset channels as before when the wallet took the policy, or was given none', async () => {
		const tag = 'policy taken';
		const alice = host(tag, 1, false);
		const bob = host(tag, 2, false);
		connectHosts(alice, bob);
		expect(alice.node.getFixedOutputFeeStatus()).to.equal(undefined);
		await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 900n,
			acceptorUnits: 100n
		});
		expect(alice.node.listChannels()).to.have.length(1);
		expect(bob.node.listChannels()).to.have.length(1);
	});
});
