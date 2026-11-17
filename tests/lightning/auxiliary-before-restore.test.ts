/**
 * INodeConfig.beforeRestore (issue #2093): a host is handed the node when it
 * is built and before it restores from storage, so that the hooks of its
 * asset channel provider are bound to the node by the time a stored channel
 * can call one.
 *
 * The provider here is like a host's own: every hook fails closed until the
 * node was given to it.
 */

import { expect } from 'chai';
import type { IChannelAuxiliaryProvider } from '../../src/lightning/channel/auxiliary';
import type { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { INodeConfig } from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import {
	assetHost,
	connectHosts,
	IAssetHost,
	openAssetChannel,
	withAssetOpens
} from './helpers/auxiliary-nodes';
import { referenceProvider } from './helpers/auxiliary-pair';
import { makeNodeConfig } from './helpers/loopback-nodes';

interface IBinding {
	/** The node the host was given, once it was. */
	node?: LightningNode;
	/** Every hook the node called, and whether the host was bound by then. */
	calls: Array<{ hook: string; bound: boolean }>;
	/** What happened, in order: the binding, and each read of the stored rows. */
	order: string[];
	provider: IChannelAuxiliaryProvider;
}

/** A provider whose every hook refuses to run until its node is bound. */
function failClosed(): IBinding {
	const binding: IBinding = {
		calls: [],
		order: [],
		provider: undefined as unknown as IChannelAuxiliaryProvider
	};
	binding.provider = new Proxy(referenceProvider(), {
		get(target, name, receiver): unknown {
			const member = Reflect.get(target, name, receiver);
			if (typeof member !== 'function') return member;
			return (...args: unknown[]): unknown => {
				const bound = binding.node !== undefined;
				binding.calls.push({ hook: String(name), bound });
				if (!bound) throw new Error('the asset host is not bound to a node');
				return (member as (...given: unknown[]) => unknown).apply(target, args);
			};
		}
	});
	return binding;
}

describe('INodeConfig.beforeRestore: the node is handed over before it restores', () => {
	withAssetOpens();

	let live: LightningNode[];
	let hosts: IAssetHost[];

	beforeEach(() => {
		live = [];
		hosts = [];
	});

	afterEach(() => {
		for (const node of live) node.destroy();
		for (const host of hosts) host.node.destroy();
	});

	/** Storage holding one asset channel in NORMAL, and that channel's id. */
	const storedAssetChannel = async (
		tag: string
	): Promise<{ storage: MemoryStorage; channelId: Buffer }> => {
		const storage = new MemoryStorage();
		const alice = assetHost(tag, 1, {}, { extra: { storage } });
		const bob = assetHost(tag, 2);
		hosts.push(bob);
		connectHosts(alice, bob);
		const channelId = await openAssetChannel(alice, bob, {
			tag,
			openerUnits: 900n,
			acceptorUnits: 100n
		});
		alice.node.destroy();
		return { storage, channelId };
	};

	/** The config of the stored node again, over a storage whose reads are told. */
	const configOver = (
		tag: string,
		storage: MemoryStorage,
		binding: IBinding
	): INodeConfig => {
		const load = storage.loadAllChannels.bind(storage);
		storage.loadAllChannels = (): ReturnType<typeof load> => {
			binding.order.push('rows read');
			return load();
		};
		return {
			...makeNodeConfig(tag, 1),
			storage,
			auxiliaryChannels: {
				provider: binding.provider,
				allowLegacyHtlcSignatures: () => true,
				resolveIncoming: () => undefined
			}
		};
	};

	for (const path of ['the constructor', 'LightningNode.create'] as const) {
		it(`is called by ${path} with the node, once, before a stored row is read`, async () => {
			const { storage, channelId } = await storedAssetChannel(
				`before-restore ${path}`
			);
			const binding = failClosed();
			let restoredAtBind: unknown = 'not called';
			const config: INodeConfig = {
				...configOver(`before-restore ${path}`, storage, binding),
				beforeRestore: (node): void => {
					binding.order.push('bound');
					// Nothing was restored yet: the node is only kept.
					restoredAtBind = node.getAuxiliaryChannelInfo(channelId);
					binding.node = node;
				}
			};
			const node =
				path === 'the constructor'
					? new LightningNode(config)
					: await LightningNode.create(config);
			live.push(node);

			expect(binding.node).to.equal(node);
			expect(binding.order[0]).to.equal('bound');
			expect(binding.order.filter((event) => event === 'bound')).to.have.length(
				1
			);
			expect(binding.order).to.include('rows read');
			expect(restoredAtBind).to.equal(undefined);
			// The stored asset channel was restored with the provider.
			expect(node.getAuxiliaryChannelInfo(channelId)).to.not.equal(undefined);
			// And every hook it called on the way found the node bound.
			expect(binding.calls.filter((call) => !call.bound)).to.deep.equal([]);
		});
	}

	it('finds the node bound in a hook the restored channel calls', async () => {
		const tag = 'before-restore hook';
		const { storage, channelId } = await storedAssetChannel(tag);
		const binding = failClosed();
		const node = new LightningNode({
			...configOver(tag, storage, binding),
			beforeRestore: (given): void => {
				binding.node = given;
			}
		});
		live.push(node);
		const before = binding.calls.length;
		// The restored channel carries the provider, and the next commitment
		// it builds for the peer asks it for the asset outputs.
		const state = (
			node as unknown as { channelManager: ChannelManager }
		).channelManager
			.getChannel(channelId)!
			.getFullState();
		expect(state.auxiliaryProvider).to.equal(binding.provider);
		buildRemoteCommitment(
			state,
			state.remoteCurrentPerCommitmentPoint!,
			state.remoteCommitmentNumber + 1n
		);
		expect(binding.calls.length).to.be.greaterThan(before);
		expect(binding.calls.filter((call) => !call.bound)).to.deep.equal([]);
	});

	it('ends the construction before a row is read when it throws', async () => {
		const tag = 'before-restore refusal';
		const { storage } = await storedAssetChannel(tag);
		const before = storage.loadAllChannels();
		const binding = failClosed();
		let given: LightningNode | undefined;
		expect(
			() =>
				new LightningNode({
					...configOver(tag, storage, binding),
					beforeRestore: (node): void => {
						given = node;
						throw new Error('this host is bound to another node');
					}
				})
		).to.throw('this host is bound to another node');
		given?.destroy();
		expect(binding.order).to.deep.equal([]);
		expect(binding.calls).to.deep.equal([]);
		expect(storage.loadAllChannels()).to.deep.equal(before);
	});

	it('is not called on a node that was not given it', async () => {
		const tag = 'before-restore absent';
		const { storage, channelId } = await storedAssetChannel(tag);
		const binding = failClosed();
		// Bound from the start, as a host with nothing to wait for is.
		binding.node = {} as LightningNode;
		const config = configOver(tag, storage, binding);
		expect(config).to.not.have.property('beforeRestore');
		const node = new LightningNode(config);
		live.push(node);
		expect(node.getAuxiliaryChannelInfo(channelId)).to.not.equal(undefined);
		expect(binding.order).to.deep.equal(['rows read']);
	});
});
