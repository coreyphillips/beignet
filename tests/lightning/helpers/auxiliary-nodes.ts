/**
 * Loopback nodes that hold asset channels, for the asset payment tests
 * (issue #2093). A host here is a node, the asset openings it will accept,
 * and what it broadcast; an asset channel between two of them is opened the
 * way a real host opens one, with a funding transaction of its own making.
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../../src/lightning/channel/auxiliary-funding';
import { auxiliaryChannelOpens } from '../../../src/lightning/channel/auxiliary-switch';
import { ChannelState } from '../../../src/lightning/channel/types';
import { randomBytes as engineRandomBytes } from '../../../src/lightning/crypto/provider';
import { Feature, FeatureFlags } from '../../../src/lightning/features/flags';
import type { LightningNode } from '../../../src/lightning/node/lightning-node';
import type {
	IFundingProvider,
	INodeConfig
} from '../../../src/lightning/node/types';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { ASSET_FUNDING_ROOT, hash, referenceProvider } from './auxiliary-pair';
import { connectNodes, createNode } from './loopback-nodes';

/**
 * Turn asset openings on for the tests of the describe block this is called
 * in, and back to what they were after it. The build keeps them off until
 * an asset channel can be closed and defended on chain.
 */
export function withAssetOpens(enabled = true): void {
	let prior = false;
	before(() => {
		prior = auxiliaryChannelOpens.enabled;
		auxiliaryChannelOpens.enabled = enabled;
	});
	after(() => {
		auxiliaryChannelOpens.enabled = prior;
	});
}

export interface IAssetHost {
	node: LightningNode;
	/** Set when the node was made with `sqlite`. */
	storage?: SqliteStorage;
	/** Asset openings this host accepts, by temporary channel id hex. */
	incoming: Map<string, IAuxiliaryFundingDescriptor>;
	/** Every funding transaction this host broadcast. */
	broadcasts: string[];
	/** Every node:error the node raised, as text. */
	errors: string[];
}

/** What a peer that runs asset channels advertises in its init. */
function assetPeerFeatures(): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.STATIC_REMOTE_KEY);
	flags.setOptional(Feature.OPTION_TAPROOT);
	flags.setOptional(Feature.OPTION_TAPROOT_OVERLAY);
	return flags;
}

/**
 * A node with asset channels configured. `hooks` are the host's callbacks
 * beyond the provider. Loopback nodes exchange no init, so the node is told
 * what its peers advertise in place of reading it.
 */
export function assetHost(
	tag: string,
	seedId: number,
	hooks: Partial<IAuxiliaryChannelConfig> = {},
	options: { sqlite?: boolean; extra?: Partial<INodeConfig> } = {}
): IAssetHost {
	const storage = options.sqlite ? new SqliteStorage(':memory:') : undefined;
	storage?.open();
	const host: IAssetHost = {
		incoming: new Map(),
		broadcasts: [],
		errors: [],
		...(storage ? { storage } : {})
	} as unknown as IAssetHost;
	host.node = createNode(tag, seedId, storage, {
		fundingProvider: {
			buildFundingTransaction: async () => {
				throw new Error('an asset channel is funded by the host');
			},
			broadcastTransaction: async (txHex: string) => {
				host.broadcasts.push(txHex);
				return 'broadcast';
			}
		} as unknown as IFundingProvider,
		auxiliaryChannels: {
			provider: referenceProvider(),
			allowLegacyHtlcSignatures: () => true,
			resolveIncoming: (_peer, id) => host.incoming.get(id.toString('hex')),
			...hooks
		},
		...options.extra
	});
	host.node.on('node:error', (error: { code?: string; message?: string }) => {
		host.errors.push(`${error.code ?? ''}: ${error.message ?? ''}`);
	});
	(
		host.node as unknown as { peerInitFeatures: () => FeatureFlags }
	).peerInitFeatures = assetPeerFeatures;
	return host;
}

/** A node without asset channels. */
export function plainHost(
	tag: string,
	seedId: number,
	options: { sqlite?: boolean } = {}
): IAssetHost {
	const storage = options.sqlite ? new SqliteStorage(':memory:') : undefined;
	storage?.open();
	const host: IAssetHost = {
		node: createNode(tag, seedId, storage),
		incoming: new Map(),
		broadcasts: [],
		errors: [],
		...(storage ? { storage } : {})
	};
	host.node.on('node:error', (error: { code?: string; message?: string }) => {
		host.errors.push(`${error.code ?? ''}: ${error.message ?? ''}`);
	});
	return host;
}

export function connectHosts(a: IAssetHost, b: IAssetHost): void {
	connectNodes(a.node, b.node);
}

const settle = async (): Promise<void> => {
	for (let i = 0; i < 20; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
};

/**
 * Open an asset channel from `opener` to `acceptor` and take it to NORMAL
 * on both sides. The opener holds `openerUnits` and the acceptor
 * `acceptorUnits`; the acceptor is pushed bitcoin to carry its side.
 */
export async function openAssetChannel(
	opener: IAssetHost,
	acceptor: IAssetHost,
	options: {
		tag: string;
		openerUnits: bigint;
		acceptorUnits: bigint;
		fundingSatoshis?: bigint;
		pushMsat?: bigint;
	}
): Promise<Buffer> {
	const funding = options.fundingSatoshis ?? 2_000_000n;
	const push = options.pushMsat ?? 500_000_000n;
	const descriptor: IAuxiliaryFundingDescriptor = {
		temporaryChannelId: hash(`asset channel ${options.tag}`),
		fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
		channelData: Buffer.from('proposed asset funding'),
		localBalance: options.openerUnits,
		remoteBalance: options.acceptorUnits
	};
	acceptor.incoming.set(descriptor.temporaryChannelId.toString('hex'), {
		...descriptor,
		localBalance: options.acceptorUnits,
		remoteBalance: options.openerUnits
	});
	const peer = acceptor.node.getNodeId();
	const channel = opener.node.openAuxiliaryChannel(
		peer,
		funding,
		descriptor,
		push
	);
	await settle();
	const state = channel.getFullState();
	if (!state.remoteBasepoints) {
		throw new Error(
			`asset opening ${options.tag} was not accepted: ${[
				...opener.errors,
				...acceptor.errors
			].join('; ')}`
		);
	}
	const tx = new bitcoin.Transaction();
	tx.version = 2;
	tx.addInput(hash(`asset funding input ${options.tag}`), 0);
	tx.setWitness(0, [Buffer.alloc(64, 7)]);
	tx.addOutput(Buffer.from('6a', 'hex'), 0);
	tx.addOutput(
		createTaprootFundingScript(
			state.localBasepoints.fundingPubkey,
			state.remoteBasepoints.fundingPubkey,
			undefined,
			ASSET_FUNDING_ROOT
		).p2trOutput,
		Number(funding)
	);
	const channelId = opener.node.fundAuxiliaryChannel(
		peer,
		descriptor.temporaryChannelId,
		tx.toHex(),
		1,
		Buffer.from('final funding proofs')
	);
	await settle();
	opener.node.handleFundingConfirmed(channelId);
	acceptor.node.handleFundingConfirmed(channelId);
	await settle();
	for (const host of [opener, acceptor]) {
		const info = host.node.getAuxiliaryChannelInfo(channelId);
		if (info?.state !== ChannelState.NORMAL) {
			throw new Error(
				`asset channel ${options.tag} did not open: ${[
					...opener.errors,
					...acceptor.errors
				].join('; ')}`
			);
		}
	}
	return channelId;
}

const realRandomBytes = crypto.randomBytes;

/**
 * Replace the platform's randomness with a counter, so two runs of one
 * flow put the same bytes on the wire. Undo with restoreRandomness.
 */
export function fixRandomness(label: string): void {
	// The engine tests its source of randomness on first use, drawing from
	// it twice. Have that done before the counter starts.
	engineRandomBytes(1);
	let counter = 0;
	(crypto as unknown as { randomBytes: unknown }).randomBytes = (
		size: number
	): Buffer => {
		const out = Buffer.alloc(size);
		const n = counter++;
		for (let i = 0; i < size; i += 32) {
			hash(`${label}:${n}:${i}`).copy(out, i);
		}
		return out;
	};
}

export function restoreRandomness(): void {
	(crypto as unknown as { randomBytes: unknown }).randomBytes = realRandomBytes;
}
