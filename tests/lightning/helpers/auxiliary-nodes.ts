/**
 * Loopback nodes that hold asset channels, for the asset payment tests
 * (issue #2093). A host here is a node, the asset openings it will accept,
 * and what it broadcast; an asset channel between two of them is opened the
 * way a real host opens one, with a funding transaction of its own making.
 */

import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import type { IChannelAuxiliaryProvider } from '../../../src/lightning/channel/auxiliary';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../../src/lightning/channel/auxiliary-funding';
import {
	auxiliaryChannelOpens,
	auxiliaryForwards
} from '../../../src/lightning/channel/auxiliary-switch';
import * as auxiliarySwitches from '../../../src/lightning/channel/auxiliary-switch';
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
import { connectNodes, createNode, makeNodeConfig } from './loopback-nodes';

/**
 * Set asset openings on, or off, for the tests of the describe block this
 * is called in, and back to what they were after it. The build has them
 * on; a block that calls this says that it depends on them.
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

/**
 * Set forwards with an asset leg on, or off, for the tests of the describe
 * block this is called in, and back to what they were after it (issue
 * #2098). The build has them on since step 5 of that issue; a block that
 * calls this says that it depends on them, or with `false` on their
 * absence.
 */
export function withAssetForwards(enabled = true): void {
	let prior = false;
	before(() => {
		prior = auxiliaryForwards.enabled;
		auxiliaryForwards.enabled = enabled;
	});
	after(() => {
		auxiliaryForwards.enabled = prior;
	});
}

/**
 * The build's switch for collecting an asset invoice's parts (issue #2098,
 * step 8), or undefined in a build that has none. Read from the module as
 * a namespace, so a test file that uses it loads on a build before it.
 */
export function assetPartsSwitch(): { enabled: boolean } | undefined {
	return (
		auxiliarySwitches as unknown as {
			auxiliaryPartsReceived?: { enabled: boolean };
		}
	).auxiliaryPartsReceived;
}

/**
 * Set the collecting of an asset invoice's parts on, or off, for the tests
 * of the describe block this is called in, and back to what it was after
 * it (issue #2098, step 8). A build without the switch is left as it is.
 */
export function withAssetPartsReceived(enabled = true): void {
	let prior: boolean | undefined;
	before(() => {
		const parts = assetPartsSwitch();
		if (!parts) return;
		prior = parts.enabled;
		parts.enabled = enabled;
	});
	after(() => {
		const parts = assetPartsSwitch();
		if (parts && prior !== undefined) parts.enabled = prior;
	});
}

/**
 * A host's opt-in to being paid an asset invoice in parts (issue #2098,
 * step 8): `receiveInParts: true` in its auxiliary channel configuration.
 * Typed loosely, so that it also builds where the field is not declared.
 */
export const RECEIVE_IN_PARTS = {
	receiveInParts: true
} as unknown as Partial<IAuxiliaryChannelConfig>;

/**
 * The build's switch for sending an asset payment in parts (issue #2098,
 * step 9), or undefined in a build that has none. Read from the module as
 * a namespace, so a test file that uses it loads on a build before it.
 */
export function assetPartsSentSwitch(): { enabled: boolean } | undefined {
	return (
		auxiliarySwitches as unknown as {
			auxiliaryPartsSent?: { enabled: boolean };
		}
	).auxiliaryPartsSent;
}

/**
 * Set the sending of an asset payment in parts on, or off, for the tests
 * of the describe block this is called in, and back to what it was after
 * it (issue #2098, step 9). A build without the switch is left as it is.
 */
export function withAssetPartsSent(enabled = true): void {
	let prior: boolean | undefined;
	before(() => {
		const parts = assetPartsSentSwitch();
		if (!parts) return;
		prior = parts.enabled;
		parts.enabled = enabled;
	});
	after(() => {
		const parts = assetPartsSentSwitch();
		if (parts && prior !== undefined) parts.enabled = prior;
	});
}

/**
 * A host's opt-in to sending an asset payment in parts (issue #2098, step
 * 9): `sendInParts: true` in its auxiliary channel configuration. Typed
 * loosely, so that it also builds where the field is not declared.
 */
export const SEND_IN_PARTS = {
	sendInParts: true
} as unknown as Partial<IAuxiliaryChannelConfig>;

/**
 * Another build of the engine to make a host with, such as a release
 * installed from npm (the downgrade tests): its node and its storage, as
 * loaded from its dist. Typed as this tree's, which the release's match
 * in what these helpers use.
 */
export interface IEngineBuild {
	LightningNode: new (config: INodeConfig) => LightningNode;
	SqliteStorage: new (file: string) => SqliteStorage;
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
	options: {
		sqlite?: boolean;
		/** A database file in place of memory, so a later node can restart from it. */
		sqlitePath?: string;
		/** Handed the storage before the node is made, and restores from it. */
		onStorage?: (storage: SqliteStorage) => void;
		extra?: Partial<INodeConfig>;
		/** The build to make the node and its storage with; this tree's unless said. */
		build?: IEngineBuild;
	} = {}
): IAssetHost {
	const Storage = options.build?.SqliteStorage ?? SqliteStorage;
	const storage =
		options.sqlite || options.sqlitePath
			? new Storage(options.sqlitePath ?? ':memory:')
			: undefined;
	storage?.open();
	if (storage) options.onStorage?.(storage);
	const host: IAssetHost = {
		incoming: new Map(),
		broadcasts: [],
		errors: [],
		...(storage ? { storage } : {})
	} as unknown as IAssetHost;
	const config: Partial<INodeConfig> = {
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
	};
	host.node = options.build
		? new options.build.LightningNode({
				...makeNodeConfig(tag, seedId, storage),
				...config
		  })
		: createNode(tag, seedId, storage, config);
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
		/**
		 * Called when both have signed and the opener has handed its funding
		 * transaction to its broadcaster, before either is told the funding
		 * is confirmed. Answering false stops the open there, unconfirmed.
		 */
		beforeConfirmation?: (
			channelId: Buffer
		) => void | boolean | Promise<void | boolean>;
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
	if ((await options.beforeConfirmation?.(channelId)) === false) {
		return channelId;
	}
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

/** Let queued work run: `rounds` turns of the event loop. */
export async function turns(rounds = 60): Promise<void> {
	for (let i = 0; i < rounds; i++) {
		await new Promise<void>((resolve) => setImmediate(resolve));
	}
}

/**
 * Drop the connection between two hosts and bring it back, so that both
 * send channel_reestablish. Both sides learn of the new connection before
 * either reads a message of it.
 */
export async function reconnectHosts(
	a: IAssetHost,
	b: IAssetHost
): Promise<void> {
	a.node.getChannelManager().handlePeerDisconnected(b.node.getNodeId());
	b.node.getChannelManager().handlePeerDisconnected(a.node.getNodeId());
	await turns(20);
	const held: Array<() => void> = [];
	const originals = [a, b].map((host) => host.node.handlePeerMessage);
	for (const host of [a, b]) {
		const deliver = host.node.handlePeerMessage.bind(host.node);
		host.node.handlePeerMessage = ((
			peer: string,
			type: number,
			payload: Buffer
		) => {
			held.push(() => deliver(peer, type, payload));
		}) as typeof host.node.handlePeerMessage;
	}
	a.node.getChannelManager().handlePeerReconnected(b.node.getNodeId());
	b.node.getChannelManager().handlePeerReconnected(a.node.getNodeId());
	// Drained in the order sent, with later messages queued behind them.
	while (held.length > 0) held.shift()!();
	a.node.handlePeerMessage = originals[0];
	b.node.handlePeerMessage = originals[1];
	await turns(200);
}

/**
 * Pay `units` over the asset channel `channelId` from `payer` to `payee`,
 * for an invoice of `amountMsat`, as a host does: one hop, a 354 sat
 * carrier, the units in a custom record.
 */
export function payAssetUnits(
	payer: IAssetHost,
	payee: IAssetHost,
	channelId: Buffer,
	invoice: { paymentHash: Buffer; paymentSecret?: Buffer },
	amountMsat: bigint,
	units: bigint
): void {
	const amount = Buffer.alloc(8);
	amount.writeBigUInt64BE(units);
	payer.node.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(payee.node.getNodeId(), 'hex'),
					shortChannelId: Buffer.alloc(8, 9),
					amountToForwardMsat: amountMsat,
					outgoingCltvValue: 40
				}
			]
		},
		invoice.paymentHash,
		40,
		invoice.paymentSecret,
		undefined,
		undefined,
		undefined,
		undefined,
		{
			assetPayment: {
				channelId,
				wireAmountMsat: 354_000n,
				customRecords: new Map([[65536n, amount]])
			}
		}
	);
}

/**
 * The reference provider, with a throw wherever `fail` says so: a provider
 * that cannot answer, as one whose asset store is down.
 */
export function failingProvider(
	fail: (method: string, args: unknown[]) => boolean
): IChannelAuxiliaryProvider {
	const inner = referenceProvider() as unknown as Record<
		string,
		(...args: unknown[]) => unknown
	>;
	const out: Record<string, unknown> = {};
	for (const method of Object.keys(inner)) {
		out[method] = (...args: unknown[]): unknown => {
			if (fail(method, args)) throw new Error(`provider down in ${method}`);
			return inner[method](...args);
		};
	}
	return out as unknown as IChannelAuxiliaryProvider;
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
