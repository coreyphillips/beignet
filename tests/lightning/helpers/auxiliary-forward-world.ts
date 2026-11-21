/**
 * Forwards with an asset leg on a chain (issue #2098, step 5): Alice, Bob
 * and Carol, each with its own connection to one test chain and its own
 * chain watcher. Bob holds a channel with each of the others, funded in a
 * block: the one Alice opened to him (the incoming side of a forward) and
 * the one he opened to Carol (the outgoing side). Either is an asset channel
 * or an ordinary one. Bob runs from a database file, so a test can stop him
 * and start him again on the same chain, and each link between two hosts
 * can be cut and brought back on its own.
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import type { IChannelAuxiliaryProvider } from '../../../src/lightning/channel/auxiliary';
import type {
	IAuxiliaryChannelConfig,
	IAuxiliaryFundingDescriptor
} from '../../../src/lightning/channel/auxiliary-funding';
import { ChannelState } from '../../../src/lightning/channel/types';
import {
	PaymentStatus,
	type INodeConfig
} from '../../../src/lightning/node/types';
import { createTaprootFundingScript } from '../../../src/lightning/script/funding-taproot';
import type { IFixedOutputFeePolicy } from '../../../src/lightning/wallet/fixed-output-fees';
import { TestChain, TestChainBackend } from './auxiliary-chain';
import { chainWallet, type IChainWallet } from './auxiliary-fee-wallet';
import {
	assetHost,
	type IAssetHost,
	type IEngineBuild
} from './auxiliary-nodes';
import {
	SWEEP_DESTINATION,
	errorsOf,
	settle,
	sweepingProvider,
	type ISweepCall,
	type ISweepControl
} from './auxiliary-on-chain';
import { ASSET_FUNDING_ROOT, amountRecord, hash } from './auxiliary-pair';
import { makeSeed } from './loopback-nodes';

export type ForwardHostName = 'alice' | 'bob' | 'carol';
export type ForwardChannelKind = 'asset' | 'ordinary';
export type ForwardLinkName = 'in' | 'out';

/** The bitcoin each asset HTLC of these tests carries on the wire. */
export const FORWARD_CARRIER_MSAT = 354_000n;

/** One link between two hosts, which a test can cut and bring back. */
export interface IForwardLink {
	readonly ends: [ForwardHostName, ForwardHostName];
	up: boolean;
}

export interface IForwardWorld {
	chain: TestChain;
	hosts: Record<ForwardHostName, IAssetHost>;
	backends: Record<ForwardHostName, TestChainBackend>;
	/** Every time a host's provider was asked for the asset side of a sweep. */
	sweeps: Record<ForwardHostName, ISweepCall[]>;
	/** The wallet whose coins pay the fees of a host's fixed-output spends. */
	wallets: Partial<Record<ForwardHostName, IChainWallet>>;
	/** Bob's database file, from which a restart starts him again. */
	bobPath: string;
	/** Carol's database file, when she was opened with `carolOnFile`. */
	carolPath?: string;
	/** Alice's channel with Bob: the incoming side of a forward. */
	inChannel: Buffer;
	/** Bob's channel with Carol: the outgoing side of a forward. */
	outChannel: Buffer;
	/** A second channel of Bob's with Carol, when opened with `secondOut`. */
	outChannel2?: Buffer;
	kinds: Record<ForwardLinkName, ForwardChannelKind>;
	links: Record<ForwardLinkName, IForwardLink>;
}

export interface IForwardWorldOptions {
	kinds: Record<ForwardLinkName, ForwardChannelKind>;
	hooks?: Partial<Record<ForwardHostName, Partial<IAuxiliaryChannelConfig>>>;
	/** Give a host a wallet on the chain and the real fee pool over it. */
	feeWallet?: Partial<
		Record<ForwardHostName, Partial<IFixedOutputFeePolicy> | true>
	>;
	control?: Partial<Record<ForwardHostName, ISweepControl>>;
	/** Put something between a host and its provider, as one that is down at times. */
	wrapProvider?: Partial<
		Record<
			ForwardHostName,
			(provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider
		>
	>;
	/**
	 * Each node reads the features the other really advertises, in place of
	 * the fixed set the hosts of these tests are otherwise told.
	 */
	realInit?: boolean;
	/** Units of each asset channel: what its opener and its acceptor hold. */
	units?: Partial<
		Record<ForwardLinkName, { opener: bigint; acceptor: bigint }>
	>;
	/** Carol runs from a database file too, so a test can restart her. */
	carolOnFile?: boolean;
	/** A second channel from Bob to Carol, of this kind, on the same link. */
	secondOut?: ForwardChannelKind;
	/** More of a host's node configuration, such as its features. */
	nodes?: Partial<Record<ForwardHostName, Partial<INodeConfig>>>;
}

/** A payment from Alice to Carol through Bob, put in flight. */
export interface IForwardPayment {
	paymentHash: Buffer;
	preimage: Buffer;
	paymentSecret: Buffer;
	/** The expiry of Alice's HTLC to Bob, and of Bob's to Carol. */
	incomingExpiry: number;
	outgoingExpiry: number;
}

const seedOf = (name: ForwardHostName): number =>
	name === 'alice' ? 1 : name === 'bob' ? 2 : 3;

export function forwardChainWorld(): {
	open(tag: string, options: IForwardWorldOptions): Promise<IForwardWorld>;
	mine(world: IForwardWorld, blocks: number): Promise<void>;
	/** Let blocks pass up to a height, the watchers hearing only of the last. */
	passTo(world: IForwardWorld, height: number): Promise<void>;
	/**
	 * Stop Carol and start her again from her database, on the same chain
	 * (a world opened with `carolOnFile`).
	 */
	restartCarol(
		world: IForwardWorld,
		tag: string,
		options?: {
			hooks?: Partial<IAuxiliaryChannelConfig>;
			wrapProvider?: (
				provider: IChannelAuxiliaryProvider
			) => IChannelAuxiliaryProvider;
			/** Runs while Carol is down. */
			whileDown?: () => void | Promise<void>;
			/** Her link with Bob comes back with her, unless false. */
			reconnect?: boolean;
			/** The build she comes back on, such as a release; this tree's unless said. */
			build?: IEngineBuild;
		}
	): Promise<void>;
	/** Stop Bob and start him again from his database, on the same chain. */
	restartBob(
		world: IForwardWorld,
		tag: string,
		options?: {
			hooks?: Partial<IAuxiliaryChannelConfig>;
			/** Runs while Bob is down. */
			whileDown?: () => void | Promise<void>;
			/** The links that come back with him; both unless said. */
			reconnect?: ForwardLinkName[];
		}
	): Promise<void>;
	/** The two hosts of a link stop hearing each other. */
	cut(world: IForwardWorld, link: ForwardLinkName): void;
	/**
	 * What the two hosts of a link send each other is lost from now on, and
	 * neither is told: each still takes the other to be there.
	 */
	silence(world: IForwardWorld, link: ForwardLinkName): void;
	/** The two hosts of a link hear each other again, and reestablish. */
	reconnect(world: IForwardWorld, link: ForwardLinkName): Promise<void>;
	dispose(): void;
} {
	const made: IAssetHost[] = [];
	const backends: TestChainBackend[] = [];
	const files: string[] = [];
	const options = new WeakMap<IForwardWorld, IForwardWorldOptions>();

	const chainHost = async (
		tag: string,
		name: ForwardHostName,
		chain: TestChain,
		calls: ISweepCall[],
		control: ISweepControl | undefined,
		hooks: Partial<IAuxiliaryChannelConfig> | undefined,
		sqlitePath: string | undefined,
		wallet: IChainWallet | undefined,
		wrap?: (provider: IChannelAuxiliaryProvider) => IChannelAuxiliaryProvider,
		node?: Partial<INodeConfig>,
		build?: IEngineBuild
	): Promise<{ host: IAssetHost; backend: TestChainBackend }> => {
		const backend = new TestChainBackend(chain);
		backends.push(backend);
		wallet?.attach(backend);
		// The secrets of the basepoints a loopback node is made with: what it
		// signs a sweep or a penalty with (as assetChainWorld has them).
		const secret = (index: number): Buffer =>
			crypto
				.createHash('sha256')
				.update(makeSeed(tag, seedOf(name)))
				.update(Buffer.from([index]))
				.digest();
		const host = assetHost(
			tag,
			seedOf(name),
			{
				provider: (
					wrap ??
					((provider: IChannelAuxiliaryProvider): IChannelAuxiliaryProvider =>
						provider)
				)(sweepingProvider(calls, control)),
				...hooks
			},
			{
				...(sqlitePath ? { sqlitePath } : { sqlite: true }),
				extra: {
					chainBackend: backend,
					...(wallet ? { fundingProvider: wallet.provider() } : {}),
					revocationBasepointSecret: secret(1),
					paymentBasepointSecret: secret(2),
					delayedPaymentBasepointSecret: secret(3),
					...node
				},
				...(build ? { build } : {})
			}
		);
		made.push(host);
		await host.node.startChainWatcher();
		return { host, backend };
	};

	/** Messages one host sends the other pass while the link is up. */
	const wire = (
		world: IForwardWorld,
		link: IForwardLink,
		from: ForwardHostName,
		to: ForwardHostName
	): void => {
		const sender = world.hosts[from].node;
		sender.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (!link.up) return;
				const receiver = world.hosts[to].node;
				if (pubkey !== receiver.getNodeId()) return;
				receiver.handlePeerMessage(sender.getNodeId(), type, payload);
			}
		);
	};

	const readsRealInit = (host: IAssetHost, peers: IAssetHost[]): void => {
		const features = new Map(
			peers.map((peer) => [peer.node.getNodeId(), peer] as const)
		);
		(
			host.node as unknown as {
				peerInitFeatures: (pubkey: string) => unknown;
			}
		).peerInitFeatures = (pubkey: string): unknown =>
			features.get(pubkey)?.node.getLocalFeatures();
	};

	const mine = async (world: IForwardWorld, blocks: number): Promise<void> => {
		for (let i = 0; i < blocks; i++) {
			world.chain.mine();
			await settle();
		}
	};

	const openAsset = async (
		tag: string,
		chain: TestChain,
		opener: IAssetHost,
		acceptor: IAssetHost,
		units: { opener: bigint; acceptor: bigint }
	): Promise<Buffer> => {
		const fundingSatoshis = 2_000_000n;
		const descriptor: IAuxiliaryFundingDescriptor = {
			temporaryChannelId: hash(`asset channel ${tag}`),
			fundingTaprootMerkleRoot: Buffer.from(ASSET_FUNDING_ROOT),
			channelData: Buffer.from('proposed asset funding'),
			localBalance: units.opener,
			remoteBalance: units.acceptor
		};
		acceptor.incoming.set(descriptor.temporaryChannelId.toString('hex'), {
			...descriptor,
			localBalance: units.acceptor,
			remoteBalance: units.opener
		});
		const channel = opener.node.openAuxiliaryChannel(
			acceptor.node.getNodeId(),
			fundingSatoshis,
			descriptor,
			500_000_000n
		);
		await settle();
		const state = channel.getFullState();
		if (!state.remoteBasepoints) {
			throw new Error(
				`asset opening ${tag} was not accepted: ${[
					...opener.errors,
					...acceptor.errors
				].join('; ')}`
			);
		}
		const funding = new bitcoin.Transaction();
		funding.version = 2;
		funding.addInput(hash(`asset funding input ${tag}`), 0);
		funding.addOutput(Buffer.from('6a', 'hex'), 0);
		funding.addOutput(
			createTaprootFundingScript(
				state.localBasepoints.fundingPubkey,
				state.remoteBasepoints.fundingPubkey,
				undefined,
				ASSET_FUNDING_ROOT
			).p2trOutput,
			Number(fundingSatoshis)
		);
		const channelId = opener.node.fundAuxiliaryChannel(
			acceptor.node.getNodeId(),
			descriptor.temporaryChannelId,
			funding.toHex(),
			1,
			Buffer.from('final funding proofs'),
			{ prevoutScripts: [SWEEP_DESTINATION] }
		);
		await settle();
		// Somebody else signs and publishes the funding.
		const signed = funding.clone();
		signed.setWitness(0, [Buffer.alloc(72, 7), Buffer.alloc(33, 2)]);
		chain.seed(signed);
		await settle();
		return channelId;
	};

	const openOrdinary = async (
		tag: string,
		chain: TestChain,
		opener: IAssetHost,
		acceptor: IAssetHost
	): Promise<Buffer> => {
		const fundingSatoshis = 2_000_000n;
		// The opener funds the channel itself once the peer accepts. Its
		// provider builds a funding transaction of this test's making, which
		// somebody else signs and publishes, as with the asset channels.
		const provider = (
			opener.node as unknown as {
				fundingProvider: {
					buildFundingTransaction: (
						address: string,
						amountSats: bigint
					) => Promise<{ txHex: string; txid: Buffer; outputIndex: number }>;
				};
			}
		).fundingProvider;
		const build = provider.buildFundingTransaction;
		let funding: bitcoin.Transaction | undefined;
		provider.buildFundingTransaction = async (
			address: string,
			amountSats: bigint
		): Promise<{ txHex: string; txid: Buffer; outputIndex: number }> => {
			const tx = new bitcoin.Transaction();
			tx.version = 2;
			tx.addInput(hash(`ordinary funding input ${tag}`), 0);
			tx.setWitness(0, [Buffer.alloc(72, 7), Buffer.alloc(33, 2)]);
			tx.addOutput(
				bitcoin.address.toOutputScript(address, bitcoin.networks.regtest),
				Number(amountSats)
			);
			funding = tx;
			return {
				txHex: tx.toHex(),
				txid: Buffer.from(tx.getHash()),
				outputIndex: 0
			};
		};
		let channelId: Buffer | null = null;
		try {
			const channel = opener.node.openChannel(
				acceptor.node.getNodeId(),
				fundingSatoshis,
				500_000_000n
			);
			for (let i = 0; i < 4 && !channel.getChannelId(); i++) await settle();
			channelId = channel.getChannelId();
		} finally {
			provider.buildFundingTransaction = build;
		}
		if (!channelId || !funding) {
			throw new Error(
				`ordinary opening ${tag} was not funded: ${[
					...opener.errors,
					...acceptor.errors
				].join('; ')}`
			);
		}
		chain.seed(funding);
		await settle();
		return channelId;
	};

	const cut = (world: IForwardWorld, name: ForwardLinkName): void => {
		const link = world.links[name];
		link.up = false;
		const [a, b] = link.ends;
		world.hosts[a].node
			.getChannelManager()
			.handlePeerDisconnected(world.hosts[b].node.getNodeId());
		world.hosts[b].node
			.getChannelManager()
			.handlePeerDisconnected(world.hosts[a].node.getNodeId());
	};

	const reconnect = async (
		world: IForwardWorld,
		name: ForwardLinkName
	): Promise<void> => {
		const link = world.links[name];
		const [a, b] = link.ends.map((end) => world.hosts[end]);
		// Both sides learn of the new connection before either reads a
		// message of it, as reconnectHosts has it.
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
		link.up = true;
		a.node.getChannelManager().handlePeerReconnected(b.node.getNodeId());
		b.node.getChannelManager().handlePeerReconnected(a.node.getNodeId());
		// In the order they were sent, as one connection has them: what a
		// delivery sends waits behind what was already sent, so a node's
		// reestablish is read before anything it sends once its channel is
		// back (a fulfil the restart redispatch makes, for one).
		while (held.length > 0) held.shift()!();
		a.node.handlePeerMessage = originals[0];
		b.node.handlePeerMessage = originals[1];
		for (let i = 0; i < 5; i++) await settle();
	};

	return {
		mine,
		async passTo(world, height): Promise<void> {
			if (world.chain.height < height) {
				world.chain.advance(height - world.chain.height);
				await settle();
			}
		},
		cut,
		silence(world, name): void {
			world.links[name].up = false;
		},
		reconnect,
		async open(tag, given): Promise<IForwardWorld> {
			const chain = new TestChain();
			// The ordinary channels of these tests are P2WSH when they are not
			// taproot: their scripts are taken on their hash.
			chain.witnessScriptsOnTrust = true;
			const bobPath = path.join(
				os.tmpdir(),
				`${tag}-${process.pid}-${crypto.randomBytes(4).toString('hex')}.sqlite`
			);
			files.push(bobPath, `${bobPath}-wal`, `${bobPath}-shm`);
			const carolPath = given.carolOnFile
				? path.join(
						os.tmpdir(),
						`${tag}-carol-${process.pid}-${crypto
							.randomBytes(4)
							.toString('hex')}.sqlite`
				  )
				: undefined;
			if (carolPath) {
				files.push(carolPath, `${carolPath}-wal`, `${carolPath}-shm`);
			}
			const sweeps: Record<ForwardHostName, ISweepCall[]> = {
				alice: [],
				bob: [],
				carol: []
			};
			const wallets: Partial<Record<ForwardHostName, IChainWallet>> = {};
			for (const name of ['alice', 'bob', 'carol'] as const) {
				const asked = given.feeWallet?.[name];
				if (asked) {
					wallets[name] = chainWallet(
						chain,
						`${tag} ${name}`,
						asked === true ? {} : asked
					);
				}
			}
			const hosts = {} as Record<ForwardHostName, IAssetHost>;
			const hostBackends = {} as Record<ForwardHostName, TestChainBackend>;
			for (const name of ['alice', 'bob', 'carol'] as const) {
				const { host, backend } = await chainHost(
					tag,
					name,
					chain,
					sweeps[name],
					given.control?.[name],
					given.hooks?.[name],
					name === 'bob' ? bobPath : name === 'carol' ? carolPath : undefined,
					wallets[name],
					given.wrapProvider?.[name],
					given.nodes?.[name]
				);
				hosts[name] = host;
				hostBackends[name] = backend;
			}
			if (given.realInit) {
				readsRealInit(hosts.alice, [hosts.bob]);
				readsRealInit(hosts.bob, [hosts.alice, hosts.carol]);
				readsRealInit(hosts.carol, [hosts.bob]);
			}
			const world: IForwardWorld = {
				chain,
				hosts,
				backends: hostBackends,
				sweeps,
				wallets,
				bobPath,
				...(carolPath ? { carolPath } : {}),
				inChannel: Buffer.alloc(0),
				outChannel: Buffer.alloc(0),
				kinds: { ...given.kinds },
				links: {
					in: { ends: ['alice', 'bob'], up: true },
					out: { ends: ['bob', 'carol'], up: true }
				}
			};
			options.set(world, given);
			wire(world, world.links.in, 'alice', 'bob');
			wire(world, world.links.in, 'bob', 'alice');
			wire(world, world.links.out, 'bob', 'carol');
			wire(world, world.links.out, 'carol', 'bob');

			const open = (
				which: ForwardLinkName,
				opener: IAssetHost,
				acceptor: IAssetHost
			): Promise<Buffer> =>
				given.kinds[which] === 'asset'
					? openAsset(
							`${tag} ${which}`,
							chain,
							opener,
							acceptor,
							given.units?.[which] ?? { opener: 9000n, acceptor: 1000n }
					  )
					: openOrdinary(`${tag} ${which}`, chain, opener, acceptor);
			world.inChannel = await open('in', hosts.alice, hosts.bob);
			world.outChannel = await open('out', hosts.bob, hosts.carol);
			if (given.secondOut) {
				world.outChannel2 =
					given.secondOut === 'asset'
						? await openAsset(
								`${tag} out2`,
								chain,
								hosts.bob,
								hosts.carol,
								given.units?.out ?? { opener: 9000n, acceptor: 1000n }
						  )
						: await openOrdinary(`${tag} out2`, chain, hosts.bob, hosts.carol);
			}
			await mine(world, 6);
			const opened: Array<[string, Buffer, IAssetHost[]]> = [
				['in', world.inChannel, [hosts.alice, hosts.bob]],
				['out', world.outChannel, [hosts.bob, hosts.carol]]
			];
			if (world.outChannel2) {
				opened.push(['out2', world.outChannel2, [hosts.bob, hosts.carol]]);
			}
			for (const [which, channelId, pair] of opened) {
				for (const host of pair) {
					const now = host.node
						.getChannelManager()
						.getChannel(channelId)
						?.getState();
					if (now !== ChannelState.NORMAL) {
						throw new Error(
							`the ${which} channel of ${tag} is ${now}: ${errorsOf(host).join(
								'; '
							)}`
						);
					}
				}
			}
			return world;
		},
		async restartCarol(world, tag, restart = {}): Promise<void> {
			const given = options.get(world)!;
			if (!world.carolPath) {
				throw new Error(
					'Carol runs from memory: open the world with carolOnFile'
				);
			}
			cut(world, 'out');
			world.hosts.carol.node.destroy();
			world.hosts.carol.storage?.close();
			world.backends.carol.close();
			world.sweeps.carol = [];
			await restart.whileDown?.();
			const { host, backend } = await chainHost(
				tag,
				'carol',
				world.chain,
				world.sweeps.carol,
				given.control?.carol,
				restart.hooks ?? given.hooks?.carol,
				world.carolPath,
				world.wallets.carol,
				restart.wrapProvider ?? given.wrapProvider?.carol,
				given.nodes?.carol,
				restart.build
			);
			world.hosts.carol = host;
			world.backends.carol = backend;
			if (given.realInit) readsRealInit(host, [world.hosts.bob]);
			wire(world, world.links.out, 'carol', 'bob');
			await settle();
			if (restart.reconnect !== false) await reconnect(world, 'out');
		},
		async restartBob(world, tag, restart = {}): Promise<void> {
			const given = options.get(world)!;
			for (const name of ['in', 'out'] as const) cut(world, name);
			world.hosts.bob.node.destroy();
			world.hosts.bob.storage?.close();
			world.backends.bob.close();
			world.sweeps.bob = [];
			await restart.whileDown?.();
			const { host, backend } = await chainHost(
				tag,
				'bob',
				world.chain,
				world.sweeps.bob,
				given.control?.bob,
				restart.hooks ?? given.hooks?.bob,
				world.bobPath,
				world.wallets.bob,
				given.wrapProvider?.bob,
				given.nodes?.bob
			);
			world.hosts.bob = host;
			world.backends.bob = backend;
			if (given.realInit) {
				readsRealInit(host, [world.hosts.alice, world.hosts.carol]);
			}
			wire(world, world.links.in, 'bob', 'alice');
			wire(world, world.links.out, 'bob', 'carol');
			await settle();
			for (const name of restart.reconnect ?? (['in', 'out'] as const)) {
				await reconnect(world, name);
			}
		},
		dispose(): void {
			for (const host of made.splice(0)) {
				try {
					host.node.destroy();
				} catch {
					// Destroyed by a restart already.
				}
				try {
					host.storage?.close();
				} catch {
					// Closed by a restart already.
				}
			}
			for (const backend of backends.splice(0)) backend.close();
			for (const file of files.splice(0)) fs.rmSync(file, { force: true });
		}
	};
}

/**
 * Alice pays an invoice of Carol's through Bob and the payment stays in
 * flight at Carol, who holds it: Carol's invoice is a hold invoice, so
 * neither HTLC is settled until the test says. Over an incoming asset
 * channel Alice pays `units` with a carrier; over an ordinary one she pays
 * `incomingMsat`. The onion names `next` as Bob's next hop.
 */
export async function forwardHeld(
	world: IForwardWorld,
	tag: string,
	route: {
		next: Buffer;
		forwardMsat: bigint;
		/** The expiry of Bob's HTLC to Carol, as blocks above the tip. */
		outgoingDelta: number;
		/** Blocks between the outgoing expiry and the incoming one. */
		cltvDelta: number;
		units?: bigint;
		incomingMsat?: bigint;
		/** Carol must hold the HTLC; false when it is not to reach her. */
		held?: boolean;
	}
): Promise<IForwardPayment> {
	const { alice, bob, carol } = world.hosts;
	const preimage = hash(`forward preimage ${tag}`);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const invoice = carol.node.createInvoice({
		amountMsat: route.forwardMsat,
		description: `forward ${tag}`,
		hold: true,
		paymentHash
	});
	const assetIn = world.kinds.in === 'asset';
	alice.node.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
					// An asset payment goes over the channel it names; a plain
					// one over Alice's only ordinary channel to Bob.
					shortChannelId: Buffer.alloc(8, 9),
					amountToForwardMsat: assetIn
						? route.units! * 1000n
						: route.incomingMsat!,
					// The expiries of a route are given above the payer's tip.
					outgoingCltvValue: route.outgoingDelta + route.cltvDelta
				},
				{
					pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
					shortChannelId: route.next,
					amountToForwardMsat: route.forwardMsat,
					outgoingCltvValue: route.outgoingDelta
				}
			]
		},
		paymentHash,
		route.cltvDelta,
		invoice.paymentSecret,
		undefined,
		undefined,
		undefined,
		undefined,
		assetIn
			? {
					assetPayment: {
						channelId: world.inChannel,
						wireAmountMsat: FORWARD_CARRIER_MSAT,
						customRecords: amountRecord(route.units!)
					}
			  }
			: undefined
	);
	for (let i = 0; i < 4; i++) await settle();
	if (route.held !== false) {
		const parked = (
			carol.node as unknown as { heldHtlcs: Map<string, unknown[]> }
		).heldHtlcs.get(paymentHash.toString('hex'));
		if (!parked || parked.length !== 1) {
			throw new Error(
				`the forward ${tag} is not held at Carol: alice ${errorsOf(alice).join(
					' | '
				)}; bob ${errorsOf(bob).join(' | ')}; carol ${errorsOf(carol).join(
					' | '
				)}; payment ${
					alice.node.getPayment(paymentHash)?.status ?? PaymentStatus.FAILED
				}`
			);
		}
	}
	// The expiries the HTLCs have in their channels, which the chain goes by.
	const expiryOf = (channelId: Buffer, key: string): number =>
		[
			...(bob.node.getChannelManager().getChannel(channelId)?.getFullState()
				.htlcs ?? new Map())
		].find(
			([at, entry]) =>
				at.startsWith(key) && entry.paymentHash.equals(paymentHash)
		)?.[1].cltvExpiry ?? 0;
	return {
		paymentHash,
		preimage,
		paymentSecret: invoice.paymentSecret,
		incomingExpiry: expiryOf(world.inChannel, 'received-'),
		outgoingExpiry: expiryOf(world.outChannel, 'offered-')
	};
}

/** An ordinary invoice of Carol's, which Alice pays in parts through Bob. */
export interface IPartsInvoice {
	paymentHash: Buffer;
	paymentSecret: Buffer;
	/** What Carol's invoice asks. */
	invoiceMsat: bigint;
	/** The total each part's onion declares. */
	totalMsat: bigint;
}

/** How one part of a payment in parts is sent. */
export interface IPartOptions {
	/** The next hop the part's onion names; Bob's channel with Carol unless said. */
	next?: Buffer;
	/** What Alice pays Bob over what he forwards; 2 percent and a satoshi unless said. */
	feeMsat?: bigint;
	/** The expiry of Bob's HTLC to Carol, as blocks above the tip; 60 unless said. */
	outgoingDelta?: number;
	/** Blocks between the outgoing expiry and the incoming one; 40 unless said. */
	cltvDelta?: number;
	/** The total this part's onion declares, in place of the invoice's. */
	totalMsat?: bigint;
}

/** The alias a host knows its channel by, which an onion names as the next hop. */
export function aliasOf(host: IAssetHost, channelId: Buffer): Buffer {
	return Buffer.from(
		host.node.getChannelManager().getChannel(channelId)!.getFullState()
			.scidAlias!
	);
}

/** Carol makes an ordinary invoice (not a hold invoice) for parts to pay. */
export function partsInvoice(
	world: IForwardWorld,
	tag: string,
	invoiceMsat: bigint,
	totalMsat = invoiceMsat
): IPartsInvoice {
	const invoice = world.hosts.carol.node.createInvoice({
		amountMsat: invoiceMsat,
		description: `parts ${tag}`
	});
	return {
		paymentHash: invoice.paymentHash,
		paymentSecret: invoice.paymentSecret,
		invoiceMsat,
		totalMsat
	};
}

/**
 * Alice sends one part of `invoice` through Bob, in bitcoin: `partMsat` is
 * what the onion asks Bob to forward to Carol, and the part declares the
 * total of the set. Nothing is awaited.
 */
export function sendPart(
	world: IForwardWorld,
	invoice: IPartsInvoice,
	partMsat: bigint,
	options: IPartOptions = {}
): void {
	const { alice, bob, carol } = world.hosts;
	const outgoingDelta = options.outgoingDelta ?? 60;
	const cltvDelta = options.cltvDelta ?? 40;
	alice.node.sendPaymentToRoute(
		{
			hops: [
				{
					pubkey: Buffer.from(bob.node.getNodeId(), 'hex'),
					// Over Alice's only ordinary channel to Bob.
					shortChannelId: Buffer.alloc(8, 9),
					amountToForwardMsat:
						partMsat + (options.feeMsat ?? partMsat / 50n + 1000n),
					outgoingCltvValue: outgoingDelta + cltvDelta
				},
				{
					pubkey: Buffer.from(carol.node.getNodeId(), 'hex'),
					shortChannelId: options.next ?? aliasOf(bob, world.outChannel),
					amountToForwardMsat: partMsat,
					outgoingCltvValue: outgoingDelta
				}
			]
		},
		invoice.paymentHash,
		cltvDelta,
		invoice.paymentSecret,
		options.totalMsat ?? invoice.totalMsat
	);
}

/**
 * Alice pays an ordinary invoice of Carol's in parts through Bob: one
 * sendPaymentToRoute per part, under one hash and secret, each declaring
 * the total, and none an asset payment of hers (bitcoin in). Bob's host
 * makes each part an asset HTLC to Carol. The invoice asks the sum of the
 * parts unless said.
 */
export async function payInParts(
	world: IForwardWorld,
	tag: string,
	parts: bigint[],
	options: {
		invoiceMsat?: bigint;
		/** The total each part declares; the invoice's unless said. */
		totalMsat?: bigint;
		part?: (index: number) => IPartOptions;
		/** Message rounds after the parts are sent; 8 unless said. */
		rounds?: number;
	} = {}
): Promise<IPartsInvoice> {
	const sum = parts.reduce((all, part) => all + part, 0n);
	const invoiceMsat = options.invoiceMsat ?? sum;
	const invoice = partsInvoice(
		world,
		tag,
		invoiceMsat,
		options.totalMsat ?? invoiceMsat
	);
	parts.forEach((partMsat, index) =>
		sendPart(world, invoice, partMsat, options.part?.(index))
	);
	for (let i = 0; i < (options.rounds ?? 8); i++) await settle();
	return invoice;
}
