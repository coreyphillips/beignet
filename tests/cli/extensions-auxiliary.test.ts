/**
 * Host extensions: the attachment members that reach the Lightning node
 * (docs/EXTENSIONS.md, "Asset channels"; issue #2093).
 *
 * An attachment may supply `auxiliaryChannels`, `fixedOutputFees` and
 * `bind(node)`. The host is tested on its own first, then a BeignetNode
 * built on injected storage, with the options its LightningNode was made
 * from read at the one place the daemon makes it.
 *
 * Chainless, like tests/cli/extensions.test.ts: an unreachable Electrum,
 * and nothing here needs a chain.
 */

import { expect } from 'chai';
import { BeignetNode, BeignetNodeOptions } from '../../src/cli/beignet-node';
import { BeignetError } from '../../src/cli/errors';
import {
	EXTENSION_API_VERSION,
	ExtensionHost,
	IBeignetExtension,
	IExtensionAttachment,
	IExtensionBuild,
	IExtensionContext,
	IExtensionInfo
} from '../../src/cli/extension';
import type { IChannelAuxiliaryState } from '../../src/lightning/channel/auxiliary';
import type { IAuxiliaryChannelConfig } from '../../src/lightning/channel/auxiliary-funding';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import type { IFundingProvider } from '../../src/lightning/node/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	isStorageTransactionActive,
	withStorageTransaction
} from '../../src/lightning/storage/transaction';
import type { Wallet } from '../../src/wallet';
import { referenceProvider } from '../lightning/helpers/auxiliary-pair';
import {
	connectNodes,
	createNode,
	openReadyChannel
} from '../lightning/helpers/loopback-nodes';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const BOOT: BeignetNodeOptions = {
	network: 'regtest',
	mnemonic: MNEMONIC,
	logLevel: 'silent',
	rapidGossipSync: false,
	autoGossipSync: false,
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

/** What the app passes: the caps, and four fee coins. */
const FEES = {
	maxFeeSatoshis: 10_000n,
	maxTotalFeeSatoshis: 1_000_000n,
	maxPreparationFeeSatoshis: 10_000n,
	feeCoinCount: 4
};

const auxiliaryChannels = (): IAuxiliaryChannelConfig => ({
	provider: referenceProvider(),
	resolveIncoming: () => undefined
});

type Attach = (
	context: IExtensionContext
) => IExtensionAttachment | Promise<IExtensionAttachment>;

const extension = (id: string, attach: Attach): IBeignetExtension => ({
	id,
	version: '1.0.0',
	api: EXTENSION_API_VERSION,
	attach
});

/** attach() of an extension that does not know the members exist. */
const plainAttach =
	(contexts: IExtensionContext[] = []): Attach =>
	(context) => {
		contexts.push(context);
		return { start: (): void => undefined, status: () => ({ ok: true }) };
	};

const refusalOf = async (work: Promise<unknown>): Promise<BeignetError> => {
	try {
		await work;
	} catch (err) {
		expect(err).to.be.instanceOf(BeignetError);
		return err as BeignetError;
	}
	throw new Error('expected a refusal');
};

describe('host extensions: the members that reach the node, in the host', () => {
	let storage: SqliteStorage;
	const node = { marker: 'node' } as unknown as LightningNode;

	const build = (): IExtensionBuild => ({
		network: 'regtest',
		dataDir: undefined,
		wallet: {} as Wallet,
		storage: () => storage
	});
	const host = (extensions: IBeignetExtension[]): ExtensionHost =>
		new ExtensionHost(extensions, {
			engineVersion: '9.9.9',
			log: (): void => undefined
		});
	const only = (h: ExtensionHost): IExtensionInfo => h.describe()[0];

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});

	afterEach(() => {
		storage.close();
	});

	it('finds nothing to supply or bind in an attachment without the members', async () => {
		const h = host([extension('plain', plainAttach())]);
		await h.attach(build());
		expect(h.auxiliarySupply()).to.equal(undefined);
		h.bindNode(node);
		h.startInBackground();
		await h.started;
		expect(only(h)).to.deep.equal({
			id: 'plain',
			version: '1.0.0',
			state: 'ready',
			generation: 1,
			routes: [],
			events: [],
			status: { ok: true }
		});
	});

	it('supplies the provider of the one extension that has one, with its fee policy only when it gave one', async () => {
		const given = auxiliaryChannels();
		const h = host([
			extension('plain', plainAttach()),
			extension('assets', () => ({
				auxiliaryChannels: given,
				fixedOutputFees: FEES
			}))
		]);
		await h.attach(build());
		const supply = h.auxiliarySupply();
		expect(supply?.id).to.equal('assets');
		expect(supply?.auxiliaryChannels).to.equal(given);
		expect(supply?.fixedOutputFees).to.equal(FEES);

		const bare = host([
			extension('assets', () => ({ auxiliaryChannels: given }))
		]);
		await bare.attach(build());
		expect(bare.auxiliarySupply()).to.have.keys(['id', 'auxiliaryChannels']);
	});

	it('refuses two extensions that both supply a provider', async () => {
		const h = host([
			extension('assets', () => ({ auxiliaryChannels: auxiliaryChannels() })),
			extension('tokens', () => ({ auxiliaryChannels: auxiliaryChannels() }))
		]);
		await h.attach(build());
		let thrown: unknown;
		try {
			h.auxiliarySupply();
		} catch (err) {
			thrown = err;
		}
		expect(thrown).to.be.instanceOf(BeignetError);
		expect((thrown as BeignetError).code).to.equal('ASSET_PROVIDER_CONFLICT');
		expect((thrown as BeignetError).message).to.match(
			/"assets" and "tokens" both supply asset channels/
		);
	});

	it('fails an attachment whose members are malformed, and stops it', async () => {
		const cases: Array<[string, Record<string, unknown>, RegExp]> = [
			[
				'a provider with no resolveIncoming',
				{ auxiliaryChannels: { provider: referenceProvider() } },
				/attach: auxiliaryChannels must carry a provider and resolveIncoming/
			],
			[
				'a config with no provider',
				{ auxiliaryChannels: { resolveIncoming: () => undefined } },
				/attach: auxiliaryChannels must carry a provider and resolveIncoming/
			],
			[
				'a fee policy without a provider',
				{ fixedOutputFees: FEES },
				/attach: fixedOutputFees is read only beside auxiliaryChannels/
			],
			[
				'a fee policy that is not an object',
				{ auxiliaryChannels: auxiliaryChannels(), fixedOutputFees: 5 },
				/attach: fixedOutputFees must be an object/
			],
			[
				'a bind that is not a function',
				{ bind: 'node' },
				/attach: bind must be a function/
			]
		];
		for (const [name, members, error] of cases) {
			let stops = 0;
			const h = host([
				extension(
					'assets',
					() =>
						({
							...members,
							stop: (): void => {
								stops++;
							}
						}) as unknown as IExtensionAttachment
				)
			]);
			await h.attach(build());
			expect(only(h).state, name).to.equal('failed');
			expect(only(h).error, name).to.match(error);
			expect(h.auxiliarySupply(), name).to.equal(undefined);
			await h.shutdown();
			expect(stops, name).to.equal(1);
		}
	});

	it('gives the node to bind before start, and outside any storage transaction', async () => {
		const order: string[] = [];
		const seen: unknown[] = [];
		const binding = (id: string): IBeignetExtension =>
			extension(id, (context) => ({
				bind: (bound): void => {
					order.push('bind');
					seen.push(bound);
					// Refused if the node's storage is inside a transaction.
					context.storage.transaction(() => context.storage.set('bound', '1'));
				},
				start: (): void => {
					order.push('start');
				}
			}));
		const h = host([binding('assets')]);
		await h.attach(build());
		h.bindNode(node);
		h.startInBackground();
		await h.started;
		expect(order).to.deep.equal(['bind', 'start']);
		expect(seen).to.deep.equal([node]);
		expect(storage.loadMetadata('x/assets/bound')).to.equal('1');
		expect(only(h).state).to.equal('ready');

		// The probe is a real one: the same bind made from inside a
		// transaction of the node's storage is refused.
		const inside = host([binding('inside')]);
		await inside.attach(build());
		withStorageTransaction(storage, () => inside.bindNode(node));
		expect(only(inside).state).to.equal('failed');
		expect(only(inside).error).to.match(/^bind: .*inside another transaction/);
		expect(storage.loadMetadata('x/inside/bound')).to.equal(null);
	});

	it("fails an extension whose bind throws, and passes the throw on only for the provider's", async () => {
		const stops: string[] = [];
		const refusing = (id: string, withProvider: boolean): IBeignetExtension =>
			extension(id, () => ({
				...(withProvider ? { auxiliaryChannels: auxiliaryChannels() } : {}),
				bind: (): void => {
					throw new Error('bound to another node');
				},
				stop: (): void => {
					stops.push(id);
				}
			}));
		const h = host([refusing('notes', false), refusing('assets', true)]);
		await h.attach(build());
		const supply = h.auxiliarySupply();
		let thrown: unknown;
		try {
			h.bindNode(node, supply?.id);
		} catch (err) {
			thrown = err;
		}
		expect(thrown).to.be.instanceOf(BeignetError);
		expect((thrown as BeignetError).code).to.equal('ASSET_PROVIDER_FAILED');
		expect((thrown as BeignetError).message).to.match(
			/"assets" supplies this node's asset channels .* bound to another node/
		);
		const states = h
			.describe()
			.map((info) => [info.id, info.state, info.error]);
		expect(states).to.deep.equal([
			['notes', 'failed', 'bind: bound to another node'],
			['assets', 'failed', 'bind: bound to another node']
		]);
		await h.shutdown();
		expect(stops.sort()).to.deep.equal(['assets', 'notes']);
	});

	for (const end of ['shutdown', 'rebuild'] as const) {
		it(`keeps an extension whose start throws unstopped and its storage open while the node holds its provider, until the ${end}`, async () => {
			const stops: string[] = [];
			const contexts: IExtensionContext[] = [];
			const failing = (
				id: string,
				withProvider: boolean
			): IBeignetExtension => ({
				...extension(id, (context) => {
					contexts.push(context);
					return {
						...(withProvider ? { auxiliaryChannels: auxiliaryChannels() } : {}),
						handlers: { 'GET /a': (): unknown => ({ ok: true }) },
						start: (): void => {
							throw new Error('the asset service did not start');
						},
						stop: (reason): void => {
							stops.push(`${id}:${reason}`);
						}
					};
				}),
				routes: [{ method: 'GET', path: '/a', summary: 's' }]
			});
			const h = host([failing('notes', false), failing('assets', true)]);
			await h.attach(build());
			const [notes, assets] = contexts;
			h.bindNode(node, h.auxiliarySupply()?.id);
			await h.start();

			// Both failed, and the routes of both are closed.
			expect(
				h.describe().map((info) => [info.id, info.state, info.error])
			).to.deep.equal([
				['notes', 'failed', 'start: the asset service did not start'],
				['assets', 'failed', 'start: the asset service did not start']
			]);
			expect(() => h.handler('notes', 'GET /a')).to.throw(/failed: start/);
			expect(() => h.handler('assets', 'GET /a')).to.throw(/failed: start/);
			// The one without a provider was stopped and fenced, as before.
			expect(stops).to.deep.equal(['notes:shutdown']);
			expect(() => notes.storage.get('k')).to.throw();
			// The one whose provider the node holds was not: what its hooks
			// need to defend a channel is still there to read and to write.
			assets.storage.set('proof', 'kept');
			expect(assets.storage.get('proof')).to.equal('kept');
			expect(storage.loadMetadata('x/assets/proof')).to.equal('kept');

			if (end === 'shutdown') await h.shutdown();
			else {
				h.fenceForRebuild();
				await h.attach(build());
			}
			expect(stops).to.deep.equal(['notes:shutdown', `assets:${end}`]);
			expect(() => assets.storage.get('proof')).to.throw();
			if (end === 'rebuild') {
				// The next build attaches it afresh.
				expect(contexts).to.have.length(4);
				expect(h.describe().map((info) => info.state)).to.deep.equal([
					'attached',
					'attached'
				]);
				await h.shutdown();
			}
		});
	}

	it('drops a supply the node refuses, as if attach had thrown', async () => {
		let stops = 0;
		const h = host([
			extension('assets', () => ({
				auxiliaryChannels: auxiliaryChannels(),
				fixedOutputFees: FEES,
				stop: (): void => {
					stops++;
				}
			}))
		]);
		await h.attach(build());
		h.refuseSupply('assets', new Error('fixedOutputFees: too small'));
		expect(only(h).state).to.equal('failed');
		expect(only(h).error).to.equal('attach: fixedOutputFees: too small');
		expect(h.auxiliarySupply()).to.equal(undefined);
		await h.shutdown();
		expect(stops).to.equal(1);
	});
});

describe('host extensions: the members that reach the node, in a node', function () {
	this.timeout(90_000);

	type SeedOptions = NonNullable<
		Parameters<typeof LightningNode.fromMnemonic>[1]
	>;
	interface IBuilt {
		options: SeedOptions;
		node?: LightningNode;
	}
	const original = LightningNode.fromMnemonic;
	let built: IBuilt[];
	let running: BeignetNode[];
	let wallets: Wallet[];

	/** Boot on fresh injected storage, or on the one given. */
	const boot = async (
		extensions: IBeignetExtension[],
		storage: MemoryStorage = new MemoryStorage()
	): Promise<BeignetNode> => {
		const node = await BeignetNode.create({ ...BOOT, storage, extensions });
		running.push(node);
		return node;
	};

	/** An extension that keeps the wallet it was given, to stop it afterwards. */
	const watching = (id: string, attach: Attach): IBeignetExtension =>
		extension(id, (context) => {
			wallets.push(context.wallet);
			return attach(context);
		});

	const infoOf = (node: BeignetNode): IExtensionInfo =>
		(node.extensionHost as ExtensionHost).describe()[0];

	const fundingProviderOf = (index = 0): IFundingProvider =>
		built[index].options.fundingProvider as IFundingProvider;

	beforeEach(() => {
		built = [];
		running = [];
		wallets = [];
		LightningNode.fromMnemonic = function (
			mnemonic: string,
			options?: SeedOptions
		): LightningNode {
			const entry: IBuilt = { options: options as SeedOptions };
			built.push(entry);
			entry.node = original.call(LightningNode, mnemonic, options);
			return entry.node;
		};
	});

	afterEach(async () => {
		LightningNode.fromMnemonic = original;
		for (const node of running) await node.destroy();
		// A start that was refused never handed its node back: stop the
		// wallet it had made, so nothing of it outlives the test.
		for (const wallet of wallets) {
			try {
				await wallet.stop();
			} catch {
				// Stopped with its node already.
			}
		}
	});

	it('hands the provider, the fee policy and the node to the build', async () => {
		const given = auxiliaryChannels();
		const order: string[] = [];
		const bound: unknown[] = [];
		let inTransaction: boolean | undefined;
		const storage = new MemoryStorage();
		const node = await boot(
			[
				extension('assets', (context) => ({
					auxiliaryChannels: given,
					fixedOutputFees: FEES,
					bind: (lightning): void => {
						order.push('bind');
						bound.push(lightning);
						inTransaction = isStorageTransactionActive(storage);
						context.storage.transaction(() =>
							context.storage.set('bound', '1')
						);
					},
					start: (): void => {
						order.push('start');
					}
				}))
			],
			storage
		);
		await node.extensionHost?.started;

		expect(built).to.have.length(1);
		expect(built[0].options.auxiliaryChannels).to.equal(given);
		expect(fundingProviderOf().supportsFixedOutputFees?.()).to.equal(true);
		expect(
			fundingProviderOf().getFixedOutputFeeActionIds?.(Buffer.alloc(32))
		).to.deep.equal([]);
		expect(order).to.deep.equal(['bind', 'start']);
		expect(bound).to.deep.equal([built[0].node]);
		// The node itself gave it, before its restore.
		expect(built[0].options.beforeRestore).to.be.a('function');
		expect(inTransaction).to.equal(false);
		expect(storage.loadMetadata('x/assets/bound')).to.equal('1');
		expect(infoOf(node).state).to.equal('ready');
	});

	it('builds the node of a host with none of the members exactly as one with no extension', async () => {
		await boot([]);
		const storage = new MemoryStorage();
		const node = await boot([extension('plain', plainAttach())], storage);
		await node.extensionHost?.started;

		const [without, withPlain] = built.map((entry) => entry.options);
		expect(Object.keys(withPlain)).to.deep.equal(Object.keys(without));
		expect(withPlain).to.not.have.property('auxiliaryChannels');
		const scalars = (options: SeedOptions): Array<[string, unknown]> =>
			Object.entries(options).filter(([, value]) =>
				['string', 'number', 'boolean', 'undefined'].includes(typeof value)
			);
		expect(scalars(withPlain)).to.deep.equal(scalars(without));
		for (const index of [0, 1]) {
			const provider = fundingProviderOf(index);
			expect(provider.supportsFixedOutputFees?.()).to.equal(false);
			expect(
				(provider as { fixedOutputFeePool?: unknown }).fixedOutputFeePool
			).to.equal(undefined);
		}
		// No fee journal, and no row at all outside the extension's own.
		expect(storage.loadMetadataByPrefix('fixed-output-fees:')).to.deep.equal(
			[]
		);
		expect(infoOf(node).state).to.equal('ready');
	});

	it('leaves the provider with the node whether the extension is ready, still starting or failed to start', async () => {
		const paths: Array<[string, Partial<IExtensionAttachment>, string]> = [
			['nothing but the provider', {}, 'ready'],
			['a start that returns', { start: (): void => undefined }, 'ready'],
			[
				'a start that has not returned',
				{ start: (): Promise<void> => new Promise<void>(() => undefined) },
				'attached'
			],
			[
				'a start that throws',
				{
					start: (): void => {
						throw new Error('the asset service did not start');
					}
				},
				'failed'
			]
		];
		for (const [name, members, state] of paths) {
			const given = auxiliaryChannels();
			const node = await boot([
				extension('assets', () => ({ auxiliaryChannels: given, ...members }))
			]);
			// Every start hook has been called by now, and one that returned or
			// threw has settled after a turn of the loop.
			await new Promise((resolve) => setTimeout(resolve, 50));
			const latest = built[built.length - 1];
			expect(latest.options.auxiliaryChannels, name).to.equal(given);
			// No extension asked for the node, so the node is told of none.
			expect(latest.options, name).to.not.have.property('beforeRestore');
			expect(latest.node, name).to.have.property('auxiliaryChannels', given);
			expect(infoOf(node).state, name).to.equal(state);
		}
	});

	it('builds the node without the provider of an extension whose fee policy the wallet refuses', async () => {
		const node = await boot([
			extension('assets', () => ({
				auxiliaryChannels: auxiliaryChannels(),
				// A split into no coins is not a policy.
				fixedOutputFees: { ...FEES, feeCoinCount: 0 }
			}))
		]);
		expect(built[0].options).to.not.have.property('auxiliaryChannels');
		expect(fundingProviderOf().supportsFixedOutputFees?.()).to.equal(false);
		const info = infoOf(node);
		expect(info.state).to.equal('failed');
		expect(info.error).to.match(/^attach: fixedOutputFees: /);
	});

	describe('with an asset channel in the database', () => {
		let others: LightningNode[];

		/** A node's storage holding one channel that carries an asset root. */
		const storageWithAssetChannel = (): {
			storage: MemoryStorage;
			id: string;
		} => {
			const storage = new MemoryStorage();
			// Made with the engine's own factory, not the one watched above.
			const alice = createNode('ext-aux', 1, undefined, { storage });
			const bob = createNode('ext-aux', 2);
			others.push(alice, bob);
			alice.on('node:error', () => undefined);
			bob.on('node:error', () => undefined);
			connectNodes(alice, bob);
			const id = openReadyChannel(alice, bob).toString('hex');
			alice.destroy();
			others.splice(others.indexOf(alice), 1);
			const row = storage.loadChannel(id);
			if (!row) throw new Error('the channel was not stored');
			row.state.fundingTaprootMerkleRoot = Buffer.alloc(32, 0xa7);
			const assets: IChannelAuxiliaryState = {
				channelData: Buffer.from('asset funding blob'),
				localBalance: 825n,
				remoteBalance: 175n,
				localCommitments: new Map(),
				remoteCommitments: new Map()
			};
			row.state.auxiliaryState = assets;
			storage.saveChannel(id, row.state, row.peerPubkey);
			return { storage, id };
		};

		beforeEach(() => {
			others = [];
		});

		afterEach(() => {
			for (const node of others) node.destroy();
		});

		it('refuses the start with ASSET_PROVIDER_REQUIRED when no extension supplies a provider, and changes no row', async () => {
			const { storage } = storageWithAssetChannel();
			const before = storage.loadAllChannels();
			const refusal = await refusalOf(
				boot([watching('plain', plainAttach())], storage)
			);
			expect(refusal.code).to.equal('ASSET_PROVIDER_REQUIRED');
			expect(refusal.message).to.equal(
				'This wallet has 1 asset channel and no extension attached to it ' +
					'can run them, so it was not started and nothing was changed. ' +
					'Start it with the extension that opened them.'
			);
			expect(storage.loadAllChannels()).to.deep.equal(before);
		});

		it('gives the node to bind before the node reads the stored channel, so no hook of its provider runs unbound', async () => {
			const { storage, id } = storageWithAssetChannel();
			const order: string[] = [];
			const load = storage.loadAllChannels.bind(storage);
			storage.loadAllChannels = (): ReturnType<typeof load> => {
				// Only the node's own restore, not the daemon's reads before it.
				if (built.length > 0) order.push('rows read');
				return load();
			};
			let bound: LightningNode | undefined;
			const calls: Array<{ hook: string; bound: boolean }> = [];
			// Like the library's provider: every hook fails closed until the
			// node was given to bind.
			const provider = new Proxy(referenceProvider(), {
				get(target, name, receiver): unknown {
					const member = Reflect.get(target, name, receiver);
					if (typeof member !== 'function') return member;
					return (...args: unknown[]): unknown => {
						calls.push({ hook: String(name), bound: bound !== undefined });
						if (!bound) throw new Error('not bound to a node');
						return (member as (...given: unknown[]) => unknown).apply(
							target,
							args
						);
					};
				}
			});
			const node = await boot(
				[
					watching('assets', () => ({
						auxiliaryChannels: {
							provider,
							resolveIncoming: (): undefined => undefined
						},
						bind: (given): void => {
							order.push('bind');
							bound = given;
						}
					}))
				],
				storage
			);
			await node.extensionHost?.started;

			expect(order[0]).to.equal('bind');
			expect(order.filter((event) => event === 'bind')).to.have.length(1);
			expect(order).to.include('rows read');
			expect(bound).to.equal(built[0].node);
			expect(built[0].options).to.have.property('beforeRestore');
			expect(calls.filter((call) => !call.bound)).to.deep.equal([]);
			// The stored asset channel is the node's again, with the provider.
			expect(
				built[0].node?.getAuxiliaryChannelInfo(Buffer.from(id, 'hex'))
			).to.not.equal(undefined);
			expect(infoOf(node).state).to.equal('ready');
		});

		it('says which extension failed when the one that would supply the provider did', async () => {
			const { storage } = storageWithAssetChannel();
			const refusal = await refusalOf(
				boot(
					[
						watching('assets', () => ({
							auxiliaryChannels: auxiliaryChannels(),
							fixedOutputFees: { ...FEES, feeCoinCount: 0 }
						}))
					],
					storage
				)
			);
			expect(refusal.code).to.equal('ASSET_PROVIDER_REQUIRED');
			expect(refusal.message).to.match(
				/Start it with the extension that opened them\. Extension "assets" failed: attach: fixedOutputFees: /
			);
		});
	});

	it('refuses the start when two extensions supply a provider, before a node is built', async () => {
		const refusal = await refusalOf(
			boot([
				watching('assets', () => ({ auxiliaryChannels: auxiliaryChannels() })),
				watching('tokens', () => ({ auxiliaryChannels: auxiliaryChannels() }))
			])
		);
		expect(refusal.code).to.equal('ASSET_PROVIDER_CONFLICT');
		expect(built).to.deep.equal([]);
	});

	it("keeps the provider's extension running, with its storage open, until the node has drained, and stops and fences it after", async () => {
		const events: string[] = [];
		let provided: IExtensionContext | undefined;
		let other: IExtensionContext | undefined;
		const writes = (context: IExtensionContext | undefined): string => {
			try {
				context!.storage.set('state', 'of the next commitment');
				return 'open';
			} catch {
				return 'fenced';
			}
		};
		const node = await boot([
			watching('assets', (context) => {
				provided = context;
				return {
					auxiliaryChannels: auxiliaryChannels(),
					stop: (): void => {
						events.push(`assets stops: its storage ${writes(provided)}`);
					}
				};
			}),
			watching('reports', (context) => {
				other = context;
				return {
					stop: (): void => {
						events.push('reports stops');
					}
				};
			})
		]);
		await node.extensionHost?.started;
		const engine = built[0].node as LightningNode;
		const drain = engine.gracefulShutdown.bind(engine);
		engine.gracefulShutdown = async (timeoutMs?: number): Promise<void> => {
			// Here the node still waits for its in-flight HTLCs, each through
			// commitment updates that call the provider's hooks.
			events.push(
				`node drains: assets storage ${writes(provided)}, ` +
					`reports storage ${writes(other)}`
			);
			return drain(timeoutMs);
		};
		await node.gracefulShutdown(4000);
		expect(events).to.deep.equal([
			'reports stops',
			'node drains: assets storage open, reports storage fenced',
			'assets stops: its storage open'
		]);
		// Fenced once its stop hook has run.
		expect(writes(provided)).to.equal('fenced');
		expect(
			(node.extensionHost as ExtensionHost)
				.describe()
				.map((info) => [info.id, info.state])
		).to.deep.equal([
			['assets', 'stopped'],
			['reports', 'stopped']
		]);
	});

	it("restores nothing and takes the node down when the provider's extension refuses it in bind", async () => {
		const storage = new MemoryStorage();
		const reads: string[] = [];
		const load = storage.loadAllChannels.bind(storage);
		storage.loadAllChannels = (): ReturnType<typeof load> => {
			if (built.length > 0) reads.push('rows read');
			return load();
		};
		let given: LightningNode | undefined;
		const refusal = await refusalOf(
			boot(
				[
					watching('assets', () => ({
						auxiliaryChannels: auxiliaryChannels(),
						bind: (node): void => {
							given = node;
							throw new Error(
								'the asset Lightning host is bound to another node'
							);
						}
					}))
				],
				storage
			)
		);
		expect(refusal.code).to.equal('ASSET_PROVIDER_FAILED');
		expect(refusal.message).to.match(
			/bound to another node.*The node was not started\.$/
		);
		// The node was built, given to bind, and never restored or handed on.
		expect(built).to.have.length(1);
		expect(built[0].node).to.equal(undefined);
		expect(reads).to.deep.equal([]);
		expect(given).to.have.property('_destroyed', true);
	});
});
