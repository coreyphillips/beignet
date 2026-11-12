/**
 * The daemon side of Porch (issue #1980): the settings that name the relays,
 * the links a node hands out and takes back, and what GET /info, GET /peers
 * and the /porch/links routes say about them. The relay in these tests is a
 * real one, in process.
 */

import { expect } from 'chai';
import * as bip39 from 'bip39';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { resolveConfig } from '../../src/cli/config';
import { IStartedDaemon, startDaemon } from '../../src/cli/daemon';
import { daemonOptions } from '../../src/cli/daemon-options';
import { PORCH_LINKS_STORAGE_KEY } from '../../src/cli/daemon-state-keys';
import {
	PorchDaemonConfig,
	porchRelayEntries,
	porchRelaysEnv,
	porchStandbysEnv,
	porchViaEnv,
	validatePorchConfig
} from '../../src/cli/porch-config';
import {
	IPorchLinkStorage,
	PORCH_LINK_LABEL_MAX,
	PorchLinkStore,
	porchLinkLabel
} from '../../src/cli/porch-links';
import { PorchRelay } from '../../src/cli/porch-relay';
import { ROUTES } from '../../src/cli/routes';
import {
	BeignetConfig,
	ListenerProblem,
	NodeInfo,
	PeerInfo,
	PorchInfo,
	PorchLinkInfo,
	PorchLinksInfo
} from '../../src/cli/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { parsePeerUri } from '../../src/lightning/transport/peer-uri';
import {
	PORCH_MAX_TAGS,
	derivePorchDefaultTag,
	derivePorchHostSecret,
	porchRouteId
} from '../../src/lightning/transport/porch';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const VISITOR_MNEMONICS = [
	'legal winner thank year wave sausage worth useful legal winner thank yellow',
	'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'
];

const SEED = bip39.mnemonicToSeedSync(MNEMONIC);
const DEFAULT_TAG = derivePorchDefaultTag(SEED);
const DEFAULT_ID = DEFAULT_TAG.toString('hex');
const HOST_KEY = getPublicKey(derivePorchHostSecret(SEED));

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
	cond: () => boolean | Promise<boolean>,
	label: string,
	timeoutMs = 15_000
): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!(await cond())) {
		if (Date.now() > deadline)
			throw new Error(`Timed out waiting for ${label}`);
		await sleep(25);
	}
}

/** A port nothing is listening on, for a relay whose name includes it. */
async function freePort(): Promise<number> {
	const server = net.createServer();
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	const { port } = server.address() as net.AddressInfo;
	await new Promise<void>((resolve) => server.close(() => resolve()));
	return port;
}

/** Set environment variables for one test and put back what was there. */
function withEnv(
	vars: Record<string, string | undefined>,
	run: () => void
): void {
	const previous: Record<string, string | undefined> = {};
	for (const [name, value] of Object.entries(vars)) {
		previous[name] = process.env[name];
		if (value === undefined) delete process.env[name];
		else process.env[name] = value;
	}
	try {
		run();
	} finally {
		for (const [name, value] of Object.entries(previous)) {
			if (value === undefined) delete process.env[name];
			else process.env[name] = value;
		}
	}
}

function memory(initial: string | null = null): IPorchLinkStorage & {
	value: string | null;
	saves: number;
} {
	return {
		value: initial,
		saves: 0,
		load(): string | null {
			return this.value;
		},
		save(next: string): void {
			this.value = next;
			this.saves++;
		}
	};
}

describe('Porch daemon configuration', () => {
	it('reads the relays, the route to them and the standby count from the environment', () => {
		withEnv(
			{
				BEIGNET_PORCH_RELAYS: undefined,
				BEIGNET_PORCH_VIA: undefined,
				BEIGNET_PORCH_STANDBYS: undefined
			},
			() => {
				expect(porchRelaysEnv()).to.equal(undefined);
				expect(porchViaEnv()).to.equal(undefined);
				expect(porchStandbysEnv()).to.equal(undefined);
			}
		);
		// Empty turns Porch off, whatever the config file lists.
		for (const value of ['', ' , ']) {
			withEnv({ BEIGNET_PORCH_RELAYS: value }, () => {
				expect(porchRelaysEnv()).to.deep.equal([]);
			});
		}
		withEnv(
			{
				BEIGNET_PORCH_RELAYS: ' wss://one.example , ws://two.example:8080,',
				BEIGNET_PORCH_VIA: 'tor',
				BEIGNET_PORCH_STANDBYS: '4'
			},
			() => {
				expect(porchRelaysEnv()).to.deep.equal([
					'wss://one.example',
					'ws://two.example:8080'
				]);
				expect(porchViaEnv()).to.equal('tor');
				expect(porchStandbysEnv()).to.equal(4);
			}
		);
		withEnv({ BEIGNET_PORCH_VIA: 'direct' }, () => {
			expect(porchViaEnv()).to.equal('direct');
		});
		// Unset by being empty, as a compose file leaves it.
		withEnv({ BEIGNET_PORCH_VIA: '', BEIGNET_PORCH_STANDBYS: '' }, () => {
			expect(porchViaEnv()).to.equal(undefined);
			expect(porchStandbysEnv()).to.equal(undefined);
		});
		for (const value of ['Tor', 'onion', 'true']) {
			withEnv({ BEIGNET_PORCH_VIA: value }, () => {
				expect(() => porchViaEnv(), value).to.throw('exactly direct or tor');
			});
		}
		for (const value of ['two', '2.5', '-1', '3x', '0x2']) {
			withEnv({ BEIGNET_PORCH_STANDBYS: value }, () => {
				expect(() => porchStandbysEnv(), value).to.throw('whole number');
			});
		}
	});

	it('carries the environment through resolveConfig and into the daemon options', () => {
		withEnv(
			{
				BEIGNET_PORCH_RELAYS: 'wss://relay.example',
				BEIGNET_PORCH_VIA: 'tor',
				BEIGNET_PORCH_STANDBYS: '3',
				BEIGNET_PORCH_TOKEN: 'open sesame'
			},
			() => {
				const config = resolveConfig({});
				expect(config.porchRelays).to.deep.equal(['wss://relay.example']);
				const options = daemonOptions(config, 0);
				expect(options.porchRelays).to.deep.equal(['wss://relay.example']);
				expect(options.porchVia).to.equal('tor');
				expect(options.porchStandbys).to.equal(3);
				expect(options.porchToken).to.equal('open sesame');
				// A flag beats the environment.
				expect(
					resolveConfig({
						porchRelays: ['wss://flag.example'],
						porchStandbys: 1
					})
				).to.include({ porchStandbys: 1 });
			}
		);
		const config = { network: 'regtest' } as BeignetConfig;
		const off = daemonOptions(config, 0);
		expect(off.porchRelays).to.equal(undefined);
		expect(off.porchToken).to.equal(undefined);
	});

	it('refuses settings no relay could be reached with', () => {
		const bad: Array<[PorchDaemonConfig, string]> = [
			[{ porchRelays: 'wss://relay.example' as unknown as string[] }, 'array'],
			[{ porchRelays: [7 as unknown as string] }, 'array of relay URLs'],
			[{ porchRelays: [null as unknown as string] }, 'array of relay URLs'],
			[{ porchRelays: [{ token: 'x' } as never] }, 'array of relay URLs'],
			[{ porchRelays: ['https://relay.example'] }, 'ws:// or wss://'],
			[
				{ porchRelays: ['wss://relay.example/v1/host'] },
				'scheme, host and port'
			],
			[
				{ porchRelays: ['wss://relay.example', 'wss://RELAY.example:443'] },
				'lists relay.example twice'
			],
			[
				{ porchRelays: [{ url: 'wss://relay.example', token: '' }] },
				'The token of relay.example must be a string of 1 to 256 bytes'
			],
			[
				{ porchRelays: [{ url: 'wss://relay.example', token: 5 as never }] },
				'1 to 256 bytes'
			],
			[{ porchToken: '' }, 'porchToken must be a string of 1 to 256 bytes'],
			[{ porchToken: 'x'.repeat(257) }, 'porchToken must be a string'],
			[{ porchVia: 'onion' as never }, "porchVia must be 'direct' or 'tor'"],
			[{ porchStandbys: 0 }, 'from 1 to 8'],
			[{ porchStandbys: 9 }, 'from 1 to 8'],
			[{ porchStandbys: 1.5 }, 'from 1 to 8'],
			[{ porchStandbys: '2' as never }, 'from 1 to 8']
		];
		for (const [config, message] of bad) {
			expect(
				() => validatePorchConfig(config),
				JSON.stringify(config).slice(0, 90)
			).to.throw(message);
		}
		// What is allowed, including the settings left behind with Porch off.
		for (const config of [
			{},
			{ porchRelays: [] },
			{ porchVia: 'tor', porchStandbys: 8, porchToken: 'x'.repeat(256) },
			{ porchRelays: ['wss://relay.example'], porchStandbys: 1 },
			{ porchRelays: ['ws://abcdefghijklmnop.onion'], porchVia: 'tor' }
		] as PorchDaemonConfig[]) {
			expect(() => validatePorchConfig(config)).to.not.throw();
		}
	});

	it('sends a token to the relay it was written for and to no other', () => {
		expect(porchRelayEntries({})).to.deep.equal([]);
		expect(porchRelayEntries({ porchToken: 'secret' })).to.deep.equal([]);
		expect(
			porchRelayEntries({ porchRelays: ['wss://relay.example'] })
		).to.deep.equal([{ url: 'wss://relay.example' }]);
		// One relay: porchToken is its token.
		expect(
			porchRelayEntries({
				porchRelays: ['wss://relay.example'],
				porchToken: 'secret'
			})
		).to.deep.equal([{ url: 'wss://relay.example', token: 'secret' }]);
		// Several: each has its own, or none.
		expect(
			porchRelayEntries({
				porchRelays: [
					{ url: 'wss://one.example', token: 'first' },
					'wss://two.example',
					{ url: 'wss://three.example' }
				]
			})
		).to.deep.equal([
			{ url: 'wss://one.example', token: 'first' },
			{ url: 'wss://two.example' },
			{ url: 'wss://three.example' }
		]);
		// One token and two relays would hand the token to both operators.
		expect(() =>
			porchRelayEntries({
				porchRelays: ['wss://one.example', 'wss://two.example'],
				porchToken: 'secret'
			})
		).to.throw('porchToken is the token of a single relay');
		expect(() =>
			porchRelayEntries({
				porchRelays: [{ url: 'wss://one.example', token: 'first' }],
				porchToken: 'second'
			})
		).to.throw('set one');
	});

	it('rejects invalid settings before a node is started', async () => {
		const failures: Array<[PorchDaemonConfig, string]> = [
			[{ porchRelays: ['http://relay.example'] }, 'ws:// or wss://'],
			[
				{ porchRelays: ['wss://relay.example'], porchStandbys: 20 },
				'from 1 to 8'
			],
			// Tor does not reach a private address, and an onion name resolves
			// nowhere else: neither can be rescued by a proxy setting.
			[
				{ porchRelays: ['ws://127.0.0.1:2114'], porchVia: 'tor' },
				'private address'
			],
			[
				{ porchRelays: ['ws://abcdefghijklmnop.onion'], porchVia: 'direct' },
				'onion service'
			]
		];
		for (const [config, message] of failures) {
			const error = await BeignetNode.create(config).then(
				() => null,
				(err: Error & { code?: string }) => err
			);
			expect(error?.message, JSON.stringify(config)).to.contain(message);
			expect(error?.code).to.equal('INVALID_PARAMS');
		}
		const daemonError = await startDaemon({
			network: 'regtest',
			porchRelays: ['wss://one.example', 'wss://two.example'],
			porchToken: 'secret'
		}).then(
			() => null,
			(err: Error & { code?: string }) => err
		);
		expect(daemonError?.code).to.equal('INVALID_PARAMS');
		expect(daemonError?.message).to.contain('single relay');
	});

	it('lets a readonly key list the links and only an admin make or revoke one', () => {
		const scopes = (method: string, route: string): unknown =>
			ROUTES.find((r) => r.method === method && r.path === route)?.scopes;
		expect(scopes('GET', '/porch/links')).to.deep.equal(['readonly']);
		expect(scopes('POST', '/porch/links/create')).to.deep.equal([]);
		expect(scopes('POST', '/porch/links/revoke')).to.deep.equal([]);
	});
});

describe('Porch link store', () => {
	it("starts with the seed's link, and nothing is written until something changes", () => {
		const storage = memory();
		const store = new PorchLinkStore(DEFAULT_TAG, storage);
		expect(store.unreadable).to.equal(false);
		expect(store.list()).to.deep.equal([{ id: DEFAULT_ID, default: true }]);
		expect(store.tags().map((tag) => tag.toString('hex'))).to.deep.equal([
			DEFAULT_ID
		]);
		expect(storage.saves).to.equal(0);
		expect(() => new PorchLinkStore(Buffer.alloc(15), memory())).to.throw(
			'16 bytes'
		);
	});

	it('makes links with tags of their own and keeps them across a restart', () => {
		const storage = memory();
		const store = new PorchLinkStore(DEFAULT_TAG, storage);
		const phone = store.create('phone', 1_000);
		const plain = store.create(undefined, 2_000);
		expect(phone).to.deep.equal({
			id: phone.id,
			label: 'phone',
			createdAt: 1_000
		});
		expect(plain).to.deep.equal({ id: plain.id, createdAt: 2_000 });
		for (const id of [phone.id, plain.id])
			expect(id).to.match(/^[0-9a-f]{32}$/);
		expect(new Set([DEFAULT_ID, phone.id, plain.id]).size).to.equal(3);
		expect(storage.saves).to.equal(2);

		const expected = [{ id: DEFAULT_ID, default: true }, phone, plain];
		expect(store.list()).to.deep.equal(expected);
		const reopened = new PorchLinkStore(DEFAULT_TAG, storage);
		expect(reopened.list()).to.deep.equal(expected);
		expect(reopened.tags().map((tag) => tag.toString('hex'))).to.deep.equal([
			DEFAULT_ID,
			phone.id,
			plain.id
		]);
	});

	it('revokes a link for good, the seed link included', () => {
		const storage = memory();
		const store = new PorchLinkStore(DEFAULT_TAG, storage);
		const phone = store.create('phone', 1_000);
		const tablet = store.create('tablet', 2_000);

		expect(store.revoke('ab'.repeat(16))).to.equal(false);
		expect(storage.saves).to.equal(2);
		expect(store.revoke(phone.id)).to.equal(true);
		expect(store.revoke(phone.id)).to.equal(false);
		expect(store.list()).to.deep.equal([
			{ id: DEFAULT_ID, default: true },
			tablet
		]);

		expect(store.revoke(DEFAULT_ID)).to.equal(true);
		expect(store.revoke(DEFAULT_ID)).to.equal(false);
		expect(store.list()).to.deep.equal([tablet]);
		expect(storage.saves).to.equal(4);

		// Neither comes back with the next start.
		const reopened = new PorchLinkStore(DEFAULT_TAG, storage);
		expect(reopened.list()).to.deep.equal([tablet]);
		expect(reopened.revoke(tablet.id)).to.equal(true);
		expect(reopened.list()).to.deep.equal([]);
		expect(reopened.tags()).to.deep.equal([]);
		expect(new PorchLinkStore(DEFAULT_TAG, storage).list()).to.deep.equal([]);
	});

	it('does not count a change that could not be written', () => {
		const storage = memory();
		const store = new PorchLinkStore(DEFAULT_TAG, storage);
		const kept = store.create('kept', 1_000);
		const failing = new Error('disk full');
		storage.save = (): void => {
			throw failing;
		};
		expect(() => store.create('lost')).to.throw('disk full');
		expect(() => store.revoke(kept.id)).to.throw('disk full');
		expect(() => store.revoke(DEFAULT_ID)).to.throw('disk full');
		expect(store.list()).to.deep.equal([
			{ id: DEFAULT_ID, default: true },
			kept
		]);
	});

	it('serves at most as many links as a registration can list', () => {
		const storage = memory();
		const store = new PorchLinkStore(DEFAULT_TAG, storage);
		for (let i = 1; i < PORCH_MAX_TAGS; i++) store.create(undefined, i);
		expect(store.list()).to.have.length(PORCH_MAX_TAGS);
		expect(() => store.create()).to.throw('at most 256 Porch links');
		// The seed's link counts: revoking it makes room for one.
		store.revoke(DEFAULT_ID);
		store.create('room', 9_999);
		expect(store.list()).to.have.length(PORCH_MAX_TAGS);
		expect(() => store.create()).to.throw('at most 256');
	});

	it('serves nothing from a record it cannot read, until a link is made', () => {
		const other = 'cd'.repeat(16);
		const link = { tag: other, createdAt: 1 };
		const unreadable = [
			'not json',
			'[]',
			'{}',
			JSON.stringify({ links: 'none' }),
			JSON.stringify({ defaultRevoked: 'yes', links: [] }),
			JSON.stringify({ links: [null] }),
			JSON.stringify({ links: [{ tag: 'short', createdAt: 1 }] }),
			JSON.stringify({ links: [{ tag: other.toUpperCase(), createdAt: 1 }] }),
			JSON.stringify({ links: [{ tag: other }] }),
			JSON.stringify({ links: [{ tag: other, createdAt: '1' }] }),
			JSON.stringify({ links: [{ tag: other, createdAt: 1, label: 7 }] }),
			// The same link twice, or the seed's link listed as a made one.
			JSON.stringify({ links: [link, link] }),
			JSON.stringify({ links: [{ tag: DEFAULT_ID, createdAt: 1 }] })
		];
		for (const raw of unreadable) {
			const storage = memory(raw);
			const store = new PorchLinkStore(DEFAULT_TAG, storage);
			expect(store.unreadable, raw).to.equal(true);
			// Which links were revoked is not known, so none is served.
			expect(store.list(), raw).to.deep.equal([]);
			expect(store.revoke(DEFAULT_ID), raw).to.equal(false);
			// Nothing is overwritten by looking.
			expect(storage.value).to.equal(raw);
		}

		const storage = memory('not json');
		const store = new PorchLinkStore(DEFAULT_TAG, storage);
		const fresh = store.create('fresh', 5);
		expect(store.unreadable).to.equal(false);
		expect(store.list()).to.deep.equal([fresh]);
		// The seed's link stays out: it may have been revoked.
		const reopened = new PorchLinkStore(DEFAULT_TAG, storage);
		expect(reopened.unreadable).to.equal(false);
		expect(reopened.list()).to.deep.equal([fresh]);

		// More links than a registration can list: with the seed's link 257,
		// without it 256, which is the most a node serves.
		const many = Array.from({ length: PORCH_MAX_TAGS }, (_, i) => ({
			tag: i.toString(16).padStart(32, '0'),
			createdAt: i
		}));
		const over = new PorchLinkStore(
			DEFAULT_TAG,
			memory(JSON.stringify({ links: many }))
		);
		expect(over.unreadable).to.equal(true);
		expect(over.tags()).to.deep.equal([]);
		const exact = new PorchLinkStore(
			DEFAULT_TAG,
			memory(JSON.stringify({ defaultRevoked: true, links: many }))
		);
		expect(exact.unreadable).to.equal(false);
		expect(exact.tags()).to.have.length(PORCH_MAX_TAGS);

		// A record this version wrote is read back whatever else it carries.
		const readable = new PorchLinkStore(
			DEFAULT_TAG,
			memory(JSON.stringify({ links: [link], later: true }))
		);
		expect(readable.unreadable).to.equal(false);
		expect(readable.list()).to.deep.equal([
			{ id: DEFAULT_ID, default: true },
			{ id: other, createdAt: 1 }
		]);
	});

	it('takes a label as the operator typed it, within reason', () => {
		expect(porchLinkLabel(undefined)).to.equal(undefined);
		expect(porchLinkLabel(null)).to.equal(undefined);
		expect(porchLinkLabel('   ')).to.equal(undefined);
		expect(porchLinkLabel("  Dana's phone ")).to.equal("Dana's phone");
		expect(porchLinkLabel('x'.repeat(PORCH_LINK_LABEL_MAX))).to.have.length(64);
		expect(() => porchLinkLabel('x'.repeat(PORCH_LINK_LABEL_MAX + 1))).to.throw(
			'at most 64 characters'
		);
		expect(() => porchLinkLabel(7)).to.throw('label must be a string');
		for (const label of ['a\nb', 'a\u0000b', 'a\u007fb', 'tab\there']) {
			expect(() => porchLinkLabel(label), JSON.stringify(label)).to.throw(
				'control characters'
			);
		}
	});
});

/**
 * A BeignetNode with no node behind it: enough of one to drive the Porch
 * listener through the states a guardian recovery mode puts it in.
 */
interface IPorchInternals {
	node: unknown;
	destroyed: boolean;
	mnemonic: string;
	storage: {
		loadWalletData(key: string): string | null;
		saveWalletData(key: string, value: string): void;
	};
	log: (level: string, message: string, data?: unknown) => void;
	_listenBinds: Record<string, unknown>;
	_listenEpoch: number;
	_porchListenError?: ListenerProblem;
	porchNodeConfig(
		opts: PorchDaemonConfig,
		proxy: { host: string; port: number } | undefined,
		scope: 'all' | 'onion',
		announced: Array<{ type: number; host: string; port: number }> | undefined
	):
		| { relays: unknown[]; tags: Buffer[]; via?: string; standbys?: number }
		| undefined;
	bindListener(kind: string, port: number): Promise<void>;
	bindHeldListeners(): void;
	fenceListeners(): void;
	resetListenerState(): void;
	porchInfo(): PorchInfo | undefined;
	getPorchLinks(): PorchLinksInfo;
	createPorchLink(label?: string): PorchLinkInfo;
	revokePorchLink(id: string): { revoked: true; id: string };
}

function bareNode(stored: Record<string, string> = {}): {
	node: IPorchInternals;
	logs: Array<{ level: string; message: string }>;
	stored: Record<string, string>;
} {
	const logs: Array<{ level: string; message: string }> = [];
	const node = Object.create(BeignetNode.prototype) as IPorchInternals;
	node.destroyed = false;
	node.mnemonic = MNEMONIC;
	node._listenBinds = {};
	node._listenEpoch = 0;
	node.storage = {
		loadWalletData: (key): string | null => stored[key] ?? null,
		saveWalletData: (key, value): void => {
			stored[key] = value;
		}
	};
	node.log = (level, message): void => {
		logs.push({ level, message });
	};
	return { node, logs, stored };
}

describe('Porch on a daemon node', () => {
	const RELAY = 'wss://relay.example';

	it('builds the node settings from the options and the stored links', () => {
		const { node, logs, stored } = bareNode();
		expect(node.porchNodeConfig({}, undefined, 'all', undefined)).to.equal(
			undefined
		);
		expect(
			node.porchNodeConfig({ porchRelays: [] }, undefined, 'all', undefined)
		).to.equal(undefined);
		expect(node.getPorchLinks()).to.deep.equal({
			enabled: false,
			listening: false,
			links: [],
			relays: []
		});
		expect(node.porchInfo()).to.equal(undefined);

		const plain = node.porchNodeConfig(
			{ porchRelays: [RELAY] },
			undefined,
			'all',
			undefined
		);
		expect(plain).to.deep.equal({
			relays: [{ url: RELAY }],
			tags: [DEFAULT_TAG]
		});
		const full = node.porchNodeConfig(
			{
				porchRelays: [RELAY],
				porchVia: 'tor',
				porchStandbys: 3,
				porchToken: 'secret'
			},
			undefined,
			'all',
			undefined
		);
		expect(full).to.deep.equal({
			relays: [{ url: RELAY, token: 'secret' }],
			tags: [DEFAULT_TAG],
			via: 'tor',
			standbys: 3
		});
		expect(logs).to.deep.equal([]);
		expect(stored).to.deep.equal({});

		// The links served are the stored ones, as they stand.
		const store = new PorchLinkStore(DEFAULT_TAG, {
			load: (): string | null => stored[PORCH_LINKS_STORAGE_KEY] ?? null,
			save: (value): void => {
				stored[PORCH_LINKS_STORAGE_KEY] = value;
			}
		});
		const made = store.create('phone', 1);
		store.revoke(DEFAULT_ID);
		const again = node.porchNodeConfig(
			{ porchRelays: [RELAY] },
			undefined,
			'all',
			undefined
		);
		expect(again?.tags.map((tag) => tag.toString('hex'))).to.deep.equal([
			made.id
		]);
	});

	it('says which relays see the node and which are reached through the proxy', () => {
		const { node } = bareNode();
		const proxy = { host: '127.0.0.1', port: 9050 };
		const relays = ['wss://relay.example', 'ws://192.168.1.9:2114'];
		node.node = {
			getPorchStatus: (): unknown =>
				relays.map((relay) => ({
					relay,
					state: 'stopped',
					idle: 0,
					circuits: 0
				})),
			getPorchLinks: (): unknown => []
		};
		const proxied = (
			opts: PorchDaemonConfig,
			via: typeof proxy | undefined,
			scope: 'all' | 'onion'
		): boolean[] => {
			node.porchNodeConfig(
				{ porchRelays: relays, ...opts },
				via,
				scope,
				undefined
			);
			return node.getPorchLinks().relays.map((relay) => relay.proxied);
		};
		// No proxy: the relay's operator sees the node's address.
		expect(proxied({}, undefined, 'all')).to.deep.equal([false, false]);
		// A Tor proxy carries the public relay, as it would any public peer.
		expect(proxied({}, proxy, 'all')).to.deep.equal([true, false]);
		// Hybrid mode keeps the proxy for onion peers.
		expect(proxied({}, proxy, 'onion')).to.deep.equal([false, false]);
		// 'direct' overrides the proxy for the relays alone.
		expect(proxied({ porchVia: 'direct' }, proxy, 'all')).to.deep.equal([
			false,
			false
		]);
		// 'tor' sends a public relay through Tor with or without torProxy,
		// and is refused for a private one.
		node.porchNodeConfig(
			{ porchRelays: [relays[0]], porchVia: 'tor' },
			undefined,
			'onion',
			undefined
		);
		expect(node.getPorchLinks().relays[0].proxied).to.equal(true);
		expect(() =>
			node.porchNodeConfig(
				{ porchRelays: relays, porchVia: 'tor' },
				proxy,
				'all',
				undefined
			)
		)
			.to.throw('private address')
			.with.property('code', 'INVALID_PARAMS');
	});

	it('warns when an announced clearnet address would say where the node is', () => {
		const { node, logs } = bareNode();
		const onion = { type: 4, host: `${'a'.repeat(56)}.onion`, port: 9735 };
		const clearnet = { type: 1, host: '203.0.113.5', port: 9735 };
		node.porchNodeConfig({ porchRelays: [RELAY] }, undefined, 'all', [onion]);
		expect(logs).to.deep.equal([]);
		// Without Porch the announcement is nobody's business here.
		node.porchNodeConfig({}, undefined, 'all', [clearnet]);
		expect(logs).to.deep.equal([]);
		node.porchNodeConfig({ porchRelays: [RELAY] }, undefined, 'all', [
			onion,
			clearnet
		]);
		expect(logs).to.have.length(1);
		expect(logs[0].level).to.equal('warn');
		expect(logs[0].message).to.contain(
			'announceAddresses publishes 1 clearnet address(es)'
		);
	});

	it('serves no link from a record it cannot read, and says so', () => {
		const { node, logs, stored } = bareNode({
			[PORCH_LINKS_STORAGE_KEY]: 'not json'
		});
		const tagsSet: string[][] = [];
		node.node = {
			getPorchStatus: (): unknown => [],
			getPorchLinks: (): unknown => [],
			setPorchTags: (tags: Buffer[]): void => {
				tagsSet.push(tags.map((tag) => tag.toString('hex')));
			}
		};
		const config = node.porchNodeConfig(
			{ porchRelays: [RELAY] },
			undefined,
			'all',
			undefined
		);
		expect(config?.tags).to.deep.equal([]);
		expect(logs).to.have.length(1);
		expect(logs[0].level).to.equal('warn');
		expect(logs[0].message).to.contain('could not be read');
		const listed = node.getPorchLinks();
		expect(listed.links).to.deep.equal([]);
		expect(listed.problem).to.contain('could not be read');
		expect(stored[PORCH_LINKS_STORAGE_KEY]).to.equal('not json');

		// Making a link starts the record again, without the seed's link.
		const made = node.createPorchLink('fresh');
		expect(tagsSet).to.deep.equal([[made.id]]);
		expect(node.getPorchLinks().problem).to.equal(undefined);
		expect(JSON.parse(stored[PORCH_LINKS_STORAGE_KEY]).defaultRevoked).to.equal(
			true
		);
	});

	it('writes a change before the node acts on it, and refuses what it cannot serve', () => {
		const { node, stored } = bareNode();
		const applied: Array<{ tags: string[]; stored: string }> = [];
		node.node = {
			getPorchStatus: (): unknown => [],
			getPorchLinks: (): unknown => [
				{ relay: RELAY, tag: DEFAULT_ID, uri: 'seed-uri' }
			],
			setPorchTags: (tags: Buffer[]): void => {
				applied.push({
					tags: tags.map((tag) => tag.toString('hex')),
					stored: stored[PORCH_LINKS_STORAGE_KEY]
				});
			}
		};
		const refusal = (
			run: () => unknown
		): { code?: string; message: string } => {
			try {
				run();
			} catch (err) {
				return err as { code?: string; message: string };
			}
			throw new Error('expected a refusal');
		};
		// With Porch off there is nothing to make a link for.
		for (const run of [
			(): unknown => node.createPorchLink('x'),
			(): unknown => node.revokePorchLink(DEFAULT_ID)
		]) {
			const off = refusal(run);
			expect(off.code).to.equal('INVALID_PARAMS');
			expect(off.message).to.contain('Porch is not enabled');
		}

		node.porchNodeConfig({ porchRelays: [RELAY] }, undefined, 'all', undefined);
		const made = node.createPorchLink('  phone ');
		expect(made.label).to.equal('phone');
		expect(applied).to.have.length(1);
		expect(applied[0].tags).to.have.members([DEFAULT_ID, made.id]);
		// The database had the link before the relays were told of it.
		expect(JSON.parse(applied[0].stored).links[0].tag).to.equal(made.id);

		for (const [run, code, message] of [
			[
				(): unknown => node.createPorchLink('x'.repeat(65)),
				'INVALID_PARAMS',
				'at most 64'
			],
			[
				(): unknown => node.createPorchLink('a\nb'),
				'INVALID_PARAMS',
				'control'
			],
			[(): unknown => node.revokePorchLink('nope'), 'INVALID_PARAMS', '32 hex'],
			[
				(): unknown => node.revokePorchLink(7 as never),
				'INVALID_PARAMS',
				'32 hex'
			],
			[
				(): unknown => node.revokePorchLink('ab'.repeat(16)),
				'NOT_FOUND',
				'No such'
			]
		] as Array<[() => unknown, string, string]>) {
			const refused = refusal(run);
			expect(refused.code, message).to.equal(code);
			expect(refused.message).to.contain(message);
		}
		expect(applied).to.have.length(1);

		// An id is taken in either case, and the revocation is on disk first.
		expect(node.revokePorchLink(made.id.toUpperCase())).to.deep.equal({
			revoked: true,
			id: made.id
		});
		expect(applied).to.have.length(2);
		expect(applied[1].tags).to.deep.equal([DEFAULT_ID]);
		expect(JSON.parse(applied[1].stored).links).to.deep.equal([]);
		expect(refusal(() => node.revokePorchLink(made.id)).code).to.equal(
			'NOT_FOUND'
		);

		// Full: refused by name, and nothing is written.
		const before = stored[PORCH_LINKS_STORAGE_KEY];
		const full: Record<string, unknown> = {
			links: Array.from({ length: PORCH_MAX_TAGS - 1 }, (_, i) => ({
				tag: i.toString(16).padStart(32, '0'),
				createdAt: i
			}))
		};
		stored[PORCH_LINKS_STORAGE_KEY] = JSON.stringify(full);
		node.porchNodeConfig({ porchRelays: [RELAY] }, undefined, 'all', undefined);
		const over = refusal(() => node.createPorchLink());
		expect(over.code).to.equal('INVALID_PARAMS');
		expect(over.message).to.contain('at most 256 Porch links');
		expect(stored[PORCH_LINKS_STORAGE_KEY]).to.equal(JSON.stringify(full));
		expect(before).to.not.equal(undefined);
	});

	it('holds the listener under the startup quarantine and keeps it down when fenced', async () => {
		const { node, logs } = bareNode();
		let quarantined = true;
		let fenced = false;
		let listening = false;
		node.node = {
			listenPorch: (): void => {
				if (quarantined) {
					throw Object.assign(new Error('startup quarantine'), {
						code: 'STARTUP_QUARANTINE'
					});
				}
				listening = true;
			},
			getRecoveryGateState: (): unknown => (fenced ? 'fenced' : 'confirmed'),
			getRecoveryStatus: (): unknown => ({ fenced }),
			getGuardianHostStatus: (): unknown => null,
			emit: (): unknown => true,
			getPorchStatus: (): unknown => [
				{
					relay: RELAY,
					state: listening ? 'ready' : 'stopped',
					idle: listening ? 2 : 0,
					circuits: 0
				}
			],
			getPorchLinks: (): unknown => [
				{ relay: RELAY, tag: DEFAULT_ID, uri: 'seed-uri' }
			]
		};
		node.porchNodeConfig(
			{ porchRelays: [RELAY], porchVia: 'tor' },
			undefined,
			'all',
			undefined
		);

		// Held: no URI is handed out for a node that is not waiting anywhere.
		await node.bindListener('porch', 0);
		expect(node._porchListenError?.state).to.equal('held');
		expect(node.getPorchLinks().listening).to.equal(false);
		expect(node.porchInfo()).to.deep.equal({
			uris: [],
			links: 1,
			relays: [
				{ relay: RELAY, state: 'stopped', idle: 0, circuits: 0, proxied: true }
			]
		});
		// The full list still names the link: it is the one to hand out.
		expect(node.getPorchLinks().links).to.deep.equal([
			{ id: DEFAULT_ID, default: true, uris: ['seed-uri'] }
		]);

		// Still held: a retry records the hold again and binds nothing.
		node.bindHeldListeners();
		await sleep(5);
		expect(node._porchListenError?.state).to.equal('held');
		expect(listening).to.equal(false);

		// Writer ownership confirmed: it starts, and says so.
		quarantined = false;
		node.bindHeldListeners();
		await sleep(5);
		expect(listening).to.equal(true);
		expect(node._porchListenError).to.equal(undefined);
		expect(node.getPorchLinks().listening).to.equal(true);
		expect(node.porchInfo()?.uris).to.deep.equal(['seed-uri']);
		expect(logs.map((entry) => entry.message)).to.include(
			'Porch listener started: the node is dialing its relays'
		);

		// Fenced: the freeze stopped it, and it reads fenced from then on.
		fenced = true;
		node.fenceListeners();
		expect(node._porchListenError?.state).to.equal('fenced');
		expect(node.getPorchLinks().listening).to.equal(false);
		expect(node.porchInfo()?.uris).to.deep.equal([]);
		node.bindHeldListeners();
		await sleep(5);
		expect(node._porchListenError?.state).to.equal('fenced');

		// A rebuild starts from nothing.
		node.resetListenerState();
		expect(node._porchListenError).to.equal(undefined);
		expect(node.getPorchLinks().listening).to.equal(false);
	});

	it('records a fenced node that never started as fenced, not held', async () => {
		const { node } = bareNode();
		node.node = {
			listenPorch: (): void => {
				throw new Error('Connections are disabled');
			},
			getRecoveryGateState: (): unknown => 'fenced',
			getRecoveryStatus: (): unknown => ({ fenced: true }),
			getPorchStatus: (): unknown => [],
			getPorchLinks: (): unknown => []
		};
		node.porchNodeConfig({ porchRelays: [RELAY] }, undefined, 'all', undefined);
		await node.bindListener('porch', 0);
		expect(node._porchListenError).to.include({ port: 0, state: 'fenced' });
		expect(node.getPorchLinks().listening).to.equal(false);
	});

	it('carries the links made and revoked into a capsule restore', () => {
		const source = new SqliteStorage(':memory:');
		const target = new SqliteStorage(':memory:');
		source.open();
		target.open();
		try {
			const record = JSON.stringify({
				defaultRevoked: true,
				links: [{ tag: 'cd'.repeat(16), label: 'phone', createdAt: 1 }]
			});
			source.saveWalletData(PORCH_LINKS_STORAGE_KEY, record);
			const node = Object.create(BeignetNode.prototype) as {
				storage: SqliteStorage;
				networkName: string;
				carryDaemonState: (from: SqliteStorage, to: SqliteStorage) => void;
			};
			node.storage = source;
			node.networkName = 'regtest';
			node.carryDaemonState(source, target);
			// Without it the restored node would serve the revoked seed link.
			expect(target.loadWalletData(PORCH_LINKS_STORAGE_KEY)).to.equal(record);
		} finally {
			source.close();
			target.close();
		}
	});
});

describe('Porch daemon surface', function () {
	this.timeout(60_000);
	let daemon: IStartedDaemon | undefined;
	let other: IStartedDaemon | undefined;
	let relay: PorchRelay | undefined;
	let dir: string;
	let otherDir: string | undefined;
	const visitors: LightningNode[] = [];

	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-porch-api-'));
	});
	afterEach(async () => {
		for (const open of visitors.splice(0)) open.destroy();
		await other?.stop();
		other = undefined;
		await daemon?.stop();
		daemon = undefined;
		await relay?.close();
		relay = undefined;
		fs.rmSync(dir, { recursive: true, force: true });
		if (otherDir) fs.rmSync(otherDir, { recursive: true, force: true });
		otherDir = undefined;
	});

	function start(
		mnemonic: string,
		dataDir: string,
		porchRelays?: string[]
	): Promise<IStartedDaemon> {
		return startDaemon({
			mnemonic,
			network: 'regtest',
			dataDir,
			daemonPort: 0,
			electrumHost: '127.0.0.1',
			electrumPort: 65529,
			electrumTls: false,
			rapidGossipSync: false,
			autoGossipSync: false,
			autoBootstrap: false,
			autoReconnect: false,
			logLevel: 'silent',
			...(porchRelays ? { porchRelays } : {})
		});
	}

	async function boot(porchRelays?: string[]): Promise<void> {
		daemon = await start(MNEMONIC, dir, porchRelays);
	}

	async function requestOf<T>(
		target: IStartedDaemon,
		route: string,
		body?: unknown
	): Promise<{
		status: number;
		result: T;
		error?: { code: string; message: string };
	}> {
		const port = (target.server.address() as net.AddressInfo).port;
		const response = await fetch(`http://127.0.0.1:${port}${route}`, {
			method: body === undefined ? 'GET' : 'POST',
			headers: { 'content-type': 'application/json' },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		});
		const parsed = (await response.json()) as {
			result: T;
			error?: { code: string; message: string };
		};
		return { status: response.status, ...parsed };
	}

	function request<T>(
		route: string,
		body?: unknown
	): ReturnType<typeof requestOf<T>> {
		return requestOf<T>(daemon!, route, body);
	}

	const info = async (): Promise<NodeInfo> =>
		(await request<NodeInfo>('/info')).result;
	const links = async (): Promise<PorchLinksInfo> =>
		(await request<PorchLinksInfo>('/porch/links')).result;
	const peers = async (): Promise<PeerInfo[]> =>
		(await request<PeerInfo[]>('/peers')).result;

	function visitor(index: number): LightningNode {
		const node = LightningNode.fromMnemonic(VISITOR_MNEMONICS[index], {
			network: Network.REGTEST,
			enableNetworking: true,
			autoReconnect: false
		});
		node.on('node:error', () => undefined);
		visitors.push(node);
		return node;
	}

	function dial(node: LightningNode, uri: string): Promise<void> {
		const link = parsePeerUri(uri);
		return node.connectPeer(link.pubkey, link.host, link.port, link.transport);
	}

	it('says the engine can do it and stays off until a relay is configured', async () => {
		await boot();
		const node = await info();
		expect(node.porchAvailable).to.equal(true);
		expect(node.porch).to.equal(undefined);
		expect(node.porchListenError).to.equal(undefined);
		expect(await links()).to.deep.equal({
			enabled: false,
			listening: false,
			links: [],
			relays: []
		});
		for (const [route, body] of [
			['/porch/links/create', { label: 'phone' }],
			['/porch/links/revoke', { id: DEFAULT_ID }]
		] as Array<[string, unknown]>) {
			const refused = await request(route, body);
			expect(refused.status, route).to.equal(400);
			expect(refused.error?.code).to.equal('INVALID_PARAMS');
			expect(refused.error?.message).to.contain('Porch is not enabled');
		}
	});

	it('hands out links through a relay, takes one back, and remembers both across a restart', async () => {
		const relayPort = await freePort();
		const name = `127.0.0.1:${relayPort}`;
		const origin = `ws://${name}`;
		// A short wait for a host, so a revoked link is refused promptly.
		relay = new PorchRelay({
			authorities: [name],
			limits: { pairWaitMs: 250 }
		});
		await relay.listen(relayPort, '127.0.0.1');
		await boot([origin]);

		await waitFor(
			async () => (await info()).porch?.relays[0].state === 'ready',
			'the node registering with the relay'
		);
		await waitFor(
			async () => (await info()).porch?.relays[0].idle === 2,
			'both standbys'
		);
		const first = await info();
		const seedUri = `${first.nodeId}@${origin}/v1/p/${porchRouteId(
			HOST_KEY,
			DEFAULT_TAG
		)}`;
		expect(first.listening).to.equal(true);
		expect(first.porchListenError).to.equal(undefined);
		expect(first.porch).to.deep.equal({
			uris: [seedUri],
			links: 1,
			relays: [
				{ relay: origin, state: 'ready', idle: 2, circuits: 0, proxied: false }
			]
		});
		expect(await links()).to.deep.equal({
			enabled: true,
			listening: true,
			links: [{ id: DEFAULT_ID, default: true, uris: [seedUri] }],
			relays: first.porch!.relays
		});

		// A link of its own, for one device.
		const before = Date.now();
		const created = await request<PorchLinkInfo>('/porch/links/create', {
			label: '  phone '
		});
		expect(created.status).to.equal(200);
		const phone = created.result;
		expect(phone.id).to.match(/^[0-9a-f]{32}$/);
		expect(phone.id).to.not.equal(DEFAULT_ID);
		expect(phone.label).to.equal('phone');
		expect(phone.createdAt).to.be.within(before, Date.now());
		expect(phone.default).to.equal(undefined);
		expect(phone.uris).to.deep.equal([
			`${first.nodeId}@${origin}/v1/p/${porchRouteId(
				HOST_KEY,
				Buffer.from(phone.id, 'hex')
			)}`
		]);
		expect((await links()).links).to.deep.equal([
			{ id: DEFAULT_ID, default: true, uris: [seedUri] },
			phone
		]);
		// /info keeps to the seed's link and counts the rest.
		const counted = (await info()).porch!;
		expect(counted.uris).to.deep.equal([seedUri]);
		expect(counted.links).to.equal(2);

		// One visitor on each link. All the node knows of either is the relay.
		const onPhone = visitor(0);
		const onSeed = visitor(1);
		await dial(onPhone, phone.uris[0]);
		await dial(onSeed, seedUri);
		await waitFor(async () => (await peers()).length === 2, 'both visitors');
		const byKey = new Map((await peers()).map((peer) => [peer.pubkey, peer]));
		expect(byKey.get(onPhone.getNodeId())).to.include({
			host: `porch:${name}`,
			transport: 'ws'
		});
		expect(byKey.get(onPhone.getNodeId())?.porch).to.deep.equal({
			relay: name,
			link: phone.id
		});
		expect(byKey.get(onSeed.getNodeId())?.porch).to.deep.equal({
			relay: name,
			link: DEFAULT_ID
		});
		expect((await info()).porch?.relays[0].circuits).to.equal(2);

		// What cannot be asked for.
		for (const [route, body, status, code] of [
			['/porch/links/create', { label: 'x'.repeat(65) }, 400, 'INVALID_PARAMS'],
			['/porch/links/create', { label: 7 }, 400, 'INVALID_PARAMS'],
			['/porch/links/revoke', {}, 400, 'INVALID_PARAMS'],
			['/porch/links/revoke', { id: 'nope' }, 400, 'INVALID_PARAMS'],
			['/porch/links/revoke', { id: 'ab'.repeat(16) }, 404, 'NOT_FOUND']
		] as Array<[string, unknown, number, string]>) {
			const refused = await request(route, body);
			expect(refused.status, JSON.stringify(body)).to.equal(status);
			expect(refused.error?.code).to.equal(code);
		}
		expect((await links()).links).to.have.length(2);

		// Revoke the phone's link: that visitor is dropped, the other stays.
		const revoked = await request<{ revoked: boolean; id: string }>(
			'/porch/links/revoke',
			{ id: phone.id }
		);
		expect(revoked.status).to.equal(200);
		expect(revoked.result).to.deep.equal({ revoked: true, id: phone.id });
		await waitFor(async () => (await peers()).length === 1, 'the drop');
		expect((await peers())[0].pubkey).to.equal(onSeed.getNodeId());
		expect((await links()).links).to.deep.equal([
			{ id: DEFAULT_ID, default: true, uris: [seedUri] }
		]);
		// The link no longer leads anywhere, and the seed's still does.
		await waitFor(
			async () => (await info()).porch?.relays[0].idle === 2,
			'the node registering without the link'
		);
		const refusedDial = await dial(visitor(0), phone.uris[0]).then(
			() => null,
			(err: Error) => err
		);
		expect(refusedDial).to.be.instanceOf(Error);
		expect(await peers()).to.have.length(1);

		// The seed's link can go too. With none left the node leaves the relay.
		const seedGone = await request('/porch/links/revoke', { id: DEFAULT_ID });
		expect(seedGone.status).to.equal(200);
		await waitFor(async () => (await peers()).length === 0, 'the second drop');
		await waitFor(
			async () => (await info()).porch?.relays[0].state === 'no-links',
			'the node leaving the relay'
		);
		expect((await info()).porch).to.deep.equal({
			uris: [],
			links: 0,
			relays: [
				{
					relay: origin,
					state: 'no-links',
					idle: 0,
					circuits: 0,
					proxied: false
				}
			]
		});
		expect(relay.stats()).to.include({ standbys: 0 });

		// A new link brings it back, and a restart serves exactly that one.
		const tablet = (
			await request<PorchLinkInfo>('/porch/links/create', { label: 'tablet' })
		).result;
		await waitFor(
			async () => (await info()).porch?.relays[0].state === 'ready',
			'the node returning'
		);
		await daemon!.stop();
		daemon = undefined;
		await boot([origin]);
		await waitFor(
			async () => (await info()).porch?.relays[0].state === 'ready',
			'the restarted node registering'
		);
		expect((await links()).links).to.deep.equal([tablet]);
		expect((await info()).porch?.uris).to.deep.equal([]);
		const back = visitor(1);
		await dial(back, tablet.uris[0]);
		await waitFor(async () => (await peers()).length === 1, 'the visitor');
		expect((await peers())[0].porch).to.deep.equal({
			relay: name,
			link: tablet.id
		});
		// The revoked seed link stayed revoked.
		const stale = await dial(visitor(0), seedUri).then(
			() => null,
			(err: Error) => err
		);
		expect(stale).to.be.instanceOf(Error);
	});

	it('is dialed by another daemon as an ordinary wss:// peer address', async () => {
		const relayPort = await freePort();
		const name = `127.0.0.1:${relayPort}`;
		relay = new PorchRelay({ authorities: [name] });
		await relay.listen(relayPort, '127.0.0.1');
		await boot([`ws://${name}`]);
		await waitFor(
			async () => (await info()).porch?.relays[0].state === 'ready',
			'the node registering with the relay'
		);
		const [uri] = (await info()).porch!.uris;

		// The other side has no Porch setting at all: the link is the whole of
		// what it is given, split as `beignet peer connect '<link>'` splits it.
		otherDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-porch-peer-'));
		other = await start(VISITOR_MNEMONICS[0], otherDir);
		const at = uri.indexOf('@');
		const connected = await requestOf<PeerInfo>(other, '/peer/connect', {
			pubkey: uri.slice(0, at),
			url: uri.slice(at + 1)
		});
		expect(connected.status).to.equal(200);
		expect(connected.result.state).to.equal('connected');

		await waitFor(async () => (await peers()).length === 1, 'the peer');
		const otherId = (await requestOf<NodeInfo>(other, '/info')).result.nodeId;
		expect((await peers())[0]).to.deep.include({
			pubkey: otherId,
			host: `porch:${name}`,
			porch: { relay: name, link: DEFAULT_ID }
		});
		// The dialer sees a WebSocket peer at the relay, and no Porch field:
		// that is the node's side of it.
		const [seen] = (await requestOf<PeerInfo[]>(other, '/peers')).result;
		expect(seen.transport).to.equal('ws');
		expect(seen.porch).to.equal(undefined);
	});

	it('reports a relay that is away as status and keeps the listener up', async () => {
		const relayPort = await freePort();
		const origin = `ws://127.0.0.1:${relayPort}`;
		await boot([origin]);
		await waitFor(
			async () => (await info()).porch?.relays[0].state === 'unreachable',
			'the failed attempts'
		);
		const away = await info();
		// Not a failed listener: the node is waiting, and will be there when
		// the relay is.
		expect(away.porchListenError).to.equal(undefined);
		expect(away.listening).to.equal(true);
		expect(away.porch?.relays[0].lastError).to.be.a('string');
		expect(away.porch?.uris).to.have.length(1);
		expect((await links()).listening).to.equal(true);

		relay = new PorchRelay({ authorities: [`127.0.0.1:${relayPort}`] });
		await relay.listen(relayPort, '127.0.0.1');
		await waitFor(
			async () => (await info()).porch?.relays[0].state === 'ready',
			'the node finding the relay',
			30_000
		);
		expect((await info()).porch?.relays[0].lastError).to.equal(undefined);

		// What GET /info says when the node is not waiting at all. The states
		// themselves are driven in 'holds the listener under the startup
		// quarantine'; this is the route reporting one.
		const internals = daemon!.node as unknown as {
			_porchBound: boolean;
			_porchListenError?: ListenerProblem;
		};
		const held: ListenerProblem = { port: 0, state: 'held', message: 'held' };
		internals._porchBound = false;
		internals._porchListenError = held;
		const reported = await info();
		expect(reported.porchListenError).to.deep.equal(held);
		expect(reported.porch?.uris).to.deep.equal([]);
		expect(reported.porch?.links).to.equal(1);
		expect((await links()).listening).to.equal(false);
	});
});
