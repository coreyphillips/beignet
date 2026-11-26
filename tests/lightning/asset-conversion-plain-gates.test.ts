/**
 * #2151 step 1 behaviour that today's names already reach: the per-channel
 * plain gates of a wallet that also runs asset channels, the node's masking
 * of bit 463 and the type refusal of a generation 6 node.
 *
 * Generation 6 is enrolled through the fixtures' loose generation helper
 * (helpers/final-generation.ts), so this file compiles on the base and each
 * test fails on its behaviour. The "generation 2 seen as generation 6" view
 * reproduces the bug that observedFinalExit has today in any wallet where
 * canSpliceDualFundedAssets holds: a real generation 2 store whose
 * capability getters (and the private assetSpliceWallet) answer as a
 * generation 6 original does. The view exposes no new name.
 */
import { expect } from 'chai';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { finalOpeningOutputClaims } from '../../src/lightning/chain/final-output-claims';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import {
	ASSET_OPENING_TYPE_HEX,
	ASSET_SPLICE_RECOVERY_TYPE_HEX
} from '../../src/lightning/features/asset-opening';
import { finalOpeningChannelType } from '../../src/lightning/features/final-opening';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';
import {
	announce,
	completeRecoveryHost,
	finalTestNode,
	type IFinalTestNode
} from './helpers/asset-conversion-node';
import {
	fundReadyPair,
	generateSide,
	type Side
} from './helpers/final-update-pair';
import { plainUpdates, plainWire } from './helpers/final-plain-wire';

const CONVERSION = 462;
const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');

/** A generation 2 original seen with the wallet-level capabilities of a generation 6 original. */
function asGeneration6(store: SqliteStorage): SqliteStorage {
	const both = new Set<PropertyKey>([
		'assetSpliceWallet',
		'canOpenDualFundedAssets',
		'canSpliceDualFundedAssets',
		'canRecoverAssetSplice',
		'supportsAssetSpliceRecovery',
		'supportsAssetConversion',
		'canConvertAssetChannels'
	]);
	return new Proxy(store, {
		get(target, key, receiver) {
			if (both.has(key)) return true;
			return Reflect.get(target, key, receiver);
		}
	});
}

function deadlineManager(
	storage: SqliteStorage,
	side: Side,
	depth: string[],
	id: string
) {
	const manager = Object.assign(Object.create(ChannelManager.prototype), {
		config: { finalOpening: { storage, root: side.root } },
		assetCollateral: new Map(),
		finalObservedFunding: new Map(),
		finalDepthByChannel: new Map([[id, new Set(depth)]]),
		finalObservedClose: new Map(),
		finalTransport: { closed: () => {} }
	}) as ChannelManager;
	const broadcasts: Transaction[] = [],
		errors: string[] = [];
	manager.on('broadcast:tx', (raw: Buffer) =>
		broadcasts.push(Transaction.fromBuffer(raw))
	);
	manager.on('error', (_id: Buffer | null, message: string) => {
		errors.push(message);
	});
	return { manager, broadcasts, errors };
}

const wallets = [
	{ name: 'a generation 6 original', generation: 6 as const, view: false },
	{
		name: 'a generation 2 original seen as generation 6',
		generation: 2 as const,
		view: true
	}
];

describe('Plain exits in a wallet that also runs asset channels (#2151 step 1, item 9)', function () {
	this.timeout(120000);
	let dir: string, stores: SqliteStorage[];
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-conversion-exit-'));
		stores = [];
	});
	afterEach(() => {
		for (const s of stores) s.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	function plainPair(generation: 2 | 6) {
		const sides = [generateSide(generation), generateSide(generation)];
		stores = sides.map((s, i) =>
			SqliteStorage.createFinalWallet(path.join(dir, 'w' + i), s.binding)
		);
		const id = fundReadyPair(stores[0], stores[1], sides[0], sides[1]);
		plainUpdates(stores, sides, id).add(1100);
		return { sides, id };
	}

	for (const wallet of wallets) {
		it(
			'broadcasts the exit of a plain channel at an HTLC deadline in ' +
				wallet.name,
			() => {
				const { sides, id } = plainPair(wallet.generation);
				const storage = wallet.view ? asGeneration6(stores[0]) : stores[0];
				expect(storage.canSpliceDualFundedAssets).to.equal(true);
				const funding = Transaction.fromHex(
					stores[0].loadFinalOpening(id)!.fundingTxHex
				);
				const { manager, broadcasts, errors } = deadlineManager(
					storage,
					sides[0],
					[funding.getId()],
					id
				);
				manager.checkFinalHtlcDeadlines(1099, 10, 0);
				expect(broadcasts, 'before the deadline').to.deep.equal([]);
				manager.checkFinalHtlcDeadlines(1100, 10, 0);
				expect(errors).to.deep.equal([]);
				expect(broadcasts, 'exit broadcast at the deadline').to.have.length(1);
				expect(broadcasts[0].ins[0].hash).to.deep.equal(funding.getHash());
			}
		);

		it(
			'broadcasts the parent exit while a plain splice is pending, and selects among the exits as generation 2 does, in ' +
				wallet.name,
			async () => {
				const { sides, id } = plainPair(wallet.generation);
				const wire = plainWire(stores, sides, id);
				const child = await wire.spliceOut();
				wire.destroy();
				const storage = wallet.view ? asGeneration6(stores[0]) : stores[0];
				const exits = storage.loadFinalFundingExits(id);
				expect(
					exits
						.map((e) => Buffer.from(e.fundingTxid).reverse().toString('hex'))
						.sort()
				).to.deep.equal([wire.parent, child.getId()].sort());
				const { manager, broadcasts, errors } = deadlineManager(
					storage,
					sides[0],
					[wire.parent],
					id
				);
				manager.checkFinalHtlcDeadlines(1100, 10, 0);
				expect(errors).to.deep.equal([]);
				expect(broadcasts, 'parent exit at the deadline').to.have.length(1);
				expect(
					Buffer.from(broadcasts[0].ins[0].hash).reverse().toString('hex')
				).to.equal(wire.parent);
				// With no outpoint named, selection takes the first matching exit, as in
				// generation 2, and never refuses with the asset outpoint rule.
				const chosen = Transaction.fromBuffer(
					storage.requestFinalOpeningExit(id)
				);
				expect(chosen.ins[0].hash).to.deep.equal(exits[0].fundingTxid);
				expect(
					Transaction.fromBuffer(
						storage.requestFinalOpeningExit(id, child.getHash())
					).ins[0].hash
				).to.deep.equal(child.getHash());
			}
		);
	}
});

describe('Fail-closed plain entry points for an asset channel (#2151 step 1, item 8)', function () {
	this.timeout(90000);
	let dir: string;
	let f: ReturnType<typeof setupAssetSpliceProofs> | undefined;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-conversion-closed-'));
		f = undefined;
	});
	afterEach(() => {
		for (const d of f?.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	function fundedAssetChannel(generation: 5 | 6) {
		f = setupAssetSpliceProofs(dir, undefined, generation);
		f.fundOpening();
		const ready = f.devices.map((d) =>
			d.store.finalOpeningChannelReady(f!.id, d.party.root)
		);
		f.devices.forEach((d, i) =>
			d.store.rememberFinalPeerChannelReady(f!.id, ready[1 - i], true)
		);
		return f;
	}

	type Outcome = { value: unknown } | { threw: string };
	function outcome(run: () => unknown): Outcome {
		try {
			const value = run();
			return { value: value === undefined ? 'undefined' : value };
		} catch (e) {
			return { threw: (e as Error).message };
		}
	}
	function table(fixture: ReturnType<typeof setupAssetSpliceProofs>) {
		const { store, party } = fixture.devices[0];
		const id = fixture.id;
		const close = {
			start: true,
			script: destination,
			blockHeight: 200,
			feeratePerKw: 1000
		};
		const rows: Record<string, () => unknown> = {
			finalUpdateView: () => store['finalUpdateView'](id),
			loadFinalUpdateStatus: () => store.loadFinalUpdateStatus(id),
			loadFinalResolutionStates: () => store.loadFinalResolutionStates(id),
			loadFinalSimpleClose: () => store.loadFinalSimpleClose(id),
			finalSimpleCloseTransactions: () =>
				store.finalSimpleCloseTransactions(id),
			finalOpeningOutputClaims: () =>
				finalOpeningOutputClaims(
					{ storage: store, root: party.root },
					Buffer.from(id, 'hex'),
					fixture.views[1].parent.expected,
					destination,
					1
				),
			readFinalSpliceAttempts: () => store['readFinalSpliceAttempts'](id),
			loadFinalSpliceAttempts: () => store.loadFinalSpliceAttempts(id),
			updateFinalLedger: () => store['updateFinalLedger'](id, () => 'changed'),
			finalSpliceSession: () => store.finalSpliceSession(id, party.root),
			finalSimpleCloseStep: () =>
				store.finalSimpleCloseStep(id, party.root, close)
		};
		const result: Record<string, unknown> = {};
		for (const [name, run] of Object.entries(rows)) {
			const o = outcome(run);
			result[name] = 'threw' in o ? 'throws' : o.value;
		}
		return { result, rows };
	}

	it('answers each plain reader as for a channel with no plain state, and refuses each plain writer, on a generation 6 wallet', () => {
		const fixture = fundedAssetChannel(6);
		expect(fixture.devices[0].store.canUpdateFinalCommitments).to.equal(true);
		expect(
			fixture.devices[0].store.loadFinalOpeningSession(fixture.id)!.updateLimits
		).to.not.equal(undefined);
		const { result, rows } = table(fixture);
		expect(result).to.deep.equal({
			finalUpdateView: null,
			loadFinalUpdateStatus: null,
			loadFinalResolutionStates: null,
			loadFinalSimpleClose: null,
			finalSimpleCloseTransactions: [],
			finalOpeningOutputClaims: [],
			readFinalSpliceAttempts: [],
			loadFinalSpliceAttempts: [],
			updateFinalLedger: 'throws',
			finalSpliceSession: 'throws',
			finalSimpleCloseStep: 'throws'
		});
		expect(outcome(rows.updateFinalLedger)).to.deep.equal({
			threw: 'Final updates require a plain final channel'
		});
		expect(outcome(rows.finalSpliceSession)).to.deep.equal({
			threw: 'Final splice requires a plain final channel'
		});
		expect(outcome(rows.finalSimpleCloseStep)).to.deep.equal({
			threw: 'Final close requires a plain final channel'
		});
	});

	it('keeps the results and error texts of generation 5 unchanged', () => {
		const fixture = fundedAssetChannel(5);
		const { result, rows } = table(fixture);
		expect(result).to.deep.equal({
			finalUpdateView: null,
			loadFinalUpdateStatus: null,
			loadFinalResolutionStates: null,
			loadFinalSimpleClose: null,
			finalSimpleCloseTransactions: [],
			finalOpeningOutputClaims: [],
			readFinalSpliceAttempts: [],
			loadFinalSpliceAttempts: [],
			updateFinalLedger: 'throws',
			finalSpliceSession: 'throws',
			finalSimpleCloseStep: 'throws'
		});
		expect(outcome(rows.updateFinalLedger)).to.deep.equal({
			threw:
				'Final updates require an original update wallet and a top-level commit'
		});
		expect(outcome(rows.finalSpliceSession)).to.deep.equal({
			threw: 'Splice requires the original update wallet and a top-level commit'
		});
		expect(outcome(rows.finalSimpleCloseStep)).to.deep.equal({
			threw: 'Final close requires the original update-capable wallet'
		});
	});

	it('restarts a generation 6 node holding an asset channel and lists its channels without error', () => {
		const fixture = fundedAssetChannel(6);
		const d = fixture.devices[0];
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		const running = finalTestNode(6, {
			wallet: { db: d.store, mnemonic: d.mnemonic }
		});
		try {
			running.node.getChannelManager().restoreFinalOpeningBroadcasts();
			const listed = running.node.listChannels();
			const asset = listed.filter(
				(c) => Buffer.from(c.channelId).toString('hex') === fixture.id
			);
			expect(asset).to.have.length(1);
			expect((asset[0] as { auxiliary?: boolean }).auxiliary).to.equal(true);
			expect(
				running.node.getChannel(Buffer.from(fixture.id, 'hex'))
			).to.not.equal(undefined);
			expect(running.errors).to.deep.equal([]);
			expect(running.calls).to.deep.equal([]);
		} finally {
			running.close();
		}
	});
});

describe('Bit 463 at node level (#2151 step 1, item 4)', function () {
	this.timeout(60000);
	const nodes: IFinalTestNode[] = [];
	afterEach(() => {
		for (const n of nodes.splice(0)) n.close();
	});
	const make = (...args: Parameters<typeof finalTestNode>) => {
		const n = finalTestNode(...args);
		nodes.push(n);
		return n;
	};
	const advertised = (n: IFinalTestNode) =>
		FeatureFlags.fromBuffer(n.node.getLocalFeatures().toBuffer());

	it('advertises 463 from a generation 6 node with a complete recovery host, and never 462', () => {
		const n = make(6);
		const local = n.node.getLocalFeatures();
		expect(local.hasBit(Feature.OPTION_ASSET_SPLICE_RECOVERY + 1)).to.equal(
			true
		);
		expect(local.hasBit(CONVERSION + 1), 'live 463').to.equal(true);
		expect(advertised(n).hasBit(CONVERSION + 1), 'advertised 463').to.equal(
			true
		);
		expect(local.listSetBits()).to.include(CONVERSION + 1);
		local.setBit(CONVERSION);
		expect(local.hasBit(CONVERSION)).to.equal(false);
		expect(advertised(n).hasBit(CONVERSION)).to.equal(false);
		expect(local.listSetBits()).to.not.include(CONVERSION);
		expect(n.calls).to.deep.equal([]);
	});

	it('masks 463 for generation 5, for a generation 6 node without a complete recovery host, and whenever 461 is masked', () => {
		const masked = (n: IFinalTestNode, why: string) => {
			const local = n.node.getLocalFeatures();
			local.setBit(CONVERSION + 1);
			local.setBit(CONVERSION);
			expect(local.hasBit(CONVERSION + 1), why).to.equal(false);
			expect(advertised(n).hasBit(CONVERSION + 1), why).to.equal(false);
			expect(local.hasBit(CONVERSION), why).to.equal(false);
			expect(advertised(n).hasBit(CONVERSION), why).to.equal(false);
		};
		masked(make(5), 'generation 5 with a complete host');
		masked(make(6, { host: null }), 'generation 6 without a host');
		masked(
			make(6, { host: completeRecoveryHost([], 'recoverHtlc') }),
			'generation 6 without recoverHtlc'
		);
		const noQuiesce = LightningNode.defaultFeatures();
		noQuiesce.clearBit(Feature.QUIESCE);
		noQuiesce.clearBit(Feature.QUIESCE + 1);
		const withoutSplice = make(6, { localFeatures: noQuiesce });
		expect(
			withoutSplice.node
				.getLocalFeatures()
				.hasBit(Feature.OPTION_ASSET_SPLICE_RECOVERY + 1)
		).to.equal(false);
		masked(withoutSplice, '461 masked');
		for (const missing of [Feature.SHUTDOWN_ANY_SEGWIT, Feature.CHANNEL_TYPE]) {
			const vector = LightningNode.defaultFeatures();
			vector.clearBit(missing);
			vector.clearBit(missing + 1);
			masked(make(6, { localFeatures: vector }), 'without ' + Feature[missing]);
		}
	});
});

describe('Channel types of a generation 6 node (#2151 step 1, item 12)', function () {
	this.timeout(60000);
	const nodes: IFinalTestNode[] = [];
	afterEach(() => {
		for (const n of nodes.splice(0)) n.close();
	});
	function pair(peerWith463 = true) {
		const alice = finalTestNode(6),
			bob = finalTestNode(6);
		nodes.push(alice, bob);
		const bobInit = FeatureFlags.fromBuffer(
			bob.node.getLocalFeatures().toBuffer()
		);
		if (!peerWith463) {
			bobInit.clearBit(CONVERSION);
			bobInit.clearBit(CONVERSION + 1);
		}
		announce(alice.node, bobInit);
		announce(bob.node, alice.node.getLocalFeatures());
		const refusal = (type: Buffer) =>
			(
				alice.node.getChannelManager() as unknown as {
					finalOpeningRefusal(
						peer: string,
						type: Buffer,
						flags: number | undefined,
						unsupported: boolean
					): string | null;
				}
			).finalOpeningRefusal(bob.node.getNodeId(), type, 0, false);
		return { alice, bob, refusal };
	}

	it('refuses the generation 4 asset type both ways and accepts the recovery type and the plain type with 463 on both', () => {
		const { alice, bob, refusal } = pair();
		expect(refusal(Buffer.from(ASSET_OPENING_TYPE_HEX, 'hex'))).to.be.a(
			'string'
		);
		expect(
			refusal(Buffer.from(ASSET_SPLICE_RECOVERY_TYPE_HEX, 'hex'))
		).to.equal(null);
		expect(refusal(finalOpeningChannelType()), 'plain final type').to.equal(
			null
		);
		const options = {
			fundingSatoshis: 400_000n,
			fundingFeeratePerkw: 1000,
			commitmentFeeratePerkw: 1000
		};
		expect(() =>
			alice.node.openChannelV2(bob.node.getNodeId(), {
				...options,
				dualFundedAssets: true,
				channelType: Buffer.from(ASSET_OPENING_TYPE_HEX, 'hex')
			})
		).to.throw(/Conflicting asset opening channel type/);
		expect(() =>
			alice.node.openChannelV2(bob.node.getNodeId(), {
				...options,
				channelType: Buffer.from(ASSET_OPENING_TYPE_HEX, 'hex')
			})
		).to.throw(/explicit opt-in/);
		expect(alice.calls).to.deep.equal([]);
	});

	it('opens and accepts no plain final channel without 463 on both, and names the conversion bit', () => {
		const { alice, bob, refusal } = pair(false);
		expect(refusal(finalOpeningChannelType())).to.be.a('string');
		expect(() =>
			alice.node.openChannelV2(bob.node.getNodeId(), {
				finalTaproot: true,
				fundingSatoshis: 400_000n,
				fundingFeeratePerkw: 1000,
				commitmentFeeratePerkw: 1000
			})
		).to.throw(/conversion|463/i);
		expect(alice.calls).to.deep.equal([]);
	});
});

describe('Asset payout slots of a plain opening in generation 5 (#2151 step 1)', function () {
	this.timeout(60000);
	it('keeps the answers and error texts of generation 5', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-conversion-g5-'));
		const sides = [generateSide(5), generateSide(5)];
		const stores = sides.map((s, i) =>
			SqliteStorage.createFinalWallet(path.join(dir, 'w' + i), s.binding)
		);
		try {
			const id = fundReadyPair(stores[0], stores[1], sides[0], sides[1]);
			const parent = 'ab'.repeat(32);
			expect(stores[0].assetOpeningPayoutReceipt(id, parent, 0)).to.equal(null);
			expect(() => stores[0].assetOpeningPayout(id, parent)).to.throw(
				'Asset payout requires a valid commitment output index'
			);
		} finally {
			for (const s of stores) s.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
