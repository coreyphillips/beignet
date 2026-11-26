/**
 * #2151 step 1: a generation 6 wallet runs plain final Taproot channels and
 * asset channels of the recovery profile side by side. Nothing converts yet.
 *
 * The per-channel claim dispatcher these tests pin is exported from
 * src/lightning/chain/final-output-claims.ts with this exact signature:
 *
 *   export function finalChannelOutputClaims(
 *     runtime: IFinalOpeningRuntime,
 *     id: Buffer,
 *     parent: Transaction,
 *     destination: Buffer,
 *     feeRate: number,
 *     provider: IAuxiliaryDualFunding | undefined,
 *     trimmed:
 *       | ((hash: Buffer, htlcId: bigint, preimage?: Buffer) => void)
 *       | undefined,
 *     kindOf: (channelId: string) => 'plain' | 'asset' | null,
 *     builders?: {
 *       plain?: typeof finalOpeningOutputClaims;
 *       asset?: typeof assetOpeningOutputClaims;
 *     }
 *   ): IFinalOutputClaim[];
 *
 * kindOf receives the channel ID in hex (lightning-node.ts passes
 * storage.loadFinalChannelKind). For 'plain' it returns
 * builders.plain(runtime, id, parent, destination, feeRate, trimmed), for
 * 'asset' builders.asset(runtime, id, parent, destination, feeRate, provider,
 * trimmed), and for null it returns [] without calling either. The builders
 * default to finalOpeningOutputClaims and assetOpeningOutputClaims.
 */
import { expect } from 'chai';
import { strict as assert } from 'assert';
import Database from 'better-sqlite3';
import { payments, Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { assetOpeningOutputClaims } from '../../src/lightning/chain/asset-opening-claims';
import {
	finalChannelOutputClaims,
	finalOpeningOutputClaims,
	type IFinalOutputClaim
} from '../../src/lightning/chain/final-output-claims';
import type {
	IAssetOpeningPayout,
	IAuxiliaryDualFunding
} from '../../src/lightning/channel/asset-opening-provider';
import type { IFinalOpeningRuntime } from '../../src/lightning/channel/final-opening-runtime';
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';
import { MessageType as M } from '../../src/lightning/message/types';
import { finalWalletIdentity } from '../../src/lightning/storage/final-wallet-format';
import type { IFinalWalletBinding } from '../../src/lightning/storage/final-wallet-format';
import {
	finalWalletGeneration,
	generateFinalDaemonWallet
} from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { setupAssetSpliceProofs } from './helpers/asset-splice-proof-release';
import {
	assetUpdateTestHost,
	setupFundedAssetUpdatePair
} from './helpers/asset-splice-update';
import { boundParticipant } from './helpers/final-opening-signing';
import { fundReadyPair, type Side } from './helpers/final-update-pair';
import {
	closeCooperatively,
	plainUpdates,
	plainWire
} from './helpers/final-plain-wire';

const destination = Buffer.from('0014' + 'cd'.repeat(20), 'hex');
const unknown = '77'.repeat(32);
const flagsFor = (index?: number) =>
	[0, 1, 2, 3, 4].map((i) => i === index) as [
		boolean,
		boolean,
		boolean,
		boolean,
		boolean
	];
const conversion = () => generateFinalDaemonWallet(...flagsFor(4));
const earlier: Array<Partial<IFinalWalletBinding>> = [
	{},
	{ finalCommitmentUpdates: true },
	{ dualFundedAssets: true },
	{ assetSplice: true },
	{ assetSpliceRecovery: true }
];

/** A provider that records every asset payout call and builds a plain sweep. */
function recordingProvider(calls: string[]) {
	return {
		assetSpliceRecoveryVersion: 1,
		outputRecoveryReceipt(
			_c: string,
			_p: string,
			_i: number,
			payout: Transaction
		) {
			calls.push('receipt');
			return Buffer.from(payout.getId(), 'hex');
		},
		async restoreOutputReceipt() {
			calls.push('restore');
		},
		async recoverOutput(ctx: IAssetOpeningPayout) {
			calls.push('recover:' + ctx.walletGeneration);
			const sweep = new Transaction();
			sweep.version = 2;
			sweep.addInput(ctx.parent.getHash(), ctx.outputIndex, ctx.delay);
			sweep.addOutput(
				destination,
				ctx.parent.outs[ctx.outputIndex].value - 400
			);
			sweep.setWitness(0, ctx.signSweep(sweep, [ctx.parent]));
			return sweep;
		}
	} as unknown as IAuxiliaryDualFunding;
}

const shape = (claims: IFinalOutputClaim[]) =>
	claims.map((c) => [
		c.outputIndex,
		c.relativeDelay,
		c.absoluteHeight,
		c.tx?.toHex() ?? null,
		!!c.recover,
		!!c.assetBalanceOutput
	]);

describe('Generation 6 enrollment (#2151 step 1)', () => {
	let dir: string;
	const open: SqliteStorage[] = [];
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-conversion-enroll-'));
	});
	afterEach(() => {
		for (const s of open.splice(0)) s.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('gives generation 6 for assetConversion alone and refuses it with any other capability', () => {
		expect(finalWalletGeneration(...flagsFor(4))).to.equal(6);
		expect(finalWalletGeneration(false, false, false, false, false)).to.equal(
			1
		);
		for (let other = 0; other < 4; other++) {
			const pair = flagsFor(4);
			pair[other] = true;
			expect(() => finalWalletGeneration(...pair), 'pair ' + other).to.throw(
				'Invalid or conflicting final wallet capabilities'
			);
			expect(() => generateFinalDaemonWallet(...pair)).to.throw(
				'Invalid or conflicting final wallet capabilities'
			);
			expect(finalWalletGeneration(...flagsFor(other))).to.equal(other + 2);
		}
		expect(() =>
			finalWalletGeneration(false, false, false, false, 1 as unknown as boolean)
		).to.throw('Invalid or conflicting final wallet capabilities');
		const { binding } = conversion();
		expect(binding.assetConversion).to.equal(true);
		for (const field of [
			'finalCommitmentUpdates',
			'dualFundedAssets',
			'assetSplice',
			'assetSpliceRecovery'
		] as const)
			expect(binding[field], field).to.equal(undefined);
		const file = path.join(dir, 'wallet.db');
		expect(finalWalletIdentity(file, binding)).to.equal(
			JSON.stringify([6, binding.nodeId, 'regtest'])
		);
		expect(() =>
			finalWalletIdentity(file, { ...binding, network: 'mainnet' })
		).to.throw('This final wallet generation requires regtest');
	});

	it('holds every capability on the original and keeps only the readable ones on a copy', async () => {
		const { binding } = conversion();
		const file = path.join(dir, 'wallet.db'),
			copy = path.join(dir, 'copy.db');
		const store = SqliteStorage.createFinalWallet(file, binding);
		open.push(store);
		for (const capability of [
			'canSignFinalOpening',
			'canOpenDualFundedAssets',
			'canSpliceDualFundedAssets',
			'canRecoverAssetSplice',
			'canUpdateFinalCommitments',
			'supportsAssetSpliceRecovery',
			'supportsAssetConversion',
			'canConvertAssetChannels'
		] as const)
			expect(store[capability], capability).to.equal(true);
		expect(store['updateWallet'], 'updateWallet').to.equal(true);
		expect(store['assetSpliceWallet'], 'assetSpliceWallet').to.equal(true);
		const tables = store['db']
			.prepare("SELECT name FROM sqlite_master WHERE type='table'")
			.all()
			.map((r) => (r as { name: string }).name);
		expect(tables).to.include.members([
			'final_lifecycle_log',
			'final_channel_update_log'
		]);
		await store.backup(copy);
		const backup = SqliteStorage.openFinalWallet(copy, binding);
		open.push(backup);
		for (const deviceBound of [
			'canSignFinalOpening',
			'canOpenDualFundedAssets',
			'canSpliceDualFundedAssets',
			'canRecoverAssetSplice',
			'canUpdateFinalCommitments',
			'canConvertAssetChannels'
		] as const)
			expect(backup[deviceBound], deviceBound).to.equal(false);
		expect(backup.supportsAssetSpliceRecovery).to.equal(true);
		expect(backup.supportsAssetConversion).to.equal(true);
		expect(() =>
			SqliteStorage.createFinalWallet(path.join(dir, 'main.db'), {
				...conversion().binding,
				network: 'mainnet'
			})
		).to.throw(/regtest/);
		// The live original holds its signer under an exclusive lock, so the
		// signer's pragma is read once the original is closed.
		store.close();
		const signer = new Database(file + '.opening-signer', { readonly: true });
		try {
			expect(signer.pragma('auto_vacuum', { simple: true })).to.equal(1);
		} finally {
			signer.close();
		}
	});

	it('names no capability of generation 6 in the earlier generations', () => {
		for (let g = 0; g < 4; g++) {
			const store = SqliteStorage.createFinalWallet(
				path.join(dir, 'g' + (g + 2)),
				generateFinalDaemonWallet(...flagsFor(g)).binding
			);
			open.push(store);
			expect(store.supportsAssetConversion, 'generation ' + (g + 2)).to.equal(
				false
			);
			expect(store.canConvertAssetChannels).to.equal(false);
			expect(store.supportsAssetSpliceRecovery).to.equal(g === 3);
			// Defined for every generation: an unknown channel has no kind.
			expect(store.loadFinalChannelKind(unknown)).to.equal(null);
		}
	});

	it('refuses a generation 6 binding that was not freshly generated (item 10)', () => {
		const { binding } = conversion();
		expect(() =>
			SqliteStorage.createFinalWallet(path.join(dir, 'imported.db'), {
				...binding
			})
		).to.throw(/fresh/);
		const imported: IFinalWalletBinding = {
			network: 'regtest',
			assetConversion: true,
			nodeId: binding.nodeId,
			encryptionKey: binding.encryptionKey
		};
		expect(() =>
			SqliteStorage.createFinalWallet(path.join(dir, 'other.db'), imported)
		).to.throw(/fresh/);
	});
});

describe('Generation 6 downgrade fence (#2151 step 1, section 4)', () => {
	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-conversion-fence-'));
	});
	afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

	it('refuses a generation 6 wallet and its backup under every earlier binding', async () => {
		const { binding } = conversion();
		const file = path.join(dir, 'wallet.db'),
			copy = path.join(dir, 'copy.db');
		const store = SqliteStorage.createFinalWallet(file, binding);
		await store.backup(copy);
		store.close();
		for (const where of [file, copy])
			for (const old of earlier)
				expect(
					() =>
						SqliteStorage.openFinalWallet(where, {
							...binding,
							assetConversion: false,
							...old
						}),
					where + ' ' + JSON.stringify(old)
				).to.throw('Final wallet binding does not match');
		SqliteStorage.openFinalWallet(copy, binding).close();
	});

	it('refuses a generation 5 wallet under a conversion binding', () => {
		const { binding } = generateFinalDaemonWallet(...flagsFor(3));
		const file = path.join(dir, 'recovery.db');
		SqliteStorage.createFinalWallet(file, binding).close();
		expect(() =>
			SqliteStorage.openFinalWallet(file, {
				...binding,
				assetSpliceRecovery: false,
				assetConversion: true
			})
		).to.throw('Final wallet binding does not match');
		expect(() =>
			SqliteStorage.openFinalWallet(file, { ...binding, assetConversion: true })
		).to.throw('Invalid or conflicting final wallet capabilities');
	});

	it('refuses a generation 6 backup under the generation 5 binding of the same seed', async () => {
		const { binding } = conversion();
		const file = path.join(dir, 'wallet.db'),
			copy = path.join(dir, 'copy.db');
		const store = SqliteStorage.createFinalWallet(file, binding);
		await store.backup(copy);
		store.close();
		const own = SqliteStorage.openFinalWallet(copy, binding);
		try {
			expect(own.supportsAssetConversion).to.equal(true);
		} finally {
			own.close();
		}
		expect(() =>
			SqliteStorage.openFinalWallet(copy, {
				...binding,
				assetConversion: false,
				assetSpliceRecovery: true
			})
		).to.throw('Final wallet binding does not match');
	});
});

describe('One generation 6 wallet with both kinds of channel (#2151 step 1, items 6, 7 and 11)', function () {
	this.timeout(180000);
	let dir: string;
	let current:
		| Awaited<ReturnType<typeof setupFundedAssetUpdatePair>>
		| undefined;
	let stores: SqliteStorage[], plainSides: Side[];
	let assetId: string, plainId: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-conversion-both-'));
		current = undefined;
	});
	afterEach(() => {
		for (const d of current?.f.devices ?? []) d.store.close();
		fs.rmSync(dir, { recursive: true, force: true });
	});
	// Each test builds its own pair, so a failing setup is reported per test.
	async function setup(): Promise<NonNullable<typeof current>> {
		// The asset splice keys sit at index 2, which signatureRoundFixture(...,
		// false) allocates at setup. The plain channel then takes index 3.
		const s = await setupFundedAssetUpdatePair(dir, 6);
		current = s;
		stores = s.f.devices.map((d) => d.store);
		assetId = s.f.id;
		plainSides = s.f.devices.map((d) =>
			boundParticipant(d.party.root, 3, d.party.binding)
		);
		plainId = fundReadyPair(stores[0], stores[1], plainSides[0], plainSides[1]);
		return s;
	}

	async function assetUpdateRound(): Promise<void> {
		const { f } = current!;
		const batch = f.devices.map(({ store, party }, i) =>
			store.assetSpliceUpdateBatch(
				f.id,
				party.root,
				1n,
				[
					{
						kind: 'add',
						htlc: {
							offeredBy: i === 0 ? 'local' : 'peer',
							id: 0n,
							amountMsat: 5000000n,
							cltvExpiry: 601000,
							paymentHash: Buffer.alloc(32, 17),
							allocations: [{ assetId: '4c'.repeat(32), units: 3n }]
						}
					}
				],
				() => 600900
			)
		);
		const hosts = [assetUpdateTestHost(0), assetUpdateTestHost(1)];
		const offers = batch.map((b) => b.offer());
		batch.forEach((b, i) => b.acceptOffer(offers[1 - i]));
		const shares = (await Promise.all(
			batch.map((b, i) => b.signAssetShares(hosts[i]))
		)) as [Buffer, Buffer];
		const htlcs = (await Promise.all(
			batch.map((b, i) => b.signAssetHtlcs(hosts[i], shares))
		)) as [Buffer, Buffer];
		await Promise.all(
			batch.map((b, i) => b.verifyAssetShares(hosts[i], shares, htlcs))
		);
		const commits = batch.map((b) => b.commitments());
		await Promise.all(
			batch.map((b, i) => b.acceptCommitments(hosts[i], commits[1 - i]))
		);
		const revocations = batch.map((b) => b.revocation());
		batch.forEach((b, i) => b.receiveRevocation(revocations[1 - i]));
	}

	it('names each kind, claims each through its own builder and restores both from a backup', async () => {
		const s = await setup();
		const runtime: IFinalOpeningRuntime = {
			storage: stores[0],
			root: s.f.devices[0].party.root
		};
		const plainRuntime: IFinalOpeningRuntime = {
			storage: stores[0],
			root: plainSides[0].root
		};
		const kindOf = (id: string) => stores[0].loadFinalChannelKind(id);
		expect(kindOf(assetId)).to.equal('asset');
		expect(kindOf(plainId)).to.equal('plain');
		expect(kindOf(unknown)).to.equal(null);

		// The plain channel takes updates both ways.
		const updates = plainUpdates(stores, plainSides, plainId);
		updates.add();
		updates.fulfill();
		const status = stores[0].loadFinalUpdateStatus(plainId)!;
		expect(status.localHeight).to.equal(2n);
		expect(status.remoteHeight).to.equal(2n);
		expect(status.htlcs).to.deep.equal([]);

		// The asset channel, already spliced by the fixture, takes an update round.
		await assetUpdateRound();
		const revoked = s.f.views[1].candidate.expected;
		const calls: string[] = [];
		const provider = recordingProvider(calls);
		const assetClaims = assetOpeningOutputClaims(
			runtime,
			Buffer.from(assetId, 'hex'),
			revoked,
			destination,
			1,
			provider
		);
		expect(assetClaims).to.have.length(2);
		expect(assetClaims.every((c) => !!c.recover)).to.equal(true);
		const swept = await Promise.all(assetClaims.map((c) => c.recover!()));
		expect(swept.every((tx) => !!tx)).to.equal(true);
		// The host sees the asset profile (5), not the wallet identity (6).
		expect(calls.filter((c) => c.startsWith('recover'))).to.deep.equal([
			'recover:5',
			'recover:5'
		]);
		calls.length = 0;

		// The plain unilateral close is claimed by the plain builder alone.
		const plainExit = Transaction.fromBuffer(
			stores[0].loadFinalResolutionStates(plainId)!.locals[0].tx
		);
		const plainClaims = finalOpeningOutputClaims(
			plainRuntime,
			Buffer.from(plainId, 'hex'),
			plainExit,
			destination,
			1
		);
		expect(plainClaims.length).to.be.greaterThan(0);
		expect(
			assetOpeningOutputClaims(
				plainRuntime,
				Buffer.from(plainId, 'hex'),
				plainExit,
				destination,
				1,
				provider
			)
		).to.deep.equal([]);
		expect(
			finalOpeningOutputClaims(
				runtime,
				Buffer.from(assetId, 'hex'),
				revoked,
				destination,
				1
			)
		).to.deep.equal([]);

		// The dispatcher picks the builder by the channel's own kind.
		const dispatchedPlain = finalChannelOutputClaims(
			plainRuntime,
			Buffer.from(plainId, 'hex'),
			plainExit,
			destination,
			1,
			provider,
			undefined,
			kindOf
		);
		expect(shape(dispatchedPlain)).to.deep.equal(shape(plainClaims));
		for (const claim of dispatchedPlain) {
			expect(claim.recover).to.equal(undefined);
			expect(claim.assetBalanceOutput).to.equal(undefined);
			expect(claim.matchesAssetPayout).to.equal(undefined);
			expect(claim.confirmAssetPayout).to.equal(undefined);
		}
		expect(calls, 'no asset payout for the plain channel').to.deep.equal([]);
		const dispatchedAsset = finalChannelOutputClaims(
			runtime,
			Buffer.from(assetId, 'hex'),
			revoked,
			destination,
			1,
			provider,
			undefined,
			kindOf
		);
		expect(dispatchedAsset).to.have.length(2);
		expect(dispatchedAsset.every((c) => !!c.recover)).to.equal(true);

		// Backup keeps both kinds, and reopening the original restores both.
		const copy = path.join(dir, 'both.db');
		const journal = stores[0].readAssetSpliceJournal(assetId);
		await stores[0].backup(copy);
		const backup = SqliteStorage.openFinalWallet(
			copy,
			s.f.devices[0].party.binding
		);
		try {
			expect(backup.loadFinalChannelKind(assetId)).to.equal('asset');
			expect(backup.loadFinalChannelKind(plainId)).to.equal('plain');
			expect(
				backup
					.loadFinalOpenings()
					.map((c) => c.channelId)
					.sort()
			).to.deep.equal([assetId, plainId].sort());
			expect(backup.readAssetSpliceJournal(assetId)).to.deep.equal(journal);
			expect(backup.canUpdateFinalCommitments).to.equal(false);
			expect(backup.supportsAssetConversion).to.equal(true);
		} finally {
			backup.close();
		}
		const d = s.f.devices[0];
		d.store.close();
		d.store = SqliteStorage.openFinalWallet(d.file, d.party.binding);
		stores[0] = d.store;
		expect(d.store.loadFinalChannelKind(assetId)).to.equal('asset');
		expect(d.store.loadFinalChannelKind(plainId)).to.equal('plain');
		expect(d.store.readAssetSpliceJournal(assetId)).to.deep.equal(journal);
		expect(d.store.loadFinalUpdateStatus(plainId)!.localHeight).to.equal(2n);
		expect(d.store.canConvertAssetChannels).to.equal(true);
	});

	it('dispatches each kind to exactly one builder and an unknown channel to none', async () => {
		const s = await setup();
		const runtime: IFinalOpeningRuntime = {
			storage: stores[0],
			root: s.f.devices[0].party.root
		};
		const seen: string[] = [];
		const builders = {
			plain: ((_r, id) => {
				seen.push('plain:' + id.toString('hex'));
				return [];
			}) as typeof finalOpeningOutputClaims,
			asset: ((_r, id, _p, _d, _f, provider) => {
				seen.push('asset:' + id.toString('hex') + ':' + !!provider);
				return [];
			}) as typeof assetOpeningOutputClaims
		};
		const tx = s.f.views[1].candidate.expected;
		const provider = recordingProvider([]);
		for (const id of [plainId, assetId, unknown])
			finalChannelOutputClaims(
				runtime,
				Buffer.from(id, 'hex'),
				tx,
				destination,
				1,
				provider,
				undefined,
				(channelId) => stores[0].loadFinalChannelKind(channelId),
				builders
			);
		expect(seen).to.deep.equal([
			'plain:' + plainId,
			'asset:' + assetId + ':true'
		]);
	});

	it('splices the plain channel and closes it cooperatively through the final close, which reads no init features', async () => {
		await setup();
		const journal = stores[0].readAssetSpliceJournal(assetId);
		const wire = plainWire(stores, plainSides, plainId);
		const child = await wire.spliceOut();
		wire.adopt(child);
		wire.destroy();
		expect(stores[0].loadFinalChannelKind(assetId)).to.equal('asset');
		expect(stores[0].readAssetSpliceJournal(assetId)).to.deep.equal(journal);
		const txs = closeCooperatively(stores, plainSides, plainId);
		for (const raw of txs)
			expect(Transaction.fromBuffer(raw).ins[0].hash).to.deep.equal(
				child.getHash()
			);
		expect(stores[0].finalSimpleCloseTransactions(plainId)).to.not.be.empty;
		expect(stores[0].loadFinalSimpleClose(assetId)).to.equal(null);
		expect(stores[0].readAssetSpliceJournal(assetId)).to.deep.equal(journal);
	});

	it('never offers an asset channel to the plain ledger, splice or close, nor a plain channel to the asset paths', async () => {
		const s = await setup();
		expect(
			stores[0].loadFinalOpeningSession(assetId)!.updateLimits
		).to.not.equal(undefined);
		const assetRoot = s.f.devices[0].party.root,
			plainRoot = plainSides[0].root;
		expect(stores[0].loadFinalUpdateStatus(assetId)).to.equal(null);
		expect(stores[0].loadFinalResolutionStates(assetId)).to.equal(null);
		expect(stores[0].loadFinalSpliceAttempts(assetId)).to.deep.equal([]);
		expect(stores[0].loadFinalSimpleClose(assetId)).to.equal(null);
		expect(() => stores[0].finalSpliceSession(assetId, assetRoot)).to.throw(
			/plain final channel/
		);
		expect(
			() =>
				stores[0].finalSimpleCloseStep(assetId, assetRoot, {
					start: true,
					script: destination,
					blockHeight: 200,
					feeratePerKw: 1000
				})
			// The existing readiness check may come first; the gate's own text is
			// proven on a funded asset channel in asset-conversion-plain-gates.
		).to.throw(
			/Funding is unavailable for cooperative close|plain final channel/
		);
		expect(() =>
			stores[0].stageFinalHtlcUpdate(
				assetId,
				'local',
				M.UPDATE_ADD_HTLC,
				encodeUpdateAddHtlcMessage({
					channelId: Buffer.from(assetId, 'hex'),
					id: 0n,
					amountMsat: 8000000n,
					paymentHash: Buffer.alloc(32, 9),
					cltvExpiry: 1100,
					onionRoutingPacket: Buffer.alloc(1366)
				})
			)
		).to.throw(/plain final channel/);
		const probe = plainWire(
			stores,
			s.f.devices.map((d) => d.party),
			assetId,
			false
		);
		await probe.drain();
		expect(probe.sockets.map((x) => x.updatesReady(assetId))).to.deep.equal([
			false,
			false
		]);
		probe.destroy();
		const wire = plainWire(stores, plainSides, plainId);
		await wire.drain();
		expect(wire.sockets.map((x) => x.updatesReady(plainId))).to.deep.equal([
			true,
			true
		]);
		wire.destroy();

		expect(() => stores[0].readAssetSpliceJournal(plainId)).to.throw(
			/asset channel/
		);
		expect(() =>
			stores[0].assetSpliceUpdateBatch(plainId, plainRoot, 1n, [], () => 600900)
		).to.throw();
		expect(() => stores[0].loadAssetSpliceFundingInfo(plainId)).to.throw();
		const calls: string[] = [];
		const plainExit = Transaction.fromBuffer(
			stores[0].loadFinalResolutionStates(plainId)!.locals[0].tx
		);
		expect(
			assetOpeningOutputClaims(
				{ storage: stores[0], root: plainRoot },
				Buffer.from(plainId, 'hex'),
				plainExit,
				destination,
				1,
				recordingProvider(calls)
			)
		).to.deep.equal([]);
		expect(calls).to.deep.equal([]);
	});
});

describe('Wallet input reservations of both kinds (#2151 step 1, item 7)', function () {
	this.timeout(90000);
	it('returns the asset reservation and the plain splice input together', () => {
		const dir = fs.mkdtempSync(
			path.join(os.tmpdir(), 'asset-conversion-reserve-')
		);
		const f = setupAssetSpliceProofs(dir, undefined, 6);
		try {
			f.fundOpening();
			const stores = f.devices.map((d) => d.store);
			// Index 2 belongs to the asset splice keys; the plain channel takes 3.
			for (const store of stores) store.allocateFinalChannelKeyIndex(2);
			const sides = f.devices.map((d) =>
				boundParticipant(d.party.root, 3, d.party.binding)
			);
			const plainId = fundReadyPair(stores[0], stores[1], sides[0], sides[1]);
			const c = f.candidates[0];
			const input = c.tx.ins[c.localInputs[0]];
			const assetCoin =
				Buffer.from(input.hash).reverse().toString('hex') + ':' + input.index;
			const parent = f.terms[0].parent.getId() + ':' + f.terms[0].parentIndex;
			stores[0].reserveAssetSpliceWalletInputs(f.id, '3a'.repeat(32), parent, [
				assetCoin
			]);
			const coin = new Transaction();
			coin.addInput(Buffer.alloc(32, 55), 1);
			const script = payments.p2wpkh({
				pubkey: sides[0].keys.channelBasepoints.fundingPubkey
			}).output!;
			coin.addOutput(script, 17000);
			stores[0].finalSpliceSession(plainId, sides[0].root).begin(true, {
				localDelta: '10000',
				feeBudget: '500',
				feerate: 253,
				locktime: 0,
				inputs: [{ prevTxHex: coin.toHex(), vout: 0, sequence: 0xfffffffd }],
				outputs: [{ value: '6500', script: script.toString('hex') }]
			});
			assert.deepEqual(
				stores[0].loadFinalSpliceWalletOutpoints(),
				new Set([assetCoin, coin.getId() + ':0'])
			);
		} finally {
			for (const d of f.devices) d.store.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
