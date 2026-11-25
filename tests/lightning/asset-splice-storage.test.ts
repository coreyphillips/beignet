import { expect } from 'chai';
import { mnemonicToSeedSync } from 'bip39';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	ASSET_OPENING_TYPE_HEX,
	ASSET_SPLICE_RECOVERY_TYPE_HEX
} from '../../src/lightning/features/asset-opening';
import { bip32RootFromSeed } from '../../src/lightning/keys/wallet-keys';
import { createTaprootFundingScript } from '../../src/lightning/script/funding-taproot';
import {
	finalWalletGeneration,
	generateFinalDaemonWallet
} from '../../src/lightning/storage/final-wallet-generation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	bob,
	boundParticipant,
	signingFixture
} from './helpers/final-opening-signing';

const older = [
	{ finalCommitmentUpdates: false, dualFundedAssets: false },
	{ finalCommitmentUpdates: true, dualFundedAssets: false },
	{ finalCommitmentUpdates: false, dualFundedAssets: true }
];

describe('Original-device asset splice storage', () => {
	let dir: string, file: string, copy: string;
	let store: SqliteStorage | undefined;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'asset-splice-storage-'));
		file = path.join(dir, 'wallet.db');
		copy = path.join(dir, 'backup.db');
	});
	afterEach(() => {
		store?.close();
		store = undefined;
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('uses a fresh regtest identity that each earlier opener rejects on the original and its backup', async () => {
		const { binding } = generateFinalDaemonWallet(false, false, true);
		expect(finalWalletGeneration(false, false, true)).to.equal(4);
		expect(binding.assetSplice).to.equal(true);
		store = SqliteStorage.createFinalWallet(file, binding);
		expect(store.canSpliceDualFundedAssets).to.equal(true);
		expect(store.canOpenDualFundedAssets).to.equal(true);
		expect(store.canUpdateFinalCommitments).to.equal(false);
		await store.backup(copy);
		store.close();
		store = undefined;
		for (const db of [file, copy]) {
			for (const old of older)
				expect(() =>
					SqliteStorage.openFinalWallet(db, {
						...binding,
						...old,
						assetSplice: false
					})
				).to.throw(/binding/);
		}
		store = SqliteStorage.openFinalWallet(copy, binding);
		expect(store.canSpliceDualFundedAssets).to.equal(false);
		expect(store.canOpenDualFundedAssets).to.equal(false);
		expect(() => store!.requestFinalOpeningExit('13'.repeat(32))).to.throw(
			/original/
		);
		expect(() => store!.loadFinalOpeningExit('13'.repeat(32))).to.throw(
			/original/
		);
	});

	it('enrolls recovery only on a fresh original and binds its copies to the same generation', async () => {
		const { binding } = generateFinalDaemonWallet(false, false, false, true);
		expect(finalWalletGeneration(false, false, false, true)).to.equal(5);
		expect(() => finalWalletGeneration(false, false, true, true)).to.throw();
		store = SqliteStorage.createFinalWallet(file, binding);
		expect(store.canRecoverAssetSplice).to.equal(true);
		expect(store.canSpliceDualFundedAssets).to.equal(true);
		expect(store.canOpenDualFundedAssets).to.equal(true);
		expect(store.canUpdateFinalCommitments).to.equal(false);
		await store.backup(copy);
		store.close();
		store = undefined;
		for (const where of [file, copy]) {
			expect(() =>
				SqliteStorage.openFinalWallet(where, {
					...binding,
					assetSplice: true,
					assetSpliceRecovery: false
				})
			).to.throw(/binding/);
		}
		store = SqliteStorage.openFinalWallet(copy, binding);
		expect(store.supportsAssetSpliceRecovery).to.equal(true);
		expect(store.canRecoverAssetSplice).to.equal(false);
		expect(store.canSpliceDualFundedAssets).to.equal(false);
		expect(() => store!.loadFinalFundingExits('12'.repeat(32))).to.throw(
			/original/
		);
		expect(() =>
			SqliteStorage.createFinalWallet(file + '.imported', { ...binding })
		).to.throw(/fresh/);
		expect(() =>
			SqliteStorage.createFinalWallet(file + '.mainnet', {
				...binding,
				network: 'mainnet'
			})
		).to.throw(/regtest/);
	});

	it('recognizes only the live original signing authority of this splice wallet outside a transaction', () => {
		const fresh = () => generateFinalDaemonWallet(false, false, true).binding;
		const a = SqliteStorage.createFinalWallet(file, fresh());
		const b = SqliteStorage.createFinalWallet(
			path.join(dir, 'other.db'),
			fresh()
		);
		const openingOnly = SqliteStorage.createFinalWallet(
			path.join(dir, 'old.db'),
			generateFinalDaemonWallet(false, true).binding
		);
		try {
			const authority = a['openingAuthority']!;
			expect(() => a.assertAssetSpliceAuthority(authority)).not.to.throw();
			expect(() => b.assertAssetSpliceAuthority(authority)).to.throw();
			expect(() =>
				openingOnly.assertAssetSpliceAuthority(openingOnly['openingAuthority']!)
			).to.throw();
			expect(() =>
				a['db'].transaction(() => a.assertAssetSpliceAuthority(authority))()
			).to.throw();
		} finally {
			a.close();
			b.close();
			openingOnly.close();
		}
	});
	it('preserves previous enrollments and rejects imported, mixed or non-regtest enrollment', () => {
		for (const old of older) {
			const { binding } = generateFinalDaemonWallet(
				old.finalCommitmentUpdates,
				old.dualFundedAssets
			);
			const loc = path.join(
				dir,
				String(
					finalWalletGeneration(
						old.finalCommitmentUpdates,
						old.dualFundedAssets
					)
				)
			);
			store = SqliteStorage.createFinalWallet(loc, binding);
			expect(store.canSpliceDualFundedAssets).to.equal(false);
			expect(store.canOpenDualFundedAssets).to.equal(old.dualFundedAssets);
			store.close();
			store = undefined;
			const upgraded = {
				...binding,
				assetSplice: true,
				dualFundedAssets: false,
				finalCommitmentUpdates: false
			};
			expect(() => SqliteStorage.openFinalWallet(loc, upgraded)).to.throw(
				/binding/
			);
			expect(() =>
				SqliteStorage.createFinalWallet(loc + '.imported', upgraded)
			).to.throw(/freshly generated/);
			expect(() =>
				SqliteStorage.createFinalWallet(loc + '.mainnet', {
					...upgraded,
					network: 'mainnet'
				})
			).to.throw(/regtest/);
		}
		expect(() => generateFinalDaemonWallet(true, false, true)).to.throw();
		expect(() => generateFinalDaemonWallet(false, true, true)).to.throw();
	});

	const limits = {
		local: {
			channelReserveSats: '1000',
			htlcMinimumMsat: '1',
			maxHtlcValueInFlightMsat: '1000000',
			maxAcceptedHtlcs: 8
		},
		remote: {
			channelReserveSats: '1100',
			htlcMinimumMsat: '2',
			maxHtlcValueInFlightMsat: '1000100',
			maxAcceptedHtlcs: 6
		}
	};
	function opened(recovery = false, type = ASSET_OPENING_TYPE_HEX) {
		const { binding, mnemonic } = generateFinalDaemonWallet(
			false,
			false,
			!recovery,
			recovery
		);
		store = SqliteStorage.createFinalWallet(file, binding);
		const alice = boundParticipant(
			bip32RootFromSeed(mnemonicToSeedSync(mnemonic)),
			1,
			binding
		);
		const { candidate, terms, id, funding } = signingFixture(false, alice, bob);
		const root = Buffer.alloc(32, 42);
		candidate.channelType = type;
		funding.outs[candidate.fundingOutputIndex].script =
			createTaprootFundingScript(
				alice.keys.channelBasepoints.fundingPubkey,
				bob.keys.channelBasepoints.fundingPubkey,
				undefined,
				root
			).p2trOutput;
		candidate.fundingTxHex = funding.toHex();
		store.allocateFinalChannelKeyIndex(1);
		const side = (proofs: string) => ({
			toLocal: { script: '6a01aa' },
			toRemote: { script: '6a01bb' },
			proofs
		});
		store.rememberAssetOpeningSession(
			candidate,
			bob.binding.nodeId,
			terms,
			1,
			bob.keys.channelBasepoints.paymentBasepoint.toString('hex'),
			{
				fundingRoot: root.toString('hex'),
				layoutDigest: 'ab'.repeat(32),
				finalDigest: 'cd'.repeat(32),
				fundingProofs: '01',
				local: side('02'),
				remote: side('03')
			},
			limits
		);
		return { binding, id };
	}

	for (const recovery of [true, false]) {
		it(
			'requires the enrolled channel type when recovery is ' + recovery,
			() => {
				const otherType = recovery
					? ASSET_OPENING_TYPE_HEX
					: ASSET_SPLICE_RECOVERY_TYPE_HEX;
				expect(() => opened(recovery, otherType)).to.throw(/channel type/);
			}
		);
	}

	it('retains the actual opening HTLC and reserve terms for splice admission after restart', () => {
		const { binding, id } = opened();
		store!.close();
		store = SqliteStorage.openFinalWallet(file, binding);
		expect(store.loadFinalOpeningSession(id)?.updateLimits).to.deep.equal(
			limits
		);
	});

	it('repairs the lost SQLite tail from the original device and includes exact evidence bytes in a fresh backup', async () => {
		const { binding, id } = opened();
		const a = store!;
		const first = {
			attempt: 'a1'.repeat(32),
			proof: '6347'.repeat(128),
			parentExit: '11'.repeat(128),
			candidateExit: '22'.repeat(128)
		};
		const second = { attempt: first.attempt, released: 'c991'.repeat(128) };
		const start = a.readAssetSpliceJournal(id);
		expect(start.records).to.deep.equal([]);
		const secured = a.appendAssetSpliceEvent(id, start, first);
		expect(() => a.appendAssetSpliceEvent(id, start, second)).to.throw(/head/);
		const released = a.appendAssetSpliceEvent(id, secured, second);
		expect(a.readAssetSpliceJournal(id)).to.deep.equal({
			...released,
			records: [first, second]
		});
		const query = (s: SqliteStorage) =>
			s['db']
				.prepare(
					"SELECT record FROM final_lifecycle_log WHERE scope='asset-splice' AND channel_id=? ORDER BY sequence"
				)
				.all(id);
		const before = query(a);
		expect(before).to.have.length(2);
		expect(JSON.stringify(before)).not.to.contain(first.proof);
		a['db']
			.prepare(
				"DELETE FROM final_lifecycle_log WHERE scope='asset-splice' AND channel_id=? AND sequence=2"
			)
			.run(id);
		await a.backup(copy);
		expect(query(a)).to.deep.equal(before);
		a.close();
		store = SqliteStorage.openFinalWallet(copy, binding);
		const history = store.readAssetSpliceJournal(id);
		expect(history).to.deep.equal({ ...released, records: [first, second] });
		expect(() => store!.appendAssetSpliceEvent(id, history, second)).to.throw(
			/original/
		);
		store.close();
		store = SqliteStorage.openFinalWallet(file, binding);
		expect(store.readAssetSpliceJournal(id)).to.deep.equal(history);
	});

	it('refuses a conflicting stored history, an unknown channel and an outer transaction that could roll back after release', () => {
		const { id } = opened();
		const a = store!;
		const head = a.readAssetSpliceJournal(id);
		expect(() => a.appendAssetSpliceEvent(id, head, undefined)).to.throw();
		expect(() =>
			a.appendAssetSpliceEvent(id, head, { proof: Buffer.of(1) })
		).to.throw();
		expect(() =>
			a.appendAssetSpliceEvent(id, head, { proof: undefined })
		).to.throw();
		expect(() =>
			a.appendAssetSpliceEvent(id, head, { proofs: BigInt(1) })
		).to.throw();
		expect(() =>
			a.appendAssetSpliceEvent('88'.repeat(32), head, { proof: 'ab' })
		).to.throw();
		expect(() =>
			a['db'].transaction(() =>
				a.appendAssetSpliceEvent(id, head, { proof: 'ab' })
			)()
		).to.throw(/transaction/);
		expect(a.readAssetSpliceJournal(id)).to.deep.equal(head);
		a.appendAssetSpliceEvent(id, head, { proof: 'ab' });
		a['db']
			.prepare(
				"UPDATE final_lifecycle_log SET record='damaged' WHERE scope='asset-splice' AND channel_id=?"
			)
			.run(id);
		expect(() => a.readAssetSpliceJournal(id)).to.throw();
		expect(() =>
			a.appendAssetSpliceEvent(id, head, { proof: 'ab' })
		).to.throw();
	});
});
