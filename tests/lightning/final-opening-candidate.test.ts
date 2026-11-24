import { expect } from 'chai';
import Database from 'better-sqlite3';
import { Transaction } from 'bitcoinjs-lib';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	createOpenerState,
	type IChannelState
} from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { basepointsOf, seedFor } from './helpers/taproot-revoked-fixture';

import {
	opening,
	wallet,
	inputTransaction,
	channelType,
	type Candidate
} from './helpers/final-opening';

function changeFunding(
	candidate: Candidate,
	change: (tx: Transaction) => void
): Candidate {
	const tx = Transaction.fromHex(candidate.fundingTxHex);
	change(tx);
	return { ...candidate, fundingTxHex: tx.toHex() };
}

function ordinaryChannel(
	channelId: string,
	fundingTxid: Buffer
): IChannelState {
	const state = createOpenerState({
		temporaryChannelId: seedFor(188),
		fundingSatoshis: 140_000n,
		pushMsat: 0n,
		localConfig: DEFAULT_CHANNEL_CONFIG,
		localBasepoints: basepointsOf(seedFor(189)),
		localPerCommitmentSeed: seedFor(190)
	});
	state.channelId = Buffer.from(channelId, 'hex');
	state.fundingTxid = fundingTxid;
	state.fundingOutputIndex = 0;
	return state;
}

describe('Final opening funding candidate', () => {
	let directory: string;
	let file: string;
	let store: SqliteStorage;

	beforeEach(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-opening-'));
		file = path.join(directory, 'regtest.db');
		store = SqliteStorage.createFinalWallet(file, wallet);
	});

	afterEach(() => {
		store?.close();
		fs.rmSync(directory, { recursive: true, force: true });
	});

	it('recovers both funding roles, ownership, and the exact transactions after restart and backup', async () => {
		const initiator = opening();
		const acceptor = opening(true);
		const copy = path.join(directory, 'backup.db');
		for (const candidate of [initiator, acceptor]) {
			expect(store.loadFinalOpening(candidate.channelId)).to.equal(null);
			store.rememberFinalOpening(candidate);
			store.rememberFinalOpening(candidate);
		}
		await store.backup(copy);
		store.close();
		store = SqliteStorage.openFinalWallet(file, wallet);
		const backup = SqliteStorage.openFinalWallet(copy, wallet);
		try {
			for (const candidate of [initiator, acceptor]) {
				for (const opened of [store, backup]) {
					expect(opened.loadFinalOpening(candidate.channelId)).to.deep.equal(
						candidate
					);
					opened.rememberFinalOpening(candidate);
				}
				expect(fs.readFileSync(copy).includes(candidate.fundingTxHex)).to.equal(
					false
				);
				expect(
					fs.readFileSync(copy).includes(candidate.inputs[0].prevTxHex)
				).to.equal(false);
			}
		} finally {
			backup.close();
		}
	});

	it('discovers all remembered openings after restart without saved channel IDs', () => {
		expect(store.loadFinalOpenings()).to.deep.equal([]);
		const candidates = [opening(true), opening()];
		for (const candidate of candidates) store.rememberFinalOpening(candidate);
		store.close();
		store = SqliteStorage.openFinalWallet(file, wallet);
		expect(store.loadFinalOpenings()).to.have.deep.members(candidates);
	});

	it('binds the first reservation to every negotiated field and the full funding outpoint', () => {
		const candidate = opening();
		store.rememberFinalOpening(candidate);
		const changes: Candidate[] = [
			{ ...candidate, minimumDepth: candidate.minimumDepth + 1 },
			{ ...candidate, fundingFeeratePerKw: candidate.fundingFeeratePerKw + 1 },
			{ ...candidate, isInitiator: !candidate.isInitiator },
			{ ...candidate, channelType: channelType(80, 46) },
			{ ...candidate, outputSerialIds: ['4'] },
			{
				...candidate,
				inputs: [candidate.inputs[0], { ...candidate.inputs[1], serialId: '3' }]
			},
			{
				...candidate,
				localContributionSats: 89_999,
				remoteContributionSats: 50_001
			},
			{
				...candidate,
				localFundingPubkey: candidate.remoteFundingPubkey,
				remoteFundingPubkey: candidate.localFundingPubkey
			},
			changeFunding(candidate, (tx) => {
				tx.locktime++;
			}),
			{ ...candidate, channelId: seedFor(179).toString('hex') }
		];
		for (const change of changes) {
			expect(() => store.rememberFinalOpening(change)).to.throw();
			expect(store.loadFinalOpening(candidate.channelId)).to.deep.equal(
				candidate
			);
		}
		expect(
			store.loadFinalOpening(changes[changes.length - 1].channelId)
		).to.equal(null);
	});

	it('validates funding type, value, exact prevouts, input ownership, and unsigned transaction bytes before writing', () => {
		const candidate = opening();
		const duplicateInputs = changeFunding(candidate, (tx) => {
			tx.ins[1].hash = Buffer.from(tx.ins[0].hash);
		});
		duplicateInputs.inputs = [
			candidate.inputs[0],
			{ ...candidate.inputs[1], prevTxHex: candidate.inputs[0].prevTxHex }
		];
		const ambiguous = changeFunding(candidate, (tx) => {
			tx.outs[0].value = 70_000;
			tx.addOutput(tx.outs[0].script, 70_000);
		});
		const invalid: Candidate[] = [
			{ ...candidate, channelType: '00' + candidate.channelType },
			{ ...candidate, channelType: channelType(81) },
			{ ...candidate, minimumDepth: 0 },
			{ ...candidate, fundingFeeratePerKw: 0 },
			{ ...candidate, fundingOutputIndex: 1 },
			{ ...candidate, outputSerialIds: [] },
			{ ...candidate, outputSerialIds: ['02'] },
			{ ...candidate, outputSerialIds: ['0'] },
			{ ...candidate, outputSerialIds: ['3'] },
			{ ...candidate, outputSerialIds: ['18446744073709551616'] },
			{
				...candidate,
				inputs: [
					candidate.inputs[0],
					{ ...candidate.inputs[1], serialId: '18446744073709551616' }
				]
			},
			{
				...candidate,
				inputs: [
					candidate.inputs[0],
					{ ...candidate.inputs[1], serialId: '07' }
				]
			},
			{
				...candidate,
				inputs: [candidate.inputs[0], { ...candidate.inputs[1], serialId: '6' }]
			},
			{
				...candidate,
				inputs: [
					{ ...candidate.inputs[0], serialId: '6' },
					{ ...candidate.inputs[1], serialId: '5' }
				]
			},
			{
				...candidate,
				localContributionSats: -1,
				remoteContributionSats: 140_001
			},
			{
				...candidate,
				localContributionSats: 90_500,
				remoteContributionSats: 49_500
			},
			{
				...candidate,
				localContributionSats: 89_500,
				remoteContributionSats: 50_500
			},
			{ ...candidate, remoteContributionSats: 50_001 },
			{ ...candidate, inputs: candidate.inputs.slice(1) },
			{ ...candidate, inputs: [...candidate.inputs].reverse() },
			{
				...candidate,
				inputs: candidate.inputs.map((input) => ({ ...input, isLocal: true }))
			},
			{ ...candidate, localFundingPubkey: candidate.remoteFundingPubkey },
			{ ...candidate, fundingTxHex: candidate.fundingTxHex + '00' },
			changeFunding(candidate, (tx) => {
				tx.ins[0].index = 1;
			}),
			changeFunding(candidate, (tx) => {
				tx.ins[0].script = Buffer.from([0]);
			}),
			changeFunding(candidate, (tx) => tx.setWitness(0, [Buffer.from([1])])),
			changeFunding(candidate, (tx) => {
				tx.outs[0].script = Buffer.alloc(34);
			}),
			duplicateInputs,
			{
				...ambiguous,
				localContributionSats: 40_000,
				remoteContributionSats: 30_000,
				outputSerialIds: ['2', '4']
			}
		];
		for (const bad of invalid) {
			expect(() => store.rememberFinalOpening(bad)).to.throw();
			expect(store.loadFinalOpening(candidate.channelId)).to.equal(null);
		}
		store.rememberFinalOpening(candidate);
	});

	it('accounts for change by output serial before either side can reserve its contribution', () => {
		const candidate = opening();
		const coins = [
			inputTransaction(183, 99_000),
			inputTransaction(184, 56_000)
		];
		const withChange = changeFunding(candidate, (tx) => {
			for (const [index, coin] of coins.entries())
				tx.ins[index].hash = coin.getHash();
			tx.addOutput(coins[0].outs[0].script, 8_000);
			tx.addOutput(coins[1].outs[0].script, 5_000);
		});
		withChange.inputs = candidate.inputs.map((input, index) => ({
			...input,
			prevTxHex: coins[index].toHex()
		}));
		withChange.outputSerialIds = ['2', '4', '5'];
		for (const outputSerialIds of [
			['2', '3', '4'],
			['2', '5', '4'],
			['2', '4', '4']
		]) {
			expect(() =>
				store.rememberFinalOpening({ ...withChange, outputSerialIds })
			).to.throw();
		}
		expect(store.loadFinalOpening(candidate.channelId)).to.equal(null);
		store.rememberFinalOpening(withChange);
		expect(store.loadFinalOpening(candidate.channelId)).to.deep.equal(
			withChange
		);
	});

	it('refuses a reservation inside a caller transaction before claiming durability', () => {
		const candidate = opening();
		expect(() =>
			store.transaction(() => store.rememberFinalOpening(candidate))
		).to.throw();
		expect(store.loadFinalOpening(candidate.channelId)).to.equal(null);
		store.rememberFinalOpening(candidate);
		expect(store.loadFinalOpening(candidate.channelId)).to.deep.equal(
			candidate
		);
	});

	it('requires one actual prevout record for every funding input', () => {
		const candidate = opening(true);
		const other = inputTransaction(185, 1_000);
		const withAnotherInput = changeFunding(candidate, (tx) => {
			tx.addInput(other.getHash(), 0, 0xfffffffd);
		});
		withAnotherInput.inputs.length++;
		expect(() => store.rememberFinalOpening(withAnotherInput)).to.throw();
		expect(store.loadFinalOpening(candidate.channelId)).to.equal(null);
	});

	for (const first of ['ordinary', 'final']) {
		for (const same of ['channel id', 'outpoint']) {
			it(
				'keeps the ' +
					same +
					' of the ' +
					first +
					' reservation exclusive across channel profiles',
				() => {
					const candidate = opening();
					const ordinaryId =
						same === 'channel id'
							? candidate.channelId
							: seedFor(187).toString('hex');
					const ordinary = ordinaryChannel(
						ordinaryId,
						same === 'outpoint'
							? Transaction.fromHex(candidate.fundingTxHex).getHash()
							: seedFor(191)
					);
					const saveOrdinary = (): void =>
						store.saveChannel(
							ordinaryId,
							ordinary,
							candidate.remoteFundingPubkey
						);
					const saveFinal = (): void => store.rememberFinalOpening(candidate);
					if (first === 'ordinary') {
						saveOrdinary();
						expect(saveFinal).to.throw();
					} else {
						saveFinal();
						expect(saveOrdinary).to.throw();
					}
					expect(store.loadChannel(ordinaryId) !== null).to.equal(
						first === 'ordinary'
					);
					expect(store.loadFinalOpening(candidate.channelId) !== null).to.equal(
						first === 'final'
					);
				}
			);
		}
	}

	it('checks all persisted ordinary channels against final candidates before reopening', async () => {
		const candidate = opening();
		const ordinaryId = seedFor(193).toString('hex');
		const state = ordinaryChannel(
			ordinaryId,
			Transaction.fromHex(candidate.fundingTxHex).getHash()
		);
		const source = path.join(directory, 'ordinary.db');
		const copy = path.join(directory, 'copy.db');
		store.saveChannel(ordinaryId, state, candidate.remoteFundingPubkey);
		await store.backup(source);
		store.deleteChannel(ordinaryId);
		store.rememberFinalOpening(candidate);
		await store.backup(copy);
		const db = new Database(copy);
		try {
			db.prepare('ATTACH DATABASE ? AS ordinary').run(source);
			db.exec('INSERT INTO main.channels SELECT * FROM ordinary.channels');
		} finally {
			db.close();
		}
		expect(() =>
			SqliteStorage.openFinalWallet(copy, wallet).close()
		).to.throw();
	});

	it('keeps a superseded funding outpoint exclusive until its spend watch retires', () => {
		const candidate = opening();
		const funding = Transaction.fromHex(candidate.fundingTxHex);
		const id = seedFor(194).toString('hex');
		const ordinary = ordinaryChannel(id, seedFor(195));
		ordinary.preSpliceSpendWatches = [
			{
				txid: funding.getId(),
				outputIndex: candidate.fundingOutputIndex,
				script:
					funding.outs[candidate.fundingOutputIndex].script.toString('hex'),
				spliceTxid: seedFor(196).toString('hex')
			}
		];
		store.saveChannel(id, ordinary, candidate.remoteFundingPubkey);
		expect(() => store.rememberFinalOpening(candidate)).to.throw();
		expect(store.loadFinalOpening(candidate.channelId)).to.equal(null);
	});

	it('only acknowledges a candidate that SQLite actually stored', () => {
		const db = (store as unknown as { db: Database.Database }).db;
		db.exec(
			'CREATE TRIGGER interrupt_insert BEFORE INSERT ON final_opening_candidates BEGIN SELECT RAISE(IGNORE); END'
		);
		const candidate = opening();
		expect(() => store.rememberFinalOpening(candidate)).to.throw();
		expect(store.loadFinalOpening(candidate.channelId)).to.equal(null);
	});

	it('refuses candidate storage on the legacy wallet format', () => {
		const legacy = new SqliteStorage(
			path.join(directory, 'legacy.db'),
			undefined,
			{ encryptionKey: wallet.encryptionKey }
		);
		try {
			legacy.open();
			const candidate = opening();
			expect(() => legacy.rememberFinalOpening(candidate)).to.throw();
			expect(() => legacy.loadFinalOpenings()).to.throw();
		} finally {
			legacy.close();
		}
	});
});
