/**
 * Revoked-commitment HTLC snapshots live in their own table (issue #1670).
 *
 * Every remote commitment a channel signs adds a snapshot, and nothing ever
 * removes one, so a channel row that carried them re-encoded the channel's
 * whole history on every save, and a journaled save encoded it twice. These
 * tests drive a real channel through many commitments and check that each
 * save writes only what it adds, while the penalty path still finds every
 * snapshot after a restart or a journal restore.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import Database from 'better-sqlite3';
import sinon from 'sinon';
import { Channel } from '../../src/lightning/channel/channel';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import {
	HtlcDirection,
	IHtlcSnapshotEntry
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeUpdateAddHtlcMessage,
	decodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';
import {
	decodeCommitmentSignedMessage,
	decodeRevokeAndAckMessage
} from '../../src/lightning/message/channel-commitment';
import { buildRemoteCommitment } from '../../src/lightning/channel/commitment-builder';
import {
	IResolvedOutput,
	resolveRevokedCommitmentOutputs
} from '../../src/lightning/chain/output-resolver';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { nodeStorageView } from '../../src/cli/node-storage-view';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { encryptValue } from '../../src/lightning/storage/encryption';
import { withStorageTransaction } from '../../src/lightning/storage/transaction';
import { serializeChannelState } from '../../src/lightning/storage/serialization';
import {
	RecoveryCriticality,
	RecoveryJournal,
	RecoveryManager,
	reconstructFromFrames
} from '../../src/lightning/recovery';
import {
	exchangeCommitments,
	findSendAction,
	setupNormalChannels
} from './helpers/revoked-commitment-fixture';
import { realCommitmentSigs } from './helpers/real-signing';

const NETWORK = bitcoin.networks.regtest;
const PEER = getPublicKey(Buffer.alloc(32, 7)).toString('hex');
const DEST = Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 9)]);

function snapshotRows(storage: SqliteStorage, channelId: string): number {
	const db = (storage as unknown as { db: Database.Database }).db;
	return (
		db
			.prepare(
				'SELECT COUNT(*) AS n FROM revoked_htlc_snapshots WHERE channel_id = ?'
			)
			.get(channelId) as { n: number }
	).n;
}

/** Counts snapshot rows written from now on, replaced ones included. */
function countSnapshotWrites(storage: SqliteStorage): () => number {
	const db = (storage as unknown as { db: Database.Database }).db;
	db.exec(`
		CREATE TEMP TABLE snapshot_writes (n INTEGER);
		CREATE TEMP TRIGGER count_snapshot_writes
			AFTER INSERT ON main.revoked_htlc_snapshots
			BEGIN INSERT INTO snapshot_writes VALUES (1); END;
	`);
	return () =>
		(
			db.prepare('SELECT COUNT(*) AS n FROM snapshot_writes').get() as {
				n: number;
			}
		).n;
}

function rowBytes(storage: SqliteStorage, channelId: string): number {
	const db = (storage as unknown as { db: Database.Database }).db;
	return (
		db
			.prepare('SELECT state_json FROM channels WHERE channel_id = ?')
			.get(channelId) as { state_json: string }
	).state_json.length;
}

function save(
	manager: RecoveryManager,
	channelId: string,
	state: IChannelState,
	extra: Parameters<RecoveryManager['commit']>[0]['mutations'] = []
): boolean {
	return manager.commit({
		criticality: RecoveryCriticality.SafetyCritical,
		mutations: [
			{ type: 'channel_state', channelId, state, peerPubkey: PEER },
			...extra
		],
		outboundMessages: []
	}).committed;
}

/** Offer one HTLC from the opener and have the acceptor record it. */
function offerHtlc(
	opener: Channel,
	acceptor: Channel,
	paymentHash: Buffer
): void {
	const add = findSendAction(
		opener.addHtlc(10_000_000n, paymentHash, 500, Buffer.alloc(1366)),
		MessageType.UPDATE_ADD_HTLC
	);
	acceptor.handleUpdateAddHtlc(decodeUpdateAddHtlcMessage(add.payload));
}

/**
 * The opener signs one commitment and the acceptor revokes the previous one.
 * Half the cost of exchangeCommitments, once both sides hold the HTLC.
 */
function signOnce(opener: Channel, acceptor: Channel): void {
	const sigs = realCommitmentSigs(opener);
	const signed = findSendAction(
		opener.signCommitment(sigs.signature, sigs.htlcSignatures),
		MessageType.COMMITMENT_SIGNED
	);
	const revoke = findSendAction(
		acceptor.handleCommitmentSigned(
			decodeCommitmentSignedMessage(signed.payload)
		),
		MessageType.REVOKE_AND_ACK
	);
	opener.handleRevokeAndAck(decodeRevokeAndAckMessage(revoke.payload));
}

/** The acceptor settles the HTLC; rounds run until the opener forgets it. */
function settleHtlc(
	opener: Channel,
	acceptor: Channel,
	preimage: Buffer
): void {
	const fulfill = findSendAction(
		acceptor.fulfillHtlc(0n, preimage),
		MessageType.UPDATE_FULFILL_HTLC
	);
	opener.handleUpdateFulfillHtlc(
		decodeUpdateFulfillHtlcMessage(fulfill.payload)
	);
	for (let i = 0; i < 4 && opener.getFullState().htlcs.size > 0; i++) {
		exchangeCommitments(opener, acceptor);
	}
	expect(opener.getFullState().htlcs.size).to.equal(0);
}

/** What the penalty would broadcast against `revokedTx`, as comparable bytes. */
function sweepSet(
	state: IChannelState,
	commitmentNumber: bigint,
	revokedTx: bitcoin.Transaction,
	privkeys: Buffer[]
): string[] {
	const resolved: IResolvedOutput[] = resolveRevokedCommitmentOutputs(
		state,
		[],
		commitmentNumber,
		revokedTx,
		DEST,
		10,
		privkeys[1],
		privkeys[2],
		NETWORK
	);
	return resolved
		.map((r) => `${r.trackedOutput.outputIndex}:${r.spendTx?.toHex()}`)
		.sort();
}

describe('Revoked HTLC snapshot store', function () {
	this.timeout(240000);

	let dir: string;
	beforeEach(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'htlc-history-'));
	});
	afterEach(() => {
		sinon.restore();
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('does not record a commitment that carries no HTLCs', () => {
		const { opener, acceptor } = setupNormalChannels();
		for (let i = 0; i < 3; i++) exchangeCommitments(opener, acceptor);
		expect(opener.getFullState().revokedHtlcSnapshots).to.equal(undefined);
	});

	it('keeps the channel row flat over 1,000 signed commitments, and restart restores the same sweep set', () => {
		const file = path.join(dir, 'node.sqlite');
		let storage = new SqliteStorage(file);
		storage.open({ synchronous: 'NORMAL' });
		const journal = new RecoveryJournal(
			storage,
			Buffer.alloc(32, 1),
			Buffer.from(PEER, 'hex'),
			Buffer.alloc(32, 2),
			// Interval snapshots land mid-run, so a restore starts from one
			// carrying the history so far and replays deltas after it.
			{ snapshotIntervalFrames: 400, snapshotIntervalBytes: 1e12 }
		);
		const manager = new RecoveryManager(storage, { journal });

		const { opener, acceptor, openerPrivkeys } = setupNormalChannels();
		const channelId = opener.getChannelId()!.toString('hex');
		const preimage = crypto.randomBytes(32);
		offerHtlc(
			opener,
			acceptor,
			crypto.createHash('sha256').update(preimage).digest()
		);
		expect(save(manager, channelId, opener.getFullState())).to.be.true;

		const COMMITMENTS = 1000;
		const BREACHED = 500;
		let revoked: { tx: bitcoin.Transaction; number: bigint } | undefined;
		let earlyRow = 0;
		for (let i = 1; i <= COMMITMENTS; i++) {
			if (i === BREACHED) {
				// The commitment the acceptor is about to receive, which it can
				// later broadcast once it is revoked.
				const state = opener.getFullState();
				const number = state.remoteCommitmentNumber + 1n;
				const point =
					state.remoteNextPerCommitmentPoint ??
					state.remoteCurrentPerCommitmentPoint!;
				revoked = {
					tx: buildRemoteCommitment(state, point, number).result.tx,
					number
				};
			}
			if (i === 1) exchangeCommitments(opener, acceptor);
			else signOnce(opener, acceptor);
			expect(save(manager, channelId, opener.getFullState())).to.be.true;
			if (i === 100) earlyRow = rowBytes(storage, channelId);
		}

		const live = opener.getFullState();
		expect(live.revokedHtlcSnapshots!.size).to.equal(COMMITMENTS);
		expect(snapshotRows(storage, channelId)).to.equal(COMMITMENTS);
		// Counters gain digits and the shachain store changes shape, but nothing
		// in the row grows with the history any more. Inline, the snapshots
		// alone would add over 100 KB here.
		const lateRow = rowBytes(storage, channelId);
		const inline = JSON.stringify(serializeChannelState(live)).length;
		expect(lateRow - earlyRow).to.be.lessThan(2000);
		expect(inline - lateRow).to.be.greaterThan(100_000);

		// A journaled save carries the one snapshot it adds, not the history;
		// a snapshot frame carries all of it.
		const frames = journal.loadVerifiedFrames();
		const base = frames[0].snapshot!.channels.find(
			(c) => c.channelId === channelId
		)!;
		expect(base.state.revokedHtlcSnapshots!.size).to.be.greaterThan(400);
		const last = frames[frames.length - 1].mutations.find(
			(m) => m.type === 'channel_state'
		);
		expect(last?.type).to.equal('channel_state');
		// Older readers accept versions 1 and 2 and would replace the history.
		expect(frames[frames.length - 1].version).to.equal(3);
		if (last?.type !== 'channel_state') return;
		expect([...last.state.revokedHtlcSnapshots!.keys()]).to.deep.equal([
			[...live.revokedHtlcSnapshots!.keys()].pop()
		]);

		// The HTLC settles and leaves the live state: only its snapshot can
		// rebuild its output on the old commitment now.
		settleHtlc(opener, acceptor, preimage);
		expect(save(manager, channelId, opener.getFullState())).to.be.true;
		const before = sweepSet(live, revoked!.number, revoked!.tx, openerPrivkeys);
		expect(before).to.have.length(1);
		expect(revoked!.tx.outs[Number(before[0].split(':')[0])].value).to.equal(
			10_000
		);

		storage.close();
		storage = new SqliteStorage(file);
		storage.open({ synchronous: 'NORMAL' });
		try {
			const restarted = storage.loadChannel(channelId)!.state;
			expect(restarted.revokedHtlcSnapshots).to.deep.equal(
				live.revokedHtlcSnapshots
			);
			expect(
				sweepSet(restarted, revoked!.number, revoked!.tx, openerPrivkeys)
			).to.deep.equal(before);

			const target = new SqliteStorage(':memory:');
			target.open();
			try {
				reconstructFromFrames(
					target,
					new RecoveryJournal(
						storage,
						Buffer.alloc(32, 1),
						Buffer.from(PEER, 'hex'),
						Buffer.alloc(32, 2)
					).loadVerifiedFrames()
				);
				const restored = target.loadChannel(channelId)!.state;
				expect(snapshotRows(target, channelId)).to.equal(
					snapshotRows(storage, channelId)
				);
				expect(
					sweepSet(restored, revoked!.number, revoked!.tx, openerPrivkeys)
				).to.deep.equal(before);
			} finally {
				target.close();
			}
		} finally {
			storage.close();
		}
	});

	for (const journaled of [false, true]) {
		it(`writes one snapshot per save through the CLI's node storage view${
			journaled ? ', and its frame carries only that one' : ''
		}`, () => {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			// The daemon's recovery manager and journal hold the view, while
			// saveChannel runs on the instance underneath it.
			const view = nodeStorageView(storage);
			const journal = journaled
				? new RecoveryJournal(
						view,
						Buffer.alloc(32, 1),
						Buffer.from(PEER, 'hex'),
						Buffer.alloc(32, 2)
				  )
				: undefined;
			const manager = new RecoveryManager(view, { journal });
			try {
				const writes = countSnapshotWrites(storage);
				const { opener, acceptor } = setupNormalChannels();
				const channelId = opener.getChannelId()!.toString('hex');
				offerHtlc(opener, acceptor, crypto.randomBytes(32));
				expect(save(manager, channelId, opener.getFullState())).to.be.true;
				const COMMITMENTS = 20;
				for (let i = 1; i <= COMMITMENTS; i++) {
					if (i === 1) exchangeCommitments(opener, acceptor);
					else signOnce(opener, acceptor);
					const before = writes();
					expect(save(manager, channelId, opener.getFullState())).to.be.true;
					expect(writes() - before).to.equal(1);
				}
				expect(snapshotRows(storage, channelId)).to.equal(COMMITMENTS);
				if (!journal) return;

				const frames = journal.loadVerifiedFrames();
				const last = frames[frames.length - 1].mutations.find(
					(m) => m.type === 'channel_state'
				);
				expect(last?.type).to.equal('channel_state');
				if (last?.type !== 'channel_state') return;
				expect([...last.state.revokedHtlcSnapshots!.keys()]).to.deep.equal([
					[...opener.getFullState().revokedHtlcSnapshots!.keys()].pop()
				]);
			} finally {
				storage.close();
			}
		});
	}

	it('writes a snapshot again after the commit that carried it rolls back', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const manager = new RecoveryManager(storage);
		try {
			const { opener, acceptor } = setupNormalChannels();
			const channelId = opener.getChannelId()!.toString('hex');
			offerHtlc(opener, acceptor, crypto.randomBytes(32));
			expect(save(manager, channelId, opener.getFullState())).to.be.true;
			exchangeCommitments(opener, acceptor);
			expect(save(manager, channelId, opener.getFullState())).to.be.true;
			expect(snapshotRows(storage, channelId)).to.equal(1);

			exchangeCommitments(opener, acceptor);
			sinon.stub(storage, 'saveChannelKeyIndex').throws(new Error('disk full'));
			expect(
				save(manager, channelId, opener.getFullState(), [
					{ type: 'channel_key_index', channelId, channelIndex: 1 }
				])
			).to.be.false;
			expect(snapshotRows(storage, channelId)).to.equal(1);

			sinon.restore();
			expect(save(manager, channelId, opener.getFullState())).to.be.true;
			expect(snapshotRows(storage, channelId)).to.equal(2);
			expect(
				storage.loadChannel(channelId)!.state.revokedHtlcSnapshots
			).to.deep.equal(opener.getFullState().revokedHtlcSnapshots);
		} finally {
			storage.close();
		}
	});

	it('writes a snapshot again after an outer storage transaction rolls back', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const manager = new RecoveryManager(storage);
		try {
			const { opener, acceptor } = setupNormalChannels();
			const channelId = opener.getChannelId()!.toString('hex');
			offerHtlc(opener, acceptor, crypto.randomBytes(32));
			exchangeCommitments(opener, acceptor);
			expect(() =>
				storage.transaction(() => {
					expect(save(manager, channelId, opener.getFullState())).to.be.true;
					throw new Error('outer rollback');
				})
			).to.throw('outer rollback');
			expect(snapshotRows(storage, channelId)).to.equal(0);

			expect(save(manager, channelId, opener.getFullState())).to.be.true;
			expect(snapshotRows(storage, channelId)).to.equal(1);
		} finally {
			storage.close();
		}
	});

	for (const wrapper of ['storage.transaction', 'withStorageTransaction']) {
		for (const loader of ['loadChannel', 'loadAllChannels']) {
			it(`writes snapshots ${loader} read inside a rolled-back ${wrapper}`, () => {
				const storage = new SqliteStorage(':memory:');
				storage.open();
				const manager = new RecoveryManager(storage);
				try {
					const { opener, acceptor } = setupNormalChannels();
					const channelId = opener.getChannelId()!.toString('hex');
					offerHtlc(opener, acceptor, crypto.randomBytes(32));
					exchangeCommitments(opener, acceptor);
					let loaded: IChannelState | undefined;
					const inner = (): never => {
						expect(save(manager, channelId, opener.getFullState())).to.be.true;
						loaded =
							loader === 'loadChannel'
								? storage.loadChannel(channelId)!.state
								: storage.loadAllChannels()[0].state;
						throw new Error('outer rollback');
					};
					expect(() =>
						wrapper === 'storage.transaction'
							? storage.transaction(inner)
							: withStorageTransaction(storage, inner)
					).to.throw('outer rollback');
					expect(snapshotRows(storage, channelId)).to.equal(0);

					expect(save(manager, channelId, loaded!)).to.be.true;
					expect(snapshotRows(storage, channelId)).to.equal(1);
				} finally {
					storage.close();
				}
			});
		}
	}

	it('writes the whole history into a store the state was not saved to', () => {
		const stores: SqliteStorage[] = [];
		const open = (): { storage: SqliteStorage; journal: RecoveryJournal } => {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			stores.push(storage);
			const journal = new RecoveryJournal(
				storage,
				Buffer.alloc(32, 1),
				Buffer.from(PEER, 'hex'),
				Buffer.alloc(32, 2)
			);
			return { storage, journal };
		};
		try {
			const source = open();
			const manager = new RecoveryManager(source.storage, {
				journal: source.journal
			});
			const { opener, acceptor } = setupNormalChannels();
			const channelId = opener.getChannelId()!.toString('hex');
			offerHtlc(opener, acceptor, crypto.randomBytes(32));
			expect(save(manager, channelId, opener.getFullState())).to.be.true;
			for (let i = 0; i < 3; i++) {
				exchangeCommitments(opener, acceptor);
				expect(save(manager, channelId, opener.getFullState())).to.be.true;
			}
			const history = opener.getFullState().revokedHtlcSnapshots;
			expect(history!.size).to.equal(3);
			const holdsHistory = (storage: SqliteStorage): void => {
				expect(
					storage.loadChannel(channelId)!.state.revokedHtlcSnapshots
				).to.deep.equal(history);
			};

			const copy = open().storage;
			copy.saveChannel(
				channelId,
				source.storage.loadChannel(channelId)!.state,
				PEER
			);
			holdsHistory(copy);

			const frames = source.journal.loadVerifiedFrames();
			for (let i = 0; i < 2; i++) {
				const target = open().storage;
				reconstructFromFrames(target, frames);
				holdsHistory(target);
			}

			// The first commit bootstraps this journal, so the loaded state
			// lands in a delta frame, which has to carry all of it.
			const other = open();
			const otherManager = new RecoveryManager(other.storage, {
				journal: other.journal
			});
			expect(
				otherManager.commit({
					criticality: RecoveryCriticality.SafetyCritical,
					mutations: [
						{ type: 'channel_key_index', channelId, channelIndex: 1 }
					],
					outboundMessages: []
				}).committed
			).to.be.true;
			expect(
				save(
					otherManager,
					channelId,
					source.storage.loadChannel(channelId)!.state
				)
			).to.be.true;
			const restored = open().storage;
			reconstructFromFrames(restored, other.journal.loadVerifiedFrames());
			holdsHistory(restored);
		} finally {
			for (const storage of stores) storage.close();
		}
	});

	it('drops a closed channel’s snapshots with its row', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		try {
			const { opener, acceptor } = setupNormalChannels();
			const channelId = opener.getChannelId()!.toString('hex');
			offerHtlc(opener, acceptor, crypto.randomBytes(32));
			exchangeCommitments(opener, acceptor);
			storage.saveChannel(channelId, opener.getFullState(), PEER);
			expect(snapshotRows(storage, channelId)).to.equal(1);
			storage.deleteChannel(channelId);
			expect(snapshotRows(storage, channelId)).to.equal(0);
		} finally {
			storage.close();
		}
	});

	it('encrypts stored snapshots when a key is first set', () => {
		const file = path.join(dir, 'plain.sqlite');
		const plain = new SqliteStorage(file);
		plain.open();
		const { opener, acceptor } = setupNormalChannels();
		const channelId = opener.getChannelId()!.toString('hex');
		offerHtlc(opener, acceptor, crypto.randomBytes(32));
		exchangeCommitments(opener, acceptor);
		plain.saveChannel(channelId, opener.getFullState(), PEER);
		plain.close();

		const keyed = new SqliteStorage(file, undefined, {
			encryptionKey: Buffer.alloc(32, 0x42)
		});
		keyed.open();
		try {
			const db = (keyed as unknown as { db: Database.Database }).db;
			const rows = db
				.prepare('SELECT htlcs_json FROM revoked_htlc_snapshots')
				.all() as Array<{ htlcs_json: string }>;
			expect(rows).to.have.length(1);
			expect(rows[0].htlcs_json.startsWith('enc1:')).to.be.true;
			expect(
				keyed.loadChannel(channelId)!.state.revokedHtlcSnapshots
			).to.deep.equal(opener.getFullState().revokedHtlcSnapshots);
		} finally {
			keyed.close();
		}
	});

	describe('moving a schema 18 row’s snapshots into the table', () => {
		const KEY = Buffer.alloc(32, 0x42);
		const entry = (n: number): IHtlcSnapshotEntry => ({
			paymentHash: Buffer.alloc(32, n),
			amountMsat: BigInt(n) * 1000n,
			cltvExpiry: 500 + n,
			direction: n % 2 ? HtlcDirection.OFFERED : HtlcDirection.RECEIVED
		});

		/** A database as schema 18 left it: the history inline in the row. */
		function legacyDatabase(
			file: string,
			compact: boolean,
			key?: Buffer
		): { channelId: string; history: Map<string, IHtlcSnapshotEntry[]> } {
			const { opener } = setupNormalChannels();
			const channelId = opener.getChannelId()!.toString('hex');
			const state = opener.getFullState();
			if (compact) state.compactHtlcHistory = true;
			state.revokedHtlcSnapshots = new Map([
				['0', []],
				['1', [entry(1)]],
				['2', [entry(1), entry(2)]],
				['3', []],
				['4', [entry(2)]]
			]);
			const storage = new SqliteStorage(file, undefined, {
				encryptionKey: key
			});
			storage.open();
			storage.close();
			const json = JSON.stringify(serializeChannelState(state));
			expect(json).to.include(
				compact ? 'compactHtlcHistory' : 'revokedHtlcSnapshots'
			);
			const db = new Database(file);
			db.prepare(
				'INSERT INTO channels (channel_id, state_json, peer_pubkey) VALUES (?, ?, ?)'
			).run(channelId, key ? encryptValue(key, json) : json, PEER);
			db.exec('DELETE FROM schema_version WHERE version > 18');
			db.close();
			return {
				channelId,
				history: new Map(
					[...state.revokedHtlcSnapshots].filter(([, e]) => e.length)
				)
			};
		}

		for (const compact of [false, true]) {
			for (const key of [undefined, KEY]) {
				it(`${compact ? 'compact' : 'legacy'} history${
					key ? ', encrypted' : ''
				}`, () => {
					const file = path.join(dir, 'old.sqlite');
					const { channelId, history } = legacyDatabase(file, compact, key);
					const storage = new SqliteStorage(file, undefined, {
						encryptionKey: key
					});
					storage.open();
					try {
						expect(snapshotRows(storage, channelId)).to.equal(history.size);
						const loaded = storage.loadChannel(channelId)!.state;
						expect(loaded.revokedHtlcSnapshots).to.deep.equal(history);
						expect(loaded.compactHtlcHistory).to.equal(
							compact ? true : undefined
						);
						const db = (storage as unknown as { db: Database.Database }).db;
						const raw = db
							.prepare('SELECT state_json FROM channels WHERE channel_id = ?')
							.get(channelId) as { state_json: string };
						const row = key
							? (storage as unknown as { _dec(v: string): string })._dec(
									raw.state_json
							  )
							: raw.state_json;
						const parsed = JSON.parse(row);
						expect(parsed.revokedHtlcSnapshots).to.equal(undefined);
						if (compact)
							expect(parsed.compactHtlcHistory.snapshots).to.deep.equal([]);
						else expect(parsed.compactHtlcHistory).to.equal(undefined);
					} finally {
						storage.close();
					}
				});
			}
		}
	});
});
