import { expect } from 'chai';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
	HtlcDirection,
	IHtlcSnapshotEntry
} from '../../src/lightning/channel/types';
import {
	encodeHtlcHistory,
	decodeHtlcHistory
} from '../../src/lightning/storage/htlc-history';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';
import {
	RecoveryCriticality,
	RecoveryFrame,
	RecoveryJournal,
	RecoveryManager,
	encodeFrame,
	decodeFrame,
	reconstructFromFrames
} from '../../src/lightning/recovery';
import {
	createPair,
	activate,
	pay,
	record,
	restart,
	expectVouchersCarried
} from './helpers/ffor-concurrent-pair';

function sampleHistory(): Map<string, IHtlcSnapshotEntry[]> {
	const first: IHtlcSnapshotEntry = {
		paymentHash: Buffer.alloc(32, 3),
		amountMsat: 1000001n,
		cltvExpiry: 800000,
		direction: HtlcDirection.RECEIVED
	};
	return new Map([
		['0', []],
		[
			'9007199254740993',
			[
				first,
				first,
				{ ...first, amountMsat: 1000002n },
				{ ...first, cltvExpiry: 800001 },
				{ ...first, direction: HtlcDirection.OFFERED }
			]
		],
		['9007199254740994', [first]],
		['9007199254740995', []],
		['9007199254740996', [first, first]]
	]);
}

describe('Concurrent commitment history persistence', function () {
	this.timeout(180000);

	it('re-encodes a frame captured before compaction byte for byte', () => {
		// Captured with the serializer at 3082014f, using only synthetic keys.
		const bytes = fs.readFileSync(
			path.join(__dirname, 'fixtures/ffor/legacy-concurrent-history-frame.json')
		);
		expect(encodeFrame(decodeFrame(bytes)).equals(bytes)).to.be.true;
	});

	it('preserves tuple variants, duplicates, order, empty commitments and independent buffers', () => {
		const original = sampleHistory();
		const decoded = decodeHtlcHistory(encodeHtlcHistory(original))!;
		expect([...decoded]).to.deep.equal([...original]);
		const entries = decoded.get('9007199254740993')!;
		entries[0].paymentHash.fill(7);
		expect(entries[1].paymentHash.equals(Buffer.alloc(32, 3))).to.be.true;
		expect(
			decoded
				.get('9007199254740994')![0]
				.paymentHash.equals(Buffer.alloc(32, 3))
		).to.be.true;
		expect(
			original
				.get('9007199254740993')![0]
				.paymentHash.equals(Buffer.alloc(32, 3))
		).to.be.true;
	});

	it('keeps legacy channel and frame bytes while upgrading the next durable channel row', () => {
		const pair = createPair();
		const baseline = pair.rChannel.getFullState();
		baseline.revokedHtlcSnapshots = sampleHistory();
		expect(JSON.stringify(serializeChannelState(baseline))).to.equal(
			JSON.stringify(
				serializeChannelState(baseline, { legacyHtlcHistory: true })
			)
		);
		activate(pair, [1000000n, 1000000n], true, 2);
		const frame: RecoveryFrame = {
			version: 1,
			writerEpoch: 1n,
			sequence: 2n,
			previousFrameHash: Buffer.alloc(32),
			timestamp: 1,
			mutations: [
				{
					type: 'channel_state',
					channelId: pair.channelId.toString('hex'),
					state: pair.rChannel.getFullState(),
					peerPubkey: pair.sPub
				}
			],
			outboundMessages: []
		};
		const legacy = encodeFrame(frame);
		expect(encodeFrame(decodeFrame(legacy)).equals(legacy)).to.be.true;
		const oldRow = serializeChannelState(pair.rChannel.getFullState(), {
			legacyHtlcHistory: true
		});
		expect(oldRow.compactHtlcHistory).to.equal(undefined);
		const restored = deserializeChannelState(
			JSON.parse(JSON.stringify(oldRow))
		);
		expect(restored.revokedHtlcSnapshots).to.deep.equal(
			pair.rChannel.getFullState().revokedHtlcSnapshots
		);
		expect(serializeChannelState(restored).compactHtlcHistory).not.to.equal(
			undefined
		);
		frame.version = 2;
		const compact = encodeFrame(frame);
		expect(encodeFrame(decodeFrame(compact)).equals(compact)).to.be.true;
		expect(
			JSON.parse(compact.toString()).mutations[0].state.revokedHtlcSnapshots
		).to.equal(undefined);
	});

	it('retains compact history through disk restart, retirement and a later baseline epoch', () => {
		const pair = createPair();
		activate(pair, [1000000n, 1000000n], true, 2);
		pay(pair, 'S', 1000000n);
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ffor-history-'));
		const file = path.join(dir, 'state.sqlite');
		let storage = new SqliteStorage(file);
		try {
			storage.open();
			storage.saveChannel(
				pair.channelId.toString('hex'),
				pair.rChannel.getFullState(),
				pair.sPub
			);
			storage.close();
			storage = new SqliteStorage(file);
			storage.open();
			const saved = storage.loadChannel(pair.channelId.toString('hex'))!;
			expect(saved.state.revokedHtlcSnapshots).to.deep.equal(
				pair.rChannel.getFullState().revokedHtlcSnapshots
			);
			restart(pair, 'R', JSON.stringify(serializeChannelState(saved.state)));
			restart(pair, 'S');
			pair.link.reconnect();
			for (const preimage of record(pair.sChannel).preimages)
				expect(pair.rManager.fforAddPreimage(pair.channelId, preimage).ok).to.be
					.true;
			expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.be.true;
			activate(pair, [1000000n], false);
			for (const channel of [pair.rChannel, pair.sChannel]) {
				const row = serializeChannelState(channel.getFullState());
				expect(row.revokedHtlcSnapshots).to.equal(undefined);
				expect(row.compactHtlcHistory).not.to.equal(undefined);
			}
		} finally {
			storage.close();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	for (const slots of [2, 16, 128]) {
		it(`keeps repeated voucher history growth small with ${slots} live slots`, () => {
			const pair = createPair({ pushSat: 200000n });
			activate(pair, Array(slots).fill(1000000n), true, 2);
			const state = (): ReturnType<typeof pair.rChannel.getFullState> =>
				pair.rChannel.getFullState();
			const bytes = (legacy: boolean): number => {
				const row = serializeChannelState(state(), {
					legacyHtlcHistory: legacy
				});
				return Buffer.byteLength(
					JSON.stringify(
						legacy ? row.revokedHtlcSnapshots : row.compactHtlcHistory
					)
				);
			};
			const before = { legacy: bytes(true), compact: bytes(false) };
			for (let i = 0; i < 5; i++) {
				pay(pair, 'S', 1000000n);
				pay(pair, 'R', 1000000n);
			}
			expectVouchersCarried(
				pair,
				Array.from({ length: slots }, (_, i) => i + 1)
			);
			const growth = {
				legacy: bytes(true) - before.legacy,
				compact: bytes(false) - before.compact
			};
			expect(growth.compact).to.be.lessThan(4000);
			expect(growth.compact).to.be.lessThan(growth.legacy);
			expect(
				deserializeChannelState(serializeChannelState(state()))
					.revokedHtlcSnapshots
			).to.deep.equal(state().revokedHtlcSnapshots);
			console.log(
				JSON.stringify({ slots, payments: 10, historyGrowthBytes: growth })
			);
		});
	}

	for (const paged of [false, true]) {
		it(`restores ${
			paged
				? 'paged compact snapshots'
				: 'a legacy snapshot followed by compact deltas'
		} through the journal`, () => {
			const source = new SqliteStorage(':memory:');
			const target = new SqliteStorage(':memory:');
			source.open();
			target.open();
			try {
				const pair = createPair();
				if (paged) {
					activate(pair, [1000000n, 1000000n], true, 2);
					for (let i = 0; i < 500; i++) {
						const hash = Buffer.alloc(32, 9);
						hash.writeUInt32BE(i);
						source.savePayment(hash.toString('hex'), {
							paymentHash: hash,
							amountMsat: 1000000n,
							status: PaymentStatus.COMPLETED,
							direction: PaymentDirection.INCOMING,
							createdAt: i,
							completedAt: i
						});
					}
				}
				const journal = new RecoveryJournal(
					source,
					Buffer.alloc(32, 1),
					Buffer.from(pair.rPub, 'hex'),
					Buffer.alloc(32, 2),
					{
						snapshotIntervalFrames: 1000,
						snapshotIntervalBytes: 10000000,
						...(paged ? { maxFrameCiphertextBytes: (): number => 50000 } : {})
					}
				);
				const manager = new RecoveryManager(source, { journal });
				const save = (): void => {
					const result = manager.commit({
						criticality: RecoveryCriticality.SafetyCritical,
						mutations: [
							{
								type: 'channel_state',
								channelId: pair.channelId.toString('hex'),
								state: pair.rChannel.getFullState(),
								peerPubkey: pair.sPub
							}
						],
						outboundMessages: []
					});
					expect(result.committed).to.be.true;
				};
				save();
				if (!paged) {
					activate(pair, [1000000n, 1000000n], true, 2);
					save();
				}
				pay(pair, 'S', 1000000n);
				save();
				const frames = journal.loadVerifiedFrames();
				expect(frames[0].version).to.equal(paged ? 2 : 1);
				expect(frames[frames.length - 1].version).to.equal(2);
				if (paged) {
					expect(frames[0].snapshot!.schemaVersion).to.equal(
						'2+ffor-vouchers+htlc-history+pages'
					);
					expect(frames[0].snapshot!.pageFrames).to.be.greaterThan(0);
					for (const row of source.loadRecoveryFrames())
						expect(row.ciphertext.length).to.be.at.most(50000);
				}
				reconstructFromFrames(target, frames);
				expect(
					serializeChannelState(
						target.loadChannel(pair.channelId.toString('hex'))!.state
					)
				).to.deep.equal(
					serializeChannelState(
						source.loadChannel(pair.channelId.toString('hex'))!.state
					)
				);
				expect(target.loadAllPayments()).to.deep.equal(
					source.loadAllPayments()
				);
			} finally {
				source.close();
				target.close();
			}
		});
	}
});
