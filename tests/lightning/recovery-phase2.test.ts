/**
 * Recovery Protocol phase 2: the recovery journal (docs/RECOVERY-PROTOCOL.md
 * 5.3 and 9).
 *
 * Tests cover:
 * 1. Frame codec round trip over every mutation variant
 * 2. Bootstrap: the first journaled commit emits a full-state snapshot
 * 3. Delta frames hash-chain and verify against the recorded tip
 * 4. Atomicity: a failed transition journals nothing
 * 5. Property test: reconstructFromFrames rebuilds byte-identical tables from
 *    randomized transition sequences, with and without snapshot boundaries
 * 6. Compaction prunes deltas below the snapshot without breaking rebuild
 * 7. Corruption: tampered, reordered and truncated journals are detected
 * 8. Outbox rows are stamped with the frame that carried them
 * 9. The journal is off by default and node wiring enables it end to end
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig } from '../../src/lightning/node/types';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	RecoveryCriticality,
	RecoveryManager,
	RecoveryMutation,
	RecoveryOutboundMessage,
	RecoveryJournal,
	RecoveryFrame,
	deriveRecoveryMasterKey,
	reconstructFromFrames,
	encodeFrame,
	decodeFrame,
	hashFrame
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	DEFAULT_CHANNEL_CONFIG,
	ChannelState
} from '../../src/lightning/channel/types';
import {
	IChannelState,
	createOpenerState
} from '../../src/lightning/channel/channel-state';
import {
	serializeChannelState,
	serializePaymentInfo
} from '../../src/lightning/storage/serialization';
import { MessageType } from '../../src/lightning/message/types';
import {
	IPaymentInfo,
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

// ─────────────── Fixtures ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(`recovery-phase2-seed-${id}`)
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeChannelState(channelId: Buffer, balance: bigint): IChannelState {
	const state = createOpenerState({
		temporaryChannelId: crypto.createHash('sha256').update(channelId).digest(),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(makeSeed(1)),
		localPerCommitmentSeed: makeSeed(3)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = channelId;
	state.fundingTxid = crypto.createHash('sha256').update(channelId).digest();
	state.fundingOutputIndex = 0;
	state.localBalanceMsat = balance;
	state.remoteBalanceMsat = 1_000_000_000n - balance;
	state.remoteBasepoints = makeBasepoints(makeSeed(2));
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints.firstPerCommitmentPoint;
	return state;
}

function makePayment(hash: Buffer, amount: bigint): IPaymentInfo {
	return {
		paymentHash: hash,
		amountMsat: amount,
		status: PaymentStatus.COMPLETED,
		direction: PaymentDirection.OUTGOING,
		createdAt: 1_700_000_000_000
	} as IPaymentInfo;
}

/** Deterministic PRNG so a failing sequence reproduces from its seed. */
function mulberry32(seed: number): () => number {
	let a = seed >>> 0;
	return (): number => {
		a |= 0;
		a = (a + 0x6d2b79f5) | 0;
		let t = Math.imul(a ^ (a >>> 15), 1 | a);
		t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

function prngBytes(rand: () => number, length: number): Buffer {
	const out = Buffer.alloc(length);
	for (let i = 0; i < length; i++) out[i] = Math.floor(rand() * 256);
	return out;
}

const NODE_SECRET = makeSeed(9);
const NODE_ID = getPublicKey(NODE_SECRET);
const MASTER_KEY = deriveRecoveryMasterKey(NODE_SECRET);

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function makeJournaledManager(
	storage: SqliteStorage,
	snapshotIntervalFrames = 1000
): { manager: RecoveryManager; journal: RecoveryJournal } {
	const journal = new RecoveryJournal(storage, MASTER_KEY, NODE_ID, {
		snapshotIntervalFrames
	});
	const manager = new RecoveryManager(storage, { journal });
	return { manager, journal };
}

/**
 * Generate one randomized safety transition. Covers every mutation variant
 * over a few recurring keys (so deletes hit rows that exist) and outbox rows
 * of both supersede classes.
 */
function randomTransition(
	rand: () => number,
	channelIds: Buffer[]
): {
	mutations: RecoveryMutation[];
	outboundMessages: RecoveryOutboundMessage[];
} {
	const channelId = channelIds[Math.floor(rand() * channelIds.length)];
	const idHex = channelId.toString('hex');
	const mutations: RecoveryMutation[] = [
		{
			type: 'channel_state',
			channelId: idHex,
			state: makeChannelState(
				channelId,
				BigInt(Math.floor(rand() * 900_000_000))
			),
			peerPubkey: 'aa'.repeat(33)
		},
		{
			type: 'channel_key_index',
			channelId: idHex,
			channelIndex: Math.floor(rand() * 10)
		}
	];
	const keySlot = Math.floor(rand() * 4);
	const hash = prngBytes(rand, 32);
	const roll = rand();
	if (roll < 0.3) {
		mutations.push(
			{
				type: 'payment_preimage',
				paymentHash: hash.toString('hex'),
				preimage: prngBytes(rand, 32)
			},
			{
				type: 'payment_state',
				paymentHash: hash.toString('hex'),
				payment: makePayment(hash, BigInt(Math.floor(rand() * 100_000)))
			},
			{
				type: 'payment_secret',
				paymentHash: hash.toString('hex'),
				secret: prngBytes(rand, 32)
			}
		);
	} else if (roll < 0.5) {
		mutations.push(
			{
				type: 'htlc_payment_mapping',
				htlcKey: `${idHex}:${keySlot}`,
				paymentHash: hash.toString('hex')
			},
			{
				type: 'htlc_shared_secret',
				key: `${idHex}:${keySlot}`,
				secret: prngBytes(rand, 32)
			},
			{
				type: 'forwarded_htlc',
				outKey: `${idHex}:offered-${keySlot}`,
				inChannelId: channelIds[0],
				inHtlcId: BigInt(keySlot)
			}
		);
	} else if (roll < 0.65) {
		mutations.push(
			{ type: 'delete_htlc_payment_mapping', htlcKey: `${idHex}:${keySlot}` },
			{ type: 'delete_htlc_shared_secret', key: `${idHex}:${keySlot}` },
			{ type: 'delete_forwarded_htlc', outKey: `${idHex}:offered-${keySlot}` }
		);
	} else if (roll < 0.75) {
		mutations.push({
			type: 'outbox_supersede',
			channelId: idHex,
			messageTypes: [MessageType.UPDATE_ADD_HTLC, MessageType.COMMITMENT_SIGNED]
		});
	}

	const outboundMessages: RecoveryOutboundMessage[] = [];
	const sends = Math.floor(rand() * 3);
	const sendTypes = [
		MessageType.UPDATE_ADD_HTLC,
		MessageType.COMMITMENT_SIGNED,
		MessageType.REVOKE_AND_ACK
	];
	for (let i = 0; i < sends; i++) {
		outboundMessages.push({
			peerId: 'aa'.repeat(33),
			channelId: idHex,
			messageType: sendTypes[Math.floor(rand() * sendTypes.length)],
			wireMessage: prngBytes(rand, 40 + Math.floor(rand() * 80)),
			disposition: 'pending_send'
		});
	}
	return { mutations, outboundMessages };
}

/**
 * Deterministic dump of every safety-critical table, for byte-identical
 * comparison between a live database and a reconstructed one.
 *
 * Outbox rows compare content in insertion order; ids and frame stamps are
 * excluded (a snapshot re-insert renumbers rows, and reconstruction replays
 * without a journal so frame_sequence is writer-side bookkeeping), as is
 * created_at. Everything else must match exactly.
 */
function dumpTables(storage: IStorageBackend): string {
	const sortByFirst = <T extends { 0: string }>(rows: T[]): T[] =>
		rows.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
	const dump = {
		channels: sortByFirst(
			storage
				.loadAllChannels()
				.map(
					(c) =>
						[
							c.channelId,
							JSON.stringify(serializeChannelState(c.state)),
							c.peerPubkey,
							String(storage.loadChannelKeyIndex(c.channelId))
						] as [string, string, string, string]
				)
		),
		monitors: sortByFirst(
			storage
				.loadAllChainMonitors()
				.map(
					(m) =>
						[m.channelId, JSON.stringify(m.state, bigintSafe)] as [
							string,
							string
						]
				)
		),
		preimages: sortByFirst(
			storage
				.loadAllPreimages()
				.map(
					(p) => [p.paymentHash, p.preimage.toString('hex')] as [string, string]
				)
		),
		payments: sortByFirst(
			storage
				.loadAllPayments()
				.map(
					(p) =>
						[
							p.paymentHash,
							JSON.stringify(serializePaymentInfo(p.payment))
						] as [string, string]
				)
		),
		paymentSecrets: sortByFirst(
			storage
				.loadAllPaymentSecrets()
				.map(
					(s) =>
						[s.paymentHashHex, s.secret.toString('hex')] as [string, string]
				)
		),
		htlcPaymentMappings: sortByFirst(
			storage
				.loadAllHtlcPaymentMappings()
				.map((m) => [m.key, m.paymentHashHex] as [string, string])
		),
		forwardedHtlcs: sortByFirst(
			storage
				.loadAllForwardedHtlcs()
				.map(
					(f) =>
						[
							f.outKey,
							f.inChannelId.toString('hex'),
							f.inHtlcId.toString()
						] as [string, string, string]
				)
		),
		htlcSharedSecrets: sortByFirst(
			storage
				.loadAllHtlcSharedSecrets()
				.map((s) => [s.key, s.secret.toString('hex')] as [string, string])
		),
		outbox: (storage.loadOutboxMessages?.() ?? []).map((row) => [
			row.peerId,
			row.channelId ?? '',
			String(row.messageType),
			row.wireMessage.toString('hex'),
			row.disposition
		])
	};
	return JSON.stringify(dump);
}

function bigintSafe(_key: string, value: unknown): unknown {
	return typeof value === 'bigint' ? `${value.toString()}n` : value;
}

// ─────────────── 1. Codec ───────────────

describe('Recovery phase 2: frame codec', () => {
	it('round trips a frame carrying every mutation variant', () => {
		const channelId = prngBytes(mulberry32(7), 32);
		const rand = mulberry32(11);
		const state = makeChannelState(channelId, 500_000_000n);
		const frame: RecoveryFrame = {
			version: 1,
			writerEpoch: 1n,
			sequence: 42n,
			previousFrameHash: prngBytes(rand, 32),
			timestamp: 1_700_000_000_000,
			mutations: [
				{
					type: 'channel_state',
					channelId: channelId.toString('hex'),
					state,
					peerPubkey: 'ab'.repeat(33)
				},
				{
					type: 'channel_key_index',
					channelId: channelId.toString('hex'),
					channelIndex: 3
				},
				{
					type: 'payment_preimage',
					paymentHash: '11'.repeat(32),
					preimage: prngBytes(rand, 32)
				},
				{
					type: 'htlc_payment_mapping',
					htlcKey: 'k1',
					paymentHash: '22'.repeat(32)
				},
				{ type: 'delete_htlc_payment_mapping', htlcKey: 'k1' },
				{ type: 'htlc_shared_secret', key: 'k2', secret: prngBytes(rand, 32) },
				{ type: 'delete_htlc_shared_secret', key: 'k2' },
				{
					type: 'forwarded_htlc',
					outKey: 'o1',
					inChannelId: channelId,
					inHtlcId: 7n
				},
				{ type: 'delete_forwarded_htlc', outKey: 'o1' },
				{
					type: 'payment_state',
					paymentHash: '33'.repeat(32),
					payment: makePayment(Buffer.alloc(32, 0x33), 1234n)
				},
				{
					type: 'payment_secret',
					paymentHash: '33'.repeat(32),
					secret: prngBytes(rand, 32)
				},
				{ type: 'delete_payment_secret', paymentHash: '33'.repeat(32) },
				{ type: 'channel_closed', channelId: '44'.repeat(32) },
				{
					type: 'outbox_supersede',
					channelId: channelId.toString('hex'),
					messageTypes: [MessageType.COMMITMENT_SIGNED]
				}
			],
			outboundMessages: [
				{
					peerId: 'ab'.repeat(33),
					channelId: channelId.toString('hex'),
					messageType: MessageType.COMMITMENT_SIGNED,
					wireMessage: prngBytes(rand, 64),
					disposition: 'pending_send'
				}
			]
		};

		const plaintext = encodeFrame(frame);
		const decoded = decodeFrame(plaintext);
		// Re-encoding the decoded frame reproduces the exact bytes, so the
		// frame hash is stable across a store/load cycle.
		expect(encodeFrame(decoded).equals(plaintext)).to.equal(true);
		expect(
			hashFrame(encodeFrame(decoded)).equals(hashFrame(plaintext))
		).to.equal(true);
		expect(decoded.sequence).to.equal(42n);
		expect(decoded.mutations).to.have.length(frame.mutations.length);
		const decodedState = decoded.mutations[0] as {
			state: IChannelState;
		};
		expect(JSON.stringify(serializeChannelState(decodedState.state))).to.equal(
			JSON.stringify(serializeChannelState(state))
		);
	});
});

// ─────────────── 2-4. Journal behavior ───────────────

describe('Recovery phase 2: journal append', () => {
	it('bootstraps with a full-state snapshot that already contains the first transition', () => {
		const storage = openStorage();
		// Pre-journal state that deltas alone could never rebuild.
		storage.savePreimage('aa'.repeat(32), Buffer.alloc(32, 1));
		const { manager, journal } = makeJournaledManager(storage);

		const channelId = prngBytes(mulberry32(1), 32);
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'channel_state',
					channelId: channelId.toString('hex'),
					state: makeChannelState(channelId, 100_000_000n),
					peerPubkey: 'aa'.repeat(33)
				}
			],
			outboundMessages: []
		});
		expect(result.committed).to.equal(true);

		const frames = journal.loadVerifiedFrames();
		expect(frames).to.have.length(1);
		expect(frames[0].sequence).to.equal(1n);
		expect(frames[0].snapshot, 'first frame is a snapshot').to.not.equal(
			undefined
		);
		expect(frames[0].mutations).to.have.length(0);
		// Both the pre-journal preimage AND the bootstrapping transition are in.
		expect(frames[0].snapshot!.preimages).to.have.length(1);
		expect(frames[0].snapshot!.channels).to.have.length(1);
		storage.close();
	});

	it('chains deltas and verifies them against the recorded tip', () => {
		const storage = openStorage();
		const { manager, journal } = makeJournaledManager(storage);
		const rand = mulberry32(2);
		const channelIds = [prngBytes(rand, 32), prngBytes(rand, 32)];

		for (let i = 0; i < 5; i++) {
			const t = randomTransition(rand, channelIds);
			expect(
				manager.commit({
					criticality: RecoveryCriticality.SafetyCritical,
					...t
				}).committed
			).to.equal(true);
		}

		const frames = journal.loadVerifiedFrames();
		expect(frames).to.have.length(5);
		expect(frames[0].snapshot).to.not.equal(undefined);
		for (let i = 1; i < frames.length; i++) {
			expect(frames[i].sequence).to.equal(frames[i - 1].sequence + 1n);
		}
		expect(journal.getTip()!.sequence).to.equal(5n);
		storage.close();
	});

	it('journals nothing when the transition fails', () => {
		const storage = openStorage();
		const { manager, journal } = makeJournaledManager(storage);
		const channelId = prngBytes(mulberry32(3), 32);

		// Seed one good frame, then break a later mutation.
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: 'bb'.repeat(32),
					preimage: Buffer.alloc(32, 2)
				}
			],
			outboundMessages: []
		});
		const tipBefore = journal.getTip()!;

		const broken = new RecoveryManager(
			new Proxy(storage, {
				get(target, prop, receiver): unknown {
					if (prop === 'saveChannelKeyIndex') {
						return (): never => {
							throw new Error('disk on fire');
						};
					}
					const value = Reflect.get(target, prop, receiver);
					return typeof value === 'function' ? value.bind(target) : value;
				}
			}) as IStorageBackend,
			{ journal: new RecoveryJournal(storage, MASTER_KEY, NODE_ID) }
		);
		const result = broken.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'channel_state',
					channelId: channelId.toString('hex'),
					state: makeChannelState(channelId, 1_000_000n),
					peerPubkey: 'aa'.repeat(33)
				},
				{
					type: 'channel_key_index',
					channelId: channelId.toString('hex'),
					channelIndex: 1
				}
			],
			outboundMessages: []
		});
		expect(result.committed).to.equal(false);

		const tipAfter = journal.getTip()!;
		expect(tipAfter.sequence).to.equal(tipBefore.sequence);
		expect(tipAfter.frameHash.equals(tipBefore.frameHash)).to.equal(true);
		expect(journal.loadVerifiedFrames()).to.have.length(1);
		storage.close();
	});

	it('stamps outbox rows with the frame that carried them', () => {
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		const channelId = prngBytes(mulberry32(4), 32);

		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [],
			outboundMessages: [
				{
					peerId: 'aa'.repeat(33),
					channelId: channelId.toString('hex'),
					messageType: MessageType.COMMITMENT_SIGNED,
					wireMessage: Buffer.from([1, 2, 3]),
					disposition: 'pending_send'
				}
			]
		});

		const rows = storage.loadOutboxMessages(channelId.toString('hex'));
		expect(rows).to.have.length(1);
		// Frame 1 (the bootstrap snapshot) carried this insert.
		expect(rows[0].frameSequence).to.equal(1);
		storage.close();
	});
});

// ─────────────── 5-6. Deterministic reconstruction ───────────────

describe('Recovery phase 2: deterministic reconstruction', () => {
	function runReconstructionProperty(
		seed: number,
		steps: number,
		snapshotIntervalFrames: number
	): void {
		const live = openStorage();
		const { manager, journal } = makeJournaledManager(
			live,
			snapshotIntervalFrames
		);
		const rand = mulberry32(seed);
		const channelIds = [
			prngBytes(rand, 32),
			prngBytes(rand, 32),
			prngBytes(rand, 32)
		];

		for (let i = 0; i < steps; i++) {
			const t = randomTransition(rand, channelIds);
			const result = manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				...t
			});
			expect(result.committed, `step ${i} committed (seed ${seed})`).to.equal(
				true
			);
		}

		const frames = journal.loadVerifiedFrames();
		const rebuilt = openStorage();
		reconstructFromFrames(rebuilt, frames);

		expect(
			dumpTables(rebuilt),
			`byte-identical tables (seed ${seed}, interval ${snapshotIntervalFrames})`
		).to.equal(dumpTables(live));
		live.close();
		rebuilt.close();
	}

	it('rebuilds byte-identical tables from bootstrap snapshot + deltas', () => {
		for (const seed of [101, 202, 303]) {
			runReconstructionProperty(seed, 25, 1000);
		}
	});

	it('rebuilds byte-identical tables across snapshot + compaction boundaries', () => {
		for (const seed of [404, 505, 606]) {
			runReconstructionProperty(seed, 30, 7);
		}
	});

	it('compaction prunes deltas below the latest snapshot', () => {
		const storage = openStorage();
		const { manager, journal } = makeJournaledManager(storage, 5);
		const rand = mulberry32(8);
		const channelIds = [prngBytes(rand, 32)];
		for (let i = 0; i < 12; i++) {
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				...randomTransition(rand, channelIds)
			});
		}
		const frames = journal.loadVerifiedFrames();
		// Everything below the newest snapshot is gone.
		let lastSnapshotIndex = -1;
		for (let i = frames.length - 1; i >= 0; i--) {
			if (frames[i].snapshot) {
				lastSnapshotIndex = i;
				break;
			}
		}
		expect(lastSnapshotIndex).to.equal(0);
		expect(frames[0].snapshot).to.not.equal(undefined);
		storage.close();
	});
});

// ─────────────── 7. Corruption detection ───────────────

describe('Recovery phase 2: corruption detection', () => {
	function journalWithFrames(): {
		storage: SqliteStorage;
		journal: RecoveryJournal;
	} {
		const storage = openStorage();
		const { manager, journal } = makeJournaledManager(storage);
		const rand = mulberry32(5);
		const channelIds = [prngBytes(rand, 32)];
		for (let i = 0; i < 4; i++) {
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				...randomTransition(rand, channelIds)
			});
		}
		return { storage, journal };
	}

	function rawDb(storage: SqliteStorage): {
		prepare: (sql: string) => {
			run: (...args: unknown[]) => unknown;
			get: (...args: unknown[]) => unknown;
		};
	} {
		return (storage as unknown as { db: never }).db;
	}

	it('detects a tampered ciphertext', () => {
		const { storage, journal } = journalWithFrames();
		const row = rawDb(storage)
			.prepare('SELECT ciphertext FROM recovery_frames WHERE sequence = 2')
			.get() as { ciphertext: Buffer };
		const tampered = Buffer.from(row.ciphertext);
		tampered[tampered.length - 1] ^= 0x01;
		rawDb(storage)
			.prepare('UPDATE recovery_frames SET ciphertext = ? WHERE sequence = 2')
			.run(tampered);
		expect(() => journal.loadVerifiedFrames()).to.throw(
			/failed authentication/
		);
		storage.close();
	});

	it('detects a reordered (transplanted) frame', () => {
		const { storage, journal } = journalWithFrames();
		// Swap the payloads of frames 2 and 3: each ciphertext is now at a
		// sequence its AAD does not bind.
		const db = rawDb(storage);
		const two = db
			.prepare('SELECT ciphertext FROM recovery_frames WHERE sequence = 2')
			.get() as { ciphertext: Buffer };
		const three = db
			.prepare('SELECT ciphertext FROM recovery_frames WHERE sequence = 3')
			.get() as { ciphertext: Buffer };
		db.prepare(
			'UPDATE recovery_frames SET ciphertext = ? WHERE sequence = 2'
		).run(three.ciphertext);
		db.prepare(
			'UPDATE recovery_frames SET ciphertext = ? WHERE sequence = 3'
		).run(two.ciphertext);
		expect(() => journal.loadVerifiedFrames()).to.throw(
			/failed authentication/
		);
		storage.close();
	});

	it('detects a truncated tail against the recorded tip', () => {
		const { storage, journal } = journalWithFrames();
		rawDb(storage)
			.prepare(
				'DELETE FROM recovery_frames WHERE sequence = (SELECT MAX(sequence) FROM recovery_frames)'
			)
			.run();
		expect(() => journal.loadVerifiedFrames()).to.throw(/truncated/);
		storage.close();
	});

	it('detects a gap in the sequence', () => {
		const { storage, journal } = journalWithFrames();
		rawDb(storage)
			.prepare('DELETE FROM recovery_frames WHERE sequence = 2')
			.run();
		expect(() => journal.loadVerifiedFrames()).to.throw(/gap/);
		storage.close();
	});
});

// ─────────────── 8-9. Wiring ───────────────

describe('Recovery phase 2: wiring and defaults', () => {
	it('writes no frames unless a journal is configured', () => {
		const storage = openStorage();
		const manager = new RecoveryManager(storage);
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: 'cc'.repeat(32),
					preimage: Buffer.alloc(32, 3)
				}
			],
			outboundMessages: []
		});
		expect(storage.loadRecoveryFrames()).to.have.length(0);
		expect(storage.getRecoveryMeta('journal_tip_sequence')).to.equal(null);
		storage.close();
	});

	it('journals real node transitions end to end when enabled by config', () => {
		const storage = openStorage();
		const makeNode = (
			seedId: number,
			withStorage?: SqliteStorage
		): LightningNode => {
			const seed = crypto
				.createHash('sha256')
				.update(`recovery-phase2-node-${seedId}`)
				.digest();
			const config: INodeConfig = {
				nodePrivateKey: crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from('node-identity'))
					.digest(),
				network: Network.REGTEST as Network,
				channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
				channelBasepoints: makeBasepoints(seed),
				perCommitmentSeed: crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from('percommit'))
					.digest(),
				fundingPrivkey: crypto
					.createHash('sha256')
					.update(seed)
					.update(Buffer.from([0]))
					.digest(),
				storage: withStorage,
				recovery: withStorage
					? { enabled: true, snapshotIntervalFrames: 64 }
					: undefined
			};
			const node = new LightningNode(config);
			node.on('error', () => {});
			node.on('node:error', () => {});
			return node;
		};
		const alice = makeNode(1, storage);
		const bob = makeNode(2);
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === bob.getNodeId())
				bob.handlePeerMessage(alice.getNodeId(), t, p);
		});
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === alice.getNodeId()) {
				alice.handlePeerMessage(bob.getNodeId(), t, p);
			}
		});

		const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
		const channelId = alice.createFunding(
			channel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		)!;
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);

		// Every safety transition of the real open flow journaled: frame 1 is
		// the bootstrap snapshot, and the chain verifies end to end.
		const aliceKey = crypto
			.createHash('sha256')
			.update(
				crypto.createHash('sha256').update('recovery-phase2-node-1').digest()
			)
			.update(Buffer.from('node-identity'))
			.digest();
		const journal = new RecoveryJournal(
			storage,
			deriveRecoveryMasterKey(aliceKey),
			Buffer.from(alice.getNodeId(), 'hex')
		);
		const frames = journal.loadVerifiedFrames();
		expect(frames.length).to.be.greaterThan(1);
		expect(frames[0].snapshot).to.not.equal(undefined);
		// The rebuilt channel table matches the live one exactly.
		const rebuilt = openStorage();
		reconstructFromFrames(rebuilt, frames);
		expect(dumpTables(rebuilt)).to.equal(dumpTables(storage));

		alice.destroy();
		bob.destroy();
		storage.close();
		rebuilt.close();
	});

	it('skips Reconstructable transitions', () => {
		const storage = openStorage();
		const { manager, journal } = makeJournaledManager(storage);
		manager.commit({
			criticality: RecoveryCriticality.Reconstructable,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: 'dd'.repeat(32),
					preimage: Buffer.alloc(32, 4)
				}
			],
			outboundMessages: []
		});
		expect(journal.getTip()).to.equal(null);
		storage.close();
	});
});
