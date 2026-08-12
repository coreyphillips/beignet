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
import {
	CorruptRecoveryRowError,
	IStorageBackend
} from '../../src/lightning/storage/types';
import {
	assertEmptyTarget,
	RecoveryCriticality,
	RecoveryManager,
	RecoveryMutation,
	RecoveryOutboundMessage,
	RecoveryJournal,
	RecoveryFrame,
	deriveRecoveryMasterKey,
	deriveRecoveryRoot,
	deriveFrameIv,
	deriveFrameKey,
	encryptFrame,
	decryptFrame,
	frameAad,
	journalSupported,
	reconstructFromFrames,
	encodeFrame,
	decodeFrame,
	hashFrame,
	resolveWatermarkAnchor,
	JOURNAL_META_KEYS,
	META_REPLICATED_THROUGH,
	META_REPLICATED_THROUGH_HASH
} from '../../src/lightning/recovery';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { withStorageTransaction } from '../../src/lightning/storage/transaction';
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
const RECOVERY_ID = deriveRecoveryRoot(NODE_SECRET).recoveryId;

function openStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

function makeJournaledManager(
	storage: SqliteStorage,
	snapshotIntervalFrames = 1000
): { manager: RecoveryManager; journal: RecoveryJournal } {
	const journal = new RecoveryJournal(
		storage,
		MASTER_KEY,
		NODE_ID,
		RECOVERY_ID,
		{
			snapshotIntervalFrames
		}
	);
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
	} else if (roll < 0.85) {
		mutations.push(
			{
				type: 'invoice_state',
				paymentHash: hash.toString('hex'),
				invoice: {
					paymentHash: hash.toString('hex'),
					bolt11: `lnbcrt1${hash.toString('hex').slice(0, 20)}`,
					amountMsat: BigInt(Math.floor(rand() * 100_000)),
					expiry: 3600,
					createdAt: 1_700_000_000_000,
					bolt12: rand() < 0.5
				}
			},
			{
				type: 'invoice_path_id',
				paymentHash: hash.toString('hex'),
				pathId: prngBytes(rand, 32)
			},
			{
				type: 'forwarding_event',
				event: {
					settledAt: 1_700_000_000_000 + Math.floor(rand() * 1000),
					inChannelId: channelIds[0].toString('hex'),
					outChannelId: idHex,
					amountInMsat: BigInt(1000 + Math.floor(rand() * 1000)),
					amountOutMsat: BigInt(900 + Math.floor(rand() * 100)),
					feeMsat: BigInt(Math.floor(rand() * 100))
				}
			}
		);
	} else if (roll < 0.95) {
		mutations.push(
			{ type: 'delete_preimage', paymentHash: hash.toString('hex') },
			{ type: 'delete_payment_secret', paymentHash: hash.toString('hex') },
			{ type: 'delete_invoice_path_id', paymentHash: hash.toString('hex') },
			{ type: 'delete_invoice', paymentHash: hash.toString('hex') },
			{ type: 'delete_payment', paymentHash: hash.toString('hex') }
		);
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
 * Outbox rows compare content in insertion order, frame_sequence stamp
 * included: snapshot rows carry their stamp and replay re-stamps delta rows
 * with the frame that carried them. Only the row id (AUTOINCREMENT
 * renumbering on re-insert) and created_at (wall clock) are excluded as
 * nonsemantic. Everything else must match exactly.
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
		invoices: sortByFirst(
			storage
				.loadAllInvoices()
				.map(
					(i) =>
						[i.paymentHashHex, JSON.stringify(i.invoice, bigintSafe)] as [
							string,
							string
						]
				)
		),
		invoicePathIds: sortByFirst(
			(storage.loadAllInvoicePathIds?.() ?? []).map(
				(i) => [i.paymentHashHex, i.pathId.toString('hex')] as [string, string]
			)
		),
		forwardingEvents: (storage.listForwardingEvents?.() ?? []).map(
			({ id: _id, ...event }) => JSON.stringify(event, bigintSafe)
		),
		outbox: (storage.loadOutboxMessages?.() ?? []).map((row) => [
			row.peerId,
			row.channelId ?? '',
			String(row.messageType),
			row.wireMessage.toString('hex'),
			row.disposition,
			String(row.frameSequence)
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
				{ type: 'delete_payment', paymentHash: '33'.repeat(32) },
				{ type: 'delete_preimage', paymentHash: '33'.repeat(32) },
				{
					type: 'invoice_state',
					paymentHash: '55'.repeat(32),
					invoice: {
						paymentHash: '55'.repeat(32),
						bolt11: 'lnbcrt1example',
						amountMsat: 42_000n,
						expiry: 3600,
						createdAt: 1_700_000_000_000,
						hold: true
					}
				},
				{ type: 'delete_invoice', paymentHash: '55'.repeat(32) },
				{
					type: 'invoice_path_id',
					paymentHash: '55'.repeat(32),
					pathId: prngBytes(rand, 32)
				},
				{ type: 'delete_invoice_path_id', paymentHash: '55'.repeat(32) },
				{
					type: 'forwarding_event',
					event: {
						settledAt: 1_700_000_000_001,
						inChannelId: '66'.repeat(32),
						outChannelId: '77'.repeat(32),
						inScid: 'aabbcc',
						amountInMsat: 10_000n,
						amountOutMsat: 9_900n,
						feeMsat: 100n
					}
				},
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

	it('derives every frame IV deterministically from the recovery namespace (wire 3.2)', () => {
		const storage = openStorage();
		const { manager, journal } = makeJournaledManager(storage);
		const rand = mulberry32(11);
		const channelIds = [prngBytes(rand, 32)];
		for (let i = 0; i < 4; i++) {
			const t = randomTransition(rand, channelIds);
			expect(
				manager.commit({
					criticality: RecoveryCriticality.SafetyCritical,
					...t
				}).committed
			).to.equal(true);
		}
		expect(journal.loadVerifiedFrames().length).to.be.greaterThan(0);
		// The stored IV (first 12 ciphertext bytes) is exactly the tagged-hash
		// derivation over (recovery_id, epoch, sequence, frameHash): no RNG
		// anywhere, so a VM-snapshot RNG rollback cannot repeat a (key, IV)
		// pair across different plaintexts.
		for (const row of storage.loadRecoveryFrames()) {
			const expected = deriveFrameIv(
				RECOVERY_ID,
				BigInt(row.writerEpoch),
				BigInt(row.sequence),
				row.frameHash
			);
			expect(row.ciphertext.subarray(0, 12).equals(expected)).to.equal(true);
			// And never keyed by the PUBLIC node id: that would be an offline
			// linkage oracle against the stored record (wire 1.1).
			const nodeKeyed = deriveFrameIv(
				NODE_ID.subarray(1),
				BigInt(row.writerEpoch),
				BigInt(row.sequence),
				row.frameHash
			);
			expect(row.ciphertext.subarray(0, 12).equals(nodeKeyed)).to.equal(false);
		}
		storage.close();
	});

	it('keeps frames written under the old random IVs decryptable', () => {
		// Pre-revision-4 frames drew the IV from the CSPRNG; the IV travels
		// with the ciphertext and decryption never re-derives it, so they
		// stay readable forever.
		const key = deriveFrameKey(MASTER_KEY, NODE_ID, 1n);
		const plaintext = Buffer.from('a legacy frame payload', 'utf8');
		const aad = Buffer.concat([NODE_ID, Buffer.alloc(16)]);
		const randomIv = Buffer.from('0102030405060708090a0b0c', 'hex');
		const legacy = encryptFrame(key, plaintext, aad, randomIv);
		expect(decryptFrame(key, legacy, aad).equals(plaintext)).to.equal(true);
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
			{
				journal: new RecoveryJournal(storage, MASTER_KEY, NODE_ID, RECOVERY_ID)
			}
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

	it('re-bases with a fresh snapshot on the first append of a new run', () => {
		const storage = openStorage();
		{
			const { manager } = makeJournaledManager(storage);
			const rand = mulberry32(31);
			const channelIds = [prngBytes(rand, 32)];
			for (let i = 0; i < 3; i++) {
				expect(
					manager.commit({
						criticality: RecoveryCriticality.SafetyCritical,
						...randomTransition(rand, channelIds)
					}).committed
				).to.equal(true);
			}
		}

		// Journaling disabled for a while: a write the journal never saw.
		storage.savePreimage('ab'.repeat(32), Buffer.alloc(32, 7));

		// New process run (new journal instance): the first append must
		// re-base on the drifted tables instead of chaining a delta onto the
		// stale tip, or reconstruction would verify cleanly and silently miss
		// the out-of-band write.
		const { manager: restarted, journal } = makeJournaledManager(storage);
		for (const fill of [8, 9]) {
			expect(
				restarted.commit({
					criticality: RecoveryCriticality.SafetyCritical,
					mutations: [
						{
							type: 'payment_preimage',
							paymentHash: Buffer.alloc(32, fill).toString('hex'),
							preimage: Buffer.alloc(32, fill)
						}
					],
					outboundMessages: []
				}).committed
			).to.equal(true);
		}

		const frames = journal.loadVerifiedFrames();
		// First append re-based (snapshot, compaction pruned the old chain);
		// the second was an ordinary delta again.
		expect(frames).to.have.length(2);
		expect(frames[0].snapshot, 're-base snapshot is the base').to.not.equal(
			undefined
		);
		expect(frames[1].snapshot).to.equal(undefined);

		const rebuilt = openStorage();
		reconstructFromFrames(rebuilt, frames);
		expect(dumpTables(rebuilt)).to.equal(dumpTables(storage));
		// The out-of-band write is reachable from the chain again.
		expect(
			rebuilt.loadAllPreimages().some((p) => p.paymentHash === 'ab'.repeat(32))
		).to.equal(true);
		storage.close();
		rebuilt.close();
	});

	it('journalSupported requires compaction support', () => {
		const storage = openStorage();
		const noCompact = new Proxy(storage, {
			get(target, prop, receiver): unknown {
				if (prop === 'deleteRecoveryFramesBelow') return undefined;
				const value = Reflect.get(target, prop, receiver);
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as IStorageBackend;
		// Verification requires the retained base to BE the recorded snapshot,
		// which only compaction guarantees; a backend without it must not
		// qualify for journaling at all.
		expect(journalSupported(noCompact)).to.equal(false);
		expect(journalSupported(storage)).to.equal(true);
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
		// The storage layer refuses UPDATEs on frame rows (append-only
		// trigger), so simulated tampering replaces the row wholesale.
		const full = rawDb(storage)
			.prepare('SELECT * FROM recovery_frames WHERE sequence = 2')
			.get() as Record<string, unknown>;
		rawDb(storage)
			.prepare('DELETE FROM recovery_frames WHERE sequence = 2')
			.run();
		rawDb(storage)
			.prepare(
				'INSERT INTO recovery_frames (sequence, writer_epoch, frame_hash, previous_hash, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)'
			)
			.run(
				full.sequence,
				full.writer_epoch,
				full.frame_hash,
				full.previous_hash,
				tampered,
				full.created_at
			);
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
		const swap = (sequence: number, ciphertext: Buffer): void => {
			const full = db
				.prepare('SELECT * FROM recovery_frames WHERE sequence = ?')
				.get(sequence) as Record<string, unknown>;
			db.prepare('DELETE FROM recovery_frames WHERE sequence = ?').run(
				sequence
			);
			db.prepare(
				'INSERT INTO recovery_frames (sequence, writer_epoch, frame_hash, previous_hash, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)'
			).run(
				full.sequence,
				full.writer_epoch,
				full.frame_hash,
				full.previous_hash,
				ciphertext,
				full.created_at
			);
		};
		swap(2, three.ciphertext);
		swap(3, two.ciphertext);
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

	// Physical corruption below the byte level the chain hashes over: rows
	// whose columns do not even hold the declared types (issue #317). SQLite
	// affinity does not enforce them, and Buffer.from would silently coerce.
	function replaceFrameColumn(
		storage: SqliteStorage,
		sequence: number,
		column: string,
		value: unknown
	): void {
		const db = rawDb(storage);
		const full = db
			.prepare('SELECT * FROM recovery_frames WHERE sequence = ?')
			.get(sequence) as Record<string, unknown>;
		full[column] = value;
		db.prepare('DELETE FROM recovery_frames WHERE sequence = ?').run(sequence);
		db.prepare(
			'INSERT INTO recovery_frames (sequence, writer_epoch, frame_hash, previous_hash, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)'
		).run(
			full.sequence,
			full.writer_epoch,
			full.frame_hash,
			full.previous_hash,
			full.ciphertext,
			full.created_at
		);
	}

	it('refuses a frame row whose hash column holds text, not a 32-byte blob', () => {
		const { storage, journal } = journalWithFrames();
		const full = rawDb(storage)
			.prepare('SELECT frame_hash FROM recovery_frames WHERE sequence = 2')
			.get() as { frame_hash: Buffer };
		// The SAME 32 bytes, stored as their hex text: coercion would
		// utf8-encode it into a plausible 64-byte buffer.
		replaceFrameColumn(
			storage,
			2,
			'frame_hash',
			full.frame_hash.toString('hex')
		);
		expect(() => journal.loadVerifiedFrames()).to.throw(
			CorruptRecoveryRowError,
			/frame_hash/
		);
		storage.close();
	});

	it('refuses a truncated frame hash column', () => {
		const { storage, journal } = journalWithFrames();
		const full = rawDb(storage)
			.prepare('SELECT frame_hash FROM recovery_frames WHERE sequence = 2')
			.get() as { frame_hash: Buffer };
		replaceFrameColumn(
			storage,
			2,
			'frame_hash',
			full.frame_hash.subarray(0, 31)
		);
		expect(() => journal.loadVerifiedFrames()).to.throw(/32-byte/);
		storage.close();
	});

	it('refuses a non-integer writer epoch column', () => {
		const { storage, journal } = journalWithFrames();
		// Today this would surface as an opaque BigInt SyntaxError, or be
		// coerced if the text happens to look numeric.
		replaceFrameColumn(storage, 2, 'writer_epoch', 'abc');
		expect(() => journal.loadVerifiedFrames()).to.throw(/writer_epoch/);
		storage.close();
	});

	it('refuses to snapshot over an outbox row that does not decode', () => {
		const { storage } = journalWithFrames();
		rawDb(storage)
			.prepare(
				"INSERT INTO recovery_outbox (peer_pubkey, message_type, wire_message, disposition, created_at) VALUES ('aa', 136, 'zz-not-hex', 'pending_send', 0)"
			)
			.run();
		const tipBefore = storage.getRecoveryMeta!(JOURNAL_META_KEYS.tipSequence);
		// A fresh journal re-bases on its first replication; the re-base
		// snapshot must refuse to capture state a skipped row is missing from.
		const fresh = new RecoveryJournal(
			storage,
			MASTER_KEY,
			NODE_ID,
			RECOVERY_ID
		);
		expect(() => fresh.prepareForReplication()).to.throw(
			CorruptRecoveryRowError,
			/do not decode/
		);
		// The refused snapshot rolled back: no frame was written.
		expect(storage.getRecoveryMeta!(JOURNAL_META_KEYS.tipSequence)).to.equal(
			tipBefore
		);
		storage.close();
	});

	it('refuses to treat a restore target with undecodable rows as empty', () => {
		const storage = openStorage();
		rawDb(storage)
			.prepare(
				"INSERT INTO recovery_outbox (peer_pubkey, message_type, wire_message, disposition, created_at) VALUES ('aa', 136, 'zz-not-hex', 'pending_send', 0)"
			)
			.run();
		expect(() => assertEmptyTarget(storage)).to.throw(
			/refusing to treat it as empty/
		);
		storage.close();
	});

	it('refuses a malformed stored tip hash', () => {
		const { storage, journal } = journalWithFrames();
		storage.setRecoveryMeta!(JOURNAL_META_KEYS.tipHash, 'zz'.repeat(32));
		expect(() => journal.getTip()).to.throw(/tip hash/);
		expect(() => journal.loadVerifiedFrames()).to.throw(/tip hash/);
		storage.close();
	});
});

// ─────────────── Verification and reconstruction fail closed ───────────────

describe('Recovery phase 2: fail-closed verification', () => {
	function compactedJournal(): {
		storage: SqliteStorage;
		journal: RecoveryJournal;
	} {
		const storage = openStorage();
		const { manager, journal } = makeJournaledManager(storage, 4);
		const rand = mulberry32(21);
		const channelIds = [prngBytes(rand, 32)];
		// 7 commits with interval 4: compaction leaves [snapshot, delta, delta],
		// so deleting the snapshot leaves a contiguous authenticated suffix.
		for (let i = 0; i < 7; i++) {
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				...randomTransition(rand, channelIds)
			});
		}
		return { storage, journal };
	}

	it('rejects a journal whose retained base snapshot was deleted', () => {
		const { storage, journal } = compactedJournal();
		// The compacted base IS the first frame; deleting it leaves a
		// contiguous, fully authenticated suffix of deltas.
		(
			storage as unknown as {
				db: { prepare: (sql: string) => { run: () => unknown } };
			}
		).db
			.prepare(
				'DELETE FROM recovery_frames WHERE sequence = (SELECT MIN(sequence) FROM recovery_frames)'
			)
			.run();
		expect(() => journal.loadVerifiedFrames()).to.throw(
			/base snapshot|missing its retained/
		);
		storage.close();
	});

	it('rejects reconstruction without a base snapshot', () => {
		const { storage, journal } = compactedJournal();
		const frames = journal.loadVerifiedFrames();
		const deltasOnly = frames.filter((f) => !f.snapshot);
		const target = openStorage();
		expect(() => reconstructFromFrames(target, deltasOnly)).to.throw(
			/requires an authenticated base snapshot/
		);
		storage.close();
		target.close();
	});

	it('rejects reconstruction into a dirty target', () => {
		const { storage, journal } = compactedJournal();
		const frames = journal.loadVerifiedFrames();
		const target = openStorage();
		target.savePreimage('ee'.repeat(32), Buffer.alloc(32, 9));
		expect(() => reconstructFromFrames(target, frames)).to.throw(
			/EMPTY target/
		);
		storage.close();
		target.close();
	});

	it('snapshots on accumulated delta BYTES, not only frame count', () => {
		const storage = openStorage();
		const journal = new RecoveryJournal(
			storage,
			MASTER_KEY,
			NODE_ID,
			RECOVERY_ID,
			{
				snapshotIntervalFrames: 10_000,
				snapshotIntervalBytes: 1
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		const rand = mulberry32(22);
		const channelIds = [prngBytes(rand, 32)];
		// Frame 1: bootstrap snapshot. Frame 2: delta, whose plaintext alone
		// exceeds the byte budget, so frame 3 must be a snapshot.
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			...randomTransition(rand, channelIds)
		});
		manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			...randomTransition(rand, channelIds)
		});
		const frames = journal.loadVerifiedFrames();
		const last = frames[frames.length - 1];
		expect(last.snapshot, 'byte budget forced a snapshot').to.not.equal(
			undefined
		);
		// And compaction pruned everything below it.
		expect(frames[0].sequence).to.equal(last.sequence);
		storage.close();
	});
});

// ─────────────── Arbitrary-prefix reconstruction ───────────────

describe('Recovery phase 2: every prefix reconstructs', () => {
	it('rebuilds byte-identical tables at EVERY intermediate journal state', () => {
		// The acceptance criterion is reconstruction from any prefix ending at
		// a snapshot boundary plus deltas. Every intermediate journal state IS
		// such a prefix, so verify all of them, across compaction boundaries.
		const live = openStorage();
		const { manager, journal } = makeJournaledManager(live, 5);
		const rand = mulberry32(23);
		const channelIds = [prngBytes(rand, 32), prngBytes(rand, 32)];

		for (let i = 0; i < 14; i++) {
			const result = manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				...randomTransition(rand, channelIds)
			});
			expect(result.committed, `step ${i}`).to.equal(true);

			const frames = journal.loadVerifiedFrames();
			const rebuilt = openStorage();
			reconstructFromFrames(rebuilt, frames);
			expect(dumpTables(rebuilt), `prefix after step ${i}`).to.equal(
				dumpTables(live)
			);
			rebuilt.close();
		}
		live.close();
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
		// An Important write outside any channel transition: the invoice's
		// record set must reach the journal through the same chokepoint.
		alice.createInvoice({ amountMsat: 25_000n, description: 'journaled' });
		// A hold-invoice cancel journals as ONE transition: the deleted
		// payment secret and the cancelledAt stamp must not be resurrected by
		// a reconstruction (that would re-arm the cancelled hash).
		const held = alice.createInvoice({
			amountMsat: 10_000n,
			description: 'journaled-hold',
			hold: true
		});
		expect(alice.cancelHoldInvoice(held.paymentHash)).to.not.equal(null);

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
			Buffer.from(alice.getNodeId(), 'hex'),
			deriveRecoveryRoot(aliceKey).recoveryId
		);
		const frames = journal.loadVerifiedFrames();
		expect(frames.length).to.be.greaterThan(1);
		expect(frames[0].snapshot).to.not.equal(undefined);
		// The rebuilt channel table matches the live one exactly.
		const rebuilt = openStorage();
		reconstructFromFrames(rebuilt, frames);
		expect(dumpTables(rebuilt)).to.equal(dumpTables(storage));
		// The cancelled hold invoice's secret must be gone in the rebuild too,
		// not resurrected from the frame that created it.
		expect(
			rebuilt
				.loadAllPaymentSecrets()
				.some((s) => s.paymentHashHex === held.paymentHash.toString('hex'))
		).to.equal(false);

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

describe('Recovery phase 2: authenticated snapshot schema at the write boundary', () => {
	/**
	 * Rewrite the single bootstrap frame's snapshot schema IN PLACE with a
	 * valid AEAD seal and a matching tip hash: exactly what a journal
	 * written by a future release looks like on disk.
	 */
	function tamperBaseSchema(storage: SqliteStorage, schema: string): void {
		const row = storage.loadRecoveryFrames!(0)[0];
		const epoch = BigInt(row.writerEpoch);
		const key = deriveFrameKey(MASTER_KEY, NODE_ID, epoch);
		const aad = frameAad(
			NODE_ID,
			epoch,
			BigInt(row.sequence),
			row.previousFrameHash
		);
		const frame = decodeFrame(decryptFrame(key, row.ciphertext, aad));
		frame.snapshot!.schemaVersion = schema;
		const plaintext = encodeFrame(frame);
		const frameHash = hashFrame(plaintext);
		const iv = deriveFrameIv(
			RECOVERY_ID,
			epoch,
			BigInt(row.sequence),
			frameHash
		);
		(
			storage as unknown as {
				db: { prepare(sql: string): { run(...args: unknown[]): unknown } };
			}
		).db
			.prepare('DELETE FROM recovery_frames WHERE sequence = ?')
			.run(row.sequence);
		storage.saveRecoveryFrame!({
			sequence: row.sequence,
			writerEpoch: row.writerEpoch,
			frameHash,
			previousFrameHash: row.previousFrameHash,
			ciphertext: encryptFrame(key, plaintext, aad, iv),
			createdAt: row.createdAt
		});
		storage.setRecoveryMeta!('journal_tip_hash', frameHash.toString('hex'));
	}

	function commitPreimage(
		manager: RecoveryManager,
		fill: number
	): ReturnType<RecoveryManager['commit']> {
		return manager.commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, fill).toString('hex'),
					preimage: Buffer.alloc(32, fill)
				}
			],
			outboundMessages: []
		});
	}

	it('refuses to rewrite a journal whose AUTHENTICATED base is future-schema, even with the local marker gone', () => {
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 1).committed).to.equal(true);
		tamperBaseSchema(storage, '3');
		// The unauthenticated local marker is REMOVED: metadata alone now
		// reads as migratable legacy. The frames say otherwise.
		storage.setRecoveryMeta!('journal_snapshot_schema', '');
		const framesBefore = storage.loadRecoveryFrames!(0).length;

		const { manager: fresh } = makeJournaledManager(storage);
		const result = commitPreimage(fresh, 2);
		expect(result.committed, 'the rewrite is refused').to.equal(false);
		expect(String(result.error?.message)).to.match(
			/retained base snapshot declares schema '3'/
		);
		// Nothing was re-based or compacted: the future base survives.
		expect(storage.loadRecoveryFrames!(0).length).to.equal(framesBefore);
		const base = storage.loadRecoveryFrames!(0)[0];
		const key = deriveFrameKey(MASTER_KEY, NODE_ID, BigInt(base.writerEpoch));
		const aad = frameAad(
			NODE_ID,
			BigInt(base.writerEpoch),
			BigInt(base.sequence),
			base.previousFrameHash
		);
		const decoded = decodeFrame(decryptFrame(key, base.ciphertext, aad));
		expect(decoded.snapshot!.schemaVersion).to.equal('3');
		storage.close();
	});

	it('refuses to rewrite over an AEAD-valid frame this release cannot decode', () => {
		// A future release's tail frame decrypts (same keys) but its shape
		// is unknown to this decoder. Skipping it in favor of an older
		// readable snapshot would let the next re-base compact the future
		// frames away; the write boundary must fail closed instead.
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 5).committed).to.equal(true);
		const base = storage.loadRecoveryFrames!(0)[0];
		const epoch = BigInt(base.writerEpoch);
		const key = deriveFrameKey(MASTER_KEY, NODE_ID, epoch);
		// An AEAD-valid frame at sequence 2 whose plaintext this release's
		// decodeFrame refuses (unsupported frame version).
		const plaintext = Buffer.from(
			JSON.stringify({ version: 2, shape: 'from the future' }),
			'utf8'
		);
		const frameHash = hashFrame(plaintext);
		const aad = frameAad(NODE_ID, epoch, 2n, base.frameHash);
		const iv = deriveFrameIv(RECOVERY_ID, epoch, 2n, frameHash);
		storage.saveRecoveryFrame!({
			sequence: 2,
			writerEpoch: base.writerEpoch,
			frameHash,
			previousFrameHash: base.frameHash,
			ciphertext: encryptFrame(key, plaintext, aad, iv),
			createdAt: base.createdAt
		});
		storage.setRecoveryMeta!('journal_tip_sequence', '2');
		storage.setRecoveryMeta!('journal_tip_hash', frameHash.toString('hex'));
		storage.setRecoveryMeta!('journal_snapshot_schema', '');
		const framesBefore = storage.loadRecoveryFrames!(0).length;

		const { manager: fresh } = makeJournaledManager(storage);
		const result = commitPreimage(fresh, 6);
		expect(result.committed, 'the rewrite is refused').to.equal(false);
		expect(String(result.error?.message)).to.match(/fails verification/);
		// The future frame survives untouched.
		expect(storage.loadRecoveryFrames!(0).length).to.equal(framesBefore);
		const kept = storage.loadRecoveryFrames!(0).find((r) => r.sequence === 2);
		expect(kept, 'the undecodable frame is still stored').to.not.equal(
			undefined
		);
		expect(kept!.frameHash.equals(frameHash)).to.equal(true);
		storage.close();
	});

	it('prepareForReplication hits the same wall as any other write', () => {
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 3).committed).to.equal(true);
		storage.setRecoveryMeta!('journal_snapshot_schema', '3');
		const framesBefore = storage.loadRecoveryFrames!(0).length;

		const { journal: fresh } = makeJournaledManager(storage);
		expect(() => fresh.prepareForReplication()).to.throw(
			/not one this release can migrate/
		);
		expect(storage.loadRecoveryFrames!(0).length).to.equal(framesBefore);
		storage.close();
	});

	it('refuses to rewrite a journal whose chain does not verify against its tip', () => {
		// Deleting the tail, emptying the frame store while keeping the tip
		// metadata, or swapping the tip hash must all refuse the rewrite:
		// the compaction it triggers would destroy the evidence and leave a
		// journal that verifies.
		const sql = (
			storage: SqliteStorage
		): { prepare(q: string): { run(...args: unknown[]): unknown } } =>
			(
				storage as unknown as {
					db: { prepare(q: string): { run(...args: unknown[]): unknown } };
				}
			).db;

		// (a) Deleted tail: tip says 2, rows end at 1.
		const s1 = openStorage();
		const m1 = makeJournaledManager(s1);
		expect(commitPreimage(m1.manager, 10).committed).to.equal(true);
		expect(commitPreimage(m1.manager, 11).committed).to.equal(true);
		sql(s1).prepare('DELETE FROM recovery_frames WHERE sequence = 2').run();
		const r1 = commitPreimage(makeJournaledManager(s1).manager, 12);
		expect(r1.committed, 'deleted tail refused').to.equal(false);
		expect(String(r1.error?.message)).to.match(
			/do not match the recorded tip|fails verification/
		);
		s1.close();

		// (b) Every frame deleted, tip metadata retained.
		const s2 = openStorage();
		const m2 = makeJournaledManager(s2);
		expect(commitPreimage(m2.manager, 13).committed).to.equal(true);
		sql(s2).prepare('DELETE FROM recovery_frames').run();
		const r2 = commitPreimage(makeJournaledManager(s2).manager, 14);
		expect(r2.committed, 'emptied store refused').to.equal(false);
		expect(String(r2.error?.message)).to.match(
			/do not match the recorded tip|fails verification/
		);
		s2.close();

		// (c) Tip hash swapped for a plausible but wrong value.
		const s3 = openStorage();
		const m3 = makeJournaledManager(s3);
		expect(commitPreimage(m3.manager, 15).committed).to.equal(true);
		s3.setRecoveryMeta!('journal_tip_hash', 'ab'.repeat(32));
		const r3 = commitPreimage(makeJournaledManager(s3).manager, 16);
		expect(r3.committed, 'swapped tip hash refused').to.equal(false);
		expect(String(r3.error?.message)).to.match(
			/do not match the recorded tip|fails verification/
		);
		s3.close();
	});

	it('refuses an emptied store that kept partial journal metadata', () => {
		// Deleting frame 1 plus ONLY the tip hash (keeping the sequence and
		// base records) used to read as a fresh journal; the next commit
		// then created frame 2 with the genesis predecessor, a local chain
		// that verifies but forks from every guardian retaining frame 1.
		const sql = (
			storage: SqliteStorage
		): { prepare(q: string): { run(...args: unknown[]): unknown } } =>
			(
				storage as unknown as {
					db: { prepare(q: string): { run(...args: unknown[]): unknown } };
				}
			).db;

		// (a) Tip hash deleted, sequence and base retained.
		const s1 = openStorage();
		expect(
			commitPreimage(makeJournaledManager(s1).manager, 20).committed
		).to.equal(true);
		sql(s1).prepare('DELETE FROM recovery_frames').run();
		s1.deleteRecoveryMeta!('journal_tip_hash');
		const r1 = commitPreimage(makeJournaledManager(s1).manager, 21);
		expect(r1.committed, 'partial tip metadata refused').to.equal(false);
		expect(String(r1.error?.message)).to.match(
			/tip metadata is partial|fails verification/
		);
		expect(
			s1.loadRecoveryFrames!(0),
			'no genesis-predecessor frame was created'
		).to.have.length(0);
		s1.close();

		// (b) Tip AND base records deleted, but other frame-derived
		// metadata (the writer epoch) survives: still not a fresh journal.
		const s2 = openStorage();
		expect(
			commitPreimage(makeJournaledManager(s2).manager, 22).committed
		).to.equal(true);
		sql(s2).prepare('DELETE FROM recovery_frames').run();
		for (const key of [
			'journal_tip_hash',
			'journal_tip_sequence',
			'journal_last_snapshot_sequence',
			'journal_last_snapshot_written'
		]) {
			s2.deleteRecoveryMeta!(key);
		}
		const r2 = commitPreimage(makeJournaledManager(s2).manager, 23);
		expect(r2.committed, 'surviving frame-derived metadata refused').to.equal(
			false
		);
		expect(String(r2.error?.message)).to.match(/metadata \('.*'\) survives/);
		s2.close();
	});

	it('refuses a store rewritten UNDER a live writer, not just at startup', () => {
		// The expensive chain verification is one-shot per run, but the
		// cheap invariants are not: deleting the frames and tip metadata
		// while the SAME journal instance keeps writing must refuse the
		// next commit instead of silently creating a new frame 1 that
		// forks from every replica holding the original history.
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 30).committed).to.equal(true);
		(
			storage as unknown as {
				db: { prepare(q: string): { run(...args: unknown[]): unknown } };
			}
		).db
			.prepare('DELETE FROM recovery_frames')
			.run();
		for (const key of [
			'journal_tip_hash',
			'journal_tip_sequence',
			'journal_last_snapshot_sequence',
			'journal_last_snapshot_written',
			'journal_delta_bytes_since_snapshot',
			'journal_snapshot_schema'
		]) {
			storage.deleteRecoveryMeta!(key);
		}
		// SAME manager instance: the one-shot verification already ran.
		const result = commitPreimage(manager, 31);
		expect(result.committed, 'the mid-process rewrite is refused').to.equal(
			false
		);
		expect(String(result.error?.message)).to.match(
			/tip changed outside this writer/
		);
		expect(
			storage.loadRecoveryFrames!(),
			'no forked frame 1 was created'
		).to.have.length(0);
		storage.close();
	});

	it('refuses empty stores carrying a replication watermark or explicit empty values', () => {
		// (a) A dangling guardian watermark over an empty store: writing
		// frame 1 under it would leave replication believing everything at
		// or below the watermark was already sent.
		const s1 = openStorage();
		s1.setRecoveryMeta!('guardian_replicated_through', '1');
		const r1 = commitPreimage(makeJournaledManager(s1).manager, 32);
		expect(r1.committed, 'watermark residue refused').to.equal(false);
		expect(String(r1.error?.message)).to.match(/guardian_replicated_through/);
		s1.close();

		// (b) PRESENCE is residue: an explicitly stored empty value is not
		// absence.
		const s2 = openStorage();
		s2.setRecoveryMeta!('journal_last_snapshot_sequence', '');
		const r2 = commitPreimage(makeJournaledManager(s2).manager, 33);
		expect(r2.committed, 'explicit empty value refused').to.equal(false);
		expect(String(r2.error?.message)).to.match(
			/journal_last_snapshot_sequence|fails verification/
		);
		s2.close();
	});

	it('refuses a present-but-null or empty schema declaration outright', () => {
		// Only a truly ABSENT property means pre-versioning: an explicit
		// null or empty declaration is an evasive shape that could smuggle
		// unknown snapshot content past the schema gate.
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 4).committed).to.equal(true);
		const row = storage.loadRecoveryFrames!(0)[0];
		const key = deriveFrameKey(MASTER_KEY, NODE_ID, BigInt(row.writerEpoch));
		const aad = frameAad(
			NODE_ID,
			BigInt(row.writerEpoch),
			BigInt(row.sequence),
			row.previousFrameHash
		);
		const plaintext = decryptFrame(key, row.ciphertext, aad);
		for (const bad of [null, '']) {
			const parsed = JSON.parse(plaintext.toString('utf8')) as {
				snapshot: { schemaVersion?: unknown };
			};
			parsed.snapshot.schemaVersion = bad;
			expect(
				() => decodeFrame(Buffer.from(JSON.stringify(parsed), 'utf8')),
				`declaration ${JSON.stringify(bad)}`
			).to.throw(/nonempty string/);
		}
		storage.close();
	});
});

describe('Recovery phase 2: attempt-owned commit and rollback', () => {
	const sql = (
		storage: SqliteStorage
	): { prepare(q: string): { run(...args: unknown[]): unknown } } =>
		(
			storage as unknown as {
				db: { prepare(q: string): { run(...args: unknown[]): unknown } };
			}
		).db;

	function commitPreimage(
		manager: RecoveryManager,
		fill: number
	): ReturnType<RecoveryManager['commit']> {
		return manager.commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, fill).toString('hex'),
					preimage: Buffer.alloc(32, fill)
				}
			],
			outboundMessages: []
		});
	}

	it('a refusal never erases the evidence it refused on', () => {
		// The guard's own refusal must NOT count as a rollback of journal
		// expectations: after tampering, EVERY retry keeps refusing instead
		// of the second one writing a forked frame 1.
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 40).committed).to.equal(true);
		sql(storage).prepare('DELETE FROM recovery_frames').run();
		for (const key of [
			'journal_tip_hash',
			'journal_tip_sequence',
			'journal_last_snapshot_sequence',
			'journal_last_snapshot_written',
			'journal_delta_bytes_since_snapshot',
			'journal_snapshot_schema'
		]) {
			storage.deleteRecoveryMeta!(key);
		}
		const first = commitPreimage(manager, 41);
		expect(first.committed, 'first retry refused').to.equal(false);
		const second = commitPreimage(manager, 42);
		expect(second.committed, 'second retry STILL refused').to.equal(false);
		expect(String(second.error?.message)).to.match(
			/tip changed outside this writer/
		);
		expect(
			storage.loadRecoveryFrames!(),
			'no forked frame 1 was ever created'
		).to.have.length(0);
		storage.close();
	});

	it('a genuine rollback restores EVERY journal field and the retry works', () => {
		// (a) A bootstrap that rolls back must not leave rebasedThisRun
		// true or a phantom written tip: the retry re-bootstraps cleanly.
		const s1 = openStorage();
		const h1 = makeJournaledManager(s1);
		const realSave = s1.saveRecoveryFrame!.bind(s1);
		let failNext = true;
		s1.saveRecoveryFrame = (frame): void => {
			if (failNext) {
				failNext = false;
				throw new Error('disk hiccup');
			}
			realSave(frame);
		};
		const failed = commitPreimage(h1.manager, 43);
		expect(failed.committed).to.equal(false);
		const retried = commitPreimage(h1.manager, 44);
		expect(retried.committed, 'the retry commits cleanly').to.equal(true);
		const frames = h1.journal.loadVerifiedFrames();
		expect(frames[0].snapshot, 'the retry re-bootstrapped').to.not.equal(
			undefined
		);
		expect(commitPreimage(h1.manager, 45).committed).to.equal(true);
		s1.close();

		// (b) A failed prepareForReplication must not leave the run marked
		// as re-based: the next append still re-bases with a snapshot.
		const s2 = openStorage();
		const h2 = makeJournaledManager(s2);
		expect(commitPreimage(h2.manager, 46).committed).to.equal(true);
		const h3 = makeJournaledManager(s2);
		const realSave2 = s2.saveRecoveryFrame!.bind(s2);
		let failOnce = true;
		s2.saveRecoveryFrame = (frame): void => {
			if (failOnce) {
				failOnce = false;
				throw new Error('replication rebase failed');
			}
			realSave2(frame);
		};
		expect(() => h3.journal.prepareForReplication()).to.throw(
			/replication rebase failed/
		);
		const after = commitPreimage(h3.manager, 47);
		expect(after.committed, 'the next append commits').to.equal(true);
		const chain = h3.journal.loadVerifiedFrames();
		expect(
			chain[chain.length - 1].snapshot,
			'and it re-based with a snapshot, not a drift-blind delta'
		).to.not.equal(undefined);
		s2.close();
	});

	it('binds the frame epoch: missing and regressed records refuse', () => {
		// Missing after epoch 2 was observed.
		const s1 = openStorage();
		s1.setRecoveryMeta!('journal_writer_epoch', '2');
		const h1 = makeJournaledManager(s1);
		expect(commitPreimage(h1.manager, 50).committed).to.equal(true);
		s1.deleteRecoveryMeta!('journal_writer_epoch');
		const missing = commitPreimage(h1.manager, 51);
		expect(missing.committed, 'missing epoch refused').to.equal(false);
		expect(String(missing.error?.message)).to.match(/epoch record is missing/);
		s1.close();

		// Regressed below the observed floor.
		const s2 = openStorage();
		s2.setRecoveryMeta!('journal_writer_epoch', '2');
		const h2 = makeJournaledManager(s2);
		expect(commitPreimage(h2.manager, 52).committed).to.equal(true);
		s2.setRecoveryMeta!('journal_writer_epoch', '1');
		const regressed = commitPreimage(h2.manager, 53);
		expect(regressed.committed, 'regressed epoch refused').to.equal(false);
		expect(String(regressed.error?.message)).to.match(/epoch regressed/);
		s2.close();
	});

	it('binds the frame epoch to the ACTIVE lease when one is injected', () => {
		const storage = openStorage();
		storage.setRecoveryMeta!('journal_writer_epoch', '1');
		let leaseEpoch: bigint | null = 1n;
		const journal = new RecoveryJournal(
			storage,
			MASTER_KEY,
			NODE_ID,
			RECOVERY_ID,
			{ activeLeaseEpoch: (): bigint | null => leaseEpoch }
		);
		const manager = new RecoveryManager(storage, { journal });
		expect(commitPreimage(manager, 54).committed).to.equal(true);
		// The lease advances (a takeover granted epoch 2) but the journal
		// record was not updated: the mismatch refuses the write.
		leaseEpoch = 2n;
		const mismatch = commitPreimage(manager, 55);
		expect(mismatch.committed, 'lease mismatch refused').to.equal(false);
		expect(String(mismatch.error?.message)).to.match(
			/does not match the active lease epoch/
		);
		storage.close();
	});

	it('refuses a replication watermark raised above the journal tip', () => {
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 56).committed).to.equal(true);
		storage.setRecoveryMeta!('guardian_replicated_through', '999');
		const result = commitPreimage(manager, 57);
		expect(result.committed, 'the raised watermark refused').to.equal(false);
		expect(String(result.error?.message)).to.match(
			/watermark.*exceeds the journal tip/
		);
		storage.close();
	});

	it('detects interior frame deletion, not just a damaged tip', () => {
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 58).committed).to.equal(true);
		expect(commitPreimage(manager, 59).committed).to.equal(true);
		expect(commitPreimage(manager, 60).committed).to.equal(true);
		sql(storage)
			.prepare('DELETE FROM recovery_frames WHERE sequence = 2')
			.run();
		const result = commitPreimage(manager, 61);
		expect(result.committed, 'the interior gap refused').to.equal(false);
		expect(String(result.error?.message)).to.match(
			/do not match the recorded tip/
		);
		storage.close();
	});

	it('validates pre-frame metadata VALUES, not only keys', () => {
		for (const bad of ['', '9', 'garbage']) {
			const storage = openStorage();
			storage.setRecoveryMeta!('startup_repair_tail', bad);
			const result = commitPreimage(makeJournaledManager(storage).manager, 62);
			expect(result.committed, `tail ${JSON.stringify(bad)} refused`).to.equal(
				false
			);
			expect(String(result.error?.message)).to.match(/illegitimate value/);
			storage.close();
		}
		// The bare sentinel is the ONE legitimate pre-frame shape.
		const ok = openStorage();
		ok.setRecoveryMeta!('startup_repair_tail', 'owed');
		expect(
			commitPreimage(makeJournaledManager(ok).manager, 63).committed,
			'the owed sentinel is allowed'
		).to.equal(true);
		ok.close();
	});
});

describe('Recovery phase 2: round-16 complete invariants', () => {
	const sql = (
		storage: SqliteStorage
	): {
		prepare(q: string): {
			run(...args: unknown[]): unknown;
			get(...args: unknown[]): unknown;
		};
	} =>
		(
			storage as unknown as {
				db: {
					prepare(q: string): {
						run(...args: unknown[]): unknown;
						get(...args: unknown[]): unknown;
					};
				};
			}
		).db;

	function commitPreimage(
		manager: RecoveryManager,
		fill: number
	): ReturnType<RecoveryManager['commit']> {
		return manager.commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, fill).toString('hex'),
					preimage: Buffer.alloc(32, fill)
				}
			],
			outboundMessages: []
		});
	}

	it('a rollback never un-observes durable state', () => {
		// The failed attempt OBSERVED durable tip 1 before writing; rolling
		// its floors back must not forget that, or deleting the journal
		// afterwards would let the retry restart at frame 1.
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 70).committed).to.equal(true);
		const realSave = storage.saveRecoveryFrame!.bind(storage);
		let failNext = true;
		storage.saveRecoveryFrame = (frame): void => {
			if (failNext) {
				failNext = false;
				throw new Error('disk hiccup');
			}
			realSave(frame);
		};
		expect(commitPreimage(manager, 71).committed).to.equal(false);
		sql(storage).prepare('DELETE FROM recovery_frames').run();
		for (const key of storage.listRecoveryMetaKeys!()) {
			storage.deleteRecoveryMeta!(key);
		}
		const retry = commitPreimage(manager, 72);
		expect(retry.committed, 'the emptied store is refused').to.equal(false);
		expect(String(retry.error?.message)).to.match(
			/disappeared|changed outside this writer/
		);
		expect(storage.loadRecoveryFrames!()).to.have.length(0);
		storage.close();
	});

	it('journaled writes refuse to join an outer storage transaction', () => {
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 73).committed).to.equal(true);
		let inner: ReturnType<RecoveryManager['commit']> | null = null;
		withStorageTransaction(storage, () => {
			inner = commitPreimage(manager, 74);
		});
		expect(inner!.committed, 'the joined commit is refused').to.equal(false);
		expect(String(inner!.error?.message)).to.match(/cannot join an outer/);
		expect(
			storage.loadRecoveryFrames!(),
			'nothing was written under the outer transaction'
		).to.have.length(1);
		// The journal-owned paths refuse too.
		const fresh = makeJournaledManager(storage).journal;
		expect(() =>
			withStorageTransaction(storage, () => fresh.prepareForReplication())
		).to.throw(/cannot run inside an outer storage transaction/);
		// And a normal commit afterwards still works.
		expect(commitPreimage(manager, 75).committed).to.equal(true);
		storage.close();
	});

	it('detects a deleted retained prefix and a corrupted tip on the next write', () => {
		// Prefix deletion: [1,2,3] -> [2,3] passes bare count-vs-span
		// arithmetic but not the VERIFIED minimum.
		const s1 = openStorage();
		const m1 = makeJournaledManager(s1);
		expect(commitPreimage(m1.manager, 76).committed).to.equal(true);
		expect(commitPreimage(m1.manager, 77).committed).to.equal(true);
		expect(commitPreimage(m1.manager, 78).committed).to.equal(true);
		sql(s1).prepare('DELETE FROM recovery_frames WHERE sequence = 1').run();
		const r1 = commitPreimage(m1.manager, 79);
		expect(r1.committed, 'deleted prefix refused').to.equal(false);
		expect(String(r1.error?.message)).to.match(/do not match the recorded tip/);
		s1.close();

		// Corrupted tip ciphertext (replaced wholesale; UPDATEs are blocked
		// at the storage layer): refused by per-write authentication.
		const s2 = openStorage();
		const m2 = makeJournaledManager(s2);
		expect(commitPreimage(m2.manager, 80).committed).to.equal(true);
		const full = sql(s2)
			.prepare('SELECT * FROM recovery_frames WHERE sequence = 1')
			.get() as Record<string, unknown>;
		sql(s2).prepare('DELETE FROM recovery_frames WHERE sequence = 1').run();
		sql(s2)
			.prepare(
				'INSERT INTO recovery_frames (sequence, writer_epoch, frame_hash, previous_hash, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)'
			)
			.run(
				full.sequence,
				full.writer_epoch,
				full.frame_hash,
				full.previous_hash,
				Buffer.alloc(64),
				full.created_at
			);
		const r2 = commitPreimage(m2.manager, 81);
		expect(r2.committed, 'corrupt tip refused').to.equal(false);
		expect(String(r2.error?.message)).to.match(/fails authentication/);
		s2.close();

		// And in-place mutation is refused AT the storage layer.
		const s3 = openStorage();
		const m3 = makeJournaledManager(s3);
		expect(commitPreimage(m3.manager, 82).committed).to.equal(true);
		expect(() =>
			sql(s3)
				.prepare(
					'UPDATE recovery_frames SET ciphertext = zeroblob(8) WHERE sequence = 1'
				)
				.run()
		).to.throw(/append-only/);
		s3.close();
	});

	it('derives the epoch floor from the verified chain itself', () => {
		// Frames written under epoch 2; then BOTH the epoch record and any
		// lease disappear. A fresh journal must refuse to default to epoch
		// 1 and compact the epoch-2 history away.
		const storage = openStorage();
		storage.setRecoveryMeta!('journal_writer_epoch', '2');
		const first = makeJournaledManager(storage);
		expect(commitPreimage(first.manager, 83).committed).to.equal(true);
		storage.deleteRecoveryMeta!('journal_writer_epoch');
		const fresh = makeJournaledManager(storage);
		const result = commitPreimage(fresh.manager, 84);
		expect(result.committed, 'the epoch-less rebase refused').to.equal(false);
		expect(String(result.error?.message)).to.match(
			/epoch record is missing|below the verified chain/
		);
		const rows = storage.loadRecoveryFrames!();
		expect(
			rows.every((row) => row.writerEpoch === 2),
			'the epoch-2 history survives untouched'
		).to.equal(true);
		storage.close();
	});

	it('binds the replication watermark to the receipted history', () => {
		const storage = openStorage();
		const { manager } = makeJournaledManager(storage);
		expect(commitPreimage(manager, 85).committed).to.equal(true);
		expect(commitPreimage(manager, 86).committed).to.equal(true);
		const frame2 = storage.loadRecoveryFrames!(1)[0];
		storage.setRecoveryMeta!('guardian_replicated_through', '2');
		storage.setRecoveryMeta!(
			'guardian_replicated_through_hash',
			frame2.frameHash.toString('hex')
		);
		expect(
			commitPreimage(manager, 87).committed,
			'a correctly bound watermark passes'
		).to.equal(true);
		// The recorded receipt now names a frame this store does not hold:
		// the receipts belong to a different history.
		storage.setRecoveryMeta!(
			'guardian_replicated_through_hash',
			'cd'.repeat(32)
		);
		const result = commitPreimage(manager, 88);
		expect(result.committed, 'the divergent history refused').to.equal(false);
		expect(String(result.error?.message)).to.match(
			/is not the receipted frame/
		);
		storage.close();
	});

	it('validates pre-frame artifacts with their real shapes', () => {
		const storage = openStorage();
		storage.setRecoveryMeta!('writer_lease_v1', 'not json at all');
		const result = commitPreimage(makeJournaledManager(storage).manager, 89);
		expect(result.committed, 'a non-JSON lease refused').to.equal(false);
		expect(String(result.error?.message)).to.match(/illegitimate value/);
		storage.close();
	});
});

describe('Recovery phase 2: round-17 watermark anchoring', () => {
	function commitPreimage(
		manager: RecoveryManager,
		fill: number
	): ReturnType<RecoveryManager['commit']> {
		return manager.commit({
			criticality: RecoveryCriticality.Important,
			mutations: [
				{
					type: 'payment_preimage',
					paymentHash: Buffer.alloc(32, fill).toString('hex'),
					preimage: Buffer.alloc(32, fill)
				}
			],
			outboundMessages: []
		});
	}

	/**
	 * A journal whose compaction floor tracks a test-controlled watermark,
	 * with a short snapshot cadence so pruning is reachable in a few commits.
	 */
	function compactableJournal(watermark: () => bigint): {
		storage: SqliteStorage;
		journal: RecoveryJournal;
		manager: RecoveryManager;
	} {
		const storage = openStorage();
		const journal = new RecoveryJournal(
			storage,
			MASTER_KEY,
			NODE_ID,
			RECOVERY_ID,
			{
				snapshotIntervalFrames: 2,
				retainFrom: (): bigint => watermark() + 1n
			}
		);
		return {
			storage,
			journal,
			manager: new RecoveryManager(storage, { journal })
		};
	}

	/** Commit frames, then bind and prune at watermark = base - 1. */
	function compactedFixture(hash?: string): {
		storage: SqliteStorage;
		manager: RecoveryManager;
		base: bigint;
		receiptedHash: string;
	} {
		let watermark = 0n;
		const fixture = compactableJournal(() => watermark);
		for (let i = 0; i < 6; i++) {
			expect(commitPreimage(fixture.manager, 100 + i).committed).to.equal(true);
		}
		const base = BigInt(
			fixture.storage.getRecoveryMeta!(JOURNAL_META_KEYS.lastSnapshotWritten)!
		);
		expect(base > 2n, 'a snapshot above frame 2 exists').to.equal(true);
		watermark = base - 1n;
		const receipted = fixture.storage.loadRecoveryFrames!(
			Number(watermark) - 1
		)[0];
		expect(BigInt(receipted.sequence)).to.equal(watermark);
		const receiptedHash = receipted.frameHash.toString('hex');
		fixture.storage.setRecoveryMeta!(
			META_REPLICATED_THROUGH,
			watermark.toString()
		);
		fixture.storage.setRecoveryMeta!(
			META_REPLICATED_THROUGH_HASH,
			hash ?? receiptedHash
		);
		fixture.journal.compact();
		const retained = fixture.storage.loadRecoveryFrames!();
		expect(
			BigInt(retained[0].sequence),
			'the receipted frame was pruned beneath the base snapshot'
		).to.equal(base);
		return {
			storage: fixture.storage,
			manager: fixture.manager,
			base,
			receiptedHash
		};
	}

	it('a compacted watermark stays bound through the retained base snapshot', () => {
		const { storage, manager, base, receiptedHash } = compactedFixture();
		// The anchor resolves through the base snapshot's previousFrameHash,
		// which names exactly the pruned frame.
		const anchor = resolveWatermarkAnchor(storage, base - 1n);
		expect(anchor?.toString('hex')).to.equal(receiptedHash);
		expect(
			commitPreimage(manager, 110).committed,
			'a correctly bound compacted watermark passes the write gate'
		).to.equal(true);
		storage.close();
	});

	it('a compacted watermark bound to a foreign history is refused', () => {
		// A receipt for a DIFFERENT chain at the same height: once the frame
		// is compacted, only the base snapshot can expose the divergence.
		const { storage, manager } = compactedFixture('cd'.repeat(32));
		const result = commitPreimage(manager, 111);
		expect(result.committed, 'the divergent history refused').to.equal(false);
		expect(String(result.error?.message)).to.match(
			/is not the receipted frame/
		);
		storage.close();
	});

	it('a watermark below the retained base minus one resolves nowhere and is refused', () => {
		const { storage, manager } = compactedFixture();
		// Neither the frame at 1 nor a base snapshot at 2 survives, so no
		// anchor exists and the binding must fail closed.
		storage.setRecoveryMeta!(META_REPLICATED_THROUGH, '1');
		storage.setRecoveryMeta!(META_REPLICATED_THROUGH_HASH, 'ab'.repeat(32));
		const result = commitPreimage(manager, 112);
		expect(result.committed, 'the unanchorable watermark refused').to.equal(
			false
		);
		expect(String(result.error?.message)).to.match(
			/is not the receipted frame/
		);
		storage.close();
	});

	it('a forced prune past the watermark RESETS the mark and records the loss', () => {
		const storage = openStorage();
		const journal = new RecoveryJournal(
			storage,
			MASTER_KEY,
			NODE_ID,
			RECOVERY_ID,
			{
				snapshotIntervalFrames: 2,
				maxRetainedFrameGap: 3,
				retainFrom: (): bigint => 2n
			}
		);
		const manager = new RecoveryManager(storage, { journal });
		expect(commitPreimage(manager, 120).committed).to.equal(true);
		const frame1 = storage.loadRecoveryFrames!()[0];
		storage.setRecoveryMeta!(META_REPLICATED_THROUGH, '1');
		storage.setRecoveryMeta!(
			META_REPLICATED_THROUGH_HASH,
			frame1.frameHash.toString('hex')
		);
		for (let i = 1; i < 10; i++) {
			expect(commitPreimage(manager, 120 + i).committed).to.equal(true);
		}
		// The prune destroyed the anchor: the mark was reset WITH its hash
		// (a bare positive height resolvable by nothing must not linger),
		// and the loss is recorded durably.
		expect(
			storage.loadRecoveryFrames!()[0].sequence,
			'frames below the forced snapshot are gone'
		).to.be.greaterThan(2);
		expect(storage.getRecoveryMeta!(META_REPLICATED_THROUGH)).to.equal(null);
		expect(storage.getRecoveryMeta!(META_REPLICATED_THROUGH_HASH)).to.equal(
			null
		);
		expect(storage.getRecoveryMeta!(JOURNAL_META_KEYS.backfillLost)).to.be.a(
			'string'
		);
		expect(
			commitPreimage(manager, 130).committed,
			'the journal keeps writing after the reset'
		).to.equal(true);
		storage.close();
	});
});
