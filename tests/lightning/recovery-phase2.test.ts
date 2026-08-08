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
		expect(String(result.error?.message)).to.match(
			/frame 2 cannot be read by this release/
		);
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
