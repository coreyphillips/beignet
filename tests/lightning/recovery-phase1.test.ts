/**
 * Recovery Protocol phase 1: safety transitions + durable outbox.
 * docs/RECOVERY-PROTOCOL.md sections 5.1, 5.2 and 9.
 *
 * Tests cover:
 * 1. recovery_outbox storage: round trip, disposition, delete by type, prune
 * 2. RecoveryManager atomicity: a throw mid-transition leaves NOTHING visible
 * 3. A failed transition releases no messages (persist before send)
 * 4. persistChannel commits state + key index + monitor as one unit
 * 5. Staged mutations ride in the channel's transaction
 * 6. Structural persist-before-send: the DB write precedes the socket write
 * 7. A failed persist withholds the sends it authorized
 * 8. Outbox rows are written for a real commitment round and superseded on
 *    the peer's revoke_and_ack
 * 9. Exact retransmission bytes survive a restart (the taproot D2 case)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	RecoveryManager,
	RecoveryCriticality
} from '../../src/lightning/recovery';
import { Channel } from '../../src/lightning/channel/channel';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { Network } from '../../src/lightning/invoice/types';
import { INodeConfig } from '../../src/lightning/node/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	BITCOIN_CHAIN_HASH,
	ChannelState
} from '../../src/lightning/channel/types';
import {
	IChannelState,
	createOpenerState
} from '../../src/lightning/channel/channel-state';
import { MessageType } from '../../src/lightning/message/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	IChannelAnnouncementMessage,
	IChannelUpdateMessage,
	encodeShortChannelId
} from '../../src/lightning/gossip/types';

// ─────────────── Fixtures ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(`recovery-phase1-seed-${id}`)
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

function makeNodeConfig(
	seedId: number,
	storage?: IStorageBackend
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		storage
	};
}

function createNode(seedId: number, storage?: IStorageBackend): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId, storage));
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on('message:outbound', (pubkey: string, type: number, p: Buffer) => {
		if (pubkey === nodeB.getNodeId()) {
			nodeB.handlePeerMessage(nodeA.getNodeId(), type, p);
		}
	});
	nodeB.on('message:outbound', (pubkey: string, type: number, p: Buffer) => {
		if (pubkey === nodeA.getNodeId()) {
			nodeA.handlePeerMessage(nodeB.getNodeId(), type, p);
		}
	});
}

function openReadyChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const channelId = alice.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

function buildDirectGraph(alice: LightningNode): void {
	const alicePubkey = getPublicKey(makeNodeConfig(1).nodePrivateKey);
	const bobPubkey = getPublicKey(makeNodeConfig(2).nodePrivateKey);
	const scid = encodeShortChannelId({ block: 500, txIndex: 1, outputIndex: 0 });
	const aliceIsNode1 = Buffer.compare(alicePubkey, bobPubkey) < 0;
	const announcement: IChannelAnnouncementMessage = {
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: aliceIsNode1 ? alicePubkey : bobPubkey,
		nodeId2: aliceIsNode1 ? bobPubkey : alicePubkey,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	};
	alice.getGraph().addChannelAnnouncement(announcement);

	const update: IChannelUpdateMessage = {
		signature: Buffer.alloc(64),
		chainHash: BITCOIN_CHAIN_HASH,
		shortChannelId: scid,
		timestamp: Math.floor(Date.now() / 1000),
		messageFlags: 1,
		channelFlags: 0,
		cltvExpiryDelta: 40,
		htlcMinimumMsat: 1000n,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 1,
		htlcMaximumMsat: 1_000_000_000n
	};
	alice.getGraph().applyChannelUpdate(update);
	alice.getGraph().applyChannelUpdate({ ...update, channelFlags: 1 });

	alice.registerChannelScid(
		alice.getChannelManager().listChannels()[0].getChannelId()!,
		scid
	);
}

/** Storage wrapper that fails one named method, to crash a transition. */
function failingStorage(
	inner: IStorageBackend,
	method: keyof IStorageBackend,
	message = 'disk on fire'
): IStorageBackend {
	return new Proxy(inner, {
		get(target, prop, receiver): unknown {
			if (prop === method) {
				return (): never => {
					throw new Error(message);
				};
			}
			const value = Reflect.get(target, prop, receiver);
			return typeof value === 'function' ? value.bind(target) : value;
		}
	}) as IStorageBackend;
}

/** A realistic NORMAL-state channel, the shape the serializer expects. */
function makeChannelState(channelId?: Buffer): IChannelState {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 1_000_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(makeSeed(1)),
		localPerCommitmentSeed: makeSeed(3)
	});
	state.state = ChannelState.NORMAL;
	state.channelId = channelId ?? crypto.randomBytes(32);
	state.fundingTxid = crypto.randomBytes(32);
	state.fundingOutputIndex = 0;
	state.localBalanceMsat = 800_000_000n;
	state.remoteBalanceMsat = 200_000_000n;
	state.remoteBasepoints = makeBasepoints(makeSeed(2));
	state.remoteCurrentPerCommitmentPoint =
		state.remoteBasepoints.firstPerCommitmentPoint;
	return state;
}

// ─────────────── 1. Outbox storage ───────────────

describe('Recovery phase 1: recovery_outbox storage', () => {
	let storage: SqliteStorage;

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});
	afterEach(() => storage.close());

	it('schema is at the version that introduces the outbox', () => {
		expect(SqliteStorage.CURRENT_SCHEMA_VERSION).to.be.at.least(12);
		expect(storage.getSchemaVersion()).to.equal(
			SqliteStorage.CURRENT_SCHEMA_VERSION
		);
	});

	it('round trips a row with its exact wire bytes', () => {
		const wire = crypto.randomBytes(120);
		const id = storage.saveOutboxMessage({
			peerId: 'aa'.repeat(33),
			channelId: 'bb'.repeat(32),
			messageType: MessageType.COMMITMENT_SIGNED,
			wireMessage: wire,
			disposition: 'pending_send'
		});
		expect(id).to.be.greaterThan(0);

		const rows = storage.loadOutboxMessages('bb'.repeat(32));
		expect(rows).to.have.length(1);
		expect(rows[0].wireMessage.equals(wire)).to.equal(true);
		expect(rows[0].messageType).to.equal(MessageType.COMMITMENT_SIGNED);
		expect(rows[0].disposition).to.equal('pending_send');
		expect(rows[0].frameSequence).to.equal(null);
	});

	it('advances a disposition and deletes by message type', () => {
		const channelId = 'cc'.repeat(32);
		const id = storage.saveOutboxMessage({
			peerId: 'aa'.repeat(33),
			channelId,
			messageType: MessageType.COMMITMENT_SIGNED,
			wireMessage: Buffer.from([1, 2, 3]),
			disposition: 'pending_send'
		});
		storage.saveOutboxMessage({
			peerId: 'aa'.repeat(33),
			channelId,
			messageType: MessageType.REVOKE_AND_ACK,
			wireMessage: Buffer.from([4, 5, 6]),
			disposition: 'pending_send'
		});

		storage.setOutboxDisposition(id, 'sent_unacked');
		expect(storage.loadOutboxMessages(channelId)[0].disposition).to.equal(
			'sent_unacked'
		);

		// Only the commitment is superseded; our own revoke_and_ack survives.
		storage.deleteOutboxMessages(channelId, [MessageType.COMMITMENT_SIGNED]);
		const left = storage.loadOutboxMessages(channelId);
		expect(left).to.have.length(1);
		expect(left[0].messageType).to.equal(MessageType.REVOKE_AND_ACK);
	});

	it('prunes to the newest rows, keeping the most recent bytes', () => {
		const channelId = 'dd'.repeat(32);
		for (let i = 0; i < 10; i++) {
			storage.saveOutboxMessage({
				peerId: 'aa'.repeat(33),
				channelId,
				messageType: MessageType.UPDATE_ADD_HTLC,
				wireMessage: Buffer.from([i]),
				disposition: 'pending_send'
			});
		}
		storage.pruneOutboxMessages(channelId, 3);
		const rows = storage.loadOutboxMessages(channelId);
		expect(rows).to.have.length(3);
		expect(rows.map((r) => r.wireMessage[0])).to.deep.equal([7, 8, 9]);
	});

	it('drops a channel outbox when the channel is deleted', () => {
		const channelId = 'ee'.repeat(32);
		storage.saveChannel(channelId, makeChannelState(Buffer.alloc(32)), 'ff');
		storage.saveOutboxMessage({
			peerId: 'aa'.repeat(33),
			channelId,
			messageType: MessageType.COMMITMENT_SIGNED,
			wireMessage: Buffer.from([9]),
			disposition: 'sent_unacked'
		});
		storage.deleteChannel(channelId);
		expect(storage.loadOutboxMessages(channelId)).to.have.length(0);
	});
});

// ─────────────── 2-3. Transition atomicity ───────────────

describe('Recovery phase 1: safety transition atomicity', () => {
	let storage: SqliteStorage;

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});
	afterEach(() => storage.close());

	it('commits every mutation plus its outbox rows as one unit', () => {
		const manager = new RecoveryManager(storage);
		const channelId = '11'.repeat(32);
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'channel_state',
					channelId,
					state: makeChannelState(Buffer.alloc(32)),
					peerPubkey: 'aa'.repeat(33)
				},
				{ type: 'channel_key_index', channelId, channelIndex: 7 },
				{
					type: 'payment_preimage',
					paymentHash: '22'.repeat(32),
					preimage: Buffer.alloc(32, 3)
				}
			],
			outboundMessages: [
				{
					peerId: 'aa'.repeat(33),
					channelId,
					messageType: MessageType.COMMITMENT_SIGNED,
					wireMessage: Buffer.from([1, 2, 3, 4]),
					disposition: 'pending_send'
				}
			]
		});

		expect(result.committed).to.equal(true);
		expect(result.released).to.have.length(1);
		expect(result.released[0].id).to.be.a('number');
		expect(storage.loadChannelKeyIndex(channelId)).to.equal(7);
		expect(storage.loadPreimage('22'.repeat(32))).to.not.equal(null);
		expect(storage.loadOutboxMessages(channelId)).to.have.length(1);
	});

	it('a throw mid-transition leaves NOTHING visible (all or nothing)', () => {
		const channelId = '33'.repeat(32);
		// Seed a committed baseline so we can prove the failed transition did
		// not partially overwrite it.
		storage.saveChannel(
			channelId,
			makeChannelState(Buffer.alloc(32)),
			'baseline'
		);

		const manager = new RecoveryManager(
			failingStorage(storage, 'saveChannelKeyIndex')
		);
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'channel_state',
					channelId,
					state: makeChannelState(Buffer.alloc(32, 9)),
					peerPubkey: 'updated'
				},
				// Throws here, AFTER the channel write inside the same transaction.
				{ type: 'channel_key_index', channelId, channelIndex: 42 },
				{
					type: 'payment_preimage',
					paymentHash: '44'.repeat(32),
					preimage: Buffer.alloc(32, 5)
				}
			],
			outboundMessages: [
				{
					peerId: 'aa'.repeat(33),
					channelId,
					messageType: MessageType.COMMITMENT_SIGNED,
					wireMessage: Buffer.from([7]),
					disposition: 'pending_send'
				}
			]
		});

		expect(result.committed).to.equal(false);
		expect(result.error).to.be.an('error');
		// The channel write rolled back to the baseline peer.
		expect(storage.loadChannel(channelId)!.peerPubkey).to.equal('baseline');
		expect(storage.loadChannelKeyIndex(channelId)).to.equal(null);
		expect(storage.loadPreimage('44'.repeat(32))).to.equal(null);
		expect(storage.loadOutboxMessages(channelId)).to.have.length(0);
	});

	it('releases NO message when the transition failed', () => {
		const manager = new RecoveryManager(failingStorage(storage, 'saveChannel'));
		const result = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'channel_state',
					channelId: '55'.repeat(32),
					state: makeChannelState(Buffer.alloc(32)),
					peerPubkey: 'aa'.repeat(33)
				}
			],
			outboundMessages: [
				{
					peerId: 'aa'.repeat(33),
					channelId: '55'.repeat(32),
					messageType: MessageType.REVOKE_AND_ACK,
					wireMessage: Buffer.from([8]),
					disposition: 'pending_send'
				}
			]
		});
		expect(result.committed).to.equal(false);
		expect(result.released).to.have.length(0);
	});

	it('reports the failure through onError without throwing', () => {
		const seen: Error[] = [];
		const manager = new RecoveryManager(
			failingStorage(storage, 'saveChannel'),
			{ onError: (err): number => seen.push(err) }
		);
		expect(() =>
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [
					{
						type: 'channel_state',
						channelId: '66'.repeat(32),
						state: makeChannelState(Buffer.alloc(32)),
						peerPubkey: 'aa'.repeat(33)
					}
				],
				outboundMessages: []
			})
		).to.not.throw();
		expect(seen).to.have.length(1);
	});

	it('supersedes a channel outbox by message type', () => {
		const manager = new RecoveryManager(storage);
		const channelId = '77'.repeat(32);
		for (const messageType of [
			MessageType.COMMITMENT_SIGNED,
			MessageType.REVOKE_AND_ACK
		]) {
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [],
				outboundMessages: [
					{
						peerId: 'aa'.repeat(33),
						channelId,
						messageType,
						wireMessage: Buffer.from([messageType]),
						disposition: 'pending_send'
					}
				]
			});
		}
		manager.supersedeChannelOutbox(channelId, [MessageType.COMMITMENT_SIGNED]);
		const rows = manager.getOutbox(channelId);
		expect(rows).to.have.length(1);
		expect(rows[0].messageType).to.equal(MessageType.REVOKE_AND_ACK);
	});
});

// ─────────────── 4-5. Node-level atomicity ───────────────

describe('Recovery phase 1: node persistence is one transaction', () => {
	it('persists channel state and key index together or not at all', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const guarded = failingStorage(storage, 'saveChannelKeyIndex');
		const alice = createNode(1, guarded);
		const bob = createNode(2);
		connectNodes(alice, bob);

		openReadyChannel(alice, bob);

		// Every persist attempt failed on the key index, so the channel row must
		// not exist either: a channel restored without its key index signs its
		// force-close with the wrong key.
		expect(storage.loadAllChannels()).to.have.length(0);

		alice.destroy();
		bob.destroy();
		storage.close();
	});

	it('a persisted channel carries its key index', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(1, storage);
		const bob = createNode(2);
		connectNodes(alice, bob);

		const channelId = openReadyChannel(alice, bob);
		const idHex = channelId.toString('hex');
		expect(storage.loadChannel(idHex)).to.not.equal(null);
		expect(storage.loadChannelKeyIndex(idHex)).to.not.equal(null);

		alice.destroy();
		bob.destroy();
		storage.close();
	});
});

// ─────────────── 6-8. Persist before send, end to end ───────────────

describe('Recovery phase 1: persist before send', () => {
	it('writes channel state to disk BEFORE the message reaches the wire', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();

		const sequence: string[] = [];
		const observed = new Proxy(storage, {
			get(target, prop, receiver): unknown {
				const value = Reflect.get(target, prop, receiver);
				if (prop === 'saveChannel') {
					return (...args: unknown[]): unknown => {
						sequence.push('persist');
						return (value as (...a: unknown[]) => unknown).apply(target, args);
					};
				}
				return typeof value === 'function' ? value.bind(target) : value;
			}
		}) as IStorageBackend;

		const alice = createNode(1, observed);
		const bob = createNode(2);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		buildDirectGraph(alice);

		sequence.length = 0;
		alice.on('message:outbound', (_pubkey: string, type: number) => {
			if (type === MessageType.UPDATE_ADD_HTLC) sequence.push('send');
		});

		const invoice = bob.createInvoice({
			amountMsat: 10_000n,
			description: 'persist-before-send'
		});
		alice.sendPayment(invoice.bolt11);

		const firstSend = sequence.indexOf('send');
		expect(firstSend, 'an update_add_htlc was sent').to.be.greaterThan(-1);
		expect(
			sequence.indexOf('persist'),
			'state persisted before the HTLC hit the wire'
		)
			.to.be.greaterThan(-1)
			.and.to.be.lessThan(firstSend);

		expect(channelId).to.be.instanceOf(Buffer);
		alice.destroy();
		bob.destroy();
		storage.close();
	});

	it('withholds the sends a FAILED persist authorized', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();

		const alice = createNode(1, storage);
		const bob = createNode(2);
		connectNodes(alice, bob);
		openReadyChannel(alice, bob);
		buildDirectGraph(alice);

		// Break persistence only now, so the channel is already open: from here
		// no state can reach disk, therefore no HTLC may reach the peer.
		const sent: number[] = [];
		alice.on('message:outbound', (_pubkey: string, type: number) => {
			sent.push(type);
		});
		(
			storage as unknown as { transaction: (fn: () => unknown) => unknown }
		).transaction = (): never => {
			throw new Error('disk on fire');
		};

		const invoice = bob.createInvoice({
			amountMsat: 10_000n,
			description: 'withheld'
		});
		try {
			alice.sendPayment(invoice.bolt11);
		} catch {
			// The payment failing is fine; what matters is what went out.
		}

		expect(
			sent.includes(MessageType.UPDATE_ADD_HTLC),
			'no HTLC on the wire without its state on disk'
		).to.equal(false);

		alice.destroy();
		bob.destroy();
	});

	it('records outbox rows for a commitment round and supersedes them on revoke_and_ack', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(1, storage);
		const bob = createNode(2);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		buildDirectGraph(alice);

		const seenTypes: number[] = [];
		const originalSave = storage.saveOutboxMessage.bind(storage);
		storage.saveOutboxMessage = (message): number => {
			seenTypes.push(message.messageType);
			return originalSave(message);
		};

		const invoice = bob.createInvoice({
			amountMsat: 10_000n,
			description: 'outbox-round'
		});
		alice.sendPayment(invoice.bolt11);

		// The add and the commitment that covers it were both retained.
		expect(seenTypes).to.include(MessageType.UPDATE_ADD_HTLC);
		expect(seenTypes).to.include(MessageType.COMMITMENT_SIGNED);

		// The loopback ran the full round, so the peer's revoke_and_ack has
		// already superseded everything it acknowledges.
		const left = storage
			.loadOutboxMessages(channelId.toString('hex'))
			.map((r) => r.messageType);
		expect(left).to.not.include(MessageType.UPDATE_ADD_HTLC);
		expect(left).to.not.include(MessageType.COMMITMENT_SIGNED);

		alice.destroy();
		bob.destroy();
		storage.close();
	});
});

// ─────────────── 9. Exact retransmission bytes ───────────────

describe('Recovery phase 1: exact retransmission bytes', () => {
	it('restores an un-acked batch from stored bytes without re-signing', () => {
		const startBatch = crypto.randomBytes(40);
		const commitments = [crypto.randomBytes(100), crypto.randomBytes(100)];

		const channel = new Channel(makeChannelState(crypto.randomBytes(32)));
		channel.restoreLastSentBatch(startBatch, commitments);

		const restored = (
			channel as unknown as {
				_lastSentBatch: { startBatch: Buffer; commitments: Buffer[] } | null;
			}
		)._lastSentBatch;
		expect(restored).to.not.equal(null);
		expect(restored!.startBatch.equals(startBatch)).to.equal(true);
		expect(restored!.commitments).to.have.length(2);
		expect(restored!.commitments[0].equals(commitments[0])).to.equal(true);
		expect(restored!.commitments[1].equals(commitments[1])).to.equal(true);
	});

	it('never lets a stored batch overwrite a live one', () => {
		const channel = new Channel(makeChannelState(crypto.randomBytes(32)));
		const live = crypto.randomBytes(40);
		channel.restoreLastSentBatch(live, [crypto.randomBytes(80)]);
		channel.restoreLastSentBatch(crypto.randomBytes(40), [
			crypto.randomBytes(80)
		]);

		const restored = (
			channel as unknown as {
				_lastSentBatch: { startBatch: Buffer } | null;
			}
		)._lastSentBatch;
		expect(restored!.startBatch.equals(live)).to.equal(true);
	});

	it('ignores an empty or half-present batch', () => {
		const channel = new Channel(makeChannelState(crypto.randomBytes(32)));
		channel.restoreLastSentBatch(crypto.randomBytes(40), []);
		const restored = (channel as unknown as { _lastSentBatch: unknown | null })
			._lastSentBatch;
		expect(restored).to.equal(null);
	});
});

// ─────────────── 10. Outbox retention ───────────────

describe('Recovery phase 1: the outbox stays bounded', () => {
	let storage: SqliteStorage;

	beforeEach(() => {
		storage = new SqliteStorage(':memory:');
		storage.open();
	});
	afterEach(() => storage.close());

	it('keeps only the newest row of a type nothing else supersedes', () => {
		const manager = new RecoveryManager(storage);
		const channelId = 'ab'.repeat(32);

		// Three commitment rounds worth of our own revoke_and_ack. No peer
		// message ever proves receipt of these, so without same-kind
		// superseding they would accumulate for the life of the channel.
		for (let i = 0; i < 3; i++) {
			const result = manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [],
				outboundMessages: [
					{
						peerId: 'aa'.repeat(33),
						channelId,
						messageType: MessageType.REVOKE_AND_ACK,
						wireMessage: Buffer.from([i]),
						disposition: 'pending_send'
					}
				]
			});
			expect(result.committed).to.equal(true);
		}

		const rows = storage.loadOutboxMessages(channelId);
		expect(rows).to.have.length(1);
		// The newest is the one a reconnect could ask for.
		expect(rows[0].wireMessage[0]).to.equal(2);
	});

	it('leaves types with a real supersede trigger alone', () => {
		const manager = new RecoveryManager(storage);
		const channelId = 'cd'.repeat(32);
		for (let i = 0; i < 3; i++) {
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [],
				outboundMessages: [
					{
						peerId: 'aa'.repeat(33),
						channelId,
						messageType: MessageType.UPDATE_ADD_HTLC,
						wireMessage: Buffer.from([i]),
						disposition: 'pending_send'
					}
				]
			});
		}
		// All three belong to the round in flight; the peer's revoke_and_ack
		// retires them together.
		expect(storage.loadOutboxMessages(channelId)).to.have.length(3);
	});

	it('counts rows without drifting when the cache is cold', () => {
		const manager = new RecoveryManager(storage, {
			maxOutboxRowsPerChannel: 4
		});
		const channelId = 'ef'.repeat(32);
		for (let i = 0; i < 4; i++) {
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [],
				outboundMessages: [
					{
						peerId: 'aa'.repeat(33),
						channelId,
						messageType: MessageType.UPDATE_ADD_HTLC,
						wireMessage: Buffer.from([i]),
						disposition: 'pending_send'
					}
				]
			});
		}
		// Exactly at the cap, so nothing has been pruned yet: an over-count
		// would have evicted the oldest row early.
		expect(storage.loadOutboxMessages(channelId)).to.have.length(4);
	});
});

// ─────────────── 11. Reconnect retransmission obeys the same gate ────────

describe('Recovery phase 1: reestablish retransmission persists first', () => {
	/** A channel with one un-acked update queued for replay. */
	function channelWithQueuedUpdate(): Channel {
		const state = makeChannelState(crypto.randomBytes(32));
		state.localChannelReady = true;
		state.pendingLocalUpdates = [
			{ type: MessageType.UPDATE_ADD_HTLC, payload: crypto.randomBytes(64) }
		];
		return new Channel(state);
	}

	function reestablishMsg(channelId: Buffer): {
		channelId: Buffer;
		nextCommitmentNumber: bigint;
		nextRevocationNumber: bigint;
		yourLastPerCommitmentSecret: Buffer;
		myCurrentPerCommitmentPoint: Buffer;
	} {
		return {
			channelId,
			nextCommitmentNumber: 1n,
			nextRevocationNumber: 0n,
			yourLastPerCommitmentSecret: Buffer.alloc(32),
			myCurrentPerCommitmentPoint: getPublicKey(makeSeed(9))
		};
	}

	it('puts a persist ahead of everything it retransmits', () => {
		const channel = channelWithQueuedUpdate();
		const actions = channel.handleReestablish(
			reestablishMsg(channel.getChannelId()!)
		);

		const sendIndex = actions.findIndex(
			(a) => a.type === ChannelActionType.SEND_MESSAGE
		);
		expect(sendIndex, 'the reconnect replays something').to.be.greaterThan(-1);
		// Without this the whole reconnect path bypassed the batch gate, so a
		// transition whose commit failed could still reach the peer one
		// connection later.
		expect(actions[0].type).to.equal(ChannelActionType.PERSIST_STATE);
	});

	it('marks replays so they are not written to the outbox again', () => {
		const channel = channelWithQueuedUpdate();
		const actions = channel.handleReestablish(
			reestablishMsg(channel.getChannelId()!)
		);

		const sends = actions.filter(
			(a) => a.type === ChannelActionType.SEND_MESSAGE
		) as Array<{ messageType: number; replay?: boolean }>;
		expect(sends.length).to.be.greaterThan(0);
		for (const send of sends) {
			expect(
				send.replay,
				`replayed ${send.messageType} must not be re-stored`
			).to.equal(true);
		}
	});

	it('adds no persist action when there is nothing to send', () => {
		const state = makeChannelState(crypto.randomBytes(32));
		const channel = new Channel(state);
		const actions = channel.handleReestablish(
			reestablishMsg(channel.getChannelId()!)
		);
		expect(
			actions.some((a) => a.type === ChannelActionType.SEND_MESSAGE)
		).to.equal(false);
		expect(
			actions.some((a) => a.type === ChannelActionType.PERSIST_STATE)
		).to.equal(false);
	});
});

// ─────────────── 12. Failure leaves nothing ahead of the channel ─────────

describe('Recovery phase 1: a failed transition strands nothing on disk', () => {
	it('holds a monitor delta back rather than committing it alone', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		// Channel writes fail; monitor writes would succeed. The monitor delta
		// must NOT slip out on its own, or disk ends up with a revocation whose
		// causing channel state never landed.
		const guarded = failingStorage(storage, 'saveChannel');
		const alice = createNode(1, guarded);
		const bob = createNode(2);
		connectNodes(alice, bob);

		openReadyChannel(alice, bob);

		expect(storage.loadAllChannels()).to.have.length(0);
		expect(storage.loadAllChainMonitors()).to.have.length(0);

		alice.destroy();
		bob.destroy();
		storage.close();
	});

	it('reports one error per failed channel transition, not two', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const guarded = failingStorage(storage, 'saveChannel');
		const node = new LightningNode(makeNodeConfig(1, guarded));
		node.on('error', () => {});
		const errors: string[] = [];
		node.on('node:error', (err: { code: string; message: string }) => {
			if (err.code === 'PERSISTENCE_ERROR') errors.push(err.message);
		});
		const bob = createNode(2);
		connectNodes(node, bob);

		openReadyChannel(node, bob);

		expect(errors.length).to.be.greaterThan(0);
		// Every persistence error carries the channel context; none is the
		// bare duplicate from the manager hook.
		for (const message of errors) {
			expect(message).to.match(/^Failed to persist channel/);
		}

		node.destroy();
		bob.destroy();
		storage.close();
	});
});
