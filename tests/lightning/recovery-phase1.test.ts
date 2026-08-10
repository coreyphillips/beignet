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
 * 10. One commit per batch: repeated PERSIST_STATE markers do not re-commit
 * 11. A failed persist withholds broadcasts, not just wire messages
 * 12. The revoke supersede rides the persist transaction (rolls back with it)
 * 13. A blocked transition is surfaced so the node can force a reconnect
 * 14. A held-back monitor delta retries as a combined channel+monitor commit
 * 15. Staged mutations survive a failed standalone flush
 * 16. Restart restores the LAST start_batch group from stored rows
 * 17. splice:complete retires the splice negotiation rows
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';
import {
	RecoveryManager,
	RecoveryCriticality,
	RecoveryMutation
} from '../../src/lightning/recovery';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
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
import {
	ChannelAction,
	ChannelActionType,
	IChannelPersistEvent,
	IChannelPersistRequest
} from '../../src/lightning/channel/channel-actions';
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

// ─────────────── 10-11. Batch dispatch invariants ───────────────

describe('Recovery phase 1: batch dispatch invariants', () => {
	function stubChannel(channelId: Buffer): Channel {
		return {
			getChannelId: (): Buffer => channelId,
			getTemporaryChannelId: (): Buffer | null => null,
			getState: (): ChannelState => ChannelState.NORMAL
		} as unknown as Channel;
	}

	function makeManager(): ChannelManager {
		return new ChannelManager(
			{} as unknown as ConstructorParameters<typeof ChannelManager>[0]
		);
	}

	function dispatch(
		manager: ChannelManager,
		channel: Channel,
		actions: ChannelAction[]
	): void {
		(
			manager as unknown as {
				processActions(
					peerPubkey: string,
					channel: Channel,
					actions: ChannelAction[]
				): void;
			}
		).processActions('aa'.repeat(33), channel, actions);
	}

	it('emits ONE persist per batch no matter how many markers it carries', () => {
		// The v2 open and splice signing flows compose helpers that each lead
		// with their own PERSIST_STATE. Channel methods mutate state while
		// BUILDING the action array, so every marker would write identical
		// state; re-emitting used to re-commit the same outbound list per
		// marker and duplicate its outbox rows.
		const manager = makeManager();
		const channel = stubChannel(crypto.randomBytes(32));

		const persists: IChannelPersistRequest[] = [];
		manager.on('channel:persist', ({ request }: IChannelPersistEvent) => {
			if (request) persists.push(request);
		});
		const sent: number[] = [];
		manager.on('message:outbound', (_pk: string, type: number) => {
			sent.push(type);
		});

		dispatch(manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			{
				type: ChannelActionType.SEND_MESSAGE,
				messageType: MessageType.COMMITMENT_SIGNED,
				payload: Buffer.from([1])
			},
			{ type: ChannelActionType.PERSIST_STATE },
			{
				type: ChannelActionType.SEND_MESSAGE,
				messageType: MessageType.UPDATE_ADD_HTLC,
				payload: Buffer.from([2])
			},
			{ type: ChannelActionType.PERSIST_STATE }
		]);

		expect(persists).to.have.length(1);
		// The one commit still covers EVERY send in the batch.
		expect(persists[0].outbound.map((m) => m.messageType)).to.deep.equal([
			MessageType.COMMITMENT_SIGNED,
			MessageType.UPDATE_ADD_HTLC
		]);
		expect(sent).to.deep.equal([
			MessageType.COMMITMENT_SIGNED,
			MessageType.UPDATE_ADD_HTLC
		]);
	});

	it('withholds broadcasts and force-close alongside the sends of a failed persist', () => {
		// The persist-first comments at the splice/funding producers promise the
		// network never sees a tx whose justifying state missed disk; the gate
		// must therefore cover BROADCAST_TX and FORCE_CLOSE, not just wire
		// messages.
		const manager = makeManager();
		const channel = stubChannel(crypto.randomBytes(32));

		manager.on('channel:persist', ({ request }: IChannelPersistEvent) => {
			if (request) request.committed = false;
		});
		const leaked: string[] = [];
		manager.on('message:outbound', () => leaked.push('send'));
		manager.on('broadcast:tx', () => leaked.push('broadcast'));
		manager.on('force:close', () => leaked.push('force-close'));
		const blocked: string[] = [];
		manager.on('transition:blocked', (peerPubkey: string) => {
			blocked.push(peerPubkey);
		});

		dispatch(manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			{
				type: ChannelActionType.SEND_MESSAGE,
				messageType: MessageType.COMMITMENT_SIGNED,
				payload: Buffer.from([1])
			},
			{ type: ChannelActionType.BROADCAST_TX, tx: Buffer.from([2]) },
			{
				type: ChannelActionType.FORCE_CLOSE,
				commitmentTx: Buffer.from([3]),
				channelId: channel.getChannelId()!
			}
		]);

		expect(leaked).to.deep.equal([]);
		// The block is surfaced so the node can force the reconnect that
		// retries the persist and replays the withheld messages.
		expect(blocked).to.deep.equal(['aa'.repeat(33)]);
	});

	it('raises no blocked signal when the persist commits', () => {
		const manager = makeManager();
		const channel = stubChannel(crypto.randomBytes(32));
		manager.on('channel:persist', ({ request }: IChannelPersistEvent) => {
			if (request) request.committed = true;
		});
		let blockedCount = 0;
		manager.on('transition:blocked', () => {
			blockedCount++;
		});
		dispatch(manager, channel, [
			{ type: ChannelActionType.PERSIST_STATE },
			{
				type: ChannelActionType.SEND_MESSAGE,
				messageType: MessageType.REVOKE_AND_ACK,
				payload: Buffer.from([1])
			}
		]);
		expect(blockedCount).to.equal(0);
	});
});

// ─────────────── 12. Supersede rides the persist transaction ───────────────

describe('Recovery phase 1: revoke supersede is transactional', () => {
	it('keeps the outbox rows when the revoke transition fails to commit', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(1, storage);
		const bob = createNode(2);

		// Bridge that breaks alice's storage for exactly the delivery of bob's
		// first revoke_and_ack, then DROPS everything after it: the crashed-
		// after-failed-persist shape. The rows the revoke would have retired
		// must survive, because the state that processed the proof rolled back
		// with the transaction.
		let broke = false;
		const originalTransaction = storage.transaction.bind(storage);
		alice.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk === bob.getNodeId() && !broke) {
				bob.handlePeerMessage(alice.getNodeId(), t, p);
			}
		});
		bob.on('message:outbound', (pk: string, t: number, p: Buffer) => {
			if (pk !== alice.getNodeId() || broke) return;
			if (t === MessageType.REVOKE_AND_ACK) {
				(storage as unknown as { transaction: unknown }).transaction =
					(): never => {
						throw new Error('disk on fire');
					};
				try {
					alice.handlePeerMessage(bob.getNodeId(), t, p);
				} finally {
					(storage as unknown as { transaction: unknown }).transaction =
						originalTransaction;
					broke = true;
				}
				return;
			}
			alice.handlePeerMessage(bob.getNodeId(), t, p);
		});

		const channelId = openReadyChannel(alice, bob);
		buildDirectGraph(alice);

		const invoice = bob.createInvoice({
			amountMsat: 10_000n,
			description: 'supersede-transactional'
		});
		try {
			alice.sendPayment(invoice.bolt11);
		} catch {
			// The stalled payment is expected; the rows are what matters.
		}

		const left = storage
			.loadOutboxMessages(channelId.toString('hex'))
			.map((r) => r.messageType);
		expect(
			left,
			'rows the failed transition would have retired must survive'
		).to.include(MessageType.UPDATE_ADD_HTLC);
		expect(left).to.include(MessageType.COMMITMENT_SIGNED);

		alice.destroy();
		bob.destroy();
		storage.close();
	});

	it('deletes acknowledged rows on commit and never lets the count cache drift', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const channelId = 'cd'.repeat(32);
		const manager = new RecoveryManager(storage);
		const row = (messageType: number): void => {
			manager.commit({
				criticality: RecoveryCriticality.SafetyCritical,
				mutations: [],
				outboundMessages: [
					{
						peerId: 'aa'.repeat(33),
						channelId,
						messageType,
						wireMessage: crypto.randomBytes(60),
						disposition: 'pending_send'
					}
				]
			});
		};
		row(MessageType.COMMITMENT_SIGNED);
		row(MessageType.UPDATE_ADD_HTLC);

		// Success path: the supersede mutation deletes inside the commit.
		const committed = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'outbox_supersede',
					channelId,
					messageTypes: [MessageType.COMMITMENT_SIGNED]
				}
			],
			outboundMessages: []
		});
		expect(committed.committed).to.equal(true);
		expect(
			storage.loadOutboxMessages(channelId).map((r) => r.messageType)
		).to.deep.equal([MessageType.UPDATE_ADD_HTLC]);

		// Rollback path, SAME manager instance: the supersede ran its deletes
		// mid-transaction and reseeded the cached count from the post-delete
		// table, so the rollback must also throw that cache away or the next
		// insert under-counts against the row cap.
		const originalSave = storage.saveChannel.bind(storage);
		(storage as unknown as { saveChannel: unknown }).saveChannel =
			(): never => {
				throw new Error('disk on fire');
			};
		const rolledBack = manager.commit({
			criticality: RecoveryCriticality.SafetyCritical,
			mutations: [
				{
					type: 'outbox_supersede',
					channelId,
					messageTypes: [MessageType.UPDATE_ADD_HTLC]
				},
				{
					type: 'channel_state',
					channelId,
					state: makeChannelState(Buffer.from(channelId, 'hex')),
					peerPubkey: 'aa'.repeat(33)
				}
			],
			outboundMessages: []
		});
		(storage as unknown as { saveChannel: unknown }).saveChannel = originalSave;
		expect(rolledBack.committed).to.equal(false);
		expect(storage.loadOutboxMessages(channelId)).to.have.length(1);

		row(MessageType.UPDATE_FULFILL_HTLC);
		expect(storage.loadOutboxMessages(channelId)).to.have.length(2);
		storage.close();
	});
});

// ─────────────── 13-15. Failure recovery paths ───────────────

describe('Recovery phase 1: failure recovery paths', () => {
	it('retries the latest standalone monitor state after a failed commit', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const node = createNode(1, storage);
		const channelId = crypto.randomBytes(32);
		const idHex = channelId.toString('hex');
		const state = makeChannelState(channelId);
		const monitor = new ChainMonitor(
			state,
			Buffer.concat([Buffer.from([0x00, 0x14]), Buffer.alloc(20, 1)]),
			1,
			makeSeed(20),
			makeSeed(21)
		);
		node.getChannelManager().restoreMonitor(idHex, monitor);

		const internals = node as unknown as {
			dirtyMonitors: Set<string>;
			persistMonitorAlone(idHex: string): void;
		};
		const originalSave = storage.saveChainMonitor.bind(storage);
		let saveAttempts = 0;
		storage.saveChainMonitor = (id, monitorState): void => {
			saveAttempts++;
			if (saveAttempts === 1) throw new Error('disk on fire');
			originalSave(id, monitorState);
		};

		monitor.handleNewBlock(101);
		internals.dirtyMonitors.add(idHex);
		internals.persistMonitorAlone(idHex);

		expect(saveAttempts).to.equal(1);
		expect(storage.loadChainMonitor(idHex)).to.equal(null);
		expect(
			internals.dirtyMonitors.has(idHex),
			'a failed standalone commit remains queued'
		).to.equal(true);

		monitor.handleNewBlock(102);
		internals.persistMonitorAlone(idHex);

		expect(saveAttempts).to.equal(2);
		expect(storage.loadChainMonitor(idHex)?.currentBlockHeight).to.equal(102);
		expect(internals.dirtyMonitors.has(idHex)).to.equal(false);

		node.destroy();
		storage.close();
	});

	it('a held-back monitor delta retries as a combined channel commit', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(1, storage);
		const bob = createNode(2);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		const idHex = channelId.toString('hex');

		// Simulate a transition that failed with its monitor delta on board.
		const internals = alice as unknown as {
			dirtyMonitors: Set<string>;
			monitorsAwaitingChannel: Set<string>;
			persistMonitorAlone(idHex: string): void;
		};
		internals.dirtyMonitors.add(idHex);
		internals.monitorsAwaitingChannel.add(idHex);

		let channelSaves = 0;
		const originalSave = storage.saveChannel.bind(storage);
		storage.saveChannel = (id, state, peer): void => {
			channelSaves++;
			originalSave(id, state, peer);
		};

		// The next standalone monitor attempt (a new block, in production) must
		// retry the COMBINED commit instead of refusing forever.
		internals.persistMonitorAlone(idHex);

		expect(channelSaves, 'channel state rode the retry').to.be.greaterThan(0);
		expect(internals.monitorsAwaitingChannel.has(idHex)).to.equal(false);
		expect(internals.dirtyMonitors.has(idHex)).to.equal(false);

		alice.destroy();
		bob.destroy();
		storage.close();
	});

	it('staged mutations survive a failed standalone flush and commit on retry', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const node = createNode(1, storage);
		const hashHex = 'ab'.repeat(32);

		const internals = node as unknown as {
			stagedMutations: RecoveryMutation[];
			flushStagedMutations(): void;
		};
		internals.stagedMutations.push({
			type: 'payment_preimage',
			paymentHash: hashHex,
			preimage: Buffer.alloc(32, 7)
		});

		const originalTransaction = storage.transaction.bind(storage);
		(storage as unknown as { transaction: unknown }).transaction =
			(): never => {
				throw new Error('disk on fire');
			};
		internals.flushStagedMutations();
		expect(
			internals.stagedMutations,
			'a failed flush re-arms instead of dropping'
		).to.have.length(1);
		expect(storage.loadPreimage(hashHex)).to.equal(null);

		(storage as unknown as { transaction: unknown }).transaction =
			originalTransaction;
		internals.flushStagedMutations();
		expect(internals.stagedMutations).to.have.length(0);
		expect(storage.loadPreimage(hashHex)).to.not.equal(null);

		node.destroy();
		storage.close();
	});

	it('releases the monitor hold when the channel is gone from the manager', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const node = createNode(1, storage);
		const idHex = 'ab'.repeat(32);
		const internals = node as unknown as {
			dirtyMonitors: Set<string>;
			monitorsAwaitingChannel: Set<string>;
			persistMonitorAlone(idHex: string): void;
		};
		internals.dirtyMonitors.add(idHex);
		internals.monitorsAwaitingChannel.add(idHex);

		internals.persistMonitorAlone(idHex);

		// No channel left to pair with is not a reason to park the flag
		// forever: the hold must release rather than survive to block every
		// later monitor write for a reused id.
		expect(internals.monitorsAwaitingChannel.has(idHex)).to.equal(false);

		node.destroy();
		storage.close();
	});
});

// ─────────────── 16-17. Outbox lifecycle end to end ───────────────

describe('Recovery phase 1: outbox lifecycle end to end', () => {
	it('restores the LAST start_batch group from stored rows on restart', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const channelId = crypto.randomBytes(32);
		const idHex = channelId.toString('hex');
		storage.saveChannel(idHex, makeChannelState(channelId), 'aa'.repeat(33));

		const staleBatch = crypto.randomBytes(40);
		const liveBatch = crypto.randomBytes(40);
		const liveCommitments = [crypto.randomBytes(90), crypto.randomBytes(90)];
		const rows: Array<{ messageType: number; wireMessage: Buffer }> = [
			{ messageType: MessageType.START_BATCH, wireMessage: staleBatch },
			{
				messageType: MessageType.COMMITMENT_SIGNED,
				wireMessage: crypto.randomBytes(90)
			},
			{ messageType: MessageType.START_BATCH, wireMessage: liveBatch },
			{
				messageType: MessageType.COMMITMENT_SIGNED,
				wireMessage: liveCommitments[0]
			},
			{
				messageType: MessageType.COMMITMENT_SIGNED,
				wireMessage: liveCommitments[1]
			}
		];
		for (const row of rows) {
			storage.saveOutboxMessage({
				peerId: 'aa'.repeat(33),
				channelId: idHex,
				messageType: row.messageType,
				wireMessage: row.wireMessage,
				disposition: 'sent_unacked'
			});
		}

		// A restart: the node restores channels from storage in its constructor.
		const node = createNode(1, storage);
		const channel = node.getChannelManager().getChannel(channelId);
		expect(channel).to.not.equal(undefined);
		const restored = (
			channel as unknown as {
				_lastSentBatch: { startBatch: Buffer; commitments: Buffer[] } | null;
			}
		)._lastSentBatch;
		expect(restored, 'the un-acked batch came back').to.not.equal(null);
		expect(restored!.startBatch.equals(liveBatch)).to.equal(true);
		expect(restored!.commitments).to.have.length(2);
		expect(restored!.commitments[0].equals(liveCommitments[0])).to.equal(true);
		expect(restored!.commitments[1].equals(liveCommitments[1])).to.equal(true);

		node.destroy();
		storage.close();
	});

	it('splice:complete retires the splice negotiation rows', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const alice = createNode(1, storage);
		const bob = createNode(2);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);
		const idHex = channelId.toString('hex');

		for (const messageType of [
			MessageType.SPLICE,
			MessageType.SPLICE_ACK,
			MessageType.SPLICE_LOCKED
		]) {
			storage.saveOutboxMessage({
				peerId: bob.getNodeId(),
				channelId: idHex,
				messageType,
				wireMessage: Buffer.from([messageType & 0xff]),
				disposition: 'sent_unacked'
			});
		}

		// Nothing else ever retires splice/splice_ack: no revoke acknowledges
		// them, and they never supersede their own kind (one splice at a time).
		alice.getChannelManager().emit('splice:complete', channelId);

		const left = storage.loadOutboxMessages(idHex).map((r) => r.messageType);
		expect(left).to.not.include(MessageType.SPLICE);
		expect(left).to.not.include(MessageType.SPLICE_ACK);
		// splice_locked stays: BOLT 2 can still ask for it after a reconnect.
		expect(left).to.include(MessageType.SPLICE_LOCKED);

		alice.destroy();
		bob.destroy();
		storage.close();
	});

	it('counts rows without loading them', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		const idHex = 'cd'.repeat(32);
		for (let i = 0; i < 5; i++) {
			storage.saveOutboxMessage({
				peerId: 'aa'.repeat(33),
				channelId: idHex,
				messageType: MessageType.UPDATE_ADD_HTLC,
				wireMessage: Buffer.from([i]),
				disposition: 'pending_send'
			});
		}
		expect(storage.countOutboxMessages(idHex)).to.equal(5);
		expect(storage.countOutboxMessages('ef'.repeat(32))).to.equal(0);
		storage.close();
	});
});
