/**
 * Issue #917: the channel key index allocation high-water mark.
 *
 * Issue #906 (PR #914) bounded the index a bare-seed RESTORE may start at.
 * This is the within-device half of the same reuse: an index was recorded
 * durably only when the channel ROW persisted, which is long after
 * accept_channel (or our own open_channel, funding_created, funding_signed)
 * showed the peer that index's funding key, basepoints and first
 * per-commitment point, and never at all for an open the process did not
 * survive. The next boot handed the same index to the next channel, so two
 * channels the same peer holds share a funding key, four basepoints and a
 * per-commitment seed: every commitment of the new one below the old one's
 * head is already revoked in the peer's view, and under taproot two
 * sighashes would be signed with one MuSig2 secnonce.
 *
 * The fix records the index at the moment it is handed out, before any key
 * is derived from it, in a metadata row (`channel_key_index_allocated`)
 * beside #906's floor row, and every later boot starts above
 * max(key-index table, that mark). The record is monotone: a rejected
 * inbound open hands its index back IN MEMORY (#906's release, which keeps
 * a junk-open flood from burning the floor's per-block budget) while the
 * durable mark stays where it was, so a restart leaves a one-index hole in
 * the sequence and never a repeat.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as bip32 from 'bip32';
import * as bip39 from 'bip39';
import * as ecc from '@bitcoinerlab/secp256k1';
import { Channel } from '../../src/lightning/channel/channel';
import {
	CHANNEL_INDEX_FLOOR_STRIDE,
	ChannelManager,
	IChannelManagerConfig,
	IPerChannelKeys
} from '../../src/lightning/channel/channel-manager';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { deriveV2TemporaryChannelId } from '../../src/lightning/channel/validation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import {
	deriveChannelKeys,
	LnCoinType
} from '../../src/lightning/keys/wallet-keys';
import {
	decodeOpenChannelMessage,
	encodeOpenChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	encodeOpenChannel2Message,
	IOpenChannel2Message
} from '../../src/lightning/message/dual-funding';
import { decodeErrorMessage } from '../../src/lightning/message/error';
import { MessageType } from '../../src/lightning/message/types';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IStorageBackend } from '../../src/lightning/storage/types';

const BIP32Factory = bip32.BIP32Factory(ecc);
const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
/** A mainnet-scale height, as #906's fixtures use. */
const TIP = 850_000;
/** Where a birth boot at TIP floors the counter. */
const FLOOR = TIP * CHANNEL_INDEX_FLOOR_STRIDE;
/** Where LightningNode keeps #906's floor row. */
const FLOOR_KEY = 'channel_key_index_floor';
/** Where LightningNode keeps the allocation mark (issue #917). */
const MARK_KEY = 'channel_key_index_allocated';
const LSP_PUBKEY = '02' + 'ab'.repeat(32);
const WALLET_PUBKEY = '03' + 'cd'.repeat(32);
const noop = (): void => {};

// ─── Helpers ───

function makeSeed(tag: string): Buffer {
	return crypto.createHash('sha256').update(`ckiam-${tag}`).digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(derivePrivkey(seed, i));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

/** A deriver whose material actually differs per index. */
function makePerChannelKeys(channelIndex: number): IPerChannelKeys {
	const seed = makeSeed(`per-channel-${channelIndex}`);
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		fundingPrivkey,
		basepoints: {
			...makeBasepoints(seed),
			fundingPubkey: getPublicKey(fundingPrivkey)
		},
		perCommitmentSeed: makeSeed(`pcs-${channelIndex}`),
		htlcBasepointSecret: derivePrivkey(seed, 4)
	};
}

function makeManager(
	tag: string,
	extra: Partial<IChannelManagerConfig> = {}
): ChannelManager {
	const seed = makeSeed(tag);
	const manager = new ChannelManager({
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(`${tag}-pcs`),
		localFundingPrivkey: derivePrivkey(seed, 0),
		htlcBasepointSecret: derivePrivkey(seed, 4),
		chainHash: REGTEST_CHAIN_HASH,
		channelKeyDeriver: makePerChannelKeys,
		...extra
	});
	manager.on('error', noop);
	return manager;
}

/** An open_channel from `opener` to `peer`, captured off the wire. */
function offerOpen(
	opener: ChannelManager,
	peer: string
): { payload: Buffer; tempId: Buffer } {
	let captured: Buffer | null = null;
	const capture = (_peer: string, type: number, payload: Buffer): void => {
		if (type === MessageType.OPEN_CHANNEL) captured = payload;
	};
	opener.on('message:outbound', capture);
	const channel = opener.openChannel(peer, 100_000n);
	opener.off('message:outbound', capture);
	expect(captured, 'captured the open_channel').to.not.equal(null);
	return { payload: captured!, tempId: channel.getTemporaryChannelId() };
}

function makeOpenChannel2(tag: string): IOpenChannel2Message {
	const remoteBp = makeBasepoints(makeSeed(`${tag}-remote`));
	const remoteSeed = makeSeed(`${tag}-remote-pcs`);
	remoteBp.firstPerCommitmentPoint = perCommitmentPointFromSecret(
		generateFromSeed(remoteSeed, MAX_INDEX)
	);
	return {
		chainHash: REGTEST_CHAIN_HASH,
		channelId: deriveV2TemporaryChannelId(remoteBp.revocationBasepoint),
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 500,
		fundingSatoshis: 100_000n,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 100_000_000n,
		htlcMinimumMsat: 1n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 30,
		locktime: 0,
		fundingPubkey: remoteBp.fundingPubkey,
		revocationBasepoint: remoteBp.revocationBasepoint,
		paymentBasepoint: remoteBp.paymentBasepoint,
		delayedPaymentBasepoint: remoteBp.delayedPaymentBasepoint,
		htlcBasepoint: remoteBp.htlcBasepoint,
		firstPerCommitmentPoint: remoteBp.firstPerCommitmentPoint,
		secondPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(remoteSeed, MAX_INDEX - 1n)
		),
		channelFlags: 0x01,
		channelType: Buffer.from('1000', 'hex')
	};
}

function dualFundingParams(
	tag: string
): Parameters<ChannelManager['createDualFundedChannel']>[1] {
	const seed = makeSeed(`${tag}-df-pcs`);
	return {
		fundingSatoshis: 100_000n,
		fundingFeeratePerkw: 1000,
		commitmentFeeratePerkw: 500,
		dustLimitSatoshis: 546n,
		maxHtlcValueInFlightMsat: 100_000_000n,
		htlcMinimumMsat: 1n,
		toSelfDelay: 144,
		maxAcceptedHtlcs: 30,
		locktime: 0,
		localBasepoints: makeBasepoints(makeSeed(`${tag}-df`)),
		localPerCommitmentSeed: seed,
		secondPerCommitmentPoint: perCommitmentPointFromSecret(
			generateFromSeed(seed, MAX_INDEX - 1n)
		)
	};
}

interface IInboundResult {
	wireTypes: number[];
	wireErrors: Array<{ channelId: Buffer; data: string }>;
	errors: string[];
}

/** Feed one inbound message and collect what came back, wire and local. */
function inbound(
	target: ChannelManager,
	from: string,
	type: number,
	payload: Buffer
): IInboundResult {
	const wire: Array<{ type: number; payload: Buffer }> = [];
	const errors: string[] = [];
	const onWire = (_peer: string, t: number, body: Buffer): void => {
		wire.push({ type: t, payload: body });
	};
	const onError = (_id: Buffer | null, message: string): void => {
		errors.push(message);
	};
	target.on('message:outbound', onWire);
	target.on('error', onError);
	target.handleMessage(from, type, payload);
	target.off('message:outbound', onWire);
	target.off('error', onError);
	return {
		wireTypes: wire.map((w) => w.type),
		wireErrors: wire
			.filter((w) => w.type === MessageType.ERROR)
			.map((w) => {
				const decoded = decodeErrorMessage(w.payload);
				return {
					channelId: decoded.channelId,
					data: decoded.data.toString('utf8')
				};
			}),
		errors
	};
}

function peersOf(manager: ChannelManager): Map<string, string> {
	return (manager as unknown as { channelPeers: Map<string, string> })
		.channelPeers;
}

function bootNode(storage: IStorageBackend): LightningNode {
	const node = LightningNode.fromMnemonic(MNEMONIC, {
		coinType: LnCoinType.REGTEST,
		storage,
		enableNetworking: false
	});
	node.on('error', noop);
	node.on('node:error', noop);
	return node;
}

/**
 * The liquidity peer opens inbound (automatic offline receive): the
 * acceptor derives this channel's keys and answers accept_channel, which
 * is the message our basepoints leave the node in.
 */
function acceptLspOpen(node: LightningNode, tag: string): Channel {
	const manager = node.getChannelManager();
	const lsp = makeManager(tag);
	const open = offerOpen(lsp, WALLET_PUBKEY);
	const result = inbound(
		manager,
		LSP_PUBKEY,
		MessageType.OPEN_CHANNEL,
		open.payload
	);
	expect(result.wireErrors).to.deep.equal([]);
	expect(result.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
	const channel = manager.getTempChannel(open.tempId);
	expect(channel, 'the open was accepted').to.not.equal(undefined);
	return channel!;
}

/** An inbound open the CHANNEL rejects, after the acceptor derived keys. */
function rejectedLspOpen(node: LightningNode, tag: string): void {
	const manager = node.getChannelManager();
	const lsp = makeManager(tag);
	const offered = offerOpen(lsp, WALLET_PUBKEY);
	const junk = decodeOpenChannelMessage(offered.payload);
	junk.fundingSatoshis = 0n;
	const result = inbound(
		manager,
		LSP_PUBKEY,
		MessageType.OPEN_CHANNEL,
		encodeOpenChannelMessage(junk)
	);
	expect(result.wireTypes).to.deep.equal([MessageType.ERROR]);
	expect(result.wireErrors[0].data).to.match(
		/funding_satoshis.*greater than 0/
	);
	expect(manager.getTempChannel(junk.temporaryChannelId)).to.equal(undefined);
}

/** The keys this seed derives at `index`: what the lost open put on the wire. */
function keysAt(index: number): ReturnType<typeof deriveChannelKeys> {
	const root = BIP32Factory.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC));
	return deriveChannelKeys(root, LnCoinType.REGTEST, index);
}

/** `channel` shares no key material with the channel at `index`. */
function expectKeysDiffer(channel: Channel, index: number): void {
	const state = channel.getFullState();
	const other = keysAt(index);
	expect(
		state.localBasepoints.fundingPubkey.equals(
			other.channelBasepoints.fundingPubkey
		),
		`funding pubkey at index ${index}`
	).to.equal(false);
	expect(
		state.localBasepoints.revocationBasepoint.equals(
			other.channelBasepoints.revocationBasepoint
		),
		`revocation basepoint at index ${index}`
	).to.equal(false);
	expect(
		state.localPerCommitmentSeed.equals(other.perCommitmentSeed),
		`per-commitment seed at index ${index}`
	).to.equal(false);
}

/** `channel` carries exactly the keys this seed derives at `index`. */
function expectKeysAt(channel: Channel, index: number): void {
	const state = channel.getFullState();
	const expected = keysAt(index);
	expect(
		state.localBasepoints.fundingPubkey.equals(
			expected.channelBasepoints.fundingPubkey
		),
		`funding pubkey at index ${index}`
	).to.equal(true);
	expect(
		state.localPerCommitmentSeed.equals(expected.perCommitmentSeed),
		`per-commitment seed at index ${index}`
	).to.equal(true);
}

/** A storage whose saveMetadata throws for one key, and works for the rest. */
function failingMetadata(
	storage: SqliteStorage,
	failKey: string
): IStorageBackend {
	return new Proxy(storage, {
		get(target, prop, receiver): unknown {
			if (prop === 'saveMetadata') {
				return (key: string, value: string): void => {
					if (key === failKey) throw new Error('disk full (test)');
					target.saveMetadata(key, value);
				};
			}
			const value = Reflect.get(target, prop, receiver);
			return typeof value === 'function' ? value.bind(target) : value;
		}
	}) as IStorageBackend;
}

/** An in-memory database a second node can be booted over, as a restart. */
function memoryStorage(): SqliteStorage {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	return storage;
}

/**
 * A file-backed database, for the tests that restart over it: a node's
 * destroy() closes the storage it was given, which takes an in-memory
 * database with it, and only a file survives the death this is standing in
 * for. The caller removes the directory.
 */
function fileStorage(): {
	dir: string;
	dbPath: string;
	storage: SqliteStorage;
} {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ckiam-'));
	const dbPath = path.join(dir, 'wallet.db');
	const storage = new SqliteStorage(dbPath);
	storage.open();
	return { dir, dbPath, storage };
}

function reopen(dbPath: string): SqliteStorage {
	const storage = new SqliteStorage(dbPath);
	storage.open();
	return storage;
}

// ─── The crash that used to repeat an index ───

describe('Channel key index allocation mark (issue #917)', () => {
	it('never re-hands an index an accepted open put on the wire and a crash lost', function () {
		this.timeout(20_000);
		// The shape of the bug: the acceptor answers accept_channel with the
		// index's basepoints, the process dies before any channel row lands,
		// and the key-index table, the only durable record before #917, has
		// learned nothing at all.
		const { dir, dbPath, storage } = fileStorage();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			const manager = node.getChannelManager();
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			expect(storage.loadMetadata(MARK_KEY), 'nothing allocated yet').to.equal(
				null
			);

			const lost = acceptLspOpen(node, 'crash-lost');
			expect(lost.channelKeyIndex).to.equal(FLOOR);
			expectKeysAt(lost, FLOOR);
			// Durable at the moment it was handed out, not when a row lands.
			expect(storage.loadMetadata(MARK_KEY)).to.equal(String(FLOOR));
			// And the row that used to be the only record is not there: this
			// is exactly the window the crash falls in.
			expect(storage.loadAllChannels()).to.deep.equal([]);
			expect(
				storage.loadNextChannelIndex(),
				'the table learned nothing'
			).to.equal(1);

			// SIGKILL-shaped: nothing flushes the open, the file holds only
			// what was already committed, and a successor opens it.
			node.destroy();
			const reopened = reopen(dbPath);
			second = bootNode(reopened);
			const successor = second.getChannelManager();
			expect(successor.channelIndexTipFloorArmed).to.equal(false);
			expect(successor.nextChannelIndex, 'above the lost index').to.equal(
				FLOOR + 1
			);

			// The peer that saw the lost open's basepoints now opens again:
			// a different index, and no key material in common with it.
			const successorChannel = acceptLspOpen(second, 'crash-successor');
			expect(successorChannel.channelKeyIndex).to.equal(FLOOR + 1);
			expectKeysDiffer(successorChannel, FLOOR);
			expectKeysAt(successorChannel, FLOOR + 1);
			expect(reopened.loadMetadata(MARK_KEY)).to.equal(String(FLOOR + 1));
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('records an outbound open before open_channel leaves the node', () => {
		// The opener's half: open_channel carries our basepoints and
		// funding_created signs with the funding key, all before any row.
		const { dir, dbPath, storage } = fileStorage();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			const manager = node.getChannelManager();
			node.handleNewBlock(TIP);
			const channel = manager.openChannel(LSP_PUBKEY, 100_000n);
			expect(channel.channelKeyIndex).to.equal(FLOOR);
			expect(storage.loadMetadata(MARK_KEY)).to.equal(String(FLOOR));
			expect(storage.loadAllChannels()).to.deep.equal([]);
			node.destroy();

			second = bootNode(reopen(dbPath));
			expect(second.getChannelManager().nextChannelIndex).to.equal(FLOOR + 1);
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('records every entry point ahead of its key derivation', () => {
		// All five paths that consume an index, at the manager level, with
		// the ordering the durability rests on: the record is written BEFORE
		// the deriver runs, so nothing derived from an unrecorded index can
		// exist, let alone reach the wire.
		const order: string[] = [];
		const allocated: number[] = [];
		const manager = makeManager('entry-points', {
			channelKeyDeriver: (index: number): IPerChannelKeys => {
				order.push(`derive:${index}`);
				return makePerChannelKeys(index);
			},
			onChannelIndexAllocated: (index: number): void => {
				order.push(`record:${index}`);
				allocated.push(index);
			}
		});
		const peer = '02' + 'ee'.repeat(32);
		manager.addTrustedPeer(peer);

		manager.openChannel(peer, 100_000n);
		manager.openZeroConfChannel(peer, 100_000n);
		manager.createDualFundedChannel(peer, dualFundingParams('entry-points'));
		const lsp = makeManager('entry-points-lsp');
		const open = offerOpen(lsp, WALLET_PUBKEY);
		inbound(manager, LSP_PUBKEY, MessageType.OPEN_CHANNEL, open.payload);
		inbound(
			manager,
			LSP_PUBKEY,
			MessageType.OPEN_CHANNEL2,
			encodeOpenChannel2Message(makeOpenChannel2('entry-points-v2'))
		);

		expect(allocated, 'five entry points, five records').to.deep.equal([
			1, 2, 3, 4, 5
		]);
		expect(order).to.deep.equal([
			'record:1',
			'derive:1',
			'record:2',
			'derive:2',
			'record:3',
			'derive:3',
			'record:4',
			'derive:4',
			'record:5',
			'derive:5'
		]);
		expect(manager.nextChannelIndex).to.equal(6);
	});

	// ─── What must NOT raise or lower it ───

	it('records nothing for a fenced refusal', () => {
		// #906's fence refuses before the chokepoint consumes anything, so
		// there is no allocation to record: neither the library's own
		// armed-floor fence nor a configured predicate may write the row.
		const storage = memoryStorage();
		const node = bootNode(storage);
		try {
			const manager = node.getChannelManager();
			expect(manager.channelIndexTipFloorArmed, 'birth boot, no tip').to.equal(
				true
			);
			const lsp = makeManager('fenced-lsp');
			const open = offerOpen(lsp, WALLET_PUBKEY);
			const refused = inbound(
				manager,
				LSP_PUBKEY,
				MessageType.OPEN_CHANNEL,
				open.payload
			);
			expect(refused.wireTypes).to.deep.equal([MessageType.ERROR]);
			expect(() => manager.openChannel(LSP_PUBKEY, 100_000n)).to.throw(
				/until the chain tip is known/
			);
			expect(manager.nextChannelIndex).to.equal(1);
			expect(storage.loadMetadata(MARK_KEY)).to.equal(null);
			// The birth marker is the floor's, untouched by any of this.
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal('0');
		} finally {
			node.destroy();
			storage.close();
		}

		// The configured predicate, same rule, at the manager level.
		const recorded: number[] = [];
		const fenced = makeManager('fenced-predicate', {
			newChannelsRefused: (): string | null => 'refused (test)',
			onChannelIndexAllocated: (index: number): void => {
				recorded.push(index);
			}
		});
		expect(() => fenced.openChannel(LSP_PUBKEY, 100_000n)).to.throw(
			'refused (test)'
		);
		expect(recorded).to.deep.equal([]);
		expect(fenced.nextChannelIndex).to.equal(1);
	});

	it('keeps the mark at a rejected open index and never lowers it', () => {
		// #906 hands a rejected inbound open's index back so junk opens
		// cannot burn the floor's per-block budget. That release is in
		// memory only: the durable mark stays, because "this index may have
		// been used" is the claim that keeps a restart off it.
		const { dir, dbPath, storage } = fileStorage();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			const manager = node.getChannelManager();
			node.handleNewBlock(TIP);

			rejectedLspOpen(node, 'rejected-1');
			expect(manager.nextChannelIndex, 'the counter got it back').to.equal(
				FLOOR
			);
			expect(storage.loadMetadata(MARK_KEY), 'the mark kept it').to.equal(
				String(FLOOR)
			);

			// A second rejection reuses the released index in memory and
			// writes nothing new: the mark is monotone, never lowered.
			rejectedLspOpen(node, 'rejected-2');
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			expect(storage.loadMetadata(MARK_KEY)).to.equal(String(FLOOR));
			expect(peersOf(manager).size, 'nothing retained').to.equal(0);

			// A fenced refusal beside them writes nothing either.
			expect(storage.loadAllChannels()).to.deep.equal([]);
			node.destroy();

			// Across the restart the released index is skipped: a hole in the
			// sequence, which costs nothing, rather than a repeat.
			second = bootNode(reopen(dbPath));
			const successor = second.getChannelManager();
			expect(successor.nextChannelIndex).to.equal(FLOOR + 1);
			const accepted = acceptLspOpen(second, 'rejected-successor');
			expect(accepted.channelKeyIndex).to.equal(FLOOR + 1);
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('refuses the open when the mark cannot be written', () => {
		// Returning from the hook is the promise that a restart will not
		// hand this index out again; a write that failed cannot make it, so
		// the open is refused with the counter untouched rather than run on
		// an index no successor knows about.
		const storage = memoryStorage();
		const node = bootNode(failingMetadata(storage, MARK_KEY));
		const persistenceErrors: string[] = [];
		node.on('node:error', (err: { message: string }) => {
			persistenceErrors.push(err.message);
		});
		try {
			const manager = node.getChannelManager();
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(FLOOR);

			// Inbound: contained by handleMessage, nothing accepted, nothing
			// retained, no index burned.
			const lsp = makeManager('write-fail-lsp');
			const open = offerOpen(lsp, WALLET_PUBKEY);
			const result = inbound(
				manager,
				LSP_PUBKEY,
				MessageType.OPEN_CHANNEL,
				open.payload
			);
			expect(result.wireTypes).to.not.include(MessageType.ACCEPT_CHANNEL);
			expect(manager.getTempChannel(open.tempId)).to.equal(undefined);
			expect(peersOf(manager).size).to.equal(0);
			expect(manager.nextChannelIndex).to.equal(FLOOR);

			// Outbound: the caller sees it.
			expect(() => manager.openChannel(LSP_PUBKEY, 100_000n)).to.throw(
				/cannot record channel key index/
			);
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			expect(
				persistenceErrors.some((m) =>
					m.includes('saveChannelKeyIndexAllocation')
				),
				'the failed write was reported'
			).to.equal(true);
			expect(storage.loadMetadata(MARK_KEY)).to.equal(null);
		} finally {
			node.destroy();
			storage.close();
		}
	});

	// ─── The row itself ───

	it('round-trips the mark and validates it on decode', () => {
		// A row that is not a positive number is no record: the counter
		// falls back to the other sources rather than to a decoded NaN.
		for (const bad of ['', '   ', 'abc', '-3', '0', 'null']) {
			const storage = memoryStorage();
			storage.saveChannelKeyIndex('ch0', 3);
			storage.saveChannelKeyIndex('ch1', 7);
			storage.saveMetadata(MARK_KEY, bad);
			const node = bootNode(storage);
			try {
				expect(
					node.getChannelManager().nextChannelIndex,
					`mark row ${JSON.stringify(bad)}`
				).to.equal(8);
			} finally {
				node.destroy();
				storage.close();
			}
		}

		// A valid mark above the table's high-water mark wins, and a valid
		// mark below it changes nothing (the counter only ever rises).
		for (const [mark, expected] of [
			['5000', 5001],
			['2', 8]
		] as Array<[string, number]>) {
			const storage = memoryStorage();
			storage.saveChannelKeyIndex('ch0', 3);
			storage.saveChannelKeyIndex('ch1', 7);
			storage.saveMetadata(MARK_KEY, mark);
			const node = bootNode(storage);
			try {
				expect(node.getChannelManager().nextChannelIndex).to.equal(expected);
			} finally {
				node.destroy();
				storage.close();
			}
		}
	});

	it('boots a database with channel rows and no mark exactly as before', () => {
		// Backward compatibility: every database written before #917 has no
		// mark row, and must keep seeding from the key-index table alone.
		const storage = memoryStorage();
		storage.saveChannelKeyIndex('ch0', 3);
		storage.saveChannelKeyIndex('ch1', 7);
		const node = bootNode(storage);
		try {
			const manager = node.getChannelManager();
			expect(manager.nextChannelIndex).to.equal(8);
			expect(manager.channelIndexTipFloorArmed, 'not a birth boot').to.equal(
				false
			);
			expect(storage.loadMetadata(MARK_KEY)).to.equal(null);
			expect(storage.loadMetadata(FLOOR_KEY), 'no floor row either').to.equal(
				null
			);
			// A header moves nothing, as before.
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(8);

			// The first open on such a database starts the row where the
			// table left off, so the upgrade needs no migration.
			const channel = acceptLspOpen(node, 'legacy-db');
			expect(channel.channelKeyIndex).to.equal(8);
			expect(storage.loadMetadata(MARK_KEY)).to.equal('8');
		} finally {
			node.destroy();
			storage.close();
		}
	});

	it('never floors a birth boot below a mark it already carries', () => {
		// The floor (#906) and the mark (#917) answer different questions:
		// what a previous DEVICE may have used, and what THIS database
		// handed out. A birth boot consults both and takes the higher, and
		// the floor only ever raises, so neither can undo the other.
		const storage = memoryStorage();
		storage.saveMetadata(MARK_KEY, String(FLOOR + 40));
		const node = bootNode(storage);
		try {
			const manager = node.getChannelManager();
			expect(manager.nextChannelIndex, 'seeded from the mark').to.equal(
				FLOOR + 41
			);
			// An empty key-index table with no floor row is still a birth
			// boot: the mark says nothing about a previous device.
			expect(manager.channelIndexTipFloorArmed).to.equal(true);
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex, 'the floor cannot lower it').to.equal(
				FLOOR + 41
			);
			// And a later tip floors above both, as it would without a mark.
			const higher = memoryStorage();
			higher.saveMetadata(MARK_KEY, '12');
			const later = bootNode(higher);
			try {
				later.handleNewBlock(TIP);
				expect(later.getChannelManager().nextChannelIndex).to.equal(FLOOR);
			} finally {
				later.destroy();
				higher.close();
			}
		} finally {
			node.destroy();
			storage.close();
		}
	});
});
