/**
 * Issue #906: the channel key index fence and the chain-tip floor.
 *
 * Per-channel keys are a pure function of the seed and one small integer,
 * the channel key index, whose high-water mark lives only in local state.
 * A node booted from the mnemonic alone would hand its first channel index
 * 1 and derive the funding key, basepoints and per-commitment seed of
 * whatever channel a previous device held there, live or closed. Two guards
 * close that:
 *  - the fence (newChannelsRefused): while the predicate answers a reason,
 *    every entry point refuses with it and no index is consumed;
 *  - the floor: a boot with NO key-index row floors the next index at the
 *    chain tip once a height is known and never lowers it; the counter it
 *    reaches is persisted, so a partial restore on that boot (rows below
 *    the floor) cannot hand the NEXT boot a burned index either.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as bip32 from 'bip32';
import * as bip39 from 'bip39';
import * as ecc from '@bitcoinerlab/secp256k1';
import { IScbChannelEntry } from '../../src/lightning/backup/scb';
import { Channel } from '../../src/lightning/channel/channel';
import {
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
/** A mainnet-scale tip: far above any index a wallet reaches by counting. */
const TIP = 850_000;
const REASON = 'new channels refused: the restore outcome is not known (test)';
const LSP_PUBKEY = '02' + 'ab'.repeat(32);
const WALLET_PUBKEY = '03' + 'cd'.repeat(32);
/** Where LightningNode keeps the floor's durable row (issue #906 review). */
const FLOOR_KEY = 'channel_key_index_floor';
const noop = (): void => {};

// ─── Helpers ───

function makeSeed(tag: string): Buffer {
	return crypto.createHash('sha256').update(`ckif-${tag}`).digest();
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

/** A deriver that actually advances the index: keys differ per index. */
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

function makeManagerConfig(
	tag: string,
	extra: Partial<IChannelManagerConfig> = {}
): IChannelManagerConfig {
	const seed = makeSeed(tag);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(`${tag}-pcs`),
		localFundingPrivkey: derivePrivkey(seed, 0),
		htlcBasepointSecret: derivePrivkey(seed, 4),
		chainHash: REGTEST_CHAIN_HASH,
		channelKeyDeriver: makePerChannelKeys,
		...extra
	};
}

function makeManager(
	tag: string,
	extra: Partial<IChannelManagerConfig> = {}
): ChannelManager {
	const manager = new ChannelManager(makeManagerConfig(tag, extra));
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
		// BOLT 2 makes channel_type REQUIRED on open_channel2.
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

function bootNode(storage?: IStorageBackend): LightningNode {
	const node = LightningNode.fromMnemonic(MNEMONIC, {
		coinType: LnCoinType.REGTEST,
		storage,
		enableNetworking: false
	});
	node.on('error', noop);
	node.on('node:error', noop);
	return node;
}

/** A storage whose named optional methods are hidden from the node. */
function hiding(storage: SqliteStorage, hidden: string[]): IStorageBackend {
	return new Proxy(storage, {
		get(target, prop, receiver): unknown {
			if (typeof prop === 'string' && hidden.includes(prop)) return undefined;
			const value = Reflect.get(target, prop, receiver);
			return typeof value === 'function' ? value.bind(target) : value;
		}
	}) as IStorageBackend;
}

/** The keys this seed derives at `index`: what a previous device used. */
function keysAt(index: number): ReturnType<typeof deriveChannelKeys> {
	const root = BIP32Factory.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC));
	return deriveChannelKeys(root, LnCoinType.REGTEST, index);
}

/** The funding pubkey, revocation basepoint and seed of `channel` differ from the keys at `index`. */
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

/**
 * The liquidity peer opens inbound (automatic offline receive): no operator
 * action, and the acceptor derives the channel's keys. Returns the channel
 * the node registered for it.
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
	const channel = manager.getTempChannel(open.tempId);
	expect(channel, 'the open was accepted').to.not.equal(undefined);
	return channel!;
}

/** A peer node id validateScbEntry accepts (it checks the curve). */
const SCB_PEER = getPublicKey(derivePrivkey(makeSeed('scb-peer'), 0)).toString(
	'hex'
);

/** The previous device's channel at `index`, as its static backup recorded it. */
function scbEntry(index: number): IScbChannelEntry {
	return {
		channelId: crypto
			.createHash('sha256')
			.update(`ckif-scb-channel-${index}`)
			.digest('hex'),
		peerNodeId: SCB_PEER,
		peerAddresses: [],
		fundingTxid: crypto
			.createHash('sha256')
			.update(`ckif-scb-funding-${index}`)
			.digest('hex'),
		fundingOutputIndex: 0,
		fundingSatoshis: '100000',
		channelKeyIndex: index,
		channelType: '',
		role: 'ACCEPTOR',
		isTaproot: false,
		isAnchor: false
	};
}

/** The MuSig2 verification nonce `channel` derives for `height`. */
function verificationNonce(channel: Channel, height: bigint): Buffer {
	return Buffer.from(
		(
			channel as unknown as {
				_deriveVerificationNonce(h: bigint): Uint8Array;
			}
		)._deriveVerificationNonce(height)
	);
}

// ─── The fence ───

describe('Channel key index fence (issue #906)', () => {
	it('refuses every entry point while the predicate answers, consuming no index', () => {
		let refusal: string | null = REASON;
		const bob = makeManager('bob', {
			newChannelsRefused: (): string | null => refusal
		});
		const bobPubkey = '02' + 'b0'.repeat(32);
		const alice = makeManager('alice');
		const alicePubkey = '02' + 'a1'.repeat(32);
		const peer = '02' + 'ee'.repeat(32);
		const before = bob.nextChannelIndex;

		// Outbound: v1, v2 and the zero-conf primitive all surface the throw.
		expect(() => bob.openChannel(peer, 100_000n)).to.throw(REASON);
		expect(() =>
			bob.createDualFundedChannel(peer, dualFundingParams('fenced'))
		).to.throw(REASON);
		bob.addTrustedPeer(peer);
		expect(() => bob.openZeroConfChannel(peer, 100_000n)).to.throw(REASON);

		// Inbound v1: a BOLT 1 error scoped to the opener's id, naming the
		// reason, and nothing retained.
		const open = offerOpen(alice, bobPubkey);
		const v1 = inbound(
			bob,
			alicePubkey,
			MessageType.OPEN_CHANNEL,
			open.payload
		);
		expect(v1.wireTypes).to.deep.equal([MessageType.ERROR]);
		expect(v1.wireErrors[0].channelId.equals(open.tempId)).to.equal(true);
		expect(v1.wireErrors[0].data).to.equal(REASON);
		expect(v1.errors).to.deep.equal([REASON]);
		expect(bob.getTempChannel(open.tempId)).to.equal(undefined);
		expect(peersOf(bob).has(open.tempId.toString('hex'))).to.equal(false);

		// Inbound v2: the same, scoped to the open_channel2 channel_id.
		const open2 = makeOpenChannel2('fenced');
		const v2 = inbound(
			bob,
			peer,
			MessageType.OPEN_CHANNEL2,
			encodeOpenChannel2Message(open2)
		);
		expect(v2.wireTypes).to.deep.equal([MessageType.ERROR]);
		expect(v2.wireErrors[0].channelId.equals(open2.channelId)).to.equal(true);
		expect(v2.wireErrors[0].data).to.equal(REASON);
		expect(v2.errors).to.deep.equal([REASON]);
		expect(bob.getTempChannel(open2.channelId)).to.equal(undefined);
		expect(peersOf(bob).has(open2.channelId.toString('hex'))).to.equal(false);

		// Five refusals, zero indices burned.
		expect(bob.nextChannelIndex).to.equal(before);
		expect(bob.listChannels()).to.have.length(0);
		expect(peersOf(bob).size).to.equal(0);

		// The predicate is read anew on every consultation: once it answers
		// null the same opens go through and the index advances.
		refusal = null;
		const open3 = offerOpen(alice, bobPubkey);
		const v1Open = inbound(
			bob,
			alicePubkey,
			MessageType.OPEN_CHANNEL,
			open3.payload
		);
		expect(v1Open.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
		expect(bob.getTempChannel(open3.tempId)).to.not.equal(undefined);
		expect(bob.getTempChannel(open3.tempId)!.channelKeyIndex).to.equal(before);
		expect(bob.nextChannelIndex).to.equal(before + 1);

		const open4 = makeOpenChannel2('open');
		const v2Open = inbound(
			bob,
			peer,
			MessageType.OPEN_CHANNEL2,
			encodeOpenChannel2Message(open4)
		);
		expect(v2Open.wireErrors).to.have.length(0);
		expect(bob.nextChannelIndex).to.equal(before + 2);

		const opened = bob.openChannel('02' + 'ef'.repeat(32), 100_000n);
		expect(opened.channelKeyIndex).to.equal(before + 2);
		expect(bob.nextChannelIndex).to.equal(before + 3);
	});

	it('reaches the manager through the node config', () => {
		const node = LightningNode.fromMnemonic(MNEMONIC, {
			coinType: LnCoinType.REGTEST,
			enableNetworking: false,
			newChannelsRefused: (): string | null => REASON
		});
		node.on('error', noop);
		node.on('node:error', noop);
		try {
			const manager = node.getChannelManager();
			const before = manager.nextChannelIndex;
			const lsp = makeManager('lsp');
			const open = offerOpen(lsp, WALLET_PUBKEY);
			const result = inbound(
				manager,
				LSP_PUBKEY,
				MessageType.OPEN_CHANNEL,
				open.payload
			);
			expect(result.wireTypes).to.deep.equal([MessageType.ERROR]);
			expect(result.wireErrors[0].data).to.equal(REASON);
			expect(manager.getTempChannel(open.tempId)).to.equal(undefined);
			expect(() => node.openChannel(LSP_PUBKEY, 100_000n)).to.throw(REASON);
			expect(manager.nextChannelIndex).to.equal(before);
		} finally {
			node.destroy();
		}
	});
});

// ─── The floor ───

describe('Channel key index floor (issue #906)', () => {
	it('SqliteStorage tells an empty key-index table from one whose top index is 0', () => {
		const storage = new SqliteStorage(':memory:');
		storage.open();
		try {
			expect(storage.hasChannelKeyIndices()).to.equal(false);
			expect(storage.loadNextChannelIndex()).to.equal(1);
			// Index 0 is the node-level shared-key channel: the next index is
			// still 1, but the table is no longer empty.
			storage.saveChannelKeyIndex('ch0', 0);
			expect(storage.hasChannelKeyIndices()).to.equal(true);
			expect(storage.loadNextChannelIndex()).to.equal(1);
			storage.saveChannelKeyIndex('ch7', 7);
			expect(storage.hasChannelKeyIndices()).to.equal(true);
			expect(storage.loadNextChannelIndex()).to.equal(8);
		} finally {
			storage.close();
		}
	});

	it('floors the next index at the tip once armed and never lowers it', () => {
		const manager = makeManager('floor');
		const peer = '02' + 'f1'.repeat(32);
		manager.armChannelIndexTipFloor();
		// No tip yet: nothing to floor at.
		expect(manager.nextChannelIndex).to.equal(1);
		manager.handleNewBlock(0);
		expect(manager.nextChannelIndex).to.equal(1);
		manager.handleNewBlock(TIP);
		expect(manager.nextChannelIndex).to.equal(TIP);
		// Nothing lowers it: not an older header, not the setter.
		manager.handleNewBlock(TIP - 10);
		expect(manager.nextChannelIndex).to.equal(TIP);
		manager.nextChannelIndex = 5;
		expect(manager.nextChannelIndex).to.equal(TIP);
		// A higher answer (a capsule, a peer) still raises it.
		manager.nextChannelIndex = TIP + 3;
		expect(manager.nextChannelIndex).to.equal(TIP + 3);
		const channel = manager.openChannel(peer, 100_000n);
		expect(channel.channelKeyIndex).to.equal(TIP + 3);
		expect(manager.nextChannelIndex).to.equal(TIP + 4);
		// A header below the consumed counter changes nothing; one above it
		// floors again.
		manager.handleNewBlock(TIP + 1);
		expect(manager.nextChannelIndex).to.equal(TIP + 4);
		manager.handleNewBlock(TIP + 10);
		expect(manager.nextChannelIndex).to.equal(TIP + 10);

		// An unarmed manager is untouched by headers.
		const plain = makeManager('plain');
		plain.handleNewBlock(TIP);
		expect(plain.nextChannelIndex).to.equal(1);
	});

	it('a bare-seed boot starts at the tip and derives keys no earlier device could have used', () => {
		// File-backed: the second boot reopens what the first one journaled
		// (destroy() closes the storage a node was given).
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ckif-'));
		const dbPath = path.join(dir, 'wallet.db');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			const manager = node.getChannelManager();
			expect(manager.nextChannelIndex).to.equal(1);
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(TIP);

			// The previous device's channel: the keys this seed derives at 1.
			const root = BIP32Factory.fromSeed(bip39.mnemonicToSeedSync(MNEMONIC));
			const old = deriveChannelKeys(root, LnCoinType.REGTEST, 1);

			// The liquidity peer opens inbound (automatic offline receive): no
			// operator action, and the acceptor derives the channel's keys.
			const lsp = makeManager('lsp-floor');
			const open = offerOpen(lsp, WALLET_PUBKEY);
			const result = inbound(
				manager,
				LSP_PUBKEY,
				MessageType.OPEN_CHANNEL,
				open.payload
			);
			expect(result.wireErrors).to.deep.equal([]);
			const channel = manager.getTempChannel(open.tempId);
			expect(channel, 'the open was accepted').to.not.equal(undefined);
			expect(channel!.channelKeyIndex).to.equal(TIP);
			const state = channel!.getFullState();
			expect(
				state.localBasepoints.fundingPubkey.equals(
					old.channelBasepoints.fundingPubkey
				)
			).to.equal(false);
			expect(
				state.localBasepoints.revocationBasepoint.equals(
					old.channelBasepoints.revocationBasepoint
				)
			).to.equal(false);
			expect(
				state.localPerCommitmentSeed.equals(old.perCommitmentSeed)
			).to.equal(false);
			// And they are exactly the keys at the floored index.
			const fresh = deriveChannelKeys(root, LnCoinType.REGTEST, TIP);
			expect(
				state.localBasepoints.fundingPubkey.equals(
					fresh.channelBasepoints.fundingPubkey
				)
			).to.equal(true);
			expect(
				state.localBasepoints.revocationBasepoint.equals(
					fresh.channelBasepoints.revocationBasepoint
				)
			).to.equal(true);
			expect(
				state.localPerCommitmentSeed.equals(fresh.perCommitmentSeed)
			).to.equal(true);

			// The floor is durable: its row holds the counter the header
			// raised it to.
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal(String(TIP));

			// Once the channel is journaled, a second boot continues from
			// storage alone (H + 1 before any header); and a database born
			// from a bare-seed boot keeps the floor armed for its life, so
			// later headers keep the counter at the tip and in the row.
			storage.saveChannelKeyIndex(open.tempId.toString('hex'), TIP);
			node.destroy();
			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			second = bootNode(reopened);
			expect(second.getChannelManager().nextChannelIndex).to.equal(TIP + 1);
			second.handleNewBlock(TIP + 500);
			expect(second.getChannelManager().nextChannelIndex).to.equal(TIP + 500);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(TIP + 500));
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('a non-empty table is never floored, a top index of 0 included', () => {
		for (const rows of [[3, 7], [0]]) {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			rows.forEach((idx, i) => storage.saveChannelKeyIndex(`ch${i}`, idx));
			const expected = Math.max(...rows) + 1;
			const node = bootNode(storage);
			try {
				expect(node.getChannelManager().nextChannelIndex).to.equal(expected);
				node.handleNewBlock(TIP);
				expect(node.getChannelManager().nextChannelIndex).to.equal(expected);
				// And no floor row is written: the table is its own record.
				expect(storage.loadMetadata(FLOOR_KEY)).to.equal(null);
			} finally {
				node.destroy();
				storage.close();
			}
		}
	});

	it('falls back to the enumerator, then to the next index, on backends without the query', () => {
		for (const hidden of [
			['hasChannelKeyIndices'],
			['hasChannelKeyIndices', 'loadAllChannelKeyIndices']
		]) {
			// Empty: the floor arms through the fallback.
			const empty = new SqliteStorage(':memory:');
			empty.open();
			const armed = bootNode(hiding(empty, hidden));
			try {
				armed.handleNewBlock(TIP);
				expect(armed.getChannelManager().nextChannelIndex).to.equal(TIP);
			} finally {
				armed.destroy();
				empty.close();
			}
			// Populated: the fallback reads it as non-empty and nothing arms.
			const populated = new SqliteStorage(':memory:');
			populated.open();
			populated.saveChannelKeyIndex('ch', 4);
			const seeded = bootNode(hiding(populated, hidden));
			try {
				seeded.handleNewBlock(TIP);
				expect(seeded.getChannelManager().nextChannelIndex).to.equal(5);
			} finally {
				seeded.destroy();
				populated.close();
			}
		}
	});

	it('a partial SCB restore that drops the highest-index entry never reaches it, on that boot or the next', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ckif-'));
		const dbPath = path.join(dir, 'wallet.db');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			const manager = node.getChannelManager();
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(TIP);

			// The previous device held indices 1..4 and its backup lost the
			// entry at 4 (the issue's second UNSAFE scenario): 1..3 come back,
			// so the table's own high-water mark now reads 4, the very index
			// the dropped channel burned. Restore only ever raises the
			// counter, so the floor stands.
			const result = await node.recoverFromStaticChannelBackup(
				[1, 2, 3].map(scbEntry)
			);
			expect(result.skipped).to.deep.equal([]);
			expect(result.recovering).to.have.length(3);
			expect(storage.loadNextChannelIndex()).to.equal(4);
			expect(manager.nextChannelIndex).to.equal(TIP);

			// The next open derives above the dropped index.
			const first = acceptLspOpen(node, 'lsp-partial-1');
			expect(first.channelKeyIndex).to.equal(TIP);
			for (const idx of [1, 2, 3, 4]) expectKeysDiffer(first, idx);
			expect(manager.nextChannelIndex).to.equal(TIP + 1);

			// The row records the counter, consumed index included, at the
			// next header; that channel's own row never lands (a temporary
			// channel has none). Then the process restarts.
			node.handleNewBlock(TIP + 1);
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal(String(TIP + 1));
			node.destroy();

			// Boot 2 reads a POPULATED table whose top index is the dropped
			// channel's predecessor: without the row the floor would not arm
			// and the counter would be 4. From the row alone, before any
			// header, it is TIP + 1, and the LSP's open lands there.
			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			expect(reopened.loadNextChannelIndex()).to.equal(4);
			second = bootNode(reopened);
			const again = second.getChannelManager();
			expect(again.nextChannelIndex).to.equal(TIP + 1);
			const opened = acceptLspOpen(second, 'lsp-partial-2');
			expect(opened.channelKeyIndex).to.equal(TIP + 1);
			for (const idx of [1, 2, 3, 4, TIP]) expectKeysDiffer(opened, idx);
			// No two channels share a per-commitment seed across the restart.
			expect(
				opened
					.getFullState()
					.localPerCommitmentSeed.equals(
						first.getFullState().localPerCommitmentSeed
					)
			).to.equal(false);
			// The reopened database keeps the floor armed.
			second.handleNewBlock(TIP + 9);
			expect(again.nextChannelIndex).to.equal(TIP + 9);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(TIP + 9));
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('a bare-seed boot that restores before its first header still floors the next boot', async () => {
		// The birth boot never learns a tip (the daemon fences opens until
		// it does), a partial SCB restore lands rows 1..3, and the process
		// restarts. The table is populated on boot 2, so only the row this
		// boot wrote at arm time can re-arm the floor there.
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ckif-'));
		const dbPath = path.join(dir, 'wallet.db');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal('1');
			const result = await node.recoverFromStaticChannelBackup(
				[1, 2, 3].map(scbEntry)
			);
			expect(result.skipped).to.deep.equal([]);
			expect(node.getChannelManager().nextChannelIndex).to.equal(4);
			node.destroy();

			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			second = bootNode(reopened);
			const manager = second.getChannelManager();
			// Nothing better is known yet: the table's 4 stands until the
			// first header, which floors it at the tip.
			expect(manager.nextChannelIndex).to.equal(4);
			second.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(TIP);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(TIP));
			const opened = acceptLspOpen(second, 'lsp-blind');
			expect(opened.channelKeyIndex).to.equal(TIP);
			for (const idx of [1, 2, 3, 4]) expectKeysDiffer(opened, idx);
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});

// ─── The verification nonce ───

describe('Channel key index and the taproot verification nonce (issue #906)', () => {
	it('two channels at one key index share every verification nonce; distinct indices never do', () => {
		// The nonce is HMAC(localPerCommitmentSeed, tag || height), and the
		// seed is a pure function of the key index: two channels at one
		// index sign two sighashes under one secnonce at any shared height,
		// which is the collision the floor removes.
		const peer = '02' + 'dd'.repeat(32);
		const first = makeManager('nonce-first');
		const a = first.openChannel(peer, 100_000n);
		const b = first.openChannel('02' + 'de'.repeat(32), 100_000n);
		expect(a.channelKeyIndex).to.equal(1);
		expect(b.channelKeyIndex).to.equal(2);
		// A second node from the same seed, counting from 1 again.
		const second = makeManager('nonce-second');
		const c = second.openChannel(peer, 100_000n);
		expect(c.channelKeyIndex).to.equal(1);
		// A floored one: its first channel sits at the tip.
		const floored = makeManager('nonce-floored');
		floored.armChannelIndexTipFloor(TIP);
		const d = floored.openChannel(peer, 100_000n);
		expect(d.channelKeyIndex).to.equal(TIP);

		for (const height of [0n, 1n, 42n]) {
			const nonceA = verificationNonce(a, height);
			// Same index, same seed: the same nonce at the same height.
			expect(nonceA.equals(verificationNonce(c, height))).to.equal(true);
			// Distinct indices: distinct nonces at the same height.
			expect(nonceA.equals(verificationNonce(b, height))).to.equal(false);
			expect(nonceA.equals(verificationNonce(d, height))).to.equal(false);
			expect(
				verificationNonce(b, height).equals(verificationNonce(d, height))
			).to.equal(false);
		}
		// Reproducible, and distinct across heights within one channel.
		expect(verificationNonce(a, 7n).equals(verificationNonce(a, 7n))).to.equal(
			true
		);
		expect(verificationNonce(a, 7n).equals(verificationNonce(a, 8n))).to.equal(
			false
		);
	});
});
