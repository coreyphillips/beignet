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
 *    chain tip once a height is known and never lowers it.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as bip32 from 'bip32';
import * as bip39 from 'bip39';
import * as ecc from '@bitcoinerlab/secp256k1';
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

			// Once the channel is journaled, a second boot continues from
			// storage alone: no floor is armed, and headers no longer move it.
			storage.saveChannelKeyIndex(open.tempId.toString('hex'), TIP);
			node.destroy();
			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			second = bootNode(reopened);
			expect(second.getChannelManager().nextChannelIndex).to.equal(TIP + 1);
			second.handleNewBlock(TIP + 500);
			expect(second.getChannelManager().nextChannelIndex).to.equal(TIP + 1);
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
});
