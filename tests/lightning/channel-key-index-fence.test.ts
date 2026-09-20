/**
 * Issue #906: the channel key index fence and the chain-tip floor.
 *
 * Per-channel keys are a pure function of the seed and one small integer,
 * the channel key index, whose high-water mark lives only in local state.
 * A node booted from the mnemonic alone would hand its first channel index
 * 1 and derive the funding key, basepoints and per-commitment seed of
 * whatever channel a previous device held there, live or closed. Two guards
 * reduce that risk:
 *  - the fence: while the configured predicate (newChannelsRefused) answers
 *    a reason, or while the floor below is armed and unfired, every entry
 *    point refuses and no index is consumed;
 *  - the floor: a birth boot (no key-index row, no persisted floor) floors
 *    the next index at the first real chain tip it learns times
 *    CHANNEL_INDEX_FLOOR_STRIDE (128 indices per block, a margin for the
 *    opens a device can answer between two blocks; an open it REFUSED hands
 *    its index straight back, so junk opens cost nothing; the product
 *    clamped at CHANNEL_INDEX_FLOOR_MAX, below the hardened derivation
 *    limit), ONCE, and never lowers it; the value is persisted, every later
 *    boot seeds the counter from max(table, floor) with no header moving
 *    it, and a partial restore on the birth boot (rows below the floor)
 *    cannot lower the NEXT boot below that floor. This spacing is bounded:
 *    same-block restores and attempts beyond the stride budget can collide.
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
	CHANNEL_INDEX_FLOOR_MAX,
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
/** A mainnet-scale height used by these fixtures. */
const TIP = 850_000;
/** Where the floor lands for a birth boot at TIP: the stride's worth per block. */
const FLOOR = TIP * CHANNEL_INDEX_FLOOR_STRIDE;
const REASON = 'new channels refused: the restore outcome is not known (test)';
/**
 * What the OPENER is told: the fence's own reason names our recovery state,
 * which the counterparty has no business learning (issue #906 review), so
 * the wire carries this and the reason stays on the local 'error' event.
 */
const WIRE_REASON = 'new channels are temporarily refused';
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
		// Generic on the wire, detailed locally: the opener learns only that
		// new channels are refused for now, never that we are mid-recovery.
		expect(v1.wireErrors[0].data).to.equal(WIRE_REASON);
		expect(v1.wireErrors[0].data).to.not.contain('restore outcome');
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
		expect(v2.wireErrors[0].data).to.equal(WIRE_REASON);
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
			expect(result.wireErrors[0].data).to.equal(WIRE_REASON);
			// The detail is ours, on the local event and in the throw an
			// outbound open surfaces to its own caller.
			expect(result.errors).to.deep.equal([REASON]);
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

	it('floors the next index at the first real height times the stride once armed, then leaves it to the counter', () => {
		const manager = makeManager('floor');
		const peer = '02' + 'f1'.repeat(32);
		manager.armChannelIndexTipFloor();
		expect(manager.channelIndexTipFloorArmed).to.equal(true);
		// No real tip yet: nothing to floor at, and the floor stays armed.
		expect(manager.nextChannelIndex).to.equal(1);
		manager.handleNewBlock(0);
		expect(manager.nextChannelIndex).to.equal(1);
		expect(manager.channelIndexTipFloorArmed).to.equal(true);
		// The first real height fires it, once, at the stride's worth of
		// indices per block.
		manager.handleNewBlock(TIP);
		expect(manager.nextChannelIndex).to.equal(FLOOR);
		expect(manager.channelIndexTipFloorArmed).to.equal(false);
		// Nothing lowers it: not an older header, not the setter.
		manager.handleNewBlock(TIP - 10);
		expect(manager.nextChannelIndex).to.equal(FLOOR);
		manager.nextChannelIndex = 5;
		expect(manager.nextChannelIndex).to.equal(FLOOR);
		// A higher answer (a capsule, a peer) still raises it.
		manager.nextChannelIndex = FLOOR + 3;
		expect(manager.nextChannelIndex).to.equal(FLOOR + 3);
		const channel = manager.openChannel(peer, 100_000n);
		expect(channel.channelKeyIndex).to.equal(FLOOR + 3);
		expect(manager.nextChannelIndex).to.equal(FLOOR + 4);
		// Later headers, below or above the counter, do not move it: the
		// floor fired once, and the counter is the table's business now.
		manager.handleNewBlock(TIP + 1);
		expect(manager.nextChannelIndex).to.equal(FLOOR + 4);
		manager.handleNewBlock(TIP + 10);
		expect(manager.nextChannelIndex).to.equal(FLOOR + 4);

		// Armed with a height already known, it fires at once.
		const known = makeManager('known');
		known.armChannelIndexTipFloor(TIP);
		expect(known.nextChannelIndex).to.equal(FLOOR);
		expect(known.channelIndexTipFloorArmed).to.equal(false);
		known.handleNewBlock(TIP + 10);
		expect(known.nextChannelIndex).to.equal(FLOOR);

		// Why the stride: a device answers as many opens between two blocks
		// as its peer asks for, while the floor moves once
		// per block. A device born at TIP whose LSP opens three channels
		// across two blocks burns three indices; a second device restored
		// from the same seed two blocks later starts above all of them,
		// which a floor of one index per block (TIP + 2) would not have.
		expect(CHANNEL_INDEX_FLOOR_STRIDE).to.equal(128);
		const earlier = makeManager('earlier-device');
		earlier.armChannelIndexTipFloor(TIP);
		const burned = ['e1', 'e2', 'e3'].map(
			(tag) =>
				earlier.openChannel('02' + tag.repeat(32), 100_000n).channelKeyIndex
		);
		expect(burned).to.deep.equal([FLOOR, FLOOR + 1, FLOOR + 2]);
		const later = makeManager('later-device');
		later.armChannelIndexTipFloor(TIP + 2);
		expect(later.nextChannelIndex).to.equal(
			(TIP + 2) * CHANNEL_INDEX_FLOOR_STRIDE
		);
		expect(later.nextChannelIndex).to.be.above(FLOOR + 2);
		expect(TIP + 2).to.be.below(FLOOR + 2);
		// The residual the floor does not cover: a second device restored
		// within the SAME block starts where the first did. The active-restore
		// fence does not prevent two idle devices from opening there.
		const sameBlock = makeManager('same-block-device');
		sameBlock.armChannelIndexTipFloor(TIP);
		expect(sameBlock.nextChannelIndex).to.equal(burned[0]);
		// And the stride keeps every plausible tip's floor a derivable
		// hardened index (under 2^31 - 1, see backup/scb.ts).
		expect(FLOOR).to.be.below(0x7fffffff);
		expect(16_777_215 * CHANNEL_INDEX_FLOOR_STRIDE).to.be.below(0x7fffffff);
		expect(16_777_216 * CHANNEL_INDEX_FLOOR_STRIDE).to.be.above(0x7fffffff);

		// An unarmed manager is untouched by headers.
		const plain = makeManager('plain');
		plain.handleNewBlock(TIP);
		expect(plain.nextChannelIndex).to.equal(1);
		expect(plain.channelIndexTipFloorArmed).to.equal(false);
	});

	it('a rejected inbound open hands its key index back, v1 and v2', () => {
		// Issue #906 review, H1: both acceptors derive keys BEFORE the channel
		// validates the open (amount, reserve, dust, feerate, channel_type), so
		// an open that never becomes a channel would otherwise consume an
		// index. At 128 a block that is the whole spacing budget the floor
		// gives one block, and a peer offering junk could walk this device's
		// counter into the range the NEXT block's floor hands a freshly
		// restored one: the collision the floor exists to prevent, reinstated
		// for free. No accept_channel was sent, so nothing carrying those keys
		// ever left the node and the index is provably unused.
		const victim = makeManager('rejected-opens-victim');
		victim.armChannelIndexTipFloor(TIP);
		expect(victim.nextChannelIndex).to.equal(FLOOR);
		const lsp = makeManager('rejected-opens-lsp');
		const offered = offerOpen(lsp, WALLET_PUBKEY);
		const junk = decodeOpenChannelMessage(offered.payload);
		// Decodable, on the right chain, past every manager pre-check: only
		// the channel's own parameter validation refuses it.
		junk.fundingSatoshis = 0n;
		for (let i = 0; i < CHANNEL_INDEX_FLOOR_STRIDE; i++) {
			junk.temporaryChannelId = Buffer.alloc(32);
			junk.temporaryChannelId.writeUInt32BE(i + 1, 28);
			const result = inbound(
				victim,
				LSP_PUBKEY,
				MessageType.OPEN_CHANNEL,
				encodeOpenChannelMessage(junk)
			);
			expect(result.wireTypes).to.deep.equal([MessageType.ERROR]);
			expect(result.wireErrors[0].data).to.match(
				/funding_satoshis.*greater than 0/
			);
			expect(
				result.wireErrors[0].channelId.equals(junk.temporaryChannelId)
			).to.equal(true);
			expect(victim.getTempChannel(junk.temporaryChannelId)).to.equal(
				undefined
			);
			// The whole point: a full block's budget of refusals, zero indices.
			expect(
				victim.nextChannelIndex,
				`after ${i + 1} refused open_channel`
			).to.equal(FLOOR);
		}

		// v2 the same way: a dust limit under the protocol floor is refused by
		// the channel, after the acceptor derived its keys.
		for (let i = 0; i < 4; i++) {
			const open2 = makeOpenChannel2(`rejected-opens-v2-${i}`);
			open2.dustLimitSatoshis = 100n;
			const result = inbound(
				victim,
				LSP_PUBKEY,
				MessageType.OPEN_CHANNEL2,
				encodeOpenChannel2Message(open2)
			);
			expect(result.wireTypes).to.deep.equal([MessageType.ERROR]);
			expect(result.wireErrors[0].data).to.match(
				/dust_limit_satoshis .* below minimum/
			);
			expect(victim.getTempChannel(open2.channelId)).to.equal(undefined);
			expect(
				victim.nextChannelIndex,
				`after ${i + 1} refused open_channel2`
			).to.equal(FLOOR);
		}
		// Nothing retained for any of them either.
		expect(peersOf(victim).size).to.equal(0);

		// So a device restored one block later still starts above everything
		// this one could have allocated, and the two next channels share no
		// key material, which is what the spacing is for.
		const later = makeManager('rejected-opens-later');
		later.armChannelIndexTipFloor(TIP + 1);
		expect(later.nextChannelIndex).to.equal(
			(TIP + 1) * CHANNEL_INDEX_FLOOR_STRIDE
		);
		expect(later.nextChannelIndex).to.be.above(victim.nextChannelIndex);
		const a = victim.openChannel(LSP_PUBKEY, 100_000n);
		const b = later.openChannel(LSP_PUBKEY, 100_000n);
		expect(a.channelKeyIndex).to.equal(FLOOR);
		expect(b.channelKeyIndex).to.equal((TIP + 1) * CHANNEL_INDEX_FLOOR_STRIDE);
		const aState = a.getFullState();
		const bState = b.getFullState();
		expect(
			aState.localBasepoints.fundingPubkey.equals(
				bState.localBasepoints.fundingPubkey
			)
		).to.equal(false);
		expect(
			aState.localPerCommitmentSeed.equals(bState.localPerCommitmentSeed)
		).to.equal(false);
	});

	it('an ACCEPTED open consumes its index, and the next open gets the next', () => {
		// The other half of the release rule: only a refusal gives an index
		// back. Anything that answered accept_channel / accept_channel2 put
		// our basepoints on the wire, so its index is spent for good.
		const node = makeManager('accepted-consumes');
		node.armChannelIndexTipFloor(TIP);
		const lsp = makeManager('accepted-consumes-lsp');
		const first = offerOpen(lsp, WALLET_PUBKEY);
		const v1 = inbound(
			node,
			LSP_PUBKEY,
			MessageType.OPEN_CHANNEL,
			first.payload
		);
		expect(v1.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
		expect(node.getTempChannel(first.tempId)!.channelKeyIndex).to.equal(FLOOR);
		expect(node.nextChannelIndex).to.equal(FLOOR + 1);

		const open2 = makeOpenChannel2('accepted-consumes-v2');
		const v2 = inbound(
			node,
			LSP_PUBKEY,
			MessageType.OPEN_CHANNEL2,
			encodeOpenChannel2Message(open2)
		);
		expect(v2.wireErrors).to.have.length(0);
		expect(node.getTempChannel(open2.channelId)!.channelKeyIndex).to.equal(
			FLOOR + 1
		);
		expect(node.nextChannelIndex).to.equal(FLOOR + 2);

		const outbound = node.openChannel('02' + 'aa'.repeat(32), 100_000n);
		expect(outbound.channelKeyIndex).to.equal(FLOOR + 2);
		expect(node.nextChannelIndex).to.equal(FLOOR + 3);
	});

	it('refuses every new channel while the floor is armed but unfired, with no predicate configured', () => {
		// Issue #906 review, H2: newChannelsRefused is the daemon's, and a
		// plain LightningNode embedder supplies none. An armed, unfired floor
		// is precisely the window in which this database has no record of the
		// next index AND no tip to floor it at, so the counter still stands at
		// 1 and the liquidity peer's automatic open would take it. The library
		// fences that window itself, and lifts on the first block.
		const manager = makeManager('self-fenced');
		manager.armChannelIndexTipFloor();
		expect(manager.channelIndexTipFloorArmed).to.equal(true);
		expect(manager.nextChannelIndex).to.equal(1);
		const lsp = makeManager('self-fenced-lsp');
		const open = offerOpen(lsp, WALLET_PUBKEY);
		const refused = inbound(
			manager,
			LSP_PUBKEY,
			MessageType.OPEN_CHANNEL,
			open.payload
		);
		expect(refused.wireTypes).to.deep.equal([MessageType.ERROR]);
		expect(refused.wireErrors[0].data).to.equal(WIRE_REASON);
		expect(refused.errors[0]).to.match(/until the chain tip is known/);
		expect(manager.getTempChannel(open.tempId)).to.equal(undefined);
		expect(peersOf(manager).size).to.equal(0);
		expect(manager.nextChannelIndex).to.equal(1);
		// Outbound opens surface the same reason, and burn nothing either.
		expect(() => manager.openChannel(LSP_PUBKEY, 100_000n)).to.throw(
			/until the chain tip is known/
		);
		expect(manager.nextChannelIndex).to.equal(1);

		// The first block lifts it: no operator, no predicate, no restart.
		manager.handleNewBlock(TIP);
		expect(manager.channelIndexTipFloorArmed).to.equal(false);
		const second = offerOpen(lsp, WALLET_PUBKEY);
		const accepted = inbound(
			manager,
			LSP_PUBKEY,
			MessageType.OPEN_CHANNEL,
			second.payload
		);
		expect(accepted.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
		const channel = manager.getTempChannel(second.tempId);
		expect(channel, 'the open was accepted').to.not.equal(undefined);
		expect(channel!.channelKeyIndex).to.be.at.least(
			TIP * CHANNEL_INDEX_FLOOR_STRIDE
		);
		expect(channel!.channelKeyIndex).to.equal(FLOOR);

		// The self-fence needs an index to protect. Without a
		// channelKeyDeriver every channel takes the node-level shared keys at
		// index 0 and the counter is never consumed, so an armed floor
		// refuses nothing: that configuration's key reuse is the separate gap
		// #906 leaves out of scope, and no chain tip would fix it.
		const shared = makeManager('self-fenced-shared', {
			channelKeyDeriver: undefined
		});
		shared.armChannelIndexTipFloor();
		expect(shared.channelIndexTipFloorArmed).to.equal(true);
		const sharedOpen = offerOpen(lsp, WALLET_PUBKEY);
		const admitted = inbound(
			shared,
			LSP_PUBKEY,
			MessageType.OPEN_CHANNEL,
			sharedOpen.payload
		);
		expect(admitted.wireTypes).to.deep.equal([MessageType.ACCEPT_CHANNEL]);
		expect(shared.getTempChannel(sharedOpen.tempId)!.channelKeyIndex).to.equal(
			0
		);
		expect(shared.nextChannelIndex).to.equal(1);
	});

	it('does not fire the floor on a height that is not a finite number', () => {
		// NaN fails every comparison, so a bare `tip <= 0` guard would disarm
		// the floor without applying it and leave the counter at 1 for the
		// node to persist as this database's floor forever (issue #906
		// review). Infinity is no more a tip than NaN is.
		for (const height of [NaN, Infinity, -Infinity]) {
			const armed = makeManager(`nonfinite-armed-${String(height)}`);
			armed.armChannelIndexTipFloor(height);
			expect(armed.channelIndexTipFloorArmed, `armed at ${height}`).to.equal(
				true
			);
			expect(armed.nextChannelIndex).to.equal(1);
			const header = makeManager(`nonfinite-header-${String(height)}`);
			header.armChannelIndexTipFloor();
			header.handleNewBlock(height);
			expect(header.channelIndexTipFloorArmed).to.equal(true);
			expect(header.nextChannelIndex).to.equal(1);
			// And the next real header still floors, however poisoned the
			// remembered height is.
			header.handleNewBlock(TIP);
			expect(header.channelIndexTipFloorArmed).to.equal(false);
			expect(header.nextChannelIndex).to.equal(FLOOR);
		}
	});

	it('clamps the floor from an implausible height below the hardened derivation limit', () => {
		// The height the floor multiplies is the chain backend's word. No
		// real tip nears 16,777,216, the first height whose product with
		// the stride is 2^31 and past the last derivable hardened child,
		// but a backend that reports one must not carry the counter past
		// the limit in one step: the product is clamped 2^20 short of it,
		// leaving that many indices to hand out before the deriver refuses.
		expect(CHANNEL_INDEX_FLOOR_MAX).to.equal(0x7fffffff - 2 ** 20);
		expect(CHANNEL_INDEX_FLOOR_MAX).to.equal(0x7fefffff);
		expect(CHANNEL_INDEX_FLOOR_MAX + 2 ** 20).to.equal(0x7fffffff);
		// The limit is the deriver's own: the ceiling and the limit itself
		// derive, the index one past the limit (where 16,777,216 * 128
		// would have put the counter) does not.
		expect(() => keysAt(CHANNEL_INDEX_FLOOR_MAX)).to.not.throw();
		expect(() => keysAt(0x7fffffff)).to.not.throw();
		expect(16_777_216 * CHANNEL_INDEX_FLOOR_STRIDE).to.equal(0x7fffffff + 1);
		expect(() => keysAt(0x7fffffff + 1)).to.throw();

		// A huge height known at arm time or arriving as a header, up to
		// the largest integers: every one clamps to the ceiling, disarms,
		// and the channel opened there is derivable with room to move on.
		const peer = '02' + 'c1'.repeat(32);
		for (const height of [
			16_777_216,
			100_000_000,
			2 ** 31,
			Number.MAX_SAFE_INTEGER
		]) {
			const known = makeManager(`huge-known-${height}`);
			known.armChannelIndexTipFloor(height);
			expect(known.nextChannelIndex, `armed at ${height}`).to.equal(
				CHANNEL_INDEX_FLOOR_MAX
			);
			expect(known.channelIndexTipFloorArmed).to.equal(false);
			const header = makeManager(`huge-header-${height}`);
			header.armChannelIndexTipFloor();
			header.handleNewBlock(height);
			expect(header.nextChannelIndex, `header at ${height}`).to.equal(
				CHANNEL_INDEX_FLOOR_MAX
			);
			expect(header.channelIndexTipFloorArmed).to.equal(false);
			const channel = header.openChannel(peer, 100_000n);
			expect(channel.channelKeyIndex).to.equal(CHANNEL_INDEX_FLOOR_MAX);
			expect(header.nextChannelIndex).to.equal(CHANNEL_INDEX_FLOOR_MAX + 1);
			expect(header.nextChannelIndex).to.be.below(0x7fffffff);
		}

		// The edge: the last height whose product fits floors unclamped, the
		// next one clamps, and the clamp never lowers a counter already
		// standing above the ceiling.
		const lastFit = Math.floor(
			CHANNEL_INDEX_FLOOR_MAX / CHANNEL_INDEX_FLOOR_STRIDE
		);
		expect(lastFit).to.equal(16_769_023);
		const fits = makeManager('last-fit');
		fits.armChannelIndexTipFloor(lastFit);
		expect(fits.nextChannelIndex).to.equal(
			lastFit * CHANNEL_INDEX_FLOOR_STRIDE
		);
		expect(fits.nextChannelIndex).to.be.at.most(CHANNEL_INDEX_FLOOR_MAX);
		const clamped = makeManager('first-clamped');
		clamped.armChannelIndexTipFloor(lastFit + 1);
		expect(clamped.nextChannelIndex).to.equal(CHANNEL_INDEX_FLOOR_MAX);
		const higher = makeManager('already-higher');
		higher.nextChannelIndex = CHANNEL_INDEX_FLOOR_MAX + 5;
		higher.armChannelIndexTipFloor(Number.MAX_SAFE_INTEGER);
		expect(higher.nextChannelIndex).to.equal(CHANNEL_INDEX_FLOOR_MAX + 5);
	});

	it('a bare-seed boot starts at the tip times the stride and avoids previously used low indices', () => {
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
			// Born from a bare seed with no tip yet: the row holds the birth
			// marker until the floor fires.
			expect(manager.channelIndexTipFloorArmed).to.equal(true);
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal('0');
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			// The floor fired: its value is the row, written once.
			expect(manager.channelIndexTipFloorArmed).to.equal(false);
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));

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
			expect(channel!.channelKeyIndex).to.equal(FLOOR);
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
			const fresh = deriveChannelKeys(root, LnCoinType.REGTEST, FLOOR);
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
			expect(manager.nextChannelIndex).to.equal(FLOOR + 1);

			// A later header on the same boot moves neither the counter nor
			// the row: the floor is a one-time snapshot of the birth tip
			// (times the stride).
			node.handleNewBlock(TIP + 5);
			expect(manager.nextChannelIndex).to.equal(FLOOR + 1);
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));

			// Once the channel is journaled, a second boot continues from
			// max(table, row) = FLOOR + 1 before any header, and headers do
			// not move it.
			storage.saveChannelKeyIndex(open.tempId.toString('hex'), FLOOR);
			node.destroy();
			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			second = bootNode(reopened);
			const again = second.getChannelManager();
			expect(again.channelIndexTipFloorArmed).to.equal(false);
			expect(again.nextChannelIndex).to.equal(FLOOR + 1);
			second.handleNewBlock(TIP + 500);
			expect(again.nextChannelIndex).to.equal(FLOOR + 1);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
		} finally {
			if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('a later boot seeds the counter from max(table, floor) and no header moves it', () => {
		// The floor above the table (rows a partial restore landed below
		// it), then the table above the floor (channels opened since).
		for (const [rows, floor, expected] of [
			[[3, 7], FLOOR, FLOOR],
			[[3, FLOOR + 20], FLOOR, FLOOR + 21]
		] as Array<[number[], number, number]>) {
			const storage = new SqliteStorage(':memory:');
			storage.open();
			rows.forEach((idx, i) => storage.saveChannelKeyIndex(`ch${i}`, idx));
			storage.saveMetadata(FLOOR_KEY, String(floor));
			const node = bootNode(storage);
			try {
				const manager = node.getChannelManager();
				expect(manager.channelIndexTipFloorArmed).to.equal(false);
				expect(manager.nextChannelIndex).to.equal(expected);
				node.handleNewBlock(TIP + 1000);
				expect(manager.nextChannelIndex).to.equal(expected);
				expect(storage.loadMetadata(FLOOR_KEY)).to.equal(String(floor));
			} finally {
				node.destroy();
				storage.close();
			}
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
				expect(armed.getChannelManager().nextChannelIndex).to.equal(FLOOR);
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

	it('a partial SCB restore cannot reuse an omitted index below the persisted floor on either boot', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ckif-'));
		const dbPath = path.join(dir, 'wallet.db');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		let third: LightningNode | null = null;
		try {
			const manager = node.getChannelManager();
			node.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));

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
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			node.destroy();

			// Boot 2 reads a POPULATED table whose top index is the dropped
			// channel's predecessor: without the row the floor would not arm
			// and the counter would be 4. From the row alone, before any
			// header, it is FLOOR, and the LSP's open lands there.
			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			expect(reopened.loadNextChannelIndex()).to.equal(4);
			second = bootNode(reopened);
			const again = second.getChannelManager();
			expect(again.channelIndexTipFloorArmed).to.equal(false);
			expect(again.nextChannelIndex).to.equal(FLOOR);
			const first = acceptLspOpen(second, 'lsp-partial-1');
			expect(first.channelKeyIndex).to.equal(FLOOR);
			for (const idx of [1, 2, 3, 4]) expectKeysDiffer(first, idx);
			expect(again.nextChannelIndex).to.equal(FLOOR + 1);
			// Headers move neither the counter nor the row: the row is the
			// birth tip, written once, and the consumed index is the table's
			// to record once the channel persists.
			second.handleNewBlock(TIP + 9);
			expect(again.nextChannelIndex).to.equal(FLOOR + 1);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
			reopened.saveChannelKeyIndex(
				first.getTemporaryChannelId().toString('hex'),
				FLOOR
			);
			second.destroy();

			// Boot 3: max(table, row) = FLOOR + 1. The next open lands there,
			// unlike every earlier key, and shares no per-commitment seed
			// with the first; headers still move nothing.
			const third_ = new SqliteStorage(dbPath);
			third_.open();
			third = bootNode(third_);
			const more = third.getChannelManager();
			expect(more.nextChannelIndex).to.equal(FLOOR + 1);
			const opened = acceptLspOpen(third, 'lsp-partial-2');
			expect(opened.channelKeyIndex).to.equal(FLOOR + 1);
			for (const idx of [1, 2, 3, 4, FLOOR]) expectKeysDiffer(opened, idx);
			expect(
				opened
					.getFullState()
					.localPerCommitmentSeed.equals(
						first.getFullState().localPerCommitmentSeed
					)
			).to.equal(false);
			third.handleNewBlock(TIP + 20);
			expect(more.nextChannelIndex).to.equal(FLOOR + 2);
			expect(third_.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
		} finally {
			if (third) third.destroy();
			else if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('a birth boot that restarts before any tip re-arms on the next boot', () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ckif-'));
		const dbPath = path.join(dir, 'wallet.db');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		let third: LightningNode | null = null;
		try {
			// No header on the birth boot: the floor stays armed and the row
			// holds only the birth marker.
			expect(node.getChannelManager().channelIndexTipFloorArmed).to.equal(true);
			expect(node.getChannelManager().nextChannelIndex).to.equal(1);
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal('0');
			node.destroy();

			// Boot 2 is a birth boot again: its first header floors the
			// counter at the tip and writes the value, once.
			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			second = bootNode(reopened);
			const manager = second.getChannelManager();
			expect(manager.channelIndexTipFloorArmed).to.equal(true);
			expect(manager.nextChannelIndex).to.equal(1);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal('0');
			second.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			expect(manager.channelIndexTipFloorArmed).to.equal(false);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
			second.handleNewBlock(TIP + 3);
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
			second.destroy();

			// Boot 3 seeds from the row, unarmed, and no header moves it.
			const again = new SqliteStorage(dbPath);
			again.open();
			third = bootNode(again);
			const later = third.getChannelManager();
			expect(later.channelIndexTipFloorArmed).to.equal(false);
			expect(later.nextChannelIndex).to.equal(FLOOR);
			third.handleNewBlock(TIP + 100);
			expect(later.nextChannelIndex).to.equal(FLOOR);
			expect(again.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
		} finally {
			if (third) third.destroy();
			else if (second) second.destroy();
			else node.destroy();
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it('a birth boot that restores before its first header is a birth boot again after a restart', async () => {
		// The birth boot never learns a tip (the daemon fences opens until
		// it does), a partial SCB restore lands rows 1..3, and the process
		// restarts. The table is populated on boot 2, so only the birth
		// marker tells it from a wallet that was populated all its life.
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-ckif-'));
		const dbPath = path.join(dir, 'wallet.db');
		const storage = new SqliteStorage(dbPath);
		storage.open();
		const node = bootNode(storage);
		let second: LightningNode | null = null;
		try {
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal('0');
			const result = await node.recoverFromStaticChannelBackup(
				[1, 2, 3].map(scbEntry)
			);
			expect(result.skipped).to.deep.equal([]);
			expect(node.getChannelManager().nextChannelIndex).to.equal(4);
			// Still no tip: the marker stands.
			expect(storage.loadMetadata(FLOOR_KEY)).to.equal('0');
			node.destroy();

			const reopened = new SqliteStorage(dbPath);
			reopened.open();
			expect(reopened.loadNextChannelIndex()).to.equal(4);
			second = bootNode(reopened);
			const manager = second.getChannelManager();
			// Nothing better is known yet: the table's 4 stands, armed, until
			// the first header floors it at the tip.
			expect(manager.channelIndexTipFloorArmed).to.equal(true);
			expect(manager.nextChannelIndex).to.equal(4);
			second.handleNewBlock(TIP);
			expect(manager.nextChannelIndex).to.equal(FLOOR);
			expect(manager.channelIndexTipFloorArmed).to.equal(false);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
			const opened = acceptLspOpen(second, 'lsp-blind');
			expect(opened.channelKeyIndex).to.equal(FLOOR);
			for (const idx of [1, 2, 3, 4]) expectKeysDiffer(opened, idx);
			second.handleNewBlock(TIP + 5);
			expect(manager.nextChannelIndex).to.equal(FLOOR + 1);
			expect(reopened.loadMetadata(FLOOR_KEY)).to.equal(String(FLOOR));
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
		// which distinct indices avoid. The floor provides bounded separation.
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
		// A floored one: its first channel sits at the tip times the stride.
		const floored = makeManager('nonce-floored');
		floored.armChannelIndexTipFloor(TIP);
		const d = floored.openChannel(peer, 100_000n);
		expect(d.channelKeyIndex).to.equal(FLOOR);

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
