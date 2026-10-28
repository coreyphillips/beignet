/**
 * A durable record of the fundings a channel has locked (issue #1899).
 *
 * A client could not tell that a funding had locked once the channel had
 * closed, or while its peer was away: the state it reads says neither. The
 * channel now keeps `lockedFundingTxids`, appended when channel_ready has
 * crossed both ways for the open and when splice_locked has for a splice,
 * kept through close and reported by listChannels. Rows written before the
 * field existed are seeded on restore with what the row proves, and a
 * direct-funding payment's received record carries `lockedAt` from the lock.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import {
	createAcceptorState,
	createOpenerState,
	IChannelState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeAcceptChannelMessage,
	decodeOpenChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeChannelReadyMessage,
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage
} from '../../src/lightning/message/channel-funding';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import {
	estimateSpliceTxWeight,
	spliceFeeSats
} from '../../src/lightning/channel/splice-weight';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { MemoryStorage } from '../../src/lightning/storage/memory-storage';
import { DirectFundingReceiver } from '../../src/lightning/direct-funding/receiver/engine';
import {
	signerFromSeed,
	realInitialCommitmentSig
} from './helpers/real-signing';
import { writableState } from './helpers/writable-state';
import { COMMIT_ALL } from './helpers/channel-persistence';

const FUNDING_SATOSHIS = 1_000_000n;

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
		firstPerCommitmentPoint: getPublicKey(crypto.randomBytes(32))
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findSendAction(actions: any[], msgType: MessageType): any {
	return actions.find(
		(a) => a.type === 'SEND_MESSAGE' && a.messageType === msgType
	);
}

const display = (b: Buffer): string => Buffer.from(b).reverse().toString('hex');

const lockedHex = (channel: Channel): string[] | undefined =>
	channel.getFullState().lockedFundingTxids?.map((t) => t.toString('hex'));

/**
 * A v1 open between two Channel objects with real signatures, stopped before
 * either side has seen the funding confirm.
 */
function pendingOpen(): {
	opener: Channel;
	acceptor: Channel;
	fundingTxid: Buffer;
} {
	const openerSeed = crypto.randomBytes(32);
	const acceptorSeed = crypto.randomBytes(32);
	const openerBasepoints = makeBasepoints(openerSeed);
	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: crypto.randomBytes(32),
			fundingSatoshis: FUNDING_SATOSHIS,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: openerBasepoints,
			localPerCommitmentSeed: crypto.randomBytes(32)
		})
	);
	const openActions = opener.initiateOpen();
	const openMsg = decodeOpenChannelMessage(
		findSendAction(openActions, MessageType.OPEN_CHANNEL).payload
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: openMsg.temporaryChannelId,
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: makeBasepoints(acceptorSeed),
			localPerCommitmentSeed: crypto.randomBytes(32),
			remoteBasepoints: openerBasepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));
	const acceptActions = acceptor.handleOpenChannel(openMsg);
	opener.handleAcceptChannel(
		decodeAcceptChannelMessage(
			findSendAction(acceptActions, MessageType.ACCEPT_CHANNEL).payload
		)
	);
	const fundingTxid = crypto.randomBytes(32);
	const fcActions = opener.createFundingCreated(
		fundingTxid,
		0,
		realInitialCommitmentSig(opener, fundingTxid, 0)
	);
	const fc = decodeFundingCreatedMessage(
		findSendAction(fcActions, MessageType.FUNDING_CREATED).payload
	);
	const fsActions = acceptor.handleFundingCreated(
		fc,
		realInitialCommitmentSig(acceptor, fc.fundingTxid, fc.fundingOutputIndex)
	);
	opener.handleFundingSigned(
		decodeFundingSignedMessage(
			findSendAction(fsActions, MessageType.FUNDING_SIGNED).payload
		)
	);
	expect(opener.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
	expect(acceptor.getState()).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);
	return { opener, acceptor, fundingTxid };
}

describe('Locked fundings: the open (issue #1899)', function () {
	it('records the funding on both sides, whichever side sends channel_ready last', function () {
		const { opener, acceptor, fundingTxid } = pendingOpen();
		const funding = fundingTxid.toString('hex');

		// The opener's channel_ready goes first: nothing has locked yet.
		const openerReady = findSendAction(
			opener.fundingConfirmed(),
			MessageType.CHANNEL_READY
		);
		expect(opener.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
		expect(lockedHex(opener)).to.equal(undefined);
		acceptor.handleChannelReady(decodeChannelReadyMessage(openerReady.payload));
		expect(lockedHex(acceptor)).to.equal(undefined);

		// The acceptor sends last: its own confirmation completes the exchange.
		const acceptorReady = findSendAction(
			acceptor.fundingConfirmed(),
			MessageType.CHANNEL_READY
		);
		expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		expect(lockedHex(acceptor)).to.deep.equal([funding]);

		// The opener receives last.
		expect(lockedHex(opener)).to.equal(undefined);
		opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(lockedHex(opener)).to.deep.equal([funding]);
	});

	it('a duplicate channel_ready, a repeat confirmation and a second backfill add nothing', function () {
		const { opener, acceptor, fundingTxid } = pendingOpen();
		const acceptorReady = findSendAction(
			acceptor.fundingConfirmed(),
			MessageType.CHANNEL_READY
		);
		const openerReady = findSendAction(
			opener.fundingConfirmed(),
			MessageType.CHANNEL_READY
		);
		opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));
		acceptor.handleChannelReady(decodeChannelReadyMessage(openerReady.payload));
		expect(lockedHex(opener)).to.deep.equal([fundingTxid.toString('hex')]);

		opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));
		opener.fundingConfirmed();
		expect(opener.backfillLockedFundingTxids()).to.equal(false);
		expect(lockedHex(opener)).to.deep.equal([fundingTxid.toString('hex')]);
		expect(opener.hasLockedFunding(display(fundingTxid))).to.equal(true);
		expect(opener.hasLockedFunding(fundingTxid.toString('hex'))).to.equal(
			false
		);
	});
});

// ─────────────── A splice, driven between two managers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`locked-funding-seed-${id}`))
		.digest();
}

function makeConfig(seedId: number): IChannelManagerConfig {
	const seed = makeSeed(seedId);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: makeSeed(seedId + 100),
		localFundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest(),
		htlcBasepointSecret: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([4]))
			.digest(),
		persistence: COMMIT_ALL
	};
}

function normalManagerPair(): {
	openerConfig: IChannelManagerConfig;
	openerManager: ChannelManager;
	acceptorManager: ChannelManager;
	openerPubkey: string;
	acceptorPubkey: string;
	channelId: Buffer;
	openerChannel: Channel;
	acceptorChannel: Channel;
	fundingTxid: Buffer;
} {
	const openerConfig = makeConfig(1899);
	const acceptorConfig = makeConfig(1900);
	const openerPubkey =
		openerConfig.localBasepoints.fundingPubkey.toString('hex');
	const acceptorPubkey =
		acceptorConfig.localBasepoints.fundingPubkey.toString('hex');
	const openerManager = new ChannelManager(openerConfig);
	const acceptorManager = new ChannelManager(acceptorConfig);
	openerManager.on('error', () => {});
	acceptorManager.on('error', () => {});
	openerManager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === acceptorPubkey)
				acceptorManager.handleMessage(openerPubkey, type, payload);
		}
	);
	acceptorManager.on(
		'message:outbound',
		(peer: string, type: number, payload: Buffer) => {
			if (peer === openerPubkey)
				openerManager.handleMessage(acceptorPubkey, type, payload);
		}
	);
	const openerChannel = openerManager.openChannel(
		acceptorPubkey,
		FUNDING_SATOSHIS
	);
	const fundingTxid = crypto.randomBytes(32);
	openerManager.createFunding(
		openerChannel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	);
	const channelId = openerChannel.getChannelId()!;
	openerManager.handleFundingConfirmed(channelId);
	acceptorManager.handleFundingConfirmed(channelId);
	const acceptorChannel = acceptorManager.getChannelsByPeer(openerPubkey)[0];
	expect(openerChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
	return {
		openerConfig,
		openerManager,
		acceptorManager,
		openerPubkey,
		acceptorPubkey,
		channelId,
		openerChannel,
		acceptorChannel,
		fundingTxid
	};
}

/** A splice-out negotiated and signed both ways, splice_locked not yet sent. */
function pendingLockSplice(pair: ReturnType<typeof normalManagerPair>): void {
	pair.openerManager.initiateQuiescence(pair.channelId);
	const destScript = Buffer.concat([
		Buffer.from([0x00, 0x14]),
		crypto.randomBytes(20)
	]);
	const fee = spliceFeeSats(
		estimateSpliceTxWeight({
			walletInputCount: 0,
			destinationScriptLen: destScript.length
		}),
		253
	);
	pair.openerChannel.setSpliceOutDestination(destScript, 50_000n);
	expect(
		pair.openerManager.initiateSplice(pair.channelId, -(50_000n + fee), 253).ok
	).to.equal(true);
	expect(pair.openerChannel.isSplicePendingLock()).to.equal(true);
	expect(pair.acceptorChannel.isSplicePendingLock()).to.equal(true);
}

/** The row as an older version wrote it: the same state with no field. */
function legacyCopy(state: Readonly<IChannelState>): IChannelState {
	const json = JSON.parse(JSON.stringify(serializeChannelState(state)));
	delete json.lockedFundingTxids;
	return deserializeChannelState(json);
}

describe('Locked fundings: a splice (issue #1899)', function () {
	it('records the new funding once splice_locked has crossed both ways, after the open', function () {
		const pair = normalManagerPair();
		const open = pair.fundingTxid.toString('hex');
		expect(lockedHex(pair.openerChannel)).to.deep.equal([open]);
		expect(lockedHex(pair.acceptorChannel)).to.deep.equal([open]);

		pendingLockSplice(pair);
		// The pending-lock window: the channel still runs on, and has still
		// locked only, the open's funding.
		expect(pair.openerChannel.getState()).to.equal(ChannelState.SPLICING);
		expect(
			pair.openerChannel.getFullState().fundingTxid!.toString('hex')
		).to.equal(open);
		expect(lockedHex(pair.openerChannel)).to.deep.equal([open]);

		// One side's splice_locked is not a lock.
		pair.openerManager.sendSpliceLocked(pair.channelId);
		expect(pair.openerChannel.getState()).to.equal(ChannelState.SPLICING);
		expect(lockedHex(pair.openerChannel)).to.deep.equal([open]);
		expect(lockedHex(pair.acceptorChannel)).to.deep.equal([open]);

		// The acceptor sends last and the opener receives last: both record it.
		pair.acceptorManager.sendSpliceLocked(pair.channelId);
		expect(pair.openerChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.acceptorChannel.getState()).to.equal(ChannelState.NORMAL);
		const splice = pair.openerChannel.getFullState().fundingTxid!;
		expect(splice.toString('hex')).to.not.equal(open);
		expect(lockedHex(pair.openerChannel)).to.deep.equal([
			open,
			splice.toString('hex')
		]);
		expect(lockedHex(pair.acceptorChannel)).to.deep.equal([
			open,
			splice.toString('hex')
		]);
		expect(pair.openerChannel.hasLockedFunding(display(splice))).to.equal(true);
	});

	it('a legacy row in the pending-lock window is seeded with the old funding only', function () {
		const pair = normalManagerPair();
		pendingLockSplice(pair);
		const row = new Channel(legacyCopy(pair.openerChannel.getFullState()));
		expect(row.getFullState().lockedFundingTxids).to.equal(undefined);
		expect(row.backfillLockedFundingTxids()).to.equal(true);
		expect(lockedHex(row)).to.deep.equal([pair.fundingTxid.toString('hex')]);
	});
});

describe('Locked fundings: persistence and the restore backfill (issue #1899)', function () {
	function normalChannel(): { channel: Channel; fundingTxid: Buffer } {
		const { opener, acceptor, fundingTxid } = pendingOpen();
		const acceptorReady = findSendAction(
			acceptor.fundingConfirmed(),
			MessageType.CHANNEL_READY
		);
		opener.fundingConfirmed();
		opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady.payload));
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		return { channel: opener, fundingTxid };
	}

	it('round-trips through the serialized state; an older row reads as absent', function () {
		const { channel, fundingTxid } = normalChannel();
		const json = JSON.parse(
			JSON.stringify(serializeChannelState(channel.getFullState()))
		);
		expect(json.lockedFundingTxids).to.deep.equal([
			fundingTxid.toString('hex')
		]);
		const restored = deserializeChannelState(json);
		expect(Buffer.isBuffer(restored.lockedFundingTxids![0])).to.equal(true);
		expect(restored.lockedFundingTxids![0].equals(fundingTxid)).to.equal(true);
		expect(legacyCopy(channel.getFullState()).lockedFundingTxids).to.equal(
			undefined
		);
		// A channel that has locked nothing writes no field.
		const { opener } = pendingOpen();
		expect(
			JSON.parse(JSON.stringify(serializeChannelState(opener.getFullState())))
		).to.not.have.property('lockedFundingTxids');
	});

	describe('the backfill of a row written before the field', function () {
		/** Seed a legacy copy of a NORMAL row reshaped by `shape`. */
		function seeded(shape: (s: IChannelState) => void): {
			locked: string[] | undefined;
			fundingTxid: Buffer;
		} {
			const { channel, fundingTxid } = normalChannel();
			const state = legacyCopy(channel.getFullState());
			shape(state);
			const row = new Channel(state);
			row.backfillLockedFundingTxids();
			return { locked: lockedHex(row), fundingTxid };
		}

		it('seeds the funding of an open channel, wrapped for reestablish or not', function () {
			for (const shape of [
				(): void => {},
				(s: IChannelState): void => {
					s.state = ChannelState.AWAITING_REESTABLISH;
					s.preReestablishState = ChannelState.NORMAL;
				},
				(s: IChannelState): void => {
					s.state = ChannelState.SHUTTING_DOWN;
				},
				(s: IChannelState): void => {
					s.state = ChannelState.AWAITING_REESTABLISH;
					s.preReestablishState = ChannelState.NEGOTIATING_CLOSING;
				}
			]) {
				const { locked, fundingTxid } = seeded(shape);
				expect(locked).to.deep.equal([fundingTxid.toString('hex')]);
			}
		});

		it("seeds a spliced channel's open and current fundings, oldest first", function () {
			const splice = crypto.randomBytes(32);
			const { locked, fundingTxid } = seeded((s) => {
				s.previousFundingTxids = [Buffer.from(s.fundingTxid!)];
				s.fundingTxid = splice;
			});
			expect(locked).to.deep.equal([
				fundingTxid.toString('hex'),
				splice.toString('hex')
			]);
		});

		it('seeds nothing for an open whose channel_ready has not crossed both ways', function () {
			for (const shape of [
				(s: IChannelState): void => {
					s.state = ChannelState.AWAITING_CHANNEL_READY;
					s.remoteChannelReady = false;
				},
				(s: IChannelState): void => {
					s.state = ChannelState.AWAITING_REESTABLISH;
					s.preReestablishState = ChannelState.AWAITING_CHANNEL_READY;
					s.localChannelReady = false;
				},
				(s: IChannelState): void => {
					s.state = ChannelState.FORCE_CLOSED;
					s.localChannelReady = false;
					s.remoteChannelReady = false;
				}
			]) {
				expect(seeded(shape).locked).to.equal(undefined);
			}
		});

		it("seeds a closed channel with its open's funding only", function () {
			// The current funding of a closed channel may have been adopted by a
			// force close, which locks nothing.
			const splice = crypto.randomBytes(32);
			const forced = seeded((s) => {
				s.state = ChannelState.FORCE_CLOSED;
				s.previousFundingTxids = [Buffer.from(s.fundingTxid!)];
				s.fundingTxid = splice;
			});
			expect(forced.locked).to.deep.equal([forced.fundingTxid.toString('hex')]);
			// A stale preReestablishState on a closed row does not count.
			const closed = seeded((s) => {
				s.state = ChannelState.CLOSED;
				s.preReestablishState = ChannelState.NORMAL;
				s.previousFundingTxids = [Buffer.from(s.fundingTxid!)];
				s.fundingTxid = splice;
			});
			expect(closed.locked).to.deep.equal([closed.fundingTxid.toString('hex')]);
		});

		it('seeds no open funding for a row spliced before previousFundingTxids existed', function () {
			// Before 0.31 a splice left no history, so fundingTxid may be a
			// splice a force close adopted with no lock. Every adoption leaves
			// spliceFundingTxid equal to it, and since #1020 sets hasBeenSpliced.
			const splice = crypto.randomBytes(32);
			const preHistory = seeded((s) => {
				s.state = ChannelState.FORCE_CLOSED;
				s.fundingTxid = splice;
				s.spliceFundingTxid = Buffer.from(splice);
				delete s.hasBeenSpliced;
			});
			expect(preHistory.locked).to.equal(undefined);
			const flagged = seeded((s) => {
				s.state = ChannelState.FORCE_CLOSED;
				s.fundingTxid = splice;
				s.hasBeenSpliced = true;
			});
			expect(flagged.locked).to.equal(undefined);
			// The same row while the channel is open: its current funding was
			// adopted by completeSplice, so it locked, and only it is seeded.
			const open = seeded((s) => {
				s.fundingTxid = splice;
				s.spliceFundingTxid = Buffer.from(splice);
				s.hasBeenSpliced = true;
			});
			expect(open.locked).to.deep.equal([splice.toString('hex')]);
			// A first splice still in flight leaves the open's funding as the
			// current one, and it is seeded.
			const inFlight = seeded((s) => {
				s.state = ChannelState.FORCE_CLOSED;
				s.spliceFundingTxid = crypto.randomBytes(32);
			});
			expect(inFlight.locked).to.deep.equal([
				inFlight.fundingTxid.toString('hex')
			]);
		});

		it('leaves a row that already carries the field alone', function () {
			const other = crypto.randomBytes(32);
			const { channel } = normalChannel();
			writableState(channel).lockedFundingTxids = [other];
			expect(channel.backfillLockedFundingTxids()).to.equal(false);
			expect(lockedHex(channel)).to.deep.equal([other.toString('hex')]);
		});
	});

	it('ChannelManager.restoreChannel seeds a legacy row, and the next write carries it', function () {
		const pair = normalManagerPair();
		const row = new Channel(legacyCopy(pair.openerChannel.getFullState()));
		const manager = new ChannelManager(pair.openerConfig);
		manager.on('error', () => {});
		manager.restoreChannel(row, pair.acceptorPubkey);
		const restored = manager.getChannel(pair.channelId)!;
		expect(restored.getState()).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(lockedHex(restored)).to.deep.equal([
			pair.fundingTxid.toString('hex')
		]);
		expect(
			serializeChannelState(restored.getFullState()).lockedFundingTxids
		).to.deep.equal([pair.fundingTxid.toString('hex')]);
	});
});

// ─────────────── On the node ───────────────

/** A backend that accepts every broadcast. */
class AcceptingBackend implements IChainBackend {
	async subscribeToHeaders(): Promise<void> {}
	async subscribeToScriptHash(): Promise<void> {}
	async getScriptHashHistory(): Promise<
		Array<{ txid: string; height: number }>
	> {
		return [];
	}
	async getTransaction(): Promise<Buffer> {
		throw new Error('not needed');
	}
	async broadcastTransaction(hex: string): Promise<string> {
		return bitcoin.Transaction.fromHex(hex).getId();
	}
}

function makeNodeConfig(
	seedId: number,
	extra: Partial<INodeConfig> = {}
): INodeConfig {
	const seed = makeSeed(seedId);
	return {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
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
		...extra
	};
}

function wire(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

const tick = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe('Locked fundings on the node (issue #1899)', function () {
	this.timeout(10_000);
	const nodes: LightningNode[] = [];
	afterEach(function () {
		for (const n of nodes.splice(0)) n.destroy();
	});

	function node(
		seedId: number,
		extra: Partial<INodeConfig> = {}
	): LightningNode {
		const n = new LightningNode(makeNodeConfig(seedId, extra));
		n.on('node:error', () => {});
		nodes.push(n);
		return n;
	}

	/** Open alice to bob up to the funding; the caller confirms it. */
	function fund(
		alice: LightningNode,
		bob: LightningNode
	): { channelId: Buffer; fundingTxid: Buffer } {
		wire(alice, bob);
		const fundingTxid = crypto.randomBytes(32);
		const channelId = alice.createFunding(
			alice.openChannel(bob.getNodeId(), FUNDING_SATOSHIS),
			fundingTxid,
			0,
			crypto.randomBytes(64)
		)!;
		return { channelId, fundingTxid };
	}

	const listed = (
		n: LightningNode,
		channelId: Buffer
	): ReturnType<LightningNode['listChannels']>[number] =>
		n.listChannels().find((c) => c.channelId.equals(channelId))!;

	it('reports the lock in display order, writes it with the transition, and keeps it through a force close and a restart', async function () {
		const storage = new MemoryStorage();
		const alice = node(18991, {
			storage,
			chainBackend: new AcceptingBackend()
		});
		const bob = node(18992);
		const { channelId, fundingTxid } = fund(alice, bob);
		expect(listed(alice, channelId)).to.not.have.property('lockedFundingTxids');
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		await tick();

		for (const n of [alice, bob]) {
			expect(listed(n, channelId).state).to.equal(ChannelState.NORMAL);
			expect(listed(n, channelId).lockedFundingTxids).to.deep.equal([
				display(fundingTxid)
			]);
		}
		// Internal order on disk, written by the persist the lock had.
		expect(
			storage
				.loadChannel(channelId.toString('hex'))!
				.state.lockedFundingTxids!.map((t) => t.toString('hex'))
		).to.deep.equal([fundingTxid.toString('hex')]);

		const destination = bitcoin.payments.p2wpkh({
			pubkey: Buffer.from(alice.getNodeId(), 'hex')
		}).output!;
		expect(alice.forceCloseChannel(channelId, destination).ok).to.equal(true);
		const closed = listed(alice, channelId);
		expect(closed.state).to.equal(ChannelState.FORCE_CLOSED);
		expect(closed.lockedFundingTxids).to.deep.equal([display(fundingTxid)]);

		// A restart reads it back from the row.
		alice.removeAllListeners('message:outbound');
		const restarted = node(18991, { storage });
		expect(listed(restarted, channelId).lockedFundingTxids).to.deep.equal([
			display(fundingTxid)
		]);
	});

	it('seeds a row written before the field when the node restores it', async function () {
		const storage = new MemoryStorage();
		const alice = node(18993, { storage });
		const bob = node(18994);
		const { channelId, fundingTxid } = fund(alice, bob);
		alice.handleFundingConfirmed(channelId);
		bob.handleFundingConfirmed(channelId);
		await tick();

		// Rewrite the row as an older version wrote it.
		const id = channelId.toString('hex');
		const row = storage.loadChannel(id)!;
		delete row.state.lockedFundingTxids;
		storage.saveChannel(id, row.state, row.peerPubkey);
		expect(storage.loadChannel(id)!.state.lockedFundingTxids).to.equal(
			undefined
		);

		alice.removeAllListeners('message:outbound');
		const restarted = node(18993, { storage });
		const info = listed(restarted, channelId);
		expect(info.state).to.equal(ChannelState.AWAITING_REESTABLISH);
		expect(info.lockedFundingTxids).to.deep.equal([display(fundingTxid)]);
	});

	describe('the direct-funding received record', function () {
		const OFFER = 'a1'.repeat(16);

		/** A PAID receipt bound to `channelId` and its funding, as the receiver leaves one. */
		function paidAgainst(
			requests: NonNullable<
				ReturnType<LightningNode['getDirectFundingRequests']>
			>,
			channelId: Buffer,
			fundingTxid: Buffer
		): string {
			const request = requests.mint();
			requests.beginAttempt(request.receiptHash, OFFER, Date.now() + 60_000);
			requests.markAttemptFunding(
				request.receiptHash,
				OFFER,
				{
					outpoint: `${display(fundingTxid)}:0`,
					channelId: channelId.toString('hex'),
					splice: false,
					contentHash: 'ef'.repeat(32),
					payerEphemeralKey: `02${'ab'.repeat(32)}`,
					fundingTxid: display(fundingTxid)
				},
				Date.now() + 60_000
			);
			requests.markReceiptRevealed(request.receiptHash, {
				offerIdHex: OFFER,
				fundingTxidHex: display(fundingTxid)
			});
			return request.receiptHash;
		}

		it('an open that locked and then lost its funding takes its payment back (issue #1909)', async function () {
			// A zero-conf open locks before its funding confirms; a payer that
			// double-spends the funding leaves the node to void the channel.
			const alice = node(19001, { directFunding: {} });
			const bob = node(19002);
			const requests = alice.getDirectFundingRequests()!;
			const { channelId, fundingTxid } = fund(alice, bob);
			const receipt = paidAgainst(requests, channelId, fundingTxid);
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			await tick();
			expect(requests.receivedFor(receipt)!.lockedAt).to.be.a('number');

			const voided = (
				alice as unknown as {
					voidMissingFundingChannel(id: Buffer, txid: string): boolean;
				}
			).voidMissingFundingChannel(channelId, display(fundingTxid));
			expect(voided).to.equal(true);
			const record = requests.receivedFor(receipt)!;
			expect(record.status).to.equal('REVERTED');
			expect(record.lockedAt, 'the lock it saw stays on record').to.be.a(
				'number'
			);
		});

		it('any other void takes back the payments recorded against that channel only (issue #1909)', function () {
			const alice = node(19003, { directFunding: {} });
			const requests = alice.getDirectFundingRequests()!;
			const voidedId = crypto.randomBytes(32);
			const otherId = crypto.randomBytes(32);
			const gone = paidAgainst(requests, voidedId, crypto.randomBytes(32));
			const kept = paidAgainst(requests, otherId, crypto.randomBytes(32));
			alice.emit('channel:voided', { channelId: voidedId });
			expect(requests.receivedFor(gone)!.status).to.equal('REVERTED');
			expect(requests.receivedFor(kept)!.status).to.equal('PAID');
		});

		it('a lock event stamps lockedAt on the payment its funding carried', async function () {
			const alice = node(18995, { directFunding: {} });
			const bob = node(18996);
			const requests = alice.getDirectFundingRequests()!;
			const { channelId, fundingTxid } = fund(alice, bob);
			const request = requests.mint();
			requests.markReceiptRevealed(request.receiptHash, {
				offerIdHex: OFFER,
				fundingTxidHex: display(fundingTxid)
			});
			const other = requests.mint();
			requests.markReceiptRevealed(other.receiptHash, {
				offerIdHex: OFFER,
				fundingTxidHex: 'ab'.repeat(32)
			});
			expect(requests.receivedFor(request.receiptHash)).to.not.have.property(
				'lockedAt'
			);

			alice.handleFundingConfirmed(channelId);
			expect(requests.receivedFor(request.receiptHash)).to.not.have.property(
				'lockedAt'
			);
			bob.handleFundingConfirmed(channelId);
			await tick();
			expect(listed(alice, channelId).state).to.equal(ChannelState.NORMAL);
			expect(requests.receivedFor(request.receiptHash)!.lockedAt).to.be.a(
				'number'
			);
			expect(requests.receivedFor(other.receiptHash)).to.not.have.property(
				'lockedAt'
			);
		});

		it('a splice lock stamps lockedAt on the payment that funded the splice', async function () {
			const alice = node(18999, { directFunding: {} });
			const bob = node(19000);
			const requests = alice.getDirectFundingRequests()!;
			const { channelId } = fund(alice, bob);
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			await tick();
			const splice = crypto.randomBytes(32);
			const request = requests.mint();
			requests.markReceiptRevealed(request.receiptHash, {
				offerIdHex: OFFER,
				fundingTxidHex: display(splice)
			});
			expect(requests.receivedFor(request.receiptHash)).to.not.have.property(
				'lockedAt'
			);
			// What completeSplice leaves on the channel, then the event the node
			// emits once it has persisted the step (internal byte order).
			const state = writableState(alice.getRawChannel(channelId)!);
			state.lockedFundingTxids = [
				...(state.lockedFundingTxids ?? []),
				Buffer.from(splice)
			];
			alice.emit('splice:complete', { channelId, fundingTxid: splice });
			expect(requests.receivedFor(request.receiptHash)!.lockedAt).to.be.a(
				'number'
			);
		});

		it('the receiver marks, at start, a payment whose funding the channel already locked', async function () {
			const alice = node(18997, { directFunding: {} });
			const bob = node(18998);
			const requests = alice.getDirectFundingRequests()!;
			const { channelId, fundingTxid } = fund(alice, bob);
			alice.handleFundingConfirmed(channelId);
			bob.handleFundingConfirmed(channelId);
			await tick();

			// Recorded after the lock event, so only the channel's own record of
			// the lock can stamp it.
			const request = requests.mint();
			requests.beginAttempt(request.receiptHash, OFFER, Date.now() + 60_000);
			requests.markAttemptFunding(
				request.receiptHash,
				OFFER,
				{
					outpoint: `${display(fundingTxid)}:0`,
					channelId: channelId.toString('hex'),
					splice: false,
					contentHash: 'ef'.repeat(32),
					payerEphemeralKey: `02${'ab'.repeat(32)}`,
					fundingTxid: display(fundingTxid)
				},
				Date.now() + 60_000
			);
			requests.markReceiptRevealed(request.receiptHash, {
				offerIdHex: OFFER,
				fundingTxidHex: display(fundingTxid)
			});
			const before = requests.receivedFor(request.receiptHash)!;
			expect(before.channelId).to.equal(channelId.toString('hex'));
			expect(before).to.not.have.property('lockedAt');

			const receiver = (
				alice as unknown as {
					directFunding: { receiver: DirectFundingReceiver };
				}
			).directFunding.receiver;
			receiver.start();
			receiver.stop();
			expect(requests.receivedFor(request.receiptHash)!.lockedAt).to.be.a(
				'number'
			);
		});
	});
});
