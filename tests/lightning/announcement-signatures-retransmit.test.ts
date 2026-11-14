/**
 * announcement_signatures retransmission and the 6-confirmation hold on
 * channel_announcement (issue #2041, BOLT 7 after bolts#1215 and #1220).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	createOpenerState,
	createAcceptorState
} from '../../src/lightning/channel/channel-state';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelManager } from '../../src/lightning/channel/channel-manager';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { MessageType } from '../../src/lightning/message/types';
import {
	decodeOpenChannelMessage,
	decodeAcceptChannelMessage
} from '../../src/lightning/message/channel-open';
import {
	decodeFundingCreatedMessage,
	decodeFundingSignedMessage,
	decodeChannelReadyMessage
} from '../../src/lightning/message/channel-funding';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { decodeAnnouncementSignaturesMessage } from '../../src/lightning/gossip/messages';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChainBackend } from '../../src/lightning/chain/chain-watcher';
import { Network } from '../../src/lightning/invoice/types';
import {
	signerFromSeed,
	realInitialCommitmentSig
} from './helpers/real-signing';
import { writableState } from './helpers/writable-state';
import { COMMIT_ALL } from './helpers/channel-persistence';

function sha256d(data: Buffer): Buffer {
	return crypto
		.createHash('sha256')
		.update(crypto.createHash('sha256').update(data).digest())
		.digest();
}

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
	}
	return {
		basepoints: {
			fundingPubkey: getPublicKey(privkeys[0]),
			revocationBasepoint: getPublicKey(privkeys[1]),
			paymentBasepoint: getPublicKey(privkeys[2]),
			delayedPaymentBasepoint: getPublicKey(privkeys[3]),
			htlcBasepoint: getPublicKey(privkeys[4]),
			firstPerCommitmentPoint: Buffer.alloc(33)
		},
		privkeys
	};
}

function sendsOf(actions: any[], msgType: MessageType): Buffer[] {
	return actions
		.filter((a) => a.type === 'SEND_MESSAGE' && a.messageType === msgType)
		.map((a) => a.payload as Buffer);
}

function firstSend(actions: any[], msgType: MessageType): Buffer {
	const found = sendsOf(actions, msgType);
	expect(found.length, `a ${msgType} send`).to.be.greaterThan(0);
	return found[0];
}

/** Parse an encoded channel_announcement and verify all four signatures. */
function verifyFullAnnouncement(payload: Buffer): {
	scid: Buffer;
	allValid: boolean;
} {
	const hash = sha256d(payload.subarray(256));
	const sigs: Buffer[] = [];
	let o = 0;
	for (let i = 0; i < 4; i++, o += 64) sigs.push(payload.subarray(o, o + 64));
	o += 2 + payload.readUInt16BE(o) + 32;
	const scid = Buffer.from(payload.subarray(o, o + 8));
	o += 8;
	const keys: Buffer[] = [];
	for (let i = 0; i < 4; i++, o += 33) keys.push(payload.subarray(o, o + 33));
	const allValid = sigs.every((sig, i) => {
		try {
			return ecc.verify(hash, keys[i], sig);
		} catch {
			return false;
		}
	});
	return { scid, allValid };
}

const FUNDING_BLOCK = 700_000;
const FUNDING_TX_INDEX = 42;
const SCID = encodeShortChannelId({
	block: FUNDING_BLOCK,
	txIndex: FUNDING_TX_INDEX,
	outputIndex: 0
});

const openerNodePriv = crypto.createHash('sha256').update('2041-a').digest();
const acceptorNodePriv = crypto.createHash('sha256').update('2041-b').digest();
const openerNodeId = getPublicKey(openerNodePriv);
const acceptorNodeId = getPublicKey(acceptorNodePriv);

interface ISide {
	channel: Channel;
	manager: ChannelManager;
	nodeId: Buffer;
	peerHex: string;
	sign: (data: Buffer) => { nodeSig: Buffer; bitcoinSig: Buffer };
	ready: Buffer[];
}

/**
 * Two public channels (opener A, acceptor B), each held by its own
 * ChannelManager, with outbound messages delivered to the other side unless
 * `drop` says otherwise. With `openerAwaitingReady` the opener stops one step
 * short of NORMAL: it has sent channel_ready but not received B's, which is
 * returned for the test to deliver.
 */
function setupPair(opts: { openerAwaitingReady?: boolean } = {}): {
	a: ISide;
	b: ISide;
	channelId: Buffer;
	drop: { aToB: boolean; bToA: boolean };
	delivered: Array<{ from: 'a' | 'b'; type: MessageType }>;
	pendingOpenerReady: Buffer | null;
} {
	const openerSeed = Buffer.alloc(32, 0x71);
	const acceptorSeed = Buffer.alloc(32, 0x72);
	const opener_ = makeBasepoints(openerSeed);
	const acceptor_ = makeBasepoints(acceptorSeed);
	const openerCommitmentSeed = Buffer.alloc(32, 0x73);
	const acceptorCommitmentSeed = Buffer.alloc(32, 0x74);

	const opener = new Channel(
		createOpenerState({
			temporaryChannelId: Buffer.alloc(32, 0xee),
			fundingSatoshis: 1_000_000n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: opener_.basepoints,
			localPerCommitmentSeed: openerCommitmentSeed
		})
	);
	const acceptor = new Channel(
		createAcceptorState({
			temporaryChannelId: Buffer.alloc(32, 0xee),
			fundingSatoshis: 0n,
			pushMsat: 0n,
			localConfig: { ...DEFAULT_CHANNEL_CONFIG },
			localBasepoints: acceptor_.basepoints,
			localPerCommitmentSeed: acceptorCommitmentSeed,
			remoteBasepoints: opener_.basepoints,
			remoteConfig: { ...DEFAULT_CHANNEL_CONFIG }
		})
	);
	opener.setSigner(signerFromSeed(openerSeed));
	acceptor.setSigner(signerFromSeed(acceptorSeed));

	const openActions = opener.initiateOpen();
	const acceptActions = acceptor.handleOpenChannel(
		decodeOpenChannelMessage(firstSend(openActions, MessageType.OPEN_CHANNEL))
	);
	opener.handleAcceptChannel(
		decodeAcceptChannelMessage(
			firstSend(acceptActions, MessageType.ACCEPT_CHANNEL)
		)
	);
	const fundingTxid = crypto.randomBytes(32);
	const fc = decodeFundingCreatedMessage(
		firstSend(
			opener.createFundingCreated(
				fundingTxid,
				0,
				realInitialCommitmentSig(opener, fundingTxid, 0)
			),
			MessageType.FUNDING_CREATED
		)
	);
	opener.handleFundingSigned(
		decodeFundingSignedMessage(
			firstSend(
				acceptor.handleFundingCreated(
					fc,
					realInitialCommitmentSig(
						acceptor,
						fc.fundingTxid,
						fc.fundingOutputIndex
					)
				),
				MessageType.FUNDING_SIGNED
			)
		)
	);
	acceptor.handleChannelReady(
		decodeChannelReadyMessage(
			firstSend(opener.fundingConfirmed(), MessageType.CHANNEL_READY)
		)
	);
	const acceptorReady = firstSend(
		acceptor.fundingConfirmed(),
		MessageType.CHANNEL_READY
	);
	let pendingOpenerReady: Buffer | null = acceptorReady;
	if (!opts.openerAwaitingReady) {
		opener.handleChannelReady(decodeChannelReadyMessage(acceptorReady));
		pendingOpenerReady = null;
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
	}
	expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
	writableState(opener).announceChannel = true;
	writableState(acceptor).announceChannel = true;

	const channelId = opener.getChannelId()!;
	const idHex = channelId.toString('hex');
	const makeManager = (
		channel: Channel,
		basepoints: IChannelBasepoints,
		commitmentSeed: Buffer,
		fundingPriv: Buffer,
		nodePriv: Buffer,
		peerHex: string
	): ChannelManager => {
		const manager = new ChannelManager({
			localBasepoints: basepoints,
			localPerCommitmentSeed: commitmentSeed,
			localFundingPrivkey: fundingPriv,
			nodePrivateKey: nodePriv,
			persistence: COMMIT_ALL
		});
		(manager as any).channels.set(idHex, channel);
		(manager as any).channelPeers.set(idHex, peerHex);
		manager.on('error', () => {});
		return manager;
	};
	const mkSign =
		(nodePriv: Buffer, fundingPriv: Buffer) =>
		(data: Buffer): { nodeSig: Buffer; bitcoinSig: Buffer } => {
			const hash = sha256d(data);
			return {
				nodeSig: Buffer.from(ecc.sign(hash, nodePriv)),
				bitcoinSig: Buffer.from(ecc.sign(hash, fundingPriv))
			};
		};
	const a: ISide = {
		channel: opener,
		manager: makeManager(
			opener,
			opener_.basepoints,
			openerCommitmentSeed,
			opener_.privkeys[0],
			openerNodePriv,
			acceptorNodeId.toString('hex')
		),
		nodeId: openerNodeId,
		peerHex: acceptorNodeId.toString('hex'),
		sign: mkSign(openerNodePriv, opener_.privkeys[0]),
		ready: []
	};
	const b: ISide = {
		channel: acceptor,
		manager: makeManager(
			acceptor,
			acceptor_.basepoints,
			acceptorCommitmentSeed,
			acceptor_.privkeys[0],
			acceptorNodePriv,
			openerNodeId.toString('hex')
		),
		nodeId: acceptorNodeId,
		peerHex: openerNodeId.toString('hex'),
		sign: mkSign(acceptorNodePriv, acceptor_.privkeys[0]),
		ready: []
	};

	const drop = { aToB: false, bToA: false };
	const delivered: Array<{ from: 'a' | 'b'; type: MessageType }> = [];
	const wire = (from: ISide, to: ISide, tag: 'a' | 'b'): void => {
		from.manager.on(
			'message:outbound',
			(_peer: string, type: MessageType, payload: Buffer) => {
				if (tag === 'a' ? drop.aToB : drop.bToA) return;
				delivered.push({ from: tag, type });
				to.manager.handleMessage(from.nodeId.toString('hex'), type, payload);
			}
		);
		// What LightningNode does on announcement:needs-signing, minus the
		// merkle-position check.
		from.manager.on(
			'announcement:needs-signing',
			(cid: Buffer, scid: Buffer) => {
				const block = (scid[0] << 16) | (scid[1] << 8) | scid[2];
				const txIndex = (scid[3] << 16) | (scid[4] << 8) | scid[5];
				from.manager.triggerAnnouncementDepth(
					cid,
					block,
					txIndex,
					from.nodeId,
					from.sign
				);
			}
		);
		from.manager.on('announcement:ready', (_cid: Buffer, ann: Buffer) => {
			from.ready.push(ann);
		});
	};
	wire(a, b, 'a');
	wire(b, a, 'b');
	return { a, b, channelId, drop, delivered, pendingOpenerReady };
}

function depthReached(side: ISide, channelId: Buffer): void {
	side.manager.triggerAnnouncementDepth(
		channelId,
		FUNDING_BLOCK,
		FUNDING_TX_INDEX,
		side.nodeId,
		side.sign
	);
}

/** Drop and re-establish the connection at the channel level. */
function reconnect(a: ISide, b: ISide): void {
	a.channel.markForReestablish();
	b.channel.markForReestablish();
	const fromA = decodeChannelReestablishMessage(
		firstSend(a.channel.createReestablish(), MessageType.CHANNEL_REESTABLISH)
	);
	const fromB = decodeChannelReestablishMessage(
		firstSend(b.channel.createReestablish(), MessageType.CHANNEL_REESTABLISH)
	);
	a.channel.handleReestablish(fromB);
	b.channel.handleReestablish(fromA);
	expect(a.channel.getState()).to.equal(ChannelState.NORMAL);
	expect(b.channel.getState()).to.equal(ChannelState.NORMAL);
}

/** What LightningNode does for each side after a reestablish. */
function afterReestablish(side: ISide, channelId: Buffer): void {
	const st = side.channel.getFullState();
	if (st.announcementSigsSent && !st.announcementSigsReceived) {
		side.manager.resendAnnouncementSignatures(channelId);
	}
}

function annSigsFrom(
	delivered: Array<{ from: 'a' | 'b'; type: MessageType }>,
	from: 'a' | 'b'
): number {
	return delivered.filter(
		(d) => d.from === from && d.type === MessageType.ANNOUNCEMENT_SIGNATURES
	).length;
}

describe('announcement_signatures retransmission (issue #2041)', function () {
	it('both sides build the announcement after a dropped message and a reconnect', function () {
		const { a, b, channelId, drop } = setupPair();
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);

		// A's signatures are lost on the way out (sent just before a
		// disconnect), and so is its answer to B's.
		drop.aToB = true;
		depthReached(a, channelId);
		depthReached(b, channelId);
		expect(a.ready.length, 'A has both halves').to.equal(1);
		expect(b.ready.length, 'B never got A').to.equal(0);
		expect(b.channel.getFullState().announcementSigsReceived).to.be.false;

		drop.aToB = false;
		reconnect(a, b);
		afterReestablish(a, channelId);
		afterReestablish(b, channelId);

		expect(b.ready.length, 'B builds it after the reconnect').to.equal(1);
		const ann = verifyFullAnnouncement(b.ready[0]);
		expect(ann.scid.equals(SCID)).to.be.true;
		expect(ann.allValid, 'every signature in B announcement verifies').to.be
			.true;
		expect(a.ready.length).to.be.greaterThan(0);
		expect(verifyFullAnnouncement(a.ready[a.ready.length - 1]).allValid).to.be
			.true;
	});

	it('answers a peer that re-sends on the same connection, once per connection', function () {
		const { a, b, channelId, drop, delivered } = setupPair();
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);

		// A's message is dropped by a peer not ready for it; B signs later.
		drop.aToB = true;
		depthReached(a, channelId);
		drop.aToB = false;
		depthReached(b, channelId);

		expect(b.ready.length, 'A answered with its stored signatures').to.equal(1);
		expect(verifyFullAnnouncement(b.ready[0]).allValid).to.be.true;

		// B answers A's answer once; A does not answer again on this
		// connection, so the exchange stops.
		const fromA = annSigsFrom(delivered, 'a');
		const fromB = annSigsFrom(delivered, 'b');
		expect(fromA).to.equal(1);
		expect(fromB).to.equal(2);

		// Neither answers a second time before a reconnect.
		const resent = b.manager.resendAnnouncementSignatures(channelId);
		expect(resent).to.be.true;
		expect(annSigsFrom(delivered, 'a')).to.equal(1);

		// After one, each side answers again.
		reconnect(a, b);
		b.manager.resendAnnouncementSignatures(channelId);
		expect(annSigsFrom(delivered, 'a')).to.equal(2);
	});

	it('signs for a peer that signs at 3 confirmations and holds the announcement until the sixth', function () {
		const { a, b, channelId, drop, delivered } = setupPair();
		// 3 confirmations: the channel is NORMAL but not announceable.
		a.manager.handleNewBlock(FUNDING_BLOCK + 2);
		b.manager.handleNewBlock(FUNDING_BLOCK + 2);

		// B (a peer following bolts#1215) signs now; A answers without
		// waiting for its own depth trigger. A signs in answer to B, B answers
		// that, and A answers B's answer once.
		drop.aToB = false;
		depthReached(b, channelId);
		expect(annSigsFrom(delivered, 'a'), 'A answered B').to.equal(2);
		expect(annSigsFrom(delivered, 'b')).to.equal(2);
		expect(a.channel.getFullState().announcementSigsSent).to.be.true;
		expect(a.ready.length, 'held at 3 confirmations').to.equal(0);
		expect(b.ready.length, 'held at 3 confirmations').to.equal(0);

		a.manager.handleNewBlock(FUNDING_BLOCK + 4);
		expect(a.ready.length, 'held at 5 confirmations').to.equal(0);

		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);
		expect(a.ready.length, 'released at 6 confirmations').to.equal(1);
		expect(b.ready.length).to.equal(1);
		const ann = verifyFullAnnouncement(a.ready[0]);
		expect(ann.scid.equals(SCID)).to.be.true;
		expect(ann.allValid).to.be.true;

		// Released once, not on every block after.
		a.manager.handleNewBlock(FUNDING_BLOCK + 6);
		expect(a.ready.length).to.equal(1);
	});

	it('reannounceChannel waits for depth too', function () {
		const { a, b, channelId } = setupPair();
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);
		depthReached(a, channelId);
		depthReached(b, channelId);
		expect(a.ready.length).to.equal(1);

		// A restart before the tip is known holds the rebuild.
		(a.manager as any)._currentBlockHeight = 0;
		a.manager.reannounceChannel(channelId);
		expect(a.ready.length).to.equal(1);
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		expect(a.ready.length).to.equal(2);
	});

	it('defers announcement_signatures that arrive before channel_ready', async function () {
		const { a, b, channelId, pendingOpenerReady } = setupPair({
			openerAwaitingReady: true
		});
		expect(a.channel.getState()).to.equal(ChannelState.AWAITING_CHANNEL_READY);
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);

		depthReached(b, channelId);
		expect(a.channel.getFullState().announcementSigsReceived).to.be.false;

		a.manager.handleMessage(
			b.nodeId.toString('hex'),
			MessageType.CHANNEL_READY,
			pendingOpenerReady!
		);
		expect(a.channel.getState()).to.equal(ChannelState.NORMAL);
		await new Promise((resolve) => setImmediate(resolve));

		expect(a.channel.getFullState().announcementSigsReceived).to.be.true;
		expect(a.ready.length, 'A signed and built it').to.equal(1);
		expect(b.ready.length, 'and B got A signatures').to.equal(1);
		expect(verifyFullAnnouncement(b.ready[0]).allValid).to.be.true;
	});

	it('ignores announcement_signatures from a peer that does not own the channel', function () {
		const { a, b, channelId } = setupPair();
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		const stranger = getPublicKey(crypto.randomBytes(32)).toString('hex');
		b.manager.removeAllListeners('message:outbound');
		const out: Buffer[] = [];
		b.manager.on('message:outbound', (_p: string, _t: MessageType, p: Buffer) =>
			out.push(p)
		);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);
		depthReached(b, channelId);
		a.manager.handleMessage(
			stranger,
			MessageType.ANNOUNCEMENT_SIGNATURES,
			out[0]
		);
		expect(a.channel.getFullState().announcementSigsReceived).to.be.false;
	});

	it('does not answer with stale signatures when the peer moves to a new SCID', function () {
		const { a, b, channelId } = setupPair();
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);
		depthReached(a, channelId);
		depthReached(b, channelId);
		reconnect(a, b);

		const newScid = encodeShortChannelId({
			block: FUNDING_BLOCK + 100,
			txIndex: 7,
			outputIndex: 0
		});
		const actions = a.channel.handleAnnouncementSignatures(
			{
				channelId,
				shortChannelId: newScid,
				nodeSignature: crypto.randomBytes(64),
				bitcoinSignature: crypto.randomBytes(64)
			},
			a.nodeId,
			b.nodeId,
			a.channel.getFullState().localAnnouncementNodeSig ?? undefined,
			a.channel.getFullState().localAnnouncementBitcoinSig ?? undefined
		);
		expect(
			sendsOf(actions, MessageType.ANNOUNCEMENT_SIGNATURES)
		).to.have.length(0);
		expect(a.channel.getFullState().announcementSigsSent).to.be.false;
	});

	it('retransmitAnnouncementSignatures sends the stored signatures and nothing before signing', function () {
		const { a, b, channelId } = setupPair();
		expect(a.channel.retransmitAnnouncementSignatures(a.nodeId, b.nodeId)).to.be
			.empty;
		a.manager.removeAllListeners('message:outbound');
		depthReached(a, channelId);
		const st = a.channel.getFullState();
		const [payload] = sendsOf(
			a.channel.retransmitAnnouncementSignatures(a.nodeId, b.nodeId),
			MessageType.ANNOUNCEMENT_SIGNATURES
		);
		const msg = decodeAnnouncementSignaturesMessage(payload);
		expect(msg.shortChannelId.equals(SCID)).to.be.true;
		expect(msg.nodeSignature.equals(st.localAnnouncementNodeSig!)).to.be.true;
		expect(msg.bitcoinSignature.equals(st.localAnnouncementBitcoinSig!)).to.be
			.true;

		a.channel.markForReestablish();
		expect(a.channel.retransmitAnnouncementSignatures(a.nodeId, b.nodeId)).to.be
			.empty;
	});
});

describe('LightningNode announcement work after reestablish (issue #2041)', function () {
	function makeNode(): LightningNode {
		const backend: IChainBackend = {
			subscribeToHeaders: async () => {},
			subscribeToScriptHash: async () => {},
			getScriptHashHistory: async () => [],
			getTransaction: async () => Buffer.alloc(0),
			broadcastTransaction: async () => ''
		};
		const seed = crypto.createHash('sha256').update('2041-node').digest();
		const node = new LightningNode({
			nodePrivateKey: openerNodePriv,
			channelBasepoints: makeBasepoints(seed).basepoints,
			perCommitmentSeed: seed,
			fundingPrivkey: crypto.createHash('sha256').update('2041-fund').digest(),
			network: Network.REGTEST,
			chainBackend: backend
		});
		node.on('node:error', () => {});
		return node;
	}

	it('re-sends stored signatures to a peer that has not sent its own', function () {
		const node = makeNode();
		const { a, channelId } = setupPair();
		a.manager.removeAllListeners('message:outbound');
		depthReached(a, channelId);
		node.getChannelManager().restoreChannel(a.channel, a.peerHex);
		writableState(a.channel).state = ChannelState.NORMAL;

		const resent: Buffer[] = [];
		node.getChannelManager().resendAnnouncementSignatures = ((cid: Buffer) => {
			resent.push(cid);
			return true;
		}) as any;
		node.getChannelManager().emit('channel:reestablished', channelId);
		expect(resent).to.have.length(1);
		expect(resent[0].equals(channelId)).to.be.true;
		node.destroy();
	});

	it('re-arms the depth trigger when the sixth confirmation came while the channel was not NORMAL', function () {
		const node = makeNode();
		const { a, channelId } = setupPair();
		node.getChannelManager().restoreChannel(a.channel, a.peerHex);
		writableState(a.channel).state = ChannelState.NORMAL;
		const fundingTxid = a.channel.getFullState().fundingTxid!;

		const rearmed: string[] = [];
		(node as any).chainWatcher.rearmAnnouncementTracking = (
			_cid: Buffer,
			txid: string
		) => rearmed.push(txid);
		node.getChannelManager().emit('channel:reestablished', channelId);
		expect(rearmed).to.deep.equal([
			Buffer.from(fundingTxid).reverse().toString('hex')
		]);
		node.destroy();
	});

	it('does nothing once both sides have signed', function () {
		const node = makeNode();
		const { a, b, channelId } = setupPair();
		a.manager.handleNewBlock(FUNDING_BLOCK + 5);
		b.manager.handleNewBlock(FUNDING_BLOCK + 5);
		depthReached(a, channelId);
		depthReached(b, channelId);
		node.getChannelManager().restoreChannel(a.channel, a.peerHex);
		writableState(a.channel).state = ChannelState.NORMAL;

		let calls = 0;
		node.getChannelManager().resendAnnouncementSignatures = (() => {
			calls++;
			return true;
		}) as any;
		(node as any).chainWatcher.rearmAnnouncementTracking = () => calls++;
		node.getChannelManager().emit('channel:reestablished', channelId);
		expect(calls).to.equal(0);
		node.destroy();
	});
});
