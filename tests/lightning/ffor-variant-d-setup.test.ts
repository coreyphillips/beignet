/**
 * FFOR Variant D, M8.1: voucher book setup and signed activation
 * (specs/ffor-offline-receive.md sections 7, 7.5, 9.5.1; section 15.2 M8.1).
 *
 * Two ChannelManagers in loopback, peer ids = node ids, every message on a
 * wire log. The gate: the section 9.5.1 sequence exactly, no update message
 * between either stfu and the ack, both sides holding the same T_init,
 * T_setup, H_book, H_commit and H_act, K vouchers in both views, ACTIVE
 * surviving a disconnect and a restart on each side, and a disconnect before
 * the ack aborting with the vouchers failed.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../src/lightning/storage/serialization';
import { decodeChannelReestablishMessage } from '../../src/lightning/message/channel-reestablish';
import {
	FF_ACTIVATE_ACK_TYPE,
	FF_ACTIVATE_TYPE,
	FforAbortReason,
	FforState,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';
import {
	decodeFforAbortMessage,
	decodeFforActivateMessage,
	fforWireBytes,
	verifyFforMessage
} from '../../src/lightning/ffor/messages';
import {
	buildVoucherBook,
	computeHAct,
	computeHBook,
	computeTInit,
	computeTSetup
} from '../../src/lightning/ffor/transcript';
import { FforVariant } from '../../src/lightning/ffor/types';
import {
	encodeUpdateAddHtlcMessage,
	encodeUpdateBlockheightMessage,
	encodeUpdateFailHtlcMessage,
	encodeUpdateFeeMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';
import { encodeCommitmentSignedMessage } from '../../src/lightning/message/channel-commitment';
import { encodeShutdownMessage } from '../../src/lightning/message/channel-close';
import { encodeStfuMessage } from '../../src/lightning/message/stfu';
import { encodeSpliceMessage } from '../../src/lightning/message/splice';
import {
	encodeFforAbortUnsigned,
	encodeFforAcceptUnsigned,
	encodeFforErrorMessage,
	signFforMessage
} from '../../src/lightning/ffor/messages';
import { FF_ABORT_TYPE, FF_ACCEPT_TYPE } from '../../src/lightning/ffor/types';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';

// ─────────────── Harness ───────────────

function sha(...parts: (Buffer | string)[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts) h.update(p);
	return h.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const k = (i: number): Buffer => getPublicKey(sha(seed, Buffer.from([i])));
	return {
		fundingPubkey: k(0),
		revocationBasepoint: k(1),
		paymentBasepoint: k(2),
		delayedPaymentBasepoint: k(3),
		htlcBasepoint: k(4),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeConfig(
	seedId: number
): IChannelManagerConfig & { nodePrivateKey: Buffer } {
	const seed = sha(`ffor-d-seed-${seedId}`);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: sha(seed, 'per-commitment'),
		localFundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		nodePrivateKey: sha(seed, 'node-key'),
		// Section 5: anchor commitments.
		preferAnchors: true
	};
}

interface IWireEntry {
	from: 'S' | 'R';
	type: number;
	payload: Buffer;
}

/** A loopback link with a wire log, a drop filter and a connect switch. */
class Link {
	readonly log: IWireEntry[] = [];
	connected = true;
	/** Return true to drop the message (it is still logged as dropped). */
	drop: ((from: 'S' | 'R', type: number, payload: Buffer) => boolean) | null =
		null;
	readonly dropped: IWireEntry[] = [];
	/** While set, deliveries queue FIFO (a real socket pair's ordering). */
	private queue: IWireEntry[] | null = null;

	constructor(
		readonly s: ChannelManager,
		readonly sPub: string,
		readonly r: ChannelManager,
		readonly rPub: string
	) {
		s.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === rPub) this.deliver('S', type, payload);
		});
		r.on('message:outbound', (peer: string, type: number, payload: Buffer) => {
			if (peer === sPub) this.deliver('R', type, payload);
		});
	}

	private deliver(from: 'S' | 'R', type: number, payload: Buffer): void {
		if (!this.connected || (this.drop && this.drop(from, type, payload))) {
			this.dropped.push({ from, type, payload });
			return;
		}
		if (this.queue) {
			this.queue.push({ from, type, payload });
			return;
		}
		this.direct({ from, type, payload });
	}

	private direct(m: IWireEntry): void {
		this.log.push(m);
		if (m.from === 'S') this.r.handleMessage(this.sPub, m.type, m.payload);
		else this.s.handleMessage(this.rPub, m.type, m.payload);
	}

	types(): number[] {
		return this.log.map((e) => e.type);
	}

	/** Disconnect both sides (BOLT 2: quiescence and setup state react). */
	disconnect(): void {
		this.connected = false;
		this.s.handlePeerDisconnected(this.rPub);
		this.r.handlePeerDisconnected(this.sPub);
	}

	/**
	 * Reconnect the way a socket pair delivers: both channel_reestablish
	 * messages cross first, and everything each side sends in response is
	 * delivered in FIFO order behind them.
	 */
	reconnect(): void {
		this.connected = true;
		this.queue = [];
		this.s.handlePeerReconnected(this.rPub);
		this.r.handlePeerReconnected(this.sPub);
		while (this.queue.length > 0) {
			this.direct(this.queue.shift()!);
		}
		this.queue = null;
	}
}

interface IPair {
	link: Link;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sPub: string;
	rPub: string;
	sChannel: Channel;
	rChannel: Channel;
	channelId: Buffer;
	sConfig: ReturnType<typeof makeConfig>;
	rConfig: ReturnType<typeof makeConfig>;
	sErrors: string[];
	rErrors: string[];
}

const FUNDING_SATOSHIS = 1_000_000n;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;
const TIP = 790_000;
const AMOUNTS = [994_000n, 546_250n, 49_749_000n];

let pairSeed = 0;

/** S opens and funds; R accepts. Both at tip 790000. */
function createPair(opts: { height?: number } = {}): IPair {
	pairSeed += 10;
	const sConfig = makeConfig(500 + pairSeed);
	const rConfig = makeConfig(501 + pairSeed);
	const sPub = getPublicKey(sConfig.nodePrivateKey).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey).toString('hex');
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	const sErrors: string[] = [];
	const rErrors: string[] = [];
	sManager.on('error', (_id: Buffer | null, msg: string) => sErrors.push(msg));
	rManager.on('error', (_id: Buffer | null, msg: string) => rErrors.push(msg));
	const link = new Link(sManager, sPub, rManager, rPub);

	const sChannel = sManager.openChannel(rPub, FUNDING_SATOSHIS);
	sManager.createFunding(
		sChannel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	);
	const channelId = sChannel.getChannelId()!;
	sManager.handleFundingConfirmed(channelId);
	rManager.handleFundingConfirmed(channelId);
	const rChannel = rManager.getChannelsByPeer(sPub)[0];
	expect(sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(rChannel.getState()).to.equal(ChannelState.NORMAL);
	const height = opts.height ?? TIP;
	sManager.handleNewBlock(height);
	rManager.handleNewBlock(height);
	link.log.length = 0;
	return {
		link,
		sManager,
		rManager,
		sPub,
		rPub,
		sChannel,
		rChannel,
		channelId,
		sConfig,
		rConfig,
		sErrors,
		rErrors
	};
}

function terms(amounts = AMOUNTS): {
	voucherAmountsMsat: bigint[];
	minPaymentMsat: bigint;
	settlementDeadline: number;
	voucherExpiry: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
} {
	return {
		voucherAmountsMsat: amounts,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000
	};
}

function record(ch: Channel): IFforEpochRecord {
	const f = ch.getFforEpoch();
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

const UPDATE_TYPES = new Set<number>([
	MessageType.UPDATE_ADD_HTLC,
	MessageType.UPDATE_FULFILL_HTLC,
	MessageType.UPDATE_FAIL_HTLC,
	MessageType.UPDATE_FAIL_MALFORMED_HTLC,
	MessageType.UPDATE_FEE,
	MessageType.COMMITMENT_SIGNED,
	MessageType.REVOKE_AND_ACK,
	MessageType.SPLICE,
	MessageType.SHUTDOWN
]);

/** Voucher HTLC entries on one side. */
function vouchers(ch: Channel): Array<[string, HtlcState]> {
	const out: Array<[string, HtlcState]> = [];
	for (const [key, e] of ch.getFullState().htlcs) {
		if (e.fforVoucher === true) out.push([key, e.state]);
	}
	return out;
}

/** Run setup to ACTIVE and return the pair. */
function activate(pair: IPair, amounts = AMOUNTS): void {
	const res = pair.rManager.initiateFforEpoch(pair.channelId, terms(amounts));
	expect(res.ok, res.error).to.equal(true);
	const why = (): string =>
		JSON.stringify({
			sErrors: pair.sErrors,
			rErrors: pair.rErrors,
			wire: pair.link.types()
		});
	expect(record(pair.sChannel).state, why()).to.equal(FforState.ACTIVE);
	expect(record(pair.rChannel).state, why()).to.equal(FforState.ACTIVE);
}

/** Serialize a manager's channel, restore it into a fresh manager. */
function restart(
	pair: IPair,
	side: 'S' | 'R'
): { manager: ChannelManager; channel: Channel; errors: string[] } {
	const old = side === 'S' ? pair.sChannel : pair.rChannel;
	const config = side === 'S' ? pair.sConfig : pair.rConfig;
	const peer = side === 'S' ? pair.rPub : pair.sPub;
	const state = deserializeChannelState(
		JSON.parse(JSON.stringify(serializeChannelState(old.getFullState())))
	);
	const manager = new ChannelManager(config);
	const errors: string[] = [];
	manager.on('error', (_id: Buffer | null, msg: string) => errors.push(msg));
	const channel = new Channel(state);
	manager.restoreChannel(channel, peer);
	manager.handleNewBlock(TIP);
	return { manager, channel, errors };
}

// ─────────────── Tests ───────────────

describe('FFOR Variant D: voucher book setup and activation (M8.1)', function () {
	this.timeout(30_000);

	it('runs the section 9.5.1 sequence exactly and activates both sides', () => {
		const pair = createPair();
		activate(pair);
		const types = pair.link.types();
		const K = AMOUNTS.length;
		// The one legal sequence.
		const expected = [
			MessageType.FF_INIT,
			MessageType.FF_ACCEPT,
			...Array.from({ length: K }, () => MessageType.UPDATE_ADD_HTLC),
			MessageType.COMMITMENT_SIGNED,
			MessageType.REVOKE_AND_ACK,
			MessageType.COMMITMENT_SIGNED,
			MessageType.REVOKE_AND_ACK,
			MessageType.STFU,
			MessageType.STFU,
			MessageType.FF_ACTIVATE,
			MessageType.FF_ACTIVATE_ACK
		];
		expect(types).to.deep.equal(expected);
		const from = pair.link.log.map((e) => e.from);
		expect(from.slice(0, 2)).to.deep.equal(['R', 'S']);
		expect(from[2 + K]).to.equal('S'); // commitment_signed
		expect(from[3 + K]).to.equal('R'); // revoke_and_ack
		expect(from[4 + K]).to.equal('R'); // commitment_signed
		expect(from[5 + K]).to.equal('S'); // revoke_and_ack
		expect(from[6 + K]).to.equal('R'); // stfu
		expect(from[7 + K]).to.equal('S'); // stfu
		expect(from[8 + K]).to.equal('R'); // ff_activate
		expect(from[9 + K]).to.equal('S'); // ff_activate_ack

		// Gate: no update message between either stfu and the ack.
		const firstStfu = types.indexOf(MessageType.STFU);
		const ack = types.indexOf(MessageType.FF_ACTIVATE_ACK);
		for (const t of types.slice(firstStfu, ack + 1)) {
			expect(UPDATE_TYPES.has(t), `update ${t} inside quiescence`).to.be.false;
		}
		// Quiescence ended with the ack on both sides.
		expect(pair.sChannel.isQuiescing()).to.be.false;
		expect(pair.rChannel.isQuiescing()).to.be.false;
		expect(pair.sErrors).to.deep.equal([]);
		expect(pair.rErrors).to.deep.equal([]);
	});

	it('both sides compute the same T_init, T_setup, H_book, H_commit and H_act', () => {
		const pair = createPair();
		activate(pair);
		const s = record(pair.sChannel);
		const r = record(pair.rChannel);
		for (const key of [
			'tInit',
			'tSetup',
			'hBook',
			'hCommit',
			'hAct'
		] as const) {
			expect(s[key], key).to.not.equal(null);
			expect(s[key]!.equals(r[key]!), key).to.be.true;
		}
		expect(s.epochStartHeight).to.equal(TIP);
		expect(r.epochStartHeight).to.equal(TIP);
		// Independent recomputation from the wire bytes and the book.
		const tInit = computeTInit(r.initWire);
		expect(tInit.equals(r.tInit)).to.be.true;
		const tSetup = computeTSetup(tInit, r.acceptWire!);
		expect(tSetup.equals(r.tSetup!)).to.be.true;
		const book = buildVoucherBook(
			r.epochId,
			FforVariant.D,
			r.paymentHashes.map((h, i) => ({
				k: i + 1,
				paymentHash: h,
				amountMsat: AMOUNTS[i],
				voucherExpiry: T_EXP,
				settlementDeadline: D_DEADLINE,
				sHtlcId: r.sHtlcIdBase! + BigInt(i)
			}))
		);
		expect(computeHBook(book).equals(r.hBook!)).to.be.true;
		expect(computeHAct(tSetup, r.hBook!, r.hCommit!, TIP).equals(r.hAct!)).to.be
			.true;
		// The activation transcript is mutually signed over those hashes.
		const activateWire = pair.link.log.find(
			(e) => e.type === MessageType.FF_ACTIVATE
		)!;
		const act = decodeFforActivateMessage(activateWire.payload);
		expect(act.setupHash.equals(tSetup)).to.be.true;
		expect(act.bookHash.equals(r.hBook!)).to.be.true;
		expect(act.commitHash.equals(r.hCommit!)).to.be.true;
		expect(
			verifyFforMessage(
				FF_ACTIVATE_TYPE,
				activateWire.payload,
				Buffer.from(pair.rPub, 'hex')
			)
		).to.be.true;
		const ackWire = pair.link.log.find(
			(e) => e.type === MessageType.FF_ACTIVATE_ACK
		)!;
		expect(
			verifyFforMessage(
				FF_ACTIVATE_ACK_TYPE,
				ackWire.payload,
				Buffer.from(pair.sPub, 'hex')
			)
		).to.be.true;
		expect(
			fforWireBytes(FF_ACTIVATE_TYPE, activateWire.payload).equals(
				r.activateWire!
			)
		).to.be.true;
		expect(
			fforWireBytes(FF_ACTIVATE_ACK_TYPE, ackWire.payload).equals(
				s.activateAckWire!
			)
		).to.be.true;
	});

	it('holds K committed vouchers in both views, S alone holding the preimages', () => {
		const pair = createPair();
		const sBefore = pair.sChannel.getFullState().localBalanceMsat;
		const rBefore = pair.rChannel.getFullState().localBalanceMsat;
		activate(pair);
		const s = record(pair.sChannel);
		const r = record(pair.rChannel);
		expect(s.role).to.equal('S');
		expect(r.role).to.equal('R');
		expect(s.preimages.length).to.equal(AMOUNTS.length);
		expect(r.preimages.length).to.equal(0);
		s.preimages.forEach((p, i) => {
			expect(sha(p).equals(s.paymentHashes[i])).to.be.true;
			expect(r.paymentHashes[i].equals(s.paymentHashes[i])).to.be.true;
		});
		expect(s.sHtlcIdBase).to.equal(0n);
		expect(r.sHtlcIdBase).to.equal(0n);
		const sV = vouchers(pair.sChannel);
		const rV = vouchers(pair.rChannel);
		expect(sV.length).to.equal(AMOUNTS.length);
		expect(rV.length).to.equal(AMOUNTS.length);
		for (const [, st] of [...sV, ...rV])
			expect(st).to.equal(HtlcState.COMMITTED);
		for (const [key, entry] of pair.rChannel.getFullState().htlcs) {
			expect(key.startsWith('received-')).to.be.true;
			expect(entry.cltvExpiry).to.equal(T_EXP);
			expect(entry.forwardEmitted).to.not.equal(true);
		}
		const budget = AMOUNTS.reduce((a, b) => a + b, 0n);
		expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
			sBefore - budget
		);
		expect(pair.rChannel.getFullState().localBalanceMsat).to.equal(rBefore);
		expect(pair.sChannel.getFullState().remoteBalanceMsat).to.equal(rBefore);
		expect(pair.rChannel.getFullState().remoteBalanceMsat).to.equal(
			sBefore - budget
		);
	});

	it('ACTIVE forbids every ordinary update on both sides', () => {
		const pair = createPair();
		activate(pair);
		const onion = Buffer.alloc(1366);
		const hash = crypto.randomBytes(32);
		const sAdd = pair.sManager.addHtlc(
			pair.channelId,
			10_000n,
			hash,
			TIP + 100,
			onion
		);
		expect(sAdd.ok).to.be.false;
		expect(sAdd.error).to.include('ACTIVE');
		const rAdd = pair.rManager.addHtlc(
			pair.channelId,
			10_000n,
			hash,
			TIP + 100,
			onion
		);
		expect(rAdd.ok).to.be.false;
		const q = pair.sManager.initiateQuiescence(pair.channelId);
		expect(q.ok).to.be.false;
		const rQ = pair.rManager.initiateQuiescence(pair.channelId);
		expect(rQ.ok).to.be.false;
		const fee = pair.sChannel.updateFee(3000);
		expect(fee.some((a) => a.type === 'ERROR')).to.be.true;
		const sVoucherId = record(pair.sChannel).sHtlcIdBase!;
		const fulfil = pair.rManager.fulfillHtlc(
			pair.channelId,
			sVoucherId,
			Buffer.alloc(32)
		);
		expect(fulfil.ok).to.be.false;
		const fail = pair.rManager.failHtlc(
			pair.channelId,
			sVoucherId,
			Buffer.alloc(292)
		);
		expect(fail.ok).to.be.false;
		const shutdown = pair.rChannel.initiateShutdown(
			Buffer.from('0014' + '11'.repeat(20), 'hex')
		);
		expect(shutdown.some((a) => a.type === 'ERROR')).to.be.true;
		// A peer add on the wire under the freeze is a provable violation.
		const before = pair.link.log.length;
		pair.rManager.handleMessage(
			pair.sPub,
			MessageType.UPDATE_ADD_HTLC,
			encodeUpdateAddHtlcMessage({
				channelId: pair.channelId,
				id: 7n,
				amountMsat: 10_000n,
				paymentHash: hash,
				cltvExpiry: TIP + 100,
				onionRoutingPacket: onion
			})
		);
		const sent = pair.link.log.slice(before).map((e) => e.type);
		expect(sent).to.include(MessageType.ERROR);
		expect(pair.rChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	it('ACTIVE survives a disconnect on both sides with TLV 55001 carried', () => {
		const pair = createPair();
		activate(pair);
		pair.link.log.length = 0;
		pair.link.disconnect();
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		pair.link.reconnect();
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		const reest = pair.link.log.filter(
			(e) => e.type === MessageType.CHANNEL_REESTABLISH
		);
		expect(reest.length).to.equal(2);
		for (const e of reest) {
			const msg = decodeChannelReestablishMessage(e.payload);
			expect(msg.ffor).to.not.be.undefined;
			expect(msg.ffor!.state).to.equal(FforState.ACTIVE);
			expect(msg.ffor!.epochId.equals(record(pair.rChannel).epochId)).to.be
				.true;
			expect(msg.ffor!.activationHash.equals(record(pair.rChannel).hAct!)).to.be
				.true;
		}
		// Nothing else moved: two ACTIVE peers agreeing on H_act owe nothing.
		expect(
			pair.link.log.filter((e) => e.type !== MessageType.CHANNEL_REESTABLISH)
		).to.deep.equal([]);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(vouchers(pair.rChannel).length).to.equal(AMOUNTS.length);
	});

	for (const side of ['S', 'R'] as const) {
		it(`ACTIVE survives a restart of ${side} from persisted state`, () => {
			const pair = createPair();
			activate(pair);
			const hAct = record(pair.rChannel).hAct!;
			pair.link.disconnect();
			const restarted = restart(pair, side);
			const rec = record(restarted.channel);
			expect(rec.state).to.equal(FforState.ACTIVE);
			expect(rec.hAct!.equals(hAct)).to.be.true;
			expect(vouchers(restarted.channel).length).to.equal(AMOUNTS.length);
			if (side === 'S') {
				expect(rec.preimages.length).to.equal(AMOUNTS.length);
			}
			// Reconnect the restarted side to the live peer.
			const other = side === 'S' ? pair.rManager : pair.sManager;
			const otherPub = side === 'S' ? pair.rPub : pair.sPub;
			const link =
				side === 'S'
					? new Link(restarted.manager, pair.sPub, other, otherPub)
					: new Link(other, otherPub, restarted.manager, pair.rPub);
			link.reconnect();
			expect(record(restarted.channel).state).to.equal(FforState.ACTIVE);
			expect(restarted.channel.getState()).to.equal(ChannelState.NORMAL);
			const otherChannel = side === 'S' ? pair.rChannel : pair.sChannel;
			expect(record(otherChannel).state).to.equal(FforState.ACTIVE);
			expect(restarted.errors).to.deep.equal([]);
			expect(
				link.log.filter((e) => e.type !== MessageType.CHANNEL_REESTABLISH)
			).to.deep.equal([]);
		});
	}

	it('a disconnect before the ack aborts the setup and R fails every voucher', () => {
		const pair = createPair();
		// Drop R's ff_activate: S stays VOUCHERS_COMMITTED, R is ACTIVATING.
		pair.link.drop = (_from, type): boolean => type === MessageType.FF_ACTIVATE;
		const res = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(res.ok, res.error).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		expect(pair.sChannel.isQuiescent()).to.be.true;
		pair.link.drop = null;
		pair.link.log.length = 0;
		pair.link.disconnect();
		// S never persisted ACTIVE: its setup died with the connection.
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.sChannel).abortReason).to.equal(
			FforAbortReason.DISCONNECT
		);
		// R could not know whether S had persisted ACTIVE: it waits for the
		// reestablish, learns S aborted, aborts, and unwinds the vouchers.
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		pair.link.reconnect();
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		const fails = pair.link.log.filter(
			(e) => e.type === MessageType.UPDATE_FAIL_HTLC
		);
		expect(fails.length).to.equal(AMOUNTS.length);
		expect(fails.every((e) => e.from === 'R')).to.be.true;
		const abort = pair.link.log.find((e) => e.type === MessageType.FF_ABORT);
		expect(abort).to.not.be.undefined;
		expect(decodeFforAbortMessage(abort!.payload).reason).to.equal(
			FforAbortReason.DISCONNECT
		);
		// The removal round completed: no voucher in either commitment and the
		// balances are back where they started.
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
			pair.rChannel.getFullState().remoteBalanceMsat
		);
		expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
			FUNDING_SATOSHIS * 1000n
		);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.sChannel.isQuiescing()).to.be.false;
		expect(pair.rChannel.isQuiescing()).to.be.false;
		// The epoch id is spent on both sides.
		const epochId = record(pair.rChannel).epochId;
		const again = pair.rManager.initiateFforEpoch(pair.channelId, {
			...terms(),
			epochId
		});
		expect(again.ok).to.be.false;
		expect(again.error).to.include('fresh');
		// And a fresh epoch still works: ordinary operation resumed.
		activate(pair);
	});

	it('S retransmits ff_activate_ack when R reestablishes before ACTIVE', () => {
		const pair = createPair();
		pair.link.drop = (_from, type): boolean =>
			type === MessageType.FF_ACTIVATE_ACK;
		const res = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(res.ok, res.error).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		pair.link.drop = null;
		pair.link.log.length = 0;
		pair.link.disconnect();
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		pair.link.reconnect();
		const types = pair.link.types();
		expect(
			types.filter((t) => t === MessageType.FF_ACTIVATE_ACK).length
		).to.equal(1);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).hAct!.equals(record(pair.sChannel).hAct!)).to
			.be.true;
		expect(vouchers(pair.rChannel).length).to.equal(AMOUNTS.length);
		expect(pair.rErrors).to.deep.equal([]);
	});

	it('a byte-identical ff_activate is answered again; a differing one is refused', () => {
		const pair = createPair();
		activate(pair);
		const activate1 = pair.link.log.find(
			(e) => e.type === MessageType.FF_ACTIVATE
		)!;
		pair.link.log.length = 0;
		pair.sManager.handleMessage(
			pair.rPub,
			MessageType.FF_ACTIVATE,
			activate1.payload
		);
		expect(pair.link.types()).to.deep.equal([MessageType.FF_ACTIVATE_ACK]);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		// A different signed ff_activate for the same transition.
		const tampered = Buffer.from(activate1.payload);
		tampered[100] ^= 0x01;
		pair.link.log.length = 0;
		pair.sManager.handleMessage(pair.rPub, MessageType.FF_ACTIVATE, tampered);
		expect(pair.link.types()).to.deep.equal([]);
		expect(pair.sErrors.some((e) => e.includes('differs'))).to.be.true;
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
	});

	it('S refuses a book that fails the setup checks with ff_abort alone', () => {
		const pair = createPair();
		// 353 sat trims at the 354 sat default dust limit.
		const bad = [353_000n, 1_000_000n];
		const res = pair.rManager.initiateFforEpoch(pair.channelId, {
			...terms(bad),
			minPaymentMsat: 1n
		});
		// R's own precheck already refuses the trimming amount.
		expect(res.ok).to.be.false;
		expect(res.error).to.include('trim');
		expect(pair.rChannel.getFforEpoch()).to.equal(null);
		expect(pair.link.log.length).to.equal(0);

		// A book R accepts but S cannot fund: budget above S's balance.
		const tooBig = [FUNDING_SATOSHIS * 1000n];
		const res2 = pair.rManager.initiateFforEpoch(pair.channelId, terms(tooBig));
		expect(res2.ok).to.be.false;
		expect(pair.link.log.length).to.equal(0);

		// Force a book past R's precheck that S refuses: R's check uses its
		// view of S's balance, so lower S's real balance behind R's back.
		const sState = pair.sChannel.getFullState();
		const saved = sState.localBalanceMsat;
		sState.localBalanceMsat = 20_000_000n;
		const res3 = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		sState.localBalanceMsat = saved;
		expect(res3.ok).to.equal(true);
		// Section 11.1: a declined book gets ff_abort alone (reason 2), no
		// ff_error; ff_error is reserved for protocol violations.
		expect(pair.link.types()).to.deep.equal([
			MessageType.FF_INIT,
			MessageType.FF_ABORT
		]);
		const refusal = pair.link.log.find((e) => e.type === MessageType.FF_ABORT)!;
		expect(decodeFforAbortMessage(refusal.payload).reason).to.equal(
			FforAbortReason.TERMS_REFUSED
		);
		expect(record(pair.rChannel).abortReason).to.equal(
			FforAbortReason.TERMS_REFUSED
		);
		expect(pair.sChannel.getFforEpoch()).to.equal(null);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		// Both remember the id as spent.
		expect(pair.sChannel.getFullState().fforUsedEpochIds).to.deep.equal(
			pair.rChannel.getFullState().fforUsedEpochIds
		);
	});

	it('an operator abort after the voucher round unwinds it', () => {
		const pair = createPair();
		pair.link.drop = (_from, type): boolean => type === MessageType.FF_ACTIVATE;
		const res = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(res.ok, res.error).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		expect(record(pair.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
		expect(pair.sChannel.isQuiescent()).to.be.true;
		expect(pair.rChannel.isQuiescent()).to.be.true;
		pair.link.drop = null;
		pair.link.log.length = 0;
		// S aborts (reason 1, timeout): the abort ends quiescence on both
		// sides (section 7.5.4) and R unwinds the vouchers.
		const abort = pair.sManager.abortFforEpoch(
			pair.channelId,
			FforAbortReason.TIMEOUT,
			'setup timed out'
		);
		expect(abort.ok, abort.error).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(pair.sChannel.isQuiescing()).to.be.false;
		expect(pair.rChannel.isQuiescing()).to.be.false;
		const fails = pair.link.log.filter(
			(e) => e.type === MessageType.UPDATE_FAIL_HTLC
		);
		expect(fails.length).to.equal(AMOUNTS.length);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
			FUNDING_SATOSHIS * 1000n
		);
	});

	it('refuses to start with HTLCs on the channel or a live epoch', () => {
		const pair = createPair();
		activate(pair);
		const again = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(again.ok).to.be.false;
		expect(again.error).to.include('already in progress');
	});
});

// ─────────────── Review round 1 ───────────────

type AddHtlcFn = Channel['addHtlc'];

/** Replace S's addHtlc on the instance so the voucher round misbehaves. */
function patchSAdds(
	pair: IPair,
	patch: (
		orig: AddHtlcFn,
		call: number,
		...args: Parameters<AddHtlcFn>
	) => ReturnType<AddHtlcFn>
): void {
	const orig: AddHtlcFn = pair.sChannel.addHtlc.bind(pair.sChannel);
	let call = 0;
	(pair.sChannel as unknown as { addHtlc: AddHtlcFn }).addHtlc = (...args) =>
		patch(orig, ++call, ...args);
}

const ONION = Buffer.alloc(1366);
const SHUTDOWN_SCRIPT = Buffer.from('0014' + '11'.repeat(20), 'hex');

/** Every message the freeze forbids, as (name, side that receives it, payload). */
function forbiddenMessages(
	pair: IPair,
	state: 'ACTIVATING' | 'ACTIVE' | 'DRAINING'
): Array<{ name: string; into: 'S' | 'R'; type: number; payload: Buffer }> {
	const channelId = pair.channelId;
	const hash = crypto.randomBytes(32);
	const out: Array<{
		name: string;
		into: 'S' | 'R';
		type: number;
		payload: Buffer;
	}> = [];
	const add = encodeUpdateAddHtlcMessage({
		channelId,
		id: 99n,
		amountMsat: 10_000n,
		paymentHash: hash,
		cltvExpiry: TIP + 100,
		onionRoutingPacket: ONION
	});
	const fulfil = encodeUpdateFulfillHtlcMessage({
		channelId,
		id: 99n,
		paymentPreimage: crypto.randomBytes(32)
	});
	const fail = encodeUpdateFailHtlcMessage({
		channelId,
		id: 99n,
		reason: Buffer.alloc(292)
	});
	const fee = encodeUpdateFeeMessage({ channelId, feeratePerKw: 3000 });
	const blockheight = encodeUpdateBlockheightMessage({
		channelId,
		blockheight: TIP + 1
	});
	const shutdown = encodeShutdownMessage({
		channelId,
		scriptPubkey: SHUTDOWN_SCRIPT
	});
	const stfu = encodeStfuMessage({ channelId, initiator: true });
	const splice = encodeSpliceMessage({
		channelId,
		fundingPubkey: pair.sConfig.localBasepoints.fundingPubkey,
		relativeSatoshis: 10_000n,
		fundingFeeratePerkw: 1000,
		locktime: 0
	});
	const commit = encodeCommitmentSignedMessage({
		channelId,
		signature: Buffer.alloc(64),
		htlcSignatures: []
	});
	const sides: Array<'S' | 'R'> = state === 'ACTIVATING' ? ['R'] : ['S', 'R'];
	for (const into of sides) {
		out.push({
			name: 'update_add_htlc',
			into,
			type: MessageType.UPDATE_ADD_HTLC,
			payload: add
		});
		out.push({
			name: 'update_fee',
			into,
			type: MessageType.UPDATE_FEE,
			payload: fee
		});
		out.push({
			name: 'shutdown',
			into,
			type: MessageType.SHUTDOWN,
			payload: shutdown
		});
		out.push({ name: 'stfu', into, type: MessageType.STFU, payload: stfu });
		out.push({
			name: 'splice_init',
			into,
			type: MessageType.SPLICE,
			payload: splice
		});
		if (state !== 'DRAINING') {
			out.push({
				name: 'commitment_signed',
				into,
				type: MessageType.COMMITMENT_SIGNED,
				payload: commit
			});
		}
		if (into === 'S') {
			out.push({
				name: 'update_fulfill_htlc (non-voucher id)',
				into,
				type: MessageType.UPDATE_FULFILL_HTLC,
				payload: fulfil
			});
			out.push({
				name: 'update_fail_htlc (non-voucher id)',
				into,
				type: MessageType.UPDATE_FAIL_HTLC,
				payload: fail
			});
			out.push({
				name: 'update_blockheight',
				into,
				type: MessageType.UPDATE_BLOCKHEIGHT,
				payload: blockheight
			});
		}
	}
	return out;
}

/** Bring a fresh pair to the named epoch state on both sides. */
function pairIn(state: 'ACTIVATING' | 'ACTIVE' | 'DRAINING'): IPair {
	const pair = createPair();
	if (state === 'ACTIVATING') {
		pair.link.drop = (_from, type): boolean =>
			type === MessageType.FF_ACTIVATE_ACK;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		pair.link.drop = null;
		return pair;
	}
	activate(pair);
	if (state === 'DRAINING') {
		// Hold R's drain so both sides stay DRAINING.
		pair.link.drop = (from, type): boolean =>
			from === 'R' &&
			(type === MessageType.UPDATE_FULFILL_HTLC ||
				type === MessageType.UPDATE_FAIL_HTLC ||
				type === MessageType.COMMITMENT_SIGNED);
		expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.equal(true);
		expect(record(pair.sChannel).state).to.equal(FforState.DRAINING);
		expect(record(pair.rChannel).state).to.equal(FforState.DRAINING);
		pair.link.drop = null;
	}
	return pair;
}

describe('FFOR Variant D: review round 1 (setup)', function () {
	this.timeout(60_000);

	for (const state of ['ACTIVATING', 'ACTIVE', 'DRAINING'] as const) {
		it(`refuses every forbidden peer message in ${state} as a protocol violation`, () => {
			const probe = pairIn(state);
			const cases = forbiddenMessages(probe, state);
			for (const c of cases) {
				const pair = pairIn(state);
				const target = c.into === 'S' ? pair.sChannel : pair.rChannel;
				const manager = c.into === 'S' ? pair.sManager : pair.rManager;
				const fromPub = c.into === 'S' ? pair.rPub : pair.sPub;
				const before = record(target).state;
				const beforeHtlcs = target.getFullState().htlcs.size;
				pair.link.log.length = 0;
				const payload = forbiddenMessages(pair, state).find(
					(m) => m.name === c.name && m.into === c.into
				)!.payload;
				manager.handleMessage(fromPub, c.type, payload);
				const label = `${c.name} into ${c.into} in ${state}`;
				expect(record(target).state, label).to.equal(before);
				expect(target.getFullState().htlcs.size, label).to.equal(beforeHtlcs);
				expect(target.getState(), label).to.equal(ChannelState.ERRORED);
				expect(
					pair.link.log.some(
						(e) => e.from === c.into && e.type === MessageType.ERROR
					),
					`${label}: wire error`
				).to.be.true;
				expect(
					pair.link.log.filter(
						(e) => e.from === c.into && e.type !== MessageType.ERROR
					),
					`${label}: nothing else sent`
				).to.deep.equal([]);
			}
		});
	}

	it('a slot that never arrives (K-1) aborts at the setup timeout and fails the vouchers that did', () => {
		const pair = createPair();
		patchSAdds(pair, (orig, call, ...args) =>
			call === 3 ? [] : orig(...args)
		);
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		// The round committed two vouchers; neither side can complete.
		expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
		expect(record(pair.sChannel).state).to.equal(FforState.NEGOTIATING);
		expect(vouchers(pair.rChannel).length).to.equal(2);
		expect(
			pair.link.types().filter((t) => t === MessageType.STFU)
		).to.deep.equal([]);
		pair.link.log.length = 0;
		const timedOut = pair.rManager.fforSetupTimeout(pair.channelId);
		expect(timedOut.ok, timedOut.error).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason).to.equal(FforAbortReason.TIMEOUT);
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		expect(
			pair.link.log.filter((e) => e.type === MessageType.UPDATE_FAIL_HTLC)
				.length
		).to.equal(2);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
			FUNDING_SATOSHIS * 1000n
		);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
		// A timeout on an already ACTIVE epoch is a no-op.
		const fresh = createPair();
		activate(fresh);
		expect(fresh.rManager.fforSetupTimeout(fresh.channelId).ok).to.equal(true);
		expect(record(fresh.rChannel).state).to.equal(FforState.ACTIVE);
	});

	it('a misbehaving S whose add does not match the book: R fails it and aborts with reason 5', () => {
		const pair = createPair();
		patchSAdds(pair, (orig, call, amount, ...rest) =>
			orig(call === 2 ? amount + 1n : amount, ...rest)
		);
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason).to.equal(
			FforAbortReason.VOUCHER_ROUND_FAILED
		);
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		const fails = pair.link.log.filter(
			(e) => e.type === MessageType.UPDATE_FAIL_HTLC
		);
		expect(fails.length).to.equal(3);
		expect(fails.every((e) => e.from === 'R')).to.be.true;
		const aborts = pair.link.log.filter((e) => e.type === MessageType.FF_ABORT);
		expect(aborts.length).to.be.at.least(1);
		expect(
			aborts.every(
				(e) =>
					decodeFforAbortMessage(e.payload).reason ===
					FforAbortReason.VOUCHER_ROUND_FAILED
			)
		).to.be.true;
		expect(
			pair.link.types().filter((t) => t === MessageType.STFU)
		).to.deep.equal([]);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
			FUNDING_SATOSHIS * 1000n
		);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	});

	it('an extra add during the round (K+1) is a mismatch: failed, never forwarded, abort reason 5', () => {
		const pair = createPair();
		let forwarded = 0;
		pair.rManager.on('htlc:forwarded', () => forwarded++);
		patchSAdds(pair, (orig, call, ...args) => {
			const actions = orig(...args);
			if (call !== 3) return actions;
			return [
				...actions,
				...orig(10_000n, crypto.randomBytes(32), T_EXP, ONION)
			];
		});
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason).to.equal(
			FforAbortReason.VOUCHER_ROUND_FAILED
		);
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		expect(
			forwarded,
			'the extra add never reached the forwarding path'
		).to.equal(0);
		const fails = pair.link.log.filter(
			(e) => e.type === MessageType.UPDATE_FAIL_HTLC
		);
		expect(fails.length).to.equal(4);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getFullState().localBalanceMsat).to.equal(
			FUNDING_SATOSHIS * 1000n
		);
	});

	it('checks every revealed secret on a channel past 2016 revocations', () => {
		const pair = createPair();
		pair.link.drop = (_from, type): boolean => type === MessageType.FF_INIT;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
		pair.link.drop = null;
		// R has seen 2100 of S's per-commitment secrets.
		const rState = pair.rChannel.getFullState();
		const sSeed = pair.sConfig.localPerCommitmentSeed;
		const secretOf = (n: bigint): Buffer =>
			generateFromSeed(sSeed, MAX_INDEX - n);
		const REVEALED = 2100n;
		for (let n = 0n; n < REVEALED; n++) {
			expect(rState.shaChainStore.addSecret(MAX_INDEX - n, secretOf(n))).to.be
				.true;
		}
		rState.remoteRevocationNumber = REVEALED;
		const bound = (h: Buffer): boolean =>
			(
				pair.rChannel as unknown as {
					_fforHashesBindRevealedSecret(x: Set<string>): boolean;
				}
			)._fforHashesBindRevealedSecret(new Set([h.toString('hex')]));
		// Older than any 2016-wide window, and the newest, both caught.
		expect(bound(sha(secretOf(5n)))).to.be.true;
		expect(bound(sha(secretOf(0n)))).to.be.true;
		expect(bound(sha(secretOf(REVEALED - 1n)))).to.be.true;
		// A secret not yet revealed, and an unrelated hash, pass.
		expect(bound(sha(secretOf(REVEALED)))).to.be.false;
		expect(bound(crypto.randomBytes(32))).to.be.false;
		// And the ff_accept path enforces it: H_1 bound to secret 5.
		const f = record(pair.rChannel);
		const body = signFforMessage(
			FF_ACCEPT_TYPE,
			encodeFforAcceptUnsigned({
				channelId: pair.channelId,
				epochId: f.epochId,
				sCommitmentNumber: rState.remoteCommitmentNumber,
				paymentHashes: [
					sha(secretOf(5n)),
					crypto.randomBytes(32),
					crypto.randomBytes(32)
				],
				sHtlcIdBase: 0n,
				voucherAmountsMsat: AMOUNTS,
				initHash: f.tInit
			}),
			pair.sConfig.nodePrivateKey
		);
		pair.link.log.length = 0;
		pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, body);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason).to.equal(
			FforAbortReason.BOOK_MISMATCH
		);
		const abort = pair.link.log.find((e) => e.type === MessageType.FF_ABORT)!;
		expect(decodeFforAbortMessage(abort.payload).reason).to.equal(
			FforAbortReason.BOOK_MISMATCH
		);
	});

	it('acknowledgement loss: R completes on a matching H_act and aborts on any other report', () => {
		// Matching: covered by the retransmission test above; here the other
		// branch. S reports ACTIVE under a different H_act.
		const pair = createPair();
		pair.link.drop = (_from, type): boolean =>
			type === MessageType.FF_ACTIVATE_ACK;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		pair.link.drop = null;
		pair.link.disconnect();
		// R keeps its ACTIVATING record across the disconnect.
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVATING);
		record(pair.sChannel).hAct = crypto.randomBytes(32);
		pair.link.log.length = 0;
		pair.link.reconnect();
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason).to.equal(
			FforAbortReason.DISCONNECT
		);
		expect(
			pair.link.log.filter((e) => e.type === MessageType.UPDATE_FAIL_HTLC)
				.length
		).to.equal(AMOUNTS.length);
		// And S reporting VOUCHERS_COMMITTED (it never persisted ACTIVE) aborts too.
		const pair2 = createPair();
		pair2.link.drop = (_from, type): boolean =>
			type === MessageType.FF_ACTIVATE;
		expect(
			pair2.rManager.initiateFforEpoch(pair2.channelId, terms()).ok
		).to.equal(true);
		expect(record(pair2.rChannel).state).to.equal(FforState.ACTIVATING);
		expect(record(pair2.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
		pair2.link.drop = null;
		pair2.link.disconnect();
		expect(record(pair2.sChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair2.rChannel).state).to.equal(FforState.ACTIVATING);
		pair2.link.reconnect();
		expect(record(pair2.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair2.rChannel).abortReason).to.equal(
			FforAbortReason.DISCONNECT
		);
		expect(
			pair2.link.types().filter((t) => t === MessageType.FF_ACTIVATE)
		).to.deep.equal([]);
		expect(pair2.rChannel.getFullState().htlcs.size).to.equal(0);
	});

	it('ff_error signals a violation only; the ff_abort that follows carries the reason', () => {
		const pair = createPair();
		pair.link.drop = (_from, type): boolean => type === MessageType.FF_INIT;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		pair.link.drop = null;
		const f = record(pair.rChannel);
		pair.rManager.handleMessage(
			pair.sPub,
			MessageType.FF_ERROR,
			encodeFforErrorMessage({
				channelId: pair.channelId,
				epochId: f.epochId,
				data: Buffer.from('bad')
			})
		);
		expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
		expect(pair.rErrors.some((e) => e.includes('ff_error from peer'))).to.be
			.true;
		const abort = signFforMessage(
			FF_ABORT_TYPE,
			encodeFforAbortUnsigned({
				channelId: pair.channelId,
				epochId: f.epochId,
				transcriptHash: f.tInit,
				reason: FforAbortReason.PROTOCOL_ERROR,
				data: Buffer.from('bad')
			}),
			pair.sConfig.nodePrivateKey
		);
		pair.rManager.handleMessage(pair.sPub, MessageType.FF_ABORT, abort);
		expect(record(pair.rChannel).state).to.equal(FforState.ABORTED);
		expect(record(pair.rChannel).abortReason).to.equal(
			FforAbortReason.PROTOCOL_ERROR
		);
		// The refused epoch id is spent: a retry needs a fresh one.
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, {
				...terms(),
				epochId: f.epochId
			}).ok
		).to.equal(false);
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
	});

	it('refuses to start without a known tip', () => {
		const pair = createPair({ height: 0 });
		const res = pair.rManager.initiateFforEpoch(pair.channelId, terms());
		expect(res.ok).to.equal(false);
		expect(res.error).to.include('tip height unknown');
		pair.sManager.handleNewBlock(TIP);
		pair.rManager.handleNewBlock(TIP);
		activate(pair);
	});
});
