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
import { encodeUpdateAddHtlcMessage } from '../../src/lightning/message/channel-update';

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

	it('S refuses a book that fails the setup checks with ff_error and ff_abort', () => {
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
		expect(pair.link.types()).to.deep.equal([
			MessageType.FF_INIT,
			MessageType.FF_ERROR,
			MessageType.FF_ABORT
		]);
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
