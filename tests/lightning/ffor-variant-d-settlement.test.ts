/**
 * FFOR Variant D, M8.2 and M8.3: silent settlement and cooperative return
 * (specs/ffor-offline-receive.md sections 7.3, 7.5.4, 7.5.6, 7.6, 8, 9.5.1;
 * section 15.2 M8.2 and M8.3).
 *
 * Three LightningNodes in loopback: a payer P, the settlement peer S and the
 * recipient R. Every message on every link is logged. R sets up an epoch on
 * its channel with S, exposes voucher invoices and goes offline; P pays them
 * through S, which settles upstream with the slot preimage and sends R
 * nothing; R returns, closes, drains, and ordinary operation resumes.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	HtlcState,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { encodeChannelAnnouncementMessage } from '../../src/lightning/gossip/messages';
import { signChannelAnnouncement } from '../../src/lightning/gossip/validation';
import { SqliteStorage } from '../../src/lightning/storage/sqlite-storage';
import { IChannelState } from '../../src/lightning/channel/channel-state';
import { MessageType } from '../../src/lightning/message/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import {
	FEE_INSUFFICIENT,
	TEMPORARY_NODE_FAILURE
} from '../../src/lightning/onion/types';
import {
	FforSlotState,
	FforState,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';
import {
	bitmapGet,
	decodeFforCloseAckMessage
} from '../../src/lightning/ffor/messages';
import {
	checkDelegatedAmounts,
	feeS,
	grossIntoS,
	inverseAmtToForward,
	roundingSlackMsat
} from '../../src/lightning/ffor/amounts';

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

function makeNodeConfig(seedId: number, storage?: SqliteStorage): INodeConfig {
	const seed = sha(`ffor-d-node-${seedId}`);
	return {
		...(storage ? { storage } : {}),
		nodePrivateKey: sha(seed, 'node-identity'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: sha(seed, 'per-commitment'),
		fundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4]))
	};
}

interface IWireEntry {
	from: string;
	type: number;
	payload: Buffer;
}

/** A loopback link between two nodes with a wire log and a FIFO reconnect. */
class NodeLink {
	readonly log: IWireEntry[] = [];
	connected = true;
	drop: ((from: string, type: number, payload: Buffer) => boolean) | null =
		null;
	private queue: IWireEntry[] | null = null;

	constructor(
		readonly a: LightningNode,
		readonly b: LightningNode
	) {
		a.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === b.getNodeId())
					this.deliver(a.getNodeId(), type, payload);
			}
		);
		b.on(
			'message:outbound',
			(pubkey: string, type: number, payload: Buffer) => {
				if (pubkey === a.getNodeId())
					this.deliver(b.getNodeId(), type, payload);
			}
		);
	}

	private deliver(from: string, type: number, payload: Buffer): void {
		if (!this.connected) return;
		if (this.drop && this.drop(from, type, payload)) return;
		if (this.queue) {
			this.queue.push({ from, type, payload });
			return;
		}
		this.direct({ from, type, payload });
	}

	private direct(m: IWireEntry): void {
		this.log.push(m);
		const to = m.from === this.a.getNodeId() ? this.b : this.a;
		to.handlePeerMessage(m.from, m.type, m.payload);
	}

	sentBy(node: LightningNode): IWireEntry[] {
		return this.log.filter((e) => e.from === node.getNodeId());
	}

	disconnect(): void {
		this.connected = false;
		this.a.getChannelManager().handlePeerDisconnected(this.b.getNodeId());
		this.b.getChannelManager().handlePeerDisconnected(this.a.getNodeId());
	}

	reconnect(): void {
		this.connected = true;
		this.queue = [];
		this.a.getChannelManager().handlePeerReconnected(this.b.getNodeId());
		this.b.getChannelManager().handlePeerReconnected(this.a.getNodeId());
		while (this.queue.length > 0) this.direct(this.queue.shift()!);
		this.queue = null;
	}
}

/** Open a channel from `opener` to `acceptor` and pin it published. */
function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = opener.openChannel(acceptor.getNodeId(), fundingSatoshis);
	const channelId = opener.createFunding(
		channel,
		crypto.randomBytes(32),
		0,
		crypto.randomBytes(64)
	)!;
	opener.handleFundingConfirmed(channelId);
	acceptor.handleFundingConfirmed(channelId);
	for (const n of [opener, acceptor]) {
		for (const ch of n.getChannelManager().listChannels()) {
			const st = ch.getFullState();
			st.announceChannel = true;
			st.announcementSigsSent = true;
			st.announcementSigsReceived = true;
		}
	}
	return channelId;
}

/** Publish a direct channel between two nodes on `viewer`'s graph. */
function publishChannel(
	viewer: LightningNode,
	x: LightningNode,
	y: LightningNode,
	channelId: Buffer,
	scid: Buffer,
	feeBaseMsat = 1000,
	feeProportionalMillionths = 1
): void {
	const xk = Buffer.from(x.getNodeId(), 'hex');
	const yk = Buffer.from(y.getNodeId(), 'hex');
	const xFirst = Buffer.compare(xk, yk) < 0;
	viewer.getGraph().addChannelAnnouncement({
		nodeSignature1: Buffer.alloc(64),
		nodeSignature2: Buffer.alloc(64),
		bitcoinSignature1: Buffer.alloc(64),
		bitcoinSignature2: Buffer.alloc(64),
		features: Buffer.alloc(0),
		chainHash: REGTEST_CHAIN_HASH,
		shortChannelId: scid,
		nodeId1: xFirst ? xk : yk,
		nodeId2: xFirst ? yk : xk,
		bitcoinKey1: Buffer.alloc(33, 2),
		bitcoinKey2: Buffer.alloc(33, 3)
	});
	for (const channelFlags of [0, 1]) {
		viewer.getGraph().applyChannelUpdate({
			signature: Buffer.alloc(64),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scid,
			timestamp: Math.floor(Date.now() / 1000),
			messageFlags: 1,
			channelFlags,
			cltvExpiryDelta: 40,
			htlcMinimumMsat: 1000n,
			feeBaseMsat,
			feeProportionalMillionths,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
	viewer.registerChannelScid(channelId, scid);
	x.registerChannelScid(channelId, scid);
	y.registerChannelScid(channelId, scid);
}

/**
 * Put the channel_announcement of one of S's channels (the epoch channel by
 * default) on S's own graph under `scid`, carrying both funding keys, as the
 * announcement exchange leaves it: verified only when every signature
 * checked out.
 */
function announceSR(
	w: IWorld,
	scid: Buffer,
	verified: boolean,
	channelId = w.srChannelId,
	peer = w.r
): void {
	const st = w.s.getChannelManager().getChannel(channelId)!.getFullState();
	st.shortChannelId = scid;
	const sk = Buffer.from(w.s.getNodeId(), 'hex');
	const rk = Buffer.from(peer.getNodeId(), 'hex');
	const sFirst = Buffer.compare(sk, rk) < 0;
	const sKey = st.localBasepoints.fundingPubkey;
	const rKey = st.remoteBasepoints!.fundingPubkey;
	const added = w.s.getGraph().addChannelAnnouncement(
		{
			nodeSignature1: crypto.randomBytes(64),
			nodeSignature2: crypto.randomBytes(64),
			bitcoinSignature1: crypto.randomBytes(64),
			bitcoinSignature2: crypto.randomBytes(64),
			features: Buffer.alloc(0),
			chainHash: REGTEST_CHAIN_HASH,
			shortChannelId: scid,
			nodeId1: sFirst ? sk : rk,
			nodeId2: sFirst ? rk : sk,
			bitcoinKey1: sFirst ? sKey : rKey,
			bitcoinKey2: sFirst ? rKey : sKey
		},
		{ verified }
	);
	expect(added).to.equal(true);
}

/** Disable `from`'s direction of a channel already on `viewer`'s graph. */
function disableChannel(
	viewer: LightningNode,
	from: LightningNode,
	to: LightningNode,
	scid: Buffer
): void {
	const fromFirst =
		Buffer.compare(
			Buffer.from(from.getNodeId(), 'hex'),
			Buffer.from(to.getNodeId(), 'hex')
		) < 0;
	const current = viewer.getGraph().getChannel(scid)!;
	const update = fromFirst ? current.update1! : current.update2!;
	const applied = viewer.getGraph().applyChannelUpdate({
		...update,
		timestamp: update.timestamp + 1,
		channelFlags: update.channelFlags | 2
	});
	expect(applied).to.equal(true);
}

/**
 * R exposes voucher 1 and leaves. P then knows the epoch channel from gossip
 * but disabled, and a second S-R edge under a fresh SCID at 0 msat + 0 ppm.
 * S backs that SCID with `channelId`, its channel to `peer`, at the same
 * policy.
 */
function exposeOverSecondEdge(
	w: IWorld,
	channelId: Buffer,
	peer: LightningNode,
	verified: boolean
): { inv: string; scid: Buffer } {
	w.s.setChannelPolicy(channelId, {
		feeBaseMsat: 0,
		feeProportionalMillionths: 0
	});
	const [inv] = exposeAndLeave(w, [1]);
	const epochScid = decodeInvoice(inv).routingHints![0][0].shortChannelId;
	publishChannel(w.p, w.s, w.r, w.srChannelId, epochScid, 1000, 1);
	disableChannel(w.p, w.s, w.r, epochScid);
	announceSR(w, epochScid, true);
	const scid = encodeShortChannelId({ block: 500, txIndex: 3, outputIndex: 0 });
	publishChannel(w.p, w.s, w.r, channelId, scid, 0, 0);
	announceSR(w, scid, verified, channelId, peer);
	return { inv, scid };
}

const TIP = 790_000;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;
const AMOUNTS = [1_000_000n, 546_250n, 2_000_000n];
const FEE_BASE = 1000;
const FEE_PPM = 5000;

interface IWorld {
	p: LightningNode;
	s: LightningNode;
	r: LightningNode;
	pConfig: INodeConfig;
	sConfig: INodeConfig;
	rConfig: INodeConfig;
	ps: NodeLink;
	sr: NodeLink;
	psChannelId: Buffer;
	srChannelId: Buffer;
	srHex: string;
	errors: { p: string[]; s: string[]; r: string[] };
}

let worldSeed = 0;

function createWorld(opts: { sStorage?: SqliteStorage } = {}): IWorld {
	worldSeed += 10;
	const pConfig = makeNodeConfig(worldSeed + 1);
	const sConfig = makeNodeConfig(worldSeed + 2, opts.sStorage);
	const rConfig = makeNodeConfig(worldSeed + 3);
	const p = new LightningNode(pConfig);
	const s = new LightningNode(sConfig);
	const r = new LightningNode(rConfig);
	const errors = { p: [] as string[], s: [] as string[], r: [] as string[] };
	p.on('node:error', (e: { message: string }) => errors.p.push(e.message));
	s.on('node:error', (e: { message: string }) => errors.s.push(e.message));
	r.on('node:error', (e: { message: string }) => errors.r.push(e.message));
	const ps = new NodeLink(p, s);
	const sr = new NodeLink(s, r);
	const psChannelId = openReadyChannel(p, s, 1_000_000n);
	const srChannelId = openReadyChannel(s, r, 1_000_000n);
	const scidPS = encodeShortChannelId({
		block: 500,
		txIndex: 1,
		outputIndex: 0
	});
	const scidSR = encodeShortChannelId({
		block: 500,
		txIndex: 2,
		outputIndex: 0
	});
	// P sees P-S; S sees S-R (for the ordinary S-to-R payment after the epoch).
	publishChannel(p, p, s, psChannelId, scidPS);
	publishChannel(s, s, r, srChannelId, scidSR);
	for (const n of [p, s, r]) n.handleNewBlock(TIP);
	ps.log.length = 0;
	sr.log.length = 0;
	return {
		p,
		s,
		r,
		pConfig,
		sConfig,
		rConfig,
		ps,
		sr,
		psChannelId,
		srChannelId,
		srHex: srChannelId.toString('hex'),
		errors
	};
}

function record(node: LightningNode, srHex: string): IFforEpochRecord {
	const f = node.getFforEpoch(srHex);
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

/** R sets up the epoch to ACTIVE on the S-R channel. */
function activate(w: IWorld, amounts = AMOUNTS): void {
	const res = w.r.startFforEpoch(w.srHex, {
		voucherAmountsMsat: amounts,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: FEE_BASE,
		feeProportionalMillionths: FEE_PPM
	});
	expect(res.ok, res.error).to.equal(true);
	expect(record(w.s, w.srHex).state, JSON.stringify(w.errors)).to.equal(
		FforState.ACTIVE
	);
	expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
}

/** R exposes voucher k's invoice, then goes offline. */
function exposeAndLeave(w: IWorld, ks: number[]): string[] {
	const invoices = ks.map(
		(k) => w.r.createFforVoucherInvoice(w.srHex, k).bolt11
	);
	w.sr.disconnect();
	return invoices;
}

/** P pays; returns P's payment record for the hash. */
function pay(w: IWorld, bolt11: string): IPaymentInfo {
	const decoded = decodeInvoice(bolt11);
	w.p.sendPayment(bolt11);
	const payment = w.p.getPayment(decoded.paymentHash);
	expect(payment, 'payer payment record').to.exist;
	return payment!;
}

/** A voucher invoice re-signed by R with a different amount or hint terms. */
function craftInvoice(
	w: IWorld,
	real: string,
	overrides: {
		amountMsat?: bigint;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
	}
): string {
	const decoded = decodeInvoice(real);
	const hint = decoded.routingHints![0][0];
	const features = FeatureFlags.empty();
	features.setCompulsory(Feature.TLV_ONION);
	features.setCompulsory(Feature.PAYMENT_SECRET);
	return encodeInvoice({
		network: Network.REGTEST,
		amountMsat: overrides.amountMsat ?? decoded.amountMsat,
		paymentHash: decoded.paymentHash,
		paymentSecret: decoded.paymentSecret,
		description: 'crafted',
		expiry: 3600,
		minFinalCltvExpiry: 40,
		routingHints: [
			[
				{
					...hint,
					feeBaseMsat: overrides.feeBaseMsat ?? hint.feeBaseMsat,
					feeProportionalMillionths:
						overrides.feeProportionalMillionths ??
						hint.feeProportionalMillionths
				}
			]
		],
		featureBits: features,
		privateKey: w.rConfig.nodePrivateKey,
		payeeNodeKey: getPublicKey(w.rConfig.nodePrivateKey)
	});
}

function voucherStates(node: LightningNode, channelId: Buffer): HtlcState[] {
	const out: HtlcState[] = [];
	for (const e of node
		.getChannelManager()
		.getChannel(channelId)!
		.getFullState()
		.htlcs.values()) {
		if (e.fforVoucher === true) out.push(e.state);
	}
	return out;
}

// ─────────────── Tests ───────────────

describe('FFOR Variant D: silent settlement (M8.2)', function () {
	this.timeout(60_000);

	it('R exposes a fixed-amount invoice for exactly d_k with S fee terms in the hint', () => {
		const w = createWorld();
		activate(w);
		const inv = w.r.createFforVoucherInvoice(w.srHex, 2);
		const decoded = decodeInvoice(inv.bolt11);
		expect(decoded.amountMsat).to.equal(AMOUNTS[1]);
		expect(decoded.paymentHash.equals(record(w.r, w.srHex).paymentHashes[1])).to
			.be.true;
		expect(decoded.routingHints).to.have.length(1);
		const hint = decoded.routingHints![0][0];
		expect(hint.pubkey.toString('hex')).to.equal(w.s.getNodeId());
		expect(hint.feeBaseMsat).to.equal(FEE_BASE);
		expect(hint.feeProportionalMillionths).to.equal(FEE_PPM);
		// Section 7.5.6: no later than 8 minutes per remaining block.
		expect(decoded.expiry).to.be.at.most((D_DEADLINE - TIP) * 480);
		// R holds no preimage for it and it is not a hold invoice.
		expect(w.r.listHoldInvoices().length).to.equal(0);
		// Before ACTIVE no invoice may be exposed.
		const w2 = createWorld();
		expect(() => w2.r.createFforVoucherInvoice(w2.srHex, 1)).to.throw(
			'no FFOR epoch'
		);
	});

	it('settles a delegated payment upstream with t_k and sends R nothing', () => {
		const w = createWorld();
		activate(w);
		const ackIndex = w.sr.log.findIndex(
			(e) => e.type === MessageType.FF_ACTIVATE_ACK
		);
		expect(ackIndex).to.be.greaterThan(0);
		const [inv] = exposeAndLeave(w, [1]);
		const settled: unknown[] = [];
		w.s.on('ffor:settled', (e: unknown) => settled.push(e));
		const payment = pay(w, inv);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		const t1 = record(w.s, w.srHex).preimages[0];
		expect(payment.preimage!.equals(t1)).to.be.true;
		expect(sha(payment.preimage!).equals(decodeInvoice(inv).paymentHash)).to.be
			.true;
		expect(settled.length).to.equal(1);
		expect(record(w.s, w.srHex).slotStates).to.deep.equal([
			FforSlotState.SETTLED,
			FforSlotState.UNUSED,
			FforSlotState.UNUSED
		]);
		// The proof of payment P holds is R's claim key (section 9.5.3).
		expect(
			w.p.getPaymentProof(decodeInvoice(inv).paymentHash)!.preimage!.equals(t1)
		).to.be.true;
		// Gate: zero messages from S to R for the whole epoch after the ack.
		expect(
			w.sr.log.slice(ackIndex + 1).filter((e) => e.from === w.s.getNodeId())
		).to.deep.equal([]);
		// And nothing was dropped on the floor either: the link is down.
		expect(w.sr.connected).to.be.false;
		// R's vouchers are untouched and R never held the preimage.
		expect(voucherStates(w.r, w.srChannelId)).to.deep.equal([
			HtlcState.COMMITTED,
			HtlcState.COMMITTED,
			HtlcState.COMMITTED
		]);
		expect(record(w.r, w.srHex).knownPreimages).to.deep.equal([
			null,
			null,
			null
		]);
		expect(w.errors.s).to.deep.equal([]);
	});

	it('refuses a second payment on a consumed hash', () => {
		const w = createWorld();
		activate(w);
		const [inv] = exposeAndLeave(w, [1]);
		expect(pay(w, inv).status).to.equal(PaymentStatus.COMPLETED);
		// A second payer on the same invoice.
		const p2 = new LightningNode(makeNodeConfig(worldSeed + 7));
		const p2s = new NodeLink(p2, w.s);
		const p2ChannelId = openReadyChannel(p2, w.s, 1_000_000n);
		publishChannel(
			p2,
			p2,
			w.s,
			p2ChannelId,
			encodeShortChannelId({ block: 500, txIndex: 9, outputIndex: 0 })
		);
		p2.handleNewBlock(TIP);
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const decoded = decodeInvoice(inv);
		p2.sendPayment(inv);
		const payment = p2.getPayment(decoded.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
		// The payer may retry once on a temporary failure; every attempt is
		// refused for the same reason and the slot stays settled.
		expect(failures.length).to.be.at.least(1);
		for (const f of failures) {
			expect(f.reason).to.equal(
				'duplicate delegated payment for consumed hash'
			);
		}
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.SETTLED);
		expect(p2s.sentBy(w.s).map((e) => e.type)).to.include(
			MessageType.UPDATE_FAIL_HTLC
		);
	});

	it('applies the section 7.6 amount checks: underpay, overpay, fee-insufficient', () => {
		const w = createWorld();
		activate(w);
		const [inv] = exposeAndLeave(w, [1]);
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const d = AMOUNTS[0];

		const under = pay(w, craftInvoice(w, inv, { amountMsat: d - 1n }));
		expect(under.status).to.equal(PaymentStatus.FAILED);
		expect(under.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
		expect(failures.pop()!.reason).to.include('underpay');

		// A fresh payer per attempt: P refuses to re-pay a hash it has tried.
		const w2 = createWorld();
		activate(w2);
		const [inv2] = exposeAndLeave(w2, [1]);
		w2.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const over = pay(w2, craftInvoice(w2, inv2, { amountMsat: d + 1n }));
		expect(over.status).to.equal(PaymentStatus.FAILED);
		expect(over.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
		expect(failures.pop()!.reason).to.include('overpay');

		const w3 = createWorld();
		activate(w3);
		const [inv3] = exposeAndLeave(w3, [1]);
		w3.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const cheap = pay(
			w3,
			craftInvoice(w3, inv3, { feeBaseMsat: 0, feeProportionalMillionths: 0 })
		);
		expect(cheap.status).to.equal(PaymentStatus.FAILED);
		expect(cheap.failureCode).to.equal(FEE_INSUFFICIENT);
		expect(failures.pop()!.reason).to.equal('fee_insufficient');

		// Exact amount and fee terms settle.
		const w4 = createWorld();
		activate(w4);
		const [inv4] = exposeAndLeave(w4, [1]);
		expect(pay(w4, inv4).status).to.equal(PaymentStatus.COMPLETED);
		// Fee overpayment belongs to S and is accepted (check 2 is >=).
		const w5 = createWorld();
		activate(w5);
		const [inv5] = exposeAndLeave(w5, [1]);
		expect(
			pay(w5, craftInvoice(w5, inv5, { feeBaseMsat: FEE_BASE * 3 })).status
		).to.equal(PaymentStatus.COMPLETED);
		for (const s of [w, w2, w3, w4, w5]) {
			expect(record(s.r, s.srHex).knownPreimages).to.deep.equal([
				null,
				null,
				null
			]);
		}
	});

	it('settles a payer that priced a public S-R hop from S policy instead of the book terms', () => {
		const w = createWorld();
		activate(w);
		const [inv] = exposeAndLeave(w, [1]);
		// P now knows S-R from gossip at S's default policy (1000 msat + 1 ppm),
		// so it prices S's hop from that channel_update, not the hint's book
		// terms (1000 msat + 5000 ppm).
		const hint = decodeInvoice(inv).routingHints![0][0];
		publishChannel(w.p, w.s, w.r, w.srChannelId, hint.shortChannelId, 1000, 1);
		announceSR(w, hint.shortChannelId, true);
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const d = AMOUNTS[0];
		const payment = pay(w, inv);
		expect(failures).to.deep.equal([]);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		expect(payment.route!.totalFeeMsat).to.equal(feeS(d, 1000, 1));
		expect(payment.route!.totalFeeMsat < feeS(d, FEE_BASE, FEE_PPM)).to.be.true;
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.SETTLED);
	});

	it('holds an S-R hop whose announcement did not verify to the book terms', () => {
		const w = createWorld();
		activate(w);
		const [inv] = exposeAndLeave(w, [1]);
		// announcement_signatures went both ways (the world pins the flags),
		// but R's signatures were garbage, so nothing was published.
		announceSR(w, decodeInvoice(inv).routingHints![0][0].shortChannelId, false);
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		// Covers S's default policy (1000 msat + 1 ppm) but not the book.
		const payment = pay(
			w,
			craftInvoice(w, inv, { feeBaseMsat: 1000, feeProportionalMillionths: 1 })
		);
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(FEE_INSUFFICIENT);
		expect(failures.pop()!.reason).to.equal('fee_insufficient');
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
	});

	it('settles a payer that routed over a parallel public S-R channel at that channel policy', () => {
		const w = createWorld();
		const second = openReadyChannel(w.s, w.r);
		activate(w);
		const { inv, scid } = exposeOverSecondEdge(w, second, w.r, true);
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const payment = pay(w, inv);
		expect(failures).to.deep.equal([]);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		const hops = payment.route!.hops;
		expect(hops[hops.length - 1].shortChannelId.equals(scid)).to.be.true;
		expect(payment.route!.totalFeeMsat).to.equal(0n);
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.SETTLED);
	});

	it('holds a named channel that is not a public channel to R to the book terms', () => {
		// A second S-R channel whose announcement did not verify, a private
		// S-R channel under a verified S-R announcement carrying its keys, then
		// S's public channel to P, which P's graph places between S and R.
		for (const kind of ['unverified', 'private', 'toP'] as const) {
			const w = createWorld();
			const toR = kind !== 'toP';
			const named = toR ? openReadyChannel(w.s, w.r) : w.psChannelId;
			w.s
				.getChannelManager()
				.getChannel(named)!
				.getFullState().announceChannel = kind !== 'private';
			activate(w);
			const { inv } = exposeOverSecondEdge(
				w,
				named,
				toR ? w.r : w.p,
				kind !== 'unverified'
			);
			const failures: { reason: string }[] = [];
			w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
				failures.push(e)
			);
			const payment = pay(w, inv);
			expect(payment.status).to.equal(PaymentStatus.FAILED);
			expect(payment.failureCode).to.equal(FEE_INSUFFICIENT);
			expect(failures.pop()!.reason).to.equal('fee_insufficient');
			expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
		}
	});

	it('holds an S-R channel moved onto the SCID of S public channel to P to the book terms', () => {
		// S uses one funding key for every channel here, so the S-P
		// announcement carries the key of the S-R channel R moved onto it.
		const w = createWorld();
		const moved = openReadyChannel(w.s, w.r);
		w.s.setChannelPolicy(moved, {
			feeBaseMsat: 0,
			feeProportionalMillionths: 0
		});
		activate(w);
		const { inv, scid } = exposeOverSecondEdge(w, w.psChannelId, w.p, true);
		w.s.getChannelManager().getChannel(moved)!.getFullState().shortChannelId =
			scid;
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const payment = pay(w, inv);
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(FEE_INSUFFICIENT);
		expect(failures.pop()!.reason).to.equal('fee_insufficient');
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
	});

	it('holds an S-R channel moved onto the SCID of its sibling S-R channel to the book terms', () => {
		// Both S-R channels carry S's one funding key, but R funded the moved
		// one under a key the sibling's announcement does not carry.
		const w = createWorld();
		const moved = openReadyChannel(w.s, w.r);
		const movedState = w.s
			.getChannelManager()
			.getChannel(moved)!
			.getFullState();
		movedState.remoteBasepoints!.fundingPubkey = getPublicKey(sha('other-key'));
		w.s.setChannelPolicy(moved, {
			feeBaseMsat: 0,
			feeProportionalMillionths: 0
		});
		activate(w);
		const [inv] = exposeAndLeave(w, [1]);
		const scid = decodeInvoice(inv).routingHints![0][0].shortChannelId;
		publishChannel(w.p, w.s, w.r, w.srChannelId, scid, 0, 0);
		announceSR(w, scid, true);
		w.s
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState().shortChannelId = encodeShortChannelId({
			block: 500,
			txIndex: 4,
			outputIndex: 0
		});
		movedState.shortChannelId = scid;
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const payment = pay(w, inv);
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(FEE_INSUFFICIENT);
		expect(failures.pop()!.reason).to.equal('fee_insufficient');
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
	});

	it('under a blinded path derives amt_to_forward by the inverse formula within rounding_slack', () => {
		const d = 1_000_000n;
		const gross = grossIntoS(d, FEE_BASE, FEE_PPM);
		expect(inverseAmtToForward(gross, FEE_BASE, FEE_PPM)).to.equal(d);
		const slack = roundingSlackMsat(d);
		expect(slack).to.equal(17n + 8n);
		const check = (
			amountMsat: bigint
		): ReturnType<typeof checkDelegatedAmounts> =>
			checkDelegatedAmounts({
				payeeAmountMsat: d,
				amountMsat,
				amtToForwardMsat: null,
				hopKind: 'blinded',
				feeBaseMsat: FEE_BASE,
				feeProportionalMillionths: FEE_PPM
			});
		expect(check(gross)).to.equal(null);
		// Up to the slack over d is fee rounding and settles.
		let inside = gross;
		while (inverseAmtToForward(inside + 1n, FEE_BASE, FEE_PPM)! <= d + slack)
			inside++;
		expect(check(inside)).to.equal(null);
		expect(
			Number(inverseAmtToForward(inside, FEE_BASE, FEE_PPM)! - d)
		).to.be.at.most(Number(slack));
		// One millisatoshi past the slack is an overpay.
		const over = check(inside + 1n);
		expect(over).to.not.equal(null);
		expect(over!.check).to.equal(1);
		expect((over as { reason: string }).reason).to.equal('overpay');
		// Below gross the derived amount undershoots d.
		let below = gross - 1n;
		while (inverseAmtToForward(below, FEE_BASE, FEE_PPM)! >= d) below--;
		const under = check(below);
		expect(under).to.not.equal(null);
		expect((under as { reason: string }).reason).to.equal('underpay');
		// Plaintext: equality only.
		const plain = (
			forward: bigint,
			amount: bigint
		): ReturnType<typeof checkDelegatedAmounts> =>
			checkDelegatedAmounts({
				payeeAmountMsat: d,
				amountMsat: amount,
				amtToForwardMsat: forward,
				hopKind: 'plaintext',
				feeBaseMsat: FEE_BASE,
				feeProportionalMillionths: FEE_PPM
			});
		expect(plain(d, gross)).to.equal(null);
		expect(plain(d + 1n, gross + 1n)!.check).to.equal(1);
		expect(plain(d - 1n, gross)!.check).to.equal(1);
		expect(plain(d, d + feeS(d, FEE_BASE, FEE_PPM) - 1n)!.check).to.equal(2);
		// A fee covering S's advertised policy settles a plaintext hop; one
		// below both terms does not, and a blinded hop reads the book alone.
		const advertisedFee = { feeBaseMsat: 1000, feeProportionalMillionths: 1 };
		const policyFee = d + feeS(d, 1000, 1);
		const withPolicy = (
			hopKind: 'plaintext' | 'blinded',
			amount: bigint
		): ReturnType<typeof checkDelegatedAmounts> =>
			checkDelegatedAmounts({
				payeeAmountMsat: d,
				amountMsat: amount,
				amtToForwardMsat: d,
				hopKind,
				feeBaseMsat: FEE_BASE,
				feeProportionalMillionths: FEE_PPM,
				advertisedFee
			});
		expect(withPolicy('plaintext', policyFee)).to.equal(null);
		expect(withPolicy('plaintext', policyFee - 1n)!.check).to.equal(2);
		// One msat under the book still derives d, so only check 2 can refuse it.
		expect(inverseAmtToForward(gross - 1n, FEE_BASE, FEE_PPM)).to.equal(d);
		expect(withPolicy('plaintext', gross - 1n)).to.equal(null);
		expect(withPolicy('blinded', gross - 1n)!.check).to.equal(2);
	});

	it('fails a payment that arrives before ACTIVE, at or past D, or after ff_close', () => {
		// Before ACTIVE: S is VOUCHERS_COMMITTED (ff_activate dropped).
		const w = createWorld();
		w.sr.drop = (_from, type): boolean => type === MessageType.FF_ACTIVATE;
		const res = w.r.startFforEpoch(w.srHex, {
			voucherAmountsMsat: AMOUNTS,
			minPaymentMsat: 400_000n,
			settlementDeadline: D_DEADLINE,
			voucherExpiry: T_EXP,
			feeBaseMsat: FEE_BASE,
			feeProportionalMillionths: FEE_PPM
		});
		expect(res.ok).to.equal(true);
		expect(record(w.s, w.srHex).state).to.equal(FforState.VOUCHERS_COMMITTED);
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		// R cannot expose an invoice before ACTIVE; craft what a leaked one
		// would look like from the hash S already committed.
		const hash = record(w.s, w.srHex).paymentHashes[0];
		const features = FeatureFlags.empty();
		features.setCompulsory(Feature.TLV_ONION);
		features.setCompulsory(Feature.PAYMENT_SECRET);
		const early = encodeInvoice({
			network: Network.REGTEST,
			amountMsat: AMOUNTS[0],
			paymentHash: hash,
			paymentSecret: crypto.randomBytes(32),
			description: 'early',
			expiry: 3600,
			minFinalCltvExpiry: 40,
			routingHints: [
				[
					{
						pubkey: Buffer.from(w.s.getNodeId(), 'hex'),
						shortChannelId: encodeShortChannelId({
							block: 500,
							txIndex: 2,
							outputIndex: 0
						}),
						feeBaseMsat: FEE_BASE,
						feeProportionalMillionths: FEE_PPM,
						cltvExpiryDelta: 40
					}
				]
			],
			featureBits: features,
			privateKey: w.rConfig.nodePrivateKey,
			payeeNodeKey: getPublicKey(w.rConfig.nodePrivateKey)
		});
		const earlyPayment = pay(w, early);
		expect(
			earlyPayment.status,
			JSON.stringify({
				reason: earlyPayment.failureReason,
				code: earlyPayment.failureCode,
				failures: failures.map((f) => f.reason),
				ps: w.ps.log.map((e) => e.type),
				errors: w.errors
			})
		).to.equal(PaymentStatus.FAILED);
		expect(earlyPayment.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
		expect(failures.pop()!.reason).to.include('VOUCHERS_COMMITTED');

		// At D: S's tip reached settlement_deadline.
		const w2 = createWorld();
		activate(w2);
		const [inv2] = exposeAndLeave(w2, [1]);
		w2.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		// The whole network reaches D (a payer behind S's tip would send an
		// HTLC S must refuse for its CLTV, not for the deadline).
		for (const n of [w2.p, w2.s, w2.r]) n.handleNewBlock(D_DEADLINE);
		const late = pay(w2, inv2);
		expect(late.status).to.equal(PaymentStatus.FAILED);
		expect(failures.pop()!.reason).to.include('settlement_deadline');
		expect(record(w2.s, w2.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);

		// After ff_close (section 7.5.6): the stopping condition wins.
		const w3 = createWorld();
		activate(w3);
		const [inv3] = exposeAndLeave(w3, [1]);
		w3.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		w3.sr.reconnect();
		const closed = w3.r.closeFforEpoch(w3.srHex);
		expect(closed.ok, closed.error).to.equal(true);
		const afterClose = pay(w3, inv3);
		expect(afterClose.status).to.equal(PaymentStatus.FAILED);
		// R drained inside the close call, so S may already be CLOSED.
		expect(failures.pop()!.reason).to.match(/ff_close|CLOSED/);
	});
});

describe('FFOR Variant D: cooperative return (M8.3)', function () {
	this.timeout(60_000);

	it('closes with the bitmap and preimages, drains in one round, and resumes', () => {
		const w = createWorld();
		const sBefore = w.s
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState().localBalanceMsat;
		const rBefore = w.r
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState().localBalanceMsat;
		activate(w);
		const [inv1, inv3] = exposeAndLeave(w, [1, 3]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		expect(pay(w, inv3).status).to.equal(PaymentStatus.COMPLETED);
		const t1 = record(w.s, w.srHex).preimages[0];
		const t3 = record(w.s, w.srHex).preimages[2];

		// The invoices minted are readable back by slot (issue #875): a host
		// that lost the string reads it from the epoch, not from a second
		// mint the book refuses.
		expect(w.r.fforSlotInvoices(w.srHex)).to.deep.equal([inv1, null, inv3]);
		expect(w.s.fforSlotInvoices(w.srHex)).to.deep.equal([]);

		// Nothing on the onion path completed the voucher invoices: R never
		// saw the payer's HTLCs.
		const hash1 = decodeInvoice(inv1).paymentHash;
		const hash3 = decodeInvoice(inv3).paymentHash;
		expect(w.r.getPayment(hash1)!.status).to.equal(PaymentStatus.PENDING);
		const received: IPaymentInfo[] = [];
		const settled: { paymentHash: Buffer; bolt11: string }[] = [];
		w.r.on('payment:received', (p: IPaymentInfo) => received.push(p));
		w.r.on('invoice:settled', (e: { paymentHash: Buffer; bolt11: string }) =>
			settled.push(e)
		);

		// R returns.
		w.sr.reconnect();
		expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
		w.sr.log.length = 0;
		const closed = w.r.closeFforEpoch(w.srHex);
		expect(closed.ok, closed.error).to.equal(true);

		// The paid vouchers' invoices read paid once the close credited them
		// (issue #876), announced the way any receive is; the unpaid slot's
		// invoice stays pending.
		const paid1 = w.r.getPayment(hash1)!;
		expect(paid1.status).to.equal(PaymentStatus.COMPLETED);
		expect(paid1.preimage!.equals(t1)).to.be.true;
		expect(paid1.amountMsat).to.equal(AMOUNTS[0]);
		expect(w.r.getPayment(hash3)!.status).to.equal(PaymentStatus.COMPLETED);
		expect(received.map((p) => p.amountMsat)).to.deep.equal([
			AMOUNTS[0],
			AMOUNTS[2]
		]);
		expect(settled.map((e) => e.bolt11)).to.deep.equal([inv1, inv3]);
		const hash2 = record(w.r, w.srHex).paymentHashes[1];
		expect(w.r.getPayment(hash2)?.status ?? PaymentStatus.PENDING).to.equal(
			PaymentStatus.PENDING
		);

		const types = w.sr.log.map((e) => e.type);
		// The only FFOR messages after activation are ff_close and ff_close_ack.
		expect(types.filter((t) => t >= 55000)).to.deep.equal([
			MessageType.FF_CLOSE,
			MessageType.FF_CLOSE_ACK
		]);
		// Stock BOLT 2 after the ack: R's fulfils and fail, one round each way.
		const ackIdx = types.indexOf(MessageType.FF_CLOSE_ACK);
		const after = types.slice(ackIdx + 1);
		expect(
			after.filter((t) => t === MessageType.UPDATE_FULFILL_HTLC).length
		).to.equal(2);
		expect(
			after.filter((t) => t === MessageType.UPDATE_FAIL_HTLC).length
		).to.equal(1);
		expect(
			after.filter((t) => t === MessageType.COMMITMENT_SIGNED).length
		).to.equal(2);
		expect(
			after.filter((t) => t === MessageType.REVOKE_AND_ACK).length
		).to.equal(2);
		expect(after.length).to.equal(7);

		// The ack's bitmap and preimages.
		const ack = decodeFforCloseAckMessage(w.sr.log[ackIdx].payload);
		expect(ack.numSlots).to.equal(3);
		expect(bitmapGet(ack.settled, 1)).to.be.true;
		expect(bitmapGet(ack.settled, 2)).to.be.false;
		expect(bitmapGet(ack.settled, 3)).to.be.true;
		expect(ack.preimages.map((p) => p.k)).to.deep.equal([1, 3]);
		expect(ack.preimages[0].preimage.equals(t1)).to.be.true;
		expect(ack.preimages[1].preimage.equals(t3)).to.be.true;

		// CLOSED on both sides, no voucher left, balances correct.
		expect(record(w.s, w.srHex).state).to.equal(FforState.CLOSED);
		expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
		expect(voucherStates(w.s, w.srChannelId)).to.deep.equal([]);
		expect(voucherStates(w.r, w.srChannelId)).to.deep.equal([]);
		const sAfter = w.s
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState();
		const rAfter = w.r
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState();
		const credited = AMOUNTS[0] + AMOUNTS[2];
		expect(rAfter.localBalanceMsat).to.equal(rBefore + credited);
		expect(sAfter.localBalanceMsat).to.equal(sBefore - credited);
		expect(sAfter.remoteBalanceMsat).to.equal(rAfter.localBalanceMsat);
		expect(rAfter.remoteBalanceMsat).to.equal(sAfter.localBalanceMsat);
		expect(sAfter.htlcs.size).to.equal(0);
		expect(rAfter.htlcs.size).to.equal(0);
		// The invoices stay readable after the close.
		expect(w.r.fforSlotInvoices(w.srHex)).to.deep.equal([inv1, null, inv3]);

		// Ordinary operation resumes: S pays R over the channel.
		const ordinary = w.r.createInvoice({
			amountMsat: 50_000n,
			description: 'after'
		});
		w.s.sendPayment(ordinary.bolt11);
		expect(w.s.getPayment(ordinary.paymentHash)!.status).to.equal(
			PaymentStatus.COMPLETED
		);
		expect(w.errors.r).to.deep.equal([]);
	});

	it('a payment racing ff_close lands on exactly one side of the bitmap', () => {
		// Committed before S processed ff_close: settled, in the bitmap.
		const w = createWorld();
		activate(w);
		const [inv1, inv2] = exposeAndLeave(w, [1, 2]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		w.sr.reconnect();
		const closed = w.r.closeFforEpoch(w.srHex);
		expect(closed.ok).to.equal(true);
		// After: failed upstream, not in the bitmap, and R failed the slot.
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const late = pay(w, inv2);
		expect(late.status).to.equal(PaymentStatus.FAILED);
		// R's drain completed inside the close call, so S may already be
		// CLOSED; either way the stopping condition, not the slot, answers.
		expect(failures.pop()!.reason).to.match(/ff_close|CLOSED/);
		const bitmap = record(w.s, w.srHex).settledBitmap!;
		expect(bitmapGet(bitmap, 1)).to.be.true;
		expect(bitmapGet(bitmap, 2)).to.be.false;
		expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
		expect(record(w.s, w.srHex).state).to.equal(FforState.CLOSED);
		const rAfter = w.r
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState();
		expect(rAfter.htlcs.size).to.equal(0);
	});

	it('S retransmits ff_close_ack to an ACTIVE R, and R retransmits ff_close to an ACTIVE S', () => {
		// Drop the ack: S is DRAINING, R still ACTIVE with ff_close sent.
		const w = createWorld();
		activate(w);
		const [inv1] = exposeAndLeave(w, [1]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		w.sr.reconnect();
		w.sr.drop = (_from, type): boolean => type === MessageType.FF_CLOSE_ACK;
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		expect(record(w.s, w.srHex).state).to.equal(FforState.DRAINING);
		expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
		w.sr.drop = null;
		w.sr.disconnect();
		w.sr.log.length = 0;
		w.sr.reconnect();
		const types = w.sr.log.map((e) => e.type);
		expect(types.filter((t) => t === MessageType.FF_CLOSE_ACK).length).to.equal(
			1
		);
		expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
		expect(record(w.s, w.srHex).state).to.equal(FforState.CLOSED);

		// Drop ff_close: R has sent it, S is still ACTIVE.
		const w2 = createWorld();
		activate(w2);
		exposeAndLeave(w2, [1]);
		w2.sr.reconnect();
		w2.sr.drop = (_from, type): boolean => type === MessageType.FF_CLOSE;
		expect(w2.r.closeFforEpoch(w2.srHex).ok).to.equal(true);
		expect(record(w2.s, w2.srHex).state).to.equal(FforState.ACTIVE);
		expect(record(w2.r, w2.srHex).closeSent).to.equal(true);
		w2.sr.drop = null;
		w2.sr.disconnect();
		w2.sr.log.length = 0;
		w2.sr.reconnect();
		const types2 = w2.sr.log.map((e) => e.type);
		expect(types2.filter((t) => t === MessageType.FF_CLOSE).length).to.equal(1);
		expect(
			types2.filter((t) => t === MessageType.FF_CLOSE_ACK).length
		).to.equal(1);
		expect(record(w2.r, w2.srHex).state).to.equal(FforState.CLOSED);
		expect(record(w2.s, w2.srHex).state).to.equal(FforState.CLOSED);
	});

	it('a preimage from a payer credits a slot the ack marked unsettled (section 7.5.6)', () => {
		const w = createWorld();
		activate(w);
		const [inv1] = exposeAndLeave(w, [1]);
		const payment = pay(w, inv1);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		// A withholding S: forget the settlement before R returns.
		const rec = record(w.s, w.srHex);
		rec.slotStates[0] = FforSlotState.UNUSED;
		rec.slotUpstream[0] = null;
		w.sr.reconnect();
		// R learned t_1 from the payer's receipt.
		const credited = w.r.fforAddPreimage(w.srHex, payment.preimage!);
		expect(credited.ok, credited.error).to.equal(true);
		const rBefore = w.r
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState().localBalanceMsat;
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		const ackEntry = w.sr.log.find((e) => e.type === MessageType.FF_CLOSE_ACK)!;
		const ack = decodeFforCloseAckMessage(ackEntry.payload);
		expect(bitmapGet(ack.settled, 1)).to.be.false;
		// R never fails a slot it holds a preimage for: slot 1 was fulfilled.
		expect(record(w.r, w.srHex).state).to.equal(FforState.CLOSED);
		const rAfter = w.r
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState();
		expect(rAfter.localBalanceMsat).to.equal(rBefore + AMOUNTS[0]);
		const fulfils = w.sr.log.filter(
			(e) => e.type === MessageType.UPDATE_FULFILL_HTLC
		);
		expect(fulfils.length).to.equal(1);
	});
});

// ─────────────── Review round 1 ───────────────

/** S with real SQLite persistence whose channel write can be made to fail. */
function worldWithStorage(): IWorld & { storage: SqliteStorage } {
	const storage = new SqliteStorage(':memory:');
	storage.open();
	const w = createWorld({ sStorage: storage });
	return { ...w, storage };
}

/** Make S's channel write fail whenever `when(state)` holds. */
function failSaveWhen(
	storage: SqliteStorage,
	when: (state: IChannelState) => boolean
): () => number {
	const orig = storage.saveChannel.bind(storage);
	let failures = 0;
	storage.saveChannel = (
		id: string,
		state: IChannelState,
		peer: string
	): void => {
		if (when(state)) {
			failures++;
			throw new Error('disk full');
		}
		orig(id, state, peer);
	};
	return () => failures;
}

describe('FFOR Variant D: review round 1 (settlement)', function () {
	this.timeout(60_000);

	it('a failed durable write at activation withholds the ack', () => {
		const w = worldWithStorage();
		let count = (): number => 0;
		// Arm the fault as ff_activate crosses, so only the ACTIVE write fails.
		w.sr.drop = (_from, type): boolean => {
			if (type === MessageType.FF_ACTIVATE) {
				count = failSaveWhen(
					w.storage,
					(st) => st.ffor?.state === FforState.ACTIVE
				);
			}
			return false;
		};
		const res = w.r.startFforEpoch(w.srHex, {
			voucherAmountsMsat: AMOUNTS,
			minPaymentMsat: 400_000n,
			settlementDeadline: D_DEADLINE,
			voucherExpiry: T_EXP,
			feeBaseMsat: FEE_BASE,
			feeProportionalMillionths: FEE_PPM
		});
		expect(res.ok).to.equal(true);
		expect(count()).to.be.at.least(1);
		expect(
			w.sr.log.filter((e) => e.type === MessageType.FF_ACTIVATE_ACK)
		).to.deep.equal([]);
		expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVATING);
		expect(w.errors.s.some((e) => /disk full|persist/i.test(e))).to.be.true;
		// Nothing left S after the failed write.
		const activateIdx = w.sr.log.findIndex(
			(e) => e.type === MessageType.FF_ACTIVATE
		);
		expect(
			w.sr.log.slice(activateIdx + 1).filter((e) => e.from === w.s.getNodeId())
		).to.deep.equal([]);
	});

	it('a failed durable SETTLING write reveals no preimage and sends nothing', () => {
		const w = worldWithStorage();
		activate(w);
		const [inv] = exposeAndLeave(w, [1]);
		const count = failSaveWhen(w.storage, (st) =>
			(st.ffor?.slotStates ?? []).includes(FforSlotState.SETTLING)
		);
		const before = w.ps.log.length;
		const decoded = decodeInvoice(inv);
		w.p.sendPayment(inv);
		expect(count()).to.be.at.least(1);
		const payment = w.p.getPayment(decoded.paymentHash)!;
		expect(payment.status).to.equal(PaymentStatus.PENDING);
		expect(payment.preimage).to.be.undefined;
		const fromS = w.ps.log
			.slice(before)
			.filter((e) => e.from === w.s.getNodeId())
			.map((e) => e.type);
		expect(fromS).to.not.include(MessageType.UPDATE_FULFILL_HTLC);
		expect(fromS).to.not.include(MessageType.UPDATE_FAIL_HTLC);
		// Memory follows disk: the slot is not SETTLING anywhere.
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
		expect(record(w.s, w.srHex).slotUpstream[0]).to.equal(null);
		expect(w.storage.loadChannel(w.srHex)!.state.ffor!.slotStates[0]).to.equal(
			FforSlotState.UNUSED
		);
	});

	it('a failed durable DRAINING write withholds ff_close_ack and every preimage', () => {
		const w = worldWithStorage();
		activate(w);
		const [inv] = exposeAndLeave(w, [1]);
		expect(pay(w, inv).status).to.equal(PaymentStatus.COMPLETED);
		w.sr.reconnect();
		const count = failSaveWhen(
			w.storage,
			(st) => st.ffor?.state === FforState.DRAINING
		);
		w.sr.log.length = 0;
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		expect(count()).to.be.at.least(1);
		expect(
			w.sr.log.filter((e) => e.type === MessageType.FF_CLOSE_ACK)
		).to.deep.equal([]);
		expect(w.sr.log.filter((e) => e.from === w.s.getNodeId())).to.deep.equal(
			[]
		);
		expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
		expect(record(w.r, w.srHex).knownPreimages).to.deep.equal([
			null,
			null,
			null
		]);
		expect(w.storage.loadChannel(w.srHex)!.state.ffor!.state).to.equal(
			FforState.ACTIVE
		);
	});

	it('invoice creation and settlement fail closed at D and on an unknown tip', () => {
		const w = createWorld();
		activate(w);
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 1)).to.not.throw();
		w.r.handleNewBlock(D_DEADLINE);
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 2)).to.throw(
			'at or past settlement_deadline'
		);
		(w.r as unknown as { currentBlockHeight: number }).currentBlockHeight = 0;
		expect(() => w.r.createFforVoucherInvoice(w.srHex, 2)).to.throw(
			'tip height unknown'
		);

		const w2 = createWorld();
		activate(w2);
		const [inv] = exposeAndLeave(w2, [1]);
		const failures: { reason: string }[] = [];
		w2.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		(w2.s as unknown as { currentBlockHeight: number }).currentBlockHeight = 0;
		w2.s.getChannelManager().handleNewBlock(0);
		const late = pay(w2, inv);
		expect(late.status).to.equal(PaymentStatus.FAILED);
		expect(failures.pop()!.reason).to.include('tip height unknown');
		expect(record(w2.s, w2.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
	});
});

// ─────────────── Public S-R fee across an S restart (issue #899) ───────────────

/**
 * Run the real announcement_signatures exchange for S's channel to R at
 * SCID 500x`txIndex`x0, so S assembles, verifies and publishes the signed
 * channel_announcement itself. Returns the SCID.
 */
function exchangeAnnouncement(
	w: IWorld,
	channelId: Buffer,
	txIndex: number
): Buffer {
	for (const n of [w.s, w.r]) {
		const st = n.getChannelManager().getChannel(channelId)!.getFullState();
		st.announcementSigsSent = false;
		st.announcementSigsReceived = false;
	}
	const scid = encodeShortChannelId({ block: 500, txIndex, outputIndex: 0 });
	w.s.getChannelManager().emit('announcement:needs-signing', channelId, scid);
	expect(w.s.getGraph().getChannel(scid)?.announcementVerified).to.equal(true);
	return scid;
}

/**
 * S publishes its S-R channel for real, R exposes vouchers 1 and 2 and
 * leaves, and P learns S's policy for the edge it will route over: the
 * epoch channel at S's default 1000 msat + 1 ppm or, with `parallel`, a
 * second S-R channel at 0 + 0 with the epoch edge disabled.
 */
function publishAndExpose(
	w: IWorld,
	parallel = false
): { invs: string[]; scid: Buffer; fee: (d: bigint) => bigint } {
	const second = parallel ? openReadyChannel(w.s, w.r) : null;
	if (second) {
		w.s.setChannelPolicy(second, {
			feeBaseMsat: 0,
			feeProportionalMillionths: 0
		});
	}
	const epochScid = exchangeAnnouncement(w, w.srChannelId, 2);
	const scid = second ? exchangeAnnouncement(w, second, 3) : epochScid;
	activate(w);
	const invs = exposeAndLeave(w, [1, 2]);
	publishChannel(w.p, w.s, w.r, w.srChannelId, epochScid, 1000, 1);
	if (second) {
		disableChannel(w.p, w.s, w.r, epochScid);
		publishChannel(w.p, w.s, w.r, second, scid, 0, 0);
	}
	return { invs, scid, fee: (d) => (second ? 0n : feeS(d, 1000, 1)) };
}

/**
 * Restart S from its SQLite store. R stays offline and no gossip reaches the
 * new instance; only the upstream link to P comes back.
 */
function restartS(w: IWorld): void {
	w.ps.connected = false;
	w.p.getChannelManager().handlePeerDisconnected(w.s.getNodeId());
	const s = new LightningNode(w.sConfig);
	s.on('node:error', (e: { message: string }) => w.errors.s.push(e.message));
	s.handleNewBlock(TIP);
	w.s = s;
	w.sr = new NodeLink(s, w.r);
	w.sr.connected = false;
	w.ps = new NodeLink(w.p, s);
	w.ps.reconnect();
}

/**
 * Rewrite S's stored row for `scid` the way lazy intake leaves one, with
 * its provenance unsettled: as published, with one signature broken, or
 * with the two funding keys validly re-signed in each other's positions.
 */
function storeDeferred(
	w: IWorld & { storage: SqliteStorage },
	scid: Buffer,
	variant: 'valid' | 'tampered' | 'swapped'
): void {
	const row = w.storage
		.loadAllGossipChannels()
		.find((c) => c.shortChannelId.equals(scid))!;
	let ann = row.announcement;
	if (variant === 'tampered') {
		const sig = Buffer.from(ann.bitcoinSignature2);
		sig[40] ^= 1;
		ann = { ...ann, bitcoinSignature2: sig };
	} else if (variant === 'swapped') {
		ann = {
			...ann,
			bitcoinKey1: ann.bitcoinKey2,
			bitcoinKey2: ann.bitcoinKey1
		};
		const privkeys = new Map<string, Buffer>();
		for (const c of [w.sConfig, w.rConfig]) {
			for (const k of [c.nodePrivateKey, c.fundingPrivkey]) {
				privkeys.set(getPublicKey(k).toString('hex'), k);
			}
		}
		const priv = (pub: Buffer): Buffer => privkeys.get(pub.toString('hex'))!;
		const payload = encodeChannelAnnouncementMessage(ann);
		const one = signChannelAnnouncement(
			payload,
			priv(ann.nodeId1),
			priv(ann.bitcoinKey1)
		);
		const two = signChannelAnnouncement(
			payload,
			priv(ann.nodeId2),
			priv(ann.bitcoinKey2)
		);
		ann = {
			...ann,
			nodeSignature1: one.nodeSignature,
			bitcoinSignature1: one.bitcoinSignature,
			nodeSignature2: two.nodeSignature,
			bitcoinSignature2: two.bitcoinSignature
		};
	}
	w.storage.saveGossipChannel(scid.toString('hex'), {
		...row,
		announcement: ann,
		announcementVerified: undefined,
		announcementVerifyDeferred: true
	});
}

describe('FFOR Variant D: public S-R fee across an S restart (issue #899)', function () {
	this.timeout(60_000);

	for (const parallel of [false, true]) {
		const edge = parallel ? 'a parallel S-R channel' : 'the epoch channel';
		it(`settles at the public policy of ${edge} before and after S restarts with R offline`, () => {
			const w = worldWithStorage();
			const { invs, scid, fee } = publishAndExpose(w, parallel);
			const first = pay(w, invs[0]);
			expect(first.status, JSON.stringify(w.errors.s)).to.equal(
				PaymentStatus.COMPLETED
			);
			expect(first.route!.totalFeeMsat).to.equal(fee(AMOUNTS[0]));

			restartS(w);
			const failures: { reason: string }[] = [];
			w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
				failures.push(e)
			);
			const second = pay(w, invs[1]);
			expect(failures).to.deep.equal([]);
			expect(second.status).to.equal(PaymentStatus.COMPLETED);
			const hops = second.route!.hops;
			expect(hops[hops.length - 1].shortChannelId.equals(scid)).to.be.true;
			expect(second.route!.totalFeeMsat).to.equal(fee(AMOUNTS[1]));
			expect(fee(AMOUNTS[1]) < feeS(AMOUNTS[1], FEE_BASE, FEE_PPM)).to.be.true;
			expect(record(w.s, w.srHex).slotStates.slice(0, 2)).to.deep.equal([
				FforSlotState.SETTLED,
				FforSlotState.SETTLED
			]);
		});
	}

	it('verifies a restored deferred S-R announcement at settlement and holds an invalid or mismatched one to the book terms', () => {
		for (const variant of ['valid', 'tampered', 'swapped'] as const) {
			const w = worldWithStorage();
			const { invs, scid, fee } = publishAndExpose(w);
			storeDeferred(w, scid, variant);
			restartS(w);
			const row = w.s.getGraph().getChannel(scid)!;
			expect(row.announcementVerifyDeferred).to.equal(true);
			const failures: { reason: string }[] = [];
			w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
				failures.push(e)
			);
			const payment = pay(w, invs[0]);
			// Settlement resolved the row: the swapped keys are validly signed,
			// so only the position binding refuses them.
			expect(row.announcementVerified, variant).to.equal(
				variant !== 'tampered'
			);
			if (variant === 'valid') {
				expect(failures).to.deep.equal([]);
				expect(payment.status).to.equal(PaymentStatus.COMPLETED);
				expect(payment.route!.totalFeeMsat).to.equal(fee(AMOUNTS[0]));
				continue;
			}
			expect(payment.status, variant).to.equal(PaymentStatus.FAILED);
			expect(payment.failureCode).to.equal(FEE_INSUFFICIENT);
			expect(failures.pop()!.reason).to.equal('fee_insufficient');
			expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
		}
	});

	it('rebuilds a published row missing from storage when S restarts with R offline', () => {
		// 'never saved' is a channel announced before announcement:ready
		// saved its row, as on the restart that upgrades to this version.
		for (const missing of ['failed save', 'never saved'] as const) {
			const w = worldWithStorage();
			const save = w.storage.saveGossipChannel.bind(w.storage);
			if (missing === 'failed save') {
				w.storage.saveGossipChannel = (): void => {
					throw new Error('disk full');
				};
			}
			const { invs, scid, fee } = publishAndExpose(w);
			w.storage.saveGossipChannel = save;
			if (missing === 'failed save') {
				expect(w.errors.s).to.include('saveGossipChannel: disk full');
			}
			// The verified row in memory still counts for this session.
			expect(pay(w, invs[0]).status).to.equal(PaymentStatus.COMPLETED);
			w.storage.deleteGossipChannel(scid.toString('hex'));

			restartS(w);
			expect(w.s.getGraph().getChannel(scid)?.announcementVerified).to.equal(
				true
			);
			const stored = w.storage.loadAllGossipChannels();
			expect(stored.some((c) => c.shortChannelId.equals(scid))).to.be.true;
			const payment = pay(w, invs[1]);
			expect(payment.status, missing).to.equal(PaymentStatus.COMPLETED);
			expect(payment.route!.totalFeeMsat).to.equal(fee(AMOUNTS[1]));
		}
	});

	it('holds a row rebuilt with a bad counterparty signature to the book terms', () => {
		const w = worldWithStorage();
		const { invs, scid } = publishAndExpose(w);
		w.storage.deleteGossipChannel(scid.toString('hex'));
		const id = w.srChannelId.toString('hex');
		const { state, peerPubkey } = w.storage.loadChannel(id)!;
		const sig = Buffer.from(state.remoteAnnouncementBitcoinSig!);
		sig[40] ^= 1;
		w.storage.saveChannel(
			id,
			{ ...state, remoteAnnouncementBitcoinSig: sig },
			peerPubkey
		);

		restartS(w);
		expect(w.s.getGraph().getChannel(scid)?.announcementVerified).to.equal(
			false
		);
		const stored = w.storage.loadAllGossipChannels();
		expect(stored.some((c) => c.shortChannelId.equals(scid))).to.be.false;
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		const payment = pay(w, invs[0]);
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.failureCode).to.equal(FEE_INSUFFICIENT);
		expect(failures.pop()!.reason).to.equal('fee_insufficient');
		expect(record(w.s, w.srHex).slotStates[0]).to.equal(FforSlotState.UNUSED);
	});
});
