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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = sha(`ffor-d-node-${seedId}`);
	return {
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
	rConfig: INodeConfig;
	ps: NodeLink;
	sr: NodeLink;
	psChannelId: Buffer;
	srChannelId: Buffer;
	srHex: string;
	errors: { p: string[]; s: string[]; r: string[] };
}

let worldSeed = 0;

function createWorld(): IWorld {
	worldSeed += 10;
	const pConfig = makeNodeConfig(worldSeed + 1);
	const sConfig = makeNodeConfig(worldSeed + 2);
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

		// R returns.
		w.sr.reconnect();
		expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
		w.sr.log.length = 0;
		const closed = w.r.closeFforEpoch(w.srHex);
		expect(closed.ok, closed.error).to.equal(true);

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
