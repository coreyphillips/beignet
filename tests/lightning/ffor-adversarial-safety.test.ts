/**
 * FFOR Variant D: adversarial fund-safety and protocol-safety review of
 * draft PR #718 (specs/ffor-offline-receive.md sections 7, 7.2, 7.5, 7.6, 8,
 * 9.5.1, 9.5.2, 12.1, 13.7.1).
 *
 * Every test encodes an outcome the spec requires against a malicious or
 * faulty S, R, payer or third party. Tests that PASS are candidates that
 * were probed and found conforming; tests that FAIL are findings, each
 * with a comment quoting the spec sentence and the observed behaviour.
 *
 * Two harnesses: a ChannelManager pair (S and R) with a wire log for
 * message-level tampering, and a three-LightningNode world (payer P, S, R)
 * for payer-side probes and force-close views.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { Channel } from '../../src/lightning/channel/channel';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcState,
	REGTEST_CHAIN_HASH
} from '../../src/lightning/channel/types';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	INodeConfig,
	IPaymentInfo,
	PaymentStatus
} from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { decode as decodeInvoice } from '../../src/lightning/invoice/decode';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import { Feature, FeatureFlags } from '../../src/lightning/features/flags';
import { TEMPORARY_NODE_FAILURE } from '../../src/lightning/onion/types';
import {
	OutputStatus,
	OutputType,
	CommitmentType
} from '../../src/lightning/chain/types';
import {
	FF_ABORT_TYPE,
	FF_ACCEPT_TYPE,
	FF_ACTIVATE_ACK_TYPE,
	FF_ACTIVATE_TYPE,
	FF_CLOSE_ACK_TYPE,
	FF_CLOSE_TYPE,
	FF_INIT_TYPE,
	FforAbortReason,
	FforSlotState,
	FforState,
	IFforEpochRecord
} from '../../src/lightning/ffor/types';
import {
	bitmapLength,
	bitmapSet,
	decodeFforAbortMessage,
	decodeFforAcceptMessage,
	encodeFforAbortUnsigned,
	encodeFforAcceptUnsigned,
	encodeFforActivateAckUnsigned,
	encodeFforActivateUnsigned,
	encodeFforCloseAckUnsigned,
	encodeFforCloseUnsigned,
	fforMessageDigest,
	signFforMessage
} from '../../src/lightning/ffor/messages';
import {
	encodeUpdateFailHtlcMessage,
	encodeUpdateFulfillHtlcMessage
} from '../../src/lightning/message/channel-update';
import { encodeTlvStream } from '../../src/lightning/message/tlv';
import {
	decodeCommitmentSignedMessage,
	encodeCommitmentSignedMessage
} from '../../src/lightning/message/channel-commitment';
import { buildVoucherOnion } from '../../src/lightning/ffor/voucher';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';

bitcoin.initEccLib(ecc);
const REGTEST = bitcoin.networks.regtest;

// ─────────────── Shared ───────────────

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

const TIP = 790_000;
const T_EXP = 800_000;
const D_DEADLINE = 798_992;
const FEE_BASE = 1000;
const FEE_PPM = 5000;

function destScriptFor(privkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(privkey),
		network: REGTEST
	}).output!;
}

/** Sign an FFOR body with a raw 64-byte compact signature of our choosing. */
function withSignature(unsigned: Buffer, sig: Buffer): Buffer {
	return Buffer.concat([unsigned, sig]);
}

/** Negate s: the same digest verifies non-strictly but is high-S. */
function highS(sig: Buffer): Buffer {
	const N = BigInt(
		'0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
	);
	const r = sig.subarray(0, 32);
	const s = BigInt('0x' + sig.subarray(32).toString('hex'));
	const flipped = (N - s).toString(16).padStart(64, '0');
	return Buffer.concat([r, Buffer.from(flipped, 'hex')]);
}

// ─────────────── Harness A: ChannelManager pair ───────────────

function makeManagerConfig(
	seedId: number
): IChannelManagerConfig & { nodePrivateKey: Buffer } {
	const seed = sha(`ffor-adv-seed-${seedId}`);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: sha(seed, 'per-commitment'),
		localFundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		nodePrivateKey: sha(seed, 'node-key'),
		preferAnchors: true
	};
}

interface IWireEntry {
	from: 'S' | 'R';
	type: number;
	payload: Buffer;
}

class Link {
	readonly log: IWireEntry[] = [];
	connected = true;
	drop: ((from: 'S' | 'R', type: number, payload: Buffer) => boolean) | null =
		null;
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

	disconnect(): void {
		this.connected = false;
		this.s.handlePeerDisconnected(this.rPub);
		this.r.handlePeerDisconnected(this.sPub);
	}

	reconnect(): void {
		this.connected = true;
		this.queue = [];
		this.s.handlePeerReconnected(this.rPub);
		this.r.handlePeerReconnected(this.sPub);
		while (this.queue.length > 0) this.direct(this.queue.shift()!);
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
	sConfig: ReturnType<typeof makeManagerConfig>;
	rConfig: ReturnType<typeof makeManagerConfig>;
	sErrors: string[];
	rErrors: string[];
}

const FUNDING_SATOSHIS = 1_000_000n;
const AMOUNTS = [994_000n, 546_250n, 49_749_000n];
let pairSeed = 0;

function createPair(): IPair {
	pairSeed += 10;
	const sConfig = makeManagerConfig(700 + pairSeed);
	const rConfig = makeManagerConfig(701 + pairSeed);
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
	sManager.handleNewBlock(TIP);
	rManager.handleNewBlock(TIP);
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
		feeBaseMsat: FEE_BASE,
		feeProportionalMillionths: FEE_PPM
	};
}

function record(ch: Channel): IFforEpochRecord {
	const f = ch.getFforEpoch();
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

function activatePair(pair: IPair): void {
	const res = pair.rManager.initiateFforEpoch(pair.channelId, terms());
	expect(res.ok, res.error).to.equal(true);
	expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
	expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
}

/** R has sent ff_init; S's ff_accept was intercepted, so R is NEGOTIATING with no accept. */
function pairAwaitingAccept(pair: IPair): Buffer {
	let accept: Buffer | null = null;
	pair.link.drop = (from, type, payload): boolean => {
		if (from === 'S' && type === MessageType.FF_ACCEPT) {
			accept = payload;
			return true;
		}
		// S's adds are meaningless to an R without the accept; hold them.
		return from === 'S';
	};
	expect(pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok).to.equal(
		true
	);
	pair.link.drop = null;
	expect(accept, 'intercepted ff_accept').to.not.equal(null);
	expect(record(pair.rChannel).state).to.equal(FforState.NEGOTIATING);
	expect(record(pair.rChannel).acceptWire).to.equal(null);
	return accept!;
}

// ─────────────── Harness B: three LightningNodes ───────────────

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = sha(`ffor-adv-node-${seedId}`);
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

interface INodeWire {
	from: string;
	type: number;
	payload: Buffer;
}

class NodeLink {
	readonly log: INodeWire[] = [];
	connected = true;
	drop: ((from: string, type: number, payload: Buffer) => boolean) | null =
		null;
	private queue: INodeWire[] | null = null;

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

	private direct(m: INodeWire): void {
		this.log.push(m);
		const to = m.from === this.a.getNodeId() ? this.b : this.a;
		to.handlePeerMessage(m.from, m.type, m.payload);
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

function publishChannel(
	viewer: LightningNode,
	x: LightningNode,
	y: LightningNode,
	channelId: Buffer,
	scid: Buffer
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
			feeBaseMsat: 1000,
			feeProportionalMillionths: 1,
			htlcMaximumMsat: 1_000_000_000n
		});
	}
	viewer.registerChannelScid(channelId, scid);
	x.registerChannelScid(channelId, scid);
	y.registerChannelScid(channelId, scid);
}

const NODE_AMOUNTS = [1_000_000n, 546_250n, 2_000_000n];

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

function nodeRecord(node: LightningNode, srHex: string): IFforEpochRecord {
	const f = node.getFforEpoch(srHex);
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

function activateWorld(w: IWorld): void {
	const res = w.r.startFforEpoch(w.srHex, {
		voucherAmountsMsat: NODE_AMOUNTS,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: FEE_BASE,
		feeProportionalMillionths: FEE_PPM
	});
	expect(res.ok, res.error).to.equal(true);
	expect(nodeRecord(w.s, w.srHex).state, JSON.stringify(w.errors)).to.equal(
		FforState.ACTIVE
	);
	expect(nodeRecord(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
}

function exposeAndLeave(w: IWorld, ks: number[]): string[] {
	const invoices = ks.map(
		(k) => w.r.createFforVoucherInvoice(w.srHex, k).bolt11
	);
	w.sr.disconnect();
	return invoices;
}

function pay(w: IWorld, bolt11: string): IPaymentInfo {
	const decoded = decodeInvoice(bolt11);
	w.p.sendPayment(bolt11);
	const payment = w.p.getPayment(decoded.paymentHash);
	expect(payment, 'payer payment record').to.exist;
	return payment!;
}

/** A voucher invoice re-signed by R with altered terms. */
function craftInvoice(
	w: IWorld,
	real: string,
	overrides: {
		amountMsat?: bigint;
		feeBaseMsat?: number;
		feeProportionalMillionths?: number;
		cltvExpiryDelta?: number;
		minFinalCltvExpiry?: number;
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
		minFinalCltvExpiry: overrides.minFinalCltvExpiry ?? 40,
		routingHints: [
			[
				{
					...hint,
					cltvExpiryDelta: overrides.cltvExpiryDelta ?? hint.cltvExpiryDelta,
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

/**
 * Force-close `closer`'s S-R channel and report the commitment to
 * `observer`'s chain monitor. Returns the observer's tracked outputs.
 */
function forceCloseAndObserve(
	w: IWorld,
	closer: LightningNode,
	closerKey: Buffer,
	observer: LightningNode,
	observerKey: Buffer
): {
	tx: bitcoin.Transaction;
	outputs: ReturnType<
		NonNullable<ReturnType<ChannelManager['getMonitor']>>['getTrackedOutputs']
	>;
	commitmentType: CommitmentType | undefined;
} {
	// 1 sat/vB: a direct preimage claim on the peer's commitment pays its fee
	// out of the voucher itself, and a 1000 sat voucher cannot fund one at
	// 10 sat/vB (the resolver declines it as uneconomic and holds it for a
	// fee change, section 8's "collectible only cooperatively" floor).
	const feeRatePerVbyte = 1;
	const closerDest = destScriptFor(closerKey);
	const res = closer
		.getChannelManager()
		.forceClose(w.srChannelId, closerDest, feeRatePerVbyte, REGTEST);
	expect(res.ok, res.error).to.equal(true);
	const broadcast = res.actions.find(
		(a) => a.type === ChannelActionType.BROADCAST_TX
	) as { tx: Buffer } | undefined;
	expect(broadcast, 'commitment broadcast').to.exist;
	const tx = bitcoin.Transaction.fromBuffer(broadcast!.tx);
	const observerDest = destScriptFor(observerKey);
	observer
		.getChannelManager()
		.handleFundingSpent(
			w.srChannelId,
			tx,
			TIP + 1,
			observerDest,
			feeRatePerVbyte,
			undefined,
			undefined,
			REGTEST
		);
	// Release CSV-1 (anchor) sweeps: the claim is held until the block after
	// the commitment's confirmation.
	observer.getChannelManager().handleNewBlock(TIP + 3);
	const monitor = observer.getChannelManager().getMonitor(w.srChannelId);
	expect(monitor, 'observer monitor').to.exist;
	return {
		tx,
		outputs: monitor!.getTrackedOutputs(),
		commitmentType: monitor!.getFullState().commitmentBroadcast?.commitmentType
	};
}

// ═══════════════════════════════════════════════════════════════════════════
// 5 and 6. Fund-safety at the channel level and force-close views
// ═══════════════════════════════════════════════════════════════════════════

describe('FFOR adversarial: force-close views and preimage custody', function () {
	this.timeout(60_000);

	/**
	 * Section 9.5.1 "Force-close, both views": "From R's commitment, a voucher
	 * is a received HTLC: R claims it with t_k through the HTLC-success
	 * transaction S signed at step 4". Section 7.5.4: ff_close_ack carries
	 * "TLV 1: preimages, REQUIRED in Variant D for every set bit". Section
	 * 9.5.3: "R's on-chain claim requires the preimage and nothing else".
	 *
	 * Control first: a preimage R learned from a payer (fforAddPreimage) is
	 * wired to the chain monitors and the voucher is claimed on R's own
	 * commitment. Then the ack path: R learned t_1 from S's signed
	 * ff_close_ack, S vanished before the drain round completed, and R
	 * force-closes.
	 *
	 * OBSERVED (FAILS): the control passes; on the ack path
	 * ChannelManager._knownPreimages lacks H_1, the tracked RECEIVED_HTLC
	 * for voucher 1 has no sweep built and stays CONFIRMED. The ack's
	 * preimages live only in the channel record (Channel.handleFforCloseAck
	 * writes f.knownPreimages; Channel._fforDrain calls Channel.fulfillHtlc
	 * directly, bypassing ChannelManager.fulfillHtlc's recordPreimage), so
	 * no chain monitor ever learns them. After T_exp S takes the voucher
	 * through HTLC-timeout: R loses a slot S was paid for.
	 */
	it('R claims a voucher on-chain with the preimage the ff_close_ack delivered (own commitment view)', () => {
		// Control: the payer-supplied preimage path.
		const c = createWorld();
		activateWorld(c);
		const [cInv] = exposeAndLeave(c, [1]);
		const cPay = pay(c, cInv);
		expect(cPay.status).to.equal(PaymentStatus.COMPLETED);
		c.sr.reconnect();
		expect(c.r.fforAddPreimage(c.srHex, cPay.preimage!).ok).to.equal(true);
		const cH1 = nodeRecord(c.r, c.srHex).paymentHashes[0];
		const control = forceCloseAndObserve(
			c,
			c.r,
			c.rConfig.fundingPrivkey!,
			c.r,
			c.rConfig.fundingPrivkey!
		);
		expect(control.commitmentType).to.equal(CommitmentType.OUR_COMMITMENT);
		const controlOut = control.outputs.find(
			(o) =>
				o.outputType === OutputType.RECEIVED_HTLC &&
				o.paymentHash !== undefined &&
				o.paymentHash.equals(cH1)
		);
		expect(controlOut, 'control: voucher 1 tracked').to.exist;
		expect(
			controlOut!.status,
			'control: HTLC-success for a payer-learned preimage'
		).to.equal(OutputStatus.SPEND_BROADCAST);

		// The ack path.
		const w = createWorld();
		activateWorld(w);
		const [inv1] = exposeAndLeave(w, [1]);
		const payment = pay(w, inv1);
		expect(payment.status).to.equal(PaymentStatus.COMPLETED);
		const t1 = nodeRecord(w.s, w.srHex).preimages[0];
		const h1 = nodeRecord(w.s, w.srHex).paymentHashes[0];
		w.sr.reconnect();
		// S sends ff_close_ack, then falls off the network: nothing R sends
		// afterwards reaches S, so the drain never completes.
		w.sr.drop = (from, type): boolean =>
			from === w.r.getNodeId() && type !== MessageType.FF_CLOSE;
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		const rRec = nodeRecord(w.r, w.srHex);
		expect(rRec.state).to.equal(FforState.DRAINING);
		expect(rRec.knownPreimages[0]!.equals(t1), 'R holds t_1 from the ack').to.be
			.true;
		w.sr.disconnect();
		// R force-closes its own commitment.
		const view = forceCloseAndObserve(
			w,
			w.r,
			w.rConfig.fundingPrivkey!,
			w.r,
			w.rConfig.fundingPrivkey!
		);
		expect(view.commitmentType).to.equal(CommitmentType.OUR_COMMITMENT);
		const voucher1 = view.outputs.find(
			(o) =>
				o.outputType === OutputType.RECEIVED_HTLC &&
				o.paymentHash !== undefined &&
				o.paymentHash.equals(h1)
		);
		expect(voucher1, 'voucher 1 tracked on R commitment').to.exist;
		const known = (
			w.r.getChannelManager() as unknown as {
				_knownPreimages: Map<string, Buffer>;
			}
		)._knownPreimages;
		expect(
			known.has(h1.toString('hex')),
			'ack preimage reached the chain monitors (ChannelManager.recordPreimage)'
		).to.be.true;
		expect(
			voucher1!.status,
			'HTLC-success broadcast for the settled voucher'
		).to.equal(OutputStatus.SPEND_BROADCAST);
	});

	/**
	 * Section 9.5.1 "Force-close, both views": "From S's commitment, a
	 * voucher is an offered HTLC: R claims it directly with t_k and its own
	 * key (no second-stage signature needed)". Same custody question from
	 * the other view: S broadcasts its commitment after sending ff_close_ack.
	 *
	 * OBSERVED (FAILS): same root cause as the own-commitment view; the
	 * monitor does not know t_1, no direct claim is built, the output stays
	 * CONFIRMED until S's HTLC-timeout at T_exp.
	 */
	it('R claims a voucher on-chain with the ack preimage when S force-closes (their commitment view)', () => {
		const w = createWorld();
		activateWorld(w);
		const [inv1] = exposeAndLeave(w, [1]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		const h1 = nodeRecord(w.s, w.srHex).paymentHashes[0];
		w.sr.reconnect();
		w.sr.drop = (from, type): boolean =>
			from === w.r.getNodeId() && type !== MessageType.FF_CLOSE;
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		expect(nodeRecord(w.r, w.srHex).state).to.equal(FforState.DRAINING);
		w.sr.disconnect();
		// S broadcasts its own current commitment; R observes it.
		const view = forceCloseAndObserve(
			w,
			w.s,
			w.sConfig.fundingPrivkey!,
			w.r,
			w.rConfig.fundingPrivkey!
		);
		expect(view.commitmentType).to.equal(
			CommitmentType.THEIR_CURRENT_COMMITMENT
		);
		const voucher1 = view.outputs.find(
			(o) =>
				o.outputType === OutputType.RECEIVED_HTLC &&
				o.paymentHash !== undefined &&
				o.paymentHash.equals(h1)
		);
		expect(voucher1, 'voucher 1 tracked on S commitment').to.exist;
		const known = (
			w.r.getChannelManager() as unknown as {
				_knownPreimages: Map<string, Buffer>;
			}
		)._knownPreimages;
		const observed = {
			monitorKnowsPreimage: known.has(h1.toString('hex')),
			sweepBuilt: voucher1!.sweepTxHex !== undefined,
			status: voucher1!.status
		};
		expect(
			observed,
			'direct preimage claim for the settled voucher'
		).to.deep.equal({
			monitorKnowsPreimage: true,
			sweepBuilt: true,
			status: OutputStatus.SPEND_BROADCAST
		});
	});

	/**
	 * Section 9.5.1 "Force-close, both views": "S takes an unclaimed one after
	 * T_exp through the HTLC-timeout transaction R signed at step 4."
	 * Section 7.5.1: on-chain enforcement is available from ACTIVE. S
	 * force-closes while ACTIVE after settling slot 1: every voucher has an
	 * HTLC-timeout prepared, none is broadcast before T_exp, and nothing is
	 * swept twice.
	 */
	it('S force-closing while ACTIVE prepares one HTLC-timeout per voucher, none before T_exp', () => {
		const w = createWorld();
		activateWorld(w);
		const [inv1] = exposeAndLeave(w, [1]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		const view = forceCloseAndObserve(
			w,
			w.s,
			w.sConfig.fundingPrivkey!,
			w.s,
			w.sConfig.fundingPrivkey!
		);
		expect(view.commitmentType).to.equal(CommitmentType.OUR_COMMITMENT);
		const offered = view.outputs.filter(
			(o) => o.outputType === OutputType.OFFERED_HTLC
		);
		expect(offered.length).to.equal(NODE_AMOUNTS.length);
		const hashes = new Set(offered.map((o) => o.paymentHash!.toString('hex')));
		expect(hashes.size, 'one output per voucher').to.equal(NODE_AMOUNTS.length);
		for (const o of offered) {
			expect(o.sweepTxHex, 'HTLC-timeout prepared').to.not.equal(undefined);
			expect(o.maturityHeight, 'held until T_exp').to.equal(T_EXP);
			expect(o.status).to.not.equal(OutputStatus.SPEND_BROADCAST);
		}
		// The settlement itself is unaffected: S was paid upstream.
		expect(nodeRecord(w.s, w.srHex).slotStates[0]).to.equal(
			FforSlotState.SETTLED
		);
	});
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Signatures and transcript
// ═══════════════════════════════════════════════════════════════════════════

describe('FFOR adversarial: signatures and transcript', function () {
	this.timeout(60_000);

	/**
	 * Section 7: "a node-key signature over SHA256("ffor/msg" || message_type
	 * || body_excluding_the_signature) ... signed directly ... as a 64-byte
	 * compact ECDSA signature with low-S." Section 7.2: "R MUST reject an
	 * ff_accept whose ... TLV 11 is absent or is not the digest of the
	 * ff_init it sent." A signature over the wrong domain, the wrong type,
	 * by the wrong key, or high-S must not be accepted.
	 */
	it('R rejects an ff_accept whose signature is over the wrong domain, type or key, or is high-S', () => {
		const cases: Array<{
			name: string;
			sig: (unsigned: Buffer, sKey: Buffer) => Buffer;
		}> = [
			{
				name: 'no tag (plain sha256 of type||body)',
				sig: (u, k): Buffer =>
					Buffer.from(ecc.sign(sha(Buffer.from([0xd6, 0xdb]), u), k))
			},
			{
				name: 'wrong message type in the digest',
				sig: (u, k): Buffer =>
					Buffer.from(ecc.sign(fforMessageDigest(FF_INIT_TYPE, u), k))
			},
			{
				name: 'wrong key',
				sig: (u): Buffer =>
					Buffer.from(
						ecc.sign(fforMessageDigest(FF_ACCEPT_TYPE, u), sha('not-s'))
					)
			},
			{
				name: 'high-S',
				sig: (u, k): Buffer =>
					highS(Buffer.from(ecc.sign(fforMessageDigest(FF_ACCEPT_TYPE, u), k)))
			}
		];
		for (const c of cases) {
			const pair = createPair();
			const real = pairAwaitingAccept(pair);
			const decoded = decodeFforAcceptMessage(real);
			const unsigned = encodeFforAcceptUnsigned(decoded);
			const forged = withSignature(
				unsigned,
				c.sig(unsigned, pair.sConfig.nodePrivateKey)
			);
			pair.link.log.length = 0;
			pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, forged);
			const f = record(pair.rChannel);
			expect(f.acceptWire, `${c.name}: not adopted`).to.equal(null);
			expect(f.state, `${c.name}: aborted`).to.equal(FforState.ABORTED);
			expect(f.abortReason, `${c.name}: reason 7`).to.equal(
				FforAbortReason.PROTOCOL_ERROR
			);
		}
	});

	/**
	 * Section 7.5.1: "There is no transition out of ACTIVE except to
	 * DRAINING ... a peer that wants out of an active epoch closes it, it
	 * cannot abort it." Section 7.5.4, ff_abort: "Permitted only before
	 * ACTIVE."
	 *
	 * A garbage ff_init naming the LIVE epoch id (an unsigned byte-flip of
	 * the original) reaches S while S is ACTIVE. S must not answer it with
	 * a signed ff_abort for that epoch.
	 *
	 * OBSERVED (FAILS): Channel.handleFforInit's refuse() path runs before
	 * any state check and answers with ff_error plus a node-key-signed
	 * ff_abort (reason 7) carrying the ACTIVE epoch's id and T_init, while
	 * S stays ACTIVE. A peer can thus obtain S's signature over an abort of
	 * an epoch S also signed as activated: two contradictory signed
	 * transitions, which section 7.5.5 calls section 12.2 evidence, here
	 * manufactured against an honest S. Also burns the live epoch id into
	 * fforUsedEpochIds.
	 */
	it('S never signs an ff_abort naming an ACTIVE epoch', () => {
		const pair = createPair();
		activatePair(pair);
		const init = pair.link.log.find((e) => e.type === MessageType.FF_INIT)!;
		const garbage = Buffer.from(init.payload);
		garbage[70] ^= 0x01; // inside the fixed fields, invalidating the signature
		pair.link.log.length = 0;
		pair.sManager.handleMessage(pair.rPub, MessageType.FF_INIT, garbage);
		const aborts = pair.link.log.filter(
			(e) => e.from === 'S' && e.type === MessageType.FF_ABORT
		);
		const epochId = record(pair.sChannel).epochId;
		const forLive = aborts.filter((e) =>
			decodeFforAbortMessage(e.payload).epochId.equals(epochId)
		);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expect(
			forLive.map((e) => decodeFforAbortMessage(e.payload).reason),
			'signed ff_abort messages S sent for the ACTIVE epoch'
		).to.deep.equal([]);
	});

	/**
	 * Section 7.5.4, ff_close is R to S and ff_close_ack is S to R; ff_activate
	 * is R to S, ff_activate_ack S to R. A message from the wrong party must
	 * be refused without effect.
	 */
	it('refuses ff_close from S, ff_close_ack from R, ff_activate from S and ff_activate_ack from R', () => {
		const pair = createPair();
		activatePair(pair);
		const s = record(pair.sChannel);
		const r = record(pair.rChannel);
		const sKey = pair.sConfig.nodePrivateKey;
		const rKey = pair.rConfig.nodePrivateKey;
		const closeFromS = signFforMessage(
			FF_CLOSE_TYPE,
			encodeFforCloseUnsigned({
				channelId: pair.channelId,
				epochId: s.epochId,
				activationHash: s.hAct!
			}),
			sKey
		);
		pair.rManager.handleMessage(pair.sPub, MessageType.FF_CLOSE, closeFromS);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).closeWire).to.equal(null);

		const bitmap = Buffer.alloc(bitmapLength(3));
		const ackFromR = signFforMessage(
			FF_CLOSE_ACK_TYPE,
			encodeFforCloseAckUnsigned({
				channelId: pair.channelId,
				epochId: r.epochId,
				activationHash: r.hAct!,
				numSlots: 3,
				settled: bitmap,
				preimages: []
			}),
			rKey
		);
		pair.sManager.handleMessage(pair.rPub, MessageType.FF_CLOSE_ACK, ackFromR);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);

		const activateFromS = signFforMessage(
			FF_ACTIVATE_TYPE,
			encodeFforActivateUnsigned({
				channelId: pair.channelId,
				epochId: s.epochId,
				setupHash: s.tSetup!,
				bookHash: s.hBook!,
				commitHash: s.hCommit!,
				epochStartHeight: TIP
			}),
			sKey
		);
		pair.rManager.handleMessage(
			pair.sPub,
			MessageType.FF_ACTIVATE,
			activateFromS
		);
		expect(record(pair.rChannel).state).to.equal(FforState.ACTIVE);

		const ackFromRAct = signFforMessage(
			FF_ACTIVATE_ACK_TYPE,
			encodeFforActivateAckUnsigned({
				channelId: pair.channelId,
				epochId: r.epochId,
				activationHash: r.hAct!
			}),
			rKey
		);
		pair.sManager.handleMessage(
			pair.rPub,
			MessageType.FF_ACTIVATE_ACK,
			ackFromRAct
		);
		expect(record(pair.sChannel).state).to.equal(FforState.ACTIVE);
		expect(pair.sChannel.getState()).to.equal(ChannelState.NORMAL);
		expect(pair.rChannel.getState()).to.equal(ChannelState.NORMAL);
	});

	/**
	 * Section 7: "unknown odd TLVs are permitted ... unknown even TLVs are a
	 * decode error, as in BOLT 1". An ff_accept carrying an unknown even TLV
	 * or a truncated TLV stream must not be adopted.
	 */
	it('R does not adopt an ff_accept with an unknown even TLV or a truncated stream', () => {
		for (const variant of ['even', 'truncated'] as const) {
			const pair = createPair();
			const real = pairAwaitingAccept(pair);
			const decoded = decodeFforAcceptMessage(real);
			const unsigned = encodeFforAcceptUnsigned(decoded);
			let body: Buffer;
			if (variant === 'even') {
				// Rebuild the stream with an extra even record after TLV 11.
				const fixedEnd = 64 + 8;
				const stream = unsigned.subarray(fixedEnd);
				const extra = encodeTlvStream([{ type: 12n, value: Buffer.alloc(4) }]);
				const withEven = Buffer.concat([
					unsigned.subarray(0, fixedEnd),
					stream,
					extra
				]);
				body = signFforMessage(
					FF_ACCEPT_TYPE,
					withEven,
					pair.sConfig.nodePrivateKey
				);
			} else {
				const cut = unsigned.subarray(0, unsigned.length - 5);
				body = signFforMessage(
					FF_ACCEPT_TYPE,
					cut,
					pair.sConfig.nodePrivateKey
				);
			}
			pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, body);
			const f = record(pair.rChannel);
			expect(f.acceptWire, `${variant}: not adopted`).to.equal(null);
			expect(f.state, `${variant}: not advanced`).to.not.equal(
				FforState.VOUCHERS_COMMITTED
			);
		}
	});

	/**
	 * Section 7.5.4, ff_abort: "signature | 64 | sender's node-key sig".
	 * Observation probe: does R act on an ff_abort whose signature does not
	 * verify (a message it could never use as section 12.2 evidence)?
	 *
	 * OBSERVED (FAILS): R records an ERROR action but still marks the epoch
	 * ABORTED (Channel.handleFforAbort applies _fforMarkAborted whether or
	 * not the signature or transcript hash verify). The peer is Noise
	 * authenticated, so only S can inject it; the cost is evidentiary (R
	 * unwinds K vouchers on a message it cannot attribute) and the spec text
	 * does not spell out a rejection, so this is reported as low.
	 */
	it('R does not act on an ff_abort whose signature does not verify', () => {
		const pair = createPair();
		pairAwaitingAccept(pair);
		const f = record(pair.rChannel);
		const forged = signFforMessage(
			FF_ABORT_TYPE,
			encodeFforAbortUnsigned({
				channelId: pair.channelId,
				epochId: f.epochId,
				transcriptHash: f.tInit,
				reason: FforAbortReason.OPERATOR,
				data: Buffer.from('forged')
			}),
			sha('someone-else')
		);
		pair.rManager.handleMessage(pair.sPub, MessageType.FF_ABORT, forged);
		// Decision (Channel.handleFforAbort): the peer sent it over the
		// authenticated link, so the setup is treated as abandoned the way a
		// disconnect abandons it (reason 6); the forged message's reason
		// (OPERATOR) is never recorded and nothing of it is kept as evidence.
		const f2 = record(pair.rChannel);
		expect(f2.state).to.equal(FforState.ABORTED);
		expect(f2.abortReason).to.equal(FforAbortReason.DISCONNECT);
	});
});

// ═══════════════════════════════════════════════════════════════════════════
// 1 and 2. Malicious S and malicious R at setup
// ═══════════════════════════════════════════════════════════════════════════

describe('FFOR adversarial: setup against a malicious S or R', function () {
	this.timeout(60_000);

	/**
	 * Section 7.2: "R MUST reject an ff_accept whose TLV 9 is absent or
	 * differs from the one it sent, or whose TLV 11 is absent or is not the
	 * digest of the ff_init it sent." Section 9.5.1 step 2: "s_htlc_id_base
	 * MUST equal S's next offered HTLC id at this moment".
	 */
	it('R rejects ff_accept with one TLV 9 amount altered, a wrong TLV 11, or a wrong n0', () => {
		const tamper: Array<{
			name: string;
			mutate: (m: ReturnType<typeof decodeFforAcceptMessage>) => void;
			reason: FforAbortReason;
		}> = [
			{
				name: 'TLV 9 amount +1',
				mutate: (m): void => {
					m.voucherAmountsMsat = [...m.voucherAmountsMsat];
					m.voucherAmountsMsat[1] += 1n;
				},
				reason: FforAbortReason.BOOK_MISMATCH
			},
			{
				name: 'TLV 11 wrong',
				mutate: (m): void => {
					m.initHash = crypto.randomBytes(32);
				},
				reason: FforAbortReason.PROTOCOL_ERROR
			},
			{
				name: 'n0 off by one',
				mutate: (m): void => {
					m.sCommitmentNumber += 1n;
				},
				reason: FforAbortReason.PROTOCOL_ERROR
			}
		];
		for (const t of tamper) {
			const pair = createPair();
			const real = pairAwaitingAccept(pair);
			const m = decodeFforAcceptMessage(real);
			t.mutate(m);
			const body = signFforMessage(
				FF_ACCEPT_TYPE,
				encodeFforAcceptUnsigned(m),
				pair.sConfig.nodePrivateKey
			);
			pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, body);
			const f = record(pair.rChannel);
			expect(f.state, t.name).to.equal(FforState.ABORTED);
			expect(f.abortReason, t.name).to.equal(t.reason);
		}
	});

	/**
	 * Section 7.5.4: "S MUST recompute T_setup, H_book and H_commit from its
	 * own state and reject the message with ff_abort if any differs", and
	 * "epoch_start_height ... S MUST reject if not within 6 blocks of its
	 * own".
	 */
	it('S aborts an ff_activate with a wrong H_book, H_commit, T_setup or far epoch_start_height', () => {
		const variants: Array<{
			name: string;
			mutate: (m: {
				setupHash: Buffer;
				bookHash: Buffer;
				commitHash: Buffer;
				epochStartHeight: number;
			}) => void;
			reason: FforAbortReason;
		}> = [
			{
				name: 'book',
				mutate: (m) => (m.bookHash = crypto.randomBytes(32)),
				reason: FforAbortReason.BOOK_MISMATCH
			},
			{
				name: 'commit',
				mutate: (m) => (m.commitHash = crypto.randomBytes(32)),
				reason: FforAbortReason.COMMIT_MISMATCH
			},
			{
				name: 'setup',
				mutate: (m) => (m.setupHash = crypto.randomBytes(32)),
				reason: FforAbortReason.BOOK_MISMATCH
			},
			{
				name: 'height',
				mutate: (m) => (m.epochStartHeight = TIP + 7),
				reason: FforAbortReason.PROTOCOL_ERROR
			}
		];
		for (const v of variants) {
			const pair = createPair();
			pair.link.drop = (_from, type): boolean =>
				type === MessageType.FF_ACTIVATE;
			expect(
				pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
			).to.equal(true);
			pair.link.drop = null;
			const s = record(pair.sChannel);
			expect(s.state).to.equal(FforState.VOUCHERS_COMMITTED);
			const fields = {
				setupHash: s.tSetup!,
				bookHash: s.hBook!,
				commitHash: s.hCommit!,
				epochStartHeight: TIP
			};
			v.mutate(fields);
			const body = signFforMessage(
				FF_ACTIVATE_TYPE,
				encodeFforActivateUnsigned({
					channelId: pair.channelId,
					epochId: s.epochId,
					...fields
				}),
				pair.rConfig.nodePrivateKey
			);
			pair.link.log.length = 0;
			pair.sManager.handleMessage(pair.rPub, MessageType.FF_ACTIVATE, body);
			expect(record(pair.sChannel).state, v.name).to.equal(FforState.ABORTED);
			expect(record(pair.sChannel).abortReason, v.name).to.equal(v.reason);
			expect(
				pair.link.types().filter((t) => t === MessageType.FF_ACTIVATE_ACK),
				v.name
			).to.deep.equal([]);
		}
	});

	/**
	 * Section 7.5.4, ff_activate_ack: "R MUST verify activation_hash against
	 * its own H_act". A wrong H_act must not make R ACTIVE.
	 */
	it('R does not go ACTIVE on an ff_activate_ack with a wrong H_act, nor adopt a differing second ack', () => {
		const pair = createPair();
		pair.link.drop = (_from, type): boolean =>
			type === MessageType.FF_ACTIVATE_ACK;
		expect(
			pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok
		).to.equal(true);
		pair.link.drop = null;
		const r = record(pair.rChannel);
		expect(r.state).to.equal(FforState.ACTIVATING);
		const wrong = signFforMessage(
			FF_ACTIVATE_ACK_TYPE,
			encodeFforActivateAckUnsigned({
				channelId: pair.channelId,
				epochId: r.epochId,
				activationHash: crypto.randomBytes(32)
			}),
			pair.sConfig.nodePrivateKey
		);
		pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACTIVATE_ACK, wrong);
		expect(record(pair.rChannel).state).to.not.equal(FforState.ACTIVE);
		expect(record(pair.rChannel).activateAckWire).to.equal(null);

		// A correct ack followed by a differing one: the first stands.
		const pair2 = createPair();
		activatePair(pair2);
		const r2 = record(pair2.rChannel);
		const first = r2.activateAckWire!;
		const other = signFforMessage(
			FF_ACTIVATE_ACK_TYPE,
			Buffer.concat([
				encodeFforActivateAckUnsigned({
					channelId: pair2.channelId,
					epochId: r2.epochId,
					activationHash: r2.hAct!
				}),
				encodeTlvStream([{ type: 99n, value: Buffer.from([1]) }])
			]),
			pair2.sConfig.nodePrivateKey
		);
		pair2.rManager.handleMessage(
			pair2.sPub,
			MessageType.FF_ACTIVATE_ACK,
			other
		);
		expect(record(pair2.rChannel).activateAckWire!.equals(first)).to.be.true;
		expect(record(pair2.rChannel).state).to.equal(FforState.ACTIVE);
	});

	/**
	 * Section 7.2 TLV 7 is a u64 and the book entry carries
	 * `s_htlc_id_k = s_htlc_id_base + k - 1` as a u64. A base near 2^64 makes
	 * the book unencodable; R must refuse it as a protocol error, not throw
	 * out of the handler leaving a half-adopted record.
	 *
	 * OBSERVED (FAILS): buildVoucherBook's writeBigUInt64BE throws a
	 * RangeError out of Channel.handleFforAccept after acceptWire,
	 * sCommitmentNumber, sHtlcIdBase, paymentHashes and tSetup were already
	 * written and before hBook and PERSIST_STATE; ChannelManager.handleMessage
	 * catches it as "Error handling message type 55003". The record is
	 * half-adopted in memory (acceptWire set, hBook null, not persisted) and
	 * the epoch stays NEGOTIATING; it later self-heals by reason 5 or the
	 * setup timeout. Robustness only.
	 */
	it('R handles an ff_accept whose s_htlc_id_base overflows the book encoding', () => {
		const pair = createPair();
		const real = pairAwaitingAccept(pair);
		const m = decodeFforAcceptMessage(real);
		m.sHtlcIdBase = (1n << 64n) - 1n;
		const body = signFforMessage(
			FF_ACCEPT_TYPE,
			encodeFforAcceptUnsigned(m),
			pair.sConfig.nodePrivateKey
		);
		pair.rErrors.length = 0;
		pair.rManager.handleMessage(pair.sPub, MessageType.FF_ACCEPT, body);
		const f = record(pair.rChannel);
		const observed = {
			escapedExceptions: pair.rErrors.filter((e) =>
				/Error handling message/.test(e)
			),
			// Either refused outright (not adopted) or aborted; never half-adopted.
			halfAdopted: f.acceptWire !== null && f.hBook === null,
			state: FforState[f.state]
		};
		expect(observed).to.deep.equal({
			escapedExceptions: [],
			halfAdopted: false,
			state: FforState[FforState.ABORTED]
		});
	});

	/**
	 * Section 7.2 (Variant D): R "MUST re-run the check against
	 * per_commitment_secret_S[n0] when the voucher round's revoke_and_ack
	 * reveals it (section 9.5.1 step 4), aborting with reason 3 on a match".
	 * S generates t_1 = per_commitment_secret_S[n0]; at ff_accept R cannot
	 * know it, after the round it must.
	 */
	it('R aborts (reason 3) when the round reveals that H_1 binds per_commitment_secret_S[n0]', () => {
		const pair = createPair();
		const n0 = pair.rChannel.getFullState().remoteCommitmentNumber;
		expect(n0).to.equal(pair.sChannel.getFullState().localCommitmentNumber);
		const secretN0 = generateFromSeed(
			pair.sConfig.localPerCommitmentSeed,
			MAX_INDEX - n0
		);
		// S's first random 32 bytes inside handleFforInit become t_1.
		const cryptoModule = crypto as unknown as {
			randomBytes: (n: number) => Buffer;
		};
		const orig = cryptoModule.randomBytes;
		let armed = true;
		cryptoModule.randomBytes = (n: number): Buffer => {
			if (armed && n === 32) {
				armed = false;
				return Buffer.from(secretN0);
			}
			return orig(n);
		};
		try {
			const res = pair.rManager.initiateFforEpoch(pair.channelId, {
				...terms(),
				epochId: sha('pinned-epoch-id', String(pairSeed))
			});
			expect(res.ok, res.error).to.equal(true);
		} finally {
			cryptoModule.randomBytes = orig;
		}
		expect(record(pair.sChannel).paymentHashes[0].equals(sha(secretN0))).to.be
			.true;
		const r = record(pair.rChannel);
		expect(r.state).to.equal(FforState.ABORTED);
		expect(r.abortReason).to.equal(FforAbortReason.BOOK_MISMATCH);
		expect(record(pair.sChannel).state).to.equal(FforState.ABORTED);
		expect(pair.rChannel.getFullState().htlcs.size).to.equal(0);
		expect(pair.sChannel.getFullState().htlcs.size).to.equal(0);
	});

	/**
	 * Section 9.5.1 step 3: "R recognises a voucher by (id, amount_msat,
	 * payment_hash, cltv_expiry) matching the book exactly ... Any add in
	 * this window that does not match the book exactly ... is a failed
	 * voucher round"; and "An R that does decode [the onion] MUST find
	 * exactly these values or treat the add as mismatching."
	 */
	it('R aborts (reason 5) on an add whose cltv, hash or onion payload is off', () => {
		type AddFn = Channel['addHtlc'];
		const variants: Array<{
			name: string;
			patch: (
				orig: AddFn,
				pair: IPair,
				...args: Parameters<AddFn>
			) => ReturnType<AddFn>;
		}> = [
			{
				name: 'cltv + 1',
				patch: (orig, _p, amount, hash, cltv, onion) =>
					orig(amount, hash, cltv + 1, onion)
			},
			{
				name: 'different hash',
				patch: (orig, _p, amount, _hash, cltv, onion) =>
					orig(amount, crypto.randomBytes(32), cltv, onion)
			},
			{
				name: 'onion amt_to_forward + 1',
				patch: (orig, p, amount, hash, cltv) =>
					orig(
						amount,
						hash,
						cltv,
						buildVoucherOnion({
							recipientNodeId: Buffer.from(p.rPub, 'hex'),
							epochId: record(p.sChannel).epochId,
							k: 2,
							amountMsat: amount + 1n,
							voucherExpiry: cltv,
							paymentHash: hash
						})
					)
			}
		];
		for (const v of variants) {
			const pair = createPair();
			const orig: AddFn = pair.sChannel.addHtlc.bind(pair.sChannel);
			let call = 0;
			(pair.sChannel as unknown as { addHtlc: AddFn }).addHtlc = (
				...args
			): ReturnType<AddFn> =>
				++call === 2 ? v.patch(orig, pair, ...args) : orig(...args);
			expect(
				pair.rManager.initiateFforEpoch(pair.channelId, terms()).ok,
				v.name
			).to.equal(true);
			const r = record(pair.rChannel);
			expect(r.state, v.name).to.equal(FforState.ABORTED);
			expect(r.abortReason, v.name).to.equal(
				FforAbortReason.VOUCHER_ROUND_FAILED
			);
			expect(pair.rChannel.getFullState().htlcs.size, v.name).to.equal(0);
			expect(pair.sChannel.getFullState().localBalanceMsat, v.name).to.equal(
				FUNDING_SATOSHIS * 1000n
			);
			expect(
				pair.link.types().filter((t) => t === MessageType.STFU),
				v.name
			).to.deep.equal([]);
		}
	});

	/**
	 * Section 9.5.1 step 4: S's commitment_signed "htlc_signature list is the
	 * pre-signed HTLC-success material R needs for every voucher". BOLT 2:
	 * a commitment_signed with the wrong number of htlc signatures fails the
	 * channel. R must not treat a round missing a signature as committed.
	 */
	it('R rejects a commitment_signed that omits one voucher htlc_signature', () => {
		const pair = createPair();
		let tampered = false;
		pair.link.drop = (from, type, payload): boolean => {
			if (from !== 'S' || type !== MessageType.COMMITMENT_SIGNED || tampered)
				return false;
			tampered = true;
			const msg = decodeCommitmentSignedMessage(payload);
			msg.htlcSignatures = msg.htlcSignatures.slice(0, -1);
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.COMMITMENT_SIGNED,
				encodeCommitmentSignedMessage(msg)
			);
			return true;
		};
		pair.rManager.initiateFforEpoch(pair.channelId, terms());
		pair.link.drop = null;
		expect(tampered).to.be.true;
		expect(record(pair.rChannel).state).to.not.equal(
			FforState.VOUCHERS_COMMITTED
		);
		expect(record(pair.rChannel).state).to.not.equal(FforState.ACTIVE);
		expect(pair.rChannel.getState()).to.equal(ChannelState.ERRORED);
	});

	/**
	 * Section 9.5.1 step 6 and 7.5.4: ff_activate follows the completed round
	 * under quiescence. An ff_activate reaching an S whose round is not
	 * irrevocably committed must be aborted, and S must not go ACTIVE.
	 * Also: an ff_close reaching an S that is not ACTIVE has no effect.
	 */
	it('S refuses ff_activate before its round is committed and ff_close outside ACTIVE', () => {
		const pair = createPair();
		// Hold R's revoke_and_ack: S's adds are signed but never revoked for,
		// so the round is incomplete on S's side.
		pair.link.drop = (from, type): boolean =>
			from === 'R' && type === MessageType.REVOKE_AND_ACK;
		pair.rManager.initiateFforEpoch(pair.channelId, terms());
		pair.link.drop = null;
		const s = record(pair.sChannel);
		expect(s.state).to.equal(FforState.NEGOTIATING);
		const early = signFforMessage(
			FF_ACTIVATE_TYPE,
			encodeFforActivateUnsigned({
				channelId: pair.channelId,
				epochId: s.epochId,
				setupHash: s.tSetup!,
				bookHash: s.hBook!,
				commitHash: crypto.randomBytes(32),
				epochStartHeight: TIP
			}),
			pair.rConfig.nodePrivateKey
		);
		pair.link.log.length = 0;
		pair.sManager.handleMessage(pair.rPub, MessageType.FF_ACTIVATE, early);
		expect(record(pair.sChannel).state).to.not.equal(FforState.ACTIVE);
		expect(
			pair.link.types().filter((t) => t === MessageType.FF_ACTIVATE_ACK)
		).to.deep.equal([]);

		const pair2 = createPair();
		pair2.link.drop = (_from, type): boolean =>
			type === MessageType.FF_ACTIVATE;
		pair2.rManager.initiateFforEpoch(pair2.channelId, terms());
		pair2.link.drop = null;
		const s2 = record(pair2.sChannel);
		expect(s2.state).to.equal(FforState.VOUCHERS_COMMITTED);
		const close = signFforMessage(
			FF_CLOSE_TYPE,
			encodeFforCloseUnsigned({
				channelId: pair2.channelId,
				epochId: s2.epochId,
				activationHash: crypto.randomBytes(32)
			}),
			pair2.rConfig.nodePrivateKey
		);
		pair2.link.log.length = 0;
		pair2.sManager.handleMessage(pair2.rPub, MessageType.FF_CLOSE, close);
		expect(record(pair2.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
		expect(record(pair2.sChannel).closeWire).to.equal(null);
		expect(
			pair2.link.types().filter((t) => t === MessageType.FF_CLOSE_ACK)
		).to.deep.equal([]);
	});

	/**
	 * Section 9.5.1 step 6: activation runs under quiescence over the
	 * committed book. A malicious R that removes a voucher (update_fail_htlc,
	 * itself a BOLT 2 violation under quiescence) and then activates must not
	 * get an ACTIVE S with a K-1 book: H_commit no longer matches.
	 */
	it('S does not go ACTIVE after R fails a voucher under quiescence before ff_activate', () => {
		const pair = createPair();
		let activate: Buffer | null = null;
		pair.link.drop = (from, type, payload): boolean => {
			if (from === 'R' && type === MessageType.FF_ACTIVATE) {
				activate = payload;
				return true;
			}
			return false;
		};
		pair.rManager.initiateFforEpoch(pair.channelId, terms());
		pair.link.drop = null;
		expect(activate).to.not.equal(null);
		expect(record(pair.sChannel).state).to.equal(FforState.VOUCHERS_COMMITTED);
		expect(pair.sChannel.isQuiescent()).to.be.true;
		const id = record(pair.sChannel).sHtlcIdBase!;
		pair.sManager.handleMessage(
			pair.rPub,
			MessageType.UPDATE_FAIL_HTLC,
			encodeUpdateFailHtlcMessage({
				channelId: pair.channelId,
				id,
				reason: Buffer.alloc(292)
			})
		);
		pair.link.log.length = 0;
		pair.sManager.handleMessage(pair.rPub, MessageType.FF_ACTIVATE, activate!);
		expect(record(pair.sChannel).state).to.not.equal(FforState.ACTIVE);
		expect(
			pair.link.types().filter((t) => t === MessageType.FF_ACTIVATE_ACK)
		).to.deep.equal([]);
	});

	/**
	 * Section 7.5.6 draining: "R MUST NOT fail a slot the ack marks settled."
	 * Section 7.5.5 DRAINING traffic: "only update_fulfill_htlc /
	 * update_fail_htlc for the vouchers". Observation probe of S's side: does
	 * S accept an update_fail_htlc for a slot its own bitmap marks settled?
	 * (Only R loses by it; recorded as an observation.)
	 */
	it('S accepts a drain fail on a slot it marked settled (R hurts only itself)', () => {
		const w = createWorld();
		activateWorld(w);
		const [inv1] = exposeAndLeave(w, [1]);
		expect(pay(w, inv1).status).to.equal(PaymentStatus.COMPLETED);
		w.sr.reconnect();
		// Hold R's drain so S stays DRAINING with slot 1 settled.
		w.sr.drop = (from, type): boolean =>
			from === w.r.getNodeId() && type !== MessageType.FF_CLOSE;
		expect(w.r.closeFforEpoch(w.srHex).ok).to.equal(true);
		expect(nodeRecord(w.s, w.srHex).state).to.equal(FforState.DRAINING);
		expect(nodeRecord(w.s, w.srHex).slotStates[0]).to.equal(
			FforSlotState.SETTLED
		);
		w.sr.drop = null;
		const sBefore = w.s
			.getChannelManager()
			.getChannel(w.srChannelId)!
			.getFullState().localBalanceMsat;
		const id = nodeRecord(w.s, w.srHex).sHtlcIdBase!;
		w.s.handlePeerMessage(
			w.r.getNodeId(),
			MessageType.UPDATE_FAIL_HTLC,
			encodeUpdateFailHtlcMessage({
				channelId: w.srChannelId,
				id,
				reason: Buffer.alloc(292)
			})
		);
		const sCh = w.s.getChannelManager().getChannel(w.srChannelId)!;
		expect(sCh.getState()).to.equal(ChannelState.NORMAL);
		const entry = sCh.getFullState().htlcs.get(`offered-${id}`);
		// Observation: S accepted the fail (entry FAILED); this refunds S the
		// voucher it was paid for upstream. R's loss, S's gain.
		expect(entry?.state).to.equal(HtlcState.FAILED);
		expect(sCh.getFullState().localBalanceMsat).to.equal(sBefore);
	});

	/**
	 * Section 7.5.5 ACTIVE: "No update_*, commitment_signed, ... from either
	 * side". A malicious R fulfilling or failing a VOUCHER id while ACTIVE is
	 * a freeze violation on S's side.
	 */
	it('S refuses a voucher fulfil or fail from R while ACTIVE', () => {
		for (const kind of ['fulfil', 'fail'] as const) {
			const pair = createPair();
			activatePair(pair);
			const id = record(pair.sChannel).sHtlcIdBase!;
			const payload =
				kind === 'fulfil'
					? encodeUpdateFulfillHtlcMessage({
							channelId: pair.channelId,
							id,
							paymentPreimage: record(pair.sChannel).preimages[0]
					  })
					: encodeUpdateFailHtlcMessage({
							channelId: pair.channelId,
							id,
							reason: Buffer.alloc(292)
					  });
			pair.sManager.handleMessage(
				pair.rPub,
				kind === 'fulfil'
					? MessageType.UPDATE_FULFILL_HTLC
					: MessageType.UPDATE_FAIL_HTLC,
				payload
			);
			expect(pair.sChannel.getState(), kind).to.equal(ChannelState.ERRORED);
			const entry = pair.sChannel.getFullState().htlcs.get(`offered-${id}`);
			expect(entry?.state, kind).to.equal(HtlcState.COMMITTED);
		}
	});

	/**
	 * Section 7.5.4 ff_close_ack: "A bit S sets without the preimage (Variant
	 * D) is a protocol error." A preimage that does not hash to H_k, or a
	 * num_slots that is not K, must not be adopted either.
	 */
	it('R refuses an ff_close_ack with a set bit lacking its preimage, a bad preimage, or wrong num_slots', () => {
		const build = (
			pair: IPair,
			opts: { bit: boolean; preimage: Buffer | null; numSlots: number }
		): Buffer => {
			const r = record(pair.rChannel);
			const bitmap = Buffer.alloc(bitmapLength(opts.numSlots));
			if (opts.bit) bitmapSet(bitmap, 1);
			return signFforMessage(
				FF_CLOSE_ACK_TYPE,
				encodeFforCloseAckUnsigned({
					channelId: pair.channelId,
					epochId: r.epochId,
					activationHash: r.hAct!,
					numSlots: opts.numSlots,
					settled: bitmap,
					preimages: opts.preimage ? [{ k: 1, preimage: opts.preimage }] : []
				}),
				pair.sConfig.nodePrivateKey
			);
		};
		const cases: Array<{
			name: string;
			opts: { bit: boolean; preimage: Buffer | null; numSlots: number };
		}> = [
			{
				name: 'bit without preimage',
				opts: { bit: true, preimage: null, numSlots: 3 }
			},
			{
				name: 'bad preimage',
				opts: { bit: true, preimage: crypto.randomBytes(32), numSlots: 3 }
			},
			{ name: 'num_slots 2', opts: { bit: false, preimage: null, numSlots: 2 } }
		];
		for (const c of cases) {
			const pair = createPair();
			activatePair(pair);
			pair.link.drop = (_from, type): boolean => type === MessageType.FF_CLOSE;
			expect(pair.rManager.closeFforEpoch(pair.channelId).ok).to.equal(true);
			pair.link.drop = null;
			pair.rManager.handleMessage(
				pair.sPub,
				MessageType.FF_CLOSE_ACK,
				build(pair, c.opts)
			);
			const r = record(pair.rChannel);
			expect(r.state, c.name).to.equal(FforState.ACTIVE);
			expect(r.closeAckWire, c.name).to.equal(null);
			expect(r.knownPreimages, c.name).to.deep.equal([null, null, null]);
		}
	});
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. Malicious payer / upstream
// ═══════════════════════════════════════════════════════════════════════════

describe('FFOR adversarial: payer-side probes', function () {
	this.timeout(60_000);

	/**
	 * Section 7.5.6: "S MUST NOT begin a delegated settlement once any of
	 * these holds: ... the upstream HTLC's cltv_expiry is within S's safety
	 * delta of the tip (section 8)". Section 8: "Current height < D and <
	 * upstream cltv_expiry - S's safety delta."
	 */
	it('S fails a delegated HTLC whose cltv_expiry is inside its safety delta and reveals nothing', () => {
		const w = createWorld();
		activateWorld(w);
		const [inv] = exposeAndLeave(w, [1]);
		const failures: { reason: string }[] = [];
		w.s.on('ffor:delegated-failed', (e: { reason: string }) =>
			failures.push(e)
		);
		// A hint with a 1-block delta and a 9-block final expiry: the HTLC
		// reaching S expires at tip + 10, inside S's 40-block delta.
		const tight = craftInvoice(w, inv, {
			cltvExpiryDelta: 1,
			minFinalCltvExpiry: 9
		});
		const payment = pay(w, tight);
		expect(payment.status).to.not.equal(PaymentStatus.COMPLETED);
		expect(payment.preimage).to.be.undefined;
		expect(nodeRecord(w.s, w.srHex).slotStates[0]).to.equal(
			FforSlotState.UNUSED
		);
		if (payment.status === PaymentStatus.FAILED) {
			expect(payment.failureCode).to.equal(TEMPORARY_NODE_FAILURE);
			expect(failures.some((f) => /cltv/.test(f.reason))).to.be.true;
		}
	});

	/**
	 * Section 7.6 check 2: "amount_msat - amt_to_forward >= fee_S(d_k)".
	 * One millisatoshi short must fail, and nothing may be revealed.
	 */
	it('S fails a delegated HTLC whose fee is one msat short', () => {
		const w = createWorld();
		activateWorld(w);
		const [inv] = exposeAndLeave(w, [1]);
		// fee_S(d) = 1000 + floor(d * 5000 / 1e6); a hint with base 999 and the
		// same ppm delivers exactly one msat less than fee_S.
		const short = craftInvoice(w, inv, { feeBaseMsat: FEE_BASE - 1 });
		const payment = pay(w, short);
		expect(payment.status).to.equal(PaymentStatus.FAILED);
		expect(payment.preimage).to.be.undefined;
		expect(nodeRecord(w.s, w.srHex).slotStates[0]).to.equal(
			FforSlotState.UNUSED
		);
	});
});
