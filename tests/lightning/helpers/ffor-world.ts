/**
 * The FFOR test world: a payer P, a settlement peer S and a receiver R on
 * in-process loopback links, with the helpers every FFOR suite needs to run
 * an epoch end to end (setup to ACTIVE, expose invoices and go offline, pay,
 * force-close and observe). Lifted from ffor-variant-d-settlement.test.ts
 * (#718) so the M8 and M9 suites share one harness; the settlement suite
 * keeps its own copy, byte for byte, as the reference.
 *
 * Nothing here touches a chain: funding is a random outpoint and chain
 * events are fed by hand. The regtest suite under interop/ builds the same
 * world on a real funding output (see `createWorld`'s `funding` option).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../../src/lightning/node/lightning-node';
import { INodeConfig, IPaymentInfo } from '../../../src/lightning/node/types';
import { Network } from '../../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	REGTEST_CHAIN_HASH,
	IChannelConfig
} from '../../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../../src/lightning/keys/derivation';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { decode as decodeInvoice } from '../../../src/lightning/invoice/decode';
import { encodeShortChannelId } from '../../../src/lightning/gossip/types';
import { SqliteStorage } from '../../../src/lightning/storage/sqlite-storage';
import { ChannelActionType } from '../../../src/lightning/channel/channel-actions';
import { ChannelManager } from '../../../src/lightning/channel/channel-manager';
import { CommitmentType } from '../../../src/lightning/chain/types';
import { FforState, IFforEpochRecord } from '../../../src/lightning/ffor/types';

export const REGTEST = bitcoin.networks.regtest;

export function sha(...parts: (Buffer | string)[]): Buffer {
	const h = crypto.createHash('sha256');
	for (const p of parts) h.update(p);
	return h.digest();
}

export function makeBasepoints(seed: Buffer): IChannelBasepoints {
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

export function makeNodeConfig(
	seedId: number,
	storage?: SqliteStorage,
	extra: Partial<INodeConfig> = {},
	channelConfig: Partial<IChannelConfig> = {}
): INodeConfig {
	const seed = sha(`ffor-world-node-${seedId}`);
	return {
		...(storage ? { storage } : {}),
		nodePrivateKey: sha(seed, 'node-identity'),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG, ...channelConfig },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: sha(seed, 'per-commitment'),
		fundingPrivkey: sha(seed, Buffer.from([0])),
		// The secrets behind makeBasepoints' keys 1 to 3, so the chain
		// monitors can sign justice, to_remote and to_local sweeps (the
		// regtest gates confirm them on bitcoind).
		revocationBasepointSecret: sha(seed, Buffer.from([1])),
		paymentBasepointSecret: sha(seed, Buffer.from([2])),
		delayedPaymentBasepointSecret: sha(seed, Buffer.from([3])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		...extra
	};
}

/** The P2WPKH script a node's funding key can spend: a sweep destination. */
export function destScriptFor(privkey: Buffer): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: getPublicKey(privkey),
		network: REGTEST
	}).output!;
}

export interface IWireEntry {
	from: string;
	type: number;
	payload: Buffer;
}

/** A loopback link between two nodes with a wire log and a FIFO reconnect. */
export class NodeLink {
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

/** A real funding outpoint for `openReadyChannel` (internal byte order). */
export interface IFundingOutpoint {
	txid: Buffer;
	outputIndex: number;
}

/** Open a channel from `opener` to `acceptor` and pin it published. */
export function openReadyChannel(
	opener: LightningNode,
	acceptor: LightningNode,
	fundingSatoshis = 1_000_000n,
	funding?: IFundingOutpoint,
	pushMsat = 0n
): Buffer {
	const channel = opener.openChannel(
		acceptor.getNodeId(),
		fundingSatoshis,
		pushMsat
	);
	const channelId = opener.createFunding(
		channel,
		funding?.txid ?? crypto.randomBytes(32),
		funding?.outputIndex ?? 0,
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
export function publishChannel(
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

export const TIP = 790_000;
export const T_EXP = 800_000;
export const D_DEADLINE = 798_992;
export const AMOUNTS = [1_000_000n, 546_250n, 2_000_000n];
export const FEE_BASE = 1000;
export const FEE_PPM = 5000;

export interface IWorld {
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

export interface IWorldOptions {
	sStorage?: SqliteStorage;
	rStorage?: SqliteStorage;
	/** Per-node config on top of the defaults. */
	pExtra?: Partial<INodeConfig>;
	sExtra?: Partial<INodeConfig>;
	rExtra?: Partial<INodeConfig>;
	/** Per-node channel config (a long to_self_delay, a feerate). */
	sChannel?: Partial<IChannelConfig>;
	rChannel?: Partial<IChannelConfig>;
	/** Real funding outpoints; absent means random (in-process only). */
	funding?: { ps?: IFundingOutpoint; sr?: IFundingOutpoint };
	/** The tip every node starts at. */
	tip?: number;
	srCapacitySats?: bigint;
	/** Balance S pushes to R at open, so R has a to_remote. */
	srPushMsat?: bigint;
	/**
	 * Fix the node seeds (P = base + 1, S = base + 2, R = base + 3) so a
	 * caller can build the configs first with `worldConfigs`, fund a real
	 * S-R output for their keys, and only then create the world.
	 */
	seedBase?: number;
}

/** The three node configs a world with this seed base will use. */
export function worldConfigs(
	seedBase: number,
	opts: IWorldOptions = {}
): { pConfig: INodeConfig; sConfig: INodeConfig; rConfig: INodeConfig } {
	return {
		pConfig: makeNodeConfig(seedBase + 1, undefined, opts.pExtra),
		sConfig: makeNodeConfig(
			seedBase + 2,
			opts.sStorage,
			opts.sExtra,
			opts.sChannel
		),
		rConfig: makeNodeConfig(
			seedBase + 3,
			opts.rStorage,
			opts.rExtra,
			opts.rChannel
		)
	};
}

export function createWorld(opts: IWorldOptions = {}): IWorld {
	worldSeed = opts.seedBase ?? worldSeed + 10;
	const { pConfig, sConfig, rConfig } = worldConfigs(worldSeed, opts);
	const p = new LightningNode(pConfig);
	const s = new LightningNode(sConfig);
	const r = new LightningNode(rConfig);
	const errors = { p: [] as string[], s: [] as string[], r: [] as string[] };
	p.on('node:error', (e: { message: string }) => errors.p.push(e.message));
	s.on('node:error', (e: { message: string }) => errors.s.push(e.message));
	r.on('node:error', (e: { message: string }) => errors.r.push(e.message));
	const ps = new NodeLink(p, s);
	const sr = new NodeLink(s, r);
	const psChannelId = openReadyChannel(p, s, 1_000_000n, opts.funding?.ps);
	const srChannelId = openReadyChannel(
		s,
		r,
		opts.srCapacitySats ?? 1_000_000n,
		opts.funding?.sr,
		opts.srPushMsat ?? 0n
	);
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
	const tip = opts.tip ?? TIP;
	for (const n of [p, s, r]) n.handleNewBlock(tip);
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

export function record(node: LightningNode, srHex: string): IFforEpochRecord {
	const f = node.getFforEpoch(srHex);
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

export interface IEpochRequest {
	amounts?: bigint[];
	settlementDeadline?: number;
	voucherExpiry?: number;
	witnessPeers?: Buffer[];
	hashChain?: boolean;
	minPaymentMsat?: bigint;
}

/** R sets up the epoch to ACTIVE on the S-R channel. */
export function activate(w: IWorld, req: IEpochRequest = {}): void {
	const res = w.r.startFforEpoch(w.srHex, {
		voucherAmountsMsat: req.amounts ?? AMOUNTS,
		minPaymentMsat: req.minPaymentMsat ?? 400_000n,
		settlementDeadline: req.settlementDeadline ?? D_DEADLINE,
		voucherExpiry: req.voucherExpiry ?? T_EXP,
		feeBaseMsat: FEE_BASE,
		feeProportionalMillionths: FEE_PPM,
		...(req.witnessPeers ? { witnessPeers: req.witnessPeers } : {}),
		...(req.hashChain ? { hashChain: true } : {})
	});
	expect(res.ok, res.error).to.equal(true);
	expect(record(w.s, w.srHex).state, JSON.stringify(w.errors)).to.equal(
		FforState.ACTIVE
	);
	expect(record(w.r, w.srHex).state).to.equal(FforState.ACTIVE);
}

/** R exposes voucher k's invoice, then goes offline. */
export function exposeAndLeave(w: IWorld, ks: number[]): string[] {
	const invoices = ks.map(
		(k) => w.r.createFforVoucherInvoice(w.srHex, k).bolt11
	);
	w.sr.disconnect();
	return invoices;
}

/** P pays; returns P's payment record for the hash. */
export function pay(w: IWorld, bolt11: string): IPaymentInfo {
	const decoded = decodeInvoice(bolt11);
	w.p.sendPayment(bolt11);
	const payment = w.p.getPayment(decoded.paymentHash);
	expect(payment, 'payer payment record').to.exist;
	return payment!;
}

export type TrackedOutputs = ReturnType<
	NonNullable<ReturnType<ChannelManager['getMonitor']>>['getTrackedOutputs']
>;

/**
 * Force-close `closer`'s S-R channel and report the commitment to
 * `observer`'s chain monitor at `height`. Returns the observer's view.
 */
export function forceCloseAndObserve(
	w: IWorld,
	closer: LightningNode,
	closerKey: Buffer,
	observer: LightningNode,
	observerKey: Buffer,
	height = TIP + 1,
	feeRatePerVbyte = 1
): {
	tx: bitcoin.Transaction;
	outputs: TrackedOutputs;
	commitmentType: CommitmentType | undefined;
} {
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
			height,
			observerDest,
			feeRatePerVbyte,
			undefined,
			undefined,
			REGTEST
		);
	// Release CSV-1 (anchor) sweeps: the claim is held until the block after
	// the commitment's confirmation.
	observer.getChannelManager().handleNewBlock(height + 2);
	const monitor = observer.getChannelManager().getMonitor(w.srChannelId);
	expect(monitor, 'observer monitor').to.exist;
	return {
		tx,
		outputs: monitor!.getTrackedOutputs(),
		commitmentType: monitor!.getFullState().commitmentBroadcast?.commitmentType
	};
}
