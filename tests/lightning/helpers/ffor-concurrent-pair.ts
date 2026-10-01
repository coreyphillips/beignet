/**
 * The loopback pair for the FFOR concurrent receive suites: two
 * ChannelManagers, S and R, peer ids = node ids, every message on a wire
 * log. A copy of the harness in ffor-variant-d-setup.test.ts (which keeps
 * its own, as the baseline reference), with what the concurrent suites
 * need on top:
 *
 *  - the feature seam: no transport runs here, so nothing records an init
 *    exchange. Each side's advertised features are an object the other
 *    side's manager reads through setFforPeerFeatureSource, and a test may
 *    change them between connections;
 *  - a `concurrent` option, which advertises option_ff_concurrent on both
 *    sides and lets S answer the profile;
 *  - either side as the funder, with a pushed balance;
 *  - a per-direction hold on the link, so messages can cross;
 *  - a restart that swaps the restored manager into the pair and the link;
 *  - ordinary payments, and an independent check that both commitments on
 *    both sides still carry every unresolved voucher.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../../src/lightning/channel/channel-manager';
import { Channel } from '../../../src/lightning/channel/channel';
import {
	buildLocalCommitment,
	buildRemoteCommitment
} from '../../../src/lightning/channel/commitment-builder';
import {
	ChannelResult,
	ChannelState,
	DEFAULT_CHANNEL_CONFIG,
	HtlcDirection,
	HtlcState,
	IChannelConfig
} from '../../../src/lightning/channel/types';
import { MessageType } from '../../../src/lightning/message/types';
import {
	IChannelBasepoints,
	perCommitmentPointFromSecret
} from '../../../src/lightning/keys/derivation';
import {
	generateFromSeed,
	MAX_INDEX
} from '../../../src/lightning/keys/shachain';
import { getPublicKey } from '../../../src/lightning/crypto/ecdh';
import { Feature, FeatureFlags } from '../../../src/lightning/features/flags';
import {
	deserializeChannelState,
	serializeChannelState
} from '../../../src/lightning/storage/serialization';
import {
	FforSlotState,
	FforState,
	IFforEpochRecord,
	IFforSettlePolicy
} from '../../../src/lightning/ffor/types';

export type Side = 'S' | 'R';

export function sha(...parts: (Buffer | string)[]): Buffer {
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

export type PairConfig = IChannelManagerConfig & {
	nodePrivateKey: Buffer;
	localFeatures: FeatureFlags;
};

/** The features a side advertises in init: FFOR, and the extension if asked. */
export function advertisedFeatures(concurrent: boolean): FeatureFlags {
	const flags = FeatureFlags.empty();
	flags.setOptional(Feature.QUIESCE);
	flags.setOptional(Feature.OPTION_FF_RECEIVE);
	if (concurrent) flags.setOptional(Feature.OPTION_FF_CONCURRENT);
	return flags;
}

function makeConfig(
	seedId: number,
	concurrent: boolean,
	localConfig: Partial<IChannelConfig>
): PairConfig {
	const seed = sha(`ffor-concurrent-seed-${seedId}`);
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, ...localConfig },
		localBasepoints: makeBasepoints(seed),
		localPerCommitmentSeed: sha(seed, 'per-commitment'),
		localFundingPrivkey: sha(seed, Buffer.from([0])),
		htlcBasepointSecret: sha(seed, Buffer.from([4])),
		nodePrivateKey: sha(seed, 'node-key'),
		// Section 5: anchor commitments.
		preferAnchors: true,
		// What this side advertises: its own half of the negotiation, and what
		// the peer's manager reads as our init (the feature seam).
		localFeatures: advertisedFeatures(concurrent)
	};
}

export interface IWireEntry {
	from: Side;
	type: number;
	payload: Buffer;
}

/**
 * A loopback link with a wire log, a drop filter, a connect switch and a
 * per-direction hold. A held direction is a FIFO pipe: the message that
 * tripped the hold and everything its sender sends after it wait, in
 * order, until `release`.
 */
export class Link {
	readonly log: IWireEntry[] = [];
	connected = true;
	/** Return true to drop the message (it never arrives). */
	drop: ((from: Side, type: number, payload: Buffer) => boolean) | null = null;
	readonly dropped: IWireEntry[] = [];
	/** Start holding a direction at the first message this matches. */
	holdAt: ((from: Side, type: number, payload: Buffer) => boolean) | null =
		null;
	private readonly held: Record<Side, IWireEntry[] | null> = {
		S: null,
		R: null
	};
	/** While set, deliveries queue FIFO (a real socket pair's ordering). */
	private queue: IWireEntry[] | null = null;
	private managers: Record<Side, ChannelManager>;
	private readonly listeners: Record<
		Side,
		(peer: string, type: number, payload: Buffer) => void
	>;

	constructor(
		s: ChannelManager,
		readonly sPub: string,
		r: ChannelManager,
		readonly rPub: string
	) {
		this.managers = { S: s, R: r };
		this.listeners = {
			S: (peer, type, payload): void => {
				if (peer === rPub) this.deliver({ from: 'S', type, payload });
			},
			R: (peer, type, payload): void => {
				if (peer === sPub) this.deliver({ from: 'R', type, payload });
			}
		};
		s.on('message:outbound', this.listeners.S);
		r.on('message:outbound', this.listeners.R);
	}

	/** Swap a restarted manager in for one side. */
	replace(side: Side, fresh: ChannelManager): void {
		this.managers[side].removeListener(
			'message:outbound',
			this.listeners[side]
		);
		this.managers[side] = fresh;
		fresh.on('message:outbound', this.listeners[side]);
	}

	private deliver(m: IWireEntry): void {
		if (!this.connected || this.drop?.(m.from, m.type, m.payload)) {
			this.dropped.push(m);
			return;
		}
		if (
			this.held[m.from] === null &&
			this.holdAt?.(m.from, m.type, m.payload)
		) {
			this.held[m.from] = [];
		}
		const held = this.held[m.from];
		if (held) {
			held.push(m);
			return;
		}
		if (this.queue) {
			this.queue.push(m);
			return;
		}
		this.direct(m);
	}

	private direct(m: IWireEntry): void {
		this.log.push(m);
		if (m.from === 'S') {
			this.managers.R.handleMessage(this.sPub, m.type, m.payload);
		} else {
			this.managers.S.handleMessage(this.rPub, m.type, m.payload);
		}
	}

	types(): number[] {
		return this.log.map((e) => e.type);
	}

	/** Message types one side has sent that are still in flight. */
	inFlight(from: Side): number[] {
		return (this.held[from] ?? []).map((m) => m.type);
	}

	/**
	 * Deliver what one side has in flight, in order: the next `count`
	 * messages, or everything, after which the direction is no longer held.
	 */
	release(from: Side, count = Infinity): void {
		const queue = this.held[from];
		if (!queue) return;
		for (let n = 0; n < count && queue.length > 0; n++) {
			this.direct(queue.shift()!);
		}
		if (count === Infinity) this.held[from] = null;
	}

	/** Disconnect both sides. Whatever is in flight is lost. */
	disconnect(): void {
		this.connected = false;
		this.held.S = null;
		this.held.R = null;
		this.managers.S.handlePeerDisconnected(this.rPub);
		this.managers.R.handlePeerDisconnected(this.sPub);
	}

	/**
	 * Reconnect the way a socket pair delivers: both channel_reestablish
	 * messages cross first, and everything each side sends in response is
	 * delivered in FIFO order behind them.
	 */
	reconnect(): void {
		this.connected = true;
		this.queue = [];
		this.managers.S.handlePeerReconnected(this.rPub);
		this.managers.R.handlePeerReconnected(this.sPub);
		while (this.queue.length > 0) {
			this.direct(this.queue.shift()!);
		}
		this.queue = null;
	}
}

export interface IPair {
	link: Link;
	sManager: ChannelManager;
	rManager: ChannelManager;
	sPub: string;
	rPub: string;
	sChannel: Channel;
	rChannel: Channel;
	channelId: Buffer;
	sConfig: PairConfig;
	rConfig: PairConfig;
	sErrors: string[];
	rErrors: string[];
	/** S's settle policy, reapplied when S restarts. */
	sPolicy: IFforSettlePolicy | null;
	/** Who funded the channel. */
	funder: Side;
	/** HTLC events each manager reported, for the suites that read them. */
	events: Record<
		Side,
		{ forwarded: bigint[]; fulfilled: bigint[]; failed: bigint[] }
	>;
}

export const FUNDING_SATOSHIS = 1_000_000n;
export const T_EXP = 800_000;
export const D_DEADLINE = 798_992;
export const TIP = 795_000;
export const AMOUNTS = [994_000n, 546_250n, 49_749_000n];
export const ONION = Buffer.alloc(1366);

export interface IPairOptions {
	/**
	 * Advertise option_ff_concurrent on both sides and let S answer the
	 * profile. Default true; false is the baseline pair.
	 */
	concurrent?: boolean;
	/** Override one side's advertisement (default: `concurrent`). */
	sAdvertises?: boolean;
	rAdvertises?: boolean;
	/** S's settle policy; default answers, allowing concurrent if advertised. */
	sPolicy?: IFforSettlePolicy | null;
	/** Who opens and funds the channel (default S). */
	funder?: Side;
	/** What the funder pushes to the other side at open, in sats. */
	pushSat?: bigint;
	fundingSat?: bigint;
	height?: number;
	sLocalConfig?: Partial<IChannelConfig>;
	rLocalConfig?: Partial<IChannelConfig>;
}

let pairSeed = 0;

function watch(pair: IPair, side: Side, mgr: ChannelManager): void {
	const errors = side === 'S' ? pair.sErrors : pair.rErrors;
	mgr.on('error', (_id: Buffer | null, msg: string) => errors.push(msg));
	const seen = pair.events[side];
	mgr.on('htlc:forwarded', (_c: Buffer, id: bigint) => seen.forwarded.push(id));
	mgr.on('htlc:fulfilled', (_c: Buffer, id: bigint) => seen.fulfilled.push(id));
	mgr.on('htlc:failed', (_c: Buffer, id: bigint) => seen.failed.push(id));
}

/** Point each manager at what the other side advertises (the seam). */
function wireFeatures(pair: IPair): void {
	pair.sManager.setFforPeerFeatureSource((peer) =>
		peer === pair.rPub ? pair.rConfig.localFeatures : null
	);
	pair.rManager.setFforPeerFeatureSource((peer) =>
		peer === pair.sPub ? pair.sConfig.localFeatures : null
	);
	pair.sManager.setFforSettlePolicy(pair.sPolicy);
}

/** A funded anchor channel between S and R, both at the same tip. */
export function createPair(opts: IPairOptions = {}): IPair {
	pairSeed += 10;
	const concurrent = opts.concurrent ?? true;
	const sAdvertises = opts.sAdvertises ?? concurrent;
	const rAdvertises = opts.rAdvertises ?? concurrent;
	const sConfig = makeConfig(
		900 + pairSeed,
		sAdvertises,
		opts.sLocalConfig ?? {}
	);
	const rConfig = makeConfig(
		901 + pairSeed,
		rAdvertises,
		opts.rLocalConfig ?? {}
	);
	const sPub = getPublicKey(sConfig.nodePrivateKey).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey).toString('hex');
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	const link = new Link(sManager, sPub, rManager, rPub);
	const funder = opts.funder ?? 'S';
	const fundingSat = opts.fundingSat ?? FUNDING_SATOSHIS;
	const pushMsat = (opts.pushSat ?? 0n) * 1000n;

	let sChannel: Channel;
	let rChannel: Channel;
	let channelId: Buffer;
	if (funder === 'R') {
		rChannel = rManager.openChannel(sPub, fundingSat, pushMsat);
		rManager.createFunding(
			rChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);
		channelId = rChannel.getChannelId()!;
		sChannel = sManager.getChannelsByPeer(rPub)[0];
	} else {
		sChannel = sManager.openChannel(rPub, fundingSat, pushMsat);
		sManager.createFunding(
			sChannel,
			crypto.randomBytes(32),
			0,
			crypto.randomBytes(64)
		);
		channelId = sChannel.getChannelId()!;
		rChannel = rManager.getChannelsByPeer(sPub)[0];
	}
	sManager.handleFundingConfirmed(channelId);
	rManager.handleFundingConfirmed(channelId);
	expect(sChannel.getState()).to.equal(ChannelState.NORMAL);
	expect(rChannel.getState()).to.equal(ChannelState.NORMAL);
	const height = opts.height ?? TIP;
	sManager.handleNewBlock(height);
	rManager.handleNewBlock(height);
	link.log.length = 0;
	const pair: IPair = {
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
		sErrors: [],
		rErrors: [],
		sPolicy:
			opts.sPolicy !== undefined
				? opts.sPolicy
				: { enabled: true, allowConcurrent: sAdvertises },
		funder,
		events: {
			S: { forwarded: [], fulfilled: [], failed: [] },
			R: { forwarded: [], fulfilled: [], failed: [] }
		}
	};
	watch(pair, 'S', sManager);
	watch(pair, 'R', rManager);
	wireFeatures(pair);
	return pair;
}

export interface ITerms {
	voucherAmountsMsat: bigint[];
	minPaymentMsat: bigint;
	settlementDeadline: number;
	voucherExpiry: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	epochId?: Buffer;
	hashChain?: boolean;
	concurrent?: boolean;
}

export function terms(
	amounts: bigint[] = AMOUNTS,
	extra: Partial<ITerms> = {}
): ITerms {
	return {
		voucherAmountsMsat: amounts,
		minPaymentMsat: 400_000n,
		settlementDeadline: D_DEADLINE,
		voucherExpiry: T_EXP,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		...extra
	};
}

export function manager(pair: IPair, side: Side): ChannelManager {
	return side === 'S' ? pair.sManager : pair.rManager;
}

export function channel(pair: IPair, side: Side): Channel {
	return side === 'S' ? pair.sChannel : pair.rChannel;
}

export function other(side: Side): Side {
	return side === 'S' ? 'R' : 'S';
}

export function record(ch: Channel): IFforEpochRecord {
	const f = ch.getFforEpoch();
	expect(f, 'epoch record').to.not.equal(null);
	return f!;
}

/** Voucher HTLC entries on one side, as [key, state]. */
export function vouchers(ch: Channel): Array<[string, HtlcState]> {
	const out: Array<[string, HtlcState]> = [];
	for (const [key, e] of ch.getFullState().htlcs) {
		if (e.fforVoucher === true) out.push([key, e.state]);
	}
	return out;
}

/** Everything a failing assertion needs to be read. */
export function why(pair: IPair): string {
	return JSON.stringify({
		sErrors: pair.sErrors,
		rErrors: pair.rErrors,
		wire: pair.link.log.map((e) => `${e.from}:${e.type}`),
		inFlight: { S: pair.link.inFlight('S'), R: pair.link.inFlight('R') }
	});
}

/**
 * Run setup to ACTIVE. `concurrent` asks for the profile (default: whether
 * R advertises the extension).
 */
export function activate(
	pair: IPair,
	amounts: bigint[] = AMOUNTS,
	concurrent?: boolean
): void {
	const ask =
		concurrent ??
		pair.rConfig.localFeatures.hasFeature(Feature.OPTION_FF_CONCURRENT);
	const res = pair.rManager.initiateFforEpoch(
		pair.channelId,
		terms(amounts, ask ? { concurrent: true } : {})
	);
	expect(res.ok, res.error).to.equal(true);
	expect(record(pair.sChannel).state, why(pair)).to.equal(FforState.ACTIVE);
	expect(record(pair.rChannel).state, why(pair)).to.equal(FforState.ACTIVE);
	expect(record(pair.sChannel).concurrentVersion ?? 0, why(pair)).to.equal(
		ask ? 1 : 0
	);
	expect(record(pair.rChannel).concurrentVersion ?? 0, why(pair)).to.equal(
		ask ? 1 : 0
	);
}

/** One side's channel row as storage would hold it right now. */
export function snapshot(pair: IPair, side: Side): string {
	return JSON.stringify(
		serializeChannelState(channel(pair, side).getFullState())
	);
}

/**
 * Restart one side: serialize its channel, restore it into a fresh manager,
 * and swap that into the pair and the link. The connection is down
 * afterwards (the caller reconnects), as after a real process restart.
 * `row` restores an earlier snapshot instead: a backup that predates what
 * happened since.
 */
export function restart(pair: IPair, side: Side, row?: string): void {
	if (pair.link.connected) pair.link.disconnect();
	const config = side === 'S' ? pair.sConfig : pair.rConfig;
	const peer = side === 'S' ? pair.rPub : pair.sPub;
	const state = deserializeChannelState(
		JSON.parse(row ?? snapshot(pair, side))
	);
	const fresh = new ChannelManager(config);
	const restored = new Channel(state);
	fresh.restoreChannel(restored, peer);
	fresh.handleNewBlock(TIP);
	pair.link.replace(side, fresh);
	if (side === 'S') {
		pair.sManager = fresh;
		pair.sChannel = restored;
	} else {
		pair.rManager = fresh;
		pair.rChannel = restored;
	}
	watch(pair, side, fresh);
	wireFeatures(pair);
}

/** One side offers an ordinary HTLC; returns its id and preimage. */
export function offer(
	pair: IPair,
	from: Side,
	amountMsat: bigint,
	cltvExpiry = TIP + 100
): { id: bigint; preimage: Buffer; result: ChannelResult } {
	const preimage = crypto.randomBytes(32);
	const id = channel(pair, from).getFullState().localHtlcCounter;
	const result = manager(pair, from).addHtlc(
		pair.channelId,
		amountMsat,
		sha(preimage),
		cltvExpiry,
		ONION
	);
	return { id, preimage, result };
}

/** An ordinary payment, offered and fulfilled, every round complete. */
export function pay(pair: IPair, from: Side, amountMsat: bigint): bigint {
	const { id, preimage, result } = offer(pair, from, amountMsat);
	expect(result.ok, result.error).to.equal(true);
	const res = manager(pair, other(from)).fulfillHtlc(
		pair.channelId,
		id,
		preimage
	);
	expect(res.ok, res.error).to.equal(true);
	return id;
}

/** Ordinary (non-voucher) HTLC entries on one side. */
export function ordinaryHtlcs(ch: Channel): string[] {
	const out: string[] = [];
	for (const [key, e] of ch.getFullState().htlcs) {
		if (e.fforVoucher !== true) out.push(key);
	}
	return out;
}

/** Both sides' balances, in msat, each from its own book. */
export function balances(pair: IPair): {
	s: bigint;
	r: bigint;
	sViewOfR: bigint;
	rViewOfS: bigint;
} {
	const s = pair.sChannel.getFullState();
	const r = pair.rChannel.getFullState();
	return {
		s: s.localBalanceMsat,
		r: r.localBalanceMsat,
		sViewOfR: s.remoteBalanceMsat,
		rViewOfS: r.remoteBalanceMsat
	};
}

/** Mark slot k settled on S, as a delegated settlement would. */
export function settleSlot(pair: IPair, k: number): void {
	const res = pair.sManager.fforSetSlot(
		pair.channelId,
		k,
		FforSlotState.SETTLED,
		`${'ab'.repeat(32)}:${k}`
	);
	expect(res.ok, res.error).to.equal(true);
}

/**
 * The invariant the suites assert after every round, checked without the
 * engine's own guard: each side's CURRENT local commitment and its view of
 * the peer's current commitment are rebuilt, and every slot in
 * `unresolved` must appear in all four as an untrimmed HTLC output of the
 * voucher's direction, hash, amount and expiry. The two builds of each
 * commitment must also be the same transaction.
 */
export function expectVouchersCarried(
	pair: IPair,
	unresolved: number[],
	label = '',
	agree = true
): void {
	const f = record(pair.rChannel);
	const builds: Array<{
		name: string;
		side: Side;
		txid: string;
		outputs: {
			direction: HtlcDirection;
			paymentHash: Buffer;
			amount: bigint;
			cltvExpiry: number;
		}[];
	}> = [];
	for (const side of ['S', 'R'] as Side[]) {
		const st = channel(pair, side).getFullState();
		const local = buildLocalCommitment(
			st,
			perCommitmentPointFromSecret(
				generateFromSeed(
					st.localPerCommitmentSeed,
					MAX_INDEX - st.localCommitmentNumber
				)
			),
			st.localCommitmentNumber,
			true
		);
		builds.push({
			name: `${side}'s commitment, as ${side} holds it`,
			side,
			txid: local.result.tx.getId(),
			outputs: local.htlcOutputs
		});
		const remote = buildRemoteCommitment(
			st,
			st.remoteCurrentPerCommitmentPoint!,
			st.remoteCommitmentNumber
		);
		builds.push({
			name: `${other(side)}'s commitment, as ${side} signed it`,
			side,
			txid: remote.result.tx.getId(),
			outputs: remote.htlcOutputs
		});
	}
	for (const b of builds) {
		const direction =
			b.side === 'R' ? HtlcDirection.RECEIVED : HtlcDirection.OFFERED;
		for (const k of unresolved) {
			const found = b.outputs.some(
				(o) =>
					o.direction === direction &&
					o.paymentHash.equals(f.paymentHashes[k - 1]) &&
					o.amount === f.params.voucherAmountsMsat[k - 1] / 1000n &&
					o.cltvExpiry === f.params.voucherExpiry
			);
			expect(found, `${label} voucher ${k} in ${b.name}`).to.equal(true);
		}
	}
	// Mid-round the two books legitimately differ by the update in flight.
	if (!agree) return;
	// builds: [S local, R as S signed it, R local, S as R signed it].
	expect(builds[0].txid, `${label} S's commitment, both books`).to.equal(
		builds[3].txid
	);
	expect(builds[2].txid, `${label} R's commitment, both books`).to.equal(
		builds[1].txid
	);
}

/** No wire error, no channel failure, no manager error on either side. */
export function expectHealthy(pair: IPair, label = ''): void {
	expect(pair.sErrors, `${label} S errors ${why(pair)}`).to.deep.equal([]);
	expect(pair.rErrors, `${label} R errors ${why(pair)}`).to.deep.equal([]);
	expect(pair.link.types(), label).to.not.include(MessageType.ERROR);
	expect(pair.sChannel.getState(), label).to.equal(ChannelState.NORMAL);
	expect(pair.rChannel.getState(), label).to.equal(ChannelState.NORMAL);
}
