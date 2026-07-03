/**
 * FFOR M6 shared harness (spec §15): the P - S - R triple with
 * - optional bLIP-51 lease state on the S-R channel (S = lessor),
 * - variant A or B epochs (B wires a loopback tower into S),
 * - continuous persist tracking so any side can be crash+restarted from its
 *   last DURABLE state at any protocol arrow (the crash matrix),
 * - link interceptors to drop/deliver a specific message then crash a side.
 *
 * Not a test file: imported by the M6 suites.
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
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { ChannelActionType } from '../../src/lightning/channel/channel-actions';
import { MessageType } from '../../src/lightning/message/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { FforVariant, IFforEpochParams } from '../../src/lightning/ffor/types';
import {
	FforTower,
	LoopbackTowerClient,
	MemoryTowerStore,
	generateTowerPreimages,
	IFforTowerProvisioning
} from '../../src/lightning/ffor/tower';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

export const sha256 = (b: Buffer): Buffer =>
	crypto.createHash('sha256').update(b).digest();

export const FUNDING_SATOSHIS = 1_000_000n;

// ─────────────── Configs ───────────────

function makeSeed(prefix: string, id: string): Buffer {
	return sha256(Buffer.from(`ffor-m6-${prefix}-${id}`));
}

export function makeConfig(
	prefix: string,
	name: string,
	overrides?: Partial<IChannelManagerConfig>
): IChannelManagerConfig {
	const seed = makeSeed(prefix, name);
	const k = (i: number): Buffer =>
		sha256(Buffer.concat([seed, Buffer.from([i])]));
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(k(0)),
		revocationBasepoint: getPublicKey(k(1)),
		paymentBasepoint: getPublicKey(k(2)),
		delayedPaymentBasepoint: getPublicKey(k(3)),
		htlcBasepoint: getPublicKey(k(4)),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
	return {
		localConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
		localBasepoints: basepoints,
		localPerCommitmentSeed: makeSeed(prefix, name + '-commit'),
		localFundingPrivkey: k(0),
		htlcBasepointSecret: k(4),
		revocationBasepointSecret: k(1),
		paymentBasepointSecret: k(2),
		delayedPaymentBasepointSecret: k(3),
		nodePrivateKey: makeSeed(prefix, name + '-node'),
		preferAnchors: true,
		...overrides
	};
}

// ─────────────── Links with interceptors ───────────────

export type LinkDecision = 'deliver' | 'drop';

export interface ILink {
	down: () => void;
	up: () => void;
	/**
	 * FIFO mode (models real TCP during reestablish): while paused, messages
	 * queue instead of nesting synchronously; resume() delivers them in order.
	 * Without this, a retransmission triggered by OUR reestablish would reach
	 * the peer BEFORE the peer's own reestablish — impossible on a real
	 * connection.
	 */
	pause: () => void;
	resume: () => void;
	/**
	 * Interceptor: called for every message crossing the link (in either
	 * direction) BEFORE delivery. Return 'drop' to swallow the message.
	 * `after` runs AFTER a delivered message has been fully processed
	 * (synchronous loopback): use it to crash a side "after it processed X".
	 */
	intercept?: (fromPub: string, type: number, payload: Buffer) => LinkDecision;
	after?: (fromPub: string, type: number, payload: Buffer) => void;
}

/**
 * Loopback link. Handlers are looked up through the registry so a crashed
 * side can be REPLACED (restarted manager) without rewiring the peer.
 */
interface IQueuedMsg {
	fromPub: string;
	toPub: string;
	type: number;
	payload: Buffer;
}

export function connect(
	registry: Map<string, ChannelManager>,
	aPub: string,
	bPub: string
): ILink {
	let connected = true;
	let paused = false;
	const queue: IQueuedMsg[] = [];
	const dispatch = (m: IQueuedMsg): void => {
		const decision =
			link.intercept?.(m.fromPub, m.type, m.payload) ?? 'deliver';
		if (decision === 'drop') return;
		registry.get(m.toPub)!.handleMessage(m.fromPub, m.type, m.payload);
		link.after?.(m.fromPub, m.type, m.payload);
	};
	const link: ILink = {
		down: (): void => {
			connected = false;
			queue.length = 0;
		},
		up: (): void => {
			connected = true;
		},
		pause: (): void => {
			paused = true;
		},
		resume: (): void => {
			paused = false;
			while (queue.length > 0) {
				dispatch(queue.shift()!);
			}
		}
	};
	const handler =
		(fromPub: string, toPub: string, from: ChannelManager) =>
		(peer: string, type: number, payload: Buffer): void => {
			// The registry may have swapped the manager (restart): only forward
			// events from the CURRENT manager for this pubkey.
			if (registry.get(fromPub) !== from) return;
			if (!connected || peer !== toPub) return;
			if (paused) {
				queue.push({ fromPub, toPub, type, payload });
				return;
			}
			dispatch({ fromPub, toPub, type, payload });
		};
	const forward = (fromPub: string, toPub: string): void => {
		const from = registry.get(fromPub)!;
		from.on('message:outbound', handler(fromPub, toPub, from));
	};
	forward(aPub, bPub);
	forward(bPub, aPub);
	(link as ILink & { _forward: typeof forward })._forward = forward;
	return link;
}

/** Re-arm a link's forwarding for a RESTARTED manager (new event emitter). */
export function rearm(
	registry: Map<string, ChannelManager>,
	link: ILink,
	fromPub: string,
	toPub: string
): void {
	(link as ILink & { _forward: (f: string, t: string) => void })._forward(
		fromPub,
		toPub
	);
}

// ─────────────── Persist tracking (durable-state mirror) ───────────────

/**
 * Mirrors what a real node's storage would hold: the serialized channel state
 * as of the LAST persist event. Seeded explicitly after channel open (a real
 * node persists on funding), then updated on every 'channel:persist'.
 */
export class PersistTracker {
	private latest = new Map<string, string>();

	track(manager: ChannelManager, channels: Channel[]): void {
		for (const ch of channels) {
			this.snapshot(ch);
		}
		manager.on('channel:persist', (cid: Buffer) => {
			const ch = channels.find((c) => c.getChannelId()?.equals(cid));
			if (ch) this.snapshot(ch);
		});
	}

	snapshot(ch: Channel): void {
		const id = ch.getChannelId();
		if (!id) return;
		this.latest.set(
			id.toString('hex'),
			JSON.stringify(serializeChannelState(ch.getFullState()))
		);
	}

	restore(channelId: Buffer): Channel {
		const s = this.latest.get(channelId.toString('hex'));
		if (!s) throw new Error('no persisted state for channel');
		return new Channel(deserializeChannelState(JSON.parse(s)));
	}
}

// ─────────────── The triple ───────────────

export type ParamsInput = Omit<IFforEpochParams, 'rPerCommitmentPoints'> & {
	rPerCommitmentPoints?: Buffer[];
};

export interface ITriple {
	registry: Map<string, ChannelManager>;
	pManager: ChannelManager;
	sManager: ChannelManager;
	rManager: ChannelManager;
	pPub: string;
	sPub: string;
	rPub: string;
	psChannelId: Buffer;
	pChannel: Channel;
	spChannel: Channel;
	srChannelId: Buffer;
	sChannel: Channel;
	rChannel: Channel;
	srLink: ILink;
	psLink: ILink;
	pErrors: string[];
	sErrors: string[];
	rErrors: string[];
	pFulfilled: Array<{ htlcId: bigint; preimage: Buffer }>;
	pFailed: bigint[];
	pConfig: IChannelManagerConfig;
	sConfig: IChannelManagerConfig;
	rConfig: IChannelManagerConfig;
	sTracker: PersistTracker;
	rTracker: PersistTracker;
	hashes: Buffer[];
	/** Variant B only. */
	tower?: FforTower;
	towerPreimages?: Buffer[];
}

export interface ITripleOptions {
	prefix: string;
	variant?: 'A' | 'B';
	/** Apply bLIP-51 lease state on the S-R channel (S = lessor). */
	lease?: { expiry: number };
	params?: Partial<ParamsInput>;
	sConfigOverrides?: Partial<IChannelManagerConfig>;
	/** Open channels but skip epoch initiation. */
	noEpoch?: boolean;
}

let tripleN = 0;

export function baseParamsA(overrides?: Partial<ParamsInput>): ParamsInput {
	return {
		variant: FforVariant.A,
		budgetMsat: 100_000_000n,
		maxPayments: 3,
		minPaymentMsat: 600_000n,
		settlementDeadline: 1000,
		voucherExpiry: 2008,
		feeBaseMsat: 1000,
		feeProportionalMillionths: 5000,
		escapeGranularityMsat: 0n,
		...overrides
	};
}

export function createTriple(opts: ITripleOptions): ITriple {
	tripleN++;
	const prefix = `${opts.prefix}-${tripleN}`;
	const pConfig = makeConfig(prefix, 'P');
	const sConfig = makeConfig(prefix, 'S', opts.sConfigOverrides);
	const rConfig = makeConfig(prefix, 'R');
	const pPub = getPublicKey(pConfig.nodePrivateKey!).toString('hex');
	const sPub = getPublicKey(sConfig.nodePrivateKey!).toString('hex');
	const rPub = getPublicKey(rConfig.nodePrivateKey!).toString('hex');
	const pManager = new ChannelManager(pConfig);
	const sManager = new ChannelManager(sConfig);
	const rManager = new ChannelManager(rConfig);
	const registry = new Map<string, ChannelManager>([
		[pPub, pManager],
		[sPub, sManager],
		[rPub, rManager]
	]);
	const pErrors: string[] = [];
	const sErrors: string[] = [];
	const rErrors: string[] = [];
	pManager.on('error', (_id, m: string) => pErrors.push(m));
	sManager.on('error', (_id, m: string) => sErrors.push(m));
	rManager.on('error', (_id, m: string) => rErrors.push(m));
	const pFulfilled: Array<{ htlcId: bigint; preimage: Buffer }> = [];
	const pFailed: bigint[] = [];
	pManager.on('htlc:fulfilled', (_c, htlcId: bigint, preimage: Buffer) =>
		pFulfilled.push({ htlcId, preimage })
	);
	pManager.on('htlc:failed', (_c, id: bigint) => pFailed.push(id));

	const psLink = connect(registry, pPub, sPub);
	const srLink = connect(registry, sPub, rPub);

	const open = (
		om: ChannelManager,
		am: ChannelManager,
		oPub: string
	): { id: Buffer; opener: Channel; acceptor: Channel } => {
		const opener = om.openChannel(
			oPub === pPub ? sPub : rPub,
			FUNDING_SATOSHIS
		);
		om.createFunding(opener, crypto.randomBytes(32), 0, crypto.randomBytes(64));
		const id = opener.getChannelId()!;
		om.handleFundingConfirmed(id);
		am.handleFundingConfirmed(id);
		const acceptor = am
			.getChannelsByPeer(oPub)
			.find((c) => c.getChannelId()?.equals(id))!;
		expect(opener.getState()).to.equal(ChannelState.NORMAL);
		expect(acceptor.getState()).to.equal(ChannelState.NORMAL);
		return { id, opener, acceptor };
	};
	const ps = open(pManager, sManager, pPub);
	const sr = open(sManager, rManager, sPub);

	// bLIP-51 lease (S = lessor of the S-R channel): apply the state fields
	// the dual-funding lease negotiation commits (isLessor on the lessor,
	// leaseExpiry on both) — see liquidity-ads-negotiation.test.ts for the
	// wire-level negotiation that produces exactly these.
	if (opts.lease) {
		sr.opener.getFullState().isLessor = true;
		sr.opener.getFullState().leaseExpiry = opts.lease.expiry;
		sr.acceptor.getFullState().leaseExpiry = opts.lease.expiry;
	}

	const sTracker = new PersistTracker();
	sTracker.track(sManager, [sr.opener, ps.acceptor]);
	const rTracker = new PersistTracker();
	rTracker.track(rManager, [sr.acceptor]);

	const t: ITriple = {
		registry,
		pManager,
		sManager,
		rManager,
		pPub,
		sPub,
		rPub,
		psChannelId: ps.id,
		pChannel: ps.opener,
		spChannel: ps.acceptor,
		srChannelId: sr.id,
		sChannel: sr.opener,
		rChannel: sr.acceptor,
		srLink,
		psLink,
		pErrors,
		sErrors,
		rErrors,
		pFulfilled,
		pFailed,
		pConfig,
		sConfig,
		rConfig,
		sTracker,
		rTracker,
		hashes: []
	};

	if (!opts.noEpoch) {
		initiateEpoch(t, opts);
	}
	return t;
}

/** Initiate the epoch on the S-R channel (variant A or B). */
export function initiateEpoch(t: ITriple, opts: ITripleOptions): void {
	if (opts.variant === 'B') {
		const K = (opts.params?.maxPayments as number) ?? 3;
		const tower = new FforTower(new MemoryTowerStore());
		const gen = generateTowerPreimages(K);
		const towerNodeKey = makeSeed(opts.prefix, `tower-${tripleN}`);
		const params: ParamsInput = baseParamsA({
			variant: FforVariant.B,
			paymentHashes: gen.paymentHashes,
			towerNodeId: getPublicKey(towerNodeKey),
			towerUri: 'inproc://tower',
			...opts.params
		});
		t.sManager.setFforTowerClient(new LoopbackTowerClient(tower));
		const res = t.rManager.initiateFforEpoch(t.srChannelId, params);
		expect(res.ok, t.rErrors.concat(t.sErrors).join('; ')).to.equal(true);
		const rEpoch = t.rChannel.getFforEpoch()!;
		const provisioning: IFforTowerProvisioning = {
			epochId: rEpoch.epochId,
			params: rEpoch.params,
			preimages: gen.preimages,
			channel: {
				fundingTxid: t.sChannel.getFullState().fundingTxid!,
				fundingOutputIndex: t.sChannel.getFullState().fundingOutputIndex,
				fundingSatoshis: FUNDING_SATOSHIS,
				channelType: t.sChannel.getFullState().channelType!,
				rIsOpener: false,
				rBasepoints: t.rConfig.localBasepoints,
				sBasepoints: t.sConfig.localBasepoints,
				rConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
				sConfig: { ...DEFAULT_CHANNEL_CONFIG, toSelfDelay: 6 },
				preEpochRLocalMsat: 0n,
				preEpochSLocalMsat: FUNDING_SATOSHIS * 1000n,
				nR: t.rChannel.getCommitmentNumbers().local,
				n0: t.sChannel.getCommitmentNumbers().local,
				sPerCommitmentPointN0:
					t.rChannel.getFullState().remoteCurrentPerCommitmentPoint!,
				frozenFeeratePerKw: t.sChannel.getFforEpoch()!.frozenFeeratePerKw
			},
			rNodeId: Buffer.from(t.rPub, 'hex'),
			sNodeId: Buffer.from(t.sPub, 'hex')
		};
		tower.provision(provisioning);
		tower.setBlockHeight(500);
		t.tower = tower;
		t.towerPreimages = gen.preimages;
		t.hashes = gen.paymentHashes;
	} else {
		const params = baseParamsA(opts.params);
		const res = t.rManager.initiateFforEpoch(t.srChannelId, params);
		expect(res.ok, t.rErrors.concat(t.sErrors).join('; ')).to.equal(true);
		t.hashes = t.sChannel.getFforEpoch()!.params.paymentHashes!;
	}
	// Epoch establishment persists (ff_begin, spec §7.5) — mirror it.
	t.sTracker.snapshot(t.sChannel);
	t.rTracker.snapshot(t.rChannel);
}

// ─────────────── Flow helpers ───────────────

export function goOffline(t: ITriple): void {
	t.srLink.down();
	t.sManager.handlePeerDisconnected(t.rPub);
	t.rManager.handlePeerDisconnected(t.sPub);
}

const reestablishPayload = (
	actions: ReturnType<Channel['createReestablish']>
): Buffer =>
	(
		actions.find((a) => a.type === ChannelActionType.SEND_MESSAGE) as {
			payload: Buffer;
		}
	).payload;

/**
 * Reconnect S-R: S's reestablish is delivered to R FIRST (transport FIFO —
 * S queues its reestablish before any replayed packages), then R's to S.
 */
export function reconnectSR(t: ITriple): void {
	t.srLink.up();
	// Real-connection FIFO: both reestablish messages are in flight before any
	// response either side generates while processing them.
	t.srLink.pause();
	const sRe = reestablishPayload(t.sChannel.createReestablish());
	const rRe = reestablishPayload(t.rChannel.createReestablish());
	t.rManager.handleMessage(t.sPub, MessageType.CHANNEL_REESTABLISH, sRe);
	t.sManager.handleMessage(t.rPub, MessageType.CHANNEL_REESTABLISH, rRe);
	t.srLink.resume();
}

/** Reconnect P-S after an S restart. */
export function reconnectPS(t: ITriple): void {
	t.psLink.up();
	t.psLink.pause();
	const sRe = reestablishPayload(t.spChannel.createReestablish());
	const pRe = reestablishPayload(t.pChannel.createReestablish());
	t.pManager.handleMessage(t.sPub, MessageType.CHANNEL_REESTABLISH, sRe);
	t.sManager.handleMessage(t.pPub, MessageType.CHANNEL_REESTABLISH, pRe);
	t.psLink.resume();
}

export function pay(
	t: ITriple,
	hash: Buffer,
	amountMsat: bigint,
	cltvExpiry = 900
): void {
	t.pManager.addHtlc(
		t.psChannelId,
		amountMsat,
		hash,
		cltvExpiry,
		Buffer.alloc(1366)
	);
}

/** Await fire-and-forget tower settlement microtasks (variant B). */
export function flush(ms = 5): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}

// ─────────────── Crash + restart ───────────────

/**
 * Crash S: discard the live manager and restart from the persist tracker's
 * last durable snapshots (both channels). Links are re-armed via the
 * registry; the peers see a dead connection until reconnect*() is called.
 */
export function restartS(
	t: ITriple,
	snapshots?: { sr?: string; sp?: string }
): void {
	t.psLink.down();
	t.srLink.down();
	// Peers observe the disconnect.
	t.pManager.handlePeerDisconnected(t.sPub);
	if (t.rChannel.getState() !== ChannelState.AWAITING_REESTABLISH) {
		t.rManager.handlePeerDisconnected(t.sPub);
	}
	const s2 = new ChannelManager(t.sConfig);
	s2.on('error', (_id, m: string) => t.sErrors.push(m));
	const sr2 = snapshots?.sr
		? new Channel(deserializeChannelState(JSON.parse(snapshots.sr)))
		: t.sTracker.restore(t.srChannelId);
	const sp2 = snapshots?.sp
		? new Channel(deserializeChannelState(JSON.parse(snapshots.sp)))
		: t.sTracker.restore(t.psChannelId);
	s2.restoreChannel(sr2, t.rPub);
	s2.restoreChannel(sp2, t.pPub);
	if (t.tower) {
		s2.setFforTowerClient(new LoopbackTowerClient(t.tower));
	}
	t.registry.set(t.sPub, s2);
	t.sManager = s2;
	t.sChannel = sr2;
	t.spChannel = sp2;
	// Track persists on the restarted manager too.
	t.sTracker.track(s2, [sr2, sp2]);
	rearm(t.registry, t.psLink, t.sPub, t.pPub);
	rearm(t.registry, t.srLink, t.sPub, t.rPub);
}

/** Crash R: restart from the last durable snapshot of the S-R channel. */
export function restartR(t: ITriple): void {
	t.srLink.down();
	if (t.sChannel.getState() !== ChannelState.AWAITING_REESTABLISH) {
		t.sManager.handlePeerDisconnected(t.rPub);
	}
	const r2 = new ChannelManager(t.rConfig);
	r2.on('error', (_id, m: string) => t.rErrors.push(m));
	const rc2 = t.rTracker.restore(t.srChannelId);
	r2.restoreChannel(rc2, t.sPub);
	t.registry.set(t.rPub, r2);
	t.rManager = r2;
	t.rChannel = rc2;
	t.rTracker.track(r2, [rc2]);
	rearm(t.registry, t.srLink, t.rPub, t.sPub);
}

/** Mark both S-R ends disconnected (used before a scripted reconnect). */
export function dropSR(t: ITriple): void {
	t.srLink.down();
	if (t.sChannel.getState() === ChannelState.NORMAL) {
		t.sManager.handlePeerDisconnected(t.rPub);
	}
	if (t.rChannel.getState() === ChannelState.NORMAL) {
		t.rManager.handlePeerDisconnected(t.sPub);
	}
}

// ─────────────── Balance digest (final-state invariant) ───────────────

export interface IBalanceDigest {
	pLocalMsat: bigint;
	spLocalMsat: bigint;
	sLocalMsat: bigint;
	rLocalMsat: bigint;
	pFulfilledCount: number;
	srHtlcs: number;
}

export function balanceDigest(t: ITriple): IBalanceDigest {
	return {
		pLocalMsat: t.pChannel.getBalances().localMsat,
		spLocalMsat: t.spChannel.getBalances().localMsat,
		sLocalMsat: t.sChannel.getBalances().localMsat,
		rLocalMsat: t.rChannel.getBalances().localMsat,
		pFulfilledCount: t.pFulfilled.length,
		srHtlcs: t.sChannel.getFullState().htlcs.size
	};
}
