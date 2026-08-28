/**
 * JIT channel receive, LSP side (LSPS2-inspired; issue #594, LFBW port #532
 * workstream 3A).
 *
 * A wallet with no channel, or with too little inbound, registers a receive
 * intent with its liquidity peer over the beignet custom message type (#546).
 * The LSP mints a synthetic "intercept SCID", the wallet embeds it as a routing
 * hint in its invoice, and an HTLC addressed to that SCID is HELD rather than
 * failed: the LSP funds a zero-conf channel to the wallet (or splices the
 * wallet's existing channel bigger), then forwards the held parts, deducting an
 * agreed opening fee from the delivered amount.
 *
 *   wallet                          LSP
 *     │ JIT_RECEIVE_AUTHORIZATION    │
 *     ├─────────────────────────────>│  mints interceptScid
 *     │<──── JIT_RECEIVE_ACK ────────┤  (scid, opening fee)
 *     │  invoice hint: LSP→scid      │
 *     │                              │  HTLC for unknown scid arrives
 *     │                              │  → intent found → HOLD
 *     │<══ zero-conf channel open ═══┤
 *     │<──── forwarded HTLC ─────────┤
 *
 * Trust model, LSPS2's: the LSP fronts the funding with its OWN coins, bounded
 * by its own caps, and the wallet never reveals a preimage unless it actually
 * receives the HTLC. A hold that cannot be funded is a FAILED PAYMENT, never a
 * loss: the preimage is not involved at any point.
 *
 * Two things the engine owes unconditionally, because a held HTLC is somebody
 * else's money sitting on our inbound channel:
 *
 *  - Every held part is resolved: forwarded, failed, or failed after a
 *    restart. `scanExpiringHolds` REVOKES a part approaching its inbound CLTV
 *    and fails it upstream, and a revoked part can never be forwarded
 *    afterwards, so a funding that completes late cannot pay downstream for an
 *    inbound leg that was already refunded.
 *  - Fronting is bounded. Accepting an intent widens nothing but our own
 *    outbound zero-conf authorization for that peer (see `setJitClients`); it
 *    never makes us accept an INBOUND zero-conf channel from them.
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { encodeShortChannelId } from '../gossip/types';
import {
	ChannelFundingUnavailableCode,
	ChannelFundingUnavailableError,
	IForwardablePart,
	InvalidRequestError
} from '../node/types';

// ─────────────── Wire payloads (custom subtypes 1/2) ───────────────

export interface IJitReceiveAuthorization {
	/** Client-chosen correlation id, echoed in the ack. */
	requestId: Buffer;
	/** Payment hash the intent binds to (optional; zeros = unbound). */
	paymentHash?: Buffer;
	/** Hard cap the LSP may hold and fund against (msat). */
	maxAmountMsat: bigint;
	/** Expected invoice total when known (fixed-amount invoices; 0 = unknown). */
	expectedTotalMsat?: bigint;
	/** Inbound liquidity the wallet wants left over after the receive (sat). */
	targetRemainingInboundSat: bigint;
	expirySeconds: number;
}

export interface IJitReceiveAck {
	requestId: Buffer;
	/** The SCID the LSP minted for this intent; zeros when refused. */
	interceptScid: Buffer;
	accepted: boolean;
	/** LSPS2-style opening fee the LSP will deduct: flat part (sat). */
	flatFeeSat: bigint;
	/** Proportional part, in parts-per-million of the received total. */
	feePpm: number;
	reason?: string;
}

const AUTHORIZATION_LENGTH = 68;
const ACK_HEADER_LENGTH = 31;
/** Refusal reasons are ours; a long one is truncated rather than refused. */
const MAX_ACK_REASON_BYTES = 200;

export function encodeJitAuthorization(a: IJitReceiveAuthorization): Buffer {
	if (a.requestId.length !== 8) {
		throw new Error('jit authorization requestId must be 8 bytes');
	}
	const buf = Buffer.alloc(AUTHORIZATION_LENGTH);
	(a.paymentHash ?? Buffer.alloc(32)).copy(buf, 0);
	a.requestId.copy(buf, 32);
	buf.writeBigUInt64BE(a.maxAmountMsat, 40);
	buf.writeBigUInt64BE(a.expectedTotalMsat ?? 0n, 48);
	buf.writeBigUInt64BE(a.targetRemainingInboundSat, 56);
	buf.writeUInt32BE(a.expirySeconds, 64);
	return buf;
}

export function decodeJitAuthorization(data: Buffer): IJitReceiveAuthorization {
	if (data.length < AUTHORIZATION_LENGTH) {
		throw new Error('jit authorization too short');
	}
	const paymentHash = data.subarray(0, 32);
	const expectedTotal = data.readBigUInt64BE(48);
	const result: IJitReceiveAuthorization = {
		requestId: Buffer.from(data.subarray(32, 40)),
		maxAmountMsat: data.readBigUInt64BE(40),
		targetRemainingInboundSat: data.readBigUInt64BE(56),
		expirySeconds: data.readUInt32BE(64)
	};
	if (!paymentHash.every((b) => b === 0)) {
		result.paymentHash = Buffer.from(paymentHash);
	}
	if (expectedTotal > 0n) result.expectedTotalMsat = expectedTotal;
	return result;
}

export function encodeJitAck(a: IJitReceiveAck): Buffer {
	if (a.requestId.length !== 8) {
		throw new Error('jit ack requestId must be 8 bytes');
	}
	if (a.interceptScid.length !== 8) {
		throw new Error('jit ack interceptScid must be 8 bytes');
	}
	let reason = a.reason ? Buffer.from(a.reason, 'utf8') : Buffer.alloc(0);
	if (reason.length > MAX_ACK_REASON_BYTES) {
		reason = reason.subarray(0, MAX_ACK_REASON_BYTES);
	}
	const buf = Buffer.alloc(ACK_HEADER_LENGTH + reason.length);
	a.requestId.copy(buf, 0);
	a.interceptScid.copy(buf, 8);
	buf.writeUInt8(a.accepted ? 1 : 0, 16);
	buf.writeBigUInt64BE(a.flatFeeSat, 17);
	buf.writeUInt32BE(a.feePpm >>> 0, 25);
	buf.writeUInt16BE(reason.length, 29);
	reason.copy(buf, ACK_HEADER_LENGTH);
	return buf;
}

export function decodeJitAck(data: Buffer): IJitReceiveAck {
	if (data.length < ACK_HEADER_LENGTH) throw new Error('jit ack too short');
	const reasonLen = data.readUInt16BE(29);
	// A declared length the buffer cannot supply is a malformed ack, not a
	// short reason: subarray would silently truncate it into something that
	// reads as a legitimate (and wrong) refusal message.
	if (ACK_HEADER_LENGTH + reasonLen > data.length) {
		throw new Error('jit ack reason runs past the payload');
	}
	const result: IJitReceiveAck = {
		requestId: Buffer.from(data.subarray(0, 8)),
		interceptScid: Buffer.from(data.subarray(8, 16)),
		accepted: data.readUInt8(16) === 1,
		flatFeeSat: data.readBigUInt64BE(17),
		feePpm: data.readUInt32BE(25)
	};
	if (reasonLen > 0) {
		result.reason = data
			.subarray(ACK_HEADER_LENGTH, ACK_HEADER_LENGTH + reasonLen)
			.toString('utf8');
	}
	return result;
}

/**
 * Block height every minted intercept SCID carries. BOLT 7 packs an SCID as
 * [u24 block][u24 txIndex][u16 outputIndex], so pinning the block field to its
 * maximum puts every synthetic SCID roughly three centuries beyond any real
 * one: a confirmed channel can never take a value the engine minted, and the
 * engine can never mint one a channel will later confirm into. The remaining
 * 40 bits are random, so a client cannot guess another client's SCID.
 */
export const JIT_INTERCEPT_SCID_BLOCK = 0xffffff;

/**
 * Mint a synthetic intercept SCID that no channel of ours already answers to.
 * The LSP mints it (never the client): a client-supplied SCID lets a second
 * client claim the first client's intent and be paid its payments.
 */
export function mintInterceptScid(
	isTaken: (scidHex: string) => boolean,
	attempts = 8
): Buffer | null {
	for (let i = 0; i < attempts; i++) {
		const random = crypto.randomBytes(5);
		const scid = encodeShortChannelId({
			block: JIT_INTERCEPT_SCID_BLOCK,
			txIndex: random.readUIntBE(0, 3),
			outputIndex: random.readUInt16BE(3)
		});
		if (!isTaken(scid.toString('hex'))) return scid;
	}
	return null;
}

// ─────────────── LSP-side engine ───────────────

export interface IJitReceiveConfig {
	enabled: boolean;
	/** Cap on what the LSP funds for ONE client, on either path (sat). */
	maxClientFundingSats?: bigint;
	/** Reserve/fee headroom added to the funded amount (sat). */
	fundingBufferSats?: bigint;
	/** Intent lifetime ceiling; a client may ask for less. */
	intentTtlMs?: number;
	/** How long held MPP parts wait for the rest of the set. */
	aggregationTimeoutMs?: number;
	/** Minimum CLTV cushion (blocks) an intercepted HTLC must leave us. */
	minCltvDeltaBlocks?: number;
	/** Blocks before the inbound expiry at which a hold is revoked. */
	holdExpiryMarginBlocks?: number;
	/** LSPS2-style opening fee, flat part (sat). */
	flatFeeSat?: bigint;
	/** LSPS2-style opening fee, proportional part (ppm of the held total). */
	feePpm?: number;
	/** Fundings (opens plus splices) allowed to be in flight at once. */
	maxConcurrentFundings?: number;
	/** Live intents one peer may hold at once. */
	maxLiveIntentsPerPeer?: number;
	/** Live intents across all peers. */
	maxLiveIntents?: number;
	/**
	 * Cumulative sats this engine may ever front, counted across restarts.
	 * Undefined (the default) leaves fronting bounded only by the per-client
	 * and concurrency caps, which is what bounds exposure at any instant; set
	 * it to run JIT fronting against a hard lifetime budget.
	 */
	maxTotalFundingSats?: bigint;
	/** Attempts per funding, each re-checking the deadlines first. */
	fundingAttempts?: number;
	/** Timeout handed to one open/splice attempt. */
	fundingAttemptTimeoutMs?: number;
	/** Pause between funding attempts. */
	fundingRetryDelayMs?: number;
	/** Total wall-clock budget for one funding, retries included. */
	maxHoldMs?: number;
}

export interface IJitIntent {
	interceptScidHex: string;
	walletPubkeyHex: string;
	paymentHashHex?: string;
	maxAmountMsat: bigint;
	expectedTotalMsat?: bigint;
	targetRemainingInboundSat: bigint;
	expiresAt: number;
}

/** A forward held by the engine, plus the engine's own bookkeeping. */
export interface IHeldJitPart extends IForwardablePart {
	/** Set once a splice retry has been attempted: a second failure is final. */
	spliceRetried?: boolean;
	/**
	 * Set by the deadline backstop when the part has been failed upstream.
	 * A revoked part is never forwarded, whatever a funding does afterwards.
	 */
	revoked?: boolean;
}

export interface IJitManagerDeps {
	/** Chain tip; 0 before the node has seen a block. */
	currentBlockHeight(): number;
	/** True when one of our channels already answers to this SCID or alias. */
	isScidInUse(scidHex: string): boolean;
	/** Open a zero-conf channel and resolve with its channel id when usable. */
	openZeroConfChannelAndWait(
		walletPubkeyHex: string,
		fundingSats: bigint,
		timeoutMs: number
	): Promise<Buffer>;
	/** Place a held part onto a (possibly brand new) outgoing channel. */
	forwardOnto(outChannelId: Buffer, part: IHeldJitPart): void;
	/** BOLT 4 codes used to resolve a hold upstream. */
	failureCodes: { temporaryChannelFailure: number; expiryTooSoon: number };
	/**
	 * Publish the peers we may open an OUTBOUND zero-conf channel to. Derived
	 * from the persisted intents, never a standing grant: this must not widen
	 * to the symmetric zero-conf trusted set, whose membership also makes us
	 * accept an inbound zero-conf channel from the peer.
	 */
	setJitClients(pubkeyHexes: string[]): void;
	/** Is this channel's peer a JIT client with a live intent? */
	isJitClientChannel?(outChannelId: Buffer): boolean;
	/** Splice our own funds in and resolve once the channel is usable again. */
	spliceInAndWait?(
		channelId: Buffer,
		amountSats: bigint,
		timeoutMs: number
	): Promise<void>;
	/** Durable KV (the node's storage backend); without it the engine is in-memory. */
	storage?: {
		saveMetadata(key: string, value: string): void;
		loadMetadata(key: string): string | null;
	};
	/**
	 * Fail upstream an incoming HTLC that was held BEFORE a restart. Returns
	 * true when the failure was delivered (or the HTLC is already gone), false
	 * to retry later, e.g. the channel has not reestablished yet.
	 */
	failRestoredHtlc?(part: IPersistedHeldPart): boolean;
}

/** Persisted shape of an intent (bigints as strings). */
interface IPersistedIntent {
	interceptScidHex: string;
	walletPubkeyHex: string;
	paymentHashHex?: string;
	maxAmountMsat: string;
	expectedTotalMsat?: string;
	targetRemainingInboundSat: string;
	expiresAt: number;
}

/**
 * Persisted metadata of a held HTLC. The `disposition` is the point of the
 * record (docs/RECOVERY-PROTOCOL.md 5.10 names held and intercepted HTLC
 * decisions as owing one): the funding session dies with the process, and what
 * the restart owes the inbound leg is a clean FAIL, which needs the channel,
 * the htlc id and enough context to fail it as the right kind of HTLC.
 */
export interface IPersistedHeldPart {
	inChannelIdHex: string;
	inHtlcId: string;
	paymentHashHex: string;
	amountMsat: string;
	incomingCltvExpiry: number;
	disposition: 'fail';
}

const STORAGE_KEY_INTENTS = 'jit:intents';
const STORAGE_KEY_HELD = 'jit:held';
const STORAGE_KEY_FRONTED = 'jit:fronted';

const DEFAULTS = {
	maxClientFundingSats: 1_000_000n,
	fundingBufferSats: 10_000n,
	intentTtlMs: 10 * 60 * 1000,
	aggregationTimeoutMs: 60_000,
	minCltvDeltaBlocks: 40,
	holdExpiryMarginBlocks: 18,
	flatFeeSat: 0n,
	feePpm: 0,
	maxConcurrentFundings: 3,
	maxLiveIntentsPerPeer: 2,
	maxLiveIntents: 100,
	fundingAttempts: 3,
	fundingAttemptTimeoutMs: 120_000,
	fundingRetryDelayMs: 2_000,
	maxHoldMs: 300_000
};

type ResolvedConfig = Omit<
	Required<IJitReceiveConfig>,
	'enabled' | 'maxTotalFundingSats'
> & { maxTotalFundingSats?: bigint };

/**
 * A refusal that no retry inside the hold budget can turn into a success: the
 * request as written, or this node as configured, cannot serve it. Everything
 * else is transient by the standards of a held HTLC (the wallet's coins are
 * momentarily pledged to another funding, the fee estimator has not delivered
 * its first sample, the peer is reconnecting) and is retried until the budget
 * or the CLTV deadline runs out. Typed, per issues #464 and #471/#472: the
 * fork matched error-message substrings, which both misses a rename and
 * retries something permanent.
 */
function isPermanentFundingRefusal(err: unknown): boolean {
	if (err instanceof InvalidRequestError) return true;
	if (err instanceof ChannelFundingUnavailableError) {
		return (
			err.code === ChannelFundingUnavailableCode.FUNDING_PROVIDER_REQUIRED ||
			err.code === ChannelFundingUnavailableCode.CHANNEL_NOT_FOUND
		);
	}
	return false;
}

export class JitReceiveManager extends EventEmitter {
	private intents = new Map<string, IJitIntent>();
	/** Parts held for a zero-conf open, per intercept scid. */
	private heldParts = new Map<string, IHeldJitPart[]>();
	/** Parts held for a splice, per outgoing channel id. */
	private spliceQueues = new Map<string, IHeldJitPart[]>();
	private aggregationTimers = new Map<string, NodeJS.Timeout>();
	private fundingInFlight = new Set<string>();
	private spliceInFlight = new Set<string>();
	/** Held parts from BEFORE a restart, queued to be failed upstream. */
	private restoredToFail: IPersistedHeldPart[] = [];
	/** Cumulative sats fronted (persisted) and sats a live funding has claimed. */
	private frontedSats = 0n;
	private reservedSats = 0n;
	private destroyed = false;
	private readonly cfg: ResolvedConfig;

	constructor(
		private deps: IJitManagerDeps,
		config: IJitReceiveConfig
	) {
		super();
		this.cfg = {
			maxClientFundingSats:
				config.maxClientFundingSats ?? DEFAULTS.maxClientFundingSats,
			fundingBufferSats: config.fundingBufferSats ?? DEFAULTS.fundingBufferSats,
			intentTtlMs: config.intentTtlMs ?? DEFAULTS.intentTtlMs,
			aggregationTimeoutMs:
				config.aggregationTimeoutMs ?? DEFAULTS.aggregationTimeoutMs,
			minCltvDeltaBlocks:
				config.minCltvDeltaBlocks ?? DEFAULTS.minCltvDeltaBlocks,
			holdExpiryMarginBlocks:
				config.holdExpiryMarginBlocks ?? DEFAULTS.holdExpiryMarginBlocks,
			flatFeeSat: config.flatFeeSat ?? DEFAULTS.flatFeeSat,
			feePpm: config.feePpm ?? DEFAULTS.feePpm,
			maxConcurrentFundings:
				config.maxConcurrentFundings ?? DEFAULTS.maxConcurrentFundings,
			maxLiveIntentsPerPeer:
				config.maxLiveIntentsPerPeer ?? DEFAULTS.maxLiveIntentsPerPeer,
			maxLiveIntents: config.maxLiveIntents ?? DEFAULTS.maxLiveIntents,
			fundingAttempts: config.fundingAttempts ?? DEFAULTS.fundingAttempts,
			fundingAttemptTimeoutMs:
				config.fundingAttemptTimeoutMs ?? DEFAULTS.fundingAttemptTimeoutMs,
			fundingRetryDelayMs:
				config.fundingRetryDelayMs ?? DEFAULTS.fundingRetryDelayMs,
			maxHoldMs: config.maxHoldMs ?? DEFAULTS.maxHoldMs
		};
		if (config.maxTotalFundingSats !== undefined) {
			this.cfg.maxTotalFundingSats = config.maxTotalFundingSats;
		}
	}

	// ─────────────── Persistence ───────────────

	/**
	 * Restore after a restart: live intents come back, so the invoices already
	 * out there stay payable, and every pre-restart held HTLC is queued to be
	 * failed upstream as soon as its channel reestablishes. A half-done funding
	 * is NOT resumed. Call once after the node's own storage restore; the block
	 * tick then drives the fail queue.
	 */
	restore(): void {
		const storage = this.deps.storage;
		if (!storage) return;
		try {
			const intentsJson = storage.loadMetadata(STORAGE_KEY_INTENTS);
			if (intentsJson) {
				const now = Date.now();
				for (const p of JSON.parse(intentsJson) as IPersistedIntent[]) {
					if (p.expiresAt <= now) continue;
					const intent: IJitIntent = {
						interceptScidHex: p.interceptScidHex,
						walletPubkeyHex: p.walletPubkeyHex,
						maxAmountMsat: BigInt(p.maxAmountMsat),
						targetRemainingInboundSat: BigInt(p.targetRemainingInboundSat),
						expiresAt: p.expiresAt
					};
					if (p.paymentHashHex) intent.paymentHashHex = p.paymentHashHex;
					if (p.expectedTotalMsat) {
						intent.expectedTotalMsat = BigInt(p.expectedTotalMsat);
					}
					this.intents.set(p.interceptScidHex, intent);
				}
				this.persistIntents();
			}
			const heldJson = storage.loadMetadata(STORAGE_KEY_HELD);
			if (heldJson) {
				this.restoredToFail = (
					JSON.parse(heldJson) as IPersistedHeldPart[]
				).filter((p) => p && p.inChannelIdHex && p.inHtlcId !== undefined);
			}
			const frontedRaw = storage.loadMetadata(STORAGE_KEY_FRONTED);
			if (frontedRaw) this.frontedSats = BigInt(frontedRaw);
		} catch {
			// Corrupt persisted state: run from whatever parsed rather than
			// taking the node down. Nothing here is authoritative for funds.
		}
		// The zero-conf trust the restored intents imply is re-derived here, so
		// a restart cannot leave an intent that intercepts and an open that is
		// then refused for an untrusted peer, stranding the held HTLC.
		this.refreshJitClients();
		this.sweep();
	}

	/**
	 * Drive the restored-HTLC fail queue (from restore and from the block
	 * tick). Entries that were failed leave durable storage; the rest are
	 * retried on the next sweep.
	 */
	sweep(): void {
		if (this.restoredToFail.length === 0 || !this.deps.failRestoredHtlc) return;
		const remaining: IPersistedHeldPart[] = [];
		for (const part of this.restoredToFail) {
			let failed = false;
			try {
				failed = this.deps.failRestoredHtlc(part);
			} catch {
				failed = false;
			}
			if (!failed) remaining.push(part);
		}
		if (remaining.length !== this.restoredToFail.length) {
			this.restoredToFail = remaining;
			this.persistHeld();
			this.emit('jit:restored-failed', { remaining: remaining.length });
		}
	}

	private persistIntents(): void {
		if (!this.deps.storage) return;
		const list: IPersistedIntent[] = [];
		for (const i of this.intents.values()) {
			const p: IPersistedIntent = {
				interceptScidHex: i.interceptScidHex,
				walletPubkeyHex: i.walletPubkeyHex,
				maxAmountMsat: i.maxAmountMsat.toString(),
				targetRemainingInboundSat: i.targetRemainingInboundSat.toString(),
				expiresAt: i.expiresAt
			};
			if (i.paymentHashHex) p.paymentHashHex = i.paymentHashHex;
			if (i.expectedTotalMsat) {
				p.expectedTotalMsat = i.expectedTotalMsat.toString();
			}
			list.push(p);
		}
		try {
			this.deps.storage.saveMetadata(STORAGE_KEY_INTENTS, JSON.stringify(list));
		} catch {
			// best-effort persistence
		}
	}

	private static persistedShape(part: IHeldJitPart): IPersistedHeldPart {
		return {
			inChannelIdHex: part.inChannelId.toString('hex'),
			inHtlcId: part.inHtlcId.toString(),
			paymentHashHex: part.paymentHash.toString('hex'),
			amountMsat: part.forwardAmountMsat.toString(),
			incomingCltvExpiry: part.incomingCltvExpiry,
			disposition: 'fail'
		};
	}

	private persistHeld(): void {
		if (!this.deps.storage) return;
		const live: IPersistedHeldPart[] = [];
		for (const parts of this.heldParts.values()) {
			for (const p of parts) live.push(JitReceiveManager.persistedShape(p));
		}
		for (const parts of this.spliceQueues.values()) {
			for (const p of parts) live.push(JitReceiveManager.persistedShape(p));
		}
		try {
			this.deps.storage.saveMetadata(
				STORAGE_KEY_HELD,
				JSON.stringify([...this.restoredToFail, ...live])
			);
		} catch {
			// best-effort persistence
		}
	}

	private persistFronted(): void {
		try {
			this.deps.storage?.saveMetadata(
				STORAGE_KEY_FRONTED,
				this.frontedSats.toString()
			);
		} catch {
			// best-effort persistence
		}
	}

	// ─────────────── Exposure accounting ───────────────

	/** Cumulative sats this engine has fronted, across restarts. */
	getFrontedTotalSats(): bigint {
		return this.frontedSats;
	}

	/** Clear the cumulative counter (operator action; the cap is a budget). */
	resetFrontedTotal(): void {
		this.frontedSats = 0n;
		this.persistFronted();
	}

	private fundingSlotsFree(): boolean {
		return (
			this.fundingInFlight.size + this.spliceInFlight.size <
			this.cfg.maxConcurrentFundings
		);
	}

	private reserveFunding(sats: bigint): boolean {
		const cap = this.cfg.maxTotalFundingSats;
		if (
			cap !== undefined &&
			this.frontedSats + this.reservedSats + sats > cap
		) {
			return false;
		}
		this.reservedSats += sats;
		return true;
	}

	/** A funding that never landed returns its coins; only success is fronted. */
	private releaseFunding(sats: bigint, fronted: boolean): void {
		this.reservedSats -= sats;
		if (this.reservedSats < 0n) this.reservedSats = 0n;
		if (fronted) {
			this.frontedSats += sats;
			this.persistFronted();
		}
	}

	// ─────────────── Intents ───────────────

	/**
	 * Register a wallet's receive intent and return the ack to send back. Any
	 * peer may ask (the LSPS2 shape); what bounds us is the caps, not an
	 * allowlist.
	 */
	registerIntent(
		walletPubkeyHex: string,
		auth: IJitReceiveAuthorization
	): IJitReceiveAck {
		this.sweepExpiredIntents();
		const refuse = (reason: string): IJitReceiveAck => ({
			requestId: auth.requestId,
			interceptScid: Buffer.alloc(8),
			accepted: false,
			flatFeeSat: 0n,
			feePpm: 0,
			reason
		});

		if (auth.maxAmountMsat <= 0n) {
			return refuse('maxAmountMsat must be positive');
		}
		if (auth.expirySeconds <= 0) {
			return refuse('expirySeconds must be positive');
		}
		const requestedSat = auth.maxAmountMsat / 1000n;
		if (requestedSat > this.cfg.maxClientFundingSats) {
			return refuse(`max fundable is ${this.cfg.maxClientFundingSats} sats`);
		}
		if (this.intents.size >= this.cfg.maxLiveIntents) {
			return refuse('the LSP is holding its maximum number of live intents');
		}
		let perPeer = 0;
		for (const i of this.intents.values()) {
			if (i.walletPubkeyHex === walletPubkeyHex) perPeer++;
		}
		if (perPeer >= this.cfg.maxLiveIntentsPerPeer) {
			return refuse(
				`at most ${this.cfg.maxLiveIntentsPerPeer} live intents per peer`
			);
		}

		// The LSP mints the SCID. A value that collides with a real SCID, an
		// alias or another client's intent is refused, never overwritten: an
		// overwrite hands one client's payments to another.
		const scid = mintInterceptScid(
			(hex) => this.intents.has(hex) || this.deps.isScidInUse(hex)
		);
		if (!scid) {
			return refuse('could not mint a free intercept scid');
		}
		const scidHex = scid.toString('hex');

		const intent: IJitIntent = {
			interceptScidHex: scidHex,
			walletPubkeyHex,
			maxAmountMsat: auth.maxAmountMsat,
			targetRemainingInboundSat: auth.targetRemainingInboundSat,
			expiresAt:
				Date.now() + Math.min(auth.expirySeconds * 1000, this.cfg.intentTtlMs)
		};
		if (auth.paymentHash) {
			intent.paymentHashHex = auth.paymentHash.toString('hex');
		}
		if (auth.expectedTotalMsat) {
			intent.expectedTotalMsat = auth.expectedTotalMsat;
		}
		this.intents.set(scidHex, intent);
		this.persistIntents();
		this.refreshJitClients();
		this.emit('jit:intent', intent);

		return {
			requestId: auth.requestId,
			interceptScid: scid,
			accepted: true,
			flatFeeSat: this.cfg.flatFeeSat,
			feePpm: this.cfg.feePpm
		};
	}

	/** Live intents, for the daemon surface and tests. */
	listIntents(): IJitIntent[] {
		return [...this.intents.values()];
	}

	/** Total msat currently held for an intercept scid. */
	heldTotalMsat(scidHex: string): bigint {
		return (this.heldParts.get(scidHex) ?? []).reduce(
			(s, p) => s + p.forwardAmountMsat,
			0n
		);
	}

	/**
	 * The peers whose intents authorize an OUTBOUND zero-conf open from us.
	 * Derived, never granted: an intent that expires takes the authorization
	 * with it, and a restart re-derives the same set from the same records.
	 */
	private refreshJitClients(): void {
		const clients = new Set<string>();
		for (const i of this.intents.values()) clients.add(i.walletPubkeyHex);
		this.deps.setJitClients([...clients]);
	}

	private sweepExpiredIntents(): void {
		const now = Date.now();
		let removed = false;
		for (const [scidHex, intent] of this.intents) {
			if (intent.expiresAt > now) continue;
			// An intent whose funding is running, or whose parts are held, is
			// still doing its job; its parts are bounded by their own deadline.
			if (this.fundingInFlight.has(scidHex)) continue;
			if ((this.heldParts.get(scidHex)?.length ?? 0) > 0) continue;
			this.intents.delete(scidHex);
			removed = true;
		}
		if (removed) {
			this.persistIntents();
			this.refreshJitClients();
		}
	}

	// ─────────────── Interception ───────────────

	/**
	 * Called from the forwarding path when the outgoing SCID matched no channel
	 * of ours. Returns true when the HTLC was intercepted and held, and the
	 * caller must then NOT fail it; false falls through to unknown_next_peer.
	 */
	tryInterceptUnknownScid(scidHex: string, part: IHeldJitPart): boolean {
		if (this.destroyed) return false;
		const intent = this.intents.get(scidHex);
		if (!intent) return false;
		if (Date.now() > intent.expiresAt) {
			this.intents.delete(scidHex);
			this.persistIntents();
			this.refreshJitClients();
			return false;
		}
		// A funding already running for this intent cannot take a late part:
		// its held set was consumed when the funding started.
		if (this.fundingInFlight.has(scidHex)) return false;
		// Payment-hash binding, when the wallet asked for one.
		if (
			intent.paymentHashHex &&
			part.paymentHash.toString('hex') !== intent.paymentHashHex
		) {
			return false;
		}
		// CLTV cushion: we must survive claiming the outgoing HTLC on-chain.
		if (
			part.incomingCltvExpiry - part.forwardCltv <
			this.cfg.minCltvDeltaBlocks
		) {
			return false;
		}
		// Refusing NOW beats holding something the deadline backstop revokes on
		// the next block: the sender learns immediately and can retry.
		if (this.pastDeadline(part)) return false;
		if (!this.fundingSlotsFree()) return false;

		const held = this.heldParts.get(scidHex) ?? [];
		const heldTotal = held.reduce((s, p) => s + p.forwardAmountMsat, 0n);
		if (heldTotal + part.forwardAmountMsat > intent.maxAmountMsat) {
			return false;
		}

		held.push(part);
		this.heldParts.set(scidHex, held);
		this.persistHeld();
		this.emit('jit:intercepted', {
			scidHex,
			amountMsat: part.forwardAmountMsat
		});

		const newTotal = heldTotal + part.forwardAmountMsat;
		const target = intent.expectedTotalMsat;
		if (target === undefined || newTotal >= target) {
			// Single part, unknown total, or a complete MPP set: fund now.
			this.clearAggregation(scidHex);
			void this.fund(intent);
		} else if (!this.aggregationTimers.has(scidHex)) {
			// MPP: wait, bounded, for the remaining parts.
			const t = setTimeout(() => {
				this.aggregationTimers.delete(scidHex);
				this.failAllHeld(
					scidHex,
					this.deps.failureCodes.temporaryChannelFailure
				);
			}, this.cfg.aggregationTimeoutMs);
			t.unref?.();
			this.aggregationTimers.set(scidHex, t);
		}
		return true;
	}

	// ─────────────── Deadlines ───────────────

	/** Within the revocation margin of its inbound expiry (or already past). */
	private pastDeadline(part: IHeldJitPart): boolean {
		const height = this.deps.currentBlockHeight();
		if (height <= 0 || part.incomingCltvExpiry <= 0) return false;
		return part.incomingCltvExpiry - height <= this.cfg.holdExpiryMarginBlocks;
	}

	/**
	 * Fail every held part whose inbound CLTV deadline is near, and sweep
	 * expired intents. Driven from the node's per-block work, BEFORE the node's
	 * own expiring-HTLC scan, so the engine is the one that resolves its own
	 * holds: a part the node failed behind our back would still be forwarded by
	 * a funding that completed afterwards, paying downstream for an inbound leg
	 * that no longer exists.
	 */
	scanExpiringHolds(): void {
		if (this.deps.currentBlockHeight() <= 0) return;
		let revoked = false;
		const sweep = (
			collection: Map<string, IHeldJitPart[]>,
			onEmpty?: (key: string) => void
		): void => {
			for (const [key, parts] of [...collection]) {
				const doomed: IHeldJitPart[] = [];
				const survivors: IHeldJitPart[] = [];
				for (const part of parts) {
					(this.pastDeadline(part) ? doomed : survivors).push(part);
				}
				if (doomed.length === 0) continue;
				if (survivors.length > 0) {
					collection.set(key, survivors);
				} else {
					collection.delete(key);
					onEmpty?.(key);
				}
				this.revokeAll(doomed, key);
				revoked = true;
			}
		};
		sweep(this.heldParts, (key) => this.clearAggregation(key));
		sweep(this.spliceQueues);
		if (revoked) this.persistHeld();
		this.sweepExpiredIntents();
	}

	/** Mark parts unforwardable for good, then fail them upstream. */
	private revokeAll(parts: IHeldJitPart[], scope: string): void {
		for (const part of parts) {
			part.revoked = true;
			try {
				part.failIncoming(this.deps.failureCodes.expiryTooSoon);
			} catch {
				// best-effort: the inbound channel may already be gone
			}
		}
		this.emit('jit:failed', {
			scidHex: scope,
			parts: parts.length,
			reason: 'held part reached its inbound CLTV deadline'
		});
	}

	// ─────────────── Zero-conf open path ───────────────

	private async fund(intent: IJitIntent): Promise<void> {
		const scidHex = intent.interceptScidHex;
		if (this.fundingInFlight.has(scidHex)) return;
		if (!this.fundingSlotsFree()) {
			this.failAllHeld(scidHex, this.deps.failureCodes.temporaryChannelFailure);
			return;
		}

		const parts = this.heldParts.get(scidHex) ?? [];
		const totalMsat = parts.reduce((s, p) => s + p.forwardAmountMsat, 0n);
		// The fee is checked against the parts BEFORE any state is consumed, so
		// a fee that cannot be taken fails every part upstream instead of
		// throwing past an already-emptied held map and dropping them.
		const feeError = this.validateFee(parts, totalMsat);
		if (feeError) {
			this.emit('jit:failed', { scidHex, reason: feeError });
			this.failAllHeld(scidHex, this.deps.failureCodes.temporaryChannelFailure);
			return;
		}

		let fundingSats =
			(totalMsat + 999n) / 1000n +
			intent.targetRemainingInboundSat +
			this.cfg.fundingBufferSats;
		if (fundingSats > this.cfg.maxClientFundingSats) {
			fundingSats = this.cfg.maxClientFundingSats;
		}
		if (!this.reserveFunding(fundingSats)) {
			this.emit('jit:failed', {
				scidHex,
				reason: 'cumulative JIT funding cap reached'
			});
			this.failAllHeld(scidHex, this.deps.failureCodes.temporaryChannelFailure);
			return;
		}

		this.fundingInFlight.add(scidHex);
		let fronted = false;
		try {
			this.emit('jit:funding', { scidHex, fundingSats });
			const channelId = await this.attempt(
				(timeoutMs) =>
					this.deps.openZeroConfChannelAndWait(
						intent.walletPubkeyHex,
						fundingSats,
						timeoutMs
					),
				() => this.heldParts.get(scidHex) ?? []
			);
			fronted = true;

			// Deadline re-check immediately before the forward. A revoked part
			// was already failed upstream; forwarding any of the set now would
			// pay downstream for a payment that can no longer complete.
			const toForward = this.heldParts.get(scidHex) ?? [];
			if (toForward.length === 0) {
				throw new Error('every held part was resolved before funding');
			}
			if (toForward.some((p) => p.revoked || this.pastDeadline(p))) {
				throw new Error('held part reached its inbound CLTV deadline');
			}
			const lateFeeError = this.validateFee(
				toForward,
				toForward.reduce((s, p) => s + p.forwardAmountMsat, 0n)
			);
			if (lateFeeError) throw new Error(lateFeeError);

			// From here the held set is CONSUMED, so nothing below may leave a
			// part unresolved: the forwards are individually guarded and the
			// intent is retired only once they have all been placed.
			this.heldParts.delete(scidHex);
			this.clearAggregation(scidHex);
			this.persistHeld();
			this.applyFee(toForward);
			for (const part of toForward) {
				this.forwardOrFail(channelId, part);
			}
			this.intents.delete(scidHex);
			this.persistIntents();
			this.refreshJitClients();
			this.emit('jit:forwarded', { scidHex, parts: toForward.length });
		} catch (err) {
			this.emit('jit:failed', {
				scidHex,
				reason: err instanceof Error ? err.message : String(err)
			});
			this.failAllHeld(scidHex, this.deps.failureCodes.temporaryChannelFailure);
		} finally {
			this.releaseFunding(fundingSats, fronted);
			this.fundingInFlight.delete(scidHex);
		}
	}

	// ─────────────── On-the-fly splice (oversized receive) ───────────────

	/**
	 * Called when forwarding onto an EXISTING channel was refused (too little
	 * of our balance on that side, or the channel is mid-splice). When the peer
	 * is a JIT client, hold the part, splice our own funds in, and retry the
	 * forward once. Returns true when held, and the caller must then NOT fail
	 * the HTLC.
	 *
	 * Which path runs is decided by which failure fired: an unknown SCID is a
	 * client with no channel and goes to the zero-conf open above, an addHtlc
	 * refusal on a JIT client's existing channel goes here.
	 */
	tryHoldForSplice(outChannelId: Buffer, part: IHeldJitPart): boolean {
		if (this.destroyed) return false;
		if (!this.deps.isJitClientChannel || !this.deps.spliceInAndWait) {
			return false;
		}
		if (part.spliceRetried) return false; // one retry only
		if (part.revoked) return false;
		if (!this.deps.isJitClientChannel(outChannelId)) return false;
		if (this.pastDeadline(part)) return false;

		const key = outChannelId.toString('hex');
		if (!this.spliceInFlight.has(key) && !this.fundingSlotsFree()) return false;

		const queue = this.spliceQueues.get(key) ?? [];
		queue.push(part);
		this.spliceQueues.set(key, queue);
		this.persistHeld();
		this.emit('jit:intercepted', {
			channelIdHex: key,
			amountMsat: part.forwardAmountMsat
		});

		if (!this.spliceInFlight.has(key)) {
			void this.spliceAndRetry(outChannelId);
		}
		return true;
	}

	private async spliceAndRetry(outChannelId: Buffer): Promise<void> {
		const key = outChannelId.toString('hex');
		// Fund the whole queue plus the standard buffer. A second competing
		// splice is never started: parts arriving mid-splice join the queue and
		// are forwarded together once this one locks.
		const queued = this.spliceQueues.get(key) ?? [];
		const totalMsat = queued.reduce((s, p) => s + p.forwardAmountMsat, 0n);
		let amountSats = (totalMsat + 999n) / 1000n + this.cfg.fundingBufferSats;
		// The same per-client ceiling the open path clamps to, and the same
		// budget: the fork clamped only the open, so a splice could front
		// arbitrarily much.
		if (amountSats > this.cfg.maxClientFundingSats) {
			amountSats = this.cfg.maxClientFundingSats;
		}
		if (!this.reserveFunding(amountSats)) {
			this.emit('jit:failed', {
				channelIdHex: key,
				reason: 'cumulative JIT funding cap reached'
			});
			this.failAllSpliceQueued(
				key,
				this.deps.failureCodes.temporaryChannelFailure
			);
			return;
		}

		this.spliceInFlight.add(key);
		let fronted = false;
		try {
			this.emit('jit:funding', { channelIdHex: key, fundingSats: amountSats });
			await this.attempt(
				(timeoutMs) =>
					this.deps.spliceInAndWait!(outChannelId, amountSats, timeoutMs),
				() => this.spliceQueues.get(key) ?? []
			);
			fronted = true;

			const toForward = this.spliceQueues.get(key) ?? [];
			if (toForward.length === 0) {
				throw new Error('every held part was resolved before funding');
			}
			if (toForward.some((p) => p.revoked || this.pastDeadline(p))) {
				throw new Error('held part reached its inbound CLTV deadline');
			}
			this.spliceQueues.delete(key);
			this.persistHeld();
			for (const part of toForward) {
				part.spliceRetried = true;
				this.forwardOrFail(outChannelId, part);
			}
			this.emit('jit:forwarded', {
				channelIdHex: key,
				parts: toForward.length
			});
		} catch (err) {
			this.emit('jit:failed', {
				channelIdHex: key,
				reason: err instanceof Error ? err.message : String(err)
			});
			this.failAllSpliceQueued(
				key,
				this.deps.failureCodes.temporaryChannelFailure
			);
		} finally {
			this.releaseFunding(amountSats, fronted);
			this.spliceInFlight.delete(key);
		}
	}

	// ─────────────── Shared funding mechanics ───────────────

	/**
	 * Run one funding to success or to the end of its budget. Every attempt is
	 * preceded by a deadline re-check, so a hold never rides past the point
	 * where its inbound leg can still be refunded cleanly, and the whole loop
	 * is bounded by maxHoldMs rather than by attempts alone.
	 */
	private async attempt<T>(
		run: (timeoutMs: number) => Promise<T>,
		parts: () => IHeldJitPart[]
	): Promise<T> {
		const budgetEndsAt = Date.now() + this.cfg.maxHoldMs;
		let lastErr: unknown = new Error('funding made no attempt');
		for (let i = 0; i < this.cfg.fundingAttempts; i++) {
			if (this.destroyed) throw new Error('node destroyed');
			// Each attempt gets what is LEFT of the budget, not a fresh timeout,
			// so the total hold is maxHoldMs rather than attempts times the
			// per-attempt timeout (the fork could hold for about 730 seconds).
			const remaining = budgetEndsAt - Date.now();
			if (remaining <= 0) {
				throw new Error('JIT funding exceeded its hold budget');
			}
			const held = parts();
			if (held.length === 0) {
				throw new Error('every held part was resolved before funding');
			}
			if (held.some((p) => p.revoked || this.pastDeadline(p))) {
				throw new Error('held part reached its inbound CLTV deadline');
			}
			try {
				return await run(Math.min(this.cfg.fundingAttemptTimeoutMs, remaining));
			} catch (err) {
				lastErr = err;
				if (isPermanentFundingRefusal(err)) throw err;
			}
			if (i + 1 < this.cfg.fundingAttempts) {
				await new Promise((r) => {
					const t = setTimeout(r, this.cfg.fundingRetryDelayMs);
					(t as NodeJS.Timeout).unref?.();
				});
			}
		}
		throw lastErr;
	}

	/**
	 * Place a part, and resolve it upstream if the placement itself throws.
	 * Once the held set has been consumed, a throw here is the only way a part
	 * could be left in flight with nobody owning it.
	 */
	private forwardOrFail(outChannelId: Buffer, part: IHeldJitPart): void {
		try {
			this.deps.forwardOnto(outChannelId, part);
		} catch {
			part.revoked = true;
			try {
				part.failIncoming(this.deps.failureCodes.temporaryChannelFailure);
			} catch {
				// best-effort: the inbound channel may already be gone
			}
		}
	}

	private feeMsatFor(totalMsat: bigint): bigint {
		return (
			this.cfg.flatFeeSat * 1000n +
			(totalMsat * BigInt(this.cfg.feePpm)) / 1_000_000n
		);
	}

	/** Null when the opening fee can be taken out of these parts. */
	private validateFee(parts: IHeldJitPart[], totalMsat: bigint): string | null {
		const feeMsat = this.feeMsatFor(totalMsat);
		if (feeMsat <= 0n) return null;
		if (parts.length === 0) return 'no held part to take the JIT fee from';
		const largest = parts.reduce((a, b) =>
			b.forwardAmountMsat > a.forwardAmountMsat ? b : a
		);
		if (largest.forwardAmountMsat <= feeMsat) {
			return `JIT fee ${feeMsat} msat exceeds the largest held part ${largest.forwardAmountMsat} msat`;
		}
		return null;
	}

	/**
	 * LSPS2 fee deduction: the opening fee comes out of the delivered amount,
	 * taken ONCE from the largest part so the aggregate shortfall equals the
	 * fee the wallet agreed to when it registered the intent.
	 */
	private applyFee(parts: IHeldJitPart[]): void {
		const totalMsat = parts.reduce((s, p) => s + p.forwardAmountMsat, 0n);
		const feeMsat = this.feeMsatFor(totalMsat);
		if (feeMsat <= 0n || parts.length === 0) return;
		const largest = parts.reduce((a, b) =>
			b.forwardAmountMsat > a.forwardAmountMsat ? b : a
		);
		largest.forwardAmountMsat -= feeMsat;
	}

	// ─────────────── Resolution ───────────────

	/** Fail every part held for an intercept scid. The preimage is not involved. */
	private failAllHeld(scidHex: string, failureCode: number): void {
		this.clearAggregation(scidHex);
		const parts = this.heldParts.get(scidHex) ?? [];
		this.heldParts.delete(scidHex);
		this.persistHeld();
		for (const part of parts) {
			part.revoked = true;
			try {
				part.failIncoming(failureCode);
			} catch {
				// best-effort: the channel may already be gone
			}
		}
	}

	private failAllSpliceQueued(channelIdHex: string, failureCode: number): void {
		const parts = this.spliceQueues.get(channelIdHex) ?? [];
		this.spliceQueues.delete(channelIdHex);
		this.persistHeld();
		for (const part of parts) {
			part.revoked = true;
			try {
				part.failIncoming(failureCode);
			} catch {
				// best-effort
			}
		}
	}

	private clearAggregation(scidHex: string): void {
		const t = this.aggregationTimers.get(scidHex);
		if (t) clearTimeout(t);
		this.aggregationTimers.delete(scidHex);
	}

	/**
	 * Drop timers so the engine cannot keep a shutting-down process alive, and
	 * withdraw the outbound zero-conf authorization the intents were lending.
	 */
	destroy(): void {
		this.destroyed = true;
		for (const t of this.aggregationTimers.values()) clearTimeout(t);
		this.aggregationTimers.clear();
		try {
			this.deps.setJitClients([]);
		} catch {
			// teardown is best-effort
		}
	}
}
