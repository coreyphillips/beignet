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
 *  - Fronting is bounded. Every funding, open or splice, spends a registered
 *    intent, and each is bounded by what that intent asked for and by the
 *    engine's caps. Accepting an intent widens nothing but our own outbound
 *    zero-conf authorization for that peer (see `setJitClients`); it never
 *    makes us accept an INBOUND zero-conf channel from them.
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { encodeShortChannelId } from '../gossip/types';
import {
	ChannelFundingUnavailableCode,
	ChannelFundingUnavailableError,
	FundingWaitTimeoutError,
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
	/**
	 * The wallet will accept an HTLC smaller than its onion's amt_to_forward by
	 * the agreed opening fee. Without this the LSP cannot charge one at all:
	 * the fee is skimmed off a forward whose onion the LSP cannot rewrite, and
	 * BOLT 4 makes a final hop fail anything short of amt_to_forward.
	 */
	acceptsSkimmedFee?: boolean;
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

/** Everything through `expirySeconds`; the skim flag byte follows it. */
const AUTHORIZATION_LENGTH = 68;
const AUTHORIZATION_WITH_FLAGS_LENGTH = 69;
const ACK_HEADER_LENGTH = 31;
/** Refusal reasons are ours; a long one is truncated rather than refused. */
const MAX_ACK_REASON_BYTES = 200;

export function encodeJitAuthorization(a: IJitReceiveAuthorization): Buffer {
	if (a.requestId.length !== 8) {
		throw new Error('jit authorization requestId must be 8 bytes');
	}
	const buf = Buffer.alloc(AUTHORIZATION_WITH_FLAGS_LENGTH);
	(a.paymentHash ?? Buffer.alloc(32)).copy(buf, 0);
	a.requestId.copy(buf, 32);
	buf.writeBigUInt64BE(a.maxAmountMsat, 40);
	buf.writeBigUInt64BE(a.expectedTotalMsat ?? 0n, 48);
	buf.writeBigUInt64BE(a.targetRemainingInboundSat, 56);
	buf.writeUInt32BE(a.expirySeconds, 64);
	buf.writeUInt8(a.acceptsSkimmedFee ? 1 : 0, 68);
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
		expirySeconds: data.readUInt32BE(64),
		// A payload that predates the flag byte is a client that never agreed
		// to a skim, which is exactly what its absence means here.
		acceptsSkimmedFee:
			data.length >= AUTHORIZATION_WITH_FLAGS_LENGTH && data.readUInt8(68) === 1
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

// ─────────────── Wire payloads (custom subtypes 4/5, issue #687) ───────────────

/**
 * What a wallet asks before it decides to create an invoice: the price of a
 * just-in-time receive of this size, and whether the LSP would serve it right
 * now. Registers nothing; the same numbers an ack carries, without the SCID.
 */
export interface IJitReceiveQuoteRequest {
	/** Client-chosen correlation id, echoed in the quote. */
	requestId: Buffer;
	/** The receive the wallet has in mind (msat); the cap it would register. */
	maxAmountMsat: bigint;
	/** Inbound liquidity the wallet wants left over after the receive (sat). */
	targetRemainingInboundSat: bigint;
}

export interface IJitReceiveQuote {
	requestId: Buffer;
	/** Whether the LSP would register this intent as things stand. */
	accepted: boolean;
	/** LSPS2-style opening fee the LSP would deduct: flat part (sat). */
	flatFeeSat: bigint;
	/** Proportional part, in parts-per-million of the received total. */
	feePpm: number;
	/** Most the LSP fronts for one client, open or splice (sat). */
	maxClientFundingSats: bigint;
	/** What the LSP would front for this receive (sat); 0 when refused. */
	fundingSats: bigint;
	/** Plain-language refusal, meant to be shown as is. */
	reason?: string;
}

const QUOTE_REQUEST_LENGTH = 24;
const QUOTE_HEADER_LENGTH = 39;

export function encodeJitQuoteRequest(q: IJitReceiveQuoteRequest): Buffer {
	if (q.requestId.length !== 8) {
		throw new Error('jit quote request requestId must be 8 bytes');
	}
	const buf = Buffer.alloc(QUOTE_REQUEST_LENGTH);
	q.requestId.copy(buf, 0);
	buf.writeBigUInt64BE(q.maxAmountMsat, 8);
	buf.writeBigUInt64BE(q.targetRemainingInboundSat, 16);
	return buf;
}

export function decodeJitQuoteRequest(data: Buffer): IJitReceiveQuoteRequest {
	if (data.length < QUOTE_REQUEST_LENGTH) {
		throw new Error('jit quote request too short');
	}
	return {
		requestId: Buffer.from(data.subarray(0, 8)),
		maxAmountMsat: data.readBigUInt64BE(8),
		targetRemainingInboundSat: data.readBigUInt64BE(16)
	};
}

export function encodeJitQuote(q: IJitReceiveQuote): Buffer {
	if (q.requestId.length !== 8) {
		throw new Error('jit quote requestId must be 8 bytes');
	}
	let reason = q.reason ? Buffer.from(q.reason, 'utf8') : Buffer.alloc(0);
	if (reason.length > MAX_ACK_REASON_BYTES) {
		reason = reason.subarray(0, MAX_ACK_REASON_BYTES);
	}
	const buf = Buffer.alloc(QUOTE_HEADER_LENGTH + reason.length);
	q.requestId.copy(buf, 0);
	buf.writeUInt8(q.accepted ? 1 : 0, 8);
	buf.writeBigUInt64BE(q.flatFeeSat, 9);
	buf.writeUInt32BE(q.feePpm >>> 0, 17);
	buf.writeBigUInt64BE(q.maxClientFundingSats, 21);
	buf.writeBigUInt64BE(q.fundingSats, 29);
	buf.writeUInt16BE(reason.length, 37);
	reason.copy(buf, QUOTE_HEADER_LENGTH);
	return buf;
}

export function decodeJitQuote(data: Buffer): IJitReceiveQuote {
	if (data.length < QUOTE_HEADER_LENGTH) throw new Error('jit quote too short');
	const reasonLen = data.readUInt16BE(37);
	// Same rule as the ack: a declared length the buffer cannot supply is a
	// malformed quote, not a short reason.
	if (QUOTE_HEADER_LENGTH + reasonLen > data.length) {
		throw new Error('jit quote reason runs past the payload');
	}
	const result: IJitReceiveQuote = {
		requestId: Buffer.from(data.subarray(0, 8)),
		accepted: data.readUInt8(8) === 1,
		flatFeeSat: data.readBigUInt64BE(9),
		feePpm: data.readUInt32BE(17),
		maxClientFundingSats: data.readBigUInt64BE(21),
		fundingSats: data.readBigUInt64BE(29)
	};
	if (reasonLen > 0) {
		result.reason = data
			.subarray(QUOTE_HEADER_LENGTH, QUOTE_HEADER_LENGTH + reasonLen)
			.toString('utf8');
	}
	return result;
}

/**
 * The LSPS2-style opening fee owed on a delivered total.
 *
 * Both sides run this: the LSP to size the skim it takes off the forward, the
 * wallet to size the shortfall it will accept at its final hop. They have to
 * agree to the msat, so the arithmetic lives in one place rather than being
 * written out twice.
 */
export function jitOpeningFeeMsat(
	totalMsat: bigint,
	quote: { flatFeeSat: bigint; feePpm: number }
): bigint {
	// The quote reaches bigint arithmetic from operator config on one side and
	// from a peer's ack on the other, so a fractional or negative number is
	// normalised here rather than thrown out of BigInt() mid-payment.
	const ppm = BigInt(Math.max(0, Math.floor(quote.feePpm)));
	const flat = quote.flatFeeSat > 0n ? quote.flatFeeSat : 0n;
	return flat * 1000n + (totalMsat * ppm) / 1_000_000n;
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
	/** The client will accept the opening fee skimmed off its payment. */
	acceptsSkimmedFee: boolean;
}

/** A forward held by the engine, plus the engine's own bookkeeping. */
export interface IHeldJitPart extends IForwardablePart {
	/**
	 * The intent this part is being funded against. Both paths spend an
	 * intent: the open path by its intercept SCID, the splice path by the one
	 * matched from the channel's peer.
	 */
	intentScidHex?: string;
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
	/** The peer on the other end of one of our channels. */
	peerForChannel?(outChannelId: Buffer): string | null;
	/** Splice our own funds in and resolve once the channel is usable again. */
	spliceInAndWait?(
		channelId: Buffer,
		amountSats: bigint,
		timeoutMs: number
	): Promise<void>;
	/**
	 * Most the node could front from its on-chain funds right now, priced at
	 * the current feerate (sat), or null when no figure is available (no
	 * funding provider, or a fee estimator that has not delivered a sample
	 * yet). Consulted by a quote only: a funding attempt still learns the
	 * truth from the provider at selection time.
	 */
	maxFundableSats?(): bigint | null;
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
	acceptsSkimmedFee?: boolean;
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
						expiresAt: p.expiresAt,
						acceptsSkimmedFee: p.acceptsSkimmedFee === true
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
			this.safeEmit('jit:restored-failed', { remaining: remaining.length });
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
				expiresAt: i.expiresAt,
				acceptsSkimmedFee: i.acceptsSkimmedFee
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

	/**
	 * Write the hold record, and REPORT whether it landed. Every row in it says
	 * `fail`, so a stale one is an instruction to refund an inbound leg after a
	 * restart: a caller about to forward must know the clearing write happened,
	 * or it can pay downstream for a leg the next boot refunds.
	 */
	private persistHeld(): boolean {
		if (!this.deps.storage) return true;
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
			return true;
		} catch {
			return false;
		}
	}

	/**
	 * Is this inbound HTLC one the engine held before a restart and still owes
	 * a refund? The node asks before re-dispatching a restored HTLC: dispatching
	 * one of these would forward a payment this queue is about to fail upstream.
	 */
	/**
	 * Is this inbound HTLC held by the engine right now (a refused forward it
	 * took for a splice)? A caller that owes the HTLC a failure must not
	 * fail what the engine is about to forward.
	 */
	holdsPart(inChannelIdHex: string, inHtlcId: bigint): boolean {
		for (const parts of this.heldParts.values()) {
			if (
				parts.some(
					(p) =>
						p.inChannelId.toString('hex') === inChannelIdHex &&
						p.inHtlcId === inHtlcId
				)
			) {
				return true;
			}
		}
		return false;
	}

	hasRestoredHold(inChannelIdHex: string, inHtlcId: bigint): boolean {
		const id = inHtlcId.toString();
		return this.restoredToFail.some(
			(p) => p.inChannelIdHex === inChannelIdHex && p.inHtlcId === id
		);
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

	/**
	 * The LSP role as it stands: the fee it charges, the caps that bound what
	 * it fronts, and what is committed right now (issue #668). An operator who
	 * turns the role on can otherwise only guess at the exposure.
	 */
	getStatus(): {
		flatFeeSat: bigint;
		feePpm: number;
		maxClientFundingSats: bigint;
		maxConcurrentFundings: number;
		maxTotalFundingSats: bigint | null;
		maxLiveIntentsPerPeer: number;
		maxLiveIntents: number;
		reservedSats: bigint;
		frontedSats: bigint;
		liveIntents: number;
		heldParts: number;
		fundingsInFlight: number;
	} {
		this.sweepExpiredIntents();
		let held = 0;
		for (const parts of this.heldParts.values()) held += parts.length;
		for (const parts of this.spliceQueues.values()) held += parts.length;
		return {
			flatFeeSat: this.cfg.flatFeeSat,
			feePpm: this.cfg.feePpm,
			maxClientFundingSats: this.cfg.maxClientFundingSats,
			maxConcurrentFundings: this.cfg.maxConcurrentFundings,
			maxTotalFundingSats: this.cfg.maxTotalFundingSats ?? null,
			maxLiveIntentsPerPeer: this.cfg.maxLiveIntentsPerPeer,
			maxLiveIntents: this.cfg.maxLiveIntents,
			reservedSats: this.reservedSats,
			frontedSats: this.frontedSats,
			liveIntents: this.intents.size,
			heldParts: held,
			fundingsInFlight: this.fundingInFlight.size + this.spliceInFlight.size
		};
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
		// A wallet asking again is not another peer: its own earlier intents
		// that nothing has spent against (no held part, no funding running)
		// are the ones it no longer needs, so the oldest of them makes room
		// rather than locking the wallet out until they expire (issue #674).
		// The cap keeps bounding what one peer holds OPEN; only idle intents
		// are ever retired, and only for the peer that is asking.
		let own = [...this.intents.values()].filter(
			(i) => i.walletPubkeyHex === walletPubkeyHex
		);
		while (own.length >= this.cfg.maxLiveIntentsPerPeer) {
			const idle = own
				.filter((i) => this.intentIsIdle(i.interceptScidHex))
				.sort((a, b) => a.expiresAt - b.expiresAt)[0];
			if (!idle) break;
			this.intents.delete(idle.interceptScidHex);
			// Durable and derived state follow at once, whatever this request
			// goes on to decide: a retired intent must not come back on restart.
			this.persistIntents();
			this.refreshJitClients();
			this.safeEmit('jit:intent-superseded', {
				scidHex: idle.interceptScidHex,
				walletPubkeyHex
			});
			own = own.filter((i) => i !== idle);
		}
		if (own.length >= this.cfg.maxLiveIntentsPerPeer) {
			return refuse(
				`at most ${this.cfg.maxLiveIntentsPerPeer} live intents per peer`
			);
		}
		// The opening fee is skimmed off a forward whose onion we cannot
		// rewrite, so a client that will not accept a short HTLC would only
		// fail the payment at its final hop (BOLT 4 final_incorrect_htlc_amount)
		// after we had already funded the channel. Refuse instead of charging
		// into a payment that cannot complete.
		if (this.chargesAnOpeningFee() && auth.acceptsSkimmedFee !== true) {
			return refuse(
				`this LSP deducts an opening fee (${this.cfg.flatFeeSat} sat + ${this.cfg.feePpm} ppm) from the payment; the client must accept a skimmed HTLC`
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
				Date.now() + Math.min(auth.expirySeconds * 1000, this.cfg.intentTtlMs),
			acceptsSkimmedFee: auth.acceptsSkimmedFee === true
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
		this.safeEmit('jit:intent', intent);

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

	/**
	 * Price a receive without registering anything (issue #687). The answer
	 * runs the same admission rules registerIntent applies, then the checks a
	 * funding would hit later (a free funding slot, the lifetime budget, the
	 * on-chain funds to front it), so a wallet learns BEFORE it mints an
	 * invoice whether the payment could be served right now and at what
	 * price. No intent, no SCID, no persistence, no event: asking a price
	 * must not hold anything open.
	 *
	 * The reasons are written to be shown to a person as they are.
	 */
	quote(
		walletPubkeyHex: string,
		req: IJitReceiveQuoteRequest
	): IJitReceiveQuote {
		this.sweepExpiredIntents();
		const base = {
			requestId: req.requestId,
			flatFeeSat: this.cfg.flatFeeSat,
			feePpm: this.cfg.feePpm,
			maxClientFundingSats: this.cfg.maxClientFundingSats
		};
		const refuse = (reason: string): IJitReceiveQuote => ({
			...base,
			accepted: false,
			fundingSats: 0n,
			reason
		});

		if (req.maxAmountMsat <= 0n) {
			return refuse('the amount must be positive');
		}
		const requestedSat = req.maxAmountMsat / 1000n;
		if (requestedSat > this.cfg.maxClientFundingSats) {
			return refuse(
				`the provider funds at most ${this.cfg.maxClientFundingSats} sats for one receive`
			);
		}
		if (this.intents.size >= this.cfg.maxLiveIntents) {
			return refuse(
				'the provider is holding its maximum number of live receive intents'
			);
		}
		// An intent nothing has spent against would make room for a new one
		// (issue #674), so only the ACTIVE ones count against this wallet.
		const active = [...this.intents.values()].filter(
			(i) =>
				i.walletPubkeyHex === walletPubkeyHex &&
				!this.intentIsIdle(i.interceptScidHex)
		);
		if (active.length >= this.cfg.maxLiveIntentsPerPeer) {
			return refuse(
				`the provider is already funding ${active.length} receive(s) for this wallet; wait for one to finish`
			);
		}
		if (!this.fundingSlotsFree()) {
			return refuse(
				'the provider has its maximum number of channel fundings in flight; try again shortly'
			);
		}
		let fundingSats =
			(req.maxAmountMsat + 999n) / 1000n +
			req.targetRemainingInboundSat +
			this.cfg.fundingBufferSats;
		if (fundingSats > this.cfg.maxClientFundingSats) {
			fundingSats = this.cfg.maxClientFundingSats;
		}
		const cap = this.cfg.maxTotalFundingSats;
		if (
			cap !== undefined &&
			this.frontedSats + this.reservedSats + fundingSats > cap
		) {
			return refuse('the provider has reached its lifetime funding budget');
		}
		const fundable = this.deps.maxFundableSats?.() ?? null;
		if (fundable !== null && fundable < fundingSats) {
			return refuse(
				'the provider does not hold enough on-chain funds to front this receive right now'
			);
		}
		return { ...base, accepted: true, fundingSats };
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
			// An intent whose funding is running, or whose parts are held on
			// either path, is still doing its job; its parts are bounded by
			// their own deadline.
			if (this.fundingInFlight.has(scidHex)) continue;
			if ((this.heldParts.get(scidHex)?.length ?? 0) > 0) continue;
			if (this.hasQueuedSpliceParts(scidHex)) continue;
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

		part.intentScidHex = scidHex;
		held.push(part);
		this.heldParts.set(scidHex, held);
		this.persistHeld();
		this.safeEmit('jit:intercepted', {
			scidHex,
			amountMsat: part.forwardAmountMsat
		});

		const newTotal = heldTotal + part.forwardAmountMsat;
		const target = intent.expectedTotalMsat;
		if (target === undefined || newTotal >= target) {
			// Single part, unknown total, or a complete MPP set: fund now.
			this.clearAggregation(scidHex);
			// Nothing in fund() should reject (every arm resolves its parts and
			// reports through safeEmit), but an unhandled rejection would take
			// the process down; the deadline backstop still owns the parts.
			this.fund(intent).catch(() => undefined);
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
		// The parts held for one intercept SCID are ONE payment's set: losing
		// any of them to the deadline means the sender can never complete it, so
		// forwarding the survivors would only park HTLCs on the client's fresh
		// channel until they time out. The whole set goes.
		for (const [scidHex, parts] of [...this.heldParts]) {
			if (!parts.some((p) => this.pastDeadline(p))) continue;
			this.heldParts.delete(scidHex);
			this.clearAggregation(scidHex);
			this.revokeAll(parts, scidHex);
			revoked = true;
		}
		// A splice queue holds unrelated payments to the same channel, so here
		// only the parts actually at their deadline are revoked.
		for (const [key, parts] of [...this.spliceQueues]) {
			const doomed: IHeldJitPart[] = [];
			const survivors: IHeldJitPart[] = [];
			for (const part of parts) {
				(this.pastDeadline(part) ? doomed : survivors).push(part);
			}
			if (doomed.length === 0) continue;
			if (survivors.length > 0) {
				this.spliceQueues.set(key, survivors);
			} else {
				this.spliceQueues.delete(key);
			}
			this.revokeAll(doomed, key);
			revoked = true;
		}
		if (revoked) this.persistHeld();
		this.sweepExpiredIntents();
	}

	/** Mark parts unforwardable for good, then fail them upstream. */
	private revokeAll(parts: IHeldJitPart[], scope: string): void {
		for (const part of parts) {
			this.failPart(part, this.deps.failureCodes.expiryTooSoon);
		}
		this.safeEmit('jit:failed', {
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
		const feeError = this.validateFee(parts, totalMsat, [intent]);
		if (feeError) {
			this.failFunding(scidHex, feeError);
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
			this.failFunding(scidHex, 'cumulative JIT funding cap reached');
			return;
		}

		this.fundingInFlight.add(scidHex);
		let fronted = false;
		try {
			this.safeEmit('jit:funding', { scidHex, fundingSats });
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
				toForward.reduce((s, p) => s + p.forwardAmountMsat, 0n),
				[intent]
			);
			if (lateFeeError) throw new Error(lateFeeError);

			// From here the held set is CONSUMED, so nothing below may leave a
			// part unresolved: the forwards are individually guarded and the
			// intent is retired only once they have all been placed.
			this.heldParts.delete(scidHex);
			this.clearAggregation(scidHex);
			// The clearing write has to land before the forward: while the hold
			// row survives, a restart owes these parts a refund, and refunding
			// an inbound leg we have already paid downstream for is the loss.
			if (!this.persistHeld()) {
				for (const part of toForward) {
					this.failPart(part, this.deps.failureCodes.temporaryChannelFailure);
				}
				this.safeEmit('jit:failed', {
					scidHex,
					reason: 'could not clear the durable hold record'
				});
				return;
			}
			this.applyFee(toForward, [intent]);
			for (const part of toForward) {
				this.forwardOrFail(channelId, part);
			}
			this.intents.delete(scidHex);
			this.persistIntents();
			this.refreshJitClients();
			this.safeEmit('jit:forwarded', { scidHex, parts: toForward.length });
		} catch (err) {
			// A wait timeout is the one failure that leaves the funding LIVE, so
			// its reservation is charged rather than refunded: the channel may
			// still land, and a budget that under-counts is no budget.
			if (err instanceof FundingWaitTimeoutError) fronted = true;
			this.failFunding(
				scidHex,
				err instanceof Error ? err.message : String(err)
			);
		} finally {
			this.releaseFunding(fundingSats, fronted);
			this.fundingInFlight.delete(scidHex);
		}
	}

	// ─────────────── On-the-fly splice (oversized receive) ───────────────

	/**
	 * Called when forwarding onto an EXISTING channel was refused (too little
	 * of our balance on that side, or the channel is mid-splice). When the
	 * channel's peer has a live intent this part fits, hold the part, splice
	 * our own funds in, and retry the forward once. Returns true when held, and
	 * the caller must then NOT fail the HTLC.
	 *
	 * Which path runs is decided by which failure fired: an unknown SCID is a
	 * client with no channel and goes to the zero-conf open above, an addHtlc
	 * refusal on a JIT client's existing channel goes here.
	 *
	 * The intent is the authorization on BOTH paths. Being a JIT client is not
	 * one: it is derived from having any live intent at all, so treating it as
	 * sufficient would let one 1 msat intent spend a splice, of our coins and
	 * our on-chain fees, on every unrelated payment that peer ever receives.
	 */
	tryHoldForSplice(outChannelId: Buffer, part: IHeldJitPart): boolean {
		if (this.destroyed) return false;
		if (!this.deps.peerForChannel || !this.deps.spliceInAndWait) {
			return false;
		}
		if (part.spliceRetried) return false; // one retry only
		if (part.revoked) return false;
		if (this.pastDeadline(part)) return false;
		const peer = this.deps.peerForChannel(outChannelId);
		if (!peer) return false;
		const intent = this.matchIntent(peer, part);
		if (!intent) return false;

		const key = outChannelId.toString('hex');
		if (!this.spliceInFlight.has(key) && !this.fundingSlotsFree()) return false;

		part.intentScidHex = intent.interceptScidHex;
		const queue = this.spliceQueues.get(key) ?? [];
		queue.push(part);
		this.spliceQueues.set(key, queue);
		this.persistHeld();
		this.safeEmit('jit:intercepted', {
			channelIdHex: key,
			amountMsat: part.forwardAmountMsat
		});

		if (!this.spliceInFlight.has(key)) {
			this.spliceAndRetry(outChannelId).catch(() => undefined);
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
		const intents = this.intentsBehind(queued);
		const feeError = this.validateFee(queued, totalMsat, intents);
		if (feeError) {
			this.failSplice(key, feeError);
			return;
		}
		// The inbound the intents asked to be left over comes from the largest
		// ask among them, the way the open path takes it from its one intent.
		const targetInbound = intents.reduce(
			(max, i) =>
				i.targetRemainingInboundSat > max ? i.targetRemainingInboundSat : max,
			0n
		);
		let amountSats =
			(totalMsat + 999n) / 1000n + targetInbound + this.cfg.fundingBufferSats;
		// The same per-client ceiling the open path clamps to, and the same
		// budget: the fork clamped only the open, so a splice could front
		// arbitrarily much.
		if (amountSats > this.cfg.maxClientFundingSats) {
			amountSats = this.cfg.maxClientFundingSats;
		}
		if (!this.reserveFunding(amountSats)) {
			this.failSplice(key, 'cumulative JIT funding cap reached');
			return;
		}

		this.spliceInFlight.add(key);
		let fronted = false;
		try {
			this.safeEmit('jit:funding', {
				channelIdHex: key,
				fundingSats: amountSats
			});
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
			const forwardIntents = this.intentsBehind(toForward);
			const lateFeeError = this.validateFee(
				toForward,
				toForward.reduce((s, p) => s + p.forwardAmountMsat, 0n),
				forwardIntents
			);
			if (lateFeeError) throw new Error(lateFeeError);
			this.spliceQueues.delete(key);
			// Same rule as the open path: no forward while a hold row on disk
			// still tells the next boot to refund these parts.
			if (!this.persistHeld()) {
				for (const part of toForward) {
					this.failPart(part, this.deps.failureCodes.temporaryChannelFailure);
				}
				this.safeEmit('jit:failed', {
					channelIdHex: key,
					reason: 'could not clear the durable hold record'
				});
				return;
			}
			this.applyFee(toForward, forwardIntents);
			for (const part of toForward) {
				part.spliceRetried = true;
				this.forwardOrFail(outChannelId, part);
			}
			// The intents these parts spent are consumed, exactly as the open
			// path consumes the one it funded against.
			for (const intent of forwardIntents) {
				this.intents.delete(intent.interceptScidHex);
			}
			this.persistIntents();
			this.refreshJitClients();
			this.safeEmit('jit:forwarded', {
				channelIdHex: key,
				parts: toForward.length
			});
		} catch (err) {
			// As in fund(): a timeout leaves the splice live, so it is charged.
			if (err instanceof FundingWaitTimeoutError) fronted = true;
			this.failSplice(key, err instanceof Error ? err.message : String(err));
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
				// A timeout says only that the funding did not FINISH. The open
				// or splice it started is still live, and a second attempt would
				// run a duplicate beside it: two channels for one payment, both
				// out of our coins. Every other failure proves the operation is
				// over, which is what makes it safe to retry.
				if (err instanceof FundingWaitTimeoutError) throw err;
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
			this.failPart(part, this.deps.failureCodes.temporaryChannelFailure);
		}
	}

	// ─────────────── Intent matching ───────────────

	/**
	 * The live intent a part arriving on an EXISTING channel may spend, or null.
	 * A hash-bound intent serves only its own payment and is preferred over an
	 * unbound one, and neither serves more than it registered for.
	 */
	private matchIntent(
		walletPubkeyHex: string,
		part: IHeldJitPart
	): IJitIntent | null {
		const now = Date.now();
		const hashHex = part.paymentHash.toString('hex');
		const fits = (intent: IJitIntent): boolean =>
			this.claimedAgainst(intent.interceptScidHex) + part.forwardAmountMsat <=
			intent.maxAmountMsat;
		const candidates = [...this.intents.values()].filter(
			(i) => i.walletPubkeyHex === walletPubkeyHex && i.expiresAt > now
		);
		return (
			candidates.find((i) => i.paymentHashHex === hashHex && fits(i)) ??
			candidates.find((i) => i.paymentHashHex === undefined && fits(i)) ??
			null
		);
	}

	/** Nothing held, queued or funding against this intent: safe to retire. */
	private intentIsIdle(scidHex: string): boolean {
		if (this.fundingInFlight.has(scidHex)) return false;
		if ((this.heldParts.get(scidHex) ?? []).length > 0) return false;
		return this.claimedAgainst(scidHex) === 0n;
	}

	/** Msat already spending against one intent, on either path. */
	private claimedAgainst(scidHex: string): bigint {
		let claimed = this.heldTotalMsat(scidHex);
		for (const parts of this.spliceQueues.values()) {
			for (const p of parts) {
				if (p.intentScidHex === scidHex) claimed += p.forwardAmountMsat;
			}
		}
		return claimed;
	}

	/** Is a splice queue holding parts that spend this intent? */
	private hasQueuedSpliceParts(scidHex: string): boolean {
		for (const parts of this.spliceQueues.values()) {
			if (parts.some((p) => p.intentScidHex === scidHex)) return true;
		}
		return false;
	}

	/** The live intents a set of parts is spending against. */
	private intentsBehind(parts: IHeldJitPart[]): IJitIntent[] {
		const seen = new Set<string>();
		const intents: IJitIntent[] = [];
		for (const part of parts) {
			if (!part.intentScidHex || seen.has(part.intentScidHex)) continue;
			seen.add(part.intentScidHex);
			const intent = this.intents.get(part.intentScidHex);
			if (intent) intents.push(intent);
		}
		return intents;
	}

	// ─────────────── Opening fee ───────────────

	/** Is an opening fee configured at all? */
	private chargesAnOpeningFee(): boolean {
		return this.cfg.flatFeeSat > 0n || Math.floor(this.cfg.feePpm) > 0;
	}

	/**
	 * The fee these parts owe. Zero unless every intent behind them accepted a
	 * skimmed HTLC: the deduction shrinks a forward whose onion still names the
	 * original amount, and BOLT 4 has the final hop fail anything short of it
	 * (final_incorrect_htlc_amount), so skimming at a client that did not agree
	 * would only destroy the payment after we had funded the channel.
	 */
	private feeMsatFor(totalMsat: bigint, intents: IJitIntent[]): bigint {
		if (intents.length === 0 || !intents.every((i) => i.acceptsSkimmedFee)) {
			return 0n;
		}
		return jitOpeningFeeMsat(totalMsat, {
			flatFeeSat: this.cfg.flatFeeSat,
			feePpm: this.cfg.feePpm
		});
	}

	/** Null when the opening fee can be taken out of these parts. */
	private validateFee(
		parts: IHeldJitPart[],
		totalMsat: bigint,
		intents: IJitIntent[]
	): string | null {
		const feeMsat = this.feeMsatFor(totalMsat, intents);
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
	private applyFee(parts: IHeldJitPart[], intents: IJitIntent[]): void {
		const totalMsat = parts.reduce((s, p) => s + p.forwardAmountMsat, 0n);
		const feeMsat = this.feeMsatFor(totalMsat, intents);
		if (feeMsat <= 0n || parts.length === 0) return;
		const largest = parts.reduce((a, b) =>
			b.forwardAmountMsat > a.forwardAmountMsat ? b : a
		);
		largest.forwardAmountMsat -= feeMsat;
	}

	// ─────────────── Resolution ───────────────

	/**
	 * Resolve a funding's parts and then report it. Resolution comes FIRST on
	 * every arm: a throwing observer must never be what stops a held HTLC from
	 * being failed back.
	 */
	private failFunding(scidHex: string, reason: string): void {
		this.failAllHeld(scidHex, this.deps.failureCodes.temporaryChannelFailure);
		this.safeEmit('jit:failed', { scidHex, reason });
	}

	private failSplice(channelIdHex: string, reason: string): void {
		this.failAllSpliceQueued(
			channelIdHex,
			this.deps.failureCodes.temporaryChannelFailure
		);
		this.safeEmit('jit:failed', { channelIdHex, reason });
	}

	/**
	 * Fail ONE part upstream, and keep owing it when the channel could not
	 * carry the failure. A held part is failed long after it arrived, so the
	 * inbound channel may be reestablishing by then, and the in-memory hold is
	 * already gone: without this the refund would simply vanish and the sender
	 * would wait out the CLTV. The part joins the durable queue the restart
	 * path drains, which retries on every block until it lands.
	 */
	private failPart(part: IHeldJitPart, failureCode: number): void {
		part.revoked = true;
		let delivered = false;
		try {
			delivered = part.failIncoming(failureCode);
		} catch {
			delivered = false;
		}
		if (!delivered) this.owedUpstreamFailure(part);
	}

	/**
	 * Take ownership of a refund the caller could not deliver: the part is
	 * queued durably and retried on every block until its inbound channel can
	 * carry the failure. The node calls this for a JIT part whose forward was
	 * refused at the same moment its inbound channel went away.
	 */
	owedUpstreamFailure(part: IHeldJitPart): void {
		const owed = JitReceiveManager.persistedShape(part);
		if (this.hasRestoredHold(owed.inChannelIdHex, part.inHtlcId)) return;
		this.restoredToFail.push(owed);
		this.persistHeld();
	}

	/** Fail every part held for an intercept scid. The preimage is not involved. */
	private failAllHeld(scidHex: string, failureCode: number): void {
		this.clearAggregation(scidHex);
		const parts = this.heldParts.get(scidHex) ?? [];
		this.heldParts.delete(scidHex);
		this.persistHeld();
		for (const part of parts) this.failPart(part, failureCode);
	}

	private failAllSpliceQueued(channelIdHex: string, failureCode: number): void {
		const parts = this.spliceQueues.get(channelIdHex) ?? [];
		this.spliceQueues.delete(channelIdHex);
		this.persistHeld();
		for (const part of parts) this.failPart(part, failureCode);
	}

	/** An observer's failure must never take a hold down with it. */
	private safeEmit(event: string, payload: unknown): void {
		try {
			this.emit(event, payload);
		} catch {
			// deliberately swallowed; see the method comment
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
