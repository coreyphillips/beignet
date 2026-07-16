/**
 * Beignet JIT channel receive (LSPS2-inspired, beignet-flavored).
 *
 * A wallet with no channel (or too little inbound) registers a receive intent
 * with its liquidity peer over a custom message, embeds the returned
 * synthetic "intercept SCID" as a routing hint in its invoice, and the peer
 * turns the incoming HTLC into a zero-conf channel open + forward:
 *
 *   wallet                          LSP
 *     │ JIT_RECEIVE_AUTHORIZATION    │   (interceptScid, caps)
 *     ├─────────────────────────────>│
 *     │<──── JIT_RECEIVE_ACK ────────┤
 *     │  invoice hint: LSP→scid      │
 *     │                              │  HTLC for unknown scid arrives
 *     │                              │  → intent found → HOLD
 *     │<══ zero-conf channel open ═══┤
 *     │<──── forwarded HTLC ─────────┤
 *     │  settle                      │
 *
 * Trust model (LSPS2-like): the LSP takes the funding risk (its own zero-conf
 * open); the wallet verifies the channel before settling, and the preimage is
 * never revealed unless the wallet actually receives the HTLC. All state is
 * in-memory (POC): an LSP crash fails the upstream HTLCs via reestablish/CLTV
 * timeout — a failed payment, never lost funds.
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';

// ─────────────── Wire payloads (custom subtypes 1/2) ───────────────

export interface IJitReceiveAuthorization {
	/** Payment hash the intent binds to (optional; zeros = unbound). */
	paymentHash?: Buffer;
	/** The synthetic SCID the wallet will embed in its invoice hint. */
	interceptScid: Buffer;
	/** Hard cap the LSP may hold/fund against (msat). */
	maxAmountMsat: bigint;
	/** Expected invoice total when known (fixed-amount invoices; 0=unknown). */
	expectedTotalMsat?: bigint;
	/** Inbound liquidity the wallet wants left over after the receive (sat). */
	targetRemainingInboundSat: bigint;
	expirySeconds: number;
}

export interface IJitReceiveAck {
	interceptScid: Buffer;
	accepted: boolean;
	flatFeeSat: bigint;
	reason?: string;
}

export function encodeJitAuthorization(a: IJitReceiveAuthorization): Buffer {
	const buf = Buffer.alloc(32 + 8 + 8 + 8 + 8 + 4);
	(a.paymentHash ?? Buffer.alloc(32)).copy(buf, 0);
	a.interceptScid.copy(buf, 32);
	buf.writeBigUInt64BE(a.maxAmountMsat, 40);
	buf.writeBigUInt64BE(a.expectedTotalMsat ?? 0n, 48);
	buf.writeBigUInt64BE(a.targetRemainingInboundSat, 56);
	buf.writeUInt32BE(a.expirySeconds, 64);
	return buf;
}

export function decodeJitAuthorization(data: Buffer): IJitReceiveAuthorization {
	if (data.length < 68) throw new Error('jit authorization too short');
	const paymentHash = data.subarray(0, 32);
	const expectedTotal = data.readBigUInt64BE(48);
	const result: IJitReceiveAuthorization = {
		interceptScid: Buffer.from(data.subarray(32, 40)),
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
	const reason = a.reason ? Buffer.from(a.reason, 'utf8') : Buffer.alloc(0);
	const buf = Buffer.alloc(8 + 1 + 8 + 2 + reason.length);
	a.interceptScid.copy(buf, 0);
	buf.writeUInt8(a.accepted ? 1 : 0, 8);
	buf.writeBigUInt64BE(a.flatFeeSat, 9);
	buf.writeUInt16BE(reason.length, 17);
	reason.copy(buf, 19);
	return buf;
}

export function decodeJitAck(data: Buffer): IJitReceiveAck {
	if (data.length < 19) throw new Error('jit ack too short');
	const reasonLen = data.readUInt16BE(17);
	const result: IJitReceiveAck = {
		interceptScid: Buffer.from(data.subarray(0, 8)),
		accepted: data.readUInt8(8) === 1,
		flatFeeSat: data.readBigUInt64BE(9)
	};
	if (reasonLen > 0) {
		result.reason = data.subarray(19, 19 + reasonLen).toString('utf8');
	}
	return result;
}

export function allocateInterceptScid(): Buffer {
	return crypto.randomBytes(8);
}

// ─────────────── LSP-side manager ───────────────

export interface IJitReceiveConfig {
	enabled: boolean;
	/** Cap on LSP funding per intent (sat). Default 1_000_000. */
	maxClientFundingSats?: bigint;
	/** Reserve/fee headroom added to the funded amount (sat). Default 10_000. */
	fundingBufferSats?: bigint;
	/** Intent lifetime. Default 10 minutes. */
	intentTtlMs?: number;
	/** How long held MPP parts wait for the rest. Default 60s. */
	aggregationTimeoutMs?: number;
	/** Minimum CLTV cushion (blocks) an intercepted HTLC must leave. Default 40. */
	minCltvDeltaBlocks?: number;
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

/** Everything needed to forward (or fail) a held HTLC part later. */
export interface IHeldJitPart {
	inChannelId: Buffer;
	inHtlcId: bigint;
	paymentHash: Buffer;
	forwardAmountMsat: bigint;
	forwardCltv: number;
	incomingCltvExpiry: number;
	nextPacket: {
		version: number;
		ephemeralKey: Buffer;
		routingInfo: Buffer;
		hmac: Buffer;
	};
	nextBlindingPoint?: Buffer;
	failIncoming: (failureCode: number) => void;
	/** Set once a splice retry has been attempted — the second failure is final. */
	spliceRetried?: boolean;
}

export interface IJitManagerDeps {
	/** Open a zero-conf channel and resolve with its channelId when usable. */
	openZeroConfChannelAndWait(
		walletPubkeyHex: string,
		fundingSats: bigint,
		timeoutMs: number
	): Promise<Buffer>;
	/** Forward a previously held part onto a (new) channel. */
	forwardOnto(outChannelId: Buffer, part: IHeldJitPart): void;
	getBlockHeight(): number;
	/** BOLT 4 failure code used when failing parts upstream. */
	failureCodes: { unknownNextPeer: number; temporaryChannelFailure: number };
	/** On-the-fly splice: is this channel's peer a trusted JIT client? */
	isJitClientChannel?(outChannelId: Buffer): boolean;
	/** Splice own funds into the channel and resolve once usable again. */
	spliceInAndWait?(
		channelId: Buffer,
		amountSats: bigint,
		timeoutMs: number
	): Promise<void>;
}

const DEFAULTS = {
	maxClientFundingSats: 1_000_000n,
	fundingBufferSats: 10_000n,
	intentTtlMs: 10 * 60 * 1000,
	aggregationTimeoutMs: 60_000,
	minCltvDeltaBlocks: 40,
	openTimeoutMs: 120_000
};

/**
 * LSP-side JIT engine: holds HTLCs addressed to registered intercept SCIDs,
 * funds a zero-conf channel to the wallet, then forwards the held parts.
 * In-memory only (see module docs).
 */
export class JitReceiveManager extends EventEmitter {
	private intents = new Map<string, IJitIntent>();
	private heldParts = new Map<string, IHeldJitPart[]>();
	private aggregationTimers = new Map<string, NodeJS.Timeout>();
	private fundingInFlight = new Set<string>();
	private readonly cfg: Required<Omit<IJitReceiveConfig, 'enabled'>> & {
		openTimeoutMs: number;
	};

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
			openTimeoutMs: DEFAULTS.openTimeoutMs
		};
	}

	/** Register a wallet's receive intent. Returns the ack to send back. */
	registerIntent(
		walletPubkeyHex: string,
		auth: IJitReceiveAuthorization
	): IJitReceiveAck {
		const scidHex = auth.interceptScid.toString('hex');
		const requestedSat = auth.maxAmountMsat / 1000n;
		if (requestedSat > this.cfg.maxClientFundingSats) {
			return {
				interceptScid: auth.interceptScid,
				accepted: false,
				flatFeeSat: 0n,
				reason: `max fundable is ${this.cfg.maxClientFundingSats} sats`
			};
		}
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
		this.emit('jit:intent', intent);
		// POC fee model: free (we run both sides).
		return { interceptScid: auth.interceptScid, accepted: true, flatFeeSat: 0n };
	}

	/**
	 * Called from the forwarding path when the outgoing SCID is unknown.
	 * Returns true when the HTLC was intercepted and held (caller must NOT
	 * fail it); false to fall through to the normal unknown-peer failure.
	 */
	tryInterceptUnknownScid(scidHex: string, part: IHeldJitPart): boolean {
		const intent = this.intents.get(scidHex);
		if (!intent) return false;
		if (Date.now() > intent.expiresAt) {
			this.intents.delete(scidHex);
			return false;
		}
		// Payment-hash binding, when the wallet provided one.
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
		// Cap: everything held so far + this part must stay within the intent.
		const held = this.heldParts.get(scidHex) ?? [];
		const heldTotal = held.reduce((s, p) => s + p.forwardAmountMsat, 0n);
		if (heldTotal + part.forwardAmountMsat > intent.maxAmountMsat) {
			return false;
		}

		held.push(part);
		this.heldParts.set(scidHex, held);
		this.emit('jit:intercepted', {
			scidHex,
			amountMsat: part.forwardAmountMsat
		});

		const newTotal = heldTotal + part.forwardAmountMsat;
		const target = intent.expectedTotalMsat;
		if (target === undefined || newTotal >= target) {
			// Single-part / unknown-total / MPP complete: fund now.
			this.clearAggregation(scidHex);
			void this.fund(intent);
		} else if (!this.aggregationTimers.has(scidHex)) {
			// MPP: wait (bounded) for the remaining parts.
			const t = setTimeout(() => {
				this.failAll(scidHex, this.deps.failureCodes.temporaryChannelFailure);
			}, this.cfg.aggregationTimeoutMs);
			t.unref?.();
			this.aggregationTimers.set(scidHex, t);
		}
		return true;
	}

	/** Total msat currently held for an intercept scid (visibility/tests). */
	heldTotalMsat(scidHex: string): bigint {
		return (this.heldParts.get(scidHex) ?? []).reduce(
			(s, p) => s + p.forwardAmountMsat,
			0n
		);
	}

	private async fund(intent: IJitIntent): Promise<void> {
		const scidHex = intent.interceptScidHex;
		if (this.fundingInFlight.has(scidHex)) return;
		this.fundingInFlight.add(scidHex);
		try {
			const parts = this.heldParts.get(scidHex) ?? [];
			const totalMsat = parts.reduce((s, p) => s + p.forwardAmountMsat, 0n);
			const totalSat = (totalMsat + 999n) / 1000n;
			let fundingSats =
				totalSat + intent.targetRemainingInboundSat + this.cfg.fundingBufferSats;
			if (fundingSats > this.cfg.maxClientFundingSats) {
				fundingSats = this.cfg.maxClientFundingSats;
			}
			this.emit('jit:funding', { scidHex, fundingSats });

			const channelId = await this.deps.openZeroConfChannelAndWait(
				intent.walletPubkeyHex,
				fundingSats,
				this.cfg.openTimeoutMs
			);

			// Forward every held part; settle/fail flows through the normal
			// forwarded-HTLC bookkeeping from here on.
			const toForward = this.heldParts.get(scidHex) ?? [];
			this.heldParts.delete(scidHex);
			this.intents.delete(scidHex);
			for (const part of toForward) {
				this.deps.forwardOnto(channelId, part);
			}
			this.emit('jit:forwarded', { scidHex, parts: toForward.length });
		} catch (err) {
			this.emit('jit:failed', {
				scidHex,
				reason: err instanceof Error ? err.message : String(err)
			});
			this.failAll(scidHex, this.deps.failureCodes.temporaryChannelFailure);
		} finally {
			this.fundingInFlight.delete(scidHex);
		}
	}

	// ─────────────── On-the-fly splice (oversized receive) ───────────────

	/** Parts waiting for an in-flight splice, per outgoing channel. */
	private spliceQueues = new Map<string, IHeldJitPart[]>();
	private spliceInFlight = new Set<string>();

	/**
	 * Called when forwarding onto an EXISTING channel failed (insufficient
	 * LSP-side balance, or the channel is mid-splice). When the peer is a
	 * trusted JIT client, hold the part, splice our own funds in, and retry.
	 * Returns true when held (caller must NOT fail the HTLC).
	 */
	tryHoldForSplice(outChannelId: Buffer, part: IHeldJitPart): boolean {
		if (!this.deps.isJitClientChannel || !this.deps.spliceInAndWait) {
			return false;
		}
		if (part.spliceRetried) return false; // one retry only
		if (!this.deps.isJitClientChannel(outChannelId)) return false;

		const key = outChannelId.toString('hex');
		const queue = this.spliceQueues.get(key) ?? [];
		queue.push(part);
		this.spliceQueues.set(key, queue);
		this.emit('jit:intercepted', {
			scidHex: key,
			amountMsat: part.forwardAmountMsat
		});

		if (!this.spliceInFlight.has(key)) {
			void this.spliceAndRetry(outChannelId);
		}
		return true;
	}

	private async spliceAndRetry(outChannelId: Buffer): Promise<void> {
		const key = outChannelId.toString('hex');
		this.spliceInFlight.add(key);
		try {
			// Fund the whole queue plus the standard buffer. Never start a second
			// competing splice: parts arriving mid-splice join the queue and are
			// forwarded together after this one locks (arch §12).
			const queued = this.spliceQueues.get(key) ?? [];
			const totalMsat = queued.reduce((s, p) => s + p.forwardAmountMsat, 0n);
			const amountSats =
				(totalMsat + 999n) / 1000n + this.cfg.fundingBufferSats;
			this.emit('jit:funding', { scidHex: key, fundingSats: amountSats });

			await this.deps.spliceInAndWait!(
				outChannelId,
				amountSats,
				this.cfg.openTimeoutMs
			);

			const toForward = this.spliceQueues.get(key) ?? [];
			this.spliceQueues.delete(key);
			for (const part of toForward) {
				part.spliceRetried = true;
				this.deps.forwardOnto(outChannelId, part);
			}
			this.emit('jit:forwarded', { scidHex: key, parts: toForward.length });
		} catch (err) {
			this.emit('jit:failed', {
				scidHex: key,
				reason: err instanceof Error ? err.message : String(err)
			});
			const parts = this.spliceQueues.get(key) ?? [];
			this.spliceQueues.delete(key);
			for (const part of parts) {
				try {
					part.failIncoming(this.deps.failureCodes.temporaryChannelFailure);
				} catch {
					// best-effort
				}
			}
		} finally {
			this.spliceInFlight.delete(key);
		}
	}

	/** Fail every held part upstream. The preimage was never involved. */
	private failAll(scidHex: string, failureCode: number): void {
		this.clearAggregation(scidHex);
		const parts = this.heldParts.get(scidHex) ?? [];
		this.heldParts.delete(scidHex);
		for (const part of parts) {
			try {
				part.failIncoming(failureCode);
			} catch {
				// best-effort: the channel may already be gone
			}
		}
	}

	private clearAggregation(scidHex: string): void {
		const t = this.aggregationTimers.get(scidHex);
		if (t) clearTimeout(t);
		this.aggregationTimers.delete(scidHex);
	}
}
