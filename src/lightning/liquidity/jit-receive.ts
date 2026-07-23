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
	/** LSPS2-style opening fee the LSP will deduct: flat part (sat). */
	flatFeeSat: bigint;
	/** Proportional part in parts-per-million of the received total. */
	feePpm: number;
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
	const buf = Buffer.alloc(8 + 1 + 8 + 4 + 2 + reason.length);
	a.interceptScid.copy(buf, 0);
	buf.writeUInt8(a.accepted ? 1 : 0, 8);
	buf.writeBigUInt64BE(a.flatFeeSat, 9);
	buf.writeUInt32BE(a.feePpm >>> 0, 17);
	buf.writeUInt16BE(reason.length, 21);
	reason.copy(buf, 23);
	return buf;
}

export function decodeJitAck(data: Buffer): IJitReceiveAck {
	if (data.length < 23) throw new Error('jit ack too short');
	const reasonLen = data.readUInt16BE(21);
	const result: IJitReceiveAck = {
		interceptScid: Buffer.from(data.subarray(0, 8)),
		accepted: data.readUInt8(8) === 1,
		flatFeeSat: data.readBigUInt64BE(9),
		feePpm: data.readUInt32BE(17)
	};
	if (reasonLen > 0) {
		result.reason = data.subarray(23, 23 + reasonLen).toString('utf8');
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
	/** LSPS2-style opening fee, flat part in sats (default 0 — free). */
	flatFeeSat?: bigint;
	/** LSPS2-style opening fee, proportional part in ppm (default 0). */
	feePpm?: number;
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
	/**
	 * Durable KV for intents and held-HTLC metadata (the node's storage
	 * backend). Without it the manager runs in-memory as before.
	 */
	storage?: {
		saveMetadata(key: string, value: string): void;
		loadMetadata(key: string): string | null;
	};
	/**
	 * Fail an incoming HTLC that was held BEFORE a restart, upstream and
	 * off-chain. Returns true when the failure was delivered; false to retry
	 * later (e.g. the channel has not reestablished yet).
	 */
	failRestoredHtlc?(inChannelIdHex: string, inHtlcId: bigint): boolean;
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

/** Persisted metadata of a held HTLC — enough to fail it after a restart. */
interface IPersistedHeldPart {
	inChannelIdHex: string;
	inHtlcId: string;
}

const STORAGE_KEY_INTENTS = 'jit:intents';
const STORAGE_KEY_HELD = 'jit:held';

const DEFAULTS = {
	maxClientFundingSats: 1_000_000n,
	fundingBufferSats: 10_000n,
	intentTtlMs: 10 * 60 * 1000,
	aggregationTimeoutMs: 60_000,
	minCltvDeltaBlocks: 40,
	flatFeeSat: 0n,
	feePpm: 0,
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
			flatFeeSat: config.flatFeeSat ?? DEFAULTS.flatFeeSat,
			feePpm: config.feePpm ?? DEFAULTS.feePpm,
			openTimeoutMs: DEFAULTS.openTimeoutMs
		};
	}

	// Held HTLCs from BEFORE a restart, queued to be failed upstream cleanly
	// (resuming a half-done funding flow is not attempted).
	private restoredToFail: IPersistedHeldPart[] = [];

	/**
	 * Restore persisted state after a restart: live intents come back (their
	 * invoices remain payable), and every pre-restart held HTLC is queued to
	 * be failed upstream as soon as its channel reestablishes — a fast, clean
	 * upstream failure instead of a dangling HTLC that rides to its CLTV.
	 * Call once after the node's own storage restore; then sweep() drives the
	 * fail queue (retried from the block tick).
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
				this.restoredToFail = JSON.parse(heldJson) as IPersistedHeldPart[];
			}
		} catch {
			// Corrupt persisted state: run in-memory rather than crash the node.
		}
		this.sweep();
	}

	/**
	 * Drive the restored-HTLC fail queue (invoked from restore and the node's
	 * block tick). Successfully failed entries leave durable storage; the
	 * rest are retried on the next sweep.
	 */
	sweep(): void {
		if (this.restoredToFail.length === 0 || !this.deps.failRestoredHtlc) {
			return;
		}
		const remaining: IPersistedHeldPart[] = [];
		for (const part of this.restoredToFail) {
			let failed = false;
			try {
				failed = this.deps.failRestoredHtlc(
					part.inChannelIdHex,
					BigInt(part.inHtlcId)
				);
			} catch {
				failed = false;
			}
			if (!failed) remaining.push(part);
		}
		if (remaining.length !== this.restoredToFail.length) {
			this.restoredToFail = remaining;
			this.deps.storage?.saveMetadata(
				STORAGE_KEY_HELD,
				JSON.stringify([...remaining, ...this.livePersistedHeld()])
			);
			this.emit('jit:restored-failed', {
				remaining: remaining.length
			});
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

	/** Metadata of every currently live held part (both hold mechanisms). */
	private livePersistedHeld(): IPersistedHeldPart[] {
		const list: IPersistedHeldPart[] = [];
		const collect = (parts: IHeldJitPart[]): void => {
			for (const p of parts) {
				list.push({
					inChannelIdHex: p.inChannelId.toString('hex'),
					inHtlcId: p.inHtlcId.toString()
				});
			}
		};
		for (const parts of this.heldParts.values()) collect(parts);
		for (const parts of this.spliceQueues.values()) collect(parts);
		return list;
	}

	private persistHeld(): void {
		if (!this.deps.storage) return;
		try {
			this.deps.storage.saveMetadata(
				STORAGE_KEY_HELD,
				JSON.stringify([...this.restoredToFail, ...this.livePersistedHeld()])
			);
		} catch {
			// best-effort persistence
		}
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
				feePpm: 0,
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
		this.persistIntents();
		this.emit('jit:intent', intent);
		// LSPS2-style opening fee, deducted from the forwarded amount. The
		// wallet registers the matching allowance so its final-hop checks
		// accept the shortfall.
		return {
			interceptScid: auth.interceptScid,
			accepted: true,
			flatFeeSat: this.cfg.flatFeeSat,
			feePpm: this.cfg.feePpm
		};
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
			this.persistIntents();
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
		this.persistHeld();
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

			// Retry transient funding blips, mirroring the splice path below:
			// right after another funding broadcast our spendable coins can be
			// momentarily gone (previous UTXO pledged/spent, change not yet
			// indexed). A held HTLC must not die on that window.
			let channelId: Buffer | undefined;
			let openErr: unknown;
			for (let attempt = 0; attempt < 6 && !channelId; attempt++) {
				try {
					channelId = await this.deps.openZeroConfChannelAndWait(
						intent.walletPubkeyHex,
						fundingSats,
						this.cfg.openTimeoutMs
					);
				} catch (e) {
					openErr = e;
					const msg = e instanceof Error ? e.message : String(e);
					// Only retry the transient no-spendable-coins cases (coins
					// pledged to another funding, change not yet indexed); a real
					// error (peer gone, params invalid) fails fast.
					if (
						!/insufficient wallet funds|spendable|not enough funds|no inputs specified/i.test(
							msg
						)
					) {
						throw e;
					}
					await new Promise((r) => setTimeout(r, 2_000));
				}
			}
			if (!channelId) throw openErr;

			// Forward every held part; settle/fail flows through the normal
			// forwarded-HTLC bookkeeping from here on.
			const toForward = this.heldParts.get(scidHex) ?? [];
			this.heldParts.delete(scidHex);
			this.intents.delete(scidHex);
			this.persistHeld();
			this.persistIntents();
			// LSPS2 fee deduction: our opening fee comes out of the delivered
			// amount (deducted from the largest part). The wallet agreed to
			// this bound when it registered the intent.
			const feeMsat =
				this.cfg.flatFeeSat * 1000n +
				(totalMsat * BigInt(this.cfg.feePpm)) / 1_000_000n;
			if (feeMsat > 0n && toForward.length > 0) {
				const largest = toForward.reduce((a, b) =>
					b.forwardAmountMsat > a.forwardAmountMsat ? b : a
				);
				if (largest.forwardAmountMsat <= feeMsat) {
					throw new Error('JIT fee exceeds the largest held part');
				}
				largest.forwardAmountMsat -= feeMsat;
			}
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
		this.persistHeld();
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

			// Retry transient funding blips: right after a zero-conf open the
			// LSP's own change UTXO can be momentarily absent from its wallet
			// (input spent, change not yet indexed), so selectSpliceInputs sees
			// no coins. A held HTLC must not die on that window — retry a few
			// times before giving up.
			let lastErr: unknown;
			let funded = false;
			for (let attempt = 0; attempt < 6 && !funded; attempt++) {
				try {
					await this.deps.spliceInAndWait!(
						outChannelId,
						amountSats,
						this.cfg.openTimeoutMs
					);
					funded = true;
				} catch (e) {
					lastErr = e;
					const msg = e instanceof Error ? e.message : String(e);
					// Only retry the transient "no spendable coins yet" cases; a
					// real error (channel gone, amount invalid) fails fast.
					if (
						!/insufficient wallet funds|spendable|not enough funds|no inputs specified/i.test(
							msg
						)
					) {
						throw e;
					}
					await new Promise((r) => setTimeout(r, 2_000));
				}
			}
			if (!funded) throw lastErr;

			const toForward = this.spliceQueues.get(key) ?? [];
			this.spliceQueues.delete(key);
			this.persistHeld();
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
			this.persistHeld();
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
		this.persistHeld();
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
