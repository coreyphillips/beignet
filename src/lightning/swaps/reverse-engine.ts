/**
 * Reverse swap provider (issue #737): a client pays this node a hold
 * invoice, this node funds a P2WSH contract the client claims on chain, and
 * the claim reveals the preimage that settles the hold.
 *
 * The engine owns no chain or Lightning code of its own. It takes a deps
 * object of closures into the node (hold invoices, the held snapshot, the
 * funding provider, the chain resolver, key derivation) and a ledger, and
 * every transition is persisted BEFORE the external action it licenses:
 *
 *   CREATED            record inserted, then the hold invoice minted
 *   HELD               the COMPLETE committed set admitted (never one part)
 *   FUNDING            attempt counted, then the funding transaction built,
 *                      then its bytes recorded; a row with bytes never
 *                      builds a second transaction
 *   FUNDING_BROADCAST  broadcast acknowledged; inputs re-pledged per block
 *   FUNDED             funding confirmed to policy depth
 *   CLAIMED            a claim spend with a verified preimage, at any depth,
 *                      recorded with the preimage; only then settleHeld
 *   SETTLED            the hold released against that preimage
 *   REFUND_PENDING     refund built and recorded, then broadcast; bumped by
 *                      rebuild while unconfirmed
 *   REFUNDED           refund confirmed to policy depth; ONLY THEN the hold
 *                      is cancelled
 *   EXPOSED            the node's own sweeper cancelled the hold while our
 *                      coins were on chain: keep watching, refund recovers
 *                      the coins, a late claim still records its preimage
 *
 * Rules the engine never breaks: a hold is never cancelled because the refund
 * height passed or a refund was broadcast; a claim beats a pending refund; a
 * preimage from any source is retained; the funding transaction is never
 * fee-bumped (the wallet's coin selection made it, and a replacement would
 * race a client already claiming).
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../crypto/ecdh';
import { decode as decodeInvoice } from '../invoice/decode';
import { BeignetCustomSubtype } from '../message/custom';
import type {
	IDfCustomMessage,
	IDfPeerMessaging
} from '../direct-funding/transport/types';
import type { IHeldInvoiceSnapshot } from '../node/types';
import { buildSwapHtlc, ISwapHtlc } from './htlc';
import { buildSwapRefundTx } from './transactions';
import { validateReverseSwapAdmission } from './policy';
import { deriveSwapId } from './keys';
import {
	ISwapRecord,
	ISwapResolutionRecord,
	SwapLedger,
	SwapState,
	isTerminalSwapState
} from './ledger';
import {
	ISwapChainObservation,
	ISwapSpendObservation,
	SwapChainResolver
} from './chain-resolver';
import {
	ISwapExposurePolicy,
	SwapExposureRefusal,
	evaluateSwapExposure,
	validateSwapExposurePolicy
} from './exposure';
import {
	ISwapCreate,
	ISwapCreateAck,
	ISwapQuote,
	ISwapQuoteRequest,
	ISwapStatus,
	ISwapStatusRequest,
	SWAP_MAX_FUNDING_TX_BYTES,
	SwapMessageError,
	SwapRefusalReason,
	SwapWireDirection,
	SwapWireResolutionKind,
	SwapWireState,
	decodeSwapCreate,
	decodeSwapQuoteRequest,
	decodeSwapStatusRequest,
	encodeSwapCreateAck,
	encodeSwapQuote,
	encodeSwapStatus
} from './messages';
import { reverseSwapFee } from './client';

export interface IReverseSwapProviderConfig {
	flatFeeSat: bigint;
	feePpm: number;
	exposure: ISwapExposurePolicy;
	/** Blocks from create to the contract's refund height. */
	refundDeltaBlocks: number;
	minRefundDeltaBlocks: number;
	maxRefundDeltaBlocks: number;
	fundingConfirmations: number;
	resolutionConfirmations: number;
	/** Admission margins (see validateReverseSwapAdmission). */
	fundingSafetyBlocks: number;
	resolutionSafetyBlocks: number;
	/** The node's actual early hold-cancel margin. */
	holdCancelSafetyBlocks: number;
	invoiceExpirySeconds: number;
	maxFeeRateSatPerVbyte: number;
	fundingFeeTargetBlocks: number;
	refundFeeTargetBlocks: number;
	/** Blocks an unconfirmed refund waits before a rebuild at a higher fee. */
	refundBumpIntervalBlocks: number;
	/** Funding BUILD attempts, not broadcasts. */
	maxFundingAttempts: number;
	maxCreatedPerPeer: number;
	fundingVbytesEstimate: number;
	refundVbytesEstimate: number;
}

export const REVERSE_SWAP_DEFAULTS: Omit<
	IReverseSwapProviderConfig,
	'exposure' | 'holdCancelSafetyBlocks'
> = {
	flatFeeSat: 0n,
	feePpm: 0,
	refundDeltaBlocks: 144,
	minRefundDeltaBlocks: 72,
	maxRefundDeltaBlocks: 288,
	fundingConfirmations: 1,
	resolutionConfirmations: 3,
	fundingSafetyBlocks: 12,
	resolutionSafetyBlocks: 24,
	invoiceExpirySeconds: 1800,
	maxFeeRateSatPerVbyte: 200,
	fundingFeeTargetBlocks: 6,
	refundFeeTargetBlocks: 6,
	refundBumpIntervalBlocks: 2,
	maxFundingAttempts: 3,
	maxCreatedPerPeer: 4,
	fundingVbytesEstimate: 200,
	refundVbytesEstimate: 160
};

export const REVERSE_SWAP_DEFAULT_EXPOSURE: ISwapExposurePolicy = {
	minSwapSat: 10_000n,
	maxSwapSat: 1_000_000n,
	maxTotalExposureSat: 5_000_000n,
	maxConcurrentSwaps: 8,
	feeReserveSat: 50_000n,
	fundingFeeRateCeilingSatPerVbyte: 200
};

export interface IReverseSwapProviderDeps {
	peers: IDfPeerMessaging;
	ledger: SwapLedger;
	resolver: SwapChainResolver;
	createHoldInvoice(options: {
		paymentHash: Buffer;
		amountMsat: bigint;
		expirySeconds: number;
		minFinalCltvExpiry: number;
		description: string;
	}): { bolt11: string };
	heldSnapshot(paymentHash: Buffer): IHeldInvoiceSnapshot | null;
	/**
	 * True when the node already has ANY record under this hash: an
	 * invoice, a payment it is sending or has sent, a parked hold. Minting
	 * a hold invoice on such a hash would overwrite that record (a payment
	 * we are sending would read as an unpaid incoming one), so a create on
	 * it is refused as a duplicate before anything is written.
	 */
	hashInUse?(paymentHash: Buffer): boolean;
	/** True when parked parts were released against the preimage. */
	settleHeld(paymentHash: Buffer, preimage: Buffer): boolean;
	/** Idempotent; a closed hash is not an error. */
	cancelHold(paymentHash: Buffer): void;
	onHeld(cb: (event: { paymentHash: Buffer }) => void): () => void;
	onHoldCancelled(
		cb: (event: { paymentHash: Buffer; reason: string }) => void
	): () => void;
	/** Build and sign, never broadcast, a transaction paying the address. */
	fundOutput(
		address: string,
		amountSat: bigint,
		feeRateSatPerVbyte: number
	): Promise<{ txHex: string; txid: Buffer; vout: number }>;
	broadcast(txHex: string): Promise<string>;
	pledge?(txHex: string): Promise<void> | void;
	releasePledges?(txHex: string): Promise<void> | void;
	/** sat/vB, or null when no estimate is available. */
	estimateFee(targetBlocks: number): Promise<number | null>;
	currentHeight(): number;
	deriveRefundKey(swapId: Buffer): Buffer;
	refundDestinationScript(): Buffer;
	network: bitcoin.Network;
	networkName: ISwapRecord['network'];
	now?(): number;
	log(action: string, data: Record<string, unknown>): void;
}

export interface IReverseSwapStatus {
	enabled: true;
	fee: { flatFeeSat: string; feePpm: number };
	limits: {
		minSwapSat: string;
		maxSwapSat: string;
		maxTotalExposureSat: string;
		maxConcurrentSwaps: number;
	};
	timeouts: {
		refundDeltaBlocks: number;
		fundingConfirmations: number;
		resolutionConfirmations: number;
	};
	counts: Record<string, number>;
	exposedSat: string;
	exposedCount: number;
}

type SwapEventName =
	| 'swap:created'
	| 'swap:held'
	| 'swap:funding'
	| 'swap:funded'
	| 'swap:claimed'
	| 'swap:settled'
	| 'swap:refund-broadcast'
	| 'swap:refunded'
	| 'swap:hold-cancelled'
	| 'swap:exposed'
	| 'swap:failed';

export const REVERSE_SWAP_EVENTS: readonly SwapEventName[] = [
	'swap:created',
	'swap:held',
	'swap:funding',
	'swap:funded',
	'swap:claimed',
	'swap:settled',
	'swap:refund-broadcast',
	'swap:refunded',
	'swap:hold-cancelled',
	'swap:exposed',
	'swap:failed'
];

const CLAIMABLE_STATES: readonly SwapState[] = [
	'FUNDING_BROADCAST',
	'FUNDED',
	'REFUND_PENDING'
];
const WATCHED_STATES: readonly SwapState[] = [
	'FUNDING_BROADCAST',
	'FUNDED',
	'REFUND_PENDING',
	'CLAIMED',
	'EXPOSED'
];
const DUST_FLOOR_SAT = 330n;
/** Padding past the admission inequality so any pay height satisfies it. */
const HOLD_CLTV_PADDING = 8;

function exposureRefusal(reason: SwapExposureRefusal): SwapRefusalReason {
	switch (reason) {
		case 'below-min':
			return SwapRefusalReason.AMOUNT_BELOW_MIN;
		case 'above-max':
			return SwapRefusalReason.AMOUNT_ABOVE_MAX;
		case 'exposure':
		case 'concurrency':
			return SwapRefusalReason.EXPOSURE_EXCEEDED;
		case 'fee-rate':
			return SwapRefusalReason.CHAIN_UNAVAILABLE;
		case 'insufficient-balance':
			return SwapRefusalReason.INSUFFICIENT_FUNDS;
	}
}

function wireState(state: SwapState): SwapWireState {
	switch (state) {
		case 'CREATED':
			return SwapWireState.CREATED;
		case 'HELD':
			return SwapWireState.HELD;
		case 'FUNDING':
		case 'FUNDING_BROADCAST':
			return SwapWireState.FUNDING;
		case 'FUNDED':
			return SwapWireState.FUNDED;
		case 'CLAIMED':
			return SwapWireState.CLAIMED;
		case 'SETTLED':
			return SwapWireState.SETTLED;
		case 'REFUND_PENDING':
			return SwapWireState.REFUND_PENDING;
		case 'REFUNDED':
			return SwapWireState.REFUNDED;
		case 'EXPOSED':
			return SwapWireState.EXPOSED;
		case 'CANCELLED':
			return SwapWireState.CANCELLED;
		case 'FAILED':
			return SwapWireState.FAILED;
		default:
			return SwapWireState.UNKNOWN;
	}
}

function wireResolution(
	kind: ISwapResolutionRecord['kind']
): SwapWireResolutionKind {
	switch (kind) {
		case 'claim':
			return SwapWireResolutionKind.CLAIM;
		case 'refund':
			return SwapWireResolutionKind.REFUND;
		default:
			return SwapWireResolutionKind.UNKNOWN;
	}
}

function htlcOf(record: ISwapRecord): ISwapHtlc {
	return {
		paymentHash: Buffer.from(record.paymentHashHex, 'hex'),
		claimPublicKey: Buffer.from(record.claimPubkeyHex, 'hex'),
		refundPublicKey: Buffer.from(record.refundPubkeyHex, 'hex'),
		refundHeight: record.refundHeight
	};
}

export class ReverseSwapProvider extends EventEmitter {
	readonly config: IReverseSwapProviderConfig;
	private readonly unsubscribe: Array<() => void> = [];
	private queue: Promise<void> = Promise.resolve();
	private stopped = false;

	constructor(
		private readonly deps: IReverseSwapProviderDeps,
		config: Partial<IReverseSwapProviderConfig> & {
			holdCancelSafetyBlocks: number;
		}
	) {
		super();
		this.config = {
			...REVERSE_SWAP_DEFAULTS,
			exposure: REVERSE_SWAP_DEFAULT_EXPOSURE,
			...config
		};
		validateSwapExposurePolicy(this.config.exposure);
		if (
			this.config.minRefundDeltaBlocks < 1 ||
			this.config.refundDeltaBlocks < this.config.minRefundDeltaBlocks ||
			this.config.maxRefundDeltaBlocks < this.config.refundDeltaBlocks
		) {
			throw new Error('refund deltas must satisfy 1 <= min <= default <= max');
		}
		if (
			this.config.refundDeltaBlocks <=
			this.config.fundingSafetyBlocks + this.config.resolutionSafetyBlocks
		) {
			throw new Error(
				'refundDeltaBlocks must exceed the funding and resolution margins'
			);
		}
		// Subscribed at construction so nothing between construction and
		// start() is missed; every handler contains its own errors because
		// the node runs all custom-message listeners in one try/catch.
		this.unsubscribe.push(
			deps.peers.onCustomMessage((msg) => this.onMessage(msg)),
			deps.onHeld((e) => {
				void this.enqueue(() => this.onHeld(e.paymentHash));
			}),
			deps.onHoldCancelled((e) => {
				void this.enqueue(() => this.onHoldCancelled(e.paymentHash, e.reason));
			})
		);
	}

	/** Redo every owed action from the rehydrated ledger, once. */
	async start(): Promise<void> {
		await this.enqueue(async () => {
			for (const record of this.deps.ledger.unresolved()) {
				await this.processRecord(record.id, 'start');
			}
			for (const record of this.deps.ledger.list()) {
				if (record.state === 'REFUNDED' && !record.holdCancelledAt) {
					this.cancelHoldFor(record.id, 'refund_confirmed');
				}
			}
		});
	}

	stop(): void {
		this.stopped = true;
		for (const off of this.unsubscribe) off();
		this.unsubscribe.length = 0;
	}

	/** Per-block work; ticks are serialized and never overlap. */
	onBlock(height: number): Promise<void> {
		return this.enqueue(async () => {
			for (const record of this.deps.ledger.unresolved()) {
				await this.processRecord(record.id, `block ${height}`);
			}
		});
	}

	list(): ISwapRecord[] {
		return this.deps.ledger.list();
	}

	get(swapIdHex: string): ISwapRecord | undefined {
		return this.deps.ledger.get(swapIdHex);
	}

	status(): IReverseSwapStatus {
		const counts: Record<string, number> = {};
		for (const r of this.deps.ledger.list()) {
			counts[r.state] = (counts[r.state] ?? 0) + 1;
		}
		const summary = SwapLedger.exposure(this.deps.ledger.list());
		return {
			enabled: true,
			fee: {
				flatFeeSat: this.config.flatFeeSat.toString(),
				feePpm: this.config.feePpm
			},
			limits: {
				minSwapSat: this.config.exposure.minSwapSat.toString(),
				maxSwapSat: this.config.exposure.maxSwapSat.toString(),
				maxTotalExposureSat:
					this.config.exposure.maxTotalExposureSat.toString(),
				maxConcurrentSwaps: this.config.exposure.maxConcurrentSwaps
			},
			timeouts: {
				refundDeltaBlocks: this.config.refundDeltaBlocks,
				fundingConfirmations: this.config.fundingConfirmations,
				resolutionConfirmations: this.config.resolutionConfirmations
			},
			counts,
			exposedSat: summary.exposedSat.toString(),
			exposedCount: summary.exposedCount
		};
	}

	/** Rows whose transaction is owed to the network, for a drain gate. */
	inFlightFundings(): number {
		return this.deps.ledger
			.list()
			.filter(
				(r) =>
					r.state === 'FUNDING' ||
					r.state === 'FUNDING_BROADCAST' ||
					r.state === 'REFUND_PENDING'
			).length;
	}

	/** Operator cancel: only before any funds moved. */
	cancel(swapIdHex: string): { ok: boolean; reason?: string } {
		const record = this.deps.ledger.get(swapIdHex);
		if (!record) return { ok: false, reason: 'unknown swap' };
		if (record.state !== 'CREATED' && record.state !== 'HELD') {
			return { ok: false, reason: `swap is ${record.state}` };
		}
		const moved = this.deps.ledger.move(swapIdHex, 'CANCELLED', {
			failureReason: 'operator cancel'
		});
		if (moved.outcome !== 'applied') {
			return { ok: false, reason: `ledger ${moved.outcome}` };
		}
		this.cancelHoldFor(swapIdHex, 'operator');
		this.emitSwap('swap:hold-cancelled', moved.record!, { reason: 'operator' });
		return { ok: true };
	}

	// ─────────────── wire ───────────────

	private onMessage(msg: IDfCustomMessage): void {
		let work: Promise<void> | undefined;
		try {
			switch (msg.subtype) {
				case BeignetCustomSubtype.SWAP_QUOTE_REQUEST:
					work = this.handleQuote(
						msg.peerPubkey,
						decodeSwapQuoteRequest(msg.payload)
					);
					break;
				case BeignetCustomSubtype.SWAP_CREATE: {
					const create = decodeSwapCreate(msg.payload);
					work = this.enqueue(() => this.handleCreate(msg.peerPubkey, create));
					break;
				}
				case BeignetCustomSubtype.SWAP_STATUS_REQUEST:
					this.handleStatus(
						msg.peerPubkey,
						decodeSwapStatusRequest(msg.payload)
					);
					break;
				default:
					return;
			}
		} catch (err) {
			this.deps.log('swap_message_malformed', {
				peer: msg.peerPubkey,
				subtype: msg.subtype,
				error: err instanceof SwapMessageError ? err.message : String(err)
			});
			return;
		}
		work?.catch((err) =>
			this.deps.log('swap_handler_failed', {
				peer: msg.peerPubkey,
				subtype: msg.subtype,
				error: err instanceof Error ? err.message : String(err)
			})
		);
	}

	private send(peer: string, subtype: number, payload: Buffer): void {
		try {
			this.deps.peers.sendCustomMessage(peer, subtype, payload);
		} catch (err) {
			this.deps.log('swap_send_failed', {
				peer,
				subtype,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	private async quoteFee(amountSat: bigint): Promise<{
		feeRate: number;
		minerFeeSat: bigint;
		totalFeeSat: bigint;
	} | null> {
		const feeRate = await this.safeEstimate(this.config.fundingFeeTargetBlocks);
		if (feeRate === null) return null;
		const minerFeeSat = BigInt(
			Math.ceil(feeRate * this.config.fundingVbytesEstimate)
		);
		const totalFeeSat = reverseSwapFee(amountSat, {
			flatFeeSat: this.config.flatFeeSat,
			feePpm: this.config.feePpm,
			minerFeeSat
		});
		return { feeRate, minerFeeSat, totalFeeSat };
	}

	private async safeEstimate(targetBlocks: number): Promise<number | null> {
		try {
			const rate = await this.deps.estimateFee(targetBlocks);
			if (rate === null || !(rate > 0)) return null;
			return Math.min(rate, this.config.maxFeeRateSatPerVbyte);
		} catch {
			return null;
		}
	}

	private refundDelta(preferred: number | undefined): number {
		if (preferred === undefined) return this.config.refundDeltaBlocks;
		return Math.min(
			this.config.maxRefundDeltaBlocks,
			Math.max(this.config.minRefundDeltaBlocks, preferred)
		);
	}

	private async handleQuote(
		peer: string,
		req: ISwapQuoteRequest
	): Promise<void> {
		const base: ISwapQuote = {
			requestId: req.requestId,
			direction: req.direction,
			accepted: false,
			reason: SwapRefusalReason.NONE,
			flatFeeSat: this.config.flatFeeSat,
			feePpm: this.config.feePpm,
			minSwapSat: this.config.exposure.minSwapSat,
			maxSwapSat: this.config.exposure.maxSwapSat,
			refundDeltaBlocks: this.refundDelta(req.preferredRefundDelta),
			fundingConfirmations: this.config.fundingConfirmations,
			invoiceExpirySeconds: this.config.invoiceExpirySeconds,
			currentHeight: Math.max(0, this.deps.currentHeight()),
			totalFeeSat: 0n,
			minerFeeSat: 0n,
			invoiceAmountMsat: 0n,
			minRefundDelta: this.config.minRefundDeltaBlocks,
			maxRefundDelta: this.config.maxRefundDeltaBlocks
		};
		const refuse = (reason: SwapRefusalReason, reasonText: string): void => {
			this.send(
				peer,
				BeignetCustomSubtype.SWAP_QUOTE,
				encodeSwapQuote({ ...base, reason, reasonText })
			);
		};
		if (req.direction !== SwapWireDirection.REVERSE) {
			return refuse(
				SwapRefusalReason.UNSUPPORTED_DIRECTION,
				'only reverse swaps'
			);
		}
		if (this.stopped)
			return refuse(SwapRefusalReason.DISABLED, 'provider stopped');
		if (req.amountSat === 0n) {
			this.send(
				peer,
				BeignetCustomSubtype.SWAP_QUOTE,
				encodeSwapQuote({ ...base, accepted: true })
			);
			return;
		}
		const destinationProblem = this.refundDestinationProblem();
		if (destinationProblem) {
			return refuse(SwapRefusalReason.INTERNAL, destinationProblem);
		}
		const fee = await this.quoteFee(req.amountSat);
		if (!fee)
			return refuse(SwapRefusalReason.CHAIN_UNAVAILABLE, 'no fee estimate');
		const verdict = evaluateSwapExposure(this.config.exposure, {
			direction: 'reverse',
			amountSat: req.amountSat,
			estimatedFundingFeeSat: fee.minerFeeSat,
			feeRateSatPerVbyte: fee.feeRate,
			live: this.deps.ledger.unresolved()
		});
		if (!verdict.ok)
			return refuse(exposureRefusal(verdict.reason), verdict.detail);
		this.send(
			peer,
			BeignetCustomSubtype.SWAP_QUOTE,
			encodeSwapQuote({
				...base,
				accepted: true,
				totalFeeSat: fee.totalFeeSat,
				minerFeeSat: fee.minerFeeSat,
				invoiceAmountMsat: (req.amountSat + fee.totalFeeSat) * 1000n
			})
		);
	}

	private async handleCreate(peer: string, req: ISwapCreate): Promise<void> {
		const refuse = (reason: SwapRefusalReason, reasonText: string): void => {
			this.deps.log('swap_create_refused', {
				peer,
				reason: SwapRefusalReason[reason],
				reasonText
			});
			this.send(
				peer,
				BeignetCustomSubtype.SWAP_CREATE_ACK,
				encodeSwapCreateAck({
					requestId: req.requestId,
					accepted: false,
					paymentHash: req.paymentHash,
					reason,
					reasonText
				})
			);
		};
		if (this.stopped)
			return refuse(SwapRefusalReason.DISABLED, 'provider stopped');
		if (req.direction !== SwapWireDirection.REVERSE) {
			return refuse(
				SwapRefusalReason.UNSUPPORTED_DIRECTION,
				'only reverse swaps'
			);
		}
		const height = this.deps.currentHeight();
		if (!(height > 0))
			return refuse(SwapRefusalReason.CHAIN_UNAVAILABLE, 'height unknown');

		const peerId = Buffer.from(peer, 'hex');
		const swapId = deriveSwapId(peerId, req.paymentHash);
		const swapIdHex = swapId.toString('hex');
		const hashHex = req.paymentHash.toString('hex');

		// Idempotent repeat from the same peer with the same terms: re-send
		// the stored ack. Anything else on this hash is a duplicate.
		const existing = this.deps.ledger.get(swapIdHex);
		if (existing) {
			if (
				existing.claimPubkeyHex === req.claimPubkey.toString('hex') &&
				existing.onchainSat === req.onchainAmountSat.toString() &&
				existing.bolt11 &&
				!isTerminalSwapState(existing.state)
			) {
				this.send(
					peer,
					BeignetCustomSubtype.SWAP_CREATE_ACK,
					encodeSwapCreateAck(this.ackFor(req.requestId, existing))
				);
				return;
			}
			return refuse(
				SwapRefusalReason.DUPLICATE_HASH,
				'a swap already exists for this hash'
			);
		}
		if (
			this.deps.ledger.byPaymentHash(hashHex).length > 0 ||
			this.deps.heldSnapshot(req.paymentHash) ||
			this.deps.hashInUse?.(req.paymentHash)
		) {
			return refuse(
				SwapRefusalReason.DUPLICATE_HASH,
				'this hash is already in use'
			);
		}
		const destinationProblem = this.refundDestinationProblem();
		if (destinationProblem) {
			return refuse(SwapRefusalReason.INTERNAL, destinationProblem);
		}
		const createdByPeer = this.deps.ledger
			.list()
			.filter((r) => r.peerNodeIdHex === peer && r.state === 'CREATED').length;
		if (createdByPeer >= this.config.maxCreatedPerPeer) {
			return refuse(SwapRefusalReason.RATE_LIMITED, 'too many unpaid swaps');
		}
		const fee = await this.quoteFee(req.onchainAmountSat);
		if (!fee)
			return refuse(SwapRefusalReason.CHAIN_UNAVAILABLE, 'no fee estimate');
		if (fee.totalFeeSat > req.maxTotalFeeSat) {
			return refuse(
				SwapRefusalReason.FEE_CEILING,
				`fee ${fee.totalFeeSat} sat exceeds the client ceiling`
			);
		}
		const verdict = evaluateSwapExposure(this.config.exposure, {
			direction: 'reverse',
			amountSat: req.onchainAmountSat,
			estimatedFundingFeeSat: fee.minerFeeSat,
			feeRateSatPerVbyte: fee.feeRate,
			live: this.deps.ledger.unresolved()
		});
		if (!verdict.ok)
			return refuse(exposureRefusal(verdict.reason), verdict.detail);

		const refundHeight = height + this.refundDelta(req.preferredRefundDelta);
		const refundPubkey = getPublicKey(this.deps.deriveRefundKey(swapId));
		const htlc: ISwapHtlc = {
			paymentHash: req.paymentHash,
			claimPublicKey: req.claimPubkey,
			refundPublicKey: refundPubkey,
			refundHeight
		};
		let contract: ReturnType<typeof buildSwapHtlc>;
		try {
			contract = buildSwapHtlc(htlc, this.deps.network);
		} catch (err) {
			return refuse(
				SwapRefusalReason.INVALID_KEY,
				err instanceof Error ? err.message : String(err)
			);
		}
		const invoiceMsat = (req.onchainAmountSat + fee.totalFeeSat) * 1000n;

		// Persist BEFORE the hold invoice exists: a crash between the two
		// leaves a CREATED row without bolt11, which start() fails and cleans.
		const inserted = this.deps.ledger.insert({
			id: swapIdHex,
			direction: 'reverse',
			peerNodeIdHex: peer,
			paymentHashHex: hashHex,
			claimPubkeyHex: req.claimPubkey.toString('hex'),
			refundPubkeyHex: refundPubkey.toString('hex'),
			refundHeight,
			outputScriptHex: contract.outputScript.toString('hex'),
			address: contract.address,
			network: this.deps.networkName,
			onchainSat: req.onchainAmountSat.toString(),
			invoiceMsat: invoiceMsat.toString(),
			totalFeeSat: fee.totalFeeSat.toString(),
			minerFeeSat: fee.minerFeeSat.toString(),
			createdAt: this.now(),
			createdHeight: height
		});
		if (inserted.outcome !== 'applied') {
			return refuse(SwapRefusalReason.INTERNAL, `ledger ${inserted.outcome}`);
		}
		let bolt11: string;
		let invoiceExpiresAt: number;
		try {
			const minFinalCltvExpiry =
				this.config.refundDeltaBlocks +
				this.config.resolutionSafetyBlocks +
				this.config.holdCancelSafetyBlocks +
				HOLD_CLTV_PADDING;
			bolt11 = this.deps.createHoldInvoice({
				paymentHash: req.paymentHash,
				amountMsat: invoiceMsat,
				expirySeconds: this.config.invoiceExpirySeconds,
				minFinalCltvExpiry,
				description: `reverse swap ${swapIdHex}`
			}).bolt11;
			const decoded = decodeInvoice(bolt11);
			invoiceExpiresAt =
				decoded.timestamp +
				(decoded.expiry ?? this.config.invoiceExpirySeconds);
		} catch (err) {
			this.deps.ledger.move(swapIdHex, 'FAILED', {
				failureReason: `hold invoice: ${
					err instanceof Error ? err.message : String(err)
				}`
			});
			return refuse(
				SwapRefusalReason.INTERNAL,
				'could not create the hold invoice'
			);
		}
		const patched = this.deps.ledger.patch(swapIdHex, {
			bolt11,
			invoiceExpiresAt
		});
		if (patched.outcome !== 'applied') {
			this.deps.cancelHold(req.paymentHash);
			this.deps.ledger.move(swapIdHex, 'FAILED', {
				failureReason: `ledger ${patched.outcome}`
			});
			return refuse(SwapRefusalReason.INTERNAL, 'could not record the invoice');
		}
		const record = patched.record!;
		this.send(
			peer,
			BeignetCustomSubtype.SWAP_CREATE_ACK,
			encodeSwapCreateAck(this.ackFor(req.requestId, record))
		);
		this.emitSwap('swap:created', record);
	}

	private ackFor(requestId: Buffer, record: ISwapRecord): ISwapCreateAck {
		return {
			requestId,
			accepted: true,
			paymentHash: Buffer.from(record.paymentHashHex, 'hex'),
			reason: SwapRefusalReason.NONE,
			terms: {
				swapId: Buffer.from(record.id, 'hex'),
				bolt11: record.bolt11!,
				refundPubkey: Buffer.from(record.refundPubkeyHex, 'hex'),
				refundHeight: record.refundHeight,
				outputScript: Buffer.from(record.outputScriptHex, 'hex'),
				address: record.address,
				invoiceAmountMsat: BigInt(record.invoiceMsat),
				onchainAmountSat: BigInt(record.onchainSat),
				totalFeeSat: BigInt(record.totalFeeSat),
				minerFeeSat: BigInt(record.minerFeeSat),
				fundingConfirmations: this.config.fundingConfirmations,
				invoiceExpiresAt: record.invoiceExpiresAt ?? 0,
				currentHeight: Math.max(0, this.deps.currentHeight())
			}
		};
	}

	private handleStatus(peer: string, req: ISwapStatusRequest): void {
		const swapIdHex = req.swapId.toString('hex');
		const record = this.deps.ledger.get(swapIdHex);
		const height = Math.max(0, this.deps.currentHeight());
		let status: ISwapStatus = {
			requestId: req.requestId,
			swapId: req.swapId,
			found: false,
			state: SwapWireState.UNKNOWN,
			currentHeight: height
		};
		if (record && record.peerNodeIdHex === peer) {
			const fundingTx =
				record.fundingTxHex &&
				record.fundingTxHex.length / 2 <= SWAP_MAX_FUNDING_TX_BYTES
					? Buffer.from(record.fundingTxHex, 'hex')
					: undefined;
			status = {
				...status,
				found: true,
				state: wireState(record.state),
				refundHeight: record.refundHeight,
				fundingTxid: record.fundingTxid
					? Buffer.from(record.fundingTxid, 'hex')
					: undefined,
				fundingVout: record.fundingTxid ? record.fundingVout : undefined,
				fundingHeight: record.fundingTxid
					? record.fundingHeight ?? 0
					: undefined,
				fundingConfirmations: record.fundingHeight
					? Math.max(0, height - record.fundingHeight + 1)
					: undefined,
				fundingTx: record.state === 'FUNDING' ? undefined : fundingTx,
				resolutionTxid: record.resolution
					? Buffer.from(record.resolution.txid, 'hex')
					: undefined,
				resolutionKind: record.resolution
					? wireResolution(record.resolution.kind)
					: undefined,
				resolutionHeight: record.resolution?.height,
				resolutionConfirmations: record.resolution?.confirmations
			};
		}
		this.send(peer, BeignetCustomSubtype.SWAP_STATUS, encodeSwapStatus(status));
	}

	// ─────────────── lifecycle ───────────────

	private enqueue(work: () => Promise<void> | void): Promise<void> {
		const run = this.queue.then(async () => {
			try {
				await work();
			} catch (err) {
				this.deps.log('swap_work_failed', {
					error: err instanceof Error ? err.message : String(err)
				});
			}
		});
		this.queue = run;
		return run;
	}

	private now(): number {
		return this.deps.now ? this.deps.now() : Date.now();
	}

	private async onHeld(paymentHash: Buffer): Promise<void> {
		for (const record of this.deps.ledger.byPaymentHash(
			paymentHash.toString('hex')
		)) {
			if (record.state === 'CREATED')
				await this.processRecord(record.id, 'held');
		}
	}

	private onHoldCancelled(paymentHash: Buffer, reason: string): void {
		for (const record of this.deps.ledger.byPaymentHash(
			paymentHash.toString('hex')
		)) {
			if (isTerminalSwapState(record.state) || record.holdCancelledAt) continue;
			const patch = { holdCancelledAt: this.now(), holdCancelReason: reason };
			switch (record.state) {
				case 'CREATED':
				case 'HELD': {
					const moved = this.deps.ledger.move(record.id, 'CANCELLED', {
						...patch,
						failureReason: `hold cancelled (${reason})`
					});
					if (moved.outcome === 'applied')
						this.emitSwap('swap:hold-cancelled', moved.record!, { reason });
					break;
				}
				case 'FUNDING': {
					if (record.fundingTxHex) {
						// Signed bytes exist, and a broadcast that threw may
						// still have propagated: treat them as out. The row
						// stays watched (a claim records its preimage, the
						// refund recovers the coins) and its inputs stay
						// pledged, so the wallet cannot double spend a funding
						// that may be in the mempool.
						const moved = this.deps.ledger.move(record.id, 'EXPOSED', patch);
						if (moved.outcome === 'applied') {
							this.deps.log('swap_exposed', {
								swapId: record.id,
								previousState: record.state,
								reason,
								onchainSat: record.onchainSat
							});
							this.emitSwap('swap:exposed', moved.record!, {
								reason,
								previousState: record.state
							});
						}
						break;
					}
					// No bytes were ever built: nothing left the wallet.
					const moved = this.deps.ledger.move(record.id, 'FAILED', {
						...patch,
						failureReason: `hold cancelled before broadcast (${reason})`
					});
					if (moved.outcome === 'applied') {
						this.emitSwap('swap:failed', moved.record!, {
							reason: moved.record!.failureReason
						});
					}
					break;
				}
				default: {
					const moved = this.deps.ledger.move(record.id, 'EXPOSED', patch);
					if (moved.outcome === 'applied') {
						this.deps.log('swap_exposed', {
							swapId: record.id,
							previousState: record.state,
							reason,
							onchainSat: record.onchainSat
						});
						this.emitSwap('swap:exposed', moved.record!, {
							reason,
							previousState: record.state
						});
					}
				}
			}
		}
	}

	private async release(txHex: string): Promise<void> {
		try {
			await this.deps.releasePledges?.(txHex);
		} catch (err) {
			this.deps.log('swap_release_failed', {
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	private cancelHoldFor(swapIdHex: string, why: string): void {
		const record = this.deps.ledger.get(swapIdHex);
		if (!record) return;
		try {
			this.deps.cancelHold(Buffer.from(record.paymentHashHex, 'hex'));
		} catch (err) {
			this.deps.log('swap_cancel_hold_failed', {
				swapId: swapIdHex,
				error: err instanceof Error ? err.message : String(err)
			});
			return;
		}
		if (!record.holdCancelledAt) {
			this.deps.ledger.patch(swapIdHex, {
				holdCancelledAt: this.now(),
				holdCancelReason: why
			});
		}
	}

	/** One pass over one record: whatever its state owes, done once. */
	private async processRecord(
		swapIdHex: string,
		trigger: string
	): Promise<void> {
		if (this.stopped) return;
		const record = this.deps.ledger.get(swapIdHex);
		if (!record || record.direction !== 'reverse') return;
		try {
			switch (record.state) {
				case 'CREATED':
					await this.processCreated(record);
					return;
				case 'HELD':
					await this.processFunding(record);
					return;
				case 'FUNDING':
					await this.processFunding(record);
					return;
				default:
					if (WATCHED_STATES.includes(record.state))
						await this.processWatched(record);
			}
		} catch (err) {
			this.deps.log('swap_process_failed', {
				swapId: swapIdHex,
				state: record.state,
				trigger,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	private async processCreated(record: ISwapRecord): Promise<void> {
		if (!record.bolt11) {
			// Crashed between the insert and the invoice.
			const moved = this.deps.ledger.move(record.id, 'FAILED', {
				failureReason: 'no hold invoice was recorded'
			});
			if (moved.outcome === 'applied') {
				this.cancelHoldFor(record.id, 'no_invoice');
				this.emitSwap('swap:failed', moved.record!, {
					reason: moved.record!.failureReason
				});
			}
			return;
		}
		const paymentHash = Buffer.from(record.paymentHashHex, 'hex');
		const snapshot = this.deps.heldSnapshot(paymentHash);
		if (!snapshot || !snapshot.complete) {
			if (snapshot && snapshot.parts.length > 0) {
				this.deps.log('swap_partial_hold', {
					swapId: record.id,
					committedMsat: snapshot.committedMsat.toString(),
					expectedMsat: record.invoiceMsat
				});
			}
			if (
				record.invoiceExpiresAt !== undefined &&
				this.now() > record.invoiceExpiresAt * 1000 &&
				(!snapshot || snapshot.parts.length === 0)
			) {
				const moved = this.deps.ledger.move(record.id, 'CANCELLED', {
					failureReason: 'invoice expired unpaid'
				});
				if (moved.outcome === 'applied') {
					this.cancelHoldFor(record.id, 'invoice_expired');
					this.emitSwap('swap:hold-cancelled', moved.record!, {
						reason: 'invoice_expired'
					});
				}
			}
			return;
		}
		const height = this.deps.currentHeight();
		const refusal = this.admissionProblem(record, snapshot, height);
		if (refusal) {
			const moved = this.deps.ledger.move(record.id, 'CANCELLED', {
				failureReason: refusal
			});
			if (moved.outcome === 'applied') {
				this.cancelHoldFor(record.id, 'admission_refused');
				this.deps.log('swap_admission_refused', {
					swapId: record.id,
					reason: refusal
				});
				this.emitSwap('swap:failed', moved.record!, { reason: refusal });
			}
			return;
		}
		const held = this.deps.ledger.move(record.id, 'HELD', {
			heldAt: this.now(),
			heldHeight: height,
			cancellationHeight: snapshot.cancelHeight ?? undefined
		});
		if (held.outcome !== 'applied') return;
		this.emitSwap('swap:held', held.record!);
		await this.processFunding(held.record!);
	}

	private admissionProblem(
		record: ISwapRecord,
		snapshot: IHeldInvoiceSnapshot,
		height: number
	): string | undefined {
		try {
			validateReverseSwapAdmission({
				currentHeight: height,
				refundHeight: record.refundHeight,
				paymentHash: Buffer.from(record.paymentHashHex, 'hex'),
				expectedAmountMsat: BigInt(record.invoiceMsat),
				committedHtlcs: snapshot.parts.filter((p) => p.committed),
				fundingSafetyBlocks: this.config.fundingSafetyBlocks,
				resolutionSafetyBlocks: this.config.resolutionSafetyBlocks,
				holdCancelSafetyBlocks: this.config.holdCancelSafetyBlocks
			});
		} catch (err) {
			return err instanceof Error ? err.message : String(err);
		}
		if (
			snapshot.cancelHeight === null ||
			snapshot.cancelHeight <=
				record.refundHeight + this.config.resolutionSafetyBlocks
		) {
			return 'the node would cancel the hold before the refund could resolve';
		}
		const verdict = evaluateSwapExposure(this.config.exposure, {
			direction: 'reverse',
			amountSat: BigInt(record.onchainSat),
			estimatedFundingFeeSat: BigInt(record.minerFeeSat),
			live: this.deps.ledger.unresolved().filter((r) => r.id !== record.id)
		});
		if (!verdict.ok) return `exposure: ${verdict.detail}`;
		return undefined;
	}

	/**
	 * The refund is the only way our coins come back when nobody claims,
	 * and buildSwapRefundTx pays native segwit only. A wallet whose sweep
	 * destination is anything else would leave every refund unbuildable
	 * while the held payment is eventually swept back to the client, so no
	 * swap is quoted or created for it (audit finding, 2026-09-06).
	 */
	private refundDestinationProblem(): string | undefined {
		let script: Buffer;
		try {
			script = this.deps.refundDestinationScript();
		} catch (err) {
			return `refund destination unavailable: ${
				err instanceof Error ? err.message : String(err)
			}`;
		}
		const native =
			Buffer.isBuffer(script) &&
			((script.length === 22 && script[0] === 0x00 && script[1] === 20) ||
				(script.length === 34 &&
					(script[0] === 0x00 || script[0] === 0x51) &&
					script[1] === 32));
		if (!native) {
			this.deps.log('swap_refund_destination_unusable', {
				script: Buffer.isBuffer(script) ? script.toString('hex') : 'none'
			});
			return 'refund destination is not native segwit';
		}
		return undefined;
	}

	/**
	 * A broadcast that threw may still have propagated: the backend can
	 * drop the connection after relaying, and once the transaction is mined
	 * every retry is refused as already known. The chain, not the error,
	 * says whether the bytes left.
	 */
	private async fundingSeenOnChain(record: ISwapRecord): Promise<boolean> {
		if (!record.fundingTxid || record.fundingVout === undefined) return false;
		try {
			const observation = await this.deps.resolver.observe({
				htlc: htlcOf(record),
				funding: { txid: record.fundingTxid, vout: record.fundingVout }
			});
			return (
				observation.funding.kind === 'mempool' ||
				observation.funding.kind === 'confirmed'
			);
		} catch (err) {
			this.deps.log('swap_funding_lookup_failed', {
				swapId: record.id,
				error: err instanceof Error ? err.message : String(err)
			});
			return false;
		}
	}

	private async processFunding(record: ISwapRecord): Promise<void> {
		let current = record;
		if (current.state === 'HELD') {
			const moved = this.deps.ledger.move(current.id, 'FUNDING');
			if (moved.outcome !== 'applied') return;
			current = moved.record!;
		}
		if (current.state !== 'FUNDING') return;
		if (!current.fundingTxHex) {
			if (current.fundingAttempts >= this.config.maxFundingAttempts) {
				const moved = this.deps.ledger.move(current.id, 'FAILED', {
					failureReason: `funding could not be built after ${current.fundingAttempts} attempts`
				});
				if (moved.outcome === 'applied') {
					this.cancelHoldFor(current.id, 'funding_failed');
					this.emitSwap('swap:failed', moved.record!, {
						reason: moved.record!.failureReason
					});
				}
				return;
			}
			// Count the attempt BEFORE building: a crash inside the wallet
			// still consumes one, so a wallet that keeps failing cannot be
			// asked forever.
			const counted = this.deps.ledger.patch(current.id, {
				fundingAttempts: current.fundingAttempts + 1
			});
			if (counted.outcome !== 'applied') return;
			current = counted.record!;
			const feeRate =
				(await this.safeEstimate(this.config.fundingFeeTargetBlocks)) ??
				Math.max(
					1,
					Math.ceil(
						Number(current.minerFeeSat) / this.config.fundingVbytesEstimate
					)
				);
			let built: { txHex: string; txid: Buffer; vout: number };
			try {
				built = await this.deps.fundOutput(
					current.address,
					BigInt(current.onchainSat),
					feeRate
				);
			} catch (err) {
				this.deps.log('swap_funding_build_failed', {
					swapId: current.id,
					attempt: current.fundingAttempts,
					error: err instanceof Error ? err.message : String(err)
				});
				return;
			}
			const problem = this.fundingProblem(current, built);
			if (problem) {
				this.deps.log('swap_funding_rejected', { swapId: current.id, problem });
				await this.release(built.txHex);
				const moved = this.deps.ledger.move(current.id, 'FAILED', {
					failureReason: problem
				});
				if (moved.outcome === 'applied') {
					this.cancelHoldFor(current.id, 'funding_rejected');
					this.emitSwap('swap:failed', moved.record!, { reason: problem });
				}
				return;
			}
			// The txid comes from the bytes we verified, never from the wallet's
			// field: providers report it in internal byte order.
			const recorded = this.deps.ledger.patch(current.id, {
				fundingTxHex: built.txHex,
				fundingTxid: bitcoin.Transaction.fromHex(built.txHex).getId(),
				fundingVout: built.vout,
				fundingValueSat: current.onchainSat
			});
			if (recorded.outcome !== 'applied') return;
			current = recorded.record!;
		}
		// The bytes are durable: pledge their inputs and put them out. A
		// failed broadcast is retried every block with the same bytes.
		try {
			await this.deps.pledge?.(current.fundingTxHex!);
		} catch (err) {
			this.deps.log('swap_pledge_failed', {
				swapId: current.id,
				error: err instanceof Error ? err.message : String(err)
			});
		}
		try {
			await this.deps.broadcast(current.fundingTxHex!);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			this.deps.log('swap_funding_broadcast_failed', {
				swapId: current.id,
				error: message
			});
			// The error is not the verdict: the bytes may be out already
			// (relayed before the connection dropped, or mined and refused
			// as known). A funding the chain shows moves on to be watched,
			// so the claim on it is seen and the hold settled.
			if (!(await this.fundingSeenOnChain(current))) {
				this.deps.ledger.patch(current.id, { lastError: message });
				return;
			}
			this.deps.log('swap_funding_seen_after_failed_broadcast', {
				swapId: current.id,
				fundingTxid: current.fundingTxid
			});
		}
		const moved = this.deps.ledger.move(current.id, 'FUNDING_BROADCAST', {
			fundingBroadcastAt: this.now(),
			lastError: undefined
		});
		if (moved.outcome !== 'applied') return;
		this.emitSwap('swap:funding', moved.record!, {
			fundingTxid: moved.record!.fundingTxid,
			fundingVout: moved.record!.fundingVout
		});
		await this.processWatched(moved.record!);
	}

	private fundingProblem(
		record: ISwapRecord,
		built: { txHex: string; txid: Buffer; vout: number }
	): string | undefined {
		let tx: bitcoin.Transaction;
		try {
			tx = bitcoin.Transaction.fromHex(built.txHex);
		} catch {
			return 'funding transaction does not parse';
		}
		const out = tx.outs[built.vout];
		if (!out) return 'funding output index is out of range';
		if (!out.script.equals(Buffer.from(record.outputScriptHex, 'hex'))) {
			return 'funding output does not pay the contract';
		}
		if (BigInt(out.value) !== BigInt(record.onchainSat)) {
			return `funding output pays ${out.value} sat, expected ${record.onchainSat}`;
		}
		return undefined;
	}

	private async processWatched(record: ISwapRecord): Promise<void> {
		if (!record.fundingTxid || record.fundingVout === undefined) return;
		const fundingTxid = record.fundingTxid;
		const fundingVout = record.fundingVout;
		let current = record;
		if (current.state === 'FUNDING_BROADCAST' && current.fundingTxHex) {
			try {
				await this.deps.pledge?.(current.fundingTxHex);
			} catch {
				/* logged on the funding path; a pledge miss is not fatal */
			}
		}
		const observation = await this.deps.resolver.observe({
			htlc: htlcOf(current),
			funding: { txid: fundingTxid, vout: fundingVout },
			recorded: {
				fundingHeight: current.fundingHeight,
				resolutionTxid: current.resolution?.txid,
				resolutionHeight: current.resolution?.height
			}
		});
		const height = observation.height;

		// A claim at any depth wins, in every watched state.
		const claim = observation.spends.find(
			(s) => s.kind === 'claim' && s.preimage
		);
		if (claim) {
			await this.onClaim(current, claim, observation);
			return;
		}

		if (current.state === 'CLAIMED') {
			// The preimage is recorded; the settle is what is owed.
			await this.settle(current);
			return;
		}

		// Funding depth.
		if (observation.funding.kind === 'confirmed') {
			if (
				current.state === 'FUNDING_BROADCAST' &&
				observation.funding.meetsPolicy
			) {
				const moved = this.deps.ledger.move(current.id, 'FUNDED', {
					fundingHeight: observation.funding.height
				});
				if (moved.outcome !== 'applied') return;
				current = moved.record!;
				this.emitSwap('swap:funded', current, {
					fundingHeight: observation.funding.height
				});
			} else if (current.fundingHeight !== observation.funding.height) {
				const patched = this.deps.ledger.patch(current.id, {
					fundingHeight: observation.funding.height
				});
				if (patched.outcome === 'applied') current = patched.record!;
			}
		} else if (
			observation.funding.kind === 'reorged-out' &&
			current.fundingHeight
		) {
			this.deps.log('swap_funding_reorged', {
				swapId: current.id,
				previousHeight: observation.funding.previousHeight
			});
			// Rebroadcast our own bytes; the state clock only moves forward
			// again once the chain confirms them.
			if (current.fundingTxHex) {
				try {
					await this.deps.broadcast(current.fundingTxHex);
				} catch {
					/* retried next block */
				}
			}
			const patched = this.deps.ledger.patch(current.id, {
				fundingHeight: undefined
			});
			if (patched.outcome === 'applied') current = patched.record!;
		} else if (
			observation.funding.kind === 'absent' &&
			current.fundingTxHex &&
			current.state === 'FUNDING_BROADCAST'
		) {
			// Not seen yet: the broadcast may not have propagated.
			try {
				await this.deps.broadcast(current.fundingTxHex);
			} catch {
				/* retried next block */
			}
		}

		// Refund path: after the refund height, with funding confirmed and
		// nothing claiming, recover the coins. Never while a claim is visible.
		const fundingConfirmed = observation.funding.kind === 'confirmed';
		// Several refund replacements can sit in the history at once; the
		// deepest confirmed one is the fact, and among unconfirmed ones our
		// latest replacement is the one to track.
		const refundSpend = observation.spends
			.filter(
				(s) =>
					s.kind === 'refund' ||
					(current.refundTxid !== undefined && s.txid === current.refundTxid)
			)
			.sort((a, b) => {
				if (b.confirmations !== a.confirmations) {
					return b.confirmations - a.confirmations;
				}
				return (
					(b.txid === current.refundTxid ? 1 : 0) -
					(a.txid === current.refundTxid ? 1 : 0)
				);
			})[0];
		if (refundSpend) {
			const resolution: ISwapResolutionRecord = {
				kind: 'refund',
				txid: refundSpend.txid,
				txHex:
					refundSpend.txid === current.refundTxid
						? current.refundTxHex
						: undefined,
				height: refundSpend.height > 0 ? refundSpend.height : undefined,
				confirmations: refundSpend.confirmations,
				verifiedThisSession: true
			};
			if (refundSpend.meetsPolicy && current.state === 'REFUND_PENDING') {
				const moved = this.deps.ledger.move(current.id, 'REFUNDED', {
					resolution
				});
				if (moved.outcome !== 'applied') return;
				// ONLY NOW is the Lightning side released.
				this.cancelHoldFor(current.id, 'refund_confirmed');
				this.emitSwap('swap:refunded', moved.record!, {
					refundTxid: refundSpend.txid
				});
				this.emitSwap('swap:hold-cancelled', moved.record!, {
					reason: 'refund_confirmed'
				});
				return;
			}
			const patched = this.deps.ledger.patch(current.id, { resolution });
			if (patched.outcome === 'applied') current = patched.record!;
			if (refundSpend.height > 0) return;
		}
		if (
			(current.state === 'FUNDED' ||
				current.state === 'REFUND_PENDING' ||
				current.state === 'EXPOSED') &&
			fundingConfirmed &&
			height >= current.refundHeight + 1
		) {
			await this.pursueRefund(current, observation);
		}
	}

	private async onClaim(
		record: ISwapRecord,
		claim: ISwapSpendObservation,
		observation: ISwapChainObservation
	): Promise<void> {
		const preimage = claim.preimage!;
		if (
			!crypto
				.createHash('sha256')
				.update(preimage)
				.digest()
				.equals(Buffer.from(record.paymentHashHex, 'hex'))
		) {
			this.deps.log('swap_claim_hash_mismatch', {
				swapId: record.id,
				txid: claim.txid
			});
			return;
		}
		const resolution: ISwapResolutionRecord = {
			kind: 'claim',
			txid: claim.txid,
			height: claim.height > 0 ? claim.height : undefined,
			confirmations: claim.confirmations,
			verifiedThisSession: true
		};
		let current = record;
		if (CLAIMABLE_STATES.includes(current.state)) {
			// Persist the preimage BEFORE settling, so a crash after the
			// settle can never leave a settled hold without its evidence.
			const moved = this.deps.ledger.move(current.id, 'CLAIMED', {
				preimageHex: preimage.toString('hex'),
				preimageSource: 'onchain-claim',
				resolution,
				fundingHeight:
					observation.funding.kind === 'confirmed'
						? observation.funding.height
						: current.fundingHeight
			});
			if (moved.outcome !== 'applied') return;
			current = moved.record!;
			this.emitSwap('swap:claimed', current, {
				claimTxid: claim.txid,
				exposed: false
			});
			await this.settle(current);
			return;
		}
		if (current.state === 'EXPOSED') {
			const already = current.preimageHex !== undefined;
			this.deps.ledger.recordPreimage(
				current.id,
				preimage.toString('hex'),
				'onchain-claim'
			);
			this.deps.ledger.patch(current.id, { resolution });
			if (!already) {
				this.deps.log('swap_claimed_while_exposed', {
					swapId: current.id,
					txid: claim.txid
				});
				this.emitSwap('swap:claimed', this.deps.ledger.get(current.id)!, {
					claimTxid: claim.txid,
					exposed: true
				});
			}
			return;
		}
		if (current.state === 'CLAIMED') {
			await this.settle(current);
		}
	}

	private async settle(record: ISwapRecord): Promise<void> {
		if (!record.preimageHex) return;
		const paymentHash = Buffer.from(record.paymentHashHex, 'hex');
		const preimage = Buffer.from(record.preimageHex, 'hex');
		let released = false;
		try {
			released = this.deps.settleHeld(paymentHash, preimage);
		} catch (err) {
			this.deps.log('swap_settle_failed', {
				swapId: record.id,
				error: err instanceof Error ? err.message : String(err)
			});
			return;
		}
		if (released) {
			const moved = this.deps.ledger.move(record.id, 'SETTLED', {
				settledAt: this.now()
			});
			if (moved.outcome === 'applied')
				this.emitSwap('swap:settled', moved.record!);
			return;
		}
		// Nothing was parked: the hold went away under us (or was settled
		// already by an earlier pass that crashed before recording it).
		const snapshot = this.deps.heldSnapshot(paymentHash);
		if (snapshot?.state === 'SETTLED') {
			const moved = this.deps.ledger.move(record.id, 'SETTLED', {
				settledAt: this.now()
			});
			if (moved.outcome === 'applied')
				this.emitSwap('swap:settled', moved.record!);
			return;
		}
		const moved = this.deps.ledger.move(record.id, 'EXPOSED', {
			holdCancelledAt: this.now(),
			holdCancelReason: 'settle_no_held_htlcs'
		});
		if (moved.outcome === 'applied') {
			this.deps.log('swap_exposed', {
				swapId: record.id,
				previousState: record.state,
				reason: 'settle_no_held_htlcs'
			});
			this.emitSwap('swap:exposed', moved.record!, {
				reason: 'settle_no_held_htlcs',
				previousState: record.state
			});
		}
	}

	private async pursueRefund(
		record: ISwapRecord,
		observation: ISwapChainObservation
	): Promise<void> {
		if (observation.funding.kind !== 'confirmed') return;
		const height = observation.height;
		const fundingTx = observation.funding.tx;
		const valueSat = observation.funding.valueSat;
		const needsBuild = !record.refundTxHex;
		const bumpDue =
			!needsBuild &&
			record.refundBroadcastHeight !== undefined &&
			height - record.refundBroadcastHeight >=
				this.config.refundBumpIntervalBlocks;
		if (needsBuild || bumpDue) {
			const rate =
				(await this.safeEstimate(this.config.refundFeeTargetBlocks)) ?? 1;
			const vbytes = this.config.refundVbytesEstimate;
			const previous = record.refundFeeSat ? BigInt(record.refundFeeSat) : 0n;
			// BIP 125 rule 4: a replacement pays at least the old fee plus
			// the relay increment for its size.
			let feeSat = BigInt(Math.ceil(rate * vbytes));
			if (!needsBuild)
				feeSat =
					feeSat > previous + BigInt(vbytes)
						? feeSat
						: previous + BigInt(vbytes);
			const cap = BigInt(Math.ceil(this.config.maxFeeRateSatPerVbyte * vbytes));
			if (feeSat > cap) feeSat = cap;
			if (valueSat - feeSat < DUST_FLOOR_SAT)
				feeSat = valueSat - DUST_FLOOR_SAT;
			if (!needsBuild && feeSat <= previous) {
				// At the cap already: just put the same bytes out again.
				await this.rebroadcastRefund(record);
				return;
			}
			let refund: bitcoin.Transaction;
			try {
				refund = buildSwapRefundTx({
					htlc: htlcOf(record),
					fundingTransaction: fundingTx,
					outputIndex: record.fundingVout!,
					destinationScript: this.deps.refundDestinationScript(),
					feeSatoshis: feeSat,
					privateKey: this.deps.deriveRefundKey(Buffer.from(record.id, 'hex'))
				});
			} catch (err) {
				this.deps.log('swap_refund_build_failed', {
					swapId: record.id,
					error: err instanceof Error ? err.message : String(err)
				});
				return;
			}
			const patch: Partial<ISwapRecord> = {
				refundTxHex: refund.toHex(),
				refundTxid: refund.getId(),
				refundFeeSat: feeSat.toString(),
				refundBroadcastHeight: height,
				refundBumps: needsBuild ? 0 : record.refundBumps + 1
			};
			// Persist the replacement BEFORE it goes out.
			const stored =
				record.state === 'FUNDED'
					? this.deps.ledger.move(record.id, 'REFUND_PENDING', patch)
					: this.deps.ledger.patch(record.id, patch);
			if (stored.outcome !== 'applied') return;
			const current = stored.record!;
			await this.rebroadcastRefund(current);
			this.emitSwap('swap:refund-broadcast', current, {
				refundTxid: current.refundTxid,
				feeSat: current.refundFeeSat,
				bumps: current.refundBumps
			});
			return;
		}
		await this.rebroadcastRefund(record);
	}

	private async rebroadcastRefund(record: ISwapRecord): Promise<void> {
		if (!record.refundTxHex) return;
		try {
			await this.deps.broadcast(record.refundTxHex);
		} catch (err) {
			this.deps.log('swap_refund_broadcast_failed', {
				swapId: record.id,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	private emitSwap(
		event: SwapEventName,
		record: ISwapRecord,
		extra: Record<string, unknown> = {}
	): void {
		this.emit(event, {
			swapId: record.id,
			paymentHash: record.paymentHashHex,
			peer: record.peerNodeIdHex,
			state: record.state,
			onchainSat: record.onchainSat,
			invoiceMsat: record.invoiceMsat,
			refundHeight: record.refundHeight,
			...extra
		});
	}
}
