/**
 * Submarine swap provider (issue #743, campaign 3 of #737): a client locks
 * coins in a P2WSH contract whose preimage branch is ours, this node pays the
 * client's Lightning invoice under an absolute expiry ceiling, and the
 * preimage that payment reveals claims the coins.
 *
 * Like the reverse engine it owns no chain or Lightning code: it takes a deps
 * object of closures into the node (the outgoing payment engine and its
 * honest HTLC view, the chain resolver, key derivation) and the shared swap
 * ledger, and every transition is persisted BEFORE the external action it
 * licenses:
 *
 *   CREATED             the client's invoice and terms verified, row inserted
 *   FUNDING_SEEN        an output paying the contract, of at least the amount,
 *                       seen on chain (any depth); re-pointed while unconfirmed
 *   FUNDED              that output confirmed to policy depth and unspent
 *   PAYING              the row moved and the ceiling recorded, THEN the
 *                       payment dispatched; the node binds every HTLC, retry
 *                       and MPP part to the ceiling
 *   PAYMENT_UNRESOLVED  HTLCs still out past a bounded number of blocks;
 *                       informational, the wait continues
 *   PREIMAGE_KNOWN      the preimage learned from a fulfil or an on-chain
 *                       claim downstream, recorded write-once
 *   CLAIM_BROADCAST     claim built, persisted with its bytes, then broadcast;
 *                       bumped by rebuild while unconfirmed
 *   CLAIM_CONFIRMED     claim confirmed to policy depth
 *   PAYMENT_FAILED      every HTLC terminal without a preimage; a preimage
 *                       learned later still promotes the row
 *   EXPOSED             a payment is out while the contract is not claimable
 *                       (the funding vanished, or a foreign spend confirmed)
 *   CANCELLED | FAILED  nothing was ever paid
 *
 * Rules the engine never breaks: it never pays before the exact output is
 * confirmed to policy depth and re-verified unspent immediately before the
 * dispatch; no HTLC may outlive refundHeight minus the claim and resolution
 * margins (the node enforces the ceiling, the engine asserts the fit before
 * dispatch and refuses a create whose invoice cannot fit); a wall clock, a
 * FAILED record or a lost socket never counts as "the payment failed" while
 * an HTLC is non-terminal, only the node's HTLC view does; a preimage from
 * any source is retained and the claim pursued, even after PAYMENT_FAILED;
 * the claim is persisted before it is broadcast and its bytes never leave in
 * a status answer before the attempt marker is written.
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { getPublicKey } from '../crypto/ecdh';
import { decode as decodeInvoice } from '../invoice/decode';
import {
	DEFAULT_EXPIRY,
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network as InvoiceNetwork
} from '../invoice/types';
import { BeignetCustomSubtype } from '../message/custom';
import type {
	IDfCustomMessage,
	IDfPeerMessaging
} from '../direct-funding/transport/types';
import type { IOutgoingPaymentResolution, IPaymentInfo } from '../node/types';
import { buildSwapHtlc, ISwapHtlc } from './htlc';
import { buildSwapClaimTx } from './transactions';
import { validateSubmarineSwapAdmission } from './policy';
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
	ISwapFundingCandidate,
	ISwapSpendObservation,
	SwapChainResolver
} from './chain-resolver';
import {
	ISwapExposurePolicy,
	evaluateSwapExposure,
	validateSwapExposurePolicy
} from './exposure';
import {
	SWAP_DUST_FLOOR_SAT,
	exposureRefusal,
	htlcOfRecord,
	nativeSegwitProblem,
	swapWireResolution,
	swapWireState
} from './engine-common';
import {
	ISwapQuote,
	ISwapQuoteRequest,
	ISwapStatus,
	ISwapStatusRequest,
	ISwapSubmarineCreate,
	ISwapSubmarineCreateAck,
	SwapMessageError,
	SwapRefusalReason,
	SwapWireDirection,
	SwapWireState,
	decodeSwapQuoteRequest,
	decodeSwapStatusRequest,
	decodeSwapSubmarineCreate,
	encodeSwapQuote,
	encodeSwapStatus,
	encodeSwapSubmarineCreateAck
} from './messages';
import { submarineSwapFee } from './client';
import { REVERSE_SWAP_DEFAULT_EXPOSURE } from './reverse-engine';

export interface ISubmarineSwapProviderConfig {
	flatFeeSat: bigint;
	feePpm: number;
	/** Shared with the reverse direction on the node: one set of caps. */
	exposure: ISwapExposurePolicy;
	/** Blocks from create to the contract's refund height. */
	refundDeltaBlocks: number;
	minRefundDeltaBlocks: number;
	maxRefundDeltaBlocks: number;
	/** Depth the client's funding must reach before this node pays. */
	fundingConfirmations: number;
	/** Depth our claim must reach to count as resolved. */
	resolutionConfirmations: number;
	/**
	 * Blocks between the last possible outgoing HTLC expiry and the refund
	 * height, for a late preimage to be claimed and confirmed.
	 */
	claimSafetyBlocks: number;
	/** Extra blocks under the claim margin for the claim to reach depth. */
	resolutionSafetyBlocks: number;
	/**
	 * Route headroom reserved at admission: the sum of the hop deltas a
	 * route may add on top of the invoice's final CLTV.
	 */
	routeCltvBudgetBlocks: number;
	/** Routing fee this node will spend, per million of the invoice. */
	paymentMaxFeePpm: number;
	paymentMinFeeMsat: bigint;
	/** Blocks in PAYING before the row is marked PAYMENT_UNRESOLVED. */
	unresolvedAfterBlocks: number;
	/** How many times a dispatch that left no record may be redone. */
	maxPaymentDispatchAttempts: number;
	/**
	 * After a payment event leaves a row unresolved (the record failed but
	 * an HTLC's removal still awaits the peer's revocation, which raises no
	 * event), the view is read again this often, this many times.
	 */
	resolutionRecheckMs: number;
	resolutionRecheckCount: number;
	/** Remaining invoice validity a create must carry. */
	minInvoiceExpirySeconds: number;
	/** Blocks an unconfirmed claim waits before a rebuild at a higher fee. */
	claimBumpIntervalBlocks: number;
	claimFeeTargetBlocks: number;
	/** The claim's rate cap outside the deadline window. */
	maxFeeRateSatPerVbyte: number;
	/** The rate used when no estimate is available. */
	fallbackFeeRateSatPerVbyte: number;
	claimVbytesEstimate: number;
	maxCreatedPerPeer: number;
}

export const SUBMARINE_SWAP_DEFAULTS: Omit<
	ISubmarineSwapProviderConfig,
	'exposure'
> = {
	flatFeeSat: 0n,
	feePpm: 0,
	refundDeltaBlocks: 288,
	minRefundDeltaBlocks: 144,
	maxRefundDeltaBlocks: 432,
	fundingConfirmations: 1,
	resolutionConfirmations: 3,
	claimSafetyBlocks: 24,
	resolutionSafetyBlocks: 24,
	routeCltvBudgetBlocks: 72,
	paymentMaxFeePpm: 5_000,
	paymentMinFeeMsat: 1_000n,
	unresolvedAfterBlocks: 6,
	maxPaymentDispatchAttempts: 3,
	resolutionRecheckMs: 500,
	resolutionRecheckCount: 40,
	minInvoiceExpirySeconds: 600,
	claimBumpIntervalBlocks: 2,
	claimFeeTargetBlocks: 6,
	maxFeeRateSatPerVbyte: 200,
	fallbackFeeRateSatPerVbyte: 10,
	claimVbytesEstimate: 150,
	maxCreatedPerPeer: 4
};

export const SUBMARINE_SWAP_DEFAULT_EXPOSURE: ISwapExposurePolicy =
	REVERSE_SWAP_DEFAULT_EXPOSURE;

export interface ISubmarineSwapProviderDeps {
	peers: IDfPeerMessaging;
	ledger: SwapLedger;
	resolver: SwapChainResolver;
	/**
	 * Dispatch the payment synchronously under the ceiling (the node's
	 * sendPaymentWithOptions). May throw before any HTLC is offered; the
	 * engine reads `outgoingHtlcs` afterwards whether it threw or not.
	 */
	payInvoice(
		bolt11: string,
		options: { maxCltvExpiryHeight: number; maxFeeMsat: bigint }
	): IPaymentInfo;
	/** The honest HTLC view of an outgoing payment (getOutgoingHtlcs). */
	outgoingHtlcs(paymentHash: Buffer): IOutgoingPaymentResolution;
	/**
	 * Any outgoing payment event for a hash (preimage, sent, failed, an HTLC
	 * resolved); the engine re-reads the view, never the event's claim.
	 */
	onPaymentEvent(cb: (paymentHash: Buffer) => void): () => void;
	/** True when the node already holds ANY record under this hash. */
	hashInUse?(paymentHash: Buffer): boolean;
	/** Outbound capacity the node could send right now, in msat. */
	spendableOutboundMsat(): bigint;
	/** This node's id: an invoice payable only by us is refused. */
	ownNodeId: Buffer;
	/**
	 * Whether this node has a channel to the peer that can carry an HTLC
	 * now. A route hint naming this node is ordinary when the payee is a
	 * channel peer (the hint just describes that channel); without one it
	 * is the payee asking its JIT LSP to pay it, which the local-origin
	 * path cannot do (issue #737), and the create is refused.
	 */
	hasUsableChannelWith(nodeId: Buffer): boolean;
	broadcast(txHex: string): Promise<string>;
	/** sat/vB, or null when no estimate is available. */
	estimateFee(targetBlocks: number): Promise<number | null>;
	currentHeight(): number;
	deriveClaimKey(swapId: Buffer): Buffer;
	claimDestinationScript(): Buffer;
	network: bitcoin.Network;
	networkName: ISwapRecord['network'];
	now?(): number;
	log(action: string, data: Record<string, unknown>): void;
}

export interface ISubmarineSwapStatus {
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
		claimSafetyBlocks: number;
		paymentMaxFeePpm: number;
	};
	counts: Record<string, number>;
	exposedSat: string;
	exposedCount: number;
}

type SubmarineSwapEventName =
	| 'swap:created'
	| 'swap:funding-seen'
	| 'swap:funded'
	| 'swap:funding-lost'
	| 'swap:paying'
	| 'swap:payment-unresolved'
	| 'swap:preimage'
	| 'swap:claim-broadcast'
	| 'swap:claim-confirmed'
	| 'swap:payment-failed'
	| 'swap:exposed'
	| 'swap:cancelled'
	| 'swap:failed';

export const SUBMARINE_SWAP_EVENTS: readonly SubmarineSwapEventName[] = [
	'swap:created',
	'swap:funding-seen',
	'swap:funded',
	'swap:funding-lost',
	'swap:paying',
	'swap:payment-unresolved',
	'swap:preimage',
	'swap:claim-broadcast',
	'swap:claim-confirmed',
	'swap:payment-failed',
	'swap:exposed',
	'swap:cancelled',
	'swap:failed'
];

/** Rows a cancel may still end: nothing has been paid. */
const CANCELLABLE_STATES: readonly SwapState[] = [
	'CREATED',
	'FUNDING_SEEN',
	'FUNDED',
	'FUNDING_LOST'
];
/** Rows whose Lightning side is out. */
const IN_FLIGHT_STATES: readonly SwapState[] = [
	'PAYING',
	'PAYMENT_UNRESOLVED',
	'PREIMAGE_KNOWN',
	'CLAIM_BROADCAST',
	'EXPOSED'
];
/** The node pads the invoice's final CLTV by this much when it pays. */
const FINAL_CLTV_PADDING = 3;

function invoiceNetworkOf(name: ISwapRecord['network']): InvoiceNetwork {
	switch (name) {
		case 'bitcoin':
			return InvoiceNetwork.MAINNET;
		case 'regtest':
			return InvoiceNetwork.REGTEST;
		case 'signet':
			return InvoiceNetwork.SIGNET;
		default:
			return InvoiceNetwork.TESTNET;
	}
}

interface IInvoiceFacts {
	amountMsat: bigint;
	minFinalCltvExpiry: number;
	expiresAt: number;
}

export class SubmarineSwapProvider extends EventEmitter {
	readonly config: ISubmarineSwapProviderConfig;
	private readonly unsubscribe: Array<() => void> = [];
	private queue: Promise<void> = Promise.resolve();
	private stopped = false;
	/** Rows being re-read after an event left them unresolved (see rechecks). */
	private readonly rechecks = new Map<
		string,
		{ left: number; timer: NodeJS.Timeout }
	>();

	constructor(
		private readonly deps: ISubmarineSwapProviderDeps,
		config: Partial<ISubmarineSwapProviderConfig> = {}
	) {
		super();
		this.config = {
			...SUBMARINE_SWAP_DEFAULTS,
			exposure: SUBMARINE_SWAP_DEFAULT_EXPOSURE,
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
			this.config.claimSafetyBlocks < 1 ||
			this.config.resolutionSafetyBlocks < 1 ||
			this.config.fundingConfirmations < 1 ||
			this.config.resolutionConfirmations < 1
		) {
			throw new Error(
				'claim and resolution margins and confirmations must be positive'
			);
		}
		if (
			this.config.minRefundDeltaBlocks <=
			this.config.claimSafetyBlocks +
				this.config.resolutionSafetyBlocks +
				this.config.routeCltvBudgetBlocks +
				this.config.fundingConfirmations
		) {
			throw new Error(
				'minRefundDeltaBlocks must exceed the claim, resolution and route margins'
			);
		}
		if (
			!Number.isSafeInteger(this.config.paymentMaxFeePpm) ||
			this.config.paymentMaxFeePpm < 0
		) {
			throw new Error('paymentMaxFeePpm must be a non-negative integer');
		}
		this.unsubscribe.push(
			deps.peers.onCustomMessage((msg) => this.onMessage(msg)),
			deps.onPaymentEvent((hash) => {
				void this.enqueue(() => this.onPaymentEvent(hash));
			})
		);
	}

	/** Redo every owed action from the rehydrated ledger, once. */
	async start(): Promise<void> {
		await this.enqueue(async () => {
			for (const record of this.rows()) {
				if (isTerminalSwapState(record.state)) continue;
				await this.processRecord(record.id, 'start');
			}
			// A preimage learned while this process was down promotes a row
			// the block loop no longer visits.
			for (const record of this.rows()) {
				if (record.state === 'PAYMENT_FAILED')
					await this.settlePaymentView(record, 'start');
			}
		});
	}

	stop(): void {
		this.stopped = true;
		for (const off of this.unsubscribe) off();
		this.unsubscribe.length = 0;
		for (const r of this.rechecks.values()) clearTimeout(r.timer);
		this.rechecks.clear();
	}

	/** Per-block work; ticks are serialized and never overlap. */
	onBlock(height: number): Promise<void> {
		return this.enqueue(async () => {
			for (const record of this.rows()) {
				if (isTerminalSwapState(record.state)) continue;
				await this.processRecord(record.id, `block ${height}`);
			}
		});
	}

	list(): ISwapRecord[] {
		return this.rows();
	}

	get(swapIdHex: string): ISwapRecord | undefined {
		const record = this.deps.ledger.get(swapIdHex);
		return record?.direction === 'submarine' ? record : undefined;
	}

	status(): ISubmarineSwapStatus {
		const counts: Record<string, number> = {};
		const rows = this.rows();
		for (const r of rows) counts[r.state] = (counts[r.state] ?? 0) + 1;
		const summary = SwapLedger.exposure(
			rows,
			this.config.resolutionConfirmations
		);
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
				resolutionConfirmations: this.config.resolutionConfirmations,
				claimSafetyBlocks: this.config.claimSafetyBlocks,
				paymentMaxFeePpm: this.config.paymentMaxFeePpm
			},
			counts,
			exposedSat: summary.exposedSat.toString(),
			exposedCount: summary.exposedCount
		};
	}

	/** Rows whose Lightning payment is out or whose claim is owed. */
	inFlight(): number {
		return this.rows().filter((r) => IN_FLIGHT_STATES.includes(r.state)).length;
	}

	/** Operator cancel: only before anything was paid. */
	cancel(swapIdHex: string): { ok: boolean; reason?: string } {
		const record = this.get(swapIdHex);
		if (!record) return { ok: false, reason: 'unknown swap' };
		if (!CANCELLABLE_STATES.includes(record.state)) {
			return { ok: false, reason: `swap is ${record.state}` };
		}
		const moved = this.deps.ledger.move(swapIdHex, 'CANCELLED', {
			failureReason: 'operator cancel'
		});
		if (moved.outcome !== 'applied') {
			return { ok: false, reason: `ledger ${moved.outcome}` };
		}
		this.emitSwap('swap:cancelled', moved.record!, { reason: 'operator' });
		return { ok: true };
	}

	private rows(): ISwapRecord[] {
		return this.deps.ledger.list().filter((r) => r.direction === 'submarine');
	}

	// ─────────────── wire ───────────────

	private onMessage(msg: IDfCustomMessage): void {
		let work: Promise<void> | undefined;
		try {
			switch (msg.subtype) {
				case BeignetCustomSubtype.SWAP_QUOTE_REQUEST: {
					const req = decodeSwapQuoteRequest(msg.payload);
					if (req.direction !== SwapWireDirection.SUBMARINE) return;
					work = this.handleQuote(msg.peerPubkey, req);
					break;
				}
				case BeignetCustomSubtype.SWAP_SUBMARINE_CREATE: {
					const create = decodeSwapSubmarineCreate(msg.payload);
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
		const feeRate = await this.safeEstimate(this.config.claimFeeTargetBlocks);
		if (feeRate === null) return null;
		const minerFeeSat = BigInt(
			Math.ceil(feeRate * this.config.claimVbytesEstimate)
		);
		// The routing budget the dispatch may spend is part of the floor:
		// otherwise a payee authoring its route hint's fees turns every swap
		// into a loss of up to paymentMaxFeePpm.
		const totalFeeSat = submarineSwapFee(amountSat, {
			flatFeeSat: this.config.flatFeeSat,
			feePpm: this.config.feePpm,
			minerFeeSat,
			routingFeePpm: this.config.paymentMaxFeePpm
		});
		return { feeRate, minerFeeSat, totalFeeSat };
	}

	private async safeEstimate(
		targetBlocks: number,
		clamp = true
	): Promise<number | null> {
		try {
			const rate = await this.deps.estimateFee(targetBlocks);
			if (rate === null || !(rate > 0)) return null;
			return clamp ? Math.min(rate, this.config.maxFeeRateSatPerVbyte) : rate;
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

	/** The absolute height no outgoing HTLC of the payment may expire after. */
	private ceilingFor(refundHeight: number): number {
		return (
			refundHeight -
			this.config.claimSafetyBlocks -
			this.config.resolutionSafetyBlocks
		);
	}

	/**
	 * Whether a payment dispatched now, whose invoice asks `finalCltv`, can
	 * fit every HTLC under the ceiling with the route budget to spare.
	 */
	private fitProblem(
		height: number,
		ceiling: number,
		finalCltv: number,
		extraBlocks = 0
	): string | undefined {
		const needed =
			height +
			extraBlocks +
			this.config.routeCltvBudgetBlocks +
			finalCltv +
			FINAL_CLTV_PADDING;
		if (needed > ceiling) {
			return `final cltv ${finalCltv} plus a ${this.config.routeCltvBudgetBlocks} block route budget at height ${height} needs ${needed}, above the ${ceiling} ceiling`;
		}
		return undefined;
	}

	private spendableOutbound(): bigint {
		try {
			return this.deps.spendableOutboundMsat();
		} catch {
			return 0n;
		}
	}

	private maxFeeMsatFor(invoiceMsat: bigint): bigint {
		const proportional =
			(invoiceMsat * BigInt(this.config.paymentMaxFeePpm)) / 1_000_000n;
		return proportional > this.config.paymentMinFeeMsat
			? proportional
			: this.config.paymentMinFeeMsat;
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
			invoiceExpirySeconds: this.config.minInvoiceExpirySeconds,
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
		const destinationProblem = this.claimDestinationProblem();
		if (destinationProblem) {
			return refuse(SwapRefusalReason.INTERNAL, destinationProblem);
		}
		const fee = await this.quoteFee(req.amountSat);
		if (!fee)
			return refuse(SwapRefusalReason.CHAIN_UNAVAILABLE, 'no fee estimate');
		if (fee.totalFeeSat >= req.amountSat) {
			return refuse(
				SwapRefusalReason.AMOUNT_BELOW_MIN,
				`fee ${fee.totalFeeSat} sat leaves nothing to pay`
			);
		}
		const verdict = evaluateSwapExposure(this.config.exposure, {
			resolutionConfirmations: this.config.resolutionConfirmations,
			direction: 'submarine',
			amountSat: req.amountSat,
			feeRateSatPerVbyte: fee.feeRate,
			live: this.deps.ledger.unresolved()
		});
		if (!verdict.ok)
			return refuse(exposureRefusal(verdict.reason), verdict.detail);
		const invoiceAmountMsat = (req.amountSat - fee.totalFeeSat) * 1000n;
		if (this.spendableOutbound() < invoiceAmountMsat) {
			return refuse(
				SwapRefusalReason.NO_OUTBOUND_LIQUIDITY,
				'no channel can carry the payment right now'
			);
		}
		this.send(
			peer,
			BeignetCustomSubtype.SWAP_QUOTE,
			encodeSwapQuote({
				...base,
				accepted: true,
				totalFeeSat: fee.totalFeeSat,
				minerFeeSat: fee.minerFeeSat,
				invoiceAmountMsat
			})
		);
	}

	/** Decode and judge the client's invoice; a string is the refusal text. */
	private invoiceProblem(
		req: ISwapSubmarineCreate,
		height: number,
		refundHeight: number
	):
		| { ok: true; facts: IInvoiceFacts }
		| { ok: false; reason: SwapRefusalReason; text: string } {
		let invoice: ReturnType<typeof decodeInvoice>;
		try {
			invoice = decodeInvoice(req.bolt11);
		} catch (err) {
			return {
				ok: false,
				reason: SwapRefusalReason.INVOICE_MISMATCH,
				text: `invoice does not decode: ${
					err instanceof Error ? err.message : String(err)
				}`
			};
		}
		const bad = (
			text: string
		): {
			ok: false;
			reason: SwapRefusalReason;
			text: string;
		} => ({ ok: false, reason: SwapRefusalReason.INVOICE_MISMATCH, text });
		if (invoice.network !== invoiceNetworkOf(this.deps.networkName)) {
			return bad('invoice is for another network');
		}
		if (!invoice.paymentHash.equals(req.paymentHash)) {
			return bad('invoice carries another payment hash');
		}
		if (invoice.amountMsat === undefined || invoice.amountMsat <= 0n) {
			return bad('invoice carries no amount');
		}
		if (!invoice.paymentSecret) {
			return bad('invoice carries no payment secret');
		}
		const onchainMsat = req.onchainAmountSat * 1000n;
		if (invoice.amountMsat >= onchainMsat) {
			return bad('invoice amount leaves no fee');
		}
		if ((onchainMsat - invoice.amountMsat) % 1000n !== 0n) {
			return bad('invoice amount does not leave a whole-satoshi fee');
		}
		const expiresAt = invoice.timestamp + (invoice.expiry ?? DEFAULT_EXPIRY);
		if (
			expiresAt * 1000 - this.now() <
			this.config.minInvoiceExpirySeconds * 1000
		) {
			return bad(
				`invoice expires within ${this.config.minInvoiceExpirySeconds} seconds`
			);
		}
		const payee = invoice.payeeNodeKey ?? invoice.recoveredPubkey;
		const own = this.deps.ownNodeId;
		if (payee && payee.equals(own)) {
			return {
				ok: false,
				reason: SwapRefusalReason.SELF_PAYMENT,
				text: 'invoice is payable to this node'
			};
		}
		// A hint through this node with no channel to the payee is the
		// client asking its own JIT LSP to pay it: the local-origin path does
		// not enter the forwarded HTLC interception (issue #737), so the
		// composition is refused. With a channel the hint merely names it.
		for (const hop of (invoice.routingHints ?? []).flat()) {
			if (
				hop.pubkey.equals(own) &&
				!(payee && this.deps.hasUsableChannelWith(payee))
			) {
				return {
					ok: false,
					reason: SwapRefusalReason.SELF_PAYMENT,
					text: 'a route hint names this node and it has no channel to the payee'
				};
			}
		}
		for (const path of invoice.blindedPaths ?? []) {
			const intro = path.path.introductionNodeId;
			if (Buffer.isBuffer(intro) && intro.length === 33 && intro.equals(own)) {
				return {
					ok: false,
					reason: SwapRefusalReason.SELF_PAYMENT,
					text: 'a blinded path is introduced by this node'
				};
			}
		}
		const minFinalCltvExpiry =
			invoice.minFinalCltvExpiry ?? DEFAULT_MIN_FINAL_CLTV_EXPIRY;
		const fit = this.fitProblem(
			height,
			this.ceilingFor(refundHeight),
			minFinalCltvExpiry,
			this.config.fundingConfirmations
		);
		if (fit) {
			return {
				ok: false,
				reason: SwapRefusalReason.CLTV_UNFITTABLE,
				text: fit
			};
		}
		return {
			ok: true,
			facts: { amountMsat: invoice.amountMsat, minFinalCltvExpiry, expiresAt }
		};
	}

	private async handleCreate(
		peer: string,
		req: ISwapSubmarineCreate
	): Promise<void> {
		const refuse = (reason: SwapRefusalReason, reasonText: string): void => {
			this.deps.log('swap_create_refused', {
				peer,
				direction: 'submarine',
				reason: SwapRefusalReason[reason],
				reasonText
			});
			this.send(
				peer,
				BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK,
				encodeSwapSubmarineCreateAck({
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
		if (req.direction !== SwapWireDirection.SUBMARINE) {
			return refuse(
				SwapRefusalReason.UNSUPPORTED_DIRECTION,
				'submarine create carries another direction'
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
				existing.direction === 'submarine' &&
				existing.refundPubkeyHex === req.refundPubkey.toString('hex') &&
				existing.onchainSat === req.onchainAmountSat.toString() &&
				existing.bolt11 === req.bolt11 &&
				!isTerminalSwapState(existing.state)
			) {
				this.send(
					peer,
					BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK,
					encodeSwapSubmarineCreateAck(this.ackFor(req.requestId, existing))
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
			this.deps.hashInUse?.(req.paymentHash)
		) {
			return refuse(
				SwapRefusalReason.DUPLICATE_HASH,
				'this hash is already in use'
			);
		}
		const destinationProblem = this.claimDestinationProblem();
		if (destinationProblem) {
			return refuse(SwapRefusalReason.INTERNAL, destinationProblem);
		}
		const createdByPeer = this.rows().filter(
			(r) => r.peerNodeIdHex === peer && r.state === 'CREATED'
		).length;
		if (createdByPeer >= this.config.maxCreatedPerPeer) {
			return refuse(SwapRefusalReason.RATE_LIMITED, 'too many unfunded swaps');
		}
		const refundHeight = height + this.refundDelta(req.preferredRefundDelta);
		const judged = this.invoiceProblem(req, height, refundHeight);
		if (!judged.ok) return refuse(judged.reason, judged.text);
		const facts = judged.facts;
		const totalFeeSat = req.onchainAmountSat - facts.amountMsat / 1000n;
		// Fee floor and ceiling. The invoice was minted before this create,
		// so the fee is what the invoice leaves, judged against the floor
		// the provider needs right now and the ceiling the client set.
		const fee = await this.quoteFee(req.onchainAmountSat);
		if (!fee)
			return refuse(SwapRefusalReason.CHAIN_UNAVAILABLE, 'no fee estimate');
		if (totalFeeSat < fee.totalFeeSat) {
			return refuse(
				SwapRefusalReason.FEE_CEILING,
				`invoice leaves ${totalFeeSat} sat, below the ${fee.totalFeeSat} sat fee`
			);
		}
		if (totalFeeSat > req.maxTotalFeeSat) {
			return refuse(
				SwapRefusalReason.FEE_CEILING,
				`invoice leaves ${totalFeeSat} sat, above the client ceiling`
			);
		}
		const verdict = evaluateSwapExposure(this.config.exposure, {
			resolutionConfirmations: this.config.resolutionConfirmations,
			direction: 'submarine',
			amountSat: req.onchainAmountSat,
			feeRateSatPerVbyte: fee.feeRate,
			live: this.deps.ledger.unresolved()
		});
		if (!verdict.ok)
			return refuse(exposureRefusal(verdict.reason), verdict.detail);
		if (this.spendableOutbound() < facts.amountMsat) {
			return refuse(
				SwapRefusalReason.NO_OUTBOUND_LIQUIDITY,
				'no channel can carry the payment right now'
			);
		}
		const claimPubkey = getPublicKey(this.deps.deriveClaimKey(swapId));
		if (claimPubkey.equals(req.refundPubkey)) {
			return refuse(SwapRefusalReason.INVALID_KEY, 'refund key is ours');
		}
		const htlc: ISwapHtlc = {
			paymentHash: req.paymentHash,
			claimPublicKey: claimPubkey,
			refundPublicKey: req.refundPubkey,
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
		try {
			validateSubmarineSwapAdmission({
				currentHeight: height,
				refundHeight,
				latestOutgoingHtlcExpiry: this.ceilingFor(refundHeight),
				claimSafetyBlocks: this.config.claimSafetyBlocks,
				fundingConfirmations: this.config.fundingConfirmations,
				minimumFundingConfirmations: this.config.fundingConfirmations
			});
		} catch (err) {
			return refuse(
				SwapRefusalReason.CLTV_UNFITTABLE,
				err instanceof Error ? err.message : String(err)
			);
		}
		const inserted = this.deps.ledger.insert({
			id: swapIdHex,
			direction: 'submarine',
			peerNodeIdHex: peer,
			paymentHashHex: hashHex,
			claimPubkeyHex: claimPubkey.toString('hex'),
			refundPubkeyHex: req.refundPubkey.toString('hex'),
			refundHeight,
			outputScriptHex: contract.outputScript.toString('hex'),
			address: contract.address,
			network: this.deps.networkName,
			onchainSat: req.onchainAmountSat.toString(),
			invoiceMsat: facts.amountMsat.toString(),
			totalFeeSat: totalFeeSat.toString(),
			minerFeeSat: fee.minerFeeSat.toString(),
			createdAt: this.now(),
			createdHeight: height,
			bolt11: req.bolt11,
			invoiceExpiresAt: facts.expiresAt,
			paymentMaxCltvExpiryHeight: this.ceilingFor(refundHeight)
		});
		if (inserted.outcome !== 'applied') {
			return refuse(SwapRefusalReason.INTERNAL, `ledger ${inserted.outcome}`);
		}
		const record = inserted.record!;
		this.send(
			peer,
			BeignetCustomSubtype.SWAP_SUBMARINE_CREATE_ACK,
			encodeSwapSubmarineCreateAck(this.ackFor(req.requestId, record))
		);
		this.emitSwap('swap:created', record);
	}

	private ackFor(
		requestId: Buffer,
		record: ISwapRecord
	): ISwapSubmarineCreateAck {
		return {
			requestId,
			accepted: true,
			paymentHash: Buffer.from(record.paymentHashHex, 'hex'),
			reason: SwapRefusalReason.NONE,
			terms: {
				swapId: Buffer.from(record.id, 'hex'),
				claimPubkey: Buffer.from(record.claimPubkeyHex, 'hex'),
				refundHeight: record.refundHeight,
				outputScript: Buffer.from(record.outputScriptHex, 'hex'),
				address: record.address,
				invoiceAmountMsat: BigInt(record.invoiceMsat),
				onchainAmountSat: BigInt(record.onchainSat),
				totalFeeSat: BigInt(record.totalFeeSat),
				minerFeeSat: BigInt(record.minerFeeSat),
				fundingConfirmations: this.config.fundingConfirmations,
				expiresAt: record.invoiceExpiresAt ?? 0,
				currentHeight: Math.max(0, this.deps.currentHeight()),
				paymentCeilingHeight:
					record.paymentMaxCltvExpiryHeight ??
					this.ceilingFor(record.refundHeight)
			}
		};
	}

	private handleStatus(peer: string, req: ISwapStatusRequest): void {
		const swapIdHex = req.swapId.toString('hex');
		const record = this.deps.ledger.get(swapIdHex);
		// The reverse engine answers its own rows and the unknown ones.
		if (!record || record.direction !== 'submarine') return;
		const height = Math.max(0, this.deps.currentHeight());
		let status: ISwapStatus = {
			requestId: req.requestId,
			swapId: req.swapId,
			found: false,
			state: SwapWireState.UNKNOWN,
			currentHeight: height
		};
		if (record.peerNodeIdHex === peer) {
			// The claim is reported only once a broadcast was attempted; a
			// resolution recorded from the chain is public already.
			const claimOut =
				record.claimTxid !== undefined &&
				record.claimBroadcastAttemptedAt !== undefined;
			const resolution: ISwapResolutionRecord | undefined =
				record.resolution ??
				(claimOut
					? {
							kind: 'claim',
							txid: record.claimTxid!,
							height: undefined,
							confirmations: 0,
							verifiedThisSession: false
					  }
					: undefined);
			status = {
				...status,
				found: true,
				state: swapWireState(record.state),
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
				resolutionTxid: resolution
					? Buffer.from(resolution.txid, 'hex')
					: undefined,
				resolutionKind: resolution
					? swapWireResolution(resolution.kind)
					: undefined,
				resolutionHeight: resolution?.height,
				resolutionConfirmations: resolution?.confirmations
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

	private claimDestinationProblem(): string | undefined {
		let script: Buffer;
		try {
			script = this.deps.claimDestinationScript();
		} catch (err) {
			return `claim destination unavailable: ${
				err instanceof Error ? err.message : String(err)
			}`;
		}
		if (nativeSegwitProblem(script)) {
			this.deps.log('swap_claim_destination_unusable', {
				script: Buffer.isBuffer(script) ? script.toString('hex') : 'none'
			});
			return 'claim destination is not native segwit';
		}
		return undefined;
	}

	private async onPaymentEvent(
		paymentHash: Buffer,
		trigger = 'payment event'
	): Promise<void> {
		for (const record of this.deps.ledger.byPaymentHash(
			paymentHash.toString('hex')
		)) {
			if (record.direction !== 'submarine') continue;
			if (
				record.state === 'PAYING' ||
				record.state === 'PAYMENT_UNRESOLVED' ||
				record.state === 'EXPOSED' ||
				record.state === 'PAYMENT_FAILED'
			) {
				const after = await this.settlePaymentView(record, trigger);
				if (
					after &&
					(after.state === 'PAYING' || after.state === 'PAYMENT_UNRESOLVED')
				) {
					// The record has a verdict but an HTLC is not terminal yet:
					// its removal completes on the peer's revocation, which
					// raises no event. Read again shortly, a bounded number
					// of times; a block also re-reads.
					const view = this.deps.outgoingHtlcs(paymentHash);
					if (view.status !== null && view.status !== 'PENDING') {
						this.scheduleRecheck(paymentHash);
					}
				}
			}
		}
	}

	private scheduleRecheck(paymentHash: Buffer): void {
		if (this.stopped) return;
		const key = paymentHash.toString('hex');
		const existing = this.rechecks.get(key);
		const left = existing
			? existing.left - 1
			: this.config.resolutionRecheckCount;
		if (existing) clearTimeout(existing.timer);
		if (left <= 0) {
			this.rechecks.delete(key);
			return;
		}
		const timer = setTimeout(() => {
			this.rechecks.delete(key);
			void this.enqueue(() => this.onPaymentEvent(paymentHash, 'recheck'));
		}, this.config.resolutionRecheckMs);
		timer.unref?.();
		this.rechecks.set(key, { left, timer });
	}

	/** One pass over one record: whatever its state owes, done once. */
	private async processRecord(
		swapIdHex: string,
		trigger: string
	): Promise<void> {
		if (this.stopped) return;
		const record = this.deps.ledger.get(swapIdHex);
		if (!record || record.direction !== 'submarine') return;
		try {
			switch (record.state) {
				case 'CREATED':
				case 'FUNDING_SEEN':
				case 'FUNDING_LOST':
					await this.processAwaitingFunding(record);
					return;
				case 'FUNDED':
					await this.processFunded(record);
					return;
				case 'PAYING':
				case 'PAYMENT_UNRESOLVED':
					await this.processPaying(record);
					return;
				case 'PREIMAGE_KNOWN':
				case 'CLAIM_BROADCAST':
					await this.processClaim(record);
					return;
				case 'EXPOSED':
					await this.processExposed(record);
					return;
				default:
					return;
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

	private invoiceFacts(record: ISwapRecord): IInvoiceFacts {
		let minFinalCltvExpiry = DEFAULT_MIN_FINAL_CLTV_EXPIRY;
		try {
			const decoded = decodeInvoice(record.bolt11 ?? '');
			minFinalCltvExpiry =
				decoded.minFinalCltvExpiry ?? DEFAULT_MIN_FINAL_CLTV_EXPIRY;
		} catch {
			/* a row was only inserted with a decodable invoice */
		}
		return {
			amountMsat: BigInt(record.invoiceMsat),
			minFinalCltvExpiry,
			expiresAt: record.invoiceExpiresAt ?? 0
		};
	}

	private ceilingOf(record: ISwapRecord): number {
		return (
			record.paymentMaxCltvExpiryHeight ?? this.ceilingFor(record.refundHeight)
		);
	}

	/**
	 * Why a row that has not paid yet can no longer pay: its invoice
	 * expired, or no payment dispatched now could fit under the ceiling.
	 */
	private deadlineProblem(
		record: ISwapRecord,
		height: number
	): string | undefined {
		const facts = this.invoiceFacts(record);
		if (facts.expiresAt > 0 && this.now() > facts.expiresAt * 1000) {
			return 'invoice expired unpaid';
		}
		return this.fitProblem(
			height,
			this.ceilingOf(record),
			facts.minFinalCltvExpiry
		);
	}

	private endBeforePayment(record: ISwapRecord, reason: string): void {
		// Nothing was paid: a row without a funding is cancelled, one whose
		// client's coins are on chain fails (the client refunds at height).
		const to: SwapState =
			record.state === 'CREATED' || record.state === 'FUNDING_LOST'
				? 'CANCELLED'
				: 'FAILED';
		const moved = this.deps.ledger.move(record.id, to, {
			failureReason: reason
		});
		if (moved.outcome !== 'applied') return;
		this.deps.log('swap_ended_before_payment', {
			swapId: record.id,
			previousState: record.state,
			reason
		});
		this.emitSwap(
			to === 'CANCELLED' ? 'swap:cancelled' : 'swap:failed',
			moved.record!,
			{
				reason
			}
		);
	}

	private pickCandidate(
		record: ISwapRecord,
		candidates: ISwapFundingCandidate[]
	): ISwapFundingCandidate | undefined {
		const wanted = BigInt(record.onchainSat);
		const eligible = candidates.filter((c) => c.valueSat >= wanted);
		for (const c of candidates) {
			if (c.valueSat < wanted) {
				this.deps.log('swap_funding_underpaid', {
					swapId: record.id,
					txid: c.txid,
					vout: c.vout,
					valueSat: c.valueSat.toString(),
					expectedSat: record.onchainSat
				});
			}
		}
		if (eligible.length === 0) return undefined;
		// The one we already track stays unless it vanished; otherwise the
		// deepest confirmed one, then the first unconfirmed.
		const tracked = eligible.find(
			(c) => c.txid === record.fundingTxid && c.vout === record.fundingVout
		);
		if (tracked) return tracked;
		const confirmed = eligible
			.filter((c) => c.height > 0)
			.sort((a, b) => a.height - b.height);
		return confirmed[0] ?? eligible[0];
	}

	private async processAwaitingFunding(record: ISwapRecord): Promise<void> {
		let current = record;
		const height = this.deps.currentHeight();
		const problem = this.deadlineProblem(current, height);
		if (problem) {
			this.endBeforePayment(current, problem);
			return;
		}
		if (current.state === 'FUNDING_LOST' && height > current.refundHeight) {
			this.endBeforePayment(
				current,
				'funding never returned before the refund height'
			);
			return;
		}
		// Discovery: any output paying the contract, of at least the amount.
		// While the tracked output is unconfirmed a replacement may appear;
		// the tracked one stays until it is gone.
		const discovered = await this.deps.resolver.observe({
			htlc: htlcOfRecord(current)
		});
		const candidate = this.pickCandidate(current, discovered.candidates);
		if (!candidate) {
			if (current.state === 'FUNDING_SEEN') {
				const moved = this.deps.ledger.move(current.id, 'FUNDING_LOST', {
					fundingLostAt: this.now()
				});
				if (moved.outcome === 'applied') {
					this.deps.log('swap_funding_lost', {
						swapId: current.id,
						fundingTxid: current.fundingTxid
					});
					this.emitSwap('swap:funding-lost', moved.record!, {
						fundingTxid: current.fundingTxid
					});
				}
			}
			return;
		}
		if (
			candidate.txid !== current.fundingTxid ||
			candidate.vout !== current.fundingVout ||
			current.state !== 'FUNDING_SEEN'
		) {
			const patch: Partial<ISwapRecord> = {
				fundingTxid: candidate.txid,
				fundingVout: candidate.vout,
				fundingValueSat: candidate.valueSat.toString(),
				fundingHeight: undefined,
				fundingBroadcastAt: current.fundingBroadcastAt ?? this.now()
			};
			const stored =
				current.state === 'FUNDING_SEEN'
					? this.deps.ledger.patch(current.id, patch)
					: this.deps.ledger.move(current.id, 'FUNDING_SEEN', patch);
			if (stored.outcome !== 'applied') return;
			current = stored.record!;
			this.emitSwap('swap:funding-seen', current, {
				fundingTxid: candidate.txid,
				fundingVout: candidate.vout,
				fundingValueSat: candidate.valueSat.toString()
			});
		}
		// Depth and spends of the tracked output.
		const observation = await this.deps.resolver.observe({
			htlc: htlcOfRecord(current),
			funding: { txid: current.fundingTxid!, vout: current.fundingVout! },
			recorded: { fundingHeight: current.fundingHeight }
		});
		const foreign = observation.spends.find((s) => s.kind !== 'claim');
		if (foreign) {
			// The client took its coins back (or something did) before we
			// paid: nothing is lost, and there is nothing left to pay for.
			const moved = this.deps.ledger.move(current.id, 'CANCELLED', {
				failureReason: `funding spent before payment (${foreign.kind})`,
				resolution: {
					kind: foreign.kind,
					txid: foreign.txid,
					height: foreign.height > 0 ? foreign.height : undefined,
					confirmations: foreign.confirmations,
					verifiedThisSession: true
				}
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:cancelled', moved.record!, {
					reason: 'funding spent before payment',
					resolutionTxid: foreign.txid
				});
			}
			return;
		}
		if (observation.funding.kind === 'confirmed') {
			if (observation.funding.meetsPolicy) {
				const moved = this.deps.ledger.move(current.id, 'FUNDED', {
					fundingHeight: observation.funding.height
				});
				if (moved.outcome !== 'applied') return;
				current = moved.record!;
				this.emitSwap('swap:funded', current, {
					fundingHeight: observation.funding.height
				});
				await this.processFunded(current);
				return;
			}
			if (current.fundingHeight !== observation.funding.height) {
				this.deps.ledger.patch(current.id, {
					fundingHeight: observation.funding.height
				});
			}
		}
	}

	/**
	 * FUNDED -> PAYING -> the payment call. The observation is the last
	 * await; everything after it is synchronous up to the dispatch, so a
	 * cancel or a spend landing meanwhile is seen by the re-read or fails
	 * the CAS, never raced past.
	 */
	private async processFunded(record: ISwapRecord): Promise<void> {
		if (!record.fundingTxid || record.fundingVout === undefined) return;
		const observation = await this.deps.resolver.observe({
			htlc: htlcOfRecord(record),
			funding: { txid: record.fundingTxid, vout: record.fundingVout },
			recorded: { fundingHeight: record.fundingHeight }
		});
		const live = this.deps.ledger.get(record.id);
		if (!live || live.state !== 'FUNDED') return;
		const height = observation.height;
		if (observation.spends.length > 0) {
			const spend = observation.spends[0];
			const moved = this.deps.ledger.move(live.id, 'CANCELLED', {
				failureReason: `funding spent before payment (${spend.kind})`,
				resolution: {
					kind: spend.kind,
					txid: spend.txid,
					height: spend.height > 0 ? spend.height : undefined,
					confirmations: spend.confirmations,
					verifiedThisSession: true
				}
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:cancelled', moved.record!, {
					reason: 'funding spent before payment',
					resolutionTxid: spend.txid
				});
			}
			return;
		}
		if (
			observation.funding.kind !== 'confirmed' ||
			!observation.funding.meetsPolicy
		) {
			// Reorged below policy: back to watching the output.
			this.deps.log('swap_funding_demoted', {
				swapId: live.id,
				kind: observation.funding.kind
			});
			const moved = this.deps.ledger.move(live.id, 'FUNDING_LOST', {
				fundingLostAt: this.now(),
				fundingHeight: undefined
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:funding-lost', moved.record!, {
					fundingTxid: live.fundingTxid,
					reason: observation.funding.kind
				});
			}
			return;
		}
		const deadline = this.deadlineProblem(live, height);
		if (deadline) {
			this.endBeforePayment(live, deadline);
			return;
		}
		const facts = this.invoiceFacts(live);
		if (this.spendableOutbound() < facts.amountMsat) {
			this.deps.log('swap_payment_deferred', {
				swapId: live.id,
				reason: 'insufficient outbound liquidity'
			});
			return;
		}
		const verdict = evaluateSwapExposure(this.config.exposure, {
			resolutionConfirmations: this.config.resolutionConfirmations,
			direction: 'submarine',
			amountSat: BigInt(live.onchainSat),
			live: this.deps.ledger.unresolved().filter((r) => r.id !== live.id)
		});
		if (!verdict.ok) {
			this.deps.log('swap_payment_deferred', {
				swapId: live.id,
				reason: `exposure: ${verdict.detail}`
			});
			return;
		}
		const ceiling = this.ceilingOf(live);
		const maxFeeMsat = this.maxFeeMsatFor(facts.amountMsat);
		const moved = this.deps.ledger.move(live.id, 'PAYING', {
			paymentDispatchedAt: this.now(),
			paymentDispatchedHeight: height,
			paymentMaxCltvExpiryHeight: ceiling,
			paymentMaxFeeMsat: maxFeeMsat.toString(),
			paymentDispatchAttempts: 1
		});
		if (moved.outcome !== 'applied') return;
		this.emitSwap('swap:paying', moved.record!, {
			maxCltvExpiryHeight: ceiling,
			maxFeeMsat: maxFeeMsat.toString()
		});
		await this.dispatch(moved.record!);
	}

	/** The payment call itself, then the view decides. Never awaits before. */
	private async dispatch(record: ISwapRecord): Promise<void> {
		const ceiling = this.ceilingOf(record);
		const maxFeeMsat = record.paymentMaxFeeMsat
			? BigInt(record.paymentMaxFeeMsat)
			: this.maxFeeMsatFor(BigInt(record.invoiceMsat));
		let dispatchError: string | undefined;
		try {
			this.deps.payInvoice(record.bolt11!, {
				maxCltvExpiryHeight: ceiling,
				maxFeeMsat
			});
		} catch (err) {
			dispatchError = err instanceof Error ? err.message : String(err);
			this.deps.log('swap_payment_dispatch_failed', {
				swapId: record.id,
				error: dispatchError
			});
		}
		const view = this.deps.outgoingHtlcs(
			Buffer.from(record.paymentHashHex, 'hex')
		);
		if (!view.preimage && view.status === null && view.htlcs.length === 0) {
			// The call left nothing behind: no record, no HTLC. That is a
			// failure to dispatch, final for this attempt.
			const moved = this.deps.ledger.move(record.id, 'PAYMENT_FAILED', {
				failureReason: `payment could not be dispatched: ${
					dispatchError ?? 'no record was created'
				}`
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:payment-failed', moved.record!, {
					reason: moved.record!.failureReason
				});
			}
			return;
		}
		await this.settlePaymentView(
			this.deps.ledger.get(record.id) ?? record,
			'dispatch'
		);
	}

	private async processPaying(record: ISwapRecord): Promise<void> {
		const current = await this.settlePaymentView(record, 'block');
		if (!current || current.state !== 'PAYING') return;
		const view = this.deps.outgoingHtlcs(
			Buffer.from(current.paymentHashHex, 'hex')
		);
		if (view.status !== null || view.htlcs.length > 0) return;
		// PAYING with no record and no HTLC on the node: the dispatch never
		// happened (a crash between the CAS and the call). Redo it once,
		// after the same checks a fresh dispatch runs, bounded.
		const attempts = current.paymentDispatchAttempts ?? 1;
		if (attempts >= this.config.maxPaymentDispatchAttempts) {
			const moved = this.deps.ledger.move(current.id, 'PAYMENT_FAILED', {
				failureReason: `payment never dispatched after ${attempts} attempts`
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:payment-failed', moved.record!, {
					reason: moved.record!.failureReason
				});
			}
			return;
		}
		if (!current.fundingTxid || current.fundingVout === undefined) return;
		const observation = await this.deps.resolver.observe({
			htlc: htlcOfRecord(current),
			funding: { txid: current.fundingTxid, vout: current.fundingVout },
			recorded: { fundingHeight: current.fundingHeight }
		});
		const live = this.deps.ledger.get(current.id);
		if (!live || live.state !== 'PAYING') return;
		if (
			observation.spends.length > 0 ||
			observation.funding.kind !== 'confirmed' ||
			!observation.funding.meetsPolicy
		) {
			// Nothing was paid and the coins are not ours to claim: end it.
			const moved = this.deps.ledger.move(live.id, 'PAYMENT_FAILED', {
				failureReason: 'funding no longer confirmed and unspent at re-dispatch'
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:payment-failed', moved.record!, {
					reason: moved.record!.failureReason
				});
			}
			return;
		}
		const deadline = this.deadlineProblem(live, observation.height);
		if (deadline) {
			const moved = this.deps.ledger.move(live.id, 'PAYMENT_FAILED', {
				failureReason: `re-dispatch refused: ${deadline}`
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:payment-failed', moved.record!, {
					reason: moved.record!.failureReason
				});
			}
			return;
		}
		const counted = this.deps.ledger.patch(live.id, {
			paymentDispatchAttempts: attempts + 1,
			paymentDispatchedAt: this.now(),
			paymentDispatchedHeight: observation.height
		});
		if (counted.outcome !== 'applied') return;
		this.deps.log('swap_payment_redispatch', {
			swapId: live.id,
			attempt: attempts + 1
		});
		await this.dispatch(counted.record!);
	}

	/**
	 * Read the node's HTLC view for the row and apply what it proves: a
	 * preimage promotes the row (from PAYING, PAYMENT_UNRESOLVED, EXPOSED
	 * and, late, PAYMENT_FAILED); every HTLC terminal without one fails it;
	 * a long wait marks it unresolved. Returns the row as it stands.
	 */
	private async settlePaymentView(
		record: ISwapRecord,
		trigger: string
	): Promise<ISwapRecord | undefined> {
		const paymentHash = Buffer.from(record.paymentHashHex, 'hex');
		const view = this.deps.outgoingHtlcs(paymentHash);
		let current: ISwapRecord | undefined = this.deps.ledger.get(record.id);
		if (!current) return undefined;
		if (view.preimage) {
			if (
				!crypto
					.createHash('sha256')
					.update(view.preimage)
					.digest()
					.equals(paymentHash)
			) {
				this.deps.log('swap_preimage_hash_mismatch', {
					swapId: current.id,
					trigger
				});
				return current;
			}
			const preimageHex = view.preimage.toString('hex');
			if (current.state === 'EXPOSED') {
				if (!current.preimageHex) {
					this.deps.ledger.recordPreimage(current.id, preimageHex, 'lightning');
					current = this.deps.ledger.get(current.id);
					if (current) {
						this.emitSwap('swap:preimage', current, { trigger });
					}
				}
				return current;
			}
			if (
				current.state === 'PAYING' ||
				current.state === 'PAYMENT_UNRESOLVED' ||
				current.state === 'PAYMENT_FAILED'
			) {
				const moved = this.deps.ledger.move(current.id, 'PREIMAGE_KNOWN', {
					preimageHex,
					preimageSource: 'lightning',
					failureReason: undefined
				});
				if (moved.outcome !== 'applied') return this.deps.ledger.get(record.id);
				current = moved.record!;
				this.deps.log(
					record.state === 'PAYMENT_FAILED'
						? 'swap_preimage_after_failure'
						: 'swap_preimage_known',
					{ swapId: current.id, trigger }
				);
				this.emitSwap('swap:preimage', current, {
					trigger,
					latePromotion: record.state === 'PAYMENT_FAILED'
				});
				await this.processClaim(current);
				return this.deps.ledger.get(record.id);
			}
			return current;
		}
		if (current.state === 'PAYING' || current.state === 'PAYMENT_UNRESOLVED') {
			if (view.resolved && (view.status !== null || view.htlcs.length > 0)) {
				const moved = this.deps.ledger.move(current.id, 'PAYMENT_FAILED', {
					failureReason: `payment ${
						view.status ?? 'unknown'
					}: every HTLC terminal without a preimage`
				});
				if (moved.outcome !== 'applied') return this.deps.ledger.get(record.id);
				this.emitSwap('swap:payment-failed', moved.record!, {
					reason: moved.record!.failureReason
				});
				return moved.record!;
			}
			if (
				current.state === 'PAYING' &&
				current.paymentDispatchedHeight !== undefined &&
				(view.status !== null || view.htlcs.length > 0) &&
				this.deps.currentHeight() - current.paymentDispatchedHeight >=
					this.config.unresolvedAfterBlocks
			) {
				const moved = this.deps.ledger.move(current.id, 'PAYMENT_UNRESOLVED', {
					paymentUnresolvedSince: this.deps.currentHeight()
				});
				if (moved.outcome !== 'applied') return this.deps.ledger.get(record.id);
				this.deps.log('swap_payment_unresolved', {
					swapId: current.id,
					latestOutstandingExpiry: view.latestOutstandingExpiry,
					htlcs: view.htlcs.length
				});
				this.emitSwap('swap:payment-unresolved', moved.record!, {
					latestOutstandingExpiry: view.latestOutstandingExpiry
				});
				return moved.record!;
			}
			return current;
		}
		if (current.state === 'EXPOSED' && !current.preimageHex && view.resolved) {
			// Every HTLC failed and no preimage exists: nothing was lost.
			const moved = this.deps.ledger.move(current.id, 'PAYMENT_FAILED', {
				failureReason: 'payment failed while exposed; nothing was paid'
			});
			if (moved.outcome === 'applied') {
				this.emitSwap('swap:payment-failed', moved.record!, {
					reason: moved.record!.failureReason
				});
				return moved.record!;
			}
		}
		return current;
	}

	private claimSpendOf(
		record: ISwapRecord,
		observation: ISwapChainObservation
	): ISwapSpendObservation | undefined {
		// Only the holder of the claim key can take the preimage branch, so
		// every claim-kind spend is one of our replacements; the deepest is
		// the fact.
		return observation.spends
			.filter((s) => s.kind === 'claim' || s.txid === record.claimTxid)
			.sort((a, b) => b.confirmations - a.confirmations)[0];
	}

	private async processClaim(record: ISwapRecord): Promise<void> {
		if (
			!record.preimageHex ||
			!record.fundingTxid ||
			record.fundingVout === undefined
		)
			return;
		let current = record;
		const observation = await this.deps.resolver.observe({
			htlc: htlcOfRecord(current),
			funding: { txid: record.fundingTxid, vout: record.fundingVout },
			recorded: {
				fundingHeight: current.fundingHeight,
				resolutionTxid: current.resolution?.txid,
				resolutionHeight: current.resolution?.height
			}
		});
		const live = this.deps.ledger.get(current.id);
		if (
			!live ||
			!live.preimageHex ||
			(live.state !== 'PREIMAGE_KNOWN' && live.state !== 'CLAIM_BROADCAST')
		)
			return;
		current = live;
		const height = observation.height;

		const ours = this.claimSpendOf(current, observation);
		if (ours) {
			const resolution: ISwapResolutionRecord = {
				kind: 'claim',
				txid: ours.txid,
				txHex: ours.txid === current.claimTxid ? current.claimTxHex : undefined,
				height: ours.height > 0 ? ours.height : undefined,
				confirmations: ours.confirmations,
				verifiedThisSession: true
			};
			if (ours.meetsPolicy) {
				const moved = this.deps.ledger.move(current.id, 'CLAIM_CONFIRMED', {
					resolution,
					claimTxid: ours.txid,
					settledAt: this.now()
				});
				if (moved.outcome !== 'applied') return;
				this.emitSwap('swap:claim-confirmed', moved.record!, {
					claimTxid: ours.txid,
					height: ours.height
				});
				return;
			}
			const patched = this.deps.ledger.patch(current.id, { resolution });
			if (patched.outcome === 'applied') current = patched.record!;
			if (ours.height > 0) return; // confirmed, waiting for depth
		} else if (
			current.resolution &&
			current.resolution.kind === 'claim' &&
			(current.resolution.confirmations > 0 ||
				!current.resolution.verifiedThisSession)
		) {
			// Our recorded claim is no longer in the history: it reorged out.
			this.deps.log('swap_resolution_demoted', {
				swapId: current.id,
				txid: current.resolution.txid,
				previousConfirmations: current.resolution.confirmations
			});
			const patched = this.deps.ledger.patch(current.id, {
				resolution: {
					...current.resolution,
					height: undefined,
					confirmations: 0,
					verifiedThisSession: true
				}
			});
			if (patched.outcome === 'applied') current = patched.record!;
		}

		const foreignConfirmed = observation.spends.find(
			(s) => s.kind !== 'claim' && s.txid !== current.claimTxid && s.height > 0
		);
		if (foreignConfirmed) {
			await this.expose(current, 'a foreign spend of the funding confirmed', {
				kind: foreignConfirmed.kind,
				txid: foreignConfirmed.txid,
				height: foreignConfirmed.height,
				confirmations: foreignConfirmed.confirmations,
				verifiedThisSession: true
			});
			return;
		}
		if (
			observation.funding.kind === 'absent' ||
			observation.funding.kind === 'reorged-out'
		) {
			await this.expose(current, `funding ${observation.funding.kind}`);
			return;
		}

		// Build, bump or rebroadcast.
		const fundingTx = observation.funding.tx;
		const valueSat = observation.funding.valueSat;
		const refundInMempool = observation.spends.find(
			(s) =>
				s.kind !== 'claim' && s.txid !== current.claimTxid && s.height === 0
		);
		const deadlineNear =
			height >= current.refundHeight - this.config.claimSafetyBlocks;
		if (deadlineNear) {
			this.deps.log(
				height > current.refundHeight
					? 'swap_claim_past_refund_height'
					: 'swap_claim_deadline_near',
				{
					swapId: current.id,
					height,
					refundHeight: current.refundHeight,
					claimTxid: current.claimTxid,
					level: 'error'
				}
			);
		}
		const needsBuild = !current.claimTxHex;
		const bumpDue =
			!needsBuild &&
			(refundInMempool !== undefined ||
				deadlineNear ||
				(current.claimBroadcastHeight !== undefined &&
					height - current.claimBroadcastHeight >=
						this.config.claimBumpIntervalBlocks));
		if (!needsBuild && !bumpDue) {
			if (!ours) await this.rebroadcastClaim(current);
			return;
		}
		// The bid. Outside the deadline window the market rate, clamped to
		// the configured cap. Inside it the clamp is lifted and every rebuild
		// at least doubles the previous bid, so the whole output above dust
		// is reached within a few blocks whatever the estimate says; at the
		// last block before the client's refund is eligible the bid IS the
		// whole output: losing fees beats losing the principal the preimage
		// already paid for (#743 audit).
		const vbytes = this.config.claimVbytesEstimate;
		const previous = current.claimFeeSat ? BigInt(current.claimFeeSat) : 0n;
		const rate =
			(await this.safeEstimate(
				this.config.claimFeeTargetBlocks,
				!deadlineNear
			)) ?? this.config.fallbackFeeRateSatPerVbyte;
		const allIn = valueSat - SWAP_DUST_FLOOR_SAT;
		const lastCall = height >= current.refundHeight - 1;
		let feeSat = BigInt(Math.ceil(rate * vbytes));
		let unknownRefundFee = false;
		if (!needsBuild) {
			// BIP 125 rule 4 against our own previous claim, and the
			// escalation inside the window.
			const floor = deadlineNear ? previous * 2n : previous + BigInt(vbytes);
			if (feeSat < floor) feeSat = floor;
		}
		if (refundInMempool) {
			// Outbid the client's refund on BOTH replacement rules: the
			// absolute fee plus our size (BIP 125 rule 4) and the fee rate
			// (Core rejects a replacement whose rate is not above the
			// replaced transaction's). The refund's fee is known only when
			// the contract output is its sole input; with more inputs its
			// fee is unknown and the bid goes all in.
			if (refundInMempool.tx.ins.length === 1) {
				const paid = refundInMempool.tx.outs.reduce(
					(sum, o) => sum + BigInt(o.value),
					0n
				);
				const refundFee = valueSat > paid ? valueSat - paid : 0n;
				const refundVsize = Math.max(1, refundInMempool.tx.virtualSize());
				const byFee = refundFee + BigInt(vbytes);
				const byRate =
					BigInt(Math.ceil((Number(refundFee) * vbytes) / refundVsize)) +
					BigInt(vbytes);
				const floor = byFee > byRate ? byFee : byRate;
				if (feeSat < floor) feeSat = floor;
			} else {
				unknownRefundFee = true;
			}
		}
		const cap = deadlineNear
			? allIn
			: BigInt(Math.ceil(this.config.maxFeeRateSatPerVbyte * vbytes));
		if (feeSat > cap) feeSat = cap;
		// All in, above any cap: at the last block before the refund is
		// eligible, and against a refund whose fee cannot be read (a refund
		// is only valid past the refund height, so this is the window).
		if (lastCall || unknownRefundFee) feeSat = allIn;
		if (valueSat - feeSat < SWAP_DUST_FLOOR_SAT) feeSat = allIn;
		if (!needsBuild && feeSat <= previous) {
			// At the cap already: put the same bytes out again.
			await this.rebroadcastClaim(current);
			return;
		}
		let claim: bitcoin.Transaction;
		try {
			claim = buildSwapClaimTx({
				htlc: htlcOfRecord(current),
				fundingTransaction: fundingTx,
				outputIndex: current.fundingVout!,
				destinationScript: this.deps.claimDestinationScript(),
				feeSatoshis: feeSat,
				privateKey: this.deps.deriveClaimKey(Buffer.from(current.id, 'hex')),
				preimage: Buffer.from(current.preimageHex!, 'hex')
			});
		} catch (err) {
			this.deps.log('swap_claim_build_failed', {
				swapId: current.id,
				error: err instanceof Error ? err.message : String(err)
			});
			return;
		}
		const patch: Partial<ISwapRecord> = {
			claimTxHex: claim.toHex(),
			claimTxid: claim.getId(),
			claimFeeSat: feeSat.toString(),
			claimBroadcastAttemptedAt: this.now(),
			claimBroadcastHeight: height,
			claimBumps: needsBuild ? 0 : (current.claimBumps ?? 0) + 1
		};
		// Persisted BEFORE the bytes leave.
		const stored =
			current.state === 'PREIMAGE_KNOWN'
				? this.deps.ledger.move(current.id, 'CLAIM_BROADCAST', patch)
				: this.deps.ledger.patch(current.id, patch);
		if (stored.outcome !== 'applied') return;
		current = stored.record!;
		await this.rebroadcastClaim(current);
		this.emitSwap('swap:claim-broadcast', current, {
			claimTxid: current.claimTxid,
			feeSat: current.claimFeeSat,
			bumps: current.claimBumps ?? 0
		});
	}

	private async rebroadcastClaim(record: ISwapRecord): Promise<void> {
		if (!record.claimTxHex) return;
		try {
			await this.deps.broadcast(record.claimTxHex);
		} catch (err) {
			this.deps.log('swap_claim_broadcast_failed', {
				swapId: record.id,
				error: err instanceof Error ? err.message : String(err)
			});
		}
	}

	private async expose(
		record: ISwapRecord,
		reason: string,
		resolution?: ISwapResolutionRecord
	): Promise<void> {
		const moved = this.deps.ledger.move(record.id, 'EXPOSED', {
			fundingLostAt: this.now(),
			resolution: resolution ?? record.resolution
		});
		if (moved.outcome !== 'applied') return;
		this.deps.log('swap_exposed', {
			swapId: record.id,
			previousState: record.state,
			reason,
			preimageKnown: record.preimageHex !== undefined,
			invoiceMsat: record.invoiceMsat,
			level: 'error'
		});
		this.emitSwap('swap:exposed', moved.record!, {
			reason,
			previousState: record.state,
			preimageKnown: record.preimageHex !== undefined
		});
	}

	/**
	 * A payment is out and the contract is not claimable. Keep reading the
	 * payment (a preimage or a failure still arrives), keep looking for the
	 * output (a reorg may bring it back), and keep the foreign resolution
	 * verified so exposure lifts once it is final.
	 */
	private async processExposed(record: ISwapRecord): Promise<void> {
		const settled = await this.settlePaymentView(record, 'exposed');
		if (!settled || settled.state !== 'EXPOSED') return;
		let current = settled;
		let observation: ISwapChainObservation | undefined;
		if (current.fundingTxid && current.fundingVout !== undefined) {
			observation = await this.deps.resolver.observe({
				htlc: htlcOfRecord(current),
				funding: { txid: current.fundingTxid, vout: current.fundingVout },
				recorded: {
					fundingHeight: current.fundingHeight,
					resolutionTxid: current.resolution?.txid,
					resolutionHeight: current.resolution?.height
				}
			});
		}
		const live = this.deps.ledger.get(current.id);
		if (!live || live.state !== 'EXPOSED') return;
		current = live;
		if (observation) {
			// Only a CONFIRMED foreign spend is a resolution to record; one in
			// the mempool is a refund to outbid, which the claim path does
			// once the row is back in CLAIM_BROADCAST (#743 audit).
			const foreign = observation.spends
				.filter(
					(s) =>
						s.kind !== 'claim' && s.txid !== current.claimTxid && s.height > 0
				)
				.sort((a, b) => b.confirmations - a.confirmations)[0];
			if (foreign) {
				const resolution: ISwapResolutionRecord = {
					kind: foreign.kind,
					txid: foreign.txid,
					height: foreign.height > 0 ? foreign.height : undefined,
					confirmations: foreign.confirmations,
					verifiedThisSession: true
				};
				if (
					current.preimageHex &&
					foreign.meetsPolicy &&
					!(
						current.resolution?.txid === foreign.txid &&
						current.resolution.confirmations >= foreign.confirmations
					)
				) {
					this.deps.log('swap_loss_realised', {
						swapId: current.id,
						txid: foreign.txid,
						invoiceMsat: current.invoiceMsat,
						level: 'error'
					});
				}
				this.deps.ledger.patch(current.id, { resolution });
				return;
			}
			if (
				current.resolution &&
				!observation.spends.some((s) => s.txid === current.resolution!.txid)
			) {
				// The foreign spend reorged away: exposure counts again.
				const patched = this.deps.ledger.patch(current.id, {
					resolution: {
						...current.resolution,
						height: undefined,
						confirmations: 0,
						verifiedThisSession: true
					}
				});
				if (patched.outcome === 'applied') current = patched.record!;
			}
			const present =
				observation.funding.kind === 'confirmed' ||
				observation.funding.kind === 'mempool';
			if (present && current.preimageHex) {
				// The output is back and unspent by anyone else: claim it.
				const moved = this.deps.ledger.move(current.id, 'CLAIM_BROADCAST', {
					fundingHeight:
						observation.funding.kind === 'confirmed'
							? observation.funding.height
							: undefined,
					resolution: undefined
				});
				if (moved.outcome !== 'applied') return;
				this.deps.log('swap_funding_returned', { swapId: current.id });
				await this.processClaim(moved.record!);
				return;
			}
			if (present) return;
		}
		// The tracked output is gone: another output paying the contract
		// may exist (a replacement funding after a reorg).
		const discovered = await this.deps.resolver.observe({
			htlc: htlcOfRecord(current)
		});
		const again = this.deps.ledger.get(current.id);
		if (!again || again.state !== 'EXPOSED') return;
		const candidate = this.pickCandidate(
			{ ...again, fundingTxid: undefined, fundingVout: undefined },
			discovered.candidates
		);
		if (candidate) {
			const patched = this.deps.ledger.patch(again.id, {
				fundingTxid: candidate.txid,
				fundingVout: candidate.vout,
				fundingValueSat: candidate.valueSat.toString(),
				fundingHeight: candidate.height > 0 ? candidate.height : undefined,
				resolution: undefined
			});
			if (patched.outcome === 'applied') {
				this.deps.log('swap_funding_repointed', {
					swapId: again.id,
					fundingTxid: candidate.txid
				});
			}
		}
	}

	private emitSwap(
		event: SubmarineSwapEventName,
		record: ISwapRecord,
		extra: Record<string, unknown> = {}
	): void {
		this.emit(event, {
			swapId: record.id,
			direction: 'submarine',
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
