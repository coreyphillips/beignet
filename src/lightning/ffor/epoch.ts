/**
 * FFOR: Fast-Forward Offline Receive — epoch establishment state machine
 * (spec §6/§7), M1 scope.
 *
 * Drives the setup handshake for BOTH roles:
 *
 *   R (recipient):        ff_init → (ff_accept) → ff_invoices
 *                          [+ ff_escape_sigs iff G > 0] → ff_begin → FF_EPOCH
 *   S (settlement peer):  (ff_init) → ff_accept → (ff_invoices)
 *                          [(ff_escape_sigs)] → (ff_begin) → FF_EPOCH
 *
 * plus zero-settlement cooperative close via ff_end (spec §7.5/§11.2) and
 * clean pre-ff_begin abort via ff_error (spec §11.1).
 *
 * The class wraps a plain-data IFforEpochStateData object BY REFERENCE — the
 * same object stored on IChannelState.ffor — so every mutation is picked up by
 * ordinary channel-state persistence.
 */

import crypto from 'crypto';
import { MessageType } from '../message/types';
import { HTLC_SUCCESS_WEIGHT } from '../channel/commitment-builder';
import { decode as decodeInvoice } from '../invoice/decode';
import {
	FforEpochState,
	FforVariant,
	IFforChannelContext,
	IFforEpochParams,
	IFforEpochStateData,
	IFforHandleResult,
	IFforSend,
	FFOR_RECONCILE_MARGIN_BLOCKS,
	FFOR_BEGIN_MAX_HEIGHT_SKEW
} from './types';
import {
	FF_INIT_TYPE,
	FF_ACCEPT_TYPE,
	IFforInitMessage,
	IFforAcceptMessage,
	decodeFforInitMessage,
	decodeFforAcceptMessage,
	decodeFforInvoicesMessage,
	decodeFforEscapeSigsMessage,
	decodeFforBeginMessage,
	decodeFforEndMessage,
	decodeFforErrorMessage,
	encodeFforInitMessage,
	encodeFforAcceptMessage,
	encodeFforInvoicesMessage,
	encodeFforEscapeSigsMessage,
	encodeFforBeginMessage,
	encodeFforEndMessage,
	encodeFforErrorMessage,
	verifyFforMessageSignature
} from './messages';

/**
 * Spec §8: the voucher dust floor — a voucher below
 * `dust_limit + HTLC-success fee at the frozen feerate` would be trimmed from
 * the commitment and be uncollectible on-chain. Mirrors the BOLT 3 trim rule
 * in commitment-builder's filterUntrimmedHtlcs: anchor (zero-fee-HTLC)
 * channels have a 0 second-level fee, so the floor is just the dust limit.
 * Returns msat.
 */
export function voucherDustFloorMsat(
	dustLimitSat: bigint,
	feeratePerKw: number,
	isAnchor: boolean
): bigint {
	const successFeeSat = isAnchor
		? 0n
		: BigInt(Math.floor((HTLC_SUCCESS_WEIGHT * feeratePerKw) / 1000));
	return (dustLimitSat + successFeeSat) * 1000n;
}

/**
 * §11.3: check an ff_init against S's advertised standing terms. Returns null
 * when acceptable, else the rejection reason. R "echoes" the advertised fee
 * terms in ff_init; offering MORE than advertised is fine (S only profits),
 * under-offering, over-budget, unsupported variant, or an epoch longer than
 * advertised is not.
 */
export function fforTermsViolation(
	params: IFforEpochParams,
	terms: import('../gossip/types').IFforTerms,
	currentBlockHeight: number
): string | null {
	const variantBit = 1 << (params.variant - 1);
	if ((terms.variants & variantBit) === 0) {
		return `variant ${params.variant} not offered (advertised variants bitfield ${terms.variants})`;
	}
	if (params.budgetMsat > terms.maxBudgetMsat) {
		return `budget_msat ${params.budgetMsat} exceeds advertised max_budget_msat ${terms.maxBudgetMsat}`;
	}
	if (params.feeBaseMsat < terms.ffFeeBaseMsat) {
		return `fee_base_msat ${params.feeBaseMsat} below advertised ff_fee_base_msat ${terms.ffFeeBaseMsat}`;
	}
	if (params.feeProportionalMillionths < terms.ffFeePpm) {
		return `fee_proportional_millionths ${params.feeProportionalMillionths} below advertised ff_fee_ppm ${terms.ffFeePpm}`;
	}
	if (
		currentBlockHeight > 0 &&
		params.settlementDeadline - currentBlockHeight > terms.maxEpochBlocks
	) {
		return (
			`epoch length ${params.settlementDeadline - currentBlockHeight} blocks ` +
			`exceeds advertised max_epoch_blocks ${terms.maxEpochBlocks}`
		);
	}
	return null;
}

/** Escape count J = ceil(budget / G) (spec §7.4/§10). Only valid for G > 0. */
export function escapeCount(
	budgetMsat: bigint,
	granularityMsat: bigint
): number {
	return Number((budgetMsat + granularityMsat - 1n) / granularityMsat);
}

const maxBigint = (a: bigint, b: bigint): bigint => (a > b ? a : b);

/**
 * Setup-time parameter validation derived from spec §7.1/§7.2/§8.
 * Returns null when valid, else a human-readable rejection reason.
 *
 * `sSpendableMsat` / `sReserveMsat` describe the SETTLEMENT PEER's side (its
 * spendable local balance and the reserve it must keep) as seen by whoever is
 * validating: S passes its own balance; R pre-checks with the remote balance.
 */
export function validateFforEpochParams(
	params: IFforEpochParams,
	ctx: IFforChannelContext,
	sSpendableMsat: bigint,
	sReserveMsat: bigint
): string | null {
	if (params.variant !== FforVariant.A && params.variant !== FforVariant.B) {
		return `unknown variant ${params.variant}`;
	}
	if (params.budgetMsat <= 0n) {
		return 'budget_msat must be positive';
	}
	const k = params.maxPayments;
	if (k < 1) {
		return 'max_payments must be at least 1';
	}
	if (params.minPaymentMsat <= 0n) {
		return 'min_payment_msat must be positive';
	}
	if (params.minPaymentMsat > params.budgetMsat) {
		return 'min_payment_msat exceeds budget_msat';
	}

	// §7.1: T_exp MUST satisfy T_exp ≥ D + reconcile_margin (recommended 1008).
	if (
		params.voucherExpiry <
		params.settlementDeadline + FFOR_RECONCILE_MARGIN_BLOCKS
	) {
		return (
			`voucher_expiry ${params.voucherExpiry} too close to settlement_deadline ` +
			`${params.settlementDeadline}: need at least ${FFOR_RECONCILE_MARGIN_BLOCKS} blocks of reconcile margin`
		);
	}
	// The deadline must be in the future (when we know the tip).
	if (
		ctx.currentBlockHeight > 0 &&
		params.settlementDeadline <= ctx.currentBlockHeight
	) {
		return `settlement_deadline ${params.settlementDeadline} not beyond current height ${ctx.currentBlockHeight}`;
	}

	// §8: vouchers occupy real HTLC slots on R's commitment — K must fit both
	// sides' advertised slot budgets.
	const maxHtlcs = Math.min(
		ctx.localMaxAcceptedHtlcs,
		ctx.remoteMaxAcceptedHtlcs
	);
	if (k > maxHtlcs) {
		return `max_payments ${k} exceeds max_accepted_htlcs ${maxHtlcs}`;
	}

	// §7.1: per-commitment points for n_R+1 … n_R+K — need at least K of them.
	if (params.rPerCommitmentPoints.length < k) {
		return (
			`r_per_commitment_points has ${params.rPerCommitmentPoints.length} entries, ` +
			`need max_payments = ${k}`
		);
	}
	for (const p of params.rPerCommitmentPoints) {
		if (p.length !== 33) {
			return 'r_per_commitment_points entry is not a 33-byte point';
		}
	}

	// §8: min_payment_msat must clear the voucher dust floor. Use the larger of
	// the two dust limits — the voucher output appears on R's commitment during
	// the epoch and is mirrored onto S's at reconciliation (§11.1 step 2).
	const dustFloor = voucherDustFloorMsat(
		maxBigint(ctx.localDustLimitSat, ctx.remoteDustLimitSat),
		ctx.feeratePerKw,
		ctx.isAnchor
	);
	if (params.minPaymentMsat < dustFloor) {
		return `min_payment_msat ${params.minPaymentMsat} below voucher dust floor ${dustFloor}`;
	}

	// §7.2: budget_msat ≤ S's spendable local balance − channel_reserve −
	// escape rounding slack (G).
	const spendable =
		sSpendableMsat - sReserveMsat * 1000n - params.escapeGranularityMsat;
	if (params.budgetMsat > spendable) {
		return (
			`budget_msat ${params.budgetMsat} exceeds settlement peer's spendable ` +
			`balance ${spendable} (balance − reserve − escape slack)`
		);
	}
	if (params.escapeGranularityMsat > 0n) {
		const G = params.escapeGranularityMsat;
		// §10 / B.5: G MUST be an integer multiple of 1000 msat (whole-satoshi
		// aggregate voucher) and ≥ the voucher dust floor (never trimmed).
		if (G % 1000n !== 0n) {
			return `escape_granularity_msat ${G} must be a multiple of 1000 msat`;
		}
		if (G < dustFloor) {
			return `escape_granularity_msat ${G} below the voucher dust floor ${dustFloor}`;
		}
		const j = escapeCount(params.budgetMsat, G);
		if (j > 0xffff) {
			return `escape set too large: ceil(budget/G) = ${j} exceeds 65535`;
		}
		// B.5: malformed granularity — J·G must overshoot budget by less than G
		// (i.e. (J−1)·G < budget). By construction of ceil this always holds; the
		// guard catches an inconsistent (budget, G) reaching validation.
		if (BigInt(j) * G - params.budgetMsat >= G) {
			return `malformed escape granularity: J·G − budget ≥ G (J=${j}, G=${G}, budget=${params.budgetMsat})`;
		}
	}

	// Variant/TLV consistency (§7.1/§7.2): B carries the tower hash set and
	// tower TLVs in ff_init; A's hash set arrives only in ff_accept.
	if (params.variant === FforVariant.B) {
		if (!params.paymentHashes || params.paymentHashes.length === 0) {
			return 'variant B requires payment_hashes in ff_init';
		}
		if (!params.towerNodeId) {
			return 'variant B requires tower_node_id in ff_init';
		}
		if (params.towerUri === undefined) {
			return 'variant B requires tower_uri in ff_init';
		}
	} else if (params.paymentHashes && params.paymentHashes.length > 0) {
		return 'variant A must not carry payment_hashes in ff_init (S generates them)';
	}
	// Hash-set size == K whenever the set is present.
	if (params.paymentHashes) {
		if (params.paymentHashes.length !== k) {
			return `payment_hashes has ${params.paymentHashes.length} entries, need max_payments = ${k}`;
		}
		for (const h of params.paymentHashes) {
			if (h.length !== 32) {
				return 'payment_hashes entry is not 32 bytes';
			}
		}
	}

	return null;
}

/** Fresh M2 settlement-state fields for a new epoch. */
function emptySettlementState(
	frozenFeeratePerKw: number,
	nR: bigint,
	rPreEpochPoint: Buffer | null
): Pick<
	IFforEpochStateData,
	| 'preimages'
	| 'lastSeq'
	| 'packages'
	| 'htlcAmountsMsat'
	| 'voucherAmountsMsat'
	| 'upstreamFulfilled'
	| 'upstreamHtlcIds'
	| 'sHtlcIdBase'
	| 'frozenFeeratePerKw'
	| 'nR'
	| 'rPreEpochPoint'
	| 'peerLastSeq'
> {
	return {
		preimages: [],
		lastSeq: 0,
		packages: [],
		htlcAmountsMsat: [],
		voucherAmountsMsat: [],
		upstreamFulfilled: [],
		upstreamHtlcIds: [],
		sHtlcIdBase: 0n,
		frozenFeeratePerKw,
		nR,
		rPreEpochPoint,
		peerLastSeq: null
	};
}

function ok(
	sends: IFforSend[],
	extra?: Partial<IFforHandleResult>
): IFforHandleResult {
	return { ok: true, sends, ...extra };
}

function fail(
	error: string,
	sends: IFforSend[] = [],
	extra?: Partial<IFforHandleResult>
): IFforHandleResult {
	return { ok: false, error, sends, ...extra };
}

/** Build an ff_error send for this channel/epoch. */
export function buildFforError(
	channelId: Buffer,
	epochId: Buffer,
	reason: string
): IFforSend {
	return {
		type: MessageType.FF_ERROR,
		payload: encodeFforErrorMessage({
			channelId,
			epochId,
			data: Buffer.from(reason, 'utf8')
		})
	};
}

/**
 * The epoch state machine. Holds (by reference) the plain-data state object
 * that also lives on IChannelState.ffor, so persistence sees every mutation.
 */
export class FforEpoch {
	readonly data: IFforEpochStateData;

	constructor(data: IFforEpochStateData) {
		this.data = data;
	}

	get epochId(): Buffer {
		return this.data.epochId;
	}

	get state(): FforEpochState {
		return this.data.state;
	}

	get params(): IFforEpochParams {
		return this.data.params;
	}

	isActive(): boolean {
		return this.data.state === FforEpochState.FF_EPOCH;
	}

	isSetup(): boolean {
		return (
			this.data.state === FforEpochState.FF_SETUP_INIT ||
			this.data.state === FforEpochState.FF_SETUP_ACCEPTED ||
			this.data.state === FforEpochState.FF_SETUP_INVOICES ||
			this.data.state === FforEpochState.FF_SETUP_ESCAPE_SIGS
		);
	}

	// ─────────────── R: initiate (ff_init) ───────────────

	/**
	 * R side: validate the proposed terms and produce a signed ff_init.
	 * Fee terms are proposed by R (§7.1); S accepts by responding or rejects
	 * with ff_error.
	 */
	static initiate(
		epochId: Buffer,
		params: IFforEpochParams,
		ctx: IFforChannelContext
	): { epoch?: FforEpoch; result: IFforHandleResult } {
		if (!ctx.signFn) {
			return { result: fail('cannot initiate FFOR epoch: no node key signer') };
		}
		if (ctx.usedEpochIds.has(epochId.toString('hex'))) {
			return {
				result: fail('epoch_id already used on this channel')
			};
		}
		// R's pre-flight check mirrors S's §7.2 verification: S's spendable side
		// is OUR remote balance, and the reserve S must keep is the one WE
		// required of it.
		const err = validateFforEpochParams(
			params,
			ctx,
			ctx.remoteBalanceMsat,
			ctx.remoteRequiredReserveSat
		);
		if (err) {
			return { result: fail(err) };
		}

		const msg: IFforInitMessage = {
			channelId: ctx.channelId,
			epochId,
			variant: params.variant,
			budgetMsat: params.budgetMsat,
			maxPayments: params.maxPayments,
			minPaymentMsat: params.minPaymentMsat,
			settlementDeadline: params.settlementDeadline,
			voucherExpiry: params.voucherExpiry,
			feeBaseMsat: params.feeBaseMsat,
			feeProportionalMillionths: params.feeProportionalMillionths,
			escapeGranularityMsat: params.escapeGranularityMsat,
			rPerCommitmentPoints: params.rPerCommitmentPoints,
			paymentHashes: params.paymentHashes,
			towerNodeId: params.towerNodeId,
			towerUri: params.towerUri,
			signature: Buffer.alloc(64)
		};
		// Encode with a zero placeholder signature, then sign via ctx.signFn so
		// the node private key never has to be handed to this module. The digest
		// covers type + body-without-signature (identical bytes regardless of
		// what currently sits in the 64-byte signature slot).
		const digestPayload = encodeFforInitMessage(msg);
		const sig = ctx.signFn(fforDigestForSend(FF_INIT_TYPE, digestPayload));
		sig.copy(digestPayload, digestPayload.length - 64);

		const data: IFforEpochStateData = {
			epochId: Buffer.from(epochId),
			role: 'recipient',
			state: FforEpochState.FF_SETUP_INIT,
			params,
			sCommitmentNumber: null,
			invoices: [],
			escapeSigs: [],
			escapeHtlcSigs: [],
			initSignature: Buffer.from(
				digestPayload.subarray(digestPayload.length - 64)
			),
			acceptSignature: null,
			remoteNodeId: ctx.remoteNodeId ? Buffer.from(ctx.remoteNodeId) : null,
			epochStartHeight: null,
			// M2 settlement state. R's own commitment number is n_R.
			...emptySettlementState(ctx.feeratePerKw, ctx.localCommitmentNumber, null)
		};

		return {
			epoch: new FforEpoch(data),
			result: ok([{ type: MessageType.FF_INIT, payload: digestPayload }])
		};
	}

	// ─────────────── S: handle ff_init → ff_accept ───────────────

	/**
	 * S side: validate a received ff_init and, on success, produce the epoch
	 * plus a signed ff_accept. On validation failure returns an ff_error send
	 * and no epoch (clean pre-ff_begin abort, §11.1).
	 */
	static acceptInit(
		payload: Buffer,
		ctx: IFforChannelContext
	): { epoch?: FforEpoch; result: IFforHandleResult } {
		let msg: IFforInitMessage;
		try {
			msg = decodeFforInitMessage(payload);
		} catch (e) {
			return {
				result: fail(`invalid ff_init: ${(e as Error).message}`)
			};
		}
		const reject = (reason: string): { result: IFforHandleResult } => ({
			result: fail(reason, [buildFforError(ctx.channelId, msg.epochId, reason)])
		});

		if (!ctx.signFn) {
			return reject('cannot accept FFOR epoch: no node key signer');
		}
		// ✍ non-repudiation (§7/§12.2): R's node-key signature over the init.
		if (
			!ctx.remoteNodeId ||
			!verifyFforMessageSignature(FF_INIT_TYPE, payload, ctx.remoteNodeId)
		) {
			return reject('ff_init node-key signature invalid');
		}
		if (ctx.usedEpochIds.has(msg.epochId.toString('hex'))) {
			return reject('epoch_id already used on this channel');
		}

		const params: IFforEpochParams = {
			variant: msg.variant,
			budgetMsat: msg.budgetMsat,
			maxPayments: msg.maxPayments,
			minPaymentMsat: msg.minPaymentMsat,
			settlementDeadline: msg.settlementDeadline,
			voucherExpiry: msg.voucherExpiry,
			feeBaseMsat: msg.feeBaseMsat,
			feeProportionalMillionths: msg.feeProportionalMillionths,
			escapeGranularityMsat: msg.escapeGranularityMsat,
			rPerCommitmentPoints: msg.rPerCommitmentPoints,
			paymentHashes: msg.paymentHashes,
			towerNodeId: msg.towerNodeId,
			towerUri: msg.towerUri
		};

		// §7.2: WE are S — our own local balance funds the vouchers, and the
		// reserve we must keep is the one the peer required of us.
		const err = validateFforEpochParams(
			params,
			ctx,
			ctx.localBalanceMsat,
			ctx.localRequiredReserveSat
		);
		if (err) {
			return reject(err);
		}

		// §11.3: when WE advertise standing FFOR terms, the ff_init must fall
		// within them (variant offered, budget/epoch-length capped, fees echoed).
		if (ctx.fforTerms) {
			const termsErr = fforTermsViolation(
				params,
				ctx.fforTerms,
				ctx.currentBlockHeight
			);
			if (termsErr) {
				return reject(`outside advertised FFOR terms: ${termsErr}`);
			}
		}

		// S always keeps its own per_commitment_secret_S[n0] — the seq-1
		// pre-revocation carried in every settlement package's TLV 1 (§9.1),
		// required in BOTH variants (§9.3/§12.1).
		if (!ctx.localPerCommitmentSecretN0) {
			return reject(
				'cannot accept FFOR epoch: per_commitment_secret_S[n0] unavailable'
			);
		}
		const sRevocationSecretN0 = Buffer.from(ctx.localPerCommitmentSecretN0);

		// Variant A: S also generates the preimage set P_1…P_K and retains it
		// durably (§9.2). H_1 MUST equal SHA256(per_commitment_secret_S[n0]) so
		// the upstream claim of payment 1 is itself the revocation of C_{n0}^S
		// (§7.2/§12.1) — i.e. P_1 IS that secret. Variant B: the tower holds the
		// preimages; S never sees them until ff_release.
		const preimages: Buffer[] = [];
		if (params.variant === FforVariant.A) {
			preimages.push(Buffer.from(sRevocationSecretN0));
			for (let i = 1; i < params.maxPayments; i++) {
				preimages.push(crypto.randomBytes(32));
			}
			params.paymentHashes = preimages.map((p) =>
				crypto.createHash('sha256').update(p).digest()
			);
		}

		const n0 = ctx.localCommitmentNumber;
		const acceptMsg: IFforAcceptMessage = {
			channelId: ctx.channelId,
			epochId: msg.epochId,
			sCommitmentNumber: n0,
			paymentHashes:
				params.variant === FforVariant.A ? params.paymentHashes : undefined,
			// Prototype extension (TLV 7): voucher HTLC id base — see types.ts.
			sHtlcIdBase: ctx.localNextHtlcId ?? 0n,
			signature: Buffer.alloc(64)
		};
		const acceptPayload = encodeFforAcceptMessage(acceptMsg);
		const sig = ctx.signFn(fforDigestForSend(FF_ACCEPT_TYPE, acceptPayload));
		sig.copy(acceptPayload, acceptPayload.length - 64);

		const data: IFforEpochStateData = {
			epochId: Buffer.from(msg.epochId),
			role: 'settlement_peer',
			state: FforEpochState.FF_SETUP_ACCEPTED,
			params,
			sCommitmentNumber: n0,
			invoices: [],
			escapeSigs: [],
			escapeHtlcSigs: [],
			initSignature: Buffer.from(msg.signature),
			acceptSignature: Buffer.from(
				acceptPayload.subarray(acceptPayload.length - 64)
			),
			remoteNodeId: Buffer.from(ctx.remoteNodeId),
			epochStartHeight: null,
			// M2 settlement state. From S's side, n_R is the REMOTE number, and
			// R's current point is snapshotted for the ff_revoke_batch check.
			...emptySettlementState(
				ctx.feeratePerKw,
				ctx.remoteCommitmentNumber,
				ctx.remoteCurrentPerCommitmentPoint
					? Buffer.from(ctx.remoteCurrentPerCommitmentPoint)
					: null
			),
			preimages,
			sHtlcIdBase: ctx.localNextHtlcId ?? 0n,
			sRevocationSecretN0
		};

		return {
			epoch: new FforEpoch(data),
			result: ok([{ type: MessageType.FF_ACCEPT, payload: acceptPayload }])
		};
	}

	// ─────────────── R: handle ff_accept → invoices/escapes/begin ───────────────

	/**
	 * R side: process S's ff_accept, then emit the remaining setup batch:
	 * ff_invoices, ff_escape_sigs (iff G > 0), ff_begin — after which the epoch
	 * is active on our side. The caller MUST durably persist the epoch state
	 * before the sends go out (result.persistFirst, spec §7.5).
	 */
	handleAccept(payload: Buffer, ctx: IFforChannelContext): IFforHandleResult {
		if (this.data.role !== 'recipient') {
			return this._setupViolation(ctx, 'ff_accept received by non-recipient');
		}
		if (this.data.state !== FforEpochState.FF_SETUP_INIT) {
			return this._setupViolation(
				ctx,
				`unexpected ff_accept in epoch state ${this.data.state}`
			);
		}
		let msg: IFforAcceptMessage;
		try {
			msg = decodeFforAcceptMessage(payload);
		} catch (e) {
			return this._setupViolation(
				ctx,
				`invalid ff_accept: ${(e as Error).message}`
			);
		}
		if (!msg.epochId.equals(this.data.epochId)) {
			return this._setupViolation(ctx, 'ff_accept epoch_id mismatch');
		}
		if (
			!ctx.remoteNodeId ||
			!verifyFforMessageSignature(FF_ACCEPT_TYPE, payload, ctx.remoteNodeId)
		) {
			return this._setupViolation(ctx, 'ff_accept node-key signature invalid');
		}

		const params = this.data.params;
		if (params.variant === FforVariant.A) {
			// Variant A: adopt S's hash set (count MUST equal K).
			if (
				!msg.paymentHashes ||
				msg.paymentHashes.length !== params.maxPayments
			) {
				return this._setupViolation(
					ctx,
					`ff_accept payment_hashes count ${
						msg.paymentHashes?.length ?? 0
					} != max_payments ${params.maxPayments}`
				);
			}
			// NOTE (§7.2): R cannot verify the H_1 = SHA256(per_commitment_secret_S[n0])
			// binding at setup; it is verified ex post at settlement 1 (M2).
			params.paymentHashes = msg.paymentHashes;
		} else if (msg.paymentHashes && msg.paymentHashes.length > 0) {
			return this._setupViolation(
				ctx,
				'variant B ff_accept must not carry payment_hashes'
			);
		}
		this.data.sCommitmentNumber = msg.sCommitmentNumber;
		this.data.acceptSignature = Buffer.from(msg.signature);
		// Prototype extension (ff_accept TLV 7): the voucher HTLC id base.
		this.data.sHtlcIdBase = msg.sHtlcIdBase ?? 0n;

		// ff_invoices (§7.3): K amountless BOLT 11 invoices for H_1…H_K.
		if (!ctx.invoiceFactory) {
			return this._setupViolation(ctx, 'no invoice factory configured');
		}
		let invoices: string[];
		try {
			invoices = ctx.invoiceFactory(params.paymentHashes!);
		} catch (e) {
			return this._setupViolation(
				ctx,
				`invoice factory failed: ${(e as Error).message}`
			);
		}
		if (invoices.length !== params.maxPayments) {
			return this._setupViolation(
				ctx,
				`invoice factory returned ${invoices.length} invoices, need ${params.maxPayments}`
			);
		}
		this.data.invoices = invoices;

		const sends: IFforSend[] = [
			{
				type: MessageType.FF_INVOICES,
				payload: encodeFforInvoicesMessage({
					channelId: ctx.channelId,
					epochId: this.data.epochId,
					invoices
				})
			}
		];

		// ff_escape_sigs (§7.4/§10, Appendix B), iff G > 0: R builds the
		// deterministic escape set E_1…E_J at S's commitment number n0+1 and
		// signs each with its funding key (SIGHASH_ALL). escape_htlc_sigs stays
		// empty in v1 (the aggregate voucher needs no second-level tx).
		if (params.escapeGranularityMsat > 0n) {
			if (!ctx.buildEscapeSigs) {
				return this._setupViolation(
					ctx,
					'cannot build escape signatures: no escape signer configured'
				);
			}
			try {
				this.data.escapeSigs = ctx.buildEscapeSigs(params);
			} catch (e) {
				return this._setupViolation(
					ctx,
					`escape signing failed: ${(e as Error).message}`
				);
			}
			this.data.escapeHtlcSigs = [];
			sends.push({
				type: MessageType.FF_ESCAPE_SIGS,
				payload: encodeFforEscapeSigsMessage({
					channelId: ctx.channelId,
					epochId: this.data.epochId,
					escapeSigs: this.data.escapeSigs
				})
			});
		}

		// ff_begin (§7.5). Setup state must be durably persisted BEFORE this
		// goes out — the caller orders persistence ahead of the sends
		// (result.persistFirst).
		this.data.epochStartHeight = ctx.currentBlockHeight;
		this.data.state = FforEpochState.FF_EPOCH;
		sends.push({
			type: MessageType.FF_BEGIN,
			payload: encodeFforBeginMessage({
				channelId: ctx.channelId,
				epochId: this.data.epochId,
				epochStartHeight: ctx.currentBlockHeight
			})
		});

		return ok(sends, { enteredEpoch: true, persistFirst: true });
	}

	// ─────────────── S: handle ff_invoices / ff_escape_sigs / ff_begin ───────────────

	/** S side: validate and store R's pre-signed invoice set (§7.3). */
	handleInvoices(payload: Buffer, ctx: IFforChannelContext): IFforHandleResult {
		if (this.data.role !== 'settlement_peer') {
			return this._setupViolation(
				ctx,
				'ff_invoices received by non-settlement peer'
			);
		}
		if (this.data.state !== FforEpochState.FF_SETUP_ACCEPTED) {
			return this._setupViolation(
				ctx,
				`unexpected ff_invoices in epoch state ${this.data.state}`
			);
		}
		let msg;
		try {
			msg = decodeFforInvoicesMessage(payload);
		} catch (e) {
			return this._setupViolation(
				ctx,
				`invalid ff_invoices: ${(e as Error).message}`
			);
		}
		if (!msg.epochId.equals(this.data.epochId)) {
			return this._setupViolation(ctx, 'ff_invoices epoch_id mismatch');
		}
		const params = this.data.params;
		if (msg.invoices.length !== params.maxPayments) {
			return this._setupViolation(
				ctx,
				`ff_invoices count ${msg.invoices.length} != max_payments ${params.maxPayments}`
			);
		}
		// §7.3: each invoice must be amountless, carry hash H_i, and be signed by
		// R's node key.
		for (let i = 0; i < msg.invoices.length; i++) {
			let inv;
			try {
				inv = decodeInvoice(msg.invoices[i]);
			} catch (e) {
				return this._setupViolation(
					ctx,
					`invoice ${i + 1} undecodable: ${(e as Error).message}`
				);
			}
			if (inv.amountMsat !== undefined) {
				return this._setupViolation(
					ctx,
					`invoice ${i + 1} carries an amount (must be amountless)`
				);
			}
			const expected = params.paymentHashes?.[i];
			if (!expected || !inv.paymentHash.equals(expected)) {
				return this._setupViolation(
					ctx,
					`invoice ${i + 1} payment_hash != H_${i + 1}`
				);
			}
			const signer = inv.payeeNodeKey ?? inv.recoveredPubkey;
			if (ctx.remoteNodeId && signer && !signer.equals(ctx.remoteNodeId)) {
				return this._setupViolation(
					ctx,
					`invoice ${i + 1} not signed by the recipient's node key`
				);
			}
		}
		this.data.invoices = msg.invoices;
		this.data.state = FforEpochState.FF_SETUP_INVOICES;
		return ok([]);
	}

	/**
	 * S side (§7.4/§10, Appendix B.1): verify R's escape signature set against
	 * the deterministic escape commitments, then store it. S MUST refuse the
	 * epoch on any failure.
	 */
	handleEscapeSigs(
		payload: Buffer,
		ctx: IFforChannelContext
	): IFforHandleResult {
		if (this.data.role !== 'settlement_peer') {
			return this._setupViolation(
				ctx,
				'ff_escape_sigs received by non-settlement peer'
			);
		}
		if (this.data.state !== FforEpochState.FF_SETUP_INVOICES) {
			return this._setupViolation(
				ctx,
				`unexpected ff_escape_sigs in epoch state ${this.data.state}`
			);
		}
		const params = this.data.params;
		if (params.escapeGranularityMsat <= 0n) {
			return this._setupViolation(
				ctx,
				'ff_escape_sigs received but escape_granularity_msat is 0'
			);
		}
		let msg;
		try {
			msg = decodeFforEscapeSigsMessage(payload);
		} catch (e) {
			return this._setupViolation(
				ctx,
				`invalid ff_escape_sigs: ${(e as Error).message}`
			);
		}
		if (!msg.epochId.equals(this.data.epochId)) {
			return this._setupViolation(ctx, 'ff_escape_sigs epoch_id mismatch');
		}
		const j = escapeCount(params.budgetMsat, params.escapeGranularityMsat);
		if (msg.escapeSigs.length !== j) {
			return this._setupViolation(
				ctx,
				`ff_escape_sigs count ${msg.escapeSigs.length} != ceil(budget/G) = ${j}`
			);
		}
		// Appendix B.1: S MUST verify every escape signature before ff_begin and
		// MUST refuse the epoch on any failure. escape_htlc_sigs MUST be omitted
		// in v1 (§7.4) — reject if present.
		if (msg.escapeHtlcSigs && msg.escapeHtlcSigs.length > 0) {
			return this._setupViolation(
				ctx,
				'ff_escape_sigs carries escape_htlc_sigs (MUST be omitted in v1)'
			);
		}
		if (!ctx.verifyEscapeSigs) {
			return this._setupViolation(
				ctx,
				'cannot verify escape signatures: no escape verifier configured'
			);
		}
		const verifyErr = ctx.verifyEscapeSigs(params, msg.escapeSigs);
		if (verifyErr) {
			return this._setupViolation(ctx, verifyErr);
		}
		this.data.escapeSigs = msg.escapeSigs;
		this.data.escapeHtlcSigs = [];
		this.data.state = FforEpochState.FF_SETUP_ESCAPE_SIGS;
		return ok([]);
	}

	/**
	 * S side: ff_begin (§7.5) — all setup messages must have arrived; on
	 * success the epoch becomes active and MUST be durably persisted
	 * (result.persistFirst).
	 */
	handleBegin(payload: Buffer, ctx: IFforChannelContext): IFforHandleResult {
		if (this.data.role !== 'settlement_peer') {
			return this._setupViolation(
				ctx,
				'ff_begin received by non-settlement peer'
			);
		}
		const params = this.data.params;
		const expectedState =
			params.escapeGranularityMsat > 0n
				? FforEpochState.FF_SETUP_ESCAPE_SIGS
				: FforEpochState.FF_SETUP_INVOICES;
		if (this.data.state !== expectedState) {
			return this._setupViolation(
				ctx,
				`unexpected ff_begin in epoch state ${this.data.state} (need ${expectedState})`
			);
		}
		let msg;
		try {
			msg = decodeFforBeginMessage(payload);
		} catch (e) {
			return this._setupViolation(
				ctx,
				`invalid ff_begin: ${(e as Error).message}`
			);
		}
		if (!msg.epochId.equals(this.data.epochId)) {
			return this._setupViolation(ctx, 'ff_begin epoch_id mismatch');
		}
		// §7.5: epoch_start_height MUST be within a few blocks of the current
		// tip (only checkable when we know the tip).
		if (
			ctx.currentBlockHeight > 0 &&
			Math.abs(msg.epochStartHeight - ctx.currentBlockHeight) >
				FFOR_BEGIN_MAX_HEIGHT_SKEW
		) {
			return this._setupViolation(
				ctx,
				`ff_begin epoch_start_height ${msg.epochStartHeight} not within ` +
					`${FFOR_BEGIN_MAX_HEIGHT_SKEW} blocks of tip ${ctx.currentBlockHeight}`
			);
		}
		this.data.epochStartHeight = msg.epochStartHeight;
		this.data.state = FforEpochState.FF_EPOCH;
		return ok([], { enteredEpoch: true, persistFirst: true });
	}

	// ─────────────── ff_end: zero-settlement cooperative close ───────────────

	/**
	 * Either side: close a zero-settlement epoch cooperatively (§7.5: "an epoch
	 * with zero settlements is closed cooperatively with ff_end at any time";
	 * §11.2 zero-settlement case).
	 *
	 * Escapes with G > 0: a plain ff_end is safe for a zero-settlement epoch.
	 * Nothing is owed, so any E_j S might broadcast pays R j·G ≥ 0 — it only
	 * OVERPAYS R and costs S for nothing (§12.1). The escapes live at n0+1 and
	 * die automatically the next time that index is revoked in ordinary
	 * operation (§12.1 note). A cooperative close after settlements goes through
	 * reconciliation instead, which reveals per_commitment_secret_S[n0+1] and
	 * makes every E_j penalizable at once (§11.1 step 3).
	 */
	end(ctx: IFforChannelContext): IFforHandleResult {
		// ff_end closes a zero-settlement epoch directly from FF_EPOCH (§7.5),
		// or completes reconciliation (§11.1 step 5) from FF_RECONCILE.
		if (
			this.data.state !== FforEpochState.FF_EPOCH &&
			this.data.state !== FforEpochState.FF_RECONCILE
		) {
			return fail(`cannot end FFOR epoch in state ${this.data.state}`);
		}
		this.data.state = FforEpochState.FF_CLOSED;
		return ok(
			[
				{
					type: MessageType.FF_END,
					payload: encodeFforEndMessage({
						channelId: ctx.channelId,
						epochId: this.data.epochId
					})
				}
			],
			{ closed: true, persistFirst: true }
		);
	}

	/** Either side: peer's ff_end. Echo ours if we had not closed yet (§11.1 "×2"). */
	handleEnd(payload: Buffer, ctx: IFforChannelContext): IFforHandleResult {
		let msg;
		try {
			msg = decodeFforEndMessage(payload);
		} catch (e) {
			return fail(`invalid ff_end: ${(e as Error).message}`);
		}
		if (!msg.epochId.equals(this.data.epochId)) {
			return fail('ff_end epoch_id mismatch');
		}
		if (this.data.state === FforEpochState.FF_CLOSED) {
			// We initiated and this is the echo — idempotent.
			return ok([], { closed: true });
		}
		if (
			this.data.state !== FforEpochState.FF_EPOCH &&
			this.data.state !== FforEpochState.FF_RECONCILE
		) {
			return fail(`unexpected ff_end in epoch state ${this.data.state}`);
		}
		this.data.state = FforEpochState.FF_CLOSED;
		return ok(
			[
				{
					type: MessageType.FF_END,
					payload: encodeFforEndMessage({
						channelId: ctx.channelId,
						epochId: this.data.epochId
					})
				}
			],
			{ closed: true, persistFirst: true }
		);
	}

	// ─────────────── ff_error ───────────────

	/**
	 * Peer's ff_error (§11.1): before ff_begin it aborts setup (clean); during
	 * FF_EPOCH the channel falls back to on-chain enforcement rather than
	 * aborting — M1 records/reports it and leaves the epoch untouched.
	 *
	 * TODO(FFOR M3, spec §11.1): wire the FF_EPOCH-time fallback to on-chain
	 * enforcement (force-close C_j^R / escape handling).
	 */
	handleError(payload: Buffer): IFforHandleResult {
		let reason = 'ff_error';
		try {
			const msg = decodeFforErrorMessage(payload);
			reason = `ff_error from peer: ${msg.data.toString('utf8')}`;
		} catch {
			// Undecodable error data — treat as an opaque abort signal.
		}
		if (this.isSetup()) {
			this.data.state = FforEpochState.FF_CLOSED;
			return fail(reason, [], { aborted: true });
		}
		return fail(reason);
	}

	/**
	 * Local abort during setup: mark closed and produce the ff_error to send
	 * (clean pre-ff_begin abort, §11.1).
	 */
	private _setupViolation(
		ctx: IFforChannelContext,
		reason: string
	): IFforHandleResult {
		if (this.isSetup()) {
			this.data.state = FforEpochState.FF_CLOSED;
			return fail(
				reason,
				[buildFforError(ctx.channelId, this.data.epochId, reason)],
				{ aborted: true }
			);
		}
		return fail(reason, [
			buildFforError(ctx.channelId, this.data.epochId, reason)
		]);
	}
}

/**
 * Digest for signing an outgoing ✍ message whose signature slot is still a
 * placeholder: identical bytes to messages.fforMessageDigest (the digest never
 * covers the final 64 bytes, whatever they currently contain).
 */
function fforDigestForSend(type: number, payload: Buffer): Buffer {
	const typeBuf = Buffer.alloc(2);
	typeBuf.writeUInt16BE(type, 0);
	return crypto
		.createHash('sha256')
		.update(typeBuf)
		.update(payload.subarray(0, payload.length - 64))
		.digest();
}
