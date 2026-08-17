/**
 * BOLT 2 v2: Dual-Funding Session.
 *
 * Orchestrates the v2 channel opening flow:
 *   open_channel2 -> accept_channel2 -> interactive TX negotiation
 *   -> tx_signatures -> channel_ready
 *
 * Manages state transitions and uses InteractiveTxBuilder for
 * collaborative transaction construction.
 *
 * Trust model for peer inputs (issue #311): interactive-tx is a BOLT 2
 * property, so every receive-side check of a peer's tx_add_input prev_tx
 * (parse, vout range, segwit-only, the tx_complete solvency audit, witness
 * verification) is self-consistency over bytes the peer chose. A fabricated
 * prevout yields a negotiated funding tx that can never confirm, while our
 * pledged inputs stay reserved. Two mitigations, both best effort:
 *   - When the node has a chain backend, peer prevouts are verified against
 *     the chain as tx_add_input arrives (ChannelManager.verifyPeerFundingInput)
 *     and POSITIVE evidence of a spend (the prevout's tx confirmed on its
 *     script with the output no longer unspent) aborts the negotiation.
 *     Absence from the server's view is NOT conclusive (BOLT 2 permits
 *     unconfirmed inputs and an honest parent may not be indexed yet), so a
 *     fully fabricated prevout classifies 'unknown' and proceeds; the pledge
 *     release below is the mitigation for that case. A fast negotiation can
 *     outrun the verdict. Splice inputs are not covered.
 *   - When a v2 open dies terminally before our tx_signatures were released,
 *     its funding pledges release at once (releaseInputPledges) instead of
 *     waiting out the pledge TTL. Post-signature deaths keep the TTL as the
 *     backstop: the peer may broadcast, so an early release could double
 *     spend a funding tx that still confirms.
 *
 * tx_abort and RBF refusal semantics (issue #309): tx_abort IS the refusal
 * signal for tx_init_rbf. BOLT 2 makes it explicit: the recipient "MUST
 * respond either with tx_abort or with tx_ack_rbf" and "MAY send tx_abort
 * for any reason". The refusal is ATTEMPT-scoped, never open-scoped: only
 * the replacement attempt dies, both sides retain the current attempt, and
 * with a fully signed attempt the channel keeps waiting for confirmation
 * (tx_abort receiver rule: having sent tx_signatures, a node "MUST NOT
 * forget the channel until any inputs to the negotiated tx have been
 * spent"). Verified against both major implementations:
 *   - Eclair 0.14.1 (ChannelOpenDualFunded.scala) rejects tx_init_rbf with
 *     stay() + TxAbort (status RbfAborted, channel alive), and treats an
 *     answering tx_abort to its own request as "our peer rejected our rbf
 *     attempt": it rolls back to WaitingForConfirmations and stays in
 *     WAIT_FOR_DUAL_FUNDING_CONFIRMED on the original funding tx.
 *   - CLN (openingd/dualopend.c) refuses in rbf_remote_start via
 *     open_abort() (sends tx_abort) and frees only the RBF-scoped tx_state,
 *     keeping the previously committed attempt; its handle_tx_abort echoes
 *     and aborts the negotiation without disconnecting.
 * Channel.handleTxInitRbf / handleTxAbort implement the same convergence
 * (the pending-RBF branch consumes an incoming tx_abort as the refusal and
 * resumes the frozen tx_signatures release of the retained attempt).
 *
 * RBF window (issue #360): the spec window is supported in both directions.
 * A funding tx may be replaced from the initial commitment exchange until
 * channel_ready crosses in either direction or an attempt confirms —
 * covering both beignet's legacy pre-signatures window and the BOLT 2
 * window Eclair/CLN use (a completed, broadcast, unconfirmed attempt). The
 * codecs carry the funding_output_contribution and require_confirmed_inputs
 * TLVs. Superseded broadcastable attempts are retained durably
 * (IChannelState.v2PreviousAttempts) and chain-watched beside the current
 * one: each replacement double-spends all of its predecessors (enforced at
 * tx_complete beside the fee-not-lower rule), at most one attempt can
 * confirm, and whichever does is adopted.
 *
 * Either side may change its funding_output_contribution per attempt, so
 * capacity, both balances and both capacity-derived channel reserves are
 * per-attempt too: every record snapshots the amounts its commitment #0 was
 * built at, and every rollback, adoption and restart restores them together
 * with the funding outpoint (an attempt rebuilt at another attempt's amounts
 * would not be covered by the peer's stored signature). An absent TLV means
 * "unchanged" rather than the spec's "not contributing", for compatibility
 * with beignet peers predating the TLV.
 *
 * Neither reserve is negotiated on a v2 channel (issue #379): BOLT 2 fixes it
 * at 1% of the total capacity or the dust_limit_satoshis, whichever is greater,
 * with no maximum, and both peers derive it. See Channel.v2ReserveWeKeep /
 * v2ReserveWeEnforce for which dust limit floors which side and why. A peer's
 * dust_limit_satoshis is bounded here at both receive sites, as v1 has bounded
 * it since the FS-1 audit: unbounded, it both trims our commitment output away
 * and drives the derived reserve past the whole capacity.
 *
 * open_channel2 and accept_channel2 also INHERIT their v1 counterparts'
 * requirements, so both receive sites run BOLT 2's initial-commitment MUST-fails
 * (Channel._v2InitialCommitmentRefusal, shared with the RBF path): the funder
 * must afford commitment #0's fee, and neither a both-sides-below-reserve split
 * nor one whose every output trims at either dust limit is admitted, since the
 * resulting commitment has no outputs and cannot be broadcast at all.
 *
 * Deliberate policy residuals, all spec-legal under
 * MAY-abort-for-any-reason:
 *   - post-restart replacements are refused (the wallet signing closures
 *     die with the process; adoption of persisted candidates still works);
 *   - contribution changes are refused on a leased open (bLIP-51: the
 *     will_fund signature and the lease fee were made over the original
 *     amounts);
 *   - initiation stays opener-only (the spec allows either side; Eclair
 *     and CLN only expose opener-side commands).
 */

import { InteractiveTxBuilder } from '../interactive-tx/builder';
import {
	InteractiveTxState,
	IInteractiveTxInput,
	IInteractiveTxOutput
} from '../interactive-tx/types';
import {
	IOpenChannel2Message,
	IAcceptChannel2Message,
	IRequestFunds,
	IWillFund
} from '../message/dual-funding';
import {
	MIN_DUST_LIMIT_SATOSHIS,
	MAX_DUST_LIMIT_SATOSHIS,
	MAX_ACCEPTED_HTLCS,
	MAX_FUNDING_SATOSHIS
} from './types';
import { IChannelBasepoints } from '../keys/derivation';
import { ILeaseRates } from '../gossip/types';

/**
 * BOLT 2: the minimum feerate for an RBF attempt is the greater of 25/24 of
 * the previous funding feerate (rounded down) and 25 sat/kw above it. At
 * tiny feerates the ratio arm rounds down near the previous value, so the
 * additive +25 arm is the floor there.
 */
export function rbfFeerateFloor(previousFeeratePerkw: number): number {
	return Math.max(
		Math.floor((previousFeeratePerkw * 25) / 24),
		previousFeeratePerkw + 25
	);
}

/** Dual-funding session states */
export enum DualFundingState {
	/** Initial state before open_channel2 sent/received */
	NONE = 'NONE',
	/** Opener sent open_channel2, awaiting accept_channel2 */
	AWAITING_ACCEPT = 'AWAITING_ACCEPT',
	/** Interactive TX negotiation in progress */
	TX_NEGOTIATION = 'TX_NEGOTIATION',
	/** TX construction complete, awaiting tx_signatures from peer */
	AWAITING_TX_SIGNATURES = 'AWAITING_TX_SIGNATURES',
	/** Funding tx broadcast, awaiting channel_ready from peer */
	AWAITING_CHANNEL_READY = 'AWAITING_CHANNEL_READY',
	/** Both sides exchanged channel_ready */
	COMPLETE = 'COMPLETE',
	/** Session aborted */
	ABORTED = 'ABORTED'
}

/** Parameters for opening a dual-funded channel */
export interface IDualFundingParams {
	/** Genesis hash of the target chain (open_channel2's first field). */
	chainHash?: Buffer;
	/** Our funding contribution in satoshis */
	fundingSatoshis: bigint;
	/** Fee rate for the funding transaction (sat/kw) */
	fundingFeeratePerkw: number;
	/** Fee rate for commitment transactions (sat/kw) */
	commitmentFeeratePerkw: number;
	/** Dust limit in satoshis */
	dustLimitSatoshis: bigint;
	/** Max HTLC value in flight in millisatoshis */
	maxHtlcValueInFlightMsat: bigint;
	/** HTLC minimum in millisatoshis */
	htlcMinimumMsat: bigint;
	/** to_self_delay in blocks */
	toSelfDelay: number;
	/** Max number of accepted HTLCs */
	maxAcceptedHtlcs: number;
	/** Locktime for the funding transaction */
	locktime: number;
	/** Local basepoints */
	localBasepoints: IChannelBasepoints;
	/** Local per-commitment seed */
	localPerCommitmentSeed: Buffer;
	/** Channel flags (bit 0 = announce_channel) */
	channelFlags?: number;
	/** Channel type feature bitmap */
	channelType?: Buffer;
	/**
	 * Acceptor only: minimum_depth advertised in accept_channel2. Defaults to
	 * 3; a zero_conf channel type requires 0 (BOLT 2).
	 */
	minimumDepth?: number;
	/** Second per-commitment point */
	secondPerCommitmentPoint: Buffer;
	/** Liquidity ads (bLIP-0051): buyer's inbound-liquidity request (opener). */
	requestFunds?: IRequestFunds;
	/**
	 * Liquidity ads (bLIP-0051): the MAXIMUM lease rates the buyer will accept.
	 * This MUST be a buyer-chosen local policy limit (e.g. the rates the buyer
	 * decided were acceptable before requesting), NOT copied blindly from the
	 * seller's gossip ad: the seller controls both the ad and will_fund, so a
	 * seller-derived ceiling would bound nothing. Local-only (NOT sent on the
	 * wire). The seller's will_fund rates are self-signed and otherwise
	 * unbounded, so without this ceiling an inflated will_fund could drain
	 * nearly the buyer's whole balance as a lease fee. handleAcceptChannel2
	 * rejects a lease whose computed fee exceeds the fee implied by these rates.
	 */
	maxLeaseRates?: ILeaseRates;
	/** Liquidity ads (bLIP-0051): seller's signed will_fund commitment (acceptor). */
	willFund?: IWillFund;
	/**
	 * Max (sweep-everything) open: fundingSatoshis was quoted as the whole
	 * spendable balance minus the interactive-tx fee, and funding contributes
	 * EVERY spendable UTXO so the change nets out to zero. Local-only (NOT
	 * sent on the wire); consumed by autoFundDualFundedOpen to select all
	 * inputs instead of covering a fixed amount.
	 */
	fundMax?: boolean;
}

/** Result of a dual-funding operation */
export interface IDualFundingResult {
	ok: boolean;
	error?: string;
}

/**
 * Dual-Funding Session.
 *
 * Manages the lifecycle of a v2 (dual-funded) channel opening,
 * including interactive transaction construction and RBF.
 */
export class DualFundingSession {
	private _state: DualFundingState = DualFundingState.NONE;
	private _isInitiator: boolean;
	private _channelId: Buffer;
	private _txBuilder: InteractiveTxBuilder | null = null;

	/** Our parameters */
	private _localParams: IDualFundingParams | null = null;
	/** Remote's parameters (from open_channel2 or accept_channel2) */
	private _remoteParams: Partial<IDualFundingParams> | null = null;
	/** Remote basepoints */
	private _remoteBasepoints: IChannelBasepoints | null = null;
	/** Remote's funding contribution */
	private _remoteFundingSatoshis = 0n;

	/** TX signatures tracking */
	private _localWitnesses: Buffer[][] | null = null;
	private _remoteWitnesses: Buffer[][] | null = null;
	private _fundingTxid: Buffer | null = null;
	private _fundingOutputIndex = 0;

	/** RBF tracking */
	private _rbfCount = 0;

	/** The open_channel2 message that was sent/received */
	private _openMsg: IOpenChannel2Message | null = null;
	/** The accept_channel2 message that was sent/received */
	private _acceptMsg: IAcceptChannel2Message | null = null;

	/** Per-side funding cap: 2^24 sat unless option_wumbo lifted it. */
	private _maxFundingSatoshis: bigint;

	constructor(
		isInitiator: boolean,
		channelId: Buffer,
		maxFundingSatoshis: bigint = MAX_FUNDING_SATOSHIS
	) {
		this._isInitiator = isInitiator;
		this._channelId = Buffer.from(channelId);
		this._maxFundingSatoshis = maxFundingSatoshis;
	}

	/**
	 * Rebuild a session for an in-flight v2 open past the interactive-tx
	 * negotiation (the funding tx is known and our inputs are signed into the
	 * durable record). Used after a restart to resume the commitment_signed /
	 * tx_signatures exchange over channel_reestablish.next_funding — no tx
	 * builder is needed post-negotiation, and none could be rebuilt (the
	 * wallet contribution closures die with the process).
	 */
	static restore(params: {
		channelId: Buffer;
		isInitiator: boolean;
		remoteContributionSats: bigint;
		fundingTxid: Buffer;
		fundingOutputIndex: number;
		/** Witnesses our released tx_signatures carried; null until it left. */
		ourWitnesses: Buffer[][] | null;
		receivedTxSignatures: boolean;
		/**
		 * The record's RBF attempt number. The session counter MUST match
		 * the restored record, or the record looks like retained rollback
		 * state and the next sync would erase it, unrecreatable from a
		 * builder-less session.
		 */
		rbfCount?: number;
	}): DualFundingSession {
		const session = new DualFundingSession(
			params.isInitiator,
			params.channelId
		);
		session._remoteFundingSatoshis = params.remoteContributionSats;
		session._fundingTxid = Buffer.from(params.fundingTxid);
		session._fundingOutputIndex = params.fundingOutputIndex;
		session._localWitnesses = params.ourWitnesses;
		session._rbfCount = params.rbfCount ?? 0;
		session._state =
			params.ourWitnesses && params.receivedTxSignatures
				? DualFundingState.AWAITING_CHANNEL_READY
				: DualFundingState.AWAITING_TX_SIGNATURES;
		return session;
	}

	// ─────────────── Getters ───────────────

	getState(): DualFundingState {
		return this._state;
	}

	isInitiator(): boolean {
		return this._isInitiator;
	}

	getChannelId(): Buffer {
		return this._channelId;
	}

	getTxBuilder(): InteractiveTxBuilder | null {
		return this._txBuilder;
	}

	getLocalParams(): IDualFundingParams | null {
		return this._localParams;
	}

	/** Liquidity ads: the request_funds we sent (opener) or received (acceptor). */
	getRequestFunds(): IRequestFunds | undefined {
		return this._openMsg?.requestFunds;
	}

	/** channel_type proposed in open_channel2 (what will_fund is signed over). */
	getOpenChannelType(): Buffer | undefined {
		return this._openMsg?.channelType;
	}

	getRemoteBasepoints(): IChannelBasepoints | null {
		return this._remoteBasepoints;
	}

	getRemoteFundingSatoshis(): bigint {
		return this._remoteFundingSatoshis;
	}

	getFundingTxid(): Buffer | null {
		return this._fundingTxid;
	}

	getFundingOutputIndex(): number {
		return this._fundingOutputIndex;
	}

	getLocalWitnesses(): Buffer[][] | null {
		return this._localWitnesses;
	}

	getRemoteWitnesses(): Buffer[][] | null {
		return this._remoteWitnesses;
	}

	getRbfCount(): number {
		return this._rbfCount;
	}

	getOpenMsg(): IOpenChannel2Message | null {
		return this._openMsg;
	}

	getAcceptMsg(): IAcceptChannel2Message | null {
		return this._acceptMsg;
	}

	// ─────────────── Opener Flow ───────────────

	/**
	 * Initiate dual-funded channel opening (opener side).
	 * Returns the open_channel2 message fields.
	 */
	initiateOpen(
		params: IDualFundingParams
	): IDualFundingResult & { message?: IOpenChannel2Message } {
		if (this._state !== DualFundingState.NONE) {
			return { ok: false, error: 'Cannot initiate open: wrong state' };
		}

		const validErr = this.validateLocalParams(params);
		if (validErr) {
			return { ok: false, error: validErr };
		}

		this._localParams = params;

		const msg: IOpenChannel2Message = {
			chainHash: params.chainHash,
			channelId: this._channelId,
			fundingFeeratePerkw: params.fundingFeeratePerkw,
			commitmentFeeratePerkw: params.commitmentFeeratePerkw,
			fundingSatoshis: params.fundingSatoshis,
			dustLimitSatoshis: params.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: params.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: params.htlcMinimumMsat,
			toSelfDelay: params.toSelfDelay,
			maxAcceptedHtlcs: params.maxAcceptedHtlcs,
			locktime: params.locktime,
			fundingPubkey: params.localBasepoints.fundingPubkey,
			revocationBasepoint: params.localBasepoints.revocationBasepoint,
			paymentBasepoint: params.localBasepoints.paymentBasepoint,
			delayedPaymentBasepoint: params.localBasepoints.delayedPaymentBasepoint,
			htlcBasepoint: params.localBasepoints.htlcBasepoint,
			firstPerCommitmentPoint: params.localBasepoints.firstPerCommitmentPoint,
			secondPerCommitmentPoint: params.secondPerCommitmentPoint,
			channelFlags: params.channelFlags ?? 0x01,
			channelType: params.channelType,
			requestFunds: params.requestFunds
		};

		this._openMsg = msg;
		this._state = DualFundingState.AWAITING_ACCEPT;

		return { ok: true, message: msg };
	}

	/**
	 * Handle accept_channel2 from remote (opener side).
	 * Transitions to TX_NEGOTIATION.
	 */
	handleAcceptChannel2(msg: IAcceptChannel2Message): IDualFundingResult {
		if (this._state !== DualFundingState.AWAITING_ACCEPT) {
			return { ok: false, error: 'Unexpected accept_channel2' };
		}

		if (!msg.channelId.equals(this._channelId)) {
			return { ok: false, error: 'channel_id mismatch in accept_channel2' };
		}

		const validErr = this.validateAcceptParams(msg);
		if (validErr) {
			return { ok: false, error: validErr };
		}

		// BOLT 2: the accepter echoes the channel_type it is accepting, so
		// an open that proposed one must see EXACTLY it come back. A
		// missing or different echo means the two sides would build
		// different commitment formats over one funding output; refuse
		// before any interactive-tx state exists. An accepter volunteering
		// a type the open never proposed is refused for the same reason.
		const offeredType = this._openMsg?.channelType;
		if (offeredType) {
			if (!msg.channelType) {
				return {
					ok: false,
					error: 'accept_channel2 omitted the channel_type this open proposed'
				};
			}
			if (!msg.channelType.equals(offeredType)) {
				return { ok: false, error: 'Channel type mismatch' };
			}
		} else if (msg.channelType) {
			return {
				ok: false,
				error: 'accept_channel2 set a channel_type this open did not propose'
			};
		}

		this._remoteFundingSatoshis = msg.fundingSatoshis;
		this._remoteBasepoints = {
			fundingPubkey: msg.fundingPubkey,
			revocationBasepoint: msg.revocationBasepoint,
			paymentBasepoint: msg.paymentBasepoint,
			delayedPaymentBasepoint: msg.delayedPaymentBasepoint,
			htlcBasepoint: msg.htlcBasepoint,
			firstPerCommitmentPoint: msg.firstPerCommitmentPoint
		};
		this._remoteParams = {
			fundingSatoshis: msg.fundingSatoshis,
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs
		};
		this._acceptMsg = msg;

		// Create the interactive TX builder
		const locktime = this._localParams?.locktime ?? 0;
		this._txBuilder = new InteractiveTxBuilder(true, locktime);
		this._state = DualFundingState.TX_NEGOTIATION;

		return { ok: true };
	}

	// ─────────────── Acceptor Flow ───────────────

	/**
	 * Handle open_channel2 from remote (acceptor side).
	 * Returns the accept_channel2 message fields.
	 */
	handleOpenChannel2(
		msg: IOpenChannel2Message,
		localParams: IDualFundingParams
	): IDualFundingResult & { message?: IAcceptChannel2Message } {
		if (this._state !== DualFundingState.NONE) {
			return { ok: false, error: 'Unexpected open_channel2' };
		}

		if (!msg.channelId.equals(this._channelId)) {
			return { ok: false, error: 'channel_id mismatch in open_channel2' };
		}

		const openValidErr = this.validateOpenMsg(msg);
		if (openValidErr) {
			return { ok: false, error: openValidErr };
		}

		const localValidErr = this.validateLocalParams(localParams);
		if (localValidErr) {
			return { ok: false, error: localValidErr };
		}

		this._localParams = localParams;
		this._openMsg = msg;
		this._remoteFundingSatoshis = msg.fundingSatoshis;
		this._remoteBasepoints = {
			fundingPubkey: msg.fundingPubkey,
			revocationBasepoint: msg.revocationBasepoint,
			paymentBasepoint: msg.paymentBasepoint,
			delayedPaymentBasepoint: msg.delayedPaymentBasepoint,
			htlcBasepoint: msg.htlcBasepoint,
			firstPerCommitmentPoint: msg.firstPerCommitmentPoint
		};
		this._remoteParams = {
			fundingSatoshis: msg.fundingSatoshis,
			fundingFeeratePerkw: msg.fundingFeeratePerkw,
			commitmentFeeratePerkw: msg.commitmentFeeratePerkw,
			dustLimitSatoshis: msg.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: msg.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: msg.htlcMinimumMsat,
			toSelfDelay: msg.toSelfDelay,
			maxAcceptedHtlcs: msg.maxAcceptedHtlcs,
			locktime: msg.locktime
		};

		// Channel type validation if provided
		if (msg.channelType && localParams.channelType) {
			if (!msg.channelType.equals(localParams.channelType)) {
				return { ok: false, error: 'Channel type mismatch' };
			}
		}

		const acceptMsg: IAcceptChannel2Message = {
			channelId: this._channelId,
			fundingSatoshis: localParams.fundingSatoshis,
			dustLimitSatoshis: localParams.dustLimitSatoshis,
			maxHtlcValueInFlightMsat: localParams.maxHtlcValueInFlightMsat,
			htlcMinimumMsat: localParams.htlcMinimumMsat,
			minimumDepth: localParams.minimumDepth ?? 3,
			toSelfDelay: localParams.toSelfDelay,
			maxAcceptedHtlcs: localParams.maxAcceptedHtlcs,
			fundingPubkey: localParams.localBasepoints.fundingPubkey,
			revocationBasepoint: localParams.localBasepoints.revocationBasepoint,
			paymentBasepoint: localParams.localBasepoints.paymentBasepoint,
			delayedPaymentBasepoint:
				localParams.localBasepoints.delayedPaymentBasepoint,
			htlcBasepoint: localParams.localBasepoints.htlcBasepoint,
			firstPerCommitmentPoint:
				localParams.localBasepoints.firstPerCommitmentPoint,
			secondPerCommitmentPoint: localParams.secondPerCommitmentPoint,
			// BOLT 2: the accepter echoes the channel_type it is accepting. CLN
			// REQUIRES the echo (and refuses a lease without one).
			channelType: localParams.channelType ?? msg.channelType,
			willFund: localParams.willFund
		};

		this._acceptMsg = acceptMsg;

		// Create the interactive TX builder (acceptor is not initiator)
		this._txBuilder = new InteractiveTxBuilder(false, msg.locktime);
		this._state = DualFundingState.TX_NEGOTIATION;

		return { ok: true, message: acceptMsg };
	}

	// ─────────────── Interactive TX Negotiation ───────────────

	/**
	 * Add a local input to the transaction.
	 */
	addInput(input: IInteractiveTxInput): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot add input: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.addInput(input);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Add a peer's input to the transaction.
	 */
	addPeerInput(input: IInteractiveTxInput): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot add peer input: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.addPeerInput(input);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Add a local output to the transaction.
	 */
	addOutput(output: IInteractiveTxOutput): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot add output: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.addOutput(output);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Add a peer's output to the transaction.
	 */
	addPeerOutput(output: IInteractiveTxOutput): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot add peer output: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.addPeerOutput(output);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Remove a local input.
	 */
	removeInput(serialId: bigint): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot remove input: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.removeInput(serialId);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Remove a peer's input.
	 */
	removePeerInput(serialId: bigint): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot remove peer input: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.removePeerInput(serialId);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Remove a local output.
	 */
	removeOutput(serialId: bigint): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot remove output: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.removeOutput(serialId);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Remove a peer's output.
	 */
	removePeerOutput(serialId: bigint): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot remove peer output: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.removePeerOutput(serialId);
		if (err) {
			return { ok: false, error: err };
		}
		return { ok: true };
	}

	/**
	 * Signal that we are done adding inputs/outputs (send tx_complete).
	 */
	markComplete(): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot mark complete: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.markComplete();
		if (err) {
			return { ok: false, error: err };
		}

		// If both are complete, transition to awaiting signatures
		if (this._txBuilder.isComplete()) {
			this._state = DualFundingState.AWAITING_TX_SIGNATURES;
		}

		return { ok: true };
	}

	/**
	 * Handle peer's tx_complete.
	 */
	handlePeerComplete(): IDualFundingResult {
		if (this._state !== DualFundingState.TX_NEGOTIATION) {
			return {
				ok: false,
				error: 'Cannot handle peer complete: not in TX_NEGOTIATION state'
			};
		}
		if (!this._txBuilder) {
			return { ok: false, error: 'No TX builder' };
		}

		const err = this._txBuilder.handlePeerComplete();
		if (err) {
			return { ok: false, error: err };
		}

		// If both are complete, transition to awaiting signatures
		if (this._txBuilder.isComplete()) {
			this._state = DualFundingState.AWAITING_TX_SIGNATURES;
		}

		return { ok: true };
	}

	/**
	 * Build the finalized transaction.
	 * Only valid after both sides completed TX negotiation.
	 */
	buildTransaction(): {
		inputs: IInteractiveTxInput[];
		outputs: IInteractiveTxOutput[];
		locktime: number;
	} | null {
		if (!this._txBuilder) return null;
		return this._txBuilder.buildTransaction();
	}

	/**
	 * Generate the next serial ID for our inputs/outputs.
	 */
	nextSerialId(): bigint {
		if (!this._txBuilder) {
			return this._isInitiator ? 0n : 1n;
		}
		return this._txBuilder.nextSerialIdForUs();
	}

	// ─────────────── TX Signatures ───────────────

	/**
	 * Provide our witnesses for the funding transaction.
	 */
	provideWitnesses(
		txid: Buffer,
		outputIndex: number,
		witnesses: Buffer[][]
	): IDualFundingResult {
		if (this._state !== DualFundingState.AWAITING_TX_SIGNATURES) {
			return {
				ok: false,
				error: 'Cannot provide witnesses: not in AWAITING_TX_SIGNATURES state'
			};
		}

		this._fundingTxid = Buffer.from(txid);
		this._fundingOutputIndex = outputIndex;
		this._localWitnesses = witnesses;

		// If we already have remote witnesses, transition to channel ready
		if (this._remoteWitnesses) {
			this._state = DualFundingState.AWAITING_CHANNEL_READY;
		}

		return { ok: true };
	}

	/**
	 * Handle tx_signatures from peer.
	 */
	handlePeerWitnesses(txid: Buffer, witnesses: Buffer[][]): IDualFundingResult {
		if (
			this._state !== DualFundingState.AWAITING_TX_SIGNATURES &&
			this._state !== DualFundingState.AWAITING_CHANNEL_READY
		) {
			return { ok: false, error: 'Cannot handle peer witnesses: wrong state' };
		}

		// Validate txid matches if we have one
		if (this._fundingTxid && !txid.equals(this._fundingTxid)) {
			return { ok: false, error: 'txid mismatch in tx_signatures' };
		}

		this._remoteWitnesses = witnesses;
		if (!this._fundingTxid) {
			this._fundingTxid = Buffer.from(txid);
		}

		// If we have local witnesses, transition to channel ready
		if (this._localWitnesses) {
			this._state = DualFundingState.AWAITING_CHANNEL_READY;
		}

		return { ok: true };
	}

	// ─────────────── Channel Ready ───────────────

	/**
	 * Mark the channel as ready (both sides exchanged channel_ready).
	 */
	markChannelReady(): IDualFundingResult {
		if (this._state !== DualFundingState.AWAITING_CHANNEL_READY) {
			return { ok: false, error: 'Cannot mark channel ready: wrong state' };
		}

		this._state = DualFundingState.COMPLETE;
		return { ok: true };
	}

	// ─────────────── RBF ───────────────

	/**
	 * Initiate RBF on the funding transaction (opener only).
	 * Returns new fee rate and locktime for tx_init_rbf.
	 *
	 * `newContributions` carries the split the accepted replacement is
	 * negotiated at when either side changed its funding_output_contribution
	 * (BOLT 2 allows a different one per attempt). Omitted means unchanged.
	 * The channel layer validates the amounts before calling; this only
	 * records them, atomically with the builder reset, so nothing can observe
	 * a half-applied attempt.
	 */
	initiateRbf(
		newFeeratePerkw: number,
		newLocktime?: number,
		newContributions?: { localSats: bigint; remoteSats: bigint }
	): IDualFundingResult & { feerate?: number; locktime?: number } {
		if (!this._isInitiator) {
			return { ok: false, error: 'Only initiator can initiate RBF' };
		}

		// RBF can be initiated in TX_NEGOTIATION, AWAITING_TX_SIGNATURES, or
		// AWAITING_CHANNEL_READY (the BOLT 2 window: witnesses exchanged, the
		// broadcast attempt unconfirmed; the channel layer gates channel_ready
		// and confirmation).
		if (
			this._state !== DualFundingState.TX_NEGOTIATION &&
			this._state !== DualFundingState.AWAITING_TX_SIGNATURES &&
			this._state !== DualFundingState.AWAITING_CHANNEL_READY
		) {
			return { ok: false, error: 'Cannot initiate RBF: wrong state' };
		}

		// BOLT 2: the RBF feerate MUST be at least 25/24 of the previous funding
		// feerate (a strict increase alone allows 1 sat/kw bumps that never
		// improve the replacement's mempool position).
		const currentFeerate = this._localParams?.fundingFeeratePerkw ?? 0;
		const minRbfFeerate = rbfFeerateFloor(currentFeerate);
		if (newFeeratePerkw < minRbfFeerate) {
			return {
				ok: false,
				error: `RBF fee rate ${newFeeratePerkw} below the 25/24 floor ${minRbfFeerate}`
			};
		}

		const locktime = newLocktime ?? this._localParams?.locktime ?? 0;

		// Reset TX builder with new parameters
		this._txBuilder = new InteractiveTxBuilder(true, locktime);
		this._localWitnesses = null;
		this._remoteWitnesses = null;
		this._fundingTxid = null;
		this._rbfCount++;

		if (this._localParams) {
			this._localParams.fundingFeeratePerkw = newFeeratePerkw;
			this._localParams.locktime = locktime;
			if (newContributions) {
				this._localParams.fundingSatoshis = newContributions.localSats;
			}
		}
		if (newContributions) {
			this._remoteFundingSatoshis = newContributions.remoteSats;
			if (this._remoteParams) {
				this._remoteParams.fundingSatoshis = newContributions.remoteSats;
			}
		}

		this._state = DualFundingState.TX_NEGOTIATION;

		return { ok: true, feerate: newFeeratePerkw, locktime };
	}

	/**
	 * Handle tx_init_rbf from peer (acceptor side).
	 *
	 * `newRemoteContributionSats` is the opener's changed
	 * funding_output_contribution for this attempt (BOLT 2 permits a different
	 * one per attempt); omitted means unchanged. Validated by the channel
	 * layer before this is called.
	 */
	handleRbf(
		feerate: number,
		locktime: number,
		newRemoteContributionSats?: bigint
	): IDualFundingResult {
		if (this._isInitiator) {
			return { ok: false, error: 'Initiator cannot receive tx_init_rbf' };
		}

		if (
			this._state !== DualFundingState.TX_NEGOTIATION &&
			this._state !== DualFundingState.AWAITING_TX_SIGNATURES &&
			this._state !== DualFundingState.AWAITING_CHANNEL_READY
		) {
			return { ok: false, error: 'Cannot handle RBF: wrong state' };
		}

		// BOLT 2: the RBF feerate MUST be at least 25/24 of the previous one.
		const currentFeerate = this._remoteParams?.fundingFeeratePerkw ?? 0;
		const minRbfFeerate = rbfFeerateFloor(currentFeerate);
		if (feerate < minRbfFeerate) {
			return {
				ok: false,
				error: `RBF fee rate ${feerate} below the 25/24 floor ${minRbfFeerate}`
			};
		}

		// Reset TX builder
		this._txBuilder = new InteractiveTxBuilder(false, locktime);
		this._localWitnesses = null;
		this._remoteWitnesses = null;
		this._fundingTxid = null;
		this._rbfCount++;

		if (this._remoteParams) {
			this._remoteParams.fundingFeeratePerkw = feerate;
			this._remoteParams.locktime = locktime;
			if (newRemoteContributionSats !== undefined) {
				this._remoteParams.fundingSatoshis = newRemoteContributionSats;
			}
		}
		// The peer's contribution to the funding output for THIS attempt. The
		// completed-tx solvency audit reads it back through
		// getRemoteFundingSatoshis, so a changed amount has to land here or the
		// replacement would be audited against the previous attempt's share.
		if (newRemoteContributionSats !== undefined) {
			this._remoteFundingSatoshis = newRemoteContributionSats;
		}
		// The funding feerate is the opener's and applies to the whole
		// replacement. Our local params were seeded from open_channel2, so
		// they must follow the accepted RBF too: the negotiated-tx audit and
		// the next in-flight record both read the feerate from local params,
		// and leaving the old value there prices both against the replaced
		// attempt.
		if (this._localParams) {
			this._localParams.fundingFeeratePerkw = feerate;
			this._localParams.locktime = locktime;
		}

		this._state = DualFundingState.TX_NEGOTIATION;

		return { ok: true };
	}

	// ─────────────── Abort ───────────────

	/**
	 * Abort the dual-funding session.
	 */
	abort(): void {
		if (this._txBuilder) {
			this._txBuilder.abort();
		}
		this._state = DualFundingState.ABORTED;
	}

	/**
	 * Check if the session is aborted.
	 */
	isAborted(): boolean {
		return this._state === DualFundingState.ABORTED;
	}

	/**
	 * Check if the session is complete.
	 */
	isComplete(): boolean {
		return this._state === DualFundingState.COMPLETE;
	}

	/**
	 * Get total funding amount (both sides combined).
	 */
	getTotalFunding(): bigint {
		const local = this._localParams?.fundingSatoshis ?? 0n;
		return local + this._remoteFundingSatoshis;
	}

	/**
	 * Get the interactive TX state.
	 */
	getTxState(): InteractiveTxState | null {
		return this._txBuilder?.getState() ?? null;
	}

	// ─────────────── Validation ───────────────

	private validateLocalParams(params: IDualFundingParams): string | null {
		if (params.fundingSatoshis > this._maxFundingSatoshis) {
			return `funding_satoshis ${params.fundingSatoshis} exceeds maximum ${this._maxFundingSatoshis}`;
		}

		if (params.dustLimitSatoshis < MIN_DUST_LIMIT_SATOSHIS) {
			return `dust_limit_satoshis ${params.dustLimitSatoshis} below minimum ${MIN_DUST_LIMIT_SATOSHIS}`;
		}

		if (params.maxAcceptedHtlcs > MAX_ACCEPTED_HTLCS) {
			return `max_accepted_htlcs ${params.maxAcceptedHtlcs} exceeds maximum ${MAX_ACCEPTED_HTLCS}`;
		}

		if (params.toSelfDelay === 0) {
			return 'to_self_delay must be greater than 0';
		}

		if (params.fundingFeeratePerkw === 0) {
			return 'funding_feerate must be greater than 0';
		}

		if (params.commitmentFeeratePerkw === 0) {
			return 'commitment_feerate must be greater than 0';
		}

		if (params.localBasepoints.fundingPubkey.length !== 33) {
			return 'funding_pubkey must be 33 bytes';
		}

		return null;
	}

	private validateOpenMsg(msg: IOpenChannel2Message): string | null {
		if (msg.fundingSatoshis > this._maxFundingSatoshis) {
			return `funding_satoshis ${msg.fundingSatoshis} exceeds maximum ${this._maxFundingSatoshis}`;
		}

		if (msg.dustLimitSatoshis < MIN_DUST_LIMIT_SATOSHIS) {
			return `dust_limit_satoshis ${msg.dustLimitSatoshis} below minimum ${MIN_DUST_LIMIT_SATOSHIS}`;
		}

		// An unbounded peer dust_limit is the FS-1 fund loss (v1 bounds it in
		// validateAcceptChannelParams): the peer sets it near the whole channel,
		// so every commitment built at the peer's dust limit trims our output as
		// "dust" and we sign it. It also drives the derived v2 channel reserve,
		// which BOLT 2 floors at the dust limit with no maximum.
		if (msg.dustLimitSatoshis > MAX_DUST_LIMIT_SATOSHIS) {
			return `dust_limit_satoshis ${msg.dustLimitSatoshis} exceeds maximum ${MAX_DUST_LIMIT_SATOSHIS}`;
		}

		if (msg.maxAcceptedHtlcs > MAX_ACCEPTED_HTLCS) {
			return `max_accepted_htlcs ${msg.maxAcceptedHtlcs} exceeds maximum ${MAX_ACCEPTED_HTLCS}`;
		}

		if (msg.toSelfDelay === 0) {
			return 'to_self_delay must be greater than 0';
		}

		if (msg.fundingFeeratePerkw === 0) {
			return 'funding_feerate must be greater than 0';
		}

		if (msg.commitmentFeeratePerkw === 0) {
			return 'commitment_feerate must be greater than 0';
		}

		if (msg.fundingPubkey.length !== 33) {
			return 'funding_pubkey must be 33 bytes';
		}

		return null;
	}

	private validateAcceptParams(msg: IAcceptChannel2Message): string | null {
		if (msg.dustLimitSatoshis < MIN_DUST_LIMIT_SATOSHIS) {
			return `dust_limit_satoshis ${msg.dustLimitSatoshis} below minimum ${MIN_DUST_LIMIT_SATOSHIS}`;
		}

		// Same FS-1 bound as validateOpenMsg, for the acceptor's dust limit.
		if (msg.dustLimitSatoshis > MAX_DUST_LIMIT_SATOSHIS) {
			return `dust_limit_satoshis ${msg.dustLimitSatoshis} exceeds maximum ${MAX_DUST_LIMIT_SATOSHIS}`;
		}

		if (msg.maxAcceptedHtlcs > MAX_ACCEPTED_HTLCS) {
			return `max_accepted_htlcs ${msg.maxAcceptedHtlcs} exceeds maximum ${MAX_ACCEPTED_HTLCS}`;
		}

		if (msg.toSelfDelay === 0) {
			return 'to_self_delay must be greater than 0';
		}

		if (msg.fundingPubkey.length !== 33) {
			return 'funding_pubkey must be 33 bytes';
		}

		return null;
	}
}
