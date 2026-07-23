/**
 * BOLT 2 v2: Dual-Funding Session.
 *
 * Orchestrates the v2 channel opening flow:
 *   open_channel2 -> accept_channel2 -> interactive TX negotiation
 *   -> tx_signatures -> channel_ready
 *
 * Manages state transitions and uses InteractiveTxBuilder for
 * collaborative transaction construction.
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
	MAX_ACCEPTED_HTLCS,
	MAX_FUNDING_SATOSHIS
} from './types';
import { IChannelBasepoints } from '../keys/derivation';
import { ILeaseRates } from '../gossip/types';

/**
 * BOLT 2: the minimum feerate for an RBF attempt is 25/24 of the previous
 * funding feerate. At tiny feerates the 25/24 ratio rounds down to the
 * previous value, so the floor is never below a strict +1 increase.
 */
export function rbfFeerateFloor(previousFeeratePerkw: number): number {
	return Math.max(
		Math.floor((previousFeeratePerkw * 25) / 24),
		previousFeeratePerkw + 1
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
			minimumDepth: 3,
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
	 */
	initiateRbf(
		newFeeratePerkw: number,
		newLocktime?: number
	): IDualFundingResult & { feerate?: number; locktime?: number } {
		if (!this._isInitiator) {
			return { ok: false, error: 'Only initiator can initiate RBF' };
		}

		// RBF can be initiated in TX_NEGOTIATION or AWAITING_TX_SIGNATURES
		if (
			this._state !== DualFundingState.TX_NEGOTIATION &&
			this._state !== DualFundingState.AWAITING_TX_SIGNATURES
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
		}

		this._state = DualFundingState.TX_NEGOTIATION;

		return { ok: true, feerate: newFeeratePerkw, locktime };
	}

	/**
	 * Handle tx_init_rbf from peer (acceptor side).
	 */
	handleRbf(feerate: number, locktime: number): IDualFundingResult {
		if (this._isInitiator) {
			return { ok: false, error: 'Initiator cannot receive tx_init_rbf' };
		}

		if (
			this._state !== DualFundingState.TX_NEGOTIATION &&
			this._state !== DualFundingState.AWAITING_TX_SIGNATURES
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
