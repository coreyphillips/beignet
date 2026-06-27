/**
 * BOLT 2: Splice session management.
 *
 * Orchestrates the splicing protocol:
 *   1. Quiescence required (channel must be QUIESCENT)
 *   2. splice -> splice_ack
 *   3. Interactive TX negotiation (via InteractiveTxBuilder)
 *   4. tx_signatures exchange
 *   5. splice_locked (both sides)
 *   6. Exit quiescence, resume normal operation
 *
 * Supports:
 *   - splice-in (add funds, positive relativeSatoshis)
 *   - splice-out (withdraw funds, negative relativeSatoshis)
 *   - combined splice (both sides contribute/withdraw)
 */

import { InteractiveTxBuilder } from '../interactive-tx/builder';
import {
	IInteractiveTxInput,
	IInteractiveTxOutput,
	InteractiveTxState
} from '../interactive-tx/types';
import {
	ISpliceMessage,
	ISpliceAckMessage,
	ISpliceLockedMessage
} from '../message/splice';

export enum SpliceState {
	/** Initial state before any splice messages */
	IDLE = 'IDLE',
	/** We sent splice, waiting for splice_ack */
	AWAITING_ACK = 'AWAITING_ACK',
	/** Interactive TX negotiation in progress */
	TX_NEGOTIATION = 'TX_NEGOTIATION',
	/** TX negotiation complete, waiting for tx_signatures */
	AWAITING_TX_SIGNATURES = 'AWAITING_TX_SIGNATURES',
	/** Signatures exchanged, waiting for splice_locked from both sides */
	AWAITING_SPLICE_LOCKED = 'AWAITING_SPLICE_LOCKED',
	/** Splice complete */
	COMPLETE = 'COMPLETE',
	/** Splice aborted */
	ABORTED = 'ABORTED'
}

export interface ISpliceSessionParams {
	/** Channel ID (32 bytes) */
	channelId: Buffer;
	/** Our funding pubkey for the new splice */
	localFundingPubkey: Buffer;
	/** Whether we initiated the splice */
	isInitiator: boolean;
	/** Our relative satoshis contribution (positive = splice-in, negative = splice-out) */
	localRelativeSatoshis: bigint;
	/** Funding feerate in sat/kw (for splice tx) */
	fundingFeeratePerkw: number;
	/** Locktime for the splice transaction */
	locktime: number;
}

export interface ISpliceResult {
	ok: boolean;
	error?: string;
	/** Outbound message to send (splice/splice_ack) */
	message?: ISpliceMessage | ISpliceAckMessage | ISpliceLockedMessage;
	/** Message type constant name for routing */
	messageType?: 'splice' | 'splice_ack' | 'splice_locked';
}

export class SpliceSession {
	private _state: SpliceState = SpliceState.IDLE;
	private _channelId: Buffer;
	private _localFundingPubkey: Buffer;
	private _remoteFundingPubkey: Buffer | null = null;
	private _isInitiator: boolean;
	private _localRelativeSatoshis: bigint;
	private _remoteRelativeSatoshis = 0n;
	private _fundingFeeratePerkw: number;
	private _locktime: number;
	private _txBuilder: InteractiveTxBuilder | null = null;
	private _spliceTxid: Buffer | null = null;
	private _spliceFundingOutputIndex = 0;
	private _localSpliceLocked = false;
	private _remoteSpliceLocked = false;
	private _requireConfirmedInputs = false;

	constructor(params: ISpliceSessionParams) {
		this._channelId = params.channelId;
		this._localFundingPubkey = params.localFundingPubkey;
		this._isInitiator = params.isInitiator;
		this._localRelativeSatoshis = params.localRelativeSatoshis;
		this._fundingFeeratePerkw = params.fundingFeeratePerkw;
		this._locktime = params.locktime;
	}

	/**
	 * Rebuild a session for an in-flight splice past the interactive-tx
	 * negotiation (the splice tx is known and we have signed it). Used after a
	 * restart to resume the tx_signatures / splice_locked exchange — no tx
	 * builder is needed post-negotiation.
	 */
	static restore(params: {
		channelId: Buffer;
		localFundingPubkey: Buffer;
		remoteFundingPubkey: Buffer;
		isInitiator: boolean;
		localRelativeSatoshis: bigint;
		remoteRelativeSatoshis: bigint;
		fundingFeeratePerkw: number;
		spliceTxid: Buffer;
		spliceFundingOutputIndex: number;
		receivedTxSignatures: boolean;
		localSpliceLocked: boolean;
		remoteSpliceLocked: boolean;
	}): SpliceSession {
		const session = new SpliceSession({
			channelId: params.channelId,
			localFundingPubkey: params.localFundingPubkey,
			isInitiator: params.isInitiator,
			localRelativeSatoshis: params.localRelativeSatoshis,
			fundingFeeratePerkw: params.fundingFeeratePerkw,
			locktime: 0
		});
		session._remoteFundingPubkey = params.remoteFundingPubkey;
		session._remoteRelativeSatoshis = params.remoteRelativeSatoshis;
		session._spliceTxid = params.spliceTxid;
		session._spliceFundingOutputIndex = params.spliceFundingOutputIndex;
		session._localSpliceLocked = params.localSpliceLocked;
		session._remoteSpliceLocked = params.remoteSpliceLocked;
		session._state =
			params.localSpliceLocked && params.remoteSpliceLocked
				? SpliceState.COMPLETE
				: params.receivedTxSignatures
				? SpliceState.AWAITING_SPLICE_LOCKED
				: SpliceState.AWAITING_TX_SIGNATURES;
		return session;
	}

	hasSentSpliceLocked(): boolean {
		return this._localSpliceLocked;
	}

	hasReceivedSpliceLocked(): boolean {
		return this._remoteSpliceLocked;
	}

	getState(): SpliceState {
		return this._state;
	}

	getChannelId(): Buffer {
		return this._channelId;
	}

	isInitiator(): boolean {
		return this._isInitiator;
	}

	getLocalRelativeSatoshis(): bigint {
		return this._localRelativeSatoshis;
	}

	getRemoteRelativeSatoshis(): bigint {
		return this._remoteRelativeSatoshis;
	}

	getRemoteFundingPubkey(): Buffer | null {
		return this._remoteFundingPubkey;
	}

	/** Our funding pubkey advertised for this splice (in splice_init/splice_ack). */
	getLocalFundingPubkey(): Buffer {
		return this._localFundingPubkey;
	}

	getTxBuilder(): InteractiveTxBuilder | null {
		return this._txBuilder;
	}

	getSpliceTxid(): Buffer | null {
		return this._spliceTxid;
	}

	getSpliceFundingOutputIndex(): number {
		return this._spliceFundingOutputIndex;
	}

	isComplete(): boolean {
		return this._state === SpliceState.COMPLETE;
	}

	isAborted(): boolean {
		return this._state === SpliceState.ABORTED;
	}

	getRequireConfirmedInputs(): boolean {
		return this._requireConfirmedInputs;
	}

	getFundingFeeratePerkw(): number {
		return this._fundingFeeratePerkw;
	}

	/**
	 * Compute the net capacity change from this splice.
	 * Positive = channel grows, negative = channel shrinks.
	 */
	getNetCapacityChange(): bigint {
		return this._localRelativeSatoshis + this._remoteRelativeSatoshis;
	}

	// ─────────────── Initiator side ───────────────

	/**
	 * Start a splice by generating the splice message.
	 * Returns the message to send.
	 */
	initiate(): ISpliceResult {
		if (this._state !== SpliceState.IDLE) {
			return { ok: false, error: 'Cannot initiate splice: wrong state' };
		}

		this._state = SpliceState.AWAITING_ACK;

		const message: ISpliceMessage = {
			channelId: this._channelId,
			fundingPubkey: this._localFundingPubkey,
			relativeSatoshis: this._localRelativeSatoshis,
			fundingFeeratePerkw: this._fundingFeeratePerkw,
			locktime: this._locktime,
			requireConfirmedInputs: this._requireConfirmedInputs || undefined
		};

		return { ok: true, message, messageType: 'splice' };
	}

	/**
	 * Handle splice_ack from remote (initiator side).
	 * Transitions to TX_NEGOTIATION and creates the InteractiveTxBuilder.
	 */
	handleSpliceAck(msg: ISpliceAckMessage): ISpliceResult {
		if (this._state !== SpliceState.AWAITING_ACK) {
			return { ok: false, error: 'Unexpected splice_ack: wrong state' };
		}

		if (!msg.channelId.equals(this._channelId)) {
			return { ok: false, error: 'Channel ID mismatch in splice_ack' };
		}

		this._remoteFundingPubkey = msg.fundingPubkey;
		this._remoteRelativeSatoshis = msg.relativeSatoshis;

		if (msg.requireConfirmedInputs) {
			this._requireConfirmedInputs = true;
		}

		// Create the interactive TX builder
		this._txBuilder = new InteractiveTxBuilder(
			this._isInitiator,
			this._locktime
		);
		this._state = SpliceState.TX_NEGOTIATION;

		return { ok: true };
	}

	// ─────────────── Acceptor side ───────────────

	/**
	 * Handle incoming splice message (acceptor side).
	 * Returns the splice_ack to send.
	 */
	handleSplice(msg: ISpliceMessage): ISpliceResult {
		if (this._state !== SpliceState.IDLE) {
			return { ok: false, error: 'Unexpected splice: wrong state' };
		}

		if (!msg.channelId.equals(this._channelId)) {
			return { ok: false, error: 'Channel ID mismatch in splice' };
		}

		this._remoteFundingPubkey = msg.fundingPubkey;
		this._remoteRelativeSatoshis = msg.relativeSatoshis;
		this._fundingFeeratePerkw = msg.fundingFeeratePerkw;
		this._locktime = msg.locktime;

		if (msg.requireConfirmedInputs) {
			this._requireConfirmedInputs = true;
		}

		// Create the interactive TX builder
		this._txBuilder = new InteractiveTxBuilder(
			this._isInitiator,
			this._locktime
		);

		this._state = SpliceState.TX_NEGOTIATION;

		const ackMessage: ISpliceAckMessage = {
			channelId: this._channelId,
			fundingPubkey: this._localFundingPubkey,
			relativeSatoshis: this._localRelativeSatoshis,
			requireConfirmedInputs: this._requireConfirmedInputs || undefined
		};

		return { ok: true, message: ackMessage, messageType: 'splice_ack' };
	}

	// ─────────────── Interactive TX ───────────────

	/**
	 * Add a local input to the splice transaction.
	 */
	addInput(input: IInteractiveTxInput): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot add input: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.addInput(input);
	}

	/**
	 * Add a peer's input to the splice transaction.
	 */
	addPeerInput(input: IInteractiveTxInput): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot add peer input: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.addPeerInput(input);
	}

	/**
	 * Add a local output to the splice transaction.
	 */
	addOutput(output: IInteractiveTxOutput): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot add output: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.addOutput(output);
	}

	/**
	 * Add a peer's output to the splice transaction.
	 */
	addPeerOutput(output: IInteractiveTxOutput): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot add peer output: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.addPeerOutput(output);
	}

	/**
	 * Remove a local input by serial ID.
	 */
	removeInput(serialId: bigint): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot remove input: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.removeInput(serialId);
	}

	/**
	 * Remove a peer's input by serial ID.
	 */
	removePeerInput(serialId: bigint): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot remove peer input: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.removePeerInput(serialId);
	}

	/**
	 * Remove a local output by serial ID.
	 */
	removeOutput(serialId: bigint): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot remove output: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.removeOutput(serialId);
	}

	/**
	 * Remove a peer's output by serial ID.
	 */
	removePeerOutput(serialId: bigint): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot remove peer output: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		return this._txBuilder.removePeerOutput(serialId);
	}

	/**
	 * Mark ourselves as complete for interactive TX.
	 */
	markTxComplete(): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot mark complete: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		const err = this._txBuilder.markComplete();
		if (err) return err;

		// Check if both sides are now complete
		if (this._txBuilder.isComplete()) {
			this._state = SpliceState.AWAITING_TX_SIGNATURES;
		}

		return null;
	}

	/**
	 * Handle peer's tx_complete.
	 */
	handlePeerTxComplete(): string | null {
		if (this._state !== SpliceState.TX_NEGOTIATION) {
			return 'Cannot handle peer tx_complete: not in TX_NEGOTIATION state';
		}
		if (!this._txBuilder) {
			return 'No TX builder available';
		}
		const err = this._txBuilder.handlePeerComplete();
		if (err) return err;

		// Check if both sides are now complete
		if (this._txBuilder.isComplete()) {
			this._state = SpliceState.AWAITING_TX_SIGNATURES;
		}

		return null;
	}

	/**
	 * Get the built transaction once interactive TX is complete.
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
	 * Get the interactive TX builder state.
	 */
	getTxBuilderState(): InteractiveTxState | null {
		if (!this._txBuilder) return null;
		return this._txBuilder.getState();
	}

	/**
	 * Generate next serial ID for our inputs/outputs.
	 */
	nextSerialId(): bigint | null {
		if (!this._txBuilder) return null;
		return this._txBuilder.nextSerialIdForUs();
	}

	// ─────────────── TX Signatures ───────────────

	/**
	 * Handle tx_signatures exchange completion.
	 * Sets the splice txid and transitions to AWAITING_SPLICE_LOCKED.
	 */
	handleTxSignatures(txid: Buffer, fundingOutputIndex: number): ISpliceResult {
		if (this._state !== SpliceState.AWAITING_TX_SIGNATURES) {
			return { ok: false, error: 'Unexpected tx_signatures: wrong state' };
		}

		this._spliceTxid = txid;
		this._spliceFundingOutputIndex = fundingOutputIndex;
		this._state = SpliceState.AWAITING_SPLICE_LOCKED;

		return { ok: true };
	}

	// ─────────────── Splice Locked ───────────────

	/**
	 * Send splice_locked (our side confirmed).
	 */
	sendSpliceLocked(): ISpliceResult {
		if (this._state !== SpliceState.AWAITING_SPLICE_LOCKED) {
			return { ok: false, error: 'Cannot send splice_locked: wrong state' };
		}

		if (!this._spliceTxid) {
			return { ok: false, error: 'No splice txid available' };
		}

		// A duplicate on the same connection is a protocol violation (callers
		// retransmit after reconnects via the reestablish path instead).
		if (this._localSpliceLocked) {
			return { ok: false, error: 'splice_locked already sent' };
		}

		this._localSpliceLocked = true;

		const message: ISpliceLockedMessage = {
			channelId: this._channelId,
			fundingTxid: this._spliceTxid
		};

		if (this._remoteSpliceLocked) {
			this._state = SpliceState.COMPLETE;
		}

		return { ok: true, message, messageType: 'splice_locked' };
	}

	/**
	 * Handle splice_locked from remote.
	 */
	handleSpliceLocked(msg: ISpliceLockedMessage): ISpliceResult {
		if (this._state !== SpliceState.AWAITING_SPLICE_LOCKED) {
			return { ok: false, error: 'Unexpected splice_locked: wrong state' };
		}

		if (!msg.channelId.equals(this._channelId)) {
			return { ok: false, error: 'Channel ID mismatch in splice_locked' };
		}

		// CLN v24.11.1 splice_locked carries no txid; if a caller supplied one
		// internally and it disagrees with ours, reject. Otherwise we rely on the
		// splice txid we already derived from the negotiated transaction.
		if (
			this._spliceTxid &&
			msg.fundingTxid &&
			!msg.fundingTxid.equals(this._spliceTxid)
		) {
			return { ok: false, error: 'Funding txid mismatch in splice_locked' };
		}

		this._remoteSpliceLocked = true;

		// Store txid from remote if we don't have one yet (only when provided).
		if (!this._spliceTxid && msg.fundingTxid) {
			this._spliceTxid = msg.fundingTxid;
		}

		if (this._localSpliceLocked) {
			this._state = SpliceState.COMPLETE;
		}

		return { ok: true };
	}

	// ─────────────── Abort ───────────────

	/**
	 * Abort the splice session.
	 */
	abort(reason?: string): ISpliceResult {
		if (this._state === SpliceState.COMPLETE) {
			return {
				ok: false,
				error: `Cannot abort completed splice${reason ? ': ' + reason : ''}`
			};
		}
		if (this._state === SpliceState.ABORTED) {
			return { ok: false, error: 'Splice already aborted' };
		}

		this._state = SpliceState.ABORTED;
		if (this._txBuilder) {
			this._txBuilder.abort();
		}

		return { ok: true };
	}
}
