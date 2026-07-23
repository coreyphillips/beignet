/**
 * Interactive Transaction Construction builder.
 *
 * Manages the state machine for collaboratively building a transaction.
 * Both peers add inputs and outputs, then signal tx_complete.
 * When both signal complete, the transaction is finalized.
 */

import {
	InteractiveTxState,
	IInteractiveTxInput,
	IInteractiveTxOutput,
	IInteractiveTxSession
} from './types';
import {
	validateSerialIdParity,
	validatePeerSerialIdParity,
	validateInteractiveTx,
	validatePeerInputPrevTx,
	MAX_INTERACTIVE_TX_INPUTS,
	MAX_INTERACTIVE_TX_OUTPUTS,
	MAX_INTERACTIVE_TX_MSGS,
	MAX_INTERACTIVE_TX_SEQUENCE,
	MAX_MONEY_SATS
} from './validation';

export class InteractiveTxBuilder {
	private session: IInteractiveTxSession;
	private dustLimitSats = 546n;

	constructor(isInitiator: boolean, locktime = 0) {
		this.session = {
			isInitiator,
			state: InteractiveTxState.COLLECTING,
			inputs: new Map(),
			outputs: new Map(),
			locktime,
			nextSerialId: isInitiator ? 0n : 1n
		};
	}

	/**
	 * Set the negotiated dust limit (never lowered below the 546-sat floor)
	 * used to validate output amounts.
	 */
	setDustLimit(sats: bigint): void {
		if (sats > this.dustLimitSats) {
			this.dustLimitSats = sats;
		}
	}

	/** Count inputs/outputs contributed by one side (even serial = initiator). */
	private countBySide(
		map: Map<string, { serialId: bigint }>,
		initiatorSide: boolean
	): number {
		let n = 0;
		for (const entry of map.values()) {
			if ((entry.serialId % 2n === 0n) === initiatorSide) n++;
		}
		return n;
	}

	getState(): InteractiveTxState {
		return this.session.state;
	}

	getSession(): IInteractiveTxSession {
		return this.session;
	}

	isComplete(): boolean {
		return this.session.state === InteractiveTxState.COMPLETE;
	}

	isAborted(): boolean {
		return this.session.state === InteractiveTxState.ABORTED;
	}

	/**
	 * Generate the next serial ID for our inputs/outputs.
	 */
	nextSerialIdForUs(): bigint {
		const id = this.session.nextSerialId;
		this.session.nextSerialId += 2n;
		return id;
	}

	/**
	 * Add a local input to the transaction.
	 */
	addInput(input: IInteractiveTxInput): string | null {
		if (this.session.state === InteractiveTxState.ABORTED) {
			return 'Session is aborted';
		}
		if (this.session.state === InteractiveTxState.COMPLETE) {
			return 'Session is already complete';
		}

		const parityErr = validateSerialIdParity(
			input.serialId,
			this.session.isInitiator
		);
		if (parityErr) return parityErr;

		const key = input.serialId.toString();
		if (this.session.inputs.has(key)) {
			return `Input with serial ID ${input.serialId} already exists`;
		}

		this.session.inputs.set(key, input);

		// Reset complete state if we were waiting
		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}

		return null;
	}

	/**
	 * Add a peer's input to the transaction.
	 */
	addPeerInput(input: IInteractiveTxInput): string | null {
		if (this.session.state === InteractiveTxState.ABORTED) {
			return 'Session is aborted';
		}
		if (this.session.state === InteractiveTxState.COMPLETE) {
			return 'Session is already complete';
		}

		// BOLT 2 DoS cap: every received tx_add_input counts (including ones
		// rejected below and re-adds after tx_remove_input).
		this.session.peerAddInputMsgs = (this.session.peerAddInputMsgs ?? 0) + 1;
		if (this.session.peerAddInputMsgs > MAX_INTERACTIVE_TX_MSGS) {
			return `Peer exceeded ${MAX_INTERACTIVE_TX_MSGS} tx_add_input messages`;
		}

		const parityErr = validatePeerSerialIdParity(
			input.serialId,
			this.session.isInitiator
		);
		if (parityErr) return parityErr;

		// BOLT 2: locktime/RBF signaling must stay enforceable on the
		// collaborative transaction.
		if (input.sequence > MAX_INTERACTIVE_TX_SEQUENCE) {
			return `tx_add_input sequence ${input.sequence} must be <= 0xfffffffd`;
		}

		// BOLT 2 receive-side prevtx checks (validity, vout range, segwit-only
		// anti-malleability). The splice shared input has no prevtx by design;
		// its outpoint is validated against the channel funding outpoint by the
		// splice layer instead.
		if (!input.isShared) {
			const prevTxErr = validatePeerInputPrevTx(
				input.prevTx,
				input.prevTxVout ?? input.prevOutputIndex
			);
			if (prevTxErr) return prevTxErr;
		}

		// BOLT 2 interactive-tx: a peer may contribute at most 252 inputs.
		if (
			this.countBySide(this.session.inputs, !this.session.isInitiator) >=
			MAX_INTERACTIVE_TX_INPUTS
		) {
			return `Peer exceeded ${MAX_INTERACTIVE_TX_INPUTS} inputs`;
		}

		const key = input.serialId.toString();
		if (this.session.inputs.has(key)) {
			return `Input with serial ID ${input.serialId} already exists`;
		}

		this.session.inputs.set(key, input);

		// A peer add after we sent tx_complete continues the negotiation (BOLT 2):
		// we will need to send tx_complete again, so leave SENT_COMPLETE.
		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}
		return null;
	}

	/**
	 * Add a local output to the transaction.
	 */
	addOutput(output: IInteractiveTxOutput): string | null {
		if (this.session.state === InteractiveTxState.ABORTED) {
			return 'Session is aborted';
		}
		if (this.session.state === InteractiveTxState.COMPLETE) {
			return 'Session is already complete';
		}

		const parityErr = validateSerialIdParity(
			output.serialId,
			this.session.isInitiator
		);
		if (parityErr) return parityErr;

		const key = output.serialId.toString();
		if (this.session.outputs.has(key)) {
			return `Output with serial ID ${output.serialId} already exists`;
		}

		this.session.outputs.set(key, output);

		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}

		return null;
	}

	/**
	 * Add a peer's output to the transaction.
	 */
	addPeerOutput(output: IInteractiveTxOutput): string | null {
		if (this.session.state === InteractiveTxState.ABORTED) {
			return 'Session is aborted';
		}
		if (this.session.state === InteractiveTxState.COMPLETE) {
			return 'Session is already complete';
		}

		// BOLT 2 DoS cap: every received tx_add_output counts.
		this.session.peerAddOutputMsgs = (this.session.peerAddOutputMsgs ?? 0) + 1;
		if (this.session.peerAddOutputMsgs > MAX_INTERACTIVE_TX_MSGS) {
			return `Peer exceeded ${MAX_INTERACTIVE_TX_MSGS} tx_add_output messages`;
		}

		const parityErr = validatePeerSerialIdParity(
			output.serialId,
			this.session.isInitiator
		);
		if (parityErr) return parityErr;

		// BOLT 2 interactive-tx: a peer may contribute at most 252 outputs, each
		// within [dust_limit, MAX_MONEY].
		if (
			this.countBySide(this.session.outputs, !this.session.isInitiator) >=
			MAX_INTERACTIVE_TX_OUTPUTS
		) {
			return `Peer exceeded ${MAX_INTERACTIVE_TX_OUTPUTS} outputs`;
		}
		if (output.amountSats > MAX_MONEY_SATS) {
			return `Output amount ${output.amountSats} exceeds MAX_MONEY`;
		}
		if (output.amountSats < this.dustLimitSats) {
			return `Output amount ${output.amountSats} below dust limit ${this.dustLimitSats}`;
		}

		const key = output.serialId.toString();
		if (this.session.outputs.has(key)) {
			return `Output with serial ID ${output.serialId} already exists`;
		}

		this.session.outputs.set(key, output);

		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}
		return null;
	}

	/**
	 * Remove an input by serial ID.
	 */
	removeInput(serialId: bigint): string | null {
		const key = serialId.toString();
		if (!this.session.inputs.has(key)) {
			return `Input with serial ID ${serialId} not found`;
		}
		this.session.inputs.delete(key);

		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}
		return null;
	}

	/**
	 * Remove a peer's input by serial ID.
	 */
	removePeerInput(serialId: bigint): string | null {
		const key = serialId.toString();
		if (!this.session.inputs.has(key)) {
			return `Input with serial ID ${serialId} not found`;
		}
		this.session.inputs.delete(key);
		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}
		return null;
	}

	/**
	 * Remove an output by serial ID.
	 */
	removeOutput(serialId: bigint): string | null {
		const key = serialId.toString();
		if (!this.session.outputs.has(key)) {
			return `Output with serial ID ${serialId} not found`;
		}
		this.session.outputs.delete(key);

		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}
		return null;
	}

	/**
	 * Remove a peer's output by serial ID.
	 */
	removePeerOutput(serialId: bigint): string | null {
		const key = serialId.toString();
		if (!this.session.outputs.has(key)) {
			return `Output with serial ID ${serialId} not found`;
		}
		this.session.outputs.delete(key);
		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			this.session.state = InteractiveTxState.COLLECTING;
		}
		return null;
	}

	/**
	 * Mark ourselves as complete (send tx_complete).
	 */
	markComplete(): string | null {
		if (this.session.state === InteractiveTxState.ABORTED) {
			return 'Session is aborted';
		}
		if (this.session.state === InteractiveTxState.COMPLETE) {
			return 'Session is already complete';
		}
		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			return 'Already sent tx_complete';
		}

		if (this.session.state === InteractiveTxState.RECEIVED_COMPLETE) {
			// Peer already complete -- both complete now
			this.session.state = InteractiveTxState.COMPLETE;
		} else {
			this.session.state = InteractiveTxState.SENT_COMPLETE;
		}
		return null;
	}

	/**
	 * Handle peer's tx_complete.
	 */
	handlePeerComplete(): string | null {
		if (this.session.state === InteractiveTxState.ABORTED) {
			return 'Session is aborted';
		}
		if (this.session.state === InteractiveTxState.COMPLETE) {
			return 'Session is already complete';
		}

		if (this.session.state === InteractiveTxState.SENT_COMPLETE) {
			// We already sent complete -- both complete now
			this.session.state = InteractiveTxState.COMPLETE;
		} else {
			this.session.state = InteractiveTxState.RECEIVED_COMPLETE;
		}
		return null;
	}

	/**
	 * Abort the session.
	 */
	abort(): void {
		this.session.state = InteractiveTxState.ABORTED;
	}

	/**
	 * Build the final transaction with inputs and outputs sorted by serial ID.
	 * Returns the sorted inputs and outputs for transaction construction.
	 */
	buildTransaction(): {
		inputs: IInteractiveTxInput[];
		outputs: IInteractiveTxOutput[];
		locktime: number;
	} | null {
		if (this.session.state !== InteractiveTxState.COMPLETE) {
			return null;
		}

		const inputs = [...this.session.inputs.values()].sort((a, b) =>
			a.serialId < b.serialId ? -1 : a.serialId > b.serialId ? 1 : 0
		);
		const outputs = [...this.session.outputs.values()].sort((a, b) =>
			a.serialId < b.serialId ? -1 : a.serialId > b.serialId ? 1 : 0
		);

		const error = validateInteractiveTx(inputs, outputs, this.dustLimitSats);
		if (error) return null;

		return { inputs, outputs, locktime: this.session.locktime };
	}

	/**
	 * Get all inputs.
	 */
	getInputs(): IInteractiveTxInput[] {
		return [...this.session.inputs.values()];
	}

	/**
	 * Get all outputs.
	 */
	getOutputs(): IInteractiveTxOutput[] {
		return [...this.session.outputs.values()];
	}
}
