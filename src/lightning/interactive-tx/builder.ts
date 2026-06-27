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
	validateInteractiveTx
} from './validation';

export class InteractiveTxBuilder {
	private session: IInteractiveTxSession;

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

		const parityErr = validatePeerSerialIdParity(
			input.serialId,
			this.session.isInitiator
		);
		if (parityErr) return parityErr;

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

		const parityErr = validatePeerSerialIdParity(
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

		const error = validateInteractiveTx(inputs, outputs);
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
