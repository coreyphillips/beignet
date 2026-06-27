/**
 * BOLT 2: Quiescence (STFU) state machine.
 *
 * State transitions:
 *   NORMAL -> SENT_STFU (we initiate) -> QUIESCENT (peer responds with STFU)
 *   NORMAL -> RECEIVED_STFU (peer initiates) -> QUIESCENT (we respond with STFU)
 *   QUIESCENT -> NORMAL (exit quiescence)
 *
 * Rules:
 *   - Cannot initiate quiescence with pending HTLCs
 *   - Reject new update_add_htlc during quiescence
 *   - Both sides must send STFU to enter QUIESCENT state
 */

export enum QuiescenceState {
	NORMAL = 'NORMAL',
	SENT_STFU = 'SENT_STFU',
	RECEIVED_STFU = 'RECEIVED_STFU',
	QUIESCENT = 'QUIESCENT'
}

export class QuiescenceManager {
	private state: QuiescenceState = QuiescenceState.NORMAL;
	private _initiator = false;

	getState(): QuiescenceState {
		return this.state;
	}

	isQuiescent(): boolean {
		return this.state === QuiescenceState.QUIESCENT;
	}

	isQuiescing(): boolean {
		return this.state !== QuiescenceState.NORMAL;
	}

	isInitiator(): boolean {
		return this._initiator;
	}

	/**
	 * Initiate quiescence (send STFU).
	 * Returns true if we should send STFU, false if not allowed.
	 */
	initiate(): boolean {
		if (this.state !== QuiescenceState.NORMAL) {
			return false;
		}
		this.state = QuiescenceState.SENT_STFU;
		this._initiator = true;
		return true;
	}

	/**
	 * Handle receiving STFU from peer.
	 * Returns true if we should respond with our own STFU.
	 */
	handlePeerStfu(): { shouldRespond: boolean; error?: string } {
		switch (this.state) {
			case QuiescenceState.NORMAL:
				// Peer initiated -- we need to respond
				this.state = QuiescenceState.RECEIVED_STFU;
				this._initiator = false;
				return { shouldRespond: true };
			case QuiescenceState.SENT_STFU:
				// Both sides sent STFU -- enter quiescent
				this.state = QuiescenceState.QUIESCENT;
				return { shouldRespond: false };
			case QuiescenceState.RECEIVED_STFU:
			case QuiescenceState.QUIESCENT:
				return {
					shouldRespond: false,
					error: 'Unexpected STFU in current state'
				};
			default:
				return { shouldRespond: false, error: 'Unknown quiescence state' };
		}
	}

	/**
	 * Complete the quiescence handshake after we respond.
	 * Called after we send our STFU response.
	 */
	completeHandshake(): void {
		if (this.state === QuiescenceState.RECEIVED_STFU) {
			this.state = QuiescenceState.QUIESCENT;
		}
	}

	/**
	 * Exit quiescence and return to normal operation.
	 */
	exitQuiescence(): boolean {
		if (this.state !== QuiescenceState.QUIESCENT) {
			return false;
		}
		this.state = QuiescenceState.NORMAL;
		this._initiator = false;
		return true;
	}

	/**
	 * Reset to normal state (e.g., on disconnect).
	 */
	reset(): void {
		this.state = QuiescenceState.NORMAL;
		this._initiator = false;
	}
}
