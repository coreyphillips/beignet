/**
 * Interactive Transaction Construction types (BOLT 2 v2).
 *
 * Used by dual-funding and splicing protocols for collaborative
 * transaction building.
 */

export enum InteractiveTxState {
	/** Initial state -- waiting for inputs/outputs */
	COLLECTING = 'COLLECTING',
	/** We have sent tx_complete */
	SENT_COMPLETE = 'SENT_COMPLETE',
	/** We have received tx_complete from peer */
	RECEIVED_COMPLETE = 'RECEIVED_COMPLETE',
	/** Both sides completed -- ready to sign */
	COMPLETE = 'COMPLETE',
	/** Transaction aborted */
	ABORTED = 'ABORTED'
}

export interface IInteractiveTxInput {
	/** Unique identifier -- even for initiator, odd for acceptor */
	serialId: bigint;
	/** Previous output txid (32 bytes) */
	prevTxid: Buffer;
	/** Previous output index */
	prevOutputIndex: number;
	/** Sequence number */
	sequence: number;
	/** Previous tx (for validation) -- serialized transaction */
	prevTx?: Buffer;
	/** Previous tx output vout */
	prevTxVout?: number;
}

export interface IInteractiveTxOutput {
	/** Unique identifier -- even for initiator, odd for acceptor */
	serialId: bigint;
	/** Amount in satoshis */
	amountSats: bigint;
	/** Output script */
	scriptPubkey: Buffer;
}

export interface IInteractiveTxSession {
	/** Whether we are the initiator (serial IDs must be even) */
	isInitiator: boolean;
	/** Current state */
	state: InteractiveTxState;
	/** Collected inputs */
	inputs: Map<string, IInteractiveTxInput>;
	/** Collected outputs */
	outputs: Map<string, IInteractiveTxOutput>;
	/** Lock time */
	locktime: number;
	/** Next serial ID counter */
	nextSerialId: bigint;
}
