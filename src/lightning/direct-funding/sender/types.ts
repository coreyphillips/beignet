/**
 * The payer engine's injected surface (issue #613, LFBW port #532 workstream
 * 4D).
 *
 * Declared here rather than importing a wallet, the shape 3A established with
 * IJitManagerDeps and 4C repeated: the engine is a library module driven by a
 * stub in tests, and `src/cli` is what binds these to a real wallet and node.
 *
 * Note what the wallet surface deliberately does NOT expose. There is no
 * `getPrivateKey`: a coin hands back a signer that can produce exactly two
 * things, an ownership proof over a digest and a witness for one input of one
 * transaction. Key material never crosses this boundary, so no future change to
 * the engine can sign anything else with it.
 */

import type * as bitcoin from 'bitcoinjs-lib';
import type { DfTransportRegistry } from '../transport/registry';
import type { DfTransportLog } from '../transport/types';
import type { DirectFundingPaymentStore } from './records';

// ─────────────── Limits ───────────────

/**
 * The nSequence every offer commits to, and the only one the payer will sign.
 * 0xfffffffd is RBF-signalling and below BOLT 2's interactive-tx ceiling, which
 * is what the receiver's builder requires.
 */
export const DF_PAYER_SEQUENCE = 0xfffffffd;

/**
 * Default ceiling on the payer's own cost above the amount, in satoshis. The
 * LFBW app posts `feeHeadroomSats: 1000` and nothing else, so this is the
 * number in production until that app is updated.
 */
export const DF_DEFAULT_MAX_TOTAL_FEE_SAT = 1_000n;

/**
 * When a lost offer is re-sent. Offers are idempotent at the receiver (4C
 * replays the recorded responses verbatim), so at-least-once delivery of the
 * offer is what makes a fire-and-forget lane usable.
 */
export const DF_OFFER_RESEND_DELAYS_MS = [4_000, 12_000, 30_000];

/** Time from the first offer to a verified sign request. */
export const DF_OFFER_TIMEOUT_MS = 120_000;

/**
 * Time from the witness leaving to the receipt arriving. Short, and its expiry
 * is a SUCCESS: the payment is already chain-atomic by then and the receipt is
 * proof, not delivery.
 */
export const DF_RECEIPT_TIMEOUT_MS = 45_000;

/** How often SIGNED_PENDING records are reconciled against the wallet. */
export const DF_SENDER_SWEEP_INTERVAL_MS = 60_000;

// ─────────────── Config ───────────────

export interface IDfSenderConfig {
	sequence?: number;
	defaultMaxTotalFeeSat?: bigint;
	offerResendDelaysMs?: number[];
	offerTimeoutMs?: number;
	receiptTimeoutMs?: number;
	sweepIntervalMs?: number;
}

// ─────────────── The wallet surface ───────────────

/** One spendable coin, in the shape the offer needs it. */
export interface IDfSenderCoin {
	/** Display (big-endian) txid, the order every wallet API here prints. */
	txidHex: string;
	vout: number;
	valueSat: bigint;
	/** The scriptPubKey being spent. */
	script: Buffer;
	/** Confirmation height; 0 means unconfirmed. */
	height: number;
}

/**
 * What a coin can sign, and nothing more. `kind` decides which sighash the
 * witness is built over and which scheme the receiver verifies the ownership
 * proof under, so it is carried rather than re-derived from the script twice.
 */
export interface IDfCoinSigner {
	kind: 'p2wpkh' | 'p2tr';
	/**
	 * 33-byte compressed for P2WPKH (ECDSA), 32-byte x-only for P2TR key path
	 * (Schnorr). The width is how the receiver knows which scheme to verify
	 * under, so it is the proof's own field rather than a lookup.
	 */
	ownershipPubkey: Buffer;
	/** The offer's ownership proof: 64 bytes either way. */
	signOwnership(digest: Buffer): Buffer;
	/**
	 * The witness stack for our input. `prevouts` carries every input's script
	 * and value because BIP 341 commits to all of them; a P2WPKH signer ignores
	 * it.
	 */
	signInput(
		tx: bitcoin.Transaction,
		inputIndex: number,
		prevouts: { scripts: Buffer[]; values: bigint[] }
	): Buffer[];
}

export interface IDfSenderWallet {
	/** Coins this wallet can spend right now: unfrozen, of a supported kind. */
	listSpendable(): IDfSenderCoin[];
	/**
	 * One coin by outpoint, FROZEN ONES INCLUDED. Resuming needs it: a run that
	 * died between reserving a coin and recording its witness leaves the payer's
	 * own freeze behind, and a spendable-only lookup would read that as a coin
	 * that went somewhere else and abandon a payment over it.
	 */
	findCoin(txidHex: string, vout: number): IDfSenderCoin | null;
	/** Raw previous transaction for a DISPLAY txid. */
	getTransaction(txidHex: string): Promise<Buffer>;
	/** A fresh change script. */
	changeScript(): Promise<Buffer>;
	/** The signer for one coin, or null when this wallet cannot spend it. */
	signerFor(coin: IDfSenderCoin): IDfCoinSigner | null;
	/** Does this wallet control the outpoint? Used to refuse a second input. */
	ownsOutpoint(txidHex: string, vout: number): boolean;
	/**
	 * Exclude the outpoint from every wallet selection path. Reports whether it
	 * landed, because a payer that cannot reserve its own coin must refuse
	 * BEFORE the witness rather than race its own wallet afterwards.
	 */
	freezeUtxo(txidHex: string, vout: number): Promise<boolean>;
	unfreezeUtxo(txidHex: string, vout: number): Promise<boolean>;
	/** What this wallet knows about a transaction, or null when unknown. */
	txStatus(txidHex: string): { known: boolean; confirmed: boolean } | null;
	/**
	 * A CONFIRMED transaction of ours spending this outpoint, or null. The only
	 * source of a conflicting spend is this wallet (the coin is ours), and rev 2
	 * makes a payment FAILED only when the conflict confirms.
	 */
	confirmedSpendOf(txidHex: string, vout: number): string | null;
}

// ─────────────── Deps ───────────────

export interface IDfSenderDeps {
	wallet: IDfSenderWallet;
	/** The lane registry 4B builds; the engine never opens a lane itself. */
	registry: DfTransportRegistry;
	/** Durable payment records, the D1 persist-before-emit half. */
	payments: DirectFundingPaymentStore;
	/** The BOLT chain_hash this wallet pays on. */
	chainHash(): Buffer;
	now?(): number;
	/** Structured-log sink, the same one 4B's lanes and 4C's engine take. */
	log?: DfTransportLog;
}

// ─────────────── Result ───────────────

export interface IDfSendResult {
	offerId: string;
	/** The coin we offered, display byte order. */
	spentTxid: string;
	spentVout: number;
	amountSat: number;
	/** The funding transaction our witness completes, once one exists. */
	fundingTxid?: string;
	/**
	 * True once the receiver's node-key attestation over the funding output
	 * verified against the node the payment request named.
	 */
	attested: boolean;
	/**
	 * The delivery receipt: the preimage of the request's receipt hash, revealed
	 * by the receiver after broadcast. Null when it did not arrive in time,
	 * which is not a failure: delivery is chain-atomic by then.
	 */
	receiptPreimageHex: string | null;
	/** The negotiated transaction we signed. */
	rawTxHex?: string;
	/** The fully signed transaction, when the receipt carried it. */
	broadcastTxHex?: string;
	/** Rev 2's payer state, as recorded. */
	status: DfPaymentStatus;
	/**
	 * What went wrong AFTER the witness left. The call resolves in that case
	 * (rev 2 MUST), so this is the only place the caller can learn of it.
	 */
	caveat?: string;
}

// ─────────────── Records ───────────────

/**
 * Rev 2's payer state machine.
 *
 *   CREATED -> OFFERED -> ABORTED                       (fallback allowed)
 *                      -> SIGNED_PENDING -> MEMPOOL_SEEN -> CONFIRMED
 *                                        -> FAILED       (a conflict CONFIRMED)
 *
 * Everything from SIGNED_PENDING on describes a coin that may already be
 * spent, which is why only CREATED and OFFERED permit a fallback payment.
 */
export type DfPaymentStatus =
	| 'CREATED'
	| 'OFFERED'
	| 'SIGNED_PENDING'
	| 'MEMPOOL_SEEN'
	| 'CONFIRMED'
	| 'ABORTED'
	| 'FAILED';

/** The states in which the payer's coin may already be spent. */
export const DF_POST_WITNESS_STATES: ReadonlySet<DfPaymentStatus> =
	new Set<DfPaymentStatus>([
		'SIGNED_PENDING',
		'MEMPOOL_SEEN',
		'CONFIRMED',
		'FAILED'
	]);

/**
 * The states in which a record still holds its coin, so no OTHER request may
 * select it. The freeze cannot carry this on its own: it only lands when an
 * exchange reaches its sign request, and until then the wallet still reports
 * the coin as spendable.
 */
export const DF_COIN_HELD_STATES: ReadonlySet<DfPaymentStatus> =
	new Set<DfPaymentStatus>([
		'CREATED',
		'OFFERED',
		'SIGNED_PENDING',
		'MEMPOOL_SEEN'
	]);

/**
 * One direct-funding payment, durable from before the first frame leaves.
 *
 * The fork persisted nothing at all: the funding txid and the raw transaction
 * lived in closure state, so a crash between the witness send and the HTTP
 * response lost every record of a payment that may already be on chain (defect
 * D7). It is also what makes the send idempotent: the coin is pinned to the
 * request here, so a retry cannot select a different one (defect D6).
 */
export interface IDfPaymentRecord {
	/** 16-byte hex request id: the primary key and the idempotency key. */
	requestId: string;
	receiptHash: string;
	receiverNodeId: string;
	/** Decimal satoshis. */
	amountSat: string;
	maxTotalFeeSat: string;
	offerId: string;
	/**
	 * The encoded offer, byte for byte as it was first sent. A resumed attempt
	 * re-emits THESE bytes rather than rebuilding an equivalent offer: 4C keys
	 * its replay on the offer's content hash, and a Schnorr ownership proof is
	 * not deterministic, so a rebuilt offer would read as an id reused with
	 * different content and be refused.
	 */
	offerBody: string;
	/** The coin, pinned at the first attempt. */
	spentTxid: string;
	spentVout: number;
	spentValueSat: string;
	/** Hex; pinned with the coin so a retry offers byte-identical terms. */
	changeScript: string;
	status: DfPaymentStatus;
	createdAt: number;
	updatedAt: number;
	/** Set once the coin was excluded from this wallet's coin selection. */
	frozen?: boolean;
	/** The receiver's attestation, kept as proof of what we were told. */
	attestation?: {
		fundingOutputIndex: number;
		localFundingPubkey: string;
		remoteFundingPubkey: string;
		signature: string;
	};
	/** The transaction we verified and signed, hex. */
	negotiatedTx?: string;
	/** Our witness stack, hex per item. */
	witness?: string[];
	fundingTxid?: string;
	/** The complete signed transaction from the receipt, when it arrived. */
	broadcastTx?: string;
	receiptPreimage?: string;
	/** Why a terminal record ended where it did. */
	reason?: string;
}

// ─────────────── Logging ───────────────

export const DF_LOG_SEND_STARTED = 'df_send_started';
export const DF_LOG_SEND_REPLAYED = 'df_send_replayed';
export const DF_LOG_SEND_REFUSED = 'df_send_refused';
export const DF_LOG_SEND_COMMITTED = 'df_send_committed';
export const DF_LOG_SEND_COMPLETED = 'df_send_completed';
export const DF_LOG_SEND_CAVEAT = 'df_send_caveat';
/** A receipt whose preimage does not hash to the request's receipt hash. */
export const DF_LOG_FORGED_RECEIPT = 'df_forged_receipt';
export const DF_LOG_PAYMENT_RECONCILED = 'df_payment_reconciled';
