/**
 * FFOR: Fast-Forward Offline Receive, Variant D (specs/ffor-offline-receive.md
 * v0.9, sections 7, 7.5, 7.6, 9.5). Plain Variant D only: no tower, no
 * witnesses, no escapes, no settlement packages. The whole protocol is the
 * signed lifecycle of section 7.5 wrapped around one stock BOLT 2 voucher
 * round (section 9.5.1), silent preimage settlement (section 9.5.1
 * "Settlement") and a stock drain (section 7.5.6).
 *
 * Message types (section 14) are odd, in the experimental range, and thus
 * ignorable by a peer that does not implement them.
 */

/** Section 14 message types used by Variant D. */
export const FF_INIT_TYPE = 55001;
export const FF_ACCEPT_TYPE = 55003;
export const FF_INVOICES_TYPE = 55005;
export const FF_ERROR_TYPE = 55023;
export const FF_ACTIVATE_TYPE = 55045;
export const FF_ACTIVATE_ACK_TYPE = 55047;
export const FF_ABORT_TYPE = 55049;
export const FF_CLOSE_TYPE = 55051;
export const FF_CLOSE_ACK_TYPE = 55053;

/** channel_reestablish TLV carrying the epoch state (section 11.1). */
export const FF_REESTABLISH_TLV_TYPE = 55001n;

/** Feature bits 560/561, option_ff_receive (section 5). */
export const FF_RECEIVE_FEATURE_BIT = 560;

/** section 7.1 `variant`. Only D is implemented here. */
export enum FforVariant {
	A = 1,
	B = 2,
	C = 3,
	D = 4
}

/** section 7.5.3 `profile` byte: 1 when TLV 9 is present (always in D). */
export const FF_PROFILE_FIXED_AMOUNT = 1;

/** section 7.5.1 states, with the section 11.1 wire encoding as values. */
export enum FforState {
	NEGOTIATING = 0,
	VOUCHERS_COMMITTED = 1,
	ACTIVATING = 2,
	ACTIVE = 3,
	DRAINING = 4,
	CLOSED = 5,
	ABORTED = 6
}

/** section 7.5.4 ff_abort `reason`. */
export enum FforAbortReason {
	OPERATOR = 0,
	TIMEOUT = 1,
	TERMS_REFUSED = 2,
	BOOK_MISMATCH = 3,
	COMMIT_MISMATCH = 4,
	VOUCHER_ROUND_FAILED = 5,
	DISCONNECT = 6,
	PROTOCOL_ERROR = 7
}

/** section 9.5.1 per-slot settlement state on S, durable across restart. */
export enum FforSlotState {
	UNUSED = 'UNUSED',
	SETTLING = 'SETTLING',
	SETTLED = 'SETTLED'
}

/** Which side of the epoch this node plays. */
export type FforRole = 'R' | 'S';

/** The BOLT 2 upper bound on HTLCs one side may offer (section 8). */
export const FF_MAX_K = 483;

/** section 7.5.5: S aborts a setup not ACTIVE within 60 s of stfu. */
export const FF_ACTIVATION_TIMEOUT_MS = 60_000;

/**
 * section 7.5.4 `ff_activate`: S rejects an epoch_start_height not within 6
 * blocks of its own tip.
 */
export const FF_EPOCH_START_TOLERANCE_BLOCKS = 6;

/** section 7.1 recommended `T_exp - D` margin, enforced as the minimum. */
export const FF_RECONCILE_MARGIN_BLOCKS = 1008;

/** section 7.6 `N`: blinded hops before and including S bound by R. */
export const FF_BLINDED_HOPS_N = 8;

/**
 * The epoch parameters of ff_init (section 7.1) that both sides keep.
 * `rPerCommitmentPoints` is always empty in Variant D and kept only so the
 * codec is complete.
 */
export interface IFforEpochParams {
	variant: FforVariant;
	budgetMsat: bigint;
	maxPayments: number;
	minPaymentMsat: bigint;
	settlementDeadline: number;
	voucherExpiry: number;
	feeBaseMsat: number;
	feeProportionalMillionths: number;
	escapeGranularityMsat: bigint;
	rPerCommitmentPoints: Buffer[];
	/** TLV 9, REQUIRED in Variant D: d_1..d_K in slot order. */
	voucherAmountsMsat: bigint[];
}

/** One section 7.5.3 book entry. */
export interface IFforBookEntry {
	/** 1-based slot index. */
	k: number;
	paymentHash: Buffer;
	amountMsat: bigint;
	voucherExpiry: number;
	settlementDeadline: number;
	sHtlcId: bigint;
}

/**
 * The durable epoch record (section 7.5.5 "Durable"): everything a restart
 * with the peer offline needs to serve every later transition from disk.
 * Lives on the channel state and is persisted with it.
 */
export interface IFforEpochRecord {
	role: FforRole;
	state: FforState;
	epochId: Buffer;
	params: IFforEpochParams;
	/** The peer's node id: every signed message verifies against it. */
	remoteNodeId: Buffer;
	/** ff_init as sent/received: `[2: type] || body`, the T_init input. */
	initWire: Buffer;
	/** ff_accept as sent/received, or null while NEGOTIATING before it. */
	acceptWire: Buffer | null;
	/** ff_accept fixed field n0. */
	sCommitmentNumber: bigint | null;
	/** ff_accept TLV 7. */
	sHtlcIdBase: bigint | null;
	/** ff_accept TLV 1, S-generated. */
	paymentHashes: Buffer[];
	/** S only: t_1..t_K. Never populated on R (section 9.5.2). */
	preimages: Buffer[];
	/** section 7.5.2 hashes, fixed as the transcript advances. */
	tInit: Buffer;
	tSetup: Buffer | null;
	hBook: Buffer | null;
	hCommit: Buffer | null;
	hAct: Buffer | null;
	epochStartHeight: number | null;
	/** ff_activate as sent/received (idempotent replay, retransmission). */
	activateWire: Buffer | null;
	activateAckWire: Buffer | null;
	closeWire: Buffer | null;
	closeAckWire: Buffer | null;
	/** S: per-slot settlement state (section 9.5.1). R: unused. */
	slotStates: FforSlotState[];
	/**
	 * S: the upstream HTLC each SETTLING/SETTLED slot answers, as
	 * "channelIdHex:htlcId", so a restart can tell a fulfilled slot from one
	 * whose fulfil never left (section 9.5.1 "SETTLING after a crash").
	 */
	slotUpstream: (string | null)[];
	/** Both: the ff_close_ack bitmap once it exists (bit k-1 = slot k). */
	settledBitmap: Buffer | null;
	/** R: preimages learned from the ack, a payer or a witness, by slot. */
	knownPreimages: (Buffer | null)[];
	/**
	 * S: set once ff_close has been processed (section 7.5.6 stopping
	 * condition), before the drain round completes and DRAINING is
	 * persisted.
	 */
	closeProcessed: boolean;
	/**
	 * R: an add in the voucher-round window did not match the book, or a
	 * voucher onion decoded to something other than the section 9.5.1
	 * payload. The round completes as ordinary BOLT 2 traffic and is then
	 * unwound with ff_abort (reason 5).
	 */
	voucherRoundFailed: boolean;
	/**
	 * R: the epoch aborted after vouchers were added; every voucher (and any
	 * mismatching add) still owes an update_fail_htlc once the channel is
	 * synchronized (section 9.5.1 "Abort after the voucher round").
	 */
	unwindOwed: boolean;
	/** The ff_abort reason recorded when the epoch aborted, if it did. */
	abortReason: FforAbortReason | null;
	/**
	 * R: ff_close was sent and the ff_close_ack is still owed; retransmitted
	 * whenever S reestablishes reporting ACTIVE (section 7.5.5).
	 */
	closeSent: boolean;
	/**
	 * Both: two ACTIVE peers reported different H_act values at reestablish
	 * (section 7.5.5). S stops settling; R's remedy is on-chain.
	 */
	activationMismatch: boolean;
}

/** What the channel needs from its host to run an epoch. */
export interface IFforChannelContext {
	/** The peer's node id; every signed FFOR message verifies against it. */
	remoteNodeId: Buffer;
	/** Sign a 32-byte digest with our node key, or absent when we have none. */
	signFn: ((digest: Buffer) => Buffer) | null;
	/**
	 * Our node private key, used by R to decode voucher onions and to build
	 * the failure messages that unwind an aborted round; absent means the
	 * onion is not verified and failures carry an unencryptable reason.
	 */
	nodePrivateKey: Buffer | null;
}

/** Wire-level ff_init (section 7.1). */
export interface IFforInitMessage extends IFforEpochParams {
	channelId: Buffer;
	epochId: Buffer;
	/** TLV 1, Variant B only. */
	paymentHashes?: Buffer[];
	/** TLV 3, Variant B only. */
	towerNodeId?: Buffer;
	/** TLV 5, Variant B only. */
	towerUri?: Buffer;
	signature: Buffer;
}

/** Wire-level ff_accept (section 7.2). */
export interface IFforAcceptMessage {
	channelId: Buffer;
	epochId: Buffer;
	sCommitmentNumber: bigint;
	/** TLV 1. */
	paymentHashes: Buffer[];
	/** TLV 7. */
	sHtlcIdBase: bigint;
	/** TLV 9. */
	voucherAmountsMsat: bigint[];
	/** TLV 11. */
	initHash: Buffer;
	signature: Buffer;
}

/** Wire-level ff_invoices (section 7.3), one chunk. */
export interface IFforInvoicesMessage {
	channelId: Buffer;
	epochId: Buffer;
	firstIndex: number;
	totalInvoices: number;
	invoices: string[];
}

/** Wire-level ff_activate (section 7.5.4). */
export interface IFforActivateMessage {
	channelId: Buffer;
	epochId: Buffer;
	setupHash: Buffer;
	bookHash: Buffer;
	commitHash: Buffer;
	epochStartHeight: number;
	signature: Buffer;
}

/** Wire-level ff_activate_ack (section 7.5.4). */
export interface IFforActivateAckMessage {
	channelId: Buffer;
	epochId: Buffer;
	activationHash: Buffer;
	signature: Buffer;
}

/** Wire-level ff_abort (section 7.5.4). */
export interface IFforAbortMessage {
	channelId: Buffer;
	epochId: Buffer;
	transcriptHash: Buffer;
	reason: FforAbortReason;
	data: Buffer;
	signature: Buffer;
}

/** Wire-level ff_close (section 7.5.4). */
export interface IFforCloseMessage {
	channelId: Buffer;
	epochId: Buffer;
	activationHash: Buffer;
	signature: Buffer;
}

/** Wire-level ff_close_ack (section 7.5.4). */
export interface IFforCloseAckMessage {
	channelId: Buffer;
	epochId: Buffer;
	activationHash: Buffer;
	numSlots: number;
	/** ceil(K/8) bytes; bit k-1 set iff slot k settled. */
	settled: Buffer;
	/** TLV 1: [2: k][32: t_k] per set bit, in k order. */
	preimages: { k: number; preimage: Buffer }[];
	signature: Buffer;
}

/** Wire-level ff_error (section 11.1), unsigned. */
export interface IFforErrorMessage {
	channelId: Buffer;
	epochId: Buffer;
	data: Buffer;
}

/** channel_reestablish TLV 55001 (section 11.1). */
export interface IFforReestablishTlv {
	epochId: Buffer;
	state: FforState;
	lastSeq: number;
	/** H_act, or 32 zero bytes before ACTIVE. */
	activationHash: Buffer;
}
