/**
 * CLI error types and BOLT failure code descriptions.
 */

export enum BeignetErrorCode {
	// Wallet
	WALLET_CREATE_FAILED = 'WALLET_CREATE_FAILED',
	ADDRESS_FAILED = 'ADDRESS_FAILED',
	SEND_FAILED = 'SEND_FAILED',
	REFRESH_FAILED = 'REFRESH_FAILED',
	/** Transaction cannot be fee-bumped (unknown, confirmed, or not RBF/CPFP-able). */
	NOT_BOOSTABLE = 'NOT_BOOSTABLE',
	/** Consolidation needs at least two spendable UTXOs. */
	NOTHING_TO_CONSOLIDATE = 'NOTHING_TO_CONSOLIDATE',
	/** Another instance already holds the data-dir lock. */
	INSTANCE_ALREADY_RUNNING = 'INSTANCE_ALREADY_RUNNING',

	// Payments
	PAYMENT_FAILED = 'PAYMENT_FAILED',
	PAYMENT_TIMEOUT = 'PAYMENT_TIMEOUT',
	INVOICE_EXPIRED = 'INVOICE_EXPIRED',
	NO_ROUTE = 'NO_ROUTE',
	/** User-supplied BOLT 11 string failed to parse. */
	INVALID_INVOICE = 'INVALID_INVOICE',
	/** User-supplied BOLT 12 offer string failed to parse. */
	INVALID_OFFER = 'INVALID_OFFER',

	// Channels
	CHANNEL_NOT_FOUND = 'CHANNEL_NOT_FOUND',
	CLOSE_FAILED = 'CLOSE_FAILED',
	FORCE_CLOSE_FAILED = 'FORCE_CLOSE_FAILED',
	ZERO_CONF_FAILED = 'ZERO_CONF_FAILED',

	// Peers
	PEER_NOT_CONNECTED = 'PEER_NOT_CONNECTED',
	CONNECT_TIMEOUT = 'CONNECT_TIMEOUT',
	CONNECT_FAILED = 'CONNECT_FAILED',

	// Channels
	INSUFFICIENT_BALANCE = 'INSUFFICIENT_BALANCE',
	DUPLICATE_PAYMENT = 'DUPLICATE_PAYMENT',
	CHANNEL_NOT_READY = 'CHANNEL_NOT_READY',
	OPEN_FAILED = 'OPEN_FAILED',
	/** The node has no funding provider able to serve this open or splice. */
	FUNDING_PROVIDER_REQUIRED = 'FUNDING_PROVIDER_REQUIRED',
	/** The fee estimator has not delivered its first sample; retry shortly. */
	FEE_ESTIMATE_NOT_READY = 'FEE_ESTIMATE_NOT_READY',
	/** option_splice/option_quiesce is missing on one side of the pair. */
	SPLICING_NOT_NEGOTIATED = 'SPLICING_NOT_NEGOTIATED',
	/** The channel exists but would not start the splice (state, peer, size). */
	SPLICE_REFUSED = 'SPLICE_REFUSED',

	// Budget
	SPENDING_LIMIT_EXCEEDED = 'SPENDING_LIMIT_EXCEEDED',
	SERVICE_DRAINING = 'SERVICE_DRAINING',
	IDEMPOTENCY_CONFLICT = 'IDEMPOTENCY_CONFLICT',

	// Node
	NODE_DESTROYED = 'NODE_DESTROYED',
	INVALID_PARAMS = 'INVALID_PARAMS',
	NOT_FOUND = 'NOT_FOUND',
	BODY_TOO_LARGE = 'BODY_TOO_LARGE',
	MNEMONIC_REQUIRES_AUTH = 'MNEMONIC_REQUIRES_AUTH',
	UNAUTHORIZED = 'UNAUTHORIZED',
	RATE_LIMITED = 'RATE_LIMITED'
}

export class BeignetError extends Error {
	code: BeignetErrorCode | string;
	failureCode?: number;

	constructor(
		code: BeignetErrorCode | string,
		message: string,
		failureCode?: number
	) {
		super(message);
		this.name = 'BeignetError';
		this.code = code;
		this.failureCode = failureCode;
	}

	toJSON(): { code: string; message: string; failureCode?: number } {
		const json: { code: string; message: string; failureCode?: number } = {
			code: this.code,
			message: this.message
		};
		if (this.failureCode !== undefined) json.failureCode = this.failureCode;
		return json;
	}
}

/**
 * Check if a BeignetError is retryable.
 * Returns false for permanent failures (BOLT 4 PERM flag, invalid params, etc.).
 * Returns true for transient failures (timeout, no route, peer disconnected).
 */
export function isRetryableError(err: BeignetError): boolean {
	// Permanent error codes — never retry
	const permanentCodes: Set<string> = new Set([
		BeignetErrorCode.INVALID_PARAMS,
		BeignetErrorCode.INVALID_INVOICE,
		BeignetErrorCode.INVALID_OFFER,
		BeignetErrorCode.NODE_DESTROYED,
		BeignetErrorCode.INVOICE_EXPIRED,
		BeignetErrorCode.DUPLICATE_PAYMENT,
		BeignetErrorCode.UNAUTHORIZED,
		BeignetErrorCode.BODY_TOO_LARGE,
		BeignetErrorCode.MNEMONIC_REQUIRES_AUTH,
		BeignetErrorCode.SPENDING_LIMIT_EXCEEDED,
		BeignetErrorCode.SERVICE_DRAINING,
		// A node with no funding provider will not grow one on a retry.
		BeignetErrorCode.FUNDING_PROVIDER_REQUIRED
	]);
	if (permanentCodes.has(err.code)) return false;

	// BOLT 4 PERM flag (0x4000) — permanent failure
	if (err.failureCode !== undefined && err.failureCode & 0x4000) return false;

	// Retryable error codes. Every code the daemon answers with a 502/503/504
	// must be in here: those statuses tell a caller to try again, and a
	// permanent failure that reads as retryable is worse than no code at all.
	// A test walks the status map and fails if the two ever disagree.
	const retryableCodes: Set<string> = new Set([
		BeignetErrorCode.PAYMENT_TIMEOUT,
		BeignetErrorCode.PEER_NOT_CONNECTED,
		BeignetErrorCode.NO_ROUTE,
		// The estimator's seed lands within milliseconds of construction.
		BeignetErrorCode.FEE_ESTIMATE_NOT_READY,
		// A peer that is down or slow now can be up on the next attempt. These
		// only read as permanent before because they fell through the default.
		BeignetErrorCode.CONNECT_FAILED,
		BeignetErrorCode.CONNECT_TIMEOUT,
		// Reaching an upstream (the fee source, an L402 target, a guardian
		// quorum) failed; the next attempt reaches a different world.
		'FEE_ESTIMATE_FAILED',
		'L402_FETCH_FAILED',
		'RESTORE_HEAD_UNVERIFIABLE',
		'RECOVERY_UNAVAILABLE',
		// Recovery holds that resolve on their own or on a restart.
		'NODE_RESTORE_PENDING',
		'NODE_RESTART_REQUIRED',
		'RESTORE_NO_QUORUM',
		'RESTORE_CAS_EXHAUSTED'
	]);
	if (retryableCodes.has(err.code)) return true;

	// PAYMENT_FAILED without PERM failureCode is retryable
	if (err.code === BeignetErrorCode.PAYMENT_FAILED) return true;

	// Default: not retryable for unknown codes
	return false;
}

/**
 * Check if a BeignetError is a permanent (non-retryable) failure.
 * Inverse of isRetryableError — returns true for errors the agent should give up on.
 */
export function isPermanentFailure(err: BeignetError): boolean {
	return !isRetryableError(err);
}

/**
 * BOLT 4 failure codes (base values, without flag bits) → human-readable names.
 * Numbers are the spec failure codes; flag bits (PERM 0x4000 / NODE 0x2000 /
 * BADONION 0x8000 / UPDATE 0x1000) are stripped and reported separately by
 * describeFailureCode().
 */
const FAILURE_DESCRIPTIONS: Record<number, string> = {
	0x8000: 'BadOnion flag',
	0x4000: 'Perm flag (permanent failure)',
	0x2000: 'Node flag (node failure)',
	0x1000: 'Update flag (channel update enclosed)',
	1: 'invalid_realm',
	2: 'node_failure',
	3: 'required_node_feature_missing',
	4: 'invalid_onion_version',
	5: 'invalid_onion_hmac',
	6: 'invalid_onion_key',
	7: 'temporary_channel_failure',
	8: 'permanent_channel_failure',
	9: 'required_channel_feature_missing',
	10: 'unknown_next_peer',
	11: 'amount_below_minimum',
	12: 'fee_insufficient',
	13: 'incorrect_cltv_expiry',
	14: 'expiry_too_soon',
	15: 'incorrect_or_unknown_payment_details',
	18: 'final_incorrect_cltv_expiry',
	19: 'final_incorrect_htlc_amount',
	20: 'channel_disabled',
	21: 'expiry_too_far',
	23: 'mpp_timeout'
};

export function describeFailureCode(code: number): string {
	// Direct lookup first (handles both base codes and standalone flags)
	const direct = FAILURE_DESCRIPTIONS[code];
	if (direct) return direct;

	// Decompose composite BOLT 4 failure codes by stripping flag bits
	const PERM = 0x4000;
	const NODE = 0x2000;
	const UPDATE = 0x1000;

	const flags: string[] = [];
	let baseCode = code;

	if (baseCode & PERM) {
		flags.push('PERM');
		baseCode &= ~PERM;
	}
	if (baseCode & NODE) {
		flags.push('NODE');
		baseCode &= ~NODE;
	}
	if (baseCode & UPDATE) {
		flags.push('UPDATE');
		baseCode &= ~UPDATE;
	}

	if (flags.length > 0) {
		const baseName = FAILURE_DESCRIPTIONS[baseCode];
		if (baseName) {
			return `${flags.join('|')}|${baseName}`;
		}
	}

	return `unknown_failure (${code})`;
}
