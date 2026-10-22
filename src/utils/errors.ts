/**
 * An error a caller branches on by `code`. The message is for people and may
 * be reworded in any release; the code is the contract.
 */
export class CodedError<C extends string = string> extends Error {
	readonly code: C;
	/** The failure this error was raised from, when it wraps one. */
	readonly cause?: unknown;

	constructor(code: C, message: string, options?: { cause?: unknown }) {
		super(message);
		this.name = 'CodedError';
		this.code = code;
		if (options && 'cause' in options) this.cause = options.cause;
	}
}

/**
 * Codes the on-chain layer (Wallet, Transaction, Electrum) puts on the errors
 * its Results carry. A Result error can also carry the code of an error it
 * passes through, such as WATCH_ONLY_CANNOT_SIGN or a BoostError's, so
 * `code` is typed as a string: compare it against these.
 */
export enum EWalletErrorCode {
	/** Built from a bare message, so it names no failure in particular. */
	UNSPECIFIED = 'UNSPECIFIED',
	/** The new fee would reach half the value of the transaction's inputs. */
	FEE_EXCEEDS_HALF_INPUTS = 'FEE_EXCEEDS_HALF_INPUTS',
	/** The new fee would reach half the amount the transaction sends. */
	FEE_EXCEEDS_HALF_OUTPUTS = 'FEE_EXCEEDS_HALF_OUTPUTS',
	/** An RBF replacement's fee rate is below what outbids the original. */
	REPLACEMENT_FEE_TOO_LOW = 'REPLACEMENT_FEE_TOO_LOW'
}
