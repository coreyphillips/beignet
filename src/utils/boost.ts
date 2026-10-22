import { CodedError } from './errors';

/**
 * Typed error returned by Wallet.boost. The code says which step failed:
 * NOT_BOOSTABLE when the transaction cannot be boosted that way, INVALID_FEE
 * when the requested fee was refused, and SEND_FAILED when the boost could
 * not be built or broadcast.
 */
export class BoostError extends CodedError<
	'NOT_BOOSTABLE' | 'INVALID_FEE' | 'SEND_FAILED'
> {
	constructor(
		code: 'NOT_BOOSTABLE' | 'INVALID_FEE' | 'SEND_FAILED',
		message: string,
		cause?: unknown
	) {
		super(code, message, cause === undefined ? undefined : { cause });
		this.name = 'BoostError';
	}
}
