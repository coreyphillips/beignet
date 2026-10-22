import { CodedError, EWalletErrorCode } from './errors';

/**
 * Represents a result that can be successful (Ok) or contain an error (Err).
 */
export type Result<T> = Ok<T> | Err<T>;

/**
 * Represents a successful result containing a value of type T.
 */
class Ok<T> {
	/**
	 * Constructs an Ok result containing the given value.
	 * @param value - The value contained in the result.
	 */
	public constructor(public readonly value: T) {}

	/**
	 * Checks if the result is of type Ok.
	 * @returns True if the result is of type Ok, otherwise false.
	 */
	public isOk(): this is Ok<T> {
		return true;
	}

	/**
	 * Checks if the result is of type Err.
	 * @returns False, as the result is of type Ok.
	 */
	public isErr(): this is Err<T> {
		return false;
	}
}

/**
 * Represents an error result. Its error always has a `code` to branch on.
 */
class Err<T> {
	/**
	 * Constructs an Err result containing the given error.
	 * @param error - The error contained in the result.
	 */
	public constructor(public readonly error: CodedError) {}

	/**
	 * Checks if the result is of type Ok.
	 * @returns False, as the result is of type Err.
	 */
	public isOk(): this is Ok<T> {
		return false;
	}

	/**
	 * Checks if the result is of type Err.
	 * @returns True if the result is of type Err, otherwise false.
	 */
	public isErr(): this is Err<T> {
		return true;
	}
}

/**
 * Construct a new Ok result value.
 * @param value - The value to be wrapped in an Ok result.
 * @returns An Ok result containing the given value.
 */
export const ok = <T>(value: T): Ok<T> => new Ok(value);

/**
 * Construct a new Err result value.
 *
 * `err(code, message, cause)` names the failure. `err(message)` carries
 * UNSPECIFIED. `err(error)` returns a CodedError as it is and wraps any other
 * error in one with the same message, keeping that error's own string code if
 * it has one, and the error itself as the cause.
 * @returns An Err result containing the error.
 */
export function err<T>(code: string, message: string, cause?: unknown): Err<T>;
export function err<T>(error: Error | string): Err<T>;
export function err<T>(
	error: Error | string,
	message?: string,
	cause?: unknown
): Err<T> {
	if (message !== undefined) {
		return new Err(
			new CodedError(
				error as string,
				message,
				cause === undefined ? undefined : { cause }
			)
		);
	}
	if (typeof error === 'string') {
		return new Err(new CodedError(EWalletErrorCode.UNSPECIFIED, error));
	}
	if (error instanceof CodedError) return new Err(error);
	// Not every caller passes a real Error: a catch hands over whatever was
	// thrown, and Electrum rejects with plain objects.
	const { code, message: text } = (error ?? {}) as {
		code?: unknown;
		message?: unknown;
	};
	return new Err(
		new CodedError(
			typeof code === 'string' ? code : EWalletErrorCode.UNSPECIFIED,
			typeof text === 'string' ? text : String(error),
			{ cause: error }
		)
	);
}
