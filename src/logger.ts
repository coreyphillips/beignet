/**
 * Leveled diagnostic logging with an injectable logger.
 *
 * This is the human-oriented diagnostic channel (debug/info/warn/error),
 * separate from and alongside the structured action log persisted by the
 * Lightning node (IStructuredLog / SQLite action_log). Library consumers
 * inject an ILogger via config (Wallet, LightningNode INodeConfig,
 * BeignetNodeOptions) to route diagnostics into their own logging stack;
 * the defaults preserve pre-existing behavior at every call site.
 *
 * The module is platform-neutral (no Node imports) so browser/React Native
 * ports can use it unchanged.
 */

/** Log severity, ordered debug < info < warn < error. 'silent' disables all output. */
export type TLogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

/** Minimal leveled logger surface. Implementations decide formatting/routing. */
export interface ILogger {
	debug(message: string, meta?: unknown): void;
	info(message: string, meta?: unknown): void;
	warn(message: string, meta?: unknown): void;
	error(message: string, meta?: unknown): void;
}

/** Numeric priority for each level (higher = more severe). */
export const LOG_LEVEL_PRIORITY: Record<TLogLevel, number> = {
	debug: 0,
	info: 1,
	warn: 2,
	error: 3,
	silent: 4
};

/**
 * Whether a message at `level` should be emitted given a configured
 * `threshold`. A 'silent' threshold suppresses everything; 'silent' is never
 * a valid message level so it never passes any threshold.
 */
export function shouldLog(
	level: Exclude<TLogLevel, 'silent'>,
	threshold: TLogLevel
): boolean {
	return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[threshold];
}

/** The subset of the console surface a console logger writes to. Injectable for tests/custom sinks. */
export interface IConsoleSink {
	debug(message?: unknown, ...optionalParams: unknown[]): void;
	info(message?: unknown, ...optionalParams: unknown[]): void;
	warn(message?: unknown, ...optionalParams: unknown[]): void;
	error(message?: unknown, ...optionalParams: unknown[]): void;
}

/**
 * Create an ILogger that filters by `level` and writes to a console-like
 * sink (the global console by default). Messages below the threshold are
 * dropped; `meta` is forwarded as a second console argument only when
 * provided, so output matches plain console usage exactly.
 */
export function createConsoleLogger(
	level: TLogLevel = 'info',
	sink: IConsoleSink = console
): ILogger {
	const write = (
		msgLevel: Exclude<TLogLevel, 'silent'>,
		message: string,
		meta?: unknown
	): void => {
		if (!shouldLog(msgLevel, level)) return;
		if (meta === undefined) {
			sink[msgLevel](message);
		} else {
			sink[msgLevel](message, meta);
		}
	};
	return {
		debug: (message, meta): void => write('debug', message, meta),
		info: (message, meta): void => write('info', message, meta),
		warn: (message, meta): void => write('warn', message, meta),
		error: (message, meta): void => write('error', message, meta)
	};
}

const noop = (): void => undefined;

/** A logger that discards everything. Default where silence is the status quo. */
export const noopLogger: ILogger = {
	debug: noop,
	info: noop,
	warn: noop,
	error: noop
};
