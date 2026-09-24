/**
 * Process-level fault handlers for `beignet start` (issue #1003).
 *
 * Node's default for an unhandled promise rejection is to throw it, which
 * terminates the process, and a single unauthenticated request once did just
 * that. A routing node that stays up can still claim and time out its HTLCs;
 * the exit is the loss vector. So the daemon process logs the fault, stack
 * included, and keeps running. Library code (BeignetNode, LightningNode)
 * never installs these: a host owns its process.
 */

import { ILogger } from '../logger';

export interface IProcessFaultHandlers {
	onUnhandledRejection: (reason: unknown) => void;
	onUncaughtException: (err: Error) => void;
	/** How many faults the handlers have reported since they were created. */
	faults: () => number;
}

/** The stack when there is one, else the message, else the value itself. */
export function describeFault(reason: unknown): string {
	return reason instanceof Error
		? reason.stack ?? reason.message
		: String(reason);
}

/**
 * Handlers that report and return, never exit. With no logger the line goes
 * to stderr, the way the daemon reports an unclassified route error, so the
 * fault is never silently swallowed.
 */
export function createProcessFaultHandlers(
	logger?: ILogger
): IProcessFaultHandlers {
	let count = 0;
	const report = (kind: string, reason: unknown): void => {
		count += 1;
		const message =
			`${kind} (process fault ${count}, the daemon keeps running): ` +
			describeFault(reason);
		if (logger) {
			logger.error(message, { kind, fault: count });
		} else {
			process.stderr.write(`[beignet-daemon] ${message}\n`);
		}
	};
	return {
		onUnhandledRejection: (reason) =>
			report('Unhandled promise rejection', reason),
		onUncaughtException: (err) => report('Uncaught exception', err),
		faults: () => count
	};
}

/** Register both handlers on this process and hand them back for removal. */
export function installProcessFaultHandlers(
	logger?: ILogger
): IProcessFaultHandlers {
	const handlers = createProcessFaultHandlers(logger);
	process.on('unhandledRejection', handlers.onUnhandledRejection);
	process.on('uncaughtException', handlers.onUncaughtException);
	return handlers;
}
