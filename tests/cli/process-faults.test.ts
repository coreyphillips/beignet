/**
 * The process-level fault handlers `beignet start` installs (issue #1003):
 * they log the fault with its stack and return, never exit. Called directly
 * rather than by emitting a real unhandled rejection, which would reach
 * mocha's own listener as well.
 */

import { expect } from 'chai';
import {
	createProcessFaultHandlers,
	describeFault,
	installProcessFaultHandlers
} from '../../src/cli/process-faults';
import { ILogger } from '../../src/logger';

describe('process fault handlers (issue #1003)', () => {
	const logged: Array<{ message: string; meta?: unknown }> = [];
	const logger: ILogger = {
		debug: () => {},
		info: () => {},
		warn: () => {},
		error: (message: string, meta?: unknown) => {
			logged.push({ message, meta });
		}
	};
	let exitCalls = 0;
	const realExit = process.exit;

	beforeEach(() => {
		logged.length = 0;
		exitCalls = 0;
		process.exit = ((): never => {
			exitCalls += 1;
			throw new Error('process.exit called');
		}) as typeof process.exit;
	});

	afterEach(() => {
		process.exit = realExit;
	});

	it('logs an unhandled rejection with its stack and does not exit', () => {
		const handlers = createProcessFaultHandlers(logger);
		const reason = new Error('route rejected');
		handlers.onUnhandledRejection(reason);
		expect(exitCalls).to.equal(0);
		expect(logged).to.have.length(1);
		expect(logged[0].message).to.include('Unhandled promise rejection');
		expect(logged[0].message).to.include('route rejected');
		expect(logged[0].message).to.include(reason.stack?.split('\n')[1].trim());
		expect(logged[0].meta).to.deep.equal({
			kind: 'Unhandled promise rejection',
			fault: 1
		});
		expect(handlers.faults()).to.equal(1);
	});

	it('logs an uncaught exception, counts it, and does not exit', () => {
		const handlers = createProcessFaultHandlers(logger);
		handlers.onUnhandledRejection('not even an Error');
		handlers.onUncaughtException(new Error('boom'));
		expect(exitCalls).to.equal(0);
		expect(logged).to.have.length(2);
		expect(logged[0].message).to.include('not even an Error');
		expect(logged[1].message).to.include('Uncaught exception');
		expect(logged[1].message).to.include('boom');
		expect(logged[1].meta).to.deep.equal({
			kind: 'Uncaught exception',
			fault: 2
		});
		expect(handlers.faults()).to.equal(2);
	});

	it('falls back to stderr when no logger is configured', () => {
		const written: string[] = [];
		const realWrite = process.stderr.write;
		process.stderr.write = ((chunk: string | Uint8Array): boolean => {
			written.push(String(chunk));
			return true;
		}) as typeof process.stderr.write;
		try {
			createProcessFaultHandlers().onUnhandledRejection(new Error('quiet'));
		} finally {
			process.stderr.write = realWrite;
		}
		expect(exitCalls).to.equal(0);
		expect(written).to.have.length(1);
		expect(written[0]).to.include('[beignet-daemon]');
		expect(written[0]).to.include('quiet');
	});

	it('describes a fault by its stack, message or value', () => {
		const err = new Error('with stack');
		expect(describeFault(err)).to.equal(err.stack);
		const bare = new Error('no stack');
		bare.stack = undefined;
		expect(describeFault(bare)).to.equal('no stack');
		expect(describeFault(42)).to.equal('42');
	});

	it('installs both listeners on the process and leaves the others alone', () => {
		const rejectionsBefore = process.listeners('unhandledRejection');
		const exceptionsBefore = process.listeners('uncaughtException');
		const handlers = installProcessFaultHandlers(logger);
		try {
			expect(process.listeners('unhandledRejection')).to.include(
				handlers.onUnhandledRejection
			);
			expect(process.listeners('uncaughtException')).to.include(
				handlers.onUncaughtException
			);
		} finally {
			process.removeListener(
				'unhandledRejection',
				handlers.onUnhandledRejection
			);
			process.removeListener('uncaughtException', handlers.onUncaughtException);
		}
		expect(process.listeners('unhandledRejection')).to.deep.equal(
			rejectionsBefore
		);
		expect(process.listeners('uncaughtException')).to.deep.equal(
			exceptionsBefore
		);
	});
});
