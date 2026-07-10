/**
 * Leveled logging (M6) — fully OFFLINE unit tests.
 *
 * Covers:
 * 1. createConsoleLogger level filtering (debug < info < warn < error, 'silent')
 * 2. Default level ('info') and meta forwarding semantics
 * 3. noopLogger discards everything without throwing
 * 4. shouldLog / LOG_LEVEL_PRIORITY ordering
 * 5. Injection into LightningNode via INodeConfig.logger (structured action
 *    log entries are mirrored to logger.debug) and the silent no-op default
 * 6. Injection into Wallet via IWallet.logger and the console-backed default
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import net from 'net';
import tls from 'tls';
import {
	ILogger,
	IConsoleSink,
	TLogLevel,
	LOG_LEVEL_PRIORITY,
	createConsoleLogger,
	noopLogger,
	shouldLog
} from '../../src/logger';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Wallet } from '../../src/wallet';
import { EAvailableNetworks, EProtocol } from '../../src/types';

// ─────────────── Test doubles ───────────────

interface ISinkCall {
	level: string;
	args: unknown[];
}

function makeSink(): { calls: ISinkCall[]; sink: IConsoleSink } {
	const calls: ISinkCall[] = [];
	const record =
		(level: string) =>
		(...args: unknown[]): void => {
			calls.push({ level, args });
		};
	return {
		calls,
		sink: {
			debug: record('debug'),
			info: record('info'),
			warn: record('warn'),
			error: record('error')
		}
	};
}

interface ILoggerCall {
	level: string;
	message: string;
	meta?: unknown;
}

function makeLogger(): { calls: ILoggerCall[]; logger: ILogger } {
	const calls: ILoggerCall[] = [];
	const record =
		(level: string) =>
		(message: string, meta?: unknown): void => {
			calls.push({ level, message, meta });
		};
	return {
		calls,
		logger: {
			debug: record('debug'),
			info: record('info'),
			warn: record('warn'),
			error: record('error')
		}
	};
}

// ─────────────── createConsoleLogger ───────────────

describe('createConsoleLogger level filtering', () => {
	const emitAll = (logger: ILogger): void => {
		logger.debug('d');
		logger.info('i');
		logger.warn('w');
		logger.error('e');
	};

	it("level 'debug' lets all four levels through", () => {
		const { calls, sink } = makeSink();
		emitAll(createConsoleLogger('debug', sink));
		expect(calls.map((c) => c.level)).to.deep.equal([
			'debug',
			'info',
			'warn',
			'error'
		]);
	});

	it("level 'info' drops debug only", () => {
		const { calls, sink } = makeSink();
		emitAll(createConsoleLogger('info', sink));
		expect(calls.map((c) => c.level)).to.deep.equal(['info', 'warn', 'error']);
	});

	it("level 'warn' keeps warn and error only", () => {
		const { calls, sink } = makeSink();
		emitAll(createConsoleLogger('warn', sink));
		expect(calls.map((c) => c.level)).to.deep.equal(['warn', 'error']);
	});

	it("level 'error' keeps error only", () => {
		const { calls, sink } = makeSink();
		emitAll(createConsoleLogger('error', sink));
		expect(calls.map((c) => c.level)).to.deep.equal(['error']);
	});

	it("level 'silent' drops everything", () => {
		const { calls, sink } = makeSink();
		emitAll(createConsoleLogger('silent', sink));
		expect(calls).to.have.length(0);
	});

	it("defaults to 'info' when no level is given", () => {
		const { calls, sink } = makeSink();
		emitAll(createConsoleLogger(undefined, sink));
		expect(calls.map((c) => c.level)).to.deep.equal(['info', 'warn', 'error']);
	});

	it('forwards meta as a second argument only when provided', () => {
		const { calls, sink } = makeSink();
		const logger = createConsoleLogger('debug', sink);
		logger.info('plain');
		const meta = { txid: 'abc', code: 42 };
		logger.warn('with meta', meta);
		expect(calls[0].args).to.deep.equal(['plain']);
		expect(calls[1].args).to.have.length(2);
		expect(calls[1].args[0]).to.equal('with meta');
		expect(calls[1].args[1]).to.equal(meta);
	});
});

// ─────────────── shouldLog / priorities ───────────────

describe('shouldLog / LOG_LEVEL_PRIORITY', () => {
	it('orders levels debug < info < warn < error < silent', () => {
		expect(LOG_LEVEL_PRIORITY.debug).to.be.lessThan(LOG_LEVEL_PRIORITY.info);
		expect(LOG_LEVEL_PRIORITY.info).to.be.lessThan(LOG_LEVEL_PRIORITY.warn);
		expect(LOG_LEVEL_PRIORITY.warn).to.be.lessThan(LOG_LEVEL_PRIORITY.error);
		expect(LOG_LEVEL_PRIORITY.error).to.be.lessThan(LOG_LEVEL_PRIORITY.silent);
	});

	it('a message passes thresholds at or below its own level', () => {
		expect(shouldLog('warn', 'debug')).to.equal(true);
		expect(shouldLog('warn', 'warn')).to.equal(true);
		expect(shouldLog('warn', 'error')).to.equal(false);
		expect(shouldLog('debug', 'info')).to.equal(false);
		expect(shouldLog('error', 'error')).to.equal(true);
	});

	it("nothing passes a 'silent' threshold", () => {
		const levels: Array<Exclude<TLogLevel, 'silent'>> = [
			'debug',
			'info',
			'warn',
			'error'
		];
		for (const level of levels) {
			expect(shouldLog(level, 'silent')).to.equal(false);
		}
	});
});

// ─────────────── noopLogger ───────────────

describe('noopLogger', () => {
	it('exposes all four methods and never throws', () => {
		expect(() => {
			noopLogger.debug('d');
			noopLogger.info('i', { some: 'meta' });
			noopLogger.warn('w');
			noopLogger.error('e', new Error('boom'));
		}).to.not.throw();
	});
});

// ─────────────── LightningNode injection ───────────────

function makeSeed(id: number): Buffer {
	return crypto.createHash('sha256').update(`logger-test-seed-${id}`).digest();
}

function makeBasepoints(seed: Buffer): INodeConfig['channelBasepoints'] {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([i]))
			.digest();
		keys.push(privkey);
	}
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNodeConfig(seedId: number, logger?: ILogger): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST as Network,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey,
		enableNetworking: false,
		...(logger ? { logger } : {})
	};
}

type TEmitStructuredLog = (
	category: string,
	action: string,
	data: Record<string, unknown>
) => void;

describe('LightningNode logger injection', () => {
	it('mirrors structured action log entries to logger.debug', () => {
		const { calls, logger } = makeLogger();
		const node = new LightningNode(makeNodeConfig(1, logger));
		node.on('error', () => {}); // absorb node error events

		(
			node as unknown as { emitStructuredLog: TEmitStructuredLog }
		).emitStructuredLog('payment', 'test_action', { amountSats: 21 });

		const debugCalls = calls.filter((c) => c.level === 'debug');
		expect(debugCalls).to.have.length.greaterThanOrEqual(1);
		const mirrored = debugCalls.find(
			(c) => c.message === 'payment:test_action'
		);
		expect(mirrored).to.not.equal(undefined);
		expect(mirrored!.meta).to.deep.equal({ amountSats: 21 });

		node.destroy();
	});

	it('defaults to a silent no-op logger (no throw, no output)', () => {
		const node = new LightningNode(makeNodeConfig(2));
		node.on('error', () => {}); // absorb node error events

		expect(() => {
			(
				node as unknown as { emitStructuredLog: TEmitStructuredLog }
			).emitStructuredLog('channel', 'ready', { channelId: 'ff'.repeat(32) });
		}).to.not.throw();

		node.destroy();
	});
});

// ─────────────── Wallet injection ───────────────

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

// Unreachable on purpose: these tests must work offline.
const electrumOptions = {
	net,
	tls,
	servers: {
		host: '127.0.0.1',
		ssl: 65529,
		tcp: 65529,
		protocol: EProtocol.tcp
	}
};

describe('Wallet logger injection', function () {
	this.timeout(30000);

	it('uses the injected logger instance', async () => {
		const { logger } = makeLogger();
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'loggertest',
			network: EAvailableNetworks.regtest,
			electrumOptions,
			logger
		});
		if (res.isErr()) throw res.error;
		const wallet = res.value;
		expect(wallet.logger).to.equal(logger);
	});

	it('defaults to a console-backed logger with all four methods', async () => {
		const res = await Wallet.create({
			mnemonic: MNEMONIC,
			name: 'loggerdefault',
			network: EAvailableNetworks.regtest,
			electrumOptions
		});
		if (res.isErr()) throw res.error;
		const wallet = res.value;
		expect(wallet.logger).to.be.an('object');
		expect(wallet.logger.debug).to.be.a('function');
		expect(wallet.logger.info).to.be.a('function');
		expect(wallet.logger.warn).to.be.a('function');
		expect(wallet.logger.error).to.be.a('function');
	});
});
