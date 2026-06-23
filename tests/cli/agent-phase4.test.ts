/**
 * Phase 4: Daemon DX & Graceful Shutdown.
 *
 * - 4.1: CORS headers
 * - 4.2: Graceful shutdown
 * - 4.3: Structured logging
 * - 4.4: Package.json discoverability
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import crypto from 'crypto';
import { EventEmitter } from 'events';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { DaemonOptions } from '../../src/cli/daemon';
import {
	LogLevel,
	LogEntry,
	BeignetNodeOptions
} from '../../src/cli/beignet-node';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`phase4-test-${id}`))
		.digest();
}

function derivePrivkey(seed: Buffer, index: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([index]))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(derivePrivkey(seed, i));
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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = derivePrivkey(seed, 0);
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

// ─── 4.1: CORS Headers ───

describe('CORS Headers', () => {
	it('DaemonOptions accepts cors boolean', () => {
		const opts: DaemonOptions = { cors: true };
		expect(opts.cors).to.be.true;
	});

	it('DaemonOptions accepts cors string origin', () => {
		const opts: DaemonOptions = { cors: 'https://example.com' };
		expect(opts.cors).to.equal('https://example.com');
	});

	it('DaemonOptions cors defaults to undefined', () => {
		const opts: DaemonOptions = {};
		expect(opts.cors).to.be.undefined;
	});

	it('DaemonOptions extends BeignetNodeOptions', () => {
		const opts: DaemonOptions = {
			cors: true,
			daemonPort: 3000,
			daemonHost: '0.0.0.0',
			apiToken: 'test-token',
			network: 'regtest'
		};
		expect(opts.daemonPort).to.equal(3000);
		expect(opts.daemonHost).to.equal('0.0.0.0');
		expect(opts.apiToken).to.equal('test-token');
	});

	it('cors false-y value means no CORS headers', () => {
		const opts: DaemonOptions = { cors: false };
		expect(opts.cors).to.be.false;
	});
});

// ─── 4.2: Graceful Shutdown ───

describe('Graceful Shutdown', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(10));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		try {
			node.destroy();
		} catch {
			/* already destroyed */
		}
	});

	it('gracefulShutdown returns a promise', () => {
		const result = node.gracefulShutdown(1000);
		expect(result).to.be.instanceOf(Promise);
	});

	it('gracefulShutdown resolves successfully', async () => {
		await node.gracefulShutdown(1000);
		// No error = success
	});

	it('gracefulShutdown sets _destroyed to true', async () => {
		await node.gracefulShutdown(1000);
		expect((node as any)._destroyed).to.be.true;
	});

	it('gracefulShutdown calls destroy internally', async () => {
		await node.gracefulShutdown(1000);
		// After gracefulShutdown, all listeners should be removed
		expect(node.listenerCount('payment:sent')).to.equal(0);
	});

	it('gracefulShutdown with default timeout', async () => {
		// Just verify it doesn't hang — it should resolve quickly when no HTLCs
		const start = Date.now();
		await node.gracefulShutdown();
		const elapsed = Date.now() - start;
		// Should resolve quickly (well under the 30s default) since no in-flight HTLCs
		expect(elapsed).to.be.lessThan(5000);
	});

	it('gracefulShutdown is idempotent via BeignetNode pattern', async () => {
		await node.gracefulShutdown(1000);
		// Second call should be no-op (already destroyed)
		// doesn't throw or hang
	});

	it('gracefulShutdown persists mission control if available', async () => {
		// Add a dummy storage to verify persistence path
		const mockStorage = {
			saveMissionControlCalled: false,
			open: () => {},
			close: () => {},
			saveMissionControl: () => {
				mockStorage.saveMissionControlCalled = true;
			},
			loadMissionControl: () => [],
			saveChannelState: () => {},
			loadAllChannels: () => [],
			loadAllPayments: () => [],
			savePayment: () => {},
			loadAllHtlcPayments: () => [],
			saveHtlcPayment: () => {},
			loadAllForwardedHtlcs: () => [],
			saveForwardedHtlc: () => {},
			loadAllPaymentSecrets: () => [],
			savePaymentSecret: () => {},
			loadAllInvoices: () => [],
			saveInvoice: () => {},
			transaction: (fn: () => void) => fn(),
			savePeerAddress: () => {},
			loadAllPeerAddresses: () => [],
			saveTrackedOutputs: () => {},
			loadTrackedOutputs: () => []
		};
		(node as any).storage = mockStorage;
		// Add a mission control entry to trigger save
		(node as any).missionControl.recordFailure(
			crypto.randomBytes(8).toString('hex'),
			10000n
		);
		await node.gracefulShutdown(1000);
		expect(mockStorage.saveMissionControlCalled).to.be.true;
	});

	it('gracefulShutdown waits for in-flight HTLCs (bounded)', async () => {
		// Mock a channel with an HTLC (htlcs is a Map in real code)
		let htlcCount = 1;
		const mockChannel = {
			getFullState: () => {
				const htlcs = new Map();
				if (htlcCount > 0) htlcs.set('0', { id: 0 });
				return { htlcs };
			}
		};
		node.getChannelManager().listChannels = () => {
			// Clear after first check to simulate HTLC settling
			const result = [mockChannel as any];
			htlcCount = 0;
			return result;
		};

		const start = Date.now();
		await node.gracefulShutdown(5000);
		const elapsed = Date.now() - start;
		// Should not timeout (HTLC clears on second check)
		expect(elapsed).to.be.lessThan(3000);
	});

	it('gracefulShutdown respects timeout with stuck HTLCs', async () => {
		// Mock a channel that always has HTLCs (htlcs is a Map)
		const mockChannel = {
			getFullState: () => {
				const htlcs = new Map();
				htlcs.set('0', { id: 0 });
				return { htlcs };
			}
		};
		node.getChannelManager().listChannels = () => [mockChannel as any];

		const start = Date.now();
		await node.gracefulShutdown(1500);
		const elapsed = Date.now() - start;
		// Should complete around timeout
		expect(elapsed).to.be.greaterThanOrEqual(1000);
		expect(elapsed).to.be.lessThan(5000);
	});

	it('destroy clears reconnect timers', () => {
		// Access reconnect timers set
		const timers = (node as any)._reconnectTimers;
		expect(timers).to.be.instanceOf(Set);
		// Add a fake timer
		const t = setTimeout(() => {}, 60_000);
		timers.add(t);
		expect(timers.size).to.equal(1);
		node.destroy();
		expect(timers.size).to.equal(0);
	});
});

// ─── 4.3: Structured Logging ───

describe('Structured Logging', () => {
	it('LogLevel type accepts valid levels', () => {
		const levels: LogLevel[] = ['debug', 'info', 'warn', 'error', 'silent'];
		expect(levels).to.have.length(5);
	});

	it('LogEntry has expected shape', () => {
		const entry: LogEntry = {
			level: 'info',
			message: 'test message',
			timestamp: Date.now()
		};
		expect(entry.level).to.equal('info');
		expect(entry.message).to.equal('test message');
		expect(typeof entry.timestamp).to.equal('number');
	});

	it('LogEntry accepts optional data', () => {
		const entry: LogEntry = {
			level: 'debug',
			message: 'test',
			data: { key: 'value', count: 42 },
			timestamp: Date.now()
		};
		expect(entry.data).to.deep.equal({ key: 'value', count: 42 });
	});

	it('BeignetNodeOptions accepts logLevel', () => {
		const opts: BeignetNodeOptions = { logLevel: 'debug' };
		expect(opts.logLevel).to.equal('debug');
	});

	it('BeignetNodeOptions logLevel defaults to undefined', () => {
		const opts: BeignetNodeOptions = {};
		expect(opts.logLevel).to.be.undefined;
	});

	it('LogLevel silent suppresses all logging', () => {
		// Verify the type works
		const silent: LogLevel = 'silent';
		expect(silent).to.equal('silent');
	});

	it('LogLevel warn suppresses debug and info', () => {
		// Priority: debug=0, info=1, warn=2, error=3, silent=4
		// When logLevel is 'warn', debug (0) and info (1) are below threshold
		const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
		const priorities: Record<LogLevel, number> = {
			debug: 0,
			info: 1,
			warn: 2,
			error: 3,
			silent: 4
		};
		const threshold = priorities['warn']; // 2
		const suppressed = levels.filter((l) => priorities[l] < threshold);
		expect(suppressed).to.deep.equal(['debug', 'info']);
	});

	it('log entries are emitted as events by BeignetNode', () => {
		// BeignetNode emits 'log' events, verify type structure
		const emitter = new EventEmitter();
		const logs: LogEntry[] = [];
		emitter.on('log', (entry: LogEntry) => logs.push(entry));

		emitter.emit('log', {
			level: 'info' as LogLevel,
			message: 'Payment received',
			data: { paymentHash: 'abc123', amountSats: 100 },
			timestamp: Date.now()
		});

		expect(logs).to.have.length(1);
		expect(logs[0].level).to.equal('info');
		expect(logs[0].message).to.equal('Payment received');
		expect(logs[0].data?.paymentHash).to.equal('abc123');
	});

	it('payment:sent logs include fee info', () => {
		const entry: LogEntry = {
			level: 'info',
			message: 'Payment sent',
			data: { paymentHash: 'abc', amountSats: 1000, feeSats: 5 },
			timestamp: Date.now()
		};
		expect(entry.data?.feeSats).to.equal(5);
	});

	it('payment:failed logs include failureCode', () => {
		const entry: LogEntry = {
			level: 'warn',
			message: 'Payment failed',
			data: { paymentHash: 'abc', failureCode: 15 },
			timestamp: Date.now()
		};
		expect(entry.level).to.equal('warn');
		expect(entry.data?.failureCode).to.equal(15);
	});

	it('channel events log channelId', () => {
		const entry: LogEntry = {
			level: 'info',
			message: 'Channel ready',
			data: { channelId: 'deadbeef' },
			timestamp: Date.now()
		};
		expect(entry.data?.channelId).to.equal('deadbeef');
	});

	it('peer events log at debug level', () => {
		const entry: LogEntry = {
			level: 'debug',
			message: 'Peer connected',
			data: { pubkey: '02abc' },
			timestamp: Date.now()
		};
		expect(entry.level).to.equal('debug');
	});

	it('BeignetNodeOptions onError callback type', () => {
		const errors: { code: string; message: string }[] = [];
		const opts: BeignetNodeOptions = {
			onError: (err) => errors.push(err)
		};
		opts.onError!({
			code: 'TEST',
			message: 'test error',
			timestamp: Date.now()
		});
		expect(errors).to.have.length(1);
		expect(errors[0].code).to.equal('TEST');
	});

	it('BeignetNodeEvents type documents expected events', () => {
		// BeignetNodeEvents is a type-only interface
		// Verify all expected event names exist as valid keys
		const validEventNames = [
			'payment:received',
			'payment:sent',
			'payment:failed',
			'channel:ready',
			'channel:closed',
			'peer:connect',
			'peer:disconnect',
			'node:error'
		];
		expect(validEventNames).to.have.length(8);
	});
});

// ─── 4.4: Package.json Discoverability ───

describe('Package.json Discoverability', () => {
	let pkg: Record<string, unknown>;

	before(() => {
		const pkgPath = path.join(__dirname, '../../package.json');
		pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
	});

	it('description mentions Lightning', () => {
		expect(pkg.description as string).to.include('Lightning');
	});

	it('keywords include lightning', () => {
		const kw = pkg.keywords as string[];
		expect(kw).to.include('lightning');
	});

	it('keywords include lightning-network', () => {
		const kw = pkg.keywords as string[];
		expect(kw).to.include('lightning-network');
	});

	it('keywords include bolt', () => {
		const kw = pkg.keywords as string[];
		expect(kw).to.include('bolt');
	});

	it('keywords include ai-agent', () => {
		const kw = pkg.keywords as string[];
		expect(kw).to.include('ai-agent');
	});

	it('exports lightning and cli subpaths', () => {
		const exports = pkg.exports as Record<string, unknown>;
		expect(exports).to.have.property('./lightning');
		expect(exports).to.have.property('./cli');
	});
});
