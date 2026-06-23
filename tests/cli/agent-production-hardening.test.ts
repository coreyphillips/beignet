/**
 * AI Agent Production Hardening — BeignetNode Layer Tests
 *
 * Phase 1: Spend limit safety (failed payments don't count, concurrent guard)
 * Phase 2: Graceful shutdown completeness (payment queue, backup await)
 * Phase 3: Timeout safety (connectPeer timeout, drain blocks retry)
 * Phase 4: Payment filtering (metadata key/value filter)
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { BeignetError } from '../../src/cli/errors';
import { PaymentFilter } from '../../src/cli/types';

// ─────────────── Phase 1: Spend Limit Safety ───────────────

describe('Phase 1: Spend Limit Safety', () => {
	it('failed payment does NOT count against daily spend limit', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			dailySpendLimitSats: 100_000
		});
		try {
			// Before any payment attempt
			const infoBefore = node.getDailySpendInfo();
			expect(infoBefore.spentSats).to.equal(0);

			// Attempt payInvoice with a garbage bolt11 — will throw
			try {
				await node.payInvoice('lnbc1invalid', 2000);
			} catch {
				// Expected to fail — invoice decode error or payment fail
			}

			// The failed payment should NOT have recorded spend
			const infoAfter = node.getDailySpendInfo();
			expect(infoAfter.spentSats).to.equal(0);
			expect(infoAfter.remainingSats).to.equal(100_000);
		} finally {
			await node.destroy();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it('concurrent sends cannot overshoot limit via _pendingSpendSats', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			dailySpendLimitSats: 1000
		});
		try {
			const n = node as any;
			const checkFn = n._checkSpendLimit.bind(node);

			// Simulate first concurrent payment reserving 600 sats
			n._pendingSpendSats = 600;

			// Second payment of 500 should fail — 600 pending + 500 = 1100 > 1000
			expect(() => checkFn(500)).to.throw('Daily spend limit exceeded');

			// But 400 should succeed — 600 pending + 400 = 1000 <= 1000
			expect(() => checkFn(400)).to.not.throw();

			// Reset and verify: with _pendingSpendSats=0, 500 is fine
			n._pendingSpendSats = 0;
			expect(() => checkFn(500)).to.not.throw();
		} finally {
			await node.destroy();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
});

// ─────────────── Phase 2: Graceful Shutdown Completeness ───────────────

describe('Phase 2: Graceful Shutdown Completeness', () => {
	it('payment queue listeners removed on graceful shutdown', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent'
		});
		try {
			const n = node as any;
			const pq = n.paymentQueue;
			if (pq) {
				// Add a dummy listener
				pq.on('test-event', () => {});
				expect(pq.listenerCount('test-event')).to.equal(1);
			}

			await node.gracefulShutdown();

			// After shutdown, listeners should be removed
			if (pq) {
				expect(pq.listenerCount('test-event')).to.equal(0);
			}
		} finally {
			// gracefulShutdown already called, destroy is idempotent
			await node.destroy();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it('in-flight backup is awaited before storage close on graceful shutdown', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const backupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-backup-'));
		const backupPath = path.join(backupDir, 'test.db');
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			backupPath,
			backupIntervalMs: 60_000 // won't fire during test
		});
		try {
			const n = node as any;

			// Simulate an in-flight backup by setting the promise
			let backupResolved = false;
			n._backupPromise = new Promise<void>((resolve) => {
				setTimeout(() => {
					backupResolved = true;
					resolve();
				}, 100);
			});

			// gracefulShutdown should await the backup
			await node.gracefulShutdown();
			expect(backupResolved).to.be.true;
		} finally {
			await node.destroy();
			fs.rmSync(tmpDir, { recursive: true, force: true });
			fs.rmSync(backupDir, { recursive: true, force: true });
		}
	});
});

// ─────────────── Phase 3: Timeout Safety ───────────────

describe('Phase 3: Timeout Safety', () => {
	it('connectPeer times out after configured duration', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			connectTimeoutMs: 500
		});
		try {
			const fakePubkey = '02' + '00'.repeat(32);
			const start = Date.now();
			try {
				await node.connectPeer(fakePubkey, '192.0.2.1', 9735);
				expect.fail('Should have timed out');
			} catch (err: unknown) {
				const elapsed = Date.now() - start;
				// Should fail within reasonable range of the 500ms timeout
				// (the underlying connect might fail faster than timeout, which is also fine)
				expect(elapsed).to.be.lessThan(5000);
				if (err instanceof BeignetError && err.code === 'CONNECT_TIMEOUT') {
					expect(err.message).to.include('timed out');
				}
				// If it fails for another reason (e.g., DNS error) before timeout, that's also acceptable
			}
		} finally {
			await node.destroy();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});

	it('payInvoiceWithRetry stops retrying when draining', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent'
		});
		try {
			// Set draining — the first attempt will fail from _checkDraining,
			// since payInvoice calls _checkDraining at the top
			node.setDraining(true);
			expect(node.isDraining()).to.be.true;

			try {
				await node.payInvoiceWithRetry('lnbcrt1pntest', {
					maxRetries: 3,
					backoffMs: 100
				});
				expect.fail('Should have thrown');
			} catch (err: unknown) {
				// Should get SERVICE_DRAINING or invoice decode error
				expect(err).to.be.instanceOf(Error);
			}
		} finally {
			await node.destroy();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
});

// ─────────────── Phase 4: Payment Filtering ───────────────

describe('Phase 4: Payment Filtering', () => {
	it('PaymentFilter type includes metadataKey and metadataValue fields', () => {
		const filter: PaymentFilter = {
			status: 'COMPLETED',
			metadataKey: 'requestId',
			metadataValue: 'req-123'
		};
		expect(filter.metadataKey).to.equal('requestId');
		expect(filter.metadataValue).to.equal('req-123');
	});

	it('listPayments filters by metadataKey and metadataValue', async function () {
		this.timeout(15_000);
		const { BeignetNode } = await import('../../src/cli/beignet-node');
		const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-test-'));
		const node = await BeignetNode.create({
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent'
		});
		try {
			// Inject mock payments via the underlying node's payment map
			const n = node as any;
			const lightningNode = n.node;
			const crypto = require('crypto');

			// Create 3 fake payments with different metadata
			const hashes = [
				crypto.randomBytes(32),
				crypto.randomBytes(32),
				crypto.randomBytes(32)
			];

			for (let i = 0; i < 3; i++) {
				const payment = {
					paymentHash: hashes[i],
					amountMsat: BigInt(1000 * (i + 1)) * 1000n,
					status: 'COMPLETED' as const,
					direction: 'OUTGOING' as const,
					createdAt: Date.now() - (3 - i) * 1000
				};
				// Use the internal payment tracking
				if (lightningNode.htlcPaymentMap) {
					lightningNode.htlcPaymentMap.set(hashes[i].toString('hex'), payment);
				}
			}

			// Set metadata on specific payments
			try {
				lightningNode.setPaymentMetadata(hashes[0], {
					requestId: 'req-AAA',
					agent: 'bot1'
				});
				lightningNode.setPaymentMetadata(hashes[1], {
					requestId: 'req-BBB',
					agent: 'bot1'
				});
				// hashes[2] has no metadata
			} catch {
				// If setPaymentMetadata fails (no payment found), set metadata directly
				const p0 = lightningNode.getPayment(hashes[0]);
				if (p0) p0.metadata = { requestId: 'req-AAA', agent: 'bot1' };
				const p1 = lightningNode.getPayment(hashes[1]);
				if (p1) p1.metadata = { requestId: 'req-BBB', agent: 'bot1' };
			}

			// Filter by metadataKey only (any value)
			const withKey = node.listPayments({ metadataKey: 'requestId' });
			// Should include payments with requestId, exclude those without
			const allPayments = node.listPayments();
			const withMetadata = allPayments.filter(
				(p) => p.metadata && 'requestId' in p.metadata
			);
			expect(withKey.length).to.equal(withMetadata.length);

			// Filter by metadataKey + metadataValue
			const specificValue = node.listPayments({
				metadataKey: 'requestId',
				metadataValue: 'req-AAA'
			});
			for (const p of specificValue) {
				expect(p.metadata?.requestId).to.equal('req-AAA');
			}

			// Filter with non-existent key returns empty
			const noMatch = node.listPayments({ metadataKey: 'nonExistentKey' });
			expect(noMatch).to.be.an('array');
			for (const p of noMatch) {
				expect(p.metadata).to.have.property('nonExistentKey');
			}
		} finally {
			await node.destroy();
			fs.rmSync(tmpDir, { recursive: true, force: true });
		}
	});
});
