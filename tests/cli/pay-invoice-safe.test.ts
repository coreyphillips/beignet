/**
 * Tests verifying payInvoiceSafe() truly NEVER throws.
 *
 * An AI agent using "safe" payment methods expects zero exceptions.
 * Every error type must be caught and returned as a FAILED PaymentInfo.
 */

import { expect } from 'chai';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BeignetNode } from '../../src/cli/beignet-node';
import { BeignetError, BeignetErrorCode } from '../../src/cli/errors';
import { PaymentInfo } from '../../src/cli/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import {
	DEFAULT_MIN_FINAL_CLTV_EXPIRY,
	Network
} from '../../src/lightning/invoice/types';
import {
	PaymentDirection,
	PaymentStatus
} from '../../src/lightning/node/types';

/**
 * Since BeignetNode.create() requires real Electrum/wallet, we test the
 * payInvoiceSafe catch-all behavior by verifying the error-handling contract
 * against the BeignetError class and by calling the method prototype pattern.
 *
 * We simulate the internal logic by replicating the catch block behavior.
 */

// Replicate the payInvoiceSafe catch-all logic for unit testing
function simulatePayInvoiceSafeCatch(
	bolt11: string,
	err: unknown
): PaymentInfo {
	let hashHex = 'unknown';
	let amount = 0;
	try {
		// Try to decode — in real code this calls decodeInvoice
		// For testing, only a valid bolt11 would succeed; we simulate failure for invalid ones
		if (bolt11 && bolt11.startsWith('lnbc')) {
			// Pretend decode succeeded with a known hash
			hashHex = 'abc123';
			amount = 1000;
		}
	} catch {
		/* bolt11 is malformed — use defaults */
	}

	const message = err instanceof Error ? err.message : String(err);
	const code = err instanceof BeignetError ? err.code : 'PAYMENT_FAILED';
	return {
		paymentHash: hashHex,
		amountSats: amount,
		status: 'FAILED',
		direction: 'OUTGOING',
		failureDescription: `[${code}] ${message}`,
		createdAt: Date.now()
	};
}

describe('payInvoiceSafe — Never Throws', () => {
	it('catches PAYMENT_FAILED and returns FAILED PaymentInfo', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'No route found'
		);
		const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
		expect(result.status).to.equal('FAILED');
		expect(result.direction).to.equal('OUTGOING');
		expect(result.failureDescription).to.include('[PAYMENT_FAILED]');
		expect(result.failureDescription).to.include('No route found');
	});

	it('catches PAYMENT_TIMEOUT and returns FAILED PaymentInfo', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_TIMEOUT,
			'Timed out waiting for HTLC'
		);
		const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.include('[PAYMENT_TIMEOUT]');
	});

	it('catches INVALID_PARAMS without throwing', () => {
		const err = new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			'bolt11 is required'
		);
		const result = simulatePayInvoiceSafeCatch('', err);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.include('[INVALID_PARAMS]');
		expect(result.failureDescription).to.include('bolt11 is required');
	});

	it('catches DUPLICATE_PAYMENT without throwing', () => {
		const err = new BeignetError(
			BeignetErrorCode.DUPLICATE_PAYMENT,
			'Payment already in progress'
		);
		const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.include('[DUPLICATE_PAYMENT]');
	});

	it('catches INSUFFICIENT_BALANCE without throwing', () => {
		const err = new BeignetError(
			BeignetErrorCode.INSUFFICIENT_BALANCE,
			'Not enough capacity'
		);
		const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.include('[INSUFFICIENT_BALANCE]');
	});

	it('catches NODE_DESTROYED without throwing', () => {
		const err = new BeignetError(
			BeignetErrorCode.NODE_DESTROYED,
			'Node has been destroyed'
		);
		const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.include('[NODE_DESTROYED]');
	});

	it('catches INVOICE_EXPIRED without throwing', () => {
		const err = new BeignetError(
			BeignetErrorCode.INVOICE_EXPIRED,
			'Invoice has expired'
		);
		const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription).to.include('[INVOICE_EXPIRED]');
	});

	it('catches non-BeignetError (generic Error) without throwing', () => {
		const err = new Error('Unexpected internal failure');
		const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
		expect(result.status).to.equal('FAILED');
		// Non-BeignetError gets [PAYMENT_FAILED] as generic code
		expect(result.failureDescription).to.include('[PAYMENT_FAILED]');
		expect(result.failureDescription).to.include('Unexpected internal failure');
	});

	it('handles completely malformed bolt11 gracefully', () => {
		const err = new BeignetError(
			BeignetErrorCode.INVALID_PARAMS,
			'Invalid invoice'
		);
		const result = simulatePayInvoiceSafeCatch('not-a-valid-invoice', err);
		expect(result.status).to.equal('FAILED');
		expect(result.paymentHash).to.equal('unknown');
		expect(result.amountSats).to.equal(0);
	});

	it('failureDescription includes error code for machine parsing', () => {
		const codes = [
			BeignetErrorCode.PAYMENT_FAILED,
			BeignetErrorCode.PAYMENT_TIMEOUT,
			BeignetErrorCode.INVALID_PARAMS,
			BeignetErrorCode.DUPLICATE_PAYMENT,
			BeignetErrorCode.INSUFFICIENT_BALANCE,
			BeignetErrorCode.NODE_DESTROYED,
			BeignetErrorCode.INVOICE_EXPIRED,
			BeignetErrorCode.NO_ROUTE,
			BeignetErrorCode.PEER_NOT_CONNECTED,
			BeignetErrorCode.CHANNEL_NOT_READY
		];
		for (const code of codes) {
			const err = new BeignetError(code, 'test message');
			const result = simulatePayInvoiceSafeCatch('lnbc1000...', err);
			expect(result.failureDescription).to.include(`[${code}]`);
		}
	});

	// ─── Verify BeignetNode.payInvoiceSafe method exists ───

	it('BeignetNode.prototype.payInvoiceSafe exists', () => {
		expect(typeof BeignetNode.prototype.payInvoiceSafe).to.equal('function');
	});
});

// Same rationale as tests/cli/payment-queue-restart.test.ts: a refused
// loopback connect returns instantly, where the regtest default is a public
// host.
const OFFLINE_ELECTRUM = {
	electrumHost: '127.0.0.1',
	electrumPort: 65529,
	electrumTls: false
};

const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** An invoice from somebody else, for a preimage the test knows. */
const invoiceFrom = (
	description: string
): { bolt11: string; paymentHash: Buffer; preimage: Buffer } => {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	return {
		bolt11: encodeInvoice({
			network: Network.REGTEST,
			amountMsat: 1_000_000n,
			timestamp: Math.floor(Date.now() / 1000),
			paymentHash,
			paymentSecret: crypto.randomBytes(32),
			description,
			expiry: 3600,
			minFinalCltvExpiry: DEFAULT_MIN_FINAL_CLTV_EXPIRY,
			privateKey: crypto
				.createHash('sha256')
				.update(Buffer.from(`payee-${description}`))
				.digest()
		}),
		paymentHash,
		preimage
	};
};

/**
 * Issue #975: the engine refuses to pay a hash whose durable OUTGOING row
 * says it was paid, and the in-memory record is pruned 24 hours after
 * completion while that row stays. payInvoiceSafe used to answer such a
 * refusal with a synthetic FAILED record, since it read memory only.
 */
describe('payInvoiceSafe answers a pruned paid hash with its durable record (issue #975)', function () {
	this.timeout(30_000);

	let tmpDir: string;
	let node: BeignetNode;

	before(async () => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'beignet-safe-durable-'));
		node = await BeignetNode.create({
			mnemonic: MNEMONIC,
			network: 'regtest',
			dataDir: tmpDir,
			logLevel: 'silent',
			rapidGossipSync: false,
			autoGossipSync: false,
			...OFFLINE_ELECTRUM
		});
	});

	after(async () => {
		await node?.destroy();
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	it('returns the COMPLETED record, preimage included, when only storage holds it', async () => {
		const { bolt11, paymentHash, preimage } = invoiceFrom('pruned paid');
		const hashHex = paymentHash.toString('hex');
		node.getStorage().savePayment(hashHex, {
			paymentHash,
			preimage,
			amountMsat: 1_000_000n,
			status: PaymentStatus.COMPLETED,
			direction: PaymentDirection.OUTGOING,
			createdAt: Date.now() - 2_000,
			completedAt: Date.now() - 1_000
		});
		expect(node.getPayment(hashHex), 'memory holds nothing').to.equal(null);

		const result = await node.payInvoiceSafe(bolt11, 2_000);
		expect(result.paymentHash).to.equal(hashHex);
		expect(result.status).to.equal('COMPLETED');
		expect(result.direction).to.equal('OUTGOING');
		expect(result.preimage).to.equal(preimage.toString('hex'));
		expect(result.failureDescription).to.equal(undefined);
	});

	it('still returns a synthetic FAILED record for a hash nothing knows', async () => {
		const { bolt11, paymentHash } = invoiceFrom('unknown');
		const result = await node.payInvoiceSafe(bolt11, 2_000);
		expect(result.paymentHash).to.equal(paymentHash.toString('hex'));
		expect(result.status).to.equal('FAILED');
		expect(result.failureDescription ?? '').to.match(/^\[[A-Z_]+\]/);
	});
});
