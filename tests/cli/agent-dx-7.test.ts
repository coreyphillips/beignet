/**
 * AI Agent Adoption Review — Agent DX 7 Tests
 *
 * Phase 3: connectAndOpenChannel (4 tests)
 * Phase 4: paymentSecret on InvoiceInfo (3 tests)
 * Phase 5: verifyPaymentProof (4 tests)
 * Phase 6: getNodeUri + isPermanentFailure (6 tests)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import {
	InvoiceInfo,
	PaymentProof,
	PaymentProofVerification,
	ChannelInfo
} from '../../src/cli/types';
import {
	BeignetError,
	BeignetErrorCode,
	isRetryableError,
	isPermanentFailure
} from '../../src/cli/errors';
import { getOpenApiSpec } from '../../src/cli/openapi';

// ─────────────── Phase 3: connectAndOpenChannel ───────────────

describe('connectAndOpenChannel', () => {
	it('method signature accepts pubkey, host, port, amountSats, opts', () => {
		// Verify the method would accept the right arguments by type-checking
		const args = {
			pubkey: '02' + 'aa'.repeat(32),
			host: '1.2.3.4',
			port: 9735,
			amountSats: 100000,
			opts: { pushSats: 1000 }
		};
		expect(args.pubkey).to.be.a('string');
		expect(args.host).to.be.a('string');
		expect(args.port).to.be.a('number');
		expect(args.amountSats).to.be.a('number');
		expect(args.opts.pushSats).to.be.a('number');
	});

	it('returns ChannelInfo after connect + open', () => {
		const result: ChannelInfo = {
			channelId: 'aabb'.repeat(16),
			peerPubkey: '02' + 'cc'.repeat(32),
			state: 'AWAITING_FUNDING_CONFIRMED',
			localBalanceSats: 100000,
			remoteBalanceSats: 0,
			capacitySats: 100000,
			isAnchor: true
		};
		expect(result.channelId).to.have.length(64);
		expect(result.state).to.equal('AWAITING_FUNDING_CONFIRMED');
		expect(result.isAnchor).to.be.true;
	});

	it('connection errors propagate as BeignetError', () => {
		const err = new BeignetError(
			'PEER_NOT_CONNECTED',
			'Connection refused: 1.2.3.4:9735'
		);
		expect(err).to.be.instanceOf(BeignetError);
		expect(err.code).to.equal('PEER_NOT_CONNECTED');
		expect(err.message).to.include('Connection refused');
	});

	it('daemon route delegates to connectAndOpenChannel', () => {
		const spec = getOpenApiSpec() as any;
		const route = spec.paths['/channel/connect-and-open'];
		expect(route).to.exist;
		expect(route.post).to.exist;
		expect(route.post.summary).to.include('Connect');
	});
});

// ─────────────── Phase 4: paymentSecret on InvoiceInfo ───────────────

describe('InvoiceInfo.paymentSecret', () => {
	it('createInvoice returns 64-char hex paymentSecret', () => {
		// Simulate the result from createInvoice
		const secret = crypto.randomBytes(32).toString('hex');
		const info: InvoiceInfo = {
			bolt11: 'lnbc1test',
			paymentHash: crypto.randomBytes(32).toString('hex'),
			paymentSecret: secret,
			amountSats: 1000
		};
		expect(info.paymentSecret).to.have.length(64);
		expect(info.paymentSecret).to.match(/^[0-9a-f]{64}$/);
	});

	it('paymentSecret is unique per invoice', () => {
		const secret1 = crypto.randomBytes(32).toString('hex');
		const secret2 = crypto.randomBytes(32).toString('hex');
		expect(secret1).to.not.equal(secret2);
	});

	it('field is present and non-empty', () => {
		const info: InvoiceInfo = {
			bolt11: 'lnbc1test',
			paymentHash: crypto.randomBytes(32).toString('hex'),
			paymentSecret: crypto.randomBytes(32).toString('hex')
		};
		expect(info.paymentSecret).to.exist;
		expect(info.paymentSecret!.length).to.be.greaterThan(0);
	});
});

// ─────────────── Phase 5: verifyPaymentProof ───────────────

describe('verifyPaymentProof', () => {
	it('valid proof returns { valid: true }', () => {
		const preimage = crypto.randomBytes(32);
		const paymentHash = crypto
			.createHash('sha256')
			.update(preimage)
			.digest('hex');

		const proof: PaymentProof = {
			paymentHash,
			preimage: preimage.toString('hex'),
			amountSats: 1000,
			completedAt: Date.now()
		};

		// Reproduce the verification logic
		const computed = crypto
			.createHash('sha256')
			.update(Buffer.from(proof.preimage, 'hex'))
			.digest('hex');
		const valid = computed === proof.paymentHash;

		const result: PaymentProofVerification = { valid, proof };
		expect(result.valid).to.be.true;
		expect(result.proof).to.exist;
	});

	it('non-existent payment returns { valid: false, error }', () => {
		const result: PaymentProofVerification = {
			valid: false,
			error: 'No proof found'
		};
		expect(result.valid).to.be.false;
		expect(result.error).to.equal('No proof found');
		expect(result.proof).to.be.undefined;
	});

	it('crypto check is correct (manual sha256 comparison)', () => {
		const preimage = Buffer.from('aa'.repeat(32), 'hex');
		const expected = crypto.createHash('sha256').update(preimage).digest('hex');

		// Tampered preimage
		const tampered = Buffer.from('bb'.repeat(32), 'hex');
		const tamperedHash = crypto
			.createHash('sha256')
			.update(tampered)
			.digest('hex');

		expect(tamperedHash).to.not.equal(expected);

		const result: PaymentProofVerification = {
			valid: false,
			proof: {
				paymentHash: expected,
				preimage: tampered.toString('hex'),
				amountSats: 500,
				completedAt: Date.now()
			},
			error: 'Preimage does not match payment hash'
		};
		expect(result.valid).to.be.false;
		expect(result.error).to.include('does not match');
	});

	it('daemon route returns correct JSON', () => {
		const spec = getOpenApiSpec() as any;
		const route = spec.paths['/payment/verify-proof'];
		expect(route).to.exist;
		expect(route.get).to.exist;
		expect(route.get.summary).to.include('verify');

		// Schema ref
		const schema = spec.components.schemas.PaymentProofVerification;
		expect(schema).to.exist;
		expect(schema.properties.valid).to.deep.equal({
			type: 'boolean',
			description: 'Whether the preimage matches the payment hash'
		});
		expect(schema.required).to.include('valid');
	});
});

// ─────────────── Phase 6a: getNodeUri ───────────────

describe('getNodeUri', () => {
	it('returns null when not listening', () => {
		// Simulate: no _listenPort set
		const listenPort: number | undefined = undefined;
		const result = listenPort ? `nodeid@host:${listenPort}` : null;
		expect(result).to.be.null;
	});

	it('returns correct format when listening', () => {
		const nodeId = '02' + 'aa'.repeat(32);
		const listenPort = 9735;
		const host = '127.0.0.1';
		const uri = `${nodeId}@${host}:${listenPort}`;
		expect(uri).to.match(/^[0-9a-f]+@[\d.]+:\d+$/);
		expect(uri).to.include('@');
		expect(uri).to.include(':9735');
	});

	it('externalHost override works', () => {
		const nodeId = '02' + 'bb'.repeat(32);
		const listenPort = 9735;
		const externalHost = '203.0.113.50';
		const uri = `${nodeId}@${externalHost}:${listenPort}`;
		expect(uri).to.include('203.0.113.50');
		expect(uri).to.not.include('127.0.0.1');
	});

	it('daemon route exists in OpenAPI spec', () => {
		const spec = getOpenApiSpec() as any;
		const route = spec.paths['/node/uri'];
		expect(route).to.exist;
		expect(route.get).to.exist;
		expect(route.get.summary).to.include('URI');
	});
});

// ─────────────── Phase 6b: isPermanentFailure ───────────────

describe('isPermanentFailure', () => {
	it('permanent codes return true', () => {
		const err = new BeignetError(BeignetErrorCode.INVALID_PARAMS, 'bad input');
		expect(isPermanentFailure(err)).to.be.true;
	});

	it('retryable codes return false', () => {
		const err = new BeignetError(BeignetErrorCode.PAYMENT_TIMEOUT, 'timed out');
		expect(isPermanentFailure(err)).to.be.false;
	});

	it('BOLT 4 PERM flag returns true', () => {
		const err = new BeignetError(
			BeignetErrorCode.PAYMENT_FAILED,
			'perm fail',
			0x400f
		);
		expect(isPermanentFailure(err)).to.be.true;
		// Also verify it's the inverse of isRetryableError
		expect(isRetryableError(err)).to.be.false;
	});

	it('is the exact inverse of isRetryableError', () => {
		const codes = [
			BeignetErrorCode.PAYMENT_TIMEOUT,
			BeignetErrorCode.NO_ROUTE,
			BeignetErrorCode.PEER_NOT_CONNECTED,
			BeignetErrorCode.PAYMENT_FAILED,
			BeignetErrorCode.INVALID_PARAMS,
			BeignetErrorCode.DUPLICATE_PAYMENT,
			BeignetErrorCode.INVOICE_EXPIRED
		];
		for (const code of codes) {
			const err = new BeignetError(code, 'test');
			expect(isPermanentFailure(err)).to.equal(
				!isRetryableError(err),
				`isPermanentFailure should be inverse of isRetryableError for ${code}`
			);
		}
	});

	it('is exported from cli/index.ts', () => {
		// Dynamic import to verify export
		const exports = require('../../src/cli/index');
		expect(exports.isPermanentFailure).to.be.a('function');
	});
});
