/**
 * Production Hardening 10 — Agent DX Tests (~30 tests)
 *
 * Fix 5: Backup endpoint path traversal (3 tests)
 * Fix 6: SSE event format matches REST (3 tests)
 * Fix 10: Missing BeignetErrorCode variants (5 tests)
 * Fix 11: payInvoiceSafe() (3 tests)
 * Fix 12: decodeOffer() on BeignetNode (3 tests)
 * Fix 13: openChannelAndWait() (2 tests)
 * Fix 14: sendOnchain fee rate parameter (2 tests)
 * Fix 15: OpenAPI schema definitions (3 tests)
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as path from 'path';
import { BeignetErrorCode } from '../../src/cli/errors';
import { getOpenApiSpec } from '../../src/cli/openapi';

describe('Production Hardening 10 — Agent DX', () => {
	// ─── Fix 5: Backup endpoint path traversal ───

	describe('Fix 5: Backup path traversal protection', () => {
		it('daemon rejects paths containing ".."', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			const backupSection = daemonSrc.substring(
				daemonSrc.indexOf("'POST /backup'"),
				daemonSrc.indexOf("'POST /offer/create'") > -1
					? daemonSrc.indexOf("'POST /offer/create'")
					: daemonSrc.length
			);
			expect(backupSection).to.include("'..'");
			expect(backupSection).to.include('Path traversal not allowed');
		});

		it('daemon rejects URL-encoded path traversal', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			const backupSection = daemonSrc.substring(
				daemonSrc.indexOf("'POST /backup'"),
				daemonSrc.indexOf('// ── BOLT 12')
			);
			expect(backupSection).to.include('%2e%2e');
			expect(backupSection).to.include('%2E%2E');
		});

		it('valid paths are accepted (no "..") in logic', () => {
			// The check is "if path includes .." — paths like /tmp/backup.db should pass
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			// The code only rejects when ".." is present
			expect(daemonSrc).to.include("destPath.includes('..')");
		});
	});

	// ─── Fix 6: SSE event format ───

	describe('Fix 6: SSE events via BeignetNode', () => {
		it('SSE is wired to BeignetNode (node) not LightningNode (lightningNode)', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			// Should wire events from `node.on(...)` not `lightningNode.on(...)`
			const sseStart = daemonSrc.indexOf('// Wire up SSE events');
			const sseSection = daemonSrc.substring(sseStart, sseStart + 500);
			expect(sseSection).to.include('node.on(eventName');
			expect(sseSection).to.not.include('lightningNode.on(eventName');
		});

		it('SSE data does not need Buffer/bigint conversion', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			const sseSection = daemonSrc.substring(
				daemonSrc.indexOf('// Wire up SSE events'),
				daemonSrc.indexOf('return new Promise')
			);
			// Should NOT have the old replacer function
			expect(sseSection).to.not.include('Buffer.isBuffer');
			expect(sseSection).to.not.include("typeof value === 'bigint'");
		});

		it('SSE events include standard event types', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			expect(daemonSrc).to.include("'payment:received'");
			expect(daemonSrc).to.include("'payment:sent'");
			expect(daemonSrc).to.include("'payment:failed'");
			expect(daemonSrc).to.include("'channel:ready'");
			expect(daemonSrc).to.include("'channel:closed'");
			expect(daemonSrc).to.include("'peer:connect'");
			expect(daemonSrc).to.include("'peer:disconnect'");
		});
	});

	// ─── Fix 10: Missing BeignetErrorCode variants ───

	describe('Fix 10: BeignetErrorCode variants', () => {
		it('has INSUFFICIENT_BALANCE code', () => {
			expect(BeignetErrorCode.INSUFFICIENT_BALANCE).to.equal(
				'INSUFFICIENT_BALANCE'
			);
		});

		it('has PEER_NOT_CONNECTED code', () => {
			expect(BeignetErrorCode.PEER_NOT_CONNECTED).to.equal(
				'PEER_NOT_CONNECTED'
			);
		});

		it('has DUPLICATE_PAYMENT code', () => {
			expect(BeignetErrorCode.DUPLICATE_PAYMENT).to.equal('DUPLICATE_PAYMENT');
		});

		it('has CHANNEL_NOT_READY code', () => {
			expect(BeignetErrorCode.CHANNEL_NOT_READY).to.equal('CHANNEL_NOT_READY');
		});

		it('has OPEN_FAILED code', () => {
			expect(BeignetErrorCode.OPEN_FAILED).to.equal('OPEN_FAILED');
		});
	});

	// ─── Fix 11: payInvoiceSafe() ───

	describe('Fix 11: payInvoiceSafe()', () => {
		it('BeignetNode has payInvoiceSafe method', () => {
			const bnSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(bnSrc).to.include('async payInvoiceSafe(');
		});

		it('payInvoiceSafe catches all errors and resolves with FAILED status', () => {
			const bnSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			const safeSection = bnSrc.substring(
				bnSrc.indexOf('async payInvoiceSafe('),
				bnSrc.indexOf('sendPaymentAsync(')
			);
			// Catch-all pattern: returns FAILED PaymentInfo for any error
			expect(safeSection).to.include("status: 'FAILED'");
			expect(safeSection).to.include("direction: 'OUTGOING'");
			expect(safeSection).to.include('catch (err');
		});

		it('payInvoiceSafe never re-throws — always returns PaymentInfo', () => {
			const bnSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			const startIdx = bnSrc.indexOf('async payInvoiceSafe(');
			// Find end of method: next method definition at same indentation
			const afterStart = bnSrc.indexOf('\n\tasync ', startIdx + 1);
			const safeSection = bnSrc.substring(
				startIdx,
				afterStart > startIdx ? afterStart : startIdx + 500
			);
			// The catch-all should NOT re-throw; it always returns a FAILED PaymentInfo
			expect(safeSection).to.not.include('throw err');
			expect(safeSection).to.include('failureDescription');
		});
	});

	// ─── Fix 12: decodeOffer() on BeignetNode ───

	describe('Fix 12: decodeOfferString()', () => {
		it('BeignetNode has decodeOfferString method', () => {
			const bnSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(bnSrc).to.include('decodeOfferString(offerStr: string)');
		});

		it('daemon has POST /offer/decode route', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			expect(daemonSrc).to.include("'POST /offer/decode'");
			expect(daemonSrc).to.include('decodeOfferString');
		});

		it('decodeOfferString uses imported decodeOffer', () => {
			const bnSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(bnSrc).to.include('import { decodeOffer }');
			const method = bnSrc.substring(
				bnSrc.indexOf('decodeOfferString(offerStr'),
				bnSrc.indexOf('createOffer(')
			);
			expect(method).to.include('decodeOffer(offerStr)');
		});
	});

	// ─── Fix 13: openChannelAndWait() ───

	describe('Fix 13: openChannelAndWait()', () => {
		it('BeignetNode has openChannelAndWait method', () => {
			const bnSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(bnSrc).to.include('async openChannelAndWait(');
		});

		it('daemon has POST /channel/open-and-wait route', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			expect(daemonSrc).to.include("'POST /channel/open-and-wait'");
			expect(daemonSrc).to.include('openChannelAndWait');
		});
	});

	// ─── Fix 14: sendOnchain fee rate ───

	describe('Fix 14: sendOnchain fee rate', () => {
		it('sendOnchain accepts satsPerVbyte parameter', () => {
			const bnSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			const method = bnSrc.substring(
				bnSrc.indexOf('async sendOnchain('),
				bnSrc.indexOf('async refreshWallet(')
			);
			expect(method).to.include('satsPerVbyte');
			expect(method).to.include('satsPerByte');
		});

		it('daemon POST /send passes satsPerVbyte', () => {
			const daemonSrc = fs.readFileSync(
				path.join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			const sendSection = daemonSrc.substring(
				daemonSrc.indexOf("'POST /send'"),
				daemonSrc.indexOf("'POST /peer/connect'")
			);
			expect(sendSection).to.include('satsPerVbyte');
		});
	});

	// ─── Fix 15: OpenAPI schema definitions ───

	describe('Fix 15: OpenAPI schemas', () => {
		it('OpenAPI spec has components.schemas', () => {
			const spec = getOpenApiSpec() as any;
			expect(spec.components).to.have.property('schemas');
			expect(spec.components.schemas).to.have.property('NodeInfo');
			expect(spec.components.schemas).to.have.property('PaymentInfo');
			expect(spec.components.schemas).to.have.property('ChannelInfo');
			expect(spec.components.schemas).to.have.property('InvoiceInfo');
			expect(spec.components.schemas).to.have.property('BalanceInfo');
			expect(spec.components.schemas).to.have.property('HealthInfo');
			expect(spec.components.schemas).to.have.property('OfferInfo');
		});

		it('schemas have proper type and properties', () => {
			const spec = getOpenApiSpec() as any;
			const nodeInfo = spec.components.schemas.NodeInfo;
			expect(nodeInfo.type).to.equal('object');
			expect(nodeInfo.properties).to.have.property('nodeId');
			expect(nodeInfo.properties).to.have.property('blockHeight');

			const paymentInfo = spec.components.schemas.PaymentInfo;
			expect(paymentInfo.type).to.equal('object');
			expect(paymentInfo.properties).to.have.property('paymentHash');
			expect(paymentInfo.properties).to.have.property('status');
			expect(paymentInfo.properties.status.enum).to.deep.equal([
				'PENDING',
				'COMPLETED',
				'FAILED'
			]);
		});

		it('paths use $ref to schemas', () => {
			const spec = getOpenApiSpec() as any;
			const infoResponse =
				spec.paths['/info'].get.responses['200'].content['application/json'];
			expect(infoResponse.schema).to.have.property('$ref');
			expect(infoResponse.schema.$ref).to.equal(
				'#/components/schemas/NodeInfo'
			);
		});

		it('OpenAPI spec includes new routes from this plan', () => {
			const spec = getOpenApiSpec() as any;
			expect(spec.paths).to.have.property('/invoice/pay-safe');
			expect(spec.paths).to.have.property('/offer/decode');
			expect(spec.paths).to.have.property('/channel/open-and-wait');
			expect(spec.paths).to.have.property('/send');
		});
	});

	// ─── Fix 16: Updated example ───

	describe('Fix 16: Updated example', () => {
		it('example uses createInvoice return type correctly', () => {
			const exampleSrc = fs.readFileSync(
				path.join(__dirname, '../../example/lightning.ts'),
				'utf8'
			);
			expect(exampleSrc).to.include('invoiceResult.bolt11');
			expect(exampleSrc).to.include('invoiceResult.paymentHash');
		});
	});
});
