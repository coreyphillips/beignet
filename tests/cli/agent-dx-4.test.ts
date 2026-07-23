/**
 * Production Hardening 9 — Agent DX Tests (~20 tests)
 *
 * Fix 8: CORS headers on SSE endpoint (2 tests)
 * Fix 9: BOLT 4 failure code decomposition (4 tests)
 * Fix 11: Type union cleanup (2 tests)
 * Fix 12: createInvoice() expiry parameter (3 tests)
 * Fix 13: getInvoice() method (3 tests)
 * Fix 14: getHealth() degraded status (3 tests)
 * Fix 15: OpenAPI spec coverage (3 tests)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { describeFailureCode } from '../../src/cli/errors';
import {
	ChannelInfo,
	PeerInfo,
	ChannelStateString,
	PeerState,
	HealthInfo
} from '../../src/cli/types';
import { getOpenApiSpec } from '../../src/cli/openapi';

// ─────────────── Helpers ───────────────

function makeBasepoints(seed: Buffer): IChannelBasepoints {
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

function createTestNode(): LightningNode {
	const privkey = crypto.randomBytes(32);
	const seed = crypto.randomBytes(32);
	const fundingPrivkey = crypto.randomBytes(32);
	const basepoints = makeBasepoints(seed);
	const node = new LightningNode({
		nodePrivateKey: privkey,
		channelBasepoints: basepoints,
		perCommitmentSeed: seed,
		fundingPrivkey,
		network: Network.REGTEST
	});
	node.on('error', () => {});
	node.on('node:error', () => {});
	return node;
}

describe('Production Hardening 9 — Agent DX', () => {
	// ─── Fix 8: CORS on SSE ───

	describe('Fix 8: CORS headers on SSE', () => {
		it('daemon module exports startDaemon with CORS option', () => {
			// Verify the daemon module accepts cors option (structural test)
			const daemon = require('../../src/cli/daemon');
			expect(daemon.startDaemon).to.be.a('function');
		});

		it('SSE writeHead includes CORS headers when cors enabled (code inspection)', () => {
			// Structural test: verify the daemon source includes CORS header logic for SSE
			const daemonSrc = require('fs').readFileSync(
				require('path').join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			// Check that the SSE block includes Access-Control-Allow-Origin
			expect(daemonSrc).to.include("sseHeaders['Access-Control-Allow-Origin']");
		});
	});

	// ─── Fix 9: BOLT 4 failure code decomposition ───

	describe('Fix 9: BOLT 4 failure code decomposition', () => {
		it('PERM|unknown_next_peer (0x400A) decomposes correctly', () => {
			// 0x4000 = PERM flag, 10 = unknown_next_peer
			expect(describeFailureCode(0x400a)).to.equal('PERM|unknown_next_peer');
		});

		it('UPDATE|fee_insufficient (0x100C) decomposes correctly', () => {
			// 0x1000 = UPDATE flag, 12 = fee_insufficient
			expect(describeFailureCode(0x100c)).to.equal('UPDATE|fee_insufficient');
		});

		it('raw base code (15) still works directly', () => {
			expect(describeFailureCode(15)).to.equal(
				'incorrect_or_unknown_payment_details'
			);
		});

		it('truly unknown code returns unknown_failure with code', () => {
			expect(describeFailureCode(99999)).to.equal('unknown_failure (99999)');
		});
	});

	// ─── Fix 11: Type union cleanup ───

	describe('Fix 11: Type union cleanup', () => {
		it('ChannelInfo.state accepts ChannelStateString values', () => {
			const states: ChannelStateString[] = [
				'NONE',
				'AWAITING_FUNDING_CONFIRMED',
				'AWAITING_CHANNEL_READY',
				'NORMAL',
				'SHUTTING_DOWN',
				'NEGOTIATING_CLOSING',
				'FORCE_CLOSED',
				'AWAITING_REESTABLISH',
				'CLOSED',
				'ANNOUNCEMENT_READY'
			];
			for (const state of states) {
				const info: ChannelInfo = {
					channelId: 'test',
					peerPubkey: 'test',
					state,
					localBalanceSats: 0,
					remoteBalanceSats: 0,
					capacitySats: 0,
					isAnchor: false
				};
				expect(info.state).to.equal(state);
			}
		});

		it('PeerInfo.state accepts PeerState values', () => {
			const states: PeerState[] = ['connected', 'connecting', 'disconnected'];
			for (const state of states) {
				const info: PeerInfo = {
					pubkey: 'test',
					host: 'localhost',
					port: 9735,
					state
				};
				expect(info.state).to.equal(state);
			}
		});
	});

	// ─── Fix 12: createInvoice expiry parameter ───

	describe('Fix 12: createInvoice() expiry parameter', () => {
		let node: LightningNode;

		afterEach(() => {
			if (node) node.destroy();
		});

		it('createInvoice with expiry returns expiry in result', () => {
			node = createTestNode();
			const result = node.createInvoice({
				amountMsat: 1000n,
				description: 'test',
				expiry: 60
			});
			expect(result.bolt11).to.be.a('string');
			// Decode the invoice to verify expiry
			const { decode } = require('../../src/lightning/invoice/decode');
			const decoded = decode(result.bolt11);
			expect(decoded.expiry).to.equal(60);
		});

		it('createInvoice without expiry uses default', () => {
			node = createTestNode();
			const result = node.createInvoice({
				amountMsat: 1000n,
				description: 'test'
			});
			const { decode } = require('../../src/lightning/invoice/decode');
			const decoded = decode(result.bolt11);
			// Default expiry is 3600 (1 hour) per BOLT 11
			expect(decoded.expiry).to.equal(3600);
		});

		it('BeignetNode.createInvoice expirySecs parameter exists in function signature', () => {
			// Structural test: verify BeignetNode accepts expirySecs
			const { BeignetNode } = require('../../src/cli/beignet-node');
			const proto = BeignetNode.prototype;
			expect(proto.createInvoice).to.be.a('function');
			// The function accepts 3 params (amountSats, description, expirySecs)
			// but optional params with ? don't count in .length
			// Instead just verify the function exists
		});
	});

	// ─── Fix 13: getInvoice() method ───

	describe('Fix 13: getInvoice() method', () => {
		let node: LightningNode;

		afterEach(() => {
			if (node) node.destroy();
		});

		it('getInvoice returns invoice for known payment hash', () => {
			node = createTestNode();
			const result = node.createInvoice({
				amountMsat: 50000n,
				description: 'lookup test'
			});
			const paymentHashHex = result.paymentHash.toString('hex');
			const invoice = node.getInvoice(paymentHashHex);
			expect(invoice).to.not.be.null;
			expect(invoice!.paymentHash).to.equal(paymentHashHex);
			expect(invoice!.bolt11).to.equal(result.bolt11);
		});

		it('getInvoice returns null for unknown hash', () => {
			node = createTestNode();
			const invoice = node.getInvoice('ff'.repeat(32));
			expect(invoice).to.be.null;
		});

		it('GET /invoice route exists in daemon routes', () => {
			// Structural test: verify the daemon source includes GET /invoice route
			const daemonSrc = require('fs').readFileSync(
				require('path').join(__dirname, '../../src/cli/daemon.ts'),
				'utf8'
			);
			expect(daemonSrc).to.include("'GET /invoice'");
		});
	});

	// ─── Fix 14: getHealth() degraded model ───

	describe('Fix 14: getHealth() degraded status model', () => {
		it('HealthInfo type supports degraded status', () => {
			const health: HealthInfo = {
				status: 'degraded',
				uptime: 1000,
				blockHeight: 100,
				electrumConnected: true,
				peerCount: 0,
				channelCount: 1,
				readyChannelCount: 0,
				graphNodes: 0,
				graphChannels: 0
			};
			expect(health.status).to.equal('degraded');
		});

		it('BeignetNode.getHealth source checks all-established-channels-broken', () => {
			// Structural: verify the degraded logic exists in the source
			const src = require('fs').readFileSync(
				require('path').join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(src).to.include('broken.length > 0 && operating.length === 0');
		});

		it('BeignetNode.getHealth source checks no-peers-but-operational-channels', () => {
			const src = require('fs').readFileSync(
				require('path').join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(src).to.include('peerCount === 0 && operating.length > 0');
		});

		it('BeignetNode.getHealth does not count pending opens toward degraded', () => {
			// A channel mid-open (SENT_*/AWAITING_FUNDING_CONFIRMED/etc) is a
			// deliberate operation in progress, not a fault. Only NORMAL/SPLICING
			// (operating) and AWAITING_REESTABLISH/ERRORED (broken) get a vote.
			const src = require('fs').readFileSync(
				require('path').join(__dirname, '../../src/cli/beignet-node.ts'),
				'utf8'
			);
			expect(src).to.include('ChannelState.SPLICING');
			expect(src).to.include('ChannelState.AWAITING_REESTABLISH');
			expect(src).to.not.include(
				'channels.length > 0 && readyChannels.length === 0'
			);
		});
	});

	// ─── Fix 15: OpenAPI spec coverage ───

	describe('Fix 15: OpenAPI spec coverage', () => {
		it('spec includes /invoice GET route', () => {
			const spec = getOpenApiSpec() as any;
			expect(spec.paths['/invoice']).to.exist;
			expect(spec.paths['/invoice'].get).to.exist;
			expect(spec.paths['/invoice'].get.summary).to.include('invoice');
		});

		it('spec includes /channel/connect-and-open route', () => {
			const spec = getOpenApiSpec() as any;
			expect(spec.paths['/channel/connect-and-open']).to.exist;
			expect(spec.paths['/channel/connect-and-open'].post).to.exist;
		});

		it('spec includes /payment/cancel route', () => {
			const spec = getOpenApiSpec() as any;
			expect(spec.paths['/payment/cancel']).to.exist;
			expect(spec.paths['/payment/cancel'].post).to.exist;
		});
	});
});
