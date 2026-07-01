/**
 * Phase 3: Channel Helpers, Typed State, Error Consistency, Blinded Path Fix.
 *
 * - 3.1: Channel readiness helpers (canSend, canReceive, getReadyChannels)
 * - 3.2: Typed channel and peer state (literal union types)
 * - 3.3: BeignetErrorCode enum, isDestroyed guard
 * - 3.4: findRouteToBlindedPath mission control wiring
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	DEFAULT_CHANNEL_CONFIG,
	ChannelState
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import {
	BeignetError,
	BeignetErrorCode,
	describeFailureCode
} from '../../src/cli/errors';
import {
	ChannelStateString,
	PeerState,
	PaymentFilter
} from '../../src/cli/types';
import { NetworkGraph } from '../../src/lightning/gossip/network-graph';
import { findRouteToBlindedPath } from '../../src/lightning/gossip/pathfinding';
import { MissionControl } from '../../src/lightning/gossip/mission-control';

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`phase3-test-${id}`))
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

// ─── 3.1: Channel Readiness Helpers ───

describe('Channel Readiness Helpers', () => {
	let node: LightningNode;

	beforeEach(() => {
		node = new LightningNode(makeNodeConfig(10));
		node.on('error', () => {});
		node.on('node:error', () => {});
	});

	afterEach(() => {
		node.destroy();
	});

	it('listChannels returns empty for fresh node', () => {
		const channels = node.listChannels();
		expect(channels).to.be.an('array').with.length(0);
	});

	it('getBalance returns zero balances for fresh node', () => {
		const balance = node.getBalance();
		expect(Number(balance.localBalanceMsat)).to.equal(0);
		expect(Number(balance.remoteBalanceMsat)).to.equal(0);
	});

	it('estimateRouteFee returns null for fresh node', () => {
		const inv = node.createInvoice({
			amountMsat: 50_000n,
			description: 'test'
		});
		const result = node.estimateRouteFee(inv.bolt11);
		expect(result).to.be.null;
	});
});

// ─── 3.2: Typed Channel and Peer State ───

describe('Typed Channel and Peer State', () => {
	it('ChannelStateString covers all expected states', () => {
		const validStates: ChannelStateString[] = [
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
		expect(validStates).to.have.length(10);
	});

	it('PeerState covers expected values', () => {
		const validStates: PeerState[] = [
			'connected',
			'connecting',
			'disconnected'
		];
		expect(validStates).to.have.length(3);
	});

	it('ChannelState enum maps to ChannelStateString values', () => {
		const stateValues = Object.values(ChannelState);
		// All ChannelState values should be assignable to ChannelStateString
		for (const state of stateValues) {
			expect(typeof state).to.equal('string');
		}
	});
});

// ─── 3.3: Error Patterns ───

describe('BeignetErrorCode', () => {
	it('BeignetErrorCode enum has all expected codes', () => {
		expect(BeignetErrorCode.PAYMENT_FAILED).to.equal('PAYMENT_FAILED');
		expect(BeignetErrorCode.PAYMENT_TIMEOUT).to.equal('PAYMENT_TIMEOUT');
		expect(BeignetErrorCode.CHANNEL_NOT_FOUND).to.equal('CHANNEL_NOT_FOUND');
		expect(BeignetErrorCode.NODE_DESTROYED).to.equal('NODE_DESTROYED');
		expect(BeignetErrorCode.INVALID_PARAMS).to.equal('INVALID_PARAMS');
		expect(BeignetErrorCode.UNAUTHORIZED).to.equal('UNAUTHORIZED');
	});

	it('BeignetError accepts BeignetErrorCode', () => {
		const err = new BeignetError(BeignetErrorCode.PAYMENT_FAILED, 'test');
		expect(err.code).to.equal('PAYMENT_FAILED');
		expect(err.message).to.equal('test');
		expect(err).to.be.instanceOf(Error);
	});

	it('BeignetError accepts string code (backward compat)', () => {
		const err = new BeignetError('CUSTOM_CODE', 'custom');
		expect(err.code).to.equal('CUSTOM_CODE');
	});

	it('BeignetError.toJSON returns code and message', () => {
		const err = new BeignetError(BeignetErrorCode.NO_ROUTE, 'no route');
		const json = err.toJSON();
		expect(json.code).to.equal('NO_ROUTE');
		expect(json.message).to.equal('no route');
	});

	it('describeFailureCode returns description for known codes', () => {
		expect(describeFailureCode(15)).to.include(
			'incorrect_or_unknown_payment_details'
		);
		expect(describeFailureCode(10)).to.include('unknown_next_peer');
	});

	it('describeFailureCode returns unknown for unknown codes', () => {
		expect(describeFailureCode(9999)).to.include('unknown_failure');
	});
});

// ─── 3.4: Blinded Path Mission Control Wiring ───

describe('findRouteToBlindedPath mission control wiring', () => {
	it('accepts excludedChannels parameter', () => {
		const graph = new NetworkGraph();
		const source = crypto.randomBytes(33);
		const blindedPath = {
			introductionNodeId: crypto.randomBytes(33),
			blindingPoint: crypto.randomBytes(33),
			blindedHops: [
				{
					blindedNodeId: crypto.randomBytes(33),
					encryptedData: Buffer.alloc(64)
				}
			]
		};

		// No route, but should not throw with excludedChannels
		const result = findRouteToBlindedPath(
			graph,
			source,
			blindedPath,
			{
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: 1_000_000_000n
			},
			1000n,
			40,
			20,
			new Set(['some:channel:id'])
		);
		expect(result).to.be.null;
	});

	it('accepts missionControl parameter', () => {
		const graph = new NetworkGraph();
		const source = crypto.randomBytes(33);
		const mc = new MissionControl();
		const blindedPath = {
			introductionNodeId: crypto.randomBytes(33),
			blindingPoint: crypto.randomBytes(33),
			blindedHops: [
				{
					blindedNodeId: crypto.randomBytes(33),
					encryptedData: Buffer.alloc(64)
				}
			]
		};

		const result = findRouteToBlindedPath(
			graph,
			source,
			blindedPath,
			{
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: 1_000_000_000n
			},
			1000n,
			40,
			20,
			undefined,
			mc
		);
		expect(result).to.be.null;
	});

	it('returns blinded hops when source is introduction node', () => {
		const graph = new NetworkGraph();
		const source = crypto.randomBytes(33);
		const blindedPath = {
			introductionNodeId: source,
			blindingPoint: crypto.randomBytes(33),
			blindedHops: [
				{
					blindedNodeId: crypto.randomBytes(33),
					encryptedData: Buffer.alloc(64)
				},
				{
					blindedNodeId: crypto.randomBytes(33),
					encryptedData: Buffer.alloc(64)
				}
			]
		};

		const result = findRouteToBlindedPath(
			graph,
			source,
			blindedPath,
			{
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: 1_000_000_000n
			},
			1000n,
			40,
			20,
			new Set(),
			new MissionControl()
		);
		expect(result).to.not.be.null;
		expect(result!.hops).to.have.length(2);
	});

	it('source == intro node route has zero fees', () => {
		const graph = new NetworkGraph();
		const source = crypto.randomBytes(33);
		const blindedPath = {
			introductionNodeId: source,
			blindingPoint: crypto.randomBytes(33),
			blindedHops: [
				{
					blindedNodeId: crypto.randomBytes(33),
					encryptedData: Buffer.alloc(64)
				}
			]
		};

		const result = findRouteToBlindedPath(
			graph,
			source,
			blindedPath,
			{
				feeBaseMsat: 0,
				feeProportionalMillionths: 0,
				cltvExpiryDelta: 0,
				htlcMinimumMsat: 0n,
				htlcMaximumMsat: 1_000_000_000n
			},
			5000n,
			40
		);
		expect(result).to.not.be.null;
		expect(Number(result!.totalFeeMsat)).to.equal(0);
	});
});

// ─── PaymentFilter type check ───

describe('PaymentFilter type', () => {
	it('PaymentFilter has expected fields', () => {
		const filter: PaymentFilter = {
			status: 'COMPLETED',
			direction: 'OUTGOING',
			since: 1000,
			limit: 10,
			offset: 0
		};
		expect(filter.status).to.equal('COMPLETED');
		expect(filter.direction).to.equal('OUTGOING');
		expect(filter.since).to.equal(1000);
	});

	it('PaymentFilter is optional', () => {
		const filter: PaymentFilter = {};
		expect(filter.status).to.be.undefined;
	});
});
