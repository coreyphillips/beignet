/**
 * Liquidity ads (bLIP-0051) buyer side, public API: LightningNode.openChannelV2
 * threads requestFunds/maxLeaseRates into the dual-funding session so the
 * request_funds TLV goes out on open_channel2. All downstream verification
 * (will_fund sig, funded >= requested, the maxLeaseRates fee ceiling, lease
 * expiry) is covered by liquidity-ads-negotiation.test.ts — this file gates
 * the previously-unreachable API entry point.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { decodeOpenChannel2Message } from '../../src/lightning/message/dual-funding';
import { ILeaseRates } from '../../src/lightning/gossip/types';

const RATES: ILeaseRates = {
	fundingWeightWitness: 1000,
	leaseFeeBasis: 100,
	leaseFeeBaseSat: 500,
	channelFeeMaxBaseMsat: 1_000,
	channelFeeMaxProportionalThousandths: 10
};

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`lease-buyer-api-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		keys.push(
			crypto
				.createHash('sha256')
				.update(seed)
				.update(Buffer.from([i]))
				.digest()
		);
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

function makeNode(seedId: number): LightningNode {
	const seed = makeSeed(seedId);
	const config: INodeConfig = {
		nodePrivateKey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from('node-identity'))
			.digest(),
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(seed)
			.update(Buffer.from([0]))
			.digest()
	};
	const node = new LightningNode(config);
	node.on('node:error', () => {});
	node.getChannelManager().on('error', () => {});
	return node;
}

const PEER = getPublicKey(makeSeed(99)).toString('hex');

describe('Liquidity ads buyer API (openChannelV2)', function () {
	let node: LightningNode;

	afterEach(function () {
		if (node) node.destroy();
	});

	it('threads requestFunds into the open_channel2 request_funds TLV', function () {
		node = makeNode(1);
		const sent: Array<{ type: number; payload: Buffer }> = [];
		node
			.getChannelManager()
			.on('message:outbound', (_peer: string, type: number, payload: Buffer) =>
				sent.push({ type, payload })
			);

		node.openChannelV2(PEER, {
			fundingSatoshis: 200_000n,
			requestFunds: { requestedSats: 500_000n, blockheight: 800_000 },
			maxLeaseRates: RATES
		});

		const open = sent.find((m) => m.type === MessageType.OPEN_CHANNEL2);
		expect(open, 'open_channel2 sent').to.exist;
		const decoded = decodeOpenChannel2Message(open!.payload);
		expect(decoded.requestFunds, 'request_funds TLV present').to.exist;
		expect(decoded.requestFunds!.requestedSats).to.equal(500_000n);
		expect(decoded.requestFunds!.blockheight).to.equal(800_000);
	});

	it('stores maxLeaseRates as the local fee ceiling on the session', function () {
		node = makeNode(2);
		const channel = node.openChannelV2(PEER, {
			fundingSatoshis: 200_000n,
			requestFunds: { requestedSats: 500_000n, blockheight: 800_000 },
			maxLeaseRates: RATES
		});
		// The ceiling is local-only (never on the wire); handleAcceptChannel2
		// reads it from the session's local params.
		const session = channel.getDualFundingSession();
		expect(session, 'dual-funding session').to.not.be.null;
		expect(session!.getLocalParams()?.maxLeaseRates).to.deep.equal(RATES);
	});

	it('rejects requestFunds without maxLeaseRates at the API boundary', function () {
		node = makeNode(3);
		expect(() =>
			node.openChannelV2(PEER, {
				fundingSatoshis: 200_000n,
				requestFunds: { requestedSats: 500_000n, blockheight: 800_000 }
			})
		).to.throw(/maxLeaseRates/);
	});

	it('plain openChannelV2 (no lease) sends no request_funds TLV', function () {
		node = makeNode(4);
		const sent: Array<{ type: number; payload: Buffer }> = [];
		node
			.getChannelManager()
			.on('message:outbound', (_peer: string, type: number, payload: Buffer) =>
				sent.push({ type, payload })
			);

		node.openChannelV2(PEER, { fundingSatoshis: 200_000n });

		const open = sent.find((m) => m.type === MessageType.OPEN_CHANNEL2);
		expect(open).to.exist;
		const decoded = decodeOpenChannel2Message(open!.payload);
		expect(decoded.requestFunds).to.equal(undefined);
	});
});
