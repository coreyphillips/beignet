/**
 * Issue #176: a node must be able to decline being a routing hop, and forwards
 * must leave a trace in the log.
 *
 * beignet relayed HTLCs for third parties unconditionally: handleForwardHtlc
 * declined only for route-intrinsic reasons (unknown SCID, fee/CLTV shortfall).
 * A wallet had no supported way to opt out. forwardingEnabled: false now
 * declines every forward up front with temporary_channel_failure, before any
 * onward lookup. A forward attempt and its resolution are also logged, so a
 * relay is as visible as a payment.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { encodeShortChannelId } from '../../src/lightning/gossip/types';
import {
	ROUTING_INFO_LENGTH,
	TEMPORARY_CHANNEL_FAILURE
} from '../../src/lightning/onion/types';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { IStructuredLog } from '../../src/lightning/node/types';

function makeBasepoints(): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) keys.push(crypto.randomBytes(32));
	return {
		fundingPubkey: getPublicKey(keys[0]),
		revocationBasepoint: getPublicKey(keys[1]),
		paymentBasepoint: getPublicKey(keys[2]),
		delayedPaymentBasepoint: getPublicKey(keys[3]),
		htlcBasepoint: getPublicKey(keys[4]),
		firstPerCommitmentPoint: Buffer.alloc(33)
	};
}

function makeNode(forwardingEnabled?: boolean): LightningNode {
	return new LightningNode({
		nodePrivateKey: crypto.randomBytes(32),
		perCommitmentSeed: crypto.randomBytes(32),
		channelBasepoints: makeBasepoints(),
		fundingPrivkey: crypto.randomBytes(32),
		forwardingEnabled
	});
}

function plainChannelType(): Buffer {
	const flags = FeatureFlags.empty();
	flags.setCompulsory(Feature.STATIC_REMOTE_KEY);
	return flags.toBuffer();
}

/** A confirmed channel with a real SCID, installed and SCID-registered. */
function installChannel(node: LightningNode): {
	channelId: Buffer;
	realScid: Buffer;
} {
	const state = createOpenerState({
		temporaryChannelId: crypto.randomBytes(32),
		fundingSatoshis: 100_000n,
		pushMsat: 0n,
		localConfig: { ...DEFAULT_CHANNEL_CONFIG },
		localBasepoints: makeBasepoints(),
		localPerCommitmentSeed: crypto.randomBytes(32)
	});
	const channelId = crypto.randomBytes(32);
	const realScid = encodeShortChannelId({
		block: 900_000,
		txIndex: 42,
		outputIndex: 0
	});
	state.channelId = channelId;
	state.shortChannelId = realScid;
	state.scidAlias = crypto.randomBytes(8);
	state.announceChannel = true;
	state.channelType = plainChannelType();
	const channel = new Channel(state);
	(node as any).channelManager.restoreChannel(
		channel,
		crypto.randomBytes(33).toString('hex')
	);
	(node as any).registerChannelScids(channelId);
	return { channelId, realScid };
}

describe('Issue #176: forwarding opt-out and forward logging', function () {
	this.timeout(10_000);

	let node: LightningNode;
	let addHtlcCalls: number;
	let failHtlcCalls: Array<{ reason: Buffer }>;
	let logs: IStructuredLog[];
	let sharedSecret: Buffer;

	function wire(n: LightningNode): void {
		node = n;
		addHtlcCalls = 0;
		failHtlcCalls = [];
		logs = [];
		sharedSecret = crypto.randomBytes(32);
		const cm = (node as any).channelManager;
		cm.addHtlc = (): { ok: boolean } => {
			addHtlcCalls++;
			return { ok: true };
		};
		cm.failHtlc = (_c: Buffer, _id: bigint, reason: Buffer): void => {
			failHtlcCalls.push({ reason });
		};
		node.on('log', (l: IStructuredLog) => logs.push(l));
		node.on('error', () => {});
	}

	afterEach(function () {
		node.destroy();
	});

	function forward(outgoingScid: Buffer): void {
		(node as any).handleForwardHtlc(
			crypto.randomBytes(32),
			0n,
			crypto.randomBytes(32),
			{
				hopPayload: {
					amountToForwardMsat: 1_000_000n,
					outgoingCltvValue: 700_000,
					shortChannelId: outgoingScid
				},
				nextPacket: {
					version: 0,
					ephemeralKey: crypto.randomBytes(33),
					routingInfo: Buffer.alloc(ROUTING_INFO_LENGTH),
					hmac: crypto.randomBytes(32)
				},
				sharedSecret
			},
			1_100_000n,
			700_500
		);
	}

	function failureCode(): number | undefined {
		if (failHtlcCalls.length === 0) return undefined;
		return decryptFailureMessage([sharedSecret], failHtlcCalls[0].reason)
			?.failure.failureCode;
	}

	function logActions(): string[] {
		return logs.filter((l) => l.category === 'htlc').map((l) => l.action);
	}

	it('declines every forward with temporary_channel_failure when disabled', function () {
		wire(makeNode(false));
		const { realScid } = installChannel(node);

		forward(realScid);

		// Declined up front: no onward add, and the incoming HTLC is failed with
		// the well-defined temporary_channel_failure code.
		expect(addHtlcCalls).to.equal(0);
		expect(failureCode()).to.equal(TEMPORARY_CHANNEL_FAILURE);
		expect(logActions()).to.include('forward_declined');
		expect(logActions()).to.not.include('forward_attempt');
	});

	it('declines even when a valid outgoing channel exists', function () {
		// The decline must not depend on the route: a perfectly forwardable HTLC
		// is still refused, which is the whole point of the opt-out.
		wire(makeNode(false));
		const { realScid } = installChannel(node);

		forward(realScid);

		expect(addHtlcCalls).to.equal(0);
		expect(failureCode()).to.equal(TEMPORARY_CHANNEL_FAILURE);
	});

	it('forwards and logs the attempt when enabled (default)', function () {
		wire(makeNode()); // default: forwarding on
		const { realScid } = installChannel(node);

		forward(realScid);

		expect(failureCode(), 'a forwardable HTLC must not be declined').to.be
			.undefined;
		expect(addHtlcCalls).to.equal(1);
		expect(logActions()).to.include('forward_attempt');
		expect(logActions()).to.not.include('forward_declined');
	});

	it('explicit forwardingEnabled: true behaves like the default', function () {
		wire(makeNode(true));
		const { realScid } = installChannel(node);

		forward(realScid);

		expect(addHtlcCalls).to.equal(1);
		expect(failureCode()).to.be.undefined;
	});
});
