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
	TEMPORARY_NODE_FAILURE
} from '../../src/lightning/onion/types';
import { decryptFailureMessage } from '../../src/lightning/onion/failures';
import { FeatureFlags, Feature } from '../../src/lightning/features/flags';
import { IStructuredLog } from '../../src/lightning/node/types';
import { decodeChannelUpdateMessage } from '../../src/lightning/gossip/messages';

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

	it('declines every forward with temporary_node_failure when disabled', function () {
		wire(makeNode(false));
		const { realScid } = installChannel(node);

		forward(realScid);

		// Declined up front: no onward add, and the incoming HTLC is failed with
		// temporary_node_failure. This is a node-wide policy, not one channel
		// misbehaving, and unlike temporary_channel_failure it needs no
		// channel_update payload (BOLT 4) — a data-less temporary_channel_failure
		// would be a malformed onion failure.
		expect(addHtlcCalls).to.equal(0);
		expect(failureCode()).to.equal(TEMPORARY_NODE_FAILURE);
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
		expect(failureCode()).to.equal(TEMPORARY_NODE_FAILURE);
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

	describe('gossip disable bit (BOLT 7)', function () {
		const DISABLE = 0x02;

		it('sets the disable bit on our channel_update when forwarding is off', function () {
			wire(makeNode(false));
			const { channelId } = installChannel(node);

			const update = (node as any).buildDirectChannelUpdate(channelId);
			expect(update, 'built an update').to.not.equal(null);
			const decoded = decodeChannelUpdateMessage(update);
			expect(decoded.channelFlags & DISABLE).to.equal(DISABLE);
		});

		it('leaves the disable bit clear when forwarding is on', function () {
			wire(makeNode(true));
			const { channelId } = installChannel(node);

			const update = (node as any).buildDirectChannelUpdate(channelId);
			const decoded = decodeChannelUpdateMessage(update);
			expect(decoded.channelFlags & DISABLE).to.equal(0);
			// The direction bit and everything else are untouched.
			expect(decoded.channelFlags & ~DISABLE).to.equal(decoded.channelFlags);
		});

		it('refreshChannelUpdate stamps the disable bit while preserving direction', function () {
			// Build an enabled update (bit clear, direction bit set), then refresh
			// it through a disabled node: the disable bit is set and the direction
			// bit is preserved.
			wire(makeNode(true));
			const { channelId } = installChannel(node);
			const enabledUpdate = (node as any).buildDirectChannelUpdate(channelId);
			const direction =
				decodeChannelUpdateMessage(enabledUpdate).channelFlags & 0x01;
			node.destroy();

			wire(makeNode(false));
			const refreshed = (node as any).refreshChannelUpdate(
				enabledUpdate,
				Math.floor(Date.now() / 1000)
			);
			const decoded = decodeChannelUpdateMessage(refreshed);
			expect(decoded.channelFlags & DISABLE).to.equal(DISABLE);
			expect(decoded.channelFlags & 0x01).to.equal(direction);
		});

		it('refreshChannelUpdate clears a stale disable bit when forwarding is on', function () {
			wire(makeNode(false));
			const { channelId } = installChannel(node);
			const disabledUpdate = (node as any).buildDirectChannelUpdate(channelId);
			expect(
				decodeChannelUpdateMessage(disabledUpdate).channelFlags & DISABLE
			).to.equal(DISABLE);
			node.destroy();

			wire(makeNode(true));
			const refreshed = (node as any).refreshChannelUpdate(
				disabledUpdate,
				Math.floor(Date.now() / 1000)
			);
			expect(
				decodeChannelUpdateMessage(refreshed).channelFlags & DISABLE
			).to.equal(0);
		});
	});

	it('logs and emits when a forwarded HTLC fails downstream', function () {
		wire(makeNode());
		const inChannelId = crypto.randomBytes(32);
		const outChannelId = crypto.randomBytes(32);
		const outHtlcId = 4n;
		const outKey = `${outChannelId.toString('hex')}:offered-${outHtlcId}`;
		(node as any).forwardedHtlcs.set(outKey, { inChannelId, inHtlcId: 2n });
		(node as any).receivedHtlcSharedSecrets.set(
			`${inChannelId.toString('hex')}:2`,
			crypto.randomBytes(32)
		);
		let failedEvent = false;
		node.on('htlc:forward-failed', () => {
			failedEvent = true;
		});

		(node as any).handleHtlcFailed(
			outChannelId,
			outHtlcId,
			crypto.randomBytes(32)
		);

		expect(logActions()).to.include('forward_failed');
		expect(failedEvent).to.equal(true);
	});
});
