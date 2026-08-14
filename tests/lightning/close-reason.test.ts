/**
 * Issue #214: the reason WE closed a channel is persisted on channel state
 * (state.closeReason) instead of living only in a transient node:error
 * event, so a restarted daemon can still explain a FORCE_CLOSED row.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { MessageType } from '../../src/lightning/message/types';
import { encodeErrorMessage } from '../../src/lightning/message/error';
import { Channel } from '../../src/lightning/channel/channel';
import {
	serializeChannelState,
	deserializeChannelState
} from '../../src/lightning/storage/serialization';

// ─── Helpers (model: error-forecloses-channel.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`close-reason-seed-${id}`))
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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	return {
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
}

function createNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	return node;
}

function connectNodes(a: LightningNode, b: LightningNode): void {
	a.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === b.getNodeId())
			b.handlePeerMessage(a.getNodeId(), type, payload);
	});
	b.on('message:outbound', (pubkey: string, type: number, payload: Buffer) => {
		if (pubkey === a.getNodeId())
			a.handlePeerMessage(b.getNodeId(), type, payload);
	});
}

function openReadyChannel(alice: LightningNode, bob: LightningNode): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
	const fundingTxid = crypto.randomBytes(32);
	const channelId = alice.createFunding(
		channel,
		fundingTxid,
		0,
		crypto.randomBytes(64)
	)!;
	alice.handleFundingConfirmed(channelId);
	bob.handleFundingConfirmed(channelId);
	return channelId;
}

function destScript(node: LightningNode): Buffer {
	return bitcoin.payments.p2wpkh({
		pubkey: Buffer.from(node.getNodeId(), 'hex')
	}).output!;
}

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	channel: Channel;
}

function setup(seedBase: number): IFixture {
	const alice = createNode(seedBase);
	const bob = createNode(seedBase + 1);
	connectNodes(alice, bob);
	const channelId = openReadyChannel(alice, bob);
	const channel = (alice as any).channelManager.getChannel(channelId);
	return { alice, bob, channelId, channel };
}

describe('Issue #214: persisted close reason', function () {
	this.timeout(10_000);

	it('records on a live channel, refuses same-value rewrites, clears', () => {
		const fx = setup(11);

		expect(fx.channel.recordCloseReason('user')).to.equal(true);
		expect(fx.channel.getFullState().closeReason).to.equal('user');
		expect(fx.channel.recordCloseReason('user')).to.equal(false);
		// Pre-terminal relabel is allowed: a user coop close that times out
		// escalates to a force-close with the terminal reason.
		expect(fx.channel.recordCloseReason('STUCK_CHANNEL_FORCE_CLOSED')).to.equal(
			true
		);
		expect(fx.channel.getFullState().closeReason).to.equal(
			'STUCK_CHANNEL_FORCE_CLOSED'
		);
		fx.channel.clearCloseReason();
		expect(fx.channel.getFullState().closeReason).to.equal(undefined);

		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('the API force-close stamps user and the stamp is then write-once', () => {
		const fx = setup(21);

		const result = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);
		expect(result.ok).to.equal(true);
		const state = fx.channel.getFullState();
		expect(state.state).to.equal(ChannelState.FORCE_CLOSED);
		expect(state.closeReason).to.equal('user');
		// Terminal: a later automatic path must not relabel the close that
		// actually happened.
		expect(
			fx.channel.recordCloseReason('REESTABLISH_TIMEOUT_FORCE_CLOSED')
		).to.equal(false);
		expect(state.closeReason).to.equal('user');

		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('an automatic close stamps its node:error code durably', () => {
		const fx = setup(31);

		fx.alice.handlePeerMessage(
			fx.bob.getNodeId(),
			MessageType.ERROR,
			encodeErrorMessage({
				channelId: fx.channelId,
				data: Buffer.from('internal error', 'utf8')
			})
		);

		const state = fx.channel.getFullState();
		expect(state.state).to.equal(ChannelState.FORCE_CLOSED);
		expect(state.closeReason).to.equal('CHANNEL_FAILED_FORCE_CLOSED');

		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('a refused force-close leaves no stale stamp', () => {
		const fx = setup(41);
		fx.channel.getFullState().dataLossDetected = true;

		const result = fx.alice.forceCloseChannel(
			fx.channelId,
			destScript(fx.alice)
		);

		expect(result.ok).to.equal(false);
		expect(fx.channel.getFullState().closeReason).to.equal(undefined);

		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('round-trips the serializer and tolerates rows without the field', () => {
		const fx = setup(51);
		fx.alice.forceCloseChannel(fx.channelId, destScript(fx.alice));
		const state = fx.channel.getFullState();
		expect(state.closeReason).to.equal('user');

		const serialized = serializeChannelState(state);
		const jsonRow = JSON.parse(JSON.stringify(serialized));
		expect(deserializeChannelState(jsonRow).closeReason).to.equal('user');

		// A pre-#214 row has no closeReason: it must deserialize as undefined,
		// not throw.
		delete jsonRow.closeReason;
		expect(deserializeChannelState(jsonRow).closeReason).to.equal(undefined);

		fx.alice.destroy();
		fx.bob.destroy();
	});
});
