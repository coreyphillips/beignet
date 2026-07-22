/**
 * Issue #175: a BOLT 1 error must FAIL the channel, not merely remember it.
 *
 * markErrored used to flip state to ERRORED and stop: no force-close, and a
 * later channel_reestablish was answered with "unknown or closed channel".
 * Both sides could then wait forever for the other to broadcast (LND reaches
 * ErrRecoveryError with FailureAction none and its docs say the REMOTE party
 * must close). Now every path that fails a channel by wire error drives our
 * own commitment on chain, except when data loss was detected, where
 * broadcasting a provably stale commitment would hand the peer the justice
 * path.
 */

import { expect } from 'chai';
import crypto from 'crypto';
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
import {
	decodeErrorMessage,
	encodeErrorMessage
} from '../../src/lightning/message/error';

// ─── Helpers (model: errored-channel-backstops.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`error-forecloses-seed-${id}`))
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

interface IFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	events: string[];
	aliceState: () => ChannelState;
}

function setup(seedBase: number): IFixture {
	const alice = createNode(seedBase);
	const bob = createNode(seedBase + 1);
	connectNodes(alice, bob);
	const channelId = openReadyChannel(alice, bob);
	const events: string[] = [];
	alice.on('node:error', (err: any) => events.push(err.code));
	return {
		alice,
		bob,
		channelId,
		events,
		aliceState: () =>
			(alice as any).channelManager.getChannel(channelId).getFullState().state
	};
}

function sendErrorToAlice(fx: IFixture, channelId: Buffer): void {
	fx.alice.handlePeerMessage(
		fx.bob.getNodeId(),
		MessageType.ERROR,
		encodeErrorMessage({
			channelId,
			data: Buffer.from('internal error', 'utf8')
		})
	);
}

describe('Issue #175: a BOLT 1 error fails the channel on chain', function () {
	this.timeout(10_000);

	it('force-closes a funded channel when the peer errors it', () => {
		const fx = setup(71);

		sendErrorToAlice(fx, fx.channelId);

		expect(fx.aliceState()).to.equal(ChannelState.FORCE_CLOSED);
		expect(fx.events).to.include('CHANNEL_FAILED_FORCE_CLOSED');
		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('never broadcasts when data loss was detected', () => {
		const fx = setup(73);
		(fx.alice as any).channelManager
			.getChannel(fx.channelId)
			.getFullState().dataLossDetected = true;

		sendErrorToAlice(fx, fx.channelId);

		// ERRORED, not FORCE_CLOSED: our commitment is provably stale, so the
		// only safe resolution is the peer's broadcast.
		expect(fx.aliceState()).to.equal(ChannelState.ERRORED);
		expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSED');
		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('leaves every channel alone on a connection-wide error', () => {
		const fx = setup(75);

		sendErrorToAlice(fx, Buffer.alloc(32));

		expect(fx.aliceState()).to.equal(ChannelState.NORMAL);
		expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSED');
		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('closes a pre-existing ERRORED channel when the peer reestablishes it', () => {
		const fx = setup(77);
		const chan = (fx.alice as any).channelManager.getChannel(fx.channelId);
		// A channel errored before force-close-on-error existed: failed, nothing
		// on chain, and the peer clearly has not closed either since it is
		// reestablishing.
		expect(chan.markErrored()).to.equal(true);

		const replies: string[] = [];
		fx.alice.on(
			'message:outbound',
			(_pubkey: string, type: number, payload: Buffer) => {
				if (type === MessageType.ERROR) {
					replies.push(decodeErrorMessage(payload).data.toString('utf8'));
				}
			}
		);

		// Bob still thinks the channel is live and reestablishes on reconnect.
		const bobChan = (fx.bob as any).channelManager.getChannel(fx.channelId);
		bobChan.markForReestablish();
		(fx.bob as any).channelManager.processActions(
			fx.alice.getNodeId(),
			bobChan,
			bobChan.createReestablish()
		);

		expect(fx.aliceState()).to.equal(ChannelState.FORCE_CLOSED);
		expect(fx.events).to.include('CHANNEL_FAILED_FORCE_CLOSED');
		// The reply names the real condition instead of "unknown or closed
		// channel": it is often the only diagnostic the peer's operator sees.
		expect(replies).to.include('channel failed; closing on chain');
		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('fails the channel on chain when WE send the wire error', () => {
		const fx = setup(79);
		const chan = (fx.alice as any).channelManager.getChannel(fx.channelId);

		// The peer-violation path: _failChannelWithWireError returns the error
		// send + persist actions and leaves the channel ERRORED; processActions
		// must drive the close, since BOLT 1 binds the sender of an error too.
		const actions = (chan as any)._failChannelWithWireError('bad signature');
		(fx.alice as any).channelManager.processActions(
			fx.bob.getNodeId(),
			chan,
			actions
		);

		expect(fx.aliceState()).to.equal(ChannelState.FORCE_CLOSED);
		expect(fx.events).to.include('CHANNEL_FAILED_FORCE_CLOSED');
		fx.alice.destroy();
		fx.bob.destroy();
	});

	it('leaves a channel with no funding on chain in ERRORED', () => {
		const fx = setup(81);
		(fx.alice as any).channelManager
			.getChannel(fx.channelId)
			.getFullState().fundingTxid = null;

		sendErrorToAlice(fx, fx.channelId);

		expect(fx.aliceState()).to.equal(ChannelState.ERRORED);
		expect(fx.events).to.not.include('CHANNEL_FAILED_FORCE_CLOSED');
		fx.alice.destroy();
		fx.bob.destroy();
	});
});
