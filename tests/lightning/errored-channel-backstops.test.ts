/**
 * Issue #174: an ERRORED channel must keep its HTLC safety backstops.
 *
 * All four scanners used to skip any channel not in NORMAL, so the moment a
 * channel was failed (peer error, protocol violation) every on-chain backstop
 * disarmed: an inbound HTLC we hold the preimage for was never claimed before
 * the peer's timeout path, an offered HTLC was never reclaimed, a forwarded
 * HTLC was never resolved, and the channel itself sat ERRORED forever waiting
 * for a peer broadcast that may never come.
 *
 * ERRORED channels are admitted to the force-close branches only; off-chain
 * fulfill/fail stays NORMAL-only (BOLT 2 forbids updates on a failed channel),
 * and dataLossDetected channels stay fully excluded (broadcasting our provably
 * stale commitment would hand the peer the justice path).
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import {
	ChannelState,
	HtlcDirection,
	HtlcState,
	IHtlcEntry,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';

// ─── Helpers (model: forward-onchain-resolution.test.ts) ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`errored-backstop-seed-${id}`))
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

const HEIGHT = 800_000;

interface IErroredFixture {
	alice: LightningNode;
	bob: LightningNode;
	channelId: Buffer;
	events: string[];
}

/** Alice with a ready channel to Bob, marked ERRORED, node:error codes captured. */
function setupErroredChannel(seedBase: number): IErroredFixture {
	const alice = createNode(seedBase);
	const bob = createNode(seedBase + 1);
	connectNodes(alice, bob);
	const channelId = openReadyChannel(alice, bob);
	(alice as any).currentBlockHeight = HEIGHT;

	const events: string[] = [];
	alice.on('node:error', (err: any) => events.push(err.code));

	const chan = (alice as any).channelManager.getChannel(channelId);
	expect(chan.markErrored()).to.equal(true);
	expect(chan.getFullState().state).to.equal(ChannelState.ERRORED);

	return { alice, bob, channelId, events };
}

function addHtlc(
	node: LightningNode,
	channelId: Buffer,
	key: string,
	htlc: Partial<IHtlcEntry> & { id: bigint; cltvExpiry: number }
): IHtlcEntry {
	const entry: IHtlcEntry = {
		amountMsat: 50_000n,
		paymentHash: crypto.randomBytes(32),
		onionRoutingPacket: Buffer.alloc(1366),
		direction: key.startsWith('received-')
			? HtlcDirection.RECEIVED
			: HtlcDirection.OFFERED,
		state: HtlcState.COMMITTED,
		...htlc
	} as IHtlcEntry;
	(node as any).channelManager
		.getChannel(channelId)
		.getFullState()
		.htlcs.set(key, entry);
	return entry;
}

describe('Issue #174: ERRORED channels keep their HTLC backstops', function () {
	this.timeout(10_000);

	describe('scanExpiringHtlcs', () => {
		it('force-closes to claim an inbound HTLC whose preimage we hold', () => {
			const fx = setupErroredChannel(41);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			(fx.alice as any).preimages.set(paymentHash.toString('hex'), preimage);
			// Inside the claim buffer (max(18, margin) blocks before expiry).
			addHtlc(fx.alice, fx.channelId, 'received-3', {
				id: 3n,
				paymentHash,
				cltvExpiry: HEIGHT + 10
			});

			(fx.alice as any).scanExpiringHtlcs(HEIGHT);

			expect(fx.events).to.include('HTLC_CLAIM_FORCE_CLOSE');
			fx.alice.destroy();
			fx.bob.destroy();
		});

		it('never fails an unclaimable inbound HTLC off-chain on a failed channel', () => {
			const fx = setupErroredChannel(43);
			// No preimage known: on a NORMAL channel this would update_fail_htlc
			// inside the safety margin. A failed channel cannot carry updates.
			addHtlc(fx.alice, fx.channelId, 'received-4', {
				id: 4n,
				cltvExpiry: HEIGHT + 2
			});
			const failHtlcCalls: bigint[] = [];
			const mgr = (fx.alice as any).channelManager;
			const realFail = mgr.failHtlc.bind(mgr);
			mgr.failHtlc = (channelId: Buffer, htlcId: bigint, reason: Buffer) => {
				failHtlcCalls.push(htlcId);
				return realFail(channelId, htlcId, reason);
			};

			(fx.alice as any).scanExpiringHtlcs(HEIGHT);

			expect(failHtlcCalls).to.have.length(0);
			expect(fx.events).to.not.include('HTLC_CLAIM_FORCE_CLOSE');
			fx.alice.destroy();
			fx.bob.destroy();
		});

		it('stays away from a channel with detected data loss', () => {
			const fx = setupErroredChannel(45);
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			(fx.alice as any).preimages.set(paymentHash.toString('hex'), preimage);
			addHtlc(fx.alice, fx.channelId, 'received-5', {
				id: 5n,
				paymentHash,
				cltvExpiry: HEIGHT + 10
			});
			(fx.alice as any).channelManager
				.getChannel(fx.channelId)
				.getFullState().dataLossDetected = true;

			(fx.alice as any).scanExpiringHtlcs(HEIGHT);

			expect(fx.events).to.not.include('HTLC_CLAIM_FORCE_CLOSE');
			fx.alice.destroy();
			fx.bob.destroy();
		});
	});

	describe('scanForwardTimeouts', () => {
		function setupForward(seedBase: number): IErroredFixture & {
			outChannelId: Buffer;
		} {
			const fx = setupErroredChannel(seedBase);
			const carol = createNode(seedBase + 2);
			connectNodes(fx.alice, carol);
			const outChannelId = openReadyChannel(fx.alice, carol);
			const paymentHash = crypto.randomBytes(32);
			// Inbound leg on the ERRORED Bob channel, inside the double margin.
			addHtlc(fx.alice, fx.channelId, 'received-7', {
				id: 7n,
				paymentHash,
				cltvExpiry: HEIGHT + 8
			});
			// Outbound leg to Carol, still in flight.
			addHtlc(fx.alice, outChannelId, 'offered-7', {
				id: 7n,
				paymentHash,
				amountMsat: 49_000n,
				cltvExpiry: HEIGHT - 40
			});
			(fx.alice as any).forwardedHtlcs.set(
				`${outChannelId.toString('hex')}:offered-7`,
				{ inChannelId: fx.channelId, inHtlcId: 7n }
			);
			return { ...fx, outChannelId };
		}

		it('force-closes the errored inbound channel when the outbound leg is unresolved', () => {
			const fx = setupForward(47);

			(fx.alice as any).scanForwardTimeouts(HEIGHT);

			expect(fx.events).to.include('FORWARD_TIMEOUT_FORCE_CLOSE');
			fx.alice.destroy();
			fx.bob.destroy();
		});

		it('takes the force-close path even when the outbound leg failed cleanly', () => {
			const fx = setupForward(50);
			const outChan = (fx.alice as any).channelManager.getChannel(
				fx.outChannelId
			);
			outChan.getFullState().htlcs.get('offered-7')!.state = HtlcState.FAILED;
			const failHtlcCalls: bigint[] = [];
			const mgr = (fx.alice as any).channelManager;
			const realFail = mgr.failHtlc.bind(mgr);
			mgr.failHtlc = (channelId: Buffer, htlcId: bigint, reason: Buffer) => {
				failHtlcCalls.push(htlcId);
				return realFail(channelId, htlcId, reason);
			};

			(fx.alice as any).scanForwardTimeouts(HEIGHT);

			// The upstream refund cannot travel over a failed channel, so no
			// update_fail_htlc: resolution moves on-chain instead.
			expect(failHtlcCalls).to.have.length(0);
			expect(fx.events).to.include('FORWARD_TIMEOUT_FORCE_CLOSE');
			fx.alice.destroy();
			fx.bob.destroy();
		});
	});

	describe('scanExpiringOfferedHtlcs', () => {
		it('force-closes at expiry with no grace on a failed channel', () => {
			const fx = setupErroredChannel(53);
			addHtlc(fx.alice, fx.channelId, 'offered-9', {
				id: 9n,
				cltvExpiry: HEIGHT
			});

			(fx.alice as any).scanExpiringOfferedHtlcs(HEIGHT);

			expect(fx.events).to.include('HTLC_EXPIRY_FORCE_CLOSE');
			fx.alice.destroy();
			fx.bob.destroy();
		});

		it('keeps the off-chain grace period on an operational channel', () => {
			const alice = createNode(55);
			const bob = createNode(56);
			connectNodes(alice, bob);
			const channelId = openReadyChannel(alice, bob);
			(alice as any).currentBlockHeight = HEIGHT;
			const events: string[] = [];
			alice.on('node:error', (err: any) => events.push(err.code));
			addHtlc(alice, channelId, 'offered-9', {
				id: 9n,
				cltvExpiry: HEIGHT
			});

			(alice as any).scanExpiringOfferedHtlcs(HEIGHT);

			expect(events).to.not.include('HTLC_EXPIRY_FORCE_CLOSE');
			alice.destroy();
			bob.destroy();
		});
	});

	describe('scanStuckChannels', () => {
		it('force-closes a funded channel stuck in ERRORED past the reestablish timeout', () => {
			const fx = setupErroredChannel(57);
			const timeout = (fx.alice as any).reestablishTimeoutBlocks;

			(fx.alice as any).scanStuckChannels(HEIGHT);
			expect(fx.events).to.not.include('ERRORED_TIMEOUT_FORCE_CLOSED');

			(fx.alice as any).scanStuckChannels(HEIGHT + timeout + 1);

			expect(fx.events).to.include('ERRORED_TIMEOUT_FORCE_CLOSED');
			const chan = (fx.alice as any).channelManager.getChannel(fx.channelId);
			expect(chan.getFullState().state).to.equal(ChannelState.FORCE_CLOSED);
			fx.alice.destroy();
			fx.bob.destroy();
		});

		it('leaves an errored channel alone before the timeout elapses', () => {
			const fx = setupErroredChannel(59);
			const timeout = (fx.alice as any).reestablishTimeoutBlocks;

			(fx.alice as any).scanStuckChannels(HEIGHT);
			(fx.alice as any).scanStuckChannels(HEIGHT + timeout - 1);

			expect(fx.events).to.not.include('ERRORED_TIMEOUT_FORCE_CLOSED');
			fx.alice.destroy();
			fx.bob.destroy();
		});

		it('skips an errored channel whose funding never reached the chain', () => {
			const fx = setupErroredChannel(61);
			const timeout = (fx.alice as any).reestablishTimeoutBlocks;
			(fx.alice as any).channelManager
				.getChannel(fx.channelId)
				.getFullState().fundingTxid = null;

			(fx.alice as any).scanStuckChannels(HEIGHT);
			(fx.alice as any).scanStuckChannels(HEIGHT + timeout + 1);

			expect(fx.events).to.not.include('ERRORED_TIMEOUT_FORCE_CLOSED');
			fx.alice.destroy();
			fx.bob.destroy();
		});
	});
});
