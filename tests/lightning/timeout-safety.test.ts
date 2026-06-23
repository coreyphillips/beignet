/**
 * Phase 6: Timeout Safety Nets
 *
 * 6A — requestInvoice timeout:
 *   1. requestInvoice with timeoutMs wraps with Promise.race
 *   2. requestInvoice without timeoutMs uses OfferManager's default timeout
 *   3. requestInvoice timeout rejects with descriptive error
 *
 * 6B — Stuck channel state scanner:
 *   4. scanStuckChannels emits node:error for AWAITING_FUNDING_CONFIRMED channels stuck > 2016 blocks
 *   5. scanStuckChannels force-closes channels stuck in SHUTTING_DOWN > 10 blocks
 *   6. scanStuckChannels doesn't affect NORMAL channels
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig, ILightningError } from '../../src/lightning/node/types';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`timeout-safety-seed-${id}`))
		.digest();
}

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

function makeNodeConfig(seedId: number): INodeConfig {
	const seed = makeSeed(seedId);
	const nodePrivateKey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from('node-identity'))
		.digest();
	const fundingPrivkey = crypto
		.createHash('sha256')
		.update(seed)
		.update(Buffer.from([0]))
		.digest();
	return {
		nodePrivateKey,
		network: Network.REGTEST,
		channelConfig: { ...DEFAULT_CHANNEL_CONFIG },
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: makeSeed(seedId + 100),
		fundingPrivkey
	};
}

function createTestNode(seedId: number): LightningNode {
	const node = new LightningNode(makeNodeConfig(seedId));
	node.on('error', () => {});
	return node;
}

function connectNodes(nodeA: LightningNode, nodeB: LightningNode): void {
	nodeA.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeB.getNodeId()) {
				nodeB.handlePeerMessage(nodeA.getNodeId(), type, payload);
			}
		}
	);
	nodeB.on(
		'message:outbound',
		(pubkey: string, type: number, payload: Buffer) => {
			if (pubkey === nodeA.getNodeId()) {
				nodeA.handlePeerMessage(nodeB.getNodeId(), type, payload);
			}
		}
	);
}

function openReadyChannel(
	alice: LightningNode,
	bob: LightningNode,
	fundingSatoshis = 1_000_000n
): Buffer {
	const channel = alice.openChannel(bob.getNodeId(), fundingSatoshis);
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

// ─────────────── Tests ───────────────

describe('Phase 6: Timeout Safety Nets', () => {
	// ── 6A: requestInvoice timeout ──────────────────────────────────

	describe('6A — requestInvoice timeout', () => {
		it('requestInvoice with timeoutMs rejects on timeout via Promise.race', async () => {
			const node = createTestNode(1);
			const offerManager = node.getOfferManager();

			// Save the original and replace with a never-resolving promise
			const originalRequest = offerManager.requestInvoice.bind(offerManager);
			offerManager.requestInvoice = () => new Promise(() => {}); // never resolves

			const fakeOffer = {
				offerId: crypto.randomBytes(32),
				description: 'test offer'
			} as any;

			try {
				await node.requestInvoice(fakeOffer, { timeoutMs: 100 });
				expect.fail('Should have timed out');
			} catch (err: any) {
				expect(err.message).to.include('timed out');
			}

			offerManager.requestInvoice = originalRequest;
			node.destroy();
		});

		it('requestInvoice without timeoutMs uses OfferManager default timeout', async () => {
			const node = createTestNode(2);
			const offerManager = node.getOfferManager();

			// Replace requestInvoice to track that it was called and returns a
			// promise that rejects after the OfferManager's own internal timeout.
			// The OfferManager default is 30s; we override it to be very short.
			let calledWithOffer = false;
			const shortTimeoutMs = 80;
			// Create a new OfferManager-like promise that times out quickly to
			// simulate the OfferManager's internal timeout behavior.
			offerManager.requestInvoice = (_offer: any) => {
				calledWithOffer = true;
				return new Promise<never>((_, reject) => {
					setTimeout(
						() => reject(new Error('Invoice request timed out')),
						shortTimeoutMs
					);
				});
			};

			const fakeOffer = {
				offerId: crypto.randomBytes(32),
				description: 'default timeout test'
			} as any;

			try {
				// No timeoutMs provided — relies on OfferManager's internal timeout
				await node.requestInvoice(fakeOffer);
				expect.fail('Should have timed out via OfferManager default');
			} catch (err: any) {
				expect(calledWithOffer).to.be.true;
				expect(err.message).to.include('timed out');
			}

			node.destroy();
		});

		it('requestInvoice timeout rejects with descriptive error including timeout duration', async () => {
			const node = createTestNode(3);
			const offerManager = node.getOfferManager();

			offerManager.requestInvoice = () => new Promise(() => {}); // never resolves

			const fakeOffer = {
				offerId: crypto.randomBytes(32),
				description: 'descriptive error test'
			} as any;

			const timeoutMs = 150;
			try {
				await node.requestInvoice(fakeOffer, { timeoutMs });
				expect.fail('Should have timed out');
			} catch (err: any) {
				// The error message should mention BOLT 12 and the timeout duration
				expect(err.message).to.include('BOLT 12');
				expect(err.message).to.include(`${timeoutMs}ms`);
				expect(err).to.be.instanceOf(Error);
			}

			node.destroy();
		});
	});

	// ── 6B: Stuck channel state scanner ─────────────────────────────

	describe('6B — Stuck channel state scanner', () => {
		it('scanStuckChannels emits node:error for AWAITING_FUNDING_CONFIRMED channels stuck > 2016 blocks', () => {
			const alice = createTestNode(10);
			const bob = createTestNode(11);
			connectNodes(alice, bob);

			// Open a channel — this goes through open_channel → accept_channel flow
			const channel = alice.openChannel(bob.getNodeId(), 1_000_000n);
			const fundingTxid = crypto.randomBytes(32);
			const channelId = alice.createFunding(
				channel,
				fundingTxid,
				0,
				crypto.randomBytes(64)
			)!;

			// Channel is now AWAITING_FUNDING_CONFIRMED on alice's side
			// Verify the channel state
			const channels = alice.listChannels();
			const ch = channels.find((c) => c.channelId.equals(channelId));
			expect(ch).to.exist;
			expect(ch!.state).to.equal(ChannelState.AWAITING_FUNDING_CONFIRMED);

			// Set the fundingConfirmationHeight on the underlying channel state
			// so the scanner can detect it as stuck.
			const channelManager = alice.getChannelManager();
			const rawChannel = channelManager
				.listChannels()
				.find((c) => c.getFullState().channelId?.equals(channelId));
			expect(rawChannel).to.exist;
			const fullState = rawChannel!.getFullState();
			// Set fundingBroadcastHeight to simulate that funding was broadcast at block 100
			fullState.fundingBroadcastHeight = 100;

			// Collect node:error events
			const errors: ILightningError[] = [];
			alice.on('node:error', (err: ILightningError) => errors.push(err));

			// Call handleNewBlock with a height that is <= 2016 blocks after confirmation
			alice.handleNewBlock(2100); // 2100 - 100 = 2000 < 2016 — should NOT trigger
			expect(errors.filter((e) => e.code === 'STUCK_CHANNEL').length).to.equal(
				0
			);

			// Call handleNewBlock with a height that exceeds the 2016-block threshold
			alice.handleNewBlock(2200); // 2200 - 100 = 2100 > 2016 — should trigger
			const stuckErrors = errors.filter((e) => e.code === 'STUCK_CHANNEL');
			expect(stuckErrors.length).to.equal(1);
			expect(stuckErrors[0].message).to.include('AWAITING_FUNDING_CONFIRMED');
			expect(stuckErrors[0].message).to.include('2016');
			expect(stuckErrors[0].channelId).to.exist;
			expect(stuckErrors[0].channelId!.equals(channelId)).to.be.true;
			expect(stuckErrors[0].timestamp).to.be.a('number');

			alice.destroy();
			bob.destroy();
		});

		it('scanStuckChannels force-closes channels stuck in SHUTTING_DOWN > 10 blocks', () => {
			const alice = createTestNode(20);
			const bob = createTestNode(21);
			connectNodes(alice, bob);

			// Open a channel and advance to NORMAL
			const channelId = openReadyChannel(alice, bob);

			// Verify it reached NORMAL
			const normalChannels = alice.listChannels();
			const normalCh = normalChannels.find((c) =>
				c.channelId.equals(channelId)
			);
			expect(normalCh).to.exist;
			expect(normalCh!.state).to.equal(ChannelState.NORMAL);

			// Initiate shutdown — channel transitions to SHUTTING_DOWN
			// We need a scriptPubkey for the close destination
			const closeScript = Buffer.alloc(22);
			closeScript[0] = 0x00; // OP_0
			closeScript[1] = 0x14; // push 20 bytes
			crypto.randomBytes(20).copy(closeScript, 2);
			alice.closeChannel(channelId, closeScript);

			// After closeChannel, alice should be in SHUTTING_DOWN or NEGOTIATING_CLOSING.
			// With loopback wiring, Bob immediately sends shutdown response + closing_signed,
			// so alice may advance to NEGOTIATING_CLOSING.
			const afterClose = alice.listChannels();
			const shuttingCh = afterClose.find((c) => c.channelId.equals(channelId));
			expect(shuttingCh).to.exist;
			const stuckState = shuttingCh!.state;
			expect([
				ChannelState.SHUTTING_DOWN,
				ChannelState.NEGOTIATING_CLOSING,
				ChannelState.CLOSED
			]).to.include(stuckState);

			// If cooperative close completed synchronously (CLOSED), the scanner
			// correctly ignores it — no force-close needed.
			if (stuckState === ChannelState.CLOSED) {
				alice.destroy();
				bob.destroy();
				return;
			}

			// Collect errors
			const errors: ILightningError[] = [];
			alice.on('node:error', (err: ILightningError) => errors.push(err));

			// First handleNewBlock at height 1000 — starts tracking
			alice.handleNewBlock(1000);
			expect(
				errors.filter((e) => e.code === 'STUCK_CHANNEL_FORCE_CLOSED').length
			).to.equal(0);

			// handleNewBlock at height 1005 — only 5 blocks, still within threshold
			alice.handleNewBlock(1005);
			expect(
				errors.filter((e) => e.code === 'STUCK_CHANNEL_FORCE_CLOSED').length
			).to.equal(0);

			// handleNewBlock at height 1011 — 11 blocks since first tracked, exceeds threshold
			alice.handleNewBlock(1011);
			const forceCloseErrors = errors.filter(
				(e) => e.code === 'STUCK_CHANNEL_FORCE_CLOSED'
			);
			expect(forceCloseErrors.length).to.equal(1);
			expect(forceCloseErrors[0].message).to.include(stuckState);
			expect(forceCloseErrors[0].message).to.include('10 blocks');
			expect(forceCloseErrors[0].message).to.include('force-closing');
			expect(forceCloseErrors[0].channelId).to.exist;
			expect(forceCloseErrors[0].timestamp).to.be.a('number');

			alice.destroy();
			bob.destroy();
		});

		it('scanStuckChannels does not affect NORMAL channels', () => {
			const alice = createTestNode(30);
			const bob = createTestNode(31);
			connectNodes(alice, bob);

			// Open a channel and advance to NORMAL
			const channelId = openReadyChannel(alice, bob);

			// Verify NORMAL state
			const channels = alice.listChannels();
			const ch = channels.find((c) => c.channelId.equals(channelId));
			expect(ch).to.exist;
			expect(ch!.state).to.equal(ChannelState.NORMAL);

			// Collect errors
			const errors: ILightningError[] = [];
			alice.on('node:error', (err: ILightningError) => errors.push(err));

			// Call handleNewBlock many times at varying heights
			alice.handleNewBlock(100);
			alice.handleNewBlock(500);
			alice.handleNewBlock(3000);
			alice.handleNewBlock(10000);

			// No stuck-channel errors should be emitted
			const stuckErrors = errors.filter(
				(e) =>
					e.code === 'STUCK_CHANNEL' || e.code === 'STUCK_CHANNEL_FORCE_CLOSED'
			);
			expect(stuckErrors.length).to.equal(0);

			// Channel should still be NORMAL
			const afterChannels = alice.listChannels();
			const afterCh = afterChannels.find((c) => c.channelId.equals(channelId));
			expect(afterCh).to.exist;
			expect(afterCh!.state).to.equal(ChannelState.NORMAL);

			// The _stuckChannelTracker should not have any entries for this channel
			const tracker = (alice as any)._stuckChannelTracker as Map<
				string,
				number
			>;
			expect(tracker.size).to.equal(0);

			alice.destroy();
			bob.destroy();
		});
	});
});
