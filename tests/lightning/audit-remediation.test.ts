/**
 * Pre-custody fund-safety audit remediation regression tests.
 *
 * Each describe block reproduces a distinct loss-of-funds / stranding scenario
 * flagged by the adversarial fund-safety audit and asserts the fix. Every test
 * here was verified to FAIL against the pre-fix tree.
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

// ─── Helpers ───

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`audit-seed-${id}`))
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

// ═══════════════════════════════════════════════════════════════════════
// HIGH-1: coop-close CLOSED channels re-watched + rebroadcast on restart
// ═══════════════════════════════════════════════════════════════════════

describe('Audit HIGH-1: coop-close CLOSED channel re-armed on restart', function () {
	this.timeout(10_000);

	it('re-arms the funding watch and rebroadcasts the stored mutual close', async () => {
		const alice = createNode(1);
		const bob = createNode(2);
		connectNodes(alice, bob);
		const channelId = openReadyChannel(alice, bob);

		// Put the channel into the coop-close pre-confirmation window: CLOSED at
		// fee/sig agreement with the signed mutual close persisted, but the tx not
		// yet confirmed (no ChainMonitor exists for it).
		const chan = (alice as any).channelManager.getChannel(channelId);
		const st = chan.getFullState();
		st.state = ChannelState.CLOSED;
		st.lastCooperativeCloseTxHex = 'deadbeefcafe';

		// Inject a spy chain watcher + backend (restoreChainWatches only needs the
		// watcher to be present and the backend for rebroadcast).
		const fundingWatches: unknown[][] = [];
		const rebroadcasts: string[] = [];
		(alice as any).chainWatcher = {
			watchFundingOutput: async (...args: unknown[]): Promise<void> => {
				fundingWatches.push(args);
			},
			watchOutputByTxid: async (): Promise<void> => {},
			stop: (): void => {}
		};
		(alice as any)._chainBackend = {
			broadcastTransaction: async (hex: string): Promise<void> => {
				rebroadcasts.push(hex);
			}
		};

		await alice.restoreChainWatches();

		// Before the fix restoreChainWatches unconditionally `continue`d on CLOSED,
		// so the funding output was never re-watched and the close never rebroadcast.
		expect(fundingWatches.length).to.equal(1);
		expect(rebroadcasts).to.include('deadbeefcafe');

		alice.destroy();
		bob.destroy();
	});
});
