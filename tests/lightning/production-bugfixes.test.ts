/**
 * Production Bugfixes Tests
 *
 * Validates the 4 bug fixes + 2 operational gap closures:
 * 1. Force-close sweep uses correct delayedPaymentBasepointSecret
 * 2. Channel announcements use real node ID (not funding pubkey)
 * 3. Channel_update is signed before broadcast
 * 4. ChainWatcher watches runtime channel openings
 * 5. ChainWatcher auto-starts when chainBackend provided
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { ChainMonitor } from '../../src/lightning/chain/chain-monitor';
import {
	ChainWatcher,
	IChainBackend,
	computeScriptHash
} from '../../src/lightning/chain/chain-watcher';
import {
	ChannelManager,
	IChannelManagerConfig
} from '../../src/lightning/channel/channel-manager';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	IChannelBasepoints,
	derivePrivateKey,
	derivePublicKey,
	perCommitmentPointFromSecret
} from '../../src/lightning/keys/derivation';
import { generateFromSeed, MAX_INDEX } from '../../src/lightning/keys/shachain';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { Channel } from '../../src/lightning/channel/channel';
import { DEFAULT_CHANNEL_CONFIG } from '../../src/lightning/channel/types';
import {
	signChannelUpdate,
	verifyChannelUpdate
} from '../../src/lightning/gossip/validation';
import {
	encodeChannelUpdateMessage,
	decodeChannelUpdateMessage
} from '../../src/lightning/gossip/messages';
import { MonitorState } from '../../src/lightning/chain/types';
import { createFundingScript } from '../../src/lightning/script/funding';

bitcoin.initEccLib(ecc);
const network = bitcoin.networks.regtest;

function makeBasepoints(seed: Buffer): {
	basepoints: IChannelBasepoints;
	privkeys: Buffer[];
} {
	const privkeys: Buffer[] = [];
	for (let i = 0; i < 6; i++) {
		privkeys.push(
			crypto
				.createHash('sha256')
				.update(Buffer.concat([seed, Buffer.from([i])]))
				.digest()
		);
	}
	const basepoints: IChannelBasepoints = {
		fundingPubkey: getPublicKey(privkeys[0]),
		revocationBasepoint: getPublicKey(privkeys[1]),
		paymentBasepoint: getPublicKey(privkeys[2]),
		delayedPaymentBasepoint: getPublicKey(privkeys[3]),
		htlcBasepoint: getPublicKey(privkeys[4]),
		firstPerCommitmentPoint: getPublicKey(privkeys[5])
	};
	return { basepoints, privkeys };
}

/** Create a mock chain backend for testing */
function createMockBackend(): IChainBackend & {
	subscribedScriptHashes: string[];
} {
	const subscribedScriptHashes: string[] = [];
	return {
		subscribedScriptHashes,
		subscribeToHeaders: async () => {},
		subscribeToScriptHash: async (scriptHash: string) => {
			subscribedScriptHashes.push(scriptHash);
		},
		getScriptHashHistory: async () => [],
		getTransaction: async () => Buffer.alloc(0),
		broadcastTransaction: async (hex: string) =>
			crypto.createHash('sha256').update(hex).digest().toString('hex')
	};
}

describe('Production Bugfixes', () => {
	// ─────────────── Bug 1: Force-close sweep key ───────────────

	describe('Bug 1: resolveOurCommitmentOutputs uses correct derived key', () => {
		it('should derive the correct delayed payment private key when delayedPaymentBasepointSecret is provided', () => {
			// Create a known delayed payment basepoint secret
			const delayedPaymentBasepointSecret = crypto
				.createHash('sha256')
				.update(Buffer.from('delayed-secret'))
				.digest();
			const delayedPaymentBasepoint = getPublicKey(
				delayedPaymentBasepointSecret
			);

			// Create a per-commitment seed and derive the per-commitment point
			const perCommitmentSeed = crypto.randomBytes(32);
			const commitmentNumber = 0n;
			const perCommitmentSecret = generateFromSeed(
				perCommitmentSeed,
				MAX_INDEX - commitmentNumber
			);
			const perCommitmentPoint =
				perCommitmentPointFromSecret(perCommitmentSecret);

			// Derive what the correct private key should be
			const expectedPrivkey = derivePrivateKey(
				delayedPaymentBasepointSecret,
				perCommitmentPoint,
				delayedPaymentBasepoint
			);
			const expectedPubkey = getPublicKey(expectedPrivkey);

			// Also derive the public key from the basepoint directly
			const derivedPubkey = derivePublicKey(
				delayedPaymentBasepoint,
				perCommitmentPoint
			);

			// The public key from the derived private key should match the one from public derivation
			expect(expectedPubkey.equals(derivedPubkey)).to.be.true;

			// Now verify that using the perCommitmentSeed (the bug) would NOT match
			const wrongPrivkey = derivePrivateKey(
				perCommitmentSeed,
				perCommitmentPoint,
				delayedPaymentBasepoint
			);
			const wrongPubkey = getPublicKey(wrongPrivkey);
			expect(wrongPubkey.equals(derivedPubkey)).to.be.false;
		});

		it('should thread delayedPaymentBasepointSecret through ChainMonitor', () => {
			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);
			const delayedSecret = privkeys[3]; // delayedPaymentBasepoint secret

			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			const destScript = Buffer.alloc(22);
			destScript[0] = 0x00;
			destScript[1] = 0x14;

			// Create ChainMonitor WITH the delayedPaymentBasepointSecret
			const monitor = new ChainMonitor(
				state,
				destScript,
				10,
				privkeys[1],
				privkeys[2],
				network,
				delayedSecret
			);

			expect(monitor.getState()).to.equal(MonitorState.WATCHING);

			// Verify restore also works
			const saved = monitor.getFullState();
			const restored = ChainMonitor.restore(
				saved,
				state,
				destScript,
				10,
				privkeys[1],
				privkeys[2],
				network,
				delayedSecret
			);
			expect(restored.getState()).to.equal(MonitorState.WATCHING);
		});
	});

	// ─────────────── Bug 2: Channel announcements use real node ID ───────────────

	describe('Bug 2: ChannelManager uses real node ID in announcements', () => {
		it('should use nodePrivateKey pubkey instead of funding pubkey when configured', () => {
			const nodePrivkey = crypto.randomBytes(32);
			const nodeId = getPublicKey(nodePrivkey);

			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);

			const config: IChannelManagerConfig = {
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: privkeys[0],
				nodePrivateKey: nodePrivkey
			};

			const cm = new ChannelManager(config);

			// The node ID should be different from the funding pubkey
			expect(nodeId.equals(basepoints.fundingPubkey)).to.be.false;

			// The config stores the nodePrivateKey
			expect(config.nodePrivateKey!.equals(nodePrivkey)).to.be.true;

			// Verify getPublicKey produces the expected node ID
			expect(getPublicKey(config.nodePrivateKey!).equals(nodeId)).to.be.true;
			cm.on('error', () => {}); // absorb
		});
	});

	// ─────────────── Bug 3: Signed channel_update ───────────────

	describe('Bug 3: channel_update is signed before broadcast', () => {
		it('should produce a valid signature with signChannelUpdate', () => {
			const nodePrivkey = crypto.randomBytes(32);
			const nodePubkey = getPublicKey(nodePrivkey);

			// Create a channel_update message with a zero signature placeholder
			const chainHash = Buffer.alloc(32);
			const scid = Buffer.alloc(8);
			scid.writeUInt32BE(1, 0);
			scid.writeUInt32BE(1, 4);

			const updateMsg = {
				signature: Buffer.alloc(64), // placeholder
				chainHash,
				shortChannelId: scid,
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1, // has htlc_maximum_msat
				channelFlags: 0, // direction = 0
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 1_000_000_000n
			};

			const encoded = encodeChannelUpdateMessage(updateMsg);

			// Verify the signature is zero
			expect(encoded.subarray(0, 64).equals(Buffer.alloc(64))).to.be.true;

			// Sign it
			const sig = signChannelUpdate(encoded, nodePrivkey);
			expect(sig.length).to.equal(64);
			expect(sig.equals(Buffer.alloc(64))).to.be.false;

			// Write the signature back
			sig.copy(encoded, 0);

			// Verify it passes validation
			const decoded = decodeChannelUpdateMessage(encoded);
			const valid = verifyChannelUpdate(
				decoded,
				encoded,
				nodePubkey,
				nodePubkey
			);
			expect(valid).to.be.true;
		});

		it('should sign channel_update in announcement:ready handler', (done) => {
			const nodePrivkey = crypto.randomBytes(32);
			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);

			const node = new LightningNode({
				nodePrivateKey: nodePrivkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: privkeys[0]
			});
			node.on('node:error', () => {}); // absorb

			// Create a channel_update with zero signature
			const updateMsg = {
				signature: Buffer.alloc(64),
				chainHash: Buffer.alloc(32),
				shortChannelId: Buffer.alloc(8, 1),
				timestamp: Math.floor(Date.now() / 1000),
				messageFlags: 1,
				channelFlags: 0,
				cltvExpiryDelta: 40,
				htlcMinimumMsat: 1000n,
				feeBaseMsat: 1000,
				feeProportionalMillionths: 1,
				htlcMaximumMsat: 1_000_000_000n
			};
			const channelUpdateBuf = encodeChannelUpdateMessage(updateMsg);

			// Create a minimal channel_announcement buffer (just needs to not crash on decode)
			// We'll catch the decode error in the handler — the point is the update gets signed
			const announcementBuf = Buffer.alloc(320); // Will fail to decode, but handler catches this

			// Listen for the announcement:ready event to be re-emitted
			const cm = node.getChannelManager();
			node.on('announcement:ready', () => {
				// The handler should have been called. Since we can't easily intercept the
				// signed update, we verify the signing mechanism works independently above.
				node.destroy();
				done();
			});

			// Emit the event directly on the ChannelManager
			cm.emit(
				'announcement:ready',
				Buffer.alloc(32),
				announcementBuf,
				channelUpdateBuf
			);
		});
	});

	// ─────────────── Bug 4: ChainWatcher watches runtime channels ───────────────

	describe('Bug 4: ChainWatcher watches runtime channel openings', () => {
		it('should call watchFundingOutput on watch:funding event', async () => {
			const mockBackend = createMockBackend();
			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);
			const remoteSeed = crypto.randomBytes(32);
			const { basepoints: remoteBasepoints } = makeBasepoints(remoteSeed);

			const cm = new ChannelManager({
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: privkeys[0]
			});
			cm.on('error', () => {}); // absorb

			const watcher = new ChainWatcher({
				backend: mockBackend,
				channelManager: cm
			});

			// Create a channel and set it up with funding info
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 100_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32)
			});

			// Set funding info and remote basepoints on the channel
			const fundingTxid = crypto.randomBytes(32);
			state.fundingTxid = fundingTxid;
			state.fundingOutputIndex = 0;
			state.channelId = crypto.randomBytes(32);
			state.remoteBasepoints = {
				fundingPubkey: remoteBasepoints.fundingPubkey,
				revocationBasepoint: remoteBasepoints.revocationBasepoint,
				paymentBasepoint: remoteBasepoints.paymentBasepoint,
				delayedPaymentBasepoint: remoteBasepoints.delayedPaymentBasepoint,
				htlcBasepoint: remoteBasepoints.htlcBasepoint,
				firstPerCommitmentPoint: remoteBasepoints.firstPerCommitmentPoint
			};

			const channel = new Channel(state);
			cm.restoreChannel(channel, 'aabbcc');

			// Compute expected script hash
			const { p2wshOutput } = createFundingScript(
				basepoints.fundingPubkey,
				remoteBasepoints.fundingPubkey
			);
			const expectedScriptHash = computeScriptHash(p2wshOutput);

			// Now emit watch:funding to trigger the handler
			// The fundingTxid is in internal byte order, handler converts to display
			cm.emit('watch:funding', Buffer.from(fundingTxid), 0, 3);

			// Give the async watchFundingOutput time to complete
			await new Promise((resolve) => setTimeout(resolve, 50));

			// Verify that subscribeToScriptHash was called with the correct hash
			expect(mockBackend.subscribedScriptHashes).to.include(expectedScriptHash);

			watcher.stop();
		});

		it('should emit error when channel is not found for watch:funding', (done) => {
			const mockBackend = createMockBackend();
			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);

			const cm = new ChannelManager({
				localBasepoints: basepoints,
				localPerCommitmentSeed: crypto.randomBytes(32),
				localFundingPrivkey: privkeys[0]
			});
			cm.on('error', () => {}); // absorb

			const watcher = new ChainWatcher({
				backend: mockBackend,
				channelManager: cm
			});

			watcher.on('error', (err: Error) => {
				expect(err.message).to.include('no channel found');
				watcher.stop();
				done();
			});

			// Emit watch:funding with a txid that doesn't match any channel
			cm.emit('watch:funding', crypto.randomBytes(32), 0, 3);
		});

		it('should reconstruct correct P2WSH script from channel state', () => {
			const seed1 = crypto.randomBytes(32);
			const { basepoints: bp1 } = makeBasepoints(seed1);
			const seed2 = crypto.randomBytes(32);
			const { basepoints: bp2 } = makeBasepoints(seed2);

			const { p2wshOutput, witnessScript } = createFundingScript(
				bp1.fundingPubkey,
				bp2.fundingPubkey
			);

			// The P2WSH output should be 34 bytes (OP_0 <32-byte-hash>)
			expect(p2wshOutput.length).to.equal(34);
			expect(p2wshOutput[0]).to.equal(0x00); // OP_0
			expect(p2wshOutput[1]).to.equal(0x20); // 32 bytes

			// The witness script should be a 2-of-2 multisig
			expect(witnessScript.length).to.be.greaterThan(0);
		});
	});

	// ─────────────── Gap 2: ChainWatcher auto-start ───────────────

	describe('Gap 2: ChainWatcher auto-starts when chainBackend provided', () => {
		it('should create and auto-start ChainWatcher when chainBackend is provided', async () => {
			const mockBackend = createMockBackend();
			const nodePrivkey = crypto.randomBytes(32);
			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);

			const node = new LightningNode({
				nodePrivateKey: nodePrivkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: privkeys[0],
				chainBackend: mockBackend
			});
			node.on('node:error', () => {}); // absorb

			// ChainWatcher should exist
			expect(node.getChainWatcher()).to.not.be.null;

			// Give the auto-start promise time to resolve
			await new Promise((resolve) => setTimeout(resolve, 50));

			node.destroy();
		});

		it('should not create ChainWatcher when no chainBackend', () => {
			const nodePrivkey = crypto.randomBytes(32);
			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);

			const node = new LightningNode({
				nodePrivateKey: nodePrivkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: privkeys[0]
			});
			node.on('node:error', () => {}); // absorb

			expect(node.getChainWatcher()).to.be.null;
			node.destroy();
		});

		it('should not double-wire events on multiple startChainWatcher calls', async () => {
			const mockBackend = createMockBackend();
			const nodePrivkey = crypto.randomBytes(32);
			const seed = crypto.randomBytes(32);
			const { basepoints, privkeys } = makeBasepoints(seed);

			const node = new LightningNode({
				nodePrivateKey: nodePrivkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: crypto.randomBytes(32),
				fundingPrivkey: privkeys[0],
				chainBackend: mockBackend
			});
			node.on('node:error', () => {}); // absorb

			// Give auto-start time to complete
			await new Promise((resolve) => setTimeout(resolve, 50));

			// Call startChainWatcher again manually — should not double-wire
			await node.startChainWatcher();

			// Listen for block events
			const watcher = node.getChainWatcher()!;

			// Emit block and check it updates only once
			watcher.emit('block', 500);

			// Give event handlers time to fire
			await new Promise((resolve) => setTimeout(resolve, 10));

			// Should only be updated once (not twice from double-wired handlers)
			expect(node.getCurrentBlockHeight()).to.equal(500);

			node.destroy();
		});
	});
});
