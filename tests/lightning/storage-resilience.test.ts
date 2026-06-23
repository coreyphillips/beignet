/**
 * Storage Failure Resilience Tests
 *
 * Tests that LightningNode gracefully handles storage failures by emitting
 * node:error events instead of crashing the process.
 */

import { expect } from 'chai';
import crypto from 'crypto';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import { INodeConfig } from '../../src/lightning/node/types';
import { Network } from '../../src/lightning/invoice/types';
import { BITCOIN_CHAIN_HASH } from '../../src/lightning/channel/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { IStorageBackend } from '../../src/lightning/storage/types';
import { FeatureFlags } from '../../src/lightning/features/flags';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`storage-resilience-seed-${id}`))
		.digest();
}

function makeBasepoints(seed: Buffer): IChannelBasepoints {
	const keys: Buffer[] = [];
	for (let i = 0; i < 5; i++) {
		const privkey = crypto
			.createHash('sha256')
			.update(Buffer.concat([seed, Buffer.from([i])]))
			.digest();
		keys.push(getPublicKey(privkey));
	}
	return {
		fundingPubkey: keys[0],
		revocationBasepoint: keys[1],
		paymentBasepoint: keys[2],
		delayedPaymentBasepoint: keys[3],
		htlcBasepoint: keys[4],
		firstPerCommitmentPoint: keys[0]
	};
}

/** Storage mock that throws on every write/delete call */
function makeThrowingStorage(): IStorageBackend {
	const throwFn = (): never => {
		throw new Error('disk full');
	};
	return {
		open: () => {},
		close: () => {},
		saveChannel: throwFn,
		loadChannel: () => null,
		loadAllChannels: () => [],
		deleteChannel: throwFn,
		savePayment: throwFn,
		loadPayment: () => null,
		loadAllPayments: () => [],
		deletePayment: throwFn,
		savePreimage: throwFn,
		loadPreimage: () => null,
		loadAllPreimages: () => [],
		savePaymentSecret: throwFn,
		loadAllPaymentSecrets: () => [],
		deletePaymentSecret: throwFn,
		saveHtlcPaymentMapping: throwFn,
		loadAllHtlcPaymentMappings: () => [],
		deleteHtlcPaymentMapping: throwFn,
		saveForwardedHtlc: throwFn,
		loadAllForwardedHtlcs: () => [],
		deleteForwardedHtlc: throwFn,
		saveInvoice: throwFn,
		loadAllInvoices: () => [],
		saveGossipChannel: throwFn,
		loadAllGossipChannels: () => [],
		saveGossipNode: throwFn,
		loadAllGossipNodes: () => [],
		saveMissionControl: throwFn,
		loadMissionControl: () => null,
		saveScidMapping: throwFn,
		loadAllScidMappings: () => [],
		saveChainMonitor: throwFn,
		loadChainMonitor: () => null,
		loadAllChainMonitors: () => [],
		saveMetadata: throwFn,
		loadMetadata: () => null,
		savePeerAddress: throwFn,
		loadAllPeerAddresses: () => [],
		saveHtlcSharedSecret: throwFn,
		deleteHtlcSharedSecret: throwFn,
		loadAllHtlcSharedSecrets: () => [],
		transaction: (fn: () => void) => fn()
	} as unknown as IStorageBackend;
}

function createNodeConfig(id: number, storage?: IStorageBackend): INodeConfig {
	const seed = makeSeed(id);
	const seed2 = crypto
		.createHash('sha256')
		.update(Buffer.concat([seed, Buffer.from([0xff])]))
		.digest();
	return {
		nodePrivateKey: seed,
		network: Network.REGTEST,
		channelBasepoints: makeBasepoints(seed),
		perCommitmentSeed: seed2,
		fundingPrivkey: crypto
			.createHash('sha256')
			.update(Buffer.concat([seed, Buffer.from([0xfe])]))
			.digest(),
		localFeatures: FeatureFlags.empty(),
		chainHashes: [BITCOIN_CHAIN_HASH],
		storage
	};
}

describe('Storage Failure Resilience', () => {
	it('safeStorage emits PERSISTENCE_ERROR on storage failure', () => {
		const storage = makeThrowingStorage();
		const config = createNodeConfig(1, storage);
		const node = new LightningNode(config);

		const errors: Array<{ code: string; message: string }> = [];
		node.on('node:error', (err: { code: string; message: string }) => {
			errors.push(err);
		});

		// createInvoice will try to save preimage, paymentSecret, invoice, and payment
		// All should fail gracefully (emit error, not throw)
		const result = node.createInvoice({
			amountMsat: 1000n,
			description: 'test'
		});

		// Invoice should still be created in-memory even if storage fails
		expect(result.bolt11).to.be.a('string');
		expect(Buffer.isBuffer(result.paymentHash)).to.be.true;

		// At least one PERSISTENCE_ERROR should have been emitted
		expect(errors.length).to.be.greaterThan(0);
		expect(errors[0].code).to.equal('PERSISTENCE_ERROR');

		node.destroy();
	});

	it('registerChannelScid should not throw on storage failure', () => {
		const storage = makeThrowingStorage();
		const config = createNodeConfig(2, storage);
		const node = new LightningNode(config);

		const errors: Array<{ code: string; message: string }> = [];
		node.on('node:error', (err: { code: string; message: string }) => {
			errors.push(err);
		});

		// Should not throw
		const channelId = crypto.randomBytes(32);
		const scid = crypto.randomBytes(8);
		node.registerChannelScid(channelId, scid);

		// Error should have been emitted
		expect(errors.length).to.be.greaterThan(0);
		expect(errors[0].code).to.equal('PERSISTENCE_ERROR');
		expect(errors[0].message).to.include('saveScidMapping');

		node.destroy();
	});

	it('setPaymentMetadata should not throw on storage failure', () => {
		const storage = makeThrowingStorage();
		const config = createNodeConfig(3, storage);
		const node = new LightningNode(config);

		const errors: Array<{ code: string; message: string }> = [];
		node.on('node:error', (err: { code: string; message: string }) => {
			errors.push(err);
		});

		// Create a payment in memory first
		const result = node.createInvoice({
			amountMsat: 5000n,
			description: 'test'
		});
		errors.length = 0; // Clear invoice creation errors

		// Set metadata — should not throw
		node.setPaymentMetadata(result.paymentHash, { label: 'coffee' });

		// Error should have been emitted
		expect(errors.length).to.be.greaterThan(0);
		expect(errors.some((e) => e.message.includes('savePaymentMetadata'))).to.be
			.true;

		node.destroy();
	});

	it('node continues operating after storage failures', () => {
		const storage = makeThrowingStorage();
		const config = createNodeConfig(4, storage);
		const node = new LightningNode(config);

		// Absorb errors
		node.on('node:error', () => {});

		// Create multiple invoices — node should not crash
		for (let i = 0; i < 5; i++) {
			const result = node.createInvoice({
				amountMsat: BigInt(1000 * (i + 1)),
				description: `invoice ${i}`
			});
			expect(result.bolt11).to.be.a('string');
		}

		// List payments should still work (in-memory)
		const payments = node.listPayments();
		expect(payments.length).to.equal(5);

		node.destroy();
	});

	it('error messages include operation name for debugging', () => {
		const storage = makeThrowingStorage();
		const config = createNodeConfig(5, storage);
		const node = new LightningNode(config);

		const errors: string[] = [];
		node.on('node:error', (err: { message: string }) => {
			errors.push(err.message);
		});

		node.createInvoice({ amountMsat: 1000n, description: 'test' });

		// Verify error message includes operation name
		expect(errors.some((m) => m.includes('saveInvoiceData'))).to.be.true;
		expect(errors.some((m) => m.includes('disk full'))).to.be.true;

		node.destroy();
	});

	it('node without storage should not emit errors', () => {
		const config = createNodeConfig(6);
		const node = new LightningNode(config);

		const errors: Array<{ code: string }> = [];
		node.on('node:error', (err: { code: string }) => {
			errors.push(err);
		});

		const result = node.createInvoice({
			amountMsat: 1000n,
			description: 'test'
		});
		expect(result.bolt11).to.be.a('string');

		// No errors because no storage is attached
		const storageErrors = errors.filter((e) => e.code === 'PERSISTENCE_ERROR');
		expect(storageErrors.length).to.equal(0);

		node.destroy();
	});

	it('handleNewBlock with saveMetadata failure is handled', () => {
		const storage = makeThrowingStorage();
		const config = createNodeConfig(7, storage);
		const node = new LightningNode(config);

		// Absorb errors
		node.on('node:error', () => {});

		// handleNewBlock should not throw even if saveMetadata fails
		// (it already has try/catch for this one)
		node.handleNewBlock(100);
		expect(node.getCurrentBlockHeight()).to.equal(100);

		node.destroy();
	});

	it('gracefulShutdown completes even if storage fails', async () => {
		const storage = makeThrowingStorage();
		const config = createNodeConfig(8, storage);
		const node = new LightningNode(config);
		node.on('node:error', () => {});

		// gracefulShutdown has its own try/catch wrapper
		await node.gracefulShutdown(1_000);
		// Should not throw
	});
});
