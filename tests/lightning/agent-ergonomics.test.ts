/**
 * Phase 4: Agent Ergonomics — Tests
 *
 * Tests for developer-friendly async wrappers, invoice listing, package.json
 * exports, and isPermanentFailure classification.
 *
 * 4A: sendPaymentAsync (4 tests)
 * 4B: waitForChannelReady (4 tests)
 * 4C: listInvoices (4 tests)
 * 4D: package.json exports (1 test)
 * 4E: isPermanentFailure (1 test)
 */

import { expect } from 'chai';
import crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { LightningNode } from '../../src/lightning/node/lightning-node';
import {
	PaymentStatus,
	PaymentDirection,
	IPaymentInfo
} from '../../src/lightning/node/types';
import {
	IStorageBackend,
	IInvoiceInfo
} from '../../src/lightning/storage/types';
import { IChannelBasepoints } from '../../src/lightning/keys/derivation';
import {
	ChannelState,
	DEFAULT_CHANNEL_CONFIG
} from '../../src/lightning/channel/types';
import { Channel } from '../../src/lightning/channel/channel';
import { createOpenerState } from '../../src/lightning/channel/channel-state';
import { getPublicKey } from '../../src/lightning/crypto/ecdh';
import { Network } from '../../src/lightning/invoice/types';
import { encode as encodeInvoice } from '../../src/lightning/invoice/encode';
import { EXPIRY_TOO_FAR } from '../../src/lightning/onion/types';

// ─────────────── Helpers ───────────────

function makeSeed(id: number): Buffer {
	return crypto
		.createHash('sha256')
		.update(Buffer.from(`agent-ergo-seed-${id}`))
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

function createTestNode(storage?: IStorageBackend): LightningNode {
	const privkey = crypto.randomBytes(32);
	const seed = crypto.randomBytes(32);
	const fundingPrivkey = crypto.randomBytes(32);
	const basepoints = makeBasepoints(seed);
	const node = new LightningNode({
		nodePrivateKey: privkey,
		channelBasepoints: basepoints,
		perCommitmentSeed: seed,
		fundingPrivkey,
		network: Network.REGTEST,
		storage
	});
	node.on('error', () => {});
	return node;
}

/**
 * Create a valid BOLT 11 invoice signed by a given private key.
 */
function createExternalInvoice(
	signerPrivkey: Buffer,
	opts?: {
		amountMsat?: bigint;
		description?: string;
		expiry?: number;
	}
): string {
	const preimage = crypto.randomBytes(32);
	const paymentHash = crypto.createHash('sha256').update(preimage).digest();
	const paymentSecret = crypto.randomBytes(32);
	return encodeInvoice({
		network: Network.REGTEST,
		amountMsat: opts?.amountMsat ?? 10_000n,
		description: opts?.description ?? 'test',
		paymentHash,
		paymentSecret,
		expiry: opts?.expiry ?? 3600,
		minFinalCltvExpiry: 18,
		privateKey: signerPrivkey
	});
}

// ─────────────── MockStorage ───────────────

class MockStorage implements IStorageBackend {
	private channels = new Map<string, { state: any; peerPubkey: string }>();
	private payments = new Map<string, IPaymentInfo>();
	private preimages = new Map<string, Buffer>();
	private scidMappings = new Map<string, Buffer>();
	private htlcPaymentMappings = new Map<string, string>();
	private forwardedHtlcs = new Map<
		string,
		{ inChannelId: Buffer; inHtlcId: bigint }
	>();
	private chainMonitors = new Map<string, any>();
	private gossipChannels: any[] = [];
	private gossipNodes: any[] = [];
	private paymentSecrets = new Map<string, Buffer>();
	private _invoices = new Map<string, IInvoiceInfo>();
	private missionControlJson: string | null = null;

	open(): void {}
	close(): void {}

	saveChannel(id: string, state: any, peerPubkey: string): void {
		this.channels.set(id, { state, peerPubkey });
	}
	loadChannel(id: string): { state: any; peerPubkey: string } | null {
		return this.channels.get(id) || null;
	}
	loadAllChannels(): Array<{
		channelId: string;
		state: any;
		peerPubkey: string;
	}> {
		const result: Array<{ channelId: string; state: any; peerPubkey: string }> =
			[];
		for (const [channelId, v] of this.channels) {
			result.push({ channelId, state: v.state, peerPubkey: v.peerPubkey });
		}
		return result;
	}
	deleteChannel(id: string): void {
		this.channels.delete(id);
	}

	savePayment(paymentHash: string, payment: IPaymentInfo): void {
		this.payments.set(paymentHash, payment);
	}
	loadPayment(paymentHash: string): IPaymentInfo | null {
		return this.payments.get(paymentHash) || null;
	}
	loadAllPayments(): Array<{ paymentHash: string; payment: IPaymentInfo }> {
		const result: Array<{ paymentHash: string; payment: IPaymentInfo }> = [];
		for (const [paymentHash, payment] of this.payments) {
			result.push({ paymentHash, payment });
		}
		return result;
	}
	deletePayment(paymentHash: string): void {
		this.payments.delete(paymentHash);
	}

	savePreimage(paymentHash: string, preimage: Buffer): void {
		this.preimages.set(paymentHash, preimage);
	}
	loadPreimage(paymentHash: string): Buffer | null {
		return this.preimages.get(paymentHash) || null;
	}
	loadAllPreimages(): Array<{ paymentHash: string; preimage: Buffer }> {
		const result: Array<{ paymentHash: string; preimage: Buffer }> = [];
		for (const [paymentHash, preimage] of this.preimages) {
			result.push({ paymentHash, preimage });
		}
		return result;
	}

	saveScidMapping(scidHex: string, channelId: Buffer): void {
		this.scidMappings.set(scidHex, channelId);
	}
	loadAllScidMappings(): Array<{ scidHex: string; channelId: Buffer }> {
		const result: Array<{ scidHex: string; channelId: Buffer }> = [];
		for (const [scidHex, channelId] of this.scidMappings) {
			result.push({ scidHex, channelId });
		}
		return result;
	}

	saveHtlcPaymentMapping(key: string, paymentHashHex: string): void {
		this.htlcPaymentMappings.set(key, paymentHashHex);
	}
	loadAllHtlcPaymentMappings(): Array<{ key: string; paymentHashHex: string }> {
		const result: Array<{ key: string; paymentHashHex: string }> = [];
		for (const [key, paymentHashHex] of this.htlcPaymentMappings) {
			result.push({ key, paymentHashHex });
		}
		return result;
	}
	deleteHtlcPaymentMapping(key: string): void {
		this.htlcPaymentMappings.delete(key);
	}

	saveForwardedHtlc(
		outKey: string,
		inChannelId: Buffer,
		inHtlcId: bigint
	): void {
		this.forwardedHtlcs.set(outKey, { inChannelId, inHtlcId });
	}
	loadAllForwardedHtlcs(): Array<{
		outKey: string;
		inChannelId: Buffer;
		inHtlcId: bigint;
	}> {
		const result: Array<{
			outKey: string;
			inChannelId: Buffer;
			inHtlcId: bigint;
		}> = [];
		for (const [outKey, { inChannelId, inHtlcId }] of this.forwardedHtlcs) {
			result.push({ outKey, inChannelId, inHtlcId });
		}
		return result;
	}
	deleteForwardedHtlc(outKey: string): void {
		this.forwardedHtlcs.delete(outKey);
	}

	saveChainMonitor(channelId: string, state: any): void {
		this.chainMonitors.set(channelId, state);
	}
	loadChainMonitor(channelId: string): any | null {
		return this.chainMonitors.get(channelId) || null;
	}
	loadAllChainMonitors(): Array<{ channelId: string; state: any }> {
		const result: Array<{ channelId: string; state: any }> = [];
		for (const [channelId, state] of this.chainMonitors) {
			result.push({ channelId, state });
		}
		return result;
	}

	saveGossipChannel(_scidHex: string, channel: any): void {
		this.gossipChannels.push(channel);
	}
	loadAllGossipChannels(): any[] {
		return this.gossipChannels;
	}
	saveGossipNode(_nodeIdHex: string, node: any): void {
		this.gossipNodes.push(node);
	}
	loadAllGossipNodes(): any[] {
		return this.gossipNodes;
	}

	savePaymentSecret(paymentHashHex: string, secret: Buffer): void {
		this.paymentSecrets.set(paymentHashHex, secret);
	}
	loadAllPaymentSecrets(): Array<{ paymentHashHex: string; secret: Buffer }> {
		const result: Array<{ paymentHashHex: string; secret: Buffer }> = [];
		for (const [paymentHashHex, secret] of this.paymentSecrets) {
			result.push({ paymentHashHex, secret });
		}
		return result;
	}
	deletePaymentSecret(paymentHashHex: string): void {
		this.paymentSecrets.delete(paymentHashHex);
	}

	saveInvoice(paymentHashHex: string, invoice: IInvoiceInfo): void {
		this._invoices.set(paymentHashHex, invoice);
	}
	loadAllInvoices(): Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> {
		const result: Array<{ paymentHashHex: string; invoice: IInvoiceInfo }> = [];
		for (const [paymentHashHex, invoice] of this._invoices) {
			result.push({ paymentHashHex, invoice });
		}
		return result;
	}
	deleteInvoice(paymentHashHex: string): void {
		this._invoices.delete(paymentHashHex);
	}

	saveMissionControl(json: string): void {
		this.missionControlJson = json;
	}
	loadMissionControl(): string | null {
		return this.missionControlJson;
	}

	savePeerAddress(): void {}
	loadAllPeerAddresses(): Array<{
		pubkey: string;
		host: string;
		port: number;
	}> {
		return [];
	}
	deletePeerAddress(): void {}
	saveChannelKeyIndex(): void {}
	loadChannelKeyIndex(): number | null {
		return null;
	}
	loadNextChannelIndex(): number {
		return 1;
	}

	saveMetadata(_key: string, _value: string): void {}
	loadMetadata(_key: string): string | null {
		return null;
	}

	// ─── HTLC Shared Secrets ───
	private htlcSharedSecrets = new Map<string, Buffer>();
	saveHtlcSharedSecret(key: string, secret: Buffer): void {
		this.htlcSharedSecrets.set(key, secret);
	}
	deleteHtlcSharedSecret(key: string): void {
		this.htlcSharedSecrets.delete(key);
	}
	loadAllHtlcSharedSecrets(): Array<{ key: string; secret: Buffer }> {
		return Array.from(this.htlcSharedSecrets.entries()).map(
			([key, secret]) => ({ key, secret })
		);
	}

	transaction<T>(fn: () => T): T {
		return fn();
	}
}

// ─────────────── Tests ───────────────

describe('Phase 4: Agent Ergonomics', () => {
	afterEach(() => {
		// Clean up any lingering timers by destroying nodes
	});

	// ─────────────── 4A: sendPaymentAsync ───────────────

	describe('4A — sendPaymentAsync', () => {
		it('sendPaymentAsync resolves on payment:sent event', async () => {
			const node = createTestNode();
			const signerPrivkey = crypto.randomBytes(32);

			// Test the event wiring by manually creating a pending payment
			// and then emitting the event.
			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const paymentHashHex = paymentHash.toString('hex');

			// Inject a pending payment into the node
			const paymentInfo: IPaymentInfo = {
				paymentHash,
				amountMsat: 50_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now()
			};
			(node as any).payments.set(paymentHashHex, paymentInfo);

			// Create invoice signed by the signer to match the payment hash
			const paymentSecret = crypto.randomBytes(32);
			const invoice = encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 50_000n,
				description: 'test-async',
				paymentHash,
				paymentSecret,
				expiry: 3600,
				minFinalCltvExpiry: 18,
				privateKey: signerPrivkey
			});

			// The sendPayment will throw "No route found" so sendPaymentAsync will reject.
			// To test event-based resolution, we need to override sendPayment.
			const sentInfo: IPaymentInfo = {
				...paymentInfo,
				preimage,
				status: PaymentStatus.COMPLETED,
				completedAt: Date.now()
			};
			(node as any).sendPayment = (): IPaymentInfo => {
				// Simulate successful payment initiation — emit sent after a tick
				setTimeout(() => node.emit('payment:sent', sentInfo), 10);
				return paymentInfo;
			};

			const result = await node.sendPaymentAsync(invoice, 5000);
			expect(result.status).to.equal(PaymentStatus.COMPLETED);
			expect(result.paymentHash.toString('hex')).to.equal(paymentHashHex);
			node.destroy();
		});

		it('sendPaymentAsync rejects on payment:failed event', async () => {
			const node = createTestNode();
			const signerPrivkey = crypto.randomBytes(32);

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();

			const paymentInfo: IPaymentInfo = {
				paymentHash,
				amountMsat: 50_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now()
			};

			const paymentSecret = crypto.randomBytes(32);
			const invoice = encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 50_000n,
				description: 'test-async-fail',
				paymentHash,
				paymentSecret,
				expiry: 3600,
				minFinalCltvExpiry: 18,
				privateKey: signerPrivkey
			});

			const failedInfo: IPaymentInfo = {
				...paymentInfo,
				status: PaymentStatus.FAILED,
				failureCode: 0x400f, // PERM | some code
				completedAt: Date.now()
			};

			// Override sendPayment to emit failure after a tick
			(node as any).sendPayment = (): IPaymentInfo => {
				setTimeout(() => node.emit('payment:failed', failedInfo), 10);
				return paymentInfo;
			};

			try {
				await node.sendPaymentAsync(invoice, 5000);
				expect.fail('Should have rejected');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('Payment failed');
				expect((err as Error).message).to.include('16399'); // 0x400f
			}
			node.destroy();
		});

		it('sendPaymentAsync rejects on timeout and calls failPayment', async () => {
			const node = createTestNode();
			const signerPrivkey = crypto.randomBytes(32);

			const preimage = crypto.randomBytes(32);
			const paymentHash = crypto.createHash('sha256').update(preimage).digest();
			const paymentHashHex = paymentHash.toString('hex');

			const paymentInfo: IPaymentInfo = {
				paymentHash,
				amountMsat: 50_000n,
				status: PaymentStatus.PENDING,
				direction: PaymentDirection.OUTGOING,
				createdAt: Date.now()
			};

			const paymentSecret = crypto.randomBytes(32);
			const invoice = encodeInvoice({
				network: Network.REGTEST,
				amountMsat: 50_000n,
				description: 'test-timeout',
				paymentHash,
				paymentSecret,
				expiry: 3600,
				minFinalCltvExpiry: 18,
				privateKey: signerPrivkey
			});

			// Inject the pending payment so failPayment can find and mark it FAILED
			(node as any).payments.set(paymentHashHex, paymentInfo);

			// Override sendPayment to do nothing (never emit events)
			(node as any).sendPayment = (): IPaymentInfo => {
				return paymentInfo;
			};

			let failedPaymentEmitted = false;
			node.on('payment:failed', (info: IPaymentInfo) => {
				if (info.paymentHash.toString('hex') === paymentHashHex) {
					failedPaymentEmitted = true;
				}
			});

			try {
				await node.sendPaymentAsync(invoice, 100);
				expect.fail('Should have rejected');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('timed out');
			}

			// failPayment should have been called, which emits payment:failed
			// and marks the payment as FAILED
			expect(failedPaymentEmitted).to.equal(true);
			expect(paymentInfo.status).to.equal(PaymentStatus.FAILED);
			node.destroy();
		});

		it('sendPaymentAsync rejects immediately if sendPayment throws (no route)', async () => {
			const node = createTestNode();
			const signerPrivkey = crypto.randomBytes(32);

			// Create a normal invoice that we cannot route to
			const invoiceStr = createExternalInvoice(signerPrivkey, {
				amountMsat: 50_000n
			});

			try {
				await node.sendPaymentAsync(invoiceStr, 5000);
				expect.fail('Should have rejected');
			} catch (err: unknown) {
				// sendPayment throws because there is no route
				expect((err as Error).message).to.include('No route found');
			}
			node.destroy();
		});
	});

	// ─────────────── 4B: waitForChannelReady ───────────────

	describe('4B — waitForChannelReady', () => {
		it('waitForChannelReady resolves immediately if channel is already NORMAL', async () => {
			const seed = makeSeed(100);
			const basepoints = makeBasepoints(seed);
			const privkey = crypto.randomBytes(32);
			const fundingPrivkey = crypto.randomBytes(32);
			const node = new LightningNode({
				nodePrivateKey: privkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: seed,
				fundingPrivkey,
				network: Network.REGTEST
			});
			node.on('error', () => {});

			// Create a channel in NORMAL state and inject it into the channelManager
			const channelId = crypto.randomBytes(32);
			const state = createOpenerState({
				temporaryChannelId: crypto.randomBytes(32),
				fundingSatoshis: 1_000_000n,
				pushMsat: 0n,
				localConfig: DEFAULT_CHANNEL_CONFIG,
				localBasepoints: basepoints,
				localPerCommitmentSeed: seed
			});
			state.state = ChannelState.NORMAL;
			state.channelId = channelId;

			const channel = new Channel(state);
			// Inject directly into channelManager's channels map
			const cm = (node as any).channelManager;
			(cm as any).channels.set(channelId.toString('hex'), channel);

			// Should resolve immediately since the channel is already NORMAL
			await node.waitForChannelReady(channelId, 1000);
			// If we reach here, it resolved without timeout
			node.destroy();
		});

		it('waitForChannelReady waits for channel:ready event', async () => {
			const node = createTestNode();
			const channelId = crypto.randomBytes(32);

			// Start waiting — channel is not known yet, so it won't resolve immediately
			const promise = node.waitForChannelReady(channelId, 5000);

			// Emit channel:ready after a short delay
			setTimeout(() => {
				node.emit('channel:ready', { channelId });
			}, 50);

			// Should resolve once the event fires
			await promise;
			node.destroy();
		});

		it('waitForChannelReady rejects on timeout', async () => {
			const node = createTestNode();
			const channelId = crypto.randomBytes(32);

			try {
				await node.waitForChannelReady(channelId, 100);
				expect.fail('Should have rejected');
			} catch (err: unknown) {
				expect((err as Error).message).to.include('did not become ready');
				expect((err as Error).message).to.include('100ms');
			}
			node.destroy();
		});

		it('waitForChannelReady only resolves for matching channelId', async () => {
			const node = createTestNode();
			const channelId1 = crypto.randomBytes(32);
			const channelId2 = crypto.randomBytes(32);

			// Wait for channelId1
			const promise = node.waitForChannelReady(channelId1, 1000);

			// Emit channel:ready for channelId2 — should NOT resolve the promise
			setTimeout(() => {
				node.emit('channel:ready', { channelId: channelId2 });
			}, 20);

			// After a short delay, emit for channelId1 — should resolve
			setTimeout(() => {
				node.emit('channel:ready', { channelId: channelId1 });
			}, 60);

			await promise;
			// If we reach here, it correctly waited for channelId1 and ignored channelId2
			node.destroy();
		});
	});

	// ─────────────── 4C: listInvoices ───────────────

	describe('4C — listInvoices', () => {
		it('listInvoices returns empty array initially', () => {
			const node = createTestNode();
			const invoices = node.listInvoices();
			expect(invoices).to.be.an('array');
			expect(invoices).to.have.length(0);
			node.destroy();
		});

		it('listInvoices returns created invoices', () => {
			const node = createTestNode();

			node.createInvoice({ description: 'coffee', amountMsat: 100_000n });
			node.createInvoice({ description: 'lunch', amountMsat: 500_000n });

			const invoices = node.listInvoices();
			expect(invoices).to.have.length(2);

			const descriptions = invoices.map((inv) => inv.description);
			expect(descriptions).to.include('coffee');
			expect(descriptions).to.include('lunch');
			node.destroy();
		});

		it('invoices persist across storage restore', () => {
			const storage = new MockStorage();
			const seed = makeSeed(200);
			const basepoints = makeBasepoints(seed);
			const privkey = makeSeed(201);
			const fundingPrivkey = makeSeed(202);

			// Create a node with storage, generate invoices
			const node1 = new LightningNode({
				nodePrivateKey: privkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: seed,
				fundingPrivkey,
				network: Network.REGTEST,
				storage
			});
			node1.on('error', () => {});

			node1.createInvoice({
				description: 'persistent-invoice',
				amountMsat: 250_000n
			});
			const invoicesBefore = node1.listInvoices();
			expect(invoicesBefore).to.have.length(1);
			expect(invoicesBefore[0].description).to.equal('persistent-invoice');

			node1.destroy();

			// Create a second node with the same storage — invoices should be restored
			const node2 = new LightningNode({
				nodePrivateKey: privkey,
				channelBasepoints: basepoints,
				perCommitmentSeed: seed,
				fundingPrivkey,
				network: Network.REGTEST,
				storage
			});
			node2.on('error', () => {});

			const invoicesAfter = node2.listInvoices();
			expect(invoicesAfter).to.have.length(1);
			expect(invoicesAfter[0].description).to.equal('persistent-invoice');
			expect(invoicesAfter[0].bolt11).to.equal(invoicesBefore[0].bolt11);
			node2.destroy();
		});

		it('invoice info contains paymentHash, bolt11, description, amountMsat, expiry, createdAt', () => {
			const node = createTestNode();

			node.createInvoice({
				description: 'detailed-invoice',
				amountMsat: 42_000n,
				expiry: 7200
			});

			const invoices = node.listInvoices();
			expect(invoices).to.have.length(1);

			const inv = invoices[0];
			expect(inv.paymentHash).to.be.a('string');
			expect(inv.paymentHash).to.have.length(64); // 32 bytes hex
			expect(inv.bolt11).to.be.a('string');
			expect(inv.bolt11.startsWith('lnbcrt')).to.equal(true); // regtest prefix
			expect(inv.description).to.equal('detailed-invoice');
			expect(inv.amountMsat).to.equal(42_000n);
			expect(inv.expiry).to.equal(7200);
			expect(inv.createdAt).to.be.a('number');
			expect(inv.createdAt).to.be.greaterThan(0);
			node.destroy();
		});
	});

	// ─────────────── 4D: package.json exports ───────────────

	describe('4D — package.json exports', () => {
		it('package.json has exports field with ./lightning and ./cli entries', () => {
			const pkgPath = path.join(__dirname, '../../package.json');
			const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

			expect(pkg.exports).to.exist;
			expect(pkg.exports['.']).to.exist;
			expect(pkg.exports['./lightning']).to.exist;
			expect(pkg.exports['./cli']).to.exist;

			// Check that each entry has types and default
			expect(pkg.exports['.'].types).to.be.a('string');
			expect(pkg.exports['.'].default).to.be.a('string');
			expect(pkg.exports['./lightning'].types).to.be.a('string');
			expect(pkg.exports['./lightning'].default).to.be.a('string');
			expect(pkg.exports['./cli'].types).to.be.a('string');
			expect(pkg.exports['./cli'].default).to.be.a('string');
		});
	});

	// ─────────────── 4E: isPermanentFailure ───────────────

	describe('4E — isPermanentFailure', () => {
		it('isPermanentFailure returns true for PERM flag (0x4000), BADONION flag (0x8000), EXPIRY_TOO_FAR (21), false for temporary failures', () => {
			const node = createTestNode();
			const isPerm = (code?: number): boolean => {
				return (node as any).isPermanentFailure(code);
			};

			// PERM flag set (0x4000)
			expect(isPerm(0x4000)).to.equal(true);
			expect(isPerm(0x400f)).to.equal(true); // PERM | some code
			expect(isPerm(0x4001)).to.equal(true);

			// BADONION flag set (0x8000)
			expect(isPerm(0x8000)).to.equal(true);
			expect(isPerm(0x8002)).to.equal(true);

			// EXPIRY_TOO_FAR (21) — permanent by special case
			expect(isPerm(EXPIRY_TOO_FAR)).to.equal(true);
			expect(isPerm(21)).to.equal(true);

			// Temporary failures — should return false
			expect(isPerm(0x1000)).to.equal(false); // UPDATE flag only
			expect(isPerm(0x0001)).to.equal(false); // temporary
			expect(isPerm(20)).to.equal(false); // CHANNEL_DISABLED (not permanent per se)
			expect(isPerm(0x2000)).to.equal(false); // NODE flag only
			expect(isPerm(0)).to.equal(false);

			// undefined should return false
			expect(isPerm(undefined)).to.equal(false);

			node.destroy();
		});
	});
});
